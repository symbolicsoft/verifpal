/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::deduction::compute_knowledge_closure;
use crate::equivalence::homeomorphically_embeds;
use crate::info::info_message;
use crate::primitive::primitive_get;
use crate::reexec::attacker_authored;
use crate::theory::can_rewrite;
use crate::types::*;
use crate::util::min_int_in_slice;
use crate::verify::verify_resolve_queries;

use super::symbolic::SymbolicState;
use super::vars::{Substitution, apply};

pub(crate) fn validate(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps_base: &PrincipalState,
	sym: &SymbolicState,
	attacker: &AttackerState,
	subst: &Substitution,
) -> VResult<bool> {
	let ps = ps_base.clone_for_depth(true);
	let mut installs: Vec<(SlotIdx, Value)> = Vec::new();
	let mut worthwhile = false;

	for &slot in &sym.var_slots {
		let Some(var_term) = &sym.var_terms[slot] else {
			continue;
		};
		if !subst.contains_key(&super::vars::attacker_var_id(slot)) {
			continue;
		}
		let ground = super::vars::ground_free(&apply(var_term, subst));
		if super::vars::contains_var(&ground) {
			continue;
		}
		if slot >= ps.values.len() {
			continue;
		}
		if contains_failed_check(&ground, &ps) {
			return Ok(false);
		}
		if is_self_feeding_pump(ctx, slot, &ground, &ps, attacker) {
			return Ok(false);
		}
		if !attacker_can_derive(ctx, slot, &ground, &ps, attacker) {
			return Ok(false);
		}
		if attacker_authored(&ground, slot, km, &ps) {
			worthwhile = true;
		}
		installs.push((SlotIdx(slot), ground));
	}

	if !worthwhile {
		return Ok(false);
	}

	for (slot, ground) in &installs {
		if let Some(ancestor) = pump_ancestor(slot.get(), ground, &ps, attacker) {
			ctx.lineage_record(ps.id, slot.get(), ground, &ancestor);
		}
	}

	let governing = crate::reexec::governing_attacker(ctx, &installs, &ps, attacker);
	let Ok(ps) = crate::reexec::reexecute(&ps, &installs, &governing, km) else {
		return Ok(false);
	};

	let _ = compute_knowledge_closure(ctx, km, &ps);
	let _ = verify_resolve_queries(ctx, km, &ps);
	Ok(true)
}

/// A *self-feeding replay pump*: the attacker offers a value for slot `S` that
/// it holds only because it already injected a strictly smaller version of that
/// same value into that same slot, in that same principal's session.
///
/// This is what makes an active search diverge. Where one key covers both
/// directions of a principal's leg and a growing constructor sits on the return
/// path — `d = AEAD_DEC(k, e, nil)`, `h = HASH(d)`, `e' = AEAD_ENC(k, h, nil)` —
/// the principal's own output is a well-typed input to itself, one rung deeper.
/// Feeding it back is new knowledge, so `verify_active`'s round loop sees
/// progress and goes again, forever. `needham-schroeder.vp` did exactly this:
/// 213 nested `HASH`es and 132k proposals in 45s, no query resolved.
///
/// It is a cycle test rather than a size test, which is what keeps the cost to
/// completeness narrow. Rung 1 is learned from the honest run and carries no
/// diff at `S`, so reflection attacks survive; and the injection condition asks
/// "do I hold this *because* I injected into this wire", which goal-directed
/// proposals never satisfy — a protocol that genuinely needs a deep term still
/// gets it built from the check that demands it. Only the blind-replay route to
/// that term is lost.
///
/// The embedding is tested against every term previously installed at `S`, not
/// against a single recorded ancestor. Kruskal's theorem gives *some* earlier
/// term embedded in *some* later one; the two need not be adjacent, so a
/// predecessor-only test does not bound the sequence.
fn is_self_feeding_pump(
	ctx: &VerifyContext,
	slot: usize,
	ground: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> bool {
	// The attacker must hold `ground` by a derivation that already substituted
	// at this same slot of this same principal. Goal-directed constructions do
	// not qualify: the attacker builds those because a check demands them, not
	// because they came back off the wire.
	let Some(immediate) = pump_ancestor(slot, ground, ps, attacker) else {
		return false;
	};
	// Test the whole lineage, not just the immediate ancestor. Kruskal's
	// theorem yields *some* earlier term embedded in *some* later one, and the
	// two need not be adjacent, so a predecessor-only test does not bound the
	// sequence.
	//
	// Bare constants are excluded because the blanket substitution installs
	// `nil`, which embeds into almost every term; the constants are interned
	// per model and so cannot hide an infinite sequence.
	let Some(previous) = ctx
		.lineage_of(ps.id, slot, &immediate)
		.into_iter()
		.find(|u| {
			matches!(u, Value::Primitive(_))
				&& !u.equivalent(ground, true)
				&& homeomorphically_embeds(u, ground)
		})
	else {
		return false;
	};
	if ctx.note_pump_cut(ps.id, slot) {
		let name = &ps.meta[slot].constant.name;
		info_message(
			&format!(
				"Search cut a self-feeding replay chain at {}'s {name}: the attacker holds \
				 {ground} only by replaying its own {previous} back into {name}. Deeper \
				 replays of this shape were not explored.",
				ps.name
			),
			InfoLevel::Info,
			false,
		);
	}
	true
}

/// The term the attacker had substituted at `slot` in the derivation that
/// produced `ground`, if `ground` is held because of such a substitution.
fn pump_ancestor(
	slot: usize,
	ground: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<Value> {
	let record = attacker.record(attacker.knows(ground)?)?;
	// Slot indices are per-principal.
	if record.principal_id != ps.id {
		return None;
	}
	record
		.diffs
		.iter()
		.find(|d| d.index.get() == slot)
		.map(|d| d.value.clone())
}

/// The trusted-region re-derivation of an injected term: `ground` is accepted
/// only if the Dolev-Yao attacker could itself have constructed it, from
/// knowledge available no later than slot `S`'s own phase.
///
/// This is the check that lets the soundness theorem quantify over an arbitrary
/// solver. The solver already places every binding under a constructibility
/// obligation (`require_constructible`), but that obligation lives in the
/// untrusted search: were it buggy — or replaced wholesale — it could hand the
/// validator a term the attacker cannot build, such as a signature under a key
/// it does not hold, and re-execution would install it, the recipient's checks
/// would pass, and a forgery no attacker can mount would be reported. Re-deriving
/// `ground` here, against the same closed knowledge the honest analysis trusts,
/// forecloses that: a term the attacker cannot construct is not an attack.
///
/// The predicate is deliberately one-sided. It over-approximates rejection
/// rather than acceptance: `derivable` is sound (it says yes only when the
/// attacker genuinely can build the term), so a solver bug can at worst cost a
/// missed attack here, never a false one — the same trade the rest of the
/// engine makes. Because `attacker.known` is already closed under the deduction
/// rules of the knowledge closure, the recursion below adds only the synthesis
/// direction: applying a public primitive to arguments the attacker can itself
/// derive.
fn attacker_can_derive(
	ctx: &VerifyContext,
	slot: usize,
	ground: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> bool {
	let earliest = ps
		.meta
		.get(slot)
		.and_then(|meta| min_int_in_slice(&meta.phase).ok());
	match earliest {
		Some(earliest) if earliest < attacker.current_phase => {
			// A value whose slot predates the current phase must be derivable
			// from knowledge archived at that earlier phase, so that a value
			// learned later cannot retroactively justify an earlier injection.
			match ctx.attacker_knowledge_at(earliest) {
				Some(snapshot) => derivable(ground, ps, &snapshot),
				None => false,
			}
		}
		_ => derivable(ground, ps, attacker),
	}
}

/// Sound (one-sided) Dolev-Yao derivability of `v` against `snapshot`.
///
/// The two branches are the two ways the attacker obtains a term. The trusted
/// `obtainable` covers analysis — decomposition, and reconstruction that is
/// capability-aware, so a `forgeable`-annotated primitive is derivable without
/// its secret argument exactly as the honest closure treats it. The recursive
/// branch covers synthesis: the attacker applies a public primitive to
/// arguments it can itself derive, which is what makes `PUBKEY(nil)` and other
/// `nil`-leafed man-in-the-middle terms constructible without their appearing in
/// any assigned slot.
fn derivable(v: &Value, ps: &PrincipalState, snapshot: &AttackerState) -> bool {
	if snapshot.knows(v).is_some() {
		return true;
	}
	match v {
		Value::Constant(c) => c.is_nil(),
		Value::Primitive(p) => {
			if crate::theory::obtainable(v, ps, snapshot, 0) {
				return true;
			}
			let exempt = forgeable_secret_position(p, ps, snapshot);
			p.arguments
				.iter()
				.enumerate()
				.all(|(i, a)| Some(i) == exempt || derivable(a, ps, snapshot))
		}
	}
}

/// The argument position of `p` that a declared `forgeable` assumption exempts
/// from the derivability obligation, if one is in force for `p`.
///
/// A `forgeable` annotation says the scheme has lost authenticity: the attacker
/// can produce this primitive, under this secret, over a message of its
/// choosing. The exemption is therefore keyed on the secret argument rather
/// than on the whole term. `SIGN[forgeable](sk, m)` licenses `SIGN(sk, m')` for
/// any derivable `m'`, which is the point of the assumption, but licenses
/// nothing under a different signing key. Matching the whole term instead would
/// make the annotation useless, since a forgery is by definition over a message
/// the honest run never signed; matching on the primitive alone would let one
/// annotation weaken every key in the model.
fn forgeable_secret_position(
	p: &Primitive,
	ps: &PrincipalState,
	snapshot: &AttackerState,
) -> Option<usize> {
	let position = primitive_get(p.id).ok()?.forgeable_secret?;
	let secret = p.arguments.get(position)?;
	let phase = snapshot.current_phase;
	if ps.capabilities.in_force(p, Capability::Forgeable, phase) {
		return Some(position);
	}
	ps.capabilities
		.annotated_terms()
		.any(|(term, caps)| {
			caps.in_force(Capability::Forgeable, phase)
				&& matches!(term, Value::Primitive(q)
					if q.id == p.id
						&& q.arguments.get(position).is_some_and(|s| s.equivalent(secret, true)))
		})
		.then_some(position)
}

fn contains_failed_check(v: &Value, ps: &PrincipalState) -> bool {
	match v {
		Value::Primitive(p) => {
			if p.instance_check
				&& primitive_get(p.id).is_ok_and(|spec| spec.rewrite.has_rule)
				&& !can_rewrite(p, ps, 0).0
			{
				return true;
			}
			p.arguments.iter().any(|a| contains_failed_check(a, ps))
		}
		Value::Constant(_) => false,
	}
}

#[cfg(test)]
mod tests {
	use super::derivable;
	use crate::primitive::{PRIM_ENC, PRIM_PUBKEY, PRIM_SIGN};
	use crate::testutil::*;
	use crate::value::value_nil;

	fn empty_state() -> crate::types::PrincipalState {
		make_principal_state("Test", 0, vec![], vec![])
	}

	#[test]
	fn derivable_accepts_a_directly_known_term() {
		let m = make_constant("der_known_m");
		let attacker = make_attacker_state(vec![m.clone()]);
		assert!(derivable(&m, &empty_state(), &attacker));
	}

	#[test]
	fn derivable_accepts_nil_and_a_primitive_over_nil() {
		let attacker = make_attacker_state(vec![]);
		assert!(derivable(&value_nil(), &empty_state(), &attacker));
		// PUBKEY(nil) is the man-in-the-middle key: nil is public, so the
		// attacker can apply PUBKEY to it.
		let pubkey_nil = make_primitive(PRIM_PUBKEY, vec![value_nil()], 0);
		assert!(derivable(&pubkey_nil, &empty_state(), &attacker));
	}

	#[test]
	fn derivable_accepts_synthesis_from_held_arguments() {
		let k = make_constant("der_k");
		let m = make_constant("der_m");
		let attacker = make_attacker_state(vec![k.clone(), m.clone()]);
		// The attacker holds k and m, so it can encrypt m under k itself.
		let enc = make_primitive(PRIM_ENC, vec![k, m], 0);
		assert!(derivable(&enc, &empty_state(), &attacker));
	}

	#[test]
	fn derivable_rejects_an_unknown_constant() {
		let secret = make_constant("der_secret");
		let unrelated = make_constant("der_unrelated");
		let attacker = make_attacker_state(vec![unrelated]);
		assert!(!derivable(&secret, &empty_state(), &attacker));
	}

	#[test]
	fn derivable_rejects_a_forgery_under_an_unheld_key() {
		// The reviewer's counterexample to a solver-quantified soundness claim:
		// a signature under a key the attacker does not hold, with no forgeable
		// assumption in force. The attacker holds only the message; SIGN(sk, m)
		// must not be derivable, or an adversarially buggy solver could inject a
		// forgery no attacker can mount.
		let sk = make_constant("der_sk");
		let m = make_constant("der_msg");
		let attacker = make_attacker_state(vec![m.clone()]);
		let forged = make_primitive(PRIM_SIGN, vec![sk, m], 0);
		assert!(!derivable(&forged, &empty_state(), &attacker));
	}
}
