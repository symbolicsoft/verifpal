/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Faithful re-execution of a hypothetical principal state
//!
//! Installing attacker-chosen values into a principal and running it forward
//! is needed in two places: the goal-directed solver validating a proposal
//! ([`crate::solve::validate`]) and the trace minimizer deciding whether a
//! mutation is load-bearing ([`crate::witness`]).  Both must agree exactly —
//! a minimizer that re-executed differently could drop a mutation the real
//! engine needs, and report an attack trace that does not reproduce.
//!
//! So the logic lives here once: install, resolve, rewrite, then either
//! bypass guards the attacker can defeat or truncate at the checked primitive
//! that halts the principal.

use std::sync::Arc;

use crate::primitive::primitive_extract_bypass_key;
use crate::principal::ATTACKER_ID;
use crate::theory::{can_reconstruct_equation, can_reconstruct_primitive, can_rewrite};
use crate::types::*;
use crate::value::{resolve_trace_values, value_g_nil};

/// What the principal actually computes under `installs`, with guard bypass
/// and halt truncation already applied.
pub(crate) fn reexecute(
	ps_base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	attacker: &AttackerState,
	km: &ProtocolTrace,
) -> VResult<PrincipalState> {
	let mut ps = ps_base.clone();
	// Judged against the pristine state so one slot's substitution cannot change
	// the verdict on another's, and decided here so the solver and the minimizer
	// cannot drift apart.
	let authored: Vec<bool> = installs
		.iter()
		.map(|(slot, ground)| {
			slot.get() < ps.values.len() && attacker_authored(ground, slot.get(), km, &ps)
		})
		.collect();
	for ((slot, ground), authored) in installs.iter().zip(authored) {
		if slot.get() < ps.values.len() {
			install(&mut ps, slot.get(), ground.clone(), authored);
		}
	}

	// Keep the pre-resolution form: guard bypass has to inject into it and
	// re-resolve, because once values are inlined an injection no longer
	// propagates to the slots that referenced the constant.
	let ps_pre = ps.clone();
	ps.resolve_all_values(attacker)?;
	let failures = ps.perform_all_rewrites();

	if let Some(bypassed) = try_guard_bypass(&ps_pre, &ps, &failures, attacker)? {
		ps = bypassed;
	} else if let Some((truncate_at, halted_at)) = truncation_point(&ps, &failures) {
		// A checked primitive that still fails halts the principal.  Everything
		// it would have computed afterwards never existed, so the state is
		// truncated there rather than handing later values to the attacker.
		ps = drop_after_index(ps, truncate_at);
		ps.halted_at = Some(halted_at);
	}
	Ok(ps)
}

/// Maximum cascade rounds when bypassing guards.  Bypassing one guard can make
/// a later one bypassable, because the key it depended on has become derivable.
/// Chains longer than this do not occur in practice.
const MAX_BYPASS_ROUNDS: usize = 5;

/// A checked primitive that fails does not always halt the principal.
///
/// If the attacker can obtain the value the check is really testing — the
/// decryption key for `AEAD_DEC?`, the private exponent behind the public key
/// for `SIGNVERIF?` — then it could have produced an input that passes.  This
/// is the decisive case for man-in-the-middle: substituting `G^nil` for an
/// identity key fails the signature check, but the attacker *knows the private
/// key for `G^nil`*, so it can present a signature that verifies.  Treating
/// that as a halt would discard the entire attack.
///
/// This has to work from the pre-resolution state: injecting into an
/// already-inlined state would not propagate to the slots that referenced the
/// guard's output.
///
/// Returns `None` when no guard is bypassable, leaving the caller to truncate.
fn try_guard_bypass(
	ps_pre: &PrincipalState,
	ps_resolved: &PrincipalState,
	failures: &[(Primitive, usize)],
	attacker: &AttackerState,
) -> VResult<Option<PrincipalState>> {
	let bypassable: Vec<usize> = failures
		.iter()
		.filter(|(prim, idx)| {
			prim.instance_check
				&& ps_resolved.values[*idx].provenance.creator == ps_resolved.id
				&& primitive_extract_bypass_key(prim)
					.is_some_and(|key| can_obtain(&key, ps_resolved, attacker))
		})
		.map(|(_, idx)| *idx)
		.collect();

	if bypassable.is_empty() {
		return Ok(None);
	}

	let mut ps = ps_pre.clone();
	for idx in bypassable {
		if idx < ps.values.len() {
			ps.values[idx].override_all_bypassed(value_g_nil());
		}
	}

	for _ in 0..MAX_BYPASS_ROUNDS {
		ps.resolve_all_values(attacker)?;
		let round = ps.perform_all_rewrites();
		let mut injected = false;
		for (prim, idx) in &round {
			if !prim.instance_check || ps.values[*idx].provenance.creator != ps.id {
				continue;
			}
			if primitive_extract_bypass_key(prim).is_some_and(|key| can_obtain(&key, &ps, attacker))
			{
				ps.values[*idx].override_all_bypassed(value_g_nil());
				injected = true;
			}
		}
		if !injected {
			break;
		}
	}

	// Whatever still fails after all bypasses really does halt the principal.
	ps.resolve_all_values(attacker)?;
	let remaining = ps.perform_all_rewrites();
	if let Some((truncate_at, halted_at)) = truncation_point(&ps, &remaining) {
		ps = drop_after_index(ps, truncate_at);
		ps.halted_at = Some(halted_at);
	}
	Ok(Some(ps))
}

fn can_obtain(v: &Value, ps: &PrincipalState, attacker: &AttackerState) -> bool {
	if attacker.knows(v).is_some() {
		return true;
	}
	match v {
		Value::Primitive(p) => can_reconstruct_primitive(p, ps, attacker, 0).is_some(),
		Value::Equation(e) => can_reconstruct_equation(e, attacker).is_some(),
		_ => false,
	}
}

/// Whether putting `ground` in `slot` is something the *attacker* did, as
/// opposed to the honest message arriving unchanged.
///
/// A term that reduces back to the honest value is a replay: the recipient
/// cannot tell it apart from the real message (issue #18).
///
/// This governs authorship, not installation.  A proposal binds the slot it is
/// attacking alongside several it merely forwards, and those still have to be
/// installed or the principal computes from a state no run produced — but
/// stamping them attacker-sent is what manufactures a false authentication
/// attack.
pub(crate) fn attacker_authored(
	ground: &Value,
	slot: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> bool {
	let honest = &ps.values[slot].value;
	let (trace_resolved, _) = resolve_trace_values(honest, km);
	let trace_reduct = reduce(&trace_resolved, ps).unwrap_or(trace_resolved);
	let ground_reduct = reduce(ground, ps).unwrap_or_else(|| ground.clone());
	!ground_reduct.equivalent(&trace_reduct, true)
}

/// Rewrite a primitive if doing so changes it.
fn reduce(v: &Value, ps: &PrincipalState) -> Option<Value> {
	let p = v.as_primitive()?;
	let (_, rewritten) = can_rewrite(p, ps, 0);
	if rewritten.equivalent(v, true) {
		None
	} else {
		Some(rewritten)
	}
}

/// Install an attacker-chosen value in a slot, with the provenance the rest of
/// the engine expects.
///
/// `original` keeps the value the principal believes it received.  Losing that
/// distinction is what causes false authentication attacks, because principals
/// would then "see" the attacker's tampering inside their own computations.
///
/// `authored` is [`attacker_authored`]: when false the value is installed but
/// the provenance is left alone, because the attacker forwarded the honest
/// message rather than replacing it.
pub(crate) fn install(ps: &mut PrincipalState, slot: usize, ground: Value, authored: bool) {
	let previous = ps.values[slot].value.clone();
	let sv = &mut ps.values[slot];
	sv.original = previous;
	sv.provenance.creator = ATTACKER_ID;
	sv.provenance.attacker_tainted = true;
	// Taint says the value passed through the attacker's hands, which is true of
	// a relay too, and governs what the principal perceives.  `sender` is the
	// narrower claim that the attacker produced it — the only thing an
	// authentication query reads.
	if authored {
		sv.provenance.sender = ATTACKER_ID;
	}
	sv.pre_rewrite = ground.clone();
	sv.value = ground;
}

/// The slot index to truncate at, and the `declared_at` to record as the halt
/// point, given the failures reported by `perform_all_rewrites`.
///
/// Only checked primitives (`?`) this principal computed itself can halt it.
fn truncation_point(ps: &PrincipalState, failures: &[(Primitive, usize)]) -> Option<(usize, i32)> {
	for (prim, idx) in failures {
		if !prim.instance_check || ps.values[*idx].provenance.creator != ps.id {
			continue;
		}
		let declared_at = ps.meta[*idx].declared_at;
		let truncate_at = if declared_at == ps.max_declared_at {
			idx + 1
		} else {
			match ps.meta.iter().position(|m| m.declared_at == declared_at) {
				Some(pos) => pos + 1,
				None => idx + 1,
			}
		};
		return Some((truncate_at, declared_at));
	}
	None
}

fn drop_after_index(mut ps: PrincipalState, at: usize) -> PrincipalState {
	Arc::make_mut(&mut ps.meta).truncate(at);
	ps.values.truncate(at);
	ps
}

#[cfg(test)]
mod tests {
	use crate::testutil::*;
	use crate::types::SlotIdx;

	#[test]
	fn reexecute_installs_with_attacker_provenance() {
		use crate::reexec::reexecute;
		let a = make_constant("rex_a");
		let b = make_constant("rex_b");
		let ca = a.as_constant().expect("constant").clone();
		let cb = b.as_constant().expect("constant").clone();
		let meta = vec![make_slot_meta(&ca, true), make_slot_meta(&cb, false)];
		let values = vec![make_slot_values(&a, 0), make_slot_values(&b, 1)];
		let ps = make_principal_state("Alice", 0, meta, values);
		let attacker = make_attacker_state(vec![]);

		let km = make_trace();
		let out = reexecute(&ps, &[(SlotIdx(1), a.clone())], &attacker, &km).expect("reexecute");

		// The installed slot carries the attacker's value and provenance.
		assert!(out.values[1].value.equivalent(&a, true));
		assert!(out.values[1].provenance.attacker_tainted);
		assert_eq!(
			out.values[1].provenance.sender,
			crate::principal::ATTACKER_ID
		);
		// `original` keeps what the principal believed it received.
		assert!(out.values[1].original.equivalent(&b, true));
		// Untouched slots are unaffected.
		assert!(!out.values[0].provenance.attacker_tainted);
	}

	/// Forwarding the honest value is a relay: installed, but not the attacker's
	/// to claim.  Stamping it made every unrelated slot of a multi-slot proposal
	/// look attacker-sent — the false `signal.vp` authentication attack.
	#[test]
	fn reexecute_does_not_attribute_a_relayed_value_to_the_attacker() {
		use crate::reexec::reexecute;
		let a = make_constant("relay_a");
		let b = make_constant("relay_b");
		let ca = a.as_constant().expect("constant").clone();
		let cb = b.as_constant().expect("constant").clone();
		let meta = vec![make_slot_meta(&ca, true), make_slot_meta(&cb, false)];
		let values = vec![make_slot_values(&a, 0), make_slot_values(&b, 1)];
		let ps = make_principal_state("Alice", 0, meta, values);
		let attacker = make_attacker_state(vec![]);
		let km = make_trace();

		// Slot 1 already holds `b`; installing `b` there changes nothing.
		let out = reexecute(&ps, &[(SlotIdx(1), b.clone())], &attacker, &km).expect("reexecute");

		assert!(out.values[1].value.equivalent(&b, true));
		// Taint still applies; authorship does not.
		assert!(out.values[1].provenance.attacker_tainted);
		assert_ne!(
			out.values[1].provenance.sender,
			crate::principal::ATTACKER_ID,
			"a forwarded value must not be attributed to the attacker"
		);
	}
}
