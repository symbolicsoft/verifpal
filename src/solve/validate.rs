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
		if !phase_permits(ctx, slot, &ground, &ps, attacker.current_phase) {
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
/// diff at `S`, so reflection attacks survive; and the lineage condition asks
/// "do I hold this *because* I injected into this wire", which goal-directed
/// proposals never satisfy — a protocol that genuinely needs a deep term still
/// gets it built from the check that demands it. Only the blind-replay route to
/// that term is lost. Termination is Kruskal's theorem via
/// [`homeomorphically_embeds`], not a constant.
fn is_self_feeding_pump(
	ctx: &VerifyContext,
	slot: usize,
	ground: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> bool {
	let Some(idx) = attacker.knows(ground) else {
		return false;
	};
	let Some(record) = attacker.record(idx) else {
		return false;
	};
	// Slot indices are per-principal.
	if record.principal_id != ps.id {
		return false;
	}
	let Some(previous) = record
		.diffs
		.iter()
		.find(|d| d.index.get() == slot)
		.map(|d| &d.value)
	else {
		return false;
	};
	// A bare constant predecessor is the blanket substitution, not a pump: what
	// came back is a genuine new observation, free to replay once. Allowing it
	// would also gut the test, since `nil` embeds into almost every term.
	// Constants are interned per model and so finite, so excluding them cannot
	// hide an infinite chain.
	if !matches!(previous, Value::Primitive(_)) {
		return false;
	}
	if previous.equivalent(ground, true) {
		return false;
	}
	if !homeomorphically_embeds(previous, ground) {
		return false;
	}
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

fn phase_permits(
	ctx: &VerifyContext,
	slot: usize,
	ground: &Value,
	ps: &PrincipalState,
	current_phase: i32,
) -> bool {
	let Some(meta) = ps.meta.get(slot) else {
		return true;
	};
	let Ok(earliest) = min_int_in_slice(&meta.phase) else {
		return true;
	};
	if earliest >= current_phase {
		return true;
	}
	match ctx.attacker_knowledge_at(earliest) {
		Some(snapshot) => available_at(ground, &snapshot),
		None => false,
	}
}

fn available_at(v: &Value, snapshot: &AttackerState) -> bool {
	if snapshot.knows(v).is_some() {
		return true;
	}
	match v {
		Value::Constant(c) => c.is_nil(),
		Value::Primitive(p) => p.arguments.iter().all(|a| available_at(a, snapshot)),
	}
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
