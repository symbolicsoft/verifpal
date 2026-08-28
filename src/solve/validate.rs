/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::deduction::compute_knowledge_closure;
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
	guards: &crate::reexec::Guards,
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
		if !guards.controllable.admits(&ps, attacker, slot) {
			return Ok(false);
		}
		if !crate::primitive::admissible(&ground) {
			return Ok(false);
		}
		if !guards.bound.admits(&ground) {
			note_depth_cut(ctx, slot, &ground, &ps, guards.bound);
			return Ok(false);
		}
		if contains_failed_check(&ground) {
			return Ok(false);
		}
		if !attacker_can_derive(ctx, slot, &ground, &ps, attacker) {
			return Ok(false);
		}
		if ctx.replication_only() && replays_own_freshness(km, &ground, &ps, attacker) {
			ctx.note_replication_rejection();
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

fn replays_own_freshness(
	km: &ProtocolTrace,
	ground: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> bool {
	let produced_here = match attacker
		.knows(ground)
		.and_then(|idx| attacker.derivation(idx))
	{
		Some(DerivationRecord::Obtained { slot }) | Some(DerivationRecord::Leaked { slot }) => {
			km.slots.get(slot.get()).is_some_and(|s| s.creator == ps.id)
		}
		_ => false,
	};
	produced_here && carries_own_fresh(ground, ps)
}

fn carries_own_fresh(v: &Value, ps: &PrincipalState) -> bool {
	match v {
		Value::Constant(c) => ps
			.index_of(c)
			.is_some_and(|i| ps.meta[i].constant.fresh && ps.values[i].provenance.creator == ps.id),
		Value::Primitive(p) => p.arguments.iter().any(|a| carries_own_fresh(a, ps)),
	}
}

fn note_depth_cut(
	ctx: &VerifyContext,
	slot: usize,
	ground: &Value,
	ps: &PrincipalState,
	bound: &crate::reexec::TermBound,
) {
	if !ctx.note_depth_cut(ps.id, slot) {
		return;
	}
	let Some(meta) = ps.meta.get(slot) else {
		return;
	};
	info_message(
		&format!(
			"Search declined {ground} at {}'s {}: it nests deeper than the {} levels this \
			 protocol itself computes. Attacks needing a term deeper than the protocol \
			 builds are out of reach.",
			ps.name,
			meta.constant.name,
			bound.depth(),
		),
		InfoLevel::Info,
		false,
	);
}

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
			match ctx.attacker_knowledge_at(earliest) {
				Some(snapshot) => derivable(ground, ps, &snapshot),
				None => false,
			}
		}
		_ => derivable(ground, ps, attacker),
	}
}

fn derivable(v: &Value, ps: &PrincipalState, snapshot: &AttackerState) -> bool {
	if snapshot.knows(v).is_some() {
		return true;
	}
	match v {
		Value::Constant(c) => c.is_nil(),
		Value::Primitive(p) => {
			if crate::theory::obtainable(v, ps, snapshot) {
				return true;
			}
			if let Some(vary) = malleable_positions(p, ps, snapshot) {
				return p
					.arguments
					.iter()
					.enumerate()
					.all(|(i, a)| !vary.contains(&i) || derivable(a, ps, snapshot));
			}
			let exempt = forgeable_secret_position(p, ps, snapshot);
			p.arguments
				.iter()
				.enumerate()
				.all(|(i, a)| Some(i) == exempt || derivable(a, ps, snapshot))
		}
	}
}

fn malleable_positions(
	p: &Primitive,
	ps: &PrincipalState,
	snapshot: &AttackerState,
) -> Option<Vec<usize>> {
	let spec = primitive_get(p.id).ok()?;
	if spec.malleable_vary.is_empty() {
		return None;
	}
	for known in snapshot.known.iter() {
		let Value::Primitive(held) = known else {
			continue;
		};
		if held.id != p.id || held.output != p.output || held.arguments.len() != p.arguments.len() {
			continue;
		}
		if !ps
			.capabilities
			.in_force(held, Capability::Malleable, snapshot.current_phase)
		{
			continue;
		}
		let anchored = p
			.arguments
			.iter()
			.zip(held.arguments.iter())
			.enumerate()
			.all(|(i, (a, b))| spec.malleable_vary.contains(&i) || a.equivalent(b, true));
		if anchored {
			return Some(spec.malleable_vary.clone());
		}
	}
	None
}

fn forgeable_secret_position(
	p: &Primitive,
	ps: &PrincipalState,
	snapshot: &AttackerState,
) -> Option<usize> {
	ps.capabilities
		.forgeable_secret_position(p, snapshot.current_phase)
}

fn contains_failed_check(v: &Value) -> bool {
	match v {
		Value::Primitive(p) => {
			if p.instance_check
				&& primitive_get(p.id).is_ok_and(|spec| spec.rewrite.is_some())
				&& !can_rewrite(p).0
			{
				return true;
			}
			p.arguments.iter().any(contains_failed_check)
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
		let pubkey_nil = make_primitive(PRIM_PUBKEY, vec![value_nil()], 0);
		assert!(derivable(&pubkey_nil, &empty_state(), &attacker));
	}

	#[test]
	fn derivable_accepts_synthesis_from_held_arguments() {
		let k = make_constant("der_k");
		let m = make_constant("der_m");
		let attacker = make_attacker_state(vec![k.clone(), m.clone()]);
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
	fn every_divergence_filler_is_derivable_with_no_attacker_knowledge() {
		let attacker = make_attacker_state(vec![]);
		for filler in crate::solve::diverge::fillers() {
			assert!(
				derivable(&filler, &empty_state(), &attacker),
				"{filler} is offered as a divergence filler but the validator cannot build \
				 it, so every proposal carrying it is discarded and the rule never fires"
			);
		}
	}

	#[test]
	fn derivable_rejects_a_forgery_under_an_unheld_key() {
		let sk = make_constant("der_sk");
		let m = make_constant("der_msg");
		let attacker = make_attacker_state(vec![m.clone()]);
		let forged = make_primitive(PRIM_SIGN, vec![sk, m], 0);
		assert!(!derivable(&forged, &empty_state(), &attacker));
	}
}
