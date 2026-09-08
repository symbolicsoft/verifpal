/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::deduction::compute_knowledge_closure;
use crate::info::info_message;
use crate::primitive::primitive_get;
use crate::reexec::attacker_authored;
use crate::theory::{can_rewrite, reduce_once};
use crate::types::*;
use crate::value::resolve_trace_constant;
use crate::verify::verify_resolve_queries;

pub(crate) fn validate(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps_base: &PrincipalState,
	guards: &crate::reexec::Guards,
	attacker: &AttackerState,
	signature: &[(usize, Value)],
	key: u64,
) -> VResult<bool> {
	let ps = ps_base.clone_for_depth(true);
	let mut installs: Vec<(SlotIdx, Value)> = Vec::new();
	let mut phases: Vec<i32> = Vec::new();

	let mut authored = Vec::new();
	for (i, &(slot, ref ground)) in signature.iter().enumerate() {
		if slot >= ps.values.len()
			|| super::vars::contains_var(ground)
			|| signature[..i].iter().any(|(seen, _)| *seen == slot)
		{
			return Ok(false);
		}
		if attacker_authored(ground, slot, km, &ps) {
			authored.push(slot);
		}
	}
	let coherent = guards.history.compatible(ctx, km, &ps, &authored, attacker);
	let attacker = coherent.as_deref().unwrap_or(attacker);

	for &(slot, ref ground) in signature {
		if !guards.controllable.admits(&ps, attacker, slot) {
			return Ok(false);
		}
		if !crate::primitive::admissible(ground) {
			return Ok(false);
		}
		if !guards.bound.admits_at(km, ps.id, slot, ground) {
			note_depth_cut(ctx, slot, ground, &ps, guards.bound);
			return Ok(false);
		}
		if contains_failed_check(ground) {
			return Ok(false);
		}
		let Some(at) = attacker_can_derive(ctx, slot, ground, &ps, attacker) else {
			return Ok(false);
		};
		if let Some(available) = crate::reexec::available_before_receive(km, &ps, slot, attacker)
			&& !derivable(ground, &ps, &available)
		{
			return Ok(false);
		}
		if ctx.replication_only() && replays_own_freshness(km, ground, &ps, attacker) {
			ctx.note_replication_rejection();
			return Ok(false);
		}
		installs.push((SlotIdx(slot), ground.clone()));
		phases.push(at);
	}

	if authored.is_empty() || spends_another_execution(km, &ps, signature, attacker) {
		return Ok(false);
	}

	let governing = crate::reexec::governing_attacker(ctx, &phases, attacker);
	let restricted = guards
		.history
		.compatible(ctx, km, &ps, &authored, &governing);
	let governing = restricted.as_deref().unwrap_or(&governing);
	let phase = governing.current_phase;
	let recalled = ctx.recall_execution(ps.id, key, signature, phase, |decisions| {
		decisions.iter().all(|(who, prim, at, was)| {
			ctx.principal_states()
				.iter()
				.find(|state| state.id == *who)
				.is_none_or(|state| {
					*was == crate::reexec::bypass_constructible_at(km, prim, state, *at, governing)
				})
		})
	});
	let executed = match recalled {
		Some((executed, closed)) => {
			if closed {
				for _ in &executed {
					ctx.analysis_count_increment();
				}
				return Ok(true);
			}
			executed
		}
		None => {
			crate::reexec::record_bypass_decisions();
			let executed =
				crate::reexec::execute_forward(ctx, km, &ps, &installs, Some(&phases), governing);
			let decisions = crate::reexec::take_bypass_decisions();
			let Ok(executed) = executed else {
				return Ok(false);
			};
			ctx.remember_execution(ps.id, key, signature, phase, &executed, decisions);
			executed
		}
	};

	let against = ctx.knowledge_saturation();
	for (i, state) in executed.iter().enumerate() {
		if i == 0 {
			note_malleable_reshapes(ctx, km, state, &installs, governing);
		}
		let _ = compute_knowledge_closure(ctx, km, state);
	}
	for state in &executed {
		let _ = verify_resolve_queries(ctx, km, state);
	}
	ctx.note_execution_closed(ps.id, key, signature, phase, against);
	Ok(true)
}

pub(crate) fn note_malleable_reshapes(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	snapshot: &AttackerState,
) {
	if ps.capabilities.is_empty() {
		return;
	}
	let mut record = None;
	for (_, ground) in installs {
		let Value::Primitive(p) = ground else {
			continue;
		};
		if snapshot.knows(ground).is_some() || crate::theory::obtainable(ground, ps, snapshot) {
			continue;
		}
		let Some((held, vary)) = malleable_positions(p, ps, snapshot) else {
			continue;
		};
		let using: Vec<Value> = vary
			.iter()
			.filter_map(|&i| p.arguments.get(i).cloned())
			.collect();
		if !using.iter().all(|a| derivable(a, ps, snapshot)) {
			continue;
		}
		let diffs = record
			.get_or_insert_with(|| crate::value::compute_slot_diffs(ps, km, snapshot.current_phase))
			.clone();
		ctx.attacker_put_with(
			ground,
			&diffs,
			DerivationRecord::Broken {
				of: held,
				capability: Capability::Malleable,
				using,
			},
		);
	}
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
	v.constant_leaves().any(|c| {
		ps.index_of(c)
			.is_some_and(|i| ps.meta[i].constant.fresh && ps.values[i].provenance.creator == ps.id)
	})
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

fn spends_another_execution(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	chosen: &[(usize, Value)],
	attacker: &AttackerState,
) -> bool {
	let mut pending: Vec<_> = chosen.iter().rev().map(|(_, ground)| ground).collect();
	let mut seen = IdSet::default();
	while let Some(ground) = pending.pop() {
		if let Value::Primitive(p) = ground
			&& !seen.insert(std::sync::Arc::as_ptr(p) as usize)
		{
			continue;
		}
		if attacker.knows(ground).is_none() {
			if let Value::Primitive(p) = ground {
				pending.extend(p.arguments.iter().rev());
			}
			continue;
		}
		if crate::deduction::needs_of(km, attacker, ground)
			.iter()
			.any(|(who, at, need)| {
				let at = at.get();
				*who == ps.id
					&& ps
						.meta
						.get(at)
						.is_some_and(|meta| meta.wire.contains(&ps.id))
					&& {
						let here = chosen
							.iter()
							.find(|(slot, _)| *slot == at)
							.map(|(_, value)| value.clone())
							.or_else(|| {
								km.slots
									.get(at)
									.map(|slot| resolve_trace_constant(&slot.constant, km))
							});
						here.is_some_and(|here| {
							!reduce_once(&here).equivalent(&reduce_once(need), true)
						})
					}
			}) {
			return true;
		}
	}
	false
}

pub(crate) fn attacker_can_derive(
	ctx: &VerifyContext,
	slot: usize,
	ground: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<i32> {
	let meta = ps.meta.get(slot)?;
	let cap = meta
		.delivery_phases
		.iter()
		.find(|&&(who, _)| who == ps.id)
		.map(|&(_, phase)| phase)
		.unwrap_or(attacker.current_phase)
		.min(attacker.current_phase);
	let mut candidates: Vec<i32> = meta
		.delivery_phases
		.iter()
		.map(|&(_, phase)| phase)
		.filter(|&phase| phase <= cap)
		.collect();
	candidates.sort_unstable();
	candidates.dedup();
	candidates.into_iter().find(|&phase| {
		if phase < attacker.current_phase {
			ctx.attacker_knowledge_at(phase)
				.is_some_and(|snapshot| derivable(ground, ps, &snapshot))
		} else {
			derivable(ground, ps, attacker)
		}
	})
}

pub(crate) fn derivable(v: &Value, ps: &PrincipalState, snapshot: &AttackerState) -> bool {
	let _memo = crate::theory::DeductionMemo::ensure(ps, snapshot);
	derivable_shared(v, ps, snapshot, &mut IdMap::default())
}

fn derivable_shared(
	v: &Value,
	ps: &PrincipalState,
	snapshot: &AttackerState,
	seen: &mut IdMap<usize, bool>,
) -> bool {
	if snapshot.knows(v).is_some() {
		return true;
	}
	match v {
		Value::Constant(c) => c.is_nil(),
		Value::Primitive(p) => {
			let key = std::sync::Arc::as_ptr(p) as usize;
			if let Some(&result) = seen.get(&key) {
				return result;
			}
			if crate::theory::obtainable(v, ps, snapshot) {
				return true;
			}
			let result = if let Some((_, vary)) = malleable_positions(p, ps, snapshot) {
				p.arguments
					.iter()
					.enumerate()
					.all(|(i, a)| !vary.contains(&i) || derivable_shared(a, ps, snapshot, seen))
			} else {
				let exempt_secret = forgeable_secret_position(p, ps, snapshot);
				let by_reuse = crate::theory::forgeable_by_reuse(p, snapshot);
				p.arguments.iter().enumerate().all(|(i, a)| {
					Some(i) == exempt_secret
						|| by_reuse.contains(&i)
						|| derivable_shared(a, ps, snapshot, seen)
				})
			};
			seen.insert(key, result);
			result
		}
	}
}

fn malleable_positions(
	p: &Primitive,
	ps: &PrincipalState,
	snapshot: &AttackerState,
) -> Option<(Value, Vec<usize>)> {
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
			return Some((known.clone(), spec.malleable_vary.clone()));
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

pub(crate) fn contains_failed_check(v: &Value) -> bool {
	crate::value::subterms(v).any(|term| {
		matches!(term, Value::Primitive(p) if p.instance_check
				&& primitive_get(p.id).is_ok_and(|spec| spec.rewrite.is_some())
				&& !can_rewrite(p).0)
	})
}

#[cfg(test)]
mod tests {
	use super::derivable;
	use crate::primitive::{PRIM_AEAD_ENC, PRIM_ENC, PRIM_PUBKEY, PRIM_SIGN};
	use crate::testutil::*;
	use crate::value::value_nil;

	fn empty_state() -> crate::types::PrincipalState {
		make_principal_state("Test", 0, vec![], vec![])
	}

	#[test]
	fn receive_history_check_handles_shared_terms() {
		use crate::types::Value;
		let mut term = value_nil();
		for _ in 0..40 {
			term = Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![term.clone(), term.clone(), term],
				0,
			);
		}
		assert!(!super::spends_another_execution(
			&make_trace(),
			&empty_state(),
			&[(0, term)],
			&make_attacker_state(vec![value_nil()]),
		));
	}

	#[test]
	fn concrete_proposals_are_checked_independently_of_the_solver() {
		use crate::context::VerifyContext;
		use crate::reexec::{Coherence, Controllable, Guards};
		use crate::types::Value;
		let _generation = crate::context::GenerationGuard::enter();
		let model = crate::parser::parse_string(
			"concrete_proposals.vp",
			"attacker[active]\nprincipal Alice[\ngenerates a, b\n]\nAlice -> Bob: a, [b]\nprincipal Bob[\nx = HASH(a)\n]\nqueries[\nequivalence? a, b\n]\n",
		)
		.unwrap();
		let (km, states) = crate::sanity::sanity(&model).unwrap();
		let ps = states.iter().find(|ps| ps.name == "Bob").unwrap();
		let slot = |name| {
			km.index_of(trace_constant(&km, name).as_constant().unwrap())
				.unwrap()
		};
		let a = slot("a");
		let attacker = make_attacker_state(vec![value_nil()]);
		let ctx = VerifyContext::new(&model, &states, Vec::new(), 1, None, Vec::new());
		let controllable = Controllable::of(&km, ps, &attacker);
		let history = Coherence::of(&km, ps);
		let guards = Guards {
			controllable: &controllable,
			bound: ctx.term_bound(&km),
			history: &history,
		};
		for bad in [
			vec![(slot("b"), value_nil()), (a, value_nil())],
			vec![(slot("x"), value_nil()), (a, value_nil())],
			vec![(a, trace_constant(&km, "b"))],
			vec![(ps.values.len(), value_nil()), (a, value_nil())],
			vec![(a, crate::solve::vars::free_var(0))],
			vec![
				(a, value_nil()),
				(
					a,
					Value::primitive(crate::primitive::PRIM_HASH, vec![value_nil()], 0),
				),
			],
		] {
			assert!(!super::validate(&ctx, &km, ps, &guards, &attacker, &bad, 0).unwrap());
			assert!(!ctx.query_is_resolved(0));
			assert_eq!(ctx.attacker_known_count(), 0);
		}
		let _minimizing = crate::witness::minimization_guard();
		assert!(
			super::validate(&ctx, &km, ps, &guards, &attacker, &[(a, value_nil())], 0).unwrap()
		);
		assert!(ctx.query_is_resolved(0));
	}

	#[test]
	fn validation_predicates_visit_shared_terms_once() {
		use crate::types::Value;
		let leaf = make_constant("validation_dag_leaf");
		let mut metadata = make_slot_meta(leaf.as_constant().unwrap(), true);
		metadata.constant.fresh = true;
		let mut ps = make_principal_state(
			"Beacon",
			1,
			vec![metadata],
			vec![make_slot_values(&leaf, 1)],
		);
		let mut term = leaf;
		for _ in 0..40 {
			term = Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![term.clone(), term.clone(), term],
				0,
			);
		}
		assert!(!super::contains_failed_check(&term));
		assert!(super::carries_own_fresh(&term, &ps));
		ps.values[0].provenance.creator = 2;
		assert!(!super::carries_own_fresh(&term, &ps));
		let mut check = crate::types::Primitive::new(
			crate::primitive::PRIM_AEAD_DEC,
			vec![value_nil(), value_nil(), value_nil(), value_nil()],
			0,
		);
		check.instance_check = true;
		let checked = Value::Primitive(std::sync::Arc::new(check));
		let wrapped = Value::primitive(crate::primitive::PRIM_HASH, vec![term, checked], 0);
		assert!(super::contains_failed_check(&wrapped));
	}

	#[test]
	fn derivability_checks_shared_malleable_terms() {
		use crate::types::{Capability, Primitive, Value};
		use std::sync::Arc;
		let key = make_private("derive_dag_key");
		let mut ciphertext = Primitive::new(
			PRIM_ENC,
			vec![key.clone(), make_private("derive_dag_message")],
			0,
		);
		ciphertext.capabilities.set(Capability::Malleable, 0);
		let ciphertext = Value::Primitive(Arc::new(ciphertext));
		let attacker = make_attacker_state(vec![value_nil(), ciphertext.clone()]);
		let mut ps = empty_state();
		Arc::make_mut(&mut ps.capabilities).insert(&ciphertext);
		let mut term = Value::primitive(PRIM_ENC, vec![key.clone(), value_nil()], 0);
		for _ in 0..40 {
			term = Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![term.clone(), term.clone(), term],
				0,
			);
		}
		assert!(derivable(&term, &ps, &attacker));
		let secret = Value::primitive(crate::primitive::PRIM_HASH, vec![term.clone(), key], 0);
		assert!(!derivable(&secret, &ps, &attacker));
		assert!(!derivable(&term, &empty_state(), &attacker));
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
	fn the_attacker_key_filler_is_derivable_with_no_attacker_knowledge() {
		let attacker = make_attacker_state(vec![]);
		let key = crate::primitive::attacker_public_key();
		assert!(
			derivable(&key, &empty_state(), &attacker),
			"{key} is offered at every free position the protocol itself fills with a key \
			 derivation, but the validator cannot build it, so every proposal carrying it \
			 is discarded and the rule never fires"
		);
	}

	#[test]
	fn derivable_forges_under_a_reused_nonce_without_the_key() {
		let k = make_constant("drn_k");
		let n = make_constant("drn_n");
		let ad = make_constant("drn_ad");
		let e1 = make_primitive(
			PRIM_AEAD_ENC,
			vec![k.clone(), n.clone(), make_constant("drn_m1"), ad.clone()],
			0,
		);
		let e2 = make_primitive(
			PRIM_AEAD_ENC,
			vec![k.clone(), n.clone(), make_constant("drn_m2"), ad.clone()],
			0,
		);
		let target = make_primitive(PRIM_AEAD_ENC, vec![k, n, value_nil(), ad.clone()], 0);
		let mut confirmed = make_attacker_state(vec![e1.clone(), e2.clone(), ad.clone()]);
		confirmed.reused = std::sync::Arc::new(vec![[e1.clone(), e2.clone()]]);
		assert!(derivable(&target, &empty_state(), &confirmed));
		assert!(!derivable(
			&target,
			&empty_state(),
			&make_attacker_state(vec![e1.clone(), e2, ad.clone()])
		));
		assert!(!derivable(
			&target,
			&empty_state(),
			&make_attacker_state(vec![e1, ad])
		));
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
