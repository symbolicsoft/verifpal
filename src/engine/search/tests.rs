/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::*;
use crate::engine::exec::execute;
use crate::syntax::Query;
use crate::term::Constant;
use crate::util::index::Idx;

#[test]
fn removing_inputs_after_relevant_actions_preserves_query_violations() {
	let fixtures = [
		(
			"precondition_unlink_halt.vp",
			include_str!("../../../examples/test/precondition_unlink_halt.vp"),
		),
		(
			"auth_use_through_checked_relay.vp",
			include_str!("../../../examples/test/auth_use_through_checked_relay.vp"),
		),
		(
			"phase_claim_never_reached_use.vp",
			include_str!("../../../examples/test/phase_claim_never_reached_use.vp"),
		),
		(
			"equivalence_borrowed_while_starved.vp",
			include_str!("../../../examples/test/equivalence_borrowed_while_starved.vp"),
		),
		(
			"freshness_replayed_across_sessions.vp",
			include_str!("../../../examples/test/freshness_replayed_across_sessions.vp"),
		),
		(
			"search_source_alternative.vp",
			include_str!("../../../examples/test/search_source_alternative.vp"),
		),
	];
	let mut removed = 0;
	for (name, source) in fixtures {
		let _generation = crate::util::generation::GenerationGuard::enter();
		let model = crate::syntax::parser::parse_string(name, source).unwrap();
		let km = crate::protocol::sanity::sanity(&model).unwrap();
		let program = crate::engine::program::Program::of(&model, &km);
		let cx = Context::new(&program, &km);
		let ctx = VerifyContext::new(&model, Vec::new(), 1, None, Vec::new(), Vec::new());
		let root = execute(&cx, &Vec::new());
		let search = Search::new(&ctx, &cx, root);
		let mut choices: Installs = program
			.deliveries
			.iter()
			.flat_map(|delivery| {
				delivery
					.slots
					.iter()
					.filter(|(_, guarded)| !guarded)
					.flat_map(|(slot, _)| {
						[
							crate::term::value_nil(),
							crate::primitive::attacker_public_key(),
						]
						.into_iter()
						.map(|value| Install::Value {
							run: delivery.recipient,
							slot: *slot,
							value,
						})
					})
			})
			.collect();
		choices.extend(program.runs.indices().map(|run| Install::Idle { run }));
		for first in &choices {
			for second in &choices {
				let plan = normalize(vec![first.clone(), second.clone()]);
				let projected = search.project(plan.clone());
				if same_installs(&plan, &projected) {
					continue;
				}
				removed += 1;
				let original = execute(&cx, &plan);
				if !original.stuck.is_empty() {
					continue;
				}
				let after = execute(&cx, &projected);
				assert!(after.stuck.is_empty(), "{name}");
				for phase in 0..=km.max_phase {
					let claims = |principal| ctx.claims_at(principal, phase);
					let violates = |ex: &Execution, query: &Query| {
						crate::engine::judgment::Judge {
							cx: &cx,
							ex: ex.at(phase),
							whole: ex,
							claims: &claims,
						}
						.evaluate(query)
						.is_some()
					};
					for query in &model.queries {
						assert!(
							!violates(&original, query) || violates(&after, query),
							"{name}: {plan:?}"
						);
					}
				}
			}
		}
	}
	assert!(removed > 0);
}

#[test]
fn colliding_install_maps_keep_their_own_continuations() {
	let constant = |name: &str, id| {
		Value::Constant(Constant {
			name: Arc::from(name),
			id,
			..Default::default()
		})
	};
	let left = Value::primitive(
		crate::primitive::PRIM_HASH,
		vec![constant("sig_a", 10), constant("sig_b", 100)],
		0,
	);
	let right = Value::primitive(
		crate::primitive::PRIM_HASH,
		vec![constant("sig_c", 11), constant("sig_d", 69)],
		0,
	);
	let left = vec![Install::Value {
		run: RunIdx::new(1),
		slot: SlotIdx::new(7),
		value: left,
	}];
	let right = vec![Install::Value {
		run: RunIdx::new(1),
		slot: SlotIdx::new(7),
		value: right,
	}];
	assert_eq!(installs_hash(&left), installs_hash(&right));
	let mut tried = Tried::default();
	assert!(tried.remember(&left, vec![None, Some(8)]));
	assert!(tried.remember(&right, vec![None, Some(10)]));
	assert_eq!(tried.get(&left), Some(&vec![None, Some(8)]));
	assert_eq!(tried.get(&right), Some(&vec![None, Some(10)]));
}

#[test]
fn a_repeated_execution_keeps_its_repair_continuation() {
	let _generation = crate::util::generation::GenerationGuard::enter();
	let model = crate::syntax::parser::parse_string(
		"solver_mac_then_tuple.vp",
		include_str!("../../../examples/test/solver_mac_then_tuple.vp"),
	)
	.unwrap();
	let km = crate::protocol::sanity::sanity(&model).unwrap();
	let program = crate::engine::program::Program::of(&model, &km);
	let cx = Context::new(&program, &km);
	let ctx = VerifyContext::new(&model, Vec::new(), 1, None, Vec::new(), Vec::new());
	let root = execute(&cx, &Vec::new());
	let mut search = Search::new(&ctx, &cx, root);
	let bob = program.runs.position(|run| run.name == "Bob").unwrap();
	let slot = km
		.slots
		.position(|slot| &*slot.constant.name == "ciphertext")
		.unwrap();
	let plan = vec![Install::Value {
		run: bob,
		slot,
		value: crate::term::value_nil(),
	}];
	let first = search.consider(plan.clone());
	assert!(
		search
			.outcome(first)
			.is_some_and(|outcome| outcome.halts.iter().any(|&(run, _)| run == bob))
	);
	let executed = search.attempts.executed;
	assert_eq!(search.consider(plan), first);
	assert_eq!(search.attempts.executed, executed);
}
