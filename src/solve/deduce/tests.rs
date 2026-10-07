/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::checks::{combine, constraint_sets};
use super::combination::dedupe_counts;
use super::decomposition::DecompositionMemo;
use super::*;
use crate::primitive::*;
use crate::primitive::{Capabilities, Capability};
use crate::protocol::SlotIdx;
use crate::term::Application;
use crate::util::index::Idx;
use crate::util::index::IndexVec;

#[test]
fn deduction_uses_the_bound_of_its_inputs_and_keeps_reducible_inputs() {
	let nil = value_nil();
	let km = make_trace(vec![]);
	let sym = SymbolicState::default();
	let attacker = make_attacker_state(vec![nil.clone()]);
	let input = crate::solve::vars::attacker_var(SlotIdx::new(0));
	let hash = |v| Value::primitive(PRIM_HASH, vec![v], 0);
	let too_deep = hash(hash(nil.clone()));
	let reducible = Value::primitive(
		PRIM_DEC,
		vec![
			too_deep.clone(),
			Value::primitive(PRIM_ENC, vec![too_deep.clone(), nil.clone()], 0),
		],
		0,
	);
	for (value, accepted) in [(too_deep, false), (reducible, true)] {
		let deducer = Deducer::new(&km, &attacker, &sym).with_bound(vec![(input.clone(), 1)]);
		let binding = [(as_var(&input).unwrap(), value)].into_iter().collect();
		assert_eq!(!deducer.solve(&nil, &binding).is_empty(), accepted);
		assert_eq!(deducer.declined_bound(), !accepted);
	}
}

#[test]
fn an_oracle_accepts_a_constructed_goal_outside_the_protocol_basis() {
	let key = make_private("oracle_constructed_seal");
	let signing = make_private("oracle_constructed_signing");
	let message = make_constant("oracle_constructed_message");
	let input = crate::solve::vars::attacker_var(SlotIdx::new(2));
	let cipher = crate::solve::vars::attacker_var(SlotIdx::new(3));
	let sealed = Value::primitive(
		PRIM_ENC,
		vec![
			key.clone(),
			Value::primitive(PRIM_SIGN, vec![signing.clone(), input.clone()], 0),
		],
		0,
	);
	let opened = Value::primitive(PRIM_DEC, vec![key, cipher.clone()], 0);
	let km = make_trace(vec![
		crate::testing::make_wire_slot(&make_constant("oracle_constructed_sealed"), &sealed, 0),
		crate::testing::make_wire_slot(&make_constant("oracle_constructed_opened"), &opened, 1),
	]);
	let sym = SymbolicState {
		terms: IndexVec::from(vec![sealed, opened, input.clone(), cipher.clone()]),
		var_terms: IndexVec::from(vec![None, None, Some(input.clone()), Some(cipher.clone())]),
	};
	let attacker = make_attacker_state(vec![message.clone(), value_nil()]);
	let deducer = Deducer::new(&km, &attacker, &sym);
	let chosen = Value::primitive(PRIM_HASH, vec![message], 0);
	let goal = Value::primitive(PRIM_SIGN, vec![signing, chosen.clone()], 0);
	assert!(
		!sym.terms
			.iter()
			.chain(attacker.known.iter())
			.any(|term| crate::term::subterms(term).any(|t| t.equivalent(&goal, true)))
	);
	let solutions = deducer.solve(&goal, &Substitution::default());
	assert!(solutions.iter().any(|solution| {
		apply(&input, solution).equivalent(&chosen, true)
			&& crate::theory::reduce_once(&apply(&sym.terms[SlotIdx::new(1)], solution))
				.equivalent(&goal, true)
	}));
}

#[test]
fn forgeable_goals_share_only_the_declared_key_primitive_and_phase() {
	let key = make_private("forge_scope_key");
	let other = make_private("forge_scope_other");
	let message = make_constant("forge_scope_message");
	let hidden = make_private("forge_scope_hidden");
	let annotated = Primitive::new(PRIM_SIGN, vec![key.clone(), value_nil()], 0)
		.with(|application| application.capabilities.set(Capability::Forgeable, 2));
	let mut km = make_trace(vec![]);
	km.capabilities
		.insert(&Value::Primitive(Arc::new(annotated)));
	let sym = SymbolicState::default();
	for phase in [1, 2] {
		let mut attacker = make_attacker_state(vec![value_nil(), message.clone()]);
		attacker.current_phase = phase;
		let deducer = Deducer::new(&km, &attacker, &sym);
		for (id, secret, payload, expected) in [
			(PRIM_SIGN, &key, &message, phase == 2),
			(PRIM_SIGN, &other, &message, false),
			(PRIM_SIGN, &key, &hidden, false),
			(PRIM_MAC, &key, &message, false),
		] {
			let goal = Value::primitive(id, vec![secret.clone(), payload.clone()], 0);
			assert_eq!(
				!deducer.solve(&goal, &Substitution::default()).is_empty(),
				expected,
				"{goal} at phase {phase}"
			);
		}
		let variable = crate::solve::vars::attacker_var(SlotIdx::new(0));
		let goal = Value::primitive(PRIM_SIGN, vec![variable.clone(), message.clone()], 0);
		let solutions = deducer.solve(&goal, &Substitution::default());
		assert!(
			solutions
				.iter()
				.any(|s| apply(&variable, s).equivalent(&value_nil(), true))
		);
		assert_eq!(
			solutions
				.iter()
				.any(|s| apply(&variable, s).equivalent(&key, true)),
			phase == 2,
		);
	}
}

#[test]
fn solving_a_reducible_goal_requires_its_result_to_be_derivable() {
	let key = make_private("reduct_goal_key");
	let hidden = make_private("reduct_goal_hidden");
	let public = Value::primitive(PRIM_PUBKEY, vec![key.clone()], 0);
	let sealed = Value::primitive(PRIM_PKE_ENC, vec![public.clone(), hidden.clone()], 0);
	let km = make_trace(vec![]);
	let sym = SymbolicState::default();
	let attacker = make_attacker_state(vec![value_nil(), public, sealed]);
	let variable = crate::solve::vars::attacker_var(SlotIdx::new(0));
	let goal = Value::primitive(PRIM_PKE_DEC, vec![key, variable.clone()], 0);
	let deducer = Deducer::new(&km, &attacker, &sym);
	let bound = Substitution::from_iter([(
		as_var(&variable).unwrap(),
		Value::primitive(
			PRIM_PKE_ENC,
			vec![attacker.known[1].clone(), value_nil()],
			0,
		),
	)]);
	let before = deducer.variables.borrow().clone();
	let solved = deducer.solve(&goal, &bound);
	assert_eq!(solved.len(), 1);
	assert!(same_substitution(&solved[0], &bound));
	assert_eq!(deducer.variables.borrow().clone(), before);
	let solutions = deducer.solve(&goal, &Substitution::default());
	assert!(!solutions.is_empty());
	for solution in solutions {
		let sent = crate::solve::vars::ground_free(&apply(&variable, &solution));
		assert!(crate::theory::obtainable(
			&sent,
			&km.capabilities,
			&attacker
		));
		let reduced =
			crate::theory::reduce_once(&crate::solve::vars::ground_free(&apply(&goal, &solution)));
		assert!(crate::theory::obtainable(
			&reduced,
			&km.capabilities,
			&attacker
		));
		assert!(!reduced.equivalent(&hidden, true));
	}
}

#[test]
fn combining_constraint_groups_keeps_alignments_needed_by_later_groups() {
	let x = crate::solve::vars::free_var(0);
	let y = crate::solve::vars::free_var(1);
	let a = make_private("combine_later_a");
	let b = make_private("combine_later_b");
	let key = |a, b| {
		Value::primitive(
			PRIM_DH_KEX,
			vec![Value::primitive(PRIM_PUBKEY, vec![a], 0), b],
			0,
		)
	};
	let slot = crate::solve::vars::attacker_var_id(SlotIdx::new(0));
	let left = Substitution::from_iter([(slot.clone(), key(x.clone(), y.clone()))]);
	let right = Substitution::from_iter([(slot.clone(), key(a.clone(), b.clone()))]);
	let merged = combine(&[left], &[right]);
	assert_eq!(merged.len(), 2);
	for (wanted, other) in [(&a, &b), (&b, &a)] {
		let later = Substitution::from_iter([(as_var(&x).unwrap(), wanted.clone())]);
		let found = combine(&merged, &[later]);
		assert_eq!(found.len(), 1);
		assert!(apply(&x, &found[0]).equivalent(wanted, true));
		assert!(apply(&y, &found[0]).equivalent(other, true));
	}
}

#[test]
fn rewrite_inversion_keeps_bindings_in_the_reduct() {
	let key = make_private("invert_reduct_key");
	let message = make_constant("invert_reduct_message");
	let input = crate::solve::vars::attacker_var(SlotIdx::new(0));
	let signature = crate::solve::vars::attacker_var(SlotIdx::new(1));
	let term = Value::primitive(PRIM_UNBLIND, vec![value_nil(), input.clone(), signature], 0);
	let target = Value::primitive(PRIM_SIGN, vec![key, message.clone()], 0);
	let km = make_trace(vec![]);
	let sym = SymbolicState::default();
	let attacker = make_attacker_state(vec![]);
	let deducer = Deducer::new(&km, &attacker, &sym);
	let found = deducer.invert(&term, &target, &Substitution::default());
	assert!(!found.is_empty());
	for solution in found {
		assert!(solution.keys().all(crate::solve::vars::is_slot_var_id));
		assert!(apply(&input, &solution).equivalent(&message, true));
		assert!(crate::theory::reduce_once(&apply(&term, &solution)).equivalent(&target, true));
	}
}

#[test]
fn rewrite_inversion_retains_commutative_alternatives_and_incoming_bindings() {
	let a = make_constant("invert_alternatives_a");
	let b = make_constant("invert_alternatives_b");
	let key = make_private("invert_alternatives_key");
	let x = crate::solve::vars::attacker_var(SlotIdx::new(0));
	let y = crate::solve::vars::attacker_var(SlotIdx::new(1));
	let sig = crate::solve::vars::attacker_var(SlotIdx::new(2));
	let dh = |a, b| {
		Value::primitive(
			PRIM_DH_KEX,
			vec![Value::primitive(PRIM_PUBKEY, vec![a], 0), b],
			0,
		)
	};
	let term = Value::primitive(
		PRIM_UNBLIND,
		vec![value_nil(), dh(x.clone(), y.clone()), sig],
		0,
	);
	let target = Value::primitive(PRIM_SIGN, vec![key, dh(a.clone(), b.clone())], 0);
	let km = make_trace(vec![]);
	let sym = SymbolicState::default();
	let attacker = make_attacker_state(vec![]);
	let deducer = Deducer::new(&km, &attacker, &sym);
	let all = deducer.invert(&term, &target, &Substitution::default());
	assert_eq!(all.len(), 2);
	for (first, second) in [(a.clone(), b.clone()), (b, a)] {
		assert!(all.iter().any(
			|s| apply(&x, s).equivalent(&first, true) && apply(&y, s).equivalent(&second, true)
		));
		let incoming = Substitution::from_iter([(as_var(&x).unwrap(), first.clone())]);
		let constrained = deducer.invert(&term, &target, &incoming);
		assert_eq!(constrained.len(), 1);
		assert!(apply(&x, &constrained[0]).equivalent(&first, true));
		assert!(apply(&y, &constrained[0]).equivalent(&second, true));
		assert!(
			crate::theory::reduce_once(&apply(&term, &constrained[0])).equivalent(&target, true)
		);
	}
}

#[test]
fn lanes_share_inputs_without_sharing_search_or_replay_restrictions() {
	let key = make_private("lane_inputs_key");
	let message = make_private("lane_inputs_message");
	let held = Value::primitive(PRIM_ENC, vec![key.clone(), message.clone()], 0);
	let attacker = make_attacker_state(vec![held]);
	let km = make_trace(vec![]);
	let sym = SymbolicState::default();
	let original = Deducer::new(&km, &attacker, &sym);
	let [restricted, sibling]: [Deducer; 2] = original.lanes(2).try_into().ok().unwrap();
	assert!(Arc::ptr_eq(&original.shared, &restricted.shared));
	assert!(Arc::ptr_eq(&original.shared, &sibling.shared));
	let mut variables = IdSet::default();
	for deducer in [&restricted, &original, &sibling] {
		let variable = deducer.fresh_var();
		assert!(variables.insert(as_var(&variable).unwrap()));
		assert!(deducer.memo.borrow().is_empty());
		let goal = Value::primitive(PRIM_ENC, vec![key.clone(), variable.clone()], 0);
		let solutions = deducer.solve(&goal, &Substitution::default());
		assert_eq!(solutions.len(), 1);
		for solution in solutions {
			assert!(apply(&variable, &solution).equivalent(&message, true));
		}
	}
}

#[test]
fn rewrite_matching_keeps_the_alignment_required_by_the_nonce() {
	let a = make_private("rewrite_match_a");
	let b = make_private("rewrite_match_b");
	let secret = make_private("rewrite_match_secret");
	let x = crate::solve::vars::attacker_var(SlotIdx::new(0));
	let y = crate::solve::vars::attacker_var(SlotIdx::new(1));
	let dh = |a: Value, b| {
		Value::primitive(
			PRIM_DH_KEX,
			vec![Value::primitive(PRIM_PUBKEY, vec![a], 0), b],
			0,
		)
	};
	let hash = |v| Value::primitive(PRIM_HASH, vec![v], 0);
	let encrypted = Value::primitive(
		PRIM_AEAD_ENC,
		vec![
			dh(x.clone(), y.clone()),
			hash(x.clone()),
			secret.clone(),
			value_nil(),
		],
		0,
	);
	let wire = Value::primitive(
		PRIM_AEAD_DEC,
		vec![
			dh(a.clone(), b.clone()),
			hash(b.clone()),
			encrypted,
			value_nil(),
		],
		0,
	);
	let km = make_trace(vec![]);
	let sym = SymbolicState {
		terms: IndexVec::from(vec![wire.clone()]),
		..SymbolicState::default()
	};
	let attacker = make_attacker_state(vec![a.clone(), b.clone()]);
	let deducer = Deducer::new(&km, &attacker, &sym);
	let mut found = Vec::new();
	let p = wire.as_primitive().unwrap();
	let rule = rewrite_rule(p.id).unwrap();
	deducer.solve_by_rewrite_match(p, rule, &secret, &Substitution::default(), &mut found);
	assert_eq!(found.len(), 1);
	assert!(apply(&x, &found[0]).equivalent(&b, true));
	assert!(apply(&y, &found[0]).equivalent(&a, true));
	assert!(crate::theory::reduce_once(&apply(&wire, &found[0])).equivalent(&secret, true));
}

#[test]
fn weak_decomposition_respects_capabilities_and_their_phase() {
	let secret = make_private("weak_route_secret");
	let message = make_constant("weak_route_message");
	let variable = crate::solve::vars::attacker_var(SlotIdx::new(0));
	let goal = Value::primitive(PRIM_MAC, vec![secret.clone(), message.clone()], 0);
	for annotated in [false, true] {
		let p = Primitive::new(
			PRIM_HASH,
			vec![Value::primitive(
				PRIM_MAC,
				vec![secret.clone(), variable.clone()],
				0,
			)],
			0,
		);
		let p = if annotated {
			p.with(|application| application.capabilities.set(Capability::Weak, 1))
		} else {
			p
		};
		let wire = Value::Primitive(Arc::new(p));
		let mut km = make_trace(vec![]);
		let declared = apply(
			&wire,
			&Substitution::from_iter([(as_var(&variable).unwrap(), message.clone())]),
		);
		km.capabilities.insert(&declared);
		let sym = SymbolicState {
			terms: IndexVec::from(vec![wire.clone()]),
			..SymbolicState::default()
		};
		for phase in [0, 1, 2] {
			let mut attacker = make_attacker_state(vec![message.clone()]);
			attacker.current_phase = phase;
			let deducer = Deducer::new(&km, &attacker, &sym);
			let found = deducer.solve_decomposition_from(
				&wire,
				&goal,
				&Substitution::default(),
				&mut DecompositionMemo::default(),
			);
			assert_eq!(found.len(), usize::from(annotated && phase >= 1));
			let other = Value::primitive(PRIM_MAC, vec![secret.clone(), value_nil()], 0);
			assert!(
				deducer
					.solve_decomposition_from(
						&wire,
						&other,
						&Substitution::default(),
						&mut DecompositionMemo::default(),
					)
					.is_empty()
			);
			for solution in found {
				assert!(apply(&variable, &solution).equivalent(&message, true));
			}
		}
	}
}

#[test]
fn reuse_matching_keeps_the_alignment_required_by_the_nonce() {
	let a = make_private("reuse_match_a");
	let b = make_private("reuse_match_b");
	let x = crate::solve::vars::free_var(10000);
	let y = crate::solve::vars::free_var(10001);
	let dh = |a: Value, b| {
		Value::primitive(
			PRIM_DH_KEX,
			vec![Value::primitive(PRIM_PUBKEY, vec![a], 0), b],
			0,
		)
	};
	let hash = |v| Value::primitive(PRIM_HASH, vec![v], 0);
	let cipher = |key: Value, nonce: Value, message| {
		Value::primitive(PRIM_AEAD_ENC, vec![key, nonce, message, value_nil()], 0)
	};
	let first = cipher(dh(a.clone(), b.clone()), hash(b.clone()), value_nil());
	let second = cipher(dh(a.clone(), b.clone()), hash(b.clone()), hash(value_nil()));
	let mut attacker = make_attacker_state(vec![value_nil(), first.clone(), second.clone()]);
	attacker.reused = Arc::new(vec![[first, second]]);
	let km = make_trace(vec![]);
	let sym = SymbolicState::default();
	let deducer = Deducer::new(&km, &attacker, &sym);
	let target = cipher(
		dh(x.clone(), y.clone()),
		hash(x.clone()),
		hash(hash(value_nil())),
	);
	let mut found = Vec::new();
	deducer.solve_by_reuse(
		target.as_primitive().unwrap(),
		&Substitution::default(),
		&mut found,
	);
	assert_eq!(found.len(), 1);
	assert!(apply(&x, &found[0]).equivalent(&b, true));
	assert!(apply(&y, &found[0]).equivalent(&a, true));
	assert!(attacker.knows(&apply(&target, &found[0])).is_none());
	assert!(crate::theory::obtainable(
		&apply(&target, &found[0]),
		&km.capabilities,
		&attacker
	));
}

#[test]
fn malleability_matching_keeps_the_constructible_alignment() {
	let a = make_private("malleable_match_a");
	let b = make_private("malleable_match_b");
	let x = crate::solve::vars::free_var(10000);
	let y = crate::solve::vars::free_var(10001);
	let dh = |a: Value, b| {
		Value::primitive(
			PRIM_DH_KEX,
			vec![Value::primitive(PRIM_PUBKEY, vec![a], 0), b],
			0,
		)
	};
	let held = Primitive::new(PRIM_ENC, vec![dh(a.clone(), b.clone()), value_nil()], 0)
		.with(|application| application.capabilities.set(Capability::Malleable, 0));
	let held = Value::Primitive(Arc::new(held));
	let mut km = make_trace(vec![]);
	km.capabilities.insert(&held);
	let attacker = make_attacker_state(vec![value_nil(), b.clone(), held]);
	let sym = SymbolicState::default();
	let deducer = Deducer::new(&km, &attacker, &sym);
	let target = Value::primitive(PRIM_ENC, vec![dh(x.clone(), y.clone()), x.clone()], 0);
	let mut found = Vec::new();
	deducer.solve_by_malleability(
		target.as_primitive().unwrap(),
		&Substitution::default(),
		&mut found,
	);
	assert_eq!(found.len(), 1);
	assert!(apply(&x, &found[0]).equivalent(&b, true));
	assert!(apply(&y, &found[0]).equivalent(&a, true));
	assert!(attacker.knows(&apply(&target, &found[0])).is_none());
	assert!(crate::theory::obtainable(
		&apply(&target, &found[0]),
		&km.capabilities,
		&attacker
	));
}

#[test]
fn threshold_search_constructs_a_missing_partial_with_a_committed_nonce() {
	let key = make_private("threshold_bound_key");
	let message = make_private("threshold_bound_message");
	let honest_nonce = make_private("threshold_bound_honest_nonce");
	let owned_nonce = make_private("threshold_bound_owned_nonce");
	let commitments = Value::primitive(
		PRIM_CONCAT,
		vec![
			Value::primitive(PRIM_PUBKEY, vec![honest_nonce.clone()], 0),
			Value::primitive(PRIM_PUBKEY, vec![owned_nonce.clone()], 0),
		],
		0,
	);
	let split = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![key.clone()], 0)
		.with(|application| application.threshold = 2);
	let held = Value::primitive(
		PRIM_THRESHOLD_SIGN,
		vec![
			Value::Primitive(Arc::new(split.with_output(2))),
			honest_nonce,
			commitments.clone(),
			message.clone(),
		],
		0,
	);
	let attacker = make_attacker_state(vec![
		held,
		Value::Primitive(Arc::new(split)),
		owned_nonce,
		commitments,
		message.clone(),
	]);
	let km = make_trace(vec![]);
	let sym = SymbolicState::default();
	let deducer = Deducer::new(&km, &attacker, &sym);
	let signature = Primitive::new(PRIM_SIGN, vec![key, message], 0);
	let mut found = Vec::new();
	deducer.solve_by_combination(&signature, &Substitution::default(), &mut found);
	assert!(!found.is_empty());
	assert!(crate::theory::obtainable(
		&Value::Primitive(Arc::new(signature)),
		&km.capabilities,
		&attacker
	));
}

#[test]
fn threshold_search_retains_key_alignments_until_the_message_matches() {
	let a = make_private("threshold_alignment_a");
	let b = make_private("threshold_alignment_b");
	let x = crate::solve::vars::attacker_var(SlotIdx::new(0));
	let y = crate::solve::vars::attacker_var(SlotIdx::new(1));
	let dh = |a: Value, b| {
		Value::primitive(
			PRIM_DH_KEX,
			vec![Value::primitive(PRIM_PUBKEY, vec![a], 0), b],
			0,
		)
	};
	let split = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![dh(a.clone(), b.clone())], 0)
		.with(|application| application.threshold = 2);
	let partials = (0..2)
		.map(|output| {
			Value::primitive(
				PRIM_THRESHOLD_SIGN,
				vec![
					Value::Primitive(Arc::new(split.with_output(output))),
					value_nil(),
					Value::primitive(PRIM_PUBKEY, vec![value_nil()], 0),
					b.clone(),
				],
				0,
			)
		})
		.collect();
	let attacker = make_attacker_state(partials);
	let km = make_trace(vec![]);
	let sym = SymbolicState::default();
	let deducer = Deducer::new(&km, &attacker, &sym);
	let target = Primitive::new(PRIM_SIGN, vec![dh(x.clone(), y.clone()), x.clone()], 0);
	let mut found = Vec::new();
	deducer.solve_by_combination(&target, &Substitution::default(), &mut found);
	assert!(
		found
			.iter()
			.any(|s| apply(&x, s).equivalent(&b, true) && apply(&y, s).equivalent(&a, true))
	);
}

#[test]
fn threshold_search_keeps_one_state_per_distinct_choice() {
	let key = make_private("subset_search_key");
	let message = make_private("subset_search_message");
	let wanted = crate::solve::vars::free_var(10000);
	let split = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![key.clone()], 0)
		.with(|application| application.threshold = 8);
	let commitments = Value::primitive(
		PRIM_CONCAT,
		(0..16)
			.map(|output| {
				Value::primitive(
					PRIM_PUBKEY,
					vec![make_private(&format!("subset_search_nonce_{output}"))],
					0,
				)
			})
			.collect(),
		0,
	);
	let partials: Vec<_> = (0..16)
		.map(|output| {
			Value::primitive(
				PRIM_THRESHOLD_SIGN,
				vec![
					Value::Primitive(Arc::new(split.with_output(output))),
					make_private(&format!("subset_search_nonce_{output}")),
					commitments.clone(),
					message.clone(),
				],
				0,
			)
		})
		.collect();
	let attacker = make_attacker_state(partials);
	let km = make_trace(vec![]);
	let sym = SymbolicState::default();
	let deducer = Deducer::new(&km, &attacker, &sym);
	let target = Primitive::new(PRIM_SIGN, vec![key, wanted.clone()], 0);
	let mut found = Vec::new();
	deducer.solve_by_combination(&target, &Substitution::default(), &mut found);
	assert_eq!(found.len(), 1);
	assert!(apply(&wanted, &found[0]).equivalent(&message, true));
	let regrouped = attacker
		.known
		.iter()
		.enumerate()
		.map(|(i, value)| {
			let Value::Primitive(p) = value else {
				unreachable!();
			};
			let mut arguments = p.arguments.clone();
			arguments[2] = Value::primitive(
				PRIM_CONCAT,
				vec![
					commitments.clone(),
					make_constant(&format!("subset_commitments_{}", i % 4)),
				],
				0,
			);
			Value::Primitive(Arc::new(p.with_arguments(arguments)))
		})
		.collect();
	let attacker = make_attacker_state(regrouped);
	let deducer = Deducer::new(&km, &attacker, &sym);
	let mut found = Vec::new();
	deducer.solve_by_combination(&target, &Substitution::default(), &mut found);
	assert!(
		found.is_empty(),
		"different commitments must not pool their counts"
	);
}

#[test]
fn a_lane_issues_variables_without_a_ceiling() {
	let key = make_private("unbounded_lane_key");
	let message = make_private("unbounded_lane_message");
	let held = Value::primitive(PRIM_ENC, vec![key.clone(), message.clone()], 0);
	let attacker = make_attacker_state(vec![held]);
	let km = make_trace(vec![]);
	let sym = SymbolicState::default();
	let deducer = Deducer::new(&km, &attacker, &sym).in_test_lane(3);
	let mut seen = IdSet::default();
	for _ in 0..100_000 {
		let id = as_var(&deducer.fresh_var()).expect("a variable");
		assert!(seen.insert(id), "every issued variable is distinct");
	}
	let goal = Value::primitive(PRIM_ENC, vec![key, deducer.fresh_var()], 0);
	assert!(
		!deducer.solve(&goal, &Substitution::default()).is_empty(),
		"a lane that has issued many variables keeps solving rather than giving up"
	);
}

#[test]
fn threshold_frontier_retains_distinct_counts_and_bindings_in_order() {
	let id = crate::solve::vars::attacker_var_id(SlotIdx::new(0));
	let first = Substitution::from_iter([(id.clone(), make_private("count_first"))]);
	let second = Substitution::from_iter([(id.clone(), make_private("count_second"))]);
	let reduced = dedupe_counts(vec![
		(first.clone(), 1),
		(second.clone(), 2),
		(first.clone(), 3),
		(first.clone(), 1),
	]);
	assert_eq!(reduced.len(), 3);
	assert!(same_substitution(&reduced[0].0, &first));
	assert_eq!(reduced[0].1, 1);
	assert!(same_substitution(&reduced[1].0, &second));
	assert_eq!(reduced[1].1, 2);
	assert!(same_substitution(&reduced[2].0, &first));
	assert_eq!(reduced[2].1, 3);
}

#[test]
fn forgeable_shape_collection_visits_a_shared_check_once() {
	let variable = crate::solve::vars::attacker_var(SlotIdx::new(0));
	let key = make_private("dag_shape_key");
	let check = Value::primitive(PRIM_DEC, vec![key.clone(), variable.clone()], 0);
	let mut term = check.clone();
	for _ in 0..40 {
		term = Value::primitive(PRIM_HASH, vec![term.clone(), term.clone(), term], 0);
	}
	let sym = SymbolicState {
		terms: IndexVec::from(vec![term.clone(), check, term]),
		var_terms: IndexVec::from(vec![Some(variable.clone())]),
	};
	let km = make_trace(vec![]);
	let attacker = make_attacker_state(vec![]);
	let deducer = Deducer::new(&km, &attacker, &sym);
	let shapes = deducer.forgeable_shapes(&sym, &as_var(&variable).unwrap());
	assert_eq!(shapes.len(), 1);
	let Value::Primitive(shape) = &shapes[0] else {
		panic!("a decryption requires an encryption shape");
	};
	assert_eq!(shape.id, PRIM_ENC);
	assert!(shape.arguments[0].equivalent(&key, true));
	assert!(contains_var(&shape.arguments[1]));
}

#[test]
fn constraint_sets_keep_emissions_before_later_checks() {
	let source = "attacker[active]
principal Sender[
knows public left, right
payload = CONCAT(left, right)
]
Sender -> Bob: payload
principal Bob[
first, second = SPLIT(payload)?
before = ASSERT(first, left)?
early = HASH(first)
]
Bob -> Sender: early
principal Bob[
after = ASSERT(second, right)?
late = HASH(second)
]
Bob -> Sender: late
queries[
authentication? Sender -> Bob: payload
]
";
	let model = crate::syntax::parser::parse_string("constraint-prefix.vp", source).unwrap();
	let km = crate::protocol::sanity::sanity(&model).unwrap();
	let bob = km.principal_ids[km.principals.iter().position(|p| p == "Bob").unwrap()];
	let attacker = make_attacker_state(vec![]);
	let controllable = crate::solve::control::Controllable::of(&km, bob, &attacker);
	let sym = crate::solve::symbolic::build(&controllable, &km, bob, &attacker);
	let groups = constraint_sets(&model.queries, &km, &sym);
	let slot = |name: &str| {
		km.slots
			.position(|slot| &*slot.constant.name == name)
			.unwrap()
	};
	let before = slot("before");
	let after = slot("after");
	assert!(
		groups
			.iter()
			.any(|group| group.contains(&before) && !group.contains(&after))
	);
	assert!(
		groups
			.iter()
			.any(|group| group.contains(&before) && group.contains(&after))
	);
}

#[test]
fn nested_reuse_needs_a_held_matching_vetted_pair() {
	let wrapping = make_constant("nested_reuse_wrapping");
	let key = make_private("nested_reuse_key");
	let nonce = make_private("nested_reuse_nonce");
	let other_nonce = make_private("nested_reuse_other_nonce");
	let secret = make_private("nested_reuse_secret");
	let message = make_constant("nested_reuse_message");
	let variable = crate::solve::vars::attacker_var(SlotIdx::new(0));
	let goal = Value::primitive(PRIM_MAC, vec![secret.clone(), message.clone()], 0);
	let seal = |nonce: Value, plaintext: Value| {
		Value::primitive(
			PRIM_AEAD_ENC,
			vec![key.clone(), nonce, plaintext, value_nil()],
			0,
		)
	};
	let pair = [
		seal(nonce.clone(), make_private("nested_reuse_first")),
		seal(nonce.clone(), make_private("nested_reuse_second")),
	];
	let plaintext = Value::primitive(PRIM_MAC, vec![secret, variable.clone()], 0);
	let km = make_trace(vec![]);
	for case in 0..4 {
		let inner_nonce = if case == 3 {
			other_nonce.clone()
		} else {
			nonce.clone()
		};
		let wire = Value::primitive(
			PRIM_ENC,
			vec![wrapping.clone(), seal(inner_nonce, plaintext.clone())],
			0,
		);
		let sym = SymbolicState {
			terms: IndexVec::from(vec![wire.clone()]),
			..SymbolicState::default()
		};
		let mut held = vec![wrapping.clone(), message.clone(), pair[0].clone()];
		if case != 2 {
			held.push(pair[1].clone());
		}
		let mut attacker = make_attacker_state(held);
		if case != 1 {
			attacker.reused = Arc::new(vec![pair.clone()]);
		}
		let deducer = Deducer::new(&km, &attacker, &sym);
		let solutions = deducer.solve_decomposition_from(
			&wire,
			&goal,
			&Substitution::default(),
			&mut DecompositionMemo::default(),
		);
		assert_eq!(solutions.len(), usize::from(case == 0));
		for solution in solutions {
			assert!(apply(&variable, &solution).equivalent(&message, true));
		}
	}
}

#[test]
fn nested_decomposition_requires_every_opening_input() {
	let outer = make_private("nested_open_outer");
	let nonce = make_private("nested_open_nonce");
	let inner = make_private("nested_open_inner");
	let secret = make_private("nested_open_secret");
	let message = make_constant("nested_open_message");
	let variable = crate::solve::vars::attacker_var(SlotIdx::new(0));
	let goal = Value::primitive(PRIM_MAC, vec![secret.clone(), message.clone()], 0);
	let plaintext = Value::primitive(PRIM_MAC, vec![secret, variable.clone()], 0);
	let encrypted = Value::primitive(PRIM_ENC, vec![inner.clone(), plaintext], 0);
	let wire = Value::primitive(
		PRIM_AEAD_ENC,
		vec![outer.clone(), nonce.clone(), encrypted, value_nil()],
		0,
	);
	let km = make_trace(vec![]);
	let sym = SymbolicState {
		terms: IndexVec::from(vec![wire.clone()]),
		..SymbolicState::default()
	};
	for mask in 0..8 {
		let mut held = vec![message.clone()];
		for (at, input) in [&outer, &nonce, &inner].into_iter().enumerate() {
			if mask & (1 << at) != 0 {
				held.push(input.clone());
			}
		}
		let attacker = make_attacker_state(held);
		let deducer = Deducer::new(&km, &attacker, &sym);
		let solutions = deducer.solve_decomposition_from(
			&wire,
			&goal,
			&Substitution::default(),
			&mut DecompositionMemo::default(),
		);
		assert_eq!(solutions.len(), usize::from(mask == 7));
		for solution in solutions {
			assert!(apply(&variable, &solution).equivalent(&message, true));
		}
	}
}

#[test]
fn nested_decomposition_visits_shared_carriers_once() {
	let key = make_constant("nested_dag_key");
	let secret = make_private("nested_dag_secret");
	let message = make_constant("nested_dag_message");
	let variable = crate::solve::vars::attacker_var(SlotIdx::new(0));
	let goal = Value::primitive(PRIM_MAC, vec![secret.clone(), message.clone()], 0);
	let plaintext = Value::primitive(PRIM_MAC, vec![secret, variable.clone()], 0);
	let mut wire = Value::primitive(PRIM_ENC, vec![key.clone(), plaintext], 0);
	for _ in 0..40 {
		wire = Value::primitive(PRIM_CONCAT, vec![wire.clone(), wire.clone(), wire], 0);
	}
	let km = make_trace(vec![]);
	let sym = SymbolicState {
		terms: IndexVec::from(vec![wire.clone()]),
		..SymbolicState::default()
	};
	let attacker = make_attacker_state(vec![key, message.clone()]);
	let deducer = Deducer::new(&km, &attacker, &sym);
	let mut memo = DecompositionMemo::default();
	let solutions =
		deducer.solve_decomposition_from(&wire, &goal, &Substitution::default(), &mut memo);
	assert_eq!(
		memo.len(),
		42,
		"the forty carriers and the ciphertext are each visited once, and the \
		 plaintext they all share is the forty-second: a term whose rule offers no \
		 route is recorded too, so the shaping attempt behind it is made once \
		 rather than at every carrier that reaches it"
	);
	assert_eq!(solutions.len(), 1);
	assert!(apply(&variable, &solutions[0]).equivalent(&message, true));
}

#[test]
fn deduction_routes_require_the_declared_encapsulation_projection() {
	let key = make_private("route_projection_key");
	let public = Value::primitive(PRIM_PUBKEY, vec![key.clone()], 0);
	let variable = crate::solve::vars::attacker_var(SlotIdx::new(0));
	let randomness = make_constant("route_projection_randomness");
	let secret = Value::primitive(PRIM_KEM_ENCAP, vec![public.clone(), randomness.clone()], 0);
	let name = make_constant("route_projection_wire");
	let attacker = make_attacker_state(vec![key.clone(), randomness.clone()]);
	for output in [0, 1] {
		let wire = Value::primitive(
			PRIM_KEM_ENCAP,
			vec![public.clone(), variable.clone()],
			output,
		);
		let km = make_trace(vec![make_wire_slot(&name, &wire, 1)]);
		let sym = SymbolicState {
			terms: IndexVec::from(vec![wire.clone()]),
			..SymbolicState::default()
		};
		let deducer = Deducer::new(&km, &attacker, &sym);
		let mut decomposed = Vec::new();
		deducer.solve_by_decomposition(&randomness, &Substitution::default(), &mut decomposed);
		let check = Value::primitive(PRIM_KEM_DECAP, vec![key.clone(), wire], 0);
		let mut rewritten = Vec::new();
		let p = check.as_primitive().unwrap();
		let rule = rewrite_rule(p.id).unwrap();
		deducer.solve_by_rewrite_match(p, rule, &secret, &Substitution::default(), &mut rewritten);
		for solutions in [decomposed, rewritten] {
			assert_eq!(solutions.len(), output);
			for solution in solutions {
				assert!(apply(&variable, &solution).equivalent(&randomness, true));
			}
		}
	}
}

#[test]
fn a_cached_goal_keeps_the_bindings_its_oracle_was_solved_under() {
	let key = make_private("memo_oracle_key");
	let message = make_constant("memo_oracle_message");
	let other = make_constant("memo_oracle_other");
	let variable = crate::solve::vars::attacker_var(SlotIdx::new(0));
	let wire = Value::primitive(PRIM_MAC, vec![key.clone(), variable.clone()], 0);
	let goal = Value::primitive(PRIM_MAC, vec![key, message.clone()], 0);
	let name = make_constant("memo_oracle_wire");
	let km = make_trace(vec![make_wire_slot(&name, &wire, 1)]);
	let attacker = make_attacker_state(vec![message.clone(), other.clone()]);
	let sym = SymbolicState {
		terms: IndexVec::from(vec![wire]),
		..SymbolicState::default()
	};
	let deducer = Deducer::new(&km, &attacker, &sym);
	let blocked = Substitution::from_iter([(as_var(&variable).unwrap(), other)]);
	assert!(deducer.solve(&goal, &blocked).is_empty());
	let empty = Substitution::default();
	let fresh = Deducer::new(&km, &attacker, &sym).solve(&goal, &empty);
	assert!(
		fresh
			.iter()
			.any(|s| apply(&variable, s).equivalent(&message, true))
	);
	let cached = deducer.solve(&goal, &empty);
	assert!(
		cached
			.iter()
			.any(|s| apply(&variable, s).equivalent(&message, true))
	);
}

#[test]
fn fresh_variables_are_disjoint_between_lanes_and_batches() {
	let km = make_trace(vec![]);
	let attacker = make_attacker_state(vec![]);
	let sym = SymbolicState::default();
	let deducer = Deducer::new(&km, &attacker, &sym);
	let mut seen = IdSet::default();
	for _ in 0..2 {
		for worker in deducer.lanes(7) {
			for _ in 0..1_000 {
				assert!(seen.insert(as_var(&worker.fresh_var()).unwrap()));
				assert!(seen.insert(as_var(&deducer.fresh_var()).unwrap()));
			}
		}
	}
}

use crate::testing::*;

fn unblind_over(k: &Value, m: &Value, sig: &Value) -> Primitive {
	Primitive::from(Application {
		id: PRIM_UNBLIND,
		arguments: vec![k.clone(), m.clone(), sig.clone()],
		output: 0,
		instance: 0,
		instance_check: false,
		capabilities: Capabilities::default(),
		threshold: 0,
	})
}

#[test]
fn inverting_a_rewrite_solves_for_the_target_rather_than_nesting_it() {
	let k = make_constant("inv_k");
	let m = make_constant("inv_m");
	let sk = make_constant("inv_sk");
	let sig = make_constant("inv_sig");
	let outer = unblind_over(&k, &m, &sig);
	let target = Value::primitive(PRIM_SIGN, vec![sk.clone(), m.clone()], 0);

	let km = make_trace(vec![]);
	let attacker = make_attacker_state(vec![]);
	let sym = SymbolicState::default();
	let deducer = Deducer::new(&km, &attacker, &sym);
	let rule = rewrite_rule(PRIM_UNBLIND).expect("UNBLIND declares a rewrite rule");

	let (shape, _) = deducer
		.rewrite_shapes_yielding(&outer, rule, &target, &Substitution::default())
		.into_iter()
		.next()
		.expect("UNBLIND can be inverted against a signature over its own message");

	let expected = Value::primitive(
		PRIM_SIGN,
		vec![sk, Value::primitive(PRIM_BLIND, vec![k, m], 0)],
		0,
	);
	assert!(
		shape.equivalent(&expected, true),
		"inverting a rewrite must solve `to(shape) = target` for the positions the \
		 rule leaves free, not drop the whole target into one of them. UNBLIND pins \
		 only SIGN's message, so filling SIGN's *key* with the target builds \
		 SIGN(SIGN(..), ..) and every later inversion nests that again — the search \
		 then enumerates signature chains as deep as the term bound allows. \
		 Expected {expected}, got {shape}"
	);

	let Value::Primitive(inner) = &shape else {
		panic!("a rewrite shape is a primitive");
	};
	assert!(
		rule.to.apply(inner).equivalent(&target, true),
		"the shape must actually yield the target it was built for"
	);
}

#[test]
fn inverting_a_rewrite_refuses_a_target_the_rule_cannot_produce() {
	let k = make_constant("inr_k");
	let m = make_constant("inr_m");
	let other = make_constant("inr_other");
	let sig = make_constant("inr_sig");
	let outer = unblind_over(&k, &m, &sig);
	let target = Value::primitive(PRIM_SIGN, vec![make_constant("inr_sk"), other], 0);

	let km = make_trace(vec![]);
	let attacker = make_attacker_state(vec![]);
	let sym = SymbolicState::default();
	let deducer = Deducer::new(&km, &attacker, &sym);
	let rule = rewrite_rule(PRIM_UNBLIND).expect("UNBLIND declares a rewrite rule");

	assert!(
		deducer
			.rewrite_shapes_yielding(&outer, rule, &target, &Substitution::default())
			.is_empty(),
		"unblinding with blinding factor `inr_k` over message `inr_m` can only yield a \
		 signature over `inr_m`; offering a shape for a signature over something else \
		 proposes a term the rewrite does not produce"
	);
}

#[test]
fn a_share_opened_out_of_a_sealed_tuple_is_shaped_as_the_attackers_key() {
	let seal = make_constant("sealed_share_seal");
	let nonce = make_constant("sealed_share_nonce");
	let secret = make_private("sealed_share_secret");
	let public = Value::primitive(PRIM_PUBKEY, vec![secret.clone()], 0);
	let ciphertext = crate::solve::vars::attacker_var(SlotIdx::new(0));
	let opened = Value::primitive(
		PRIM_AEAD_DEC,
		vec![seal.clone(), nonce.clone(), ciphertext.clone(), value_nil()],
		0,
	);
	let share = Value::primitive(PRIM_SPLIT, vec![opened], 1);
	let free = crate::solve::vars::free_var(0);
	let km = make_trace(vec![]);
	let sym = SymbolicState::default();
	let attacker = make_attacker_state(vec![value_nil(), seal, nonce, public.clone()]);
	let deducer = Deducer::new(&km, &attacker, &sym).in_test_lane(1);
	let own = Value::primitive(PRIM_DH_KEX, vec![public.clone(), value_nil()], 0);
	for wrapped in [share, free] {
		let goal = Value::primitive(PRIM_DH_KEX, vec![wrapped.clone(), secret.clone()], 0);
		let solutions = deducer.solve(&goal, &Substitution::default());
		assert!(
			solutions.iter().any(|s| {
				let ground = crate::solve::vars::ground_free(&apply(&goal, s));
				crate::theory::reduce_once(&ground).equivalent(&own, true)
			}),
			"the attacker cannot supply `sealed_share_secret`, but it holds its public \
			 key, so DH_KEX({wrapped}, sealed_share_secret) is obtainable once {wrapped} \
			 becomes PUBKEY of something the attacker picks: the goal commutes into \
			 DH_KEX(PUBKEY(sealed_share_secret), nil). Only a share already written as \
			 PUBKEY(..) was ever commuted, so a share projected out of a tuple the \
			 attacker can seal, or left free by a tuple shape, never was: the key \
			 substitution behind every Diffie-Hellman man-in-the-middle was missed \
			 whenever the share travelled inside a sealed hello. Got {solutions:?}"
		);
	}
}
