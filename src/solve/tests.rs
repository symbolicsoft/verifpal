/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::free::{aligned_free_positions, collect_free_positions, fill_free_positions};
use super::vars::Substitution;
use super::*;
use crate::primitive::{
	PRIM_CONCAT, PRIM_HASH, PRIM_PUBKEY, attacker_public_key, value_is_key_derivation,
};
use crate::protocol::SlotIdx;
use crate::term::value_nil;
use crate::testing::{make_attacker_state, make_constant};
use crate::util::index::Idx;
use crate::util::index::IndexVec;
use vars::free_var;

#[test]
fn free_position_walks_visit_shared_term_pairs_once() {
	let mut proposed = free_var(0);
	let key = Value::primitive(PRIM_PUBKEY, vec![make_constant("free_dag_key")], 0);
	let mut honest = key.clone();
	for _ in 0..40 {
		proposed = Value::primitive(
			PRIM_HASH,
			vec![proposed.clone(), proposed.clone(), proposed],
			0,
		);
		honest = Value::primitive(PRIM_HASH, vec![honest.clone(), honest.clone(), honest], 0);
	}
	let mut positions = Vec::new();
	collect_free_positions(&proposed, &honest, &Substitution::default(), &mut positions);
	assert_eq!(positions.len(), 3);
	assert!(
		positions
			.iter()
			.all(|(id, value)| *id == free_var_id(0) && value.equivalent(&key, true))
	);
	let filled = keyed_positions(&proposed, &honest);
	assert_eq!(filled.len(), 1);
	assert!(filled[&free_var_id(0)].equivalent(&attacker_public_key(), true));
	assert_eq!(aligned_free_positions(&honest, &honest).count(), 0);
}

#[test]
fn a_shared_proposal_keeps_distinct_honest_contexts() {
	let proposal = Value::primitive(PRIM_HASH, vec![free_var(0)], 0);
	let plain = make_constant("free_context_plain");
	let public = Value::primitive(PRIM_PUBKEY, vec![make_constant("free_context_key")], 0);
	let honest = Value::primitive(
		PRIM_CONCAT,
		vec![
			Value::primitive(PRIM_HASH, vec![plain.clone()], 0),
			Value::primitive(PRIM_HASH, vec![public.clone()], 0),
		],
		0,
	);
	let proposed = Value::primitive(PRIM_CONCAT, vec![proposal.clone(), proposal], 0);
	let positions: Vec<_> = aligned_free_positions(&proposed, &honest).collect();
	assert_eq!(positions.len(), 2);
	assert!(positions[0].1.equivalent(&plain, true));
	assert!(positions[1].1.equivalent(&public, true));
	let filled = keyed_positions(&proposed, &honest);
	assert!(filled[&free_var_id(0)].equivalent(&attacker_public_key(), true));
}

#[test]
fn blocking_slot_collection_visits_shared_checks_once() {
	let x = vars::attacker_var(SlotIdx::new(0));
	let y = vars::attacker_var(SlotIdx::new(1));
	let check = Value::primitive(
		crate::primitive::PRIM_AEAD_DEC,
		vec![x, value_nil(), y, value_nil()],
		0,
	);
	let mut term = check.clone();
	for _ in 0..40 {
		term = Value::primitive(PRIM_HASH, vec![term.clone(), term.clone(), term], 0);
	}
	let sym = SymbolicState {
		terms: IndexVec::from(vec![term.clone(), check, term]),
		..SymbolicState::default()
	};
	assert_eq!(
		slots_blocking_reduction(&sym),
		vec![vec![SlotIdx::new(0), SlotIdx::new(1)]]
	);
}

fn bundle(second: Value) -> Value {
	Value::primitive(PRIM_CONCAT, vec![make_constant("kfp_tag"), second], 0)
}

fn keyed_positions(proposed: &Value, honest: &Value) -> Substitution {
	let mut out = Substitution::default();
	fill_free_positions(
		proposed,
		honest,
		&|honest| value_is_key_derivation(honest).then(attacker_public_key),
		&mut out,
	);
	out
}

fn preserved_positions(proposed: &Value, honest: &Value, held: Vec<Value>) -> Substitution {
	let attacker = make_attacker_state(held);
	let mut out = Substitution::default();
	fill_free_positions(
		proposed,
		honest,
		&|honest| {
			if value_is_key_derivation(honest) {
				return Some(attacker_public_key());
			}
			let held = !honest.equivalent(&value_nil(), true) && attacker.knows(honest).is_some();
			held.then(|| honest.clone())
		},
		&mut out,
	);
	out
}

#[test]
fn a_free_position_beside_a_swapped_key_can_keep_the_honest_value() {
	let nonce = make_constant("kfp_nonce");
	let honest = Value::primitive(
		PRIM_CONCAT,
		vec![
			make_constant("kfp_tag2"),
			Value::primitive(PRIM_PUBKEY, vec![make_constant("kfp_x")], 0),
			nonce.clone(),
		],
		0,
	);
	let proposed = Value::primitive(
		PRIM_CONCAT,
		vec![make_constant("kfp_tag2"), free_var(0), free_var(1)],
		0,
	);
	let out = preserved_positions(&proposed, &honest, vec![nonce.clone()]);
	assert!(
		out[&free_var_id(0)].equivalent(&attacker_public_key(), true),
		"the key position is still the attacker's own"
	);
	assert!(
		out[&free_var_id(1)].equivalent(&nonce, true),
		"a forgery that must preserve one field while replacing its sibling is only \
		 expressible if the honest value the attacker holds is offered at the position \
		 beside the swapped key"
	);
}

#[test]
fn a_free_position_whose_honest_value_the_attacker_lacks_is_left_alone() {
	let secret = make_constant("kfp_secret");
	let honest = bundle(secret);
	assert!(
		preserved_positions(&bundle(free_var(0)), &honest, vec![]).is_empty(),
		"preserving a value the attacker cannot build would propose a term it has no \
		 way to construct, which the validator would reject anyway"
	);
}

#[test]
fn a_free_position_the_protocol_fills_with_a_key_gets_the_attackers_own() {
	let honest = bundle(Value::primitive(
		PRIM_PUBKEY,
		vec![make_constant("kfp_a")],
		0,
	));
	let out = keyed_positions(&bundle(free_var(0)), &honest);
	assert!(
		out[&free_var_id(0)].equivalent(&attacker_public_key(), true),
		"the protocol puts a public key in this position, so the attacker must be \
		 offered its own there and not only nil"
	);
}

#[test]
fn a_free_position_the_protocol_fills_with_a_constant_is_left_alone() {
	let honest = bundle(make_constant("kfp_plain"));
	assert!(
		keyed_positions(&bundle(free_var(0)), &honest).is_empty(),
		"keying a position the protocol fills with a plain value overwrites the tag a \
		 recipient asserts on, which halts it before the attack it is meant to reach"
	);
}

#[test]
fn a_bound_position_is_never_rekeyed() {
	let honest = bundle(Value::primitive(
		PRIM_PUBKEY,
		vec![make_constant("kfp_b")],
		0,
	));
	assert!(keyed_positions(&bundle(value_nil()), &honest).is_empty());
}

#[test]
fn a_proposal_shaped_unlike_the_honest_term_is_declined() {
	let honest = Value::primitive(PRIM_PUBKEY, vec![make_constant("kfp_c")], 0);
	assert!(keyed_positions(&bundle(free_var(0)), &honest).is_empty());
}

fn free_var_id(n: usize) -> VariableId {
	vars::as_var(&free_var(n)).unwrap()
}
