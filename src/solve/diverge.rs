/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::primitive::{PRIM_HASH, primitive_def};
use crate::types::*;

use super::symbolic::SymbolicState;
use super::vars::{Substitution, apply, attacker_var_id, collect_free_vars, collect_vars, dedupe};
use crate::value::value_nil;

pub(crate) fn solve_divergent(a: &Value, b: &Value, s: &Substitution) -> Vec<Substitution> {
	let mut a_vars = Vec::new();
	let mut b_vars = Vec::new();
	collect_vars(a, &mut a_vars);
	collect_vars(b, &mut b_vars);

	if a_vars.is_empty() && b_vars.is_empty() {
		return Vec::new();
	}

	let mut out = Vec::new();

	for id in a_vars.iter().chain(b_vars.iter()) {
		let in_a = a_vars.contains(id);
		let in_b = b_vars.contains(id);
		if in_a == in_b {
			continue;
		}
		let mut extended = s.clone();
		extended.entry(*id).or_insert_with(value_nil);
		out.push(extended);
	}

	let mut all = s.clone();
	for id in a_vars.iter().chain(b_vars.iter()) {
		all.entry(*id).or_insert_with(value_nil);
	}
	out.push(all);

	dedupe(out)
}

pub(crate) fn distinguish(sym: &SymbolicState, proposal: &Substitution) -> Option<Substitution> {
	let mut free = Vec::new();
	for &slot in &sym.var_slots {
		let Some(term) = sym.var_terms.get(slot).and_then(Option::as_ref) else {
			continue;
		};
		if proposal.contains_key(&attacker_var_id(slot)) {
			collect_free_vars(&apply(term, proposal), &mut free);
		}
	}
	if free.len() < 2 {
		return None;
	}
	let ladder = fillers();
	let mut out = proposal.clone();
	for (n, id) in free.iter().enumerate() {
		out.insert(*id, ladder[n % ladder.len()].clone());
	}
	Some(out)
}

pub(crate) fn fillers() -> Vec<Value> {
	let widths = primitive_def(PRIM_HASH)
		.map(|d| d.arity().to_vec())
		.unwrap_or_default();
	std::iter::once(value_nil())
		.chain(
			widths
				.iter()
				.map(|&k| Value::primitive(PRIM_HASH, vec![value_nil(); k.max(0) as usize], 0)),
		)
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::{PRIM_CONCAT, PRIM_DH_KEX, normalise_arguments};
	use crate::solve::symbolic::SymbolicState;
	use crate::solve::vars::{FREE_VAR_BASE, attacker_var, free_var};

	fn widest(id: PrimitiveId) -> usize {
		primitive_def(id)
			.map(|d| d.arity().iter().copied().max().unwrap_or(0))
			.unwrap_or(0) as usize
	}

	fn pairwise_distinct(values: &[Value]) -> bool {
		values
			.iter()
			.enumerate()
			.all(|(i, a)| values[i + 1..].iter().all(|b| !a.equivalent(b, true)))
	}

	#[test]
	fn the_ladder_separates_every_position_a_concat_can_hold() {
		let ladder = fillers();
		assert!(
			ladder.len() >= widest(PRIM_CONCAT),
			"a CONCAT holds {} arguments and the ladder offers {} distinct values, so two \
			 projections of one bundle would be filled alike and their divergence missed",
			widest(PRIM_CONCAT),
			ladder.len()
		);
		assert!(pairwise_distinct(&ladder));
	}

	#[test]
	fn every_filler_stays_one_level_deep() {
		for filler in fillers() {
			let Value::Primitive(p) = &filler else {
				continue;
			};
			assert!(
				p.arguments.iter().all(|a| matches!(a, Value::Constant(_))),
				"{filler} nests, so TermBound would decline it in a shallow protocol"
			);
		}
	}

	#[test]
	fn the_ladder_survives_normalisation_in_a_restricted_position() {
		let normalised: Vec<Value> = fillers()
			.into_iter()
			.map(|filler| {
				let args = normalise_arguments(PRIM_DH_KEX, vec![value_nil(), filler]);
				args[1].clone()
			})
			.collect();
		assert!(
			pairwise_distinct(&normalised),
			"normalise_arguments unwraps a key derivation where the spec forbids one, so a \
			 ladder built from such terms collapses to a single value in that position"
		);
	}

	fn one_var_slot(term: Value) -> SymbolicState {
		SymbolicState {
			terms: vec![term.clone()],
			var_slots: vec![0],
			var_terms: vec![Some(term)],
		}
	}

	fn install(v: Value) -> Substitution {
		let mut s = Substitution::default();
		s.insert(attacker_var_id(0), v);
		s
	}

	#[test]
	fn distinguish_declines_a_single_free_position() {
		let sym = one_var_slot(attacker_var(0, "x"));
		let proposal = install(Value::primitive(
			PRIM_CONCAT,
			vec![value_nil(), free_var(0)],
			0,
		));
		assert!(distinguish(&sym, &proposal).is_none());
	}

	#[test]
	fn distinguish_declines_a_slot_the_proposal_does_not_install_into() {
		let sym = one_var_slot(attacker_var(0, "x"));
		assert!(distinguish(&sym, &Substitution::default()).is_none());
	}

	#[test]
	fn distinguish_gives_each_free_position_its_own_value() {
		let sym = one_var_slot(attacker_var(0, "x"));
		let arity = widest(PRIM_CONCAT);
		let free: Vec<Value> = (0..arity).map(|n| free_var(n as u32)).collect();
		let proposal = install(Value::primitive(PRIM_CONCAT, free, 0));
		let out = distinguish(&sym, &proposal).expect("distinguished");
		let bound: Vec<Value> = (0..arity)
			.map(|n| out[&(FREE_VAR_BASE + n as ValueId)].clone())
			.collect();
		assert!(pairwise_distinct(&bound));
	}

	#[test]
	fn distinguish_keeps_the_bindings_the_solver_already_made() {
		let sym = one_var_slot(attacker_var(0, "x"));
		let installed =
			Value::primitive(PRIM_CONCAT, vec![free_var(0), free_var(1), free_var(2)], 0);
		let proposal = install(installed.clone());
		let out = distinguish(&sym, &proposal).expect("distinguished");
		assert!(out[&attacker_var_id(0)].equivalent(&installed, true));
	}
}
