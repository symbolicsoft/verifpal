/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::theory::reduce_once;
use crate::types::*;

use super::vars::attacker_var;

pub(crate) struct SymbolicState {
	pub terms: Vec<Value>,
	pub var_slots: Vec<usize>,
	pub var_terms: Vec<Option<Value>>,
}

impl SymbolicState {
	pub(crate) fn is_var_slot(&self, slot: usize) -> bool {
		self.var_terms.get(slot).is_some_and(|t| t.is_some())
	}
}

fn shaped_var(slot: usize, honest: &Value, name: &str) -> Value {
	let var = attacker_var(slot, name);
	match honest {
		Value::Primitive(_) if crate::primitive::value_is_key_derivation(honest) => {
			crate::primitive::key_derivation_of(var.clone()).unwrap_or(var)
		}
		_ => var,
	}
}

pub(crate) fn build(
	controllable: &crate::reexec::Controllable,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> SymbolicState {
	build_assuming_honest(controllable, ps, attacker, None)
}

pub(crate) fn build_assuming_honest(
	controllable: &crate::reexec::Controllable,
	ps: &PrincipalState,
	attacker: &AttackerState,
	honest: Option<usize>,
) -> SymbolicState {
	let n = ps.values.len();
	let mut var_terms: Vec<Option<Value>> = vec![None; n];
	let mut var_slots = Vec::new();

	for (idx, slot) in var_terms.iter_mut().enumerate() {
		if !controllable.admits(ps, attacker, idx) || honest == Some(idx) {
			continue;
		}
		let name = &ps.meta[idx].constant.name;
		*slot = Some(shaped_var(idx, &ps.values[idx].value, name));
		var_slots.push(idx);
	}

	let mut memo: Vec<Option<Value>> = vec![None; n];
	let mut building: Vec<bool> = vec![false; n];
	let mut terms: Vec<Value> = Vec::with_capacity(n);
	for idx in 0..n {
		terms.push(slot_term(idx, ps, &var_terms, &mut memo, &mut building));
	}

	SymbolicState {
		terms,
		var_slots,
		var_terms,
	}
}

fn slot_term(
	idx: usize,
	ps: &PrincipalState,
	var_terms: &[Option<Value>],
	memo: &mut Vec<Option<Value>>,
	building: &mut Vec<bool>,
) -> Value {
	if let Some(cached) = &memo[idx] {
		return cached.clone();
	}
	if let Some(var) = &var_terms[idx] {
		let v = var.clone();
		memo[idx] = Some(v.clone());
		return v;
	}
	if building[idx] {
		return ps.values[idx].value.clone();
	}

	let owner = ps.values[idx].provenance.creator;
	building[idx] = true;
	let inlined = inline(&ps.values[idx].value, ps, var_terms, owner, memo, building);
	building[idx] = false;

	let reduced = reduce_once(&inlined);
	memo[idx] = Some(reduced.clone());
	reduced
}

fn reaches(ps: &PrincipalState, idx: usize, owner: PrincipalId) -> bool {
	owner == ps.id || ps.meta[idx].mutatable_to.contains(&owner)
}

fn inline(
	v: &Value,
	ps: &PrincipalState,
	var_terms: &[Option<Value>],
	owner: PrincipalId,
	memo: &mut Vec<Option<Value>>,
	building: &mut Vec<bool>,
) -> Value {
	match v {
		Value::Constant(c) => match ps.index_of(c) {
			Some(idx) => {
				if var_terms[idx].is_some() && !reaches(ps, idx, owner) {
					if building[idx] {
						return v.clone();
					}
					building[idx] = true;
					let honest =
						inline(&ps.values[idx].value, ps, var_terms, owner, memo, building);
					building[idx] = false;
					return reduce_once(&honest);
				}
				slot_term(idx, ps, var_terms, memo, building)
			}
			None => v.clone(),
		},
		Value::Primitive(p) => {
			let args: Vec<Value> = p
				.arguments
				.iter()
				.map(|a| inline(a, ps, var_terms, owner, memo, building))
				.collect();
			Value::Primitive(Arc::new(p.with_arguments(args)))
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testutil::make_attacker_state;

	const SRC: &str = "attacker[active]\n\
		principal Alice[\n\
		generates sym_a\n\
		sym_ga = PUBKEY(sym_a)\n\
		]\n\
		Alice -> Bob: sym_ga\n\
		principal Bob[\n\
		knows private sym_b\n\
		sym_k = DH_KEX(sym_ga, sym_b)\n\
		sym_t = HASH(sym_k)\n\
		]\n\
		queries[\n\
		confidentiality? sym_a\n\
		]\n";

	fn bob() -> (ProtocolTrace, PrincipalState, AttackerState) {
		let m = crate::parser::parse_string("sym.vp", SRC).expect("parses");
		let (km, states) = crate::sanity::sanity(&m).expect("passes sanity");
		let ps = states
			.iter()
			.find(|s| s.name == "Bob")
			.expect("Bob exists")
			.clone_for_depth(false);
		(km, ps, make_attacker_state(vec![]))
	}

	fn slot(ps: &PrincipalState, name: &str) -> usize {
		ps.meta
			.iter()
			.position(|m| &*m.constant.name == name)
			.unwrap_or_else(|| panic!("no slot named {name}"))
	}

	#[test]
	fn a_controllable_wire_slot_becomes_a_variable_shaped_like_what_it_replaced() {
		let (km, ps, attacker) = bob();
		let controllable = crate::reexec::Controllable::of(&km, &ps, &attacker);
		let sym = build(&controllable, &ps, &attacker);
		let ga = slot(&ps, "sym_ga");
		assert!(
			sym.is_var_slot(ga),
			"an unguarded wire value is controllable"
		);
		assert!(
			super::super::vars::contains_var(&sym.terms[slot(&ps, "sym_k")]),
			"the key Bob computes is a function of the slot the attacker controls, so \
			 the symbolic term has to carry the variable: got {}",
			sym.terms[slot(&ps, "sym_k")]
		);
		assert!(
			super::super::vars::contains_var(&sym.terms[slot(&ps, "sym_t")]),
			"and so does everything downstream of it"
		);
	}

	#[test]
	fn holding_one_slot_honest_removes_it_from_the_variables_and_from_every_term() {
		let (km, ps, attacker) = bob();
		let controllable = crate::reexec::Controllable::of(&km, &ps, &attacker);
		let ga = slot(&ps, "sym_ga");
		let refined = build_assuming_honest(&controllable, &ps, &attacker, Some(ga));
		assert!(!refined.is_var_slot(ga), "the held slot is not a variable");
		assert!(refined.var_slots.is_empty());
		for name in ["sym_ga", "sym_k", "sym_t"] {
			assert!(
				!super::super::vars::contains_var(&refined.terms[slot(&ps, name)]),
				"{name} still mentions a variable after the only controllable slot \
				 was held honest"
			);
		}
	}

	#[test]
	fn a_slot_this_principal_created_is_never_a_variable() {
		let (km, ps, attacker) = bob();
		let controllable = crate::reexec::Controllable::of(&km, &ps, &attacker);
		let sym = build(&controllable, &ps, &attacker);
		for name in ["sym_b", "sym_k", "sym_t"] {
			assert!(
				!sym.is_var_slot(slot(&ps, name)),
				"{name} is Bob's own, so the attacker cannot replace it"
			);
		}
	}

	#[test]
	fn reaches_asks_whether_an_unguarded_delivery_carried_the_slot_to_the_owner() {
		let (km, ps, attacker) = bob();
		let _ = &km;
		let _ = &attacker;
		let ga = slot(&ps, "sym_ga");
		assert!(
			reaches(&ps, ga, ps.id),
			"the walked principal always reaches"
		);
		let creator = ps.values[ga].provenance.creator;
		assert_eq!(
			reaches(&ps, ga, creator),
			ps.meta[ga].mutatable_to.contains(&creator),
			"for anyone else it is exactly the unguarded-delivery question"
		);
	}
}
