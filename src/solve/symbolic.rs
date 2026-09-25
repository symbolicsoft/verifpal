/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::theory::reduce_once;
use crate::types::*;

use super::vars::attacker_var;

#[derive(Default)]
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
	controllable: &crate::solve::control::Controllable,
	km: &ProtocolTrace,
	principal: PrincipalId,
	attacker: &AttackerState,
) -> SymbolicState {
	build_with(controllable, km, principal, attacker, &[], false)
}

pub(crate) fn build_assuming_honest(
	controllable: &crate::solve::control::Controllable,
	km: &ProtocolTrace,
	principal: PrincipalId,
	attacker: &AttackerState,
	honest: &[usize],
) -> SymbolicState {
	build_with(controllable, km, principal, attacker, honest, false)
}

pub(crate) fn build_addressed(
	controllable: &crate::solve::control::Controllable,
	km: &ProtocolTrace,
	principal: PrincipalId,
	attacker: &AttackerState,
	honest: &[usize],
) -> SymbolicState {
	build_with(controllable, km, principal, attacker, honest, true)
}

struct Walk<'a> {
	km: &'a ProtocolTrace,
	principal: PrincipalId,
	var_terms: &'a [Option<Value>],
	addressed: bool,
	memo: Vec<Option<Value>>,
	building: Vec<bool>,
}

fn build_with(
	controllable: &crate::solve::control::Controllable,
	km: &ProtocolTrace,
	principal: PrincipalId,
	attacker: &AttackerState,
	honest: &[usize],
	addressed: bool,
) -> SymbolicState {
	let n = km.slots.len();
	let mut var_terms: Vec<Option<Value>> = vec![None; n];
	let mut var_slots = Vec::new();

	for (idx, slot) in var_terms.iter_mut().enumerate() {
		if !controllable.admits(principal, attacker, idx) || honest.contains(&idx) {
			continue;
		}
		let trace_slot = &km.slots[idx];
		*slot = Some(shaped_var(
			idx,
			&trace_slot.initial_value,
			&trace_slot.constant.name,
		));
		var_slots.push(idx);
	}

	let mut walk = Walk {
		km,
		principal,
		var_terms: &var_terms,
		addressed,
		memo: vec![None; n],
		building: vec![false; n],
	};
	let terms: Vec<Value> = (0..n).map(|idx| walk.slot_term(idx)).collect();

	SymbolicState {
		terms,
		var_slots,
		var_terms,
	}
}

impl Walk<'_> {
	fn slot_term(&mut self, idx: usize) -> Value {
		if let Some(cached) = &self.memo[idx] {
			return cached.clone();
		}
		if let Some(var) = &self.var_terms[idx] {
			let v = var.clone();
			self.memo[idx] = Some(v.clone());
			return v;
		}
		let slot = &self.km.slots[idx];
		if self.building[idx] {
			return slot.initial_value.clone();
		}

		self.building[idx] = true;
		let inlined = self.inline(&slot.initial_value, slot.creator);
		self.building[idx] = false;

		let reduced = reduce_once(&inlined);
		self.memo[idx] = Some(reduced.clone());
		reduced
	}

	fn reaches(&self, idx: usize, owner: PrincipalId) -> bool {
		owner == self.principal || (!self.addressed && self.km.slots[idx].mutation_reaches(owner))
	}

	fn inline(&mut self, v: &Value, owner: PrincipalId) -> Value {
		match v {
			Value::Constant(c) => match self.km.index_of(c) {
				Some(idx) => {
					if self.var_terms[idx].is_some() && !self.reaches(idx, owner) {
						if self.building[idx] {
							return v.clone();
						}
						self.building[idx] = true;
						let honest = self.inline(&self.km.slots[idx].initial_value, owner);
						self.building[idx] = false;
						return reduce_once(&honest);
					}
					self.slot_term(idx)
				}
				None => v.clone(),
			},
			Value::Primitive(p) => {
				let args: Vec<Value> = p.arguments.iter().map(|a| self.inline(a, owner)).collect();
				Value::Primitive(Arc::new(p.with_arguments(args)))
			}
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

	fn bob() -> (ProtocolTrace, PrincipalId, AttackerState) {
		let m = crate::parser::parse_string("sym.vp", SRC).expect("parses");
		let km = crate::sanity::sanity(&m).expect("passes sanity");
		let bob = km.principal_ids[km
			.principals
			.iter()
			.position(|p| p == "Bob")
			.expect("Bob exists")];
		(km, bob, make_attacker_state(vec![]))
	}

	fn slot(km: &ProtocolTrace, name: &str) -> usize {
		km.slots
			.iter()
			.position(|s| &*s.constant.name == name)
			.unwrap_or_else(|| panic!("no slot named {name}"))
	}

	#[test]
	fn a_controllable_wire_slot_becomes_a_variable_shaped_like_what_it_replaced() {
		let (km, bob, attacker) = bob();
		let controllable = crate::solve::control::Controllable::of(&km, bob, &attacker);
		let sym = build(&controllable, &km, bob, &attacker);
		let ga = slot(&km, "sym_ga");
		assert!(
			sym.is_var_slot(ga),
			"an unguarded wire value is controllable"
		);
		assert!(
			super::super::vars::contains_var(&sym.terms[slot(&km, "sym_k")]),
			"the key Bob computes is a function of the slot the attacker controls, so \
			 the symbolic term has to carry the variable: got {}",
			sym.terms[slot(&km, "sym_k")]
		);
		assert!(
			super::super::vars::contains_var(&sym.terms[slot(&km, "sym_t")]),
			"and so does everything downstream of it"
		);
	}

	#[test]
	fn holding_one_slot_honest_removes_it_from_the_variables_and_from_every_term() {
		let (km, bob, attacker) = bob();
		let controllable = crate::solve::control::Controllable::of(&km, bob, &attacker);
		let ga = slot(&km, "sym_ga");
		let refined = build_assuming_honest(&controllable, &km, bob, &attacker, &[ga]);
		assert!(!refined.is_var_slot(ga), "the held slot is not a variable");
		assert!(refined.var_slots.is_empty());
		for name in ["sym_ga", "sym_k", "sym_t"] {
			assert!(
				!super::super::vars::contains_var(&refined.terms[slot(&km, name)]),
				"{name} still mentions a variable after the only controllable slot \
				 was held honest"
			);
		}
	}

	#[test]
	fn a_slot_this_principal_created_is_never_a_variable() {
		let (km, bob, attacker) = bob();
		let controllable = crate::solve::control::Controllable::of(&km, bob, &attacker);
		let sym = build(&controllable, &km, bob, &attacker);
		for name in ["sym_b", "sym_k", "sym_t"] {
			assert!(
				!sym.is_var_slot(slot(&km, name)),
				"{name} is Bob's own, so the attacker cannot replace it"
			);
		}
	}

	#[test]
	fn reaches_asks_whether_an_unguarded_delivery_carried_the_slot_to_the_owner() {
		let (km, bob, _) = bob();
		let walk = Walk {
			km: &km,
			principal: bob,
			var_terms: &[],
			addressed: false,
			memo: Vec::new(),
			building: Vec::new(),
		};
		let ga = slot(&km, "sym_ga");
		assert!(walk.reaches(ga, bob), "the walked principal always reaches");
		let creator = km.slots[ga].creator;
		assert_eq!(
			walk.reaches(ga, creator),
			km.slots[ga].mutatable_to.contains(&creator),
			"for anyone else it is exactly the unguarded-delivery question"
		);
	}
}
