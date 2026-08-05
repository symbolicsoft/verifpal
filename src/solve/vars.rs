/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::Arc;

use crate::equivalence::splice_equation;
use crate::types::*;
use crate::value::value_nil;

pub(crate) const ATTACKER_VAR_BASE: ValueId = 0x8000_0000;

pub(crate) const FREE_VAR_BASE: ValueId = 0xC000_0000;

pub(crate) fn is_free_var_id(id: ValueId) -> bool {
	id >= FREE_VAR_BASE
}

pub(crate) fn free_var(n: u32) -> Value {
	Value::Constant(Constant {
		name: Arc::from(format!("$free{n}")),
		id: FREE_VAR_BASE + n,
		..Default::default()
	})
}

pub(crate) type Substitution = HashMap<ValueId, Value>;

pub(crate) fn attacker_var_id(slot: usize) -> ValueId {
	ATTACKER_VAR_BASE + slot as ValueId
}

pub(crate) fn is_attacker_var_id(id: ValueId) -> bool {
	id >= ATTACKER_VAR_BASE
}

pub(crate) fn attacker_var(slot: usize, hint: &str) -> Value {
	Value::Constant(Constant {
		name: Arc::from(format!("${hint}")),
		id: attacker_var_id(slot),
		..Default::default()
	})
}

pub(crate) fn as_var(v: &Value) -> Option<ValueId> {
	match v {
		Value::Constant(c) if is_attacker_var_id(c.id) => Some(c.id),
		_ => None,
	}
}

pub(crate) fn contains_var(v: &Value) -> bool {
	match v {
		Value::Constant(c) => is_attacker_var_id(c.id),
		Value::Primitive(p) => p.arguments.iter().any(contains_var),
		Value::Equation(e) => e.values.iter().any(contains_var),
	}
}

pub(crate) fn collect_vars(v: &Value, out: &mut Vec<ValueId>) {
	match v {
		Value::Constant(c) => {
			if is_attacker_var_id(c.id) && !out.contains(&c.id) {
				out.push(c.id);
			}
		}
		Value::Primitive(p) => {
			for a in &p.arguments {
				collect_vars(a, out);
			}
		}
		Value::Equation(e) => {
			for a in &e.values {
				collect_vars(a, out);
			}
		}
	}
}

pub(crate) fn apply(v: &Value, s: &Substitution) -> Value {
	apply_depth(v, s, 0)
}

const MAX_APPLY_DEPTH: usize = 32;

fn apply_depth(v: &Value, s: &Substitution, depth: usize) -> Value {
	if s.is_empty() || !contains_var(v) || depth >= MAX_APPLY_DEPTH {
		return v.clone();
	}
	match v {
		Value::Constant(c) => match s.get(&c.id) {
			Some(bound) => apply_depth(bound, s, depth + 1),
			None => v.clone(),
		},
		Value::Primitive(p) => {
			let args: Vec<Value> = p
				.arguments
				.iter()
				.map(|a| apply_depth(a, s, depth + 1))
				.collect();
			Value::Primitive(Arc::new(p.with_arguments(args)))
		}
		Value::Equation(e) => Value::Equation(Arc::new(splice_equation(
			e.values.iter().map(|item| apply_depth(item, s, depth + 1)),
		))),
	}
}

pub(crate) fn bind(s: &mut Substitution, id: ValueId, v: Value) -> bool {
	match s.get(&id) {
		Some(existing) => existing.equivalent(&v, true),
		None => {
			s.insert(id, v);
			true
		}
	}
}

pub(crate) fn compose(a: &Substitution, b: &Substitution) -> Option<Substitution> {
	let mut out = a.clone();
	for (id, v) in b {
		if !bind(&mut out, *id, v.clone()) {
			return None;
		}
	}
	Some(out)
}

pub(crate) fn ground_free(v: &Value) -> Value {
	ground_free_as(v, &value_nil())
}

pub(crate) fn ground_free_as(v: &Value, filler: &Value) -> Value {
	match v {
		Value::Constant(c) => {
			if is_free_var_id(c.id) {
				filler.clone()
			} else {
				v.clone()
			}
		}
		Value::Primitive(p) => {
			let args: Vec<Value> = p
				.arguments
				.iter()
				.map(|a| ground_free_as(a, filler))
				.collect();
			Value::Primitive(Arc::new(p.with_arguments(args)))
		}
		Value::Equation(e) => Value::Equation(Arc::new(splice_equation(
			e.values.iter().map(|a| ground_free_as(a, filler)),
		))),
	}
}

pub(crate) fn ground_remaining(v: &Value, s: &mut Substitution) {
	let mut free = Vec::new();
	collect_vars(v, &mut free);
	for id in free {
		s.entry(id).or_insert_with(value_nil);
	}
}

pub(crate) fn same_substitution(a: &Substitution, b: &Substitution) -> bool {
	a.len() == b.len()
		&& a.iter().all(|(id, v)| match b.get(id) {
			Some(other) => v.equivalent(other, true),
			None => false,
		})
}

pub(crate) fn dedupe(candidates: Vec<Substitution>) -> Vec<Substitution> {
	let mut out: Vec<Substitution> = Vec::with_capacity(candidates.len());
	for candidate in candidates {
		if !out.iter().any(|kept| same_substitution(kept, &candidate)) {
			out.push(candidate);
		}
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testutil::test_value_id;

	fn solver_constant(name: &str) -> Value {
		Value::Constant(Constant {
			name: std::sync::Arc::from(name),
			id: test_value_id(name),
			..Default::default()
		})
	}

	fn dh(base: Value, exponents: Vec<Value>) -> Value {
		let mut values = vec![base];
		values.extend(exponents);
		Value::Equation(std::sync::Arc::new(Equation { values }))
	}

	#[test]
	fn solver_var_ids_are_disjoint_from_interned_names() {
		let interned = test_value_id("solver_disjoint_a");
		assert!(interned < crate::solve::vars::ATTACKER_VAR_BASE);
		assert!(crate::solve::vars::is_attacker_var_id(
			crate::solve::vars::attacker_var_id(0)
		));
		assert!(!crate::solve::vars::is_attacker_var_id(interned));
	}

	#[test]
	fn solver_apply_resolves_chained_bindings() {
		let outer = crate::solve::vars::attacker_var(0, "solver_chain_outer");
		let inner = crate::solve::vars::attacker_var(1, "solver_chain_inner");
		let mut s = crate::solve::vars::Substitution::new();
		s.insert(crate::solve::vars::attacker_var_id(0), inner.clone());
		s.insert(
			crate::solve::vars::attacker_var_id(1),
			crate::value::value_nil(),
		);
		let resolved = crate::solve::vars::apply(&outer, &s);
		assert!(resolved.equivalent(&crate::value::value_nil(), true));
	}

	#[test]
	fn solver_apply_splices_equations() {
		let var = crate::solve::vars::attacker_var(0, "solver_splice");
		let exponent = solver_constant("solver_splice_e");
		let term = dh(crate::value::value_g(), vec![var, exponent.clone()]);
		let mut s = crate::solve::vars::Substitution::new();
		s.insert(
			crate::solve::vars::attacker_var_id(0),
			crate::value::value_nil(),
		);
		let resolved = crate::solve::vars::apply(&term, &s);
		let expected = dh(
			crate::value::value_g(),
			vec![crate::value::value_nil(), exponent],
		);
		assert!(resolved.equivalent(&expected, true));
	}

	#[test]
	fn solver_unify_respects_dh_commutativity() {
		let x = solver_constant("solver_dh_x");
		let y = solver_constant("solver_dh_y");
		let var = crate::solve::vars::attacker_var(0, "solver_dh_var");
		let pattern = dh(crate::value::value_g(), vec![var, y.clone()]);
		let target = dh(crate::value::value_g(), vec![y, x.clone()]);
		let s = crate::solve::vars::Substitution::new();
		let solved = crate::solve::matching::unify(&pattern, &target, &s)
			.expect("commuted exponents should unify");
		let bound = solved
			.get(&crate::solve::vars::attacker_var_id(0))
			.expect("variable bound");
		assert!(bound.equivalent(&x, true));
	}

	#[test]
	fn solver_grounding_free_positions_splices_equations() {
		let term = dh(
			crate::value::value_g(),
			vec![crate::solve::vars::free_var(0)],
		);
		let grounded = crate::solve::vars::ground_free_as(&term, &crate::value::value_g_nil());
		assert!(grounded.equivalent(&crate::value::value_g_nil(), true));
	}

	#[test]
	fn solver_unify_requires_matching_equation_base() {
		let x = solver_constant("solver_base_x");
		let y = solver_constant("solver_base_y");
		let var = crate::solve::vars::attacker_var(0, "solver_base_var");
		let pattern = dh(crate::value::value_g(), vec![var, y.clone()]);
		let target = dh(crate::value::value_nil(), vec![y, x]);
		let s = crate::solve::vars::Substitution::new();
		assert!(crate::solve::matching::unify(&pattern, &target, &s).is_none());
	}

	#[test]
	fn solver_merge_unifies_partial_solutions() {
		let a = solver_constant("solver_merge_a");
		let b = solver_constant("solver_merge_b");
		let slot = crate::solve::vars::attacker_var_id(0);
		let concat = |x: Value, y: Value| {
			Value::Primitive(std::sync::Arc::new(Primitive {
				id: 2,
				arguments: vec![x, y],
				output: 0,
				instance_check: false,
			}))
		};

		let mut left = crate::solve::vars::Substitution::new();
		left.insert(slot, concat(a.clone(), crate::solve::vars::free_var(0)));
		let mut right = crate::solve::vars::Substitution::new();
		right.insert(slot, concat(crate::solve::vars::free_var(1), b.clone()));

		let merged = crate::solve::matching::merge(&left, &right).expect("should unify");
		let value = merged.get(&slot).expect("slot bound");
		assert!(value.equivalent(&concat(a, b), true));
	}

	#[test]
	fn solver_free_positions_become_nil() {
		let free = crate::solve::vars::free_var(7);
		assert!(crate::solve::vars::is_free_var_id(
			crate::solve::vars::as_var(&free).expect("is a variable")
		));
		let grounded = crate::solve::vars::ground_free(&free);
		assert!(grounded.equivalent(&crate::value::value_nil(), true));
	}
}
