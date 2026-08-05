/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Attacker variables and substitutions
//!
//! The goal-directed solver needs to talk about "whatever the attacker chooses
//! to put in this wire slot" before it knows what that choice is.  Verifpal's
//! term algebra has no notion of a variable, so one is layered on top without
//! touching [`Value`]: an attacker variable is an ordinary [`Constant`] whose
//! [`ValueId`] falls in a reserved range above every id the name interner will
//! ever hand out.
//!
//! Consequences of that choice, all of them deliberate:
//!
//! - `equivalence.rs`, `hashing.rs`, `pretty.rs` and every entry in
//!   `primitive/spec.rs` need no changes.  To them a variable is a constant
//!   they have not seen before.  `Constant::equivalent` compares ids, so two
//!   distinct variables are distinct and a variable never equals a real term.
//! - No shared state is introduced.  A variable's id is a pure function of the
//!   slot it stands for (`ATTACKER_VAR_BASE + slot`), so ids stay stable
//!   per-model, and parallel tests cannot interfere.
//! - The reserved range cannot collide: `ValueNames::intern` assigns ids
//!   sequentially from 2 and refuses to reach `ATTACKER_VAR_BASE`.
//!
//! Variables carry a generated name (`$gbs` for the slot holding `gbs`) purely
//! so debug output stays readable; nothing depends on the name.

use std::collections::HashMap;
use std::sync::Arc;

use crate::equivalence::splice_equation;
use crate::types::*;
use crate::value::value_nil;

/// Reserved `ValueId` range for attacker-controlled wire slots.  Ids below this
/// are ordinary interned constant names.
pub(crate) const ATTACKER_VAR_BASE: ValueId = 0x8000_0000;

/// Sub-range for *free choice* variables: positions a rule leaves open, which
/// the attacker may fill with anything.
///
/// These have to be variables rather than a committed placeholder like `nil`.
/// A principal often makes several checks against one forged message, each
/// constraining a different part of it; with concrete placeholders the partial
/// solutions read as `CONCAT(na, nil, nil)` and `CONCAT(nil, gb, nil)`, which
/// contradict each other and cannot be merged, whereas as variables they unify
/// into the message that satisfies both.  Anything still free when the proposal
/// is materialised becomes `nil`.
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

/// A mapping from attacker variables to the ground terms the attacker chose.
pub(crate) type Substitution = HashMap<ValueId, Value>;

/// The variable id standing for wire slot `slot`.
pub(crate) fn attacker_var_id(slot: usize) -> ValueId {
	ATTACKER_VAR_BASE + slot as ValueId
}

pub(crate) fn is_attacker_var_id(id: ValueId) -> bool {
	id >= ATTACKER_VAR_BASE
}

/// Build the variable term for `slot`.  `hint` is the name of the constant the
/// slot holds, used only to make debug output legible.
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

/// Every attacker variable in `v`, without duplicates.
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

/// Replace every bound variable in `v` by its binding.
///
/// Equations are re-spliced after substitution: binding a variable that sits in
/// an equation's base position to another equation would otherwise leave a
/// nested equation, which the rest of the engine does not expect.  This mirrors
/// the splice `resolution.rs` performs (`resolve_ps_equation_depth`).
pub(crate) fn apply(v: &Value, s: &Substitution) -> Value {
	apply_depth(v, s, 0)
}

/// Guard against a binding chain that refers back to itself.  Bindings are
/// produced by matching, which can legitimately bind one variable to a term
/// mentioning another, so resolution has to be transitive — but it must not
/// loop.
const MAX_APPLY_DEPTH: usize = 32;

fn apply_depth(v: &Value, s: &Substitution, depth: usize) -> Value {
	if s.is_empty() || !contains_var(v) || depth >= MAX_APPLY_DEPTH {
		return v.clone();
	}
	match v {
		Value::Constant(c) => match s.get(&c.id) {
			// A binding may itself mention variables — matching `$tag` against
			// `MAC(key, $ciphertext)` binds one in terms of another — so keep
			// resolving rather than stopping at the first substitution.
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

/// Bind `id` to `v`, failing if it is already bound to something else.
///
/// Consistency uses `equivalent`, not syntactic equality, so two routes that
/// force the same DH public value under commutativity agree.
pub(crate) fn bind(s: &mut Substitution, id: ValueId, v: Value) -> bool {
	match s.get(&id) {
		Some(existing) => existing.equivalent(&v, true),
		None => {
			s.insert(id, v);
			true
		}
	}
}

/// Merge `b` into a copy of `a`, failing on any conflicting binding.
pub(crate) fn compose(a: &Substitution, b: &Substitution) -> Option<Substitution> {
	let mut out = a.clone();
	for (id, v) in b {
		if !bind(&mut out, *id, v.clone()) {
			return None;
		}
	}
	Some(out)
}

/// Replace every free-choice variable in `v` with `nil`.
///
/// Called when a proposal is materialised: a position no rule constrained is
/// the attacker's to pick, and `nil` is the constant it always holds.
pub(crate) fn ground_free(v: &Value) -> Value {
	ground_free_as(v, &value_nil())
}

/// As [`ground_free`], but filling open positions with `filler`.
///
/// The algebra offers the attacker two canonical values, not one: `nil` where a
/// plain constant is wanted, and `G^nil` where a group element is — its own
/// public key.  Which one an unconstrained position should take is decided by
/// what the recipient later does with it, and a position that is merely
/// forwarded is indistinguishable either way; so both are offered rather than
/// guessed at.
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
		Value::Equation(e) => Value::Equation(Arc::new(Equation {
			values: e.values.iter().map(|a| ground_free_as(a, filler)).collect(),
		})),
	}
}

/// Bind every still-free variable in `v` to `nil`.
///
/// Used when materialising a proposal: a variable the solver never had a reason
/// to constrain becomes the attacker's canonical known constant.  Inside the
/// `G^X` shape produced by `symbolic.rs` this yields `G^nil`, which is exactly
/// the attacker's own DH public key.
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

/// Drop substitutions that bind the same variables to equivalent terms.
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
		// A model would need billions of constants to reach the reserved range,
		// so a variable can never collide with a name from the model.
		let interned = test_value_id("solver_disjoint_a");
		assert!(interned < crate::solve::vars::ATTACKER_VAR_BASE);
		assert!(crate::solve::vars::is_attacker_var_id(
			crate::solve::vars::attacker_var_id(0)
		));
		assert!(!crate::solve::vars::is_attacker_var_id(interned));
	}

	#[test]
	fn solver_apply_resolves_chained_bindings() {
		// Matching can bind one variable in terms of another, so substitution
		// has to be transitive rather than stopping at the first lookup.
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
		// Binding an equation into an exponent position must splice, matching
		// what resolution does, or a nested equation escapes into the engine.
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
		// `G^x^y == G^y^x`, so unification must try both alignments before
		// giving up.
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
	fn solver_merge_unifies_partial_solutions() {
		// Two checks on one forged message each constrain a different field.
		// Merging must combine them rather than call them contradictory.
		let a = solver_constant("solver_merge_a");
		let b = solver_constant("solver_merge_b");
		let slot = crate::solve::vars::attacker_var_id(0);
		let concat = |x: Value, y: Value| {
			Value::Primitive(std::sync::Arc::new(Primitive {
				id: 2, // CONCAT
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
		// Whatever no rule constrained is the attacker's choice at the moment a
		// proposal is executed.
		let free = crate::solve::vars::free_var(7);
		assert!(crate::solve::vars::is_free_var_id(
			crate::solve::vars::as_var(&free).expect("is a variable")
		));
		let grounded = crate::solve::vars::ground_free(&free);
		assert!(grounded.equivalent(&crate::value::value_nil(), true));
	}
}
