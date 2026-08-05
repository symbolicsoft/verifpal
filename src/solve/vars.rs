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
//! - No global state is introduced.  A variable's id is a pure function of the
//!   slot it stands for (`ATTACKER_VAR_BASE + slot`), so nothing needs adding
//!   to `reset_global_state()` and parallel tests cannot interfere.
//! - The reserved range cannot collide: `value_names_map_add` assigns ids
//!   sequentially from 2, so a model would need two billion distinct constants
//!   to reach it.
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
pub const ATTACKER_VAR_BASE: ValueId = 0x8000_0000;

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
pub const FREE_VAR_BASE: ValueId = 0xC000_0000;

pub fn is_free_var_id(id: ValueId) -> bool {
	id >= FREE_VAR_BASE
}

/// Build the `n`th free-choice variable.
pub fn free_var(n: u32) -> Value {
	Value::Constant(Constant {
		name: Arc::from(format!("$free{n}")),
		id: FREE_VAR_BASE + n,
		..Default::default()
	})
}

/// A mapping from attacker variables to the ground terms the attacker chose.
pub type Substitution = HashMap<ValueId, Value>;

/// The variable id standing for wire slot `slot`.
pub fn attacker_var_id(slot: usize) -> ValueId {
	ATTACKER_VAR_BASE + slot as ValueId
}

pub fn is_attacker_var_id(id: ValueId) -> bool {
	id >= ATTACKER_VAR_BASE
}

/// Build the variable term for `slot`.  `hint` is the name of the constant the
/// slot holds, used only to make debug output legible.
pub fn attacker_var(slot: usize, hint: &str) -> Value {
	Value::Constant(Constant {
		name: Arc::from(format!("${hint}")),
		id: attacker_var_id(slot),
		..Default::default()
	})
}

/// If `v` is an attacker variable, its id.
pub fn as_var(v: &Value) -> Option<ValueId> {
	match v {
		Value::Constant(c) if is_attacker_var_id(c.id) => Some(c.id),
		_ => None,
	}
}

/// Whether `v` mentions any attacker variable.
pub fn contains_var(v: &Value) -> bool {
	match v {
		Value::Constant(c) => is_attacker_var_id(c.id),
		Value::Primitive(p) => p.arguments.iter().any(contains_var),
		Value::Equation(e) => e.values.iter().any(contains_var),
	}
}

/// Collect every attacker variable mentioned in `v`, without duplicates.
pub fn collect_vars(v: &Value, out: &mut Vec<ValueId>) {
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
pub fn apply(v: &Value, s: &Substitution) -> Value {
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
/// Consistency is checked with `equivalent`, not syntactic equality, so two
/// routes that force the same DH public value under commutativity agree.
pub fn bind(s: &mut Substitution, id: ValueId, v: Value) -> bool {
	match s.get(&id) {
		Some(existing) => existing.equivalent(&v, true),
		None => {
			s.insert(id, v);
			true
		}
	}
}

/// Merge `b` into a copy of `a`, failing on any conflicting binding.
pub fn compose(a: &Substitution, b: &Substitution) -> Option<Substitution> {
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
pub fn ground_free(v: &Value) -> Value {
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
pub fn ground_free_as(v: &Value, filler: &Value) -> Value {
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
pub fn ground_remaining(v: &Value, s: &mut Substitution) {
	let mut free = Vec::new();
	collect_vars(v, &mut free);
	for id in free {
		s.entry(id).or_insert_with(value_nil);
	}
}

/// Whether two substitutions bind the same variables to equivalent terms.
pub fn same_substitution(a: &Substitution, b: &Substitution) -> bool {
	a.len() == b.len()
		&& a.iter().all(|(id, v)| match b.get(id) {
			Some(other) => v.equivalent(other, true),
			None => false,
		})
}

/// Drop substitutions that bind the same variables to equivalent terms.
pub fn dedupe(candidates: Vec<Substitution>) -> Vec<Substitution> {
	let mut out: Vec<Substitution> = Vec::with_capacity(candidates.len());
	for candidate in candidates {
		if !out.iter().any(|kept| same_substitution(kept, &candidate)) {
			out.push(candidate);
		}
	}
	out
}
