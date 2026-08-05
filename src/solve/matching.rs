/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Matching terms that contain attacker variables
//!
//! One-sided matching, not full unification: variables are permitted on the
//! *pattern* side only.  That is all the solver needs, because the pattern is
//! always the principal's symbolic computation (which may mention attacker
//! choices) and the target is always a concrete term the attacker is trying to
//! hit.
//!
//! Matching respects the same equational theory as
//! [`crate::equivalence::equivalent_equations`], which for Verifpal means DH
//! commutativity over at most two exponents (`sanity.rs` caps equations at
//! `G^a^b`).  A three-element equation therefore has exactly two candidate
//! alignments and both are tried, with the substitution restored between
//! attempts.  This is a closed case analysis, not associative-commutative
//! unification.

use std::borrow::Cow;

use crate::types::*;

use super::vars::{Substitution, as_var, bind, contains_var};

/// Unify two terms, either of which may mention variables.
///
/// [`match_value`] is one-sided and suffices when a pattern is being fitted to a
/// concrete term.  Merging two *partial* solutions is different: each was
/// derived independently and each left different positions open, so variables
/// occur on both sides and either may absorb the other.  A principal that makes
/// two checks against one forged message produces exactly this — one solution
/// constraining the message's first field, another its second — and unifying
/// them yields the message satisfying both.
pub fn unify(a: &Value, b: &Value, s: &Substitution) -> Option<Substitution> {
	let mut out = s.clone();
	if unify_into(a, b, &mut out) {
		Some(out)
	} else {
		None
	}
}

/// Merge two substitutions, unifying rather than rejecting where they disagree.
pub fn merge(a: &Substitution, b: &Substitution) -> Option<Substitution> {
	let mut out = a.clone();
	for (id, value) in b {
		match out.get(id).cloned() {
			None => {
				out.insert(*id, value.clone());
			}
			Some(existing) => {
				if existing.equivalent(value, true) {
					continue;
				}
				out = unify(&existing, value, &out)?;
				let resolved = super::vars::apply(value, &out);
				out.insert(*id, resolved);
			}
		}
	}
	Some(out)
}

/// Resolve `v` against `s`, borrowing when no binding could apply.
///
/// Unification recurses over both terms, so cloning each side at every node
/// costs a deep copy per node — quadratic in term size on the solver's hot
/// path, and wasted entirely whenever the term mentions no variable at all.
fn resolved<'a>(v: &'a Value, s: &Substitution) -> Cow<'a, Value> {
	if s.is_empty() || !contains_var(v) {
		Cow::Borrowed(v)
	} else {
		Cow::Owned(super::vars::apply(v, s))
	}
}

fn unify_into(a: &Value, b: &Value, s: &mut Substitution) -> bool {
	let a = resolved(a, s);
	let b = resolved(b, s);

	if let Some(id) = as_var(&a) {
		return unify_bind(id, &b, s);
	}
	if let Some(id) = as_var(&b) {
		return unify_bind(id, &a, s);
	}

	match (a.as_ref(), b.as_ref()) {
		(Value::Constant(_), Value::Constant(_)) => a.equivalent(&b, true),
		(Value::Primitive(p1), Value::Primitive(p2)) => {
			if p1.id != p2.id || p1.output != p2.output || p1.arguments.len() != p2.arguments.len()
			{
				return false;
			}
			p1.arguments
				.iter()
				.zip(p2.arguments.iter())
				.all(|(x, y)| unify_into(x, y, s))
		}
		(Value::Equation(e1), Value::Equation(e2)) => {
			if e1.values.len() != e2.values.len() {
				return false;
			}
			if e1.values.len() == 3 {
				// `G^x^y == G^y^x`, so either alignment will do.
				let checkpoint = s.clone();
				if unify_into(&e1.values[1], &e2.values[1], s)
					&& unify_into(&e1.values[2], &e2.values[2], s)
				{
					return true;
				}
				*s = checkpoint;
				return unify_into(&e1.values[1], &e2.values[2], s)
					&& unify_into(&e1.values[2], &e2.values[1], s);
			}
			e1.values
				.iter()
				.zip(e2.values.iter())
				.all(|(x, y)| unify_into(x, y, s))
		}
		_ => false,
	}
}

fn unify_bind(id: ValueId, v: &Value, s: &mut Substitution) -> bool {
	if as_var(v) == Some(id) {
		return true;
	}
	match s.get(&id).cloned() {
		None => {
			s.insert(id, v.clone());
			true
		}
		Some(existing) => {
			if existing.equivalent(v, true) {
				return true;
			}
			unify_into(&existing, v, s)
		}
	}
}

/// Match `pattern` (which may mention attacker variables) against the ground
/// term `target`, extending `s`.  Returns the extended substitution, or `None`
/// if no consistent extension exists.
pub fn match_value(pattern: &Value, target: &Value, s: &Substitution) -> Option<Substitution> {
	let mut out = s.clone();
	if match_into(pattern, target, &mut out) {
		Some(out)
	} else {
		None
	}
}

fn match_into(pattern: &Value, target: &Value, s: &mut Substitution) -> bool {
	// A variable absorbs whatever is opposite it, subject to any binding it
	// already carries.
	if let Some(id) = as_var(pattern) {
		return bind(s, id, target.clone());
	}

	// An already-bound variable inside the pattern must be honoured, so compare
	// against the substituted form rather than the raw one.
	if contains_var(pattern) {
		let applied = super::vars::apply(pattern, s);
		if !contains_var(&applied) {
			return applied.equivalent(target, true);
		}
		return match_structural(&applied, target, s);
	}

	pattern.equivalent(target, true)
}

fn match_structural(pattern: &Value, target: &Value, s: &mut Substitution) -> bool {
	match (pattern, target) {
		(Value::Constant(_), _) => match_into(pattern, target, s),
		(Value::Primitive(p1), Value::Primitive(p2)) => {
			if p1.id != p2.id || p1.output != p2.output || p1.arguments.len() != p2.arguments.len()
			{
				return false;
			}
			for (a, b) in p1.arguments.iter().zip(p2.arguments.iter()) {
				if !match_into(a, b, s) {
					return false;
				}
			}
			true
		}
		(Value::Equation(e1), Value::Equation(e2)) => match_equations(e1, e2, s),
		_ => false,
	}
}

fn match_equations(e1: &Equation, e2: &Equation, s: &mut Substitution) -> bool {
	if e1.values.len() != e2.values.len() {
		return false;
	}
	match e1.values.len() {
		0 => true,
		1 => match_into(&e1.values[0], &e2.values[0], s),
		2 => {
			match_into(&e1.values[0], &e2.values[0], s)
				&& match_into(&e1.values[1], &e2.values[1], s)
		}
		3 => {
			// `G^a^b == G^b^a`, so both alignments of the two exponents are
			// admissible.  Try them in turn, rolling back on failure.
			if !match_into(&e1.values[0], &e2.values[0], s) {
				return false;
			}
			let checkpoint = s.clone();
			if match_into(&e1.values[1], &e2.values[1], s)
				&& match_into(&e1.values[2], &e2.values[2], s)
			{
				return true;
			}
			*s = checkpoint;
			match_into(&e1.values[1], &e2.values[2], s)
				&& match_into(&e1.values[2], &e2.values[1], s)
		}
		_ => {
			// Unreachable while sanity caps equations at three elements, but
			// falling back to positional matching keeps this total rather than
			// silently accepting.
			for (a, b) in e1.values.iter().zip(e2.values.iter()) {
				if !match_into(a, b, s) {
					return false;
				}
			}
			true
		}
	}
}
