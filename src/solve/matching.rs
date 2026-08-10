/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::borrow::Cow;

use crate::types::*;

use super::vars::{Substitution, as_var, bind, contains_var, occurs};

pub(crate) fn unify(a: &Value, b: &Value, s: &Substitution) -> Option<Substitution> {
	let mut out = s.clone();
	if unify_into(a, b, &mut out) {
		Some(out)
	} else {
		None
	}
}

pub(crate) fn merge(a: &Substitution, b: &Substitution) -> Option<Substitution> {
	let mut out = a.clone();
	for (id, value) in b {
		match out.get(id).cloned() {
			None => {
				if !bind(&mut out, *id, value.clone()) {
					return None;
				}
			}
			Some(existing) => {
				if existing.equivalent(value, true) {
					continue;
				}
				out = unify(&existing, value, &out)?;
				let resolved = super::vars::apply(value, &out);
				// Overwriting an existing binding bypasses `bind`, so the occurs
				// check has to be repeated here or a cycle re-enters by the one
				// door left open.
				if occurs(*id, &resolved, &out) {
					return None;
				}
				out.insert(*id, resolved);
			}
		}
	}
	Some(out)
}

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
			if crate::primitive::commutativity_rule(p1.id).is_none() {
				return p1
					.arguments
					.iter()
					.zip(p2.arguments.iter())
					.all(|(x, y)| unify_into(x, y, s));
			}
			let checkpoint = s.clone();
			if p1
				.arguments
				.iter()
				.zip(p2.arguments.iter())
				.all(|(x, y)| unify_into(x, y, s))
			{
				return true;
			}
			*s = checkpoint;
			commutative_swap(p1, p2)
				.is_some_and(|(u1, v1, u2, v2)| unify_into(u1, v2, s) && unify_into(v1, u2, s))
		}
		_ => false,
	}
}

fn commutative_swap<'a>(
	p1: &'a Primitive,
	p2: &'a Primitive,
) -> Option<(&'a Value, &'a Value, &'a Value, &'a Value)> {
	let (u1, v1) = crate::primitive::commutativity_parts_ref(p1)?;
	let (u2, v2) = crate::primitive::commutativity_parts_ref(p2)?;
	Some((u1, v1, u2, v2))
}

fn unify_bind(id: ValueId, v: &Value, s: &mut Substitution) -> bool {
	if as_var(v) == Some(id) {
		return true;
	}
	match s.get(&id).cloned() {
		None => {
			if occurs(id, v, s) {
				return false;
			}
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

pub(crate) fn match_value(
	pattern: &Value,
	target: &Value,
	s: &Substitution,
) -> Option<Substitution> {
	let mut out = s.clone();
	if match_into(pattern, target, &mut out) {
		Some(out)
	} else {
		None
	}
}

fn match_into(pattern: &Value, target: &Value, s: &mut Substitution) -> bool {
	if let Some(id) = as_var(pattern) {
		return bind(s, id, target.clone());
	}

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
			if crate::primitive::commutativity_rule(p1.id).is_none() {
				return p1
					.arguments
					.iter()
					.zip(p2.arguments.iter())
					.all(|(a, b)| match_into(a, b, s));
			}
			let checkpoint = s.clone();
			if p1
				.arguments
				.iter()
				.zip(p2.arguments.iter())
				.all(|(a, b)| match_into(a, b, s))
			{
				return true;
			}
			*s = checkpoint;
			commutative_swap(p1, p2)
				.is_some_and(|(u1, v1, u2, v2)| match_into(u1, v2, s) && match_into(v1, u2, s))
		}
		_ => false,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::primitive_get_enum;
	use crate::testutil::*;

	fn pubkey(inner: Value) -> Value {
		make_primitive(primitive_get_enum("PUBKEY").unwrap(), vec![inner], 0)
	}

	fn dh_kex(a: Value, b: Value) -> Value {
		make_primitive(primitive_get_enum("DH_KEX").unwrap(), vec![a, b], 0)
	}

	#[test]
	fn dh_kex_matches_modulo_commutativity() {
		let x = make_constant("mtc_x");
		let y = make_constant("mtc_y");
		let var = crate::solve::vars::attacker_var(0, "mtc_slot");
		let pattern = dh_kex(pubkey(var.clone()), y.clone());
		let target = dh_kex(pubkey(y), x.clone());
		let s = match_value(&pattern, &target, &Substitution::default())
			.expect("matches modulo commutativity");
		assert!(crate::solve::vars::apply(&var, &s).equivalent(&x, true));
	}

	#[test]
	fn dh_kex_unifies_modulo_commutativity() {
		let x = make_constant("unc_x");
		let y = make_constant("unc_y");
		let var = crate::solve::vars::attacker_var(1, "unc_slot");
		let a = dh_kex(pubkey(var.clone()), y.clone());
		let b = dh_kex(pubkey(y), x.clone());
		let s = unify(&a, &b, &Substitution::default()).expect("unifies modulo commutativity");
		assert!(crate::solve::vars::apply(&var, &s).equivalent(&x, true));
	}

	#[test]
	fn dh_kex_does_not_match_unrelated_pairs() {
		let x = make_constant("dnm_x");
		let y = make_constant("dnm_y");
		let z = make_constant("dnm_z");
		let pattern = dh_kex(pubkey(x.clone()), y);
		let target = dh_kex(pubkey(x), z);
		assert!(match_value(&pattern, &target, &Substitution::default()).is_none());
	}
}
