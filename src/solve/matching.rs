/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::borrow::Cow;

use crate::types::*;

use super::vars::{Substitution, as_var, bind, contains_var, occurs};

pub(crate) fn unify(a: &Value, b: &Value, s: &Substitution) -> Option<Substitution> {
	solve_equations::<true>(vec![(a.clone(), b.clone())], s.clone()).next()
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

fn solve_equations<const UNIFY: bool>(
	pending: Vec<(Value, Value)>,
	s: Substitution,
) -> impl Iterator<Item = Substitution> {
	let mut alternatives = vec![(pending, s)];
	std::iter::from_fn(move || {
		let (mut pending, mut s) = alternatives.pop()?;
		loop {
			let Some((a, b)) = pending.pop() else {
				return Some(s);
			};
			let a = resolved(&a, &s);
			let b = if UNIFY {
				resolved(&b, &s)
			} else {
				Cow::Borrowed(&b)
			};
			if a.equivalent(&b, true) {
				continue;
			}
			if let Some(id) = as_var(&a) {
				if bind(&mut s, id, b.into_owned()) {
					continue;
				}
			} else if UNIFY && let Some(id) = as_var(&b) {
				if bind(&mut s, id, a.into_owned()) {
					continue;
				}
			} else if (contains_var(&a) || (UNIFY && contains_var(&b)))
				&& let (Value::Primitive(p1), Value::Primitive(p2)) = (a.as_ref(), b.as_ref())
				&& p1.id == p2.id
				&& p1.output == p2.output
				&& p1.threshold == p2.threshold
				&& p1.arguments.len() == p2.arguments.len()
			{
				if let Some((u1, v1, u2, v2)) = commutative_swap(p1, p2)
					&& !crate::theory::structurally_identical(u1, v1)
					&& !crate::theory::structurally_identical(u2, v2)
				{
					let mut swapped = pending.clone();
					swapped.push((v1.clone(), u2.clone()));
					swapped.push((u1.clone(), v2.clone()));
					alternatives.push((swapped, s.clone()));
				}
				pending.extend(
					p1.arguments
						.iter()
						.zip(&p2.arguments)
						.rev()
						.map(|(a, b)| (a.clone(), b.clone())),
				);
				continue;
			}
			let (retry, bindings) = alternatives.pop()?;
			pending = retry;
			s = bindings;
		}
	})
}

fn commutative_swap<'a>(
	p1: &'a Primitive,
	p2: &'a Primitive,
) -> Option<(&'a Value, &'a Value, &'a Value, &'a Value)> {
	let (u1, v1) = crate::primitive::commutativity_parts_ref(p1)?;
	let (u2, v2) = crate::primitive::commutativity_parts_ref(p2)?;
	Some((u1, v1, u2, v2))
}

pub(crate) fn match_value(
	pattern: &Value,
	target: &Value,
	s: &Substitution,
) -> Option<Substitution> {
	if !contains_var(pattern) {
		return pattern.equivalent(target, true).then(|| s.clone());
	}
	match_values(pattern, target, s).next()
}

pub(crate) fn match_values(
	pattern: &Value,
	target: &Value,
	s: &Substitution,
) -> impl Iterator<Item = Substitution> {
	solve_equations::<false>(vec![(pattern.clone(), target.clone())], s.clone())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::primitive_get_enum;
	use crate::testutil::*;

	#[test]
	fn matching_and_unification_preserve_a_shares_threshold() {
		let variable = crate::solve::vars::attacker_var(0, "threshold_match");
		let key = make_private("threshold_match_key");
		let share = |secret: Value, threshold| {
			let mut p = Primitive::new(crate::primitive::PRIM_THRESHOLD_SPLIT, vec![secret], 0);
			p.threshold = threshold;
			Value::Primitive(std::sync::Arc::new(p))
		};
		let pattern = share(variable, 2);
		let empty = Substitution::default();
		for threshold in [2, 3] {
			let target = share(key.clone(), threshold);
			assert_eq!(
				match_value(&pattern, &target, &empty).is_some(),
				threshold == 2
			);
			assert_eq!(unify(&pattern, &target, &empty).is_some(), threshold == 2);
		}
	}

	fn pubkey(inner: Value) -> Value {
		make_primitive(primitive_get_enum("PUBKEY").unwrap(), vec![inner], 0)
	}

	fn dh_kex(a: Value, b: Value) -> Value {
		make_primitive(primitive_get_enum("DH_KEX").unwrap(), vec![a, b], 0)
	}

	#[test]
	fn commutative_matching_retries_after_a_later_argument_conflicts() {
		let x = crate::solve::vars::attacker_var(0, "backtrack_x");
		let y = crate::solve::vars::attacker_var(1, "backtrack_y");
		let a = make_private("backtrack_a");
		let b = make_private("backtrack_b");
		let tuple = |args| make_primitive(crate::primitive::PRIM_CONCAT, args, 0);
		let pattern = tuple(vec![dh_kex(pubkey(x.clone()), y.clone()), x.clone()]);
		let target = tuple(vec![dh_kex(pubkey(a.clone()), b.clone()), b.clone()]);
		for solve in [match_value, unify] {
			let found = solve(&pattern, &target, &Substitution::default())
				.expect("the swapped exponents satisfy both fields");
			assert!(crate::solve::vars::apply(&x, &found).equivalent(&b, true));
			assert!(crate::solve::vars::apply(&y, &found).equivalent(&a, true));
			assert!(crate::solve::vars::apply(&pattern, &found).equivalent(&target, true));
		}
	}

	#[test]
	fn matching_resolves_an_existing_variable_alias() {
		let x = crate::solve::vars::attacker_var(0, "match_alias_x");
		let y = crate::solve::vars::free_var(0);
		let target = make_private("match_alias_target");
		let initial = Substitution::from_iter([(as_var(&x).unwrap(), y.clone())]);
		let found = match_value(&x, &target, &initial).expect("the alias is still bindable");
		assert!(crate::solve::vars::apply(&x, &found).equivalent(&target, true));
		assert!(crate::solve::vars::apply(&y, &found).equivalent(&target, true));
		assert!(match_value(&x, &x, &Substitution::default()).is_some());
		assert_eq!(initial.len(), 1);
	}

	#[test]
	fn matching_enumerates_both_commutative_assignments() {
		let x = crate::solve::vars::attacker_var(0, "alternatives_x");
		let y = crate::solve::vars::attacker_var(1, "alternatives_y");
		let a = make_private("alternatives_a");
		let b = make_private("alternatives_b");
		let pattern = dh_kex(pubkey(x.clone()), y.clone());
		let target = dh_kex(pubkey(a.clone()), b.clone());
		let empty = Substitution::default();
		let found: Vec<_> = match_values(&pattern, &target, &empty).collect();
		assert_eq!(found.len(), 2);
		for (bindings, expected) in found.iter().zip([&a, &b]) {
			assert!(crate::solve::vars::apply(&x, bindings).equivalent(expected, true));
			assert!(crate::solve::vars::apply(&pattern, bindings).equivalent(&target, true));
		}
		let constrained = Substitution::from_iter([(as_var(&x).unwrap(), b)]);
		let constrained: Vec<_> = match_values(&pattern, &target, &constrained).collect();
		assert_eq!(constrained.len(), 1);
		assert!(crate::solve::vars::apply(&y, &constrained[0]).equivalent(&a, true));
	}

	#[test]
	fn symmetric_exponents_do_not_multiply_identical_match_branches() {
		let atom = make_private("symmetric_match_atom");
		let mut pattern = atom.clone();
		let mut target = atom.clone();
		for i in 0..30 {
			let x = crate::solve::vars::attacker_var(2 * i, "symmetric_match_x");
			let y = crate::solve::vars::attacker_var(2 * i + 1, "symmetric_match_y");
			pattern = Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![pattern, dh_kex(pubkey(x), y)],
				0,
			);
			target = Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![target, dh_kex(pubkey(atom.clone()), atom.clone())],
				0,
			);
		}
		let empty = Substitution::default();
		let found: Vec<_> = match_values(&pattern, &target, &empty).take(2).collect();
		assert_eq!(found.len(), 1);
		assert_eq!(found[0].len(), 60);
		assert!(crate::solve::vars::apply(&pattern, &found[0]).equivalent(&target, true));
	}

	#[test]
	fn matching_does_not_bind_target_variables() {
		let x = crate::solve::vars::attacker_var(0, "match_rigid_x");
		let y = crate::solve::vars::free_var(0);
		let constant = make_private("match_rigid_constant");
		let tuple = |args| make_primitive(crate::primitive::PRIM_CONCAT, args, 0);
		let pattern = tuple(vec![x, constant.clone()]);
		let target = tuple(vec![constant, y]);
		assert!(match_value(&pattern, &target, &Substitution::default()).is_none());
		assert!(unify(&pattern, &target, &Substitution::default()).is_some());
	}

	#[test]
	fn unifying_a_ground_shared_term_does_not_expand_it() {
		let mut term = make_private("unify_dag_seed");
		for _ in 0..40 {
			term = Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![term.clone(), term.clone(), term],
				0,
			);
		}
		assert!(unify(&term, &term, &Substitution::default()).is_some());
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
