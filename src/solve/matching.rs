/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::borrow::Cow;
use std::sync::Arc;

use super::vars::{Substitution, as_var, bind, contains_var, occurs};
use crate::term::{Primitive, Value, VariableId};

pub(crate) fn unifiers(
	a: &Value,
	b: &Value,
	s: &Substitution,
) -> impl Iterator<Item = Substitution> + use<> {
	solve_equations::<true>(vec![(a.clone(), b.clone())], s.clone())
}

pub(crate) fn merge<'a>(
	a: &Substitution,
	b: &'a Substitution,
) -> impl Iterator<Item = Substitution> + use<'a> {
	let mut pending = Vec::new();
	let mut overlapping = Vec::new();
	for (id, value) in b {
		match a.get(id) {
			None => {
				let variable = Value::Variable(id.clone());
				pending.push((variable, value.clone()));
			}
			Some(existing) if existing.equivalent(value, true) => {}
			Some(existing) => {
				pending.push((existing.clone(), value.clone()));
				overlapping.push((id.clone(), value));
			}
		}
	}
	pending.reverse();
	solve_equations::<true>(pending, a.clone()).filter_map(move |mut out| {
		for (id, value) in &overlapping {
			let resolved = super::vars::apply(value, &out);
			if occurs(id, &resolved, &out) {
				return None;
			}
			out.insert(id.clone(), resolved);
		}
		Some(out)
	})
}

fn resolved<'a>(v: &'a Value, s: &Substitution) -> Cow<'a, Value> {
	if s.is_empty() || !contains_var(v) {
		Cow::Borrowed(v)
	} else {
		Cow::Owned(super::vars::apply(v, s))
	}
}

fn head<'a>(mut v: &'a Value, s: &'a Substitution) -> &'a Value {
	while let Value::Variable(id) = v
		&& let Some(bound) = s.get(id)
	{
		v = bound;
	}
	v
}

fn clash<const UNIFY: bool>(a: &Value, b: &Value, s: &Substitution) -> bool {
	let b = if UNIFY { head(b, s) } else { b };
	match (head(a, s), b) {
		(Value::Constant(x), Value::Constant(y)) => x.id != y.id,
		(Value::Constant(_), Value::Primitive(_)) | (Value::Primitive(_), Value::Constant(_)) => {
			true
		}
		(Value::Primitive(p1), Value::Primitive(p2)) => {
			p1.id != p2.id
				|| p1.output != p2.output
				|| p1.threshold != p2.threshold
				|| p1.arguments.len() != p2.arguments.len()
		}
		_ => false,
	}
}

fn projected_variable(p: &Primitive, s: &Substitution) -> Option<(VariableId, usize)> {
	match head(p.arguments.first()?, s) {
		Value::Variable(id) => Some((id.clone(), p.output)),
		Value::Primitive(inner) if crate::primitive::is_projection(inner.id) => {
			projected_variable(inner, s)
		}
		_ => None,
	}
}

fn field_var(id: &VariableId, field: usize) -> Value {
	let name = match id {
		VariableId::Slot(slot) => format!("slot/{slot}/{field}"),
		VariableId::Free(name) => format!("{name}/{field}"),
	};
	Value::Variable(VariableId::Free(Arc::from(name)))
}

fn projection_width(id: &VariableId, output: usize, terms: &[&Value], s: &Substitution) -> usize {
	let mut width = output + 1;
	for term in terms {
		if !contains_var(term) {
			continue;
		}
		for sub in crate::term::subterms(term) {
			if let Value::Primitive(p) = sub
				&& crate::primitive::is_projection(p.id)
				&& let Some(Value::Variable(inner)) = p.arguments.first().map(|a| head(a, s))
				&& inner == id
			{
				width = width.max(p.output + 1);
			}
		}
	}
	width
}

fn reopened_side(
	side: &Value,
	other: &Value,
	s: &mut Substitution,
	pending: &[(Value, Value)],
) -> Option<Value> {
	let Value::Primitive(p) = head(side, s) else {
		return None;
	};
	let tuple = crate::primitive::projects(p.id)?;
	let applied = super::vars::apply(side, s);
	if !applied.equivalent(side, true) {
		return Some(applied);
	}
	let (id, output) = projected_variable(p, s)?;
	let mut terms: Vec<&Value> = vec![side, other];
	terms.extend(pending.iter().flat_map(|(a, b)| [a, b]));
	let needed = projection_width(&id, output, &terms, s);
	let width = crate::primitive::definition(tuple)
		.ok()?
		.arity()
		.iter()
		.map(|&arity| arity as usize)
		.find(|&arity| arity >= needed)?;
	let fields = (0..width).map(|field| field_var(&id, field)).collect();
	bind(s, id, Value::primitive(tuple, fields, 0)).then(|| super::vars::apply(side, s))
}

fn reopened<const UNIFY: bool>(
	a: &Value,
	b: &Value,
	s: &mut Substitution,
	pending: &[(Value, Value)],
) -> Option<(Value, Value)> {
	if let Some(a) = reopened_side(a, b, s, pending) {
		return Some((a, b.clone()));
	}
	if UNIFY && let Some(b) = reopened_side(b, a, s, pending) {
		return Some((a.clone(), b));
	}
	None
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
			if clash::<UNIFY>(&a, &b, &s) {
				if let Some(retry) = reopened::<UNIFY>(&a, &b, &mut s, &pending) {
					pending.push(retry);
					continue;
				}
				let (retry, bindings) = alternatives.pop()?;
				pending = retry;
				s = bindings;
				continue;
			}
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
				if let Some(equations) = commutative_equations::<UNIFY>(p1, p2) {
					let mut swapped = pending.clone();
					swapped.extend(equations.into_iter().rev());
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
			} else if let Some(retry) = reopened::<UNIFY>(&a, &b, &mut s, &pending) {
				pending.push(retry);
				continue;
			}
			let (retry, bindings) = alternatives.pop()?;
			pending = retry;
			s = bindings;
		}
	})
}

pub(crate) fn commutative_equations<const UNIFY: bool>(
	p1: &Primitive,
	p2: &Primitive,
) -> Option<Vec<(Value, Value)>> {
	let rule = crate::primitive::commutativity_rule(p1.id)?;
	let left = crate::primitive::commutativity_parts_ref(p1);
	let right = crate::primitive::commutativity_parts_ref(p2);
	if [left, right]
		.into_iter()
		.flatten()
		.any(|(u, v)| crate::term::equivalence::structurally_identical(u, v))
	{
		return None;
	}
	let mut equations = Vec::new();
	match (left, right) {
		(Some((u1, v1)), Some((u2, v2))) => {
			equations.extend([(u1.clone(), v2.clone()), (v1.clone(), u2.clone())]);
		}
		(_, Some((u2, v2))) => {
			equations.push((
				p1.arguments[rule.wrapped].clone(),
				Value::primitive(rule.constructor, vec![v2.clone()], 0),
			));
			equations.push((p1.arguments[rule.bare].clone(), u2.clone()));
		}
		_ if UNIFY => {
			equations.push((
				p1.arguments[rule.wrapped].clone(),
				Value::primitive(rule.constructor, vec![p2.arguments[rule.bare].clone()], 0),
			));
			equations.push((
				Value::primitive(rule.constructor, vec![p1.arguments[rule.bare].clone()], 0),
				p2.arguments[rule.wrapped].clone(),
			));
		}
		_ => return None,
	}
	equations.extend(
		p1.arguments
			.iter()
			.zip(&p2.arguments)
			.enumerate()
			.filter(|(at, _)| *at != rule.wrapped && *at != rule.bare)
			.map(|(_, (a, b))| (a.clone(), b.clone())),
	);
	Some(equations)
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
) -> impl Iterator<Item = Substitution> + use<> {
	solve_equations::<false>(vec![(pattern.clone(), target.clone())], s.clone())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::protocol::SlotIdx;
	use crate::testing::*;
	use crate::util::index::Idx;

	#[test]
	fn matching_and_unification_preserve_a_shares_threshold() {
		let variable = crate::solve::vars::attacker_var(SlotIdx::new(0));
		let key = make_private("threshold_match_key");
		let share = |secret: Value, threshold| {
			let p = Primitive::new(crate::primitive::PRIM_THRESHOLD_SPLIT, vec![secret], 0)
				.with(|application| application.threshold = threshold);
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
			assert_eq!(
				unifiers(&pattern, &target, &empty).next().is_some(),
				threshold == 2
			);
		}
	}

	fn pubkey(inner: Value) -> Value {
		make_primitive(crate::primitive::id_of("PUBKEY").unwrap(), vec![inner], 0)
	}

	fn dh_kex(a: Value, b: Value) -> Value {
		make_primitive(crate::primitive::id_of("DH_KEX").unwrap(), vec![a, b], 0)
	}

	#[test]
	fn commutative_matching_retries_after_a_later_argument_conflicts() {
		let x = crate::solve::vars::attacker_var(SlotIdx::new(0));
		let y = crate::solve::vars::attacker_var(SlotIdx::new(1));
		let a = make_private("backtrack_a");
		let b = make_private("backtrack_b");
		let tuple = |args| make_primitive(crate::primitive::PRIM_CONCAT, args, 0);
		let pattern = tuple(vec![dh_kex(pubkey(x.clone()), y.clone()), x.clone()]);
		let target = tuple(vec![dh_kex(pubkey(a.clone()), b.clone()), b.clone()]);
		let empty = Substitution::default();
		for found in [
			match_value(&pattern, &target, &empty),
			unifiers(&pattern, &target, &empty).next(),
		] {
			let found = found.expect("the swapped exponents satisfy both fields");
			assert!(crate::solve::vars::apply(&x, &found).equivalent(&b, true));
			assert!(crate::solve::vars::apply(&y, &found).equivalent(&a, true));
			assert!(crate::solve::vars::apply(&pattern, &found).equivalent(&target, true));
		}
	}

	#[test]
	fn matching_resolves_an_existing_variable_alias() {
		let x = crate::solve::vars::attacker_var(SlotIdx::new(0));
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
		let x = crate::solve::vars::attacker_var(SlotIdx::new(0));
		let y = crate::solve::vars::attacker_var(SlotIdx::new(1));
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
	fn commutative_matching_can_supply_a_missing_public_key_shape() {
		let x = crate::solve::vars::attacker_var(SlotIdx::new(0));
		let y = crate::solve::vars::attacker_var(SlotIdx::new(1));
		let a = make_private("opaque_match_a");
		let b = make_private("opaque_match_b");
		let pattern = dh_kex(x.clone(), y.clone());
		let target = dh_kex(pubkey(a.clone()), b.clone());
		let empty = Substitution::default();
		let matches: Vec<_> = match_values(&pattern, &target, &empty).collect();
		assert_eq!(matches.len(), 2);
		for (bindings, (key, exponent)) in matches.iter().zip([(&a, &b), (&b, &a)]) {
			assert!(crate::solve::vars::apply(&x, bindings).equivalent(&pubkey(key.clone()), true));
			assert!(crate::solve::vars::apply(&y, bindings).equivalent(exponent, true));
			assert!(crate::solve::vars::apply(&pattern, bindings).equivalent(&target, true));
		}
		let fixed = Substitution::from_iter([(as_var(&y).unwrap(), a)]);
		for (left, right) in [(&pattern, &target), (&target, &pattern)] {
			let solutions: Vec<_> = unifiers(left, right, &fixed).collect();
			assert_eq!(solutions.len(), 1);
			assert!(
				crate::solve::vars::apply(&x, &solutions[0]).equivalent(&pubkey(b.clone()), true)
			);
		}
	}

	#[test]
	fn commutative_unification_can_shape_both_public_key_inputs() {
		let x = crate::solve::vars::attacker_var(SlotIdx::new(0));
		let y = crate::solve::vars::attacker_var(SlotIdx::new(1));
		let a = make_private("opaque_unify_a");
		let b = make_private("opaque_unify_b");
		let left = dh_kex(x.clone(), a.clone());
		let right = dh_kex(y.clone(), b.clone());
		let empty = Substitution::default();
		assert!(match_values(&left, &right, &empty).next().is_none());
		let solutions: Vec<_> = unifiers(&left, &right, &empty).collect();
		assert_eq!(solutions.len(), 1);
		let bindings = &solutions[0];
		assert!(crate::solve::vars::apply(&x, bindings).equivalent(&pubkey(b), true));
		assert!(crate::solve::vars::apply(&y, bindings).equivalent(&pubkey(a), true));
		assert!(
			crate::solve::vars::apply(&left, bindings)
				.equivalent(&crate::solve::vars::apply(&right, bindings), true)
		);
	}

	#[test]
	fn merging_retries_an_exponent_ordering_across_separate_bindings() {
		let x = crate::solve::vars::free_var(0);
		let y = crate::solve::vars::free_var(1);
		let a = make_private("merge_backtrack_a");
		let b = make_private("merge_backtrack_b");
		let mut right = Substitution::from_iter([
			(
				crate::solve::vars::attacker_var_id(SlotIdx::new(0)),
				a.clone(),
			),
			(
				crate::solve::vars::attacker_var_id(SlotIdx::new(1)),
				b.clone(),
			),
		]);
		let ids: Vec<_> = right.keys().cloned().collect();
		let left = Substitution::from_iter([
			(ids[0].clone(), dh_kex(pubkey(x.clone()), y.clone())),
			(ids[1].clone(), x.clone()),
		]);
		right.insert(ids[0].clone(), dh_kex(pubkey(a.clone()), b.clone()));
		right.insert(ids[1].clone(), b.clone());
		let found = merge(&left, &right)
			.next()
			.expect("the swapped ordering satisfies both bindings");
		assert!(crate::solve::vars::apply(&x, &found).equivalent(&b, true));
		assert!(crate::solve::vars::apply(&y, &found).equivalent(&a, true));
		for (id, value) in &right {
			assert!(found[id].equivalent(value, true));
		}
	}

	#[test]
	fn merging_still_refuses_a_cycle_between_partial_solutions() {
		let x = crate::solve::vars::attacker_var(SlotIdx::new(0));
		let y = crate::solve::vars::attacker_var(SlotIdx::new(1));
		let left = Substitution::from_iter([(
			as_var(&x).unwrap(),
			Value::primitive(crate::primitive::PRIM_HASH, vec![y.clone()], 0),
		)]);
		let right = Substitution::from_iter([(
			as_var(&y).unwrap(),
			Value::primitive(crate::primitive::PRIM_HASH, vec![x], 0),
		)]);
		assert!(merge(&left, &right).next().is_none());
		assert!(merge(&right, &left).next().is_none());
	}

	#[test]
	fn merging_resolves_aliases_before_checking_new_bindings() {
		let atom = make_private("merge_resolved_alias");
		let mut right = Substitution::from_iter([
			(
				crate::solve::vars::attacker_var_id(SlotIdx::new(0)),
				atom.clone(),
			),
			(
				crate::solve::vars::attacker_var_id(SlotIdx::new(1)),
				atom.clone(),
			),
		]);
		let ids: Vec<_> = right.keys().cloned().collect();
		let variable = Value::Variable;
		let left = Substitution::from_iter([(ids[0].clone(), variable(ids[1].clone()))]);
		right.insert(ids[1].clone(), variable(ids[0].clone()));
		let found = merge(&left, &right)
			.next()
			.expect("both aliases resolve to the same atom");
		for id in ids {
			assert!(crate::solve::vars::apply(&variable(id), &found).equivalent(&atom, true));
		}
	}

	#[test]
	fn symmetric_exponents_do_not_multiply_identical_match_branches() {
		let atom = make_private("symmetric_match_atom");
		let mut pattern = atom.clone();
		let mut target = atom.clone();
		for i in 0..30 {
			let x = crate::solve::vars::attacker_var(SlotIdx::new(2 * i));
			let y = crate::solve::vars::attacker_var(SlotIdx::new(2 * i + 1));
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
		let x = crate::solve::vars::attacker_var(SlotIdx::new(0));
		let y = crate::solve::vars::free_var(0);
		let constant = make_private("match_rigid_constant");
		let tuple = |args| make_primitive(crate::primitive::PRIM_CONCAT, args, 0);
		let pattern = tuple(vec![x, constant.clone()]);
		let target = tuple(vec![constant, y]);
		assert!(match_value(&pattern, &target, &Substitution::default()).is_none());
		assert!(
			unifiers(&pattern, &target, &Substitution::default())
				.next()
				.is_some()
		);
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
		assert!(
			unifiers(&term, &term, &Substitution::default())
				.next()
				.is_some()
		);
	}

	#[test]
	fn dh_kex_matches_modulo_commutativity() {
		let x = make_constant("mtc_x");
		let y = make_constant("mtc_y");
		let var = crate::solve::vars::attacker_var(SlotIdx::new(0));
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
		let var = crate::solve::vars::attacker_var(SlotIdx::new(1));
		let a = dh_kex(pubkey(var.clone()), y.clone());
		let b = dh_kex(pubkey(y), x.clone());
		let s = unifiers(&a, &b, &Substitution::default())
			.next()
			.expect("unifies modulo commutativity");
		assert!(crate::solve::vars::apply(&var, &s).equivalent(&x, true));
	}

	fn split(tuple: Value, output: usize) -> Value {
		make_primitive(crate::primitive::PRIM_SPLIT, vec![tuple], output)
	}

	fn concat(fields: Vec<Value>) -> Value {
		make_primitive(crate::primitive::PRIM_CONCAT, fields, 0)
	}

	#[test]
	fn two_fields_of_one_split_tuple_match_through_its_projections() {
		let t = crate::solve::vars::attacker_var(SlotIdx::new(0));
		let a = make_private("open_tuple_a");
		let b = make_private("open_tuple_b");
		let pattern = dh_kex(pubkey(split(t.clone(), 0)), split(t.clone(), 1));
		let target = dh_kex(pubkey(a.clone()), b.clone());
		let empty = Substitution::default();
		let tuples: Vec<Value> = match_values(&pattern, &target, &empty)
			.map(|found| crate::solve::vars::apply(&t, &found))
			.collect();
		assert_eq!(tuples.len(), 2);
		for (tuple, expected) in tuples.iter().zip([
			concat(vec![a.clone(), b.clone()]),
			concat(vec![b.clone(), a.clone()]),
		]) {
			assert!(tuple.equivalent(&expected, true), "got {tuple}");
		}
		let unified: Vec<_> = unifiers(&target, &pattern, &empty).collect();
		assert_eq!(unified.len(), 2);
	}

	#[test]
	fn an_opened_tuple_is_as_wide_as_its_widest_projection() {
		let t = crate::solve::vars::attacker_var(SlotIdx::new(0));
		let a = make_private("wide_tuple_a");
		let c = make_private("wide_tuple_c");
		let pattern = make_primitive(
			crate::primitive::PRIM_HASH,
			vec![split(t.clone(), 0), split(t.clone(), 2)],
			0,
		);
		let target = make_primitive(crate::primitive::PRIM_HASH, vec![a.clone(), c.clone()], 0);
		let found = match_value(&pattern, &target, &Substitution::default())
			.expect("a three-field tuple carries both values");
		let Value::Primitive(tuple) = crate::solve::vars::apply(&t, &found) else {
			panic!("the slot is bound to a tuple");
		};
		assert_eq!(tuple.arguments.len(), 3);
		assert!(tuple.arguments[0].equivalent(&a, true));
		assert!(as_var(&tuple.arguments[1]).is_some());
		assert!(tuple.arguments[2].equivalent(&c, true));
	}

	#[test]
	fn a_field_defined_by_its_sibling_is_bound_without_an_occurs_cycle() {
		let t = crate::solve::vars::attacker_var(SlotIdx::new(0));
		let k = make_private("sibling_field_key");
		let tag = make_primitive(crate::primitive::PRIM_HASH, vec![k, split(t.clone(), 0)], 0);
		let found = unifiers(&split(t.clone(), 1), &tag, &Substitution::default())
			.next()
			.expect("the tag field is a function of the other field");
		let tuple = crate::solve::vars::apply(&t, &found);
		let Value::Primitive(p) = &tuple else {
			panic!("the slot is bound to a tuple");
		};
		assert!(
			crate::solve::vars::apply(&split(t.clone(), 1), &found)
				.equivalent(&crate::solve::vars::apply(&tag, &found), true)
		);
		assert_eq!(p.arguments.len(), 2);
	}

	#[test]
	fn a_projection_of_a_projection_opens_the_inner_tuple_first() {
		let t = crate::solve::vars::attacker_var(SlotIdx::new(0));
		let a = make_private("nested_tuple_a");
		let pattern = split(split(t.clone(), 1), 0);
		let found = match_value(&pattern, &a, &Substitution::default())
			.expect("the inner field becomes a tuple");
		assert!(crate::solve::vars::apply(&pattern, &found).equivalent(&a, true));
	}

	#[test]
	fn projections_of_one_tuple_still_unify_congruently() {
		let t = crate::solve::vars::attacker_var(SlotIdx::new(0));
		let u = crate::solve::vars::attacker_var(SlotIdx::new(1));
		let found: Vec<_> = unifiers(
			&split(t.clone(), 0),
			&split(u.clone(), 0),
			&Substitution::default(),
		)
		.collect();
		assert_eq!(found.len(), 1);
		assert!(crate::solve::vars::apply(&t, &found[0]).equivalent(&u, true));
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
