/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::{Deducer, match_each, refine_check};
use crate::primitive::{Capability, Reveal, reuse_rule};
use crate::solve::matching::match_values;
use crate::solve::vars::{Substitution, contains_var, dedupe};
use crate::term::equivalence::equivalent_primitives;
use crate::term::{Primitive, PrimitiveId, Value, ValueId};
use crate::util::IdMap;

pub(super) type DecompositionMemo = IdMap<usize, (Arc<Primitive>, Vec<Substitution>)>;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Head {
	Constant(ValueId),
	Primitive(PrimitiveId),
}

impl Head {
	fn of(v: &Value) -> Option<Head> {
		match v {
			Value::Primitive(p) => Some(Head::Primitive(p.id)),
			Value::Constant(c) => Some(Head::Constant(c.id)),
			Value::Variable(_) => None,
		}
	}
}

#[derive(Default)]
pub(super) struct Reach {
	heads: Vec<Head>,
	anything: bool,
}

fn reach(p: &Arc<Primitive>, seen: &mut IdMap<usize, Arc<Reach>>) -> Arc<Reach> {
	let key = Arc::as_ptr(p) as usize;
	if let Some(reach) = seen.get(&key) {
		return Arc::clone(reach);
	}
	let mut reveals: Vec<Reveal> = Vec::new();
	if crate::primitive::core_reveals_arguments(p.id) {
		reveals.extend((0..p.arguments.len()).map(Reveal::Argument));
	}
	if let Ok(spec) = crate::primitive::spec(p.id) {
		if let Some(rule) = &spec.decompose {
			reveals.extend(rule.reveals.iter().copied());
		}
		reveals.extend(spec.weak_reveals.iter().copied());
	}
	if let Some(rule) = reuse_rule(p.id) {
		reveals.extend(rule.reveals.iter().copied());
	}
	let mut out = Reach::default();
	for reveal in reveals {
		match reveal {
			Reveal::Output(_) => out.heads.push(Head::Primitive(p.id)),
			Reveal::Argument(index) => {
				let Some(argument) = p.arguments.get(index) else {
					continue;
				};
				match Head::of(argument) {
					Some(head) => out.heads.push(head),
					None => out.anything = true,
				}
				if let Value::Primitive(inner) = argument {
					let inner = reach(inner, seen);
					out.heads.extend(inner.heads.iter().copied());
					out.anything |= inner.anything;
				}
			}
		}
	}
	out.heads.sort_unstable();
	out.heads.dedup();
	let out = Arc::new(out);
	seen.insert(key, Arc::clone(&out));
	out
}

fn reduces_over_variables(v: &Value) -> bool {
	matches!(v, Value::Primitive(p) if (crate::primitive::rewrite_rule(p.id).is_some()
		|| crate::primitive::is_projection(p.id))
		&& contains_var(v))
}

fn bears_oracle(v: &Value) -> bool {
	crate::term::subterms(v).any(|term| match term {
		Value::Primitive(p) => {
			(crate::primitive::is_projection(p.id) && p.arguments.first().is_some_and(contains_var))
				|| crate::primitive::rewrite_rule(p.id)
					.is_some_and(|rule| p.arguments.get(rule.from).is_some_and(contains_var))
		}
		Value::Constant(_) | Value::Variable(_) => false,
	})
}

pub(super) fn inverts_through(v: &Value) -> bool {
	crate::term::subterms(v).any(|term| match term {
		Value::Primitive(p) => {
			(crate::primitive::is_projection(p.id) && p.arguments.first().is_some_and(contains_var))
				|| crate::primitive::rewrite_rule(p.id).is_some_and(|rule| {
					matches!(p.arguments.get(rule.from), Some(from @ Value::Primitive(inner))
						if inner.id != rule.id && contains_var(from))
				})
		}
		Value::Constant(_) | Value::Variable(_) => false,
	})
}

pub(super) fn revealed_oracles(wire_terms: &[Value]) -> Vec<(Value, Vec<Value>)> {
	let mut out: Vec<(Value, Vec<Value>)> = Vec::new();
	let mut seen: Vec<(Value, Vec<Value>)> = Vec::new();
	let mut index: IdMap<u64, Vec<usize>> = IdMap::default();
	let mut pending: Vec<(Value, Vec<Value>)> = wire_terms
		.iter()
		.filter(|term| contains_var(term))
		.map(|term| (term.clone(), Vec::new()))
		.collect();
	while let Some((term, given)) = pending.pop() {
		let Value::Primitive(p) = &term else {
			continue;
		};
		let Some((revealed, needed)) = decomposition_targets(p) else {
			continue;
		};
		for value in revealed {
			if !contains_var(&value) {
				continue;
			}
			let mut path = given.clone();
			path.extend(needed.iter().cloned());
			let bucket = index.entry(value.hash_value()).or_default();
			if bucket.iter().any(|&at| {
				let (held, route) = &seen[at];
				held.equivalent(&value, true)
					&& route.len() == path.len()
					&& route.iter().zip(&path).all(|(a, b)| a.equivalent(b, true))
			}) {
				continue;
			}
			bucket.push(seen.len());
			seen.push((value.clone(), path.clone()));
			if reduces_over_variables(&value) || bears_oracle(&value) {
				out.push((value.clone(), path.clone()));
			}
			pending.push((value, path));
		}
	}
	out
}

pub(super) fn decomposition_targets(p: &Primitive) -> Option<(Vec<Value>, Vec<Value>)> {
	if crate::primitive::core_reveals_arguments(p.id) {
		return Some((p.arguments.clone(), Vec::new()));
	}
	let rule = crate::theory::decompose_rule(p)?;
	let mut given = Vec::new();
	for &index in &rule.given {
		let argument = p.arguments.get(index)?;
		let (filtered, valid) = (rule.filter)(p, argument, index);
		if !valid {
			return None;
		}
		given.push(filtered);
	}
	Some((revealed_shapes(p, &rule.reveals), given))
}

fn revealed_shapes(p: &Primitive, reveals: &[Reveal]) -> Vec<Value> {
	reveals
		.iter()
		.filter_map(|reveal| match *reveal {
			Reveal::Argument(index) => p.arguments.get(index).cloned(),
			Reveal::Output(output) => {
				(output != p.output).then(|| Value::Primitive(Arc::new(p.with_output(output))))
			}
		})
		.collect()
}

impl<'a> Deducer<'a> {
	pub(super) fn solve_by_decomposition(
		&self,
		goal: &Value,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let mut memo = DecompositionMemo::default();
		let wanted = Head::of(goal);
		let reaches = self.shared.wire_reach.get_or_init(|| {
			let mut seen = IdMap::default();
			self.shared
				.wire_terms
				.iter()
				.map(|term| match term {
					Value::Primitive(p) => Some(reach(p, &mut seen)),
					_ => None,
				})
				.collect()
		});
		for (term, reach) in self.shared.wire_terms.iter().zip(reaches) {
			let Some(reach) = reach else {
				continue;
			};
			if !reach.anything && wanted.is_some_and(|key| reach.heads.binary_search(&key).is_err())
			{
				continue;
			}
			out.extend(self.solve_decomposition_from(term, goal, s, &mut memo));
		}
	}

	pub(super) fn solve_decomposition_from(
		&self,
		term: &Value,
		goal: &Value,
		s: &Substitution,
		memo: &mut DecompositionMemo,
	) -> Vec<Substitution> {
		let Value::Primitive(p) = term else {
			return Vec::new();
		};
		let key = Arc::as_ptr(p) as usize;
		if let Some((_, solutions)) = memo.get(&key) {
			return solutions.clone();
		}
		let targets = decomposition_targets(p);
		let blocked = targets.is_none();
		let mut routes: Vec<_> = targets
			.into_iter()
			.map(|(revealed, given)| (revealed, given, None))
			.collect();
		if let Some(rule) = reuse_rule(p.id)
			&& crate::theory::opens(p, self.shared.capabilities, self.attacker)
		{
			routes.push((revealed_shapes(p, &rule.reveals), Vec::new(), None));
		}
		let capabilities = self.shared.capabilities;
		if !capabilities.is_empty()
			&& let Ok(spec) = crate::primitive::spec(p.id)
		{
			let revealed = revealed_shapes(p, &spec.weak_reveals);
			if !revealed.is_empty() {
				for (annotated, caps) in capabilities.annotated_terms() {
					if caps.in_force(Capability::Weak, self.attacker.current_phase)
						&& matches!(annotated, Value::Primitive(q) if q.id == p.id && q.output == p.output)
					{
						routes.push((revealed.clone(), Vec::new(), Some(annotated)));
					}
				}
			}
		}
		let mut out = Vec::new();
		for (revealed, given, annotated) in routes {
			for value in revealed {
				let mut frontier: Vec<_> = match_values(&value, goal, s).collect();
				let constructible: Vec<_> = frontier
					.iter()
					.filter(|bound| {
						bound
							.iter()
							.any(|(id, value)| !s.contains_key(id) && contains_var(value))
					})
					.flat_map(|bound| self.require_constructible(bound, s, false))
					.collect();
				frontier.extend(constructible);
				frontier.extend(self.solve_decomposition_from(&value, goal, s, memo));
				if let Some(annotated) = annotated {
					frontier = match_each(term, annotated, &frontier);
				}
				for required in &given {
					if frontier.is_empty() {
						break;
					}
					frontier = self.solve_each(required, &frontier);
				}
				out.extend(frontier);
			}
		}
		if blocked {
			for (shaped, bound) in self.shape_for_decomposition(p, s) {
				let shaped = Value::Primitive(shaped);
				let mut memo = DecompositionMemo::default();
				out.extend(self.solve_decomposition_from(&shaped, goal, &bound, &mut memo));
			}
		}
		let out = dedupe(out);
		memo.insert(key, (Arc::clone(p), out.clone()));
		out
	}

	fn shape_for_decomposition(
		&self,
		p: &Primitive,
		s: &Substitution,
	) -> Vec<(Arc<Primitive>, Substitution)> {
		let Some(rule) = crate::primitive::spec(p.id)
			.ok()
			.and_then(|spec| spec.decompose.as_ref())
		else {
			return Vec::new();
		};
		let filter = rule.filter;
		let mut out = Vec::new();
		for &index in &rule.given {
			let Some(argument) = p.arguments.get(index) else {
				continue;
			};
			if !contains_var(argument) || filter(p, argument, index).1 {
				continue;
			}
			let Some(required) = crate::primitive::key_derivation_of(self.fresh_var()) else {
				continue;
			};
			if !filter(p, &required, index).1 {
				continue;
			}
			for bound in self.invert(argument, &required, s) {
				for solved in self.require_constructible(&bound, s, false) {
					let shaped = refine_check(p, &solved);
					if equivalent_primitives(&shaped, p, true)
						|| !(rule.filter)(&shaped, &shaped.arguments[index], index).1
					{
						continue;
					}
					out.push((Arc::new(shaped), solved));
				}
			}
		}
		out
	}
}
