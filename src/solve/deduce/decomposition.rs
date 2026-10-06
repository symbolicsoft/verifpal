/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::{Deducer, match_each, refine_check};
use crate::primitive::Capability;
use crate::primitive::*;
use crate::solve::matching::match_values;
use crate::solve::vars::{Substitution, contains_var, dedupe};
use crate::term::equivalence::equivalent_primitives;
use crate::term::{Primitive, Value};
use crate::util::IdMap;

pub(super) type DecompositionMemo = IdMap<usize, (Arc<Primitive>, Vec<Substitution>)>;

#[derive(Default)]
pub(super) struct Reach {
	heads: Vec<u64>,
	anything: bool,
}

fn reach(p: &Arc<Primitive>, seen: &mut IdMap<usize, Arc<Reach>>) -> Arc<Reach> {
	let key = Arc::as_ptr(p) as usize;
	if let Some(reach) = seen.get(&key) {
		return Arc::clone(reach);
	}
	let mut reveals: Vec<Reveal> = Vec::new();
	if primitive_core_reveals_args(p.id) {
		reveals.extend((0..p.arguments.len()).map(Reveal::Argument));
	}
	if let Ok(spec) = primitive_get(p.id) {
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
			Reveal::Output(_) => out.heads.push(1 << 40 | u64::from(p.id)),
			Reveal::Argument(index) => {
				let Some(argument) = p.arguments.get(index) else {
					continue;
				};
				match head_key(argument) {
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

fn head_key(v: &Value) -> Option<u64> {
	match v {
		Value::Primitive(p) => Some(1 << 40 | u64::from(p.id)),
		Value::Constant(c) => Some(u64::from(c.id)),
		Value::Variable(_) => None,
	}
}

pub(super) fn decomposition_targets(p: &Primitive) -> Option<(Vec<Value>, Vec<Value>)> {
	if primitive_core_reveals_args(p.id) {
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
	Some((revealed_values(p, &rule.reveals), given))
}

fn revealed_values(p: &Primitive, reveals: &[Reveal]) -> Vec<Value> {
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
		let wanted = head_key(goal);
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
			&& crate::theory::reused(p, self.attacker).is_some()
		{
			routes.push((revealed_values(p, &rule.reveals), Vec::new(), None));
		}
		let capabilities = self.shared.capabilities;
		if !capabilities.is_empty()
			&& let Ok(spec) = primitive_get(p.id)
		{
			let revealed = revealed_values(p, &spec.weak_reveals);
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
		if routes.is_empty() {
			let mut out = Vec::new();
			if blocked {
				for (shaped, bound) in self.shape_for_decomposition(p, s) {
					let shaped = Value::Primitive(shaped);
					let mut memo = DecompositionMemo::default();
					out.extend(self.solve_decomposition_from(&shaped, goal, &bound, &mut memo));
				}
				out = dedupe(out);
			}
			memo.insert(key, (Arc::clone(p), out.clone()));
			return out;
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
		let out = dedupe(out);
		memo.insert(key, (Arc::clone(p), out.clone()));
		out
	}

	fn shape_for_decomposition(
		&self,
		p: &Primitive,
		s: &Substitution,
	) -> Vec<(Arc<Primitive>, Substitution)> {
		let Some(rule) = primitive_get(p.id)
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
