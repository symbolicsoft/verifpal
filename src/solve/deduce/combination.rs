/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::Deducer;
use crate::primitive::{CombineRule, MAX_SHARES, combines_into, primitive_get, recompose_rule};
use crate::solve::matching::{match_values, unifiers};
use crate::solve::vars::{Distinct, Substitution, apply, as_var, dedupe};
use crate::term::equivalence::equivalent_primitives;
use crate::term::{Primitive, Value, value_nil};

fn combination_candidates(
	partial: &Value,
	rule: &CombineRule,
	candidate: &Substitution,
) -> Vec<Substitution> {
	let mut out = vec![candidate.clone()];
	for binding in &rule.bindings {
		out = out
			.into_iter()
			.flat_map(|bound| {
				let value = apply(partial, &bound);
				let Some(p) = value.as_primitive() else {
					return Vec::new();
				};
				let Some(list) = p.arguments.get(binding.list) else {
					return Vec::new();
				};
				if as_var(list).is_some() {
					return vec![bound];
				}
				let Some(argument) = p.arguments.get(binding.argument) else {
					return Vec::new();
				};
				let mut candidates: Vec<_> = crate::theory::combine_binding_values(p, binding)
					.into_iter()
					.flat_map(|nonce| match_values(argument, &nonce, &bound))
					.collect();
				let nil = value_nil();
				let owned = Value::primitive(binding.wrapper, vec![nil.clone()], 0);
				let mut pending = vec![list];
				while let Some(entry) = pending.pop() {
					if as_var(entry).is_some() {
						for committed in match_values(entry, &owned, &bound) {
							candidates.extend(match_values(argument, &nil, &committed));
						}
					} else if let Value::Primitive(sequence) = entry
						&& sequence.id == binding.sequence
					{
						pending.extend(sequence.arguments.iter().rev());
					}
				}
				candidates
			})
			.collect();
	}
	out
}

pub(super) fn dedupe_counts(candidates: Vec<(Substitution, usize)>) -> Vec<(Substitution, usize)> {
	let mut distinct = Distinct::default();
	for (candidate, count) in candidates {
		distinct.insert(candidate, count);
	}
	distinct.into_items()
}

impl<'a> Deducer<'a> {
	pub(super) fn held_like(&self, p: &Primitive) -> impl Iterator<Item = &Value> {
		self.shared
			.by_head
			.get(&(p.id, p.arguments.len()))
			.into_iter()
			.flatten()
			.filter_map(|&at| self.attacker.known.get(at))
	}

	pub(super) fn solve_by_combination(
		&self,
		target: &Primitive,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		for (_, rule) in combines_into(target.id) {
			if target.arguments.len() != 1 + rule.carry.len() {
				continue;
			}
			let Some(reveal) = recompose_rule(rule.split).map(|r| r.reveal) else {
				continue;
			};
			for split in self.held_splits(rule) {
				let Some(secret) = split.arguments.get(reveal) else {
					continue;
				};
				let mut frontier: Vec<_> = match_values(&target.arguments[0], secret, s)
					.map(|bound| (bound, 0))
					.collect();
				if frontier.is_empty() {
					continue;
				}
				let agreed: Vec<Value> = rule
					.agree
					.iter()
					.map(|&i| match rule.carry.iter().position(|&c| c == i) {
						Some(at) => target.arguments[1 + at].clone(),
						None => self.fresh_var(),
					})
					.collect();
				if !rule.bindings.is_empty() {
					let aligned = self
						.align_with_held_partials(rule, &split, reveal, secret, &agreed, &frontier);
					frontier.extend(aligned.into_iter().map(|candidate| (candidate, 0)));
					frontier = dedupe_counts(frontier);
				}
				out.extend(self.gather_partials(target, rule, &split, &agreed, frontier));
			}
		}
	}

	fn align_with_held_partials(
		&self,
		rule: &CombineRule,
		split: &Primitive,
		reveal: usize,
		secret: &Value,
		agreed: &[Value],
		frontier: &[(Substitution, usize)],
	) -> Vec<Substitution> {
		let mut aligned = Vec::new();
		for term in self
			.attacker
			.known
			.iter()
			.chain(self.shared.wire_terms.iter())
		{
			let Some(partial) = term.as_primitive() else {
				continue;
			};
			if partial.id != rule.partial {
				continue;
			}
			let Some(Value::Primitive(share)) = partial.arguments.get(rule.share) else {
				continue;
			};
			if share.id != split.id
				|| share.threshold != split.threshold
				|| share.instance != split.instance
			{
				continue;
			}
			let Some(source_secret) = share.arguments.get(reveal) else {
				continue;
			};
			let mut choices: Vec<_> = frontier
				.iter()
				.flat_map(|(candidate, _)| unifiers(secret, source_secret, candidate))
				.collect();
			for (field, variable) in rule.agree.iter().zip(agreed) {
				let Some(value) = partial.arguments.get(*field) else {
					choices.clear();
					break;
				};
				choices = choices
					.iter()
					.flat_map(|candidate| unifiers(variable, value, candidate))
					.collect();
			}
			aligned.extend(choices);
		}
		dedupe(aligned)
	}

	fn gather_partials(
		&self,
		target: &Primitive,
		rule: &CombineRule,
		split: &Primitive,
		agreed: &[Value],
		mut frontier: Vec<(Substitution, usize)>,
	) -> Vec<Substitution> {
		let arity = primitive_get(rule.partial)
			.ok()
			.and_then(|partial| partial.arity.first().copied())
			.unwrap_or(0)
			.max(0) as usize;
		let threshold = split.threshold;
		let mut done: Vec<Substitution> = Vec::new();
		let mut outputs: Vec<_> = (0..MAX_SHARES).collect();
		if !rule.bindings.is_empty() {
			outputs.sort_by_key(|&output| {
				!self.attacker.known.iter().any(|known| {
					let Some(partial) = known.as_primitive() else {
						return false;
					};
					partial.id == rule.partial
						&& partial
							.arguments
							.get(rule.share)
							.and_then(Value::as_primitive)
							.is_some_and(|share| {
								share.output == output && equivalent_primitives(share, split, false)
							})
				})
			});
		}
		for (position, output) in outputs.into_iter().enumerate() {
			let after = MAX_SHARES - position - 1;
			let share = Value::Primitive(Arc::new(split.with_output(output)));
			let mut local = Vec::new();
			let arguments: Vec<Value> = (0..arity)
				.map(|i| {
					if i == rule.share {
						share.clone()
					} else if let Some(at) = rule.agree.iter().position(|&a| a == i) {
						agreed[at].clone()
					} else if let Some(at) = rule.carry.iter().position(|&c| c == i) {
						target.arguments[1 + at].clone()
					} else {
						let variable = self.fresh_var();
						local.push(as_var(&variable).unwrap());
						variable
					}
				})
				.collect();
			let partial = Value::primitive(rule.partial, arguments, 0);
			let mut next = Vec::new();
			for (candidate, count) in &frontier {
				if count + after >= threshold {
					next.push((candidate.clone(), *count));
				}
				let constrained = combination_candidates(&partial, rule, candidate);
				for solution in self.solve_each(&partial, &constrained) {
					let materialized = apply(&partial, &solution);
					if !materialized
						.as_primitive()
						.is_some_and(|p| crate::theory::combine_bindings_hold(p, rule))
					{
						continue;
					}
					let solution = crate::solve::vars::remove_local_bindings(solution, &local);
					if count + 1 >= threshold {
						done.push(solution);
					} else {
						next.push((solution, count + 1));
					}
				}
			}
			if next.is_empty() {
				break;
			}
			frontier = dedupe_counts(next);
		}
		dedupe(done)
	}

	fn held_splits(&self, rule: &CombineRule) -> Vec<Arc<Primitive>> {
		let mut splits: Vec<Arc<Primitive>> = Vec::new();
		for known in self.attacker.known.iter() {
			let Value::Primitive(q) = known else {
				continue;
			};
			let share = if q.id == rule.split {
				q
			} else if q.id == rule.partial {
				match q.arguments.get(rule.share) {
					Some(Value::Primitive(share)) if share.id == rule.split => share,
					_ => continue,
				}
			} else {
				continue;
			};
			if share.threshold == 0
				|| splits
					.iter()
					.any(|seen| equivalent_primitives(seen, share, false))
			{
				continue;
			}
			splits.push(Arc::clone(share));
		}
		splits
	}
}
