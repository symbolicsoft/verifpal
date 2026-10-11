/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::Deducer;
use crate::primitive::{CombineRule, MAX_SHARES, combines_into, recompose_rule};
use crate::solve::matching::{match_values, unifiers};
use crate::solve::vars::{Distinct, Substitution, apply, as_var, contains_var, dedupe};
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

fn share_of(partial: &Primitive, rule: &CombineRule, split: &Primitive) -> Option<usize> {
	match partial.arguments.get(rule.share) {
		Some(Value::Primitive(share)) if equivalent_primitives(share, split, false) => {
			Some(share.output)
		}
		_ => None,
	}
}

fn same_values(a: &[Value], b: &[Value]) -> bool {
	a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.equivalent(y, true))
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
		let arity = crate::primitive::spec(rule.partial)
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

	pub(super) fn invert_combination(
		&self,
		pieces: &[Value],
		open: bool,
		whole: &Primitive,
		rule: &CombineRule,
		s: &Substitution,
	) -> Vec<Substitution> {
		let Some(reveal) = recompose_rule(rule.split).map(|r| r.reveal) else {
			return Vec::new();
		};
		if whole.arguments.len() != 1 + rule.carry.len() {
			return Vec::new();
		}
		let nil = value_nil();
		let own: Vec<Value> = rule
			.agree
			.iter()
			.map(|&i| {
				if let Some(at) = rule.carry.iter().position(|&c| c == i) {
					whole.arguments[1 + at].clone()
				} else if let Some(binding) = rule.bindings.iter().find(|b| b.list == i) {
					Value::primitive(binding.wrapper, vec![nil.clone()], 0)
				} else {
					nil.clone()
				}
			})
			.collect();
		let mut out = Vec::new();
		for split in self.held_splits(rule) {
			let Some(secret) = split.arguments.get(reveal) else {
				continue;
			};
			let fixed: Vec<Substitution> = unifiers(secret, &whole.arguments[0], s).collect();
			if fixed.is_empty() {
				continue;
			}
			let mut pieces = pieces.to_vec();
			let mut locals = Vec::new();
			while open && pieces.len() < split.threshold {
				let variable = self.fresh_var();
				locals.extend(as_var(&variable));
				pieces.push(variable);
			}
			if pieces.len() < split.threshold {
				continue;
			}
			let needed = pieces
				.iter()
				.filter(|piece| !matches!(piece, Value::Primitive(p) if p.id == rule.partial))
				.count();
			let reserved: Vec<usize> = pieces
				.iter()
				.filter_map(|piece| {
					let Value::Primitive(p) = piece else {
						return None;
					};
					let share = crate::theory::reduce_once(&apply(
						p.arguments.get(rule.share)?,
						&self.shared.honest,
					));
					match &share {
						Value::Primitive(share) if p.id == rule.partial => {
							equivalent_primitives(share, &split, false).then_some(share.output)
						}
						_ => None,
					}
				})
				.collect();
			let signable: Vec<usize> = (0..MAX_SHARES)
				.filter(|output| !reserved.contains(output))
				.filter(|&output| {
					let template = self.partial_template(&split, output, rule, &[]);
					!self
						.solve(&crate::solve::vars::ground_free(&template), s)
						.is_empty()
				})
				.collect();
			let held: Vec<&Primitive> = self
				.attacker
				.known
				.iter()
				.filter_map(Value::as_primitive)
				.filter(|p| {
					p.id == rule.partial
						&& share_of(p, rule, &split)
							.is_some_and(|output| !reserved.contains(&output))
				})
				.collect();
			let mut contexts: Vec<Vec<Value>> = vec![own.clone()];
			let committing = |anchor: &Primitive| {
				rule.bindings.iter().all(|binding| {
					crate::theory::combine_binding_values(anchor, binding)
						.iter()
						.any(|committed| contains_var(committed) || self.holds(committed))
				})
			};
			let anchors = held
				.iter()
				.copied()
				.filter(|anchor| needed > 0 && committing(anchor));
			for anchor in anchors.chain(
				pieces
					.iter()
					.filter_map(Value::as_primitive)
					.filter(|p| p.id == rule.partial),
			) {
				let agreed: Vec<Value> = rule
					.agree
					.iter()
					.filter_map(|&i| anchor.arguments.get(i).cloned())
					.collect();
				if agreed.len() == rule.agree.len()
					&& !contexts.iter().any(|seen| same_values(seen, &agreed))
				{
					contexts.push(agreed);
				}
			}
			for agreed in &contexts {
				let mut frontier = fixed.clone();
				for (field, &i) in agreed.iter().zip(&rule.agree) {
					if let Some(at) = rule.carry.iter().position(|&c| c == i) {
						frontier = frontier
							.iter()
							.flat_map(|bound| unifiers(field, &whole.arguments[1 + at], bound))
							.collect();
					}
				}
				for bound in dedupe(frontier) {
					let pool = self.combination_pool(
						&split,
						rule,
						agreed,
						(&held, &signable),
						needed,
						&bound,
					);
					let solved = self.assign_pieces(
						&pieces,
						rule,
						agreed,
						&pool,
						&mut Vec::new(),
						vec![bound],
					);
					out.extend(solved.into_iter().map(|solution| {
						crate::solve::vars::remove_local_bindings(solution, &locals)
					}));
				}
			}
		}
		dedupe(out)
	}

	fn partial_template(
		&self,
		split: &Primitive,
		output: usize,
		rule: &CombineRule,
		agreed: &[Value],
	) -> Value {
		let arity = crate::primitive::spec(rule.partial)
			.ok()
			.and_then(|partial| partial.arity.first().copied())
			.unwrap_or(0)
			.max(0) as usize;
		let arguments = (0..arity)
			.map(|i| {
				if i == rule.share {
					Value::Primitive(Arc::new(split.with_output(output)))
				} else if let Some(field) = rule
					.agree
					.iter()
					.position(|&a| a == i)
					.and_then(|at| agreed.get(at))
				{
					field.clone()
				} else {
					self.fresh_var()
				}
			})
			.collect();
		Value::primitive(rule.partial, arguments, 0)
	}

	fn combination_pool(
		&self,
		split: &Primitive,
		rule: &CombineRule,
		agreed: &[Value],
		(held, signable): (&[&Primitive], &[usize]),
		needed: usize,
		bound: &Substitution,
	) -> Vec<(usize, Value, bool)> {
		let mut pool: Vec<(usize, Value, bool)> = Vec::new();
		for partial in held {
			let fields = rule.agree.iter().filter_map(|&i| partial.arguments.get(i));
			if fields
				.zip(agreed)
				.all(|(field, agreed)| field.equivalent(&apply(agreed, bound), true))
				&& let Some(output) = share_of(partial, rule, split)
			{
				pool.push((
					output,
					Value::Primitive(Arc::new((*partial).clone())),
					false,
				));
			}
		}
		let mut outputs: Vec<usize> = pool
			.iter()
			.map(|(output, _, _)| *output)
			.chain(signable.iter().copied())
			.collect();
		outputs.sort_unstable();
		outputs.dedup();
		if outputs.len() < needed {
			return Vec::new();
		}
		for &output in signable {
			let template = self.partial_template(split, output, rule, agreed);
			for candidate in combination_candidates(&template, rule, bound) {
				let partial = crate::solve::vars::ground_free(&apply(&template, &candidate));
				if pool
					.iter()
					.any(|(_, seen, _)| seen.equivalent(&partial, true))
				{
					continue;
				}
				if !self.solve(&partial, bound).is_empty() {
					pool.push((output, partial, true));
				}
			}
		}
		pool
	}

	fn assign_pieces(
		&self,
		pieces: &[Value],
		rule: &CombineRule,
		agreed: &[Value],
		pool: &[(usize, Value, bool)],
		used: &mut Vec<Option<usize>>,
		frontier: Vec<Substitution>,
	) -> Vec<Substitution> {
		if frontier.is_empty() {
			return frontier;
		}
		let Some((piece, rest)) = pieces.split_first() else {
			if !used.iter().flatten().any(|&at| pool[at].2) {
				return Vec::new();
			}
			let mut frontier = frontier;
			for &at in used.iter().flatten() {
				frontier = self.solve_each(&pool[at].1, &frontier);
			}
			return frontier;
		};
		let mut out = Vec::new();
		if let Value::Primitive(p) = piece
			&& p.id == rule.partial
		{
			let mut itself = frontier.clone();
			for (field, &i) in agreed.iter().zip(&rule.agree) {
				let Some(argument) = p.arguments.get(i) else {
					itself.clear();
					break;
				};
				itself = itself
					.iter()
					.flat_map(|bound| unifiers(argument, field, bound))
					.collect();
			}
			let itself = itself
				.iter()
				.flat_map(|bound| combination_candidates(piece, rule, bound))
				.collect();
			used.push(None);
			out.extend(self.assign_pieces(rest, rule, agreed, pool, used, dedupe(itself)));
			used.pop();
		}
		for (at, (output, partial, _)) in pool.iter().enumerate() {
			if used
				.iter()
				.flatten()
				.any(|&taken| taken >= at || pool[taken].0 == *output)
			{
				continue;
			}
			let next = frontier
				.iter()
				.flat_map(|bound| self.invert(piece, partial, bound))
				.collect();
			used.push(Some(at));
			out.extend(self.assign_pieces(rest, rule, agreed, pool, used, dedupe(next)));
			used.pop();
		}
		out
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
