/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::{Cell, RefCell};
use std::sync::Arc;

use crate::equivalence::equivalent_primitives;
use crate::hashing::collect_subterm_hashes;
use crate::primitive::*;
use crate::theory::{forgeable_by_reuse, same_fixed};
use crate::types::*;
use crate::value::value_nil;

use super::matching::{match_value, match_values, unify};
use super::symbolic::SymbolicState;
use super::vars::{
	Substitution, apply, as_var, bind, contains_var, dedupe, same_substitution, substitution_hash,
};

struct SolvedGoal {
	goal: Value,
	bindings: Substitution,
	solutions: Vec<Substitution>,
}

type GoalMemo = IdMap<(u64, u64), Vec<SolvedGoal>>;

pub(crate) struct Deducer<'a> {
	attacker: &'a AttackerState,
	capabilities: Arc<CapabilityIndex>,
	wire_terms: Vec<Value>,
	slot_terms: Vec<(ValueId, Value)>,
	memo: RefCell<GoalMemo>,
	active: RefCell<Vec<(u64, Value)>>,
	cycles_cut: Cell<usize>,
	basis: Arc<IdSet<u64>>,
	by_head: IdMap<(PrimitiveId, usize), Vec<usize>>,
	fresh: Cell<u32>,
	fresh_end: u32,
}

impl<'a> Deducer<'a> {
	#[cfg(test)]
	pub(crate) fn new(
		ps: &PrincipalState,
		attacker: &'a AttackerState,
		sym: &'a SymbolicState,
	) -> Self {
		let mut known = IdSet::default();
		for held in attacker.known.iter() {
			collect_subterm_hashes(held, &mut known);
		}
		Self::with_basis(ps, attacker, sym, known)
	}

	pub(crate) fn with_basis(
		ps: &PrincipalState,
		attacker: &'a AttackerState,
		sym: &'a SymbolicState,
		mut basis: IdSet<u64>,
	) -> Self {
		for term in &sym.terms {
			collect_subterm_hashes(term, &mut basis);
		}
		Self::in_lane(ps, attacker, sym, Arc::new(basis), 0)
	}

	pub(crate) fn in_lane(
		ps: &PrincipalState,
		attacker: &'a AttackerState,
		sym: &'a SymbolicState,
		basis: Arc<IdSet<u64>>,
		lane: u32,
	) -> Self {
		let (fresh, fresh_end) = super::vars::free_lane_bounds(lane);
		let mut wire_terms = Vec::new();
		for (idx, meta) in ps.meta.iter().enumerate() {
			if meta.wire.is_empty() && !meta.constant.leaked {
				continue;
			}
			if sym.is_var_slot(idx) {
				continue;
			}
			if let Some(term) = sym.terms.get(idx) {
				wire_terms.push(term.clone());
			}
		}
		let mut slot_terms = Vec::new();
		for &slot in &sym.var_slots {
			if let Some(Some(term)) = sym.var_terms.get(slot)
				&& as_var(term).is_none()
			{
				slot_terms.push((super::vars::attacker_var_id(slot), term.clone()));
			}
		}

		let mut by_head: IdMap<(PrimitiveId, usize), Vec<usize>> = IdMap::default();
		for (at, held) in attacker.known.iter().enumerate() {
			if let Value::Primitive(p) = held {
				by_head
					.entry((p.id, p.arguments.len()))
					.or_default()
					.push(at);
			}
		}

		Deducer {
			attacker,
			capabilities: ps.capabilities.clone(),
			wire_terms,
			slot_terms,
			basis,
			by_head,
			memo: RefCell::new(IdMap::default()),
			active: RefCell::new(Vec::new()),
			cycles_cut: Cell::new(0),
			fresh: Cell::new(fresh),
			fresh_end,
		}
	}

	pub(crate) fn basis(&self) -> Arc<IdSet<u64>> {
		Arc::clone(&self.basis)
	}

	pub(crate) fn solve(&self, goal: &Value, s: &Substitution) -> Vec<Substitution> {
		let mut out = Vec::new();
		self.solve_into(goal, s, &mut out);
		dedupe(out)
	}

	fn solve_into(&self, goal: &Value, s: &Substitution, out: &mut Vec<Substitution>) {
		let g = apply(goal, s);
		let key = g.hash_value();
		if !contains_var(&g) && self.attacker.knows(&g).is_some() {
			out.push(s.clone());
			return;
		}

		let cycling = self
			.active
			.borrow()
			.iter()
			.any(|(seen, goal)| *seen == key && goal.equivalent(&g, true));
		if cycling {
			self.cycles_cut.set(self.cycles_cut.get() + 1);
			return;
		}
		let memo_key = (key, substitution_hash(s));
		let cached = self.memo.borrow().get(&memo_key).and_then(|bucket| {
			bucket
				.iter()
				.find(|entry| {
					entry.goal.equivalent(&g, true) && same_substitution(&entry.bindings, s)
				})
				.map(|entry| entry.solutions.clone())
		});
		if let Some(solutions) = cached {
			out.extend(solutions);
			return;
		}

		let cycles_before = self.cycles_cut.get();
		self.active.borrow_mut().push((key, g.clone()));
		let mut local = Vec::new();
		self.solve_rules(&g, s, &mut local);
		self.active.borrow_mut().pop();
		local = dedupe(local);

		if self.cycles_cut.get() == cycles_before {
			self.memo
				.borrow_mut()
				.entry(memo_key)
				.or_default()
				.push(SolvedGoal {
					goal: g,
					bindings: s.clone(),
					solutions: local.clone(),
				});
		}
		out.extend(local);
	}

	fn fresh_var(&self) -> Value {
		let n = self.fresh.get();
		assert!(
			n < self.fresh_end,
			"a solver lane ran out of fresh variables"
		);
		self.fresh.set(n + 1);
		super::vars::free_var(n)
	}

	fn rewrite_shapes(&self, outer: &Primitive, rule: &RewriteRule) -> Vec<Value> {
		build_rewrite_shapes_with(outer, rule, || self.fresh_var())
	}

	fn rewrite_shape_yielding(
		&self,
		outer: &Primitive,
		rule: &RewriteRule,
		target: &Value,
	) -> Option<Value> {
		let empty = Substitution::default();
		for shape in self.rewrite_shapes(outer, rule) {
			let Value::Primitive(inner) = &shape else {
				continue;
			};
			let Some(bound) = unify(&rule.to.apply(inner), target, &empty) else {
				continue;
			};
			return Some(apply(&shape, &bound));
		}
		None
	}

	fn tuple_shapes(&self, p: &Primitive, at_output: Option<&Value>) -> Vec<Value> {
		let Some(tuple) = primitive_projects(p.id) else {
			return Vec::new();
		};
		let Ok(tuple_spec) = primitive_def(tuple) else {
			return Vec::new();
		};
		let mut out = Vec::new();
		for arity in tuple_spec.arity().iter().map(|a| *a as usize) {
			if p.output >= arity {
				continue;
			}
			let mut arguments: Vec<Value> = (0..arity).map(|_| self.fresh_var()).collect();
			if let Some(target) = at_output {
				arguments[p.output] = target.clone();
			}
			out.push(Value::primitive(tuple, arguments, 0));
		}
		out
	}

	fn bind_from_shape(
		&self,
		shape: &Value,
		var_id: ValueId,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		for candidate in self.solve(shape, s) {
			let ground = apply(shape, &candidate);
			if contains_var(&ground) {
				continue;
			}
			let mut extended = candidate;
			if bind(&mut extended, var_id, ground) {
				out.push(extended);
			}
		}
	}

	fn solve_rules(&self, g: &Value, s: &Substitution, out: &mut Vec<Substitution>) {
		if let Some(id) = as_var(g) {
			if super::vars::is_free_var_id(id) {
				out.push(s.clone());
				return;
			}
			let mut extended = s.clone();
			extended.insert(id, value_nil());
			out.push(extended);
			return;
		}

		if let Value::Primitive(pattern) = g
			&& contains_var(g)
		{
			let head = (pattern.id, pattern.arguments.len());
			for &at in self.by_head.get(&head).map(Vec::as_slice).unwrap_or(&[]) {
				let Some(known) = self.attacker.known.get(at) else {
					continue;
				};
				for bound in match_values(g, known, s) {
					out.extend(self.require_constructible(&bound, s, true));
				}
			}
		}

		self.solve_by_wire(g, s, out);

		match g {
			Value::Primitive(p) => {
				self.solve_primitive(p, s, out);
				self.solve_by_malleability(p, s, out);
				self.solve_by_reuse(p, s, out);
				self.solve_by_combination(p, s, out);
			}
			Value::Constant(_) => {}
		}

		self.solve_by_decomposition(g, s, out);
	}

	fn solve_by_combination(
		&self,
		target: &Primitive,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		for (_, rule) in combines_into(target.id) {
			if target.arguments.len() != 1 + rule.carry.len() {
				continue;
			}
			let Some(reveal) = primitive_get(rule.split)
				.ok()
				.and_then(|split| split.recompose.as_ref())
				.map(|recompose| recompose.reveal)
			else {
				continue;
			};
			let arity = primitive_get(rule.partial)
				.ok()
				.and_then(|partial| partial.arity.first().copied())
				.unwrap_or(0)
				.max(0) as usize;
			for split in self.held_splits(rule) {
				let Some(secret) = split.arguments.get(reveal) else {
					continue;
				};
				let Some(bound) = match_value(&target.arguments[0], secret, s) else {
					continue;
				};
				let shared: Vec<Value> = rule
					.agree
					.iter()
					.map(|&i| match rule.carry.iter().position(|&c| c == i) {
						Some(at) => target.arguments[1 + at].clone(),
						None => self.fresh_var(),
					})
					.collect();
				let threshold = split.threshold;
				let mut frontier: Vec<(Substitution, usize)> = vec![(bound, 0)];
				let mut done: Vec<Substitution> = Vec::new();
				for output in 0..MAX_SHARES {
					let after = MAX_SHARES - output - 1;
					let share = Value::Primitive(Arc::new(split.with_output(output)));
					let mut local = Vec::new();
					let arguments: Vec<Value> = (0..arity)
						.map(|i| {
							if i == rule.share {
								share.clone()
							} else if let Some(at) = rule.agree.iter().position(|&a| a == i) {
								shared[at].clone()
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
						let mut solved = Vec::new();
						self.solve_into(&partial, candidate, &mut solved);
						for solution in dedupe(solved) {
							let solution = super::vars::remove_local_bindings(solution, &local);
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
				out.extend(dedupe(done));
			}
		}
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

	fn solve_by_reuse(&self, target: &Primitive, s: &Substitution, out: &mut Vec<Substitution>) {
		let Some(rule) = reuse_rule(target.id) else {
			return;
		};
		let mut offered: Vec<&Value> = Vec::new();
		for pair in self.attacker.reused.iter() {
			let Value::Primitive(held) = &pair[0] else {
				continue;
			};
			if held.id != target.id || held.arguments.len() != target.arguments.len() {
				continue;
			}
			if self.attacker.knows(&pair[0]).is_none() || self.attacker.knows(&pair[1]).is_none() {
				continue;
			}
			if offered.iter().any(|seen| same_fixed(seen, &pair[0])) {
				continue;
			}
			offered.push(&pair[0]);
			let mut fixed = s.clone();
			let mut aligned = true;
			for &at in &rule.fixed {
				match match_value(&target.arguments[at], &held.arguments[at], &fixed) {
					Some(next) => fixed = next,
					None => {
						aligned = false;
						break;
					}
				}
			}
			if !aligned {
				continue;
			}
			let mut frontier = vec![fixed];
			for (i, argument) in target.arguments.iter().enumerate() {
				if rule.forgeable.contains(&i) {
					continue;
				}
				let mut next = Vec::new();
				for candidate in &frontier {
					self.solve_into(argument, candidate, &mut next);
				}
				if next.is_empty() {
					frontier.clear();
					break;
				}
				frontier = dedupe(next);
			}
			out.extend(frontier);
		}
	}

	fn solve_by_malleability(
		&self,
		target: &Primitive,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let Ok(spec) = primitive_get(target.id) else {
			return;
		};
		if spec.malleable_vary.is_empty() {
			return;
		}
		for known in self.attacker.known.iter() {
			let Value::Primitive(held) = known else {
				continue;
			};
			if held.id != target.id
				|| held.output != target.output
				|| held.arguments.len() != target.arguments.len()
			{
				continue;
			}
			if !self.capability_in_force(held, Capability::Malleable) {
				continue;
			}
			let mut fixed = s.clone();
			let mut aligned = true;
			for (i, (want, have)) in target
				.arguments
				.iter()
				.zip(held.arguments.iter())
				.enumerate()
			{
				if spec.malleable_vary.contains(&i) {
					continue;
				}
				match match_value(want, have, &fixed) {
					Some(next) => fixed = next,
					None => {
						aligned = false;
						break;
					}
				}
			}
			if !aligned {
				continue;
			}
			let mut frontier = vec![fixed];
			for &i in &spec.malleable_vary {
				let Some(want) = target.arguments.get(i) else {
					continue;
				};
				let mut next = Vec::new();
				for candidate in &frontier {
					self.solve_into(want, candidate, &mut next);
				}
				if next.is_empty() {
					frontier.clear();
					break;
				}
				frontier = dedupe(next);
			}
			out.extend(frontier);
		}
	}

	fn solve_by_wire(&self, goal: &Value, s: &Substitution, out: &mut Vec<Substitution>) {
		for term in &self.wire_terms {
			if !contains_var(term) {
				continue;
			}
			for bound in match_values(term, goal, s) {
				out.extend(self.require_constructible(&bound, s, false));
			}
			self.solve_by_oracle(term, goal, s, out);
			self.solve_by_rewrite_match(term, goal, s, out);
		}
	}

	fn solve_by_rewrite_match(
		&self,
		term: &Value,
		goal: &Value,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let Value::Primitive(p) = term else {
			return;
		};
		let Some(rule) = primitive_get(p.id).ok().and_then(|s| s.rewrite.as_ref()) else {
			return;
		};
		let Some(Value::Primitive(inner)) = p.arguments.get(rule.from) else {
			return;
		};
		if inner.id != rule.id {
			return;
		}
		let filter = rule.filter;

		let Some(mut current) = match_value(&rule.to.apply(inner), goal, s) else {
			return;
		};

		for (outer_idx, inner_idxs) in &rule.matching {
			let Some(outer_arg) = p.arguments.get(*outer_idx) else {
				return;
			};
			let mut satisfied = false;
			for &inner_idx in inner_idxs {
				let Some(inner_arg) = inner.arguments.get(inner_idx) else {
					continue;
				};
				let (filtered, valid) = filter(p, outer_arg, inner_idx);
				if !valid {
					continue;
				}
				if let Some(next) = match_value(&filtered, inner_arg, &current)
					.or_else(|| match_value(inner_arg, &filtered, &current))
				{
					current = next;
					satisfied = true;
					break;
				}
			}
			if !satisfied {
				return;
			}
		}

		out.extend(self.require_constructible(&current, s, false));
	}

	fn solve_by_oracle(
		&self,
		term: &Value,
		goal: &Value,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let Value::Primitive(p) = term else {
			return;
		};
		let Some(rule) = primitive_get(p.id).ok().and_then(|s| s.rewrite.as_ref()) else {
			return;
		};
		let Some(from) = p.arguments.get(rule.from) else {
			return;
		};
		let Some(var_id) = as_var(from) else {
			return;
		};
		if !self.basis.contains(&goal.hash_value()) {
			return;
		}
		let Some(shape) = self.rewrite_shape_yielding(p, rule, goal) else {
			return;
		};
		self.bind_from_shape(&shape, var_id, s, out);
	}

	fn solve_primitive(&self, p: &Primitive, s: &Substitution, out: &mut Vec<Substitution>) {
		self.solve_primitive_arguments(p, s, out);
		if let Some(swapped) = commutativity_swap(p) {
			self.solve_primitive_arguments(&swapped, s, out);
		}
	}

	fn solve_primitive_arguments(
		&self,
		p: &Primitive,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let forgeable_secret = self.forgeable_secret(p);
		let by_reuse = forgeable_by_reuse(p, self.attacker);
		let mut frontier = vec![s.clone()];
		for (i, arg) in p.arguments.iter().enumerate() {
			let exempt = Some(i) == forgeable_secret || by_reuse.contains(&i);
			let mut next = Vec::new();
			for candidate in &frontier {
				self.solve_into(arg, candidate, &mut next);
			}
			if exempt {
				next.extend(frontier.iter().cloned());
			} else if next.is_empty() {
				return;
			}
			frontier = dedupe(next);
		}
		out.extend(frontier);
	}

	fn forgeable_secret(&self, p: &Primitive) -> Option<usize> {
		if !self.capability_in_force(p, Capability::Forgeable) {
			return None;
		}
		primitive_get(p.id).ok()?.forgeable_secret
	}

	fn capability_in_force(&self, p: &Primitive, cap: Capability) -> bool {
		if self.capabilities.is_empty() {
			return false;
		}
		let phase = self.attacker.current_phase;
		if self.capabilities.in_force(p, cap, phase) {
			return true;
		}
		let pattern = Value::Primitive(Arc::new(p.clone()));
		if !contains_var(&pattern) {
			return false;
		}
		let empty = Substitution::default();
		self.capabilities.annotated_terms().any(|(term, caps)| {
			caps.in_force(cap, phase)
				&& matches!(term, Value::Primitive(q) if q.id == p.id)
				&& match_value(&pattern, term, &empty).is_some()
		})
	}

	fn solve_by_decomposition(&self, goal: &Value, s: &Substitution, out: &mut Vec<Substitution>) {
		for term in &self.wire_terms {
			let Value::Primitive(p) = term else {
				continue;
			};
			if primitive_is_core(p.id) {
				continue;
			}
			let Some(rule) = primitive_get(p.id).ok().and_then(|s| s.decompose.as_ref()) else {
				continue;
			};
			for reveal in &rule.reveals {
				let revealed = match *reveal {
					Reveal::Argument(index) => match p.arguments.get(index) {
						Some(argument) => argument.clone(),
						None => continue,
					},
					Reveal::Output(output) => Value::Primitive(Arc::new(p.with_output(output))),
				};
				let Some(aligned) = match_value(&revealed, goal, s) else {
					continue;
				};
				let filter_fn = rule.filter;

				let mut frontier = vec![aligned];
				let mut viable = true;
				for &arg_idx in rule.given.iter() {
					let Some(arg) = p.arguments.get(arg_idx) else {
						viable = false;
						break;
					};
					let (filtered, valid) = filter_fn(p, arg, arg_idx);
					if !valid {
						viable = false;
						break;
					}
					let mut next = Vec::new();
					for candidate in &frontier {
						self.solve_into(&filtered, candidate, &mut next);
					}
					if next.is_empty() {
						viable = false;
						break;
					}
					frontier = dedupe(next);
				}
				if viable {
					out.extend(frontier);
				}
			}
		}
	}

	pub(crate) fn forgeable_shapes(&self, sym: &SymbolicState, var_id: ValueId) -> Vec<Value> {
		let mut out = Vec::new();
		let mut seen = IdSet::default();
		for term in &sym.terms {
			self.collect_forgeable(term, var_id, &mut out, &mut seen);
		}
		out
	}

	fn collect_forgeable(
		&self,
		v: &Value,
		var_id: ValueId,
		out: &mut Vec<Value>,
		seen: &mut IdSet<usize>,
	) {
		match v {
			Value::Primitive(p) => {
				if !seen.insert(Arc::as_ptr(p) as usize) {
					return;
				}
				if let Some(rule) = primitive_get(p.id).ok().and_then(|s| s.rewrite.as_ref())
					&& let Some(from) = p.arguments.get(rule.from)
					&& as_var(from) == Some(var_id)
				{
					for shape in self.rewrite_shapes(p, rule) {
						if !out
							.iter()
							.any(|existing: &Value| existing.equivalent(&shape, true))
						{
							out.push(shape);
						}
					}
				}
				for a in &p.arguments {
					self.collect_forgeable(a, var_id, out, seen);
				}
			}
			Value::Constant(_) => {}
		}
	}

	pub(crate) fn constraint_goals(
		&self,
		sym: &SymbolicState,
		base: &Substitution,
	) -> Vec<Substitution> {
		let mut checked = Vec::new();
		for term in &sym.terms {
			collect_checked(term, &mut checked);
		}
		let checked = widest_checked_projections(checked);
		let mut splits: Vec<Primitive> = Vec::new();
		for term in &sym.terms {
			collect_stuck_splits(term, &mut splits);
		}
		let mut out = Vec::new();
		let mut combined: Vec<Substitution> = vec![base.clone()];
		for p in &checked {
			let solved = self.satisfy_check(p, base);
			if solved.is_empty() {
				continue;
			}
			combined = combine(&combined, &solved);
			out.extend(solved);
		}
		for p in widest_projections(&splits) {
			let solved = self.satisfy_split(&p, base);
			if solved.is_empty() {
				continue;
			}
			combined = combine(&combined, &solved);
			out.extend(solved);
		}
		out.extend(combined);
		out = dedupe(out);
		let mut seen = super::vars::SeenSubstitutions::default();
		seen.absorb(&out);
		let mut frontier = out.clone();

		let check_vars: Vec<Vec<ValueId>> = checked
			.iter()
			.map(|p| {
				let mut ids = Vec::new();
				for a in &p.arguments {
					super::vars::collect_vars(a, &mut ids);
				}
				ids
			})
			.collect();

		for _ in 0..checked.len() {
			let mut discovered = Vec::new();
			for (p, vars) in checked.iter().zip(check_vars.iter()) {
				for candidate in &frontier {
					if !vars.iter().any(|id| candidate.contains_key(id)) {
						continue;
					}
					let refined = refine_check(p, candidate);
					if equivalent_primitives(&refined, p, true)
						|| !refined.arguments.iter().any(contains_var)
						|| check_passes(&refined)
					{
						continue;
					}
					discovered.extend(self.satisfy_check(&refined, candidate));
				}
			}
			discovered = dedupe(discovered);
			discovered.retain(|s| !seen.contains(&out, s));
			if discovered.is_empty() {
				break;
			}
			out.extend(discovered.clone());
			seen.absorb(&out);
			frontier = discovered;
		}
		dedupe(out)
	}

	fn invert(&self, term: &Value, target: &Value, s: &Substitution) -> Vec<Substitution> {
		let mut out = Vec::new();
		if let Some(bound) = match_value(term, target, s) {
			out.push(bound);
		}

		let Value::Primitive(p) = term else {
			return dedupe(out);
		};

		if let Some(rule) = primitive_get(p.id).ok().and_then(|s| s.rewrite.as_ref())
			&& let Some(from) = p.arguments.get(rule.from)
			&& let Some(shape) = self.rewrite_shape_yielding(p, rule, target)
		{
			out.extend(self.invert(from, &shape, s));
		}

		if primitive_is_projection(p.id)
			&& let Some(inner) = p.arguments.first()
		{
			for candidate in self.tuple_shapes(p, Some(target)) {
				out.extend(self.invert(inner, &candidate, s));
			}
		}

		dedupe(out)
	}

	fn satisfy_split(&self, p: &Primitive, base: &Substitution) -> Vec<Substitution> {
		let Some(inner) = p.arguments.first() else {
			return Vec::new();
		};
		let Some(tuple) = primitive_projects(p.id) else {
			return Vec::new();
		};
		let Some(width) = tuple_width(tuple, p.output) else {
			return Vec::new();
		};
		let arguments: Vec<Value> = (0..width).map(|_| self.fresh_var()).collect();
		let candidate = Value::primitive(tuple, arguments, 0);
		let mut out = Vec::new();
		for bound in self.invert(inner, &candidate, base) {
			out.extend(self.require_constructible(&bound, base, false));
		}
		dedupe(out)
	}

	fn satisfy_check(&self, p: &Primitive, base: &Substitution) -> Vec<Substitution> {
		self.satisfy_check_shaped(p, base, true)
	}

	fn satisfy_check_shaped(
		&self,
		p: &Primitive,
		base: &Substitution,
		may_shape: bool,
	) -> Vec<Substitution> {
		if primitive_is_equality(p.id) && p.arguments.len() == 2 {
			let mut out = Vec::new();
			for (pattern, target) in [(0usize, 1usize), (1, 0)] {
				for bound in self.invert(&p.arguments[pattern], &p.arguments[target], base) {
					out.extend(self.require_constructible(&bound, base, false));
				}
			}
			return dedupe(out);
		}

		if primitive_is_projection(p.id)
			&& let Some(inner) = p.arguments.first()
		{
			let mut out = Vec::new();
			for candidate in self.tuple_shapes(p, None) {
				for bound in self.invert(inner, &candidate, base) {
					out.extend(self.require_constructible(&bound, base, false));
				}
			}
			return dedupe(out);
		}

		let Some(rule) = primitive_get(p.id).ok().and_then(|s| s.rewrite.as_ref()) else {
			return Vec::new();
		};
		let Some(from) = p.arguments.get(rule.from) else {
			return Vec::new();
		};
		let shapes = self.rewrite_shapes(p, rule);
		if shapes.is_empty() {
			if !may_shape {
				return Vec::new();
			}
			return self.satisfy_check_by_shaping(p, rule, base);
		}
		let mut out = Vec::new();
		if let Some(var_id) = as_var(from) {
			for shape in &shapes {
				self.bind_from_shape(shape, var_id, base, &mut out);
			}
			return dedupe(out);
		}
		for shape in &shapes {
			for bound in self.invert(from, shape, base) {
				out.extend(self.require_constructible(&bound, base, false));
			}
		}
		dedupe(out)
	}

	fn satisfy_check_by_shaping(
		&self,
		p: &Primitive,
		rule: &RewriteRule,
		base: &Substitution,
	) -> Vec<Substitution> {
		let filter = rule.filter;
		let mut out = Vec::new();
		for (outer_idx, inner_idxs) in &rule.matching {
			let Some(outer_arg) = p.arguments.get(*outer_idx) else {
				continue;
			};
			if !contains_var(outer_arg) {
				continue;
			}
			if inner_idxs.iter().any(|&i| filter(p, outer_arg, i).1) {
				continue;
			}
			let Some(required) = crate::primitive::key_derivation_of(self.fresh_var()) else {
				continue;
			};
			if !inner_idxs.iter().any(|&i| filter(p, &required, i).1) {
				continue;
			}
			for bound in self.invert(outer_arg, &required, base) {
				let refined = refine_check(p, &bound);
				if equivalent_primitives(&refined, p, true) {
					continue;
				}
				out.extend(self.satisfy_check_shaped(&refined, &bound, false));
			}
		}
		dedupe(out)
	}

	fn require_constructible(
		&self,
		s: &Substitution,
		base: &Substitution,
		slots_only: bool,
	) -> Vec<Substitution> {
		let mut obligations: Vec<(ValueId, &Value)> = s
			.iter()
			.filter(|(id, _)| {
				!base.contains_key(*id) && !(slots_only && super::vars::is_free_var_id(**id))
			})
			.map(|(id, v)| (*id, v))
			.collect();
		obligations.sort_by_key(|(id, _)| *id);

		let mut frontier = vec![s.clone()];
		for (id, obligation) in obligations {
			let wire = self
				.slot_terms
				.iter()
				.find(|(slot_id, _)| *slot_id == id)
				.map(|(_, term)| apply(term, s));
			let obligation = wire.as_ref().unwrap_or(obligation);
			let mut next = Vec::new();
			for candidate in &frontier {
				self.solve_into(obligation, candidate, &mut next);
			}
			if next.is_empty() {
				return Vec::new();
			}
			frontier = dedupe(next);
		}
		frontier
	}
}

fn tuple_width(tuple: PrimitiveId, output: usize) -> Option<usize> {
	primitive_def(tuple)
		.ok()?
		.arity()
		.iter()
		.map(|&a| a.max(0) as usize)
		.filter(|&a| a > output)
		.min()
}

fn collect_stuck_splits(v: &Value, out: &mut Vec<Primitive>) {
	for term in crate::value::subterms(v) {
		if let Value::Primitive(p) = term
			&& primitive_is_projection(p.id)
			&& p.arguments.first().is_some_and(contains_var)
			&& !out.iter().any(|q| equivalent_primitives(q, p, true))
		{
			out.push((**p).clone());
		}
	}
}

fn widest_checked_projections(checked: Vec<Primitive>) -> Vec<Primitive> {
	let splits: Vec<Primitive> = checked
		.iter()
		.filter(|p| primitive_is_projection(p.id))
		.cloned()
		.collect();
	if splits.is_empty() {
		return checked;
	}
	let widest = widest_projections(&splits);
	checked
		.into_iter()
		.filter(|p| {
			!primitive_is_projection(p.id)
				|| widest.iter().any(|q| equivalent_primitives(q, p, true))
		})
		.collect()
}

fn widest_projections(splits: &[Primitive]) -> Vec<Primitive> {
	let mut out: Vec<Primitive> = Vec::new();
	for p in splits {
		match out.iter_mut().find(|q| {
			q.arguments
				.first()
				.zip(p.arguments.first())
				.is_some_and(|(a, b)| a.equivalent(b, true))
		}) {
			Some(existing) => {
				if p.output > existing.output {
					*existing = p.clone();
				}
			}
			None => out.push(p.clone()),
		}
	}
	out
}

fn refine_check(p: &Primitive, s: &Substitution) -> Primitive {
	let arguments: Vec<Value> = p
		.arguments
		.iter()
		.map(|a| crate::theory::reduce_once(&apply(a, s)))
		.collect();
	p.with_arguments(arguments)
}

fn check_passes(p: &Primitive) -> bool {
	crate::theory::can_rewrite(&Arc::new(p.clone())).0
}

fn collect_checked(v: &Value, out: &mut Vec<Primitive>) {
	for term in crate::value::subterms(v) {
		if let Value::Primitive(p) = term
			&& p.instance_check
			&& !out.iter().any(|q| equivalent_primitives(q, p, true))
		{
			out.push((**p).clone());
		}
	}
}

pub(crate) fn build_rewrite_shapes_with(
	outer: &Primitive,
	rule: &RewriteRule,
	mut fill: impl FnMut() -> Value,
) -> Vec<Value> {
	let Ok(inner_spec) = primitive_get(rule.id) else {
		return Vec::new();
	};
	let Some(&arity) = inner_spec.arity.first() else {
		return Vec::new();
	};
	let arity = arity as usize;
	let filter = rule.filter;

	let mut partials: Vec<(Vec<Value>, Vec<usize>)> =
		vec![((0..arity).map(|_| fill()).collect(), Vec::new())];
	for (outer_idx, inner_idxs) in &rule.matching {
		let Some(outer_arg) = outer.arguments.get(*outer_idx) else {
			return Vec::new();
		};
		let mut next = Vec::new();
		for (base, taken) in &partials {
			for &inner_idx in inner_idxs {
				if inner_idx >= arity || taken.contains(&inner_idx) {
					continue;
				}
				let (filtered, valid) = filter(outer, outer_arg, inner_idx);
				if !valid {
					continue;
				}
				let mut candidate = base.clone();
				candidate[inner_idx] = filtered;
				let mut claimed = taken.clone();
				claimed.push(inner_idx);
				next.push((candidate, claimed));
			}
		}
		if next.is_empty() {
			return Vec::new();
		}
		partials = next;
	}

	let output = rule.from_output.unwrap_or(0);
	partials
		.into_iter()
		.map(|(arguments, _)| arguments)
		.map(|arguments| Value::primitive(rule.id, arguments, output))
		.collect()
}

pub(crate) fn combine(left: &[Substitution], right: &[Substitution]) -> Vec<Substitution> {
	let mut out = Vec::new();
	for a in left {
		for b in right {
			if let Some(merged) = super::matching::merge(a, b) {
				out.push(merged);
			}
		}
	}
	dedupe(out)
}

fn dedupe_counts(candidates: Vec<(Substitution, usize)>) -> Vec<(Substitution, usize)> {
	let mut out: Vec<(Substitution, usize)> = Vec::new();
	let mut buckets: IdMap<(u64, usize), Vec<usize>> = IdMap::default();
	for (candidate, count) in candidates {
		let bucket = buckets
			.entry((substitution_hash(&candidate), count))
			.or_default();
		if bucket
			.iter()
			.any(|&at| same_substitution(&out[at].0, &candidate))
		{
			continue;
		}
		bucket.push(out.len());
		out.push((candidate, count));
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn threshold_search_keeps_one_state_per_distinct_choice() {
		let key = make_private("subset_search_key");
		let message = make_private("subset_search_message");
		let wanted = super::super::vars::free_var(10000);
		let mut split = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![key.clone()], 0);
		split.threshold = 8;
		let partials: Vec<_> = (0..16)
			.map(|output| {
				Value::primitive(
					PRIM_THRESHOLD_SIGN,
					vec![
						Value::Primitive(Arc::new(split.with_output(output))),
						make_private(&format!("subset_search_nonce_{output}")),
						value_nil(),
						message.clone(),
					],
					0,
				)
			})
			.collect();
		let attacker = make_attacker_state(partials);
		let ps = make_principal_state("Beacon", 1, vec![], vec![]);
		let sym = SymbolicState {
			terms: vec![],
			var_slots: vec![],
			var_terms: vec![],
		};
		let deducer = Deducer::new(&ps, &attacker, &sym);
		let target = Primitive::new(PRIM_SIGN, vec![key, wanted.clone()], 0);
		let mut found = Vec::new();
		deducer.solve_by_combination(&target, &Substitution::default(), &mut found);
		assert_eq!(found.len(), 1);
		assert!(apply(&wanted, &found[0]).equivalent(&message, true));
		let regrouped = attacker
			.known
			.iter()
			.enumerate()
			.map(|(i, value)| {
				let Value::Primitive(p) = value else {
					unreachable!();
				};
				let mut arguments = p.arguments.clone();
				arguments[2] = make_constant(&format!("subset_commitments_{}", i % 4));
				Value::Primitive(Arc::new(p.with_arguments(arguments)))
			})
			.collect();
		let attacker = make_attacker_state(regrouped);
		let deducer = Deducer::new(&ps, &attacker, &sym);
		let mut found = Vec::new();
		deducer.solve_by_combination(&target, &Substitution::default(), &mut found);
		assert!(
			found.is_empty(),
			"different commitments must not pool their counts"
		);
	}

	#[test]
	fn threshold_frontier_retains_distinct_counts_and_bindings_in_order() {
		let id = super::super::vars::attacker_var_id(0);
		let first = Substitution::from_iter([(id, make_private("count_first"))]);
		let second = Substitution::from_iter([(id, make_private("count_second"))]);
		let reduced = dedupe_counts(vec![
			(first.clone(), 1),
			(second.clone(), 2),
			(first.clone(), 3),
			(first.clone(), 1),
		]);
		assert_eq!(reduced.len(), 3);
		assert!(same_substitution(&reduced[0].0, &first));
		assert_eq!(reduced[0].1, 1);
		assert!(same_substitution(&reduced[1].0, &second));
		assert_eq!(reduced[1].1, 2);
		assert!(same_substitution(&reduced[2].0, &first));
		assert_eq!(reduced[2].1, 3);
	}

	#[test]
	fn forgeable_shape_collection_visits_a_shared_check_once() {
		let variable = super::super::vars::attacker_var(0, "dag_shape");
		let key = make_private("dag_shape_key");
		let check = Value::primitive(PRIM_DEC, vec![key.clone(), variable.clone()], 0);
		let mut term = check.clone();
		for _ in 0..40 {
			term = Value::primitive(PRIM_HASH, vec![term.clone(), term.clone(), term], 0);
		}
		let sym = SymbolicState {
			terms: vec![term.clone(), check, term],
			var_slots: vec![0],
			var_terms: vec![Some(variable.clone())],
		};
		let ps = make_principal_state("Beacon", 1, vec![], vec![]);
		let attacker = make_attacker_state(vec![]);
		let deducer = Deducer::new(&ps, &attacker, &sym);
		let shapes = deducer.forgeable_shapes(&sym, as_var(&variable).unwrap());
		assert_eq!(shapes.len(), 1);
		let Value::Primitive(shape) = &shapes[0] else {
			panic!("a decryption requires an encryption shape");
		};
		assert_eq!(shape.id, PRIM_ENC);
		assert!(shape.arguments[0].equivalent(&key, true));
		assert!(contains_var(&shape.arguments[1]));
	}

	#[test]
	fn constraint_collection_visits_shared_terms_once() {
		let variable = super::super::vars::attacker_var(0, "dag_constraint");
		let mut split = Primitive::new(PRIM_SPLIT, vec![variable], 0);
		split.instance_check = true;
		let mut term = Value::Primitive(Arc::new(split.clone()));
		for _ in 0..40 {
			term = Value::primitive(PRIM_HASH, vec![term.clone(), term.clone(), term], 0);
		}
		for collect in [collect_checked, collect_stuck_splits] {
			let mut found = Vec::new();
			collect(&term, &mut found);
			assert_eq!(found.len(), 1);
			assert!(equivalent_primitives(&found[0], &split, true));
		}
	}

	#[test]
	fn a_cached_goal_keeps_the_bindings_its_oracle_was_solved_under() {
		let key = make_private("memo_oracle_key");
		let message = make_constant("memo_oracle_message");
		let other = make_constant("memo_oracle_other");
		let variable = super::super::vars::attacker_var(0, "memo_oracle_input");
		let wire = Value::primitive(PRIM_MAC, vec![key.clone(), variable.clone()], 0);
		let goal = Value::primitive(PRIM_MAC, vec![key, message.clone()], 0);
		let name = make_constant("memo_oracle_wire");
		let ps = make_principal_state(
			"Beacon",
			1,
			vec![make_slot_meta(name.as_constant().unwrap(), false)],
			vec![make_slot_values(&wire, 1)],
		);
		let attacker = make_attacker_state(vec![message.clone(), other.clone()]);
		let sym = SymbolicState {
			terms: vec![wire],
			var_slots: vec![],
			var_terms: vec![],
		};
		let deducer = Deducer::new(&ps, &attacker, &sym);
		let blocked = Substitution::from_iter([(as_var(&variable).unwrap(), other)]);
		assert!(deducer.solve(&goal, &blocked).is_empty());
		let empty = Substitution::default();
		let fresh = Deducer::new(&ps, &attacker, &sym).solve(&goal, &empty);
		assert!(
			fresh
				.iter()
				.any(|s| apply(&variable, s).equivalent(&message, true))
		);
		let cached = deducer.solve(&goal, &empty);
		assert!(
			cached
				.iter()
				.any(|s| apply(&variable, s).equivalent(&message, true))
		);
	}

	#[test]
	fn free_variable_lanes_are_disjoint_and_leave_the_sequential_half_alone() {
		let (seq_start, seq_end) = super::super::vars::free_lane_bounds(0);
		assert_eq!(seq_start, 0);
		let (one_start, one_end) = super::super::vars::free_lane_bounds(1);
		let (two_start, two_end) = super::super::vars::free_lane_bounds(2);
		assert!(seq_end <= two_start);
		assert_eq!(two_end, one_start);
		assert_eq!(one_end, u32::MAX - super::super::vars::FREE_VAR_BASE + 1);
		let (last_start, _) = super::super::vars::free_lane_bounds(super::super::vars::FREE_LANES);
		assert_eq!(last_start, seq_end);
	}
	use crate::testutil::*;

	fn unblind_over(k: &Value, m: &Value, sig: &Value) -> Primitive {
		Primitive {
			id: PRIM_UNBLIND,
			arguments: vec![k.clone(), m.clone(), sig.clone()],
			output: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		}
	}

	#[test]
	fn inverting_a_rewrite_solves_for_the_target_rather_than_nesting_it() {
		let k = make_constant("inv_k");
		let m = make_constant("inv_m");
		let sk = make_constant("inv_sk");
		let sig = make_constant("inv_sig");
		let outer = unblind_over(&k, &m, &sig);
		let target = Value::primitive(PRIM_SIGN, vec![sk.clone(), m.clone()], 0);

		let ps = make_principal_state("Beacon", 1, vec![], vec![]);
		let attacker = make_attacker_state(vec![]);
		let sym = SymbolicState {
			terms: vec![],
			var_slots: vec![],
			var_terms: vec![],
		};
		let deducer = Deducer::new(&ps, &attacker, &sym);
		let rule = primitive_get(PRIM_UNBLIND)
			.expect("UNBLIND is a primitive")
			.rewrite
			.as_ref()
			.expect("UNBLIND declares a rewrite rule");

		let shape = deducer
			.rewrite_shape_yielding(&outer, rule, &target)
			.expect("UNBLIND can be inverted against a signature over its own message");

		let expected = Value::primitive(
			PRIM_SIGN,
			vec![sk, Value::primitive(PRIM_BLIND, vec![k, m], 0)],
			0,
		);
		assert!(
			shape.equivalent(&expected, true),
			"inverting a rewrite must solve `to(shape) = target` for the positions the \
			 rule leaves free, not drop the whole target into one of them. UNBLIND pins \
			 only SIGN's message, so filling SIGN's *key* with the target builds \
			 SIGN(SIGN(..), ..) and every later inversion nests that again — the search \
			 then enumerates signature chains as deep as the term bound allows. \
			 Expected {expected}, got {shape}"
		);

		let Value::Primitive(inner) = &shape else {
			panic!("a rewrite shape is a primitive");
		};
		assert!(
			rule.to.apply(inner).equivalent(&target, true),
			"the shape must actually yield the target it was built for"
		);
	}

	#[test]
	fn inverting_a_rewrite_refuses_a_target_the_rule_cannot_produce() {
		let k = make_constant("inr_k");
		let m = make_constant("inr_m");
		let other = make_constant("inr_other");
		let sig = make_constant("inr_sig");
		let outer = unblind_over(&k, &m, &sig);
		let target = Value::primitive(PRIM_SIGN, vec![make_constant("inr_sk"), other], 0);

		let ps = make_principal_state("Beacon", 1, vec![], vec![]);
		let attacker = make_attacker_state(vec![]);
		let sym = SymbolicState {
			terms: vec![],
			var_slots: vec![],
			var_terms: vec![],
		};
		let deducer = Deducer::new(&ps, &attacker, &sym);
		let rule = primitive_get(PRIM_UNBLIND)
			.expect("UNBLIND is a primitive")
			.rewrite
			.as_ref()
			.expect("UNBLIND declares a rewrite rule");

		assert!(
			deducer
				.rewrite_shape_yielding(&outer, rule, &target)
				.is_none(),
			"unblinding with blinding factor `inr_k` over message `inr_m` can only yield a \
			 signature over `inr_m`; offering a shape for a signature over something else \
			 proposes a term the rewrite does not produce"
		);
	}
}
