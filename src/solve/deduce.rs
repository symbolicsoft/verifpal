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

use super::matching::{match_value, match_values, unifiers};
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
type DecompositionMemo = IdMap<usize, (Arc<Primitive>, Vec<Substitution>)>;

pub(crate) struct Deducer<'a> {
	attacker: &'a AttackerState,
	capabilities: Arc<CapabilityIndex>,
	wire_terms: Arc<Vec<Value>>,
	slot_terms: Arc<Vec<(ValueId, Value)>>,
	memo: RefCell<GoalMemo>,
	active: RefCell<Vec<(u64, Value)>>,
	cycles_cut: Cell<usize>,
	basis: Arc<IdSet<u64>>,
	by_head: Arc<IdMap<(PrimitiveId, usize), Vec<usize>>>,
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
		let (fresh, fresh_end) = super::vars::free_lane_bounds(0);
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
			wire_terms: Arc::new(wire_terms),
			slot_terms: Arc::new(slot_terms),
			basis: Arc::new(basis),
			by_head: Arc::new(by_head),
			memo: RefCell::new(IdMap::default()),
			active: RefCell::new(Vec::new()),
			cycles_cut: Cell::new(0),
			fresh: Cell::new(fresh),
			fresh_end,
		}
	}

	pub(crate) fn lane_factory(&self) -> impl Fn(u32) -> Self + Send + Sync + use<'a> {
		let attacker = self.attacker;
		let capabilities = Arc::clone(&self.capabilities);
		let wire_terms = Arc::clone(&self.wire_terms);
		let slot_terms = Arc::clone(&self.slot_terms);
		let basis = Arc::clone(&self.basis);
		let by_head = Arc::clone(&self.by_head);
		move |lane| {
			let (fresh, fresh_end) = super::vars::free_lane_bounds(lane);
			Self {
				attacker,
				capabilities: Arc::clone(&capabilities),
				wire_terms: Arc::clone(&wire_terms),
				slot_terms: Arc::clone(&slot_terms),
				basis: Arc::clone(&basis),
				by_head: Arc::clone(&by_head),
				memo: RefCell::new(IdMap::default()),
				active: RefCell::new(Vec::new()),
				cycles_cut: Cell::new(0),
				fresh: Cell::new(fresh),
				fresh_end,
			}
		}
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
		build_rewrite_shapes_with(outer, rule, |_| self.fresh_var())
	}

	fn rewrite_shapes_yielding(
		&self,
		outer: &Primitive,
		rule: &RewriteRule,
		target: &Value,
		s: &Substitution,
	) -> Vec<(Value, Substitution)> {
		let mut out = Vec::new();
		let first = self.fresh.get();
		let shapes = self.rewrite_shapes(outer, rule);
		let locals = first..self.fresh.get();
		for shape in shapes {
			let Value::Primitive(inner) = &shape else {
				continue;
			};
			for bound in unifiers(&rule.to.apply(inner), target, s) {
				let bindings = bound
					.iter()
					.filter(|(id, _)| {
						!id.checked_sub(super::vars::FREE_VAR_BASE)
							.is_some_and(|n| locals.contains(&n))
					})
					.map(|(&id, value)| (id, apply(value, &bound)))
					.collect();
				out.push((apply(&shape, &bound), bindings));
			}
		}
		out
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
		defer_free: bool,
		out: &mut Vec<Substitution>,
	) {
		for candidate in self.solve(shape, s) {
			let ground = apply(shape, &candidate);
			if (!defer_free && contains_var(&ground))
				|| crate::value::subterms(&ground)
					.any(|term| as_var(term).is_some_and(super::vars::is_slot_var_id))
			{
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
			let mut frontier = vec![s.clone()];
			for &at in &rule.fixed {
				let mut next = Vec::new();
				for candidate in &frontier {
					next.extend(match_values(
						&target.arguments[at],
						&held.arguments[at],
						candidate,
					));
				}
				frontier = dedupe(next);
			}
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
			let mut frontier = vec![s.clone()];
			for (i, (want, have)) in target
				.arguments
				.iter()
				.zip(held.arguments.iter())
				.enumerate()
			{
				if spec.malleable_vary.contains(&i) {
					continue;
				}
				let mut next = Vec::new();
				for candidate in &frontier {
					next.extend(match_values(want, have, candidate));
				}
				frontier = dedupe(next);
			}
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
		for term in self.wire_terms.iter() {
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
		if inner.id != rule.id
			|| rule
				.from_output
				.is_some_and(|output| inner.output != output)
		{
			return;
		}
		for current in match_values(&rule.to.apply(inner), goal, s) {
			let refined = refine_check(p, &current);
			for shape in build_rewrite_shapes_with(&refined, rule, |at| inner.arguments[at].clone())
			{
				for bound in unifiers(&p.arguments[rule.from], &shape, &current) {
					out.extend(self.require_constructible(&bound, s, false));
				}
			}
		}
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
		for (shape, bound) in self.rewrite_shapes_yielding(p, rule, goal, s) {
			self.bind_from_shape(&shape, var_id, &bound, false, out);
		}
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
		let mut memo = DecompositionMemo::default();
		for term in self.wire_terms.iter() {
			out.extend(self.solve_decomposition_from(term, goal, s, &mut memo));
		}
	}

	fn solve_decomposition_from(
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
		let mut routes: Vec<_> = decomposition_targets(p)
			.into_iter()
			.map(|(revealed, given)| (revealed, given, None))
			.collect();
		if let Some(rule) = reuse_rule(p.id)
			&& crate::theory::reused(p, self.attacker).is_some()
		{
			routes.push((revealed_values(p, &rule.reveals), Vec::new(), None));
		}
		if !self.capabilities.is_empty()
			&& let Ok(spec) = primitive_get(p.id)
		{
			let reveals: Vec<_> = spec
				.weak_reveals
				.iter()
				.copied()
				.map(Reveal::Argument)
				.chain(spec.weak_reveals_output.map(Reveal::Output))
				.collect();
			let revealed = revealed_values(p, &reveals);
			if !revealed.is_empty() {
				for (annotated, caps) in self.capabilities.annotated_terms() {
					if caps.in_force(Capability::Weak, self.attacker.current_phase)
						&& matches!(annotated, Value::Primitive(q) if q.id == p.id && q.output == p.output)
					{
						routes.push((revealed.clone(), Vec::new(), Some(annotated)));
					}
				}
			}
		}
		if routes.is_empty() {
			return Vec::new();
		}
		let mut out = Vec::new();
		for (revealed, given, annotated) in routes {
			for value in revealed {
				let mut frontier: Vec<_> = match_values(&value, goal, s).collect();
				frontier.extend(self.solve_decomposition_from(&value, goal, s, memo));
				if let Some(annotated) = annotated {
					frontier = dedupe(
						frontier
							.iter()
							.flat_map(|candidate| match_values(term, annotated, candidate))
							.collect(),
					);
				}
				for required in &given {
					if frontier.is_empty() {
						break;
					}
					let mut next = Vec::new();
					for candidate in &frontier {
						self.solve_into(required, candidate, &mut next);
					}
					frontier = dedupe(next);
				}
				out.extend(frontier);
			}
		}
		let out = dedupe(out);
		memo.insert(key, (Arc::clone(p), out.clone()));
		out
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
		&mut self,
		ctx: &crate::context::VerifyContext,
		km: &ProtocolTrace,
		ps: &PrincipalState,
		sym: &SymbolicState,
	) -> Vec<Substitution> {
		let protocol = ctx.term_bound(km).protocol(km);
		for entries in Arc::make_mut(&mut self.by_head).values_mut() {
			entries.retain(|&at| {
				let constructed = match self.attacker.derivation(KnownIdx(at)) {
					Some(DerivationRecord::Reconstructed { .. }) => true,
					Some(DerivationRecord::Obtained { slot }) => {
						self.attacker.record(KnownIdx(at)).is_some_and(|record| {
							record
								.diffs
								.iter()
								.any(|diff| diff.index == *slot && diff.tainted)
						})
					}
					_ => false,
				};
				!constructed || protocol.contains(&self.attacker.known[at].hash_value())
			});
		}
		let base = &Substitution::default();
		let groups = constraint_sets(ctx, km, ps, sym);
		let mut out = Vec::new();
		let mut combined = vec![base.clone()];
		for slots in groups {
			let checked: Vec<_> = slots
				.iter()
				.filter_map(|&slot| sym.terms[slot].as_primitive().cloned())
				.collect();
			let checked = widest_checked_projections(checked);
			let mut frontier = vec![base.clone()];
			for check in &checked {
				if primitive_is_projection(check.id) {
					continue;
				}
				frontier.extend(self.satisfy_check(check, base));
				self.memo.borrow_mut().clear();
			}
			let mut frontier = super::vars::dedupe_slots(frontier);
			let mut seen = super::vars::SeenSubstitutions::default();
			let mut keys = Vec::new();
			for _ in 0..=checked.len() {
				let mut changed = false;
				for p in &checked {
					let mut next = Vec::new();
					for candidate in frontier {
						let refined = refine_check(p, &candidate);
						if check_passes(&refined) {
							next.push(candidate);
							continue;
						}
						if !refined.arguments.iter().any(contains_var) {
							if primitive_extract_bypass_key(&refined).is_some_and(|key| {
								crate::theory::obtainable(&key, ps, self.attacker)
							}) {
								next.push(candidate);
							}
							continue;
						}
						let solutions = self.satisfy_check(&refined, &candidate);
						self.memo.borrow_mut().clear();
						if solutions.is_empty() {
							next.push(candidate);
							continue;
						}
						for solution in &solutions {
							let key = super::vars::canonical_slots(solution);
							if !seen.contains(&keys, &key) {
								keys.push(key);
								seen.absorb(&keys);
								changed = true;
							}
						}
						next.extend(solutions);
					}
					frontier = super::vars::dedupe_slots(next);
				}
				if !changed {
					break;
				}
			}
			frontier.retain(|candidate| {
				checked.iter().all(|p| {
					let refined = refine_check(p, candidate);
					check_passes(&refined)
						|| primitive_extract_bypass_key(&refined).is_some_and(|key| {
							contains_var(&key) || crate::theory::obtainable(&key, ps, self.attacker)
						})
				})
			});
			combined = combine(&combined, &frontier);
			out.extend(frontier);
		}
		out.extend(combined);
		super::vars::dedupe_slots(out)
	}

	fn invert(&self, term: &Value, target: &Value, s: &Substitution) -> Vec<Substitution> {
		let term = crate::theory::reduce_once(&apply(term, s));
		let target = crate::theory::reduce_once(&apply(target, s));
		self.invert_reduced(&term, &target, s)
	}

	fn invert_reduced(&self, term: &Value, target: &Value, s: &Substitution) -> Vec<Substitution> {
		let mut out: Vec<_> = unifiers(term, target, s).collect();

		let Value::Primitive(p) = term else {
			return dedupe(out);
		};
		if out.is_empty()
			&& let Value::Primitive(q) = target
			&& p.id == q.id
			&& p.output == q.output
			&& p.threshold == q.threshold
			&& p.arguments.len() == q.arguments.len()
		{
			let mut frontier = vec![s.clone()];
			for (a, b) in p.arguments.iter().zip(&q.arguments) {
				frontier = dedupe(
					frontier
						.iter()
						.flat_map(|bindings| self.invert(a, b, bindings))
						.collect(),
				);
				if frontier.is_empty() {
					break;
				}
			}
			out.extend(frontier);
		}

		if let Some(rule) = primitive_get(p.id).ok().and_then(|s| s.rewrite.as_ref())
			&& let Some(from) = p.arguments.get(rule.from)
		{
			for (shape, bound) in self.rewrite_shapes_yielding(p, rule, target, s) {
				out.extend(self.invert(from, &shape, &bound));
			}
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
				self.bind_from_shape(shape, var_id, base, true, &mut out);
			}
			return dedupe(out);
		}
		for shape in &shapes {
			for solved in self.solve(shape, base) {
				let target = crate::theory::reduce_once(&apply(shape, &solved));
				for bound in self.invert(from, &target, &solved) {
					out.extend(self.require_constructible(&bound, base, false));
				}
			}
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

fn constraint_sets(
	ctx: &crate::context::VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
) -> Vec<Vec<usize>> {
	let mut checks: IdMap<PrincipalId, Vec<usize>> = IdMap::default();
	for (slot, (meta, value)) in ps.meta.iter().zip(&ps.values).enumerate() {
		if let Value::Primitive(p) = &value.value
			&& p.instance_check
		{
			checks.entry(meta.creator).or_default().push(slot);
		}
	}
	let mut endpoints: Vec<_> = checks
		.iter()
		.filter_map(|(owner, slots)| {
			slots
				.last()
				.map(|slot| (*owner, (ps.meta[*slot].declared_at, *slot + 1), Some(*slot)))
		})
		.collect();
	for (index, slot) in km.slots.iter().enumerate() {
		endpoints.extend(
			slot.sent_by
				.iter()
				.map(|event| (event.sender, (event.declared_at, 0), Some(index))),
		);
	}
	endpoints.extend(km.leaks.iter().map(|event| {
		(
			event.principal_id,
			(event.declared_at, 0),
			ps.index.get(&event.constant_id).copied(),
		)
	}));
	for result in ctx.results_get() {
		for query in std::iter::once(&result.query).chain(&result.variants) {
			for constant in query.constants.iter().chain(&query.message.constants) {
				if let Some(slot) = ps.index_of(constant) {
					endpoints.push((
						ps.meta[slot].creator,
						(ps.meta[slot].declared_at, slot + 1),
						Some(slot),
					));
				}
			}
		}
	}
	endpoints.sort_unstable();
	endpoints.dedup();
	let mut groups = Vec::new();
	for (owner, at, target) in endpoints {
		let mut pending: Vec<_> = checks
			.get(&owner)
			.into_iter()
			.flatten()
			.copied()
			.filter(|slot| (ps.meta[*slot].declared_at, *slot) < at)
			.collect();
		pending.extend(target);
		let mut visited = IdSet::default();
		let mut needed = IdSet::default();
		while let Some(slot) = pending.pop() {
			if !visited.insert(slot) || sym.is_var_slot(slot) {
				continue;
			}
			let meta = &ps.meta[slot];
			if let Value::Primitive(p) = &ps.values[slot].value
				&& primitive_is_projection(p.id)
			{
				needed.insert(slot);
			}
			for &check in checks.get(&meta.creator).into_iter().flatten() {
				if check <= slot {
					needed.insert(check);
					if check != slot {
						pending.push(check);
					}
				}
			}
			for constant in ps.values[slot].value.constant_leaves() {
				if let Some(dependency) = ps.index_of(constant) {
					pending.push(dependency);
				}
			}
		}
		let mut needed: Vec<_> = needed.into_iter().filter(|&slot| {
			matches!(&sym.terms[slot], Value::Primitive(p) if (p.instance_check || primitive_is_projection(p.id)) && p.arguments.iter().any(contains_var))
		}).collect();
		needed.sort_unstable();
		if !needed.is_empty() && !groups.contains(&needed) {
			groups.push(needed);
		}
	}
	groups
}

fn decomposition_targets(p: &Primitive) -> Option<(Vec<Value>, Vec<Value>)> {
	if primitive_core_reveals_args(p.id) {
		return Some((p.arguments.clone(), Vec::new()));
	}
	let rule = primitive_get(p.id).ok()?.decompose.as_ref()?;
	if rule.output.is_some_and(|output| p.output != output) {
		return None;
	}
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

pub(crate) fn build_rewrite_shapes_with(
	outer: &Primitive,
	rule: &RewriteRule,
	mut fill: impl FnMut(usize) -> Value,
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
		vec![((0..arity).map(&mut fill).collect(), Vec::new())];
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
	fn rewrite_inversion_keeps_bindings_in_the_reduct() {
		let key = make_private("invert_reduct_key");
		let message = make_constant("invert_reduct_message");
		let input = super::super::vars::attacker_var(0, "invert_reduct_input");
		let signature = super::super::vars::attacker_var(1, "invert_reduct_signature");
		let term = Value::primitive(PRIM_UNBLIND, vec![value_nil(), input.clone(), signature], 0);
		let target = Value::primitive(PRIM_SIGN, vec![key, message.clone()], 0);
		let ps = make_principal_state("Inversion", 1, vec![], vec![]);
		let sym = SymbolicState {
			terms: vec![],
			var_slots: vec![],
			var_terms: vec![],
		};
		let attacker = make_attacker_state(vec![]);
		let deducer = Deducer::new(&ps, &attacker, &sym);
		let found = deducer.invert(&term, &target, &Substitution::default());
		assert!(!found.is_empty());
		for solution in found {
			assert!(
				solution
					.keys()
					.all(|id| super::super::vars::is_slot_var_id(*id))
			);
			assert!(apply(&input, &solution).equivalent(&message, true));
			assert!(crate::theory::reduce_once(&apply(&term, &solution)).equivalent(&target, true));
		}
	}

	#[test]
	fn rewrite_inversion_retains_commutative_alternatives_and_incoming_bindings() {
		let a = make_constant("invert_alternatives_a");
		let b = make_constant("invert_alternatives_b");
		let key = make_private("invert_alternatives_key");
		let x = super::super::vars::attacker_var(0, "invert_alternatives_x");
		let y = super::super::vars::attacker_var(1, "invert_alternatives_y");
		let sig = super::super::vars::attacker_var(2, "invert_alternatives_sig");
		let dh = |a, b| {
			Value::primitive(
				PRIM_DH_KEX,
				vec![Value::primitive(PRIM_PUBKEY, vec![a], 0), b],
				0,
			)
		};
		let term = Value::primitive(
			PRIM_UNBLIND,
			vec![value_nil(), dh(x.clone(), y.clone()), sig],
			0,
		);
		let target = Value::primitive(PRIM_SIGN, vec![key, dh(a.clone(), b.clone())], 0);
		let ps = make_principal_state("Alternatives", 1, vec![], vec![]);
		let sym = SymbolicState {
			terms: vec![],
			var_slots: vec![],
			var_terms: vec![],
		};
		let attacker = make_attacker_state(vec![]);
		let deducer = Deducer::new(&ps, &attacker, &sym);
		let all = deducer.invert(&term, &target, &Substitution::default());
		assert_eq!(all.len(), 2);
		for (first, second) in [(a.clone(), b.clone()), (b, a)] {
			assert!(
				all.iter().any(|s| apply(&x, s).equivalent(&first, true)
					&& apply(&y, s).equivalent(&second, true))
			);
			let incoming = Substitution::from_iter([(as_var(&x).unwrap(), first.clone())]);
			let constrained = deducer.invert(&term, &target, &incoming);
			assert_eq!(constrained.len(), 1);
			assert!(apply(&x, &constrained[0]).equivalent(&first, true));
			assert!(apply(&y, &constrained[0]).equivalent(&second, true));
			assert!(
				crate::theory::reduce_once(&apply(&term, &constrained[0]))
					.equivalent(&target, true)
			);
		}
	}

	#[test]
	fn lanes_share_inputs_without_sharing_search_or_replay_restrictions() {
		let key = make_private("lane_inputs_key");
		let message = make_private("lane_inputs_message");
		let held = Value::primitive(PRIM_ENC, vec![key.clone(), message.clone()], 0);
		let attacker = make_attacker_state(vec![held]);
		let ps = make_principal_state("Lanes", 1, vec![], vec![]);
		let sym = SymbolicState {
			terms: vec![],
			var_slots: vec![],
			var_terms: vec![],
		};
		let original = Deducer::new(&ps, &attacker, &sym);
		let in_lane = original.lane_factory();
		let mut restricted = in_lane(1);
		let sibling = in_lane(2);
		assert!(Arc::ptr_eq(&original.by_head, &restricted.by_head));
		assert!(Arc::ptr_eq(&original.wire_terms, &sibling.wire_terms));
		assert!(Arc::ptr_eq(&original.slot_terms, &sibling.slot_terms));
		assert!(Arc::ptr_eq(&original.basis, &sibling.basis));
		Arc::make_mut(&mut restricted.by_head).clear();
		let mut variables = IdSet::default();
		for (deducer, expected) in [(&restricted, 0), (&original, 1), (&sibling, 1)] {
			let variable = deducer.fresh_var();
			assert!(variables.insert(as_var(&variable).unwrap()));
			assert!(deducer.memo.borrow().is_empty());
			let goal = Value::primitive(PRIM_ENC, vec![key.clone(), variable.clone()], 0);
			let solutions = deducer.solve(&goal, &Substitution::default());
			assert_eq!(solutions.len(), expected);
			for solution in solutions {
				assert!(apply(&variable, &solution).equivalent(&message, true));
			}
		}
	}

	#[test]
	fn rewrite_matching_keeps_the_alignment_required_by_the_nonce() {
		let a = make_private("rewrite_match_a");
		let b = make_private("rewrite_match_b");
		let secret = make_private("rewrite_match_secret");
		let x = super::super::vars::attacker_var(0, "rewrite_match_x");
		let y = super::super::vars::attacker_var(1, "rewrite_match_y");
		let dh = |a: Value, b| {
			Value::primitive(
				PRIM_DH_KEX,
				vec![Value::primitive(PRIM_PUBKEY, vec![a], 0), b],
				0,
			)
		};
		let hash = |v| Value::primitive(PRIM_HASH, vec![v], 0);
		let encrypted = Value::primitive(
			PRIM_AEAD_ENC,
			vec![
				dh(x.clone(), y.clone()),
				hash(x.clone()),
				secret.clone(),
				value_nil(),
			],
			0,
		);
		let wire = Value::primitive(
			PRIM_AEAD_DEC,
			vec![
				dh(a.clone(), b.clone()),
				hash(b.clone()),
				encrypted,
				value_nil(),
			],
			0,
		);
		let ps = make_principal_state("Rewrite", 1, vec![], vec![]);
		let sym = SymbolicState {
			terms: vec![wire.clone()],
			var_slots: vec![],
			var_terms: vec![],
		};
		let attacker = make_attacker_state(vec![a.clone(), b.clone()]);
		let deducer = Deducer::new(&ps, &attacker, &sym);
		let mut found = Vec::new();
		deducer.solve_by_rewrite_match(&wire, &secret, &Substitution::default(), &mut found);
		assert_eq!(found.len(), 1);
		assert!(apply(&x, &found[0]).equivalent(&b, true));
		assert!(apply(&y, &found[0]).equivalent(&a, true));
		assert!(crate::theory::reduce_once(&apply(&wire, &found[0])).equivalent(&secret, true));
	}

	#[test]
	fn weak_decomposition_respects_capabilities_and_their_phase() {
		let secret = make_private("weak_route_secret");
		let message = make_constant("weak_route_message");
		let variable = super::super::vars::attacker_var(0, "weak_route_input");
		let goal = Value::primitive(PRIM_MAC, vec![secret.clone(), message.clone()], 0);
		for annotated in [false, true] {
			let mut p = Primitive::new(
				PRIM_HASH,
				vec![Value::primitive(
					PRIM_MAC,
					vec![secret.clone(), variable.clone()],
					0,
				)],
				0,
			);
			if annotated {
				p.capabilities.set(Capability::Weak, 1);
			}
			let wire = Value::Primitive(Arc::new(p));
			let mut ps = make_principal_state("Weakness", 1, vec![], vec![]);
			let declared = apply(
				&wire,
				&Substitution::from_iter([(as_var(&variable).unwrap(), message.clone())]),
			);
			Arc::make_mut(&mut ps.capabilities).insert(&declared);
			let sym = SymbolicState {
				terms: vec![wire.clone()],
				var_slots: vec![],
				var_terms: vec![],
			};
			for phase in [0, 1, 2] {
				let mut attacker = make_attacker_state(vec![message.clone()]);
				attacker.current_phase = phase;
				let deducer = Deducer::new(&ps, &attacker, &sym);
				let found = deducer.solve_decomposition_from(
					&wire,
					&goal,
					&Substitution::default(),
					&mut DecompositionMemo::default(),
				);
				assert_eq!(found.len(), usize::from(annotated && phase >= 1));
				let other = Value::primitive(PRIM_MAC, vec![secret.clone(), value_nil()], 0);
				assert!(
					deducer
						.solve_decomposition_from(
							&wire,
							&other,
							&Substitution::default(),
							&mut DecompositionMemo::default(),
						)
						.is_empty()
				);
				for solution in found {
					assert!(apply(&variable, &solution).equivalent(&message, true));
				}
			}
		}
	}

	#[test]
	fn reuse_matching_keeps_the_alignment_required_by_the_nonce() {
		let a = make_private("reuse_match_a");
		let b = make_private("reuse_match_b");
		let x = super::super::vars::free_var(10000);
		let y = super::super::vars::free_var(10001);
		let dh = |a: Value, b| {
			Value::primitive(
				PRIM_DH_KEX,
				vec![Value::primitive(PRIM_PUBKEY, vec![a], 0), b],
				0,
			)
		};
		let hash = |v| Value::primitive(PRIM_HASH, vec![v], 0);
		let cipher = |key: Value, nonce: Value, message| {
			Value::primitive(PRIM_AEAD_ENC, vec![key, nonce, message, value_nil()], 0)
		};
		let first = cipher(dh(a.clone(), b.clone()), hash(b.clone()), value_nil());
		let second = cipher(dh(a.clone(), b.clone()), hash(b.clone()), hash(value_nil()));
		let mut attacker = make_attacker_state(vec![value_nil(), first.clone(), second.clone()]);
		attacker.reused = Arc::new(vec![[first, second]]);
		let ps = make_principal_state("Reuse", 1, vec![], vec![]);
		let sym = SymbolicState {
			terms: vec![],
			var_slots: vec![],
			var_terms: vec![],
		};
		let deducer = Deducer::new(&ps, &attacker, &sym);
		let target = cipher(
			dh(x.clone(), y.clone()),
			hash(x.clone()),
			hash(hash(value_nil())),
		);
		let mut found = Vec::new();
		deducer.solve_by_reuse(
			target.as_primitive().unwrap(),
			&Substitution::default(),
			&mut found,
		);
		assert_eq!(found.len(), 1);
		assert!(apply(&x, &found[0]).equivalent(&b, true));
		assert!(apply(&y, &found[0]).equivalent(&a, true));
		assert!(attacker.knows(&apply(&target, &found[0])).is_none());
		assert!(super::super::validate::derivable(
			&apply(&target, &found[0]),
			&ps,
			&attacker
		));
	}

	#[test]
	fn malleability_matching_keeps_the_constructible_alignment() {
		let a = make_private("malleable_match_a");
		let b = make_private("malleable_match_b");
		let x = super::super::vars::free_var(10000);
		let y = super::super::vars::free_var(10001);
		let dh = |a: Value, b| {
			Value::primitive(
				PRIM_DH_KEX,
				vec![Value::primitive(PRIM_PUBKEY, vec![a], 0), b],
				0,
			)
		};
		let mut held = Primitive::new(PRIM_ENC, vec![dh(a.clone(), b.clone()), value_nil()], 0);
		held.capabilities.set(Capability::Malleable, 0);
		let held = Value::Primitive(Arc::new(held));
		let mut ps = make_principal_state("Malleability", 1, vec![], vec![]);
		Arc::make_mut(&mut ps.capabilities).insert(&held);
		let attacker = make_attacker_state(vec![value_nil(), b.clone(), held]);
		let sym = SymbolicState {
			terms: vec![],
			var_slots: vec![],
			var_terms: vec![],
		};
		let deducer = Deducer::new(&ps, &attacker, &sym);
		let target = Value::primitive(PRIM_ENC, vec![dh(x.clone(), y.clone()), x.clone()], 0);
		let mut found = Vec::new();
		deducer.solve_by_malleability(
			target.as_primitive().unwrap(),
			&Substitution::default(),
			&mut found,
		);
		assert_eq!(found.len(), 1);
		assert!(apply(&x, &found[0]).equivalent(&b, true));
		assert!(apply(&y, &found[0]).equivalent(&a, true));
		assert!(attacker.knows(&apply(&target, &found[0])).is_none());
		assert!(super::super::validate::derivable(
			&apply(&target, &found[0]),
			&ps,
			&attacker
		));
	}

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
	fn constraint_sets_keep_emissions_before_later_checks() {
		let source = "attacker[active]
principal Sender[
knows public left, right
payload = CONCAT(left, right)
]
Sender -> Bob: payload
principal Bob[
first, second = SPLIT(payload)?
before = ASSERT(first, left)?
early = HASH(first)
]
Bob -> Sender: early
principal Bob[
after = ASSERT(second, right)?
late = HASH(second)
]
Bob -> Sender: late
queries[
authentication? Sender -> Bob: payload
]
";
		let model = crate::parser::parse_string("constraint-prefix.vp", source).unwrap();
		let (km, states) = crate::sanity::sanity(&model).unwrap();
		let ps = states.iter().find(|ps| ps.name == "Bob").unwrap();
		let attacker = make_attacker_state(vec![]);
		let controllable = crate::reexec::Controllable::of(&km, ps, &attacker);
		let sym = super::super::symbolic::build(&controllable, ps, &attacker);
		let ctx =
			crate::context::VerifyContext::new(&model, &states, Vec::new(), 1, None, Vec::new());
		let groups = constraint_sets(&ctx, &km, ps, &sym);
		let slot = |name: &str| {
			ps.meta
				.iter()
				.position(|meta| &*meta.constant.name == name)
				.unwrap()
		};
		let before = slot("before");
		let after = slot("after");
		assert!(
			groups
				.iter()
				.any(|group| group.contains(&before) && !group.contains(&after))
		);
		assert!(
			groups
				.iter()
				.any(|group| group.contains(&before) && group.contains(&after))
		);
	}

	#[test]
	fn nested_reuse_needs_a_held_matching_vetted_pair() {
		let wrapping = make_constant("nested_reuse_wrapping");
		let key = make_private("nested_reuse_key");
		let nonce = make_private("nested_reuse_nonce");
		let other_nonce = make_private("nested_reuse_other_nonce");
		let secret = make_private("nested_reuse_secret");
		let message = make_constant("nested_reuse_message");
		let variable = super::super::vars::attacker_var(0, "nested_reuse_input");
		let goal = Value::primitive(PRIM_MAC, vec![secret.clone(), message.clone()], 0);
		let seal = |nonce: Value, plaintext: Value| {
			Value::primitive(
				PRIM_AEAD_ENC,
				vec![key.clone(), nonce, plaintext, value_nil()],
				0,
			)
		};
		let pair = [
			seal(nonce.clone(), make_private("nested_reuse_first")),
			seal(nonce.clone(), make_private("nested_reuse_second")),
		];
		let plaintext = Value::primitive(PRIM_MAC, vec![secret, variable.clone()], 0);
		let ps = make_principal_state("Beacon", 1, vec![], vec![]);
		for case in 0..4 {
			let inner_nonce = if case == 3 {
				other_nonce.clone()
			} else {
				nonce.clone()
			};
			let wire = Value::primitive(
				PRIM_ENC,
				vec![wrapping.clone(), seal(inner_nonce, plaintext.clone())],
				0,
			);
			let sym = SymbolicState {
				terms: vec![wire.clone()],
				var_slots: vec![],
				var_terms: vec![],
			};
			let mut held = vec![wrapping.clone(), message.clone(), pair[0].clone()];
			if case != 2 {
				held.push(pair[1].clone());
			}
			let mut attacker = make_attacker_state(held);
			if case != 1 {
				attacker.reused = Arc::new(vec![pair.clone()]);
			}
			let deducer = Deducer::new(&ps, &attacker, &sym);
			let solutions = deducer.solve_decomposition_from(
				&wire,
				&goal,
				&Substitution::default(),
				&mut DecompositionMemo::default(),
			);
			assert_eq!(solutions.len(), usize::from(case == 0));
			for solution in solutions {
				assert!(apply(&variable, &solution).equivalent(&message, true));
			}
		}
	}

	#[test]
	fn nested_decomposition_requires_every_opening_input() {
		let outer = make_private("nested_open_outer");
		let nonce = make_private("nested_open_nonce");
		let inner = make_private("nested_open_inner");
		let secret = make_private("nested_open_secret");
		let message = make_constant("nested_open_message");
		let variable = super::super::vars::attacker_var(0, "nested_open_input");
		let goal = Value::primitive(PRIM_MAC, vec![secret.clone(), message.clone()], 0);
		let plaintext = Value::primitive(PRIM_MAC, vec![secret, variable.clone()], 0);
		let encrypted = Value::primitive(PRIM_ENC, vec![inner.clone(), plaintext], 0);
		let wire = Value::primitive(
			PRIM_AEAD_ENC,
			vec![outer.clone(), nonce.clone(), encrypted, value_nil()],
			0,
		);
		let ps = make_principal_state("Beacon", 1, vec![], vec![]);
		let sym = SymbolicState {
			terms: vec![wire.clone()],
			var_slots: vec![],
			var_terms: vec![],
		};
		for mask in 0..8 {
			let mut held = vec![message.clone()];
			for (at, input) in [&outer, &nonce, &inner].into_iter().enumerate() {
				if mask & (1 << at) != 0 {
					held.push(input.clone());
				}
			}
			let attacker = make_attacker_state(held);
			let deducer = Deducer::new(&ps, &attacker, &sym);
			let solutions = deducer.solve_decomposition_from(
				&wire,
				&goal,
				&Substitution::default(),
				&mut DecompositionMemo::default(),
			);
			assert_eq!(solutions.len(), usize::from(mask == 7));
			for solution in solutions {
				assert!(apply(&variable, &solution).equivalent(&message, true));
			}
		}
	}

	#[test]
	fn nested_decomposition_visits_shared_carriers_once() {
		let key = make_constant("nested_dag_key");
		let secret = make_private("nested_dag_secret");
		let message = make_constant("nested_dag_message");
		let variable = super::super::vars::attacker_var(0, "nested_dag_input");
		let goal = Value::primitive(PRIM_MAC, vec![secret.clone(), message.clone()], 0);
		let plaintext = Value::primitive(PRIM_MAC, vec![secret, variable.clone()], 0);
		let mut wire = Value::primitive(PRIM_ENC, vec![key.clone(), plaintext], 0);
		for _ in 0..40 {
			wire = Value::primitive(PRIM_CONCAT, vec![wire.clone(), wire.clone(), wire], 0);
		}
		let ps = make_principal_state("Beacon", 1, vec![], vec![]);
		let sym = SymbolicState {
			terms: vec![wire.clone()],
			var_slots: vec![],
			var_terms: vec![],
		};
		let attacker = make_attacker_state(vec![key, message.clone()]);
		let deducer = Deducer::new(&ps, &attacker, &sym);
		let mut memo = DecompositionMemo::default();
		let solutions =
			deducer.solve_decomposition_from(&wire, &goal, &Substitution::default(), &mut memo);
		assert_eq!(memo.len(), 41);
		assert_eq!(solutions.len(), 1);
		assert!(apply(&variable, &solutions[0]).equivalent(&message, true));
	}

	#[test]
	fn deduction_routes_require_the_declared_encapsulation_projection() {
		let key = make_private("route_projection_key");
		let public = Value::primitive(PRIM_PUBKEY, vec![key.clone()], 0);
		let variable = super::super::vars::attacker_var(0, "route_projection_input");
		let randomness = make_constant("route_projection_randomness");
		let secret = Value::primitive(PRIM_KEM_ENCAP, vec![public.clone(), randomness.clone()], 0);
		let name = make_constant("route_projection_wire");
		let attacker = make_attacker_state(vec![key.clone(), randomness.clone()]);
		for output in [0, 1] {
			let wire = Value::primitive(
				PRIM_KEM_ENCAP,
				vec![public.clone(), variable.clone()],
				output,
			);
			let ps = make_principal_state(
				"Beacon",
				1,
				vec![make_slot_meta(name.as_constant().unwrap(), false)],
				vec![make_slot_values(&wire, 1)],
			);
			let sym = SymbolicState {
				terms: vec![wire.clone()],
				var_slots: vec![],
				var_terms: vec![],
			};
			let deducer = Deducer::new(&ps, &attacker, &sym);
			let mut decomposed = Vec::new();
			deducer.solve_by_decomposition(&randomness, &Substitution::default(), &mut decomposed);
			let check = Value::primitive(PRIM_KEM_DECAP, vec![key.clone(), wire], 0);
			let mut rewritten = Vec::new();
			deducer.solve_by_rewrite_match(
				&check,
				&secret,
				&Substitution::default(),
				&mut rewritten,
			);
			for solutions in [decomposed, rewritten] {
				assert_eq!(solutions.len(), output);
				for solution in solutions {
					assert!(apply(&variable, &solution).equivalent(&randomness, true));
				}
			}
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

		let (shape, _) = deducer
			.rewrite_shapes_yielding(&outer, rule, &target, &Substitution::default())
			.into_iter()
			.next()
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
				.rewrite_shapes_yielding(&outer, rule, &target, &Substitution::default())
				.is_empty(),
			"unblinding with blinding factor `inr_k` over message `inr_m` can only yield a \
			 signature over `inr_m`; offering a shape for a signature over something else \
			 proposes a term the rewrite does not produce"
		);
	}
}
