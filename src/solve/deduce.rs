/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::equivalence::equivalent_primitives;
use crate::hashing::TermSet;
use crate::primitive::*;
use crate::theory::{forgeable_by_reuse, same_fixed};
use crate::types::*;
use crate::value::value_nil;

use super::matching::{match_values, unifiers};
use super::symbolic::SymbolicState;
use super::vars::{
	Distinct, FreshVariables, Substitution, apply, as_var, contains_var, dedupe, same_substitution,
	substitution_hash,
};

struct SolvedGoal {
	goal: Value,
	bindings: Substitution,
	solutions: Vec<Substitution>,
	cut: Vec<(u64, Value)>,
}

type GoalMemo = IdMap<(u64, u64), Vec<SolvedGoal>>;
type DecompositionMemo = IdMap<usize, (Arc<Primitive>, Vec<Substitution>)>;
type HeldByHead = IdMap<(PrimitiveId, usize), Vec<usize>>;
pub(crate) type Arities = IdMap<PrimitiveId, Vec<usize>>;

pub(crate) fn note_arities(v: &Value, out: &mut Arities) {
	for term in crate::value::subterms(v) {
		if let Value::Primitive(p) = term {
			let arities = out.entry(p.id).or_default();
			if let Err(at) = arities.binary_search(&p.arguments.len()) {
				arities.insert(at, p.arguments.len());
			}
		}
	}
}

struct Shared<'a> {
	capabilities: &'a CapabilityIndex,
	wire_terms: Vec<Value>,
	wire_reach: std::sync::OnceLock<Vec<Option<Arc<Reach>>>>,
	slot_terms: Vec<(VariableId, Value)>,
	honest: Substitution,
	arities: Arities,
	by_head: HeldByHead,
}

struct Bound {
	inputs: Vec<(Value, usize)>,
	declined: AtomicBool,
}

pub(crate) struct Deducer<'a> {
	attacker: &'a AttackerState,
	shared: Arc<Shared<'a>>,
	memo: RefCell<GoalMemo>,
	active: RefCell<Vec<(u64, Value)>>,
	cuts: RefCell<Vec<usize>>,
	variables: RefCell<FreshVariables>,
	bound: Option<Arc<Bound>>,
	saved: RefCell<crate::theory::SavedMemo>,
}

#[derive(Default)]
struct Reach {
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

impl<'a> Deducer<'a> {
	#[cfg(test)]
	pub(crate) fn in_test_lane(self, lane: usize) -> Self {
		self.in_scope(Arc::from(format!("root/lane/{lane}")))
	}

	#[cfg(test)]
	pub(crate) fn new(
		km: &'a ProtocolTrace,
		attacker: &'a AttackerState,
		sym: &'a SymbolicState,
	) -> Self {
		let mut known = Arities::default();
		for held in attacker.known.iter() {
			note_arities(held, &mut known);
		}
		Self::with_basis(km, attacker, sym, &known, Substitution::default())
	}

	pub(crate) fn with_basis(
		km: &'a ProtocolTrace,
		attacker: &'a AttackerState,
		sym: &'a SymbolicState,
		known: &Arities,
		honest: Substitution,
	) -> Self {
		let mut arities = known.clone();
		for term in &sym.terms {
			note_arities(term, &mut arities);
		}
		let wire_terms = km
			.slots
			.iter()
			.enumerate()
			.filter(|(idx, slot)| slot.disclosed() && !sym.is_var_slot(*idx))
			.filter_map(|(idx, _)| sym.terms.get(idx).cloned())
			.collect();
		let slot_terms = sym
			.var_slots
			.iter()
			.filter_map(|&slot| match sym.var_terms.get(slot) {
				Some(Some(term)) if as_var(term).is_none() => {
					Some((super::vars::attacker_var_id(slot), term.clone()))
				}
				_ => None,
			})
			.collect();
		let mut by_head = HeldByHead::default();
		for (at, held) in attacker.known.iter().enumerate() {
			if let Value::Primitive(p) = held {
				by_head
					.entry((p.id, p.arguments.len()))
					.or_default()
					.push(at);
			}
		}
		let shared = Shared {
			capabilities: &km.capabilities,
			wire_terms,
			wire_reach: std::sync::OnceLock::new(),
			slot_terms,
			honest,
			arities,
			by_head,
		};
		Self::with_shared(attacker, Arc::new(shared), Arc::from("root"))
	}

	fn with_shared(attacker: &'a AttackerState, shared: Arc<Shared<'a>>, scope: Arc<str>) -> Self {
		Deducer {
			attacker,
			shared,
			memo: RefCell::default(),
			active: RefCell::default(),
			cuts: RefCell::default(),
			variables: RefCell::new(FreshVariables::new(scope)),
			bound: None,
			saved: RefCell::default(),
		}
	}

	pub(crate) fn with_bound(mut self, inputs: Vec<(Value, usize)>) -> Self {
		self.bound = Some(Arc::new(Bound {
			inputs,
			declined: AtomicBool::new(false),
		}));
		self
	}

	pub(crate) fn declined_bound(&self) -> bool {
		self.bound
			.as_ref()
			.is_some_and(|bound| bound.declined.load(Ordering::Relaxed))
	}

	fn within_bound(&self, s: &Substitution) -> bool {
		let Some(bound) = &self.bound else {
			return true;
		};
		if bound
			.inputs
			.iter()
			.any(|(term, maximum)| super::control::minimum_term_depth(term, s) > *maximum)
		{
			bound.declined.store(true, Ordering::Relaxed);
			return false;
		}
		true
	}

	pub(crate) fn in_scope(mut self, scope: Arc<str>) -> Self {
		self.variables = RefCell::new(FreshVariables::new(scope));
		self
	}

	pub(crate) fn fresh_scope(&self) -> Arc<str> {
		let VariableId::Free(id) = self.variables.borrow_mut().fresh() else {
			unreachable!()
		};
		Arc::from(format!("{id}/scope"))
	}

	pub(crate) fn lanes(&self, count: usize) -> Vec<Self> {
		let scope = self.fresh_scope();
		(0..count)
			.map(|lane| {
				let mut deducer = Self::with_shared(
					self.attacker,
					Arc::clone(&self.shared),
					Arc::from(format!("{scope}/lane/{lane}")),
				);
				deducer.bound = self.bound.clone();
				deducer
			})
			.collect()
	}

	pub(crate) fn solve(&self, goal: &Value, s: &Substitution) -> Vec<Substitution> {
		let mut out = Vec::new();
		self.solve_into(goal, s, &mut out);
		dedupe(out)
	}

	fn solve_each(&self, goal: &Value, frontier: &[Substitution]) -> Vec<Substitution> {
		advance(frontier, |candidate, next| {
			self.solve_into(goal, candidate, next)
		})
	}

	fn solve_into(&self, goal: &Value, s: &Substitution, out: &mut Vec<Substitution>) {
		if !self.within_bound(s) {
			return;
		}
		let g = crate::theory::reduce_once(&apply(goal, s));
		let key = g.hash_value();
		if !contains_var(&g) && (self.attacker.knows(&g).is_some() || self.obtainable(&g)) {
			out.push(s.clone());
			return;
		}

		let cycling = self
			.active
			.borrow()
			.iter()
			.position(|(seen, goal)| *seen == key && goal.equivalent(&g, true));
		if let Some(at) = cycling {
			self.cut_at(at);
			return;
		}
		let relevant = relevant_bindings(&g, s);
		let memo_key = (key, substitution_hash(&relevant));
		{
			let memo = self.memo.borrow();
			let reused = memo.get(&memo_key).and_then(|bucket| {
				bucket.iter().find_map(|entry| {
					if !entry.goal.equivalent(&g, true)
						|| !same_substitution(&entry.bindings, &relevant)
					{
						return None;
					}
					self.active_at(&entry.cut).map(|at| (entry, at))
				})
			});
			if let Some((entry, at)) = reused {
				for i in at {
					self.cut_at(i);
				}
				out.extend(entry.solutions.iter().map(|delta| {
					let mut solution = s.clone();
					solution.extend(delta.iter().map(|(id, value)| (id.clone(), value.clone())));
					solution
				}));
				return;
			}
		}

		let depth = self.active.borrow().len();
		let outer = self.cuts.replace(Vec::new());
		self.active.borrow_mut().push((key, g.clone()));
		let mut local = Vec::new();
		self.solve_rules(&g, s, &mut local);
		self.active.borrow_mut().pop();
		local = dedupe(local);
		let inner = self.cuts.replace(outer);
		let below: Vec<usize> = inner.into_iter().filter(|&i| i < depth).collect();
		let cut: Vec<(u64, Value)> = {
			let active = self.active.borrow();
			below.iter().map(|&i| active[i].clone()).collect()
		};
		for &i in &below {
			self.cut_at(i);
		}

		if let Some(deltas) = local
			.iter()
			.map(|solution| extension_of(solution, s))
			.collect::<Option<Vec<Substitution>>>()
		{
			self.memo
				.borrow_mut()
				.entry(memo_key)
				.or_default()
				.push(SolvedGoal {
					goal: g,
					bindings: relevant,
					solutions: deltas,
					cut,
				});
		}
		out.extend(local);
	}

	fn cut_at(&self, at: usize) {
		let mut cuts = self.cuts.borrow_mut();
		if !cuts.contains(&at) {
			cuts.push(at);
		}
	}

	fn active_at(&self, goals: &[(u64, Value)]) -> Option<Vec<usize>> {
		let active = self.active.borrow();
		goals
			.iter()
			.map(|(key, goal)| {
				active
					.iter()
					.position(|(seen, held)| seen == key && held.equivalent(goal, true))
			})
			.collect()
	}

	fn obtainable(&self, v: &Value) -> bool {
		self.saved
			.borrow_mut()
			.within(self.shared.capabilities, self.attacker, || {
				crate::theory::obtainable(v, self.shared.capabilities, self.attacker)
			})
	}

	pub(crate) fn fresh_var(&self) -> Value {
		Value::Variable(self.variables.borrow_mut().fresh())
	}

	fn rewrite_shapes(&self, outer: &Primitive, rule: &RewriteRule) -> Vec<Value> {
		rewrite_shapes_from(outer, rule, |_| self.fresh_var(), false)
	}

	fn rewrite_shapes_yielding(
		&self,
		outer: &Primitive,
		rule: &RewriteRule,
		target: &Value,
		s: &Substitution,
	) -> Vec<(Value, Substitution)> {
		let mut out = Vec::new();
		let mut locals = Vec::new();
		let shapes = rewrite_shapes_from(
			outer,
			rule,
			|_| {
				let variable = self.fresh_var();
				locals.push(as_var(&variable).expect("a fresh variable"));
				variable
			},
			false,
		);
		for shape in shapes {
			let Value::Primitive(inner) = &shape else {
				continue;
			};
			for bound in unifiers(&rule.to.apply(inner), target, s) {
				let bindings = bound
					.iter()
					.filter(|(id, _)| !locals.contains(id))
					.map(|(id, value)| (id.clone(), apply(value, &bound)))
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
		let mut arities: Vec<usize> = tuple_spec
			.arity()
			.iter()
			.map(|a| *a as usize)
			.find(|&arity| p.output < arity)
			.into_iter()
			.collect();
		if let Some(inner) = p.arguments.first()
			&& let Value::Primitive(honest) =
				crate::theory::reduce_once(&apply(inner, &self.shared.honest))
			&& honest.id == tuple
			&& p.output < honest.arguments.len()
			&& !arities.contains(&honest.arguments.len())
		{
			arities.push(honest.arguments.len());
		}
		let seen: Vec<usize> = self
			.shared
			.arities
			.get(&tuple)
			.into_iter()
			.flatten()
			.copied()
			.filter(|arity| *arity > p.output && !arities.contains(arity))
			.collect();
		arities.extend(seen);
		arities
			.into_iter()
			.map(|arity| {
				let mut arguments: Vec<Value> = (0..arity).map(|_| self.fresh_var()).collect();
				if let Some(target) = at_output {
					arguments[p.output] = target.clone();
				}
				Value::primitive(tuple, arguments, 0)
			})
			.collect()
	}

	fn bind_from_shape(
		&self,
		shape: &Value,
		var_id: &VariableId,
		s: &Substitution,
		defer_free: bool,
		out: &mut Vec<Substitution>,
	) {
		for fixed in unifiers(&Value::Variable(var_id.clone()), shape, s) {
			for mut extended in self.solve(shape, &fixed) {
				let ground = apply(shape, &extended);
				if (!defer_free && contains_var(&ground))
					|| crate::value::subterms(&ground).any(|term| {
						as_var(term)
							.as_ref()
							.is_some_and(super::vars::is_slot_var_id)
					}) {
					continue;
				}
				extended.insert(var_id.clone(), ground);
				out.push(extended);
			}
		}
	}

	fn solve_rules(&self, g: &Value, s: &Substitution, out: &mut Vec<Substitution>) {
		if let Some(id) = as_var(g) {
			let mut extended = s.clone();
			if !super::vars::is_free_var_id(&id) {
				extended.insert(id, value_nil());
			}
			out.push(extended);
			return;
		}

		if let Value::Primitive(pattern) = g
			&& contains_var(g)
		{
			for known in self.held_like(pattern) {
				for bound in match_values(g, known, s) {
					out.extend(self.require_constructible(&bound, s, true));
				}
			}
		}

		self.solve_by_wire(g, s, out);

		if let Value::Primitive(p) = g {
			self.solve_primitive(p, s, out);
			self.solve_by_malleability(p, s, out);
			self.solve_by_reuse(p, s, out);
			self.solve_by_combination(p, s, out);
		}

		self.solve_by_decomposition(g, s, out);
	}

	fn held_like(&self, p: &Primitive) -> impl Iterator<Item = &Value> {
		self.shared
			.by_head
			.get(&(p.id, p.arguments.len()))
			.into_iter()
			.flatten()
			.filter_map(|&at| self.attacker.known.get(at))
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

	fn solve_by_reuse(&self, target: &Primitive, s: &Substitution, out: &mut Vec<Substitution>) {
		let Some(rule) = reuse_rule(target.id) else {
			return;
		};
		let supplied: Vec<usize> = (0..target.arguments.len())
			.filter(|i| !rule.forgeable.contains(i))
			.collect();
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
			out.extend(self.reshape(target, held, &rule.fixed, &supplied, s));
		}
	}

	fn solve_by_malleability(
		&self,
		target: &Primitive,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		if self.shared.capabilities.is_empty() {
			return;
		}
		let Ok(spec) = primitive_get(target.id) else {
			return;
		};
		if spec.malleable_vary.is_empty() {
			return;
		}
		let kept: Vec<usize> = (0..target.arguments.len())
			.filter(|i| !spec.malleable_vary.contains(i))
			.collect();
		for held in self.held_like(target) {
			let Value::Primitive(held) = held else {
				continue;
			};
			if held.output != target.output || held.threshold != target.threshold {
				continue;
			}
			if !self.shared.capabilities.in_force(
				held,
				Capability::Malleable,
				self.attacker.current_phase,
			) {
				continue;
			}
			out.extend(self.reshape(target, held, &kept, &spec.malleable_vary, s));
		}
	}

	fn reshape(
		&self,
		target: &Primitive,
		held: &Primitive,
		kept: &[usize],
		supplied: &[usize],
		s: &Substitution,
	) -> Vec<Substitution> {
		let mut frontier = vec![s.clone()];
		for &at in kept {
			frontier = match_each(&target.arguments[at], &held.arguments[at], &frontier);
		}
		for &at in supplied {
			let Some(want) = target.arguments.get(at) else {
				continue;
			};
			frontier = self.solve_each(want, &frontier);
			if frontier.is_empty() {
				break;
			}
		}
		frontier
	}

	fn solve_by_wire(&self, goal: &Value, s: &Substitution, out: &mut Vec<Substitution>) {
		for term in self.shared.wire_terms.iter() {
			if !contains_var(term) {
				continue;
			}
			for bound in unifiers(term, goal, s) {
				out.extend(self.require_constructible(&bound, s, false));
			}
			if let Value::Primitive(p) = term
				&& let Some(rule) = rewrite_rule(p.id)
			{
				self.solve_by_oracle(p, rule, goal, s, out);
				self.solve_by_rewrite_match(p, rule, goal, s, out);
			}
			if projects_a_variable(term) {
				for bound in self.invert(term, goal, s) {
					out.extend(self.require_constructible(&bound, s, false));
				}
			}
		}
	}

	fn solve_by_rewrite_match(
		&self,
		p: &Primitive,
		rule: &RewriteRule,
		goal: &Value,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
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
			for shape in
				rewrite_shapes_from(&refined, rule, |at| inner.arguments[at].clone(), false)
			{
				for bound in unifiers(&p.arguments[rule.from], &shape, &current) {
					out.extend(self.require_constructible(&bound, s, false));
				}
			}
		}
	}

	fn solve_by_oracle(
		&self,
		p: &Primitive,
		rule: &RewriteRule,
		goal: &Value,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let Some(var_id) = p.arguments.get(rule.from).and_then(as_var) else {
			return;
		};
		for (shape, bound) in self.rewrite_shapes_yielding(p, rule, goal, s) {
			self.bind_from_shape(&shape, &var_id, &bound, false, out);
		}
	}

	fn solve_primitive(&self, p: &Primitive, s: &Substitution, out: &mut Vec<Substitution>) {
		let before = out.len();
		self.solve_primitive_arguments(p, s, out);
		match commutativity_swap(p) {
			Some(swapped) => self.solve_primitive_arguments(&swapped, s, out),
			None if out.len() == before => self.solve_by_commuting(p, s, out),
			None => {}
		}
		if p.arguments.iter().any(contains_var) {
			let term = Value::Primitive(Arc::new(p.clone()));
			for bound in self.satisfy_check_shaped(p, s, true) {
				let applied = apply(&term, &bound);
				let reduced = crate::theory::reduce_once(&applied);
				if !applied.equivalent(&reduced, true) {
					self.solve_into(&reduced, &bound, out);
				}
			}
		}
	}

	fn solve_by_commuting(&self, p: &Primitive, s: &Substitution, out: &mut Vec<Substitution>) {
		let Some(rule) = commutativity_rule(p.id) else {
			return;
		};
		let Some(wrapped) = p.arguments.get(rule.wrapped) else {
			return;
		};
		if !contains_var(wrapped) {
			return;
		}
		let required = Value::primitive(rule.constructor, vec![self.fresh_var()], 0);
		let term = Value::Primitive(Arc::new(p.clone()));
		for bound in self.invert(wrapped, &required, s) {
			for shaped in self.require_constructible(&bound, s, false) {
				let reduced = crate::theory::reduce_once(&apply(&term, &shaped));
				if let Value::Primitive(q) = &reduced
					&& let Some(swapped) = commutativity_swap(q)
				{
					self.solve_primitive_arguments(&swapped, &shaped, out);
				}
			}
		}
	}

	fn solve_primitive_arguments(
		&self,
		p: &Primitive,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let capabilities = self.shared.capabilities;
		let forgeable_secret =
			capabilities.forgeable_secret_position(p, self.attacker.current_phase);
		let secret_position = primitive_get(p.id)
			.ok()
			.and_then(|spec| spec.forgeable_secret);
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
			} else if Some(i) == secret_position && !capabilities.is_empty() {
				for secret in capabilities.forgeable_secrets(p.id, self.attacker.current_phase) {
					for candidate in &frontier {
						next.extend(match_values(arg, secret, candidate));
					}
				}
			}
			if next.is_empty() {
				return;
			}
			frontier = dedupe(next);
		}
		out.extend(frontier);
	}

	fn solve_by_decomposition(&self, goal: &Value, s: &Substitution, out: &mut Vec<Substitution>) {
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

	pub(crate) fn forgeable_shapes(&self, sym: &SymbolicState, var_id: &VariableId) -> Vec<Value> {
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
		var_id: &VariableId,
		out: &mut Vec<Value>,
		seen: &mut IdSet<usize>,
	) {
		let Value::Primitive(p) = v else {
			return;
		};
		if !seen.insert(Arc::as_ptr(p) as usize) {
			return;
		}
		if let Some(rule) = rewrite_rule(p.id)
			&& p.arguments.get(rule.from).and_then(as_var).as_ref() == Some(var_id)
		{
			for shape in self.rewrite_shapes(p, rule) {
				if !out.iter().any(|existing| existing.equivalent(&shape, true)) {
					out.push(shape);
				}
			}
		}
		for a in &p.arguments {
			self.collect_forgeable(a, var_id, out, seen);
		}
	}

	pub(crate) fn constraint_goals(
		&self,
		queries: &[Query],
		km: &ProtocolTrace,
		sym: &SymbolicState,
	) -> Vec<Substitution> {
		let base = &Substitution::default();
		let groups = constraint_sets(queries, km, sym);
		let debug = super::debugging();
		let mut out = Vec::new();
		let mut combined = vec![base.clone()];
		for slots in groups {
			if debug {
				eprintln!("[search] constraints {:?}", slots);
			}
			let checked: Vec<_> = slots
				.iter()
				.filter_map(|&slot| sym.terms[slot].as_primitive().cloned())
				.collect();
			let checked = widest_checked_projections(checked);
			let mut frontier = vec![base.clone()];
			let mut seen = Distinct::default();
			loop {
				let mut changed = false;
				for (index, p) in checked.iter().enumerate() {
					if debug {
						eprintln!("[search] constraint {index}: {} bindings", frontier.len());
					}
					let mut next = Vec::new();
					for candidate in frontier {
						let refined = refine_check(p, &candidate);
						if check_passes(&refined) {
							next.push(candidate);
							continue;
						}
						if !refined.arguments.iter().any(contains_var) {
							if primitive_extract_check_key(&refined)
								.is_some_and(|key| self.obtainable(&key))
							{
								next.push(candidate);
							}
							continue;
						}
						let solutions = self.check_equations(&refined, &candidate);
						if solutions.is_empty() {
							next.push(candidate);
							continue;
						}
						for solution in &solutions {
							changed |= seen.insert(super::vars::canonical_slots(solution), ());
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
						|| primitive_extract_check_key(&refined)
							.is_some_and(|key| contains_var(&key) || self.obtainable(&key))
				})
			});
			frontier = frontier
				.iter()
				.flat_map(|candidate| {
					let solutions = self.require_constructible(candidate, base, true);
					self.memo.borrow_mut().clear();
					solutions
				})
				.collect();
			let frontier = super::vars::dedupe_slots(frontier);
			combined = combine(&combined, &frontier);
			out.extend(frontier);
		}
		out.extend(combined);
		super::vars::dedupe_slots(out)
	}

	fn check_equations(&self, p: &Primitive, base: &Substitution) -> Vec<Substitution> {
		if primitive_is_equality(p.id) && p.arguments.len() == 2 {
			let mut out = self.invert(&p.arguments[0], &p.arguments[1], base);
			out.extend(self.invert(&p.arguments[1], &p.arguments[0], base));
			return dedupe(out);
		}
		if primitive_is_projection(p.id)
			&& let Some(inner) = p.arguments.first()
		{
			return self
				.tuple_shapes(p, None)
				.iter()
				.flat_map(|shape| self.invert(inner, shape, base))
				.collect();
		}
		let Some(rule) = rewrite_rule(p.id) else {
			return Vec::new();
		};
		let Some(from) = p.arguments.get(rule.from) else {
			return Vec::new();
		};
		let mut out: Vec<_> = self
			.rewrite_shapes(p, rule)
			.iter()
			.flat_map(|shape| self.invert(from, shape, base))
			.collect();
		if out.is_empty() {
			for (refined, bound) in self.shape_check_inputs(p, rule, base) {
				out.extend(self.check_equations(&refined, &bound));
			}
		}
		dedupe(out)
	}

	fn invert(&self, term: &Value, target: &Value, s: &Substitution) -> Vec<Substitution> {
		let term = crate::theory::reduce_once(&apply(term, s));
		let target = crate::theory::reduce_once(&apply(target, s));
		let mut out: Vec<_> = unifiers(&term, &target, s).collect();

		let Value::Primitive(p) = &term else {
			return dedupe(out);
		};
		if out.is_empty()
			&& let Value::Primitive(q) = &target
			&& p.id == q.id
			&& p.output == q.output
			&& p.threshold == q.threshold
			&& p.arguments.len() == q.arguments.len()
		{
			let aligned = p
				.arguments
				.iter()
				.cloned()
				.zip(q.arguments.iter().cloned())
				.collect::<Vec<_>>();
			let swapped = super::matching::commutative_equations::<true>(p, q);
			for equations in std::iter::once(aligned).chain(swapped) {
				let mut frontier = vec![s.clone()];
				for (a, b) in equations {
					frontier = advance(&frontier, |bindings, next| {
						next.extend(self.invert(&a, &b, bindings))
					});
					if frontier.is_empty() {
						break;
					}
				}
				out.extend(frontier);
			}
		}

		if let Some(rule) = rewrite_rule(p.id)
			&& let Some(from) = p.arguments.get(rule.from)
		{
			for (shape, bound) in self.rewrite_shapes_yielding(p, rule, &target, s) {
				out.extend(self.invert(from, &shape, &bound));
			}
		}

		if primitive_is_projection(p.id)
			&& let Some(inner) = p.arguments.first()
		{
			for candidate in self.tuple_shapes(p, Some(&target)) {
				out.extend(self.invert(inner, &candidate, s));
			}
		}

		dedupe(out)
	}

	pub(crate) fn invert_into_revealed(
		&self,
		emission: &Value,
		shape: &Value,
	) -> Vec<Substitution> {
		let empty = Substitution::default();
		let mut out = Vec::new();
		let mut pending = vec![emission.clone()];
		let mut seen = TermSet::default();
		while let Some(term) = pending.pop() {
			let Value::Primitive(p) = &term else {
				continue;
			};
			let Some((revealed, _)) = decomposition_targets(p) else {
				continue;
			};
			for inner in revealed {
				if seen.contains(&inner) {
					continue;
				}
				seen.insert(inner.clone());
				if contains_var(&inner) {
					out.extend(self.invert(&inner, shape, &empty));
				}
				pending.push(inner);
			}
		}
		super::vars::dedupe(out)
	}

	pub(crate) fn equality_shapes(&self, p: &Primitive) -> Vec<Substitution> {
		if !(primitive_is_equality(p.id) && p.arguments.len() == 2) {
			return Vec::new();
		}
		self.check_equations(p, &Substitution::default())
	}

	pub(crate) fn repair_check(&self, p: &Primitive, base: &Substitution) -> Vec<Substitution> {
		let refined = refine_check(p, base);
		if check_passes(&refined) {
			return Vec::new();
		}
		let solutions = self.satisfy_check_shaped(&refined, base, true);
		self.memo.borrow_mut().clear();
		solutions
	}

	fn satisfy_check_shaped(
		&self,
		p: &Primitive,
		base: &Substitution,
		may_shape: bool,
	) -> Vec<Substitution> {
		if (primitive_is_equality(p.id) && p.arguments.len() == 2) || primitive_is_projection(p.id)
		{
			let out = self
				.check_equations(p, base)
				.iter()
				.flat_map(|bound| self.require_constructible(bound, base, false))
				.collect();
			return dedupe(out);
		}

		let Some(rule) = rewrite_rule(p.id) else {
			return Vec::new();
		};
		let Some(from) = p.arguments.get(rule.from) else {
			return Vec::new();
		};
		let shapes = self.rewrite_shapes(p, rule);
		let mut out = Vec::new();
		if let Some(var_id) = as_var(from) {
			for shape in &shapes {
				self.bind_from_shape(shape, &var_id, base, true, &mut out);
			}
		} else {
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
		}
		if out.is_empty() && may_shape {
			for (refined, bound) in self.shape_check_inputs(p, rule, base) {
				out.extend(self.satisfy_check_shaped(&refined, &bound, false));
			}
		}
		dedupe(out)
	}

	fn shape_check_inputs(
		&self,
		p: &Primitive,
		rule: &RewriteRule,
		base: &Substitution,
	) -> Vec<(Primitive, Substitution)> {
		let filter = rule.filter;
		let mut out = Vec::new();
		for (outer_idx, inner_idxs) in &rule.matching {
			let Some(outer_arg) = p.arguments.get(*outer_idx) else {
				continue;
			};
			if !contains_var(outer_arg) {
				continue;
			}
			let Some(required) = crate::primitive::key_derivation_of(self.fresh_var()) else {
				continue;
			};
			if !inner_idxs
				.iter()
				.any(|&i| filter(p, &required, i).1 && !filter(p, outer_arg, i).1)
			{
				continue;
			}
			for bound in self.invert(outer_arg, &required, base) {
				let refined = refine_check(p, &bound);
				if equivalent_primitives(&refined, p, true) {
					continue;
				}
				out.push((refined, bound));
			}
		}
		out
	}

	fn require_constructible(
		&self,
		s: &Substitution,
		base: &Substitution,
		slots_only: bool,
	) -> Vec<Substitution> {
		let mut obligations: Vec<(&VariableId, &Value)> = s
			.iter()
			.filter(|(id, _)| {
				!base.contains_key(*id) && !(slots_only && super::vars::is_free_var_id(id))
			})
			.collect();
		obligations.sort_by_key(|(id, _)| *id);

		let mut frontier = vec![s.clone()];
		for (id, obligation) in obligations {
			let wire = self
				.shared
				.slot_terms
				.iter()
				.find(|(slot_id, _)| slot_id == id)
				.map(|(_, term)| apply(term, s));
			frontier = self.solve_each(wire.as_ref().unwrap_or(obligation), &frontier);
			if frontier.is_empty() {
				break;
			}
		}
		frontier
	}
}

fn relevant_bindings(goal: &Value, s: &Substitution) -> Substitution {
	let mut pending: Vec<VariableId> = s
		.keys()
		.filter(|id| super::vars::is_slot_var_id(id))
		.cloned()
		.collect();
	super::vars::collect_vars(goal, &mut pending);
	let mut reached: IdSet<VariableId> = IdSet::default();
	while let Some(id) = pending.pop() {
		if !reached.insert(id.clone()) {
			continue;
		}
		if let Some(value) = s.get(&id) {
			super::vars::collect_vars(value, &mut pending);
		}
	}
	s.iter()
		.filter(|(id, _)| reached.contains(*id))
		.map(|(id, value)| (id.clone(), value.clone()))
		.collect()
}

fn extension_of(solution: &Substitution, base: &Substitution) -> Option<Substitution> {
	if !base.iter().all(|(id, value)| {
		solution
			.get(id)
			.is_some_and(|held| held.equivalent(value, true))
	}) {
		return None;
	}
	Some(
		solution
			.iter()
			.filter(|(id, _)| !base.contains_key(*id))
			.map(|(id, value)| (id.clone(), value.clone()))
			.collect(),
	)
}

fn constraint_sets(queries: &[Query], km: &ProtocolTrace, sym: &SymbolicState) -> Vec<Vec<usize>> {
	let mut checks: IdMap<PrincipalId, Vec<usize>> = IdMap::default();
	for (slot, trace_slot) in km.slots.iter().enumerate() {
		if let Value::Primitive(p) = &trace_slot.initial_value
			&& p.instance_check
		{
			checks.entry(trace_slot.creator).or_default().push(slot);
		}
	}
	let mut endpoints: Vec<_> = checks
		.iter()
		.filter_map(|(owner, slots)| {
			slots.last().map(|slot| {
				(
					*owner,
					(km.slots[*slot].declared_at, *slot + 1),
					Some(*slot),
				)
			})
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
			km.index.get(&event.constant_id).copied(),
		)
	}));
	for query in queries {
		for constant in query.constants.iter().chain(&query.message.constants) {
			if let Some(slot) = km.index_of(constant) {
				endpoints.push((
					km.slots[slot].creator,
					(km.slots[slot].declared_at, slot + 1),
					Some(slot),
				));
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
			.filter(|slot| (km.slots[*slot].declared_at, *slot) < at)
			.collect();
		pending.extend(target);
		let mut visited = IdSet::default();
		let mut needed = IdSet::default();
		while let Some(slot) = pending.pop() {
			if !visited.insert(slot) || sym.is_var_slot(slot) {
				continue;
			}
			let trace_slot = &km.slots[slot];
			if let Value::Primitive(p) = &trace_slot.initial_value
				&& primitive_is_projection(p.id)
			{
				needed.insert(slot);
			}
			for &check in checks.get(&trace_slot.creator).into_iter().flatten() {
				if check <= slot {
					needed.insert(check);
					if check != slot {
						pending.push(check);
					}
				}
			}
			for constant in trace_slot.initial_value.constant_leaves() {
				if let Some(dependency) = km.index_of(constant) {
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

/// A projection whose tuple is still open is the one shape plain unification
/// cannot see through: `unifiers` matches congruently, and rewrites already
/// have their own routes, so this is the only case worth inverting a wire term
/// for. Without the test the fallback runs for every wire term and every goal.
fn projects_a_variable(v: &Value) -> bool {
	crate::value::subterms(v).any(|term| match term {
		Value::Primitive(p) => {
			primitive_is_projection(p.id) && p.arguments.first().is_some_and(contains_var)
		}
		Value::Constant(_) | Value::Variable(_) => false,
	})
}

fn decomposition_targets(p: &Primitive) -> Option<(Vec<Value>, Vec<Value>)> {
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

fn widest_checked_projections(mut checked: Vec<Primitive>) -> Vec<Primitive> {
	let mut widest: Vec<Primitive> = Vec::new();
	for p in checked.iter().filter(|p| primitive_is_projection(p.id)) {
		match widest.iter_mut().find(|q| {
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
			None => widest.push(p.clone()),
		}
	}
	checked.retain(|p| {
		!primitive_is_projection(p.id) || widest.iter().any(|q| equivalent_primitives(q, p, true))
	});
	checked
}

fn advance(
	frontier: &[Substitution],
	mut step: impl FnMut(&Substitution, &mut Vec<Substitution>),
) -> Vec<Substitution> {
	let mut next = Vec::new();
	for candidate in frontier {
		step(candidate, &mut next);
	}
	dedupe(next)
}

fn match_each(pattern: &Value, target: &Value, frontier: &[Substitution]) -> Vec<Substitution> {
	advance(frontier, |candidate, next| {
		next.extend(match_values(pattern, target, candidate))
	})
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

pub(crate) fn rewrite_shapes_from(
	outer: &Primitive,
	rule: &RewriteRule,
	mut fill: impl FnMut(usize) -> Value,
	leave_free: bool,
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
			if leave_free {
				continue;
			}
			return Vec::new();
		}
		partials = next;
	}

	let output = rule.from_output.unwrap_or(0);
	partials
		.into_iter()
		.map(|(arguments, _)| Value::primitive(rule.id, arguments, output))
		.collect()
}

fn combine(left: &[Substitution], right: &[Substitution]) -> Vec<Substitution> {
	let mut out = Vec::new();
	for a in left {
		for b in right {
			out.extend(super::matching::merge(a, b));
		}
	}
	dedupe(out)
}

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

fn dedupe_counts(candidates: Vec<(Substitution, usize)>) -> Vec<(Substitution, usize)> {
	let mut distinct = Distinct::default();
	for (candidate, count) in candidates {
		distinct.insert(candidate, count);
	}
	distinct.into_items()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn deduction_uses_the_bound_of_its_inputs_and_keeps_reducible_inputs() {
		let nil = value_nil();
		let km = make_trace(vec![]);
		let sym = SymbolicState::default();
		let attacker = make_attacker_state(vec![nil.clone()]);
		let input = super::super::vars::attacker_var(0);
		let hash = |v| Value::primitive(PRIM_HASH, vec![v], 0);
		let too_deep = hash(hash(nil.clone()));
		let reducible = Value::primitive(
			PRIM_DEC,
			vec![
				too_deep.clone(),
				Value::primitive(PRIM_ENC, vec![too_deep.clone(), nil.clone()], 0),
			],
			0,
		);
		for (value, accepted) in [(too_deep, false), (reducible, true)] {
			let deducer = Deducer::new(&km, &attacker, &sym).with_bound(vec![(input.clone(), 1)]);
			let binding = [(as_var(&input).unwrap(), value)].into_iter().collect();
			assert_eq!(!deducer.solve(&nil, &binding).is_empty(), accepted);
			assert_eq!(deducer.declined_bound(), !accepted);
		}
	}

	#[test]
	fn an_oracle_accepts_a_constructed_goal_outside_the_protocol_basis() {
		let key = make_private("oracle_constructed_seal");
		let signing = make_private("oracle_constructed_signing");
		let message = make_constant("oracle_constructed_message");
		let input = super::super::vars::attacker_var(2);
		let cipher = super::super::vars::attacker_var(3);
		let sealed = Value::primitive(
			PRIM_ENC,
			vec![
				key.clone(),
				Value::primitive(PRIM_SIGN, vec![signing.clone(), input.clone()], 0),
			],
			0,
		);
		let opened = Value::primitive(PRIM_DEC, vec![key, cipher.clone()], 0);
		let km = make_trace(vec![
			crate::testutil::make_wire_slot(
				&make_constant("oracle_constructed_sealed"),
				&sealed,
				0,
			),
			crate::testutil::make_wire_slot(
				&make_constant("oracle_constructed_opened"),
				&opened,
				1,
			),
		]);
		let sym = SymbolicState {
			terms: vec![sealed, opened, input.clone(), cipher.clone()],
			var_slots: vec![2, 3],
			var_terms: vec![None, None, Some(input.clone()), Some(cipher.clone())],
		};
		let attacker = make_attacker_state(vec![message.clone(), value_nil()]);
		let deducer = Deducer::new(&km, &attacker, &sym);
		let chosen = Value::primitive(PRIM_HASH, vec![message], 0);
		let goal = Value::primitive(PRIM_SIGN, vec![signing, chosen.clone()], 0);
		assert!(
			!sym.terms
				.iter()
				.chain(attacker.known.iter())
				.any(|term| crate::value::subterms(term).any(|t| t.equivalent(&goal, true)))
		);
		let solutions = deducer.solve(&goal, &Substitution::default());
		assert!(solutions.iter().any(|solution| {
			apply(&input, solution).equivalent(&chosen, true)
				&& crate::theory::reduce_once(&apply(&sym.terms[1], solution))
					.equivalent(&goal, true)
		}));
	}

	#[test]
	fn forgeable_goals_share_only_the_declared_key_primitive_and_phase() {
		let key = make_private("forge_scope_key");
		let other = make_private("forge_scope_other");
		let message = make_constant("forge_scope_message");
		let hidden = make_private("forge_scope_hidden");
		let mut annotated = Primitive::new(PRIM_SIGN, vec![key.clone(), value_nil()], 0);
		annotated.capabilities.set(Capability::Forgeable, 2);
		let mut km = make_trace(vec![]);
		km.capabilities
			.insert(&Value::Primitive(Arc::new(annotated)));
		let sym = SymbolicState::default();
		for phase in [1, 2] {
			let mut attacker = make_attacker_state(vec![value_nil(), message.clone()]);
			attacker.current_phase = phase;
			let deducer = Deducer::new(&km, &attacker, &sym);
			for (id, secret, payload, expected) in [
				(PRIM_SIGN, &key, &message, phase == 2),
				(PRIM_SIGN, &other, &message, false),
				(PRIM_SIGN, &key, &hidden, false),
				(PRIM_MAC, &key, &message, false),
			] {
				let goal = Value::primitive(id, vec![secret.clone(), payload.clone()], 0);
				assert_eq!(
					!deducer.solve(&goal, &Substitution::default()).is_empty(),
					expected,
					"{goal} at phase {phase}"
				);
			}
			let variable = super::super::vars::attacker_var(0);
			let goal = Value::primitive(PRIM_SIGN, vec![variable.clone(), message.clone()], 0);
			let solutions = deducer.solve(&goal, &Substitution::default());
			assert!(
				solutions
					.iter()
					.any(|s| apply(&variable, s).equivalent(&value_nil(), true))
			);
			assert_eq!(
				solutions
					.iter()
					.any(|s| apply(&variable, s).equivalent(&key, true)),
				phase == 2,
			);
		}
	}

	#[test]
	fn solving_a_reducible_goal_requires_its_result_to_be_derivable() {
		let key = make_private("reduct_goal_key");
		let hidden = make_private("reduct_goal_hidden");
		let public = Value::primitive(PRIM_PUBKEY, vec![key.clone()], 0);
		let sealed = Value::primitive(PRIM_PKE_ENC, vec![public.clone(), hidden.clone()], 0);
		let km = make_trace(vec![]);
		let sym = SymbolicState::default();
		let attacker = make_attacker_state(vec![value_nil(), public, sealed]);
		let variable = super::super::vars::attacker_var(0);
		let goal = Value::primitive(PRIM_PKE_DEC, vec![key, variable.clone()], 0);
		let deducer = Deducer::new(&km, &attacker, &sym);
		let bound = Substitution::from_iter([(
			as_var(&variable).unwrap(),
			Value::primitive(
				PRIM_PKE_ENC,
				vec![attacker.known[1].clone(), value_nil()],
				0,
			),
		)]);
		let before = deducer.variables.borrow().clone();
		let solved = deducer.solve(&goal, &bound);
		assert_eq!(solved.len(), 1);
		assert!(same_substitution(&solved[0], &bound));
		assert_eq!(deducer.variables.borrow().clone(), before);
		let solutions = deducer.solve(&goal, &Substitution::default());
		assert!(!solutions.is_empty());
		for solution in solutions {
			let sent = super::super::vars::ground_free(&apply(&variable, &solution));
			assert!(crate::theory::obtainable(
				&sent,
				&km.capabilities,
				&attacker
			));
			let reduced = crate::theory::reduce_once(&super::super::vars::ground_free(&apply(
				&goal, &solution,
			)));
			assert!(crate::theory::obtainable(
				&reduced,
				&km.capabilities,
				&attacker
			));
			assert!(!reduced.equivalent(&hidden, true));
		}
	}

	#[test]
	fn combining_constraint_groups_keeps_alignments_needed_by_later_groups() {
		let x = super::super::vars::free_var(0);
		let y = super::super::vars::free_var(1);
		let a = make_private("combine_later_a");
		let b = make_private("combine_later_b");
		let key = |a, b| {
			Value::primitive(
				PRIM_DH_KEX,
				vec![Value::primitive(PRIM_PUBKEY, vec![a], 0), b],
				0,
			)
		};
		let slot = super::super::vars::attacker_var_id(0);
		let left = Substitution::from_iter([(slot.clone(), key(x.clone(), y.clone()))]);
		let right = Substitution::from_iter([(slot.clone(), key(a.clone(), b.clone()))]);
		let merged = combine(&[left], &[right]);
		assert_eq!(merged.len(), 2);
		for (wanted, other) in [(&a, &b), (&b, &a)] {
			let later = Substitution::from_iter([(as_var(&x).unwrap(), wanted.clone())]);
			let found = combine(&merged, &[later]);
			assert_eq!(found.len(), 1);
			assert!(apply(&x, &found[0]).equivalent(wanted, true));
			assert!(apply(&y, &found[0]).equivalent(other, true));
		}
	}

	#[test]
	fn rewrite_inversion_keeps_bindings_in_the_reduct() {
		let key = make_private("invert_reduct_key");
		let message = make_constant("invert_reduct_message");
		let input = super::super::vars::attacker_var(0);
		let signature = super::super::vars::attacker_var(1);
		let term = Value::primitive(PRIM_UNBLIND, vec![value_nil(), input.clone(), signature], 0);
		let target = Value::primitive(PRIM_SIGN, vec![key, message.clone()], 0);
		let km = make_trace(vec![]);
		let sym = SymbolicState::default();
		let attacker = make_attacker_state(vec![]);
		let deducer = Deducer::new(&km, &attacker, &sym);
		let found = deducer.invert(&term, &target, &Substitution::default());
		assert!(!found.is_empty());
		for solution in found {
			assert!(solution.keys().all(super::super::vars::is_slot_var_id));
			assert!(apply(&input, &solution).equivalent(&message, true));
			assert!(crate::theory::reduce_once(&apply(&term, &solution)).equivalent(&target, true));
		}
	}

	#[test]
	fn rewrite_inversion_retains_commutative_alternatives_and_incoming_bindings() {
		let a = make_constant("invert_alternatives_a");
		let b = make_constant("invert_alternatives_b");
		let key = make_private("invert_alternatives_key");
		let x = super::super::vars::attacker_var(0);
		let y = super::super::vars::attacker_var(1);
		let sig = super::super::vars::attacker_var(2);
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
		let km = make_trace(vec![]);
		let sym = SymbolicState::default();
		let attacker = make_attacker_state(vec![]);
		let deducer = Deducer::new(&km, &attacker, &sym);
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
		let km = make_trace(vec![]);
		let sym = SymbolicState::default();
		let original = Deducer::new(&km, &attacker, &sym);
		let [restricted, sibling]: [Deducer; 2] = original.lanes(2).try_into().ok().unwrap();
		assert!(Arc::ptr_eq(&original.shared, &restricted.shared));
		assert!(Arc::ptr_eq(&original.shared, &sibling.shared));
		let mut variables = IdSet::default();
		for deducer in [&restricted, &original, &sibling] {
			let variable = deducer.fresh_var();
			assert!(variables.insert(as_var(&variable).unwrap()));
			assert!(deducer.memo.borrow().is_empty());
			let goal = Value::primitive(PRIM_ENC, vec![key.clone(), variable.clone()], 0);
			let solutions = deducer.solve(&goal, &Substitution::default());
			assert_eq!(solutions.len(), 1);
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
		let x = super::super::vars::attacker_var(0);
		let y = super::super::vars::attacker_var(1);
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
		let km = make_trace(vec![]);
		let sym = SymbolicState {
			terms: vec![wire.clone()],
			..SymbolicState::default()
		};
		let attacker = make_attacker_state(vec![a.clone(), b.clone()]);
		let deducer = Deducer::new(&km, &attacker, &sym);
		let mut found = Vec::new();
		let p = wire.as_primitive().unwrap();
		let rule = rewrite_rule(p.id).unwrap();
		deducer.solve_by_rewrite_match(p, rule, &secret, &Substitution::default(), &mut found);
		assert_eq!(found.len(), 1);
		assert!(apply(&x, &found[0]).equivalent(&b, true));
		assert!(apply(&y, &found[0]).equivalent(&a, true));
		assert!(crate::theory::reduce_once(&apply(&wire, &found[0])).equivalent(&secret, true));
	}

	#[test]
	fn weak_decomposition_respects_capabilities_and_their_phase() {
		let secret = make_private("weak_route_secret");
		let message = make_constant("weak_route_message");
		let variable = super::super::vars::attacker_var(0);
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
			let mut km = make_trace(vec![]);
			let declared = apply(
				&wire,
				&Substitution::from_iter([(as_var(&variable).unwrap(), message.clone())]),
			);
			km.capabilities.insert(&declared);
			let sym = SymbolicState {
				terms: vec![wire.clone()],
				..SymbolicState::default()
			};
			for phase in [0, 1, 2] {
				let mut attacker = make_attacker_state(vec![message.clone()]);
				attacker.current_phase = phase;
				let deducer = Deducer::new(&km, &attacker, &sym);
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
		let km = make_trace(vec![]);
		let sym = SymbolicState::default();
		let deducer = Deducer::new(&km, &attacker, &sym);
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
		assert!(crate::theory::obtainable(
			&apply(&target, &found[0]),
			&km.capabilities,
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
		let mut km = make_trace(vec![]);
		km.capabilities.insert(&held);
		let attacker = make_attacker_state(vec![value_nil(), b.clone(), held]);
		let sym = SymbolicState::default();
		let deducer = Deducer::new(&km, &attacker, &sym);
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
		assert!(crate::theory::obtainable(
			&apply(&target, &found[0]),
			&km.capabilities,
			&attacker
		));
	}

	#[test]
	fn threshold_search_constructs_a_missing_partial_with_a_committed_nonce() {
		let key = make_private("threshold_bound_key");
		let message = make_private("threshold_bound_message");
		let honest_nonce = make_private("threshold_bound_honest_nonce");
		let owned_nonce = make_private("threshold_bound_owned_nonce");
		let commitments = Value::primitive(
			PRIM_CONCAT,
			vec![
				Value::primitive(PRIM_PUBKEY, vec![honest_nonce.clone()], 0),
				Value::primitive(PRIM_PUBKEY, vec![owned_nonce.clone()], 0),
			],
			0,
		);
		let mut split = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![key.clone()], 0);
		split.threshold = 2;
		let held = Value::primitive(
			PRIM_THRESHOLD_SIGN,
			vec![
				Value::Primitive(Arc::new(split.with_output(2))),
				honest_nonce,
				commitments.clone(),
				message.clone(),
			],
			0,
		);
		let attacker = make_attacker_state(vec![
			held,
			Value::Primitive(Arc::new(split)),
			owned_nonce,
			commitments,
			message.clone(),
		]);
		let km = make_trace(vec![]);
		let sym = SymbolicState::default();
		let deducer = Deducer::new(&km, &attacker, &sym);
		let signature = Primitive::new(PRIM_SIGN, vec![key, message], 0);
		let mut found = Vec::new();
		deducer.solve_by_combination(&signature, &Substitution::default(), &mut found);
		assert!(!found.is_empty());
		assert!(crate::theory::obtainable(
			&Value::Primitive(Arc::new(signature)),
			&km.capabilities,
			&attacker
		));
	}

	#[test]
	fn threshold_search_retains_key_alignments_until_the_message_matches() {
		let a = make_private("threshold_alignment_a");
		let b = make_private("threshold_alignment_b");
		let x = super::super::vars::attacker_var(0);
		let y = super::super::vars::attacker_var(1);
		let dh = |a: Value, b| {
			Value::primitive(
				PRIM_DH_KEX,
				vec![Value::primitive(PRIM_PUBKEY, vec![a], 0), b],
				0,
			)
		};
		let mut split = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![dh(a.clone(), b.clone())], 0);
		split.threshold = 2;
		let partials = (0..2)
			.map(|output| {
				Value::primitive(
					PRIM_THRESHOLD_SIGN,
					vec![
						Value::Primitive(Arc::new(split.with_output(output))),
						value_nil(),
						Value::primitive(PRIM_PUBKEY, vec![value_nil()], 0),
						b.clone(),
					],
					0,
				)
			})
			.collect();
		let attacker = make_attacker_state(partials);
		let km = make_trace(vec![]);
		let sym = SymbolicState::default();
		let deducer = Deducer::new(&km, &attacker, &sym);
		let target = Primitive::new(PRIM_SIGN, vec![dh(x.clone(), y.clone()), x.clone()], 0);
		let mut found = Vec::new();
		deducer.solve_by_combination(&target, &Substitution::default(), &mut found);
		assert!(
			found
				.iter()
				.any(|s| apply(&x, s).equivalent(&b, true) && apply(&y, s).equivalent(&a, true))
		);
	}

	#[test]
	fn threshold_search_keeps_one_state_per_distinct_choice() {
		let key = make_private("subset_search_key");
		let message = make_private("subset_search_message");
		let wanted = super::super::vars::free_var(10000);
		let mut split = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![key.clone()], 0);
		split.threshold = 8;
		let commitments = Value::primitive(
			PRIM_CONCAT,
			(0..16)
				.map(|output| {
					Value::primitive(
						PRIM_PUBKEY,
						vec![make_private(&format!("subset_search_nonce_{output}"))],
						0,
					)
				})
				.collect(),
			0,
		);
		let partials: Vec<_> = (0..16)
			.map(|output| {
				Value::primitive(
					PRIM_THRESHOLD_SIGN,
					vec![
						Value::Primitive(Arc::new(split.with_output(output))),
						make_private(&format!("subset_search_nonce_{output}")),
						commitments.clone(),
						message.clone(),
					],
					0,
				)
			})
			.collect();
		let attacker = make_attacker_state(partials);
		let km = make_trace(vec![]);
		let sym = SymbolicState::default();
		let deducer = Deducer::new(&km, &attacker, &sym);
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
				arguments[2] = Value::primitive(
					PRIM_CONCAT,
					vec![
						commitments.clone(),
						make_constant(&format!("subset_commitments_{}", i % 4)),
					],
					0,
				);
				Value::Primitive(Arc::new(p.with_arguments(arguments)))
			})
			.collect();
		let attacker = make_attacker_state(regrouped);
		let deducer = Deducer::new(&km, &attacker, &sym);
		let mut found = Vec::new();
		deducer.solve_by_combination(&target, &Substitution::default(), &mut found);
		assert!(
			found.is_empty(),
			"different commitments must not pool their counts"
		);
	}

	#[test]
	fn a_lane_issues_variables_without_a_ceiling() {
		let key = make_private("unbounded_lane_key");
		let message = make_private("unbounded_lane_message");
		let held = Value::primitive(PRIM_ENC, vec![key.clone(), message.clone()], 0);
		let attacker = make_attacker_state(vec![held]);
		let km = make_trace(vec![]);
		let sym = SymbolicState::default();
		let deducer = Deducer::new(&km, &attacker, &sym).in_test_lane(3);
		let mut seen = IdSet::default();
		for _ in 0..100_000 {
			let id = as_var(&deducer.fresh_var()).expect("a variable");
			assert!(seen.insert(id), "every issued variable is distinct");
		}
		let goal = Value::primitive(PRIM_ENC, vec![key, deducer.fresh_var()], 0);
		assert!(
			!deducer.solve(&goal, &Substitution::default()).is_empty(),
			"a lane that has issued many variables keeps solving rather than giving up"
		);
	}

	#[test]
	fn threshold_frontier_retains_distinct_counts_and_bindings_in_order() {
		let id = super::super::vars::attacker_var_id(0);
		let first = Substitution::from_iter([(id.clone(), make_private("count_first"))]);
		let second = Substitution::from_iter([(id.clone(), make_private("count_second"))]);
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
		let variable = super::super::vars::attacker_var(0);
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
		let km = make_trace(vec![]);
		let attacker = make_attacker_state(vec![]);
		let deducer = Deducer::new(&km, &attacker, &sym);
		let shapes = deducer.forgeable_shapes(&sym, &as_var(&variable).unwrap());
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
		let km = crate::sanity::sanity(&model).unwrap();
		let bob = km.principal_ids[km.principals.iter().position(|p| p == "Bob").unwrap()];
		let attacker = make_attacker_state(vec![]);
		let controllable = crate::solve::control::Controllable::of(&km, bob, &attacker);
		let sym = super::super::symbolic::build(&controllable, &km, bob, &attacker);
		let groups = constraint_sets(&model.queries, &km, &sym);
		let slot = |name: &str| {
			km.slots
				.iter()
				.position(|slot| &*slot.constant.name == name)
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
		let variable = super::super::vars::attacker_var(0);
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
		let km = make_trace(vec![]);
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
				..SymbolicState::default()
			};
			let mut held = vec![wrapping.clone(), message.clone(), pair[0].clone()];
			if case != 2 {
				held.push(pair[1].clone());
			}
			let mut attacker = make_attacker_state(held);
			if case != 1 {
				attacker.reused = Arc::new(vec![pair.clone()]);
			}
			let deducer = Deducer::new(&km, &attacker, &sym);
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
		let variable = super::super::vars::attacker_var(0);
		let goal = Value::primitive(PRIM_MAC, vec![secret.clone(), message.clone()], 0);
		let plaintext = Value::primitive(PRIM_MAC, vec![secret, variable.clone()], 0);
		let encrypted = Value::primitive(PRIM_ENC, vec![inner.clone(), plaintext], 0);
		let wire = Value::primitive(
			PRIM_AEAD_ENC,
			vec![outer.clone(), nonce.clone(), encrypted, value_nil()],
			0,
		);
		let km = make_trace(vec![]);
		let sym = SymbolicState {
			terms: vec![wire.clone()],
			..SymbolicState::default()
		};
		for mask in 0..8 {
			let mut held = vec![message.clone()];
			for (at, input) in [&outer, &nonce, &inner].into_iter().enumerate() {
				if mask & (1 << at) != 0 {
					held.push(input.clone());
				}
			}
			let attacker = make_attacker_state(held);
			let deducer = Deducer::new(&km, &attacker, &sym);
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
		let variable = super::super::vars::attacker_var(0);
		let goal = Value::primitive(PRIM_MAC, vec![secret.clone(), message.clone()], 0);
		let plaintext = Value::primitive(PRIM_MAC, vec![secret, variable.clone()], 0);
		let mut wire = Value::primitive(PRIM_ENC, vec![key.clone(), plaintext], 0);
		for _ in 0..40 {
			wire = Value::primitive(PRIM_CONCAT, vec![wire.clone(), wire.clone(), wire], 0);
		}
		let km = make_trace(vec![]);
		let sym = SymbolicState {
			terms: vec![wire.clone()],
			..SymbolicState::default()
		};
		let attacker = make_attacker_state(vec![key, message.clone()]);
		let deducer = Deducer::new(&km, &attacker, &sym);
		let mut memo = DecompositionMemo::default();
		let solutions =
			deducer.solve_decomposition_from(&wire, &goal, &Substitution::default(), &mut memo);
		assert_eq!(
			memo.len(),
			42,
			"the forty carriers and the ciphertext are each visited once, and the \
			 plaintext they all share is the forty-second: a term whose rule offers no \
			 route is recorded too, so the shaping attempt behind it is made once \
			 rather than at every carrier that reaches it"
		);
		assert_eq!(solutions.len(), 1);
		assert!(apply(&variable, &solutions[0]).equivalent(&message, true));
	}

	#[test]
	fn deduction_routes_require_the_declared_encapsulation_projection() {
		let key = make_private("route_projection_key");
		let public = Value::primitive(PRIM_PUBKEY, vec![key.clone()], 0);
		let variable = super::super::vars::attacker_var(0);
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
			let km = make_trace(vec![make_wire_slot(&name, &wire, 1)]);
			let sym = SymbolicState {
				terms: vec![wire.clone()],
				..SymbolicState::default()
			};
			let deducer = Deducer::new(&km, &attacker, &sym);
			let mut decomposed = Vec::new();
			deducer.solve_by_decomposition(&randomness, &Substitution::default(), &mut decomposed);
			let check = Value::primitive(PRIM_KEM_DECAP, vec![key.clone(), wire], 0);
			let mut rewritten = Vec::new();
			let p = check.as_primitive().unwrap();
			let rule = rewrite_rule(p.id).unwrap();
			deducer.solve_by_rewrite_match(
				p,
				rule,
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
		let variable = super::super::vars::attacker_var(0);
		let wire = Value::primitive(PRIM_MAC, vec![key.clone(), variable.clone()], 0);
		let goal = Value::primitive(PRIM_MAC, vec![key, message.clone()], 0);
		let name = make_constant("memo_oracle_wire");
		let km = make_trace(vec![make_wire_slot(&name, &wire, 1)]);
		let attacker = make_attacker_state(vec![message.clone(), other.clone()]);
		let sym = SymbolicState {
			terms: vec![wire],
			..SymbolicState::default()
		};
		let deducer = Deducer::new(&km, &attacker, &sym);
		let blocked = Substitution::from_iter([(as_var(&variable).unwrap(), other)]);
		assert!(deducer.solve(&goal, &blocked).is_empty());
		let empty = Substitution::default();
		let fresh = Deducer::new(&km, &attacker, &sym).solve(&goal, &empty);
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
	fn fresh_variables_are_disjoint_between_lanes_and_batches() {
		let km = make_trace(vec![]);
		let attacker = make_attacker_state(vec![]);
		let sym = SymbolicState::default();
		let deducer = Deducer::new(&km, &attacker, &sym);
		let mut seen = IdSet::default();
		for _ in 0..2 {
			for worker in deducer.lanes(7) {
				for _ in 0..1_000 {
					assert!(seen.insert(as_var(&worker.fresh_var()).unwrap()));
					assert!(seen.insert(as_var(&deducer.fresh_var()).unwrap()));
				}
			}
		}
	}

	use crate::testutil::*;

	fn unblind_over(k: &Value, m: &Value, sig: &Value) -> Primitive {
		Primitive {
			id: PRIM_UNBLIND,
			arguments: vec![k.clone(), m.clone(), sig.clone()],
			output: 0,
			instance: 0,
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

		let km = make_trace(vec![]);
		let attacker = make_attacker_state(vec![]);
		let sym = SymbolicState::default();
		let deducer = Deducer::new(&km, &attacker, &sym);
		let rule = rewrite_rule(PRIM_UNBLIND).expect("UNBLIND declares a rewrite rule");

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

		let km = make_trace(vec![]);
		let attacker = make_attacker_state(vec![]);
		let sym = SymbolicState::default();
		let deducer = Deducer::new(&km, &attacker, &sym);
		let rule = rewrite_rule(PRIM_UNBLIND).expect("UNBLIND declares a rewrite rule");

		assert!(
			deducer
				.rewrite_shapes_yielding(&outer, rule, &target, &Substitution::default())
				.is_empty(),
			"unblinding with blinding factor `inr_k` over message `inr_m` can only yield a \
			 signature over `inr_m`; offering a shape for a signature over something else \
			 proposes a term the rewrite does not produce"
		);
	}

	#[test]
	fn a_share_opened_out_of_a_sealed_tuple_is_shaped_as_the_attackers_key() {
		let seal = make_constant("sealed_share_seal");
		let nonce = make_constant("sealed_share_nonce");
		let secret = make_private("sealed_share_secret");
		let public = Value::primitive(PRIM_PUBKEY, vec![secret.clone()], 0);
		let ciphertext = super::super::vars::attacker_var(0);
		let opened = Value::primitive(
			PRIM_AEAD_DEC,
			vec![seal.clone(), nonce.clone(), ciphertext.clone(), value_nil()],
			0,
		);
		let share = Value::primitive(PRIM_SPLIT, vec![opened], 1);
		let free = super::super::vars::free_var(0);
		let km = make_trace(vec![]);
		let sym = SymbolicState::default();
		let attacker = make_attacker_state(vec![value_nil(), seal, nonce, public.clone()]);
		let deducer = Deducer::new(&km, &attacker, &sym).in_test_lane(1);
		let own = Value::primitive(PRIM_DH_KEX, vec![public.clone(), value_nil()], 0);
		for wrapped in [share, free] {
			let goal = Value::primitive(PRIM_DH_KEX, vec![wrapped.clone(), secret.clone()], 0);
			let solutions = deducer.solve(&goal, &Substitution::default());
			assert!(
				solutions.iter().any(|s| {
					let ground = super::super::vars::ground_free(&apply(&goal, s));
					crate::theory::reduce_once(&ground).equivalent(&own, true)
				}),
				"the attacker cannot supply `sealed_share_secret`, but it holds its public \
				 key, so DH_KEX({wrapped}, sealed_share_secret) is obtainable once {wrapped} \
				 becomes PUBKEY of something the attacker picks: the goal commutes into \
				 DH_KEX(PUBKEY(sealed_share_secret), nil). Only a share already written as \
				 PUBKEY(..) was ever commuted, so a share projected out of a tuple the \
				 attacker can seal, or left free by a tuple shape, never was: the key \
				 substitution behind every Diffie-Hellman man-in-the-middle was missed \
				 whenever the share travelled inside a sealed hello. Got {solutions:?}"
			);
		}
	}
}
