/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

mod checks;
mod combination;
mod decomposition;
mod inversion;
mod rules;
mod shapes;
#[cfg(test)]
mod tests;

pub(crate) use shapes::rewrite_shapes_from;

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::matching::match_values;
use super::symbolic::SymbolicState;
use super::vars::{
	FreshVariables, Substitution, apply, as_var, contains_var, dedupe, same_substitution,
	substitution_hash,
};
use crate::primitive::CapabilityIndex;
use crate::protocol::ProtocolTrace;
use crate::term::{Primitive, PrimitiveId, Value, VariableId, value_nil};
use crate::theory::AttackerState;
use crate::util::{IdMap, IdSet};
use decomposition::Reach;

struct SolvedGoal {
	goal: Value,
	bindings: Substitution,
	solutions: Vec<Substitution>,
	cut: Vec<(u64, Value)>,
}

type GoalMemo = IdMap<(u64, u64), Vec<SolvedGoal>>;
type HeldByHead = IdMap<(PrimitiveId, usize), Vec<usize>>;
pub(crate) type Arities = IdMap<PrimitiveId, Vec<usize>>;

pub(crate) fn note_arities(v: &Value, out: &mut Arities) {
	for term in crate::term::subterms(v) {
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
			.iter_enumerated()
			.filter(|(idx, slot)| slot.disclosed() && !sym.is_var_slot(*idx))
			.filter_map(|(idx, _)| sym.terms.get(idx).cloned())
			.collect();
		let slot_terms = sym
			.variables()
			.filter(|(_, term)| as_var(term).is_none())
			.map(|(slot, term)| (super::vars::attacker_var_id(slot), term.clone()))
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
