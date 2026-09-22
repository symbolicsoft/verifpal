/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::Cell;

use crate::context::VerifyContext;
use crate::deduction::compute_knowledge_closure;
use crate::info::InfoQuiet;
use crate::primitive::attacker_public_key;
use crate::principal::ATTACKER_ID;
use crate::reexec::{causally_grounded, governing_attacker, reexecute_at};
use crate::types::*;
use crate::value::value_nil;
use crate::verify::verify_resolve_queries;

thread_local! {
	static MINIMIZING: Cell<usize> = const { Cell::new(0) };
}

pub(crate) fn in_minimization() -> bool {
	MINIMIZING.with(|f| f.get() > 0)
}

pub(crate) struct MinimizingGuard;

impl MinimizingGuard {
	pub(crate) fn new() -> MinimizingGuard {
		MINIMIZING.with(|f| f.set(f.get() + 1));
		MinimizingGuard
	}
}

impl Drop for MinimizingGuard {
	fn drop(&mut self) {
		MINIMIZING.with(|f| f.set(f.get().saturating_sub(1)));
	}
}

#[derive(Clone, Copy, PartialEq)]
enum Breadth {
	Base,
	All,
}

#[derive(Clone, Copy, PartialEq)]
enum Scope {
	Own,
	Any,
}

type Installs = Vec<(SlotIdx, Value)>;

pub(crate) type Addressed = Vec<(PrincipalId, SlotIdx, Value)>;

fn phases_of(
	ctx: &VerifyContext,
	installs: &[(SlotIdx, Value)],
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Vec<i32> {
	installs
		.iter()
		.map(|(slot, value)| {
			crate::solve::validate::attacker_can_derive(
				ctx,
				slot.get(),
				value,
				ps,
				attacker,
				&|_| None,
			)
			.unwrap_or(attacker.current_phase)
		})
		.collect()
}

fn addressed_to(addressed: &[(PrincipalId, SlotIdx, Value)], id: PrincipalId) -> Installs {
	addressed
		.iter()
		.filter(|(at, _, _)| *at == id)
		.map(|(_, slot, value)| (*slot, value.clone()))
		.collect()
}

#[derive(Clone, Copy)]
enum Family {
	SingleSlot,
	WholeFlight,
	AcrossSessions,
	SplitRecipients,
}

struct Rung {
	family: Family,
	scope: Scope,
	breadth: Breadth,
}

const LADDER: [Rung; 4] = [
	Rung {
		family: Family::SingleSlot,
		scope: Scope::Own,
		breadth: Breadth::Base,
	},
	Rung {
		family: Family::WholeFlight,
		scope: Scope::Own,
		breadth: Breadth::Base,
	},
	Rung {
		family: Family::AcrossSessions,
		scope: Scope::Any,
		breadth: Breadth::All,
	},
	Rung {
		family: Family::SplitRecipients,
		scope: Scope::Any,
		breadth: Breadth::All,
	},
];

fn dedup_in_order<T: PartialEq>(items: impl IntoIterator<Item = T>) -> Vec<T> {
	let mut out: Vec<T> = Vec::new();
	for item in items {
		if !out.contains(&item) {
			out.push(item);
		}
	}
	out
}

pub(crate) struct Witness {
	pub ps: PrincipalState,
	#[cfg(test)]
	pub driver: PrincipalId,
	pub others: Vec<PrincipalState>,
	#[cfg(test)]
	pub wide: bool,
	pub attacker: AttackerState,
	pub reproduced: bool,
	pub grounded: bool,
	pub out_of_order: Vec<String>,
	#[cfg(test)]
	pub installs: Installs,
	#[cfg(test)]
	pub addressed: Addressed,
}

struct Minimizer<'a> {
	ctx: &'a VerifyContext,
	km: &'a ProtocolTrace,
	query_index: usize,
	concrete: Option<Query>,
	phase: i32,
	ambient: AttackerState,
	sessions: Vec<PrincipalState>,
	mutations: Installs,
	support: Installs,
	pruned: Installs,
	needs: Addressed,
	everywhere: Installs,
	bound: &'a crate::reexec::TermBound,
	guards: Vec<(PrincipalId, crate::reexec::Controllable)>,
	addressed_all: bool,
}

impl<'a> Minimizer<'a> {
	fn new(
		ctx: &'a VerifyContext,
		km: &'a ProtocolTrace,
		ps: &PrincipalState,
		query_index: usize,
		mut mutations: Installs,
		target: Option<&Value>,
		concrete: Option<&Query>,
	) -> Minimizer<'a> {
		let ambient = ctx.attacker_snapshot();
		let mut needs: Addressed = target
			.map(|value| crate::deduction::needs_of(km, &ambient, value))
			.unwrap_or_default();
		let support = target
			.and_then(|value| ambient.knows(value))
			.and_then(|known| ambient.worlds.get(known.get()))
			.and_then(Worlds::choose)
			.unwrap_or_else(|| needs.clone())
			.into_iter()
			.map(|(_, slot, value)| (slot, value))
			.collect();
		let addressed_all = ps
			.values
			.iter()
			.any(|sv| sv.provenance.attacker_tainted && sv.addressed);
		let signature: Vec<_> = mutations
			.iter()
			.map(|(slot, value)| (slot.get(), value.clone()))
			.collect();
		let mut compatible = crate::world::install_world(ps, &ambient, &signature, addressed_all);
		if let Some(target) = target
			&& let Some(known) = ambient.knows(target)
			&& let Some(worlds) = ambient.worlds.get(known.get())
		{
			compatible = compatible.intersect(worlds);
		}
		if let Some(support) = compatible.choose() {
			if crate::solve::solve_debug() {
				eprintln!(
					"[witness] {} query {query_index} support [{}]",
					ps.name,
					support
						.iter()
						.map(|(who, slot, value)| format!(
							"{}:{}={value}",
							km.principal_name(*who),
							km.slots[slot.get()].constant.name
						))
						.collect::<Vec<_>>()
						.join(" ")
				);
			}
			needs = support;
			for (_, slot, value) in &needs {
				if mutations.iter().any(|(existing, _)| existing == slot)
					|| ps
						.values
						.get(slot.get())
						.is_some_and(|sv| sv.original.equivalent(value, true))
				{
					continue;
				}
				mutations.push((*slot, value.clone()));
			}
		}
		let phase = ambient.current_phase;
		let mut sessions: Vec<PrincipalState> = Vec::new();
		for state in ctx.principal_states() {
			let session = state.clone_for_depth(true);
			if state.id == ps.id {
				sessions.insert(0, session);
			} else {
				sessions.push(session);
			}
		}
		if sessions.is_empty() {
			sessions.push(ps.clone_for_depth(true));
		}
		let guards = sessions
			.iter()
			.map(|session| {
				(
					session.id,
					crate::reexec::Controllable::of(km, session, &ambient),
				)
			})
			.collect();
		let mut m = Minimizer {
			ctx,
			km,
			query_index,
			concrete: concrete.cloned(),
			phase,
			ambient,
			sessions,
			mutations,
			support,
			pruned: Vec::new(),
			needs,
			everywhere: Vec::new(),
			bound: ctx.term_bound(km),
			guards,
			addressed_all,
		};
		m.everywhere = m.mitm_everywhere();
		m.support = m.controlled_by_any(m.support.clone());
		m
	}

	fn controlled(&self, session: &PrincipalState, candidate: Installs) -> Installs {
		match self.guards.iter().find(|(id, _)| *id == session.id) {
			Some((_, guard)) => admitted_by(guard, session, &self.ambient, candidate),
			None => controlled_installs(self.km, session, &self.ambient, candidate),
		}
	}

	fn controlled_by_any(&self, candidate: Installs) -> Installs {
		candidate
			.into_iter()
			.filter(|(slot, _)| {
				self.sessions.iter().any(|session| {
					self.guards
						.iter()
						.find(|(id, _)| *id == session.id)
						.is_some_and(|(_, guard)| guard.admits(session, &self.ambient, slot.get()))
				})
			})
			.collect()
	}

	fn mitm_for(&self, session: &PrincipalState) -> Installs {
		session
			.meta
			.iter()
			.enumerate()
			.filter(|(i, sm)| {
				sm.wire.contains(&session.id)
					&& self.km.slots.get(*i).is_some_and(|slot| {
						slot.creator != session.id
							&& crate::primitive::value_is_key_derivation(&slot.initial_value)
					})
			})
			.map(|(i, _)| (SlotIdx(i), attacker_public_key()))
			.collect()
	}

	fn mitm_everywhere(&self) -> Installs {
		let mut acc: Installs = Vec::new();
		for item in self.sessions.iter().flat_map(|s| self.mitm_for(s)) {
			if !acc.iter().any(|(slot, _)| *slot == item.0) {
				acc.push(item);
			}
		}
		acc
	}

	fn admitted(&self, session: &PrincipalState, candidate: Installs, wide: bool) -> Installs {
		if wide {
			self.controlled_by_any(candidate)
		} else {
			self.controlled(session, candidate)
		}
	}

	fn reachable_slots(&self, session: &PrincipalState, wide: bool) -> Vec<usize> {
		if wide {
			dedup_in_order(
				self.sessions
					.iter()
					.flat_map(|s| forgeable_slots(self.km, s)),
			)
		} else {
			forgeable_slots(self.km, session)
		}
	}

	fn forged_from(&self, session: &PrincipalState, base: Installs, wide: bool) -> Vec<Installs> {
		let keys = self.admitted(session, base, wide);
		if keys.is_empty() {
			return Vec::new();
		}
		let mine = self.controlled(session, keys.clone());
		let checks = staged_checks(self.ctx, self.km, session, &mine);
		let blank = shapes_the_checks_wanted(&checks, &mut |_| value_nil());
		let mut carrying = Vec::new();
		let mut hollow = Vec::new();
		for i in self.reachable_slots(session, wide) {
			let candidate = |shape: &Value| -> Installs {
				let mut c: Installs = keys.iter().filter(|(s, _)| s.get() != i).cloned().collect();
				c.push((SlotIdx(i), shape.clone()));
				c
			};
			for shape in payload_shapes(self.km, &self.ambient, &checks, i) {
				carrying.push(candidate(&shape));
			}
			for shape in &blank {
				hollow.push(candidate(shape));
			}
		}
		carrying.extend(hollow);
		carrying
	}

	fn scenario_cost(
		&self,
		group: &[PrincipalState],
		installs: &[(SlotIdx, Value)],
	) -> (usize, usize) {
		let mut halts = 0usize;
		let mut stuck = 0usize;
		for session in group {
			let mine = self.controlled(session, installs.to_vec());
			if mine.is_empty() {
				continue;
			}
			let Some((halted, wanting)) = self.session_cost(session, &mine) else {
				return (usize::MAX, usize::MAX);
			};
			halts += halted;
			stuck += wanting.len();
		}
		(halts, stuck)
	}

	fn session_cost(
		&self,
		session: &PrincipalState,
		mine: &Installs,
	) -> Option<(usize, Vec<usize>)> {
		let memoised = pristine(session);
		if memoised && let Some(hit) = self.ctx.staged_costs.recall(session.id, mine) {
			return hit;
		}
		let cost = self.compute_session_cost(session, mine);
		if memoised {
			self.ctx
				.staged_costs
				.remember(session.id, mine, cost.clone());
		}
		cost
	}

	fn compute_session_cost(
		&self,
		session: &PrincipalState,
		mine: &Installs,
	) -> Option<(usize, Vec<usize>)> {
		match crate::reexec::reexecute_with_failures(session, mine, &self.ambient, self.km) {
			Ok(executed) => {
				let halted = usize::from(executed.state.halted_at.is_some());
				let wanting = if mine
					.iter()
					.enumerate()
					.any(|(i, (slot, _))| mine[..i].iter().any(|(earlier, _)| earlier == slot))
				{
					staged_failures(self.ctx, self.km, session, mine)
						.into_iter()
						.map(|(at, _)| at)
						.collect()
				} else {
					executed
						.failures
						.into_iter()
						.filter_map(|(prim, at)| wanted_check(prim).map(|_| at))
						.collect()
				};
				Some((halted, wanting))
			}
			Err(_) => None,
		}
	}

	fn relevant_slots(
		&self,
		group: &[PrincipalState],
		installs: &Installs,
	) -> Option<IdSet<usize>> {
		let mut relevant: IdSet<usize> = IdSet::default();
		for session in group {
			let mine = self.controlled(session, installs.to_vec());
			if mine.is_empty() {
				continue;
			}
			let (_, failing) = self.session_cost(session, &mine)?;
			let mut frontier: Vec<usize> = failing;
			while let Some(at) = frontier.pop() {
				if !relevant.insert(at) {
					continue;
				}
				for reached in crate::deduction::own_cone(self.km, session.id, at) {
					if !relevant.contains(&reached) {
						frontier.push(reached);
					}
				}
				for (slot, value) in &mine {
					if slot.get() != at {
						continue;
					}
					for c in value.constant_leaves() {
						if let Some(reference) = session.index_of(c)
							&& !relevant.contains(&reference)
						{
							frontier.push(reference);
						}
					}
				}
			}
		}
		Some(relevant)
	}

	fn flight_shapes(
		&self,
		group: &[PrincipalState],
		installs: &Installs,
		at: usize,
	) -> Vec<Value> {
		let checks: Vec<WantedCheck> = group
			.iter()
			.flat_map(|s| {
				let mine = self.controlled(s, installs.clone());
				staged_checks(self.ctx, self.km, s, &mine)
			})
			.collect();
		if checks.is_empty() {
			return Vec::new();
		}
		let mut shapes = Shapes::from(payload_shapes(self.km, &self.ambient, &checks, at));
		for shape in shapes_the_checks_wanted(&checks, &mut |_| attacker_public_key()) {
			shapes.push_raw(shape);
		}
		for shape in shapes_the_checks_wanted(&checks, &mut |_| value_nil()) {
			shapes.push_raw(shape);
		}
		for (prim, _) in &checks {
			for argument in prim.arguments.iter() {
				shapes.push(argument.clone());
			}
		}
		if let Some((_, Value::Primitive(current))) = installs.iter().find(|(s, _)| s.get() == at) {
			let honest =
				self.km.slots.get(at).map(|slot| {
					crate::resolution::resolve_trace_term(&slot.initial_value, self.km)
				});
			let settled = |position: usize| {
				let argument = &current.arguments[position];
				let unchanged = matches!(&honest, Some(Value::Primitive(h)) if h.id == current.id
					&& h.arguments.get(position).is_some_and(|a| a.equivalent(argument, true)));
				unchanged
					&& matches!(argument, Value::Constant(c) if self
						.km
						.index_of(c)
						.and_then(|i| self.km.slots.get(i))
						.is_some_and(|slot| !slot.sent_by.is_empty()))
			};
			let wanted: Vec<Value> = shapes.values.clone();
			for shape in wanted {
				for position in 0..current.arguments.len() {
					if settled(position) || current.arguments[position].equivalent(&shape, true) {
						continue;
					}
					let mut arguments = current.arguments.clone();
					arguments[position] = shape.clone();
					let nested = Value::Primitive(std::sync::Arc::new(Primitive {
						arguments,
						hash: HashCell::default(),
						..(**current).clone()
					}));
					shapes.push(nested);
				}
			}
		}
		shapes.values
	}

	fn forged_flight(
		&self,
		session: &PrincipalState,
		base: Installs,
		wide: bool,
		relaxed: bool,
	) -> Vec<Installs> {
		let mut installs = self.admitted(session, base, wide);
		if installs.is_empty() {
			return Vec::new();
		}
		let slots: Vec<usize> = self
			.reachable_slots(session, wide)
			.into_iter()
			.filter(|&i| {
				!self
					.admitted(session, vec![(SlotIdx(i), value_nil())], wide)
					.is_empty()
			})
			.collect();
		if slots.is_empty() {
			return Vec::new();
		}
		let bound = self.bound;
		let group: &[PrincipalState] = if wide {
			&self.sessions
		} else {
			std::slice::from_ref(session)
		};
		let _memo = crate::theory::DeductionMemo::scoped(session, &self.ambient, None);
		let mut out: Vec<Installs> = Vec::new();
		let mut seen: Vec<Installs> = vec![installs.clone()];
		let mut here = self.scenario_cost(group, &installs);
		let mut relevant = if relaxed && here != (usize::MAX, usize::MAX) {
			self.relevant_slots(group, &installs)
		} else {
			None
		};
		for _ in 0..slots.len() {
			let mut advanced = false;
			for i in &slots {
				if here == (0, 0) {
					break;
				}
				if relevant
					.as_ref()
					.is_some_and(|relevant| !relevant.contains(i))
				{
					continue;
				}
				let shapes = self.flight_shapes(group, &installs, *i);
				if shapes.is_empty() {
					break;
				}
				let honest = self.km.slots.get(*i).map(|slot| {
					crate::resolution::resolve_trace_term(&slot.initial_value, self.km)
				});
				let trials: Vec<Installs> = shapes
					.into_iter()
					.filter_map(|shape| {
						if !self.validator_admits(session, bound, *i, &shape) {
							return None;
						}
						if honest.as_ref().is_some_and(|h| h.equivalent(&shape, true)) {
							return None;
						}
						let mut trial: Installs = installs
							.iter()
							.filter(|(s, _)| s.get() != *i)
							.cloned()
							.collect();
						trial.push((SlotIdx(*i), shape));
						let trial = self.admitted(session, trial, wide);
						if !trial.iter().any(|(s, _)| s.get() == *i) {
							return None;
						}
						if seen.iter().any(|s| same_install_set(s, &trial)) {
							return None;
						}
						Some(trial)
					})
					.collect();
				let accepted = trials.into_iter().filter_map(|trial| {
					let cost = self.scenario_cost(group, &trial);
					((relaxed && cost < here) || (!relaxed && cost <= here))
						.then_some((trial, cost))
				});
				if let Some((trial, cost)) = accepted.min_by_key(|(_, cost)| *cost) {
					seen.push(trial.clone());
					installs = trial;
					here = cost;
					advanced = true;
					if relaxed && here != (usize::MAX, usize::MAX) {
						relevant = self.relevant_slots(group, &installs);
					}
				}
			}
			if !advanced {
				break;
			}
			out.push(installs.clone());
		}
		out.reverse();
		out
	}

	fn forged_alone(&self, session: &PrincipalState) -> Vec<Installs> {
		let mut carrying = Vec::new();
		let mut hollow = Vec::new();
		for i in forgeable_slots(self.km, session) {
			let blanked = vec![(SlotIdx(i), value_nil())];
			if self.controlled(session, blanked.clone()).is_empty() {
				continue;
			}
			let checks = staged_checks(self.ctx, self.km, session, &blanked);
			for shape in payload_shapes(self.km, &self.ambient, &checks, i) {
				carrying.push(vec![(SlotIdx(i), shape)]);
			}
			for shape in shapes_the_checks_wanted(&checks, &mut |_| value_nil()) {
				hollow.push(vec![(SlotIdx(i), shape)]);
			}
		}
		carrying.extend(hollow);
		carrying
	}

	fn replayed_from(&self, session: &PrincipalState) -> Vec<Installs> {
		let mut flights: Vec<Installs> = Vec::new();
		let mut singles: Vec<Installs> = Vec::new();
		for (i, sm) in session.meta.iter().enumerate() {
			if sm.wire.is_empty() {
				continue;
			}
			let siblings = crate::query::copy_sibling_values(&sm.constant, self.km);
			for (n, sibling) in siblings.into_iter().enumerate() {
				if flights.len() <= n {
					flights.push(Vec::new());
				}
				flights[n].push((SlotIdx(i), sibling.clone()));
				singles.push(vec![(SlotIdx(i), sibling)]);
			}
		}
		let mut out: Vec<Installs> = flights.into_iter().filter(|f| f.len() > 1).collect();
		out.extend(singles);
		out
	}

	fn family(&self, family: Family, session: &PrincipalState) -> Vec<(Installs, Addressed)> {
		match family {
			Family::SplitRecipients => self.split_recipients(),
			other => self
				.plain_family(other, session)
				.into_iter()
				.map(|installs| (installs, Vec::new()))
				.collect(),
		}
	}

	fn plain_family(&self, family: Family, session: &PrincipalState) -> Vec<Installs> {
		match family {
			Family::SingleSlot => self.single_slot(session),
			Family::WholeFlight => self.whole_flight(session),
			Family::AcrossSessions => self.across_sessions(session),
			Family::SplitRecipients => Vec::new(),
		}
	}

	fn split_recipients(&self) -> Vec<(Installs, Addressed)> {
		let mut split: Vec<SlotIdx> = Vec::new();
		for (at, slot, value) in &self.needs {
			let differs = self
				.needs
				.iter()
				.any(|(other, s, v)| s == slot && other != at && !v.equivalent(value, true));
			if differs && !split.contains(slot) {
				split.push(*slot);
			}
		}
		if split.is_empty() {
			return Vec::new();
		}
		let addressed: Addressed = self
			.needs
			.iter()
			.filter(|(at, slot, _)| {
				split.contains(slot)
					&& self.sessions.iter().any(|session| {
						session.id == *at
							&& self
								.guards
								.iter()
								.find(|(id, _)| *id == session.id)
								.is_some_and(|(_, guard)| {
									guard.admits(session, &self.ambient, slot.get())
								})
					})
			})
			.cloned()
			.collect();
		if addressed.is_empty() {
			return Vec::new();
		}
		let shared: Installs = self
			.mutations
			.iter()
			.filter(|(s, _)| !split.contains(s))
			.cloned()
			.collect();
		vec![(shared, addressed)]
	}

	fn seeds(&self) -> Vec<Installs> {
		let mut seeds = if self.pruned.len() == self.mutations.len() {
			vec![self.mutations.clone()]
		} else {
			vec![self.pruned.clone(), self.mutations.clone()]
		};
		if !self.support.is_empty()
			&& !seeds
				.iter()
				.any(|seed| same_install_set(seed, &self.support))
		{
			seeds.insert(0, self.support.clone());
		}
		seeds
	}

	fn prune_seed(&self) -> Installs {
		let Some(session) = self.sessions.first() else {
			return self.mutations.clone();
		};
		let mut keep = self.controlled(session, self.mutations.clone());
		if keep.is_empty() {
			return self.mutations.clone();
		}
		for (slot, _) in self.mutations.clone() {
			let trial: Installs = keep.iter().filter(|(s, _)| *s != slot).cloned().collect();
			if trial.len() == keep.len() || trial.is_empty() {
				continue;
			}
			if self.probe_at(session, &trial, &[], Breadth::Base).is_some() {
				keep = trial;
			}
		}
		keep
	}

	fn single_slot(&self, session: &PrincipalState) -> Vec<Installs> {
		let mut families = vec![self.mitm_for(session)];
		families.extend(self.seeds());
		families.extend(self.forged_from(session, self.mitm_for(session), false));
		for seed in self.seeds() {
			families.extend(self.forged_from(session, seed, false));
		}
		families.extend(self.forged_alone(session));
		families.extend(self.replayed_from(session));
		families
	}

	fn whole_flight(&self, session: &PrincipalState) -> Vec<Installs> {
		let mut families: Vec<Installs> = Vec::new();
		for relaxed in [false, true] {
			for base in std::iter::once(self.mitm_for(session)).chain(self.seeds()) {
				families.extend(self.forged_flight(session, base, false, relaxed));
			}
		}
		families
	}

	fn across_sessions(&self, session: &PrincipalState) -> Vec<Installs> {
		let mut families = self.seeds();
		families.push(self.everywhere.clone());
		families.extend(self.forged_from(session, self.everywhere.clone(), true));
		for seed in self.seeds() {
			families.extend(self.forged_from(session, seed, true));
		}
		families.extend(self.replayed_from(session));
		for relaxed in [false, true] {
			for base in std::iter::once(self.everywhere.clone()).chain(self.seeds()) {
				families.extend(self.forged_flight(session, base, false, relaxed));
			}
		}
		families
	}

	fn probe_at(
		&self,
		base: &PrincipalState,
		installs: &[(SlotIdx, Value)],
		addressed: &[(PrincipalId, SlotIdx, Value)],
		breadth: Breadth,
	) -> Option<Witness> {
		probe_with(
			self.ctx,
			self.km,
			base,
			installs,
			addressed,
			self.query_index,
			self.phase,
			breadth,
			self.addressed_all,
			self.concrete.as_ref(),
		)
	}

	fn addressed_buildable(&self, addressed: &[(PrincipalId, SlotIdx, Value)]) -> bool {
		let bound = self.bound;
		addressed.iter().all(|(at, slot, value)| {
			self.sessions
				.iter()
				.find(|session| session.id == *at)
				.is_some_and(|session| self.validator_admits(session, bound, slot.get(), value))
		})
	}

	fn buildable(&self, session: &PrincipalState, candidate: &Installs) -> bool {
		if candidate.is_empty() {
			return false;
		}
		let bound = self.bound;
		candidate
			.iter()
			.all(|(slot, value)| self.validator_admits(session, bound, slot.get(), value))
	}

	fn validator_admits(
		&self,
		session: &PrincipalState,
		bound: &crate::reexec::TermBound,
		slot: usize,
		value: &Value,
	) -> bool {
		crate::primitive::admissible(value)
			&& bound.admits_at(self.km, session.id, slot, value)
			&& !crate::solve::validate::contains_failed_check(value)
			&& crate::solve::validate::attacker_can_derive(
				self.ctx,
				slot,
				value,
				session,
				&self.ambient,
				&|_| None,
			)
			.is_some()
	}

	fn choose(&self) -> Option<Chosen> {
		let mut chosen: Option<(PrincipalState, Installs, Addressed, Breadth, bool, bool)> = None;
		for rung in LADDER {
			if chosen
				.as_ref()
				.is_some_and(|(_, _, _, _, grounded, _)| *grounded)
			{
				break;
			}
			'rung: for session in &self.sessions {
				for (candidate, addressed) in self.family(rung.family, session) {
					let candidate = match rung.scope {
						Scope::Own => self.controlled(session, candidate),
						Scope::Any => self.controlled_by_any(candidate),
					};
					if (candidate.is_empty() && addressed.is_empty())
						|| (!candidate.is_empty() && !self.buildable(session, &candidate))
						|| !self.addressed_buildable(&addressed)
					{
						continue;
					}
					let Some(witness) =
						self.probe_at(session, &candidate, &addressed, rung.breadth)
					else {
						continue;
					};
					let halted = witness.ps.halted_at.is_some();
					let better = match chosen.as_ref() {
						None => true,
						Some((base, _, _, _, was_grounded, was_halted)) => {
							(witness.grounded && !*was_grounded)
								|| (base.id == session.id
									&& witness.grounded == *was_grounded
									&& !halted && *was_halted)
						}
					};
					if better {
						chosen = Some((
							session.clone(),
							candidate,
							addressed,
							rung.breadth,
							witness.grounded,
							halted,
						));
					}
					if witness.grounded && !halted {
						break 'rung;
					}
				}
				if chosen
					.as_ref()
					.is_some_and(|(_, _, _, _, grounded, _)| *grounded)
				{
					break 'rung;
				}
			}
		}
		chosen.map(|(base, installs, addressed, breadth, grounded, _)| Chosen {
			base,
			installs,
			addressed,
			breadth,
			grounded,
		})
	}

	fn drop_one(&self, chosen: &Chosen) -> (Installs, Addressed) {
		let Chosen {
			base,
			installs,
			addressed,
			breadth,
			grounded,
		} = chosen;
		let mut keep = installs.clone();
		let mut keep_addressed = addressed.clone();
		let mut settled = false;
		while !settled {
			settled = true;
			for (slot, _) in installs {
				let trial: Installs = keep.iter().filter(|(s, _)| s != slot).cloned().collect();
				if trial.len() == keep.len() {
					continue;
				}
				let Some(witness) = self.probe_at(base, &trial, &keep_addressed, *breadth) else {
					continue;
				};
				if *grounded && !witness.grounded {
					continue;
				}
				keep = trial;
				settled = false;
			}
		}
		for (at, slot, _) in addressed {
			let trial: Addressed = keep_addressed
				.iter()
				.filter(|(a, s, _)| !(a == at && s == slot))
				.cloned()
				.collect();
			if trial.len() == keep_addressed.len() {
				continue;
			}
			let Some(witness) = self.probe_at(base, &keep, &trial, *breadth) else {
				continue;
			};
			if *grounded && !witness.grounded {
				continue;
			}
			keep_addressed = trial;
		}
		(keep, keep_addressed)
	}
}

struct Chosen {
	base: PrincipalState,
	installs: Installs,
	addressed: Addressed,
	breadth: Breadth,
	grounded: bool,
}

fn seeded_mutations(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	seed: &[(SlotIdx, Value)],
	attacker: &AttackerState,
	target: Option<&Value>,
	prune_history: bool,
) -> Installs {
	let mut mutations: Installs = if seed.is_empty() {
		ps.values
			.iter()
			.enumerate()
			.filter(|(_, sv)| sv.provenance.attacker_tainted)
			.map(|(i, sv)| (SlotIdx(i), sv.pre_rewrite.clone()))
			.collect()
	} else {
		seed.iter()
			.filter(|(slot, _)| slot.get() < km.slots.len())
			.cloned()
			.collect()
	};
	for (slot, sv) in ps.values.iter().enumerate() {
		if !sv.provenance.attacker_tainted || sv.provenance.creator == ATTACKER_ID {
			continue;
		}
		let Some(known) = attacker.knows(&sv.value) else {
			continue;
		};
		let Some(record) = attacker.routes(known).find_map(|(derivation, record)| {
			let record = record?;
			(matches!(derivation, DerivationRecord::Obtained { slot: observed } if observed.get() == slot)
				&& record.principal_id == sv.provenance.creator)
				.then_some(record)
		}) else {
			continue;
		};
		for diff in record.tainted() {
			if !mutations.iter().any(|(slot, _)| *slot == diff.index) {
				mutations.push((diff.index, diff.value.clone()));
			}
		}
	}
	close_over_history(
		km,
		attacker,
		&mut mutations,
		target,
		seed.is_empty(),
		prune_history,
	);
	mutations.sort_by_key(|(slot, _)| *slot);
	mutations
}

fn close_over_history(
	km: &ProtocolTrace,
	attacker: &AttackerState,
	mutations: &mut Installs,
	target: Option<&Value>,
	seeded: bool,
	prune_history: bool,
) {
	let mut seen: Vec<KnownIdx> = Vec::new();
	let mut generation: Vec<KnownIdx> = Vec::new();
	for (_, value) in mutations.iter() {
		enqueue_history(attacker, value, &mut seen, &mut generation);
	}
	if let Some(target) = target
		&& !seeded
	{
		enqueue_history(attacker, target, &mut seen, &mut generation);
	}
	let mut next: Vec<KnownIdx> = Vec::new();
	while !generation.is_empty() {
		for idx in generation.drain(..) {
			let coexists = |record: &MutationRecord| {
				record.tainted().all(|diff| {
					!mutations.iter().any(|(slot, value)| {
						*slot == diff.index && !value.equivalent(&diff.value, true)
					})
				})
			};
			let Some((derivation, record)) = attacker
				.routes(idx)
				.filter_map(|(derivation, record)| record.map(|record| (derivation, record)))
				.find(|(_, record)| coexists(record))
				.or_else(|| attacker.derivation(idx).zip(attacker.record(idx)))
			else {
				continue;
			};
			let cone = match derivation {
				DerivationRecord::Obtained { slot } | DerivationRecord::Leaked { slot }
					if prune_history =>
				{
					km.slots
						.get(slot.get())
						.map(|source| crate::deduction::reach_cone(km, source.creator, slot.get()))
				}
				_ if prune_history => {
					for ingredient in derivation.ingredients() {
						enqueue_history(attacker, ingredient, &mut seen, &mut next);
					}
					continue;
				}
				_ => None,
			};
			for diff in record.tainted() {
				if diff.index.get() >= km.slots.len()
					|| cone
						.as_ref()
						.is_some_and(|cone| !cone.contains(&diff.index.get()))
				{
					continue;
				}
				if !mutations.iter().any(|(slot, _)| *slot == diff.index) {
					mutations.push((diff.index, diff.value.clone()));
				}
				enqueue_history(attacker, &diff.value, &mut seen, &mut next);
			}
		}
		std::mem::swap(&mut generation, &mut next);
	}
}

fn enqueue_history(
	attacker: &AttackerState,
	value: &Value,
	seen: &mut Vec<KnownIdx>,
	next: &mut Vec<KnownIdx>,
) {
	if let Some(idx) = attacker.knows(value)
		&& !seen.contains(&idx)
		&& !costs_nothing(attacker, idx, &mut Vec::new())
	{
		seen.push(idx);
		next.push(idx);
	}
	if let Value::Primitive(p) = value {
		for argument in p.arguments.iter() {
			enqueue_history(attacker, argument, seen, next);
		}
	}
}

fn costs_nothing(attacker: &AttackerState, idx: KnownIdx, walked: &mut Vec<KnownIdx>) -> bool {
	if walked.contains(&idx) {
		return true;
	}
	walked.push(idx);
	match attacker.derivation(idx) {
		Some(DerivationRecord::Initial) => true,
		Some(DerivationRecord::Leaked { .. } | DerivationRecord::Obtained { .. }) | None => false,
		Some(other) => other.ingredients().iter().all(|ingredient| {
			attacker
				.knows(ingredient)
				.is_some_and(|found| costs_nothing(attacker, found, walked))
		}),
	}
}

pub(crate) fn minimize_witness(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	query_index: usize,
	seed: &[(SlotIdx, Value)],
	target: Option<&Value>,
	concrete: Option<&Query>,
) -> Witness {
	let unminimized = |reproduced: bool| Witness {
		ps: ps.clone(),
		#[cfg(test)]
		driver: ps.id,
		others: Vec::new(),
		#[cfg(test)]
		wide: false,
		attacker: ctx.attacker_snapshot(),
		reproduced,
		grounded: reproduced,
		out_of_order: Vec::new(),
		#[cfg(test)]
		installs: Vec::new(),
		#[cfg(test)]
		addressed: Vec::new(),
	};

	if in_minimization() {
		return unminimized(true);
	}

	let _guard = MinimizingGuard::new();
	let _quiet = InfoQuiet::new();

	let mutations = seeded_mutations(km, ps, seed, &ctx.attacker_snapshot(), target, false);
	if crate::solve::solve_debug() {
		eprintln!(
			"[witness] {} query {query_index} seed [{}]",
			ps.name,
			mutations
				.iter()
				.map(|(slot, value)| format!("{}={value}", km.slots[slot.get()].constant.name))
				.collect::<Vec<_>>()
				.join(" ")
		);
	}
	if mutations.is_empty() {
		let base = ctx
			.principal_states()
			.iter()
			.find(|state| state.id == ps.id)
			.unwrap_or(ps)
			.clone_for_depth(true);
		if let Some(witness) = probe(
			ctx,
			km,
			&base,
			&[],
			query_index,
			ctx.attacker_snapshot().current_phase,
			concrete,
		) {
			return witness;
		}
	}
	let mut m = Minimizer::new(ctx, km, ps, query_index, mutations, target, concrete);
	m.pruned = m.prune_seed();

	let mut chosen = m.choose();
	if chosen.as_ref().is_none_or(|chosen| !chosen.grounded) {
		let mutations = seeded_mutations(km, ps, seed, &m.ambient, target, true);
		if !same_install_set(&mutations, &m.mutations) {
			let mut retry = Minimizer::new(ctx, km, ps, query_index, mutations, target, concrete);
			retry.pruned = retry.prune_seed();
			if let Some(recovered) = retry.choose().filter(|chosen| chosen.grounded) {
				m = retry;
				chosen = Some(recovered);
			}
		}
	}
	let Some(chosen) = chosen else {
		return unminimized(false);
	};
	let (keep, keep_addressed) = m.drop_one(&chosen);
	let base = chosen.base;
	let breadth = chosen.breadth;

	match m.probe_at(&base, &keep, &keep_addressed, breadth) {
		Some(mut witness) => {
			#[cfg(test)]
			for (slot, value) in &keep {
				assert!(
					crate::solve::validate::attacker_can_derive(
						ctx,
						slot.get(),
						value,
						&base,
						&m.ambient,
						&|_| None,
					)
					.is_some(),
					"WITNESS \u{2022} query {} is explained by installing {} into {}, a term the \
					 attacker cannot build from what it knows. A trace naming a substitution \
					 nothing derives is a trace a reader cannot follow.",
					query_index,
					value,
					km.slots
						.get(slot.get())
						.map(|s| s.constant.name.to_string())
						.unwrap_or_default(),
				);
			}
			witness.out_of_order = if keep_addressed.is_empty() {
				out_of_order_harvest(
					ctx,
					km,
					&base,
					&keep,
					query_index,
					m.phase,
					m.concrete.as_ref(),
				)
			} else {
				Vec::new()
			};
			#[cfg(test)]
			{
				witness.installs = keep;
				witness.addressed = keep_addressed;
			}
			witness
		}
		None => unminimized(false),
	}
}

pub(crate) fn forged_check_flights(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	signature: &[(usize, Value)],
) -> Vec<Vec<(usize, Value)>> {
	let installs: Installs = signature
		.iter()
		.map(|(slot, value)| (SlotIdx(*slot), value.clone()))
		.collect();
	let attacker = ctx.attacker_snapshot();
	if !staged_checks(ctx, km, ps, &installs)
		.iter()
		.any(|(check, _)| {
			crate::primitive::primitive_extract_check_key(check)
				.is_some_and(|key| crate::theory::obtainable(&key, ps, &attacker))
		}) {
		return Vec::new();
	}
	let _guard = MinimizingGuard::new();
	let _quiet = InfoQuiet::new();
	let m = Minimizer::new(ctx, km, ps, 0, installs.clone(), None, None);
	m.forged_flight(ps, installs, false, true)
		.into_iter()
		.map(|flight| {
			flight
				.into_iter()
				.map(|(slot, value)| (slot.get(), value))
				.collect()
		})
		.collect()
}

fn same_install_set(a: &[(SlotIdx, Value)], b: &[(SlotIdx, Value)]) -> bool {
	a.len() == b.len()
		&& a.iter().all(|(slot, value)| {
			b.iter()
				.any(|(s, v)| s == slot && v.equivalent(value, true))
		})
}

fn forgeable_slots(km: &ProtocolTrace, session: &PrincipalState) -> Vec<usize> {
	session
		.meta
		.iter()
		.enumerate()
		.filter(|(i, sm)| {
			sm.wire.contains(&session.id)
				&& km.slots.get(*i).is_some_and(|slot| {
					slot.creator != session.id
						&& !crate::primitive::value_is_key_derivation(&slot.initial_value)
				})
		})
		.map(|(i, _)| i)
		.collect()
}

pub(crate) type WantedCheck = (Primitive, Option<&'static crate::primitive::RewriteRule>);

fn pristine(session: &PrincipalState) -> bool {
	session.halted_at.is_none()
		&& !session.forwarded
		&& session.foreign_halts.is_empty()
		&& session.starved.is_empty()
		&& session.values.iter().all(|sv| {
			sv.installed_at.is_none()
				&& !sv.addressed
				&& !sv.provenance.attacker_tainted
				&& same_value(&sv.value, &sv.original)
				&& same_value(&sv.pre_rewrite, &sv.original)
		})
}

fn same_value(a: &Value, b: &Value) -> bool {
	match (a, b) {
		(Value::Primitive(a), Value::Primitive(b)) => std::sync::Arc::ptr_eq(a, b),
		(Value::Constant(a), Value::Constant(b)) => a.id == b.id,
		_ => false,
	}
}

fn staged_checks(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	session: &PrincipalState,
	installs: &[(SlotIdx, Value)],
) -> Vec<WantedCheck> {
	staged_failures(ctx, km, session, installs)
		.into_iter()
		.map(|(_, check)| check)
		.collect()
}

fn staged_failures(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	session: &PrincipalState,
	installs: &[(SlotIdx, Value)],
) -> Vec<(usize, WantedCheck)> {
	if !pristine(session) {
		return failures_wanting_shapes(km, session, installs);
	}
	if let Some(hit) = ctx.staged_checks.recall(session.id, installs) {
		return hit;
	}
	let failures = failures_wanting_shapes(km, session, installs);
	ctx.staged_checks
		.remember(session.id, installs, failures.clone());
	failures
}

fn wanted_check(prim: Primitive) -> Option<WantedCheck> {
	match crate::primitive::primitive_get(prim.id) {
		Ok(spec) => spec.rewrite.as_ref().map(|rule| (prim, Some(rule))),
		Err(_) => crate::primitive::primitive_is_core(prim.id).then_some((prim, None)),
	}
}

fn failures_wanting_shapes(
	km: &ProtocolTrace,
	session: &PrincipalState,
	installs: &[(SlotIdx, Value)],
) -> Vec<(usize, WantedCheck)> {
	let mut staged = session.clone();
	for (slot, value) in installs {
		if slot.get() >= staged.values.len() {
			continue;
		}
		let authored = crate::reexec::attacker_authored(value, slot.get(), km, &staged);
		crate::reexec::install(
			&mut staged,
			slot.get(),
			value.clone(),
			authored,
			None,
			false,
		);
	}
	if crate::reexec::slot_graph_is_cyclic_from(
		&staged,
		installs.iter().map(|(slot, _)| slot.get()),
	) || staged.resolve_all_values().is_err()
	{
		return Vec::new();
	}
	staged
		.perform_all_rewrites()
		.into_iter()
		.filter_map(|(prim, at)| wanted_check(prim).map(|check| (at, check)))
		.collect()
}

fn shapes_the_checks_wanted(
	checks: &[WantedCheck],
	fill: &mut dyn FnMut(usize) -> Value,
) -> Vec<Value> {
	let mut shapes = Shapes::default();
	for (prim, rule) in checks {
		let Some(rule) = rule else {
			continue;
		};
		for shape in crate::solve::deduce::build_rewrite_shapes_with(prim, rule, &mut *fill) {
			shapes.push(shape);
		}
	}
	shapes.values
}

#[derive(Default)]
struct Shapes {
	values: Vec<Value>,
	buckets: IdMap<u64, Vec<usize>>,
}

impl Shapes {
	fn from(values: Vec<Value>) -> Shapes {
		let mut shapes = Shapes::default();
		for value in values {
			shapes.push_raw(value);
		}
		shapes
	}

	fn push_raw(&mut self, value: Value) {
		self.buckets
			.entry(value.hash_value())
			.or_default()
			.push(self.values.len());
		self.values.push(value);
	}

	fn contains(&self, value: &Value) -> bool {
		self.buckets.get(&value.hash_value()).is_some_and(|bucket| {
			bucket
				.iter()
				.any(|&at| self.values[at].equivalent(value, true))
		})
	}

	fn push(&mut self, value: Value) {
		if !self.contains(&value) {
			self.push_raw(value);
		}
	}
}

fn payload_shapes(
	km: &ProtocolTrace,
	attacker: &AttackerState,
	checks: &[WantedCheck],
	slot: usize,
) -> Vec<Value> {
	if checks.is_empty() {
		return Vec::new();
	}
	let Some(honest) = km.slots.get(slot) else {
		return Vec::new();
	};
	let resolved = crate::resolution::resolve_trace_term(&honest.initial_value, km);
	let Value::Primitive(carried) = resolved else {
		return Vec::new();
	};
	let usable = |v: &Value| !v.equivalent(&value_nil(), true) && attacker.knows(v).is_some();
	if !carried.arguments.iter().any(usable) {
		return Vec::new();
	}
	let mut meaningful = false;
	let mut fill = |position: usize| -> Value {
		match carried.arguments.get(position) {
			Some(argument) if usable(argument) => {
				meaningful = true;
				argument.clone()
			}
			_ => value_nil(),
		}
	};
	let shapes = shapes_the_checks_wanted(checks, &mut fill);
	let mut keyed_any = false;
	let mut keyed = |position: usize| -> Value {
		match carried.arguments.get(position) {
			Some(argument) if crate::primitive::value_is_key_derivation(argument) => {
				keyed_any = true;
				crate::primitive::attacker_public_key()
			}
			Some(argument) if usable(argument) => argument.clone(),
			_ => value_nil(),
		}
	};
	let swapped = shapes_the_checks_wanted(checks, &mut keyed);
	let mut out = shapes;
	if keyed_any {
		out.extend(swapped);
	} else if !meaningful {
		return Vec::new();
	}
	out.into_iter()
		.filter(|shape| attacker_can_build(shape, attacker))
		.collect()
}

pub(crate) fn attacker_can_build(shape: &Value, attacker: &AttackerState) -> bool {
	if attacker.knows(shape).is_some() {
		return true;
	}
	match shape {
		Value::Constant(_) => false,
		Value::Primitive(p) => p.arguments.iter().all(|a| attacker_can_build(a, attacker)),
	}
}

fn controlled_installs(
	km: &ProtocolTrace,
	session: &PrincipalState,
	attacker: &AttackerState,
	candidate: Installs,
) -> Installs {
	let controllable = crate::reexec::Controllable::of(km, session, attacker);
	admitted_by(&controllable, session, attacker, candidate)
}

fn admitted_by(
	controllable: &crate::reexec::Controllable,
	session: &PrincipalState,
	attacker: &AttackerState,
	candidate: Installs,
) -> Installs {
	candidate
		.into_iter()
		.filter(|(slot, _)| controllable.admits(session, attacker, slot.get()))
		.collect()
}

fn out_of_order_harvest(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	query_index: usize,
	phase: i32,
	concrete: Option<&Query>,
) -> Vec<String> {
	let ambient = ctx.attacker_snapshot();
	let mut harvested: Vec<String> = Vec::new();
	let renamed: Installs = installs
		.iter()
		.map(
			|(slot, v)| match harvested_late(km, &ambient, base.id, *slot, v) {
				true => (*slot, rename_own_fresh(v, base, &mut harvested)),
				false => (*slot, v.clone()),
			},
		)
		.collect();
	if harvested.is_empty() {
		return harvested;
	}
	if probe(ctx, km, base, &renamed, query_index, phase, concrete).is_some() {
		return Vec::new();
	}
	harvested.sort();
	harvested.dedup();
	harvested
}

fn harvested_late(
	km: &ProtocolTrace,
	ambient: &AttackerState,
	target: PrincipalId,
	into: SlotIdx,
	v: &Value,
) -> bool {
	if !km
		.slots
		.get(into.get())
		.is_some_and(|slot| slot.sent_by.iter().any(|event| event.recipient == target))
	{
		return false;
	}
	match ambient.knows(v).and_then(|idx| ambient.derivation(idx)) {
		Some(DerivationRecord::Obtained { slot }) | Some(DerivationRecord::Leaked { slot }) => {
			slot.get() >= into.get()
				&& km
					.slots
					.get(slot.get())
					.is_some_and(|s| s.creator == target)
		}
		_ => false,
	}
}

fn rename_own_fresh(v: &Value, ps: &PrincipalState, seen: &mut Vec<String>) -> Value {
	match v {
		Value::Constant(c) => {
			// Read freshness off the slot rather than off the occurrence: a
			// constant reached by inlining carries the identifier but not
			// necessarily the declaration flags.
			let own = ps.index_of(c).is_some_and(|i| {
				ps.meta[i].constant.fresh && ps.values[i].provenance.creator == ps.id
			});
			if own {
				seen.push(c.name.to_string());
				crate::value::session_copy(c)
			} else {
				v.clone()
			}
		}
		Value::Primitive(p) => {
			let arguments = p
				.arguments
				.iter()
				.map(|a| rename_own_fresh(a, ps, seen))
				.collect();
			Value::Primitive(std::sync::Arc::new(p.with_arguments(arguments)))
		}
	}
}

#[cfg(test)]
pub(crate) fn assert_reported_attacks_replay(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	file_name: &str,
) {
	for result in ctx.results_get() {
		if !result.resolved {
			continue;
		}
		let Some(witness) = ctx.witness_get(result.query_index) else {
			continue;
		};
		if !witness.reproduced {
			continue;
		}
		let Some(base) = ctx
			.principal_states()
			.iter()
			.find(|s| s.id == witness.principal)
			.map(|s| s.clone_for_depth(true))
		else {
			continue;
		};
		let name_of = |slot: &SlotIdx| {
			base.meta
				.get(slot.get())
				.map(|sm| sm.constant.name.to_string())
				.unwrap_or_else(|| format!("slot {slot}"))
		};
		let listing: Vec<String> = witness
			.installs
			.iter()
			.map(|(slot, value)| format!("      {} := {}", name_of(slot), value))
			.chain(witness.addressed.iter().map(|(at, slot, value)| {
				format!(
					"      {} := {} (into {})",
					name_of(slot),
					value,
					km.principal_name(*at)
				)
			}))
			.collect();
		let caveat = if witness.out_of_order.is_empty() {
			String::new()
		} else {
			format!(
				"\n    and on {} being fed a value it only computes later, built from {}",
				base.name,
				witness.out_of_order.join(", ")
			)
		};
		assert!(
			replays(
				ctx,
				km,
				&base,
				&witness.installs,
				&witness.addressed,
				result.query_index,
				witness.phase,
				witness.wide,
				witness.addressed_all,
			),
			"WITNESS • {} query {} ({}) reports an attack that its own minimized \
			 witness does not reproduce. Re-executing {}'s session at phase {} with \
			 exactly these substitutions left the query unresolved, so the verdict \
			 and the reason recorded for it disagree.\n\n{}{}\n",
			file_name,
			result.query_index,
			result.query,
			base.name,
			witness.phase,
			listing.join("\n"),
			caveat,
		);
		let bound = crate::reexec::TermBound::of(km);
		let ambient = ctx.attacker_snapshot();
		let admits = |state: &PrincipalState, slot: &SlotIdx, value: &Value| {
			crate::primitive::admissible(value)
				&& bound.admits_at(km, state.id, slot.get(), value)
				&& !crate::solve::validate::contains_failed_check(value)
				&& crate::solve::validate::attacker_can_derive(
					ctx,
					slot.get(),
					value,
					state,
					&ambient,
					&|_| None,
				)
				.is_some()
		};
		let mut unjustified: Vec<String> = witness
			.installs
			.iter()
			.filter(|(slot, value)| !admits(&base, slot, value))
			.map(|(slot, value)| format!("{} := {}", name_of(slot), value))
			.collect();
		for (at, slot, value) in &witness.addressed {
			let justified = ctx
				.principal_states()
				.iter()
				.find(|s| s.id == *at)
				.map(|s| s.clone_for_depth(true))
				.is_some_and(|state| admits(&state, slot, value));
			if !justified {
				unjustified.push(format!(
					"{} := {} (into {})",
					name_of(slot),
					value,
					km.principal_name(*at)
				));
			}
		}
		assert!(
			unjustified.is_empty(),
			"WITNESS \u{2022} {} query {} ({}) prints a trace that installs {} term(s) \
			 the validator would have rejected: {}. The verdict is validated, so every \
			 step the reader is shown has to be one the attacker could actually take.\n\n{}{}\n",
			file_name,
			result.query_index,
			result.query,
			unjustified.len(),
			unjustified.join(", "),
			listing.join("\n"),
			caveat,
		);

		let missing: Vec<String> = witness
			.installs
			.iter()
			.map(|(slot, _)| *slot)
			.chain(witness.addressed.iter().map(|(_, slot, _)| *slot))
			.filter(|slot| !witness.narrated.contains(slot))
			.map(|slot| name_of(&slot))
			.collect();
		assert!(
			missing.is_empty(),
			"WITNESS • {} query {} ({}) prints a trace that omits {} substitution(s) \
			 the witness needed: {}. A reader following the trace cannot reach the \
			 verdict it reports.\n\n{}{}\n",
			file_name,
			result.query_index,
			result.query,
			missing.len(),
			missing.join(", "),
			listing.join("\n"),
			caveat,
		);
	}
}

#[cfg(test)]
pub(crate) fn minimization_guard() -> impl Drop {
	MinimizingGuard::new()
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn replays(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	addressed: &[(PrincipalId, SlotIdx, Value)],
	query_index: usize,
	phase: i32,
	wide: bool,
	addressed_all: bool,
) -> bool {
	let _guard = MinimizingGuard::new();
	let _quiet = InfoQuiet::new();
	let breadth = if wide || !addressed.is_empty() {
		Breadth::All
	} else {
		Breadth::Base
	};
	probe_with(
		ctx,
		km,
		base,
		installs,
		addressed,
		query_index,
		phase,
		breadth,
		addressed_all,
		None,
	)
	.is_some()
}

fn probe(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	query_index: usize,
	phase: i32,
	concrete: Option<&Query>,
) -> Option<Witness> {
	probe_with(
		ctx,
		km,
		base,
		installs,
		&[],
		query_index,
		phase,
		Breadth::Base,
		false,
		concrete,
	)
}

#[allow(clippy::too_many_arguments)]
fn probe_with(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	base: &PrincipalState,
	shared: &[(SlotIdx, Value)],
	addressed: &[(PrincipalId, SlotIdx, Value)],
	query_index: usize,
	phase: i32,
	breadth: Breadth,
	addressed_all: bool,
	concrete: Option<&Query>,
) -> Option<Witness> {
	let mut own: Installs = shared.to_vec();
	for (slot, value) in addressed_to(addressed, base.id) {
		if !own.iter().any(|(s, _)| *s == slot) {
			own.push((slot, value));
		}
	}
	let installs: &[(SlotIdx, Value)] = &own;
	let breadth = if addressed.is_empty() {
		breadth
	} else {
		Breadth::All
	};
	let scratch = ctx.scratch_for_witness(query_index, concrete);
	match ctx.cached_baseline(base.id, phase) {
		Some(baseline) => scratch.install_baseline(&baseline),
		None => {
			crate::verify::attacker_seed_phase(&scratch, km, base, phase).ok()?;
			for state in ctx.principal_states() {
				let mut honest = state.clone_for_depth(true);
				if honest.resolve_all_values().is_err() {
					continue;
				}
				let _ = honest.perform_all_rewrites();
				let honest = crate::verify::halt_honest_run(ctx, km, honest);
				if scratch.attacker_phase_update(km, &honest, phase).is_err() {
					continue;
				}
				let _ = compute_knowledge_closure(&scratch, km, &honest);
			}
			ctx.store_baseline(base.id, phase, scratch.baseline_reached());
		}
	}
	let others: Vec<(PrincipalState, crate::reexec::Controllable)> = if breadth == Breadth::All {
		ctx.principal_states()
			.iter()
			.filter(|state| state.id != base.id)
			.map(|state| {
				let session = state.clone_for_depth(true);
				let guard =
					crate::reexec::Controllable::of(km, &session, &scratch.attacker_snapshot());
				(session, guard)
			})
			.collect()
	} else {
		Vec::new()
	};

	let mut remaining: Vec<(SlotIdx, Value)> = installs.to_vec();
	remaining.sort_by_key(|(slot, _)| km.slots.get(slot.get()).map(|s| s.declared_at).unwrap_or(0));
	let mut grounded = true;
	let mut earlier: Installs = Vec::new();
	let mut earlier_phases: Vec<i32> = Vec::new();
	while !remaining.is_empty() {
		let known = scratch.attacker_snapshot();
		let next = (0..remaining.len()).find(|&at| {
			let (slot, value) = &remaining[at];
			let recipients = base
				.meta
				.get(slot.get())
				.map(|m| m.wire.as_slice())
				.unwrap_or(&[]);
			let preceded = remaining[..at].iter().any(|(other, _)| {
				base.meta
					.get(other.get())
					.is_some_and(|m| m.wire.iter().any(|r| recipients.contains(r)))
			});
			if preceded {
				return false;
			}
			crate::solve::validate::attacker_can_derive(
				&scratch,
				slot.get(),
				value,
				base,
				&known,
				&|_| None,
			)
			.is_some() && crate::reexec::available_before_receive(
				km,
				base,
				slot.get(),
				&known,
				false,
			)
			.is_none_or(|available| crate::solve::validate::derivable(value, base, &available))
		});
		let Some(at) = next else {
			grounded = false;
			break;
		};
		let (slot, value) = remaining.remove(at);
		earlier_phases.push(
			crate::solve::validate::attacker_can_derive(
				&scratch,
				slot.get(),
				&value,
				base,
				&known,
				&|_| None,
			)
			.unwrap_or(known.current_phase),
		);
		earlier.push((slot, value));
		if remaining.is_empty() {
			break;
		}
		let seeded = scratch.attacker_snapshot();
		let governing = governing_attacker(&scratch, &earlier_phases, &seeded);
		if let Ok(partial) = reexecute_at(
			base,
			&earlier,
			&earlier_phases,
			&governing,
			km,
			addressed_all,
		) {
			let _ = compute_knowledge_closure(&scratch, km, &partial);
		}
		if breadth != Breadth::All {
			continue;
		}
		for (session, guard) in &others {
			let seeded = scratch.attacker_snapshot();
			let mut mine = if addressed_all {
				Vec::new()
			} else {
				admitted_by(guard, session, &seeded, earlier.clone())
			};
			mine.extend(addressed_to(addressed, session.id));
			if mine.is_empty() {
				continue;
			}
			let phases = phases_of(&scratch, &mine, session, &seeded);
			let governing = governing_attacker(&scratch, &phases, &seeded);
			if let Ok(other) = reexecute_at(session, &mine, &phases, &governing, km, false) {
				let _ = compute_knowledge_closure(&scratch, km, &other);
			}
		}
	}

	let mut carried: Vec<PrincipalState> = Vec::new();
	if breadth == Breadth::All {
		loop {
			let held = scratch.knowledge_saturation();
			carried.clear();
			for (session, guard) in &others {
				let seeded = scratch.attacker_snapshot();
				let mut mine = if addressed_all {
					Vec::new()
				} else {
					admitted_by(guard, session, &seeded, installs.to_vec())
				};
				let theirs = addressed_to(addressed, session.id);
				let addressed_here = !theirs.is_empty();
				mine.extend(theirs);
				if mine.is_empty() {
					continue;
				}
				let phases = phases_of(&scratch, &mine, session, &seeded);
				let governing = governing_attacker(&scratch, &phases, &seeded);
				if let Ok(other) = reexecute_at(session, &mine, &phases, &governing, km, false) {
					let _ = compute_knowledge_closure(&scratch, km, &other);
					if addressed_here {
						carried.push(other);
					}
				}
			}
			if scratch.knowledge_saturation() == held {
				break;
			}
		}
	}

	let ambient = scratch.attacker_snapshot();
	let phases = phases_of(&scratch, installs, base, &ambient);
	let governing = governing_attacker(&scratch, &phases, &ambient);
	let executed = crate::reexec::execute_forward(
		&scratch,
		km,
		base,
		installs,
		Some(&phases),
		&governing,
		addressed_all,
	)
	.ok()?;
	for state in &executed {
		let _ = compute_knowledge_closure(&scratch, km, state);
	}
	let ps = executed
		.iter()
		.find(|state| {
			let _ = verify_resolve_queries(&scratch, km, state);
			scratch.query_is_resolved(query_index)
		})?
		.clone();
	for state in &executed {
		if state.id != ps.id && !carried.iter().any(|prior| prior.id == state.id) {
			carried.push(state.clone());
		}
	}
	carried.retain(|state| state.id != ps.id);
	let mut scheduled = Vec::new();
	for state in ctx.principal_states() {
		if state.id != base.id && breadth != Breadth::All {
			continue;
		}
		let state = state.clone_for_depth(true);
		let mut mine = if addressed_all && state.id != base.id {
			Vec::new()
		} else {
			controlled_installs(km, &state, &ambient, shared.to_vec())
		};
		mine.extend(addressed_to(addressed, state.id));
		scheduled.extend(
			mine.into_iter()
				.map(|(slot, value)| (state.id, slot, value)),
		);
	}
	let attacker = scratch.attacker_snapshot();
	if !causally_grounded(km, &scheduled, ctx.principal_states(), &attacker) {
		return None;
	}
	Some(Witness {
		#[cfg(test)]
		driver: base.id,
		#[cfg(test)]
		installs: installs.to_vec(),
		#[cfg(test)]
		addressed: addressed.to_vec(),
		#[cfg(test)]
		wide: breadth == Breadth::All,
		ps,
		others: carried,
		attacker,
		// A probe returns only when the re-executed state resolved the query.
		reproduced: true,
		grounded,
		// Decided by the caller, which knows whether this probe is the witness
		// or the out-of-order re-check of it.
		out_of_order: Vec::new(),
	})
}

#[cfg(test)]
mod tests {
	use crate::parser::parse_string;

	#[test]
	fn cross_session_keys_survive_a_later_confirmation_failure() {
		assert_routed_keys_replay(
			"session_key_divergence_late_confirmation.vp",
			include_str!("../examples/test/session_key_divergence_late_confirmation.vp"),
			"identity_box",
			true,
		);
	}

	#[test]
	fn cross_session_keys_survive_a_bundled_flight() {
		assert_routed_keys_replay(
			"session_key_divergence_bundled.vp",
			include_str!("../examples/test/session_key_divergence_bundled.vp"),
			"flight_a",
			false,
		);
	}

	fn assert_routed_keys_replay(
		file_name: &str,
		source: &str,
		flight: &str,
		separate_nonce: bool,
	) {
		use crate::types::SlotIdx;
		let model = parse_string(file_name, source).unwrap();
		let expanded = crate::sessions::expand_sessions(&model, 2, &[]).unwrap();
		let (km, states) = crate::sanity::sanity(&expanded.model).unwrap();
		let ctx = crate::context::VerifyContext::new(
			&expanded.model,
			&states,
			expanded.query_variants,
			2,
			None,
			Vec::new(),
		);
		let slot = |name: &str| {
			SlotIdx(
				km.slots
					.iter()
					.position(|s| &*s.constant.name == name)
					.unwrap(),
			)
		};
		let bob = states.iter().find(|s| s.name == "Bob").unwrap();
		let alice = states.iter().find(|s| s.name == "Alice#2").unwrap();
		let mut honest = bob.clone_for_depth(true);
		honest.resolve_all_values().unwrap();
		honest.perform_all_rewrites();
		let mut installs = Vec::new();
		for (into, from) in [
			("alice_ephemeral_public", "alice_ephemeral_public#2"),
			("alice_hello", "alice_hello#2"),
			("bob_ephemeral_public#2", "bob_ephemeral_public"),
			("bob_hello#2", "bob_hello"),
		] {
			installs.push((slot(into), honest.values[slot(from).get()].value.clone()));
		}
		if separate_nonce {
			installs.push((
				slot("nonce_a"),
				honest.values[slot("nonce_a#2").get()].value.clone(),
			));
		}
		let emitted =
			crate::reexec::reexecute(alice, &installs, &ctx.attacker_snapshot(), &km).unwrap();
		installs.push((
			slot(flight),
			emitted.values[slot(&format!("{flight}#2")).get()]
				.value
				.clone(),
		));
		let _guard = super::MinimizingGuard::new();
		let witness = super::probe_with(
			&ctx,
			&km,
			bob,
			&installs,
			&[],
			0,
			0,
			super::Breadth::All,
			false,
			Some(&expanded.model.queries[0]),
		)
		.expect("the routed session has computed two different keys");
		assert!(witness.reproduced);
		assert!(witness.grounded);
		let first_alice = witness.others.iter().find(|s| s.name == "Alice").unwrap();
		assert!(first_alice.halted_at.is_some());
		assert!(slot("key_a").get() < first_alice.values.len());
		assert!(!first_alice.slot_unreached(slot("key_a").get()));
		assert!(!first_alice.slot_starved(slot("key_a").get()));
	}

	#[test]
	fn replay_scoring_retains_failed_checks_beyond_the_halt() {
		let source = "attacker[active]\nprincipal Alice[\nknows private key\ngenerates message\ntag = MAC(key, message)\n]\nAlice -> Bob: message, tag\nprincipal Bob[\nknows private key\n_ = ASSERT(tag, MAC(key, message))?\n_ = ASSERT(tag, MAC(key, message))?\n]\nqueries[\nauthentication? Alice -> Bob: tag\n]\n";
		let model = parse_string("scoring_halt.vp", source).unwrap();
		let (km, states) = crate::sanity::sanity(&model).unwrap();
		let session = states
			.iter()
			.find(|state| state.name == "Bob")
			.unwrap()
			.clone_for_depth(true);
		let tag = crate::testutil::trace_constant(&km, "tag");
		let slot = crate::types::SlotIdx(km.index_of(tag.as_constant().unwrap()).unwrap());
		let installs = vec![(slot, crate::value::value_nil())];
		let attacker = crate::testutil::make_attacker_state(Vec::new());
		let replayed =
			crate::reexec::reexecute_with_failures(&session, &installs, &attacker, &km).unwrap();
		assert!(replayed.state.halted_at.is_some());
		assert_eq!(replayed.failures.len(), 2);
		assert!(replayed.failures[1].1 >= replayed.state.values.len());
		let separate = super::failures_wanting_shapes(&km, &session, &installs);
		let reused: Vec<_> = replayed
			.failures
			.into_iter()
			.filter_map(|(prim, _)| super::wanted_check(prim))
			.collect();
		assert_eq!(reused.len(), separate.len());
		for ((a, _), (_, (b, _))) in reused.iter().zip(&separate) {
			assert!(crate::theory::structurally_identical_primitive(a, b));
		}
	}

	#[test]
	fn forgeable_forwarding_retains_its_sender_execution() {
		for (name, source, expected) in [
			(
				"computed",
				include_str!("../examples/test/forward_computed_under_guard.vp"),
				"f1",
			),
			(
				"emission",
				include_str!("../examples/test/forward_emission_is_not_a_forgery.vp"),
				"a0f1",
			),
		] {
			let model = parse_string(name, &source.replace("MAC(", "MAC[forgeable](")).unwrap();
			for sessions in [1, 2] {
				let ctx = crate::verify::analyze_sessions(&model, sessions).unwrap();
				assert_eq!(
					crate::types::VerifyResult::results_code(&ctx.results_get()),
					expected
				);
			}
		}
	}

	#[test]
	fn a_guarded_request_keeps_the_witness_target_reached() {
		let source = include_str!("../examples/test/forged_key_swap_bare.vp")
			.replace("Alice -> Bob: n_req, req", "Alice -> Bob: n_req, [req]");
		let model = parse_string("guarded_key_swap.vp", &source).unwrap();
		for sessions in [1, 2] {
			let ctx = crate::verify::analyze_sessions(&model, sessions).unwrap();
			assert_eq!(
				crate::types::VerifyResult::results_code(&ctx.results_get()),
				"c0"
			);
		}
	}

	#[test]
	fn witness_installs_cannot_borrow_from_each_others_future() {
		use crate::testutil::{make_attacker_state, trace_constant};
		use crate::types::{DerivationRecord, SlotIdx};
		let source = "attacker[active]\nprincipal Alice[\ngenerates x, y\n]\nAlice -> Bob: x\nprincipal Bob[\ngenerates a\nleaks a\n]\nAlice -> Dave: y\nprincipal Dave[\ngenerates b\nleaks b\n]\nqueries[\nconfidentiality? a\n]\n";
		let model = parse_string("witness_cycle.vp", source).unwrap();
		let (km, states) = crate::sanity::sanity(&model).unwrap();
		let slot = |name: &str| {
			SlotIdx(
				km.slots
					.iter()
					.position(|s| &*s.constant.name == name)
					.unwrap(),
			)
		};
		let a = trace_constant(&km, "a");
		let b = trace_constant(&km, "b");
		let nil = crate::value::value_nil();
		let mut attacker = make_attacker_state(vec![nil.clone(), a.clone(), b.clone()]);
		attacker.derivations = std::sync::Arc::new(vec![
			DerivationRecord::Initial,
			DerivationRecord::Leaked { slot: slot("a") },
			DerivationRecord::Leaked { slot: slot("b") },
		]);
		let bob = states.iter().find(|s| s.name == "Bob").unwrap().id;
		let dave = states.iter().find(|s| s.name == "Dave").unwrap().id;
		assert!(super::harvested_late(&km, &attacker, bob, slot("x"), &a));
		assert!(!super::harvested_late(&km, &attacker, bob, slot("y"), &a));
		for (installs, expected) in [
			(
				vec![(bob, slot("x"), b.clone()), (dave, slot("y"), a.clone())],
				false,
			),
			(
				vec![(bob, slot("x"), nil), (dave, slot("y"), a.clone())],
				true,
			),
			(vec![(bob, slot("x"), b)], true),
			(vec![(bob, slot("x"), a)], false),
		] {
			assert_eq!(
				super::causally_grounded(&km, &installs, &states, &attacker),
				expected
			);
		}
	}

	#[test]
	fn pending_receives_block_all_later_disclosures_of_one_secret() {
		use crate::testutil::{make_attacker_state, trace_constant};
		use crate::types::{DerivationRecord, SlotIdx};
		let source = "attacker[active]\nprincipal Alice[\ngenerates x, y\n]\nprincipal Bob[\nknows private shared\n]\nprincipal Dave[\nknows private shared\n]\nAlice -> Bob: x\nprincipal Bob[\nleaks shared\n]\nAlice -> Dave: y\nprincipal Dave[\nleaks shared\n]\nqueries[\nconfidentiality? shared\n]\n";
		let model = parse_string("witness_disclosures.vp", source).unwrap();
		let (km, states) = crate::sanity::sanity(&model).unwrap();
		let slot = |name: &str| {
			SlotIdx(
				km.slots
					.iter()
					.position(|s| &*s.constant.name == name)
					.unwrap(),
			)
		};
		let shared = trace_constant(&km, "shared");
		let mut attacker = make_attacker_state(vec![shared.clone()]);
		attacker.derivations = std::sync::Arc::new(vec![DerivationRecord::Leaked {
			slot: slot("shared"),
		}]);
		let bob = states.iter().find(|s| s.name == "Bob").unwrap().id;
		let dave = states.iter().find(|s| s.name == "Dave").unwrap().id;
		let installs = vec![(bob, slot("x"), shared.clone()), (dave, slot("y"), shared)];
		assert!(super::causally_grounded(
			&km,
			&installs[..1],
			&states,
			&attacker
		));
		assert!(super::causally_grounded(
			&km,
			&installs[1..],
			&states,
			&attacker
		));
		assert!(!super::causally_grounded(
			&km, &installs, &states, &attacker
		));
	}

	#[test]
	fn a_disclosure_without_mutations_is_independently_reproduced() {
		use crate::context::VerifyContext;
		use crate::witness::minimize_witness;
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private mw_m\n\
			leaks mw_m\n\
			]\n\
			queries[\n\
			confidentiality? mw_m\n\
			]\n";
		let m = parse_string("mw.vp", src).expect("parse");
		let (km, states) = crate::sanity::sanity(&m).expect("sanity");
		let ctx = VerifyContext::new(&m, &states, Vec::new(), 2, None, Vec::new());
		let mut pure = states[0].clone_for_depth(true);
		pure.resolve_all_values().expect("resolve");
		ctx.attacker_phase_update(&km, &pure, 0).expect("phase");

		let w = minimize_witness(&ctx, &km, &pure, 0, &[], None, None);
		assert_eq!(w.ps.values.len(), pure.values.len());
		assert!(w.reproduced);
		assert!(w.grounded);
		assert!(
			w.attacker
				.knows(&crate::testutil::trace_constant(&km, "mw_m"))
				.is_some()
		);
	}

	#[test]
	fn an_unmutated_state_is_not_reproduced_without_a_violation() {
		use crate::context::VerifyContext;
		let source = "attacker[passive]\nprincipal Alice[\nknows private secret\n]\nqueries[\nconfidentiality? secret\n]\n";
		let model = parse_string("unviolated_witness.vp", source).unwrap();
		let (km, states) = crate::sanity::sanity(&model).unwrap();
		let ctx = VerifyContext::new(&model, &states, Vec::new(), 1, None, Vec::new());
		let mut pure = states[0].clone_for_depth(true);
		pure.resolve_all_values().unwrap();
		let witness = super::minimize_witness(&ctx, &km, &pure, 0, &[], None, None);
		assert!(!witness.reproduced);
		assert!(!witness.grounded);
	}

	#[test]
	fn minimize_witness_is_not_reentrant() {
		use crate::witness::in_minimization;
		assert!(!in_minimization());
	}

	#[test]
	fn a_nested_guard_does_not_release_its_outer_one() {
		use crate::witness::{MinimizingGuard, in_minimization};
		assert!(!in_minimization());
		let outer = MinimizingGuard::new();
		{
			let _inner = MinimizingGuard::new();
			assert!(in_minimization());
		}
		assert!(
			in_minimization(),
			"an inner guard's drop must not un-suppress minimization while an \
			 outer caller still expects witnesses to be skipped"
		);
		drop(outer);
		assert!(!in_minimization());
	}
}
