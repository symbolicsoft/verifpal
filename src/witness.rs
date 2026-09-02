/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::Cell;

use crate::context::VerifyContext;
use crate::deduction::compute_knowledge_closure;
use crate::info::InfoQuiet;
use crate::primitive::attacker_public_key;
use crate::reexec::{governing_attacker, reexecute};
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

#[derive(Clone, Copy)]
enum Family {
	SingleSlot,
	WholeFlight,
	AcrossSessions,
}

struct Rung {
	family: Family,
	scope: Scope,
	breadth: Breadth,
	keeps_fallback: bool,
}

const LADDER: [Rung; 3] = [
	Rung {
		family: Family::SingleSlot,
		scope: Scope::Own,
		breadth: Breadth::Base,
		keeps_fallback: true,
	},
	Rung {
		family: Family::WholeFlight,
		scope: Scope::Own,
		breadth: Breadth::Base,
		keeps_fallback: false,
	},
	Rung {
		family: Family::AcrossSessions,
		scope: Scope::Any,
		breadth: Breadth::All,
		keeps_fallback: true,
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
	pub wide: bool,
	pub attacker: AttackerState,
	pub reproduced: bool,
	pub grounded: bool,
	pub out_of_order: Vec<String>,
	#[cfg(test)]
	pub installs: Installs,
}

struct Minimizer<'a> {
	ctx: &'a VerifyContext,
	km: &'a ProtocolTrace,
	query_index: usize,
	phase: i32,
	ambient: AttackerState,
	sessions: Vec<PrincipalState>,
	mutations: Installs,
	everywhere: Installs,
}

impl<'a> Minimizer<'a> {
	fn new(
		ctx: &'a VerifyContext,
		km: &'a ProtocolTrace,
		ps: &PrincipalState,
		query_index: usize,
		mutations: Installs,
	) -> Minimizer<'a> {
		let ambient = ctx.attacker_snapshot();
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
		let mut m = Minimizer {
			ctx,
			km,
			query_index,
			phase,
			ambient,
			sessions,
			mutations,
			everywhere: Vec::new(),
		};
		m.everywhere = m.mitm_everywhere();
		m
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
			controlled_by_any(self.km, &self.sessions, &self.ambient, candidate)
		} else {
			controlled_installs(self.km, session, &self.ambient, candidate)
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
		let mine = controlled_installs(self.km, session, &self.ambient, keys.clone());
		let checks = checks_wanting_shapes(self.km, session, &mine);
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
	) -> (usize, usize, usize) {
		let mut bypasses = 0usize;
		let mut halts = 0usize;
		let mut stuck = 0usize;
		for session in group {
			let mine = controlled_installs(self.km, session, &self.ambient, installs.to_vec());
			if mine.is_empty() {
				continue;
			}
			match reexecute(session, &mine, &self.ambient, self.km) {
				Ok(state) => {
					bypasses += state
						.values
						.iter()
						.filter(|sv| sv.bypassed.is_some())
						.count();
					halts += usize::from(state.halted_at.is_some());
					stuck += checks_wanting_shapes(self.km, session, &mine).len();
				}
				Err(_) => return (usize::MAX, usize::MAX, usize::MAX),
			}
		}
		(bypasses, halts, stuck)
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
				let mine = controlled_installs(self.km, s, &self.ambient, installs.clone());
				checks_wanting_shapes(self.km, s, &mine)
			})
			.collect();
		if checks.is_empty() {
			return Vec::new();
		}
		let mut shapes = payload_shapes(self.km, &self.ambient, &checks, at);
		shapes.extend(shapes_the_checks_wanted(&checks, &mut |_| {
			attacker_public_key()
		}));
		shapes.extend(shapes_the_checks_wanted(&checks, &mut |_| value_nil()));
		for (prim, _) in &checks {
			for argument in prim.arguments.iter() {
				if !shapes.iter().any(|s| s.equivalent(argument, true)) {
					shapes.push(argument.clone());
				}
			}
		}
		shapes
	}

	fn forged_flight(&self, session: &PrincipalState, base: Installs, wide: bool) -> Vec<Installs> {
		let mut installs = self.admitted(session, base, wide);
		if installs.is_empty() {
			return Vec::new();
		}
		let slots = self.reachable_slots(session, wide);
		let bound = crate::reexec::TermBound::of(self.km);
		let group: &[PrincipalState] = if wide {
			&self.sessions
		} else {
			std::slice::from_ref(session)
		};
		let mut out: Vec<Installs> = Vec::new();
		let mut seen: Vec<Installs> = vec![installs.clone()];
		for _ in 0..slots.len() {
			let mut advanced = false;
			for i in &slots {
				let here = self.scenario_cost(group, &installs);
				if here == (0, 0, 0) {
					break;
				}
				let shapes = self.flight_shapes(group, &installs, *i);
				if shapes.is_empty() {
					break;
				}
				let honest = self.km.slots.get(*i).map(|slot| {
					crate::resolution::resolve_trace_term(&slot.initial_value, self.km)
				});
				for shape in shapes {
					if !self.validator_admits(session, &bound, *i, &shape) {
						continue;
					}
					if honest.as_ref().is_some_and(|h| h.equivalent(&shape, true)) {
						continue;
					}
					let mut trial: Installs = installs
						.iter()
						.filter(|(s, _)| s.get() != *i)
						.cloned()
						.collect();
					trial.push((SlotIdx(*i), shape));
					let trial = self.admitted(session, trial, wide);
					if !trial.iter().any(|(s, _)| s.get() == *i) {
						continue;
					}
					if seen.iter().any(|s| same_installs(s, &trial)) {
						continue;
					}
					if self.scenario_cost(group, &trial) <= here {
						seen.push(trial.clone());
						installs = trial;
						advanced = true;
						break;
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
			if controlled_installs(self.km, session, &self.ambient, blanked.clone()).is_empty() {
				continue;
			}
			let checks = checks_wanting_shapes(self.km, session, &blanked);
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
			let siblings = crate::query::session_sibling_values(&sm.constant, self.km);
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

	fn family(&self, family: Family, session: &PrincipalState) -> Vec<Installs> {
		match family {
			Family::SingleSlot => self.single_slot(session),
			Family::WholeFlight => self.whole_flight(session),
			Family::AcrossSessions => self.across_sessions(session),
		}
	}

	fn single_slot(&self, session: &PrincipalState) -> Vec<Installs> {
		let mut families = vec![self.mitm_for(session), self.mutations.clone()];
		families.extend(self.forged_from(session, self.mitm_for(session), false));
		families.extend(self.forged_from(session, self.mutations.clone(), false));
		families.extend(self.forged_alone(session));
		families.extend(self.replayed_from(session));
		families
	}

	fn whole_flight(&self, session: &PrincipalState) -> Vec<Installs> {
		[self.mitm_for(session), self.mutations.clone()]
			.into_iter()
			.flat_map(|base| self.forged_flight(session, base, false))
			.collect()
	}

	fn across_sessions(&self, session: &PrincipalState) -> Vec<Installs> {
		let mut families = vec![self.mutations.clone(), self.everywhere.clone()];
		families.extend(self.forged_from(session, self.everywhere.clone(), true));
		families.extend(self.forged_from(session, self.mutations.clone(), true));
		families.extend(self.replayed_from(session));
		for base in [self.everywhere.clone(), self.mutations.clone()] {
			families.extend(self.forged_flight(session, base, false));
		}
		families
	}

	fn probe_at(
		&self,
		base: &PrincipalState,
		installs: &[(SlotIdx, Value)],
		breadth: Breadth,
	) -> Option<Witness> {
		probe_with(
			self.ctx,
			self.km,
			base,
			installs,
			self.query_index,
			self.phase,
			breadth,
		)
	}

	fn buildable(&self, session: &PrincipalState, candidate: &Installs) -> bool {
		if candidate.is_empty() {
			return false;
		}
		let bound = crate::reexec::TermBound::of(self.km);
		candidate
			.iter()
			.all(|(slot, value)| self.validator_admits(session, &bound, slot.get(), value))
	}

	fn validator_admits(
		&self,
		session: &PrincipalState,
		bound: &crate::reexec::TermBound,
		slot: usize,
		value: &Value,
	) -> bool {
		crate::primitive::admissible(value)
			&& bound.admits(value)
			&& !crate::solve::validate::contains_failed_check(value)
			&& crate::solve::validate::attacker_can_derive(
				self.ctx,
				self.km,
				slot,
				value,
				session,
				&self.ambient,
			)
	}

	fn choose(&self) -> Option<(PrincipalState, Installs, Breadth, bool, bool)> {
		let mut chosen: Option<(PrincipalState, Installs, Breadth, bool)> = None;
		let mut fallback: Option<(PrincipalState, Installs, Breadth)> = None;
		for rung in LADDER {
			if chosen.as_ref().is_some_and(|(_, _, _, grounded)| *grounded) {
				break;
			}
			'rung: for session in &self.sessions {
				for candidate in self.family(rung.family, session) {
					let candidate = match rung.scope {
						Scope::Own => {
							controlled_installs(self.km, session, &self.ambient, candidate)
						}
						Scope::Any => {
							controlled_by_any(self.km, &self.sessions, &self.ambient, candidate)
						}
					};
					if !self.buildable(session, &candidate) {
						continue;
					}
					let Some(witness) = self.probe_at(session, &candidate, rung.breadth) else {
						continue;
					};
					if !needs_guard_bypass(&witness.ps) {
						let better = chosen.is_none()
							|| (witness.grounded
								&& !chosen.as_ref().is_some_and(|(_, _, _, was)| *was));
						if better {
							chosen =
								Some((session.clone(), candidate, rung.breadth, witness.grounded));
						}
						if witness.grounded {
							break 'rung;
						}
						continue;
					}
					if rung.keeps_fallback && fallback.is_none() {
						fallback = Some((session.clone(), candidate, rung.breadth));
					}
				}
			}
		}
		let explanatory = chosen.is_some();
		match chosen {
			Some((base, installs, breadth, grounded)) => {
				Some((base, installs, breadth, explanatory, grounded))
			}
			None => fallback
				.map(|(base, installs, breadth)| (base, installs, breadth, explanatory, false)),
		}
	}

	fn drop_one(
		&self,
		base: &PrincipalState,
		installs: &Installs,
		breadth: Breadth,
		explanatory: bool,
		grounded: bool,
	) -> Installs {
		let mut keep = installs.clone();
		for (slot, _) in installs {
			let trial: Installs = keep.iter().filter(|(s, _)| s != slot).cloned().collect();
			if trial.len() == keep.len() {
				continue;
			}
			let Some(witness) = self.probe_at(base, &trial, breadth) else {
				continue;
			};
			if explanatory && needs_guard_bypass(&witness.ps) {
				continue;
			}
			if grounded && !witness.grounded {
				continue;
			}
			keep = trial;
		}
		keep
	}
}

fn seeded_mutations(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	seed: &[(SlotIdx, Value)],
	attacker: &AttackerState,
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
	close_over_history(km, attacker, &mut mutations);
	mutations.sort_by_key(|(slot, _)| *slot);
	mutations
}

fn close_over_history(km: &ProtocolTrace, attacker: &AttackerState, mutations: &mut Installs) {
	let mut seen: Vec<KnownIdx> = Vec::new();
	let mut generation: Vec<KnownIdx> = Vec::new();
	for (_, value) in mutations.iter() {
		enqueue_history(attacker, value, &mut seen, &mut generation);
	}
	let mut next: Vec<KnownIdx> = Vec::new();
	while !generation.is_empty() {
		for idx in generation.drain(..) {
			let Some(record) = attacker.record(idx) else {
				continue;
			};
			for diff in record.diffs.iter().filter(|diff| diff.tainted) {
				if diff.index.get() >= km.slots.len() {
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
) -> Witness {
	let unminimized = |reproduced: bool| Witness {
		ps: ps.clone(),
		#[cfg(test)]
		wide: false,
		attacker: ctx.attacker_snapshot(),
		reproduced,
		grounded: reproduced,
		out_of_order: Vec::new(),
		#[cfg(test)]
		installs: Vec::new(),
	};

	if in_minimization() {
		return unminimized(true);
	}

	let mutations = seeded_mutations(km, ps, seed, &ctx.attacker_snapshot());
	if mutations.is_empty() {
		return unminimized(true);
	}

	let _guard = MinimizingGuard::new();
	let _quiet = InfoQuiet::new();
	let m = Minimizer::new(ctx, km, ps, query_index, mutations);

	let Some((base, candidate, breadth, explanatory, grounded)) = m.choose() else {
		return unminimized(false);
	};
	let keep = m.drop_one(&base, &candidate, breadth, explanatory, grounded);

	match m.probe_at(&base, &keep, breadth) {
		Some(mut witness) => {
			#[cfg(test)]
			for (slot, value) in &keep {
				assert!(
					crate::solve::validate::attacker_can_derive(
						ctx,
						km,
						slot.get(),
						value,
						&base,
						&m.ambient
					),
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
			witness.out_of_order =
				out_of_order_harvest(ctx, km, &base, &keep, query_index, m.phase);
			#[cfg(test)]
			{
				witness.installs = keep;
			}
			witness
		}
		None => unminimized(false),
	}
}

fn same_installs(a: &[(SlotIdx, Value)], b: &[(SlotIdx, Value)]) -> bool {
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

type WantedCheck = (Primitive, Option<&'static crate::primitive::RewriteRule>);

fn checks_wanting_shapes(
	km: &ProtocolTrace,
	session: &PrincipalState,
	installs: &[(SlotIdx, Value)],
) -> Vec<WantedCheck> {
	let mut staged = session.clone();
	for (slot, value) in installs {
		if slot.get() >= staged.values.len() {
			continue;
		}
		let authored = crate::reexec::attacker_authored(value, slot.get(), km, &staged);
		crate::reexec::install(&mut staged, slot.get(), value.clone(), authored);
	}
	if crate::reexec::slot_graph_is_cyclic(&staged) || staged.resolve_all_values().is_err() {
		return Vec::new();
	}
	staged
		.perform_all_rewrites()
		.into_iter()
		.filter_map(|(prim, _)| match crate::primitive::primitive_get(prim.id) {
			Ok(spec) => spec.rewrite.as_ref().map(|rule| (prim, Some(rule))),
			Err(_) => crate::primitive::primitive_is_core(prim.id).then_some((prim, None)),
		})
		.collect()
}

fn shapes_the_checks_wanted(
	checks: &[WantedCheck],
	fill: &mut dyn FnMut(usize) -> Value,
) -> Vec<Value> {
	let mut shapes: Vec<Value> = Vec::new();
	for (prim, rule) in checks {
		let Some(rule) = rule else {
			continue;
		};
		let mut at = 0usize;
		let filler = || {
			let position = at;
			at += 1;
			fill(position)
		};
		for shape in crate::solve::deduce::build_rewrite_shapes_with(prim, rule, filler) {
			if !shapes.iter().any(|s| s.equivalent(&shape, true)) {
				shapes.push(shape);
			}
		}
	}
	shapes
}

/// The forgeries for slot `i` that carry what the protocol itself put there.
///
/// `build_rewrite_shapes_with` fixes the positions the recipient's rewrite rule
/// matches on — the key, the associated data — and leaves the rest to a filler.
/// Filling those with `nil` always type-checks and always resolves an
/// authentication query, which is exactly why it explains nothing: "Bob accepted
/// an empty record" is a weaker claim than "Bob accepted the real file, resealed
/// under a key the attacker owns", and both resolve the same `a1`. So whenever
/// the attacker holds the honest term's own argument for a free position, offer
/// that first and let `nil` be the fallback it was meant to be.
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

/// A forged term is only an explanation if the attacker could have produced it.
/// The minimizer never records a verdict, so this cannot cost an attack — but a
/// witness naming a term nothing derives is a trace a reader cannot follow.
pub(crate) fn attacker_can_build(shape: &Value, attacker: &AttackerState) -> bool {
	if attacker.knows(shape).is_some() {
		return true;
	}
	match shape {
		Value::Constant(_) => false,
		Value::Primitive(p) => p.arguments.iter().all(|a| attacker_can_build(a, attacker)),
	}
}

fn needs_guard_bypass(ps: &PrincipalState) -> bool {
	ps.values.iter().any(|sv| sv.bypassed.is_some())
}

fn controlled_by_any(
	km: &ProtocolTrace,
	sessions: &[PrincipalState],
	attacker: &AttackerState,
	candidate: Installs,
) -> Installs {
	let guards: Vec<(&PrincipalState, crate::reexec::Controllable)> = sessions
		.iter()
		.map(|s| (s, crate::reexec::Controllable::of(km, s, attacker)))
		.collect();
	candidate
		.into_iter()
		.filter(|(slot, _)| {
			guards
				.iter()
				.any(|(s, g)| g.admits(s, attacker, slot.get()))
		})
		.collect()
}

fn controlled_installs(
	km: &ProtocolTrace,
	session: &PrincipalState,
	attacker: &AttackerState,
	candidate: Installs,
) -> Installs {
	let controllable = crate::reexec::Controllable::of(km, session, attacker);
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
	if probe(ctx, km, base, &renamed, query_index, phase).is_some() {
		return Vec::new();
	}
	harvested.sort();
	harvested.dedup();
	harvested
}

/// Was `v` lifted straight out of `target`'s own state, from a slot `target`
/// only reaches at or after the one being overwritten? A value the principal
/// published earlier is available to the attacker in the same run, so
/// reflecting it back is an ordinary attack; a value it only computes later is
/// one the run cannot supply in time, and only the atemporal within-phase
/// knowledge model admits it. Terms the attacker built itself are excluded the
/// way `solve::validate::replays_own_freshness` excludes them: their shape says
/// nothing about which run they came from.
fn harvested_late(
	km: &ProtocolTrace,
	ambient: &AttackerState,
	target: PrincipalId,
	into: SlotIdx,
	v: &Value,
) -> bool {
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

/// `v` with every constant that `ps` itself generates replaced by the copy a
/// different session of `ps` would hold, recording which ones those were.
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
				result.query_index,
				witness.phase,
				witness.wide,
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
		let unjustified: Vec<String> = witness
			.installs
			.iter()
			.filter(|(slot, value)| {
				!(crate::primitive::admissible(value)
					&& bound.admits(value)
					&& !crate::solve::validate::contains_failed_check(value)
					&& crate::solve::validate::attacker_can_derive(
						ctx,
						km,
						slot.get(),
						value,
						&base,
						&ambient,
					))
			})
			.map(|(slot, value)| format!("{} := {}", name_of(slot), value))
			.collect();
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
pub(crate) fn replays(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	query_index: usize,
	phase: i32,
	wide: bool,
) -> bool {
	let _guard = MinimizingGuard::new();
	let _quiet = InfoQuiet::new();
	let breadth = if wide { Breadth::All } else { Breadth::Base };
	probe_with(ctx, km, base, installs, query_index, phase, breadth).is_some()
}

fn probe(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	query_index: usize,
	phase: i32,
) -> Option<Witness> {
	probe_with(ctx, km, base, installs, query_index, phase, Breadth::Base)
}

#[allow(clippy::too_many_arguments)]
fn probe_with(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	query_index: usize,
	phase: i32,
	breadth: Breadth,
) -> Option<Witness> {
	let scratch = ctx.scratch_for_witness(query_index);
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

	let mut ordered: Vec<&(SlotIdx, Value)> = installs.iter().collect();
	ordered.sort_by_key(|(slot, _)| km.slots.get(slot.get()).map(|s| s.declared_at).unwrap_or(0));
	let mut grounded = true;
	for reached in 1..=ordered.len() {
		let (slot, value) = ordered[reached - 1];
		let known = scratch.attacker_snapshot();
		if !crate::solve::validate::attacker_can_derive(
			&scratch,
			km,
			slot.get(),
			value,
			base,
			&known,
		) {
			grounded = false;
			break;
		}
		if reached == ordered.len() {
			break;
		}
		let earlier: Installs = ordered[..reached]
			.iter()
			.map(|&pair| pair.clone())
			.collect();
		let seeded = scratch.attacker_snapshot();
		let governing = governing_attacker(&scratch, km, &earlier, &seeded);
		if let Ok(partial) = reexecute(base, &earlier, &governing, km) {
			let _ = compute_knowledge_closure(&scratch, km, &partial);
		}
		if breadth != Breadth::All {
			continue;
		}
		for state in ctx.principal_states() {
			if state.id == base.id {
				continue;
			}
			let session = state.clone_for_depth(true);
			let seeded = scratch.attacker_snapshot();
			let mine = controlled_installs(km, &session, &seeded, earlier.clone());
			if mine.is_empty() {
				continue;
			}
			let governing = governing_attacker(&scratch, km, &mine, &seeded);
			if let Ok(other) = reexecute(&session, &mine, &governing, km) {
				let _ = compute_knowledge_closure(&scratch, km, &other);
			}
		}
	}

	if breadth == Breadth::All {
		let mut held = 0usize;
		for _ in 0..ctx.principal_states().len().max(1) {
			for state in ctx.principal_states() {
				if state.id == base.id {
					continue;
				}
				let session = state.clone_for_depth(true);
				let seeded = scratch.attacker_snapshot();
				let mine = controlled_installs(km, &session, &seeded, installs.to_vec());
				if mine.is_empty() {
					continue;
				}
				let governing = governing_attacker(&scratch, km, &mine, &seeded);
				if let Ok(other) = reexecute(&session, &mine, &governing, km) {
					let _ = compute_knowledge_closure(&scratch, km, &other);
				}
			}
			let grown = scratch.attacker_snapshot().known.len();
			if grown == held {
				break;
			}
			held = grown;
		}
	}

	let ambient = scratch.attacker_snapshot();
	let governing = governing_attacker(&scratch, km, installs, &ambient);
	let ps = reexecute(base, installs, &governing, km).ok()?;
	crate::solve::validate::note_malleable_reshapes(&scratch, km, &ps, installs, &governing);
	let _ = compute_knowledge_closure(&scratch, km, &ps);
	let _ = verify_resolve_queries(&scratch, km, &ps);
	if !scratch.query_is_resolved(query_index) {
		return None;
	}
	Some(Witness {
		#[cfg(test)]
		installs: installs.to_vec(),
		#[cfg(test)]
		wide: breadth == Breadth::All,
		ps,
		attacker: scratch.attacker_snapshot(),
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
	fn minimize_witness_is_identity_without_mutations() {
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

		let w = minimize_witness(&ctx, &km, &pure, 0, &[]);
		assert_eq!(w.ps.values.len(), pure.values.len());
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
