/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::context::VerifyContext;
use crate::principal::ATTACKER_ID;
use crate::theory::reduce_once;
use crate::types::*;
use crate::value::{resolve_trace_constant, resolve_trace_term};

pub(crate) struct Controllable {
	principal: PrincipalId,
	phase: i32,
	slots: Vec<bool>,
}

impl Controllable {
	pub(crate) fn of(
		km: &ProtocolTrace,
		ps: &PrincipalState,
		attacker: &AttackerState,
	) -> Controllable {
		Controllable {
			principal: ps.id,
			phase: attacker.current_phase,
			slots: (0..ps.values.len())
				.map(|i| attacker_controllable(i, km, ps, attacker))
				.collect(),
		}
	}

	pub(crate) fn admits(
		&self,
		ps: &PrincipalState,
		attacker: &AttackerState,
		slot: usize,
	) -> bool {
		self.principal == ps.id
			&& self.phase == attacker.current_phase
			&& self.slots.get(slot).copied().unwrap_or(false)
	}
}

pub(crate) struct TermBound {
	max_depth: usize,
	deep: std::sync::OnceLock<Deep>,
}

struct Deep {
	protocol: crate::hashing::TermSet,
	ids: Vec<ValueId>,
	creators: Vec<PrincipalId>,
	consumes: Vec<Option<ValueId>>,
	peel: std::sync::RwLock<IdMap<(PrincipalId, usize), usize>>,
}

impl TermBound {
	pub(crate) fn of(km: &ProtocolTrace) -> TermBound {
		let max_depth = km
			.slots
			.iter()
			.map(|slot| term_depth(&resolve_trace_constant(&slot.constant, km)))
			.max()
			.unwrap_or(0);
		TermBound {
			max_depth,
			deep: std::sync::OnceLock::new(),
		}
	}

	fn deep(&self, km: &ProtocolTrace) -> &Deep {
		self.deep.get_or_init(|| {
			let mut protocol = crate::hashing::TermSet::default();
			for slot in &km.slots {
				let term = resolve_trace_constant(&slot.constant, km);
				crate::hashing::collect_subterms(&term, &mut protocol);
				crate::hashing::collect_subterms(&reduce_once(&term), &mut protocol);
			}
			Deep {
				protocol,
				ids: km.slots.iter().map(|slot| slot.constant.id).collect(),
				creators: km.slots.iter().map(|slot| slot.creator).collect(),
				consumes: km
					.slots
					.iter()
					.map(|slot| unwrapped_by(&slot.initial_value))
					.collect(),
				peel: std::sync::RwLock::new(IdMap::default()),
			}
		})
	}

	pub(crate) fn admits_at(
		&self,
		km: &ProtocolTrace,
		principal: PrincipalId,
		slot: usize,
		v: &Value,
	) -> bool {
		let depth = term_depth(v);
		if depth <= self.max_depth {
			return true;
		}
		let deep = self.deep(km);
		depth <= self.max_depth + deep.peel_depth(principal, slot)
			&& deep.depth_over_protocol(v) <= self.max_depth
	}

	pub(crate) fn protocol(&self, km: &ProtocolTrace) -> &crate::hashing::TermSet {
		&self.deep(km).protocol
	}

	pub(crate) fn depth(&self) -> usize {
		self.max_depth
	}
}

impl Deep {
	fn depth_over_protocol(&self, v: &Value) -> usize {
		term_depth_outside(v, &self.protocol, &mut IdMap::default())
	}

	fn peel_depth(&self, principal: PrincipalId, slot: usize) -> usize {
		if let Some(&hit) = self
			.peel
			.read()
			.unwrap_or_else(|e| e.into_inner())
			.get(&(principal, slot))
		{
			return hit;
		}
		let mut visiting: Vec<usize> = Vec::new();
		let depth = self.peel_from(principal, slot, &mut visiting);
		self.peel
			.write()
			.unwrap_or_else(|e| e.into_inner())
			.insert((principal, slot), depth);
		depth
	}

	fn peel_from(&self, principal: PrincipalId, slot: usize, visiting: &mut Vec<usize>) -> usize {
		let Some(&id) = self.ids.get(slot) else {
			return 0;
		};
		if visiting.contains(&slot) {
			return 0;
		}
		visiting.push(slot);
		let deepest = (0..self.ids.len())
			.filter(|&t| self.creators[t] == principal && self.consumes[t] == Some(id))
			.map(|t| 1 + self.peel_from(principal, t, visiting))
			.max()
			.unwrap_or(0);
		visiting.pop();
		deepest
	}
}

fn unwrapped_by(v: &Value) -> Option<ValueId> {
	let Value::Primitive(p) = v else {
		return None;
	};
	let at = crate::primitive::primitive_unwraps(p.id)?;
	match p.arguments.get(at) {
		Some(Value::Constant(c)) => Some(c.id),
		_ => None,
	}
}

pub(crate) fn available_before_receive(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	slot: usize,
	attacker: &AttackerState,
	addressed: bool,
) -> Option<Arc<AttackerState>> {
	let reaches = |recipient: PrincipalId| {
		recipient == ps.id
			|| (!addressed
				&& ps
					.meta
					.get(slot)
					.is_some_and(|meta| meta.mutatable_to.contains(&recipient)))
	};
	let mut after: Vec<(PrincipalId, i32)> = Vec::new();
	for event in km
		.slots
		.get(slot)?
		.sent_by
		.iter()
		.filter(|event| reaches(event.recipient))
	{
		match after.iter_mut().find(|(who, _)| *who == event.recipient) {
			Some(entry) => entry.1 = entry.1.min(event.declared_at),
			None => after.push((event.recipient, event.declared_at)),
		}
	}
	if after.is_empty() {
		return None;
	}
	after.sort_unstable();
	held_before(km, ps, after, attacker)
}

pub(crate) fn reachable_knowledge(
	ps: &PrincipalState,
	attacker: &AttackerState,
	source_allowed: impl FnMut(usize, SlotIdx) -> bool,
) -> Vec<bool> {
	reachable_knowledge_via(ps, attacker, source_allowed, |_| Vec::new())
}

fn reachable_knowledge_via(
	ps: &PrincipalState,
	attacker: &AttackerState,
	mut source_allowed: impl FnMut(usize, SlotIdx) -> bool,
	mut alternate_needs: impl FnMut(usize) -> Vec<Vec<Value>>,
) -> Vec<bool> {
	let n = attacker.known.len();
	let mut inputs = crate::theory::KnowledgeInputs::new(ps, attacker);
	let mut reachable = vec![false; n];
	let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
	let mut missing = vec![0usize; n];
	let mut ready = Vec::new();
	for i in 0..n {
		let available = match attacker.derivation(KnownIdx(i)) {
			None | Some(DerivationRecord::Initial) => true,
			Some(DerivationRecord::Leaked { slot } | DerivationRecord::Obtained { slot }) => {
				source_allowed(i, *slot)
			}
			Some(other) => {
				let mut dependencies = IdSet::default();
				let mut complete = true;
				for value in other.ingredients() {
					let Some(known) = inputs.of_value(value) else {
						complete = false;
						break;
					};
					dependencies.extend(known.into_iter().map(|idx| idx.get()));
				}
				if !complete {
					continue;
				}
				missing[i] = dependencies.len();
				for dependency in dependencies {
					dependents[dependency].push(i);
				}
				missing[i] == 0
			}
		};
		if available {
			reachable[i] = true;
			ready.push(i);
		}
	}
	let offered: Vec<usize> = (0..n)
		.filter(|&i| {
			attacker
				.alternates
				.get(i)
				.is_some_and(|routes| !routes.is_empty())
		})
		.collect();
	let mut alternates: Vec<Option<Vec<Vec<Value>>>> = Vec::new();
	loop {
		while let Some(known) = ready.pop() {
			for &dependent in &dependents[known] {
				missing[dependent] -= 1;
				if missing[dependent] == 0 && !reachable[dependent] {
					reachable[dependent] = true;
					ready.push(dependent);
				}
			}
		}
		if offered.is_empty() {
			return reachable;
		}
		if alternates.is_empty() {
			alternates = vec![None; n];
		}
		let mut changed = false;
		for &i in &offered {
			if reachable[i] {
				continue;
			}
			if alternates[i].is_none() {
				alternates[i] = Some(alternate_needs(i));
			}
			let opened = alternates[i].as_ref().is_some_and(|routes| {
				routes.iter().any(|values| {
					values.iter().all(|value| {
						inputs
							.of_value(value)
							.is_some_and(|known| known.iter().all(|idx| reachable[idx.get()]))
					})
				})
			});
			if opened {
				reachable[i] = true;
				ready.push(i);
				changed = true;
			}
		}
		if !changed {
			return reachable;
		}
	}
}

fn observable_slot(km: &ProtocolTrace, slot: usize) -> bool {
	km.slots
		.get(slot)
		.is_some_and(|trace_slot| !trace_slot.sent_by.is_empty() || trace_slot.constant.leaked)
}

fn restrict_known(
	blocked: &[bool],
	observable: &dyn Fn(usize) -> bool,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<Arc<AttackerState>> {
	let allowed = |slot: SlotIdx| !blocked.get(slot.get()).copied().unwrap_or(false);
	let reachable = reachable_knowledge_via(
		ps,
		attacker,
		|_, slot| allowed(slot),
		|i| {
			let admissible = attacker.alternates.get(i).is_some_and(|routes| {
				routes.iter().any(|(route, record)| match route {
					DerivationRecord::Obtained { slot } | DerivationRecord::Leaked { slot } => {
						observable(slot.get())
							&& allowed(*slot) && record.tainted().all(|diff| {
							!received_by(ps, diff.index.get())
								&& public_construction(attacker, &diff.value, &mut Vec::new())
						})
					}
					_ => false,
				})
			});
			if admissible {
				vec![Vec::new()]
			} else {
				Vec::new()
			}
		},
	);
	attacker.retaining(&reachable)
}

fn received_by(ps: &PrincipalState, slot: usize) -> bool {
	ps.meta
		.get(slot)
		.is_some_and(|meta| meta.wire.contains(&ps.id))
}

fn public_construction(attacker: &AttackerState, value: &Value, walked: &mut Vec<usize>) -> bool {
	let Some(idx) = attacker.knows(value) else {
		return false;
	};
	if walked.contains(&idx.get()) {
		return false;
	}
	walked.push(idx.get());
	let free = match attacker.derivation(idx) {
		Some(DerivationRecord::Initial) => true,
		Some(DerivationRecord::Reconstructed { from } | DerivationRecord::Combined { from }) => {
			from.iter()
				.all(|ingredient| public_construction(attacker, ingredient, walked))
		}
		_ => false,
	};
	walked.pop();
	free
}

fn close_influences(
	km: &ProtocolTrace,
	mut after: IdMap<PrincipalId, i32>,
) -> IdMap<PrincipalId, i32> {
	loop {
		let mut changed = false;
		for slot in &km.slots {
			for event in &slot.sent_by {
				let Some(&reached) = after.get(&event.sender) else {
					continue;
				};
				if event.declared_at < reached {
					continue;
				}
				match after.get(&event.recipient) {
					Some(&known) if known <= event.declared_at => {}
					_ => {
						after.insert(event.recipient, event.declared_at);
						changed = true;
					}
				}
			}
		}
		if !changed {
			return after;
		}
	}
}

fn unreachable_before(km: &ProtocolTrace, after: &[(PrincipalId, i32)]) -> Vec<bool> {
	let after = close_influences(km, after.iter().copied().collect());
	unreachable_from(km, &after)
}

fn available_before_pending(
	km: &ProtocolTrace,
	pending: &[(PrincipalId, SlotIdx)],
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<Arc<AttackerState>> {
	let mut after: IdMap<PrincipalId, i32> = IdMap::default();
	for &(principal, slot) in pending {
		let Some(at) = km.slots.get(slot.get()).and_then(|slot| {
			slot.sent_by
				.iter()
				.filter(|event| event.recipient == principal)
				.map(|event| event.declared_at)
				.min()
		}) else {
			continue;
		};
		after
			.entry(principal)
			.and_modify(|earliest| *earliest = (*earliest).min(at))
			.or_insert(at);
	}
	let after = close_influences(km, after);
	restrict_known(
		&unreachable_from(km, &after),
		&|slot| observable_slot(km, slot),
		ps,
		attacker,
	)
}

pub(crate) fn causally_grounded(
	km: &ProtocolTrace,
	installs: &[(PrincipalId, SlotIdx, Value)],
	states: &[PrincipalState],
	attacker: &AttackerState,
) -> bool {
	if crate::world::scheduled_world(states, attacker, installs).is_empty() {
		return false;
	}

	let mut remaining: Vec<_> = installs.iter().collect();
	remaining
		.sort_by_key(|(_, slot, _)| km.slots.get(slot.get()).map(|s| s.declared_at).unwrap_or(0));
	while !remaining.is_empty() {
		let pending: Vec<_> = remaining.iter().map(|(at, slot, _)| (*at, *slot)).collect();
		let Some(ps) = states.iter().find(|state| state.id == remaining[0].0) else {
			return false;
		};
		let available = available_before_pending(km, &pending, ps, attacker);
		let available = available.as_deref().unwrap_or(attacker);
		let next = remaining
			.iter()
			.enumerate()
			.position(|(i, (at, _, value))| {
				!remaining[..i].iter().any(|(who, _, _)| who == at)
					&& states
						.iter()
						.find(|state| state.id == *at)
						.is_some_and(|state| {
							crate::solve::validate::derivable(value, state, available)
						})
			});
		let Some(next) = next else {
			return false;
		};
		remaining.remove(next);
	}
	true
}

fn unreachable_from(km: &ProtocolTrace, after: &IdMap<PrincipalId, i32>) -> Vec<bool> {
	let downstream =
		|who: PrincipalId, when: i32| after.get(&who).is_some_and(|&reached| when >= reached);
	km.slots
		.iter()
		.map(|slot| {
			if slot.constant.is_nil() || slot.constant.qualifier == Some(Qualifier::Public) {
				return false;
			}
			if downstream(slot.creator, slot.declared_at) {
				return true;
			}
			let mut disclosed = false;
			let sends = slot
				.sent_by
				.iter()
				.map(|event| (event.sender, event.declared_at));
			let leaks = km
				.leaks
				.iter()
				.filter(|leak| leak.constant_id == slot.constant.id)
				.map(|leak| (leak.principal_id, leak.declared_at));
			for (who, when) in sends.chain(leaks) {
				disclosed = true;
				if !downstream(who, when) {
					return false;
				}
			}
			disclosed
		})
		.collect()
}

type Agreement = (Vec<usize>, Arc<Vec<Value>>, Option<Arc<AttackerState>>);

type Agreed = (Arc<MutationRecord>, Vec<usize>, Arc<Vec<Value>>, bool);

pub(crate) struct Coherence {
	principal: PrincipalId,
	forwarded: Vec<Option<Value>>,
	agreed: std::sync::Mutex<IdMap<u64, Vec<Agreement>>>,
	histories: std::sync::Mutex<Vec<Agreed>>,
}

fn locked<T>(lock: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
	lock.lock().unwrap_or_else(|e| e.into_inner())
}

impl Coherence {
	pub(crate) fn of(km: &ProtocolTrace, ps: &PrincipalState) -> Coherence {
		let forwarded = km
			.slots
			.iter()
			.map(|slot| {
				(slot.creator != ps.id && slot.sent_by.iter().any(|event| event.recipient == ps.id))
					.then(|| reduce_once(&resolve_trace_constant(&slot.constant, km)))
			})
			.collect();
		Coherence {
			principal: ps.id,
			forwarded,
			agreed: std::sync::Mutex::new(IdMap::default()),
			histories: std::sync::Mutex::new(Vec::new()),
		}
	}

	pub(crate) fn compatible(
		&self,
		ctx: &VerifyContext,
		km: &ProtocolTrace,
		ps: &PrincipalState,
		authored: &[usize],
		attacker: &AttackerState,
	) -> Option<Arc<AttackerState>> {
		if self.principal != ps.id {
			return None;
		}
		let size = attacker.known.len();
		let key = authored_hash(authored, Arc::as_ptr(&attacker.known), size);
		if let Some(bucket) = locked(&self.agreed).get(&key)
			&& let Some((_, _, hit)) = bucket
				.iter()
				.find(|(seen, known, _)| Arc::ptr_eq(known, &attacker.known) && seen == authored)
		{
			return hit.clone();
		}
		let admissible = |i: usize, slot: usize, record: &Arc<MutationRecord>| {
			self.forwards(km, attacker, i, slot, authored)
				&& self.execution_agrees(ctx, km, attacker, record, authored)
		};
		let alternate_route =
			|i: usize, route: &DerivationRecord, record: &Arc<MutationRecord>| match route {
				DerivationRecord::Obtained { slot } | DerivationRecord::Leaked { slot } => {
					observable_slot(km, slot.get())
						&& !record
							.tainted()
							.any(|diff| received_by(ps, diff.index.get()))
						&& admissible(i, slot.get(), record)
				}
				_ => false,
			};
		let consulted: std::cell::RefCell<Vec<(usize, Vec<bool>)>> =
			std::cell::RefCell::new(Vec::new());
		let keep = reachable_knowledge_via(
			ps,
			attacker,
			|i, slot| {
				attacker
					.record(KnownIdx(i))
					.is_some_and(|record| admissible(i, slot.get(), record))
			},
			|i| {
				let Some(routes) = attacker.alternates.get(i) else {
					return Vec::new();
				};
				let taken: Vec<bool> = routes
					.iter()
					.map(|(route, record)| alternate_route(i, route, record))
					.collect();
				let needs: Vec<Vec<Value>> = routes
					.iter()
					.zip(taken.iter())
					.filter(|&(_, &keep)| keep)
					.map(|((_, record), _)| {
						record.tainted().map(|diff| diff.value.clone()).collect()
					})
					.collect();
				consulted.borrow_mut().push((i, taken));
				needs
			},
		);
		let consulted = consulted.into_inner();
		let mut pruned = false;
		let mut alternates: Vec<Vec<Route>> = Vec::new();
		for (i, taken) in consulted {
			if taken.iter().all(|&keep| keep) {
				continue;
			}
			if alternates.is_empty() {
				alternates = attacker.alternates.as_ref().clone();
			}
			if let Some(routes) = alternates.get_mut(i) {
				let mut keep = taken.iter();
				routes.retain(|_| *keep.next().unwrap_or(&true));
				pruned = true;
			}
		}
		let built = if pruned {
			let base = attacker.with_alternates(alternates);
			base.retaining(&keep).or_else(|| Some(Arc::new(base)))
		} else {
			attacker.retaining(&keep)
		};
		locked(&self.agreed).entry(key).or_default().push((
			authored.to_vec(),
			Arc::clone(&attacker.known),
			built.clone(),
		));
		built
	}

	fn execution_agrees(
		&self,
		ctx: &VerifyContext,
		km: &ProtocolTrace,
		attacker: &AttackerState,
		record: &Arc<MutationRecord>,
		authored: &[usize],
	) -> bool {
		let diffs: Vec<(PrincipalId, SlotIdx, Value)> = record
			.tainted()
			.map(|diff| (diff.state, diff.index, diff.value.clone()))
			.collect();
		if diffs.is_empty() {
			return true;
		}
		if let Some((_, _, _, hit)) =
			locked(&self.histories)
				.iter()
				.find(|(seen, seen_authored, known, _)| {
					Arc::ptr_eq(seen, record)
						&& seen_authored == authored
						&& Arc::ptr_eq(known, &attacker.known)
				}) {
			return *hit;
		}
		let agrees = self.replays_agree(ctx, km, attacker, &diffs, authored);
		locked(&self.histories).push((
			Arc::clone(record),
			authored.to_vec(),
			Arc::clone(&attacker.known),
			agrees,
		));
		agrees
	}

	fn replays_agree(
		&self,
		ctx: &VerifyContext,
		km: &ProtocolTrace,
		attacker: &AttackerState,
		diffs: &[(PrincipalId, SlotIdx, Value)],
		authored: &[usize],
	) -> bool {
		for origin in ctx.principal_states() {
			if origin.id == self.principal {
				continue;
			}
			let watched: Vec<usize> = (0..origin.values.len())
				.filter(|&at| {
					self.forwarded.get(at).is_some_and(Option::is_some)
						&& !authored.contains(&at)
						&& km
							.slots
							.get(at)
							.is_some_and(|slot| slot.creator == origin.id)
				})
				.collect();
			if watched.is_empty() {
				continue;
			}
			let installs: Vec<(SlotIdx, Value)> = diffs
				.iter()
				.filter(|(state, slot, _)| {
					*state == origin.id
						&& origin.meta.get(slot.get()).is_some_and(|meta| {
							meta.creator != origin.id && meta.wire.contains(&origin.id)
						})
				})
				.map(|(_, slot, value)| (*slot, value.clone()))
				.collect();
			if installs.is_empty() {
				continue;
			}
			let Ok(out) = reexecute(&origin.clone_for_depth(true), &installs, attacker, km) else {
				continue;
			};
			for at in watched {
				let Some(Some(honest)) = self.forwarded.get(at) else {
					continue;
				};
				if at >= out.values.len()
					|| out.slot_unreached(at)
					|| !reduce_once(&out.values[at].value).equivalent(honest, true)
				{
					return false;
				}
			}
		}
		true
	}

	fn forwards(
		&self,
		km: &ProtocolTrace,
		attacker: &AttackerState,
		held: usize,
		at: usize,
		authored: &[usize],
	) -> bool {
		if authored.contains(&at) {
			return true;
		}
		let Some(from) = attacker.record(KnownIdx(held)).map(|r| r.principal_id) else {
			return true;
		};
		let Some(Some(forwarded)) = self.forwarded.get(at) else {
			return true;
		};
		if !km
			.slots
			.get(at)
			.is_some_and(|slot| from == slot.creator || from == self.principal)
		{
			return true;
		}
		reduce_once(&attacker.known[held]).equivalent(forwarded, true)
	}
}

fn authored_hash(authored: &[usize], known: *const Vec<Value>, size: usize) -> u64 {
	let mut hash = 0xcbf2_9ce4_8422_2325u64;
	let mut mix = |word: u64| {
		hash ^= word;
		hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
	};
	mix(known as u64);
	mix(size as u64);
	for slot in authored {
		mix(*slot as u64);
	}
	hash
}

pub(crate) struct Guards<'a> {
	pub(crate) controllable: &'a Controllable,
	pub(crate) bound: &'a TermBound,
	pub(crate) history: &'a Coherence,
}

fn term_depth(v: &Value) -> usize {
	term_depth_outside(
		v,
		&crate::hashing::TermSet::default(),
		&mut IdMap::default(),
	)
}

fn term_depth_outside(
	v: &Value,
	basis: &crate::hashing::TermSet,
	memo: &mut IdMap<usize, usize>,
) -> usize {
	match v {
		Value::Constant(_) => 0,
		Value::Primitive(p) => {
			if !basis.is_empty() && basis.contains(v) {
				return 0;
			}
			let key = Arc::as_ptr(p) as usize;
			if let Some(&depth) = memo.get(&key) {
				return depth;
			}
			let depth = 1 + p
				.arguments
				.iter()
				.map(|a| term_depth_outside(a, basis, memo))
				.max()
				.unwrap_or(0);
			memo.insert(key, depth);
			depth
		}
	}
}

pub(crate) fn attacker_controllable(
	idx: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> bool {
	let Some(meta) = ps.meta.get(idx) else {
		return false;
	};
	if idx >= ps.values.len() {
		return false;
	}
	if meta.constant.is_nil() {
		return false;
	}
	if meta.guard {
		if !meta
			.mutatable_to
			.contains(&ps.values[idx].provenance.sender)
		{
			return false;
		}
	} else if ps.values[idx].provenance.creator == ps.id || meta.wire.is_empty() {
		return false;
	}
	if !meta
		.delivery_phases
		.iter()
		.map(|&(_, phase)| phase)
		.min()
		.is_some_and(|phase| phase <= attacker.current_phase)
	{
		return false;
	}
	if !km.constant_used_by(ps.id, &meta.constant)
		&& meta.sent_at.is_none()
		&& !km.equivalence_queried.contains(&meta.constant.id)
	{
		return false;
	}
	true
}

pub(crate) fn governing_attacker(
	ctx: &VerifyContext,
	phases: &[i32],
	ambient: &AttackerState,
) -> AttackerState {
	let earliest = phases.iter().copied().min();
	match earliest {
		Some(phase) if phase < ambient.current_phase => {
			ctx.attacker_knowledge_at(phase).unwrap_or_default()
		}
		_ => ambient.clone(),
	}
}

pub(crate) fn reexecute(
	ps_base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	attacker: &AttackerState,
	km: &ProtocolTrace,
) -> VResult<PrincipalState> {
	reexecute_with(ps_base, installs, None, &[], attacker, km, false)
}

pub(crate) fn reexecute_at(
	ps_base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	phases: &[i32],
	attacker: &AttackerState,
	km: &ProtocolTrace,
	addressed: bool,
) -> VResult<PrincipalState> {
	reexecute_with(
		ps_base,
		installs,
		Some(phases),
		&[],
		attacker,
		km,
		addressed,
	)
}

fn reexecute_with(
	ps_base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	phases: Option<&[i32]>,
	forwarded: &[(SlotIdx, Value, bool)],
	_attacker: &AttackerState,
	km: &ProtocolTrace,
	addressed: bool,
) -> VResult<PrincipalState> {
	let mut ps = ps_base.clone();
	let relayed = relayed_installs(&ps, installs);
	let authored: Vec<bool> = installs
		.iter()
		.map(|(slot, ground)| {
			slot.get() < ps.values.len() && attacker_authored(ground, slot.get(), km, &ps)
		})
		.collect();
	for (i, ((slot, ground), authored)) in installs.iter().zip(authored).enumerate() {
		if slot.get() < ps.values.len() {
			let at = phases.and_then(|phases| phases.get(i).copied());
			install(&mut ps, slot.get(), ground.clone(), authored, at, addressed);
		}
	}
	for (slot, value, authored) in forwarded {
		if slot.get() < ps.values.len() {
			install_forwarded(&mut ps, slot.get(), value.clone(), *authored);
		}
	}

	if slot_graph_is_cyclic(&ps) {
		return Err(VerifpalError::resolution(
			"attacker-chosen values would define a slot in terms of itself".into(),
		));
	}

	ps.resolve_all_values()?;
	let failures = ps.perform_all_rewrites();

	if !relays_are_forwarded(&ps, km, &relayed, &failures) {
		return Err(VerifpalError::resolution(
			"a guarded value's forwarder halts before forwarding it".into(),
		));
	}

	let foreign = foreign_halts(&ps, &failures);
	let starved = starved_slots(km, &ps, &foreign);

	ps = halt_at(ps, &failures);
	ps.foreign_halts = foreign;
	ps.starved = starved;
	ps.forwarded = !forwarded.is_empty();
	Ok(ps)
}

fn starved_slots(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	foreign: &[(PrincipalId, usize)],
) -> Vec<usize> {
	if foreign.is_empty() {
		return Vec::new();
	}
	let n = ps.values.len().min(km.slots.len());
	let delivered = |i: usize| ps.values[i].provenance.attacker_tainted;
	let unreached = unreached_slots(km, n, foreign, &delivered);
	(0..n)
		.filter(|&i| unreached[i])
		.filter(|&i| {
			!foreign
				.iter()
				.any(|&(who, at)| who == km.slots[i].creator && i >= at)
		})
		.collect()
}

pub(crate) fn execute_forward(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	phases: Option<&[i32]>,
	attacker: &AttackerState,
	addressed: bool,
) -> VResult<Vec<PrincipalState>> {
	let first = reexecute_with(base, installs, phases, &[], attacker, km, addressed)?;
	let mut out = vec![first];
	forward_to_fixpoint(
		ctx,
		km,
		&mut out,
		&[(base.id, installs.to_vec())],
		Some(DrivingReplay {
			base,
			phases,
			addressed,
		}),
		attacker,
	)?;
	Ok(out)
}

pub(crate) type Seeds = Vec<(PrincipalId, Vec<(SlotIdx, Value)>)>;

type Forwardings = Vec<(PrincipalId, Vec<(SlotIdx, Value, bool)>)>;

fn same_forwardings(a: &[(SlotIdx, Value, bool)], b: &[(SlotIdx, Value, bool)]) -> bool {
	a.len() == b.len()
		&& a.iter()
			.zip(b)
			.all(|((slot, value, authored), (other, seen, was))| {
				slot == other && authored == was && value.equivalent(seen, true)
			})
}

struct DrivingReplay<'a> {
	base: &'a PrincipalState,
	phases: Option<&'a [i32]>,
	addressed: bool,
}

#[derive(PartialEq, Eq)]
struct ForwardReach {
	principal: PrincipalId,
	halted_at: Option<i32>,
	foreign_halts: Vec<(PrincipalId, usize)>,
	starved: Vec<usize>,
}

impl ForwardReach {
	fn of(state: &PrincipalState) -> Self {
		Self {
			principal: state.id,
			halted_at: state.halted_at,
			foreign_halts: state.foreign_halts.clone(),
			starved: state.starved.clone(),
		}
	}
}

fn forward_to_fixpoint(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	out: &mut Vec<PrincipalState>,
	seeds: &[(PrincipalId, Vec<(SlotIdx, Value)>)],
	driving: Option<DrivingReplay<'_>>,
	attacker: &AttackerState,
) -> VResult<()> {
	let mut applied: Forwardings = Vec::new();
	let mut seen: Vec<(Forwardings, Vec<ForwardReach>)> = Vec::new();
	loop {
		let mut changed = false;
		for pristine in ctx.principal_states() {
			let driver = driving
				.as_ref()
				.filter(|driver| driver.base.id == pristine.id);
			let pristine = driver.map_or(pristine, |driver| driver.base);
			let seed: &[(SlotIdx, Value)] = seeds
				.iter()
				.find(|(principal, _)| *principal == pristine.id)
				.map(|(_, mine)| mine.as_slice())
				.unwrap_or(&[]);
			let forwarded: Vec<(SlotIdx, Value, bool)> =
				forwarded_installs(ctx, km, out, pristine, attacker)
					.into_iter()
					.filter(|(slot, _, _)| !seed.iter().any(|(held, _)| held == slot))
					.collect();
			if forwarded.is_empty() && !applied.iter().any(|(id, _)| *id == pristine.id) {
				continue;
			}
			if applied
				.iter()
				.any(|(id, seen)| *id == pristine.id && same_forwardings(seen, &forwarded))
			{
				continue;
			}
			let mut state = reexecute_with(
				&pristine.clone_for_depth(true),
				seed,
				driver.and_then(|driver| driver.phases),
				&forwarded,
				attacker,
				km,
				driver.is_some_and(|driver| driver.addressed),
			)?;
			adopt_foreign_halts(km, &mut state, out);
			match applied.iter_mut().find(|(id, _)| *id == pristine.id) {
				Some((_, seen)) => *seen = forwarded,
				None => applied.push((pristine.id, forwarded)),
			}
			match out.iter_mut().find(|held| held.id == pristine.id) {
				Some(held) => *held = state,
				None => out.push(state),
			}
			changed = true;
		}
		for at in 0..out.len() {
			let mut updated = out[at].clone();
			adopt_foreign_halts(km, &mut updated, out);
			if ForwardReach::of(&updated) != ForwardReach::of(&out[at]) {
				out[at] = updated;
				changed = true;
			}
		}
		if !changed {
			return Ok(());
		}
		let reach = out.iter().map(ForwardReach::of).collect::<Vec<_>>();
		if seen.iter().any(|(prior, prior_reach)| {
			*prior_reach == reach
				&& prior.len() == applied.len()
				&& prior
					.iter()
					.zip(&applied)
					.all(|((a, left), (b, right))| a == b && same_forwardings(left, right))
		}) {
			return Err(VerifpalError::resolution(
				"message forwarding repeats an execution without stabilizing".into(),
			));
		}
		seen.push((applied.clone(), reach));
	}
}

/// Replay a recorded substitution as the one execution it describes.
/// A `MutationRecord` names the slots the attacker had changed when a value
/// was read, not the principal each change was delivered to; a merged record
/// carries diffs from several. Every principal that receives one of the
/// changed slots is run under the diffs that reach it, and the runs are then
/// carried forward together to a fixed point, so that what the substitution
/// did to the rest of the protocol is present in the result. It is one
/// execution, not one per principal: a principal that was handed a value on a
/// leg keeps it, whatever its honest peer would have emitted there, since that
/// delivery is what the substitution *is*. Running the recipients separately
/// and letting the last one's consequences win was how a man-in-the-middle
/// run of Bob got replaced by a Bob fed Alice's honest flight.
pub(crate) fn replay_diffs(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	seeds: &[(PrincipalId, Vec<(SlotIdx, Value)>)],
	attacker: &AttackerState,
) -> Option<Vec<PrincipalState>> {
	let mut bases: Vec<&PrincipalState> = Vec::new();
	let mut installed: Seeds = Vec::new();
	for (principal, mine) in seeds {
		let pristine = ctx
			.principal_states()
			.iter()
			.find(|state| state.id == *principal)?;
		let mine: Vec<(SlotIdx, Value)> = mine
			.iter()
			.filter(|(slot, _)| {
				pristine.meta.get(slot.get()).is_some_and(|meta| {
					meta.creator != pristine.id && meta.wire.contains(&pristine.id)
				})
			})
			.cloned()
			.collect();
		if mine.is_empty() {
			continue;
		}
		bases.push(pristine);
		installed.push((*principal, mine));
	}
	let scheduled: Vec<_> = installed
		.iter()
		.flat_map(|(at, mine)| mine.iter().map(|(slot, value)| (*at, *slot, value.clone())))
		.collect();
	if !causally_grounded(km, &scheduled, ctx.principal_states(), attacker) {
		return None;
	}
	let mut out = Vec::new();
	for (pristine, (_, mine)) in bases.iter().zip(&installed) {
		out.push(reexecute(&pristine.clone_for_depth(true), mine, attacker, km).ok()?);
	}
	if out.is_empty() {
		return Some(out);
	}
	forward_to_fixpoint(ctx, km, &mut out, &installed, None, attacker).ok()?;
	Some(out)
}

pub(crate) fn same_installs(a: &[(SlotIdx, Value)], b: &[(SlotIdx, Value)]) -> bool {
	a.len() == b.len()
		&& a.iter()
			.zip(b.iter())
			.all(|((sa, va), (sb, vb))| sa == sb && va.equivalent(vb, true))
}

fn forwarded_installs(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	executed: &[PrincipalState],
	target: &PrincipalState,
	attacker: &AttackerState,
) -> Vec<(SlotIdx, Value, bool)> {
	let mut out: Vec<(SlotIdx, Value, bool)> = Vec::new();
	for source in executed {
		if source.id == target.id {
			continue;
		}
		for at in 0..target.values.len() {
			if out.iter().any(|(slot, _, _)| slot.get() == at) {
				continue;
			}
			let Some(slot) = km.slots.get(at) else {
				continue;
			};
			let sends = slot.sent_by.iter().filter(|event| {
				event.sender == source.id
					&& event.recipient == target.id
					&& event.phase <= attacker.current_phase
					&& source.event_reached(km, source.id, event.declared_at)
			});
			let mut sent = false;
			let mut newly = false;
			for event in sends {
				sent = true;
				newly |= !ctx.honest_run_delivered(km, at, event);
			}
			if !sent || at >= source.values.len() || source.slot_unreached(at) {
				continue;
			}
			let emitted = &source.values[at].value;
			if !attacker_authored(emitted, at, km, target) && !(newly && !source.slot_starved(at)) {
				continue;
			}
			out.push((
				SlotIdx(at),
				emitted.clone(),
				source.values[at].provenance.sender == ATTACKER_ID,
			));
		}
	}
	out
}

fn adopt_foreign_halts(
	km: &ProtocolTrace,
	state: &mut PrincipalState,
	executed: &[PrincipalState],
) {
	let mut changed = false;
	for source in executed {
		for &(who, at) in &source.foreign_halts {
			if who == state.id || executed.iter().any(|ran| ran.id == who) {
				continue;
			}
			match state
				.foreign_halts
				.iter_mut()
				.find(|(seen, _)| *seen == who)
			{
				Some((_, known)) => {
					if at < *known {
						*known = at;
						changed = true;
					}
				}
				None => {
					state.foreign_halts.push((who, at));
					changed = true;
				}
			}
		}
	}
	for source in executed {
		if source.id == state.id {
			continue;
		}
		let actual = source
			.halted_at
			.is_some()
			.then(|| source.values.len().saturating_sub(1));
		let position = state
			.foreign_halts
			.iter()
			.position(|&(who, _)| who == source.id);
		match (position, actual) {
			(Some(i), Some(at)) => {
				if state.foreign_halts[i].1 != at {
					state.foreign_halts[i].1 = at;
					changed = true;
				}
			}
			(Some(i), None) => {
				state.foreign_halts.remove(i);
				changed = true;
			}
			(None, Some(at)) => {
				state.foreign_halts.push((source.id, at));
				changed = true;
			}
			(None, None) => {}
		}
	}
	if changed {
		state.starved = starved_slots(km, state, &state.foreign_halts);
	}
}

fn install_forwarded(ps: &mut PrincipalState, slot: usize, value: Value, authored: bool) {
	let sv = &mut ps.values[slot];
	sv.pre_rewrite = value.clone();
	sv.value = value;
	sv.provenance.attacker_tainted = true;
	if authored {
		sv.provenance.sender = ATTACKER_ID;
	}
}

fn relayed_installs(
	ps: &PrincipalState,
	installs: &[(SlotIdx, Value)],
) -> Vec<(usize, PrincipalId)> {
	installs
		.iter()
		.filter_map(|(slot, _)| {
			let i = slot.get();
			let meta = ps.meta.get(i)?;
			let sender = ps.values.get(i)?.provenance.sender;
			(meta.guard && sender != ps.id && sender != ATTACKER_ID).then_some((i, sender))
		})
		.collect()
}

fn relays_are_forwarded(
	ps: &PrincipalState,
	km: &ProtocolTrace,
	relayed: &[(usize, PrincipalId)],
	failures: &[(Primitive, usize)],
) -> bool {
	relayed.iter().all(|&(slot, sender)| {
		let send = km.slots.get(slot).and_then(|s| {
			s.sent_by
				.iter()
				.find(|event| event.sender == sender && event.recipient == ps.id)
		});
		let Some(send) = send else {
			return true;
		};
		failures.iter().all(|(prim, idx)| {
			!prim.instance_check
				|| ps.values[*idx].provenance.creator != sender
				|| ps.meta[*idx].declared_at >= send.declared_at
		})
	})
}

pub(crate) fn halt_at_failed_checks(
	km: &ProtocolTrace,
	mut ps: PrincipalState,
	failures: &[(Primitive, usize)],
) -> PrincipalState {
	let foreign = foreign_halts(&ps, failures);
	let starved = starved_slots(km, &ps, &foreign);
	ps = halt_at(ps, failures);
	ps.foreign_halts = foreign;
	ps.starved = starved;
	ps
}

pub(crate) fn creator_halts(
	ps: &PrincipalState,
	failures: &[(Primitive, usize)],
) -> Vec<(PrincipalId, usize)> {
	let mut out: Vec<(PrincipalId, usize)> = Vec::new();
	for (prim, idx) in failures {
		if !prim.instance_check {
			continue;
		}
		let Some(sv) = ps.values.get(*idx) else {
			continue;
		};
		let creator = sv.provenance.creator;
		if creator == ATTACKER_ID {
			continue;
		}
		match out.iter_mut().find(|(principal, _)| *principal == creator) {
			Some((_, at)) => *at = (*at).min(*idx),
			None => out.push((creator, *idx)),
		}
	}
	out
}

pub(crate) fn message_available(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	witness: &[PrincipalState],
	event: &SendEvent,
	slot: usize,
) -> bool {
	struct Availability<'a> {
		km: &'a ProtocolTrace,
		ps: &'a PrincipalState,
		witness: &'a [PrincipalState],
		active: Vec<(PrincipalId, usize, i32)>,
		memo: IdMap<(PrincipalId, usize, i32), bool>,
	}
	impl Availability<'_> {
		fn state(&self, who: PrincipalId) -> &PrincipalState {
			self.witness
				.iter()
				.find(|state| state.id == who)
				.unwrap_or(self.ps)
		}

		fn held(&mut self, who: PrincipalId, at: usize, before: i32) -> bool {
			let slot = &self.km.slots[at];
			let state = self.state(who);
			if !state.event_reached(self.km, who, before) {
				return false;
			}
			if slot.constant.is_nil()
				|| slot.constant.qualifier == Some(Qualifier::Public)
				|| slot
					.known_by
					.iter()
					.any(|&(holder, sender)| holder == who && sender == who)
			{
				return true;
			}
			if state.id == who
				&& state
					.values
					.get(at)
					.is_some_and(|sv| sv.provenance.attacker_tainted)
				&& slot
					.sent_by
					.iter()
					.any(|send| send.recipient == who && send.declared_at <= before)
			{
				return true;
			}
			let key = (who, at, before);
			if let Some(&held) = self.memo.get(&key) {
				return held;
			}
			if self.active.contains(&key) {
				return false;
			}
			self.active.push(key);
			let held = if slot.creator == who {
				slot.declared_at <= before
					&& slot.initial_value.constant_leaves().all(|leaf| {
						self.km.index_of(leaf).is_none_or(|input| {
							input == at || self.held(who, input, slot.declared_at)
						})
					})
			} else {
				slot.sent_by.iter().any(|send| {
					send.recipient == who
						&& send.declared_at <= before
						&& self.held(send.sender, at, send.declared_at)
				})
			};
			self.active.pop();
			self.memo.insert(key, held);
			held
		}
	}
	Availability {
		km,
		ps,
		witness,
		active: Vec::new(),
		memo: IdMap::default(),
	}
	.held(event.sender, slot, event.declared_at)
}

pub(crate) fn honest_run_unreached(
	km: &ProtocolTrace,
	halts: &[(PrincipalId, usize)],
) -> Vec<bool> {
	if halts.is_empty() {
		return vec![false; km.slots.len()];
	}
	unreached_slots(km, km.slots.len(), halts, &|_| false)
}

fn unreached_slots(
	km: &ProtocolTrace,
	n: usize,
	halts: &[(PrincipalId, usize)],
	delivered: &dyn Fn(usize) -> bool,
) -> Vec<bool> {
	let mut unreached = vec![false; n];
	let halt_of = |who: PrincipalId| {
		halts
			.iter()
			.find(|&&(halted, _)| halted == who)
			.map(|&(_, at)| at)
	};
	let event_reached = |who: PrincipalId, declared_at: i32| {
		halt_of(who)
			.and_then(|at| km.slots.get(at))
			.is_none_or(|slot| declared_at <= slot.declared_at)
	};
	for i in 0..n {
		if delivered(i) {
			continue;
		}
		let slot = &km.slots[i];
		if halt_of(slot.creator).is_some_and(|at| i >= at) {
			unreached[i] = true;
			continue;
		}
		unreached[i] = slot.initial_value.constant_leaves().any(|c| {
			km.index_of(c).is_some_and(|j| {
				j != i
					&& j < n && !slot_held(
					km,
					&unreached,
					&event_reached,
					delivered,
					slot.creator,
					j,
					&mut Vec::new(),
				)
			})
		});
	}
	unreached
}

fn slot_held(
	km: &ProtocolTrace,
	unreached: &[bool],
	event_reached: &dyn Fn(PrincipalId, i32) -> bool,
	delivered: &dyn Fn(usize) -> bool,
	who: PrincipalId,
	slot: usize,
	visiting: &mut Vec<PrincipalId>,
) -> bool {
	if delivered(slot) {
		return true;
	}
	let trace_slot = &km.slots[slot];
	if trace_slot
		.known_by
		.iter()
		.any(|&(holder, sender)| holder == who && sender == who)
	{
		return true;
	}
	if unreached[slot] {
		return false;
	}
	if trace_slot.creator == who {
		return true;
	}
	if visiting.contains(&who) {
		return false;
	}
	visiting.push(who);
	let held = trace_slot.sent_by.iter().any(|event| {
		event.recipient == who
			&& event_reached(event.sender, event.declared_at)
			&& slot_held(
				km,
				unreached,
				event_reached,
				delivered,
				event.sender,
				slot,
				visiting,
			)
	});
	visiting.pop();
	held
}

fn foreign_halts(
	ps: &PrincipalState,
	failures: &[(Primitive, usize)],
) -> Vec<(PrincipalId, usize)> {
	creator_halts(ps, failures)
		.into_iter()
		.filter(|&(principal, _)| principal != ps.id)
		.collect()
}

type BlockedAt = crate::context::Generational<IdMap<Vec<(PrincipalId, i32)>, Arc<Vec<bool>>>>;
type RestrictedAt = crate::context::Generational<
	crate::context::Recent<
		crate::context::KnowledgeKey,
		Vec<(PrincipalId, i32)>,
		Option<Arc<AttackerState>>,
	>,
>;

thread_local! {
	static BLOCKED_AT: std::cell::RefCell<BlockedAt> =
		std::cell::RefCell::new(crate::context::Generational::default());
	static RESTRICTED_AT: std::cell::RefCell<RestrictedAt> =
		std::cell::RefCell::new(crate::context::Generational::default());
}

#[cfg(test)]
fn held_at(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	at: i32,
	attacker: &AttackerState,
) -> Option<Arc<AttackerState>> {
	held_before(km, ps, vec![(ps.id, at)], attacker)
}

fn held_before(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	after: Vec<(PrincipalId, i32)>,
	attacker: &AttackerState,
) -> Option<Arc<AttackerState>> {
	let blocked = BLOCKED_AT.with(|cache| {
		cache
			.borrow_mut()
			.fresh()
			.entry(after.clone())
			.or_insert_with(|| Arc::new(unreachable_before(km, &after)))
			.clone()
	});
	if !blocked.iter().any(|&blocked| blocked) {
		return None;
	}
	let group = crate::context::KnowledgeKey::of(attacker);
	if let Some(hit) =
		RESTRICTED_AT.with(|cache| cache.borrow_mut().fresh().group(group).get(&after).cloned())
	{
		return hit;
	}
	let built = restrict_known(&blocked, &|slot| observable_slot(km, slot), ps, attacker);
	RESTRICTED_AT.with(|cache| {
		cache
			.borrow_mut()
			.fresh()
			.group(group)
			.insert(after, built.clone());
	});
	built
}

pub(crate) fn attacker_authored(
	ground: &Value,
	slot: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> bool {
	let honest = &ps.values[slot].value;
	let trace_reduct = reduce_once(&resolve_trace_term(honest, km));
	let ground_reduct = reduce_once(ground);
	!ground_reduct.equivalent(&trace_reduct, true)
}

pub(crate) fn slot_graph_is_cyclic(ps: &PrincipalState) -> bool {
	let n = ps.values.len();
	let mut edges: Vec<usize> = Vec::new();
	let mut bounds: Vec<usize> = Vec::with_capacity(n + 1);
	bounds.push(0);
	for (own, sv) in ps.values.iter().enumerate() {
		let from = edges.len();
		for v in [&sv.value, sv.perceived()] {
			match v {
				Value::Primitive(_) => collect_slot_references(v, ps, &mut edges, from),
				Value::Constant(c) => {
					if let Some(alias) = ps.index_of(c)
						&& alias != own && !edges[from..].contains(&alias)
					{
						edges.push(alias);
					}
				}
			}
		}
		bounds.push(edges.len());
	}

	// Iterative depth-first search: 0 unvisited, 1 on the current path, 2 done.
	let mut mark = vec![0u8; n];
	let mut stack: Vec<(usize, usize)> = Vec::new();
	for start in 0..n {
		if mark[start] != 0 {
			continue;
		}
		mark[start] = 1;
		stack.push((start, bounds[start]));
		while let Some((slot, edge)) = stack.pop() {
			if edge >= bounds[slot + 1] {
				mark[slot] = 2;
				continue;
			}
			let next = edges[edge];
			stack.push((slot, edge + 1));
			match mark[next] {
				1 => return true,
				0 => {
					mark[next] = 1;
					stack.push((next, bounds[next]));
				}
				_ => {}
			}
		}
	}
	false
}

fn collect_slot_references(v: &Value, ps: &PrincipalState, out: &mut Vec<usize>, from: usize) {
	for c in v.constant_leaves() {
		if let Some(i) = ps.index_of(c)
			&& !out[from..].contains(&i)
		{
			out.push(i);
		}
	}
}

pub(crate) fn install(
	ps: &mut PrincipalState,
	slot: usize,
	ground: Value,
	authored: bool,
	at: Option<i32>,
	addressed: bool,
) {
	let previous = ps.values[slot].value.clone();
	let sv = &mut ps.values[slot];
	sv.original = previous;
	sv.installed_at = at;
	sv.addressed = addressed;
	sv.provenance.creator = ATTACKER_ID;
	sv.provenance.attacker_tainted = true;
	if authored {
		sv.provenance.sender = ATTACKER_ID;
	}
	sv.pre_rewrite = ground.clone();
	sv.value = ground;
}

fn halt_at(mut ps: PrincipalState, failures: &[(Primitive, usize)]) -> PrincipalState {
	if let Some((truncate_at, halted_at)) = truncation_point(&ps, failures) {
		ps = drop_after_index(ps, truncate_at);
		ps.halted_at = Some(halted_at);
	}
	ps
}

fn truncation_point(ps: &PrincipalState, failures: &[(Primitive, usize)]) -> Option<(usize, i32)> {
	for (prim, idx) in failures {
		if !prim.instance_check || ps.values[*idx].provenance.creator != ps.id {
			continue;
		}
		let declared_at = ps.meta[*idx].declared_at;
		return Some((idx + 1, declared_at));
	}
	None
}

fn drop_after_index(mut ps: PrincipalState, at: usize) -> PrincipalState {
	Arc::make_mut(&mut ps.meta).truncate(at);
	ps.values.truncate(at);
	ps
}

#[cfg(test)]
mod tests {
	use crate::testutil::*;
	use crate::types::{PrincipalState, SlotIdx};

	#[test]
	fn causal_cache_preserves_the_receive_cut_and_knowledge_identity() {
		use super::*;
		let _generation = crate::context::GenerationGuard::enter();
		let model = crate::parser::parse_string(
			"causal_cache.vp",
			"attacker[active]\nprincipal Alice[\ngenerates x\n]\nprincipal Bob[\nknows private early, late\nleaks early\n]\nAlice -> Bob: x\nprincipal Bob[\ntag = MAC(late, x)\nleaks late\n]\nqueries[\nconfidentiality? late\n]\n",
		).unwrap();
		let (km, states) = crate::sanity::sanity(&model).unwrap();
		let ps = states.iter().find(|state| state.name == "Bob").unwrap();
		let early = trace_constant(&km, "early");
		let late = trace_constant(&km, "late");
		let slot = |value: &Value| SlotIdx(km.index_of(value.as_constant().unwrap()).unwrap());
		let mut attacker = make_attacker_state(vec![early.clone(), late.clone()]);
		attacker.derivations = Arc::new(vec![
			DerivationRecord::Leaked { slot: slot(&early) },
			DerivationRecord::Leaked { slot: slot(&late) },
		]);
		let x = slot(&trace_constant(&km, "x")).get();
		let receive_at = km.slots[x].sent_by[0].declared_at;
		let restricted = available_before_receive(&km, ps, x, &attacker, false).unwrap();
		assert!(restricted.knows(&early).is_some());
		assert!(restricted.knows(&late).is_none());
		assert!(Arc::ptr_eq(
			&restricted,
			&held_at(&km, ps, receive_at, &attacker).unwrap()
		));
		let check_at = km.slots[slot(&trace_constant(&km, "tag")).get()].declared_at;
		assert!(
			held_at(&km, ps, check_at, &attacker)
				.unwrap()
				.knows(&late)
				.is_none()
		);
		let after_leak = km.leaks.iter().map(|leak| leak.declared_at).max().unwrap() + 1;
		assert!(held_at(&km, ps, after_leak, &attacker).is_none());
		let other = make_attacker_state(vec![early, late]);
		assert!(available_before_receive(&km, ps, x, &other, false).is_none());
		let mut upgraded = attacker.clone();
		Arc::make_mut(&mut upgraded.derivations)[1] = DerivationRecord::Initial;
		upgraded.routes_epoch += 1;
		assert!(available_before_receive(&km, ps, x, &upgraded, false).is_none());
		assert!(Arc::ptr_eq(
			&restricted,
			&available_before_receive(&km, ps, x, &attacker, false).unwrap()
		));
	}

	#[test]
	fn causal_knowledge_follows_unheld_shared_inputs() {
		use super::*;
		let leaked = make_private("recipe_leaked");
		let mut factor = leaked.clone();
		for _ in 0..40 {
			factor = Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![factor.clone(), factor.clone(), factor],
				0,
			);
		}
		let target = Value::primitive(crate::primitive::PRIM_HASH, vec![factor.clone()], 0);
		let ps = make_principal_state("Alice", 0, Vec::new(), Vec::new());
		let mut attacker = make_attacker_state(vec![leaked, target.clone()]);
		attacker.derivations = Arc::new(vec![
			DerivationRecord::Leaked { slot: SlotIdx(0) },
			DerivationRecord::Reconstructed { from: vec![factor] },
		]);
		assert!(restrict_known(&[false], &|_| false, &ps, &attacker).is_none());
		let restricted = restrict_known(&[true], &|_| false, &ps, &attacker).unwrap();
		assert!(restricted.known.is_empty());
	}

	#[test]
	fn causal_knowledge_requires_grounded_later_dependencies() {
		use super::*;
		let leaf = make_private("recipe_later_leaf");
		let target = Value::primitive(crate::primitive::PRIM_HASH, vec![leaf.clone()], 0);
		let ps = make_principal_state("Alice", 0, Vec::new(), Vec::new());
		let mut attacker = make_attacker_state(vec![target.clone(), leaf.clone()]);
		attacker.derivations = Arc::new(vec![
			DerivationRecord::Reconstructed { from: vec![leaf] },
			DerivationRecord::Leaked { slot: SlotIdx(0) },
		]);
		assert!(restrict_known(&[false], &|_| false, &ps, &attacker).is_none());
		assert!(
			restrict_known(&[true], &|_| false, &ps, &attacker)
				.unwrap()
				.known
				.is_empty()
		);
		Arc::make_mut(&mut attacker.derivations)[1] = DerivationRecord::Decomposed {
			of: target,
			using: Vec::new(),
		};
		assert!(
			restrict_known(&[false], &|_| false, &ps, &attacker)
				.unwrap()
				.known
				.is_empty()
		);
	}

	#[test]
	fn slot_reference_collection_visits_shared_terms_once() {
		use super::*;
		let first = make_constant("slot_dag_first");
		let second = make_constant("slot_dag_second");
		let ps = make_principal_state(
			"Beacon",
			1,
			vec![
				make_slot_meta(first.as_constant().unwrap(), true),
				make_slot_meta(second.as_constant().unwrap(), true),
			],
			vec![make_slot_values(&first, 1), make_slot_values(&second, 1)],
		);
		let mut term = first;
		for _ in 0..40 {
			term = Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![term.clone(), term.clone(), term],
				0,
			);
		}
		let wrapped = Value::primitive(crate::primitive::PRIM_HASH, vec![term, second], 0);
		let mut references = vec![1];
		collect_slot_references(&wrapped, &ps, &mut references, 1);
		assert_eq!(references, vec![1, 0, 1]);
		collect_slot_references(&wrapped, &ps, &mut references, 1);
		assert_eq!(references, vec![1, 0, 1]);
	}

	#[test]
	fn shared_transcript_depth_respects_the_protocol_boundary() {
		use super::*;
		let mut term = make_constant("shared_depth_seed");
		let mut basis = crate::hashing::TermSet::default();
		for depth in 1..=40 {
			term = Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![term.clone(), term.clone(), term],
				0,
			);
			if depth == 16 {
				basis.insert(term.clone());
			}
		}
		assert_eq!(term_depth(&term), 40);
		assert_eq!(term_depth_outside(&term, &basis, &mut IdMap::default()), 24);
	}

	fn coherence_fixture(
		delivered: &crate::types::Value,
	) -> (crate::types::ProtocolTrace, PrincipalState) {
		use crate::types::*;
		let c = make_constant("coh_e");
		let constant = c.as_constant().expect("constant").clone();
		let trace = ProtocolTrace {
			principals: vec!["Alice".to_string(), "Bob".to_string()],
			principal_ids: vec![1, 2],
			slots: vec![TraceSlot {
				declared_span: Span::default(),
				constant: constant.clone(),
				initial_value: delivered.clone(),
				creator: 1,
				known_by: vec![(2, 1)],
				sent_by: vec![SendEvent {
					sender: 1,
					recipient: 2,
					declared_at: 1,
					phase: 0,
					guarded: false,
				}],
				declared_at: 0,
				phases: vec![0],
			}],
			index: {
				let mut m = IdMap::default();
				m.insert(constant.id, 0);
				m
			},
			max_phase: 0,
			used_by: IdMap::default(),
			leaks: std::sync::Arc::new(Vec::new()),
			session_siblings: IdMap::default(),
			copy_siblings: IdMap::default(),
			interchangeable: IdMap::default(),
			actors: IdMap::default(),
			scenario_bound: IdSet::default(),
			equivalence_queried: IdSet::default(),
		};
		let ps = make_principal_state(
			"Bob",
			2,
			vec![make_slot_meta(&constant, false)],
			vec![make_slot_values(delivered, 1)],
		);
		(trace, ps)
	}

	#[test]
	fn forwarding_stabilizes_across_repeated_principal_visits() {
		use super::*;
		let mut source = String::from(
			"attacker[active]\nprincipal Alice[\ngenerates seed\n]\nAlice -> Bob: seed\n",
		);
		let mut previous = "seed".to_owned();
		for i in 0..12 {
			let (sender, recipient) = if i % 2 == 0 {
				("Bob", "Alice")
			} else {
				("Alice", "Bob")
			};
			source.push_str(&format!(
				"principal {sender}[\nx{i} = HASH({previous})\n]\n{sender} -> {recipient}: [x{i}]\n"
			));
			previous = format!("x{i}");
		}
		source.push_str("queries[\nfreshness? x11\n]\n");
		let model = crate::parser::parse_string("forwarding_rounds.vp", &source).unwrap();
		let (km, states) = crate::sanity::sanity(&model).unwrap();
		let ctx =
			crate::context::VerifyContext::new(&model, &states, Vec::new(), 1, None, Vec::new());
		let bob = states.iter().find(|state| state.name == "Bob").unwrap();
		let seed = km
			.slots
			.iter()
			.position(|slot| slot.constant.name.as_ref() == "seed")
			.unwrap();
		let last = km
			.slots
			.iter()
			.position(|slot| slot.constant.name.as_ref() == "x11")
			.unwrap();
		let nil = crate::value::value_nil();
		let attacker = make_attacker_state(vec![nil.clone()]);
		let runs = replay_diffs(
			&ctx,
			&km,
			&[(bob.id, vec![(SlotIdx(seed), nil.clone())])],
			&attacker,
		)
		.unwrap();
		let mut expected = nil;
		for _ in 0..12 {
			expected = Value::primitive(crate::primitive::PRIM_HASH, vec![expected], 0);
		}
		let forwarded = execute_forward(
			&ctx,
			&km,
			&bob.clone_for_depth(true),
			&[(SlotIdx(seed), crate::value::value_nil())],
			None,
			&attacker,
			false,
		)
		.unwrap();
		for group in [&runs, &forwarded] {
			assert_eq!(group.len(), 2);
			for state in group {
				assert!(
					state
						.values
						.get(last)
						.is_some_and(|sv| sv.value.equivalent(&expected, true)),
					"{} retains a stale final receive",
					state.name
				);
			}
		}
		let mut continued = runs.clone();
		forward_to_fixpoint(
			&ctx,
			&km,
			&mut continued,
			&[(bob.id, vec![(SlotIdx(seed), crate::value::value_nil())])],
			None,
			&attacker,
		)
		.unwrap();
		for state in &continued {
			let prior = runs.iter().find(|prior| prior.id == state.id).unwrap();
			assert!(
				state
					.values
					.iter()
					.zip(&prior.values)
					.all(|(a, b)| a.value.equivalent(&b.value, true))
			);
		}
	}

	fn coherence_context() -> crate::context::VerifyContext {
		let src = "attacker[active]\nprincipal Alice[\nknows private coh_ctx_m\n]\nqueries[\nconfidentiality? coh_ctx_m\n]\n";
		let m = crate::parser::parse_string("coh.vp", src).expect("parse");
		crate::context::VerifyContext::new(&m, &[], Vec::new(), 1, None, Vec::new())
	}

	fn coherence_attacker(
		held: &crate::types::Value,
		from: crate::types::PrincipalId,
	) -> crate::types::AttackerState {
		use crate::types::*;
		let mut map: IdMap<u64, Vec<usize>> = IdMap::default();
		map.entry(held.hash_value()).or_default().push(0);
		AttackerState {
			current_phase: 0,
			known: std::sync::Arc::new(vec![held.clone()]),
			known_map: std::sync::Arc::new(map),
			mutation_records: std::sync::Arc::new(vec![std::sync::Arc::new(MutationRecord {
				diffs: vec![],
				principal_id: from,
				phase: 0,
			})]),
			derivations: std::sync::Arc::new(vec![DerivationRecord::Obtained { slot: SlotIdx(0) }]),
			alternates: std::sync::Arc::new(vec![Vec::new()]),
			worlds: std::sync::Arc::new(vec![Worlds::any()]),
			worlds_epoch: 0,
			reused: std::sync::Arc::new(vec![]),
			routes_epoch: 0,
			chain: crate::types::next_chain(),
		}
	}

	#[test]
	fn a_term_read_out_of_a_different_execution_of_the_sender_is_refused() {
		let honest = make_constant("coh_honest");
		let other = make_constant("coh_other");
		let (km, ps) = coherence_fixture(&honest);
		let history = super::Coherence::of(&km, &ps);
		let attacker = coherence_attacker(&other, 1);
		let restricted = history
			.compatible(&coherence_context(), &km, &ps, &[], &attacker)
			.expect("the incompatible term is dropped");
		assert!(
			restricted.knows(&other).is_none(),
			"a term obtained at a slot in the sender's own run, where that run produced \
			 something other than what this principal is being handed, belongs to an \
			 execution this one excludes"
		);
	}

	#[test]
	fn the_same_term_is_kept_where_the_attacker_authors_what_is_delivered() {
		let honest = make_constant("coh_honest_b");
		let other = make_constant("coh_other_b");
		let (km, ps) = coherence_fixture(&honest);
		let history = super::Coherence::of(&km, &ps);
		let attacker = coherence_attacker(&other, 1);
		assert!(
			history
				.compatible(&coherence_context(), &km, &ps, &[0], &attacker)
				.is_none(),
			"authoring what the recipient is handed claims nothing about what the sender \
			 produced, so the sender's other execution is not contradicted"
		);
	}

	#[test]
	fn a_term_read_while_walking_a_third_principal_is_kept() {
		let honest = make_constant("coh_honest_c");
		let other = make_constant("coh_other_c");
		let (km, ps) = coherence_fixture(&honest);
		let history = super::Coherence::of(&km, &ps);
		let attacker = coherence_attacker(&other, 3);
		assert!(
			history
				.compatible(&coherence_context(), &km, &ps, &[], &attacker)
				.is_none(),
			"a read performed while walking some other recipient says what that one was \
			 handed, and the attacker may hand two recipients different values"
		);
	}

	#[test]
	fn a_foreign_halt_never_names_the_state_it_is_recorded_on() {
		use crate::types::{Capabilities, HashCell, Primitive};
		let own = make_constant("fh_own");
		let mut ps = make_principal_state(
			"Alice",
			1,
			vec![make_slot_meta(own.as_constant().expect("constant"), true)],
			vec![make_slot_values(&own, 1)],
		);
		ps.values[0].provenance.creator = 1;
		let failing = Primitive {
			id: crate::primitive::PRIM_ASSERT,
			arguments: vec![own.clone(), own],
			output: 0,
			instance: 0,
			instance_check: true,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let halts = super::creator_halts(&ps, &[(failing.clone(), 0)]);
		assert_eq!(halts, vec![(1, 0)], "the creator's own halt is recorded");
		assert!(
			super::foreign_halts(&ps, &[(failing, 0)]).is_empty(),
			"`foreign_halts` filters the state's own principal out, which is what \
			 makes `slot_unreached` false for every slot the state itself created"
		);
	}
	#[test]
	fn a_generated_key_is_not_attacker_controllable() {
		use crate::parser::parse_string;
		let src = "attacker[active]\n\
			principal Bob[\n\
			knows private ctl_secret\n\
			generates ctl_kk\n\
			knows private ctl_n\n\
			ctl_c = AEAD_ENC(ctl_kk, ctl_n, ctl_secret, nil)\n\
			]\n\
			Bob -> Alice: ctl_c\n\
			principal Alice[\n\
			knows private ctl_kk2\n\
			knows private ctl_n\n\
			ctl_m = AEAD_DEC(ctl_kk2, ctl_n, ctl_c, nil)\n\
			]\n\
			queries[\n\
			confidentiality? ctl_secret\n\
			]\n";
		let m = parse_string("ctl.vp", src).expect("parse");
		let (km, states) = crate::sanity::sanity(&m).expect("sanity");
		let attacker = make_attacker_state(vec![]);

		let slot_named = |ps: &PrincipalState, name: &str| -> usize {
			ps.meta
				.iter()
				.position(|m| m.constant.name.as_ref() == name)
				.unwrap_or_else(|| panic!("{name} is a slot"))
		};

		let bob = states.iter().find(|s| s.name == "Bob").expect("Bob");
		let kk = slot_named(bob, "ctl_kk");
		assert!(
			!super::attacker_controllable(kk, &km, bob, &attacker),
			"a value its own principal generated is not on any wire, so no \
			 substitution over it describes a Dolev-Yao transition"
		);
		let alice = states.iter().find(|s| s.name == "Alice").expect("Alice");
		let c = slot_named(alice, "ctl_c");
		assert!(super::attacker_controllable(c, &km, alice, &attacker));
	}

	#[test]
	fn a_relay_is_controllable_only_when_its_own_delivery_phase_is_reached() {
		use crate::parser::parse_string;
		let src = "attacker[active]\nprincipal Alice[\nknows private rp_m\n]\nAlice -> Bob: [rp_m]\nphase[1]\nprincipal Bob[\n_ = HASH(rp_m)\n]\nBob -> Charlie: rp_m\nprincipal Charlie[\n_ = HASH(rp_m)\n]\nqueries[\nauthentication? Bob -> Charlie: rp_m\n]\n";
		let m = parse_string("relay-phase.vp", src).expect("parse");
		let (km, states) = crate::sanity::sanity(&m).expect("sanity");
		let charlie = states
			.iter()
			.find(|state| state.name == "Charlie")
			.expect("Charlie");
		let slot = charlie
			.meta
			.iter()
			.position(|meta| meta.constant.name.as_ref() == "rp_m")
			.expect("rp_m");
		let mut attacker = make_attacker_state(Vec::new());
		assert!(!super::attacker_controllable(slot, &km, charlie, &attacker));
		attacker.current_phase = 1;
		assert!(super::attacker_controllable(slot, &km, charlie, &attacker));
	}

	#[test]
	fn an_install_that_names_its_own_slot_is_refused() {
		use crate::parser::parse_string;
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private cyc_m\n\
			generates cyc_k\n\
			cyc_e = ENC(cyc_k, cyc_m)\n\
			]\n\
			Alice -> Bob: cyc_e\n\
			principal Bob[\n\
			knows private cyc_k2\n\
			cyc_d = DEC(cyc_k2, cyc_e)\n\
			]\n\
			queries[\n\
			confidentiality? cyc_m\n\
			]\n";
		let m = parse_string("cyc.vp", src).expect("parse");
		let (km, states) = crate::sanity::sanity(&m).expect("sanity");
		let bob = states.iter().find(|s| s.name == "Bob").expect("Bob");
		let slot = bob
			.meta
			.iter()
			.position(|m| m.constant.name.as_ref() == "cyc_e")
			.expect("cyc_e is a slot");
		let attacker = make_attacker_state(vec![]);

		// A term naming the very slot it is installed into. Honest states never
		// contain one, and a state that does denotes only its own unfolding.
		let self_naming = crate::testutil::make_primitive(
			crate::primitive::PRIM_HASH,
			vec![crate::types::Value::Constant(
				bob.meta[slot].constant.clone(),
			)],
			0,
		);
		assert!(
			super::reexecute(bob, &[(SlotIdx(slot), self_naming)], &attacker, &km,).is_err(),
			"a cyclic install must be refused, not analysed"
		);

		// The same install with a closed term goes through.
		let closed = crate::testutil::make_primitive(
			crate::primitive::PRIM_HASH,
			vec![crate::value::value_nil()],
			0,
		);
		assert!(super::reexecute(bob, &[(SlotIdx(slot), closed)], &attacker, &km).is_ok());
	}

	#[test]
	fn reexecute_installs_with_attacker_provenance() {
		use crate::reexec::reexecute;
		let a = make_constant("rex_a");
		let b = make_constant("rex_b");
		let ca = a.as_constant().expect("constant").clone();
		let cb = b.as_constant().expect("constant").clone();
		let meta = vec![make_slot_meta(&ca, true), make_slot_meta(&cb, false)];
		let values = vec![make_slot_values(&a, 0), make_slot_values(&b, 1)];
		let ps = make_principal_state("Alice", 0, meta, values);
		let attacker = make_attacker_state(vec![]);

		let km = make_trace();
		let out = reexecute(&ps, &[(SlotIdx(1), a.clone())], &attacker, &km).expect("reexecute");

		assert!(out.values[1].value.equivalent(&a, true));
		assert!(out.values[1].provenance.attacker_tainted);
		assert_eq!(
			out.values[1].provenance.sender,
			crate::principal::ATTACKER_ID
		);
		assert!(out.values[1].original.equivalent(&b, true));
		assert!(!out.values[0].provenance.attacker_tainted);
	}

	#[test]
	fn reexecute_does_not_attribute_a_relayed_value_to_the_attacker() {
		use crate::reexec::reexecute;
		let a = make_constant("relay_a");
		let b = make_constant("relay_b");
		let ca = a.as_constant().expect("constant").clone();
		let cb = b.as_constant().expect("constant").clone();
		let meta = vec![make_slot_meta(&ca, true), make_slot_meta(&cb, false)];
		let values = vec![make_slot_values(&a, 0), make_slot_values(&b, 1)];
		let ps = make_principal_state("Alice", 0, meta, values);
		let attacker = make_attacker_state(vec![]);
		let km = make_trace();

		let out = reexecute(&ps, &[(SlotIdx(1), b.clone())], &attacker, &km).expect("reexecute");

		assert!(out.values[1].value.equivalent(&b, true));
		assert!(out.values[1].provenance.attacker_tainted);
		assert_ne!(
			out.values[1].provenance.sender,
			crate::principal::ATTACKER_ID,
			"a forwarded value must not be attributed to the attacker"
		);
	}
}
