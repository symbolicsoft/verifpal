/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
	lock.read().unwrap_or_else(|e| e.into_inner())
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
	lock.write().unwrap_or_else(|e| e.into_inner())
}

thread_local! {
	static ANALYSIS_COUNT: Cell<u32> = const { Cell::new(0) };
}

pub(crate) fn analysis_count_get() -> usize {
	ANALYSIS_COUNT.with(|c| c.get()) as usize
}

fn analysis_count_reset() {
	ANALYSIS_COUNT.with(|c| c.set(0));
}

use crate::types::*;
use crate::util::*;
use crate::value::compute_slot_diffs;

type Replay = (
	u64,
	crate::reexec::Seeds,
	i32,
	usize,
	Option<Arc<Vec<PrincipalState>>>,
);

type DeferredReplay = (PrincipalId, Vec<(ValueId, Value)>);

pub(crate) struct VerifyContext {
	attacker: RwLock<AttackerState>,
	deferred_replays: RwLock<Vec<DeferredReplay>>,
	results: RwLock<Vec<VerifyResult>>,
	unresolved: AtomicI32,
	file_name: String,
	states: Vec<PrincipalState>,
	phase_knowledge: RwLock<Vec<AttackerState>>,
	depth_cuts: RwLock<IdSet<(PrincipalId, usize)>>,
	truncations: RwLock<Vec<(Truncation, Vec<usize>)>>,
	sessions: u8,
	honest: Option<IdMap<PrincipalId, i32>>,
	honest_halts: RwLock<Vec<(PrincipalId, usize)>>,
	scenarios: Vec<ScenarioSummary>,
	#[cfg(test)]
	witnesses: RwLock<Vec<Option<ResultWitness>>>,
	#[cfg(test)]
	query_goals: RwLock<Vec<usize>>,
	#[cfg(test)]
	searched: AtomicBool,
	origin_only: RwLock<IdSet<usize>>,
	replays: RwLock<Vec<Replay>>,
	basis: RwLock<(i32, usize, IdSet<u64>)>,
	prefer_replication: AtomicBool,
	replication_only: AtomicBool,
	replication_rejected: AtomicBool,
	cancel: Arc<AtomicBool>,
}

fn seeds_signature(seeds: &[(PrincipalId, Vec<(SlotIdx, Value)>)]) -> u64 {
	let mut hash = 0xcbf2_9ce4_8422_2325u64;
	let mut mix = |word: u64| {
		hash ^= word;
		hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
	};
	for (principal, diffs) in seeds {
		mix(u64::from(*principal));
		for (slot, value) in diffs {
			mix(slot.get() as u64);
			mix(value.hash_value());
		}
	}
	hash
}

fn same_seeds(
	a: &[(PrincipalId, Vec<(SlotIdx, Value)>)],
	b: &[(PrincipalId, Vec<(SlotIdx, Value)>)],
) -> bool {
	a.len() == b.len()
		&& a.iter()
			.zip(b.iter())
			.all(|((pa, da), (pb, db))| pa == pb && crate::reexec::same_installs(da, db))
}

fn derivation_provenance(
	state: &AttackerState,
	ambient: &Arc<MutationRecord>,
	derivation: &DerivationRecord,
) -> Arc<MutationRecord> {
	let ingredients = derivation.ingredients();
	if ingredients.is_empty() && !derivation.reads_from_state() {
		return Arc::new(MutationRecord {
			diffs: vec![],
			principal_id: ambient.principal_id,
			phase: ambient.phase,
		});
	}

	let mut diffs: Vec<SlotDiff> = Vec::new();
	let mut principal_id = ambient.principal_id;
	let mut phase = ambient.phase;
	let mut adopted = false;

	let rebuilt_in_place = ingredients
		.iter()
		.any(|ingredient| state.knows(ingredient).is_none());

	if derivation.reads_from_state() || rebuilt_in_place {
		diffs.extend(ambient.diffs.iter().cloned());
		adopted = true;
	}
	for ingredient in ingredients {
		let Some(idx) = state.knows(ingredient) else {
			continue;
		};
		let Some(inherited) = state.record(idx) else {
			continue;
		};
		if !adopted && !inherited.diffs.is_empty() {
			principal_id = inherited.principal_id;
			phase = inherited.phase;
			adopted = true;
		}
		for diff in &inherited.diffs {
			if !diffs
				.iter()
				.any(|d| d.index == diff.index && d.state == diff.state)
			{
				diffs.push(diff.clone());
			}
		}
	}
	diffs.sort_by_key(|d| d.index);
	Arc::new(MutationRecord {
		diffs,
		principal_id,
		phase,
	})
}

fn attacker_state_note_route(
	state: &mut AttackerState,
	value: &Value,
	record: &Arc<MutationRecord>,
	derivation: DerivationRecord,
) {
	if !derivation.reads_from_state() {
		return;
	}
	let Some(existing) = state.knows(value) else {
		return;
	};
	if state
		.routes(existing)
		.any(|(route, _)| route.same_route(&derivation))
	{
		return;
	}
	let candidate = derivation_provenance(state, record, &derivation);
	if let Some(entry) = Arc::make_mut(&mut state.alternates).get_mut(existing.get()) {
		entry.push((derivation, candidate));
	}
}

fn attacker_state_absorb(
	state: &mut AttackerState,
	value: &Value,
	record: &Arc<MutationRecord>,
	derivation: DerivationRecord,
) {
	if let Some(existing) = state.knows(value) {
		let candidate = derivation_provenance(state, record, &derivation);
		let explains = |r: &MutationRecord| r.diffs.iter().any(|d| d.tainted);
		let stale = state.record(existing).is_some_and(|r| !explains(r));
		let names_assumption = |d: &DerivationRecord| matches!(d, DerivationRecord::Broken { .. });
		let unnamed = state
			.derivation(existing)
			.is_some_and(|d| !names_assumption(d));
		let known_route = !derivation.reads_from_state()
			|| state
				.routes(existing)
				.any(|(route, _)| route.same_route(&derivation));
		if (stale && explains(&candidate)) || (names_assumption(&derivation) && unnamed) {
			let displaced = state
				.derivation(existing)
				.cloned()
				.zip(state.record(existing).cloned());
			Arc::make_mut(&mut state.mutation_records)[existing.get()] = candidate;
			Arc::make_mut(&mut state.derivations)[existing.get()] = derivation;
			if let Some((displaced, prior)) = displaced {
				let alternates = Arc::make_mut(&mut state.alternates);
				if let Some(entry) = alternates.get_mut(existing.get())
					&& !entry.iter().any(|(route, _)| route.same_route(&displaced))
				{
					entry.push((displaced, prior));
				}
			}
		} else if !known_route {
			let alternates = Arc::make_mut(&mut state.alternates);
			if let Some(entry) = alternates.get_mut(existing.get()) {
				entry.push((derivation, candidate));
			}
		}
		return;
	}
	let record = &derivation_provenance(state, record, &derivation);
	let idx = state.known.len();
	Arc::make_mut(&mut state.known).push(value.clone());
	let h = value.hash_value();
	Arc::make_mut(&mut state.known_map)
		.entry(h)
		.or_default()
		.push(idx);
	Arc::make_mut(&mut state.mutation_records).push(Arc::clone(record));
	Arc::make_mut(&mut state.derivations).push(derivation);
	Arc::make_mut(&mut state.alternates).push(Vec::new());
}

impl VerifyContext {
	pub(crate) fn new(
		m: &Model,
		states: &[PrincipalState],
		variants: Vec<Vec<Query>>,
		sessions: u8,
		honest: Option<IdMap<PrincipalId, i32>>,
		scenarios: Vec<ScenarioSummary>,
	) -> Self {
		let results: Vec<VerifyResult> = m
			.queries
			.iter()
			.enumerate()
			.map(|(i, q)| {
				let mut r = VerifyResult::new(q, i);
				r.variants = variants.get(i).cloned().unwrap_or_default();
				r
			})
			.collect();
		let unresolved = results.len() as i32;
		analysis_count_reset();
		VerifyContext {
			replays: RwLock::new(Vec::new()),
			basis: RwLock::new((-1, 0, IdSet::default())),
			origin_only: RwLock::new(IdSet::default()),
			attacker: RwLock::new(AttackerState::new()),
			deferred_replays: RwLock::new(Vec::new()),
			results: RwLock::new(results),
			unresolved: AtomicI32::new(unresolved),
			file_name: m.file_name.clone(),
			states: states.to_vec(),
			phase_knowledge: RwLock::new(vec![]),
			depth_cuts: RwLock::new(IdSet::default()),
			truncations: RwLock::new(Vec::new()),
			sessions,
			honest,
			honest_halts: RwLock::new(Vec::new()),
			scenarios,
			#[cfg(test)]
			witnesses: RwLock::new(vec![None; unresolved as usize]),
			#[cfg(test)]
			query_goals: RwLock::new(vec![0; unresolved as usize]),
			#[cfg(test)]
			searched: AtomicBool::new(false),
			prefer_replication: AtomicBool::new(false),
			replication_only: AtomicBool::new(false),
			replication_rejected: AtomicBool::new(false),
			cancel: Arc::new(AtomicBool::new(false)),
		}
	}

	pub(crate) fn set_cancel(&mut self, cancel: Arc<AtomicBool>) {
		self.cancel = cancel;
	}

	pub(crate) fn cancelled(&self) -> bool {
		self.cancel.load(Ordering::Relaxed)
	}

	pub(crate) fn prefer_replication_valid_witnesses(&self) {
		self.prefer_replication.store(true, Ordering::SeqCst);
	}

	pub(crate) fn prefers_replication(&self) -> bool {
		self.prefer_replication.load(Ordering::SeqCst)
	}

	pub(crate) fn set_replication_only(&self, on: bool) {
		self.replication_only.store(on, Ordering::SeqCst);
	}

	pub(crate) fn replication_only(&self) -> bool {
		self.replication_only.load(Ordering::SeqCst)
	}

	pub(crate) fn note_replication_rejection(&self) {
		self.replication_rejected.store(true, Ordering::SeqCst);
	}

	pub(crate) fn replication_rejected(&self) -> bool {
		self.replication_rejected.load(Ordering::SeqCst)
	}

	pub(crate) fn note_depth_cut(&self, principal: PrincipalId, slot: usize) -> bool {
		let first = write_lock(&self.depth_cuts).insert((principal, slot));
		if first {
			self.note_truncation(Truncation::TermDepth);
		}
		first
	}

	pub(crate) fn note_truncation(&self, kind: Truncation) {
		let outstanding: Vec<usize> = read_lock(&self.results)
			.iter()
			.filter(|result| !result.resolved)
			.map(|result| result.query_index)
			.collect();
		let mut state = write_lock(&self.truncations);
		match state.iter_mut().find(|(seen, _)| *seen == kind) {
			Some((_, reached)) => {
				for index in outstanding {
					if !reached.contains(&index) {
						reached.push(index);
					}
				}
				reached.sort_unstable();
			}
			None => state.push((kind, outstanding)),
		}
		state.sort_by_key(|(kind, _)| *kind);
	}

	pub(crate) fn is_honest(&self, principal: PrincipalId) -> bool {
		self.is_honest_at(principal, read_lock(&self.attacker).current_phase)
	}

	fn is_honest_at(&self, principal: PrincipalId, phase: i32) -> bool {
		match &self.honest {
			None => true,
			Some(honest) => honest
				.get(&principal)
				.is_some_and(|&corrupt_from| phase < corrupt_from),
		}
	}

	fn nothing_is_honest_at(&self, phase: i32) -> bool {
		match &self.honest {
			None => false,
			Some(honest) => honest.values().all(|&corrupt_from| phase >= corrupt_from),
		}
	}

	pub(crate) fn record_honest_halts(&self, halts: Vec<(PrincipalId, usize)>) {
		*write_lock(&self.honest_halts) = halts;
	}

	pub(crate) fn honest_run_disclosure(
		&self,
		km: &ProtocolTrace,
		slot: usize,
		phase: i32,
	) -> Option<Disclosure> {
		let halts = read_lock(&self.honest_halts);
		km.disclosure(slot, phase, |principal, declared_at| {
			halts
				.iter()
				.find(|&&(halted, _)| halted == principal)
				.and_then(|&(_, at)| km.slots.get(at))
				.is_none_or(|meta| declared_at <= meta.declared_at)
		})
	}

	pub(crate) fn claims_apply_to(&self, principal: PrincipalId) -> bool {
		let phase = read_lock(&self.attacker).current_phase;
		self.nothing_is_honest_at(phase) || self.is_honest_at(principal, phase)
	}

	pub(crate) fn relativises(&self) -> bool {
		let phase = read_lock(&self.attacker).current_phase;
		self.honest.is_some() && !self.nothing_is_honest_at(phase)
	}

	pub(crate) fn scenarios(&self) -> &[ScenarioSummary] {
		&self.scenarios
	}

	#[cfg(test)]
	pub(crate) fn truncations(&self) -> Vec<Truncation> {
		read_lock(&self.truncations)
			.iter()
			.map(|(kind, _)| *kind)
			.collect()
	}

	fn truncations_for(&self, query_index: usize) -> Vec<Truncation> {
		read_lock(&self.truncations)
			.iter()
			.filter(|(_, reached)| reached.contains(&query_index))
			.map(|(kind, _)| *kind)
			.collect()
	}

	pub(crate) fn finalize_envelopes(&self) {
		let scoped: Vec<(usize, Vec<Truncation>)> = read_lock(&self.results)
			.iter()
			.map(|vr| (vr.query_index, self.truncations_for(vr.query_index)))
			.collect();
		for (vr, (_, truncations)) in write_lock(&self.results).iter_mut().zip(scoped) {
			vr.envelope = Envelope {
				sessions: self.sessions,
				truncations,
			};
		}
	}

	pub(crate) fn note_origin_only(&self, query_index: usize) -> bool {
		write_lock(&self.origin_only).insert(query_index)
	}

	/// The execution a substitution set describes, replayed once and shared by
	/// every combination the closure then tests against it.
	///
	/// Keyed on what the attacker knows as well as on the substitution and the
	/// phase: the replay runs `try_guard_bypass`, which reads knowledge, and
	/// knowledge grows through the closure's fixed point, so a replay computed
	/// early would otherwise answer for a later state that gets further.
	pub(crate) fn replayed(
		&self,
		km: &ProtocolTrace,
		seeds: &[(PrincipalId, Vec<(SlotIdx, Value)>)],
		attacker: &AttackerState,
	) -> Option<Arc<Vec<PrincipalState>>> {
		let key = seeds_signature(seeds);
		let phase = attacker.current_phase;
		let known = attacker.known.len();
		if let Some((_, _, _, _, hit)) =
			read_lock(&self.replays)
				.iter()
				.find(|(seen, of, at, held, _)| {
					*seen == key && *at == phase && *held == known && same_seeds(of, seeds)
				}) {
			return hit.clone();
		}
		let built = crate::reexec::replay_diffs(self, km, seeds, attacker).map(Arc::new);
		write_lock(&self.replays).push((key, seeds.to_vec(), phase, known, built.clone()));
		built
	}

	pub(crate) fn known_subterms(&self, attacker: &AttackerState) -> IdSet<u64> {
		let mut basis = write_lock(&self.basis);
		let (phase, covered, set) = &mut *basis;
		if *phase != attacker.current_phase || *covered > attacker.known.len() {
			*phase = attacker.current_phase;
			*covered = 0;
			set.clear();
		}
		for known in &attacker.known[*covered..] {
			crate::hashing::collect_subterm_hashes(known, set);
		}
		*covered = attacker.known.len();
		set.clone()
	}

	pub(crate) fn principal_states(&self) -> &[PrincipalState] {
		&self.states
	}

	pub(crate) fn capability_assumptions(&self) -> Vec<(Value, Capability, i32)> {
		self.states
			.first()
			.map(|ps| ps.capabilities.assumptions())
			.unwrap_or_default()
	}

	pub(crate) fn capability_assumption_terms(&self) -> Vec<Value> {
		self.states
			.first()
			.map(|ps| ps.capabilities.assumption_terms())
			.unwrap_or_default()
	}

	pub(crate) fn attacker_phase_archive(&self, phase: i32) {
		let snapshot = self.attacker_snapshot();
		let idx = phase.max(0) as usize;
		let mut archive = write_lock(&self.phase_knowledge);
		if archive.len() <= idx {
			archive.resize_with(idx + 1, AttackerState::new);
		}
		archive[idx] = snapshot;
	}

	pub(crate) fn attacker_knowledge_at(&self, phase: i32) -> Option<AttackerState> {
		read_lock(&self.phase_knowledge)
			.get(phase.max(0) as usize)
			.cloned()
	}

	pub(crate) fn attacker_init(&self) {
		let mut state = write_lock(&self.attacker);
		*state = AttackerState::new();
	}

	pub(crate) fn attacker_snapshot(&self) -> AttackerState {
		read_lock(&self.attacker).clone()
	}

	pub(crate) fn defer_replays(
		&self,
		principal: PrincipalId,
		replays: Vec<Vec<(ValueId, Value)>>,
	) {
		let mut deferred = write_lock(&self.deferred_replays);
		deferred.retain(|(who, _)| *who != principal);
		deferred.extend(replays.into_iter().map(|bindings| (principal, bindings)));
	}

	pub(crate) fn take_deferred_replays(
		&self,
		principal: PrincipalId,
	) -> Vec<Vec<(ValueId, Value)>> {
		let mut deferred = write_lock(&self.deferred_replays);
		let (mine, rest): (Vec<_>, Vec<_>) =
			deferred.drain(..).partition(|(who, _)| *who == principal);
		*deferred = rest;
		mine.into_iter().map(|(_, bindings)| bindings).collect()
	}

	pub(crate) fn attacker_note_reuse(&self, pair: [Value; 2]) {
		let mut state = write_lock(&self.attacker);
		let seen = state.reused.iter().any(|held| {
			(held[0].equivalent(&pair[0], true) && held[1].equivalent(&pair[1], true))
				|| (held[0].equivalent(&pair[1], true) && held[1].equivalent(&pair[0], true))
		});
		if !seen {
			Arc::make_mut(&mut state.reused).push(pair);
		}
	}

	pub(crate) fn attacker_knows(&self, value: &Value) -> bool {
		read_lock(&self.attacker).knows(value).is_some()
	}

	pub(crate) fn attacker_known_count(&self) -> usize {
		read_lock(&self.attacker).known.len()
	}

	pub(crate) fn attacker_put_with(
		&self,
		known: &Value,
		record: &Arc<MutationRecord>,
		derivation: DerivationRecord,
	) -> bool {
		let mut state = write_lock(&self.attacker);
		if state.knows(known).is_some() {
			attacker_state_note_route(&mut state, known, record, derivation);
			return false;
		}
		attacker_state_absorb(&mut state, known, record, derivation);
		true
	}

	pub(crate) fn attacker_phase_update(
		&self,
		km: &ProtocolTrace,
		ps: &PrincipalState,
		phase: i32,
	) -> VResult<()> {
		let record = compute_slot_diffs(ps, km, phase);
		let mut state = write_lock(&self.attacker);
		state.current_phase = phase;

		for (sm, sv) in ps.meta.iter().zip(ps.values.iter()) {
			if sm.constant.qualifier != Some(Qualifier::Public) {
				continue;
			}
			if let Ok(earliest) = min_int_in_slice(&sm.phase)
				&& earliest > phase
			{
				continue;
			}
			attacker_state_absorb(&mut state, &sv.value, &record, DerivationRecord::Initial);
		}

		drop(state);
		self.absorb_wire_values(ps, &record, phase, |slot, _| {
			self.honest_run_disclosure(km, slot, phase)
		})
	}

	pub(crate) fn attacker_absorb_disclosed(
		&self,
		km: &ProtocolTrace,
		ps: &PrincipalState,
		record: &Arc<MutationRecord>,
		phase: i32,
	) {
		let halts = read_lock(&self.honest_halts).clone();
		if halts.is_empty() {
			return;
		}
		let _ = self.absorb_wire_values(ps, record, phase, |slot, sv| {
			if sv.provenance.creator != ps.id
				|| !halts
					.iter()
					.any(|&(principal, at)| principal == ps.id && slot >= at)
			{
				return None;
			}
			km.disclosure(slot, phase, |principal, declared_at| {
				ps.event_reached(km, principal, declared_at)
			})
		});
	}

	fn absorb_wire_values(
		&self,
		ps: &PrincipalState,
		record: &Arc<MutationRecord>,
		phase: i32,
		admit: impl Fn(usize, &SlotValues) -> Option<Disclosure>,
	) -> VResult<()> {
		let mut state = write_lock(&self.attacker);
		for (slot, (sm, sv)) in ps.meta.iter().zip(ps.values.iter()).enumerate() {
			if sm.wire.is_empty() && !sm.constant.leaked {
				continue;
			}
			if sm.constant.qualifier == Some(Qualifier::Public) {
				continue;
			}
			let earliest = min_int_in_slice(&sm.phase)?;
			if earliest > phase {
				continue;
			}
			let Some(disclosure) = admit(slot, sv) else {
				continue;
			};
			let derivation = match disclosure {
				Disclosure::Message => DerivationRecord::Obtained {
					slot: SlotIdx(slot),
				},
				Disclosure::Leak => DerivationRecord::Leaked {
					slot: SlotIdx(slot),
				},
			};
			let constant_value = Value::Constant(sm.constant.clone());
			attacker_state_absorb(&mut state, &constant_value, record, derivation.clone());
			attacker_state_absorb(&mut state, &sv.value, record, derivation);
		}
		Ok(())
	}

	pub(crate) fn results_get(&self) -> Vec<VerifyResult> {
		read_lock(&self.results).clone()
	}

	#[cfg(test)]
	pub(crate) fn witness_put(&self, query_index: usize, witness: ResultWitness) {
		let mut state = write_lock(&self.witnesses);
		if let Some(slot) = state.get_mut(query_index)
			&& slot.is_none()
		{
			*slot = Some(witness);
		}
	}

	#[cfg(test)]
	pub(crate) fn goals_noted(&self, query_index: usize, count: usize) {
		let mut state = write_lock(&self.query_goals);
		if let Some(slot) = state.get_mut(query_index) {
			*slot += count;
		}
	}

	#[cfg(test)]
	pub(crate) fn goals_for(&self, query_index: usize) -> usize {
		read_lock(&self.query_goals)
			.get(query_index)
			.copied()
			.unwrap_or(0)
	}

	#[cfg(test)]
	pub(crate) fn note_search_reached_a_controllable_slot(&self) {
		self.searched.store(true, Ordering::SeqCst);
	}

	#[cfg(test)]
	pub(crate) fn search_reached_a_controllable_slot(&self) -> bool {
		self.searched.load(Ordering::SeqCst)
	}

	#[cfg(test)]
	pub(crate) fn witness_get(&self, query_index: usize) -> Option<ResultWitness> {
		read_lock(&self.witnesses)
			.get(query_index)
			.cloned()
			.flatten()
	}

	pub(crate) fn results_file_name(&self) -> &str {
		&self.file_name
	}

	pub(crate) fn results_put(
		&self,
		result: &VerifyResult,
		_verdict: &crate::query::QueryVerdict,
	) -> bool {
		let mut state = write_lock(&self.results);
		if let Some(vr) = state.get_mut(result.query_index)
			&& !vr.resolved
		{
			vr.resolved = result.resolved;
			vr.summary = result.summary.clone();
			vr.conclusion = result.conclusion.clone();
			vr.subtype = result.subtype;
			vr.trace = result.trace.clone();
			vr.notes = result.notes.clone();
			vr.steps = result.steps.clone();
			vr.options = result.options.clone();
			if result.resolved {
				self.unresolved.fetch_sub(1, Ordering::SeqCst);
			}
			return true;
		}
		false
	}

	pub(crate) fn query_counts(&self) -> (usize, usize) {
		let total = read_lock(&self.results).len();
		let remaining = self.unresolved.load(Ordering::SeqCst).max(0) as usize;
		(total.saturating_sub(remaining), total)
	}

	pub(crate) fn all_resolved(&self) -> bool {
		self.unresolved.load(Ordering::SeqCst) <= 0
	}

	pub(crate) fn query_is_resolved(&self, query_index: usize) -> bool {
		read_lock(&self.results)
			.get(query_index)
			.is_some_and(|r| r.resolved)
	}

	#[cfg(test)]
	pub(crate) fn scratch_for_query(&self, query_index: usize) -> VerifyContext {
		self.scratch(query_index, self.honest.clone())
	}

	pub(crate) fn scratch_for_witness(&self, query_index: usize) -> VerifyContext {
		self.scratch(query_index, None)
	}

	fn scratch(
		&self,
		query_index: usize,
		honest: Option<IdMap<PrincipalId, i32>>,
	) -> VerifyContext {
		let mut results = self.results_get();
		for (i, r) in results.iter_mut().enumerate() {
			if i == query_index {
				r.resolved = false;
				r.summary = String::new();
				r.options = vec![];
			} else {
				r.resolved = true;
			}
		}
		let unresolved = i32::from(query_index < results.len());
		#[cfg(test)]
		let results_len = results.len();
		VerifyContext {
			attacker: RwLock::new(self.attacker_snapshot()),
			deferred_replays: RwLock::new(Vec::new()),
			results: RwLock::new(results),
			unresolved: AtomicI32::new(unresolved),
			file_name: self.file_name.clone(),
			states: self.states.clone(),
			phase_knowledge: RwLock::new(read_lock(&self.phase_knowledge).clone()),
			depth_cuts: RwLock::new(read_lock(&self.depth_cuts).clone()),
			truncations: RwLock::new(read_lock(&self.truncations).clone()),
			origin_only: RwLock::new(IdSet::default()),
			replays: RwLock::new(Vec::new()),
			basis: RwLock::new((-1, 0, IdSet::default())),
			sessions: self.sessions,
			honest,
			honest_halts: RwLock::new(read_lock(&self.honest_halts).clone()),
			scenarios: self.scenarios.clone(),
			#[cfg(test)]
			witnesses: RwLock::new(vec![None; results_len]),
			#[cfg(test)]
			query_goals: RwLock::new(vec![0; results_len]),
			#[cfg(test)]
			searched: AtomicBool::new(false),
			prefer_replication: AtomicBool::new(false),
			replication_only: AtomicBool::new(false),
			replication_rejected: AtomicBool::new(false),
			cancel: Arc::clone(&self.cancel),
		}
	}

	pub(crate) fn analysis_count_increment(&self) {
		if !crate::info::info_is_quiet() {
			ANALYSIS_COUNT.with(|c| c.set(c.get() + 1));
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::parser::parse_string;
	use crate::testutil::*;
	use std::sync::Arc;

	#[test]
	fn a_cancelled_analysis_returns_an_error_and_no_results() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private cx_a\n\
			cx_ga = PUBKEY(cx_a)\n\
			]\n\
			Alice -> Bob: cx_ga\n\
			principal Bob[\n\
			knows private cx_b\n\
			cx_gb = PUBKEY(cx_b)\n\
			cx_k = DH_KEX(cx_ga, cx_b)\n\
			generates cx_m, cx_n\n\
			cx_e = AEAD_ENC(cx_k, cx_n, cx_m, nil)\n\
			]\n\
			Bob -> Alice: cx_gb, cx_n, cx_e\n\
			queries[\n\
			confidentiality? cx_m\n\
			]\n";
		let m = parse_string("cx.vp", src).expect("parses");

		let cancel = Arc::new(AtomicBool::new(true));
		let outcome = crate::verify::analyze_sessions_cancellable(&m, 1, cancel);

		let err = outcome.err().expect("a cancelled analysis is an error");
		assert_eq!(err.kind, ErrorKind::Cancelled);
	}

	#[test]
	fn an_uncancelled_analysis_still_succeeds() {
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private cy_m\n\
			cy_h = HASH(cy_m)\n\
			]\n\
			Alice -> Bob: cy_h\n\
			principal Bob[\n\
			_ = HASH(cy_h)\n\
			]\n\
			queries[\n\
			confidentiality? cy_m\n\
			]\n";
		let m = parse_string("cy.vp", src).expect("parses");
		let cancel = Arc::new(AtomicBool::new(false));
		let ctx = crate::verify::analyze_sessions_cancellable(&m, 1, cancel)
			.expect("an uncancelled analysis succeeds");
		assert_eq!(ctx.results_get().len(), 1);
	}

	#[test]
	fn cancelling_mid_run_yields_no_verdicts_at_all() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private cz_a\n\
			cz_ga = PUBKEY(cz_a)\n\
			]\n\
			Alice -> Bob: cz_ga\n\
			principal Bob[\n\
			knows private cz_b\n\
			cz_gb = PUBKEY(cz_b)\n\
			cz_k = DH_KEX(cz_ga, cz_b)\n\
			generates cz_m, cz_n\n\
			cz_e = AEAD_ENC(cz_k, cz_n, cz_m, nil)\n\
			]\n\
			Bob -> Alice: cz_gb, cz_n, cz_e\n\
			principal Alice[\n\
			cz_k2 = DH_KEX(cz_gb, cz_a)\n\
			cz_d = AEAD_DEC(cz_k2, cz_n, cz_e, nil)\n\
			]\n\
			queries[\n\
			confidentiality? cz_m\n\
			authentication? Bob -> Alice: cz_e\n\
			]\n";
		let cancel = Arc::new(AtomicBool::new(false));
		let flag = Arc::clone(&cancel);

		let worker = std::thread::spawn(move || {
			let m = parse_string("cz.vp", src).expect("parses");
			crate::verify::analyze_sessions_cancellable(&m, 1, cancel).map(|ctx| ctx.results_get())
		});
		flag.store(true, Ordering::Relaxed);

		match worker.join().expect("the worker did not panic") {
			Ok(results) => assert_eq!(results.len(), 2),
			Err(e) => assert_eq!(e.kind, ErrorKind::Cancelled),
		}
	}

	#[test]
	fn scratch_context_isolates_single_query() {
		use crate::context::VerifyContext;
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private scr_m\n\
			knows private scr_k\n\
			scr_e = ENC(scr_k, scr_m)\n\
			]\n\
			queries[\n\
			confidentiality? scr_m\n\
			confidentiality? scr_k\n\
			]\n";
		let m = parse_string("scratch.vp", src).expect("parse");
		let ctx = VerifyContext::new(&m, &[], Vec::new(), 2, None, Vec::new());
		let scratch = ctx.scratch_for_query(1);

		assert!(!scratch.query_is_resolved(1));
		assert!(scratch.query_is_resolved(0));
		assert!(!scratch.all_resolved());

		let mut r = VerifyResult::new(&m.queries[1], 1);
		r.resolved = true;
		r.summary = " probe".to_string();
		assert!(scratch.results_put(&r, &crate::query::QueryVerdict::for_test()));
		assert!(scratch.query_is_resolved(1));
		assert!(scratch.all_resolved());

		assert!(!ctx.query_is_resolved(1));
		assert!(!ctx.all_resolved());
		assert_eq!(ctx.results_get()[1].summary, "");
	}

	#[test]
	fn attacker_put_with_records_derivation() {
		use crate::context::VerifyContext;
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private drv_m\n\
			knows private drv_k\n\
			drv_e = ENC(drv_k, drv_m)\n\
			]\n\
			queries[\n\
			confidentiality? drv_m\n\
			]\n";
		let m = parse_string("drv.vp", src).expect("parse");
		let ctx = VerifyContext::new(&m, &[], Vec::new(), 2, None, Vec::new());
		let record = Arc::new(MutationRecord {
			diffs: vec![],
			principal_id: 0,
			phase: 0,
		});
		let learned = make_constant("drv_learned");
		let source = make_constant("drv_source");

		assert!(ctx.attacker_put_with(
			&learned,
			&record,
			DerivationRecord::Decomposed {
				of: source.clone(),
				using: vec![learned.clone()],
			},
		));

		let attacker = ctx.attacker_snapshot();
		let idx = attacker.knows(&learned).expect("value was absorbed");
		match attacker.derivation(idx) {
			Some(DerivationRecord::Decomposed { of, using }) => {
				assert!(of.equivalent(&source, true));
				assert_eq!(using.len(), 1);
			}
			other => panic!("expected Decomposed, got {:?}", other),
		}
		assert_eq!(attacker.known.len(), attacker.derivations.len());
	}

	#[test]
	fn a_later_leak_does_not_explain_an_earlier_wire_observation() {
		let src = "attacker[passive]\nprincipal Alice[\nknows private cl_m\n]\nprincipal Bob[\n_ = HASH(nil)\n]\nAlice -> Bob: cl_m\nphase[1]\nprincipal Alice[\nleaks cl_m\n]\nqueries[\nconfidentiality? cl_m\n]\n";
		let m = parse_string("leak-origin.vp", src).expect("parses");
		let (km, states) = crate::sanity::sanity(&m).expect("passes sanity");
		let ctx = VerifyContext::new(&m, &states, Vec::new(), 1, None, Vec::new());
		let mut pure = states[0].clone_for_depth(true);
		pure.resolve_all_values().expect("resolves");
		ctx.attacker_phase_update(&km, &pure, 0)
			.expect("seeds phase zero");
		let constant = km
			.slots
			.iter()
			.find(|slot| slot.constant.name.as_ref() == "cl_m")
			.map(|slot| Value::Constant(slot.constant.clone()))
			.expect("cl_m exists");
		let attacker = ctx.attacker_snapshot();
		let index = attacker.knows(&constant).expect("attacker observes cl_m");
		assert!(matches!(
			attacker.derivation(index),
			Some(DerivationRecord::Obtained { .. })
		));
	}

	#[test]
	fn a_term_reachable_two_ways_keeps_both_routes() {
		use crate::testutil::make_constant;
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private alt_m\n\
			knows private alt_k\n\
			alt_e = ENC(alt_k, alt_m)\n\
			]\n\
			queries[\n\
			confidentiality? alt_m\n\
			]\n";
		let m = parse_string("alt.vp", src).expect("parse");
		let ctx = VerifyContext::new(&m, &[], Vec::new(), 1, None, Vec::new());
		let value = make_constant("alt_value");
		let record = std::sync::Arc::new(MutationRecord {
			diffs: vec![],
			principal_id: 1,
			phase: 0,
		});
		ctx.attacker_put_with(
			&value,
			&record,
			DerivationRecord::Obtained { slot: SlotIdx(7) },
		);
		ctx.attacker_put_with(
			&value,
			&record,
			DerivationRecord::Obtained { slot: SlotIdx(2) },
		);
		ctx.attacker_put_with(
			&value,
			&record,
			DerivationRecord::Obtained { slot: SlotIdx(7) },
		);
		let attacker = ctx.attacker_snapshot();
		let idx = attacker.knows(&value).expect("the term is known");
		let slots: Vec<usize> = attacker
			.routes(idx)
			.filter_map(|(route, _)| match route {
				DerivationRecord::Obtained { slot } => Some(slot.get()),
				_ => None,
			})
			.collect();
		assert_eq!(
			slots,
			vec![7, 2],
			"a term the attacker can reach at two slots records both, each with the \
			 execution it was found in. The repeat must not be stored twice.\n\n\
			 The filters still follow the first route only, and deliberately. A route is \
			 discovered inside some execution and is a route at all only in executions \
			 like it, so admitting one found elsewhere needs a proof that it is available \
			 here too. Letting any recorded route stand in for that was measured and \
			 returns three false attacks the corpus pins shut: incompatible_histories.vp, \
			 history_incompatible_knowledge.vp and atemporal_forward_value.vp all report \
			 an attack again. Whoever narrows this must produce that proof, not widen \
			 what counts as a route"
		);
	}

	#[test]
	fn a_context_with_no_truncation_reports_an_exhausted_search() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private trc_m\n\
			knows private trc_k\n\
			trc_e = ENC(trc_k, trc_m)\n\
			]\n\
			queries[\n\
			confidentiality? trc_m\n\
			]\n";
		let m = parse_string("trc.vp", src).expect("parse");
		let ctx = VerifyContext::new(&m, &[], Vec::new(), 2, None, Vec::new());
		ctx.finalize_envelopes();
		assert!(ctx.truncations().is_empty());
		assert!(ctx.results_get()[0].envelope.exhausted());
		assert_eq!(ctx.results_get()[0].envelope.sessions, 2);
	}

	#[test]
	fn a_depth_cut_truncates_the_search() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private tdc_m\n\
			knows private tdc_k\n\
			tdc_e = ENC(tdc_k, tdc_m)\n\
			]\n\
			queries[\n\
			confidentiality? tdc_m\n\
			]\n";
		let m = parse_string("tdc.vp", src).expect("parse");
		let ctx = VerifyContext::new(&m, &[], Vec::new(), 2, None, Vec::new());
		ctx.note_depth_cut(1, 0);
		ctx.finalize_envelopes();
		assert_eq!(ctx.truncations(), vec![Truncation::TermDepth]);
		assert!(!ctx.results_get()[0].envelope.exhausted());
	}

	#[test]
	fn a_depth_cut_qualifies_only_the_queries_it_could_still_have_answered() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private tdq_m\n\
			knows private tdq_n\n\
			knows private tdq_k\n\
			tdq_e = ENC(tdq_k, tdq_m)\n\
			tdq_f = ENC(tdq_k, tdq_n)\n\
			leaks tdq_m\n\
			]\n\
			queries[\n\
			confidentiality? tdq_m\n\
			confidentiality? tdq_n\n\
			]\n";
		let m = parse_string("tdq.vp", src).expect("parse");
		let ctx = VerifyContext::new(&m, &[], Vec::new(), 2, None, Vec::new());
		let mut resolved = crate::types::VerifyResult::new(&m.queries[0], 0);
		resolved.resolved = true;
		assert!(ctx.results_put(&resolved, &crate::query::QueryVerdict::for_test()));
		ctx.note_depth_cut(1, 0);
		ctx.finalize_envelopes();
		let results = ctx.results_get();
		assert!(
			results[0].envelope.exhausted(),
			"the first query was already answered when the search turned a term away, so \
			 that refusal cost it nothing and its verdict must not be qualified by it"
		);
		assert!(
			!results[1].envelope.exhausted(),
			"the second query was still open, so the term the search declined is a term it \
			 never got to try against this query and the hold has to say so"
		);
	}

	#[test]
	fn only_an_honest_run_records_a_verdict_unless_every_scenario_is_corrupt() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private cat_m\n\
			knows private cat_k\n\
			cat_e = ENC(cat_k, cat_m)\n\
			]\n\
			queries[\n\
			confidentiality? cat_m\n\
			]\n";
		let m = parse_string("cat.vp", src).expect("parse");

		let plain = VerifyContext::new(&m, &[], Vec::new(), 2, None, Vec::new());
		assert!(plain.claims_apply_to(1));
		assert!(plain.claims_apply_to(9));
		assert!(!plain.relativises());

		let mut honest: IdMap<PrincipalId, i32> = IdMap::default();
		honest.insert(1, i32::MAX);
		let mixed = VerifyContext::new(&m, &[], Vec::new(), 2, Some(honest), Vec::new());
		assert!(mixed.claims_apply_to(1));
		assert!(!mixed.claims_apply_to(2));
		assert!(mixed.relativises());

		let corrupt =
			VerifyContext::new(&m, &[], Vec::new(), 2, Some(IdMap::default()), Vec::new());
		assert!(
			corrupt.claims_apply_to(2),
			"a model with nothing honest to relativise against must not hold vacuously"
		);
		assert!(!corrupt.relativises());
		assert!(
			!corrupt.is_honest(2),
			"the honest-run check stays relaxed there even so"
		);
	}

	#[test]
	fn finalizing_envelopes_never_resolves_a_query() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private fev_m\n\
			knows private fev_k\n\
			fev_e = ENC(fev_k, fev_m)\n\
			]\n\
			queries[\n\
			confidentiality? fev_m\n\
			]\n";
		let m = parse_string("fev.vp", src).expect("parse");
		let ctx = VerifyContext::new(&m, &[], Vec::new(), 2, None, Vec::new());
		assert!(!ctx.all_resolved());
		ctx.finalize_envelopes();
		assert!(!ctx.all_resolved());
		assert!(!ctx.results_get()[0].resolved);
		assert_eq!(ctx.results_get()[0].summary, "");
	}
}
