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

use crate::skeleton::primitive_skeleton_hash_of;
use crate::types::*;
use crate::util::*;
use crate::value::compute_slot_diffs;

pub(crate) struct VerifyContext {
	attacker: RwLock<AttackerState>,
	results: RwLock<Vec<VerifyResult>>,
	unresolved: AtomicI32,
	file_name: String,
	states: Vec<PrincipalState>,
	phase_knowledge: RwLock<Vec<AttackerState>>,
	depth_cuts: RwLock<IdSet<(PrincipalId, usize)>>,
	truncations: RwLock<Vec<Truncation>>,
	sessions: u8,
	honest: IdSet<PrincipalId>,
	#[cfg(test)]
	witnesses: RwLock<Vec<Option<ResultWitness>>>,
	#[cfg(test)]
	query_goals: RwLock<Vec<usize>>,
	#[cfg(test)]
	searched: AtomicBool,
	prefer_replication: AtomicBool,
	replication_only: AtomicBool,
	replication_rejected: AtomicBool,
	cancel: Arc<AtomicBool>,
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
			if !diffs.iter().any(|d| d.index == diff.index) {
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
		if stale && explains(&candidate) {
			Arc::make_mut(&mut state.mutation_records)[existing.get()] = candidate;
			Arc::make_mut(&mut state.derivations)[existing.get()] = derivation;
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
	if let Value::Primitive(p) = value {
		Arc::make_mut(&mut state.skeleton_hashes).insert(primitive_skeleton_hash_of(p));
	}
	Arc::make_mut(&mut state.mutation_records).push(Arc::clone(record));
	Arc::make_mut(&mut state.derivations).push(derivation);
}

impl VerifyContext {
	pub(crate) fn new(
		m: &Model,
		states: &[PrincipalState],
		variants: Vec<Vec<Query>>,
		sessions: u8,
		honest: IdSet<PrincipalId>,
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
			attacker: RwLock::new(AttackerState::new()),
			results: RwLock::new(results),
			unresolved: AtomicI32::new(unresolved),
			file_name: m.file_name.clone(),
			states: states.to_vec(),
			phase_knowledge: RwLock::new(vec![]),
			depth_cuts: RwLock::new(IdSet::default()),
			truncations: RwLock::new(Vec::new()),
			sessions,
			honest,
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

	/// True the first time only: the depth bound turns away every term of that
	/// shape at that slot, and saying so once is what the reader needs.
	pub(crate) fn note_depth_cut(&self, principal: PrincipalId, slot: usize) -> bool {
		self.note_truncation(Truncation::TermDepth);
		write_lock(&self.depth_cuts).insert((principal, slot))
	}

	pub(crate) fn note_truncation(&self, kind: Truncation) {
		let mut state = write_lock(&self.truncations);
		if !state.contains(&kind) {
			state.push(kind);
			state.sort();
		}
	}

	/// True for every principal in a model that declares no scenarios, and
	/// otherwise only for the clones whose peer bindings all resolve to values
	/// no leak reaches. A run whose peer is the attacker is still explored —
	/// it is where the attacker learns things — but it is not a run whose
	/// claims are the protocol's to keep.
	pub(crate) fn is_honest(&self, principal: PrincipalId) -> bool {
		self.honest.is_empty() || self.honest.contains(&principal)
	}

	pub(crate) fn truncations(&self) -> Vec<Truncation> {
		read_lock(&self.truncations).clone()
	}

	pub(crate) fn finalize_envelopes(&self) {
		let envelope = Envelope {
			sessions: self.sessions,
			truncations: self.truncations(),
		};
		for vr in write_lock(&self.results).iter_mut() {
			vr.envelope = envelope.clone();
		}
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
			if !km.constant_used_by_any(&sm.constant) {
				continue;
			}
			attacker_state_absorb(&mut state, &sv.value, &record, DerivationRecord::Initial);
		}

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
			let derivation = if sm.constant.leaked {
				DerivationRecord::Leaked {
					slot: SlotIdx(slot),
				}
			} else {
				DerivationRecord::Obtained {
					slot: SlotIdx(slot),
				}
			};
			let constant_value = Value::Constant(sm.constant.clone());
			attacker_state_absorb(&mut state, &constant_value, &record, derivation.clone());
			attacker_state_absorb(&mut state, &sv.value, &record, derivation);
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

	/// Record a verdict. The token is unforgeable outside `query.rs`, which is
	/// fact (i) of the soundness theorem expressed as a type rather than as a
	/// test over the source.
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
			vr.trace = result.trace.clone();
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

	pub(crate) fn scratch_for_query(&self, query_index: usize) -> VerifyContext {
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
			results: RwLock::new(results),
			unresolved: AtomicI32::new(unresolved),
			file_name: self.file_name.clone(),
			states: self.states.clone(),
			phase_knowledge: RwLock::new(read_lock(&self.phase_knowledge).clone()),
			depth_cuts: RwLock::new(read_lock(&self.depth_cuts).clone()),
			truncations: RwLock::new(read_lock(&self.truncations).clone()),
			sessions: self.sessions,
			honest: self.honest.clone(),
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
			generates cx_m\n\
			cx_e = AEAD_ENC(cx_k, cx_m, nil)\n\
			]\n\
			Bob -> Alice: cx_gb, cx_e\n\
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
			generates cz_m\n\
			cz_e = AEAD_ENC(cz_k, cz_m, nil)\n\
			]\n\
			Bob -> Alice: cz_gb, cz_e\n\
			principal Alice[\n\
			cz_k2 = DH_KEX(cz_gb, cz_a)\n\
			cz_d = AEAD_DEC(cz_k2, cz_e, nil)\n\
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
		let ctx = VerifyContext::new(&m, &[], Vec::new(), 2, IdSet::default());
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
		let ctx = VerifyContext::new(&m, &[], Vec::new(), 2, IdSet::default());
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
		let ctx = VerifyContext::new(&m, &[], Vec::new(), 2, IdSet::default());
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
		let ctx = VerifyContext::new(&m, &[], Vec::new(), 2, IdSet::default());
		ctx.note_depth_cut(1, 0);
		ctx.finalize_envelopes();
		assert_eq!(ctx.truncations(), vec![Truncation::TermDepth]);
		assert!(!ctx.results_get()[0].envelope.exhausted());
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
		let ctx = VerifyContext::new(&m, &[], Vec::new(), 2, IdSet::default());
		assert!(!ctx.all_resolved());
		ctx.finalize_envelopes();
		assert!(!ctx.all_resolved());
		assert!(!ctx.results_get()[0].resolved);
		assert_eq!(ctx.results_get()[0].summary, "");
	}
}
