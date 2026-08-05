/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Acquire a read guard, recovering from poison.
fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
	lock.read().unwrap_or_else(|e| e.into_inner())
}

/// Acquire a write guard, recovering from poison.
fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
	lock.write().unwrap_or_else(|e| e.into_inner())
}

/// Global because the analysis count labels output from wherever it is
/// emitted, without a `VerifyContext` in hand.
static ANALYSIS_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn analysis_count_get() -> usize {
	ANALYSIS_COUNT.load(Ordering::SeqCst) as usize
}

use crate::skeleton::primitive_skeleton_hash_of;
use crate::types::*;
use crate::util::*;
use crate::value::compute_slot_diffs;

/// Central verification context. Owns all mutable state for a single
/// verification run, replacing the old global LazyLock singletons.
///
/// All mutation is interior (RwLock / Atomic), so the context is shared by
/// `&VerifyContext` rather than threaded through as `&mut`, and stays safe to
/// share across threads should any stage of the pipeline become parallel.
pub struct VerifyContext {
	attacker: RwLock<AttackerState>,
	results: RwLock<Vec<VerifyResult>>,
	unresolved: AtomicI32,
	analysis_count: AtomicU32,
	file_name: String,
	/// Every principal's starting state.
	///
	/// Held so trace narration can replay a candidate attack in the session it
	/// belongs to.  A query resolves against whichever principal reaches it
	/// first, which is often not the one whose session the attack happened in —
	/// Alice's message is compromised in Alice's run, but the query is answered
	/// while walking Bob's.
	states: Vec<PrincipalState>,
}

/// The substitutions that had to be in force for the attacker to hold this
/// value — not the ones that happened to be in force when it absorbed it.
///
/// These are different things, and conflating them is what made attack traces
/// describe one attack's actions beside another attack's consequences.  The
/// attacker learns a ciphertext in the run where it substituted a public key,
/// then decrypts it in some later run whose own substitutions are about
/// something else entirely.  Snapshotting the ambient state at absorption time
/// records the later run and loses the one that mattered.
///
/// So provenance travels along the derivation edge: a value combined out of
/// values the attacker already held inherits their provenance, and only a
/// value genuinely read out of a principal's state picks up that state's
/// substitutions.
fn derivation_provenance(
	state: &AttackerState,
	ambient: &Arc<MutationRecord>,
	derivation: &DerivationRecord,
) -> Arc<MutationRecord> {
	let ingredients = derivation.ingredients();
	if ingredients.is_empty() && !derivation.reads_from_state() {
		// Public knowledge and injected skeletons cost the attacker nothing.
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

	// An ingredient the attacker has not absorbed yet is one a rule rebuilt
	// on the spot out of the state in front of it — `can_decompose` will hand
	// back a key it reconstructed rather than one it held.  There is no record
	// to inherit for such a value, and the state that supplied it is exactly
	// the provenance, so the ambient diffs stand in.
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
		let Some(inherited) = state.mutation_records.get(idx) else {
			continue;
		};
		if !adopted && !inherited.diffs.is_empty() {
			// Attribute the session to whoever's run actually produced the
			// leverage, so the narration names the right principal.
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

/// Add a value to locked attacker state if not already known.
fn attacker_state_absorb(
	state: &mut AttackerState,
	value: &Value,
	record: &Arc<MutationRecord>,
	derivation: DerivationRecord,
) {
	if let Some(existing) = state.knows(value) {
		// The value is already known, but the run offering it again may explain
		// it better.  The search reaches the same term by several routes, and
		// the first to arrive is often one that carries no attacker actions at
		// all — the substitution that produced the term having been made in a
		// state the arriving path had already purified.  Keeping that first
		// record is how a trace ends up describing an attack with nothing in
		// it.  Knowledge is unchanged either way; only the explanation is.
		let candidate = derivation_provenance(state, record, &derivation);
		let explains = |r: &MutationRecord| r.diffs.iter().any(|d| d.tainted);
		let stale = state
			.mutation_records
			.get(existing)
			.is_some_and(|r| !explains(r));
		if stale && explains(&candidate) {
			Arc::make_mut(&mut state.mutation_records)[existing] = candidate;
			Arc::make_mut(&mut state.derivations)[existing] = derivation;
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
	/// Create a fresh context for verifying model `m`.
	pub fn new(m: &Model, states: &[PrincipalState]) -> Self {
		let results: Vec<VerifyResult> = m
			.queries
			.iter()
			.enumerate()
			.map(|(i, q)| VerifyResult::new(q, i))
			.collect();
		let unresolved = results.len() as i32;
		ANALYSIS_COUNT.store(0, Ordering::SeqCst);
		VerifyContext {
			attacker: RwLock::new(AttackerState::new()),
			results: RwLock::new(results),
			unresolved: AtomicI32::new(unresolved),
			analysis_count: AtomicU32::new(0),
			file_name: m.file_name.clone(),
			states: states.to_vec(),
		}
	}

	/// Every principal's starting state, for replaying a candidate attack in
	/// the session it belongs to.
	pub fn principal_states(&self) -> &[PrincipalState] {
		&self.states
	}

	// -----------------------------------------------------------------------
	// Attacker state
	// -----------------------------------------------------------------------

	/// Reset attacker state for a new phase.
	pub fn attacker_init(&self) {
		let mut state = write_lock(&self.attacker);
		*state = AttackerState::new();
	}

	/// Cheap O(1) snapshot of the attacker state (Arc increments only).
	pub fn attacker_snapshot(&self) -> AttackerState {
		read_lock(&self.attacker).clone()
	}

	pub fn attacker_known_count(&self) -> usize {
		read_lock(&self.attacker).known.len()
	}

	/// Add a value to attacker knowledge. Returns true if it was new.
	pub fn attacker_put(&self, known: &Value, record: &Arc<MutationRecord>) -> bool {
		self.attacker_put_with(known, record, DerivationRecord::Initial)
	}

	/// As [`Self::attacker_put`], recording how the value was derived.
	pub fn attacker_put_with(
		&self,
		known: &Value,
		record: &Arc<MutationRecord>,
		derivation: DerivationRecord,
	) -> bool {
		// Fast check with read lock
		{
			let state = read_lock(&self.attacker);
			if state.knows(known).is_some() {
				return false;
			}
		}
		// Write lock: double-check and absorb
		let mut state = write_lock(&self.attacker);
		if state.knows(known).is_some() {
			return false;
		}
		attacker_state_absorb(&mut state, known, record, derivation);
		true
	}

	/// Initialize attacker knowledge for a new phase.
	pub fn attacker_phase_update(
		&self,
		km: &ProtocolTrace,
		ps: &PrincipalState,
		phase: i32,
	) -> VResult<()> {
		let record = compute_slot_diffs(ps, km, phase);
		let mut state = write_lock(&self.attacker);
		state.current_phase = phase;

		// Public constants
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

		// Wire/leaked values
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
				DerivationRecord::Leaked { slot }
			} else {
				DerivationRecord::Obtained { slot }
			};
			let constant_value = Value::Constant(sm.constant.clone());
			attacker_state_absorb(&mut state, &constant_value, &record, derivation.clone());
			attacker_state_absorb(&mut state, &sv.value, &record, derivation);
		}

		Ok(())
	}

	// -----------------------------------------------------------------------
	// Verify results
	// -----------------------------------------------------------------------

	pub fn results_get(&self) -> Vec<VerifyResult> {
		read_lock(&self.results).clone()
	}

	pub fn results_file_name(&self) -> &str {
		&self.file_name
	}

	/// Write a resolved result. Returns true if it was newly written.
	pub fn results_put(&self, result: &VerifyResult) -> bool {
		let mut state = write_lock(&self.results);
		if let Some(vr) = state.get_mut(result.query_index)
			&& !vr.resolved
		{
			vr.resolved = result.resolved;
			vr.summary = result.summary.clone();
			vr.options = result.options.clone();
			if result.resolved {
				self.unresolved.fetch_sub(1, Ordering::SeqCst);
			}
			return true;
		}
		false
	}

	pub fn all_resolved(&self) -> bool {
		self.unresolved.load(Ordering::SeqCst) <= 0
	}

	pub fn query_is_resolved(&self, query_index: usize) -> bool {
		read_lock(&self.results)
			.get(query_index)
			.is_some_and(|r| r.resolved)
	}

	/// A disposable context for re-checking exactly one query.
	///
	/// Attacker knowledge is snapshotted, so probes start from everything the
	/// real run has learned but cannot write back into it.  Every query other
	/// than `query_index` is pre-marked resolved, which makes
	/// `verify_resolve_queries` skip them and lets `all_resolved()` short
	/// circuit the moment the target answers.
	///
	/// Constructed field-by-field rather than through `new`, because `new`
	/// resets the process-global `ANALYSIS_COUNT` that real output labels
	/// itself with.
	pub fn scratch_for_query(&self, query_index: usize) -> VerifyContext {
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
		VerifyContext {
			attacker: RwLock::new(self.attacker_snapshot()),
			results: RwLock::new(results),
			unresolved: AtomicI32::new(unresolved),
			analysis_count: AtomicU32::new(0),
			file_name: self.file_name.clone(),
			states: self.states.clone(),
		}
	}

	// -----------------------------------------------------------------------
	// Analysis counter
	// -----------------------------------------------------------------------

	pub fn analysis_count_increment(&self) {
		self.analysis_count.fetch_add(1, Ordering::SeqCst);
		if !crate::info::info_is_quiet() {
			ANALYSIS_COUNT.fetch_add(1, Ordering::SeqCst);
		}
	}
}
