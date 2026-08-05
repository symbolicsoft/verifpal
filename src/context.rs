/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::Cell;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
	lock.read().unwrap_or_else(|e| e.into_inner())
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
	lock.write().unwrap_or_else(|e| e.into_inner())
}

thread_local! {
	/// Labels output lines, which are emitted from places that have no
	/// `VerifyContext` in hand. Per thread rather than per process so that
	/// concurrent analyses — the test suite, or an embedder — do not renumber
	/// each other's output.
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

/// All mutable state for a single verification run.
///
/// Mutation is interior (RwLock / Atomic), so the context is shared by
/// `&VerifyContext` rather than threaded through as `&mut`, and stays safe to
/// share should any stage of the pipeline become parallel.
pub(crate) struct VerifyContext {
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
		let Some(inherited) = state.record(idx) else {
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
	pub(crate) fn new(m: &Model, states: &[PrincipalState]) -> Self {
		let results: Vec<VerifyResult> = m
			.queries
			.iter()
			.enumerate()
			.map(|(i, q)| VerifyResult::new(q, i))
			.collect();
		let unresolved = results.len() as i32;
		analysis_count_reset();
		VerifyContext {
			attacker: RwLock::new(AttackerState::new()),
			results: RwLock::new(results),
			unresolved: AtomicI32::new(unresolved),
			analysis_count: AtomicU32::new(0),
			file_name: m.file_name.clone(),
			states: states.to_vec(),
		}
	}

	pub(crate) fn principal_states(&self) -> &[PrincipalState] {
		&self.states
	}

	pub(crate) fn attacker_init(&self) {
		let mut state = write_lock(&self.attacker);
		*state = AttackerState::new();
	}

	/// O(1): Arc increments only.
	pub(crate) fn attacker_snapshot(&self) -> AttackerState {
		read_lock(&self.attacker).clone()
	}

	pub(crate) fn attacker_known_count(&self) -> usize {
		read_lock(&self.attacker).known.len()
	}

	/// Returns true if the value was new.
	pub(crate) fn attacker_put_with(
		&self,
		known: &Value,
		record: &Arc<MutationRecord>,
		derivation: DerivationRecord,
	) -> bool {
		{
			let state = read_lock(&self.attacker);
			if state.knows(known).is_some() {
				return false;
			}
		}
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

	pub(crate) fn results_file_name(&self) -> &str {
		&self.file_name
	}

	/// Returns true if the result was newly written.
	pub(crate) fn results_put(&self, result: &VerifyResult) -> bool {
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

	pub(crate) fn all_resolved(&self) -> bool {
		self.unresolved.load(Ordering::SeqCst) <= 0
	}

	pub(crate) fn query_is_resolved(&self, query_index: usize) -> bool {
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
	/// resets the `ANALYSIS_COUNT` that real output labels itself with.
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
		VerifyContext {
			attacker: RwLock::new(self.attacker_snapshot()),
			results: RwLock::new(results),
			unresolved: AtomicI32::new(unresolved),
			analysis_count: AtomicU32::new(0),
			file_name: self.file_name.clone(),
			states: self.states.clone(),
		}
	}

	pub(crate) fn analysis_count_increment(&self) {
		self.analysis_count.fetch_add(1, Ordering::SeqCst);
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
		let ctx = VerifyContext::new(&m, &[]);
		let scratch = ctx.scratch_for_query(1);

		// Only the target query is open in the scratch.
		assert!(!scratch.query_is_resolved(1));
		assert!(scratch.query_is_resolved(0));
		assert!(!scratch.all_resolved());

		// Resolving the target in the scratch closes it there...
		let mut r = VerifyResult::new(&m.queries[1], 1);
		r.resolved = true;
		r.summary = " probe".to_string();
		assert!(scratch.results_put(&r));
		assert!(scratch.query_is_resolved(1));
		assert!(scratch.all_resolved());

		// ...and leaves the real context untouched.
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
		let ctx = VerifyContext::new(&m, &[]);
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
}
