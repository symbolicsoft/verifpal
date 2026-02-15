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

/// Global because TUI display is inherently process-wide. The TUI thread reads
/// this counter to show progress; it cannot be scoped to a `VerifyContext`
/// without threading a reference into the TUI rendering loop.
static ANALYSIS_COUNT: AtomicU32 = AtomicU32::new(0);

pub(crate) fn analysis_count_get() -> usize {
	ANALYSIS_COUNT.load(Ordering::SeqCst) as usize
}

use crate::inject::primitive_skeleton_hash_of;
use crate::types::*;
use crate::util::*;
use crate::value::compute_slot_diffs;

/// Central verification context. Owns all mutable state for a single
/// verification run, replacing the old global LazyLock singletons.
///
/// All mutation is interior (RwLock / Atomic) so the context can be shared
/// across rayon threads via `&VerifyContext`.
pub(crate) struct VerifyContext {
	attacker: RwLock<AttackerState>,
	results: RwLock<Vec<VerifyResult>>,
	unresolved: AtomicI32,
	analysis_count: AtomicU32,
	file_name: String,
}

/// Add a value to locked attacker state if not already known.
fn attacker_state_absorb(state: &mut AttackerState, value: &Value, record: &MutationRecord) {
	if state.knows(value).is_some() {
		return;
	}
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
	Arc::make_mut(&mut state.mutation_records).push(record.clone());
}

impl VerifyContext {
	/// Create a fresh context for verifying model `m`.
	pub(crate) fn new(m: &Model) -> Self {
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
		}
	}

	// -----------------------------------------------------------------------
	// Attacker state
	// -----------------------------------------------------------------------

	/// Reset attacker state for a new phase.
	pub(crate) fn attacker_init(&self) {
		let mut state = write_lock(&self.attacker);
		*state = AttackerState::new();
	}

	/// Cheap O(1) snapshot of the attacker state (Arc increments only).
	pub(crate) fn attacker_snapshot(&self) -> AttackerState {
		read_lock(&self.attacker).clone()
	}

	pub(crate) fn attacker_is_exhausted(&self) -> bool {
		read_lock(&self.attacker).exhausted
	}

	pub(crate) fn attacker_known_count(&self) -> usize {
		read_lock(&self.attacker).known.len()
	}

	/// Add a value to attacker knowledge. Returns true if it was new.
	pub(crate) fn attacker_put(&self, known: &Value, record: &MutationRecord) -> bool {
		// Fast check with read lock
		{
			let state = read_lock(&self.attacker);
			if state.knows(known).is_some() {
				return false;
			}
		}
		// Write lock: double-check and append
		let mut state = write_lock(&self.attacker);
		if state.knows(known).is_some() {
			return false;
		}
		let idx = state.known.len();
		Arc::make_mut(&mut state.known).push(known.clone());
		let h = known.hash_value();
		Arc::make_mut(&mut state.known_map)
			.entry(h)
			.or_default()
			.push(idx);
		if let Value::Primitive(p) = known {
			Arc::make_mut(&mut state.skeleton_hashes).insert(primitive_skeleton_hash_of(p));
		}
		Arc::make_mut(&mut state.mutation_records).push(record.clone());
		let count = state.known.len();
		drop(state);
		if crate::tui::tui_enabled() {
			crate::tui::tui_attacker_known(count);
		}
		true
	}

	pub(crate) fn attacker_set_exhausted(&self) {
		let mut state = write_lock(&self.attacker);
		state.exhausted = true;
	}

	/// Initialize attacker knowledge for a new phase.
	pub(crate) fn attacker_phase_update(
		&self,
		km: &ProtocolTrace,
		ps: &PrincipalState,
		phase: i32,
	) -> VResult<()> {
		let record = compute_slot_diffs(ps, km);
		let mut state = write_lock(&self.attacker);
		state.current_phase = phase;

		// Public constants
		for (sm, sv) in ps.meta.iter().zip(ps.values.iter()) {
			if sm.constant.qualifier != Some(Qualifier::Public) {
				continue;
			}
			if let Ok(earliest) = min_int_in_slice(&sm.phase) {
				if earliest > phase {
					continue;
				}
			}
			if !km.constant_used_by_any(&sm.constant) {
				continue;
			}
			attacker_state_absorb(&mut state, &sv.assigned, &record);
		}

		// Wire/leaked values
		for (sm, sv) in ps.meta.iter().zip(ps.values.iter()) {
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
			let constant_value = Value::Constant(sm.constant.clone());
			attacker_state_absorb(&mut state, &constant_value, &record);
			attacker_state_absorb(&mut state, &sv.assigned, &record);
		}

		Ok(())
	}

	// -----------------------------------------------------------------------
	// Verify results
	// -----------------------------------------------------------------------

	pub(crate) fn results_get(&self) -> Vec<VerifyResult> {
		read_lock(&self.results).clone()
	}

	pub(crate) fn results_file_name(&self) -> &str {
		&self.file_name
	}

	/// Write a resolved result. Returns true if it was newly written.
	pub(crate) fn results_put(&self, result: &VerifyResult) -> bool {
		let mut state = write_lock(&self.results);
		if let Some(vr) = state.get_mut(result.query_index) {
			if !vr.resolved {
				vr.resolved = result.resolved;
				vr.summary = result.summary.clone();
				vr.options = result.options.clone();
				if result.resolved {
					self.unresolved.fetch_sub(1, Ordering::SeqCst);
				}
				return true;
			}
		}
		false
	}

	pub(crate) fn all_resolved(&self) -> bool {
		self.unresolved.load(Ordering::SeqCst) <= 0
	}

	// -----------------------------------------------------------------------
	// Analysis counter
	// -----------------------------------------------------------------------

	pub(crate) fn analysis_count_increment(&self) {
		self.analysis_count.fetch_add(1, Ordering::SeqCst);
		ANALYSIS_COUNT.fetch_add(1, Ordering::SeqCst);
	}
}
