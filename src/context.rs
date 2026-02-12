/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

/// Global analysis counter for display purposes (TUI/stdout are inherently global).
static ANALYSIS_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn analysis_count_get() -> usize {
	ANALYSIS_COUNT.load(Ordering::SeqCst) as usize
}

use crate::construct::construct_principal_state_clone;
use crate::inject::primitive_skeleton_hash_of;
use crate::types::*;
use crate::util::*;
use crate::value::{value_equivalent_value_in_values_map, value_hash};

/// Central verification context. Owns all mutable state for a single
/// verification run, replacing the old global LazyLock singletons.
///
/// All mutation is interior (RwLock / Atomic) so the context can be shared
/// across rayon threads via `&VerifyContext`.
pub struct VerifyContext {
	attacker: RwLock<AttackerState>,
	results: RwLock<Vec<VerifyResult>>,
	unresolved: AtomicI32,
	analysis_count: AtomicU32,
	file_name: String,
}

/// Add a value to locked attacker state if not already known.
fn attacker_state_absorb(state: &mut AttackerState, v: &Value, ps: &PrincipalState) {
	if value_equivalent_value_in_values_map(v, &state.known, &state.known_map) >= 0 {
		return;
	}
	let clone = Arc::new(construct_principal_state_clone(ps, false));
	let idx = state.known.len();
	Arc::make_mut(&mut state.known).push(v.clone());
	let h = value_hash(v);
	Arc::make_mut(&mut state.known_map)
		.entry(h)
		.or_default()
		.push(idx);
	Arc::make_mut(&mut state.principal_state).push(clone);
}

impl VerifyContext {
	/// Create a fresh context for verifying model `m`.
	pub fn new(m: &Model) -> Self {
		let results: Vec<VerifyResult> = m
			.queries
			.iter()
			.enumerate()
			.map(|(i, q)| VerifyResult {
				query: q.clone(),
				query_index: i,
				resolved: false,
				summary: String::new(),
				options: vec![],
			})
			.collect();
		let unresolved = results.len() as i32;
		ANALYSIS_COUNT.store(0, Ordering::SeqCst);
		VerifyContext {
			attacker: RwLock::new(AttackerState {
				current_phase: 0,
				exhausted: false,
				known: Arc::new(vec![]),
				known_map: Arc::new(HashMap::new()),
				skeleton_hashes: Arc::new(HashSet::new()),
				principal_state: Arc::new(vec![]),
			}),
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
	pub fn attacker_init(&self) {
		let mut state = self.attacker.write().unwrap_or_else(|e| e.into_inner());
		*state = AttackerState {
			current_phase: 0,
			exhausted: false,
			known: Arc::new(vec![]),
			known_map: Arc::new(HashMap::new()),
			skeleton_hashes: Arc::new(HashSet::new()),
			principal_state: Arc::new(vec![]),
		};
	}

	/// Cheap O(1) snapshot of the attacker state (Arc increments only).
	pub fn attacker_snapshot(&self) -> AttackerState {
		self.attacker
			.read()
			.unwrap_or_else(|e| e.into_inner())
			.clone()
	}

	pub fn attacker_is_exhausted(&self) -> bool {
		self.attacker
			.read()
			.unwrap_or_else(|e| e.into_inner())
			.exhausted
	}

	pub fn attacker_known_count(&self) -> usize {
		self.attacker
			.read()
			.unwrap_or_else(|e| e.into_inner())
			.known
			.len()
	}

	/// Add a value to attacker knowledge. Returns true if it was new.
	pub fn attacker_put(&self, known: &Value, ps: &PrincipalState) -> bool {
		// Fast check with read lock
		{
			let state = self.attacker.read().unwrap_or_else(|e| e.into_inner());
			if value_equivalent_value_in_values_map(known, &state.known, &state.known_map) >= 0 {
				return false;
			}
		}
		// Prepare clone outside write lock
		let clone = Arc::new(construct_principal_state_clone(ps, false));
		// Write lock: double-check and append
		let mut state = self.attacker.write().unwrap_or_else(|e| e.into_inner());
		if value_equivalent_value_in_values_map(known, &state.known, &state.known_map) >= 0 {
			return false;
		}
		let idx = state.known.len();
		Arc::make_mut(&mut state.known).push(known.clone());
		let h = value_hash(known);
		Arc::make_mut(&mut state.known_map)
			.entry(h)
			.or_default()
			.push(idx);
		if let Value::Primitive(p) = known {
			Arc::make_mut(&mut state.skeleton_hashes).insert(primitive_skeleton_hash_of(p));
		}
		Arc::make_mut(&mut state.principal_state).push(clone);
		let count = state.known.len();
		drop(state);
		if crate::tui::tui_enabled() {
			crate::tui::tui_attacker_known(count);
		}
		true
	}

	pub fn attacker_set_exhausted(&self) {
		let mut state = self.attacker.write().unwrap_or_else(|e| e.into_inner());
		state.exhausted = true;
	}

	/// Initialize attacker knowledge for a new phase.
	pub fn attacker_phase_update(
		&self,
		km: &KnowledgeMap,
		ps: &PrincipalState,
		phase: i32,
	) -> Result<(), String> {
		{
			let mut state = self.attacker.write().unwrap_or_else(|e| e.into_inner());
			state.current_phase = phase;
		}
		self.attacker_absorb_phase_values(km, ps)
	}

	fn attacker_absorb_phase_values(
		&self,
		km: &KnowledgeMap,
		ps: &PrincipalState,
	) -> Result<(), String> {
		let mut state = self.attacker.write().unwrap_or_else(|e| e.into_inner());
		let current_phase = state.current_phase;

		// Public constants
		for i in 0..ps.constants.len() {
			if let Value::Constant(c) = &ps.assigned[i] {
				if c.qualifier != Some(Qualifier::Public) {
					continue;
				}
				if let Ok(earliest) = min_int_in_slice(&ps.phase[i]) {
					if earliest > current_phase {
						continue;
					}
				}
				if !crate::value::value_constant_is_used_by_at_least_one_principal(km, c) {
					continue;
				}
				attacker_state_absorb(&mut state, &ps.assigned[i], ps);
			}
		}

		// Wire/leaked values
		for (i, c) in ps.constants.iter().enumerate() {
			if ps.wire[i].is_empty() && !ps.constants[i].leaked {
				continue;
			}
			if ps.constants[i].qualifier == Some(Qualifier::Public) {
				continue;
			}
			let earliest = min_int_in_slice(&ps.phase[i])?;
			if earliest > current_phase {
				continue;
			}
			let cc = Value::Constant(c.clone());
			attacker_state_absorb(&mut state, &cc, ps);
			attacker_state_absorb(&mut state, &ps.assigned[i], ps);
		}

		Ok(())
	}

	// -----------------------------------------------------------------------
	// Verify results
	// -----------------------------------------------------------------------

	pub fn results_get(&self) -> Vec<VerifyResult> {
		self.results
			.read()
			.unwrap_or_else(|e| e.into_inner())
			.clone()
	}

	pub fn results_file_name(&self) -> &str {
		&self.file_name
	}

	/// Write a resolved result. Returns true if it was newly written.
	pub fn results_put(&self, result: &VerifyResult) -> bool {
		let mut state = self.results.write().unwrap_or_else(|e| e.into_inner());
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

	pub fn all_resolved(&self) -> bool {
		self.unresolved.load(Ordering::SeqCst) <= 0
	}

	// -----------------------------------------------------------------------
	// Analysis counter
	// -----------------------------------------------------------------------

	pub fn analysis_count_increment(&self) {
		self.analysis_count.fetch_add(1, Ordering::SeqCst);
		ANALYSIS_COUNT.fetch_add(1, Ordering::SeqCst);
	}
}
