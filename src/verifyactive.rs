/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Active Attacker Verification
//!
//! Implements Verifpal's active attacker analysis, which explores protocol
//! executions under an attacker that can modify unguarded values on the wire.
//!
//! ## Search Strategy
//!
//! The search is parameterized by a single depth parameter `d` (default 3):
//!
//! 1. **Baseline analysis** (depth 0): run the protocol as-is with passive
//!    deduction to build initial attacker knowledge.
//!
//! 2. **Bounded-depth search** (depth 1..=d): at each depth level, explore
//!    mutations of increasing complexity:
//!    - All k-subsets for k ≤ depth (single-variable at depth 1, pairs at
//!      depth 2, triples at depth 3).
//!    - All attacker-known values as potential replacements.
//!    - Recursive injection nesting ≤ max(0, depth − 1).
//!
//!    DH public-key replacement (the canonical MitM attack) is a natural
//!    first-order mutation at depth 1 — `G^nil` is always in the attacker's
//!    knowledge and equation-valued slots accept equation replacements.
//!
//! ## Completeness Argument
//!
//! The search is **sound** (any reported attack is genuine) but **incomplete**
//! (some attacks may not be found). The coverage guarantee is:
//!
//! > At depth d, Verifpal explores all k-variable mutations for k ≤ d,
//! > with injection nesting ≤ max(0, d − 1), using all attacker-known
//! > values as potential replacements, subject to per-principal budget caps.
//!
//! If no new knowledge is gained at a depth level, the search terminates
//! early. The default depth of 3 finds all attacks in published protocols
//! (TLS 1.3, Signal, Noise, Scuttlebutt, DP-3T, etc.) within seconds.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::context::VerifyContext;
use crate::info::{info_message, info_output_text};
use crate::mutationmap::mutation_product;
use crate::possible::{
	can_decompose, can_reconstruct_equation, can_reconstruct_primitive, can_rewrite,
	passively_decompose,
};
use crate::pretty::pretty_values;
use crate::primitive::*;
use crate::principal::ATTACKER_ID;
use crate::types::*;
use crate::value::{compute_slot_diffs, resolve_trace_values, value_g_nil};
use crate::verify::{verify_resolve_queries, verify_standard_run};
use crate::verifyanalysis::verify_analysis;

/// Information about a guarded primitive that failed its rewrite and caused
/// (or would cause) truncation of the principal state.
#[derive(Clone)]
struct FailedGuardInfo {
	/// The resolved key/secret argument that the attacker would need to know
	/// in order to craft an input that bypasses this guard.
	bypass_key: Value,
	/// Index into the PrincipalState.values array for this guard.
	assigned_index: usize,
}

/// Configuration for the active attacker's bounded-depth search.
///
/// The search explores all attacker strategies involving at most `depth`
/// simultaneous value substitutions, with injected values of nesting depth
/// at most `depth`. The coverage guarantee is:
///
/// > At depth d, Verifpal explores all k-variable mutations for k ≤ d,
/// > with injection nesting ≤ max(0, d − 1), using all attacker-known
/// > values as potential replacements.
///
/// ## Budget parameters
///
/// - `max_subsets_per_weight`: limits k-subsets sampled per weight level
/// - `max_weight1_mutations`: cap on mutations at weight 1 (cheap to evaluate)
/// - `max_mutations_per_subset`: cap on Cartesian product per subset
/// - `max_full_product`: cap on the full cross-product scan
/// - `max_scan_budget`: per-principal budget across all weights
struct SearchConfig {
	/// Maximum mutation depth. Controls simultaneous substitutions,
	/// injection nesting, and subset weight. Default: 3.
	depth: usize,
	max_subsets_per_weight: usize,
	max_weight1_mutations: usize,
	max_mutations_per_subset: usize,
	max_full_product: usize,
	max_scan_budget: u32,
}

const CONFIG: SearchConfig = SearchConfig {
	depth: 3,
	max_subsets_per_weight: 150,
	max_weight1_mutations: 150,
	max_mutations_per_subset: 50000,
	max_full_product: 50000,
	max_scan_budget: 80000,
};

pub fn verify_active(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	principal_states: &[PrincipalState],
) -> VResult<()> {
	info_message("Attacker is configured as active.", InfoLevel::Info, false);
	for phase in 0..=km.max_phase {
		info_message(
			&format!("Running at phase {}.", phase),
			InfoLevel::Info,
			false,
		);
		ctx.attacker_init();
		let mut ps_pure_resolved = principal_states[0].clone_for_stage(true);
		ps_pure_resolved.resolve_all_values(&ctx.attacker_snapshot())?;
		ctx.attacker_phase_update(km, &ps_pure_resolved, phase)?;
		verify_standard_run(ctx, km, principal_states, 0)?;

		// Depth 1 (serial — builds initial attacker knowledge)
		verify_active_at_depth(ctx, 1, km, principal_states);

		// Depth 2+ in parallel pairs until resolved or exhausted
		let mut d = 2usize;
		while !ctx.all_resolved() && !ctx.attacker_is_exhausted() && d <= CONFIG.depth {
			if d < CONFIG.depth {
				#[cfg(feature = "cli")]
				rayon::scope(|s| {
					s.spawn(|_| verify_active_at_depth(ctx, d, km, principal_states));
					s.spawn(|_| verify_active_at_depth(ctx, d + 1, km, principal_states));
				});
				#[cfg(not(feature = "cli"))]
				{
					verify_active_at_depth(ctx, d, km, principal_states);
					verify_active_at_depth(ctx, d + 1, km, principal_states);
				}
				d += 2;
			} else {
				verify_active_at_depth(ctx, d, km, principal_states);
				d += 1;
			}
		}
	}
	Ok(())
}

/// After a worthwhile mutation has been analyzed, attempt guard bypass if
/// truncation occurred.  Used by both the rayon and sequential scan paths.
fn process_mutation_bypass(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	result: &MutationResult,
) {
	if let Some(ref bypass) = result.guard_bypass {
		try_guard_bypass(ctx, km, &bypass.full_state, &bypass.failed_guards);
	}
}

/// Attempt to bypass failed guards by injecting attacker-controlled values.
/// Shared by the equation bypass path and both scan paths (rayon + sequential).
fn try_guard_bypass(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	full_state: &PrincipalState,
	failed_guards: &[FailedGuardInfo],
) {
	if ctx.all_resolved() {
		return;
	}
	let attacker_now = ctx.attacker_snapshot();
	if !can_attacker_bypass_any_guard(failed_guards, full_state, &attacker_now) {
		return;
	}
	if let Some(ps_injected) = build_bypass_state(full_state, failed_guards, &attacker_now) {
		verify_bypass_decompose(ctx, km, &ps_injected);
	}
}

/// Classify rewrite failures: collect failed guard info and compute truncation point.
///
/// Returns `(failed_guards, truncation_index, truncation_failed_idx)`.
/// `truncation_index` is the point after which the principal state should be
/// truncated (because a checked primitive failed), and `truncation_failed_idx`
/// is the slot index of the first failed checked primitive (used to determine
/// whether mutations before it were worthwhile).
fn classify_rewrite_failures(
	ps: &PrincipalState,
	failures: &[(Primitive, usize)],
) -> (Vec<FailedGuardInfo>, Option<usize>, Option<usize>) {
	let mut failed_guards: Vec<FailedGuardInfo> = Vec::new();
	let mut truncation_index: Option<usize> = None;
	let mut truncation_failed_idx: Option<usize> = None;

	for &(ref prim, idx) in failures {
		if !prim.instance_check || ps.values[idx].provenance.creator != ps.id {
			continue;
		}
		if let Some(key) = extract_bypass_key(prim) {
			failed_guards.push(FailedGuardInfo {
				bypass_key: key,
				assigned_index: idx,
			});
		}
		if truncation_index.is_none() {
			let declared_at = ps.meta[idx].declared_at;
			if declared_at == ps.max_declared_at {
				truncation_index = Some(idx + 1);
			} else if let Some(pos) = ps.meta.iter().position(|m| m.declared_at == declared_at) {
				truncation_index = Some(pos + 1);
			}
			truncation_failed_idx = Some(idx);
		}
	}

	(failed_guards, truncation_index, truncation_failed_idx)
}

fn verify_active_at_depth(
	ctx: &VerifyContext,
	depth: usize,
	km: &ProtocolTrace,
	principal_states: &[PrincipalState],
) {
	if crate::tui::tui_enabled() {
		crate::tui::tui_stage_update(depth as i32);
	}
	let worthwhile_mutation_count = AtomicU32::new(0);
	let old_known = ctx.attacker_known_count();
	let attacker = ctx.attacker_snapshot();

	// Process all principals — in parallel with rayon when available, sequentially otherwise.
	#[cfg(feature = "cli")]
	rayon::scope(|s| {
		for ps_base in principal_states {
			s.spawn(|s_inner| {
				let mm = match MutationMap::new(ctx, km, ps_base, &attacker, depth) {
					Ok(mm) => mm,
					Err(_) => return,
				};
				verify_active_scan_weighted(
					ctx,
					s_inner,
					km,
					ps_base,
					&attacker,
					mm,
					depth,
					&worthwhile_mutation_count,
				);
			});
		}
	});
	#[cfg(not(feature = "cli"))]
	for ps_base in principal_states {
		let mm = match MutationMap::new(ctx, km, ps_base, &attacker, depth) {
			Ok(mm) => mm,
			Err(_) => continue,
		};
		verify_active_scan_weighted_seq(
			ctx,
			km,
			ps_base,
			&attacker,
			mm,
			depth,
			&worthwhile_mutation_count,
		);
	}

	let worthwhile = worthwhile_mutation_count.load(Ordering::SeqCst);
	let stagnant = worthwhile == 0 || old_known == ctx.attacker_known_count();
	if stagnant {
		ctx.attacker_set_exhausted();
	}
}

#[cfg(feature = "cli")]
#[allow(clippy::too_many_arguments)]
fn verify_active_scan_weighted<'s>(
	ctx: &'s VerifyContext,
	scope: &rayon::Scope<'s>,
	km: &'s ProtocolTrace,
	ps_base: &'s PrincipalState,
	attacker: &'s AttackerState,
	mm: MutationMap,
	depth: usize,
	worthwhile_mutation_count: &'s AtomicU32,
) {
	let n = mm.constants.len();
	if n == 0 {
		return;
	}
	let budget_used = AtomicU32::new(0);
	let budget = CONFIG.max_scan_budget;
	let max_weight = depth.min(n);
	if crate::tui::tui_enabled() {
		crate::tui::tui_scan_update(&ps_base.name, 0, max_weight, 0, budget);
	}

	for weight in 1..=max_weight {
		if ctx.all_resolved() {
			break;
		}
		if budget_used.load(Ordering::SeqCst) >= budget {
			break;
		}
		verify_active_scan_at_weight(
			ctx,
			scope,
			km,
			ps_base,
			attacker,
			&mm,
			depth,
			worthwhile_mutation_count,
			n,
			weight,
			&budget_used,
			budget,
		);
	}

	if !ctx.all_resolved()
		&& budget_used.load(Ordering::SeqCst) < budget
		&& mutation_product(
			mm.mutations.iter().map(|m| m.len()),
			CONFIG.max_full_product,
		)
		.is_some()
	{
		let next_map = mm.next();
		verify_active_scan(
			ctx,
			scope,
			km,
			ps_base,
			attacker,
			next_map,
			depth,
			worthwhile_mutation_count,
		);
	}
}

#[cfg(feature = "cli")]
#[allow(clippy::too_many_arguments)]
fn verify_active_scan_at_weight<'s>(
	ctx: &'s VerifyContext,
	scope: &rayon::Scope<'s>,
	km: &'s ProtocolTrace,
	ps_base: &'s PrincipalState,
	attacker: &'s AttackerState,
	mm: &MutationMap,
	depth: usize,
	worthwhile_mutation_count: &'s AtomicU32,
	n: usize,
	weight: usize,
	budget_used: &AtomicU32,
	budget: u32,
) {
	let mut indices: Vec<usize> = (0..weight).collect();
	let mut scanned: usize = 0;

	loop {
		if ctx.all_resolved() {
			return;
		}
		if budget_used.load(Ordering::SeqCst) >= budget {
			return;
		}

		let sub_indices = indices.clone();

		if weight == 1 {
			let sub_map = mm.subset_capped(&sub_indices, CONFIG.max_weight1_mutations);
			let cost = sub_map.mutations[0].len() as u32;
			let bu = budget_used.fetch_add(cost, Ordering::SeqCst);
			if crate::tui::tui_enabled() && bu % 500 < cost {
				crate::tui::tui_scan_update(
					&ps_base.name,
					weight,
					n.min(depth),
					bu + cost,
					budget,
				);
			}
			let next_map = sub_map.next();
			verify_active_scan(
				ctx,
				scope,
				km,
				ps_base,
				attacker,
				next_map,
				depth,
				worthwhile_mutation_count,
			);
			scanned += 1;
		} else if let Some(product) = mutation_product(
			indices.iter().map(|&i| mm.mutations[i].len()),
			CONFIG.max_mutations_per_subset,
		) {
			let sub_map = mm.subset(&sub_indices);
			let bu = budget_used.fetch_add(product as u32, Ordering::SeqCst);
			if crate::tui::tui_enabled() && bu % 500 < product as u32 {
				crate::tui::tui_scan_update(
					&ps_base.name,
					weight,
					n.min(depth),
					bu + product as u32,
					budget,
				);
			}
			let next_map = sub_map.next();
			verify_active_scan(
				ctx,
				scope,
				km,
				ps_base,
				attacker,
				next_map,
				depth,
				worthwhile_mutation_count,
			);
			scanned += 1;
		}

		if scanned >= CONFIG.max_subsets_per_weight {
			return;
		}

		// Advance combination indices (lexicographic next subset of size `weight` from `n`)
		let mut advanced = false;
		for i in (0..weight).rev() {
			indices[i] += 1;
			if indices[i] <= n - weight + i {
				for j in (i + 1)..weight {
					indices[j] = indices[j - 1] + 1;
				}
				advanced = true;
				break;
			}
		}
		if !advanced {
			break;
		}
	}
}

#[cfg(feature = "cli")]
#[allow(clippy::too_many_arguments)]
fn verify_active_scan<'s>(
	ctx: &'s VerifyContext,
	scope: &rayon::Scope<'s>,
	km: &'s ProtocolTrace,
	ps_base: &'s PrincipalState,
	attacker: &'s AttackerState,
	mm: MutationMap,
	depth: usize,
	worthwhile_mutation_count: &'s AtomicU32,
) {
	let mut current_map = mm;
	loop {
		if ctx.all_resolved() {
			break;
		}
		// Capture current combination for the spawned task
		let task_combo = current_map.combination.clone();
		let task_constants = current_map.constants.clone();
		let is_last = current_map.out_of_mutations;

		// Spawn mutate + analyze as a single parallel task (matches Go's goroutine approach)
		scope.spawn(move |_| {
			if ctx.all_resolved() {
				return;
			}
			let task_map = MutationMap {
				out_of_mutations: true,
				constants: task_constants,
				mutations: vec![],
				combination: task_combo,
				depth_index: vec![],
			};
			let result = verify_active_mutate_principal_state(
				km,
				ps_base.clone_for_stage(true),
				attacker,
				&task_map,
			);
			if result.is_worthwhile {
				worthwhile_mutation_count.fetch_add(1, Ordering::SeqCst);
				if crate::tui::tui_enabled() {
					let desc: String = task_map
						.constants
						.iter()
						.zip(task_map.combination.iter())
						.map(|(c, v)| format!("{} <- {}", c.name, v))
						.collect::<Vec<_>>()
						.join(", ");
					crate::tui::tui_mutation_detail(&desc);
				}
				if !ctx.all_resolved() {
					// Phase 2: Knowledge closure on the (possibly truncated) state.
					let _ = verify_analysis(ctx, km, &result.state, depth as i32);
				}
				if !ctx.all_resolved() {
					// Phase 3: Query evaluation.
					let _ = verify_resolve_queries(ctx, km, &result.state);
				}
				// If truncation occurred and the attacker learned enough
				// to bypass the guards, attempt guard bypass.
				process_mutation_bypass(ctx, km, &result);
			}
		});

		if is_last {
			break;
		}
		current_map = current_map.next();
	}
}

// ── Sequential (non-rayon) fallback for WASM ────────────────────────────────

#[cfg(not(feature = "cli"))]
#[allow(clippy::too_many_arguments)]
fn verify_active_scan_weighted_seq(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps_base: &PrincipalState,
	attacker: &AttackerState,
	mm: MutationMap,
	depth: usize,
	worthwhile_mutation_count: &AtomicU32,
) {
	let n = mm.constants.len();
	if n == 0 {
		return;
	}
	let budget_used = AtomicU32::new(0);
	let budget = CONFIG.max_scan_budget;
	let max_weight = depth.min(n);

	for weight in 1..=max_weight {
		if ctx.all_resolved() || budget_used.load(Ordering::SeqCst) >= budget {
			break;
		}
		verify_active_scan_at_weight_seq(
			ctx,
			km,
			ps_base,
			attacker,
			&mm,
			depth,
			worthwhile_mutation_count,
			n,
			weight,
			&budget_used,
			budget,
		);
	}

	if !ctx.all_resolved()
		&& budget_used.load(Ordering::SeqCst) < budget
		&& mutation_product(
			mm.mutations.iter().map(|m| m.len()),
			CONFIG.max_full_product,
		)
		.is_some()
	{
		verify_active_scan_seq(
			ctx,
			km,
			ps_base,
			attacker,
			mm.next(),
			depth,
			worthwhile_mutation_count,
		);
	}
}

#[cfg(not(feature = "cli"))]
#[allow(clippy::too_many_arguments)]
fn verify_active_scan_at_weight_seq(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps_base: &PrincipalState,
	attacker: &AttackerState,
	mm: &MutationMap,
	depth: usize,
	worthwhile_mutation_count: &AtomicU32,
	n: usize,
	weight: usize,
	budget_used: &AtomicU32,
	budget: u32,
) {
	let mut indices: Vec<usize> = (0..weight).collect();
	let mut scanned: usize = 0;
	loop {
		if ctx.all_resolved() || budget_used.load(Ordering::SeqCst) >= budget {
			return;
		}
		let sub_indices = indices.clone();
		if weight == 1 {
			let sub_map = mm.subset_capped(&sub_indices, CONFIG.max_weight1_mutations);
			let cost = sub_map.mutations[0].len() as u32;
			budget_used.fetch_add(cost, Ordering::SeqCst);
			verify_active_scan_seq(
				ctx,
				km,
				ps_base,
				attacker,
				sub_map.next(),
				depth,
				worthwhile_mutation_count,
			);
			scanned += 1;
		} else if let Some(product) = mutation_product(
			indices.iter().map(|&i| mm.mutations[i].len()),
			CONFIG.max_mutations_per_subset,
		) {
			let sub_map = mm.subset(&sub_indices);
			budget_used.fetch_add(product as u32, Ordering::SeqCst);
			verify_active_scan_seq(
				ctx,
				km,
				ps_base,
				attacker,
				sub_map.next(),
				depth,
				worthwhile_mutation_count,
			);
			scanned += 1;
		}
		if scanned >= CONFIG.max_subsets_per_weight {
			return;
		}
		let mut advanced = false;
		for i in (0..weight).rev() {
			indices[i] += 1;
			if indices[i] <= n - weight + i {
				for j in (i + 1)..weight {
					indices[j] = indices[j - 1] + 1;
				}
				advanced = true;
				break;
			}
		}
		if !advanced {
			break;
		}
	}
}

#[cfg(not(feature = "cli"))]
#[allow(clippy::too_many_arguments)]
fn verify_active_scan_seq(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps_base: &PrincipalState,
	attacker: &AttackerState,
	mm: MutationMap,
	depth: usize,
	worthwhile_mutation_count: &AtomicU32,
) {
	let mut current_map = mm;
	loop {
		if ctx.all_resolved() {
			break;
		}
		let task_combo = current_map.combination.clone();
		let task_constants = current_map.constants.clone();
		let is_last = current_map.out_of_mutations;

		let task_map = MutationMap {
			out_of_mutations: true,
			constants: task_constants,
			mutations: vec![],
			combination: task_combo,
			depth_index: vec![],
		};
		let result = verify_active_mutate_principal_state(
			km,
			ps_base.clone_for_stage(true),
			attacker,
			&task_map,
		);
		if result.is_worthwhile {
			worthwhile_mutation_count.fetch_add(1, Ordering::SeqCst);
			if !ctx.all_resolved() {
				let _ = verify_analysis(ctx, km, &result.state, depth as i32);
			}
			if !ctx.all_resolved() {
				let _ = verify_resolve_queries(ctx, km, &result.state);
			}
			process_mutation_bypass(ctx, km, &result);
		}

		if is_last {
			break;
		}
		current_map = current_map.next();
	}
}

/// Try to rewrite a value if it is a Primitive, returning the rewritten value
/// only if the result is also a Primitive. Otherwise returns None.
fn try_rewrite_primitive(v: &Value, ps: &PrincipalState) -> Option<Value> {
	let p = v.as_primitive()?;
	let (_, rv) = can_rewrite(p, ps, 0);
	rv.into_iter()
		.next()
		.filter(|v| matches!(v, Value::Primitive(_)))
}

/// Result of mutating a principal state and checking for worthwhile mutations.
struct MutationResult {
	/// The (possibly truncated) principal state after mutation and rewriting.
	state: PrincipalState,
	/// Whether any mutation produced a value structurally different from the original.
	is_worthwhile: bool,
	/// If truncation occurred due to failed guards, the full pre-truncation state
	/// and the failed guard info are saved for a potential second-pass analysis
	/// (where the attacker tries to bypass the guards with known keys).
	guard_bypass: Option<GuardBypassInfo>,
}

/// Saved state for attempting guard bypass in a second pass.
struct GuardBypassInfo {
	/// Full (non-truncated) pre-resolution principal state.
	full_state: PrincipalState,
	/// Guards that failed and may be bypassable.
	failed_guards: Vec<FailedGuardInfo>,
}

fn verify_active_mutate_principal_state(
	km: &ProtocolTrace,
	mut ps: PrincipalState,
	attacker: &AttackerState,
	mutation_map: &MutationMap,
) -> MutationResult {
	let mut earliest_mutation = ps.meta.len();
	let mut is_worthwhile_mutation = false;
	let attacker_id = ATTACKER_ID;

	for (constant, combo) in mutation_map
		.constants
		.iter()
		.zip(mutation_map.combination.iter())
	{
		let (resolved_assigned, slot_idx) = ps.resolve_constant(constant, true);
		let slot_idx = match slot_idx {
			Some(i) => i,
			None => continue,
		};
		let mut combo_value = combo.clone();
		let (trace_resolved, _) = resolve_trace_values(&resolved_assigned, km);

		// If trace_resolved is a primitive, try to rewrite it
		let trace_resolved = try_rewrite_primitive(&trace_resolved, &ps).unwrap_or(trace_resolved);

		// If combo_value is a primitive, try to rewrite and copy output/instance_check from original
		if let Value::Primitive(_) = &combo_value {
			if let Some(v) = try_rewrite_primitive(&combo_value, &ps) {
				combo_value = v;
			}
			if let Value::Primitive(orig_p) = &resolved_assigned {
				if let Some(combo_p) = combo_value.as_primitive_mut() {
					combo_p.output = orig_p.output;
					combo_p.instance_check = orig_p.instance_check;
				}
			}
		}

		let worthwhile = !combo_value.equivalent(&trace_resolved, true);

		ps.values[slot_idx].original = ps.values[slot_idx].value.clone();
		ps.values[slot_idx].provenance.creator = attacker_id;
		ps.values[slot_idx].provenance.sender = attacker_id;
		ps.values[slot_idx].provenance.attacker_tainted = true;
		ps.values[slot_idx].pre_rewrite = combo_value.clone();
		ps.values[slot_idx].value = combo_value;

		if slot_idx < earliest_mutation {
			earliest_mutation = slot_idx;
		}

		if worthwhile {
			is_worthwhile_mutation = true;
		}
	}

	if !is_worthwhile_mutation {
		return MutationResult {
			state: ps,
			is_worthwhile: false,
			guard_bypass: None,
		};
	}

	let ps_pre = ps.clone();
	let _ = ps.resolve_all_values(attacker);
	let failures = ps.perform_all_rewrites();
	let (failed_guards, truncation_index, truncation_failed_idx) =
		classify_rewrite_failures(&ps, &failures);

	if let Some(trunc_at) = truncation_index {
		let failed_idx = truncation_failed_idx.unwrap_or(0);
		let guard_bypass = if !failed_guards.is_empty() {
			Some(GuardBypassInfo {
				full_state: ps_pre,
				failed_guards,
			})
		} else {
			None
		};
		ps = verify_active_drop_principal_state_after_index(ps, trunc_at);
		return MutationResult {
			state: ps,
			is_worthwhile: is_worthwhile_mutation && earliest_mutation < failed_idx,
			guard_bypass,
		};
	}

	MutationResult {
		state: ps,
		is_worthwhile: is_worthwhile_mutation,
		guard_bypass: None,
	}
}

/// Extract the key/secret that the attacker would need to know in order to
/// craft an input that bypasses a failed guarded primitive.
/// Delegates to the bypass_key spec defined in PrimitiveSpec.
fn extract_bypass_key(prim: &Primitive) -> Option<Value> {
	primitive_extract_bypass_key(prim)
}

/// Check if the attacker can bypass at least one failed guard.  We only
/// require ONE guard to be immediately bypassable because `build_bypass_state`
/// iterates: injecting G^nil into the first bypassable guards may change
/// downstream keys enough to make later guards bypassable too.
fn can_attacker_bypass_any_guard(
	guards: &[FailedGuardInfo],
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> bool {
	guards
		.iter()
		.any(|guard| attacker_can_obtain_value(&guard.bypass_key, ps, attacker))
}

/// Check if the attacker can obtain a value: either it is already in their
/// known set, or they can reconstruct it from known values.
fn attacker_can_obtain_value(v: &Value, ps: &PrincipalState, attacker: &AttackerState) -> bool {
	if attacker.knows(v).is_some() {
		return true;
	}
	match v {
		Value::Primitive(p) => can_reconstruct_primitive(p, ps, attacker, 0).is_some(),
		Value::Equation(e) => can_reconstruct_equation(e, attacker).is_some(),
		_ => false,
	}
}

/// Targeted bypass analysis: add wire values from the bypass state to attacker
/// knowledge (representing the attacker intercepting modified outputs), try to
/// decompose them (to extract secrets like encrypted plaintexts), and resolve
/// queries.  This avoids the full `verify_analysis` loop which causes a
/// combinatorial explosion of reconstruction attempts on the large bypass state.
fn verify_bypass_decompose(ctx: &VerifyContext, km: &ProtocolTrace, ps: &PrincipalState) {
	// Collect wire primitive values from the bypass state for
	// decomposition.  We intentionally do NOT add all wire values to
	// attacker knowledge here — adding structurally different but
	// semantically equivalent values can bloat the injection engine.
	// Instead we only add values that decomposition actually reveals.
	let wire_prims: Vec<(Value, usize)> = ps
		.meta
		.iter()
		.zip(ps.values.iter())
		.enumerate()
		.filter_map(|(i, (sm, sv))| {
			if sm.wire.is_empty() {
				return None;
			}
			if let Value::Primitive(_) = &sv.value {
				Some((sv.value.clone(), i))
			} else {
				None
			}
		})
		.collect();

	let record = compute_slot_diffs(ps, km);

	// Iteratively decompose wire values until no new deductions.
	// Capped at 8 iterations because each round can only reveal values
	// hidden behind one layer of encryption; real protocols rarely nest
	// more than 3-4 layers deep, and 8 provides comfortable headroom.
	for _ in 0..8 {
		if ctx.all_resolved() {
			return;
		}
		let attacker_snap = ctx.attacker_snapshot();
		let mut found_new = false;
		for (wv, _idx) in &wire_prims {
			if let Value::Primitive(p) = wv {
				// Active decompose (e.g. AEAD_ENC: knowing the key reveals plaintext)
				if let Some(result) = can_decompose(p, ps, &attacker_snap, 0) {
					if ctx.attacker_put(&result.revealed, &record) {
						info_message(
							&format!(
								"{} obtained by decomposing {} with {}.",
								info_output_text(&result.revealed),
								wv,
								pretty_values(&result.used),
							),
							InfoLevel::Deduction,
							true,
						);
						found_new = true;
					}
				}
				// Passive decompose (e.g. associated data from AEAD_ENC)
				let passive = passively_decompose(p);
				for pv in &passive {
					if ctx.attacker_put(pv, &record) {
						found_new = true;
					}
				}
			}
		}
		if !found_new {
			break;
		}
	}

	let _ = verify_resolve_queries(ctx, km, ps);
}

/// Build a new PrincipalState from the full (non-truncated) state by injecting
/// attacker-controlled values (`G^nil`) into slots where guarded primitives
/// failed their rewrite but the attacker could bypass the guard (knows the key).
/// Iterates to handle cascading guard failures (e.g. a later AEAD_DEC whose
/// key depends on an earlier bypassed guard).
fn build_bypass_state(
	ps_full: &PrincipalState,
	initial_guards: &[FailedGuardInfo],
	attacker: &AttackerState,
) -> Option<PrincipalState> {
	let mut ps = ps_full.clone();

	// Round 1: inject G^nil only into guards whose keys are currently obtainable.
	// We must inject into assigned, before_rewrite AND before_mutate because
	// resolve_all_values uses before_mutate (not assigned)
	// for values created by the principal itself (which guarded primitives are).
	let mut any_injected = false;
	for guard in initial_guards {
		if attacker_can_obtain_value(&guard.bypass_key, &ps, attacker) {
			ps.values[guard.assigned_index].override_all(value_g_nil());
			any_injected = true;
		}
	}
	if !any_injected {
		return None;
	}

	// Iteratively re-resolve, re-rewrite, and inject into new bypassable guards.
	// Capped at 5 because each iteration can only cascade through one additional
	// guard dependency (e.g. AEAD_DEC whose key was derived from a previous
	// bypassed guard).  Protocol models with >5 chained guard dependencies are
	// extremely rare.
	let mut needs_final_resolve = false;
	for _ in 0..5 {
		let _ = ps.resolve_all_values(attacker);
		let failures = ps.perform_all_rewrites();

		needs_final_resolve = false;
		for &(ref prim, idx) in &failures {
			if !prim.instance_check || ps.values[idx].provenance.creator != ps.id {
				continue;
			}
			if let Some(key) = extract_bypass_key(prim) {
				if attacker_can_obtain_value(&key, &ps, attacker) {
					ps.values[idx].override_all(value_g_nil());
					needs_final_resolve = true;
				}
			}
		}
		if !needs_final_resolve {
			break;
		}
	}

	// If we injected in the last iteration, finalize the state.
	if needs_final_resolve {
		let _ = ps.resolve_all_values(attacker);
		let _ = ps.perform_all_rewrites();
	}

	Some(ps)
}

fn verify_active_drop_principal_state_after_index(
	mut ps: PrincipalState,
	f: usize,
) -> PrincipalState {
	Arc::make_mut(&mut ps.meta).truncate(f);
	ps.values.truncate(f);
	ps
}
