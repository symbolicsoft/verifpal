/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::construct::construct_principal_state_clone;
use crate::context::VerifyContext;
use crate::info::{info_message, info_output_text};
use crate::mutationmap::{mutation_map_subset_capped, mutation_product};
use crate::possible::{
	can_decompose, passively_decompose,
	can_reconstruct_equation, can_reconstruct_primitive, can_rewrite,
};
use crate::pretty::pretty_values;
use crate::primitive::*;
use crate::principal::ATTACKER_ID;
use crate::types::*;
use crate::value::{
	compute_slot_diffs, resolve_trace_values, value_g_nil,
};
use crate::verify::{verify_resolve_queries, verify_standard_run};
use crate::verifyanalysis::verify_analysis;

/// Information about a guarded primitive that failed its rewrite and caused
/// (or would cause) truncation of the principal state.
#[derive(Clone)]
struct FailedGuardInfo {
	/// The resolved key/secret argument that the attacker would need to know
	/// in order to craft an input that bypasses this guard.
	bypass_key: Value,
	/// Index into the PrincipalState.assigned array for this guard.
	assigned_index: usize,
}

/// Budget parameters controlling the active attacker's search strategy.
///
/// These values are tuned empirically against the Verifpal test suite and
/// real-world protocol models.  The goal is to explore enough of the mutation
/// space to find attacks in common protocols (TLS, Signal, Noise, etc.) while
/// keeping verification of typical models under a few seconds.
struct StageBudget {
	/// Stages beyond this threshold are considered for exhaustion detection.
	/// Set to 6 because stages 1-5 already cover single-variable mutations,
	/// explosive primitives, recursive injection, and expanded mutation maps.
	/// If no new knowledge is gained after all of those, further stages are
	/// unlikely to produce results.
	exhaustion_threshold: i32,
	/// Maximum stage number.  At 10 the search has explored single-variable
	/// through 3-variable mutations across all principals, with recursive
	/// injection active from stage 5+.  Real attacks in published protocols
	/// are consistently found before stage 8.
	max_stage: i32,
	/// Maximum subset weight (number of simultaneous variable mutations).
	/// Weight 1 = single-variable, weight 2 = pairs, weight 3 = triples.
	/// Beyond triples the combinatorial cost grows faster than the
	/// likelihood of finding real attacks.
	max_subset_weight: usize,
	/// Maximum number of subsets to scan per weight level.  Limits the
	/// number of k-subsets of n constants we actually evaluate (since C(n,k)
	/// can be very large for models with many constants).
	max_subsets_per_weight: usize,
	/// Cap on mutations per variable at weight 1 (single-variable scan).
	/// Single-variable mutations are cheap to evaluate so we allow more of
	/// them than multi-variable combinations.
	max_weight1_mutations: usize,
	/// Maximum mutation product for any multi-variable subset scan.
	/// Prevents combinatorial explosion when two or more variables each
	/// have many possible mutations (e.g. 200 x 200 = 40k is fine,
	/// 200 x 200 x 200 = 8M is not).
	max_mutations_per_subset: usize,
	/// Maximum total mutation product for the full cross-product scan
	/// that runs after all weighted scans.  Same rationale as above.
	max_full_product: usize,
	/// Per-principal scan budget (total mutations across all weights).
	/// Ensures that a single principal with many mutable constants doesn't
	/// dominate the search time at the expense of other principals.
	max_scan_budget: u32,
}

const BUDGET: StageBudget = StageBudget {
	exhaustion_threshold: 6,
	max_stage: 10,
	max_subset_weight: 3,
	max_subsets_per_weight: 150,
	max_weight1_mutations: 150,
	max_mutations_per_subset: 50000,
	max_full_product: 50000,
	max_scan_budget: 80000,
};

pub(crate) fn verify_active(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	principal_states: &[PrincipalState],
) -> VResult<()> {
	info_message("Attacker is configured as active.", InfoLevel::Info, false);
	for phase in 0..=km.max_phase {
		info_message(&format!("Running at phase {}.", phase), InfoLevel::Info, false);
		ctx.attacker_init();
		let mut ps_pure_resolved = construct_principal_state_clone(&principal_states[0], true);
		ps_pure_resolved.resolve_all_values(&ctx.attacker_snapshot())?;
		ctx.attacker_phase_update(km, &ps_pure_resolved, phase)?;
		verify_standard_run(ctx, km, principal_states, 0)?;

		// Targeted MitM bypass: try replacing equation-valued wire inputs
		// with G^nil (attacker's own public key).
		if !ctx.all_resolved() {
			verify_active_equation_bypass(ctx, km, principal_states);
		}

		// Stage 1 (serial — builds initial attacker knowledge)
		verify_active_stages(ctx, 1, km, principal_states);

		// Stages 2+ in parallel pairs until resolved or exhausted
		let mut stage = 2;
		while !ctx.all_resolved() && !ctx.attacker_is_exhausted() && stage <= BUDGET.max_stage {
			if stage < BUDGET.max_stage {
				rayon::scope(|s| {
					s.spawn(|_| verify_active_stages(ctx, stage, km, principal_states));
					s.spawn(|_| verify_active_stages(ctx, stage + 1, km, principal_states));
				});
				stage += 2;
			} else {
				verify_active_stages(ctx, stage, km, principal_states);
				stage += 1;
			}
		}
	}
	Ok(())
}

/// Inject an attacker-controlled replacement value into a PrincipalState slot,
/// marking it as attacker-created and mutated.
fn inject_attacker_value(sv: &mut SlotValues, attacker_id: PrincipalId, replacement: &Value) {
	sv.creator = attacker_id;
	sv.sender = attacker_id;
	sv.mutated = true;
	sv.assigned = replacement.clone();
	sv.before_rewrite = replacement.clone();
}

/// Targeted MitM public-key replacement attack.  For each principal, try
/// replacing each equation-valued wire input (received public key) with G^nil
/// — the attacker's own public key — one at a time, then check if the
/// resulting guard failures can be bypassed (because the attacker knows the
/// private key `nil`).
///
/// We also try replacing ALL equation wire inputs simultaneously, because some
/// protocols derive keys from multiple DH exchanges and the attacker may need
/// to control all of them.
///
/// This is much faster than brute-force mutation because it directly tests the
/// canonical MitM strategy without relying on G^nil being in the mutation map.
fn verify_active_equation_bypass(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	principal_states: &[PrincipalState],
) {
	let g_nil = value_g_nil();
	let attacker_id = ATTACKER_ID;

	for ps_base in principal_states {
		if ctx.all_resolved() {
			return;
		}

		let attacker = ctx.attacker_snapshot();

		// Collect indices of equation-valued constants received from other
		// principals (these are public keys the attacker can intercept).
		// Skip guarded constants (sent in [brackets]) — the attacker can
		// read them but cannot tamper with them.
		// Skip constants not communicated in the current phase — the attacker
		// can only manipulate values in the phase they were communicated.
		let eq_indices: Vec<usize> = ps_base
			.meta
			.iter()
			.zip(ps_base.values.iter())
			.enumerate()
			.filter_map(|(i, (sm, sv))| {
				if sv.creator == ps_base.id || sm.guard || !sm.phase.contains(&attacker.current_phase) {
					return None;
				}
				if let Value::Equation(_) = &sv.assigned {
					Some(i)
				} else {
					None
				}
			})
			.collect();
		if eq_indices.is_empty() {
			continue;
		}

		// Try replacing each equation wire input individually.
		for &target_idx in &eq_indices {
			if ctx.all_resolved() {
				return;
			}
			let mut ps = construct_principal_state_clone(ps_base, true);
			inject_attacker_value(&mut ps.values[target_idx], attacker_id, &g_nil);
			verify_active_try_equation_bypass_on_state(ctx, km, &mut ps, &attacker);
		}

		// If there are multiple equation wire inputs, also try replacing
		// all of them simultaneously (full MitM on all public keys).
		if eq_indices.len() > 1 && !ctx.all_resolved() {
			let mut ps = construct_principal_state_clone(ps_base, true);
			for &i in &eq_indices {
				inject_attacker_value(&mut ps.values[i], attacker_id, &g_nil);
			}
			verify_active_try_equation_bypass_on_state(ctx, km, &mut ps, &attacker);
		}
	}
}

/// Helper: resolve, rewrite, collect failed guards, and attempt bypass on
/// a mutated principal state.
fn verify_active_try_equation_bypass_on_state(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &mut PrincipalState,
	attacker: &AttackerState,
) {
	// Save pre-resolution state: constants still have symbolic references
	// that will properly propagate injected values during re-resolution
	// inside build_bypass_state.  After resolution, constants are inlined
	// and injected values wouldn't propagate to downstream computations.
	let ps_pre = ps.clone();

	let _ = ps.resolve_all_values(attacker);
	let failures = ps.perform_all_rewrites();

	let mut failed_guards: Vec<FailedGuardInfo> = Vec::new();
	for &(ref prim, idx) in &failures {
		if !prim.instance_check || ps.values[idx].creator != ps.id {
			continue;
		}
		if let Some(key) = extract_bypass_key(prim) {
			failed_guards.push(FailedGuardInfo {
				bypass_key: key,
				assigned_index: idx,
			});
		}
	}

	if failed_guards.is_empty() {
		return;
	}
	if !can_attacker_bypass_any_guard(&failed_guards, ps, attacker) {
		return;
	}

	if let Some(ps_injected) = build_bypass_state(&ps_pre, &failed_guards, attacker) {
		verify_bypass_decompose(ctx, km, &ps_injected);
	}
}

fn verify_active_stages(
	ctx: &VerifyContext,
	stage: i32,
	km: &ProtocolTrace,
	principal_states: &[PrincipalState],
) {
	if crate::tui::tui_enabled() {
		crate::tui::tui_stage_update(stage);
	}
	let worthwhile_mutation_count = AtomicU32::new(0);
	let old_known = ctx.attacker_known_count();
	let attacker = ctx.attacker_snapshot();

	// Process all principals in parallel within a single rayon scope.
	// Each principal is spawned as a task; analyses from all principals/weights overlap.
	rayon::scope(|s| {
		for ps_base in principal_states {
			s.spawn(|s_inner| {
				let mm = match MutationMap::new(ctx, km, ps_base, &attacker, stage) {
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
					stage,
					&worthwhile_mutation_count,
				);
			});
		}
	});

	let worthwhile = worthwhile_mutation_count.load(Ordering::SeqCst);
	let stagnant = worthwhile == 0 || old_known == ctx.attacker_known_count();
	let exhausted = stage > BUDGET.exhaustion_threshold && (stagnant || stage > BUDGET.max_stage);
	if exhausted {
		ctx.attacker_set_exhausted();
	}
}

#[allow(clippy::too_many_arguments)]
fn verify_active_scan_weighted<'s>(
	ctx: &'s VerifyContext,
	scope: &rayon::Scope<'s>,
	km: &'s ProtocolTrace,
	ps_base: &'s PrincipalState,
	attacker: &'s AttackerState,
	mm: MutationMap,
	stage: i32,
	worthwhile_mutation_count: &'s AtomicU32,
) {
	let n = mm.constants.len();
	if n == 0 {
		return;
	}
	let budget_used = AtomicU32::new(0);
	let budget = BUDGET.max_scan_budget;
	let max_weight = BUDGET.max_subset_weight.min(n);
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
			stage,
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
			BUDGET.max_full_product,
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
			stage,
			worthwhile_mutation_count,
		);
	}
}

#[allow(clippy::too_many_arguments)]
fn verify_active_scan_at_weight<'s>(
	ctx: &'s VerifyContext,
	scope: &rayon::Scope<'s>,
	km: &'s ProtocolTrace,
	ps_base: &'s PrincipalState,
	attacker: &'s AttackerState,
	mm: &MutationMap,
	stage: i32,
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
			let sub_map =
				mutation_map_subset_capped(mm, &sub_indices, BUDGET.max_weight1_mutations);
			let cost = sub_map.mutations[0].len() as u32;
			let bu = budget_used.fetch_add(cost, Ordering::SeqCst);
			if crate::tui::tui_enabled() && bu % 500 < cost {
				crate::tui::tui_scan_update(
					&ps_base.name,
					weight,
					n.min(BUDGET.max_subset_weight),
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
				stage,
				worthwhile_mutation_count,
			);
			scanned += 1;
		} else if let Some(product) = mutation_product(
			indices.iter().map(|&i| mm.mutations[i].len()),
			BUDGET.max_mutations_per_subset,
		) {
			let sub_map = mm.subset(&sub_indices);
			let bu = budget_used.fetch_add(product as u32, Ordering::SeqCst);
			if crate::tui::tui_enabled() && bu % 500 < product as u32 {
				crate::tui::tui_scan_update(
					&ps_base.name,
					weight,
					n.min(BUDGET.max_subset_weight),
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
				stage,
				worthwhile_mutation_count,
			);
			scanned += 1;
		}

		if scanned >= BUDGET.max_subsets_per_weight {
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

#[allow(clippy::too_many_arguments)]
fn verify_active_scan<'s>(
	ctx: &'s VerifyContext,
	scope: &rayon::Scope<'s>,
	km: &'s ProtocolTrace,
	ps_base: &'s PrincipalState,
	attacker: &'s AttackerState,
	mm: MutationMap,
	stage: i32,
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
					construct_principal_state_clone(ps_base, true),
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
					// Pass 1: analyze the (possibly truncated) state.
					let _ = verify_analysis(ctx, km, &result.state, stage);
				}
				// Pass 2: if truncation occurred and the attacker learned
				// enough to bypass the guards, inject attacker-controlled
				// values into the full state, decompose wire values, and
				// resolve queries.  We avoid running full verify_analysis
				// on the large bypass state to prevent reconstruction
				// explosion.
				if !ctx.all_resolved() {
					if let Some(ref bypass) = result.guard_bypass {
						let attacker_now = ctx.attacker_snapshot();
						if can_attacker_bypass_any_guard(&bypass.failed_guards, &bypass.full_state, &attacker_now) {
							if let Some(ps_injected) =
								build_bypass_state(&bypass.full_state, &bypass.failed_guards, &attacker_now)
							{
								verify_bypass_decompose(ctx, km, &ps_injected);
							}
						}
					}
				}
			}
		});

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

	for (constant, combo) in mutation_map.constants.iter().zip(mutation_map.combination.iter()) {
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

		ps.values[slot_idx].creator = attacker_id;
		ps.values[slot_idx].sender = attacker_id;
		ps.values[slot_idx].mutated = true;
		ps.values[slot_idx].before_rewrite = combo_value.clone();
		ps.values[slot_idx].assigned = combo_value;

		if slot_idx < earliest_mutation {
			earliest_mutation = slot_idx;
		}

		if worthwhile {
			is_worthwhile_mutation = true;
		}
	}

	if !is_worthwhile_mutation {
		return MutationResult { state: ps, is_worthwhile: false, guard_bypass: None };
	}

	let ps_pre = ps.clone();
	let _ = ps.resolve_all_values(attacker);
	let failures = ps.perform_all_rewrites();

	// Collect all failed guards and extract the bypass keys before truncating.
	let mut failed_guards: Vec<FailedGuardInfo> = Vec::new();
	let mut truncation_index: Option<usize> = None;
	let mut truncation_failed_idx: Option<usize> = None;

	for &(ref prim, idx) in &failures {
		if !prim.instance_check || ps.values[idx].creator != ps.id {
			continue;
		}
		// Extract the bypass key for this failed guard.
		if let Some(key) = extract_bypass_key(prim) {
			failed_guards.push(FailedGuardInfo {
				bypass_key: key,
				assigned_index: idx,
			});
		}
		// Determine the truncation point (same logic as before).
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

	if let Some(trunc_at) = truncation_index {
		let failed_idx = truncation_failed_idx.unwrap_or(0);
		let guard_bypass = if !failed_guards.is_empty() {
			Some(GuardBypassInfo { full_state: ps_pre, failed_guards })
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

	MutationResult { state: ps, is_worthwhile: is_worthwhile_mutation, guard_bypass: None }
}

/// Extract the key/secret that the attacker would need to know in order to
/// craft an input that bypasses a failed guarded primitive.
///
/// - AEAD_DEC(key, ct, ad): bypass key = key (arg 0)
/// - DEC(key, ct): bypass key = key (arg 0)
/// - PKE_DEC(sk, ct): bypass key = sk (arg 0)
/// - SIGNVERIF(pk, msg, sig): bypass key = private key from pk.
///   If pk = G^sk, the bypass key is sk.
/// - ASSERT, SPLIT, SHAMIR_JOIN, RINGSIGNVERIF, UNBLIND:
///   not handled (returns None).
fn extract_bypass_key(prim: &Primitive) -> Option<Value> {
	match prim.id {
		PRIM_AEAD_DEC | PRIM_DEC | PRIM_PKE_DEC => {
			// Key is argument 0.
			Some(prim.arguments[0].clone())
		}
		PRIM_SIGNVERIF | PRIM_RINGSIGNVERIF => {
			// Public key is argument 0. For G^sk or G^a^b, the bypass key is the last exponent.
			if let Value::Equation(e) = &prim.arguments[0] {
				if e.values.len() >= 2 {
					return Some(e.values[e.values.len() - 1].clone());
				}
			}
			None
		}
		_ => None,
	}
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
		Value::Primitive(p) => {
			let (ok, _) = can_reconstruct_primitive(p, ps, attacker, 0);
			ok
		}
		Value::Equation(e) => {
			let (ok, _) = can_reconstruct_equation(e, attacker);
			ok
		}
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
			if let Value::Primitive(_) = &sv.assigned {
				Some((sv.assigned.clone(), i))
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
				let (r, revealed, ar) = can_decompose(p, ps, &attacker_snap, 0);
				if r && ctx.attacker_put(&revealed, &record) {
					info_message(
						&format!(
							"{} obtained by decomposing {} with {}.",
							info_output_text(&revealed),
							wv,
							pretty_values(&ar),
						),
						InfoLevel::Deduction,
						true,
					);
					found_new = true;
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
			if !prim.instance_check || ps.values[idx].creator != ps.id {
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
