/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::attackerstate::{
    attacker_state_get_exhausted, attacker_state_get_known_count, attacker_state_get_read,
    attacker_state_init, attacker_state_put_exhausted, attacker_state_put_phase_update,
    attacker_state_put_write,
};
use crate::construct::construct_principal_state_clone;
use crate::info::{info_message, info_output_text};
use crate::pretty::{pretty_value, pretty_values};
use crate::mutationmap::{
    mutation_map_init, mutation_map_next, mutation_map_subset, mutation_map_subset_capped,
};
use crate::possible::{
    possible_to_decompose_primitive, possible_to_passively_decompose_primitive,
    possible_to_reconstruct_equation, possible_to_reconstruct_primitive, possible_to_rewrite,
};
use crate::primitive::*;
use crate::principal::principal_get_attacker_id;
use crate::types::*;
use crate::value::{
    value_equivalent_value_in_values_map, value_equivalent_values, value_g_nil,
    value_perform_all_rewrites, value_resolve_all_principal_state_values, value_resolve_constant,
    value_resolve_value_internal_values_from_knowledge_map,
};
use crate::util::int_in_slice;
use crate::verify::{verify_resolve_queries, verify_standard_run};
use crate::verifyanalysis::verify_analysis;
use crate::verifyresults::verify_results_all_resolved;

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

const STAGE_EXHAUSTION_THRESHOLD: i32 = 6;
const MAX_STAGE_LIMIT: i32 = 10;
const MAX_SUBSET_MUTATION_WEIGHT: usize = 3;
const MAX_SUBSETS_PER_WEIGHT: usize = 150;
const MAX_WEIGHT1_MUTATIONS_PER_VAR: usize = 150;
const MAX_MUTATIONS_PER_SUBSET: usize = 50000;
const MAX_FULL_MUTATION_PRODUCT: usize = 50000;
const MAX_SCAN_BUDGET: u32 = 80000;

pub fn verify_active(
    val_knowledge_map: &KnowledgeMap,
    val_principal_states: &[PrincipalState],
) -> Result<(), String> {
    info_message("Attacker is configured as active.", "info", false);
    let mut phase = 0;
    while phase <= val_knowledge_map.max_phase {
        info_message(&format!("Running at phase {}.", phase), "info", false);
        attacker_state_init();
        let mut val_principal_state_pure_resolved =
            construct_principal_state_clone(&val_principal_states[0], true);
        value_resolve_all_principal_state_values(
            &mut val_principal_state_pure_resolved,
            &attacker_state_get_read(),
        )?;
        attacker_state_put_phase_update(
            val_knowledge_map,
            &val_principal_state_pure_resolved,
            phase,
        )?;
        verify_standard_run(val_knowledge_map, val_principal_states, 0)?;

        // Targeted MitM bypass: try replacing equation-valued wire inputs
        // with G^nil (attacker's own public key).
        if !verify_results_all_resolved() {
            verify_active_equation_bypass(val_knowledge_map, val_principal_states);
        }

        // Stage 1
        verify_active_stages(1, val_knowledge_map, val_principal_states, &attacker_state_get_read());

        // Stages 2-3 in parallel
        {
            let as_snap = attacker_state_get_read();
            rayon::scope(|s| {
                s.spawn(|_| {
                    verify_active_stages(2, val_knowledge_map, val_principal_states, &as_snap);
                });
                s.spawn(|_| {
                    verify_active_stages(3, val_knowledge_map, val_principal_states, &as_snap);
                });
            });
        }

        // Stages 4-5 in parallel
        {
            let as_snap = attacker_state_get_read();
            rayon::scope(|s| {
                s.spawn(|_| {
                    verify_active_stages(4, val_knowledge_map, val_principal_states, &as_snap);
                });
                s.spawn(|_| {
                    verify_active_stages(5, val_knowledge_map, val_principal_states, &as_snap);
                });
            });
        }

        // Stages 6+ in pairs until resolved or exhausted
        let mut stage = 6;
        while !verify_results_all_resolved() && !attacker_state_get_exhausted() {
            if stage < MAX_STAGE_LIMIT {
                let as_snap = attacker_state_get_read();
                rayon::scope(|s| {
                    s.spawn(|_| {
                        verify_active_stages(stage, val_knowledge_map, val_principal_states, &as_snap);
                    });
                    s.spawn(|_| {
                        verify_active_stages(stage + 1, val_knowledge_map, val_principal_states, &as_snap);
                    });
                });
                stage += 2;
            } else {
                let as_snap = attacker_state_get_read();
                verify_active_stages(stage, val_knowledge_map, val_principal_states, &as_snap);
                stage += 1;
            }
        }
        phase += 1;
    }
    Ok(())
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
    val_knowledge_map: &KnowledgeMap,
    val_principal_states: &[PrincipalState],
) {
    let g_nil = value_g_nil();
    let attacker_id = principal_get_attacker_id();

    for val_principal_state in val_principal_states {
        if verify_results_all_resolved() {
            return;
        }

        let as_ = attacker_state_get_read();

        // Collect indices of equation-valued constants received from other
        // principals (these are public keys the attacker can intercept).
        // Skip guarded constants (sent in [brackets]) — the attacker can
        // read them but cannot tamper with them.
        // Skip constants not communicated in the current phase — the attacker
        // can only manipulate values in the phase they were communicated.
        let mut eq_indices: Vec<usize> = Vec::new();
        for i in 0..val_principal_state.constants.len() {
            if val_principal_state.creator[i] == val_principal_state.id {
                continue;
            }
            if val_principal_state.guard[i] {
                continue;
            }
            if !int_in_slice(as_.current_phase, &val_principal_state.phase[i]) {
                continue;
            }
            if let Value::Equation(_) = &val_principal_state.assigned[i] {
                eq_indices.push(i);
            }
        }
        if eq_indices.is_empty() {
            continue;
        }

        // Try replacing each equation wire input individually.
        for &target_idx in &eq_indices {
            if verify_results_all_resolved() {
                return;
            }
            let mut ps = construct_principal_state_clone(val_principal_state, true);
            ps.creator[target_idx] = attacker_id;
            ps.sender[target_idx] = attacker_id;
            ps.mutated[target_idx] = true;
            ps.assigned[target_idx] = g_nil.clone();
            ps.before_rewrite[target_idx] = g_nil.clone();

            verify_active_try_equation_bypass_on_state(
                val_knowledge_map, &mut ps, &as_,
            );
        }

        // If there are multiple equation wire inputs, also try replacing
        // all of them simultaneously (full MitM on all public keys).
        if eq_indices.len() > 1 && !verify_results_all_resolved() {
            let mut ps = construct_principal_state_clone(val_principal_state, true);
            for &i in &eq_indices {
                ps.creator[i] = attacker_id;
                ps.sender[i] = attacker_id;
                ps.mutated[i] = true;
                ps.assigned[i] = g_nil.clone();
                ps.before_rewrite[i] = g_nil.clone();
            }
            verify_active_try_equation_bypass_on_state(
                val_knowledge_map, &mut ps, &as_,
            );
        }
    }
}

/// Helper: resolve, rewrite, collect failed guards, and attempt bypass on
/// a mutated principal state.
fn verify_active_try_equation_bypass_on_state(
    val_knowledge_map: &KnowledgeMap,
    ps: &mut PrincipalState,
    as_: &AttackerState,
) {
    // Save pre-resolution state: constants still have symbolic references
    // that will properly propagate injected values during re-resolution
    // inside build_bypass_state.  After resolution, constants are inlined
    // and injected values wouldn't propagate to downstream computations.
    let ps_pre = ps.clone();

    let _ = value_resolve_all_principal_state_values(ps, as_);
    let (failed_rewrites, failed_rewrite_indices) = value_perform_all_rewrites(ps);

    let mut failed_guards: Vec<FailedGuardInfo> = Vec::new();
    for j in 0..failed_rewrites.len() {
        if !failed_rewrites[j].check {
            continue;
        }
        if ps.creator[failed_rewrite_indices[j]] != ps.id {
            continue;
        }
        if let Some(key) = extract_bypass_key(&failed_rewrites[j], ps) {
            failed_guards.push(FailedGuardInfo {
                bypass_key: key,
                assigned_index: failed_rewrite_indices[j],
            });
        }
    }

    if failed_guards.is_empty() {
        return;
    }
    if !can_attacker_bypass_any_guard(&failed_guards, ps, as_) {
        return;
    }

    if let Some(ps_injected) = build_bypass_state(&ps_pre, &failed_guards, as_) {
        verify_bypass_decompose(val_knowledge_map, &ps_injected);
    }
}

fn verify_active_stages(
    stage: i32,
    val_knowledge_map: &KnowledgeMap,
    val_principal_states: &[PrincipalState],
    val_attacker_state: &AttackerState,
) {
    if crate::tui::tui_enabled() {
        crate::tui::tui_stage_update(stage);
    }
    let worthwhile_mutation_count = AtomicU32::new(0);
    let old_known = val_attacker_state.known.len();
    let val_attacker_state = attacker_state_get_read();

    // Process all principals in parallel within a single rayon scope.
    // Each principal is spawned as a task; analyses from all principals/weights overlap.
    rayon::scope(|s| {
        for val_principal_state in val_principal_states {
            s.spawn(|s_inner| {
                let val_mutation_map = match mutation_map_init(
                    val_knowledge_map,
                    val_principal_state,
                    &val_attacker_state,
                    stage,
                ) {
                    Ok(mm) => mm,
                    Err(_) => return,
                };
                verify_active_scan_weighted(
                    s_inner,
                    val_knowledge_map,
                    val_principal_state,
                    &val_attacker_state,
                    val_mutation_map,
                    stage,
                    &worthwhile_mutation_count,
                );
            });
        }
    });

    let worthwhile = worthwhile_mutation_count.load(Ordering::SeqCst);
    let stagnant = worthwhile == 0 || old_known == attacker_state_get_known_count();
    let exhausted = stage > STAGE_EXHAUSTION_THRESHOLD && (stagnant || stage > MAX_STAGE_LIMIT);
    if exhausted {
        attacker_state_put_exhausted();
    }
}

fn verify_active_scan_weighted<'s>(
    scope: &rayon::Scope<'s>,
    val_knowledge_map: &'s KnowledgeMap,
    val_principal_state: &'s PrincipalState,
    val_attacker_state: &'s AttackerState,
    val_mutation_map: MutationMap,
    stage: i32,
    worthwhile_mutation_count: &'s AtomicU32,
) {
    let n = val_mutation_map.constants.len();
    if n == 0 {
        return;
    }
    let budget_used = AtomicU32::new(0);
    let budget = MAX_SCAN_BUDGET;
    let mut max_weight = MAX_SUBSET_MUTATION_WEIGHT;
    if max_weight > n {
        max_weight = n;
    }
    if crate::tui::tui_enabled() {
        crate::tui::tui_scan_update(&val_principal_state.name, 0, max_weight, 0, budget);
    }

    for weight in 1..=max_weight {
        if verify_results_all_resolved() {
            break;
        }
        if budget_used.load(Ordering::SeqCst) >= budget {
            break;
        }
        verify_active_scan_at_weight(
            scope,
            val_knowledge_map,
            val_principal_state,
            val_attacker_state,
            &val_mutation_map,
            stage,
            worthwhile_mutation_count,
            n,
            weight,
            &budget_used,
            budget,
        );
    }

    if !verify_results_all_resolved() && budget_used.load(Ordering::SeqCst) < budget {
        let mut total_product: usize = 1;
        let mut overflow = false;
        for i in 0..n {
            let m = val_mutation_map.mutations[i].len();
            if m > 0 && total_product > MAX_FULL_MUTATION_PRODUCT / m {
                overflow = true;
                break;
            }
            total_product *= m;
        }
        if !overflow && total_product <= MAX_FULL_MUTATION_PRODUCT {
            let next_map = mutation_map_next(val_mutation_map);
            verify_active_scan(
                scope,
                val_knowledge_map,
                val_principal_state,
                val_attacker_state,
                next_map,
                stage,
                worthwhile_mutation_count,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_active_scan_at_weight<'s>(
    scope: &rayon::Scope<'s>,
    val_knowledge_map: &'s KnowledgeMap,
    val_principal_state: &'s PrincipalState,
    val_attacker_state: &'s AttackerState,
    val_mutation_map: &MutationMap,
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
        if verify_results_all_resolved() {
            return;
        }
        if budget_used.load(Ordering::SeqCst) >= budget {
            return;
        }

        let sub_indices = indices.clone();

        if weight == 1 {
            let sub_map =
                mutation_map_subset_capped(val_mutation_map, &sub_indices, MAX_WEIGHT1_MUTATIONS_PER_VAR);
            let cost = sub_map.mutations[0].len() as u32;
            let bu = budget_used.fetch_add(cost, Ordering::SeqCst);
            if crate::tui::tui_enabled() && bu % 500 < cost {
                crate::tui::tui_scan_update(&val_principal_state.name, weight, n.min(MAX_SUBSET_MUTATION_WEIGHT), bu + cost, budget);
            }
            let next_map = mutation_map_next(sub_map);
            verify_active_scan(
                scope,
                val_knowledge_map,
                val_principal_state,
                val_attacker_state,
                next_map,
                stage,
                worthwhile_mutation_count,
            );
            scanned += 1;
        } else {
            let mut product: usize = 1;
            let mut overflow = false;
            for &idx in &indices {
                let m = val_mutation_map.mutations[idx].len();
                if m > 0 && product > MAX_MUTATIONS_PER_SUBSET / m {
                    overflow = true;
                    break;
                }
                product *= m;
            }
            if !overflow && product <= MAX_MUTATIONS_PER_SUBSET {
                let sub_map = mutation_map_subset(val_mutation_map, &sub_indices);
                let bu = budget_used.fetch_add(product as u32, Ordering::SeqCst);
                if crate::tui::tui_enabled() && bu % 500 < product as u32 {
                    crate::tui::tui_scan_update(&val_principal_state.name, weight, n.min(MAX_SUBSET_MUTATION_WEIGHT), bu + product as u32, budget);
                }
                let next_map = mutation_map_next(sub_map);
                verify_active_scan(
                    scope,
                    val_knowledge_map,
                    val_principal_state,
                    val_attacker_state,
                    next_map,
                    stage,
                    worthwhile_mutation_count,
                );
                scanned += 1;
            }
        }

        if scanned >= MAX_SUBSETS_PER_WEIGHT {
            return;
        }

        // Advance combination indices (lexicographic next subset of size `weight` from `n`)
        let mut i = weight as i32 - 1;
        while i >= 0 {
            indices[i as usize] += 1;
            if indices[i as usize] <= n - weight + i as usize {
                break;
            }
            i -= 1;
        }
        if i < 0 {
            break;
        }
        for j in (i as usize + 1)..weight {
            indices[j] = indices[j - 1] + 1;
        }
    }
}

fn verify_active_scan<'s>(
    scope: &rayon::Scope<'s>,
    val_knowledge_map: &'s KnowledgeMap,
    val_principal_state: &'s PrincipalState,
    val_attacker_state: &'s AttackerState,
    val_mutation_map: MutationMap,
    stage: i32,
    worthwhile_mutation_count: &'s AtomicU32,
) {
    let mut current_map = val_mutation_map;
    loop {
        if verify_results_all_resolved() {
            break;
        }
        // Capture current combination for the spawned task
        let task_combo = current_map.combination.clone();
        let task_constants = current_map.constants.clone();
        let is_last = current_map.out_of_mutations;

        // Spawn mutate + analyze as a single parallel task (matches Go's goroutine approach)
        scope.spawn(move |_| {
            if verify_results_all_resolved() { return; }
            let task_map = MutationMap {
                out_of_mutations: true,
                constants: task_constants,
                mutations: vec![],
                combination: task_combo,
                depth_index: vec![],
            };
            let (ps_mutated, is_worthwhile, guard_bypass_info) =
                verify_active_mutate_principal_state(
                    val_knowledge_map,
                    construct_principal_state_clone(val_principal_state, true),
                    val_attacker_state,
                    &task_map,
                );
            if is_worthwhile {
                worthwhile_mutation_count.fetch_add(1, Ordering::SeqCst);
                if crate::tui::tui_enabled() {
                    let desc: String = task_map.constants.iter().zip(task_map.combination.iter())
                        .map(|(c, v)| format!("{} <- {}", c.name, pretty_value(v)))
                        .collect::<Vec<_>>()
                        .join(", ");
                    crate::tui::tui_mutation_detail(&desc);
                }
                if !verify_results_all_resolved() {
                    // Pass 1: analyze the (possibly truncated) state.
                    let _ = verify_analysis(
                        val_knowledge_map,
                        &ps_mutated,
                        val_attacker_state,
                        stage,
                    );
                }
                // Pass 2: if truncation occurred and the attacker learned
                // enough to bypass the guards, inject attacker-controlled
                // values into the full state, decompose wire values, and
                // resolve queries.  We avoid running full verify_analysis
                // on the large bypass state to prevent reconstruction
                // explosion.
                if !verify_results_all_resolved() {
                    if let Some((ref ps_full, ref failed_guards)) = guard_bypass_info {
                        let as_now = attacker_state_get_read();
                        if can_attacker_bypass_any_guard(failed_guards, ps_full, &as_now) {
                            if let Some(ps_injected) =
                                build_bypass_state(ps_full, failed_guards, &as_now)
                            {
                                verify_bypass_decompose(
                                    val_knowledge_map,
                                    &ps_injected,
                                );
                            }
                        }
                    }
                }
            }
        });

        if is_last {
            break;
        }
        current_map = mutation_map_next(current_map);
    }
}

/// Returns (truncated_state, is_worthwhile, Option<(full_state, failed_guards)>).
/// The third element is Some when truncation occurred and the full pre-truncation
/// state is saved for a potential second-pass analysis if the attacker can bypass
/// the guards.
fn verify_active_mutate_principal_state(
    val_knowledge_map: &KnowledgeMap,
    mut ps: PrincipalState,
    val_attacker_state: &AttackerState,
    val_mutation_map: &MutationMap,
) -> (PrincipalState, bool, Option<(PrincipalState, Vec<FailedGuardInfo>)>) {
    let mut earliest_mutation = ps.constants.len();
    let mut is_worthwhile_mutation = false;
    let attacker_id = principal_get_attacker_id();

    for i in 0..val_mutation_map.constants.len() {
        let (ai, ii) = value_resolve_constant(&val_mutation_map.constants[i], &ps, true);
        if ii < 0 {
            continue;
        }
        let ii_usize = ii as usize;
        let mut ac = val_mutation_map.combination[i].clone();
        let (ar, _) = value_resolve_value_internal_values_from_knowledge_map(&ai, val_knowledge_map);

        // If ar is a primitive, try to rewrite it
        let ar = match &ar {
            Value::Primitive(ar_p) => {
                let (_, aar) = possible_to_rewrite(ar_p, &ps, 0);
                match &aar[0] {
                    Value::Primitive(aar_p) => Value::Primitive(aar_p.clone()),
                    _ => ar,
                }
            }
            _ => ar,
        };

        // If ac is a primitive, try to rewrite and copy output/check from original
        if let Value::Primitive(_) = &ac {
            let ac_p = ac.as_primitive().expect("ac is Primitive").clone();
            let (_, aac) = possible_to_rewrite(&ac_p, &ps, 0);
            if let Value::Primitive(aac_p) = &aac[0] {
                ac = Value::Primitive(aac_p.clone());
            }
            if let Value::Primitive(ai_p) = &ai {
                let ac_p = ac.as_primitive_mut().expect("ac is Primitive");
                ac_p.output = ai_p.output;
                ac_p.check = ai_p.check;
            }
        }

        ps.creator[ii_usize] = attacker_id;
        ps.sender[ii_usize] = attacker_id;
        ps.mutated[ii_usize] = true;
        ps.assigned[ii_usize] = ac.clone();
        ps.before_rewrite[ii_usize] = ac.clone();

        if ii_usize < earliest_mutation {
            earliest_mutation = ii_usize;
        }

        if value_equivalent_values(&ac, &ar, true) {
            continue;
        }
        is_worthwhile_mutation = true;
    }

    if !is_worthwhile_mutation {
        return (ps, is_worthwhile_mutation, None);
    }

    let _ = value_resolve_all_principal_state_values(&mut ps, val_attacker_state);
    let (failed_rewrites, failed_rewrite_indices) = value_perform_all_rewrites(&mut ps);

    // Collect all failed guards and extract the bypass keys before truncating.
    let mut failed_guards: Vec<FailedGuardInfo> = Vec::new();
    let mut truncation_index: Option<usize> = None;
    let mut truncation_failed_idx: Option<usize> = None;

    for i in 0..failed_rewrites.len() {
        if !failed_rewrites[i].check {
            continue;
        }
        if ps.creator[failed_rewrite_indices[i]] != ps.id {
            continue;
        }
        // Extract the bypass key for this failed guard.
        if let Some(key) = extract_bypass_key(&failed_rewrites[i], &ps) {
            failed_guards.push(FailedGuardInfo {
                bypass_key: key,
                assigned_index: failed_rewrite_indices[i],
            });
        }
        // Determine the truncation point (same logic as before).
        if truncation_index.is_none() {
            let declared_at = ps.declared_at[failed_rewrite_indices[i]];
            if declared_at == ps.max_declared_at {
                truncation_index = Some(failed_rewrite_indices[i] + 1);
            } else {
                for ii in 0..ps.constants.len() {
                    if ps.declared_at[ii] == declared_at {
                        truncation_index = Some(ii + 1);
                        break;
                    }
                }
            }
            truncation_failed_idx = Some(failed_rewrite_indices[i]);
        }
    }

    if let Some(trunc_at) = truncation_index {
        let failed_idx = truncation_failed_idx.unwrap();
        // Save the full (non-truncated) state if we have failed guards to
        // potentially bypass.
        let full_state_info = if !failed_guards.is_empty() {
            Some((ps.clone(), failed_guards))
        } else {
            None
        };
        ps = verify_active_drop_principal_state_after_index(ps, trunc_at);
        return (
            ps,
            is_worthwhile_mutation && earliest_mutation < failed_idx,
            full_state_info,
        );
    }

    (ps, is_worthwhile_mutation, None)
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
fn extract_bypass_key(prim: &Primitive, _ps: &PrincipalState) -> Option<Value> {
    match prim.id {
        PRIM_AEAD_DEC | PRIM_DEC | PRIM_PKE_DEC => {
            // Key is argument 0.
            Some(prim.arguments[0].clone())
        }
        PRIM_SIGNVERIF | PRIM_RINGSIGNVERIF => {
            // Public key is argument 0. For G^sk, the bypass key is sk.
            if let Value::Equation(e) = &prim.arguments[0] {
                if e.values.len() == 2 {
                    return Some(e.values[1].clone());
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
    as_: &AttackerState,
) -> bool {
    for guard in guards {
        if attacker_can_obtain_value(&guard.bypass_key, ps, as_) {
            return true;
        }
    }
    false
}

/// Check if the attacker can obtain a value: either it is already in their
/// known set, or they can reconstruct it from known values.
fn attacker_can_obtain_value(
    v: &Value,
    ps: &PrincipalState,
    as_: &AttackerState,
) -> bool {
    if value_equivalent_value_in_values_map(v, &as_.known, &as_.known_map) >= 0 {
        return true;
    }
    match v {
        Value::Primitive(p) => {
            let (ok, _) = possible_to_reconstruct_primitive(p, ps, as_, 0);
            ok
        }
        Value::Equation(e) => {
            let (ok, _) = possible_to_reconstruct_equation(e, as_);
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
fn verify_bypass_decompose(
    val_knowledge_map: &KnowledgeMap,
    ps: &PrincipalState,
) {
    // Collect wire primitive values from the bypass state for
    // decomposition.  We intentionally do NOT add all wire values to
    // attacker knowledge here — adding structurally different but
    // semantically equivalent values can bloat the injection engine.
    // Instead we only add values that decomposition actually reveals.
    let mut wire_prims: Vec<(Value, usize)> = Vec::new();
    for i in 0..ps.assigned.len() {
        if ps.wire[i].is_empty() {
            continue;
        }
        if let Value::Primitive(_) = &ps.assigned[i] {
            wire_prims.push((ps.assigned[i].clone(), i));
        }
    }

    // Iteratively decompose wire values until no new deductions.
    for _ in 0..8 {
        if verify_results_all_resolved() {
            return;
        }
        let as_snap = attacker_state_get_read();
        let mut found_new = false;
        for (wv, _idx) in &wire_prims {
            if let Value::Primitive(p) = wv {
                // Active decompose (e.g. AEAD_ENC: knowing the key reveals plaintext)
                let (r, revealed, ar) =
                    possible_to_decompose_primitive(p, ps, &as_snap, 0);
                if r && attacker_state_put_write(&revealed, ps) {
                    info_message(
                        &format!(
                            "{} obtained by decomposing {} with {}.",
                            info_output_text(&revealed),
                            pretty_value(wv),
                            pretty_values(&ar),
                        ),
                        "deduction",
                        true,
                    );
                    found_new = true;
                }
                // Passive decompose (e.g. associated data from AEAD_ENC)
                let passive = possible_to_passively_decompose_primitive(p);
                for pv in &passive {
                    if attacker_state_put_write(pv, ps) {
                        found_new = true;
                    }
                }
            }
        }
        if !found_new {
            break;
        }
    }

    let _ = verify_resolve_queries(val_knowledge_map, ps);
}

/// Build a new PrincipalState from the full (non-truncated) state by injecting
/// attacker-controlled values (`G^nil`) into slots where guarded primitives
/// failed their rewrite but the attacker could bypass the guard (knows the key).
/// Iterates to handle cascading guard failures (e.g. a later AEAD_DEC whose
/// key depends on an earlier bypassed guard).
fn build_bypass_state(
    ps_full: &PrincipalState,
    initial_guards: &[FailedGuardInfo],
    as_: &AttackerState,
) -> Option<PrincipalState> {
    let mut ps = ps_full.clone();

    // Round 1: inject G^nil only into guards whose keys are currently obtainable.
    // We must inject into assigned, before_rewrite AND before_mutate because
    // value_resolve_all_principal_state_values uses before_mutate (not assigned)
    // for values created by the principal itself (which guarded primitives are).
    let mut any_injected = false;
    for guard in initial_guards {
        if attacker_can_obtain_value(&guard.bypass_key, &ps, as_) {
            let idx = guard.assigned_index;
            ps.assigned[idx] = value_g_nil();
            ps.before_rewrite[idx] = value_g_nil();
            ps.before_mutate[idx] = value_g_nil();
            any_injected = true;
        }
    }
    if !any_injected {
        return None;
    }

    // Iteratively re-resolve, re-rewrite, and inject into new bypassable guards.
    let mut needs_final_resolve = false;
    for _ in 0..5 {
        let _ = value_resolve_all_principal_state_values(&mut ps, as_);
        let (failed_rewrites, failed_rewrite_indices) = value_perform_all_rewrites(&mut ps);

        needs_final_resolve = false;
        for i in 0..failed_rewrites.len() {
            if !failed_rewrites[i].check {
                continue;
            }
            if ps.creator[failed_rewrite_indices[i]] != ps.id {
                continue;
            }
            if let Some(key) = extract_bypass_key(&failed_rewrites[i], &ps) {
                if attacker_can_obtain_value(&key, &ps, as_) {
                    let idx = failed_rewrite_indices[i];
                    ps.assigned[idx] = value_g_nil();
                    ps.before_rewrite[idx] = value_g_nil();
                    ps.before_mutate[idx] = value_g_nil();
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
        let _ = value_resolve_all_principal_state_values(&mut ps, as_);
        let _ = value_perform_all_rewrites(&mut ps);
    }

    Some(ps)
}

fn verify_active_drop_principal_state_after_index(
    mut ps: PrincipalState,
    f: usize,
) -> PrincipalState {
    Arc::make_mut(&mut ps.constants).truncate(f);
    ps.assigned.truncate(f);
    Arc::make_mut(&mut ps.guard).truncate(f);
    Arc::make_mut(&mut ps.known).truncate(f);
    Arc::make_mut(&mut ps.known_by).truncate(f);
    ps.creator.truncate(f);
    ps.sender.truncate(f);
    ps.rewritten.truncate(f);
    ps.before_rewrite.truncate(f);
    ps.mutated.truncate(f);
    ps.before_mutate.truncate(f);
    Arc::make_mut(&mut ps.phase).truncate(f);
    ps
}
