/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::attackerstate::{
    attacker_state_get_exhausted, attacker_state_get_known_count, attacker_state_get_read,
    attacker_state_init, attacker_state_put_exhausted, attacker_state_put_phase_update,
};
use crate::construct::construct_principal_state_clone;
use crate::info::info_message;
use crate::pretty::pretty_value;
use crate::mutationmap::{
    mutation_map_init, mutation_map_next, mutation_map_subset, mutation_map_subset_capped,
};
use crate::possible::possible_to_rewrite;
use crate::principal::principal_get_attacker_id;
use crate::types::*;
use crate::value::{
    value_equivalent_values, value_perform_all_rewrites,
    value_resolve_all_principal_state_values, value_resolve_constant,
    value_resolve_value_internal_values_from_knowledge_map,
};
use crate::verify::verify_standard_run;
use crate::verifyanalysis::verify_analysis;
use crate::verifyresults::verify_results_all_resolved;

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
            let (ps_mutated, is_worthwhile) = verify_active_mutate_principal_state(
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
                    let _ = verify_analysis(
                        val_knowledge_map,
                        &ps_mutated,
                        val_attacker_state,
                        stage,
                    );
                }
            }
        });

        if is_last {
            break;
        }
        current_map = mutation_map_next(current_map);
    }
}

fn verify_active_mutate_principal_state(
    val_knowledge_map: &KnowledgeMap,
    mut ps: PrincipalState,
    val_attacker_state: &AttackerState,
    val_mutation_map: &MutationMap,
) -> (PrincipalState, bool) {
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
        return (ps, is_worthwhile_mutation);
    }

    let _ = value_resolve_all_principal_state_values(&mut ps, val_attacker_state);
    let (failed_rewrites, failed_rewrite_indices) = value_perform_all_rewrites(&mut ps);

    for i in 0..failed_rewrites.len() {
        if !failed_rewrites[i].check {
            continue;
        }
        if ps.creator[failed_rewrite_indices[i]] != ps.id {
            continue;
        }
        let declared_at = ps.declared_at[failed_rewrite_indices[i]];
        if declared_at == ps.max_declared_at {
            ps = verify_active_drop_principal_state_after_index(ps, failed_rewrite_indices[i] + 1);
            return (
                ps,
                is_worthwhile_mutation && earliest_mutation < failed_rewrite_indices[i],
            );
        }
        for ii in 0..ps.constants.len() {
            if ps.declared_at[ii] == declared_at {
                ps = verify_active_drop_principal_state_after_index(ps, ii + 1);
                return (
                    ps,
                    is_worthwhile_mutation && earliest_mutation < failed_rewrite_indices[i],
                );
            }
        }
    }
    (ps, is_worthwhile_mutation)
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
