/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::atomic::{AtomicU32, Ordering};

use crate::attackerstate::{attacker_state_get_read, attacker_state_put_write};
use crate::info::{info_analysis, info_message, info_output_text};
use crate::possible::{
    possible_to_decompose_primitive, possible_to_obtain_passwords,
    possible_to_passively_decompose_primitive, possible_to_recompose_primitive,
    possible_to_reconstruct_equation, possible_to_reconstruct_primitive,
};
use crate::pretty::{pretty_value, pretty_values};
use crate::primitive::PRIM_CONCAT;
use crate::types::*;
use crate::value::{value_equivalent_values, value_nil, value_resolve_constant};
use crate::verify::verify_resolve_queries;
use crate::verifyresults::verify_results_all_resolved;

// ---------------------------------------------------------------------------
// Global analysis counter
// ---------------------------------------------------------------------------

static VERIFY_ANALYSIS_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn verify_analysis_count_init() {
    VERIFY_ANALYSIS_COUNT.store(0, Ordering::SeqCst);
}

pub fn verify_analysis_count_increment() {
    VERIFY_ANALYSIS_COUNT.fetch_add(1, Ordering::SeqCst);
}

pub fn verify_analysis_count_get() -> usize {
    VERIFY_ANALYSIS_COUNT.load(Ordering::SeqCst) as usize
}

// ---------------------------------------------------------------------------
// Main analysis entry point
// ---------------------------------------------------------------------------

pub fn verify_analysis(
    val_knowledge_map: &KnowledgeMap,
    val_principal_state: &PrincipalState,
    _val_attacker_state: &AttackerState,
    stage: i32,
) -> Result<(), String> {
    let mut current_as = attacker_state_get_read();
    loop {
        if verify_results_all_resolved() {
            return Ok(());
        }
        verify_resolve_queries(val_knowledge_map, val_principal_state)?;

        let mut o: usize = 0;

        // Phase 1: decompose and passive decompose from attacker known values
        for i in 0..current_as.known.len() {
            o += verify_analysis_decompose(
                &current_as.known[i],
                val_principal_state,
                &current_as,
            );
            if o > 0 {
                break;
            }
            o += verify_analysis_passive_decompose(
                &current_as.known[i],
                val_principal_state,
            );
            if o > 0 {
                break;
            }
        }

        // Phase 2: reconstruct and recompose from principal assigned values
        if o == 0 {
            for i in 0..val_principal_state.assigned.len() {
                o += verify_analysis_reconstruct(
                    &val_principal_state.assigned[i],
                    val_principal_state,
                    &current_as,
                    0,
                );
                if o > 0 {
                    break;
                }
                o += verify_analysis_recompose(
                    &val_principal_state.assigned[i],
                    val_principal_state,
                    &current_as,
                );
                if o > 0 {
                    break;
                }
            }
        }

        // Phase 3: equivalize, passwords, and concat from attacker known values
        if o == 0 {
            for i in 0..current_as.known.len() {
                o += verify_analysis_equivalize(
                    &current_as.known[i],
                    val_principal_state,
                );
                if o > 0 {
                    break;
                }
                o += verify_analysis_passwords(
                    &current_as.known[i],
                    val_principal_state,
                );
                if o > 0 {
                    break;
                }
                o += verify_analysis_concat(
                    &current_as.known[i],
                    val_principal_state,
                );
                if o > 0 {
                    break;
                }
            }
        }

        if o > 0 {
            current_as = attacker_state_get_read();
            continue;
        }
        verify_analysis_count_increment();
        info_analysis(stage);
        return Ok(());
    }
}

// ---------------------------------------------------------------------------
// Decompose
// ---------------------------------------------------------------------------

fn verify_analysis_decompose(
    a: &Value,
    val_principal_state: &PrincipalState,
    val_attacker_state: &AttackerState,
) -> usize {
    let mut o: usize = 0;
    let mut r = false;
    let mut revealed = value_nil();
    let mut ar: Vec<Value> = Vec::new();
    if let Value::Primitive(p) = a {
        let result = possible_to_decompose_primitive(p, val_principal_state, val_attacker_state, 0);
        r = result.0;
        revealed = result.1;
        ar = result.2;
    }
    if r && attacker_state_put_write(&revealed, val_principal_state) {
        info_message(
            &format!(
                "{} obtained by decomposing {} with {}.",
                info_output_text(&revealed),
                pretty_value(a),
                pretty_values(&ar),
            ),
            "deduction",
            true,
        );
        o += 1;
    }
    o
}

// ---------------------------------------------------------------------------
// Passive decompose
// ---------------------------------------------------------------------------

fn verify_analysis_passive_decompose(
    a: &Value,
    val_principal_state: &PrincipalState,
) -> usize {
    let mut o: usize = 0;
    if let Value::Primitive(p) = a {
        let passive_revealed = possible_to_passively_decompose_primitive(p);
        for revealed in &passive_revealed {
            if attacker_state_put_write(revealed, val_principal_state) {
                info_message(
                    &format!(
                        "{} obtained as associated data from {}.",
                        info_output_text(revealed),
                        pretty_value(a),
                    ),
                    "deduction",
                    true,
                );
                o += 1;
            }
        }
    }
    o
}

// ---------------------------------------------------------------------------
// Recompose
// ---------------------------------------------------------------------------

fn verify_analysis_recompose(
    a: &Value,
    val_principal_state: &PrincipalState,
    val_attacker_state: &AttackerState,
) -> usize {
    let mut o: usize = 0;
    let mut r = false;
    let mut revealed = value_nil();
    let mut ar: Vec<Value> = Vec::new();
    if let Value::Primitive(p) = a {
        let result = possible_to_recompose_primitive(p, val_attacker_state);
        r = result.0;
        revealed = result.1;
        ar = result.2;
    }
    if r && attacker_state_put_write(&revealed, val_principal_state) {
        info_message(
            &format!(
                "{} obtained by recomposing {} with {}.",
                info_output_text(&revealed),
                pretty_value(a),
                pretty_values(&ar),
            ),
            "deduction",
            true,
        );
        o += 1;
    }
    o
}

// ---------------------------------------------------------------------------
// Reconstruct (recursive)
// ---------------------------------------------------------------------------

fn verify_analysis_reconstruct(
    a: &Value,
    val_principal_state: &PrincipalState,
    val_attacker_state: &AttackerState,
    mut o: usize,
) -> usize {
    let mut r = false;
    let mut ar: Vec<Value> = Vec::new();
    match a {
        Value::Primitive(p) => {
            let result =
                possible_to_reconstruct_primitive(p, val_principal_state, val_attacker_state, 0);
            r = result.0;
            ar = result.1;
            for aa in &p.arguments {
                o += verify_analysis_reconstruct(aa, val_principal_state, val_attacker_state, o);
            }
        }
        Value::Equation(e) => {
            let result = possible_to_reconstruct_equation(e, val_attacker_state);
            r = result.0;
            ar = result.1;
        }
        _ => {}
    }
    if r && attacker_state_put_write(a, val_principal_state) {
        info_message(
            &format!(
                "{} obtained by reconstructing with {}.",
                info_output_text(a),
                pretty_values(&ar),
            ),
            "deduction",
            true,
        );
        o += 1;
    }
    o
}

// ---------------------------------------------------------------------------
// Equivalize
// ---------------------------------------------------------------------------

fn verify_analysis_equivalize(
    a: &Value,
    val_principal_state: &PrincipalState,
) -> usize {
    let mut o: usize = 0;
    let ar = match a {
        Value::Constant(c) => {
            let (resolved, _) = value_resolve_constant(c, val_principal_state, true);
            resolved
        }
        _ => a.clone(),
    };
    for i in 0..val_principal_state.assigned.len() {
        if value_equivalent_values(&ar, &val_principal_state.assigned[i], true) {
            if attacker_state_put_write(&val_principal_state.assigned[i], val_principal_state) {
                info_message(
                    &format!(
                        "{} obtained by equivalizing with the current resolution of {}.",
                        info_output_text(&val_principal_state.assigned[i]),
                        pretty_value(a),
                    ),
                    "deduction",
                    true,
                );
                o += 1;
            }
        }
    }
    o
}

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

fn verify_analysis_passwords(
    a: &Value,
    val_principal_state: &PrincipalState,
) -> usize {
    let mut o: usize = 0;
    let passwords = possible_to_obtain_passwords(a, a, -1, val_principal_state);
    for password in &passwords {
        if attacker_state_put_write(password, val_principal_state) {
            info_message(
                &format!(
                    "{} obtained as a password unsafely used within {}.",
                    info_output_text(password),
                    pretty_value(a),
                ),
                "deduction",
                true,
            );
            o += 1;
        }
    }
    o
}

// ---------------------------------------------------------------------------
// Concat
// ---------------------------------------------------------------------------

fn verify_analysis_concat(
    a: &Value,
    val_principal_state: &PrincipalState,
) -> usize {
    let mut o: usize = 0;
    if let Value::Primitive(p) = a {
        if p.id == PRIM_CONCAT {
            for arg in &p.arguments {
                if attacker_state_put_write(arg, val_principal_state) {
                    info_message(
                        &format!(
                            "{} obtained as a concatenated fragment of {}.",
                            info_output_text(arg),
                            pretty_value(a),
                        ),
                        "deduction",
                        true,
                    );
                    o += 1;
                }
            }
        }
    }
    o
}
