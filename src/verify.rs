/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;
use crate::attackerstate::*;
use crate::construct::construct_principal_state_clone;
use crate::info::info_message;
use crate::inject::inject_missing_skeletons;
use crate::parser::parse_file;
use crate::pretty::pretty_query;
use crate::query::query_start;
use crate::sanity::*;
use crate::types::*;
use crate::value::*;
use crate::verifyactive::verify_active;
use crate::verifyanalysis::*;
use crate::verifhub::{verifhub, VERIFHUB_SCHEDULED};
use crate::verifyresults::*;

use std::sync::atomic::Ordering;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Runs the main verification engine for Verifpal on a model loaded from a file.
/// Returns a vec of VerifyResult and a "results code" string.
pub fn verify(file_path: &str) -> Result<(Vec<VerifyResult>, String), String> {
    let m = parse_file(file_path)?;
    verify_model(&m)
}

// ---------------------------------------------------------------------------
// Core verification pipeline
// ---------------------------------------------------------------------------

fn verify_model(m: &Model) -> Result<(Vec<VerifyResult>, String), String> {
    let (km, ps) = sanity(m)?;
    crate::tui::tui_init(m);
    let initiated = chrono_time_string();
    verify_analysis_count_init();
    verify_results_init(m);
    info_message(
        &format!(
            "Verification initiated for '{}' at {}.",
            m.file_name, initiated,
        ),
        "verifpal",
        false,
    );
    match m.attacker.as_str() {
        "passive" => verify_passive(&km, &ps)?,
        "active" => verify_active(&km, &ps)?,
        other => return Err(format!("invalid attacker ({})", other)),
    }
    verify_end(m)
}

// ---------------------------------------------------------------------------
// Resolve unresolved queries against the current principal state
// ---------------------------------------------------------------------------

pub fn verify_resolve_queries(
    km: &KnowledgeMap,
    ps: &PrincipalState,
) -> Result<(), String> {
    let (results, _) = verify_results_get_read();
    for result in &results {
        if !result.resolved {
            query_start(&result.query, result.query_index, km, ps)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Standard run: resolve, inject skeletons, rewrite, analyse each principal
// ---------------------------------------------------------------------------

pub fn verify_standard_run(
    km: &KnowledgeMap,
    principal_states: &[PrincipalState],
    stage: i32,
) -> Result<(), String> {
    let as_ = attacker_state_get_read();
    for ps in principal_states {
        let mut ps_resolved = construct_principal_state_clone(ps, false);
        value_resolve_all_principal_state_values(&mut ps_resolved, &as_)?;

        // Inject missing skeletons for all assigned primitives
        for i in 0..ps_resolved.assigned.len() {
            if let Value::Primitive(p) = &ps_resolved.assigned[i] {
                let p = Arc::clone(p);
                inject_missing_skeletons(&p, &ps_resolved, &as_);
            }
        }

        let (failed_rewrites, _) = value_perform_all_rewrites(&mut ps_resolved);
        sanity_fail_on_failed_checked_primitive_rewrite(&failed_rewrites)?;

        for a in &ps_resolved.assigned {
            sanity_check_equation_generators(a)?;
        }

        verify_analysis(km, &ps_resolved, &as_, stage)?;

        verify_resolve_queries(km, &ps_resolved)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Passive attacker verification
// ---------------------------------------------------------------------------

fn verify_passive(km: &KnowledgeMap, principal_states: &[PrincipalState]) -> Result<(), String> {
    info_message("Attacker is configured as passive.", "info", false);
    let mut phase = 0;
    while phase <= km.max_phase {
        attacker_state_init();
        let mut ps_pure_resolved = construct_principal_state_clone(&principal_states[0], true);
        value_resolve_all_principal_state_values(&mut ps_pure_resolved, &attacker_state_get_read())?;
        attacker_state_put_phase_update(km, &ps_pure_resolved, phase)?;
        verify_standard_run(km, principal_states, 0)?;
        phase += 1;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Results code
// ---------------------------------------------------------------------------

fn verify_get_results_code(results: &[VerifyResult]) -> String {
    let mut code = String::new();
    for r in results {
        let q = match r.query.kind {
            TypesEnum::Confidentiality => "c",
            TypesEnum::Authentication => "a",
            TypesEnum::Freshness => "f",
            TypesEnum::Unlinkability => "u",
            TypesEnum::Equivalence => "e",
            _ => "",
        };
        let v = if r.resolved { "1" } else { "0" };
        code.push_str(q);
        code.push_str(v);
    }
    code
}

// ---------------------------------------------------------------------------
// End of verification: print summary, optionally submit to VerifHub
// ---------------------------------------------------------------------------

fn verify_end(m: &Model) -> Result<(Vec<VerifyResult>, String), String> {
    // Leave the TUI alternate screen before printing final results
    crate::tui::tui_finish();

    let (results, file_name) = verify_results_get_read();
    let fail_count = results.iter().filter(|r| r.resolved).count();
    let total = results.len();

    println!();
    crate::info::info_separator();
    info_message(
        &format!(
            "Verification completed for '{}' at {}.",
            file_name,
            chrono_time_string(),
        ),
        "verifpal",
        false,
    );
    println!();

    for r in &results {
        if r.resolved {
            info_message(
                &format!("{}{}", pretty_query(&r.query), r.summary),
                "result",
                false,
            );
        } else {
            info_message(
                &pretty_query(&r.query),
                "pass",
                false,
            );
        }
    }

    println!();
    crate::info::info_separator();

    if fail_count == 0 {
        info_message(
            &format!("All {} queries pass.", total),
            "pass",
            false,
        );
    } else {
        info_message(
            &format!("{} of {} queries failed.", fail_count, total),
            "result",
            false,
        );
    }

    info_message("Thank you for using Verifpal.", "verifpal", false);

    let results_code = verify_get_results_code(&results);

    if VERIFHUB_SCHEDULED.load(Ordering::Relaxed) {
        verifhub(m, &file_name, &results_code)?;
    }

    Ok((results, results_code))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Produce a human-readable time string in HH:MM:SS AM/PM format.
/// Uses only the standard library to avoid extra dependencies.
fn chrono_time_string() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple UTC-based HH:MM:SS formatting
    let secs_of_day = (now % 86400) as u32;
    let hours = secs_of_day / 3600;
    let minutes = (secs_of_day % 3600) / 60;
    let seconds = secs_of_day % 60;
    let (h12, ampm) = if hours == 0 {
        (12, "AM")
    } else if hours < 12 {
        (hours, "AM")
    } else if hours == 12 {
        (12, "PM")
    } else {
        (hours - 12, "PM")
    };
    format!("{:02}:{:02}:{:02} {}", h12, minutes, seconds, ampm)
}
