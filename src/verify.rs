/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::context::VerifyContext;
use crate::info::info_message;
use crate::inject::inject_missing_skeletons;
use crate::parser::parse_file;
use crate::query::query_start;
use crate::sanity::*;
use crate::types::*;
use crate::value::*;
use crate::verifyactive::verify_active;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Runs the main verification engine for Verifpal on a model loaded from a file.
/// Returns a vec of VerifyResult and a "results code" string.
pub fn verify(file_path: &str) -> VResult<(Vec<VerifyResult>, String)> {
	let m = parse_file(file_path)?;
	verify_model(&m)
}

// ---------------------------------------------------------------------------
// Core verification pipeline
// ---------------------------------------------------------------------------

fn verify_model(m: &Model) -> VResult<(Vec<VerifyResult>, String)> {
	let (km, ps) = sanity(m)?;
	crate::tui::tui_init(m);
	let ctx = VerifyContext::new(m);
	let initiated = chrono_time_string();
	info_message(
		&format!(
			"Verification initiated for '{}' at {}.",
			m.file_name, initiated,
		),
		InfoLevel::Verifpal,
		false,
	);
	match m.attacker {
		AttackerKind::Passive => verify_passive(&ctx, &km, &ps)?,
		AttackerKind::Active => verify_active(&ctx, &km, &ps)?,
	}
	verify_end(&ctx)
}

// ---------------------------------------------------------------------------
// Resolve unresolved queries against the current principal state
// ---------------------------------------------------------------------------

pub fn verify_resolve_queries(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> VResult<()> {
	let results = ctx.results_get();
	for result in &results {
		if !result.resolved {
			query_start(ctx, &result.query, result.query_index, km, ps)?;
		}
	}
	Ok(())
}

// ---------------------------------------------------------------------------
// Standard verification pipeline
// ---------------------------------------------------------------------------
//
// For each principal, the pipeline executes three phases:
//
//   Phase 1 — Trace generation:
//     Resolve symbolic references, record mutations, inject skeletons,
//     apply cryptographic rewrites, and run sanity checks.
//
//   Phase 2 — Knowledge closure:
//     Compute the attacker's full knowledge as a monotone fixed-point
//     (see deduction.rs). No query checks, no early exits.
//
//   Phase 3 — Query evaluation:
//     Check all pending queries against the final attacker knowledge.
//

pub fn verify_standard_run(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	principal_states: &[PrincipalState],
	depth: i32,
) -> VResult<()> {
	let attacker = ctx.attacker_snapshot();
	for ps in principal_states {
		// Phase 1: Trace generation
		let ps_resolved = generate_trace(ctx, km, ps, &attacker)?;

		// Phase 2: Knowledge closure (monotone fixed-point)
		crate::deduction::compute_knowledge_closure(ctx, km, &ps_resolved, depth)?;

		// Phase 3: Query evaluation
		verify_resolve_queries(ctx, km, &ps_resolved)?;
	}
	Ok(())
}

/// Phase 1: Generate a protocol trace for a single principal.
///
/// Performs resolution, mutation recording, skeleton injection,
/// cryptographic rewriting, and sanity checks. Returns the fully
/// resolved principal state ready for knowledge closure.
pub fn generate_trace(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> VResult<PrincipalState> {
	// 1. Resolution
	let mut ps_resolved = ps.clone_for_depth(false);
	ps_resolved.resolve_all_values(attacker)?;

	// 2. Mutation record
	let record = compute_slot_diffs(&ps_resolved, km);

	// 3. Skeleton injection
	inject_skeletons_for_state(ctx, &ps_resolved, &record, attacker);

	// 4. Rewriting
	let failures = ps_resolved.perform_all_rewrites();

	// 5. Sanity checks
	sanity_fail_on_failed_checked_primitive_rewrite(&failures)?;
	for sv in &ps_resolved.values {
		sanity_check_equation_generators(&sv.value)?;
	}

	Ok(ps_resolved)
}

/// Inject skeleton templates for all assigned primitives into attacker knowledge.
fn inject_skeletons_for_state(
	ctx: &VerifyContext,
	ps: &PrincipalState,
	record: &Arc<MutationRecord>,
	attacker: &AttackerState,
) {
	for sv in &ps.values {
		if let Value::Primitive(p) = &sv.value {
			inject_missing_skeletons(ctx, p, record, attacker);
		}
	}
}

// ---------------------------------------------------------------------------
// Passive attacker verification
// ---------------------------------------------------------------------------

pub fn verify_passive(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	principal_states: &[PrincipalState],
) -> VResult<()> {
	info_message("Attacker is configured as passive.", InfoLevel::Info, false);
	for phase in 0..=km.max_phase {
		ctx.attacker_init();
		let mut ps_pure_resolved = principal_states[0].clone_for_depth(true);
		ps_pure_resolved.resolve_all_values(&ctx.attacker_snapshot())?;
		ctx.attacker_phase_update(km, &ps_pure_resolved, phase)?;
		verify_standard_run(ctx, km, principal_states, 0)?;
	}
	Ok(())
}


// ---------------------------------------------------------------------------
// End of verification: print summary
// ---------------------------------------------------------------------------

fn verify_end(
	ctx: &VerifyContext,
) -> VResult<(Vec<VerifyResult>, String)> {
	// Leave the TUI alternate screen before printing final results
	crate::tui::tui_finish();

	let results = ctx.results_get();
	let file_name = ctx.results_file_name();
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
		InfoLevel::Verifpal,
		false,
	);
	println!();

	for r in &results {
		if r.resolved {
			info_message(
				&format!("{}{}", r.query, r.summary),
				InfoLevel::Result,
				false,
			);
		} else {
			info_message(&r.query.to_string(), InfoLevel::Pass, false);
		}
	}

	println!();
	crate::info::info_separator();

	if fail_count == 0 {
		info_message(
			&format!("All {} queries pass.", total),
			InfoLevel::Pass,
			false,
		);
	} else {
		info_message(
			&format!("{} of {} queries failed.", fail_count, total),
			InfoLevel::Result,
			false,
		);
	}

	info_message("Thank you for using Verifpal.", InfoLevel::Verifpal, false);

	let results_code = VerifyResult::results_code(&results);

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
