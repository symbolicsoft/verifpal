/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::info::info_message;
use crate::inject::inject_missing_skeletons;
use crate::parser::parse_file;
use crate::query::query_start;
use crate::sanity::*;
use crate::types::*;
use crate::value::*;
use crate::verifhub::verifhub;
use crate::verifyactive::verify_active;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Runs the main verification engine for Verifpal on a model loaded from a file.
/// Returns a vec of VerifyResult and a "results code" string.
///
/// `verifhub_scheduled` — when `true`, submit the results to VerifHub on completion.
/// This replaced the old `VERIFHUB_SCHEDULED` global `AtomicBool`.
pub fn verify(file_path: &str, verifhub_scheduled: bool) -> VResult<(Vec<VerifyResult>, String)> {
	let m = parse_file(file_path)?;
	verify_model(&m, verifhub_scheduled)
}

// ---------------------------------------------------------------------------
// Core verification pipeline
// ---------------------------------------------------------------------------

fn verify_model(m: &Model, verifhub_scheduled: bool) -> VResult<(Vec<VerifyResult>, String)> {
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
	verify_end(&ctx, m, verifhub_scheduled)
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
// Standard run: resolve, inject skeletons, rewrite, analyse each principal
// ---------------------------------------------------------------------------

pub fn verify_standard_run(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	principal_states: &[PrincipalState],
	stage: i32,
) -> VResult<()> {
	let attacker = ctx.attacker_snapshot();
	for ps in principal_states {
		let mut ps_resolved = ps.clone_for_stage(false);
		ps_resolved.resolve_all_values(&attacker)?;

		// Pre-compute mutation record for this principal state
		let record = compute_slot_diffs(&ps_resolved, km);

		// Inject missing skeletons for all assigned primitives
		for sv in &ps_resolved.values {
			if let Value::Primitive(p) = &sv.assigned {
				inject_missing_skeletons(ctx, p, &record, &attacker);
			}
		}

		let failures = ps_resolved.perform_all_rewrites();
		sanity_fail_on_failed_checked_primitive_rewrite(&failures)?;

		for sv in &ps_resolved.values {
			let a = &sv.assigned;
			sanity_check_equation_generators(a)?;
		}

		crate::verifyanalysis::verify_analysis(ctx, km, &ps_resolved, stage)?;

		verify_resolve_queries(ctx, km, &ps_resolved)?;
	}
	Ok(())
}

// ---------------------------------------------------------------------------
// Passive attacker verification
// ---------------------------------------------------------------------------

fn verify_passive(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	principal_states: &[PrincipalState],
) -> VResult<()> {
	info_message("Attacker is configured as passive.", InfoLevel::Info, false);
	for phase in 0..=km.max_phase {
		ctx.attacker_init();
		let mut ps_pure_resolved = principal_states[0].clone_for_stage(true);
		ps_pure_resolved.resolve_all_values(&ctx.attacker_snapshot())?;
		ctx.attacker_phase_update(km, &ps_pure_resolved, phase)?;
		verify_standard_run(ctx, km, principal_states, 0)?;
	}
	Ok(())
}

// ---------------------------------------------------------------------------
// Results code
// ---------------------------------------------------------------------------

fn verify_get_results_code(results: &[VerifyResult]) -> String {
	let mut code = String::with_capacity(results.len() * 2);
	for r in results {
		code.push(match r.query.kind {
			QueryKind::Confidentiality => 'c',
			QueryKind::Authentication => 'a',
			QueryKind::Freshness => 'f',
			QueryKind::Unlinkability => 'u',
			QueryKind::Equivalence => 'e',
		});
		code.push(if r.resolved { '1' } else { '0' });
	}
	code
}

// ---------------------------------------------------------------------------
// End of verification: print summary, optionally submit to VerifHub
// ---------------------------------------------------------------------------

fn verify_end(
	ctx: &VerifyContext,
	m: &Model,
	verifhub_scheduled: bool,
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

	let results_code = verify_get_results_code(&results);

	if verifhub_scheduled {
		verifhub(m, file_name, &results_code)?;
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
