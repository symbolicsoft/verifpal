/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::context::VerifyContext;
use crate::info::info_message;
use crate::parser::parse_file;
use crate::query::query_start;
use crate::sanity::*;
use crate::skeleton::attacker_learn_skeletons;
use crate::solve::verify_active;
use crate::types::*;
use crate::value::*;

pub(crate) fn analyze(m: &Model) -> VResult<VerifyContext> {
	analyze_sessions(m, crate::sessions::DEFAULT_SESSIONS)
}

pub(crate) fn analyze_sessions(m: &Model, sessions: u8) -> VResult<VerifyContext> {
	crate::theory::rewrite_cache_reset();
	crate::info::info_reset_deductions();
	let expanded;
	let (m, variants, siblings) = if sessions > 1 {
		let e = crate::sessions::expand_sessions(m, sessions)?;
		expanded = e.model;
		(&expanded, e.query_variants, e.siblings)
	} else {
		(m, Vec::new(), std::collections::HashMap::new())
	};
	let (mut trace, states) = sanity(m)?;
	trace.session_siblings = siblings;
	capability_reach_notice(&trace, &states);
	let ctx = VerifyContext::new(m, &states, variants);
	if sessions > 1 {
		ctx.prefer_replication_valid_witnesses();
	}
	match m.attacker {
		AttackerKind::Passive => verify_passive(&ctx, &trace, &states)?,
		AttackerKind::Active => verify_active(&ctx, &trace, &states)?,
	}
	Ok(ctx)
}

fn capability_reach_notice(trace: &ProtocolTrace, states: &[PrincipalState]) {
	let Some(index) = states.first().map(|ps| &ps.capabilities) else {
		return;
	};
	let governed = index.governed_occurrences(&trace.slots);
	if governed.is_empty() {
		return;
	}
	for (slot, reach) in &governed {
		let message = match reach {
			Reach::SameTerm(annotated) => format!(
				"{slot} is written without an annotation, but is the same term as \
				 the annotated {annotated}, so it is analyzed under that assumption \
				 too."
			),
			Reach::SameSecret(secret) => format!(
				"{slot} is written without an annotation, but a `forgeable` \
				 assumption is declared on {secret}, so the attacker is analyzed as \
				 able to produce {slot} too."
			),
		};
		info_message(&message, InfoLevel::Info, false);
	}
}

pub fn verify(file_path: &str) -> VResult<(Vec<VerifyResult>, String)> {
	verify_with_sessions(file_path, crate::sessions::DEFAULT_SESSIONS)
}

/// `verify`, analyzed as `sessions` interleaved sessions per principal
/// (`sessions.rs`). Every entry point shares one default, so the CLI, the
/// `internal-json` IDE interface and the wasm build cannot disagree about
/// what a model means.
pub fn verify_with_sessions(file_path: &str, sessions: u8) -> VResult<(Vec<VerifyResult>, String)> {
	let m = parse_file(file_path)?;
	verify_model(&m, sessions).map_err(|e| e.located(&m.file_name, &m.source))
}

fn verify_model(m: &Model, sessions: u8) -> VResult<(Vec<VerifyResult>, String)> {
	info_message(
		&format!(
			"Verification initiated for '{}' at {}.",
			m.file_name,
			chrono_time_string(),
		),
		InfoLevel::Verifpal,
		false,
	);
	verify_end(&analyze_sessions(m, sessions)?)
}

pub(crate) fn verify_resolve_queries(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> VResult<()> {
	let results = ctx.results_get();
	for result in &results {
		if result.resolved {
			continue;
		}
		query_start(ctx, &result.query, result.query_index, km, ps)?;
		for variant in &result.variants {
			if ctx.query_is_resolved(result.query_index) {
				break;
			}
			query_start(ctx, variant, result.query_index, km, ps)?;
		}
	}
	Ok(())
}

pub(crate) fn verify_standard_run(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	principal_states: &[PrincipalState],
) -> VResult<()> {
	let attacker = ctx.attacker_snapshot();
	for ps in principal_states {
		let ps_resolved = generate_trace(ctx, km, ps, &attacker)?;

		crate::deduction::compute_knowledge_closure(ctx, km, &ps_resolved)?;

		verify_resolve_queries(ctx, km, &ps_resolved)?;
	}
	Ok(())
}

pub(crate) fn generate_trace(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> VResult<PrincipalState> {
	let mut ps_resolved = ps.clone_for_depth(false);
	ps_resolved.resolve_all_values(attacker)?;

	let record = compute_slot_diffs(&ps_resolved, km, attacker.current_phase);

	inject_skeletons_for_state(ctx, &ps_resolved, &record, attacker);

	let failures = ps_resolved.perform_all_rewrites();

	sanity_fail_on_failed_checked_primitive_rewrite(&failures)?;
	for sv in &ps_resolved.values {
		sanity_check_argument_restrictions(&sv.value)?;
	}

	Ok(ps_resolved)
}

fn inject_skeletons_for_state(
	ctx: &VerifyContext,
	ps: &PrincipalState,
	record: &Arc<MutationRecord>,
	attacker: &AttackerState,
) {
	for sv in &ps.values {
		if let Value::Primitive(p) = &sv.value {
			attacker_learn_skeletons(ctx, p, record, attacker);
		}
	}
}

pub(crate) fn verify_passive(
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
		verify_standard_run(ctx, km, principal_states)?;
	}
	Ok(())
}

fn verify_end(ctx: &VerifyContext) -> VResult<(Vec<VerifyResult>, String)> {
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

	let assumptions = ctx.capability_assumption_terms();
	if !assumptions.is_empty() {
		info_message(
			&format!(
				"Analysis performed under {} declared weakening assumption{}:",
				assumptions.len(),
				if assumptions.len() == 1 { "" } else { "s" },
			),
			InfoLevel::Warning,
			false,
		);
		for term in &assumptions {
			info_message(&format!("{}", term), InfoLevel::Warning, false);
		}
		println!();
	}

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

	let suppressed = crate::info::info_deductions_suppressed();
	if suppressed > 0 {
		info_message(
			&format!("{} further deductions were not shown.", suppressed),
			InfoLevel::Info,
			false,
		);
	}

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

fn chrono_time_string() -> String {
	use chrono::Local;
	Local::now().format("%I:%M:%S %p").to_string()
}

#[cfg(test)]
mod tests {
	use crate::parser::parse_string;

	fn model(constant: &str) -> String {
		format!(
			"attacker[passive]\n\
			principal Alice[\n\
			knows private {c}\n\
			knows private {c}_k\n\
			{c}_e = ENC({c}_k, {c})\n\
			]\n\
			principal Bob[\n\
			knows private {c}_b\n\
			]\n\
			Alice -> Bob: {c}_e\n\
			queries[\n\
			confidentiality? {c}\n\
			]\n",
			c = constant
		)
	}

	#[test]
	fn analyses_in_one_process_do_not_share_identifier_state() {
		let first = parse_string("first.vp", &model("aaa")).expect("parse");
		let second = parse_string("second.vp", &model("bbb")).expect("parse");

		let ids = |m: &crate::types::Model| {
			let (km, _) = crate::sanity::sanity(m).expect("sanity");
			let mut v: Vec<_> = km.slots.iter().map(|s| s.constant.id).collect();
			v.sort_unstable();
			v
		};
		assert_eq!(ids(&first), ids(&second));
	}

	#[test]
	fn repeated_analysis_of_the_same_model_is_stable() {
		let m = parse_string("repeat.vp", &model("ccc")).expect("parse");
		let code = |m: &crate::types::Model| {
			crate::types::VerifyResult::results_code(
				&super::analyze(m).expect("analyze").results_get(),
			)
		};
		let first = code(&m);
		let second = code(&m);
		assert_eq!(first, second);
		assert_eq!(first, "c0");
	}
}
