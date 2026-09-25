/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crate::context::VerifyContext;
use crate::engine::exec::Execution;
use crate::engine::program::Program;
use crate::info::info_message;
use crate::parser::parse_file;
use crate::sanity::*;
use crate::types::*;

#[cfg_attr(not(any(test, feature = "wasm")), allow(dead_code))]
pub(crate) fn analyze(m: &Model) -> VResult<VerifyContext> {
	analyze_sessions(m, crate::sessions::DEFAULT_SESSIONS)
}

pub(crate) fn analyze_sessions(m: &Model, sessions: u8) -> VResult<VerifyContext> {
	analyze_sessions_cancellable(m, sessions, Arc::new(AtomicBool::new(false)))
}

pub(crate) struct Expansion {
	pub(crate) model: Model,
	pub(crate) corrupt_from: Option<IdMap<PrincipalId, i32>>,
	pub(crate) scenarios: Vec<ScenarioSummary>,
	pub(crate) variants: Vec<Vec<Query>>,
	pub(crate) siblings: IdMap<ValueId, Arc<Vec<ValueId>>>,
	pub(crate) interchangeable: IdMap<PrincipalId, PrincipalId>,
	pub(crate) actors: IdMap<PrincipalId, PrincipalId>,
	pub(crate) bound: IdSet<ValueId>,
}

pub(crate) fn expand(m: &Model, sessions: u8) -> VResult<Expansion> {
	let sessions = sessions.max(1);
	let e = crate::scenario::expand_scenarios(m, sessions)?;
	if sessions == 1 {
		return Ok(e);
	}
	crate::sessions::expand_sessions(e, sessions)
}

pub(crate) fn analyze_sessions_cancellable(
	m: &Model,
	sessions: u8,
	cancel: Arc<AtomicBool>,
) -> VResult<VerifyContext> {
	let sessions = sessions.max(1);
	let _generation = crate::context::GenerationGuard::enter();
	crate::info::info_reset_deductions();
	let assumptions = crate::capability::declared_assumptions(m);
	let Expansion {
		model,
		corrupt_from,
		scenarios,
		variants,
		siblings,
		interchangeable,
		actors,
		bound,
	} = expand(m, sessions)?;
	let m = &model;
	let mut trace = sanity(m)?;
	trace.session_siblings = siblings;
	trace.copy_siblings = copy_sibling_groups(&trace.slots);
	trace.interchangeable = interchangeable;
	trace.actors = actors;
	trace.scenario_bound = bound;
	trace.equivalence_queried =
		equivalence_queried(m.queries.iter().chain(variants.iter().flatten()));
	capability_reach_notice(&trace);
	let mut ctx = VerifyContext::new(m, variants, sessions, corrupt_from, scenarios, assumptions);
	ctx.set_cancel(cancel);
	let ctx = ctx;
	crate::engine::verify(&ctx, m, &trace)?;
	if ctx.cancelled() {
		return Err(VerifpalError::cancelled());
	}
	ctx.finalize_envelopes();
	Ok(ctx)
}

fn capability_reach_notice(trace: &ProtocolTrace) {
	let governed = trace.capabilities.governed_occurrences(&trace.slots);
	if governed.is_empty() {
		return;
	}
	for (slot, reach) in &governed {
		let anonymous = crate::util::is_anonymous_name(slot);
		let slot = if anonymous {
			format!("`_{}`", &slot[crate::util::copy_base_name(slot).len()..])
		} else {
			slot.clone()
		};
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
		info_message(&message, InfoLevel::Info);
	}
}

pub struct VerifyReport {
	pub file_name: String,
	pub sessions: u8,
	pub attacker: AttackerKind,
	pub results: Vec<VerifyResult>,
	pub code: String,
	pub elapsed: Option<std::time::Duration>,
	pub assumptions: Vec<(Value, Capability, i32)>,
	pub scenarios: Vec<ScenarioSummary>,
	pub auto_queries: bool,
}

impl VerifyReport {
	pub(crate) fn of(
		m: &Model,
		ctx: &VerifyContext,
		sessions: u8,
		elapsed: Option<std::time::Duration>,
	) -> VerifyReport {
		let results = ctx.results_get();
		VerifyReport {
			file_name: ctx.results_file_name().to_string(),
			sessions,
			attacker: m.attacker,
			code: VerifyResult::results_code(&results),
			results,
			elapsed,
			assumptions: ctx.assumptions().to_vec(),
			scenarios: ctx.scenarios().to_vec(),
			auto_queries: false,
		}
	}
}

pub fn verify(file_path: &str) -> VResult<(Vec<VerifyResult>, String)> {
	verify_with_sessions(file_path, crate::sessions::DEFAULT_SESSIONS)
}

pub fn verify_report(file_path: &str, sessions: u8) -> VResult<VerifyReport> {
	verify_report_with_source(file_path, sessions).map(|(report, _)| report)
}

pub fn verify_report_with_source(file_path: &str, sessions: u8) -> VResult<(VerifyReport, String)> {
	verify_report_with_source_opts(file_path, sessions, false)
}

pub fn verify_report_with_source_opts(
	file_path: &str,
	sessions: u8,
	auto_queries: bool,
) -> VResult<(VerifyReport, String)> {
	verify_parsed(parse_file(file_path)?, sessions, auto_queries)
}

pub(crate) fn verify_parsed(
	mut m: Model,
	sessions: u8,
	auto_queries: bool,
) -> VResult<(VerifyReport, String)> {
	let source = m.source.to_string();
	if auto_queries {
		let km = sanity(&m).map_err(|e| e.located(&m.file_name, &m.source))?;
		m.queries = crate::autoquery::auto_queries(&m, &km);
	}
	let mut report = verify_model(&m, sessions).map_err(|e| e.located(&m.file_name, &m.source))?;
	report.auto_queries = auto_queries;
	Ok((report, source))
}

pub fn verify_auto_queries(file_path: &str, sessions: u8) -> VResult<(Vec<VerifyResult>, String)> {
	verify_report_with_source_opts(file_path, sessions, true)
		.map(|(report, _)| (report.results, report.code))
}

pub fn verify_with_sessions(file_path: &str, sessions: u8) -> VResult<(Vec<VerifyResult>, String)> {
	verify_report(file_path, sessions).map(|report| (report.results, report.code))
}

fn verify_model(m: &Model, sessions: u8) -> VResult<VerifyReport> {
	let sessions = sessions.max(1);
	crate::info::info_status_begin();
	info_message(
		&format!(
			"Verification initiated for '{}' at {}.",
			m.file_name,
			chrono_time_string(),
		),
		InfoLevel::Verifpal,
	);
	let analyzed = analyze_sessions(m, sessions);
	let elapsed = crate::info::info_status_elapsed();
	crate::info::info_status_end();
	let report = VerifyReport::of(m, &analyzed?, sessions, elapsed);
	verify_end(&report);
	Ok(report)
}

pub(crate) fn check_honest_run(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	program: &Program,
	root: &Execution,
) -> VResult<()> {
	let located = |e: VerifpalError, slot: usize| e.or_span(km.slots[slot].declared_span);
	let failed = root
		.runs
		.iter()
		.filter_map(|run| run.halted.map(|slot| (slot, run)))
		.filter(|&(slot, _)| {
			let creator = km.slots[slot].creator;
			ctx.is_honest_at(creator, program.phase_of(creator, slot))
		})
		.min_by_key(|&(slot, _)| slot);
	if let Some((slot, run)) = failed
		&& let Some(Value::Primitive(p)) = run.held(slot).map(|held| &held.value)
	{
		return Err(located(honest_check_failure(p), slot));
	}
	for run in &root.runs {
		for (slot, held) in run.env.iter().enumerate() {
			if let Some(held) = held {
				sanity_check_argument_restrictions(&held.value).map_err(|e| located(e, slot))?;
			}
		}
	}
	Ok(())
}

pub(crate) fn status_line(
	ctx: &VerifyContext,
	phase: i32,
	principal: &str,
	activity: &str,
) -> String {
	let (done, total) = ctx.query_counts();
	let elapsed = if cfg!(target_arch = "wasm32") {
		String::new()
	} else {
		crate::info::info_status_elapsed()
			.map(|d| format!(" \u{00b7} {}", crate::info::info_elapsed_text(d)))
			.unwrap_or_default()
	};
	format!(
		"  phase {phase} \u{00b7} {principal} \u{00b7} {activity} \u{00b7} {done}/{total} queries resolved{elapsed}"
	)
}

fn verify_end(report: &VerifyReport) {
	let results = &report.results;
	let fail_count = results.iter().filter(|r| r.resolved).count();
	let total = results.len();

	crate::info::info_blank_line();
	crate::info::info_separator();
	let took = report
		.elapsed
		.map(|d| format!(" in {}", crate::info::info_elapsed_text(d)))
		.unwrap_or_default();
	info_message(
		&format!(
			"Verification completed for '{}' at {}{}.",
			report.file_name,
			chrono_time_string(),
			took,
		),
		InfoLevel::Verifpal,
	);
	crate::info::info_blank_line();

	let scenarios = &report.scenarios;
	if !scenarios.is_empty() {
		info_message(
			&format!(
				"Analysis performed over {} declared peer scenario{}:",
				scenarios.len(),
				crate::util::plural(scenarios.len()),
			),
			InfoLevel::Warning,
		);
		for scenario in scenarios {
			info_message(
				&format!("{scenario} ({})", peer_description(scenario.corrupt_from)),
				InfoLevel::Warning,
			);
		}
		crate::info::info_blank_line();
	}

	let assumptions = &report.assumptions;
	if !assumptions.is_empty() {
		info_message(
			&format!(
				"Analysis performed under {} declared weakening assumption{}:",
				assumptions.len(),
				crate::util::plural(assumptions.len()),
			),
			InfoLevel::Warning,
		);
		for (term, _, _) in assumptions {
			info_message(&term.to_string(), InfoLevel::Warning);
		}
		crate::info::info_blank_line();
	}

	for r in results {
		if r.resolved {
			info_message(
				&format!(
					"{}{}{}",
					crate::pretty::query_line(&r.query),
					r.subtype.map(Subtype::qualifier).unwrap_or_default(),
					r.summary
				),
				InfoLevel::Result,
			);
		} else {
			info_message(
				&format!(
					"{}{}",
					crate::pretty::query_line(&r.query),
					r.envelope.qualifier()
				),
				InfoLevel::Pass,
			);
		}
	}

	crate::info::info_blank_line();
	crate::info::info_separator();

	let suppressed = crate::info::info_deductions_suppressed();
	if suppressed > 0 {
		info_message(
			&format!("{} further deductions were not shown.", suppressed),
			InfoLevel::Info,
		);
	}

	if fail_count == 0 {
		info_message(&format!("All {} queries pass.", total), InfoLevel::Pass);
	} else {
		info_message(
			&format!("{} of {} queries failed.", fail_count, total),
			InfoLevel::Result,
		);
	}

	info_message("Thank you for using Verifpal.", InfoLevel::Verifpal);
}

fn chrono_time_string() -> String {
	use chrono::Local;
	Local::now().format("%I:%M:%S %p").to_string()
}

fn equivalence_queried<'a>(queries: impl Iterator<Item = &'a Query>) -> IdSet<ValueId> {
	queries
		.filter(|query| query.kind == QueryKind::Equivalence)
		.flat_map(|query| query.constants.iter().map(|c| c.id))
		.collect()
}

fn copy_sibling_groups(slots: &[TraceSlot]) -> IdMap<ValueId, Arc<Vec<ValueId>>> {
	let mut by_base: IdMap<ValueId, Vec<ValueId>> = IdMap::default();
	for slot in slots {
		let id = slot.constant.id;
		let (_, base) = crate::value::copy_index_of(id);
		let members = by_base.entry(base).or_default();
		if !members.contains(&id) {
			members.push(id);
		}
	}
	let mut out: IdMap<ValueId, Arc<Vec<ValueId>>> = IdMap::default();
	for members in by_base.into_values() {
		if members.len() < 2 {
			continue;
		}
		let group = Arc::new(members);
		for &member in group.iter() {
			out.insert(member, Arc::clone(&group));
		}
	}
	out
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
			let km = crate::sanity::sanity(m).expect("sanity");
			let mut v: Vec<_> = km.slots.iter().map(|s| s.constant.id).collect();
			v.sort_unstable();
			v
		};
		assert_eq!(ids(&first), ids(&second));
	}

	#[test]
	fn a_verdict_is_labelled_with_the_session_count_that_ran() {
		let m = parse_string("zero.vp", &model("ddd")).expect("parse");
		let ctx = super::analyze_sessions(&m, 0).expect("analyze");
		assert_eq!(
			ctx.results_get()[0].envelope.sessions,
			1,
			"a session count below one runs a single session, and the envelope has \
			 to say what ran: `search exhausted at 0 sessions` describes no search"
		);
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
