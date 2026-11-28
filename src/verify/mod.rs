/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub(crate) mod context;
pub(crate) mod record;
pub(crate) mod result;

pub(crate) use result::{
	Envelope, QueryOptionResult, ScenarioSummary, StepKind, Subtype, TraceStep, TraceValue,
	Truncation, VerifyResult,
};

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crate::console::InfoLevel;
use crate::primitive::{Capability, Reach};
use crate::protocol::sanity::sanity;
use crate::protocol::{ProtocolTrace, TraceSlot};
use crate::syntax::{AttackerKind, Model, PrincipalId, Query, QueryKind, VResult, VerifpalError};
use crate::term::{Value, ValueId};
use crate::util::{IdMap, IdSet};
use context::VerifyContext;
use result::peer_description;

#[cfg_attr(not(any(test, feature = "wasm")), allow(dead_code))]
pub(crate) fn analyze(m: &Model) -> VResult<VerifyContext> {
	analyze_sessions(m, crate::protocol::sessions::DEFAULT_SESSIONS)
}

pub(crate) fn analyze_sessions(m: &Model, sessions: u8) -> VResult<VerifyContext> {
	analyze_sessions_cancellable(m, sessions, Arc::new(AtomicBool::new(false)))
}

pub(crate) struct Expansion {
	pub(crate) model: Model,
	pub(crate) corrupt_from: Option<IdMap<PrincipalId, i32>>,
	pub(crate) scenarios: Vec<ScenarioSummary>,
	pub(crate) siblings: IdMap<ValueId, Arc<Vec<ValueId>>>,
	pub(crate) interchangeable: IdMap<PrincipalId, PrincipalId>,
	pub(crate) actors: IdMap<PrincipalId, PrincipalId>,
	pub(crate) dependent: IdSet<ValueId>,
}

impl Expansion {
	pub(crate) fn answers(&self, principal: PrincipalId) -> bool {
		self.corrupt_from
			.as_ref()
			.filter(|corrupt_from| !corrupt_from.is_empty())
			.is_none_or(|corrupt_from| corrupt_from.contains_key(&principal))
	}
}

pub(crate) fn expand(m: &Model, sessions: u8, cancel: &AtomicBool) -> VResult<Expansion> {
	let sessions = sessions.max(1);
	let e = crate::protocol::scenario::expand_scenarios(m, sessions, cancel)?;
	if let Some(scenarios) = crate::protocol::scenario::announcement(&e.scenarios) {
		crate::console::message(&scenarios, InfoLevel::Info);
	}
	if sessions == 1 {
		return Ok(e);
	}
	crate::protocol::sessions::expand_sessions(e, sessions)
}

#[cfg_attr(not(feature = "language"), allow(dead_code))]
pub(crate) fn check(m: &Model, sessions: u8) -> VResult<()> {
	admitted(m, sessions, Arc::default(), crate::engine::check).map(drop)
}

pub(crate) fn analyze_sessions_cancellable(
	m: &Model,
	sessions: u8,
	cancel: Arc<AtomicBool>,
) -> VResult<VerifyContext> {
	let ctx = admitted(m, sessions, cancel, crate::engine::verify)?;
	if ctx.cancelled() {
		return Err(VerifpalError::cancelled());
	}
	ctx.finalize_envelopes();
	Ok(ctx)
}

fn admitted(
	m: &Model,
	sessions: u8,
	cancel: Arc<AtomicBool>,
	engine: fn(&VerifyContext, &Model, &ProtocolTrace) -> VResult<()>,
) -> VResult<VerifyContext> {
	let sessions = sessions.max(1);
	let _generation = crate::util::generation::GenerationGuard::enter();
	crate::console::reset_deductions();
	let assumptions = crate::primitive::capability::declared_assumptions(m);
	let Expansion {
		model,
		corrupt_from,
		scenarios,
		siblings,
		interchangeable,
		actors,
		dependent,
	} = expand(m, sessions, &cancel)?;
	let m = &model;
	let mut trace = sanity(m)?;
	trace.session_siblings = siblings;
	trace.copy_siblings = copy_sibling_groups(&trace.slots);
	trace.interchangeable = interchangeable;
	trace.actors = actors;
	trace.scenario_dependent = dependent;
	trace.equivalence_queried =
		equivalence_queried(m.queries.iter().chain(m.variants.iter().flatten()));
	capability_reach_notice(&trace);
	let mut ctx = VerifyContext::new(
		m,
		m.variants.clone(),
		sessions,
		corrupt_from,
		scenarios,
		assumptions,
	);
	ctx.set_cancel(cancel);
	let ctx = ctx;
	engine(&ctx, m, &trace)?;
	Ok(ctx)
}

fn capability_reach_notice(trace: &ProtocolTrace) {
	let governed = trace.capabilities.governed_occurrences(&trace.slots);
	for (slot, reach) in &governed {
		let anonymous = crate::syntax::names::is_anonymous_name(slot);
		let slot = if anonymous {
			format!(
				"`_{}`",
				&slot[crate::syntax::names::copy_base_name(slot).len()..]
			)
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
		crate::console::message(&message, InfoLevel::Info);
	}
}

pub struct VerifyReport {
	pub(crate) file_name: String,
	pub(crate) sessions: u8,
	pub(crate) attacker: AttackerKind,
	pub(crate) results: Vec<VerifyResult>,
	pub(crate) code: String,
	pub(crate) elapsed: Option<std::time::Duration>,
	pub(crate) assumptions: Vec<(Value, Capability, i32)>,
	pub(crate) scenarios: Vec<ScenarioSummary>,
	pub(crate) auto_queries: bool,
}

impl VerifyReport {
	pub fn code(&self) -> &str {
		&self.code
	}

	pub fn attacked(&self) -> bool {
		self.results.iter().any(|r| r.resolved)
	}

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

#[cfg(test)]
pub(crate) fn verify(file_path: &str) -> VResult<(Vec<VerifyResult>, String)> {
	verify_with_sessions(file_path, crate::protocol::sessions::DEFAULT_SESSIONS)
}

#[cfg(test)]
pub(crate) fn verify_report(file_path: &str, sessions: u8) -> VResult<VerifyReport> {
	verify_report_with_source(file_path, sessions).map(|(report, _)| report)
}

#[cfg(test)]
pub(crate) fn verify_report_with_source(
	file_path: &str,
	sessions: u8,
) -> VResult<(VerifyReport, String)> {
	let (report, source) = verify_report_with_source_opts(file_path, sessions, false);
	report.map(|report| (report, source))
}

pub fn verify_report_with_source_opts(
	file_path: &str,
	sessions: u8,
	auto_queries: bool,
) -> (VResult<VerifyReport>, String) {
	match crate::syntax::parser::read_file(file_path) {
		Err(e) => (Err(e), String::new()),
		Ok((file_name, source)) => {
			let report = crate::syntax::parser::parse_string(&file_name, &source)
				.and_then(|m| verify_parsed(m, sessions, auto_queries))
				.map(|(report, _)| report);
			(report, source)
		}
	}
}

pub(crate) fn verify_parsed(
	mut m: Model,
	sessions: u8,
	auto_queries: bool,
) -> VResult<(VerifyReport, String)> {
	let source = m.source.to_string();
	if auto_queries {
		m.queries = crate::protocol::autoquery::auto_queries(&m)
			.map_err(|e| e.located(&m.file_name, &m.source))?;
	}
	let mut report = verify_model(&m, sessions).map_err(|e| e.located(&m.file_name, &m.source))?;
	report.auto_queries = auto_queries;
	Ok((report, source))
}

#[cfg(test)]
pub(crate) fn verify_auto_queries(
	file_path: &str,
	sessions: u8,
) -> VResult<(Vec<VerifyResult>, String)> {
	verify_report_with_source_opts(file_path, sessions, true)
		.0
		.map(|report| (report.results, report.code))
}

#[cfg(test)]
pub(crate) fn verify_with_sessions(
	file_path: &str,
	sessions: u8,
) -> VResult<(Vec<VerifyResult>, String)> {
	verify_report(file_path, sessions).map(|report| (report.results, report.code))
}

fn verify_model(m: &Model, sessions: u8) -> VResult<VerifyReport> {
	let sessions = sessions.max(1);
	crate::console::status_begin();
	crate::console::message(
		&format!(
			"Verification initiated for '{}' at {}.",
			m.file_name,
			chrono_time_string(),
		),
		InfoLevel::Verifpal,
	);
	let analyzed = analyze_sessions(m, sessions);
	let elapsed = crate::console::status_elapsed();
	crate::console::status_end();
	let report = VerifyReport::of(m, &analyzed?, sessions, elapsed);
	verify_end(&report);
	Ok(report)
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
		crate::console::status_elapsed()
			.map(|d| format!(" \u{00b7} {}", crate::console::elapsed_text(d)))
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

	crate::console::blank_line();
	crate::console::separator();
	let took = report
		.elapsed
		.map(|d| format!(" in {}", crate::console::elapsed_text(d)))
		.unwrap_or_default();
	crate::console::message(
		&format!(
			"Verification completed for '{}' at {}{}.",
			report.file_name,
			chrono_time_string(),
			took,
		),
		InfoLevel::Verifpal,
	);
	crate::console::blank_line();
	analysis_conditions(report);

	for r in results {
		if r.resolved {
			crate::console::message(
				&format!(
					"{}{}{}",
					crate::syntax::pretty::query_line(&r.query),
					r.subtype.map(Subtype::qualifier).unwrap_or_default(),
					r.summary
				),
				InfoLevel::Result,
			);
		} else {
			crate::console::message(
				&format!(
					"{}{}",
					crate::syntax::pretty::query_line(&r.query),
					r.envelope.qualifier()
				),
				InfoLevel::Pass,
			);
		}
	}

	crate::console::blank_line();
	crate::console::separator();

	let suppressed = crate::console::deductions_suppressed();
	if suppressed > 0 {
		crate::console::message(
			&format!("{} further deductions were not shown.", suppressed),
			InfoLevel::Info,
		);
	}

	if fail_count == 0 {
		crate::console::message(&format!("All {} queries pass.", total), InfoLevel::Pass);
	} else {
		crate::console::message(
			&format!("{} of {} queries failed.", fail_count, total),
			InfoLevel::Result,
		);
	}

	crate::console::message("Thank you for using Verifpal.", InfoLevel::Verifpal);
}

fn analysis_conditions(report: &VerifyReport) {
	let scenarios = &report.scenarios;
	if !scenarios.is_empty() {
		crate::console::message(
			&format!(
				"Analysis performed over {} declared peer scenario{}:",
				scenarios.len(),
				crate::util::text::plural(scenarios.len()),
			),
			InfoLevel::Warning,
		);
		for scenario in scenarios {
			crate::console::message(
				&format!("{scenario} ({})", peer_description(scenario.corrupt_from)),
				InfoLevel::Warning,
			);
		}
		crate::console::blank_line();
	}

	let assumptions = &report.assumptions;
	if !assumptions.is_empty() {
		crate::console::message(
			&format!(
				"Analysis performed under {} declared weakening assumption{}:",
				assumptions.len(),
				crate::util::text::plural(assumptions.len()),
			),
			InfoLevel::Warning,
		);
		for (term, _, _) in assumptions {
			crate::console::message(&term.to_string(), InfoLevel::Warning);
		}
		crate::console::blank_line();
	}
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

fn copy_sibling_groups<'a>(
	slots: impl IntoIterator<Item = &'a TraceSlot>,
) -> IdMap<ValueId, Arc<Vec<ValueId>>> {
	let mut by_base: IdMap<ValueId, Vec<ValueId>> = IdMap::default();
	for slot in slots {
		let id = slot.constant.id;
		let (_, base) = crate::term::copy_index_of(id);
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
	use crate::syntax::parser::parse_string;

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

		let ids = |m: &crate::syntax::Model| {
			let km = crate::protocol::sanity::sanity(m).expect("sanity");
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
	fn a_query_sane_in_a_later_scenario_passes_every_check_a_caller_makes() {
		for model in [
			"scenario_query_each_entry.vp",
			"scenario_query_each_entry_reversed.vp",
		] {
			let m = crate::syntax::parser::parse_file(&format!("examples/test/{model}"))
				.expect("parses");
			crate::protocol::sanity::sanity(&m)
				.unwrap_or_else(|e| panic!("{model} as written: {e}"));
			for sessions in [1, 2] {
				let e = super::expand(&m, sessions, &std::sync::atomic::AtomicBool::new(false))
					.expect("expands");
				crate::protocol::sanity::sanity(&e.model)
					.unwrap_or_else(|e| panic!("{model} at {sessions}: {e}"));
				assert_eq!(
					e.model.queries.len(),
					2,
					"the written queries stay as written"
				);
				assert!(e.model.variants.iter().all(|copies| !copies.is_empty()));
			}
		}
		let m = crate::syntax::parser::parse_file("examples/test/scenario_query_no_entry.vp")
			.expect("parses");
		crate::protocol::sanity::sanity(&m).expect("its queries are read in its scenario copies");
		let e = super::expand(&m, 2, &std::sync::atomic::AtomicBool::new(false)).expect("expands");
		let error = crate::protocol::sanity::sanity(&e.model).expect_err("no copy uses gd");
		assert!(error.message.contains("`gd` but never uses it"), "{error}");
	}

	#[test]
	fn the_source_shown_for_a_model_is_the_text_that_was_read_or_nothing() {
		let stem = std::env::temp_dir().join(format!("verifpal-source-{}", std::process::id()));
		let (refused, broken) = (stem.with_extension("txt"), stem.with_extension("vp"));
		std::fs::write(&refused, "not a model").expect("creates fixture");
		std::fs::write(&broken, "attacker[active]\nprincipal").expect("creates fixture");
		let (report, source) =
			super::verify_report_with_source_opts(&refused.to_string_lossy(), 2, false);
		assert!(report.is_err() && source.is_empty(), "{source}");
		let (report, source) =
			super::verify_report_with_source_opts(&broken.to_string_lossy(), 2, false);
		assert!(report.is_err());
		assert_eq!(source, "attacker[active]\nprincipal");
		std::fs::remove_file(&refused).expect("removes fixture");
		std::fs::remove_file(&broken).expect("removes fixture");
	}

	#[test]
	fn repeated_analysis_of_the_same_model_is_stable() {
		let m = parse_string("repeat.vp", &model("ccc")).expect("parse");
		let code = |m: &crate::syntax::Model| {
			crate::verify::VerifyResult::results_code(
				&super::analyze(m).expect("analyze").results_get(),
			)
		};
		let first = code(&m);
		let second = code(&m);
		assert_eq!(first, second);
		assert_eq!(first, "c0");
	}
}
