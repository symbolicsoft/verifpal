/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::str::FromStr;

use lsp_types::{Position, PositionEncodingKind, Range, Uri};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::info;
use crate::lsp::state::{Document, Documents};
use crate::report::{ModelReport, Run};
use crate::sessions::{DEFAULT_SESSIONS, MAX_SESSIONS};
use crate::types::*;
use crate::verify::VerifyReport;

const FILE_NAME: &str = "workbench.vp";

const URI: &str = "file:///workbench.vp";

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Serialize)]
struct WasmVerify {
	ok: bool,
	error: String,
	results: Vec<WasmResult>,
	code: String,
	assumptions: Vec<WasmAssumption>,
	scenarios: Vec<WasmScenario>,
	messages: Vec<String>,
}

#[derive(Serialize)]
struct WasmScenario {
	summary: String,
	honest: bool,
}

#[derive(Serialize)]
struct WasmResult {
	query: String,
	resolved: bool,
	kind: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	subtype: Option<String>,
	summary: String,
	envelope: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WasmAssumption {
	term: String,
	capability: String,
	from_phase: i32,
}

#[derive(Serialize)]
struct WasmPretty {
	ok: bool,
	error: String,
	output: String,
}

#[derive(Serialize)]
struct WasmAnalyze {
	ok: bool,
	error: String,
	code: String,
	results: Vec<WasmResult>,
	assumptions: Vec<WasmAssumption>,
	scenarios: Vec<WasmScenario>,
	messages: Vec<String>,
	sessions: u8,
	saturation: Option<WasmSaturation>,
	report: Option<ModelReport>,
	html: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WasmSaturation {
	stable_from: u8,
	saturated: bool,
	regressed: bool,
	ceiling: u8,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct AnalyzeOptions {
	sessions: Option<i64>,
	auto_queries: bool,
	saturate: bool,
	report: bool,
}

#[derive(Serialize)]
struct WasmCheck {
	diagnostics: Vec<lsp_types::Diagnostic>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LanguageRequest {
	method: String,
	#[serde(default)]
	line: u32,
	#[serde(default)]
	character: u32,
	#[serde(default)]
	new_name: Option<String>,
}

#[derive(Serialize)]
struct WasmLanguage {
	result: serde_json::Value,
	#[serde(skip_serializing_if = "Option::is_none")]
	error: Option<String>,
}

#[derive(Serialize)]
struct WasmSuggest {
	ok: bool,
	error: String,
	queries: Vec<String>,
}

fn serialize(payload: &impl Serialize, fallback: &str) -> String {
	serde_json::to_string(payload).unwrap_or_else(|_| fallback.to_string())
}

fn results_of(results: &[VerifyResult]) -> Vec<WasmResult> {
	results
		.iter()
		.map(|r| WasmResult {
			query: r.query.to_string(),
			resolved: r.resolved,
			kind: r.query.kind.name().to_string(),
			subtype: r.subtype.map(|s| s.name().to_string()),
			summary: r.summary.clone(),
			envelope: r.envelope.summary(),
		})
		.collect()
}

fn assumptions_of(assumptions: &[(Value, Capability, i32)]) -> Vec<WasmAssumption> {
	assumptions
		.iter()
		.map(|(term, capability, onset)| WasmAssumption {
			term: term.to_string(),
			capability: capability.name().to_string(),
			from_phase: *onset,
		})
		.collect()
}

fn scenarios_of(scenarios: &[ScenarioSummary]) -> Vec<WasmScenario> {
	scenarios
		.iter()
		.map(|s| WasmScenario {
			summary: s.to_string(),
			honest: s.honest,
		})
		.collect()
}

fn begin() {
	info::wasm_messages_init();
	#[cfg(target_arch = "wasm32")]
	progress_reset();
}

fn wasm_verify_inner(input: &str) -> VResult<WasmVerify> {
	let m = crate::parser::parse_string(FILE_NAME, input)?;
	let ctx = crate::verify::analyze(&m).map_err(|e| e.located(&m.file_name, &m.source))?;
	let results = ctx.results_get();
	Ok(WasmVerify {
		ok: true,
		error: String::new(),
		code: VerifyResult::results_code(&results),
		results: results_of(&results),
		assumptions: assumptions_of(&ctx.capability_assumptions()),
		scenarios: scenarios_of(ctx.scenarios()),
		messages: info::wasm_messages_drain(),
	})
}

#[wasm_bindgen]
pub fn wasm_verify(input: &str) -> String {
	begin();
	let payload = wasm_verify_inner(input).unwrap_or_else(|e| WasmVerify {
		ok: false,
		error: e.to_string(),
		results: vec![],
		code: String::new(),
		assumptions: vec![],
		scenarios: vec![],
		messages: info::wasm_messages_drain(),
	});
	serialize(
		&payload,
		r#"{"ok":false,"error":"could not serialize the result","results":[],"code":"","assumptions":[],"scenarios":[],"messages":[]}"#,
	)
}

#[wasm_bindgen]
pub fn wasm_pretty(input: &str) -> String {
	let payload = match crate::parser::parse_string(FILE_NAME, input)
		.map(|m| crate::pretty::pretty_model(&m))
	{
		Ok(output) => WasmPretty {
			ok: true,
			error: String::new(),
			output,
		},
		Err(e) => WasmPretty {
			ok: false,
			error: e.to_string(),
			output: String::new(),
		},
	};
	serialize(
		&payload,
		r#"{"ok":false,"error":"could not serialize","output":""}"#,
	)
}

fn analyze_options(options: &str) -> Result<(u8, AnalyzeOptions), String> {
	let value = if options.trim().is_empty() {
		serde_json::Value::Null
	} else {
		serde_json::from_str(options).map_err(|e| format!("invalid options: {e}"))?
	};
	let options = match value {
		serde_json::Value::Null => AnalyzeOptions::default(),
		serde_json::Value::Object(_) => {
			serde_json::from_value(value).map_err(|e| format!("invalid options: {e}"))?
		}
		_ => return Err("invalid options: expected a JSON object".to_string()),
	};
	let sessions = match options.sessions {
		None => DEFAULT_SESSIONS,
		Some(k) => u8::try_from(k)
			.ok()
			.filter(|k| (1..=MAX_SESSIONS).contains(k))
			.ok_or_else(|| {
				format!("invalid options: sessions must be from 1 to {MAX_SESSIONS}, not {k}")
			})?,
	};
	Ok((sessions, options))
}

fn analyze_model(
	input: &str,
	sessions: u8,
	options: &AnalyzeOptions,
) -> VResult<(VerifyReport, String, Option<WasmSaturation>)> {
	let m = crate::parser::parse_string(FILE_NAME, input)?;
	if !options.saturate {
		let (report, source) = crate::verify::verify_parsed(m, sessions, options.auto_queries)?;
		return Ok((report, source, None));
	}
	let saturation = crate::verify::saturate(crate::verify::SATURATE_MAX, |k| {
		crate::verify::verify_parsed(m.clone(), k, options.auto_queries)
	})?;
	if saturation.regressed {
		crate::verify::saturation_regressed_warning();
	}
	info::info_message(&saturation.summary(), InfoLevel::Info, false);
	info::wasm_messages_replay(saturation.output);
	let note = saturation
		.report
		.provenance
		.saturation
		.map(|s| WasmSaturation {
			stable_from: s.stable_from,
			saturated: s.saturated,
			regressed: s.regressed,
			ceiling: s.ceiling,
		});
	Ok((saturation.report, saturation.source, note))
}

fn analyze(input: &str, sessions: u8, options: &AnalyzeOptions) -> WasmAnalyze {
	let (payload, outcome, source) = match analyze_model(input, sessions, options) {
		Ok((report, source, saturation)) => (
			WasmAnalyze {
				ok: true,
				error: String::new(),
				code: report.code.clone(),
				results: results_of(&report.results),
				assumptions: assumptions_of(&report.assumptions),
				scenarios: scenarios_of(&report.scenarios),
				messages: Vec::new(),
				sessions: report.sessions,
				saturation,
				report: None,
				html: None,
			},
			Ok(report),
			source,
		),
		Err(e) => {
			let error = e.to_string();
			(
				WasmAnalyze::failed(error.clone()),
				Err(error),
				input.to_string(),
			)
		}
	};
	let run = Run::of(
		VERSION,
		&[(FILE_NAME.to_string(), outcome)],
		std::slice::from_ref(&source),
	);
	let html = options.report.then(|| crate::html::html_report(&run));
	WasmAnalyze {
		report: run.models.into_iter().next(),
		html,
		messages: info::wasm_messages_drain(),
		..payload
	}
}

impl WasmAnalyze {
	fn failed(error: String) -> WasmAnalyze {
		WasmAnalyze {
			ok: false,
			error,
			code: String::new(),
			results: Vec::new(),
			assumptions: Vec::new(),
			scenarios: Vec::new(),
			messages: Vec::new(),
			sessions: 0,
			saturation: None,
			report: None,
			html: None,
		}
	}
}

#[wasm_bindgen]
pub fn wasm_analyze(input: &str, options: &str) -> String {
	begin();
	let payload = match analyze_options(options) {
		Ok((sessions, options)) => analyze(input, sessions, &options),
		Err(error) => WasmAnalyze {
			messages: info::wasm_messages_drain(),
			..WasmAnalyze::failed(error)
		},
	};
	serialize(
		&payload,
		r#"{"ok":false,"error":"could not serialize the result","code":"","results":[],"assumptions":[],"scenarios":[],"messages":[],"sessions":0,"saturation":null,"report":null,"html":null}"#,
	)
}

fn uri() -> Option<Uri> {
	Uri::from_str(URI).ok()
}

fn documents(input: &str) -> Documents {
	let mut docs = Documents::new(PositionEncodingKind::UTF16);
	docs.open(URI.to_string(), FILE_NAME.to_string(), 1, input.to_string());
	docs
}

#[wasm_bindgen]
pub fn wasm_check(input: &str) -> String {
	let _quiet = info::InfoQuiet::new();
	let docs = documents(input);
	let diagnostics = match (docs.get(URI), uri()) {
		(Some(doc), Some(uri)) => crate::lsp::diagnostics::for_document(doc, &uri),
		_ => Vec::new(),
	};
	serialize(&WasmCheck { diagnostics }, r#"{"diagnostics":[]}"#)
}

fn answer(result: impl Serialize) -> WasmLanguage {
	match serde_json::to_value(result) {
		Ok(result) => WasmLanguage {
			result,
			error: None,
		},
		Err(e) => refuse(format!("could not serialize the result: {e}")),
	}
}

fn refuse(error: String) -> WasmLanguage {
	WasmLanguage {
		result: serde_json::Value::Null,
		error: Some(error),
	}
}

fn language(doc: &Document, uri: &Uri, request: &LanguageRequest) -> WasmLanguage {
	use crate::lsp::language;
	let at = Position::new(request.line, request.character);
	match request.method.as_str() {
		"hover" => answer(language::hover(doc, at)),
		"completion" => answer(language::completions(doc, at)),
		"signatureHelp" => answer(language::signature_help(doc, at)),
		"definition" => answer(language::definition(doc, at, uri)),
		"references" => answer(language::references(doc, at, uri)),
		"highlights" => answer(language::highlights(doc, at)),
		"prepareRename" => answer(language::prepare_rename(doc, at)),
		"rename" => match &request.new_name {
			Some(name) => answer(language::rename(doc, at, name)),
			None => refuse("rename needs a newName".to_string()),
		},
		"documentSymbols" => answer(language::document_symbols(doc)),
		"inlayHints" => answer(language::inlay_hints(
			doc,
			Range::new(Position::new(0, 0), doc.line.end()),
		)),
		other => refuse(format!("unknown method: {other}")),
	}
}

#[wasm_bindgen]
pub fn wasm_language(input: &str, request: &str) -> String {
	let _quiet = info::InfoQuiet::new();
	let payload = match serde_json::from_str::<LanguageRequest>(request) {
		Ok(request) => {
			let docs = documents(input);
			match (docs.get(URI), uri()) {
				(Some(doc), Some(uri)) => language(doc, &uri, &request),
				_ => refuse("the document could not be opened".to_string()),
			}
		}
		Err(e) => refuse(format!("invalid request: {e}")),
	};
	serialize(
		&payload,
		r#"{"result":null,"error":"could not serialize the result"}"#,
	)
}

fn suggest(input: &str) -> VResult<Vec<String>> {
	let m = crate::parser::parse_string_queries_optional(FILE_NAME, input)?;
	let (km, ps) = crate::sanity::sanity(&m).map_err(|e| e.located(&m.file_name, &m.source))?;
	Ok(crate::autoquery::auto_queries(&m, &km, &ps)
		.iter()
		.map(|q| q.to_string())
		.collect())
}

#[wasm_bindgen]
pub fn wasm_suggest_queries(input: &str) -> String {
	let _quiet = info::InfoQuiet::new();
	let payload = match suggest(input) {
		Ok(queries) => WasmSuggest {
			ok: true,
			error: String::new(),
			queries,
		},
		Err(e) => WasmSuggest {
			ok: false,
			error: e.to_string(),
			queries: Vec::new(),
		},
	};
	serialize(
		&payload,
		r#"{"ok":false,"error":"could not serialize the result","queries":[]}"#,
	)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
	#[wasm_bindgen(catch, js_namespace = globalThis, js_name = verifpalProgress)]
	fn verifpal_progress(kind: &str, text: &str) -> Result<(), JsValue>;
}

#[cfg(target_arch = "wasm32")]
const PROGRESS_INTERVAL_MS: f64 = 100.0;

#[cfg(target_arch = "wasm32")]
thread_local! {
	static PROGRESS_LAST: std::cell::Cell<f64> = const { std::cell::Cell::new(f64::NEG_INFINITY) };
}

#[cfg(target_arch = "wasm32")]
fn progress_reset() {
	PROGRESS_LAST.set(f64::NEG_INFINITY);
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn progress_status(text: impl FnOnce() -> String) {
	let now = js_sys::Date::now();
	if (now - PROGRESS_LAST.get()).abs() < PROGRESS_INTERVAL_MS {
		return;
	}
	PROGRESS_LAST.set(now);
	let _ = verifpal_progress("status", text().trim_start());
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn progress_message(line: &str) {
	let _ = verifpal_progress("message", line);
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::tokens::TokenKind;

	const DH: &str = "attacker[active]\n\
		principal Alice[\n\
		\tknows private wdh_a\n\
		\twdh_ga = PUBKEY(wdh_a)\n\
		]\n\
		Alice -> Bob: wdh_ga\n\
		principal Bob[\n\
		\tknows private wdh_b\n\
		\twdh_gb = PUBKEY(wdh_b)\n\
		\twdh_k = DH_KEX(wdh_ga, wdh_b)\n\
		\tgenerates wdh_m, wdh_n\n\
		\twdh_e = AEAD_ENC(wdh_k, wdh_n, wdh_m, nil)\n\
		]\n\
		Bob -> Alice: wdh_gb, wdh_n, wdh_e\n\
		queries[\n\
		\tconfidentiality? wdh_m\n\
		]\n";

	const PASSIVE: &str = "attacker[passive]\n\
		principal Alice[\n\
		\tknows private wps_m\n\
		\twps_h = HASH(wps_m)\n\
		]\n\
		Alice -> Bob: wps_h\n\
		principal Bob[\n\
		\t_ = HASH(wps_h)\n\
		]\n\
		queries[\n\
		\tconfidentiality? wps_m\n\
		]\n";

	fn json(text: String) -> serde_json::Value {
		serde_json::from_str(&text).expect("valid JSON")
	}

	fn corpus(name: &str) -> String {
		std::fs::read_to_string(format!("examples/test/{name}"))
			.expect("the model is in the corpus")
	}

	fn position(source: &str, needle: &str) -> (u32, u32) {
		let at = source.find(needle).expect("in the source");
		let before = &source[..at];
		let start = before.rfind('\n').map_or(0, |i| i + 1);
		let character: usize = before[start..].chars().map(char::len_utf16).sum();
		(before.matches('\n').count() as u32, character as u32)
	}

	fn ask(source: &str, method: &str, needle: &str) -> serde_json::Value {
		let (line, character) = position(source, needle);
		let request = serde_json::json!({"method": method, "line": line, "character": character});
		json(wasm_language(source, &request.to_string()))
	}

	fn at(source: &str, needle: &str) -> serde_json::Value {
		let (line, character) = position(source, needle);
		serde_json::json!({"line": line, "character": character})
	}

	#[test]
	fn a_wasm_result_carries_the_verdict_qualifier() {
		let source = corpus("conf_attacker_supplied_value.vp");
		let payload = json(wasm_verify(&source));
		assert_eq!(payload["ok"], true);
		assert_eq!(payload["results"][0]["subtype"], "attacker-supplied value");
		assert!(payload["results"][1].get("subtype").is_none());
	}

	#[test]
	fn an_analysis_with_default_options_agrees_with_verify() {
		let source = corpus("hmac_ok.vp");
		let verified = json(wasm_verify(&source));
		let analyzed = json(wasm_analyze(&source, "{}"));
		assert_eq!(analyzed["ok"], true, "{analyzed}");
		assert_eq!(analyzed["error"], "");
		assert_eq!(analyzed["code"], "c0a1");
		assert_eq!(analyzed["code"], verified["code"]);
		assert_eq!(analyzed["results"], verified["results"]);
		assert_eq!(analyzed["assumptions"], verified["assumptions"]);
		assert_eq!(analyzed["scenarios"], verified["scenarios"]);
		assert_eq!(analyzed["sessions"], DEFAULT_SESSIONS);
		assert!(analyzed["saturation"].is_null());
		assert!(analyzed["html"].is_null());
		assert_eq!(analyzed["report"]["file"], FILE_NAME);
		assert_eq!(analyzed["report"]["analysis"]["code"], "c0a1");
		assert_eq!(analyzed["report"]["analysis"]["sessions"], DEFAULT_SESSIONS);
	}

	#[test]
	fn empty_or_null_options_mean_the_defaults() {
		for options in ["", " ", "null", "{}"] {
			let payload = json(wasm_analyze(PASSIVE, options));
			assert_eq!(payload["ok"], true, "{options:?}: {payload}");
			assert_eq!(payload["sessions"], DEFAULT_SESSIONS, "{options:?}");
			assert_eq!(payload["code"], "c0", "{options:?}");
		}
	}

	#[test]
	fn one_session_cannot_replay_across_sessions() {
		let source = corpus("session_replay_breaks_injectivity.vp");
		let two = json(wasm_analyze(&source, ""));
		let one = json(wasm_analyze(&source, r#"{"sessions": 1}"#));
		assert_eq!(two["code"], "a1", "{two}");
		assert_eq!(one["code"], "a0", "{one}");
		assert_eq!(one["sessions"], 1);
		assert_eq!(one["report"]["analysis"]["sessions"], 1);
		assert_eq!(
			one["results"][0]["envelope"],
			"search exhausted at 1 session"
		);
	}

	#[test]
	fn generated_queries_replace_the_written_ones() {
		let source = corpus("hmac_ok.vp");
		let payload = json(wasm_analyze(&source, r#"{"autoQueries": true}"#));
		assert_eq!(payload["ok"], true, "{payload}");
		let queries = payload["report"]["analysis"]["queries"]
			.as_array()
			.expect("queries");
		assert!(queries.len() > 2, "{queries:?}");
		assert!(
			queries.iter().all(|q| q["generated"] == true),
			"{queries:?}"
		);
		assert_eq!(
			payload["results"].as_array().map(Vec::len),
			Some(queries.len())
		);
		assert!(
			payload["report"]["analysis"]["provenance"][0]
				.as_str()
				.is_some_and(|p| p.contains("--auto-queries")),
			"{}",
			payload["report"]["analysis"]["provenance"]
		);
	}

	#[test]
	fn saturation_reports_where_the_verdicts_settled() {
		let source = corpus("session_replay_breaks_injectivity.vp");
		let payload = json(wasm_analyze(
			&source,
			r#"{"saturate": true, "sessions": 1}"#,
		));
		assert_eq!(payload["ok"], true, "{payload}");
		assert_eq!(payload["code"], "a1");
		assert_eq!(
			payload["sessions"], 3,
			"saturation overrides the requested count, as --saturate does"
		);
		assert_eq!(
			payload["saturation"],
			serde_json::json!({
				"stableFrom": 2,
				"saturated": true,
				"regressed": false,
				"ceiling": crate::verify::SATURATE_MAX,
			})
		);
		assert_eq!(payload["report"]["analysis"]["sessions"], 3);
	}

	#[test]
	fn a_report_carries_the_html_page_of_the_same_run() {
		let payload = json(wasm_analyze(DH, r#"{"report": true, "sessions": 1}"#));
		assert_eq!(payload["ok"], true, "{payload}");
		let html = payload["html"].as_str().expect("an HTML page");
		assert!(
			html.to_ascii_lowercase().starts_with("<!doctype html>"),
			"{}",
			&html[..html.len().min(80)]
		);
		assert!(html.contains("wdh_m"));
		let analysis = &payload["report"]["analysis"];
		assert_eq!(analysis["code"], "c1");
		assert_eq!(analysis["queries"][0]["resolved"], true);
		assert!(
			!analysis["queries"][0]["steps"]
				.as_array()
				.expect("steps")
				.is_empty()
		);
		assert!(
			!payload["report"]["diagram"]
				.as_array()
				.expect("diagram rows")
				.is_empty()
		);
	}

	#[test]
	fn a_query_range_points_at_the_query_in_the_source() {
		let source = corpus("hmac_ok.vp");
		let payload = json(wasm_analyze(&source, r#"{"sessions": 1}"#));
		let queries = payload["report"]["analysis"]["queries"]
			.as_array()
			.expect("queries");
		assert_eq!(queries.len(), 2);
		for q in queries {
			let range = &q["range"];
			let start = range["start"].as_u64().expect("start") as usize;
			let end = range["end"].as_u64().expect("end") as usize;
			let quoted = &source[start..end];
			let kind = q["kind"].as_str().expect("kind");
			assert!(quoted.starts_with(kind), "{kind}: {quoted:?}");
			let line = source
				.lines()
				.nth(range["line"].as_u64().expect("line") as usize - 1)
				.expect("the line exists");
			assert!(
				line.contains(quoted.lines().next().unwrap_or("")),
				"{line:?}"
			);
		}
	}

	#[test]
	fn bad_options_are_refused_rather_than_guessed() {
		for options in [
			"{",
			"[]",
			"2",
			r#"{"sessions": 0}"#,
			r#"{"sessions": 17}"#,
			r#"{"sessions": -1}"#,
			r#"{"sessions": 300}"#,
			r#"{"sessions": 2.5}"#,
			r#"{"sessions": "2"}"#,
			r#"{"session": 2}"#,
			r#"{"saturate": "yes"}"#,
		] {
			let payload = json(wasm_analyze(DH, options));
			assert_eq!(payload["ok"], false, "{options}: {payload}");
			assert!(
				payload["error"]
					.as_str()
					.is_some_and(|e| e.starts_with("invalid options")),
				"{options}: {payload}"
			);
			for empty in ["results", "assumptions", "scenarios"] {
				assert_eq!(payload[empty], serde_json::json!([]), "{options}");
			}
			assert!(payload["messages"].is_array());
			assert_eq!(payload["code"], "");
			assert!(payload["report"].is_null(), "{options}");
			assert!(payload["html"].is_null(), "{options}");
			assert!(payload["saturation"].is_null(), "{options}");
		}
	}

	#[test]
	fn a_model_that_does_not_parse_still_reports_its_error() {
		let broken = "attacker[active]\nprincipal Alice[\n\tknows private wpe_a\n";
		let payload = json(wasm_analyze(broken, r#"{"report": true}"#));
		assert_eq!(payload["ok"], false, "{payload}");
		assert_eq!(payload["error"], json(wasm_verify(broken))["error"]);
		assert_eq!(payload["results"], serde_json::json!([]));
		assert_eq!(payload["report"]["ok"], false);
		assert_eq!(payload["report"]["error"], payload["error"]);
		assert!(payload["report"].get("analysis").is_none());
		assert!(payload["html"].is_string());
	}

	#[test]
	fn a_model_that_fails_validation_still_reports_its_diagram() {
		let insane = PASSIVE.replace("confidentiality? wps_m", "confidentiality? wps_nothing");
		let payload = json(wasm_analyze(&insane, "{}"));
		assert_eq!(payload["ok"], false, "{payload}");
		assert_eq!(payload["error"], json(wasm_verify(&insane))["error"]);
		assert_eq!(payload["report"]["error"], payload["error"]);
		assert!(
			!payload["report"]["diagram"]
				.as_array()
				.expect("the model parses, so it has a diagram")
				.is_empty()
		);
	}

	#[test]
	fn a_check_places_an_undefined_constant_on_its_line() {
		let source = "attacker[passive]\n\
			principal Alice[\n\
			\tknows private wck_m\n\
			\twck_h = HASH(wck_m, wck_x)\n\
			]\n\
			queries[\n\
			\tconfidentiality? wck_m\n\
			]\n";
		let payload = json(wasm_check(source));
		let diagnostics = payload["diagnostics"].as_array().expect("diagnostics");
		assert_eq!(diagnostics.len(), 1, "{payload}");
		let d = &diagnostics[0];
		assert_eq!(d["range"]["start"]["line"], 3, "{d}");
		assert_eq!(d["severity"], 1);
		assert_eq!(d["source"], "verifpal");
		assert!(
			d["message"].as_str().is_some_and(|m| m.contains("wck_x")),
			"{d}"
		);
		assert_eq!(
			json(wasm_check(PASSIVE))["diagnostics"],
			serde_json::json!([])
		);
		let unparsed = json(wasm_check("attacker[active]\nprincipal Alice[\n"));
		assert_eq!(unparsed["diagnostics"][0]["code"], "parse error");
	}

	#[test]
	fn hovering_a_primitive_documents_it() {
		let payload = ask(DH, "hover", "AEAD_ENC");
		assert!(payload.get("error").is_none(), "{payload}");
		assert_eq!(payload["result"]["contents"]["kind"], "markdown");
		let value = payload["result"]["contents"]["value"]
			.as_str()
			.expect("markdown");
		assert!(value.contains("AEAD_ENC"), "{value}");
		assert_eq!(payload["result"]["range"]["start"], at(DH, "AEAD_ENC"));
	}

	#[test]
	fn completion_offers_primitives_inside_a_principal() {
		let payload = ask(DH, "completion", "wdh_gb = PUBKEY");
		let items = payload["result"].as_array().expect("items");
		assert!(items.iter().any(|i| i["label"] == "PUBKEY"), "{payload}");
		assert!(items.iter().any(|i| i["label"] == "wdh_ga"), "{payload}");
	}

	#[test]
	fn signature_help_names_the_argument_under_the_cursor() {
		let payload = ask(DH, "signatureHelp", "wdh_n, wdh_m, nil)");
		let help = &payload["result"];
		assert_eq!(
			help["signatures"][0]["label"], "AEAD_ENC(key, nonce, plaintext, ad)",
			"{payload}"
		);
		assert_eq!(help["activeParameter"], 1);
		assert!(ask(DH, "signatureHelp", "attacker")["result"].is_null());
	}

	#[test]
	fn definition_of_a_use_is_its_declaration() {
		let payload = ask(DH, "definition", "wdh_ga, wdh_b)");
		assert_eq!(payload["result"]["uri"], URI, "{payload}");
		assert_eq!(
			payload["result"]["range"]["start"],
			at(DH, "wdh_ga = PUBKEY")
		);
	}

	#[test]
	fn the_symbol_queries_answer_in_lsp_shapes() {
		let references = ask(DH, "references", "wdh_ga = PUBKEY");
		assert_eq!(references["result"].as_array().map(Vec::len), Some(3));
		let highlights = ask(DH, "highlights", "wdh_ga = PUBKEY");
		assert_eq!(highlights["result"][0]["kind"], 3, "{highlights}");
		assert_eq!(highlights["result"][1]["kind"], 2, "{highlights}");
		let prepared = ask(DH, "prepareRename", "wdh_ga = PUBKEY");
		assert_eq!(prepared["result"]["start"], at(DH, "wdh_ga = PUBKEY"));
		assert!(ask(DH, "prepareRename", "PUBKEY")["result"].is_null());
		let (line, character) = position(DH, "wdh_ga = PUBKEY");
		let renamed = json(wasm_language(
			DH,
			&serde_json::json!({
				"method": "rename",
				"line": line,
				"character": character,
				"newName": "wdh_alice",
			})
			.to_string(),
		));
		let edits = renamed["result"].as_array().expect("edits");
		assert_eq!(edits.len(), 3, "{renamed}");
		assert!(edits.iter().all(|e| e["newText"] == "wdh_alice"));
		let symbols = json(wasm_language(DH, r#"{"method": "documentSymbols"}"#));
		assert!(
			symbols["result"]
				.as_array()
				.expect("symbols")
				.iter()
				.any(|s| s["name"] == "Alice"),
			"{symbols}"
		);
		let hints = json(wasm_language(DH, r#"{"method": "inlayHints"}"#));
		assert!(
			hints["result"]
				.as_array()
				.expect("hints")
				.iter()
				.any(|h| h["label"] == "key: "),
			"{hints}"
		);
	}

	#[test]
	fn a_malformed_or_unknown_request_is_an_error() {
		for request in [
			"{",
			"null",
			r#"{"line": 0, "character": 0}"#,
			r#"{"method": "hover", "line": -1, "character": 0}"#,
			r#"{"method": "folding"}"#,
			r#"{"method": "rename", "line": 3, "character": 1}"#,
		] {
			let payload = json(wasm_language(DH, request));
			assert!(payload["result"].is_null(), "{request}: {payload}");
			assert!(payload["error"].is_string(), "{request}: {payload}");
		}
	}

	#[test]
	fn positions_count_utf16_code_units() {
		let source = "attacker[passive]\n\
			principal Alice[\n\
			\tknows private wu_m\n\
			\t/* \u{1F600}\u{e9} */ wu_h = HASH(wu_m)\n\
			]\n\
			queries[\n\
			\tconfidentiality? wu_m\n\
			]\n";
		let (line, character) = position(source, "HASH");
		assert_eq!(character, 18, "the astral character is two units");
		let payload = ask(source, "hover", "HASH");
		assert_eq!(
			payload["result"]["range"]["start"],
			serde_json::json!({"line": line, "character": character}),
			"{payload}"
		);
		let references = ask(source, "references", "wu_m)");
		assert_eq!(
			references["result"][1]["range"]["start"],
			at(source, "wu_m)"),
			"{references}"
		);
	}

	#[test]
	fn no_position_in_or_around_a_document_panics() {
		let source = "attacker[active]\n\
			principal Alice[\n\
			\tknows private wnp_k\n\
			\t/* \u{1F600} */ wnp_e = AEAD_ENC[forgeable from phase 1](wnp_k, wnp_k, wnp_k, nil)\n\
			]\n\
			Alice -> Bob: [wnp_e]\n\
			principal Bob[\n\
			\t_ = AEAD_DEC(wnp_k, wnp_k, wnp_e, nil)?\n\
			]\n\
			queries[\n\
			\tauthentication? Alice -> Bob: wnp_e[\n\
			\t\tprecondition[Alice -> Bob: wnp_e]\n\
			\t]\n\
			]\n";
		let methods = [
			"hover",
			"completion",
			"signatureHelp",
			"definition",
			"references",
			"highlights",
			"prepareRename",
			"rename",
			"documentSymbols",
			"inlayHints",
		];
		let lines: Vec<&str> = source.split('\n').collect();
		for (line, text) in lines.iter().enumerate().chain([(lines.len() + 2, &"")]) {
			let width: usize = text.chars().map(char::len_utf16).sum();
			for character in 0..=width + 2 {
				for method in methods {
					let request = serde_json::json!({
						"method": method,
						"line": line,
						"character": character,
						"newName": "wnp_renamed",
					});
					let payload = json(wasm_language(source, &request.to_string()));
					assert!(payload.get("error").is_none(), "{request}: {payload}");
				}
			}
		}
		for truncated in (0..source.len()).filter(|&i| source.is_char_boundary(i)) {
			json(wasm_check(&source[..truncated]));
		}
	}

	fn with_queries(source: &str, lines: &[String]) -> String {
		let (_, index) = crate::parser::parse_string_indexed(FILE_NAME, source);
		let start = index
			.tokens()
			.iter()
			.rev()
			.find(|t| t.kind == TokenKind::Keyword && t.text.eq_ignore_ascii_case("queries"))
			.map_or(source.len(), |t| t.span.start);
		let head = &source[..start];
		let separator = if head.is_empty() || head.ends_with('\n') {
			""
		} else {
			"\n"
		};
		let block: String = lines.iter().map(|line| format!("\t{line}\n")).collect();
		format!("{head}{separator}queries[\n{block}]\n")
	}

	#[test]
	fn queries_are_suggested_for_a_model_that_asks_none_yet() {
		let body = &PASSIVE[..PASSIVE.find("queries[").expect("a queries block")];
		for source in [
			body.to_string(),
			body.trim_end().to_string(),
			format!("{body}queries[]\n"),
			format!("{body}queries[\n\t// later\n]\n"),
		] {
			let payload = json(wasm_suggest_queries(&source));
			assert_eq!(payload["ok"], true, "{source:?}: {payload}");
			let lines: Vec<String> = payload["queries"]
				.as_array()
				.expect("queries")
				.iter()
				.map(|q| q.as_str().expect("a line").to_string())
				.collect();
			assert!(
				lines.contains(&"confidentiality? wps_m".to_string()),
				"{lines:?}"
			);
			let text = with_queries(&source, &lines);
			let m = crate::parser::parse_string(FILE_NAME, &text)
				.unwrap_or_else(|e| panic!("the suggestions do not parse: {e}\n{text}"));
			crate::sanity::sanity(&m).expect("the suggestions pass sanity");
			let reparsed: Vec<String> = m.queries.iter().map(|q| q.to_string()).collect();
			assert_eq!(reparsed, lines);
		}
		for refused in [
			format!("{body}queries[\n"),
			format!("{body}queries[]\nprincipal Carol[\n\tknows private wps_c\n]\n"),
			body.replace("HASH(wps_m)", "HASH(wps_x)"),
		] {
			let payload = json(wasm_suggest_queries(&refused));
			assert_eq!(payload["ok"], false, "{refused:?}: {payload}");
			assert_eq!(payload["queries"], serde_json::json!([]));
		}
		assert_eq!(json(wasm_analyze(body, "{}"))["ok"], false);
		assert_eq!(json(wasm_verify(body))["ok"], false);
		assert_eq!(
			json(wasm_check(body))["diagnostics"][0]["code"],
			"parse error"
		);
	}

	#[test]
	fn suggested_queries_round_trip_through_a_queries_block() {
		let mut checked = 0;
		for entry in std::fs::read_dir("examples/test").expect("reads examples/test") {
			let path = entry.expect("entry").path();
			if path.extension().and_then(|e| e.to_str()) != Some("vp") {
				continue;
			}
			let display = path.display().to_string();
			let source = std::fs::read_to_string(&path).expect("reads the model");
			let payload = json(wasm_suggest_queries(&source));
			if payload["ok"] != true {
				assert!(payload["error"].as_str().is_some_and(|e| !e.is_empty()));
				continue;
			}
			let lines: Vec<String> = payload["queries"]
				.as_array()
				.expect("queries")
				.iter()
				.map(|q| q.as_str().expect("a line").to_string())
				.collect();
			if lines.is_empty() {
				continue;
			}
			assert!(lines.iter().all(|l| !l.contains('\n')), "{display}");
			let text = with_queries(&source, &lines);
			let m = crate::parser::parse_string(FILE_NAME, &text)
				.unwrap_or_else(|e| panic!("{display}: the suggestions do not parse: {e}"));
			crate::sanity::sanity(&m)
				.unwrap_or_else(|e| panic!("{display}: the suggestions fail sanity: {e}"));
			let reparsed: Vec<String> = m.queries.iter().map(|q| q.to_string()).collect();
			assert_eq!(reparsed, lines, "{display}");
			let canonical = crate::pretty::pretty_model(&m);
			assert!(
				lines
					.iter()
					.all(|l| canonical.contains(&format!("\t{l}\n"))),
				"{display}"
			);
			checked += 1;
		}
		assert!(checked > 300, "expected the corpus sweep, got {checked}");
		let refused = json(wasm_suggest_queries("attacker[active]\n"));
		assert_eq!(refused["ok"], false);
		assert_eq!(refused["queries"], serde_json::json!([]));
	}
}
