/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use serde::Serialize;

use crate::tokens::Token;
use crate::types::{Block, Constant, Declaration, Span, TraceValue, VerifyResult};
use crate::verify::VerifyReport;

pub(crate) const DISCLAIMER: &str = "Verifpal is sound but incomplete. Every attack shown here is a genuine attack on the model \
	 as written; a query reported as holding means no attack was found within the search this \
	 run performed, which is never a proof that none exists.";

#[derive(Debug, Serialize)]
pub struct Run {
	pub version: String,
	pub ok: bool,
	pub models: Vec<ModelReport>,
}

#[derive(Debug, Serialize)]
pub struct ModelReport {
	pub file: String,
	pub ok: bool,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub analysis: Option<Analysis>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub diagram: Vec<DiagramRow>,
	#[serde(skip)]
	pub source: String,
	#[serde(skip)]
	pub(crate) tokens: Vec<Token>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum DiagramRow {
	#[serde(rename_all = "camelCase")]
	Message {
		hop: usize,
		phase: i32,
		sender: String,
		recipient: String,
		values: Vec<DiagramValue>,
	},
	#[serde(rename_all = "camelCase")]
	Phase { number: i32 },
	#[serde(rename_all = "camelCase")]
	Leak {
		principal: String,
		values: Vec<String>,
	},
	#[serde(rename_all = "camelCase")]
	Activity {
		principal: String,
		phase: i32,
		generates: Vec<String>,
		computes: Vec<Computation>,
	},
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Computation {
	pub names: Vec<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub primitive: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub expression: Option<String>,
	#[serde(skip_serializing_if = "std::ops::Not::not")]
	pub checked: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagramValue {
	pub name: String,
	#[serde(skip_serializing_if = "std::ops::Not::not")]
	pub guarded: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Analysis {
	pub model: String,
	pub attacker: String,
	pub sessions: u8,
	pub code: String,
	pub attacks: usize,
	pub elapsed_ms: u128,
	pub assumptions: Vec<Assumption>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub scenarios: Vec<ScenarioReport>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub notes: Vec<String>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub provenance: Vec<String>,
	pub queries: Vec<QueryReport>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScenarioReport {
	pub principal: String,
	pub bindings: Vec<Binding>,
	pub honest: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Binding {
	pub target: String,
	pub value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assumption {
	pub term: String,
	pub capability: String,
	pub from_phase: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeReport {
	pub sessions: u8,
	pub truncations: Vec<String>,
	pub exhausted: bool,
	pub summary: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryReport {
	pub query: String,
	pub kind: String,
	pub resolved: bool,
	pub envelope: EnvelopeReport,
	pub range: SourceRange,
	pub summary: String,
	pub conclusion: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub subtype: Option<String>,
	pub steps: Vec<ReportStep>,
	pub preconditions: Vec<String>,
	pub variants: usize,
}

#[derive(Debug, Serialize)]
pub struct ReportStep {
	pub kind: String,
	pub text: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub sender: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub recipient: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub principal: Option<String>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub values: Vec<TraceValue>,
}

impl ReportStep {
	pub fn new(kind: String, text: String) -> ReportStep {
		ReportStep {
			kind,
			text,
			sender: None,
			recipient: None,
			principal: None,
			values: vec![],
		}
	}
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct SourceRange {
	pub start: usize,
	pub end: usize,
	pub line: usize,
	pub column: usize,
}

impl Run {
	pub fn of(
		version: &str,
		outcomes: &[(String, Result<VerifyReport, String>)],
		sources: &[String],
	) -> Run {
		let models = outcomes
			.iter()
			.enumerate()
			.map(|(i, (path, outcome))| {
				let source = sources.get(i).map(String::as_str).unwrap_or("");
				let (diagram, tokens) = describe(source);
				ModelReport {
					file: path.clone(),
					ok: outcome.is_ok(),
					error: outcome.as_ref().err().cloned(),
					analysis: outcome.as_ref().ok().map(|r| Analysis::of(r, source)),
					diagram,
					source: source.to_string(),
					tokens,
				}
			})
			.collect();
		Run {
			version: version.to_string(),
			ok: outcomes.iter().all(|(_, outcome)| outcome.is_ok()),
			models,
		}
	}
}

impl Analysis {
	pub(crate) fn of(report: &VerifyReport, source: &str) -> Analysis {
		Analysis {
			model: report.file_name.clone(),
			attacker: report.attacker.to_string(),
			sessions: report.sessions,
			code: report.code.clone(),
			attacks: report.results.iter().filter(|r| r.resolved).count(),
			elapsed_ms: report.elapsed.map(|d| d.as_millis()).unwrap_or_default(),
			assumptions: report
				.assumptions
				.iter()
				.map(|(term, capability, onset)| Assumption {
					term: term.to_string(),
					capability: capability.name().to_string(),
					from_phase: *onset,
				})
				.collect(),
			scenarios: report
				.scenarios
				.iter()
				.map(|s| ScenarioReport {
					principal: s.principal.to_string(),
					bindings: s
						.bindings
						.iter()
						.map(|(target, value)| Binding {
							target: target.to_string(),
							value: value.to_string(),
						})
						.collect(),
					honest: s.honest,
				})
				.collect(),
			notes: analysis_notes(report),
			provenance: analysis_provenance(report),
			queries: report
				.results
				.iter()
				.map(|r| QueryReport::of(r, source))
				.collect(),
		}
	}
}

impl QueryReport {
	pub(crate) fn of(r: &VerifyResult, source: &str) -> QueryReport {
		QueryReport {
			query: crate::pretty::query_display(&r.query),
			kind: r.query.kind.name().to_string(),
			resolved: r.resolved,
			envelope: EnvelopeReport {
				sessions: r.envelope.sessions,
				truncations: r
					.envelope
					.truncations
					.iter()
					.map(|t| t.name().to_string())
					.collect(),
				exhausted: r.envelope.exhausted(),
				summary: r.envelope.summary(),
			},
			range: SourceRange::of(r.query.span, source),
			summary: r.summary.clone(),
			conclusion: r.conclusion.clone(),
			subtype: r.subtype.map(|s| s.name().to_string()),
			steps: r
				.steps
				.iter()
				.map(|s| ReportStep {
					kind: s.kind.to_string(),
					text: s.text.clone(),
					sender: s.sender.clone(),
					recipient: s.recipient.clone(),
					principal: s.principal.clone(),
					values: s.values.clone(),
				})
				.collect(),
			preconditions: r.options.iter().map(|o| o.summary.clone()).collect(),
			variants: r.variants.len(),
		}
	}
}

fn describe(source: &str) -> (Vec<DiagramRow>, Vec<Token>) {
	if source.is_empty() {
		return (Vec::new(), Vec::new());
	}
	let (parsed, index) = crate::parser::parse_string_indexed("report.vp", source);
	let mut tokens = index.tokens().to_vec();
	tokens.sort_by_key(|t| t.span.start);
	let Ok(model) = parsed else {
		return (Vec::new(), tokens);
	};
	let mut rows: Vec<DiagramRow> = Vec::new();
	let mut hop = 0usize;
	let mut phase = 0i32;
	let mut senders: Vec<&str> = Vec::new();
	for block in &model.blocks {
		match block {
			Block::Message(msg) => {
				for name in [&msg.sender_name, &msg.recipient_name] {
					if !senders.contains(&&**name) {
						senders.push(name);
					}
				}
			}
			Block::Principal(p)
				if p.expressions.iter().any(|e| e.kind == Declaration::Leaks)
					&& !senders.contains(&p.name.as_str()) =>
			{
				senders.push(&p.name);
			}
			_ => {}
		}
	}
	for block in &model.blocks {
		match block {
			Block::Message(msg) => {
				hop += 1;
				rows.push(DiagramRow::Message {
					hop,
					phase,
					sender: msg.sender_name.to_string(),
					recipient: msg.recipient_name.to_string(),
					values: msg.constants.iter().map(diagram_value).collect(),
				});
			}
			Block::Phase(p) => {
				phase = p.number;
				rows.push(DiagramRow::Phase { number: p.number });
			}
			Block::Principal(p) => {
				if !senders.contains(&p.name.as_str()) {
					continue;
				}
				let mut generates: Vec<String> = Vec::new();
				let mut computes: Vec<Computation> = Vec::new();
				for expr in &p.expressions {
					match expr.kind {
						Declaration::Knows => {}
						Declaration::Generates => {
							generates.extend(expr.constants.iter().map(|c| c.name.to_string()))
						}
						Declaration::Assignment => {
							if let Some(step) = computation(expr) {
								computes.push(step);
							}
						}
						Declaration::Leaks => {
							flush_activity(
								&mut rows,
								&p.name,
								phase,
								&mut generates,
								&mut computes,
							);
							rows.push(DiagramRow::Leak {
								principal: p.name.clone(),
								values: expr.constants.iter().map(|c| c.name.to_string()).collect(),
							});
						}
					}
				}
				flush_activity(&mut rows, &p.name, phase, &mut generates, &mut computes);
			}
		}
	}
	(rows, tokens)
}

fn flush_activity(
	rows: &mut Vec<DiagramRow>,
	principal: &str,
	phase: i32,
	generates: &mut Vec<String>,
	computes: &mut Vec<Computation>,
) {
	if generates.is_empty() && computes.is_empty() {
		return;
	}
	rows.push(DiagramRow::Activity {
		principal: principal.to_string(),
		phase,
		generates: std::mem::take(generates),
		computes: std::mem::take(computes),
	});
}

fn computation(expr: &crate::types::Expression) -> Option<Computation> {
	let names: Vec<String> = expr
		.constants
		.iter()
		.filter(|c| !crate::util::is_anonymous_name(&c.name))
		.map(|c| c.name.to_string())
		.collect();
	let (primitive, checked) = match &expr.assigned {
		Some(crate::types::Value::Primitive(p)) => (
			Some(crate::primitive::primitive_name(p.id).to_string()),
			p.instance_check,
		),
		_ => (None, false),
	};
	if names.is_empty() && !checked {
		return None;
	}
	Some(Computation {
		names,
		primitive,
		expression: expr.assigned.as_ref().map(|v| v.to_string()),
		checked,
	})
}

fn diagram_value(c: &Constant) -> DiagramValue {
	DiagramValue {
		name: c.name.to_string(),
		guarded: c.guard,
	}
}

fn analysis_provenance(report: &VerifyReport) -> Vec<String> {
	let mut out: Vec<String> = Vec::new();
	if report.provenance.auto_queries {
		out.push(
			"The model's own queries block was replaced by the set --auto-queries derives \
			 from the protocol; these are generated claims, not the author's."
				.to_string(),
		);
	}
	if let Some(s) = report.provenance.saturation {
		if s.saturated {
			out.push(format!(
				"--saturate raised the session count until the verdicts stopped moving: they \
				 were unchanged from {} to {} sessions.",
				s.stable_from, report.sessions
			));
		} else {
			out.push(format!(
				"--saturate reached {} sessions, the highest it tries, with the verdicts still \
				 changing; they may keep changing beyond it.",
				s.ceiling
			));
		}
		if s.regressed {
			out.push(
				"An attack found at a lower session count disappeared at a higher one. That is \
				 an engine bug, not a protocol result."
					.to_string(),
			);
		}
	}
	out
}

fn trace_text_contains(report: &VerifyReport, marker: char) -> bool {
	report.results.iter().any(|r| {
		r.steps.iter().any(|s| {
			s.text.contains(marker)
				|| s.values.iter().any(|v| {
					v.name.contains(marker)
						|| v.installed.as_deref().is_some_and(|t| t.contains(marker))
						|| v.was.as_deref().is_some_and(|t| t.contains(marker))
				})
		})
	})
}

fn analysis_notes(report: &VerifyReport) -> Vec<String> {
	let mut notes: Vec<String> = Vec::new();
	if report.sessions > 1 && trace_text_contains(report, '#') {
		let span = if report.sessions == 2 {
			"#2".to_string()
		} else {
			format!("#2 through #{}", report.sessions)
		};
		notes.push(format!(
			"Per-session values and principals carry the suffix {span}."
		));
	}
	if !report.scenarios.is_empty() && trace_text_contains(report, '@') {
		notes.push("Per-scenario values and principals carry the suffix @2 onward.".to_string());
	}
	let mut reasons: Vec<&'static str> = Vec::new();
	for r in &report.results {
		for t in &r.envelope.truncations {
			if !reasons.contains(&t.name()) {
				reasons.push(t.name());
			}
		}
	}
	if !reasons.is_empty() {
		notes.push(format!(
			"Some searches stopped short of exhausting the space ({}); a query reported as \
			 holding was not searched exhaustively.",
			reasons.join(", ")
		));
	}
	notes
}

impl SourceRange {
	pub(crate) fn of(span: Span, source: &str) -> SourceRange {
		let (line, column) = span.line_col(source);
		SourceRange {
			start: span.start,
			end: span.end,
			line,
			column,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_report_serializes_to_the_documented_shape() {
		let run = Run {
			version: "1.0.4".to_string(),
			ok: true,
			models: vec![ModelReport {
				file: "examples/simple.vp".to_string(),
				ok: true,
				error: None,
				diagram: Vec::new(),
				source: String::new(),
				tokens: Vec::new(),
				analysis: Some(Analysis {
					model: "simple.vp".to_string(),
					attacker: "active".to_string(),
					sessions: 2,
					code: "c1".to_string(),
					attacks: 1,
					elapsed_ms: 3,
					scenarios: Vec::new(),
					notes: Vec::new(),
					provenance: Vec::new(),
					assumptions: vec![Assumption {
						term: "HASH(m)".to_string(),
						capability: "weak".to_string(),
						from_phase: 0,
					}],
					queries: vec![QueryReport {
						query: "confidentiality? m1".to_string(),
						kind: "confidentiality".to_string(),
						resolved: true,
						envelope: EnvelopeReport {
							sessions: 2,
							truncations: vec![],
							exhausted: true,
							summary: "search exhausted at 2 sessions".to_string(),
						},
						range: SourceRange {
							start: 120,
							end: 141,
							line: 21,
							column: 2,
						},
						summary: "m1 is obtained by Attacker.".to_string(),
						conclusion: "m1 is obtained by Attacker.".to_string(),
						subtype: None,
						steps: vec![
							ReportStep::new(
								"derive".to_string(),
								"Attacker constructs PUBKEY(nil) from nil.".to_string(),
							),
							ReportStep {
								kind: "mutations".to_string(),
								text: "Attacker replaces ga with PUBKEY(nil).".to_string(),
								sender: Some("Alice".to_string()),
								recipient: Some("Bob".to_string()),
								principal: None,
								values: vec![TraceValue {
									name: "ga".to_string(),
									installed: Some("PUBKEY(nil)".to_string()),
									was: Some("PUBKEY(a)".to_string()),
									guarded: false,
								}],
							},
						],
						preconditions: vec![],
						variants: 2,
					}],
				}),
			}],
		};

		let json = serde_json::to_string(&run).expect("serializes");
		let expected = concat!(
			r#"{"version":"1.0.4","ok":true,"models":[{"file":"examples/simple.vp","#,
			r#""ok":true,"analysis":{"model":"simple.vp","attacker":"active","sessions":2,"code":"c1","#,
			r#""attacks":1,"elapsedMs":3,"assumptions":[{"term":"HASH(m)","#,
			r#""capability":"weak","fromPhase":0}],"queries":[{"#,
			r#""query":"confidentiality? m1","kind":"confidentiality","resolved":true,"#,
			r#""envelope":{"sessions":2,"truncations":[],"exhausted":true,"#,
			r#""summary":"search exhausted at 2 sessions"},"#,
			r#""range":{"start":120,"end":141,"line":21,"column":2},"#,
			r#""summary":"m1 is obtained by Attacker.","#,
			r#""conclusion":"m1 is obtained by Attacker.","#,
			r#""steps":[{"kind":"derive","#,
			r#""text":"Attacker constructs PUBKEY(nil) from nil."},"#,
			r#"{"kind":"mutations","text":"Attacker replaces ga with PUBKEY(nil).","#,
			r#""sender":"Alice","recipient":"Bob","values":[{"name":"ga","#,
			r#""installed":"PUBKEY(nil)","was":"PUBKEY(a)"}]}],"#,
			r#""preconditions":[],"variants":2}]}}]}"#,
		);
		assert_eq!(json, expected);
	}

	#[test]
	fn a_query_report_points_at_the_query_in_the_source() {
		let report = crate::verify::verify_report("examples/test/hmac_ok.vp", 2).expect("verifies");
		let source = std::fs::read_to_string("examples/test/hmac_ok.vp").expect("reads");
		let run = Run::of(
			"1.0.4",
			&[("examples/test/hmac_ok.vp".to_string(), Ok(report))],
			std::slice::from_ref(&source),
		);

		let analysis = run.models[0].analysis.as_ref().expect("an analysis");
		assert_eq!(analysis.queries.len(), 2);

		let first = &analysis.queries[0];
		assert_eq!(first.kind, "confidentiality");
		let line = source
			.lines()
			.nth(first.range.line - 1)
			.expect("the reported line exists");
		assert!(
			line.contains("confidentiality?"),
			"range points at {:?}",
			line
		);
		assert!(
			source[first.range.start..first.range.end].starts_with("confidentiality"),
			"span quotes {:?}",
			&source[first.range.start..first.range.end]
		);
	}

	#[test]
	fn a_report_lists_declared_assumptions() {
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private rcap_m\n\
			rcap_h = HASH[weak](rcap_m)\n\
			]\n\
			Alice -> Bob: rcap_h\n\
			principal Bob[\n\
			_ = HASH(rcap_h)\n\
			]\n\
			queries[\n\
			confidentiality? rcap_m\n\
			]\n";
		let m = crate::parser::parse_string("rcap.vp", src).expect("parses");
		let ctx = crate::verify::analyze(&m).expect("analyzes");
		let assumptions = ctx.capability_assumptions();
		assert_eq!(assumptions.len(), 1);
		assert_eq!(assumptions[0].1.name(), "weak");
	}

	#[test]
	fn a_report_omits_assumptions_when_none_are_declared() {
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private rnoc_m\n\
			rnoc_h = HASH(rnoc_m)\n\
			]\n\
			Alice -> Bob: rnoc_h\n\
			principal Bob[\n\
			_ = HASH(rnoc_h)\n\
			]\n\
			queries[\n\
			confidentiality? rnoc_m\n\
			]\n";
		let m = crate::parser::parse_string("rnoc.vp", src).expect("parses");
		let ctx = crate::verify::analyze(&m).expect("analyzes");
		assert!(ctx.capability_assumptions().is_empty());
	}

	#[test]
	fn an_analysis_explains_the_session_suffix_its_traces_use() {
		let path = "examples/test/session_replay_breaks_injectivity.vp";
		let report = crate::verify::verify_report(path, 2).expect("verifies");
		let source = std::fs::read_to_string(path).expect("reads");
		let a = Analysis::of(&report, &source);
		assert!(
			a.notes.iter().any(|n| n.contains("#2")),
			"notes were {:?}",
			a.notes
		);
	}

	#[test]
	fn an_analysis_explains_the_scenario_suffix_its_traces_use() {
		let path = "examples/test/spore_ns_pk.vp";
		let report = crate::verify::verify_report(path, 2).expect("verifies");
		let source = std::fs::read_to_string(path).expect("reads");
		let a = Analysis::of(&report, &source);
		assert!(
			a.notes.iter().any(|n| n.contains("@2")),
			"notes were {:?}",
			a.notes
		);
	}

	#[test]
	fn an_analysis_whose_traces_never_use_a_suffix_explains_none() {
		let path = "examples/test/relay_rewrap_oracle.vp";
		let report = crate::verify::verify_report(path, 2).expect("verifies");
		let source = std::fs::read_to_string(path).expect("reads");
		let a = Analysis::of(&report, &source);
		assert!(
			!a.notes.iter().any(|n| n.contains("suffix")),
			"nothing in this report carries a suffix, but it was explained anyway: {:?}",
			a.notes
		);
	}

	#[test]
	fn an_analysis_that_uses_no_suffix_explains_nothing() {
		let path = "examples/test/hmac_ok.vp";
		let report = crate::verify::verify_report(path, 1).expect("verifies");
		let source = std::fs::read_to_string(path).expect("reads");
		let a = Analysis::of(&report, &source);
		assert!(a.notes.is_empty(), "notes were {:?}", a.notes);
	}

	#[test]
	fn an_analysis_reports_a_truncated_search_once_for_the_whole_run() {
		let mut report =
			crate::verify::verify_report("examples/test/hmac_ok.vp", 1).expect("verifies");
		report.results[0]
			.envelope
			.truncations
			.push(crate::types::Truncation::TermDepth);
		let a = Analysis::of(&report, "");
		let hits: Vec<&String> = a
			.notes
			.iter()
			.filter(|n| n.contains("term depth"))
			.collect();
		assert_eq!(hits.len(), 1, "notes were {:?}", a.notes);
	}

	#[test]
	fn a_failed_model_reports_its_error_and_no_analysis() {
		let run = Run {
			version: "1.0.4".to_string(),
			ok: false,
			models: vec![ModelReport {
				file: "broken.vp".to_string(),
				ok: false,
				error: Some("parse error: expected `]`".to_string()),
				analysis: None,
				diagram: Vec::new(),
				source: String::new(),
				tokens: Vec::new(),
			}],
		};
		let json = serde_json::to_string(&run).expect("serializes");
		assert_eq!(
			json,
			concat!(
				r#"{"version":"1.0.4","ok":false,"models":[{"file":"broken.vp","#,
				r#""ok":false,"error":"parse error: expected `]`"}]}"#,
			)
		);
	}
}
