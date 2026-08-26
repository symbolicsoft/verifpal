/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use serde::Serialize;

use crate::types::{Span, TraceValue, VerifyResult};
use crate::verify::VerifyReport;

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
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Analysis {
	pub model: String,
	pub sessions: u8,
	pub code: String,
	pub attacks: usize,
	pub elapsed_ms: u128,
	pub assumptions: Vec<Assumption>,
	pub queries: Vec<QueryReport>,
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
				match outcome {
					Ok(report) => ModelReport {
						file: path.clone(),
						ok: true,
						error: None,
						analysis: Some(Analysis::of(report, source)),
					},
					Err(error) => ModelReport {
						file: path.clone(),
						ok: false,
						error: Some(error.clone()),
						analysis: None,
					},
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
			},
			range: SourceRange::of(r.query.span, source),
			summary: r.summary.clone(),
			conclusion: r.conclusion.clone(),
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
			preconditions: r
				.options
				.iter()
				.filter(|o| o.resolved)
				.map(|o| o.summary.clone())
				.collect(),
			variants: r.variants.len(),
		}
	}
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
				analysis: Some(Analysis {
					model: "simple.vp".to_string(),
					sessions: 2,
					code: "c1".to_string(),
					attacks: 1,
					elapsed_ms: 3,
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
						},
						range: SourceRange {
							start: 120,
							end: 141,
							line: 21,
							column: 2,
						},
						summary: "m1 is obtained by Attacker.".to_string(),
						conclusion: "m1 is obtained by Attacker.".to_string(),
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
			r#""ok":true,"analysis":{"model":"simple.vp","sessions":2,"code":"c1","#,
			r#""attacks":1,"elapsedMs":3,"assumptions":[{"term":"HASH(m)","#,
			r#""capability":"weak","fromPhase":0}],"queries":[{"#,
			r#""query":"confidentiality? m1","kind":"confidentiality","resolved":true,"#,
			r#""envelope":{"sessions":2,"truncations":[],"exhausted":true},"#,
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
	fn a_failed_model_reports_its_error_and_no_analysis() {
		let run = Run {
			version: "1.0.4".to_string(),
			ok: false,
			models: vec![ModelReport {
				file: "broken.vp".to_string(),
				ok: false,
				error: Some("parse error: expected `]`".to_string()),
				analysis: None,
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
