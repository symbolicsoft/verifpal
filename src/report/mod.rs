/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub(crate) mod html;
pub(crate) mod msc;
pub(crate) mod template;
#[cfg(test)]
mod tests;
pub(crate) mod tex;

use std::collections::HashMap;

use serde::Serialize;

use crate::primitive::Capability;
use crate::syntax::names::{copy_base_name, is_anonymous_name};
use crate::syntax::tokens::Token;
use crate::syntax::{Block, Declaration, Expression, Span};
use crate::term::Value;
use crate::util::collections::append_unique;
use crate::util::text::{article, plural};
use crate::verify::{TraceStep, VerifyReport, VerifyResult};

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
		values: Vec<DiagramValue>,
	},
	#[serde(rename_all = "camelCase")]
	Activity {
		principal: String,
		phase: i32,
		generates: Vec<String>,
		computes: Vec<Computation>,
	},
}

#[derive(Clone, Debug, Serialize)]
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
	#[serde(skip_serializing_if = "Option::is_none")]
	pub corrupt_from: Option<i32>,
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

impl Assumption {
	pub(crate) fn list(declared: &[(Value, Capability, i32)]) -> Vec<Assumption> {
		declared
			.iter()
			.map(|(term, capability, onset)| Assumption {
				term: term.to_string(),
				capability: capability.name().to_string(),
				from_phase: *onset,
			})
			.collect()
	}
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
	pub steps: Vec<TraceStep>,
	pub preconditions: Vec<String>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub notes: Vec<String>,
	#[serde(skip_serializing_if = "std::ops::Not::not")]
	pub generated: bool,
	pub variants: usize,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct SourceRange {
	pub start: usize,
	pub end: usize,
	pub line: usize,
	pub column: usize,
}

pub(crate) struct Tally {
	pub models: usize,
	pub analysed: usize,
	pub attacked: usize,
	pub attacks: usize,
	pub queries: usize,
}

impl Tally {
	pub(crate) fn failed(&self) -> usize {
		self.models - self.analysed
	}
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

	pub(crate) fn tally(&self) -> Tally {
		let analyses: Vec<&Analysis> = self
			.models
			.iter()
			.filter_map(|m| m.analysis.as_ref())
			.collect();
		Tally {
			models: self.models.len(),
			analysed: analyses.len(),
			attacked: analyses.iter().filter(|a| a.attacks > 0).count(),
			attacks: analyses.iter().map(|a| a.attacks).sum(),
			queries: analyses.iter().map(|a| a.queries.len()).sum(),
		}
	}
}

impl ModelReport {
	pub(crate) fn short_name(&self) -> &str {
		match &self.analysis {
			Some(a) => &a.model,
			None => self.file.rsplit('/').next().unwrap_or(&self.file),
		}
	}

	pub(crate) fn attacks(&self) -> usize {
		self.analysis.as_ref().map_or(0, |a| a.attacks)
	}
}

impl Analysis {
	pub(crate) fn of(report: &VerifyReport, source: &str) -> Analysis {
		let queries: Vec<QueryReport> = report
			.results
			.iter()
			.map(|r| QueryReport::of(r, source))
			.collect();
		Analysis {
			model: report.file_name.clone(),
			attacker: report.attacker.to_string(),
			sessions: report.sessions,
			code: report.code.clone(),
			attacks: report.results.iter().filter(|r| r.resolved).count(),
			elapsed_ms: report.elapsed.map(|d| d.as_millis()).unwrap_or_default(),
			assumptions: Assumption::list(&report.assumptions),
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
					honest: s.corrupt_from.is_none(),
					corrupt_from: s.corrupt_from,
				})
				.collect(),
			notes: analysis_notes(report, &queries),
			provenance: analysis_provenance(report),
			queries,
		}
	}

	pub(crate) fn attacked_values(&self) -> HashMap<String, Vec<usize>> {
		let mut out: HashMap<String, Vec<usize>> = HashMap::new();
		for (qi, q) in self.queries.iter().enumerate() {
			for s in &q.steps {
				if s.kind != "replay" && s.kind != "mutations" {
					continue;
				}
				for v in &s.values {
					append_unique(
						out.entry(copy_base_name(&v.name).to_string()).or_default(),
						qi,
					);
				}
			}
		}
		out
	}

	pub(crate) fn code_pairs(&self) -> impl Iterator<Item = &str> {
		self.code
			.as_bytes()
			.chunks(2)
			.filter_map(|pair| std::str::from_utf8(pair).ok())
	}

	pub(crate) fn scope(&self) -> String {
		let mut text = format!(
			"Every verdict above was reached against {} {} attacker, with each principal running {} \
			 concurrent session{}, over exactly the model as written. An attack is a witness and \
			 stands on its own. A query reported as holding says only that this search found no \
			 attack at those parameters: the search space this engine defines was explored, which is \
			 never the space of all attacks.",
			article(&self.attacker),
			self.attacker,
			self.sessions,
			plural(self.sessions as usize)
		);
		let reasons = truncation_reasons(&self.queries);
		if !reasons.is_empty() {
			text.push_str(&format!(
				" Some searches in this run stopped short even of that ({}), so their holds cover \
				 less still.",
				reasons.join(", ")
			));
		}
		text
	}
}

fn truncation_reasons(queries: &[QueryReport]) -> Vec<&str> {
	let mut reasons: Vec<&str> = Vec::new();
	for t in queries.iter().flat_map(|q| &q.envelope.truncations) {
		append_unique(&mut reasons, t.as_str());
	}
	reasons
}

impl QueryReport {
	pub(crate) fn of(r: &VerifyResult, source: &str) -> QueryReport {
		QueryReport {
			query: crate::syntax::pretty::query_line(&r.query),
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
			steps: r.steps.clone(),
			preconditions: r.options.iter().map(|o| o.summary.clone()).collect(),
			notes: r.notes.clone(),
			generated: r.query.span == Span::default(),
			variants: r.variants.len(),
		}
	}

	pub(crate) fn has_trace(&self) -> bool {
		self.resolved && !self.steps.is_empty()
	}
}

fn describe(source: &str) -> (Vec<DiagramRow>, Vec<Token>) {
	if source.is_empty() {
		return (Vec::new(), Vec::new());
	}
	let (parsed, index) = crate::syntax::parser::parse_string_indexed("report.vp", source);
	let tokens = index.tokens().to_vec();
	let Ok(model) = parsed else {
		return (Vec::new(), tokens);
	};
	let mut rows: Vec<DiagramRow> = Vec::new();
	let mut hop = 0usize;
	let mut phase = 0i32;
	let mut participants: Vec<&str> = Vec::new();
	for block in &model.blocks {
		match block {
			Block::Message(msg) => {
				append_unique(&mut participants, &msg.sender_name);
				append_unique(&mut participants, &msg.recipient_name);
			}
			Block::Principal(p) if p.expressions.iter().any(|e| e.kind == Declaration::Leaks) => {
				append_unique(&mut participants, &p.name);
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
					values: msg
						.constants
						.iter()
						.map(|c| DiagramValue {
							name: c.name.to_string(),
							guarded: c.guard,
						})
						.collect(),
				});
			}
			Block::Phase(p) => {
				phase = p.number;
				rows.push(DiagramRow::Phase { number: p.number });
			}
			Block::Principal(p) if participants.contains(&p.name.as_str()) => {
				let leaks = |e: &Expression| e.kind == Declaration::Leaks;
				for run in p.expressions.split_inclusive(leaks) {
					let generates: Vec<String> = run
						.iter()
						.filter(|e| e.kind == Declaration::Generates)
						.flat_map(|e| e.constants.iter().map(|c| c.name.to_string()))
						.collect();
					let computes: Vec<Computation> = run
						.iter()
						.filter(|e| e.kind == Declaration::Assignment)
						.filter_map(computation)
						.collect();
					if !generates.is_empty() || !computes.is_empty() {
						rows.push(DiagramRow::Activity {
							principal: p.name.clone(),
							phase,
							generates,
							computes,
						});
					}
					if let Some(leak) = run.last().filter(|e| leaks(e)) {
						rows.push(DiagramRow::Leak {
							principal: p.name.clone(),
							values: leak
								.constants
								.iter()
								.map(|c| DiagramValue {
									name: c.name.to_string(),
									guarded: false,
								})
								.collect(),
						});
					}
				}
			}
			Block::Principal(_) => {}
		}
	}
	(rows, tokens)
}

fn computation(expr: &Expression) -> Option<Computation> {
	let names: Vec<String> = expr
		.constants
		.iter()
		.filter(|c| !is_anonymous_name(&c.name))
		.map(|c| c.name.to_string())
		.collect();
	let (primitive, checked) = match &expr.assigned {
		Some(Value::Primitive(p)) => (
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

fn analysis_provenance(report: &VerifyReport) -> Vec<String> {
	let mut out: Vec<String> = Vec::new();
	if report.auto_queries {
		out.push(
			"The model's own queries block was replaced by the set --auto-queries derives \
			 from the protocol; these are generated claims, not the author's."
				.to_string(),
		);
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

fn analysis_notes(report: &VerifyReport, queries: &[QueryReport]) -> Vec<String> {
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
	let reasons = truncation_reasons(queries);
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
