/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::syntax::{Query, QueryKind};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioSummary {
	pub principal: Arc<str>,
	pub bindings: Vec<(Arc<str>, Arc<str>)>,
	pub corrupt_from: Option<i32>,
}

pub(crate) fn peer_description(corrupt_from: Option<i32>) -> String {
	match corrupt_from {
		None => "honest peer".to_string(),
		Some(0) => "corrupt peer".to_string(),
		Some(phase) => format!("peer corrupt from phase {phase}"),
	}
}

impl std::fmt::Display for ScenarioSummary {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}[", self.principal)?;
		for (i, (target, value)) in self.bindings.iter().enumerate() {
			if i > 0 {
				write!(f, ", ")?;
			}
			write!(f, "{target} = {value}")?;
		}
		write!(f, "]")
	}
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TraceStep {
	pub kind: &'static str,
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

impl TraceStep {
	pub fn new(kind: &'static str, text: String) -> TraceStep {
		TraceStep {
			kind,
			text,
			sender: None,
			recipient: None,
			principal: None,
			values: vec![],
		}
	}
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TraceValue {
	pub name: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub installed: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub was: Option<String>,
	#[serde(skip_serializing_if = "std::ops::Not::not")]
	pub guarded: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Truncation {
	TermDepth,
}

impl Truncation {
	pub fn name(self) -> &'static str {
		match self {
			Truncation::TermDepth => "term depth",
		}
	}
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Envelope {
	pub sessions: u8,
	pub truncations: Vec<Truncation>,
}

impl Envelope {
	pub fn exhausted(&self) -> bool {
		self.truncations.is_empty()
	}

	pub fn summary(&self) -> String {
		if self.exhausted() {
			return format!(
				"search exhausted at {} session{}",
				self.sessions,
				crate::util::text::plural(self.sessions.into())
			);
		}
		let reasons: Vec<&str> = self.truncations.iter().map(|t| t.name()).collect();
		format!("search truncated: {}", reasons.join(", "))
	}

	pub fn qualifier(&self) -> String {
		format!("  [{}]", self.summary())
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subtype {
	AttackerSuppliedValue,
	DuplicateAcceptance,
	ReplayableFirstFlight,
}

impl Subtype {
	pub fn name(self) -> &'static str {
		match self {
			Subtype::AttackerSuppliedValue => "attacker-supplied value",
			Subtype::DuplicateAcceptance => "duplicate acceptance",
			Subtype::ReplayableFirstFlight => {
				"duplicate acceptance: no recipient-generated context"
			}
		}
	}

	pub fn qualifier(self) -> String {
		format!("  [{}]", self.name())
	}
}

#[derive(Clone, Debug)]
pub struct VerifyResult {
	pub query: Query,
	pub query_index: usize,
	pub resolved: bool,
	pub envelope: Envelope,
	pub summary: String,
	pub conclusion: String,
	pub subtype: Option<Subtype>,
	pub trace: Vec<String>,
	pub notes: Vec<String>,
	pub steps: Vec<TraceStep>,
	pub options: Vec<QueryOptionResult>,
	pub variants: Vec<Query>,
}

impl VerifyResult {
	pub fn new(query: &Query, query_index: usize) -> Self {
		VerifyResult {
			query: query.clone(),
			query_index,
			resolved: false,
			envelope: Envelope::default(),
			summary: String::new(),
			conclusion: String::new(),
			subtype: None,
			trace: vec![],
			notes: vec![],
			steps: vec![],
			options: vec![],
			variants: vec![],
		}
	}

	pub fn set_summary(&mut self, mutated_info: &str, steps: Vec<TraceStep>, conclusion: &str) {
		let (notes, trace): (Vec<&str>, Vec<&str>) = mutated_info
			.lines()
			.map(str::trim)
			.filter(|line| !line.is_empty())
			.partition(|line| line.starts_with("Note: "));
		self.trace = trace.into_iter().map(str::to_string).collect();
		self.notes = notes
			.into_iter()
			.map(|line| line.trim_start_matches("Note: ").to_string())
			.collect();
		self.steps = steps;
		self.conclusion = conclusion.to_string();
		self.summary =
			crate::console::info_verify_result_summary(mutated_info, conclusion, &self.options);
	}

	pub fn results_code(results: &[VerifyResult]) -> String {
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
}

#[derive(Clone, Debug)]
pub struct QueryOptionResult {
	pub summary: String,
}
