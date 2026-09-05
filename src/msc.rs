/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;

use crate::report::{Computation, DiagramRow, ModelReport, QueryReport, ReportStep};
use crate::util::copy_base_name;

pub(crate) const ATTACKER: &str = "Attacker";

pub(crate) struct Value {
	pub name: String,
	pub guarded: bool,
	pub hit: bool,
	pub changed: bool,
	pub queries: Vec<usize>,
}

pub(crate) enum Row {
	Wire {
		num: Option<usize>,
		hop: Option<usize>,
		step: Option<String>,
		from: String,
		to: String,
		via: Option<String>,
		forged: bool,
		replay: bool,
		values: Vec<Value>,
	},
	Phase {
		number: i32,
	},
	Leak {
		principal: String,
		text: String,
	},
	Activity {
		principal: String,
		generates: Vec<String>,
		computes: Vec<Step>,
	},
	Mark {
		num: Option<usize>,
		step: Option<String>,
		principal: String,
		bypass: bool,
	},
	Run {
		step: String,
		label: String,
	},
}

impl Row {
	pub(crate) fn lanes(&self) -> Vec<&str> {
		match self {
			Row::Wire { from, to, via, .. } => match via {
				Some(via) => vec![from, via, to],
				None => vec![from, to],
			},
			Row::Leak { principal, .. }
			| Row::Activity { principal, .. }
			| Row::Mark { principal, .. } => vec![principal],
			Row::Phase { .. } | Row::Run { .. } => Vec::new(),
		}
	}
}

#[derive(Default)]
pub(crate) struct Lanes {
	names: Vec<String>,
}

impl Lanes {
	pub(crate) fn of(rows: &[Row]) -> Lanes {
		let mut lanes = Lanes::default();
		for row in rows {
			for name in row.lanes() {
				lanes.add(name);
			}
		}
		lanes
	}

	pub(crate) fn add(&mut self, name: &str) {
		if !self.names.iter().any(|n| n == name) {
			self.names.push(name.to_string());
		}
	}

	pub(crate) fn insert(&mut self, at: usize, name: &str) {
		if self.names.iter().any(|n| n == name) {
			return;
		}
		self.names
			.insert(at.min(self.names.len()), name.to_string());
	}

	pub(crate) fn is_empty(&self) -> bool {
		self.names.is_empty()
	}

	pub(crate) fn len(&self) -> usize {
		self.names.len()
	}

	pub(crate) fn contains(&self, name: &str) -> bool {
		self.names.iter().any(|n| n == name)
	}

	pub(crate) fn index(&self, name: &str) -> usize {
		self.names.iter().position(|n| n == name).unwrap_or(0)
	}

	pub(crate) fn names(&self) -> &[String] {
		&self.names
	}
}

pub(crate) struct Step {
	pub names: String,
	pub primitive: Option<String>,
	pub expression: Option<String>,
	pub checked: bool,
}

impl Step {
	fn of(c: &Computation) -> Step {
		Step {
			names: c.names.join(", "),
			primitive: c.primitive.clone(),
			expression: c.expression.clone(),
			checked: c.checked,
		}
	}

	pub(crate) fn label(&self) -> String {
		let mut out = self.names.clone();
		// The printed expression already carries its own check mark; only the
		// bare primitive name needs one added.
		let (shown, marked) = match (&self.expression, &self.primitive) {
			(Some(expression), _) => (Some(expression), true),
			(None, Some(primitive)) => (Some(primitive), false),
			(None, None) => (None, false),
		};
		if let Some(shown) = shown {
			if !out.is_empty() {
				out.push_str(" \u{2190} ");
			}
			out.push_str(shown);
		}
		if self.checked && !marked {
			out.push('?');
		}
		out
	}
}

pub(crate) enum Group<'a> {
	One(usize, &'a ReportStep),
	Run(usize, usize, Vec<(usize, &'a ReportStep)>),
}

impl Group<'_> {
	pub(crate) fn step(&self) -> String {
		match self {
			Group::One(n, _) => n.to_string(),
			Group::Run(from, to, _) => {
				if from == to {
					from.to_string()
				} else {
					format!("{from}-{to}")
				}
			}
		}
	}
}

pub(crate) fn staged(q: &QueryReport) -> Vec<Group<'_>> {
	const ACTED: [&str; 5] = ["mutations", "replay", "received", "gate", "bypass"];
	let mut out: Vec<Group> = Vec::new();
	for (i, step) in q.steps.iter().enumerate() {
		let n = i + 1;
		if ACTED.contains(&step.kind.as_str()) {
			out.push(Group::One(n, step));
			continue;
		}
		match out.last_mut() {
			Some(Group::Run(_, to, held)) => {
				*to = n;
				held.push((n, step));
			}
			_ => out.push(Group::Run(n, n, vec![(n, step)])),
		}
	}
	out
}

pub(crate) fn protocol_rows(model: &ModelReport, hits: &HashMap<String, Vec<usize>>) -> Vec<Row> {
	model
		.diagram
		.iter()
		.map(|row| match row {
			DiagramRow::Message {
				hop,
				sender,
				recipient,
				values,
				..
			} => Row::Wire {
				num: Some(*hop),
				hop: None,
				step: None,
				from: sender.clone(),
				to: recipient.clone(),
				via: None,
				forged: false,
				replay: false,
				values: values
					.iter()
					.map(|v| {
						let queries = hits.get(copy_base_name(&v.name));
						Value {
							name: v.name.clone(),
							guarded: v.guarded,
							hit: queries.is_some(),
							changed: false,
							queries: queries.cloned().unwrap_or_default(),
						}
					})
					.collect(),
			},
			DiagramRow::Phase { number } => Row::Phase { number: *number },
			DiagramRow::Leak { principal, values } => Row::Leak {
				principal: principal.clone(),
				text: format!(
					"{principal} leaks {}",
					values
						.iter()
						.map(|v| v.name.as_str())
						.collect::<Vec<_>>()
						.join(", ")
				),
			},
			DiagramRow::Activity {
				principal,
				generates,
				computes,
				..
			} => Row::Activity {
				principal: principal.clone(),
				generates: generates.clone(),
				computes: computes.iter().map(Step::of).collect(),
			},
		})
		.collect()
}

struct Hop<'a> {
	hop: usize,
	phase: i32,
	sender: &'a str,
	recipient: &'a str,
	values: Vec<&'a str>,
}

fn hops(model: &ModelReport) -> Vec<Hop<'_>> {
	model
		.diagram
		.iter()
		.filter_map(|row| match row {
			DiagramRow::Message {
				hop,
				phase,
				sender,
				recipient,
				values,
			} => Some(Hop {
				hop: *hop,
				phase: *phase,
				sender,
				recipient,
				values: values.iter().map(|v| v.name.as_str()).collect(),
			}),
			_ => None,
		})
		.collect()
}

fn matches(hop: &Hop, sender: &str, recipient: &str, names: &[String]) -> bool {
	if copy_base_name(sender) != hop.sender || copy_base_name(recipient) != hop.recipient {
		return false;
	}
	names
		.iter()
		.any(|n| hop.values.contains(&copy_base_name(n)))
}

fn names_value(text: &str, value: &str) -> bool {
	let boundary = |c: char| !c.is_alphanumeric() && c != '_' && c != '#' && c != '@';
	text.match_indices(value).any(|(at, _)| {
		let before = text[..at].chars().next_back().is_none_or(boundary);
		let after = text[at + value.len()..].chars().next().is_none_or(boundary);
		before && after
	})
}

pub(crate) fn attack_rows(q: &QueryReport, model: &ModelReport) -> (Vec<Row>, Lanes) {
	let wires = hops(model);
	let leaks: Vec<(&str, Vec<&str>)> = model
		.diagram
		.iter()
		.filter_map(|row| match row {
			DiagramRow::Leak { principal, values } => Some((
				principal.as_str(),
				values.iter().map(|v| v.name.as_str()).collect(),
			)),
			_ => None,
		})
		.collect();
	let mut rows: Vec<Row> = Vec::new();
	let mut cursor = 0usize;
	let mut phase = 0i32;
	let mut drawn: Vec<&str> = Vec::new();
	for group in staged(q) {
		let (n, step) = match &group {
			Group::One(n, step) => (*n, *step),
			Group::Run(_, _, held) => {
				rows.push(Row::Run {
					step: group.step(),
					label: match held.len() {
						1 => format!("computes (step {})", group.step()),
						_ => format!("computes (steps {})", group.step().replace('-', "\u{2013}")),
					},
				});
				for (_, held_step) in held {
					for (principal, values) in &leaks {
						if drawn.contains(principal) {
							continue;
						}
						if !values.iter().any(|v| names_value(&held_step.text, v)) {
							continue;
						}
						drawn.push(principal);
						rows.insert(
							rows.len() - 1,
							Row::Leak {
								principal: principal.to_string(),
								text: format!("{principal} leaks {}", values.join(", ")),
							},
						);
					}
				}
				continue;
			}
		};
		let names: Vec<String> = step.values.iter().map(|v| v.name.clone()).collect();
		let (sender, recipient) = (step.sender.as_deref(), step.recipient.as_deref());
		let found = match (sender, recipient) {
			(Some(sender), Some(recipient)) => wires
				.iter()
				.skip(cursor)
				.chain(wires.iter().take(cursor))
				.find(|hop| matches(hop, sender, recipient, &names)),
			_ => None,
		};
		if let Some(hop) = found {
			cursor = hop.hop;
			if hop.phase != phase {
				phase = hop.phase;
				rows.push(Row::Phase { number: phase });
			}
		}
		let hop = found.map(|found| found.hop);
		match step.kind.as_str() {
			"mutations" | "replay" | "received" => {
				let Some(recipient) = recipient else { continue };
				let forged = step.values.iter().any(|v| v.was != v.installed);
				let replay = step.kind == "replay";
				let relayed = step.kind != "received";
				rows.push(Row::Wire {
					num: Some(n),
					hop,
					step: Some(n.to_string()),
					from: sender.unwrap_or(ATTACKER).to_string(),
					to: recipient.to_string(),
					via: relayed.then(|| ATTACKER.to_string()),
					forged: forged || replay,
					replay,
					values: step
						.values
						.iter()
						.map(|v| Value {
							name: v.name.clone(),
							guarded: v.guarded,
							hit: false,
							changed: v.was != v.installed,
							queries: Vec::new(),
						})
						.collect(),
				});
			}
			"gate" | "bypass" => {
				let Some(principal) = step.principal.as_deref() else {
					continue;
				};
				rows.push(Row::Mark {
					num: Some(n),
					step: Some(n.to_string()),
					principal: principal.to_string(),
					bypass: step.kind == "bypass",
				});
			}
			_ => {}
		}
	}
	let mut lanes = Lanes::of(&rows);
	if !lanes.is_empty() {
		lanes.insert(1, ATTACKER);
	}
	(rows, lanes)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn step(names: &str, primitive: Option<&str>, expression: Option<&str>, checked: bool) -> Step {
		Step {
			names: names.to_string(),
			primitive: primitive.map(str::to_string),
			expression: expression.map(str::to_string),
			checked,
		}
	}

	#[test]
	fn a_step_label_marks_a_check_only_where_the_expression_does_not() {
		assert_eq!(
			step("k", None, Some("DH_KEX(ga, b)"), false).label(),
			"k \u{2190} DH_KEX(ga, b)"
		);
		assert_eq!(
			step("k", None, Some("AEAD_DEC(k, n, e, ad)?"), true).label(),
			"k \u{2190} AEAD_DEC(k, n, e, ad)?",
			"the printed expression already carries its own check mark"
		);
		assert_eq!(
			step("k", Some("AEAD_DEC"), None, true).label(),
			"k \u{2190} AEAD_DEC?",
			"a bare primitive name needs one added"
		);
		assert_eq!(step("k", None, None, false).label(), "k");
		assert_eq!(step("", Some("ASSERT"), None, true).label(), "ASSERT?");
	}

	#[test]
	fn lanes_keep_first_appearance_order_and_insert_only_once() {
		let mut lanes = Lanes::default();
		assert!(lanes.is_empty());
		for name in ["Alice", "Bob", "Alice"] {
			lanes.add(name);
		}
		assert_eq!(lanes.names(), ["Alice".to_string(), "Bob".to_string()]);
		lanes.insert(1, ATTACKER);
		lanes.insert(1, ATTACKER);
		assert_eq!(lanes.len(), 3);
		assert_eq!(lanes.index(ATTACKER), 1);
		assert!(lanes.contains("Bob"));
		assert_eq!(
			lanes.index("nobody"),
			0,
			"an unknown lane falls back to the first rather than panicking"
		);
		lanes.insert(99, "Charlie");
		assert_eq!(lanes.index("Charlie"), 3, "an out-of-range insert clamps");
	}

	#[test]
	fn a_wire_row_names_the_relay_lane_between_its_two_ends() {
		let row = Row::Wire {
			num: Some(1),
			hop: None,
			step: None,
			from: "Alice".to_string(),
			to: "Bob".to_string(),
			via: Some(ATTACKER.to_string()),
			forged: true,
			replay: false,
			values: vec![],
		};
		assert_eq!(row.lanes(), vec!["Alice", ATTACKER, "Bob"]);
		let phase = Row::Phase { number: 1 };
		assert!(phase.lanes().is_empty(), "a phase spans the whole diagram");
	}

	#[test]
	fn consecutive_derivations_group_and_an_action_breaks_the_run() {
		let q = QueryReport {
			query: "confidentiality? m".to_string(),
			kind: "confidentiality".to_string(),
			resolved: true,
			envelope: crate::report::EnvelopeReport {
				sessions: 1,
				truncations: vec![],
				exhausted: true,
				summary: String::new(),
			},
			range: crate::report::SourceRange {
				start: 0,
				end: 0,
				line: 1,
				column: 1,
			},
			summary: String::new(),
			conclusion: String::new(),
			subtype: None,
			steps: vec![
				ReportStep::new("derive".to_string(), "one".to_string()),
				ReportStep::new("derive".to_string(), "two".to_string()),
				ReportStep::new("mutations".to_string(), "swap".to_string()),
				ReportStep::new("derive".to_string(), "three".to_string()),
			],
			preconditions: vec![],
			notes: vec![],
			generated: false,
			variants: 0,
		};
		let groups = staged(&q);
		assert_eq!(groups.len(), 3);
		assert_eq!(groups[0].step(), "1-2");
		assert_eq!(groups[1].step(), "3");
		assert_eq!(groups[2].step(), "4");
		assert!(matches!(groups[1], Group::One(3, _)));
	}
}
