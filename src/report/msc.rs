/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;

use super::{Computation, DiagramRow, ModelReport, QueryReport};
use crate::syntax::names::copy_base_name;
use crate::util::collections::append_unique;
use crate::verify::StepKind;
use crate::verify::{TraceStep, TraceValue};

pub(crate) const ATTACKER: &str = "Attacker";

pub(crate) struct Value {
	pub name: String,
	pub guarded: bool,
	pub queries: Vec<usize>,
}

impl Value {
	pub(crate) fn hit(&self) -> bool {
		!self.queries.is_empty()
	}
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
	Direct,
	Forged,
	Replayed,
	Dropped,
}

impl Route {
	pub(crate) fn breached(self) -> bool {
		self != Route::Direct
	}

	pub(crate) fn substituted(self) -> bool {
		matches!(self, Route::Forged | Route::Replayed)
	}

	pub(crate) fn note(self) -> &'static str {
		match self {
			Route::Direct | Route::Forged => "",
			Route::Replayed => "replayed",
			Route::Dropped => "dropped",
		}
	}
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mark {
	Passes,
	Idle,
}

impl Mark {
	pub(crate) fn label(self) -> &'static str {
		match self {
			Mark::Passes => "check passes",
			Mark::Idle => "never starts",
		}
	}
}

pub(crate) enum Row {
	Wire {
		hop: Option<usize>,
		step: Option<usize>,
		from: String,
		to: String,
		route: Route,
		values: Vec<Value>,
	},
	Phase {
		number: i32,
	},
	Leak {
		principal: String,
		values: Vec<String>,
	},
	Activity {
		principal: String,
		generates: Vec<String>,
		computes: Vec<Computation>,
	},
	Mark {
		step: usize,
		principal: String,
		mark: Mark,
	},
	Run {
		first: usize,
		last: usize,
	},
}

pub(crate) const ROW_KINDS: [&str; 6] = ["wire", "phase", "leak", "activity", "mark", "run"];

impl Row {
	pub(crate) fn kind(&self) -> &'static str {
		match self {
			Row::Wire { .. } => "wire",
			Row::Phase { .. } => "phase",
			Row::Leak { .. } => "leak",
			Row::Activity { .. } => "activity",
			Row::Mark { .. } => "mark",
			Row::Run { .. } => "run",
		}
	}

	pub(crate) fn lanes(&self) -> Vec<&str> {
		match self {
			Row::Wire {
				from, to, route, ..
			} if route.breached() => vec![from, ATTACKER, to],
			Row::Wire { from, to, .. } => vec![from, to],
			Row::Leak { principal, .. }
			| Row::Activity { principal, .. }
			| Row::Mark { principal, .. } => vec![principal],
			Row::Phase { .. } | Row::Run { .. } => Vec::new(),
		}
	}
}

pub(crate) fn span(first: usize, last: usize) -> String {
	if first == last {
		first.to_string()
	} else {
		format!("{first}-{last}")
	}
}

pub(crate) fn computation_label(c: &Computation) -> String {
	let mut out = c.names.join(", ");
	let (shown, marked) = match (&c.expression, &c.primitive) {
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
	if c.checked && !marked {
		out.push('?');
	}
	out
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

	fn add(&mut self, name: &str) {
		if !self.contains(name) {
			self.names.push(name.to_string());
		}
	}

	fn insert(&mut self, at: usize, name: &str) {
		if !self.contains(name) {
			self.names
				.insert(at.min(self.names.len()), name.to_string());
		}
	}

	fn is_empty(&self) -> bool {
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

pub(crate) struct Chart {
	pub rows: Vec<Row>,
	pub lanes: Lanes,
}

impl Chart {
	fn drawn(rows: Vec<Row>, lanes: Lanes) -> Option<Chart> {
		(!lanes.is_empty()).then_some(Chart { rows, lanes })
	}

	pub(crate) fn marked(&self) -> bool {
		self.rows.iter().any(|row| match row {
			Row::Wire { values, .. } => values.iter().any(Value::hit),
			_ => false,
		})
	}

	pub(crate) fn protocol(model: &ModelReport) -> Option<Chart> {
		let hits = hits(model);
		let rows: Vec<Row> = model
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
					hop: Some(*hop),
					step: None,
					from: sender.clone(),
					to: recipient.clone(),
					route: Route::Direct,
					values: values
						.iter()
						.map(|v| Value {
							name: v.name.clone(),
							guarded: v.guarded,
							queries: hits
								.get(&(*hop, v.name.as_str()))
								.cloned()
								.unwrap_or_default(),
						})
						.collect(),
				},
				DiagramRow::Phase { number } => Row::Phase { number: *number },
				DiagramRow::Leak { principal, values } => Row::Leak {
					principal: principal.clone(),
					values: values.iter().map(|v| v.name.clone()).collect(),
				},
				DiagramRow::Activity {
					principal,
					generates,
					computes,
					..
				} => Row::Activity {
					principal: principal.clone(),
					generates: generates.clone(),
					computes: computes.clone(),
				},
			})
			.collect();
		let lanes = Lanes::of(&rows);
		Chart::drawn(rows, lanes)
	}

	pub(crate) fn attack(q: &QueryReport, model: &ModelReport) -> Option<Chart> {
		let wires = hops(model);
		let located = located(&wires, q);
		let mut rows: Vec<Row> = Vec::new();
		let mut phase = 0i32;
		for group in staged(q) {
			let (n, step) = match group {
				Group::One(n, step) => (n, step),
				Group::Run(held) => {
					rows.extend(leaks(&held));
					rows.push(Row::Run {
						first: held[0].0,
						last: held[held.len() - 1].0,
					});
					continue;
				}
			};
			let found = located[n - 1];
			if let Some(hop) = found
				&& hop.phase != phase
			{
				phase = hop.phase;
				rows.push(Row::Phase { number: phase });
			}
			rows.extend(step_row(n, step, found.map(|found| found.hop)));
		}
		let mut lanes = Lanes::of(&rows);
		if !lanes.is_empty() {
			lanes.insert(1, ATTACKER);
		}
		Chart::drawn(rows, lanes)
	}
}

pub(crate) enum Group<'a> {
	One(usize, &'a TraceStep),
	Run(Vec<(usize, &'a TraceStep)>),
}

impl Group<'_> {
	pub(crate) fn step(&self) -> String {
		match self {
			Group::One(n, _) => n.to_string(),
			Group::Run(held) => span(held[0].0, held[held.len() - 1].0),
		}
	}
}

pub(crate) fn staged(q: &QueryReport) -> Vec<Group<'_>> {
	let mut out: Vec<Group> = Vec::new();
	for (i, step) in q.steps.iter().enumerate() {
		let n = i + 1;
		match step.kind {
			StepKind::Derive => match out.last_mut() {
				Some(Group::Run(held)) => held.push((n, step)),
				_ => out.push(Group::Run(vec![(n, step)])),
			},
			StepKind::Idle
			| StepKind::Drop
			| StepKind::Mutations
			| StepKind::Replay
			| StepKind::Received
			| StepKind::Gate
			| StepKind::Static
			| StepKind::Resolves => out.push(Group::One(n, step)),
		}
	}
	out
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

impl Hop<'_> {
	fn carries(&self, sender: &str, recipient: &str, values: &[TraceValue]) -> bool {
		copy_base_name(sender) == self.sender
			&& copy_base_name(recipient) == self.recipient
			&& values
				.iter()
				.any(|v| self.values.contains(&copy_base_name(&v.name)))
	}
}

fn located<'h, 'm>(wires: &'h [Hop<'m>], q: &QueryReport) -> Vec<Option<&'h Hop<'m>>> {
	let mut cursor = 0usize;
	q.steps
		.iter()
		.map(|step| {
			let (sender, recipient) = (step.sender.as_deref()?, step.recipient.as_deref()?);
			let hop = wires
				.iter()
				.skip(cursor)
				.chain(wires.iter().take(cursor))
				.find(|hop| hop.carries(sender, recipient, &step.values))?;
			cursor = hop.hop;
			Some(hop)
		})
		.collect()
}

fn hits(model: &ModelReport) -> HashMap<(usize, &str), Vec<usize>> {
	let wires = hops(model);
	let mut out: HashMap<(usize, &str), Vec<usize>> = HashMap::new();
	let queries = model.analysis.iter().flat_map(|a| &a.queries);
	for (qi, q) in queries.enumerate() {
		for (step, hop) in q.steps.iter().zip(located(&wires, q)) {
			let Some(hop) = hop else {
				continue;
			};
			if !matches!(step.kind, StepKind::Replay | StepKind::Mutations) {
				continue;
			}
			for value in &step.values {
				let base = copy_base_name(&value.name);
				if let Some(name) = hop.values.iter().find(|name| **name == base) {
					append_unique(out.entry((hop.hop, *name)).or_default(), qi);
				}
			}
		}
	}
	out
}

fn leaks(held: &[(usize, &TraceStep)]) -> Vec<Row> {
	let mut rows: Vec<Row> = Vec::new();
	for (_, step) in held {
		let Some(leaker) = &step.principal else {
			continue;
		};
		let names = step.values.iter().map(|v| v.name.clone());
		let drawn = rows.iter_mut().find_map(|row| match row {
			Row::Leak { principal, values } if principal == leaker => Some(values),
			_ => None,
		});
		match drawn {
			Some(values) => values.extend(names),
			None => rows.push(Row::Leak {
				principal: leaker.clone(),
				values: names.collect(),
			}),
		}
	}
	rows
}

fn step_row(n: usize, step: &TraceStep, hop: Option<usize>) -> Option<Row> {
	let wire = |route: Route| {
		Some(Row::Wire {
			hop,
			step: Some(n),
			from: step.sender.clone()?,
			to: step.recipient.clone()?,
			route,
			values: step
				.values
				.iter()
				.map(|v| Value {
					name: v.name.clone(),
					guarded: v.guarded,
					queries: Vec::new(),
				})
				.collect(),
		})
	};
	let mark = |mark: Mark| {
		Some(Row::Mark {
			step: n,
			principal: step.principal.clone()?,
			mark,
		})
	};
	match step.kind {
		StepKind::Mutations => wire(Route::Forged),
		StepKind::Replay => wire(Route::Replayed),
		StepKind::Received => wire(Route::Direct),
		StepKind::Drop => wire(Route::Dropped),
		StepKind::Gate => mark(Mark::Passes),
		StepKind::Idle => mark(Mark::Idle),
		StepKind::Derive | StepKind::Static | StepKind::Resolves => None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn step(
		names: &[&str],
		primitive: Option<&str>,
		expression: Option<&str>,
		checked: bool,
	) -> String {
		computation_label(&Computation {
			names: names.iter().map(|n| n.to_string()).collect(),
			primitive: primitive.map(str::to_string),
			expression: expression.map(str::to_string),
			checked,
		})
	}

	#[test]
	fn a_step_label_marks_a_check_only_where_the_expression_does_not() {
		assert_eq!(
			step(&["k"], None, Some("DH_KEX(ga, b)"), false),
			"k \u{2190} DH_KEX(ga, b)"
		);
		assert_eq!(
			step(&["k"], None, Some("AEAD_DEC(k, n, e, ad)?"), true),
			"k \u{2190} AEAD_DEC(k, n, e, ad)?",
			"the printed expression already carries its own check mark"
		);
		assert_eq!(
			step(&["k"], Some("AEAD_DEC"), None, true),
			"k \u{2190} AEAD_DEC?",
			"a bare primitive name needs one added"
		);
		assert_eq!(step(&["k"], None, None, false), "k");
		assert_eq!(step(&[], Some("ASSERT"), None, true), "ASSERT?");
		assert_eq!(
			step(&["a", "b"], Some("SPLIT"), None, false),
			"a, b \u{2190} SPLIT"
		);
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
			hop: Some(1),
			step: None,
			from: "Alice".to_string(),
			to: "Bob".to_string(),
			route: Route::Forged,
			values: vec![],
		};
		assert_eq!(row.lanes(), vec!["Alice", ATTACKER, "Bob"]);
		let phase = Row::Phase { number: 1 };
		assert!(phase.lanes().is_empty(), "a phase spans the whole diagram");
	}

	fn query(steps: Vec<TraceStep>) -> QueryReport {
		QueryReport {
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
			steps,
			preconditions: vec![],
			generated: false,
			variants: 0,
		}
	}

	fn model(source: &str, queries: Vec<QueryReport>) -> ModelReport {
		let (diagram, tokens) = crate::report::describe(source);
		ModelReport {
			file: "t.vp".to_string(),
			ok: true,
			error: None,
			analysis: Some(crate::report::Analysis {
				model: "t.vp".to_string(),
				attacker: "active".to_string(),
				sessions: 2,
				code: String::new(),
				attacks: queries.len(),
				elapsed_ms: 0,
				assumptions: vec![],
				scenarios: vec![],
				notes: vec![],
				provenance: vec![],
				queries,
			}),
			diagram,
			source: source.to_string(),
			tokens,
		}
	}

	fn derive(text: &str) -> TraceStep {
		TraceStep::new(StepKind::Derive, text.to_string())
	}

	fn named(name: &str, guarded: bool) -> TraceValue {
		TraceValue {
			name: name.to_string(),
			installed: None,
			was: None,
			guarded,
		}
	}

	fn routed(kind: StepKind, from: &str, to: &str, values: Vec<TraceValue>) -> TraceStep {
		TraceStep {
			sender: Some(from.to_string()),
			recipient: Some(to.to_string()),
			values,
			..TraceStep::new(kind, String::new())
		}
	}

	fn about(kind: StepKind, principal: &str, values: Vec<TraceValue>) -> TraceStep {
		TraceStep {
			principal: Some(principal.to_string()),
			values,
			..TraceStep::new(kind, String::new())
		}
	}

	fn drawn(chart: &Chart) -> Vec<String> {
		chart
			.rows
			.iter()
			.map(|row| match row {
				Row::Wire {
					hop,
					step,
					from,
					to,
					route,
					values,
				} => format!(
					"{}:{} {from}>{to} {}{}{}",
					hop.map_or("-".to_string(), |n| n.to_string()),
					step.map_or("-".to_string(), |n| n.to_string()),
					values
						.iter()
						.map(|v| {
							let name = if v.guarded {
								format!("[{}]", v.name)
							} else {
								v.name.clone()
							};
							format!("{name}{}", if v.hit() { "+" } else { "" })
						})
						.collect::<Vec<String>>()
						.join(","),
					if route.breached() {
						" via Attacker"
					} else {
						""
					},
					match route.note() {
						"" => String::new(),
						note => format!(" ({note})"),
					}
				),
				Row::Phase { number } => format!("phase {number}"),
				Row::Leak { principal, values } => {
					format!("{principal} leaks {}", values.join(","))
				}
				Row::Activity { principal, .. } => format!("{principal} acts"),
				Row::Mark {
					step,
					principal,
					mark,
				} => format!("{step} {principal} {}", mark.label()),
				Row::Run { first, last } => format!("computes {}", span(*first, *last)),
			})
			.collect()
	}

	#[test]
	fn consecutive_derivations_group_and_an_action_breaks_the_run() {
		let q = query(vec![
			derive("one"),
			derive("two"),
			TraceStep::new(StepKind::Mutations, "swap".to_string()),
			derive("three"),
		]);
		let groups = staged(&q);
		assert_eq!(groups.len(), 3);
		assert_eq!(groups[0].step(), "1-2");
		assert_eq!(groups[1].step(), "3");
		assert_eq!(groups[2].step(), "4");
		assert!(matches!(groups[1], Group::One(3, _)));
	}

	#[test]
	fn only_what_the_attacker_derives_is_folded_into_a_run() {
		for kind in [
			StepKind::Idle,
			StepKind::Drop,
			StepKind::Mutations,
			StepKind::Replay,
			StepKind::Received,
			StepKind::Gate,
			StepKind::Static,
			StepKind::Resolves,
		] {
			let q = query(vec![
				derive("one"),
				TraceStep::new(kind, String::new()),
				derive("two"),
			]);
			let groups = staged(&q);
			assert_eq!(
				groups.iter().map(Group::step).collect::<Vec<String>>(),
				["1", "2", "3"],
				"a {} step is not a derivation",
				kind.name()
			);
			assert!(matches!(groups[1], Group::One(2, _)));
		}
	}

	const RELAY: &str = "attacker[active]\nprincipal Alice[\n\tgenerates x\n]\n\
		Alice -> Bob: [x]\nprincipal Bob[\n\tgenerates s\n]\nBob -> Carol: x\n\
		principal Carol[\n\tknows private k\n\te = ENC(x, k)\n]\nCarol -> Bob: e\n\
		phase[1]\nprincipal Bob[\n\tleaks s\n]\n\
		queries[\n\tauthentication? Bob -> Carol: x\n]\n";

	#[test]
	fn a_dropped_value_and_an_unstarted_run_are_drawn_as_what_they_are() {
		let q = query(vec![
			about(StepKind::Idle, "Bob#2", vec![]),
			routed(StepKind::Drop, "Alice", "Bob", vec![named("x", true)]),
			derive("Attacker constructs nil."),
			routed(StepKind::Replay, "Bob", "Carol", vec![named("x", false)]),
			about(StepKind::Gate, "Carol", vec![]),
		]);
		let m = model(RELAY, vec![]);
		let chart = Chart::attack(&q, &m).expect("a chart");
		assert_eq!(
			drawn(&chart),
			[
				"1 Bob#2 never starts",
				"1:2 Alice>Bob [x] via Attacker (dropped)",
				"computes 3",
				"2:4 Bob>Carol x via Attacker (replayed)",
				"5 Carol check passes",
			],
			"neither a drop nor an unstarted run is something the attacker computes"
		);
		assert_eq!(
			chart.lanes.names(),
			["Bob#2", "Alice", ATTACKER, "Bob", "Carol"]
		);
	}

	#[test]
	fn a_state_the_judge_reads_is_no_step_of_the_attack() {
		let q = query(vec![
			routed(StepKind::Mutations, "Bob", "Carol", vec![named("x", false)]),
			TraceStep::new(
				StepKind::Resolves,
				"In this state s resolves to s.".to_string(),
			),
			TraceStep::new(
				StepKind::Static,
				"No value x is built from is generated fresh: s.".to_string(),
			),
		]);
		let chart = Chart::attack(&q, &model(RELAY, vec![])).expect("a chart");
		assert_eq!(drawn(&chart), ["2:1 Bob>Carol x via Attacker"]);
	}

	#[test]
	fn a_leak_is_drawn_only_where_the_trace_says_the_attacker_was_handed_it() {
		let unused = query(vec![
			derive("Attacker constructs nil."),
			routed(StepKind::Mutations, "Bob", "Carol", vec![named("x", false)]),
			TraceStep::new(
				StepKind::Resolves,
				"In this state s resolves to s.".to_string(),
			),
		]);
		let m = model(RELAY, vec![]);
		assert!(
			m.diagram
				.iter()
				.any(|row| matches!(row, DiagramRow::Leak { .. })),
			"the model does leak s, in a later phase"
		);
		let chart = Chart::attack(&unused, &m).expect("a chart");
		assert_eq!(
			drawn(&chart),
			["computes 1", "2:2 Bob>Carol x via Attacker"],
			"a leak the trace never uses is not part of the attack, however its prose reads"
		);
		let used = query(vec![
			about(StepKind::Derive, "Bob#2", vec![named("s#2", false)]),
			about(StepKind::Derive, "Carol", vec![named("k", false)]),
			about(StepKind::Derive, "Bob#2", vec![named("t#2", false)]),
			routed(StepKind::Mutations, "Bob", "Carol", vec![named("x", false)]),
		]);
		let chart = Chart::attack(&used, &m).expect("a chart");
		assert_eq!(
			drawn(&chart),
			[
				"Bob#2 leaks s#2,t#2",
				"Carol leaks k",
				"computes 1-3",
				"2:4 Bob>Carol x via Attacker",
			],
			"the row names the run and the values of the trace's own leak steps"
		);
	}

	#[test]
	fn a_dagger_marks_the_hop_an_attack_replaced_and_no_other_hop_of_that_value() {
		let attack = query(vec![routed(
			StepKind::Mutations,
			"Bob#2",
			"Carol#2",
			vec![named("x#2", false)],
		)]);
		let chart = Chart::protocol(&model(RELAY, vec![attack])).expect("a chart");
		let wires: Vec<String> = drawn(&chart)
			.into_iter()
			.filter(|row| row.contains('>'))
			.collect();
		assert_eq!(
			wires,
			["1:- Alice>Bob [x]", "2:- Bob>Carol x+", "3:- Carol>Bob e"],
			"the guarded hop carries the same name but no attack replaced it there"
		);
		assert!(chart.marked());
		let dropped = query(vec![routed(
			StepKind::Drop,
			"Bob",
			"Carol",
			vec![named("x", false)],
		)]);
		let chart = Chart::protocol(&model(RELAY, vec![dropped])).expect("a chart");
		assert!(
			!chart.marked(),
			"a dagger is for a substituted or replayed value, which a dropped one is not"
		);
	}
}
