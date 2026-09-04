/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::info::InfoQuiet;
use crate::types::*;

const SESSIONS: u8 = 1;

const COSTLY_MODELS: [&str; 11] = [
	"concat_split_replay.vp",
	"junglegym_deep_ratchet.vp",
	"junglegym_hybrid_pq.vp",
	"junglegym_phase_cascade.vp",
	"junglegym_threshold_ring.vp",
	"needham-schroeder.vp",
	"piknik.vp",
	"scuttlebutt.vp",
	"signal.vp",
	"tls13-0rtt.vp",
	"tls13.vp",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sweep {
	Fast,
	Exhaustive,
}

impl Sweep {
	fn skips(self, name: &str) -> bool {
		self == Sweep::Fast && COSTLY_MODELS.contains(&name)
	}
	fn builds_traces(self) -> bool {
		self == Sweep::Exhaustive
	}
}

const KNOWN_MISSED_ATTACKS: [(&str, &str, &str); 0] = [];

const KNOWN_BAD_TRACES: [(&str, &str); 0] = [];

enum Outcome {
	Code(String),
	Rejected,
	Panicked,
}

fn analysed(model: &Model, sessions: u8, sweep: Sweep) -> Outcome {
	let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
		let _quiet = InfoQuiet::new();
		let _verdicts_only = (!sweep.builds_traces()).then(crate::witness::MinimizingGuard::new);
		crate::verify::analyze_sessions(model, sessions)
			.ok()
			.map(|ctx| VerifyResult::results_code(&ctx.results_get()))
	}));
	match attempt {
		Ok(Some(code)) => Outcome::Code(code),
		Ok(None) => Outcome::Rejected,
		Err(_) => Outcome::Panicked,
	}
}

fn code_of(model: &Model, sessions: u8, sweep: Sweep) -> Outcome {
	let rendered = crate::pretty::pretty_model(model);
	match crate::parser::parse_string(&model.file_name, &rendered) {
		Ok(reparsed) => analysed(&reparsed, sessions, sweep),
		Err(_) => Outcome::Rejected,
	}
}

fn corpus() -> Vec<(String, Model)> {
	crate::model_tests::swept_models()
		.into_iter()
		.filter_map(|(name, path)| {
			let source = std::fs::read_to_string(&path).ok()?;
			let model = crate::parser::parse_string(&name, &source).ok()?;
			Some((name, model))
		})
		.collect()
}

fn asks_the_same_question(model: &Model, variant: &Model) -> bool {
	let before = crate::scenario::honesty_profile(model);
	let after = crate::scenario::honesty_profile(variant);
	before
		.iter()
		.all(|(scenario, corrupt_from)| after.get(scenario) == Some(corrupt_from))
}

fn lost_attacks(before: &str, after: &str) -> Vec<usize> {
	assert_eq!(
		before.len(),
		after.len(),
		"a transformation changed the number of queries, so the two result codes \
		 ({before} and {after}) cannot be compared query by query. Reporting no \
		 violation here would turn the property into a silent skip"
	);
	before
		.as_bytes()
		.chunks(2)
		.zip(after.as_bytes().chunks(2))
		.enumerate()
		.filter(|(_, (b, a))| b[1] == b'1' && a[1] == b'0')
		.map(|(i, _)| i)
		.collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Strength {
	Stronger,
	Weaker,
}

fn variants_promoted(model: &Model) -> Vec<Model> {
	if model.attacker != AttackerKind::Passive {
		return Vec::new();
	}
	let mut active = model.clone();
	active.attacker = AttackerKind::Active;
	vec![active]
}

fn variants_demoted(model: &Model) -> Vec<Model> {
	if model.attacker != AttackerKind::Active {
		return Vec::new();
	}
	let mut passive = model.clone();
	passive.attacker = AttackerKind::Passive;
	vec![passive]
}

fn variants_unguarded(model: &Model) -> Vec<Model> {
	let mut out = Vec::new();
	for (bi, block) in model.blocks.iter().enumerate() {
		let Block::Message(message) = block else {
			continue;
		};
		for (ci, constant) in message.constants.iter().enumerate() {
			if !constant.guard {
				continue;
			}
			let mut variant = model.clone();
			if let Some(Block::Message(m)) = variant.blocks.get_mut(bi)
				&& let Some(c) = m.constants.get_mut(ci)
			{
				c.guard = false;
			}
			out.push(variant);
		}
	}
	out
}

fn variants_leaked(model: &Model) -> Vec<Model> {
	let mut out = Vec::new();
	for (bi, block) in model.blocks.iter().enumerate() {
		let Block::Principal(principal) = block else {
			continue;
		};
		for expression in &principal.expressions {
			let eligible = matches!(expression.kind, Declaration::Generates)
				|| (expression.kind == Declaration::Knows
					&& expression.qualifier != Some(Qualifier::Public));
			if !eligible {
				continue;
			}
			for constant in &expression.constants {
				let mut variant = model.clone();
				if let Some(Block::Principal(p)) = variant.blocks.get_mut(bi) {
					p.expressions.push(Expression {
						span: Span::default(),
						kind: Declaration::Leaks,
						qualifier: None,
						constants: vec![constant.clone()],
						assigned: None,
						leading_comments: Vec::new(),
						trailing_comment: None,
					});
				}
				out.push(variant);
			}
		}
	}
	out
}

fn annotations(value: &Value, cap: Capability) -> Vec<Value> {
	let Value::Primitive(p) = value else {
		return Vec::new();
	};
	let mut out = Vec::new();
	if crate::capability::supports(p.id, cap) && !p.capabilities.has(cap) {
		let mut updated = (**p).clone();
		updated.capabilities.set(cap, 0);
		out.push(Value::Primitive(std::sync::Arc::new(updated)));
	}
	for (i, argument) in p.arguments.iter().enumerate() {
		for replaced in annotations(argument, cap) {
			let mut updated = (**p).clone();
			updated.arguments[i] = replaced;
			out.push(Value::Primitive(std::sync::Arc::new(updated)));
		}
	}
	out
}

fn variants_weakened(model: &Model) -> Vec<Model> {
	let mut out = Vec::new();
	for cap in Capability::ALL {
		for (bi, block) in model.blocks.iter().enumerate() {
			let Block::Principal(principal) = block else {
				continue;
			};
			for (ei, expression) in principal.expressions.iter().enumerate() {
				let Some(assigned) = expression.assigned.as_ref() else {
					continue;
				};
				for annotated in annotations(assigned, cap) {
					let mut variant = model.clone();
					if let Some(Block::Principal(p)) = variant.blocks.get_mut(bi)
						&& let Some(e) = p.expressions.get_mut(ei)
					{
						e.assigned = Some(annotated);
						out.push(variant);
					}
				}
			}
		}
	}
	out
}

#[derive(Default)]
struct Report {
	compared: usize,
	violations: Vec<String>,
	panicked: Vec<String>,
	ran: Vec<String>,
}

impl Report {
	fn absorb(&mut self, other: Report) {
		self.compared += other.compared;
		self.violations.extend(other.violations);
		self.panicked.extend(other.panicked);
		self.ran.extend(other.ran);
	}
}

fn worker_cap() -> usize {
	std::env::var("VERIFPAL_METAMORPHIC_WORKERS")
		.ok()
		.and_then(|v| v.parse::<usize>().ok())
		.filter(|&n| n > 0)
		.unwrap_or(4)
}

fn spread<T, R>(items: &[T], work: impl Fn(&T) -> R + Sync) -> Vec<R>
where
	T: Sync,
	R: Send,
{
	use std::sync::atomic::{AtomicUsize, Ordering};

	if items.is_empty() {
		return Vec::new();
	}
	let workers = std::thread::available_parallelism()
		.map(|p| p.get())
		.unwrap_or(1)
		.min(items.len())
		.min(worker_cap());
	let next = AtomicUsize::new(0);
	let work = &work;
	let next = &next;
	let mut collected: Vec<(usize, R)> = std::thread::scope(|scope| {
		let handles: Vec<_> = (0..workers)
			.map(|_| {
				scope.spawn(move || {
					let mut mine = Vec::new();
					loop {
						let i = next.fetch_add(1, Ordering::Relaxed);
						if i >= items.len() {
							break;
						}
						mine.push((i, work(&items[i])));
					}
					mine
				})
			})
			.collect();
		handles
			.into_iter()
			.flat_map(|h| h.join().expect("metamorphic worker"))
			.collect()
	});
	collected.sort_by_key(|(i, _)| *i);
	collected.into_iter().map(|(_, r)| r).collect()
}

fn excused<'a>(table: &'a [(&'a str, &'a str, &'a str)], property: &str) -> Vec<&'a str> {
	table
		.iter()
		.filter(|(_, p, _)| *p == property)
		.map(|(m, _, _)| *m)
		.collect()
}

fn excused_traces<'a>(table: &'a [(&'a str, &'a str)], property: &str) -> Vec<&'a str> {
	table
		.iter()
		.filter(|(_, p)| *p == property)
		.map(|(m, _)| *m)
		.collect()
}

fn rotate_code(code: &str, queries: usize) -> String {
	let pairs: Vec<&str> = code
		.as_bytes()
		.chunks(2)
		.filter_map(|c| std::str::from_utf8(c).ok())
		.collect();
	if pairs.is_empty() {
		return code.to_string();
	}
	let k = queries % pairs.len();
	pairs[k..]
		.iter()
		.chain(pairs[..k].iter())
		.copied()
		.collect()
}

fn variant_query_rotation(model: &Model) -> Option<Model> {
	if model.queries.len() < 2 {
		return None;
	}
	let mut rotated = model.clone();
	rotated.queries.rotate_left(1);
	Some(rotated)
}

const RENAME_SUFFIX: &str = "qq";

fn renamed_constant(constant: &Constant) -> Constant {
	let mut out = constant.clone();
	let name: &str = &constant.name;
	if name == "nil" || crate::parser::check_reserved(name).is_err() {
		return out;
	}
	out.name = std::sync::Arc::from(format!("{name}{RENAME_SUFFIX}").as_str());
	out
}

fn rename_value(value: &Value) -> Value {
	match value {
		Value::Constant(c) => Value::Constant(renamed_constant(c)),
		Value::Primitive(p) => {
			let mut updated = (**p).clone();
			updated.arguments = p.arguments.iter().map(rename_value).collect();
			Value::Primitive(std::sync::Arc::new(updated))
		}
	}
}

fn rename_message(message: &mut Message) {
	message.sender_name =
		std::sync::Arc::from(format!("{}{}", message.sender_name, RENAME_SUFFIX).as_str());
	message.recipient_name =
		std::sync::Arc::from(format!("{}{}", message.recipient_name, RENAME_SUFFIX).as_str());
	message.constants = message.constants.iter().map(renamed_constant).collect();
}

fn variant_renamed(model: &Model) -> Option<Model> {
	let mut out = model.clone();
	for block in &mut out.blocks {
		match block {
			Block::Principal(p) => {
				p.name = format!("{}{}", p.name, RENAME_SUFFIX);
				for e in &mut p.expressions {
					e.constants = e.constants.iter().map(renamed_constant).collect();
					e.assigned = e.assigned.as_ref().map(rename_value);
				}
			}
			Block::Message(m) => rename_message(m),
			Block::Phase(_) => {}
		}
	}
	for q in &mut out.queries {
		q.constants = q.constants.iter().map(renamed_constant).collect();
		rename_message(&mut q.message);
		for option in &mut q.options {
			rename_message(&mut option.message);
		}
	}
	for scenario in &mut out.scenarios {
		scenario.principal_name =
			std::sync::Arc::from(format!("{}{}", scenario.principal_name, RENAME_SUFFIX).as_str());
		scenario.bindings = scenario
			.bindings
			.iter()
			.map(|(target, value)| (renamed_constant(target), renamed_constant(value)))
			.collect();
	}
	Some(out)
}

fn variant_padded(model: &Model) -> Option<Model> {
	let mut out = model.clone();
	let block = out.blocks.iter_mut().find_map(|b| match b {
		Block::Principal(p) => Some(p),
		_ => None,
	})?;
	block.expressions.insert(
		0,
		Expression {
			span: Span::default(),
			kind: Declaration::Knows,
			qualifier: Some(Qualifier::Private),
			constants: vec![Constant {
				name: std::sync::Arc::from("padding_constant_qq"),
				id: 0,
				guard: false,
				fresh: false,
				leaked: false,
				declaration: Some(Declaration::Knows),
				qualifier: Some(Qualifier::Private),
			}],
			assigned: None,
			leading_comments: Vec::new(),
			trailing_comment: None,
		},
	);
	Some(out)
}

fn identity_scenarios(model: &Model, copies: usize) -> Option<Model> {
	if !model.scenarios.is_empty() {
		return None;
	}
	let travels = |id: ValueId| {
		model.blocks.iter().any(|b| match b {
			Block::Message(msg) => msg.constants.iter().any(|c| c.id == id),
			_ => false,
		})
	};
	let (principal, name, constant) = model.blocks.iter().find_map(|b| {
		let Block::Principal(p) = b else {
			return None;
		};
		p.expressions
			.iter()
			.filter(|e| e.kind == Declaration::Knows)
			.flat_map(|e| e.constants.iter())
			.find(|c| !travels(c.id))
			.map(|c| {
				(
					p.id,
					std::sync::Arc::<str>::from(p.name.as_str()),
					c.clone(),
				)
			})
	})?;
	let mut out = model.clone();
	out.scenarios = (0..copies)
		.map(|_| Scenario {
			span: Span::default(),
			principal,
			principal_name: std::sync::Arc::clone(&name),
			bindings: vec![(constant.clone(), constant.clone())],
			leading_comments: Vec::new(),
			trailing_comment: None,
		})
		.collect();
	Some(out)
}

fn variant_identity_scenario(model: &Model) -> Option<Model> {
	identity_scenarios(model, 1)
}

fn variants_duplicated_scenario(model: &Model) -> Vec<Model> {
	identity_scenarios(model, 2).into_iter().collect()
}

fn variants_dephased(model: &Model) -> Vec<Model> {
	let Some(last) = model
		.blocks
		.iter()
		.rposition(|b| matches!(b, Block::Phase(_)))
	else {
		return Vec::new();
	};
	let mut variant = model.clone();
	variant.blocks.remove(last);
	vec![variant]
}

fn variants_restricted(model: &Model) -> Vec<Model> {
	let Some(message) = model.blocks.iter().rev().find_map(|b| match b {
		Block::Message(m) => Some(m),
		_ => None,
	}) else {
		return Vec::new();
	};
	let Some(constant) = message.constants.first() else {
		return Vec::new();
	};
	let mut variant = model.clone();
	for query in &mut variant.queries {
		query.options.push(QueryOption {
			kind: QueryOptionKind::Precondition,
			message: Message {
				span: Span::default(),
				sender: message.sender,
				sender_name: message.sender_name.clone(),
				recipient: message.recipient,
				recipient_name: message.recipient_name.clone(),
				constants: vec![constant.clone()],
				leading_comments: Vec::new(),
				trailing_comment: None,
			},
			leading_comments: Vec::new(),
			trailing_comment: None,
		});
	}
	vec![variant]
}

fn check_sessions(property: &str, floor: usize, sweep: Sweep) {
	let models = corpus();
	let parts = spread(&models, |(name, model)| {
		let mut local = Report::default();
		let Outcome::Code(one) = code_of(model, 1, sweep) else {
			return local;
		};
		match code_of(model, 2, sweep) {
			Outcome::Rejected => {}
			Outcome::Panicked => {
				local.ran.push(name.clone());
				local.panicked.push(name.clone());
			}
			Outcome::Code(two) => {
				local.ran.push(name.clone());
				local.compared += 1;
				for q in lost_attacks(&one, &two) {
					local.violations.push(format!(
						"{name}: sessions=1 {one}, sessions=2 {two}, query {q} lost"
					));
				}
			}
		}
		local
	});
	let mut report = Report::default();
	for part in parts {
		report.absorb(part);
	}
	report.panicked.sort();
	report.panicked.dedup();
	settle(property, report, floor, sweep);
}

fn check_invariant(
	property: &str,
	variant: fn(&Model) -> Option<Model>,
	expected: fn(&str) -> String,
	floor: usize,
	sweep: Sweep,
) {
	let models = corpus();
	let parts = spread(&models, |(name, model)| {
		let mut local = Report::default();
		let Outcome::Code(before) = code_of(model, SESSIONS, sweep) else {
			return local;
		};
		let Some(transformed) = variant(model) else {
			return local;
		};
		if !asks_the_same_question(model, &transformed) {
			return local;
		}
		match code_of(&transformed, SESSIONS, sweep) {
			Outcome::Rejected => {}
			Outcome::Panicked => {
				local.ran.push(name.clone());
				local.panicked.push(name.clone());
			}
			Outcome::Code(after) => {
				local.ran.push(name.clone());
				local.compared += 1;
				let want = expected(&before);
				if after != want {
					local.violations.push(format!(
						"{name}: original={before} variant={after} expected={want}"
					));
				}
			}
		}
		local
	});
	let mut report = Report::default();
	for part in parts {
		report.absorb(part);
	}
	report.panicked.sort();
	report.panicked.dedup();
	settle(property, report, floor, sweep);
}

fn settle(property: &str, report: Report, floor: usize, sweep: Sweep) {
	eprintln!(
		"the `{property}` property compared {} pairs",
		report.compared
	);
	assert!(
		report.compared >= floor,
		"the `{property}` property compared only {} pairs against a floor of {floor}, so it \
		 is passing vacuously rather than holding",
		report.compared
	);

	if sweep.builds_traces() {
		settle_traces(property, &report);
	}

	let expected = excused(&KNOWN_MISSED_ATTACKS, property);
	let unexpected: Vec<&String> = report
		.violations
		.iter()
		.filter(|v| !expected.iter().any(|m| v.starts_with(m)))
		.collect();
	assert!(
		unexpected.is_empty(),
		"the `{property}` property found a missed attack that is not in \
		 KNOWN_MISSED_ATTACKS. A transformation giving the attacker strictly more power \
		 reported strictly fewer attacks:\n  {}",
		unexpected
			.iter()
			.map(|s| s.as_str())
			.collect::<Vec<_>>()
			.join("\n  ")
	);
	let stale: Vec<&str> = expected
		.iter()
		.filter(|m| report.ran.iter().any(|e| e == *m))
		.filter(|m| !report.violations.iter().any(|v| v.starts_with(*m)))
		.copied()
		.collect();
	assert!(
		stale.is_empty(),
		"KNOWN_MISSED_ATTACKS lists {stale:?} under `{property}`, but the property now holds \
		 for it. If this was fixed, delete the entry"
	);
}

fn settle_traces(property: &str, report: &Report) {
	let expected_panics = excused_traces(&KNOWN_BAD_TRACES, property);
	let new_panics: Vec<&String> = report
		.panicked
		.iter()
		.filter(|m| !expected_panics.contains(&m.as_str()))
		.collect();
	assert!(
		new_panics.is_empty(),
		"the `{property}` property made the engine's own invariant checks fire on \
		 {new_panics:?}. A transformed model is still a legal model, so an assertion \
		 firing is an engine bug rather than a harness failure"
	);
	let stale_panics: Vec<&str> = expected_panics
		.iter()
		.filter(|m| report.ran.iter().any(|e| e == *m))
		.filter(|m| !report.panicked.iter().any(|p| p == *m))
		.copied()
		.collect();
	assert!(
		stale_panics.is_empty(),
		"KNOWN_BAD_TRACES lists {stale_panics:?} under `{property}`, but nothing fires there \
		 now. If this was fixed, delete the entry; a stale exception makes the list stop \
		 meaning anything"
	);
}

fn check_monotone(
	property: &str,
	variants: fn(&Model) -> Vec<Model>,
	strength: Strength,
	floor: usize,
	sweep: Sweep,
) {
	let models = corpus();
	let parts = spread(&models, |(name, model)| {
		let mut local = Report::default();
		if sweep.skips(name) {
			return local;
		}
		let Outcome::Code(before) = code_of(model, SESSIONS, sweep) else {
			return local;
		};
		if strength == Strength::Stronger && !before.contains('1') {
			return local;
		}
		let mut ran = false;
		for variant in variants(model) {
			if !asks_the_same_question(model, &variant) {
				continue;
			}
			match code_of(&variant, SESSIONS, sweep) {
				Outcome::Rejected => continue,
				Outcome::Panicked => {
					ran = true;
					local.panicked.push(name.clone());
				}
				Outcome::Code(after) => {
					ran = true;
					local.compared += 1;
					let lost = match strength {
						Strength::Stronger => lost_attacks(&before, &after),
						Strength::Weaker => lost_attacks(&after, &before),
					};
					for q in lost {
						local.violations.push(format!(
							"{name}: before={before} after={after}, query {q} lost"
						));
					}
				}
			}
		}
		if ran {
			local.ran.push(name.clone());
		}
		local
	});
	let mut report = Report::default();
	for part in parts {
		report.absorb(part);
	}
	report.panicked.sort();
	report.panicked.dedup();
	settle(property, report, floor, sweep);
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn lost_attacks_finds_only_ones_that_became_zeros() {
		assert_eq!(lost_attacks("c1a0", "c0a0"), vec![0]);
		assert_eq!(lost_attacks("c1a0", "c1a1"), Vec::<usize>::new());
	}

	#[test]
	#[should_panic(expected = "changed the number of queries")]
	fn comparing_codes_of_different_lengths_is_refused_rather_than_skipped() {
		lost_attacks("c1", "c1a0");
	}

	#[test]
	fn rendering_and_reparsing_a_model_preserves_every_verdict() {
		let models = corpus();
		let parts = spread(&models, |(name, model)| {
			let Outcome::Code(direct) = analysed(model, SESSIONS, Sweep::Exhaustive) else {
				return (0usize, None);
			};
			let drift = match code_of(model, SESSIONS, Sweep::Exhaustive) {
				Outcome::Code(round_tripped) if round_tripped == direct => None,
				Outcome::Code(other) => {
					Some(format!("{name}: direct={direct} round-tripped={other}"))
				}
				Outcome::Rejected => Some(format!(
					"{name}: direct={direct} but the render did not parse"
				)),
				Outcome::Panicked => {
					Some(format!("{name}: direct={direct} but the render panicked"))
				}
			};
			(1usize, drift)
		});
		let compared: usize = parts.iter().map(|(c, _)| c).sum();
		let drifted: Vec<String> = parts.into_iter().filter_map(|(_, d)| d).collect();
		assert!(
			compared > 300,
			"only {compared} models reached the comparison, so this test is passing \
			 vacuously and every property built on the pipeline is measuring nothing"
		);
		assert!(
			drifted.is_empty(),
			"a model analysed differently after being rendered and re-parsed, so every \
			 metamorphic result below would be measuring the printer rather than the \
			 engine:\n  {}",
			drifted.join("\n  ")
		);
	}

	#[test]
	fn deleting_a_phase_boundary_never_loses_an_attack() {
		check_monotone(
			"dephase",
			variants_dephased,
			Strength::Stronger,
			15,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn adding_a_session_never_loses_an_attack() {
		check_sessions("sessions", 250, Sweep::Exhaustive);
	}

	#[test]
	fn an_unused_declaration_changes_no_verdict() {
		check_invariant(
			"pad",
			variant_padded,
			|before| before.to_string(),
			300,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn renaming_actually_rewrites_the_model() {
		let mut rewritten = 0usize;
		for (_, model) in corpus() {
			let Some(renamed) = variant_renamed(&model) else {
				continue;
			};
			if crate::pretty::pretty_model(&renamed) != crate::pretty::pretty_model(&model) {
				rewritten += 1;
			}
		}
		assert!(
			rewritten > 300,
			"only {rewritten} models changed under renaming, so the invariance property is \
			 comparing models against identical copies"
		);
	}

	#[test]
	fn renaming_every_identifier_changes_no_verdict() {
		check_invariant(
			"rename",
			variant_renamed,
			|before| before.to_string(),
			300,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn rotate_code_moves_whole_queries() {
		assert_eq!(rotate_code("c1a0f1", 1), "a0f1c1");
		assert_eq!(rotate_code("c1a0f1", 3), "c1a0f1");
		assert_eq!(rotate_code("c1", 1), "c1");
	}

	#[test]
	fn a_scenario_that_binds_a_constant_to_itself_changes_no_verdict() {
		check_invariant(
			"scenario",
			variant_identity_scenario,
			|before| before.to_string(),
			300,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn a_second_copy_of_a_scenario_never_loses_an_attack() {
		check_monotone(
			"scenarios",
			variants_duplicated_scenario,
			Strength::Stronger,
			200,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn reordering_the_queries_block_changes_no_verdict() {
		check_invariant(
			"rotate",
			variant_query_rotation,
			|before| rotate_code(before, 1),
			150,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn a_weakening_annotation_survives_the_round_trip() {
		let mut annotated = 0usize;
		for (_, model) in corpus() {
			for variant in variants_weakened(&model) {
				let rendered = crate::pretty::pretty_model(&variant);
				if rendered.contains("[weak]") || rendered.contains("[forgeable]") {
					annotated += 1;
				}
			}
		}
		assert!(
			annotated > 100,
			"only {annotated} weakened variants rendered their annotation, so the \
			 capability property would be comparing a model against an identical copy"
		);
	}

	#[test]
	#[ignore = "exhaustive sweep; run with cargo test --release -- --include-ignored"]
	fn leaking_a_secret_never_loses_an_attack_exhaustively() {
		check_monotone(
			"leaks",
			variants_leaked,
			Strength::Stronger,
			250,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn leaking_a_secret_never_loses_an_attack() {
		check_monotone(
			"leaks",
			variants_leaked,
			Strength::Stronger,
			800,
			Sweep::Fast,
		);
	}

	#[test]
	#[ignore = "exhaustive sweep; run with cargo test --release -- --include-ignored"]
	fn weakening_a_primitive_never_loses_an_attack_exhaustively() {
		check_monotone(
			"weaken",
			variants_weakened,
			Strength::Stronger,
			250,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn weakening_a_primitive_never_loses_an_attack() {
		check_monotone(
			"weaken",
			variants_weakened,
			Strength::Stronger,
			1200,
			Sweep::Fast,
		);
	}

	#[test]
	#[ignore = "exhaustive sweep; run with cargo test --release -- --include-ignored"]
	fn removing_a_guard_never_loses_an_attack_exhaustively() {
		check_monotone(
			"unguard",
			variants_unguarded,
			Strength::Stronger,
			250,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn removing_a_guard_never_loses_an_attack() {
		check_monotone(
			"unguard",
			variants_unguarded,
			Strength::Stronger,
			180,
			Sweep::Fast,
		);
	}

	#[test]
	fn promoting_a_passive_model_to_active_never_loses_an_attack() {
		check_monotone(
			"promote",
			variants_promoted,
			Strength::Stronger,
			60,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn a_passive_run_never_finds_an_attack_the_active_run_misses() {
		check_monotone(
			"demote",
			variants_demoted,
			Strength::Weaker,
			200,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn restricting_a_query_to_executions_with_a_send_never_adds_an_attack() {
		check_monotone(
			"restrict",
			variants_restricted,
			Strength::Weaker,
			250,
			Sweep::Exhaustive,
		);
	}
}
