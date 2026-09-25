/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::info::InfoQuiet;
use crate::types::*;

const SESSIONS: u8 = 1;

const COSTLY_MODELS: [&str; 10] = [
	"concat_split_replay.vp",
	"junglegym_deep_ratchet.vp",
	"junglegym_hybrid_pq.vp",
	"junglegym_phase_cascade.vp",
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
}

const KNOWN_MISSED_ATTACKS: [(&str, &str, &str); 0] = [];

const KNOWN_BAD_TRACES: [(&str, &str); 0] = [];

enum Outcome {
	Code(String),
	Rejected,
	Panicked,
}

fn analysed(model: &Model, sessions: u8) -> Outcome {
	let progress = std::env::var_os("VERIFPAL_METAMORPHIC_PROGRESS").is_some();
	if progress {
		eprintln!(
			"[metamorphic {:?}] begin {} sessions={sessions} scenarios={}",
			std::thread::current().id(),
			model.file_name,
			model.scenarios.len()
		);
	}
	let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
		let _quiet = InfoQuiet::new();
		crate::verify::analyze_sessions(model, sessions)
			.ok()
			.map(|ctx| VerifyResult::results_code(&ctx.results_get()))
	}));
	if progress {
		eprintln!(
			"[metamorphic {:?}] end {}",
			std::thread::current().id(),
			model.file_name
		);
	}
	match attempt {
		Ok(Some(code)) => Outcome::Code(code),
		Ok(None) => Outcome::Rejected,
		Err(_) => Outcome::Panicked,
	}
}

fn code_of(model: &Model, sessions: u8) -> Outcome {
	let rendered = crate::pretty::pretty_model(model);
	match crate::parser::parse_string(&model.file_name, &rendered) {
		Ok(reparsed) => analysed(&reparsed, sessions),
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

#[derive(Clone, Copy)]
enum Change {
	Stronger,
	Weaker,
	Invariant(fn(&str) -> String),
}

fn variants_attacker(model: &Model, attacker: AttackerKind) -> Vec<Model> {
	if model.attacker == attacker {
		return Vec::new();
	}
	vec![Model {
		attacker,
		..model.clone()
	}]
}

fn variants_guard(model: &Model, guard: bool) -> Vec<Model> {
	let mut out = Vec::new();
	for (bi, block) in model.blocks.iter().enumerate() {
		let Block::Message(message) = block else {
			continue;
		};
		for (ci, constant) in message.constants.iter().enumerate() {
			if constant.guard == guard {
				continue;
			}
			let mut variant = model.clone();
			if let Some(Block::Message(m)) = variant.blocks.get_mut(bi)
				&& let Some(c) = m.constants.get_mut(ci)
			{
				c.guard = guard;
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
						comments: LineComments::default(),
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
	if crate::capability::supports(p.id, cap)
		&& p.capabilities.onset(cap).is_none_or(|phase| phase > 0)
	{
		let mut updated = (**p).clone();
		updated.capabilities.set(cap, 0);
		out.push(Value::Primitive(Arc::new(updated)));
	}
	for (i, argument) in p.arguments.iter().enumerate() {
		for replaced in annotations(argument, cap) {
			let mut updated = (**p).clone();
			updated.arguments[i] = replaced;
			out.push(Value::Primitive(Arc::new(updated)));
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

fn variants_rethresholded(model: &Model, delta: i64) -> Vec<Model> {
	let mut out = Vec::new();
	if model
		.queries
		.iter()
		.any(|q| matches!(q.kind, QueryKind::Equivalence | QueryKind::Unlinkability))
	{
		return out;
	}
	for (bi, block) in model.blocks.iter().enumerate() {
		let Block::Principal(principal) = block else {
			continue;
		};
		for (ei, expression) in principal.expressions.iter().enumerate() {
			let Some(Value::Primitive(p)) = expression.assigned.as_ref() else {
				continue;
			};
			let Some(rule) = crate::primitive::primitive_threshold(p.id) else {
				continue;
			};
			let threshold = p.threshold as i64 + delta;
			if threshold < rule.min as i64 || threshold > expression.constants.len() as i64 {
				continue;
			}
			let mut changed = (**p).clone();
			changed.threshold = threshold as usize;
			changed.hash = HashCell::default();
			let mut variant = model.clone();
			if let Some(Block::Principal(principal)) = variant.blocks.get_mut(bi)
				&& let Some(e) = principal.expressions.get_mut(ei)
			{
				e.assigned = Some(Value::Primitive(Arc::new(changed)));
				out.push(variant);
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

	fn tally(
		&mut self,
		name: &str,
		outcomes: impl IntoIterator<Item = Outcome>,
		violations: impl Fn(&str) -> Vec<String>,
	) {
		let mut ran = false;
		for outcome in outcomes {
			match outcome {
				Outcome::Rejected => continue,
				Outcome::Panicked => self.panicked.push(name.to_string()),
				Outcome::Code(after) => {
					self.compared += 1;
					self.violations.extend(violations(&after));
				}
			}
			ran = true;
		}
		if ran {
			self.ran.push(name.to_string());
		}
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

fn excused<'a>(
	table: impl IntoIterator<Item = (&'a str, &'a str)>,
	property: &str,
) -> Vec<&'a str> {
	table
		.into_iter()
		.filter(|&(_, p)| p == property)
		.map(|(m, _)| m)
		.collect()
}

fn stale<'a>(listed: &[&'a str], report: &Report, holds: impl Fn(&str) -> bool) -> Vec<&'a str> {
	listed
		.iter()
		.filter(|m| report.ran.iter().any(|e| e == *m))
		.filter(|m| holds(m))
		.copied()
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

fn renamed(name: &str) -> String {
	format!("{name}qq")
}

fn renamed_constant(constant: &Constant) -> Constant {
	let mut out = constant.clone();
	let name: &str = &constant.name;
	if name == "nil" || crate::parser::check_reserved(name).is_err() {
		return out;
	}
	out.name = Arc::from(renamed(name));
	out
}

fn rename_message(message: &mut Message) {
	message.sender_name = Arc::from(renamed(&message.sender_name));
	message.recipient_name = Arc::from(renamed(&message.recipient_name));
	message.constants = message.constants.iter().map(renamed_constant).collect();
}

fn variant_renamed(model: &Model) -> Model {
	let mut out = model.clone();
	for block in &mut out.blocks {
		match block {
			Block::Principal(p) => {
				p.name = renamed(&p.name);
				for e in &mut p.expressions {
					e.constants = e.constants.iter().map(renamed_constant).collect();
					e.assigned = e
						.assigned
						.as_ref()
						.map(|v| crate::sessions::map_constants(v, &renamed_constant));
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
		scenario.principal_name = Arc::from(renamed(&scenario.principal_name));
		scenario.bindings = scenario
			.bindings
			.iter()
			.map(|(target, value)| (renamed_constant(target), renamed_constant(value)))
			.collect();
	}
	out
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
				name: Arc::from("padding_constant_qq"),
				id: 0,
				guard: false,
				fresh: false,
				leaked: false,
				declaration: Some(Declaration::Knows),
				qualifier: Some(Qualifier::Private),
			}],
			assigned: None,
			comments: LineComments::default(),
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
			.map(|c| (p.id, Arc::<str>::from(p.name.as_str()), c.clone()))
	})?;
	let mut out = model.clone();
	out.scenarios = (0..copies)
		.map(|_| Scenario {
			span: Span::default(),
			principal,
			principal_name: Arc::clone(&name),
			bindings: vec![(constant.clone(), constant.clone())],
			comments: LineComments::default(),
		})
		.collect();
	Some(out)
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
				sender: message.sender,
				sender_name: message.sender_name.clone(),
				recipient: message.recipient,
				recipient_name: message.recipient_name.clone(),
				constants: vec![constant.clone()],
				..Message::default()
			},
			comments: LineComments::default(),
		});
	}
	vec![variant]
}

fn check(
	property: &str,
	floor: usize,
	sweep: Sweep,
	compare: impl Fn(&str, &Model, &mut Report) + Sync,
) {
	let models = corpus();
	let mut report = Report::default();
	for part in spread(&models, |(name, model)| {
		let mut local = Report::default();
		if !sweep.skips(name) {
			compare(name, model, &mut local);
		}
		local
	}) {
		report.absorb(part);
	}
	report.panicked.sort();
	report.panicked.dedup();
	settle(property, report, floor, sweep);
}

fn check_sessions(property: &str, floor: usize, sweep: Sweep) {
	check(property, floor, sweep, |name, model, report| {
		let Outcome::Code(one) = code_of(model, 1) else {
			return;
		};
		report.tally(name, [code_of(model, 2)], |two| {
			lost_attacks(&one, two)
				.into_iter()
				.map(|q| format!("{name}: sessions=1 {one}, sessions=2 {two}, query {q} lost"))
				.collect()
		});
	});
}

fn check_variants<V: IntoIterator<Item = Model>>(
	property: &str,
	variants: fn(&Model) -> V,
	change: Change,
	floor: usize,
	sweep: Sweep,
) {
	check(property, floor, sweep, |name, model, report| {
		let Outcome::Code(before) = code_of(model, SESSIONS) else {
			return;
		};
		if matches!(change, Change::Stronger) && !before.contains('1') {
			return;
		}
		let outcomes = variants(model)
			.into_iter()
			.filter(|variant| asks_the_same_question(model, variant))
			.map(|variant| code_of(&variant, SESSIONS));
		report.tally(name, outcomes, |after| {
			let lost = match change {
				Change::Stronger => lost_attacks(&before, after),
				Change::Weaker => lost_attacks(after, &before),
				Change::Invariant(expected) => {
					let want = expected(&before);
					return if after == want {
						Vec::new()
					} else {
						vec![format!(
							"{name}: original={before} variant={after} expected={want}"
						)]
					};
				}
			};
			lost.into_iter()
				.map(|q| format!("{name}: before={before} after={after}, query {q} lost"))
				.collect()
		});
	});
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

	if sweep == Sweep::Exhaustive {
		settle_traces(property, &report);
	}

	let expected = excused(
		KNOWN_MISSED_ATTACKS
			.iter()
			.map(|&(model, property, _)| (model, property)),
		property,
	);
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
	let stale = stale(&expected, &report, |m| {
		!report.violations.iter().any(|v| v.starts_with(m))
	});
	assert!(
		stale.is_empty(),
		"KNOWN_MISSED_ATTACKS lists {stale:?} under `{property}`, but the property now holds \
		 for it. If this was fixed, delete the entry"
	);
}

fn settle_traces(property: &str, report: &Report) {
	let expected_panics = excused(KNOWN_BAD_TRACES, property);
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
	let stale_panics = stale(&expected_panics, report, |m| {
		!report.panicked.iter().any(|p| p == m)
	});
	assert!(
		stale_panics.is_empty(),
		"KNOWN_BAD_TRACES lists {stale_panics:?} under `{property}`, but nothing fires there \
		 now. If this was fixed, delete the entry; a stale exception makes the list stop \
		 meaning anything"
	);
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
			let Outcome::Code(direct) = analysed(model, SESSIONS) else {
				return (0usize, None);
			};
			let drift = match code_of(model, SESSIONS) {
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
		check_variants(
			"dephase",
			variants_dephased,
			Change::Stronger,
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
		check_variants(
			"pad",
			variant_padded,
			Change::Invariant(str::to_string),
			300,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn renaming_actually_rewrites_the_model() {
		let mut rewritten = 0usize;
		for (_, model) in corpus() {
			if crate::pretty::pretty_model(&variant_renamed(&model))
				!= crate::pretty::pretty_model(&model)
			{
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
		check_variants(
			"rename",
			|model| Some(variant_renamed(model)),
			Change::Invariant(str::to_string),
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
		check_variants(
			"scenario",
			|model| identity_scenarios(model, 1),
			Change::Invariant(str::to_string),
			300,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn a_second_copy_of_a_scenario_never_loses_an_attack() {
		check_variants(
			"scenarios",
			|model| identity_scenarios(model, 2),
			Change::Stronger,
			200,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn reordering_the_queries_block_changes_no_verdict() {
		check_variants(
			"rotate",
			variant_query_rotation,
			Change::Invariant(|before| rotate_code(before, 1)),
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
		check_variants(
			"leaks",
			variants_leaked,
			Change::Stronger,
			250,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn leaking_a_secret_never_loses_an_attack() {
		check_variants("leaks", variants_leaked, Change::Stronger, 800, Sweep::Fast);
	}

	#[test]
	#[ignore = "exhaustive sweep; run with cargo test --release -- --include-ignored"]
	fn weakening_a_primitive_never_loses_an_attack_exhaustively() {
		check_variants(
			"weaken",
			variants_weakened,
			Change::Stronger,
			250,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn weakening_a_primitive_never_loses_an_attack() {
		check_variants(
			"weaken",
			variants_weakened,
			Change::Stronger,
			1200,
			Sweep::Fast,
		);
	}

	#[test]
	#[ignore = "exhaustive sweep; run with cargo test --release -- --include-ignored"]
	fn removing_a_guard_never_loses_an_attack_exhaustively() {
		check_variants(
			"unguard",
			|model| variants_guard(model, false),
			Change::Stronger,
			250,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn removing_a_guard_never_loses_an_attack() {
		check_variants(
			"unguard",
			|model| variants_guard(model, false),
			Change::Stronger,
			180,
			Sweep::Fast,
		);
	}

	#[test]
	#[ignore = "exhaustive sweep; run with cargo test --release -- --include-ignored"]
	fn adding_a_guard_never_adds_an_attack_exhaustively() {
		check_variants(
			"guard",
			|model| variants_guard(model, true),
			Change::Weaker,
			1800,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn adding_a_guard_never_adds_an_attack() {
		check_variants(
			"guard",
			|model| variants_guard(model, true),
			Change::Weaker,
			1700,
			Sweep::Fast,
		);
	}

	#[test]
	fn lowering_a_threshold_never_loses_an_attack() {
		check_variants(
			"lower",
			|model| variants_rethresholded(model, -1),
			Change::Stronger,
			4,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn raising_a_threshold_never_adds_an_attack() {
		check_variants(
			"raise",
			|model| variants_rethresholded(model, 1),
			Change::Weaker,
			10,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn promoting_a_passive_model_to_active_never_loses_an_attack() {
		check_variants(
			"promote",
			|model| variants_attacker(model, AttackerKind::Active),
			Change::Stronger,
			60,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn a_passive_run_never_finds_an_attack_the_active_run_misses() {
		check_variants(
			"demote",
			|model| variants_attacker(model, AttackerKind::Passive),
			Change::Weaker,
			200,
			Sweep::Exhaustive,
		);
	}

	#[test]
	fn restricting_a_query_to_executions_with_a_send_never_adds_an_attack() {
		check_variants(
			"restrict",
			variants_restricted,
			Change::Weaker,
			250,
			Sweep::Exhaustive,
		);
	}
}
