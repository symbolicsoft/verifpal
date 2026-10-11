/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::console::InfoQuiet;
use crate::primitive::Capability;
use crate::syntax::{
	AttackerKind, Block, Declaration, Expression, LineComments, Message, Model, Principal,
	PrincipalId, Qualifier, QueryKind, QueryOption, QueryOptionKind, Scenario, Span,
};
use crate::term::{Constant, Value, ValueId};
use crate::verify::VerifyResult;

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
	let rendered = crate::syntax::pretty::pretty_model(model);
	match crate::syntax::parser::parse_string(&model.file_name, &rendered) {
		Ok(reparsed) => analysed(&reparsed, sessions),
		Err(_) => Outcome::Rejected,
	}
}

fn external_corpus() -> Option<std::path::PathBuf> {
	std::env::var_os("VERIFPAL_METAMORPHIC_CORPUS").map(std::path::PathBuf::from)
}

fn corpus() -> Vec<(String, Model)> {
	let models = match external_corpus() {
		Some(dir) => {
			let mut found: Vec<(String, String)> = std::fs::read_dir(&dir)
				.expect("read VERIFPAL_METAMORPHIC_CORPUS")
				.flatten()
				.map(|e| e.path())
				.filter(|p| p.extension().is_some_and(|x| x == "vp"))
				.map(|p| {
					(
						p.file_name()
							.unwrap_or_default()
							.to_string_lossy()
							.into_owned(),
						p.to_string_lossy().into_owned(),
					)
				})
				.collect();
			found.sort();
			found
		}
		None => crate::testing::model_tests::swept_models(),
	};
	models
		.into_iter()
		.filter_map(|(name, path)| {
			let source = std::fs::read_to_string(&path).ok()?;
			let model = crate::syntax::parser::parse_string(&name, &source).ok()?;
			Some((name, model))
		})
		.collect()
}

fn asks_the_same_question(model: &Model, variant: &Model) -> bool {
	let before = crate::protocol::scenario::honesty_profile(model);
	let after = crate::protocol::scenario::honesty_profile(variant);
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
	StrongerOn(&'static [u8]),
	WeakerOn(&'static [u8]),
	Invariant(fn(&str) -> String),
}

const DISCLOSURE_QUERIES: &[u8] = b"cf";

const ORDINARY_QUERIES: &[u8] = b"caf";

fn lost_on(before: &str, after: &str, kinds: &[u8]) -> Vec<usize> {
	lost_attacks(before, after)
		.into_iter()
		.filter(|&q| kinds.contains(&before.as_bytes()[2 * q]))
		.collect()
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
	if crate::primitive::capability::supports(p.id, cap)
		&& p.capabilities.onset(cap).is_none_or(|phase| phase > 0)
	{
		let updated = p.with(|application| application.capabilities.set(cap, 0));
		out.push(Value::Primitive(Arc::new(updated)));
	}
	for (i, argument) in p.arguments.iter().enumerate() {
		for replaced in annotations(argument, cap) {
			let updated = p.with(|application| application.arguments[i] = replaced);
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

fn checked(value: &Value, check: bool) -> Option<Value> {
	let Value::Primitive(p) = value else {
		return None;
	};
	if p.instance_check == check
		|| (check && !crate::primitive::definition(p.id).is_ok_and(|d| d.definition_check()))
	{
		return None;
	}
	let updated = p.with(|application| application.instance_check = check);
	Some(Value::Primitive(Arc::new(updated)))
}

fn variants_checked(model: &Model, check: bool) -> Vec<Model> {
	let mut out = Vec::new();
	for (bi, block) in model.blocks.iter().enumerate() {
		let Block::Principal(principal) = block else {
			continue;
		};
		for (ei, expression) in principal.expressions.iter().enumerate() {
			let Some(changed) = expression
				.assigned
				.as_ref()
				.and_then(|assigned| checked(assigned, check))
			else {
				continue;
			};
			let mut variant = model.clone();
			if let Some(Block::Principal(p)) = variant.blocks.get_mut(bi)
				&& let Some(e) = p.expressions.get_mut(ei)
			{
				e.assigned = Some(changed);
				out.push(variant);
			}
		}
	}
	out
}

fn redeclared(
	principal: &Principal,
	target: ValueId,
	from: impl Fn(&Expression) -> bool,
	kind: Declaration,
	qualifier: Qualifier,
) -> Option<Principal> {
	let mut changed = false;
	let mut expressions = Vec::new();
	for e in &principal.expressions {
		let Some(at) = e
			.constants
			.iter()
			.position(|c| c.id == target)
			.filter(|_| from(e))
		else {
			expressions.push(e.clone());
			continue;
		};
		changed = true;
		let mut rest = e.clone();
		let constant = rest.constants.remove(at);
		if !rest.constants.is_empty() {
			expressions.push(rest);
		}
		expressions.push(Expression {
			span: Span::default(),
			kind,
			qualifier: Some(qualifier),
			constants: vec![constant],
			assigned: None,
			comments: LineComments::default(),
		});
	}
	changed.then(|| Principal {
		expressions,
		..principal.clone()
	})
}

fn variants_redeclared(
	model: &Model,
	from: fn(&Expression) -> bool,
	kind: Declaration,
	qualifier: Qualifier,
) -> Vec<Model> {
	let mut targets: Vec<ValueId> = Vec::new();
	for block in &model.blocks {
		let Block::Principal(principal) = block else {
			continue;
		};
		for e in principal.expressions.iter().filter(|e| from(e)) {
			for c in &e.constants {
				if !targets.contains(&c.id) {
					targets.push(c.id);
				}
			}
		}
	}
	targets
		.into_iter()
		.filter_map(|target| {
			let mut variant = model.clone();
			let mut changed = false;
			for block in &mut variant.blocks {
				if let Block::Principal(principal) = block
					&& let Some(updated) = redeclared(principal, target, from, kind, qualifier)
				{
					*principal = updated;
					changed = true;
				}
			}
			changed.then_some(variant)
		})
		.collect()
}

fn variants_ungenerated(model: &Model) -> Vec<Model> {
	variants_redeclared(
		model,
		|e| e.kind == Declaration::Generates,
		Declaration::Knows,
		Qualifier::Private,
	)
}

fn variants_publicized(model: &Model) -> Vec<Model> {
	if !model.scenarios.is_empty() {
		return Vec::new();
	}
	variants_redeclared(
		model,
		|e| e.kind == Declaration::Knows && e.qualifier == Some(Qualifier::Private),
		Declaration::Knows,
		Qualifier::Public,
	)
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
			let Some(rule) = crate::primitive::threshold(p.id) else {
				continue;
			};
			let threshold = p.threshold as i64 + delta;
			if threshold < rule.min as i64 || threshold > expression.constants.len() as i64 {
				continue;
			}
			let changed = p.with(|application| application.threshold = threshold as usize);
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

pub(crate) fn spread<T, R>(items: &[T], work: impl Fn(&T) -> R + Sync) -> Vec<R>
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
	if name == "nil" || crate::syntax::parser::check_reserved(name).is_err() {
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
						.map(|v| crate::protocol::sessions::map_constants(v, &renamed_constant));
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

fn variants_permuted(model: &Model) -> Vec<Model> {
	let mut lists = model.clone();
	let mut lists_changed = false;
	for block in &mut lists.blocks {
		if let Block::Principal(p) = block {
			for e in &mut p.expressions {
				if e.kind != Declaration::Assignment && e.constants.len() > 1 {
					e.constants.reverse();
					lists_changed = true;
				}
			}
		}
	}
	let mut messages = model.clone();
	let mut messages_changed = false;
	for block in &mut messages.blocks {
		if let Block::Message(m) = block
			&& m.constants.len() > 1
		{
			m.constants.reverse();
			messages_changed = true;
		}
	}
	let mut queries = model.clone();
	let mut queries_changed = false;
	for q in &mut queries.queries {
		if matches!(q.kind, QueryKind::Unlinkability | QueryKind::Equivalence)
			&& q.constants.len() > 1
		{
			q.constants.reverse();
			queries_changed = true;
		}
	}
	[
		(lists, lists_changed),
		(messages, messages_changed),
		(queries, queries_changed),
	]
	.into_iter()
	.filter_map(|(variant, changed)| changed.then_some(variant))
	.collect()
}

fn split_leaks(model: &Model) -> Model {
	let mut out = model.clone();
	for block in &mut out.blocks {
		if let Block::Principal(p) = block {
			p.expressions = p
				.expressions
				.iter()
				.flat_map(|e| {
					if e.kind == Declaration::Leaks {
						e.constants
							.iter()
							.map(|c| Expression {
								constants: vec![c.clone()],
								..e.clone()
							})
							.collect()
					} else {
						vec![e.clone()]
					}
				})
				.collect();
		}
	}
	out
}

fn variant_split(model: &Model) -> Option<Model> {
	let mut changed = model.blocks.iter().any(|b| {
		matches!(b, Block::Principal(p) if p
			.expressions
			.iter()
			.any(|e| e.kind == Declaration::Leaks && e.constants.len() > 1))
	});
	let mut blocks = Vec::new();
	for block in split_leaks(model).blocks {
		match block {
			Block::Message(m) if m.constants.len() > 1 => {
				changed = true;
				blocks.extend(m.constants.iter().map(|c| {
					Block::Message(Message {
						constants: vec![c.clone()],
						..m.clone()
					})
				}));
			}
			_ => blocks.push(block),
		}
	}
	changed.then(|| Model {
		blocks,
		..model.clone()
	})
}

fn variant_swapped(model: &Model) -> Option<Model> {
	let mut out = model.clone();
	let mut changed = false;
	let mut at = 0;
	while at + 1 < out.blocks.len() {
		if let (Block::Principal(a), Block::Principal(b)) = (&out.blocks[at], &out.blocks[at + 1])
			&& a.id != b.id
		{
			out.blocks.swap(at, at + 1);
			changed = true;
			at += 2;
		} else {
			at += 1;
		}
	}
	changed.then_some(out)
}

fn variant_delayed(model: &Model) -> Option<Model> {
	let mut blocks = Vec::new();
	let mut pending: Vec<Principal> = Vec::new();
	let mut moved = false;
	for block in &model.blocks {
		match block {
			Block::Phase(_) => {
				blocks.extend(pending.drain(..).map(Block::Principal));
				blocks.push(block.clone());
			}
			Block::Principal(p) => {
				let (leaks, kept): (Vec<Expression>, Vec<Expression>) = p
					.expressions
					.iter()
					.cloned()
					.partition(|e| e.kind == Declaration::Leaks);
				if !leaks.is_empty() {
					moved = true;
					match pending.iter_mut().find(|q| q.id == p.id) {
						Some(q) => q.expressions.extend(leaks),
						None => pending.push(Principal {
							expressions: leaks,
							..p.clone()
						}),
					}
				}
				blocks.push(Block::Principal(Principal {
					expressions: kept,
					..p.clone()
				}));
			}
			Block::Message(_) => blocks.push(block.clone()),
		}
	}
	blocks.extend(pending.drain(..).map(Block::Principal));
	moved.then(|| Model {
		blocks,
		..model.clone()
	})
}

fn variant_hoisted(model: &Model) -> Option<Model> {
	let model = &split_leaks(model);
	let mut known: Vec<(PrincipalId, Vec<ValueId>)> = Vec::new();
	let mut points: Vec<(PrincipalId, usize, usize, Vec<ValueId>)> = Vec::new();
	let mut moves: Vec<((usize, usize), (usize, usize))> = Vec::new();
	fn held(known: &mut Vec<(PrincipalId, Vec<ValueId>)>, who: PrincipalId) -> &mut Vec<ValueId> {
		let at = match known.iter().position(|(p, _)| *p == who) {
			Some(at) => at,
			None => {
				known.push((who, Vec::new()));
				known.len() - 1
			}
		};
		&mut known[at].1
	}
	for (bi, block) in model.blocks.iter().enumerate() {
		match block {
			Block::Phase(_) => points.clear(),
			Block::Message(m) => {
				held(&mut known, m.recipient).extend(m.constants.iter().map(|c| c.id));
			}
			Block::Principal(p) => {
				for (ei, e) in p.expressions.iter().enumerate() {
					let before = held(&mut known, p.id).clone();
					points.push((p.id, bi, ei, before));
					if e.kind == Declaration::Leaks {
						let target = points
							.iter()
							.find(|(who, _, _, before)| {
								*who == p.id && e.constants.iter().all(|c| before.contains(&c.id))
							})
							.map(|&(_, b, i, _)| (b, i));
						if let Some(target) = target
							&& target != (bi, ei)
						{
							moves.push(((bi, ei), target));
						}
					} else {
						held(&mut known, p.id).extend(e.constants.iter().map(|c| c.id));
					}
				}
				let after = held(&mut known, p.id).clone();
				points.push((p.id, bi, p.expressions.len(), after));
			}
		}
	}
	if moves.is_empty() {
		return None;
	}
	let leak = |(bi, ei): (usize, usize)| match &model.blocks[bi] {
		Block::Principal(p) => p.expressions[ei].clone(),
		_ => unreachable!("a leak sits in a principal block"),
	};
	let mut out = model.clone();
	for (bi, block) in model.blocks.iter().enumerate() {
		let Block::Principal(p) = block else {
			continue;
		};
		let mut expressions = Vec::new();
		for ei in 0..=p.expressions.len() {
			expressions.extend(
				moves
					.iter()
					.filter(|(_, target)| *target == (bi, ei))
					.map(|&(from, _)| leak(from)),
			);
			if ei < p.expressions.len() && !moves.iter().any(|(from, _)| *from == (bi, ei)) {
				expressions.push(p.expressions[ei].clone());
			}
		}
		out.blocks[bi] = Block::Principal(Principal {
			expressions,
			..p.clone()
		});
	}
	Some(out)
}

fn under(
	model: &Model,
	attacker: AttackerKind,
	variant: fn(&Model) -> Option<Model>,
) -> Option<Model> {
	(model.attacker == attacker)
		.then(|| variant(model))
		.flatten()
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
	let models = corpus();
	let originals = spread(&models, |(name, model)| {
		if sweep.skips(name) {
			return None;
		}
		let Outcome::Code(before) = code_of(model, SESSIONS) else {
			return None;
		};
		(!matches!(change, Change::Stronger | Change::StrongerOn(_)) || before.contains('1'))
			.then_some(before)
	});
	let mut jobs: Vec<(usize, Model)> = Vec::new();
	for (at, ((_, model), before)) in models.iter().zip(&originals).enumerate() {
		if before.is_none() {
			continue;
		}
		jobs.extend(
			variants(model)
				.into_iter()
				.filter(|variant| asks_the_same_question(model, variant))
				.map(|variant| (at, variant)),
		);
	}
	let mut outcomes = spread(&jobs, |(_, variant)| code_of(variant, SESSIONS)).into_iter();
	let mut report = Report::default();
	let mut next = 0;
	for (at, ((name, _), before)) in models.iter().zip(&originals).enumerate() {
		let mine: Vec<Outcome> = std::iter::from_fn(|| {
			(next < jobs.len() && jobs[next].0 == at).then(|| {
				next += 1;
				outcomes.next().expect("one outcome per variant")
			})
		})
		.collect();
		let Some(before) = before else {
			continue;
		};
		report.tally(name, mine, |after| {
			let lost = match change {
				Change::Stronger => lost_attacks(before, after),
				Change::Weaker => lost_attacks(after, before),
				Change::StrongerOn(kinds) => lost_on(before, after, kinds),
				Change::WeakerOn(kinds) => lost_on(after, before, kinds),
				Change::Invariant(expected) => {
					let want = expected(before);
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
		report.compared >= floor || external_corpus().is_some(),
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
			if crate::syntax::pretty::pretty_model(&variant_renamed(&model))
				!= crate::syntax::pretty::pretty_model(&model)
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
				let rendered = crate::syntax::pretty::pretty_model(&variant);
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
	fn reordering_a_list_changes_no_verdict() {
		check_variants(
			"permute",
			variants_permuted,
			Change::Invariant(str::to_string),
			1100,
			Sweep::Fast,
		);
	}

	#[test]
	fn splitting_a_passive_message_or_leak_changes_no_verdict() {
		check_variants(
			"split_passive",
			|model| under(model, AttackerKind::Passive, variant_split),
			Change::Invariant(str::to_string),
			120,
			Sweep::Fast,
		);
	}

	#[test]
	fn splitting_an_active_message_or_leak_never_loses_an_attack() {
		check_variants(
			"split_active",
			|model| under(model, AttackerKind::Active, variant_split),
			Change::Stronger,
			280,
			Sweep::Fast,
		);
	}

	#[test]
	fn swapping_adjacent_principal_blocks_changes_no_verdict() {
		check_variants(
			"swap",
			variant_swapped,
			Change::Invariant(str::to_string),
			340,
			Sweep::Fast,
		);
	}

	#[test]
	fn delaying_a_passive_leak_within_its_phase_changes_no_verdict() {
		check_variants(
			"delay_passive",
			|model| under(model, AttackerKind::Passive, variant_delayed),
			Change::Invariant(str::to_string),
			90,
			Sweep::Fast,
		);
	}

	#[test]
	fn delaying_an_active_leak_within_its_phase_never_adds_an_attack() {
		check_variants(
			"delay_active",
			|model| under(model, AttackerKind::Active, variant_delayed),
			Change::Weaker,
			180,
			Sweep::Fast,
		);
	}

	#[test]
	fn hoisting_a_passive_leak_within_its_phase_changes_no_verdict() {
		check_variants(
			"hoist_passive",
			|model| under(model, AttackerKind::Passive, variant_hoisted),
			Change::Invariant(str::to_string),
			65,
			Sweep::Fast,
		);
	}

	#[test]
	fn hoisting_an_active_leak_within_its_phase_never_loses_an_attack() {
		check_variants(
			"hoist_active",
			|model| under(model, AttackerKind::Active, variant_hoisted),
			Change::Stronger,
			65,
			Sweep::Fast,
		);
	}

	#[test]
	fn removing_a_check_never_loses_an_attack() {
		check_variants(
			"uncheck",
			|model| variants_checked(model, false),
			Change::StrongerOn(DISCLOSURE_QUERIES),
			680,
			Sweep::Fast,
		);
	}

	#[test]
	fn adding_a_check_never_adds_an_attack() {
		check_variants(
			"check",
			|model| variants_checked(model, true),
			Change::WeakerOn(DISCLOSURE_QUERIES),
			120,
			Sweep::Fast,
		);
	}

	#[test]
	fn a_generated_value_made_long_term_never_loses_an_attack() {
		check_variants(
			"ungenerate",
			variants_ungenerated,
			Change::StrongerOn(DISCLOSURE_QUERIES),
			1250,
			Sweep::Fast,
		);
	}

	#[test]
	fn a_private_value_made_public_never_loses_an_attack() {
		check_variants(
			"publicize",
			variants_publicized,
			Change::StrongerOn(ORDINARY_QUERIES),
			860,
			Sweep::Fast,
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
