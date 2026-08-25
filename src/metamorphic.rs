/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::info::InfoQuiet;
use crate::types::*;

const SESSIONS: u8 = 1;

const VARIANT_CAP: usize = 4;

const ANALYSIS_BUDGET: std::time::Duration = std::time::Duration::from_millis(200);

const DEFERRED_CEILING: usize = 60;

const KNOWN_MISSED_ATTACKS: [(&str, &str, &str); 1] = [(
	"exa.vp",
	"unguard",
	"unguarding msg2 makes P3's clear = AEAD_DEC(k2, $msg2, c) irreducible in \
	 symbolic::build, so the goal that produces msg1=c is never generated and the \
	 decryption-oracle attack is lost. The winning substitution never touches msg2, \
	 so the attack is still available; the search stops being able to reason its \
	 way to it once the slot becomes a variable.",
)];

const KNOWN_BAD_TRACES: [(&str, &str); 28] = [
	("passive_dh_chain.vp", "promote"),
	("dh_x3dh_signed_prekey.vp", "unguard"),
	("phase_forward_secrecy.vp", "unguard"),
	("session_dh_no_cross_feed.vp", "unguard"),
	("session_dh_static_cross.vp", "unguard"),
	("equivalence_halt_at_slot.vp", "leaks"),
	("noise_xx_mutual.vp", "leaks"),
	("phase_forward_secrecy.vp", "leaks"),
	("session_ad_binding.vp", "leaks"),
	("session_dh_no_cross_feed.vp", "leaks"),
	("session_dh_static_cross.vp", "leaks"),
	("session_hkdf_cross_feed.vp", "leaks"),
	("session_mac_key_rotation.vp", "leaks"),
	("session_psk_cross_feed.vp", "leaks"),
	("station_to_station.vp", "leaks"),
	("test2.vp", "leaks"),
	("test4.vp", "leaks"),
	("junglegym_hybrid_pq.vp", "weaken"),
	("noise_xx_mutual.vp", "weaken"),
	("phase_forward_secrecy.vp", "weaken"),
	("session_dh_no_cross_feed.vp", "weaken"),
	("session_dh_static_cross.vp", "weaken"),
	("station_to_station.vp", "weaken"),
	("subkey.vp", "weaken"),
	("subkey_hash.vp", "weaken"),
	("subkey_hkdf.vp", "weaken"),
	("test2.vp", "weaken"),
	("test4.vp", "weaken"),
];

enum Outcome {
	Code(String),
	Rejected,
	Cancelled,
	Panicked,
}

fn analysed(model: &Model, sessions: u8) -> Outcome {
	use std::sync::Arc;
	use std::sync::atomic::{AtomicBool, Ordering};

	let cancel = Arc::new(AtomicBool::new(false));
	let finished = Arc::new(AtomicBool::new(false));
	let watch_cancel = Arc::clone(&cancel);
	let watch_finished = Arc::clone(&finished);
	let watchdog = std::thread::spawn(move || {
		let deadline = std::time::Instant::now() + ANALYSIS_BUDGET;
		while std::time::Instant::now() < deadline {
			if watch_finished.load(Ordering::Relaxed) {
				return;
			}
			std::thread::sleep(std::time::Duration::from_millis(2));
		}
		watch_cancel.store(true, Ordering::SeqCst);
	});

	let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
		let _quiet = InfoQuiet::new();
		crate::verify::analyze_sessions_cancellable(model, sessions, Arc::clone(&cancel))
			.ok()
			.map(|ctx| VerifyResult::results_code(&ctx.results_get()))
	}));
	finished.store(true, Ordering::SeqCst);
	let _ = watchdog.join();

	match attempt {
		Ok(Some(code)) => Outcome::Code(code),
		Ok(None) if cancel.load(Ordering::SeqCst) => Outcome::Cancelled,
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

fn lost_attacks(before: &str, after: &str) -> Vec<usize> {
	if before.len() != after.len() {
		return Vec::new();
	}
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

fn annotate_first(value: &Value, cap: Capability) -> Option<Value> {
	let Value::Primitive(p) = value else {
		return None;
	};
	if crate::capability::supports(p.id, cap) && !p.capabilities.has(cap) {
		let mut updated = (**p).clone();
		updated.capabilities.set(cap, 0);
		return Some(Value::Primitive(std::sync::Arc::new(updated)));
	}
	for (i, argument) in p.arguments.iter().enumerate() {
		if let Some(replaced) = annotate_first(argument, cap) {
			let mut updated = (**p).clone();
			updated.arguments[i] = replaced;
			return Some(Value::Primitive(std::sync::Arc::new(updated)));
		}
	}
	None
}

fn variants_weakened(model: &Model) -> Vec<Model> {
	let mut out = Vec::new();
	for cap in [Capability::Weak, Capability::Forgeable] {
		for (bi, block) in model.blocks.iter().enumerate() {
			let Block::Principal(principal) = block else {
				continue;
			};
			for (ei, expression) in principal.expressions.iter().enumerate() {
				let Some(assigned) = expression.assigned.as_ref() else {
					continue;
				};
				let Some(annotated) = annotate_first(assigned, cap) else {
					continue;
				};
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
	out
}

#[derive(Default)]
struct Report {
	compared: usize,
	violations: Vec<String>,
	panicked: Vec<String>,
	deferred: Vec<String>,
	exercised: Vec<String>,
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
	if name == "nil" || name.starts_with("unnamed") || name.starts_with("attacker") {
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

fn check_invariant(
	property: &str,
	variant: fn(&Model) -> Option<Model>,
	expected: fn(&str) -> String,
	floor: usize,
) {
	let mut report = Report::default();
	for (name, model) in corpus() {
		let Outcome::Code(before) = code_of(&model, SESSIONS) else {
			report.deferred.push(name.clone());
			continue;
		};
		let Some(transformed) = variant(&model) else {
			continue;
		};
		match code_of(&transformed, SESSIONS) {
			Outcome::Rejected => continue,
			Outcome::Cancelled => report.deferred.push(name.clone()),
			Outcome::Panicked => {
				report.exercised.push(name.clone());
				report.panicked.push(name.clone());
			}
			Outcome::Code(after) => {
				report.exercised.push(name.clone());
				report.compared += 1;
				let want = expected(&before);
				if after != want {
					report.violations.push(format!(
						"{name}: original={before} variant={after} expected={want}"
					));
				}
			}
		}
	}
	report.panicked.sort();
	report.panicked.dedup();
	report.deferred.sort();
	report.deferred.dedup();
	settle(property, report, floor);
}

fn settle(property: &str, report: Report, floor: usize) {
	assert!(
		report.deferred.len() <= DEFERRED_CEILING,
		"the `{property}` property deferred {} models whose analysis outran the budget, \
		 against a ceiling of {DEFERRED_CEILING}. A sweep that quietly stops covering \
		 models reads as full coverage: {:?}",
		report.deferred.len(),
		report.deferred
	);
	assert!(
		report.compared >= floor,
		"the `{property}` property compared only {} pairs against a floor of {floor}, so it \
		 is passing vacuously rather than holding",
		report.compared
	);

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
		.filter(|m| report.exercised.iter().any(|e| e == *m))
		.filter(|m| !report.panicked.iter().any(|p| p == *m))
		.copied()
		.collect();
	assert!(
		stale_panics.is_empty(),
		"KNOWN_BAD_TRACES lists {stale_panics:?} under `{property}`, but nothing fires there \
		 now. If this was fixed, delete the entry; a stale exception makes the list stop \
		 meaning anything"
	);

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
		.filter(|m| report.exercised.iter().any(|e| e == *m))
		.filter(|m| !report.violations.iter().any(|v| v.starts_with(*m)))
		.copied()
		.collect();
	assert!(
		stale.is_empty(),
		"KNOWN_MISSED_ATTACKS lists {stale:?} under `{property}`, but the property now holds \
		 for it. If this was fixed, delete the entry"
	);
}

fn check_monotone(
	property: &str,
	variants: fn(&Model) -> Vec<Model>,
	strength: Strength,
	floor: usize,
) {
	let mut report = Report::default();
	for (name, model) in corpus() {
		let Outcome::Code(before) = code_of(&model, SESSIONS) else {
			report.deferred.push(name.clone());
			continue;
		};
		let mut exercised = false;
		for variant in variants(&model).into_iter().take(VARIANT_CAP) {
			match code_of(&variant, SESSIONS) {
				Outcome::Rejected => continue,
				Outcome::Cancelled => report.deferred.push(name.clone()),
				Outcome::Panicked => {
					exercised = true;
					report.panicked.push(name.clone());
				}
				Outcome::Code(after) => {
					exercised = true;
					report.compared += 1;
					let lost = match strength {
						Strength::Stronger => lost_attacks(&before, &after),
						Strength::Weaker => lost_attacks(&after, &before),
					};
					for q in lost {
						report.violations.push(format!(
							"{name}: before={before} after={after}, query {q} lost"
						));
					}
				}
			}
		}
		if exercised {
			report.exercised.push(name.clone());
		}
	}
	report.panicked.sort();
	report.panicked.dedup();
	report.deferred.sort();
	report.deferred.dedup();
	settle(property, report, floor);
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn lost_attacks_finds_only_ones_that_became_zeros() {
		assert_eq!(lost_attacks("c1a0", "c0a0"), vec![0]);
		assert_eq!(lost_attacks("c1a0", "c1a1"), Vec::<usize>::new());
		assert_eq!(lost_attacks("c1", "c1a0"), Vec::<usize>::new());
	}

	#[test]
	fn rendering_and_reparsing_a_model_preserves_every_verdict() {
		let mut drifted = Vec::new();
		let mut compared = 0usize;
		for (name, model) in corpus() {
			let Outcome::Code(direct) = analysed(&model, SESSIONS) else {
				continue;
			};
			compared += 1;
			match code_of(&model, SESSIONS) {
				Outcome::Cancelled => continue,
				Outcome::Code(round_tripped) if round_tripped == direct => {}
				Outcome::Code(other) => {
					drifted.push(format!("{name}: direct={direct} round-tripped={other}"))
				}
				Outcome::Rejected => drifted.push(format!(
					"{name}: direct={direct} but the render did not parse"
				)),
				Outcome::Panicked => {
					drifted.push(format!("{name}: direct={direct} but the render panicked"))
				}
			}
		}
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
	fn an_unused_declaration_changes_no_verdict() {
		check_invariant("pad", variant_padded, |before| before.to_string(), 300);
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
		check_invariant("rename", variant_renamed, |before| before.to_string(), 300);
	}

	#[test]
	fn rotate_code_moves_whole_queries() {
		assert_eq!(rotate_code("c1a0f1", 1), "a0f1c1");
		assert_eq!(rotate_code("c1a0f1", 3), "c1a0f1");
		assert_eq!(rotate_code("c1", 1), "c1");
	}

	#[test]
	fn reordering_the_queries_block_changes_no_verdict() {
		check_invariant(
			"rotate",
			variant_query_rotation,
			|before| rotate_code(before, 1),
			150,
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
	fn leaking_a_secret_never_loses_an_attack() {
		check_monotone("leaks", variants_leaked, Strength::Stronger, 250);
	}

	#[test]
	fn weakening_a_primitive_never_loses_an_attack() {
		check_monotone("weaken", variants_weakened, Strength::Stronger, 250);
	}

	#[test]
	fn removing_a_guard_never_loses_an_attack() {
		check_monotone("unguard", variants_unguarded, Strength::Stronger, 250);
	}

	#[test]
	fn promoting_a_passive_model_to_active_never_loses_an_attack() {
		check_monotone("promote", variants_promoted, Strength::Stronger, 90);
	}

	#[test]
	fn a_passive_run_never_finds_an_attack_the_active_run_misses() {
		check_monotone("demote", variants_demoted, Strength::Weaker, 200);
	}
}
