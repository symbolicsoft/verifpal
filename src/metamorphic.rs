/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::info::InfoQuiet;
use crate::types::*;

const SESSIONS: u8 = 1;

const VARIANT_CAP: usize = 4;

const BASELINE_BUDGET_MS: u128 = 60;

const DEFERRED_CEILING: usize = 40;

const KNOWN_MISSED_ATTACKS: [(&str, &str, &str); 1] = [(
	"exa.vp",
	"unguard",
	"unguarding msg2 makes P3's clear = AEAD_DEC(k2, $msg2, c) irreducible in \
	 symbolic::build, so the goal that produces msg1=c is never generated and the \
	 decryption-oracle attack is lost. The winning substitution never touches msg2, \
	 so the attack is still available; the search stops being able to reason its \
	 way to it once the slot becomes a variable.",
)];

const KNOWN_BAD_TRACES: [(&str, &str, &str); 5] = [
	(
		"passive_dh_chain.vp",
		"promote",
		"confidentiality? secret_c reports an attack whose trace never produces \
		 PUBKEY(nil), the value it claims the attacker learned. The sibling secret_b \
		 trace narrates that construction and this one drops it.",
	),
	(
		"dh_x3dh_signed_prekey.vp",
		"unguard",
		"equivalence? master_a, master_b prints a Resolves step naming a resolution \
		 the state does not hold.",
	),
	(
		"phase_forward_secrecy.vp",
		"unguard",
		"equivalence? secret_msg, decrypted prints a Resolves step naming a \
		 resolution the state does not hold.",
	),
	(
		"session_dh_no_cross_feed.vp",
		"unguard",
		"equivalence? m, d is a genuine man-in-the-middle on unauthenticated DH and \
		 the verdict is right, but the trace says `d resolves to ga` while naming ga \
		 as a slot the attacker overwrote two steps later. NameTable excludes the \
		 slots a Mutations step touches and does not exclude them from Resolves \
		 steps, so a queried value gets named after an attacker-substituted slot.",
	),
	(
		"session_dh_static_cross.vp",
		"unguard",
		"equivalence? m, d, same NameTable scoping fault as \
		 session_dh_no_cross_feed.vp.",
	),
];

enum Outcome {
	Code(String),
	Rejected,
	Panicked,
}

fn analysed(model: &Model, sessions: u8) -> Outcome {
	let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
		let _quiet = InfoQuiet::new();
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

#[derive(Default)]
struct Report {
	compared: usize,
	violations: Vec<String>,
	panicked: Vec<String>,
	deferred: Vec<String>,
}

fn excused<'a>(table: &'a [(&'a str, &'a str, &'a str)], property: &str) -> Vec<&'a str> {
	table
		.iter()
		.filter(|(_, p, _)| *p == property)
		.map(|(m, _, _)| *m)
		.collect()
}

fn settle(property: &str, report: Report, floor: usize) {
	assert!(
		report.deferred.len() <= DEFERRED_CEILING,
		"the `{property}` property deferred {} models for exceeding the \
		 {BASELINE_BUDGET_MS}ms baseline budget, against a ceiling of {DEFERRED_CEILING}. \
		 A sweep that quietly stops covering models reads as full coverage: {:?}",
		report.deferred.len(),
		report.deferred
	);
	assert!(
		report.compared >= floor,
		"the `{property}` property compared only {} pairs against a floor of {floor}, so it \
		 is passing vacuously rather than holding",
		report.compared
	);

	let expected_panics = excused(&KNOWN_BAD_TRACES, property);
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
		let started = std::time::Instant::now();
		let Outcome::Code(before) = code_of(&model, SESSIONS) else {
			continue;
		};
		if started.elapsed().as_millis() > BASELINE_BUDGET_MS {
			report.deferred.push(name.clone());
			continue;
		}
		for variant in variants(&model).into_iter().take(VARIANT_CAP) {
			match code_of(&variant, SESSIONS) {
				Outcome::Rejected => continue,
				Outcome::Panicked => report.panicked.push(name.clone()),
				Outcome::Code(after) => {
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
	}
	report.panicked.sort();
	report.panicked.dedup();
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
