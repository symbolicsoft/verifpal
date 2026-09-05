/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

const TRACE_USES_A_GUARD_BYPASS: [(&str, usize); 4] = [
	("history_closure_incompatible.vp", 4),
	("junglegym_hybrid_pq.vp", 4),
	("noise_xx_mutual.vp", 1),
	("noise_xx_mutual.vp", 2),
];

const TRACE_IS_NOT_A_MINIMIZED_WITNESS: [(&str, usize); 1] = [("closure_two_recipients.vp", 0)];

const TRACE_IS_NOT_CAUSALLY_ORDERED: [(&str, usize); 0] = [];

const TRACE_FEEDS_BACK_A_LATER_VALUE: [(&str, usize); 0] = [];

const ATTACK_IS_REPORTED_WITHOUT_A_TRACE: [(&str, usize); 0] = [];

const SWEPT_MODELS_OUTSIDE_EXAMPLES_TEST: [&str; 6] = [
	"examples/transport-layer/tls13-0rtt.vp",
	"examples/transport-layer/piknik.vp",
	"examples/transport-layer/needham-schroeder.vp",
	"examples/contact-tracing/lc-dp-3t.vp",
	"examples/messaging/pqxdh-weak.vp",
	"examples/silly/cloudbackup.vp",
];

pub(crate) fn swept_models() -> Vec<(String, String)> {
	let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/test");
	let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
		.expect("read examples/test")
		.flatten()
		.map(|e| e.path())
		.filter(|p| p.extension().is_some_and(|x| x == "vp"))
		.map(|p| {
			(
				p.file_name()
					.unwrap_or_default()
					.to_string_lossy()
					.into_owned(),
				format!(
					"examples/test/{}",
					p.file_name().unwrap_or_default().to_string_lossy()
				),
			)
		})
		.collect();
	for path in SWEPT_MODELS_OUTSIDE_EXAMPLES_TEST {
		let name = path.rsplit('/').next().unwrap_or(path).to_string();
		out.push((name, path.to_string()));
	}
	out.sort();
	out
}

fn message_legs(source: &str) -> Vec<(String, String, String, bool)> {
	let mut stripped = String::new();
	let mut chars = source.chars().peekable();
	let mut in_block = false;
	while let Some(c) = chars.next() {
		if in_block {
			if c == '*' && chars.peek() == Some(&'/') {
				chars.next();
				in_block = false;
			}
			continue;
		}
		if c == '/' && chars.peek() == Some(&'*') {
			chars.next();
			in_block = true;
			continue;
		}
		if c == '/' && chars.peek() == Some(&'/') {
			for n in chars.by_ref() {
				if n == '\n' {
					stripped.push('\n');
					break;
				}
			}
			continue;
		}
		stripped.push(c);
	}
	let mut legs = Vec::new();
	for line in stripped.lines() {
		let line = line.trim();
		let arrow = if let Some(i) = line.find("->") {
			(i, 2)
		} else if let Some(i) = line.find('\u{2192}') {
			(i, '\u{2192}'.len_utf8())
		} else {
			continue;
		};
		let sender = line[..arrow.0].trim();
		let rest = &line[arrow.0 + arrow.1..];
		let Some(colon) = rest.find(':') else {
			continue;
		};
		let recipient = rest[..colon].trim();
		if sender.is_empty() || recipient.is_empty() || sender.contains(char::is_whitespace) {
			continue;
		}
		if recipient.contains(char::is_whitespace) || recipient.contains('[') {
			continue;
		}
		for item in rest[colon + 1..].split(',') {
			let item = item.trim();
			if item.is_empty() {
				continue;
			}
			let guarded = item.starts_with('[');
			let name = item.trim_matches(|c| c == '[' || c == ']').trim();
			legs.push((
				sender.to_lowercase(),
				recipient.to_lowercase(),
				name.to_lowercase(),
				guarded,
			));
		}
	}
	legs
}

fn stated_result_codes(source: &str) -> Vec<String> {
	let Some(line) = source
		.lines()
		.map(|l| l.trim())
		.find(|l| l.starts_with("// Expected:"))
	else {
		return Vec::new();
	};
	let mut out = Vec::new();
	for token in line.split(|c: char| !c.is_ascii_alphanumeric()) {
		let bytes = token.as_bytes();
		if bytes.len() < 2 || !bytes.len().is_multiple_of(2) {
			continue;
		}
		if bytes.chunks(2).all(|pair| {
			matches!(pair[0], b'c' | b'a' | b'f' | b'u' | b'e') && matches!(pair[1], b'0' | b'1')
		}) {
			out.push(token.to_string());
		}
	}
	out.sort();
	out.dedup();
	out
}

fn expansion_base(name: &str) -> String {
	name.split(['#', '@'])
		.next()
		.unwrap_or(name)
		.trim()
		.to_lowercase()
}

#[test]
fn attack_traces_keep_their_shape_and_name_only_wires_that_exist() {
	let mut bypass: Vec<(String, usize)> = Vec::new();
	let mut unminimized: Vec<(String, usize)> = Vec::new();
	let mut harvested: Vec<(String, usize)> = Vec::new();
	let mut unordered: Vec<(String, usize)> = Vec::new();
	let mut traceless: Vec<(String, usize)> = Vec::new();
	let mut incoherent: Vec<String> = Vec::new();
	let mut header_problems: Vec<String> = Vec::new();
	let mut documented = 0usize;
	let mut undocumented = 0usize;

	for (model, path) in swept_models() {
		let _ = crate::verify::verify_with_sessions(&path, 1);
		let Ok((results, _)) = crate::verify::verify(&path) else {
			continue;
		};
		let source = std::fs::read_to_string(&path).expect("read model");
		let legs = message_legs(&source);
		let stated = stated_result_codes(&source);
		if stated.is_empty() {
			undocumented += 1;
		} else {
			documented += 1;
			let code = crate::types::VerifyResult::results_code(&results);
			let mut produced = vec![code.clone()];
			if source.contains("session")
				&& let Ok((one, _)) = crate::verify::verify_with_sessions(&path, 1)
			{
				produced.push(crate::types::VerifyResult::results_code(&one));
			}
			if !stated.contains(&code) {
				header_problems.push(format!(
					"{}: the header says the model produces {}, but at the shipped default it \
					 produces {}",
					model,
					stated.join(" / "),
					code
				));
			}
			for claim in &stated {
				if !produced.contains(claim) {
					header_problems.push(format!(
						"{}: the header claims a result of {}, which the model does not produce \
						 at one session or at two (it produces {})",
						model,
						claim,
						produced.join(" / ")
					));
				}
			}
		}
		for result in results.iter().filter(|r| r.resolved) {
			let summary = result.summary.as_str();
			let key = (model.clone(), result.query_index);
			if !summary.contains("Attack trace:") {
				traceless.push(key.clone());
			}
			if summary.contains("does not halt at") {
				bypass.push(key.clone());
			}
			if summary.contains("not a minimized witness") {
				unminimized.push(key.clone());
			}
			if summary.contains("itself only computes later in the same run") {
				harvested.push(key.clone());
			}
			if summary.contains("not a causally ordered execution") {
				unordered.push(key.clone());
			}
			for line in summary.lines() {
				let line = line.trim();
				let replaced = line
					.split_once("Attacker replaces ")
					.and_then(|(_, rest)| rest.split_once(" (sent by "))
					.and_then(|(names, tail)| {
						tail.split_once(") with ").map(|(route, _)| (names, route))
					});
				let replayed = line
					.split_once("Attacker replays ")
					.and_then(|(_, rest)| rest.split_once(" ("))
					.and_then(|(names, tail)| {
						tail.split_once(") ").map(|(route, _)| (names, route))
					});
				let Some((names, route)) = replaced.or(replayed) else {
					continue;
				};
				let Some((_, recipient)) = route.split_once(" to ") else {
					continue;
				};
				let recipient = expansion_base(recipient);
				for name in names.split(',') {
					let name = expansion_base(name);
					let to_recipient: Vec<&(String, String, String, bool)> = legs
						.iter()
						.filter(|(_, r, n, _)| *r == recipient && *n == name)
						.collect();
					if to_recipient.is_empty() {
						incoherent.push(format!(
							"{} query {}: trace says the attacker replaces `{}` on a message to \
							 {}, but no message in the model carries `{}` to {}",
							model, result.query_index, name, recipient, name, recipient
						));
						continue;
					}
					if to_recipient.iter().all(|(_, _, _, g)| *g)
						&& !line.contains("upstream of the guard")
						&& !legs.iter().any(|(_, _, n, g)| *n == name && !*g)
					{
						incoherent.push(format!(
							"{} query {}: trace says the attacker replaces `{}` on a message to \
							 {}, but every message carrying `{}` guards it and the step claims no \
							 guard bypass",
							model, result.query_index, name, recipient, name
						));
					}
				}
			}
		}
	}

	let pinned = |rows: &[(&str, usize)]| -> Vec<(String, usize)> {
		let mut v: Vec<(String, usize)> =
			rows.iter().map(|(m, i)| ((*m).to_string(), *i)).collect();
		v.sort();
		v
	};
	let sorted = |mut v: Vec<(String, usize)>| -> Vec<(String, usize)> {
		v.sort();
		v.dedup();
		v
	};

	eprintln!(
		"{} swept models analysed: {} state a result code, {} do not",
		documented + undocumented,
		documented,
		undocumented
	);
	assert!(
		header_problems.is_empty(),
		"a model's header states a result the model does not produce. The header is where the \
		 reason for a verdict is argued, so a header that disagrees with the run is either a \
		 stale claim or a verdict nobody has re-justified:\n  {}",
		header_problems.join("\n  ")
	);
	assert!(
		undocumented <= 126,
		"{} swept models state no expected result code in their header, up from 126. A new \
		 model must say what it expects and why, so that its verdict can be checked against \
		 an intent rather than against itself",
		undocumented
	);
	assert!(
		incoherent.is_empty(),
		"an attack trace names a wire substitution the model cannot support:\n  {}",
		incoherent.join("\n  ")
	);
	assert_eq!(
		sorted(bypass),
		pinned(&TRACE_USES_A_GUARD_BYPASS),
		"the set of traces that explain themselves with a defeated check has moved. A new \
		 entry means some attack is now narrated as `the attacker sent nil and the check was \
		 defeated` where a witness that forges a value the recipient accepts on its own would \
		 explain it; a missing entry means one of those narrations improved and the pin should \
		 be updated"
	);
	assert_eq!(
		sorted(unminimized),
		pinned(&TRACE_IS_NOT_A_MINIMIZED_WITNESS),
		"the set of attacks whose witness could not be minimized has moved. These traces list \
		 the substitutions the search recorded without confirming any subset reproduces the \
		 violation, so a new entry is a trace that got less trustworthy"
	);
	assert_eq!(
		sorted(unordered),
		pinned(&TRACE_IS_NOT_CAUSALLY_ORDERED),
		"the set of attacks whose witness is not a causally ordered execution has moved. Every \
		 install in a witness should be derivable from what the attacker holds before it is \
		 made, so a new entry is a certificate whose steps cannot be read in the order they \
		 are printed"
	);
	assert_eq!(
		sorted(harvested),
		pinned(&TRACE_FEEDS_BACK_A_LATER_VALUE),
		"the set of attacks whose witness feeds a principal a value that principal only \
		 computes later in the same run has moved. Such a witness rests on the atemporal \
		 within-phase knowledge model rather than on anything the protocol permits"
	);
	assert_eq!(
		sorted(traceless),
		pinned(&ATTACK_IS_REPORTED_WITHOUT_A_TRACE),
		"the set of attacks reported with no trace at all has moved. A freshness or \
		 equivalence violation the honest run already exhibits needs no attacker action, but a \
		 new entry elsewhere is an attack the tool asserts and does not explain"
	);
}

#[test]
fn a_hold_carries_the_envelope_it_was_reached_under() {
	let (results, _) = crate::verify::verify_with_sessions("examples/test/hmac_ok.vp", 2)
		.expect("hmac_ok.vp analyses");
	let hold = results.iter().find(|r| !r.resolved).expect("a hold");
	assert!(hold.envelope.exhausted());
	assert_eq!(hold.envelope.sessions, 2);
	assert_eq!(
		hold.envelope.qualifier(),
		"  [search exhausted at 2 sessions]"
	);
}

#[test]
fn auto_queries_asks_more_than_the_model_wrote() {
	let (written, written_code) =
		crate::verify::verify_with_sessions("examples/test/hmac_ok.vp", 2).expect("analyses");
	let (generated, generated_code) =
		crate::verify::verify_auto_queries("examples/test/hmac_ok.vp", 2).expect("analyses");
	assert_eq!(written_code, "c0a1");
	assert_eq!(generated_code, "c0c0c0a0a0a1a1f1f1f0f0");
	assert!(generated.len() > written.len());
}

#[test]
fn a_model_saturates_when_its_verdict_stops_moving() {
	let (_, code, k, regressed) =
		crate::verify::verify_saturating("examples/test/hmac_ok.vp", 4).expect("analyses");
	assert_eq!(code, "c0a1");
	assert_eq!(k, 3);
	assert!(!regressed);
}

#[test]
fn a_cross_session_attack_saturates_only_after_it_appears() {
	let (_, code, k, regressed) =
		crate::verify::verify_saturating("examples/test/session_replay_breaks_injectivity.vp", 4)
			.expect("analyses");
	assert_eq!(code, "a1");
	assert_eq!(k, 3);
	assert!(!regressed);
}

#[test]
fn test_pitoy_depth() {
	run_model("pitoy_depth.vp", "c1");
	run_model_sessions("pitoy_depth.vp", 1, "c0");
}

#[test]
fn an_oracle_can_be_handed_a_whole_earlier_message_to_open() {
	let (results, code) = crate::verify::verify("examples/test/pitoy_depth.vp").expect("analyses");
	assert_eq!(
		code, "c1",
		"the injected message nests the initiator's whole message two layers deeper \
		 than the protocol builds; the responder strips those layers itself, so a bound \
		 that reads the protocol's depth flat puts the attack out of reach"
	);
	let summary = &results[0].summary;
	assert!(
		summary.contains("m1 on the wire") && summary.contains("obtaining n"),
		"the trace has to show the held message being nested and the nonce coming \
		 out: {summary}"
	);
	let (_, single) =
		crate::verify::verify_with_sessions("examples/test/pitoy_depth.vp", 1).expect("analyses");
	assert_eq!(
		single, "c0",
		"one responder run peels one layer and returns the inner ciphertext under the \
		 attacker's key; a second run is what opens it, as it is for ProVerif"
	);
}

#[test]
fn test_injective_routed_emission_twice() {
	run_model("injective_routed_emission_twice.vp", "a1");
	run_model_sessions("injective_routed_emission_twice.vp", 1, "a0");
}

#[test]
fn a_matching_run_emission_accepted_twice_is_still_a_duplicate() {
	let report =
		crate::verify::verify_report("examples/test/injective_routed_emission_twice.vp", 2)
			.expect("analyses");
	assert!(report.results[0].resolved);
	assert_eq!(
		report.results[0].subtype,
		Some(crate::types::Subtype::DuplicateAcceptance),
		"the matching-run exemption excuses a routed emission as a forgery, and the \
		 duplicate test compares only against honest sibling emissions; whatever routing \
		 lets a second run accept the emission also lets it accept the sibling's honest \
		 one, so the duplicate is still seen and still named as one the recipient could \
		 have told apart"
	);
}

#[test]
fn test_injective_recipient_nonce_unchecked() {
	run_model("injective_recipient_nonce_unchecked.vp", "a1");
	run_model_sessions("injective_recipient_nonce_unchecked.vp", 1, "a0");
}

#[test]
fn test_scenario_replay_is_a_replay() {
	run_model("scenario_replay_is_a_replay.vp", "a1");
	run_model_sessions("scenario_replay_is_a_replay.vp", 1, "a1");
}

#[test]
fn a_cross_scenario_replay_is_named_a_replay_not_a_forgery() {
	let report = crate::verify::verify_report("examples/test/scenario_replay_is_a_replay.vp", 1)
		.expect("analyses");
	let auth = &report.results[0];
	assert!(auth.resolved);
	assert_eq!(
		auth.subtype,
		Some(crate::types::Subtype::ReplayableFirstFlight),
		"Alice signed m@2 herself in the other scenario's run, so delivering it to the \
		 honest Bob is a duplicate acceptance of a first flight, not a forgery; sibling \
		 groups built over the session axis alone left it labelled as one"
	);
	assert!(
		auth.summary.contains("Attacker replays m"),
		"the trace must say the flight was replayed, not replaced: a step that shows \
		 Alice signing a value must not be followed by a conclusion calling it forged:\n{}",
		auth.summary
	);
}

#[test]
fn a_duplicate_acceptance_says_whether_the_recipient_could_have_told() {
	let checked =
		crate::verify::verify_report("examples/test/injective_recipient_nonce_unchecked.vp", 2)
			.expect("analyses");
	assert!(checked.results[0].resolved);
	assert_eq!(
		checked.results[0].subtype,
		Some(crate::types::Subtype::DuplicateAcceptance),
		"the sealed answer carries Bob's own challenge, so Bob is a recipient that could \
		 have told two acceptances apart and did not; that is a duplicate the protocol \
		 is answerable for"
	);

	let first_flight =
		crate::verify::verify_report("examples/test/session_replay_breaks_injectivity.vp", 2)
			.expect("analyses");
	assert!(first_flight.results[0].resolved);
	assert_eq!(
		first_flight.results[0].subtype,
		Some(crate::types::Subtype::ReplayableFirstFlight),
		"a first flight the recipient contributed nothing to can be taken twice by any \
		 run of it, so the duplicate is reported as the weaker finding it is"
	);

	let zero_rtt = crate::verify::verify_report("examples/transport-layer/tls13-0rtt.vp", 2)
		.expect("analyses");
	let early = zero_rtt
		.results
		.iter()
		.find(|r| r.resolved && r.query.kind == crate::types::QueryKind::Authentication)
		.expect("the 0-RTT replay is still reported");
	assert_eq!(
		early.subtype,
		Some(crate::types::Subtype::ReplayableFirstFlight),
		"RFC 9846 section 2.3 names non-replay as a property 0-RTT does not have. That \
		 replay is exactly a first flight with no recipient-generated context, which is \
		 why the distinction is a label on the verdict and not a reason to withhold it: \
		 silencing context-free duplicates was measured to silence this one too"
	);

	let single =
		crate::verify::verify_report("examples/test/injective_recipient_nonce_unchecked.vp", 1)
			.expect("analyses");
	assert!(
		!single.results[0].resolved,
		"at one session the matching-run exemption holds: Alice honestly sealed what \
		 the attacker fed her, and Bob accepted that once"
	);
}

#[test]
fn test_halted_use_is_not_acceptance() {
	run_model("halted_use_is_not_acceptance.vp", "a0");
	run_model_sessions("halted_use_is_not_acceptance.vp", 1, "a0");
}

#[test]
fn test_history_closure_incompatible() {
	run_model("history_closure_incompatible.vp", "c0c1c1a0a1f0f1e1e1");
	run_model_sessions("history_closure_incompatible.vp", 1, "c0c1c1a0a1f0f1e1e1");
}

#[test]
fn the_closure_does_not_combine_reads_from_incompatible_executions() {
	let (_, closure) =
		crate::verify::verify("examples/test/history_closure_incompatible.vp").expect("analyses");
	let (results, weakened) =
		crate::verify::verify("examples/test/junglegym_hybrid_pq.vp").expect("analyses");
	assert_eq!(
		closure, "c0c1c1a0a1f0f1e1e1",
		"the seed is learned only where Bob was handed the attacker's key, and sealed \
		 exists only where he was handed the honest one; a root built from the first \
		 must not open a ciphertext from the second, and nothing separates the two \
		 steps but a rule inside the closure"
	);
	assert_eq!(
		weakened, "c1c1c1a0a1f0f1e1e1",
		"the same model with `PUBKEY[weak from phase 3]` hands over alice_eph, which \
		 decapsulates the honest kem_ct in one execution, so the payload is genuinely lost"
	);
	let payload = results
		.iter()
		.find(|r| {
			r.query
				.constants
				.first()
				.is_some_and(|c| &*c.name == "payload")
		})
		.expect("the payload query");
	assert!(
		!payload.summary.contains("not a minimized witness"),
		"with the incoherent route gone the phase-3 route is what remains, and it needs \
		 no substitution at all, so its witness minimizes: {}",
		payload.summary
	);
}

#[test]
fn test_history_incompatible_knowledge() {
	run_model("history_incompatible_knowledge.vp", "a0");
	run_model_sessions("history_incompatible_knowledge.vp", 1, "a0");
}

#[test]
fn test_history_compatible_oracle() {
	run_model("history_compatible_oracle.vp", "a1");
	run_model_sessions("history_compatible_oracle.vp", 1, "a1");
}

#[test]
fn every_model_in_the_corpus_is_wired_to_a_test() {
	let source =
		std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/model_tests.rs"))
			.expect("read model_tests.rs");
	let mut unwired: Vec<String> = Vec::new();
	for entry in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/test"))
		.expect("list examples/test")
	{
		let name = entry
			.expect("entry")
			.file_name()
			.to_string_lossy()
			.to_string();
		if !name.ends_with(".vp") {
			continue;
		}
		if !source.contains(&format!("\"{name}\"")) {
			unwired.push(name);
		}
	}
	unwired.sort();
	assert!(
		unwired.is_empty(),
		"every model in examples/test/ is pinned by a run_model or run_model_err test, so \
		 that its verdict cannot drift unnoticed; these are not: {unwired:?}"
	);
}

#[test]
fn test_closure_two_recipients() {
	run_model("closure_two_recipients.vp", "c1");
	run_model_sessions("closure_two_recipients.vp", 1, "c1");
}

#[test]
fn test_closure_halted_send() {
	run_model("closure_halted_send.vp", "c0c1c1");
	run_model_sessions("closure_halted_send.vp", 1, "c0c1c1");
}

#[test]
fn test_closure_cyclic_union() {
	run_model("closure_cyclic_union.vp", "c1c1c0");
	run_model_sessions("closure_cyclic_union.vp", 1, "c1c1c0");
}

#[test]
fn test_matching_run_leaked_generated_key() {
	run_model("matching_run_leaked_generated_key.vp", "a1");
	run_model_sessions("matching_run_leaked_generated_key.vp", 1, "a1");
}

#[test]
fn knowledge_from_one_execution_is_not_spent_against_another() {
	let (_, incompatible) =
		crate::verify::verify_with_sessions("examples/test/history_incompatible_knowledge.vp", 1)
			.expect("analyses");
	let (_, compatible) =
		crate::verify::verify_with_sessions("examples/test/history_compatible_oracle.vp", 1)
			.expect("analyses");
	assert_eq!(
		incompatible, "a0",
		"the substitution that lets the attacker read the sealed nonce also changes the \
		 ciphertext Bob decrypts to recover it, so no single execution both reveals the \
		 nonce and leaves Bob able to use it. The revealing message goes to a third \
		 principal, so noticing this means re-running Alice under the recorded \
		 substitution rather than comparing the slots Bob himself receives"
	);
	assert_eq!(
		compatible, "a1",
		"here the sealing key is simply leaked, so nothing the attacker did to learn the \
		 nonce disturbs what Bob is handed and the forgery is real. Dropping knowledge \
		 because it came off a message addressed elsewhere would lose it"
	);
}

#[test]
fn test_forward_transitive_relay() {
	run_model("forward_transitive_relay.vp", "f1");
	run_model_sessions("forward_transitive_relay.vp", 1, "f1");
}

#[test]
fn test_forward_relay_all_guarded() {
	run_model("forward_relay_all_guarded.vp", "f0");
	run_model_sessions("forward_relay_all_guarded.vp", 1, "f0");
}

#[test]
fn test_forward_computed_under_guard() {
	run_model("forward_computed_under_guard.vp", "f1");
	run_model_sessions("forward_computed_under_guard.vp", 1, "f1");
}

#[test]
fn test_forward_computed_guarded_input() {
	run_model("forward_computed_guarded_input.vp", "f0");
	run_model_sessions("forward_computed_guarded_input.vp", 1, "f0");
}

#[test]
fn test_forward_halted_sender_emits_nothing() {
	run_model("forward_halted_sender_emits_nothing.vp", "f0");
	run_model_sessions("forward_halted_sender_emits_nothing.vp", 1, "f0");
}

#[test]
fn test_forward_emission_is_not_a_forgery() {
	run_model("forward_emission_is_not_a_forgery.vp", "a0f1");
	run_model_sessions("forward_emission_is_not_a_forgery.vp", 1, "a0f1");
}

#[test]
fn a_guard_does_not_protect_a_sender_that_computed_on_attacker_input() {
	let (_, relayed) =
		crate::verify::verify_with_sessions("examples/test/forward_transitive_relay.vp", 1)
			.expect("analyses");
	let (_, closed) =
		crate::verify::verify_with_sessions("examples/test/forward_relay_all_guarded.vp", 1)
			.expect("analyses");
	assert_eq!(
		relayed, "f1",
		"one unguarded leg decides the value two guarded relays later, so the guard on \
		 Dave's own incoming leg protects nothing; the substitution has to be followed \
		 through every forwarder rather than one hop"
	);
	assert_eq!(
		closed, "f0",
		"with no unguarded leg anywhere there is no substitution to follow, and reporting \
		 one would be a value no execution produces"
	);

	let (_, computed) =
		crate::verify::verify_with_sessions("examples/test/forward_computed_under_guard.vp", 1)
			.expect("analyses");
	let (_, guarded_input) =
		crate::verify::verify_with_sessions("examples/test/forward_computed_guarded_input.vp", 1)
			.expect("analyses");
	let (_, halted) = crate::verify::verify_with_sessions(
		"examples/test/forward_halted_sender_emits_nothing.vp",
		1,
	)
	.expect("analyses");
	assert_eq!(
		computed, "f1",
		"the tag cannot be synthesised without the key and its leg is guarded, so the \
		 only route is Alice's own run emitting it under attacker-chosen input and that \
		 emission being delivered"
	);
	assert_eq!(
		guarded_input, "f0",
		"guard the input too and the sender has no reason to compute anything else, so a \
		 forwarded emission must carry no attack"
	);
	assert_eq!(
		halted, "f0",
		"a run that halts before its send emitted nothing, so there is nothing to carry"
	);
}

#[test]
fn test_conf_attacker_supplied_value() {
	run_model("conf_attacker_supplied_value.vp", "c1c0");
	run_model_sessions("conf_attacker_supplied_value.vp", 1, "c1c0");
}

#[test]
fn test_conf_forced_key_is_a_real_disclosure() {
	run_model("conf_forced_key_is_a_real_disclosure.vp", "c1");
	run_model_sessions("conf_forced_key_is_a_real_disclosure.vp", 1, "c1");
}

#[test]
fn a_confidentiality_break_says_whether_the_value_was_the_attackers_own() {
	let supplied = crate::verify::verify_report("examples/test/conf_attacker_supplied_value.vp", 1)
		.expect("analyses");
	assert_eq!(
		supplied.results[0].subtype,
		Some(crate::types::Subtype::AttackerSuppliedValue),
		"the attacker learns nil because it put nil there; the honest value was never \
		 shown to leak, and a report that reads the same as a real disclosure is the \
		 thing under test"
	);
	assert!(supplied.results[0].resolved);
	assert!(!supplied.results[1].resolved);
	assert!(
		supplied.results[0]
			.conclusion
			.contains("is not shown to be disclosed")
	);

	let forced =
		crate::verify::verify_report("examples/test/conf_forced_key_is_a_real_disclosure.vp", 1)
			.expect("analyses");
	assert!(forced.results[0].resolved);
	assert_eq!(
		forced.results[0].subtype, None,
		"a session key the attacker forced still carries Bob's own generated exponent, so \
		 it is a genuine disclosure and must not be qualified away"
	);

	let none_flagged = swept_models().into_iter().all(|(_, path)| {
		crate::verify::verify_report(&path, 1)
			.map(|report| {
				report.results.iter().all(|r| {
					r.subtype != Some(crate::types::Subtype::AttackerSuppliedValue)
						|| path.contains("conf_attacker_supplied_value")
				})
			})
			.unwrap_or(true)
	});
	assert!(
		none_flagged,
		"every other confidentiality break in the corpus reaches a value that carries \
		 something generated or held privately, so the qualifier must stay off them"
	);
}

#[test]
fn test_matching_run_routing() {
	run_model("matching_run_routing.vp", "a1");
	run_model_sessions("matching_run_routing.vp", 1, "a0");
}

#[test]
fn test_matching_run_two_inputs() {
	run_model("matching_run_two_inputs.vp", "a1");
	run_model_sessions("matching_run_two_inputs.vp", 1, "a0");
}

#[test]
fn test_matching_run_nested_term() {
	run_model("matching_run_nested_term.vp", "a1");
	run_model_sessions("matching_run_nested_term.vp", 1, "a0");
}

#[test]
fn test_matching_run_forged_unguarded() {
	run_model("matching_run_forged_unguarded.vp", "a1");
	run_model_sessions("matching_run_forged_unguarded.vp", 1, "a1");
}

#[test]
fn test_matching_run_forged_not_emitted() {
	run_model("matching_run_forged_not_emitted.vp", "a1");
	run_model_sessions("matching_run_forged_not_emitted.vp", 1, "a1");
}

#[test]
fn test_matching_run_constructed_not_emitted() {
	run_model("matching_run_constructed_not_emitted.vp", "a1");
	run_model_sessions("matching_run_constructed_not_emitted.vp", 1, "a1");
}

#[test]
fn test_matching_run_halts_before_send() {
	run_model("matching_run_halts_before_send.vp", "a1");
	run_model_sessions("matching_run_halts_before_send.vp", 1, "a1");
}

#[test]
fn a_matching_run_of_the_sender_is_not_an_authentication_failure() {
	let (_, routed) =
		crate::verify::verify_with_sessions("examples/test/matching_run_routing.vp", 1)
			.expect("analyses");
	let (_, forged) =
		crate::verify::verify_with_sessions("examples/test/matching_run_forged_not_emitted.vp", 1)
			.expect("analyses");
	assert_eq!(
		routed, "a0",
		"driving both deliveries of the nonce makes Alice honestly compute and send the \
		 very tag Bob accepts, so one send answers one acceptance and injective agreement \
		 holds; reporting it conflates rerouting with authoring"
	);
	assert_eq!(
		forged, "a1",
		"guarding Alice's nonce leaves no substitution that drives her into emitting the \
		 forged tag, so the exemption must not excuse a value the leaked key manufactured"
	);
}

#[test]
fn saturation_never_stops_before_it_has_looked_above_the_default() {
	let stable = crate::verify::saturation_sessions("examples/test/aead_leak.vp", 4, false)
		.expect("analyses");
	assert!(stable.saturated);
	assert_eq!(
		stable.sessions, 3,
		"a model reading alike at one and two sessions must still be probed at three: an \
		 attack needing three concurrent runs is invisible below that, and a ladder that \
		 began at one session would have called this saturated at two and stopped"
	);
	assert_eq!(stable.stable_from, 2);
}

#[test]
fn test_spore_ns_pk() {
	run_model("spore_ns_pk.vp", "c1a1a0");
	run_model_sessions("spore_ns_pk.vp", 1, "c1a1a0");
}

#[test]
fn test_scenario_three_peers_multibind() {
	run_model("scenario_three_peers_multibind.vp", "c1a1");
	run_model_sessions("scenario_three_peers_multibind.vp", 1, "c1a1");
}

#[test]
fn test_scenario_four_peers_multibind() {
	run_model("scenario_four_peers_multibind.vp", "c0a1");
	run_model_sessions("scenario_four_peers_multibind.vp", 1, "c0a0");
}

#[test]
fn test_scenario_multibind_two_honest() {
	run_model("scenario_multibind_two_honest.vp", "c0");
	run_model_sessions("scenario_multibind_two_honest.vp", 1, "c0");
}

#[test]
fn test_scenario_all_peers_corrupt() {
	run_model("scenario_all_peers_corrupt.vp", "c1");
	run_model_sessions("scenario_all_peers_corrupt.vp", 1, "c1");
}

#[test]
fn test_scenario_post_halt_no_oracle() {
	run_model("scenario_post_halt_no_oracle.vp", "c0");
	run_model_sessions("scenario_post_halt_no_oracle.vp", 1, "c0");
}

#[test]
fn test_scenario_post_halt_leak_no_oracle() {
	run_model("scenario_post_halt_leak_no_oracle.vp", "c0");
	run_model_sessions("scenario_post_halt_leak_no_oracle.vp", 1, "c0");
}

#[test]
fn test_scenario_pre_halt_oracle() {
	run_model("scenario_pre_halt_oracle.vp", "c1");
	run_model_sessions("scenario_pre_halt_oracle.vp", 1, "c1");
}

#[test]
fn test_scenario_honest_peer_only() {
	run_model("scenario_honest_peer_only.vp", "c0");
	run_model_sessions("scenario_honest_peer_only.vp", 1, "c0");
}

#[test]
fn a_halted_corrupt_peer_publishes_nothing_it_never_reached() {
	let (_, post) =
		crate::verify::verify("examples/test/scenario_post_halt_no_oracle.vp").expect("analyses");
	let (_, leaked) = crate::verify::verify("examples/test/scenario_post_halt_leak_no_oracle.vp")
		.expect("analyses");
	let (_, pre) =
		crate::verify::verify("examples/test/scenario_pre_halt_oracle.vp").expect("analyses");
	let (_, honest) =
		crate::verify::verify("examples/test/scenario_honest_peer_only.vp").expect("analyses");
	assert_eq!(honest, "c0");
	assert_eq!(pre, "c1");
	assert_eq!(
		post, "c0",
		"a corrupt-peer clone halted before it could seal or send `sealed@2`, so an 		 attack on `master` through that ciphertext is one no execution produces"
	);
	assert_eq!(
		leaked, "c0",
		"the same halt boundary has to hold for a `leaks` the clone never reached"
	);
	assert_ne!(
		post, pre,
		"suppressing the reachable ciphertext too would trade a false attack for a lost one"
	);
}

#[test]
fn a_value_computed_before_a_halt_but_sent_after_it_is_not_published() {
	let source = "attacker[passive]\nprincipal Bob[\nknows private ph_bsk\nph_bpk = PUBKEY(ph_bsk)\nph_sig = SIGN(ph_bsk, nil)\n]\nprincipal Mallory[\nknows private ph_msk\nph_mpk = PUBKEY(ph_msk)\nleaks ph_msk\n]\nprincipal Alice[\nknows public ph_peerpk\nknows private ph_master\n]\nBob -> Alice: [ph_bpk], [ph_sig]\nMallory -> Alice: [ph_mpk]\nprincipal Alice[\nph_sealed = PKE_ENC(ph_peerpk, ph_master)\n_ = SIGNVERIF(ph_peerpk, nil, ph_sig)?\n]\nAlice -> Bob: ph_sealed\nscenarios[\nAlice[ph_peerpk = ph_bpk]\nAlice[ph_peerpk = ph_mpk]\n]\nqueries[\nconfidentiality? ph_master\n]\n";
	let model = crate::parser::parse_string("precomputed-halt.vp", source).expect("parses");
	let result = crate::verify::analyze_sessions(&model, 1)
		.expect("analyzes")
		.results_get()
		.remove(0);
	assert!(!result.resolved);
}

#[test]
fn test_spore_nsl_pk() {
	run_model("spore_nsl_pk.vp", "c0a1a0");
	run_model_sessions("spore_nsl_pk.vp", 1, "c0a1a0");
}

#[test]
fn with_peer_instantiation_lowes_fix_changes_the_verdict() {
	let (_, ns) = crate::verify::verify("examples/test/spore_ns_pk.vp").expect("analyses");
	let (_, nsl) = crate::verify::verify("examples/test/spore_nsl_pk.vp").expect("analyses");
	assert_ne!(ns, nsl, "peer instantiation exists to tell these two apart");
	assert_eq!(ns, "c1a1a0");
	assert_eq!(nsl, "c0a1a0");
}

#[test]
fn test_spore_otway_rees() {
	run_model("spore_otway_rees.vp", "c0c1a1");
}

#[test]
fn test_spore_wmf() {
	run_model("spore_wmf.vp", "c1a1f0");
}

#[test]
fn test_spore_yahalom() {
	run_model("spore_yahalom.vp", "c0c0c1");
}

fn run_model(model: &str, expected: &str) {
	run_model_at(&format!("examples/test/{}", model), model, expected);
}

fn run_model_at(path: &str, model: &str, expected: &str) {
	let (results, results_code) =
		crate::verify::verify(path).unwrap_or_else(|e| panic!("ERROR \u{25cf} {} ({})", model, e));
	assert_code(model, None, &results, &results_code, expected);
}

fn run_model_sessions_at(path: &str, model: &str, sessions: u8, expected: &str) {
	let (results, results_code) = crate::verify::verify_with_sessions(path, sessions)
		.unwrap_or_else(|e| panic!("ERROR \u{25cf} {} ({})", model, e));
	assert_code(model, Some(sessions), &results, &results_code, expected);
}

fn run_model_sessions(model: &str, sessions: u8, expected: &str) {
	let path = format!("examples/test/{}", model);
	let (results, results_code) = crate::verify::verify_with_sessions(&path, sessions)
		.unwrap_or_else(|e| panic!("ERROR \u{25cf} {} ({})", model, e));
	assert_code(model, Some(sessions), &results, &results_code, expected);
}

fn kind_name(letter: char) -> &'static str {
	match letter {
		'c' => "confidentiality",
		'a' => "authentication",
		'f' => "freshness",
		'u' => "unlinkability",
		'e' => "equivalence",
		_ => "unknown",
	}
}

fn code_pairs(code: &str) -> Vec<(char, char)> {
	code.chars()
		.collect::<Vec<char>>()
		.chunks(2)
		.filter(|pair| pair.len() == 2)
		.map(|pair| (pair[0], pair[1]))
		.collect()
}

fn assert_code(
	model: &str,
	sessions: Option<u8>,
	results: &[crate::types::VerifyResult],
	got: &str,
	expected: &str,
) {
	if got == expected {
		return;
	}
	let at = match sessions {
		Some(n) => format!(" at {} session{}", n, if n == 1 { "" } else { "s" }),
		None => String::new(),
	};
	let mut out = format!(
		"FAIL \u{25cf} {}{} (expected {}, got {})\n",
		model, at, expected, got
	);
	let want = code_pairs(expected);
	let have = code_pairs(got);
	if want.len() != have.len() {
		out.push_str(&format!(
			"\n  the model answers {} quer{}, the expected code pins {}\n",
			have.len(),
			if have.len() == 1 { "y" } else { "ies" },
			want.len()
		));
	}
	for (i, answered) in have.iter().enumerate() {
		let Some(wanted) = want.get(i) else {
			break;
		};
		if wanted == answered {
			continue;
		}
		let query = results
			.get(i)
			.map(|r| format!("{}", r.query))
			.unwrap_or_else(|| "?".to_string());
		out.push_str(&format!("\n  query {}: {}\n", i, query));
		if wanted.0 != answered.0 {
			out.push_str(&format!(
				"    the code pins a {} query here, the model asks a {} query\n",
				kind_name(wanted.0),
				kind_name(answered.0)
			));
			continue;
		}
		if answered.1 == '1' {
			out.push_str("    pinned to hold, but an attack was found:\n");
			for line in results
				.get(i)
				.map(|r| r.summary.as_str())
				.unwrap_or_default()
				.lines()
				.filter(|line| !line.trim().is_empty())
			{
				out.push_str(&format!("    {}\n", line.trim()));
			}
		} else {
			out.push_str("    pinned to an attack, but the query held\n");
		}
	}
	panic!("{}", out);
}

fn run_model_err(model: &str, expected_substring: &str) {
	let path = format!("examples/test/{}", model);
	match crate::verify::verify(&path) {
		Ok((_, code)) => panic!(
			"FAIL • {} (expected an error containing {:?}, got result code {})",
			model, expected_substring, code
		),
		Err(e) => {
			let text = format!("{}", e);
			assert!(
				text.contains(expected_substring),
				"FAIL • {} (expected an error containing {:?}, got: {})",
				model,
				expected_substring,
				text
			);
		}
	}
}

#[test]
fn test_cap_err_sign_weak() {
	run_model_err("cap_err_sign_weak.vp", "did you mean `SIGN[forgeable]`");
}
#[test]
fn test_cap_err_dh_kex_weak() {
	run_model_err("cap_err_dh_kex_weak.vp", "did you mean `PUBKEY[weak]`");
}
#[test]
fn test_cap_err_hash_forgeable() {
	run_model_err("cap_err_hash_forgeable.vp", "has no secret argument");
}
#[test]
fn test_err_unknown_qualifier() {
	run_model_err("err_unknown_qualifier.vp", "unknown qualifier `password`");
}
#[test]
fn test_err_unknown_primitive() {
	run_model_err("err_unknown_primitive.vp", "unknown primitive `PW_HASH`");
}
#[test]
fn test_cap_err_aead_malleable() {
	run_model_err(
		"cap_err_aead_malleable.vp",
		"did you mean `AEAD_ENC[forgeable]`",
	);
}
#[test]
fn test_err_nil_redeclared() {
	run_model_err(
		"err_nil_redeclared.vp",
		"`nil` is built in and cannot be declared",
	);
}
#[test]
fn test_err_nil_sent() {
	run_model_err("err_nil_sent.vp", "`nil` is built in and cannot be sent");
}
#[test]
fn test_err_no_principals() {
	run_model_err("err_no_principals.vp", "declares no principals");
}
#[test]
fn test_err_nested_check() {
	run_model_err(
		"err_nested_check.vp",
		"`AEAD_DEC` is checked with `?` inside another primitive",
	);
}
#[test]
fn test_err_used_before_declared() {
	run_model_err(
		"err_used_before_declared.vp",
		"`fgb` is used before it is declared",
	);
}
#[test]
fn test_err_nested_output() {
	run_model_err(
		"err_nested_output.vp",
		"`KEM_ENCAP` produces more than one output",
	);
}
#[test]
fn test_cap_err_core_primitive() {
	run_model_err("cap_err_core_primitive.vp", "no cryptographic guarantee");
}
#[test]
fn test_cap_err_phase_unreached() {
	run_model_err(
		"cap_err_phase_unreached.vp",
		"which the model never reaches",
	);
}

#[test]
fn test_cap_reach_notice() {
	run_model("cap_reach_notice.vp", "a1");
}
#[test]
fn test_cap_reach_secret() {
	run_model("cap_reach_secret.vp", "a1");
}
#[test]
fn test_cap_weak_hash() {
	run_model("cap_weak_hash.vp", "c1c1");
}
#[test]
fn test_cap_weak_pubkey_dh() {
	run_model("cap_weak_pubkey_dh.vp", "c1");
}
#[test]
fn test_cap_malleable_enc() {
	run_model("cap_malleable_enc.vp", "a1");
}
#[test]
fn test_cap_malleable_absent() {
	run_model("cap_malleable_absent.vp", "a0");
}
#[test]
fn test_cap_weak_kem_resolved() {
	run_model("cap_weak_kem_resolved.vp", "c1c1");
}
#[test]
fn test_cap_weak_phase_delayed() {
	run_model("cap_weak_phase_delayed.vp", "c0c1");
}

#[test]
fn test_cap_forgeable_sign() {
	run_model("cap_forgeable_sign.vp", "a1");
}
#[test]
fn test_cap_forgeable_aead() {
	run_model("cap_forgeable_aead.vp", "c0a1");
}
#[test]
fn test_cap_weak_on_reduced_argument() {
	run_model("cap_weak_on_reduced_argument.vp", "c1c1");
	run_model_sessions("cap_weak_on_reduced_argument.vp", 1, "c1c1");
}
#[test]
fn test_cap_forgeable_on_reduced_key() {
	run_model("cap_forgeable_on_reduced_key.vp", "a1");
	run_model_sessions("cap_forgeable_on_reduced_key.vp", 1, "a1");
}

#[test]
fn test_cap_err_malleable_unsupported() {
	run_model_err(
		"cap_err_malleable_unsupported.vp",
		"HASH does not support the `malleable` parameter",
	);
}

#[test]
fn test_cap_multi_annotation() {
	run_model("cap_multi_annotation.vp", "c1c1");
}
#[test]
fn test_cap_noop_annotated() {
	run_model("cap_noop_annotated.vp", "c0a1");
}

#[test]
fn test_pqxdh_weak() {
	run_model_at("examples/messaging/pqxdh-weak.vp", "pqxdh-weak.vp", "c0a0");
}

#[test]
fn test_pqxdh() {
	run_model_at("examples/messaging/pqxdh.vp", "pqxdh.vp", "c0a0");
}
#[test]
fn test_cen() {
	run_model_at("examples/contact-tracing/cen.vp", "cen.vp", "c0c1c0");
}
#[test]
fn test_firefox_sync() {
	run_model_at(
		"examples/transport-layer/firefox-sync.vp",
		"firefox-sync.vp",
		"c0a0",
	);
}
#[test]
fn test_hpke_base() {
	run_model_at("examples/hpke/hpke_base.vp", "hpke_base.vp", "c0a1");
}
#[test]
fn test_hpke_auth() {
	run_model_at("examples/hpke/hpke_auth.vp", "hpke_auth.vp", "c0a1");
	run_model_sessions_at("examples/hpke/hpke_auth.vp", "hpke_auth.vp", 1, "c0a0");
}
#[test]
fn test_hpke_auth_kci() {
	run_model_at("examples/hpke/hpke_auth_kci.vp", "hpke_auth_kci.vp", "c1a1");
}
#[test]
fn test_hpke_auth_kci_signed() {
	run_model_at(
		"examples/hpke/hpke_auth_kci_signed.vp",
		"hpke_auth_kci_signed.vp",
		"c1a1",
	);
	run_model_sessions_at(
		"examples/hpke/hpke_auth_kci_signed.vp",
		"hpke_auth_kci_signed.vp",
		1,
		"c1a0",
	);
}
#[test]
fn test_hpke_psk_pq() {
	run_model_at("examples/hpke/hpke_psk_pq.vp", "hpke_psk_pq.vp", "c1c0");
}
#[test]
fn test_userbase() {
	run_model_at("examples/messaging/userbase.vp", "userbase.vp", "c0c0a1a1");
	run_model_sessions_at(
		"examples/messaging/userbase.vp",
		"userbase.vp",
		1,
		"c0c0a0a0",
	);
}
#[test]
fn test_signal() {
	run_model_at("examples/messaging/signal.vp", "signal.vp", "c0a1c1a0c0a1");
}
#[test]
fn test_scuttlebutt() {
	run_model_at(
		"examples/messaging/scuttlebutt.vp",
		"scuttlebutt.vp",
		"c1c0c1c0a1a1a1a1a1e1",
	);
}

#[test]
fn test_junglegym_hybrid_pq() {
	run_model("junglegym_hybrid_pq.vp", "c1c1c1a0a1f0f1e1e1");
}
#[test]
fn test_junglegym_threshold_ring() {
	run_model("junglegym_threshold_ring.vp", "c1c0c0a1a1a0u0u1u1f0f1e1e1");
}
#[test]
fn test_junglegym_phase_cascade() {
	run_model(
		"junglegym_phase_cascade.vp",
		"c1c1c0c1a0a0a0a0a1a1a0f0f1e0e0u1",
	);
}
#[test]
fn test_junglegym_deep_ratchet() {
	run_model(
		"junglegym_deep_ratchet.vp",
		"c0c0c0c0c0a0a0a0a0f0f1e1e1e0u0u0",
	);
}

#[test]
fn test_challengeresponse() {
	run_model("challengeresponse.vp", "a0a1");
}
#[test]
fn test_checked_aead() {
	run_model("checked_aead.vp", "c0a1a1");
}
#[test]
fn test_ephemerals_sign() {
	run_model("ephemerals_sign.vp", "c1a1");
}
#[test]
fn test_hmac_ok() {
	run_model("hmac_ok.vp", "c0a1");
}
#[test]
fn test_session_nonce_cross_one_session() {
	// One session: the only forgery route replays Bob's honest m1, so
	// authentication holds. This is the pre-sessions behavior, kept.
	run_model_sessions("session_nonce_cross.vp", 1, "a0");
}
#[test]
fn test_session_nonce_cross_two_sessions() {
	run_model_sessions("session_nonce_cross.vp", 2, "a0");
}
#[test]
fn test_incompatible_histories() {
	run_model_sessions("incompatible_histories.vp", 1, "a0");
	run_model_sessions("incompatible_histories.vp", 2, "a0");
}
#[test]
fn test_incompatible_histories_mitm() {
	run_model_sessions("incompatible_histories_mitm.vp", 1, "c1a1");
	run_model_sessions("incompatible_histories_mitm.vp", 2, "c1a1");
}
#[test]
fn test_atemporal_forward_value() {
	run_model_sessions("atemporal_forward_value.vp", 1, "a0");
	run_model_sessions("atemporal_forward_value.vp", 2, "a0");
}
#[test]
fn test_session_peer_run_matches_one_session() {
	run_model_sessions("session_peer_run_matches.vp", 1, "a0");
}
#[test]
fn test_session_peer_run_matches_two_sessions() {
	run_model_sessions("session_peer_run_matches.vp", 2, "a0");
}
#[test]
fn test_session_replay_breaks_injectivity_one_session() {
	run_model_sessions("session_replay_breaks_injectivity.vp", 1, "a0");
}
#[test]
fn test_session_replay_breaks_injectivity_two_sessions() {
	run_model_sessions("session_replay_breaks_injectivity.vp", 2, "a1");
}
#[test]
fn test_session_concat_bomb_cross_feed() {
	run_model_sessions("concat_bomb_equiv.vp", 2, "e1e1e1e1e1f0");
}
#[test]
fn test_session_hmac_ok_stable_two_sessions() {
	run_model_sessions("hmac_ok.vp", 2, "c0a1");
}
#[test]
fn test_session_pke_stable_two_sessions() {
	run_model_sessions("pke.vp", 2, "c0a0");
}
#[test]
fn test_session_psk_cross_feed_one_session() {
	run_model_sessions("session_psk_cross_feed.vp", 1, "c0e0");
}
#[test]
fn test_session_psk_cross_feed() {
	run_model("session_psk_cross_feed.vp", "c0e1");
}
#[test]
fn test_session_dh_no_cross_feed_one_session() {
	run_model_sessions("session_dh_no_cross_feed.vp", 1, "c0e0");
}
#[test]
fn test_session_dh_no_cross_feed() {
	run_model("session_dh_no_cross_feed.vp", "c0e0");
}
#[test]
fn test_session_shamir_no_phantom_shares_one_session() {
	run_model_sessions("session_shamir_no_phantom_shares.vp", 1, "c0");
}
#[test]
fn test_session_shamir_no_phantom_shares() {
	run_model("session_shamir_no_phantom_shares.vp", "c0");
}
#[test]
fn test_session_mac_replay_breaks_injectivity_one_session() {
	run_model_sessions("session_mac_replay_breaks_injectivity.vp", 1, "a0");
}
#[test]
fn test_session_mac_replay_breaks_injectivity() {
	run_model("session_mac_replay_breaks_injectivity.vp", "a1");
}
#[test]
fn test_session_forward_secrecy_one_session() {
	run_model_sessions("session_forward_secrecy.vp", 1, "c0");
}
#[test]
fn test_session_forward_secrecy() {
	run_model("session_forward_secrecy.vp", "c0");
}
#[test]
fn test_session_freshness_stable_one_session() {
	run_model_sessions("session_freshness_stable.vp", 1, "f0f1");
}
#[test]
fn test_session_freshness_stable() {
	run_model("session_freshness_stable.vp", "f0f1");
}
#[test]
fn test_session_unlink_stable_one_session() {
	run_model_sessions("session_unlink_stable.vp", 1, "u0");
}
#[test]
fn test_session_unlink_stable() {
	run_model("session_unlink_stable.vp", "u0");
}
#[test]
fn test_session_signed_challenge_one_session() {
	run_model_sessions("session_signed_challenge.vp", 1, "a0");
}
#[test]
fn test_session_signed_challenge() {
	run_model("session_signed_challenge.vp", "a0");
}
#[test]
fn test_session_kem_cross_decap_one_session() {
	run_model_sessions("session_kem_cross_decap.vp", 1, "c0e0");
}
#[test]
fn test_session_kem_cross_decap() {
	run_model("session_kem_cross_decap.vp", "c0e1");
}
#[test]
fn test_session_unguarded_mitm_one_session() {
	run_model_sessions("session_unguarded_mitm.vp", 1, "c1");
}
#[test]
fn test_session_unguarded_mitm() {
	run_model("session_unguarded_mitm.vp", "c1");
}
#[test]
fn test_session_three_sessions_one_session() {
	run_model_sessions("session_three_sessions.vp", 1, "c0");
}
#[test]
fn test_session_three_sessions() {
	run_model("session_three_sessions.vp", "c0");
}
#[test]
fn test_session_three_sessions_three() {
	run_model_sessions("session_three_sessions.vp", 3, "c0");
}
#[test]
fn test_foreign_halt_no_oracle_one_session() {
	run_model_sessions("foreign_halt_no_oracle.vp", 1, "a0");
}
#[test]
fn test_foreign_halt_no_oracle() {
	run_model("foreign_halt_no_oracle.vp", "a1");
}
#[test]
fn test_equivalence_halt_at_slot_one_session() {
	run_model_sessions("equivalence_halt_at_slot.vp", 1, "e0");
}
#[test]
fn test_equivalence_halt_at_slot() {
	run_model("equivalence_halt_at_slot.vp", "e1");
}
#[test]
fn test_hmac_unchecked_assert() {
	run_model("hmac_unchecked_assert.vp", "c0a1");
}
#[test]
fn test_hmac_unguarded_alice() {
	run_model("hmac_unguarded_alice.vp", "c0a1");
}
#[test]
fn test_hmac_unguarded_bob() {
	run_model("hmac_unguarded_bob.vp", "c1a1");
}
#[test]
fn test_concat_split_replay() {
	run_model("concat_split_replay.vp", "a0");
}
#[test]
fn test_wire_projection_replay() {
	run_model("wire_projection_replay.vp", "a0");
}
#[test]
fn test_forged_flight_mitm() {
	run_model("forged_flight_mitm.vp", "a1");
}
#[test]
fn test_unpinned_cert_flight() {
	run_model("unpinned_cert_flight.vp", "c1");
}
#[test]
fn test_unpinned_cert_flight_one_session() {
	run_model_sessions("unpinned_cert_flight.vp", 1, "c1");
}
#[test]
fn test_pinned_cert_flight() {
	run_model("pinned_cert_flight.vp", "c0");
}
#[test]
fn test_pinned_cert_flight_one_session() {
	run_model_sessions("pinned_cert_flight.vp", 1, "c0");
}
#[test]
fn test_aead_replay_not_forgery() {
	run_model("aead_replay_not_forgery.vp", "a1c0");
}
#[test]
fn test_ringsign_ring_collapse() {
	run_model("ringsign_ring_collapse.vp", "a0");
}
#[test]
fn test_unlink_kem_needs_the_private_key() {
	run_model("unlink_kem_needs_the_private_key.vp", "u0c0");
}
#[test]
fn test_unlink_kem_leaked_private_key() {
	run_model("unlink_kem_leaked_private_key.vp", "u1c1");
}
#[test]
fn test_public_constant_is_never_confidential() {
	run_model("public_constant_is_never_confidential.vp", "c1c1");
}
#[test]
fn test_bypass_needs_the_whole_check() {
	run_model("bypass_needs_the_whole_check.vp", "a0");
}
#[test]
fn test_bypass_needs_the_whole_check_ad_leaked() {
	run_model("bypass_needs_the_whole_check_ad_leaked.vp", "a1");
}
#[test]
fn test_bypass_needs_the_signed_message() {
	run_model("bypass_needs_the_signed_message.vp", "a0");
}
#[test]
fn test_scenario_order_is_not_a_verdict() {
	run_model("scenario_order_is_not_a_verdict.vp", "c0a1");
}
#[test]
fn test_scenario_order_is_not_a_verdict_swapped() {
	run_model("scenario_order_is_not_a_verdict_swapped.vp", "c0a1");
}
#[test]
fn test_bypass_needs_the_signed_message_public() {
	run_model("bypass_needs_the_signed_message_public.vp", "a1");
}
#[test]
fn test_scenario_peer_compromised_later() {
	run_model("scenario_peer_compromised_later.vp", "c1");
}
#[test]
fn test_scenario_peer_compromised_throughout() {
	run_model("scenario_peer_compromised_throughout.vp", "c0");
}
#[test]
fn test_equivalence_names_the_projection() {
	run_model("equivalence_names_the_projection.vp", "e1");
}
#[test]
fn test_leaks_without_a_message_is_visible() {
	run_model("leaks_without_a_message_is_visible.vp", "c1");
}
#[test]
fn test_cap_forgeable_names_its_assumption() {
	run_model("cap_forgeable_names_its_assumption.vp", "a1");
}
#[test]
fn test_cap_forgeable_names_its_assumption_absent() {
	run_model_sessions("cap_forgeable_names_its_assumption_absent.vp", 1, "a0");
	run_model("cap_forgeable_names_its_assumption_absent.vp", "a1");
}
#[test]
fn test_deep_nesting_reconstruct() {
	run_model("deep_nesting_reconstruct.vp", "c1");
}
#[test]
fn test_dh_exponent_not_dropped() {
	run_model("dh_exponent_not_dropped.vp", "c0c0");
}
#[test]
fn test_ok() {
	run_model("ok.vp", "c0a1a1");
}
#[test]
fn test_pke() {
	run_model("pke.vp", "c0a0");
}
#[test]
fn test_pke_unguarded_alice() {
	run_model("pke_unguarded_alice.vp", "c0a1");
}
#[test]
fn test_pke_unguarded_bob() {
	run_model("pke_unguarded_bob.vp", "c1a0");
}
#[test]
fn test_pke_unchecked_assert() {
	run_model("pke_unchecked_assert.vp", "c0a1");
}
#[test]
fn test_assert_junglegym() {
	run_model("assert_junglegym.vp", "c0");
}
#[test]
fn test_shamir() {
	run_model("shamir.vp", "c1");
}
#[test]
fn test_subkey() {
	run_model("subkey.vp", "c1");
}
#[test]
fn test_subkey_hash() {
	run_model("subkey_hash.vp", "c1");
}
#[test]
fn test_subkey_hkdf() {
	run_model("subkey_hkdf.vp", "c1");
}
#[test]
fn test_trivial() {
	run_model("trivial.vp", "c1a1");
}
#[test]
fn test_unchecked_aead() {
	run_model("unchecked_aead.vp", "c0a1a1");
}
#[test]
fn test_unguarded_alice() {
	run_model("unguarded_alice.vp", "c0a1a1");
}
#[test]
fn test_unguarded_bob() {
	run_model("unguarded_bob.vp", "c1a1a1e1");
}
#[test]
fn test_signal_small_nophase() {
	run_model("signal_small_nophase.vp", "c1a1");
}
#[test]
fn test_signal_small_unguarded() {
	run_model("signal_small_unguarded.vp", "c1a1");
}
#[test]
fn test_signal_small_unguarded_alice() {
	run_model("signal_small_unguarded_alice.vp", "c0a1");
}
#[test]
fn test_signal_small_unguarded_bob() {
	run_model("signal_small_unguarded_bob.vp", "c1a1");
}
#[test]
fn test_signal_small_leaks() {
	run_model("signal_small_leaks.vp", "c1a1");
}
#[test]
fn test_signal_small_leaks_alice() {
	run_model("signal_small_leaks_alice.vp", "c0a1");
}
#[test]
fn test_signal_small_leaks_bob() {
	run_model("signal_small_leaks_bob.vp", "c1a1");
}
#[test]
fn test_auth_with_signing() {
	run_model("auth_with_signing.vp", "c1a1a1");
}
#[test]
fn test_auth_with_signing_false_attack() {
	run_model("auth_with_signing_false-attack.vp", "c0a1a1");
}
#[test]
fn test_halted_principal_false_attack() {
	run_model("halted_principal_false-attack.vp", "c0");
}
#[test]
fn test_later_value_fed_back() {
	run_model("later_value_fed_back.vp", "a0");
}
#[test]
fn test_dh_nested_rejected() {
	run_model_err(
		"dh_nested_rejected.vp",
		"`PUBKEY` cannot take `DH_KEX` as its first argument",
	);
}
#[test]
fn test_dh_two_public_keys() {
	run_model("dh_two_public_keys.vp", "c0c0");
}
#[test]
fn test_decompose_is_not_construct() {
	run_model("decompose_is_not_construct.vp", "c0c0c0");
}
#[test]
fn test_hmac_verif() {
	run_model("hmac_verif.vp", "a1a1");
}
#[test]
fn test_sign_ciphertext() {
	run_model("sign_ciphertext.vp", "c0a1");
}
#[test]
fn test_signature() {
	run_model("signature.vp", "c0a1a1");
}
#[test]
fn test_precondition() {
	run_model("precondition.vp", "a1");
	run_model_sessions("precondition.vp", 1, "a1");
}
#[test]
fn test_precondition_halt_before_send() {
	run_model("precondition_halt_before_send.vp", "a1a0");
	run_model_sessions("precondition_halt_before_send.vp", 1, "a0a0");
}
#[test]
fn test_precondition_accepted_key() {
	run_model("precondition_accepted_key.vp", "c1c0c0");
	run_model_sessions("precondition_accepted_key.vp", 1, "c1c0c0");
}
#[test]
fn test_precondition_freshness_halt() {
	run_model("precondition_freshness_halt.vp", "f1f0");
	run_model_sessions("precondition_freshness_halt.vp", 1, "f1f0");
}
#[test]
fn test_precondition_equivalence_accepted() {
	run_model("precondition_equivalence_accepted.vp", "e1e1");
	run_model_sessions("precondition_equivalence_accepted.vp", 1, "e1e0");
}
#[test]
fn test_precondition_unlink_halt() {
	run_model("precondition_unlink_halt.vp", "u1u0");
	run_model_sessions("precondition_unlink_halt.vp", 1, "u1u0");
}
#[test]
fn test_precondition_foreign_halt() {
	run_model("precondition_foreign_halt.vp", "c1c0c1c0");
	run_model_sessions("precondition_foreign_halt.vp", 1, "c1c0c1c0");
}
#[test]
fn test_precondition_two_recipients() {
	run_model("precondition_two_recipients.vp", "a1a1a0");
	run_model_sessions("precondition_two_recipients.vp", 1, "a0a0a0");
}
#[test]
fn test_precondition_many() {
	run_model("precondition_many.vp", "c1c1c0");
	run_model_sessions("precondition_many.vp", 1, "c1c1c0");
}
#[test]
fn test_precondition_later_phase() {
	run_model("precondition_later_phase.vp", "c1c1");
	run_model_sessions("precondition_later_phase.vp", 1, "c1c1");
}
#[test]
fn test_precondition_scenarios_ns_pk() {
	run_model("precondition_scenarios_ns_pk.vp", "a1a1a0");
	run_model_sessions("precondition_scenarios_ns_pk.vp", 1, "a1a1a0");
}
#[test]
fn test_err_precondition_self() {
	run_model_err(
		"err_precondition_self.vp",
		"Alice both sends and receives this message",
	);
}
#[test]
fn test_err_precondition_unknown_constant() {
	run_model_err(
		"err_precondition_unknown_constant.vp",
		"unknown constant `nosuch`",
	);
}
#[test]
fn test_err_precondition_wrong_sender() {
	run_model_err(
		"err_precondition_wrong_sender.vp",
		"Bob never sends `m2` to Carol",
	);
}
#[test]
fn test_err_precondition_unknown_option() {
	run_model_err(
		"err_precondition_unknown_option.vp",
		"unknown query option `postcondition`",
	);
}
#[test]
fn test_err_precondition_two_constants() {
	run_model_err("err_precondition_two_constants.vp", "expected `]`");
}
#[test]
fn a_gated_query_reports_every_precondition_exactly_when_it_fails() {
	let mut checked = 0;
	for (name, path) in swept_models() {
		let source = std::fs::read_to_string(&path).expect("read model");
		if !source.contains("precondition[") {
			continue;
		}
		let Ok((results, _)) = crate::verify::verify_with_sessions(&path, 2) else {
			continue;
		};
		for result in results {
			if result.resolved {
				assert_eq!(
					result.options.len(),
					result.query.options.len(),
					"{name}: a contradicted query reports each precondition it was restricted by"
				);
				for option in &result.options {
					assert!(
						option.summary.contains("still sends"),
						"{name}: unexpected precondition line {:?}",
						option.summary
					);
				}
			} else {
				assert!(
					result.options.is_empty(),
					"{name}: a query that holds has no precondition to report"
				);
			}
			checked += 1;
		}
	}
	assert!(
		checked >= 30,
		"only {checked} queries in models carrying a precondition were checked"
	);
}
#[test]
fn test_err_precondition_never_sent() {
	run_model_err(
		"err_precondition_never_sent.vp",
		"Alice never sends `e` to Carol",
	);
}
#[test]
fn test_err_precondition_undeclared_principal() {
	run_model_err(
		"err_precondition_undeclared_principal.vp",
		"`Dave` is never declared as a principal",
	);
}
#[test]
fn test_e_collection_key() {
	run_model("e_collection_key.vp", "c0a1");
}
#[test]
fn test_ringsign() {
	run_model("ringsign.vp", "a0");
}
#[test]
fn test_ringsign_substitute() {
	run_model("ringsign_substitute.vp", "a1a0a1a1");
}
#[test]
fn test_ringsign_unguarded() {
	run_model("ringsign_unguarded.vp", "a1");
}
#[test]
fn test_saltchannel() {
	run_model("saltchannel.vp", "c1");
}
#[test]
fn test_concat1() {
	run_model("concat1.vp", "c1");
}
#[test]
fn test_concat2() {
	run_model("concat2.vp", "c0");
}
#[test]
fn test_freshness() {
	run_model("freshness.vp", "f1f0");
}
#[test]
fn test_unlinkability() {
	run_model("unlinkability.vp", "u0u1u1");
}
#[test]
fn test_unlink_seed_leaked() {
	run_model("unlink_seed_leaked.vp", "u1");
}
#[test]
fn test_unlink_active_links() {
	run_model("unlink_active_links.vp", "u1");
}
#[test]
fn test_unlink_passive_holds() {
	run_model("unlink_passive_holds.vp", "u0");
}
#[test]
fn test_unlink_identical_values() {
	run_model("unlink_identical_values.vp", "u1");
}
#[test]
fn test_unlink_independent_origins() {
	run_model("unlink_independent_origins.vp", "u0");
}
#[test]
fn test_unlink_both_values_known() {
	run_model("unlink_both_values_known.vp", "u0");
}
#[test]
fn test_unlink_seed_secret() {
	run_model("unlink_seed_secret.vp", "u0");
}
#[test]
fn test_unlink_chain_forward() {
	run_model("unlink_chain_forward.vp", "u0");
}
#[test]
fn test_unlink_chain_root() {
	run_model("unlink_chain_root.vp", "u1");
}
#[test]
fn test_unlink_no_shared_ancestor() {
	run_model("unlink_no_shared_ancestor.vp", "u0");
}
#[test]
fn test_unlink_never_sent() {
	run_model("unlink_never_sent.vp", "u0");
}
#[test]
fn test_unlink_sealed() {
	run_model("unlink_sealed.vp", "u0");
}
#[test]
fn test_unlink_sealed_opened() {
	run_model("unlink_sealed_opened.vp", "u1");
}
#[test]
fn test_unlink_nonfresh_public() {
	run_model("unlink_nonfresh_public.vp", "u0");
}
#[test]
fn test_unlink_nonfresh_secret() {
	run_model("unlink_nonfresh_secret.vp", "u0");
}
#[test]
fn test_unlink_signature_links() {
	run_model("unlink_signature_links.vp", "u1");
}
#[test]
fn test_unlink_carried_in_ciphertext() {
	run_model("unlink_carried_in_ciphertext.vp", "u1u0");
}
#[test]
fn test_unlink_reassembled_chunks() {
	run_model("unlink_reassembled_chunks.vp", "c1u1u1");
}
#[test]
fn test_unlink_reassembled_chunks_one_session() {
	run_model_sessions("unlink_reassembled_chunks.vp", 1, "c1u1u1");
}
#[test]
fn test_unlink_reassembled_by_recipient() {
	run_model("unlink_reassembled_by_recipient.vp", "u1");
}
#[test]
fn test_unlink_reassembled_control_sent() {
	run_model("unlink_reassembled_control_sent.vp", "c1u1u1");
}

#[test]
fn test_unlink_signature_recognized() {
	run_model("unlink_signature_recognized.vp", "c1c0u1u0");
}

#[test]
fn test_unlink_ringsign() {
	run_model("unlink_ringsign.vp", "u0");
}
#[test]
fn test_unlink_aead_probe() {
	run_model("unlink_aead_probe.vp", "u1");
}
#[test]
fn test_unlink_blind_signature() {
	run_model("unlink_blind_signature.vp", "u0");
}
#[test]
fn test_unlink_pubkey_pseudonym() {
	run_model("unlink_pubkey_pseudonym.vp", "u1");
}
#[test]
fn test_unlink_split_concat() {
	run_model("unlink_split_concat.vp", "u1");
}
#[test]
fn test_unlink_dh_mitm() {
	run_model("unlink_dh_mitm.vp", "u1");
}
#[test]
fn test_unlink_kem_leak() {
	run_model("unlink_kem_leak.vp", "u1");
}
#[test]
fn test_unlink_phase_compromise() {
	run_model("unlink_phase_compromise.vp", "u1");
}
#[test]
fn test_unlink_phase_holds() {
	run_model("unlink_phase_holds.vp", "u0");
}
#[test]
fn test_unlink_nary_one_pair() {
	run_model("unlink_nary_one_pair.vp", "u1");
}
#[test]
fn test_unlink_kdf_outputs() {
	run_model("unlink_kdf_outputs.vp", "u0");
}
#[test]
fn test_unlink_kdf_outputs_leaked() {
	run_model("unlink_kdf_outputs_leaked.vp", "u1");
}
#[test]
fn test_unlink_injected_equality() {
	run_model("unlink_injected_equality.vp", "u0");
}
#[test]
fn test_dp3t_root_leaked() {
	run_model("dp3t_root_leaked.vp", "c1a1u1");
}
#[test]
fn test_lc_dp_3t() {
	run_model_at(
		"examples/contact-tracing/lc-dp-3t.vp",
		"lc-dp-3t.vp",
		"c0a1u0",
	);
}
#[test]
fn test_needham_schroeder_symmetric() {
	run_model_at(
		"examples/transport-layer/needham-schroeder.vp",
		"needham-schroeder.vp",
		"c1c1a1a1a1",
	);
}
#[test]
fn test_replay_pump_reflection() {
	run_model("replay_pump_reflection.vp", "c0a1");
}
#[test]
fn test_fullresolution() {
	run_model("fullresolution.vp", "c1c1c1c1c0");
}
#[test]
fn test_ql() {
	run_model("ql.vp", "c0");
}
#[test]
fn test_escore_old() {
	run_model("escore_old.vp", "c1c1");
}
#[test]
fn test_test1() {
	run_model("test1.vp", "c1c1c1a1a1a1");
}
#[test]
fn test_test2() {
	run_model("test2.vp", "c0c0c0a0a1a1");
}
#[test]
fn test_test3() {
	run_model("test3.vp", "c1c1c1a1a1a1");
}
#[test]
fn test_test4() {
	run_model("test4.vp", "c0c0c0a0a1a1e0");
}
#[test]
fn test_test5() {
	run_model("test5.vp", "c1c1c1a1a1a1");
}
#[test]
fn test_ffgg() {
	run_model("ffgg.vp", "c1");
}
#[test]
fn test_exa() {
	run_model("exa.vp", "c1");
}
#[test]
fn test_exa2() {
	run_model("exa2.vp", "c1");
}
#[test]
fn test_fakeauth() {
	run_model("fakeauth.vp", "a0");
}
#[test]
fn test_replay_simple() {
	run_model("replay-simple.vp", "a0f0");
}
#[test]
fn test_mwe() {
	run_model("mwe.vp", "c0");
}
#[test]
fn test_dh_equiv() {
	run_model("dh_equiv.vp", "c1c1c1e0");
}
#[test]
fn test_melanie_bugs() {
	run_model("melanie_bugs.vp", "c1c1c1c1c1a1");
}
#[test]
fn test_simple_equiv() {
	run_model("simple_equiv.vp", "e0");
}
#[test]
fn test_equivalence_halt_scope() {
	run_model("equivalence_halt_scope.vp", "e0");
}
#[test]
fn test_ordering_a() {
	run_model("ordering_a.vp", "c1a1");
}
#[test]
fn test_ordering_b() {
	run_model("ordering_b.vp", "c1a1");
}
#[test]
fn test_aead_leak() {
	run_model("aead_leak.vp", "c0");
}
#[test]
fn test_deep_nesting() {
	run_model("deep_nesting.vp", "c0c0c0e1a1");
}
#[test]
fn test_triple_dh() {
	run_model("triple_dh.vp", "c0c0a0e0");
}
#[test]
fn test_key_ratchet() {
	run_model("key_ratchet.vp", "c0c0c0a1a1a1");
}
#[test]
fn test_four_party() {
	run_model("four_party.vp", "c1a1a1a1");
}
#[test]
fn test_phase_forward_secrecy() {
	run_model("phase_forward_secrecy.vp", "c0a0e0");
}

#[test]
fn test_phase_tamper_then_compromise() {
	run_model("phase_tamper_then_compromise.vp", "c1c1c1c1");
}

#[test]
fn test_phase_tamper_without_compromise() {
	run_model("phase_tamper_without_compromise.vp", "c0c0");
}

#[test]
fn test_phase_tamper_compromise_three_phases() {
	run_model("phase_tamper_compromise_three_phases.vp", "c1");
}

#[test]
fn test_phase_retroactive_forgery() {
	run_model("phase_retroactive_forgery.vp", "c0a1");
}

#[test]
fn test_phase_retroactive_aead_bypass() {
	run_model("phase_retroactive_aead_bypass.vp", "c1a1");
}

#[test]
fn test_phase_signed_prekey() {
	run_model("phase_signed_prekey.vp", "c0");
}

#[test]
fn test_phase_unsigned_prekey() {
	run_model("phase_unsigned_prekey.vp", "c1");
}
#[test]
fn test_shamir_reconstruction() {
	run_model("shamir_reconstruction.vp", "c1c1e1");
}
#[test]
fn test_blind_signature() {
	run_model("blind_signature.vp", "c0c0a1");
}
#[test]
fn test_blind_signature_forgeable_with_factor() {
	run_model("blind_signature_forgeable_with_factor.vp", "c1");
}
#[test]
fn test_blind_signature_safe_without_factor() {
	run_model("blind_signature_safe_without_factor.vp", "c0");
}
#[test]
fn test_relay_not_forgery() {
	run_model("relay_not_forgery.vp", "a1");
}
#[test]
fn test_concat_bomb() {
	run_model("concat_bomb.vp", "c0c0c0c0c0a1");
}
#[test]
fn test_concat_bomb_leak() {
	run_model("concat_bomb_leak.vp", "c1c1c1c1c1a1");
}
#[test]
fn test_concat_bomb_unguarded() {
	run_model("concat_bomb_unguarded.vp", "c0c0c0c0c0a1");
}
#[test]
fn test_concat_bomb_equiv() {
	// Pinned at one session explicitly: the default is two, where this model
	// legitimately fails (test_session_concat_bomb_cross_feed).
	run_model_sessions("concat_bomb_equiv.vp", 1, "e0e0e0e0e0f0");
}
#[test]
fn test_passive_dh_chain() {
	run_model("passive_dh_chain.vp", "c0c0c0e0");
}
#[test]
fn test_double_ratchet() {
	run_model("double_ratchet.vp", "c0c0a0a0e0e0");
}
#[test]
fn test_many_principals() {
	run_model("many_principals.vp", "c1a1a1a1a1a1f0");
}
#[test]
fn test_psk_with_dh() {
	run_model("psk_with_dh.vp", "c0c0a1a1");
}
#[test]
fn test_piknik_signature_not_forgeable() {
	run_model_at(
		"examples/transport-layer/piknik.vp",
		"piknik.vp",
		"c0a0a1a1f0",
	);
}
#[test]
fn test_kem_secret_is_not_a_ciphertext() {
	run_model("kem_secret_is_not_a_ciphertext.vp", "c0");
}
#[test]
fn test_kem_real_ciphertext_still_breaks() {
	run_model("kem_real_ciphertext_still_breaks.vp", "c1");
}
#[test]
fn test_kem_secret_does_not_reveal_randomness() {
	run_model("kem_secret_does_not_reveal_randomness.vp", "c0");
}
#[test]
fn test_kem_decap_reveals_randomness() {
	run_model("kem_decap_reveals_randomness.vp", "c1c1");
}
#[test]
fn test_kem_decap_randomness_sealed() {
	run_model("kem_decap_randomness_sealed.vp", "c0c0");
}
#[test]
fn test_kem_roundtrip() {
	run_model("kem_roundtrip.vp", "c0a1");
}
#[test]
fn test_kem_signed_ct() {
	run_model("kem_signed_ct.vp", "c0a1");
}
#[test]
fn test_kem_unguarded_ek() {
	run_model("kem_unguarded_ek.vp", "c1a1");
}
#[test]
fn test_kem_static_key_no_forward_secrecy() {
	run_model("kem_static_key_no_forward_secrecy.vp", "c1c1");
}
#[test]
fn test_kem_ephemeral_forward_secrecy() {
	run_model("kem_ephemeral_forward_secrecy.vp", "c0");
}
#[test]
fn test_kem_encapsulation_randomness_leak() {
	run_model("kem_encapsulation_randomness_leak.vp", "c1c1");
}
#[test]
fn test_kem_hybrid_classical_broken() {
	run_model("kem_hybrid_classical_broken.vp", "c0");
}
#[test]
fn test_kem_hybrid_pq_broken() {
	run_model("kem_hybrid_pq_broken.vp", "c0");
}
#[test]
fn test_kem_hybrid_both_broken() {
	run_model("kem_hybrid_both_broken.vp", "c1");
}
#[test]
fn test_kem_reused_randomness() {
	run_model("kem_reused_randomness.vp", "e0e1");
}
#[test]
fn test_kem_secret_not_forgeable() {
	run_model("kem_secret_not_forgeable.vp", "c0c0");
}
#[test]
fn test_kem_checked_decap() {
	run_model("kem_checked_decap.vp", "c0a1");
}
#[test]
fn a_replayed_value_is_narrated_as_a_replay_and_not_as_a_forgery() {
	let (results, _) = crate::verify::verify("examples/test/hmac_ok.vp").expect("verify");
	let auth = results
		.iter()
		.find(|r| r.resolved)
		.expect("the authentication query fails");
	assert!(
		!auth.summary.contains("sent by Attacker"),
		"Alice did send this value, in another session; naming the attacker as its \
		 sender describes a forgery that did not happen. Narrated: {}",
		auth.summary
	);
	assert!(
		auth.summary.contains("another session"),
		"a replay is only legible if the trace says where the value came from. \
		 Narrated: {}",
		auth.summary
	);
	assert!(
		auth.summary.contains("not injective"),
		"the reader needs to be told which agreement property failed, or the \
		 verdict reads as a forgery. Narrated: {}",
		auth.summary
	);
}
#[test]
fn the_lowe_witness_replays_through_bob_before_it_learns_the_nonce() {
	let (results, _) =
		crate::verify::verify_with_sessions("examples/test/spore_ns_pk.vp", 1).expect("verify");
	let nr = results
		.iter()
		.find(|r| r.resolved && r.query.subject().is_ok_and(|c| &*c.name == "nr"))
		.expect("the confidentiality query on nr fails");
	let trace = nr.summary.as_str();
	assert!(
		!trace.contains("not a causally ordered execution"),
		"Lowe's attack has a causally ordered witness: reseal Alice@2's request to Bob, \
		 relay Bob's reply to Alice@2, then open m3@2. Narrated: {trace}"
	);
	let replays_to_bob = trace
		.lines()
		.position(|line| line.contains("replaces m1 ") && line.contains(" to Bob"));
	let learns_nr = trace.lines().position(|line| line.contains("obtaining nr"));
	let (Some(replays_to_bob), Some(learns_nr)) = (replays_to_bob, learns_nr) else {
		panic!(
			"the witness must both reseal Alice@2's request to Bob and open m3@2 for nr. \
			 Narrated: {trace}"
		);
	};
	assert!(
		replays_to_bob < learns_nr,
		"the attacker learns nr by opening m3@2, which Alice@2 only sends because the \
		 resealed request reached Bob. A trace printing the two the other way round \
		 explains the attack with a value it has not yet obtained. Narrated: {trace}"
	);
}
#[test]
fn a_signing_oracle_witness_names_the_query_that_invoked_it() {
	let (results, _) =
		crate::verify::verify("examples/test/blind_signing_oracle.vp").expect("verify");
	let open = results
		.iter()
		.find(|r| {
			r.resolved
				&& r.query
					.message
					.constant()
					.is_ok_and(|c| &*c.name == "note_open")
		})
		.expect("the note_open authentication query fails");
	assert!(
		open.summary.contains("blinded_open"),
		"the attacker holds SIGN(sk_open, nil) only because it blinded the oracle with nil \
		 first, and the delivered note_open is nil, whose own record explains nothing. A \
		 witness that omits the blinding step cannot be read in the order it is printed. \
		 Narrated: {}",
		open.summary
	);
}
#[test]
fn a_replayed_wire_value_is_stepped_as_a_replay_not_a_substitution() {
	let (results, _) = crate::verify::verify("examples/test/hmac_ok.vp").expect("verify");
	let auth = results
		.iter()
		.find(|r| r.resolved)
		.expect("the authentication query fails");
	assert!(
		auth.summary.contains("Attacker replays ciphertext"),
		"the attacker copied a value off the wire; a step saying it replaced one \
		 invites the reader to look for a forgery that is not there. Narrated: {}",
		auth.summary
	);
	assert!(
		!auth.summary.contains("Attacker replaces ciphertext"),
		"a replay and a substitution are different attacker actions and must not \
		 share a step wording. Narrated: {}",
		auth.summary
	);
}
#[test]
fn a_replay_witness_is_minimized_rather_than_disclosed_as_unconfirmed() {
	let (results, _) = crate::verify::verify("examples/test/key_ratchet.vp").expect("verify");
	let auth = results
		.iter()
		.find(|r| r.resolved && r.query.message.constant().is_ok_and(|c| &*c.name == "e1"))
		.expect("the e1 authentication query fails");
	assert!(
		!auth.summary.contains("not a minimized witness"),
		"a replay needs one install to reproduce, so falling back to the unconfirmed \
		 witness here means the minimizer has no candidate family that can express \
		 one. Narrated: {}",
		auth.summary
	);
}
#[test]
fn aead_nonce_reuse_models() {
	run_model_sessions("aead_nonce_reuse_sessions.vp", 1, "c0");
	run_model_sessions("aead_nonce_reuse_sessions.vp", 2, "c1");
	run_model_sessions("aead_nonce_fresh_sessions.vp", 1, "c0");
	run_model_sessions("aead_nonce_fresh_sessions.vp", 2, "c0");
	run_model("aead_nonce_reuse_counter.vp", "c1c1");
	run_model("aead_nonce_reuse_same_plaintext_different_ad.vp", "c1");
	run_model_sessions("aead_nonce_reuse_same_message_twice.vp", 1, "c0");
	run_model_sessions("aead_nonce_reuse_same_message_twice.vp", 2, "c0");
	run_model("aead_nonce_reuse_other_nonce_holds.vp", "c1c1c0");
	run_model("aead_nonce_needed_to_decrypt.vp", "c0");
	run_model("aead_nonce_leaked_decrypts.vp", "c1");
	run_model_err("err_aead_wrong_nonce.vp", "cannot succeed as written");
	run_model_err(
		"err_aead_three_arguments.vp",
		"takes 4 arguments, but 3 were given",
	);
	run_model_sessions("aead_nonce_reuse_forgery.vp", 1, "a1");
	run_model_sessions("aead_nonce_reuse_forgery.vp", 2, "a1");
	run_model_sessions("aead_nonce_distinct_forgery_holds.vp", 1, "a0");
	run_model_sessions("aead_nonce_reuse_attacker_supplied.vp", 1, "c0");
	run_model_sessions("aead_nonce_reuse_attacker_supplied.vp", 2, "c1");
	run_model_sessions("aead_nonce_two_executions_not_a_reuse.vp", 1, "c0");
	run_model_sessions("aead_nonce_two_executions_not_a_reuse.vp", 2, "c0");
}

#[test]
fn a_false_attack_pin_survives_at_one_session() {
	run_model_sessions("foreign_halt_no_oracle.vp", 1, "a0");
	run_model_sessions("aead_replay_not_forgery.vp", 1, "a0c0");
	run_model_sessions("relay_not_forgery.vp", 1, "a0");
	run_model_sessions("auth_with_signing_false-attack.vp", 1, "c0a1a0");
	run_model_sessions("phase_retroactive_forgery.vp", 1, "c0a0");
	let (_, code) = crate::verify::verify_with_sessions("examples/transport-layer/piknik.vp", 1)
		.expect("piknik verifies");
	assert_eq!(
		code, "c0a0a0a0f0",
		"these four models exist to pin that something is NOT a forgery. At two \
		 sessions each also admits a replay, and a replay reports a1 -- which is the \
		 same letter a regression of the original bug would report. One session has \
		 no sibling run to replay from, so it is the only place the original claim \
		 is still pinned on its own."
	);
}
#[test]
fn test_tls13_0rtt() {
	run_model_at(
		"examples/transport-layer/tls13-0rtt.vp",
		"tls13-0rtt.vp",
		"c1c0a1a0",
	);
}
#[test]
fn test_kem_freshness() {
	run_model("kem_freshness.vp", "f0f1");
}
#[test]
fn test_minimal_witness() {
	run_model("minimal_witness.vp", "c1");
}
#[test]
fn test_bypass_witness_narration() {
	run_model("bypass_witness_narration.vp", "c0a1");
}
#[test]
fn a_witness_narrates_only_actions_the_attacker_can_take() {
	let (results, _) =
		crate::verify::verify("examples/test/bypass_witness_narration.vp").expect("verify");
	let auth = results
		.iter()
		.find(|r| r.resolved)
		.expect("the authentication query fails");
	assert!(
		!auth.summary.contains("replaces decrypted_file_alice_a"),
		"decrypted_file_alice_a is Bob's own computation: no wire crosses it, so a \
		 trace claiming the attacker replaces it describes an action no attacker can \
		 take. Narrated: {}",
		auth.summary
	);
	assert!(
		auth.summary.contains("replaces g_file_alice_a_key"),
		"the forgery is only accepted because the ephemeral public key was \
		 substituted; a trace without that step hides the attack's load-bearing \
		 move. Narrated: {}",
		auth.summary
	);
	assert!(
		auth.summary.contains("is successfully used in AEAD_DEC"),
		"the value is used in Bob's decryption; naming the slot whose injected \
		 key happens to share a term reports a usage that never happened. \
		 Narrated: {}",
		auth.summary
	);
}

// ---------------------------------------------------------------------------
// Models added in the 2026-08 coverage pass. Every expected verdict below is
// argued in the corresponding model's own header comment in examples/test/,
// which is where the reasoning belongs; this file only pins the codes.
// ---------------------------------------------------------------------------
#[test]
fn test_anonymous_constants_many() {
	run_model("anonymous_constants_many.vp", "c0c0a0");
}
#[test]
fn test_assert_nested_deep() {
	run_model("assert_nested_deep.vp", "a0a1");
}
#[test]
fn test_blind_double_blinded() {
	run_model("blind_double_blinded.vp", "c1c0");
}
#[test]
fn test_blind_factor_leaked() {
	run_model("blind_factor_leaked.vp", "c1c0c0");
}
#[test]
fn test_blind_message_substituted() {
	run_model("blind_message_substituted.vp", "a1c0");
}
#[test]
fn test_blind_signing_oracle() {
	run_model("blind_signing_oracle.vp", "a1a0");
}
#[test]
fn test_blind_unblind_wrong_factor() {
	run_model("blind_unblind_wrong_factor.vp", "c0e1");
}
#[test]
fn test_broadcast_one_malicious_member() {
	run_model("broadcast_one_malicious_member.vp", "c1c0c0");
}
#[test]
fn test_cap_aead_weak_forgeable_matrix() {
	run_model("cap_aead_weak_forgeable_matrix.vp", "c1c0c1a0a1a1");
}
#[test]
fn test_cap_err_hkdf_weak() {
	run_model_err(
		"cap_err_hkdf_weak.vp",
		"HKDF does not support the `weak` parameter",
	);
}
#[test]
fn test_cap_err_mac_malleable() {
	run_model_err("cap_err_mac_malleable.vp", "did you mean `MAC[forgeable]`");
}
#[test]
fn test_cap_forgeable_cert_chain() {
	run_model("cap_forgeable_cert_chain.vp", "c1c0a1a0");
}
#[test]
fn test_cap_forgeable_mac() {
	run_model("cap_forgeable_mac.vp", "a1a0");
}
#[test]
fn test_cap_malleable_from_phase() {
	run_model("cap_malleable_from_phase.vp", "a0a1");
}
#[test]
fn test_cap_malleable_key_scoped() {
	run_model("cap_malleable_key_scoped.vp", "a1a0");
}
#[test]
fn test_cap_weak_enc() {
	run_model("cap_weak_enc.vp", "c1c0c0");
}
#[test]
fn test_cap_weak_hash_chain() {
	run_model("cap_weak_hash_chain.vp", "c1c0c1c1");
}
#[test]
fn test_cap_weak_layered_onsets() {
	run_model("cap_weak_layered_onsets.vp", "c1c1c0c0");
}
#[test]
fn test_cap_weak_pke_enc() {
	run_model("cap_weak_pke_enc.vp", "c1c0c0");
}
#[test]
fn test_cap_weak_pubkey_pke() {
	run_model("cap_weak_pubkey_pke.vp", "c1c0c1c0");
}
#[test]
fn test_checked_order_halt() {
	run_model("checked_order_halt.vp", "a1a0");
}
#[test]
fn test_concat_arity_roundtrip() {
	run_model("concat_arity_roundtrip.vp", "e0e0e0e1");
}
#[test]
fn test_concat_five_split_five() {
	run_model("concat_five_split_five.vp", "c0e0e1");
}
#[test]
fn test_concat_nested_projection() {
	run_model("concat_nested_projection.vp", "e0e1c0");
}
#[test]
fn test_cross_protocol_message_confusion() {
	run_model("cross_protocol_message_confusion.vp", "a1a0");
}
#[test]
fn test_dec_bypass_leaked_key() {
	run_model("dec_bypass_leaked_key.vp", "a1a0");
}
#[test]
fn test_dh_exponent_reuse() {
	run_model("dh_exponent_reuse.vp", "c1c0c0");
}
#[test]
fn test_dh_key_confirmation() {
	run_model("dh_key_confirmation.vp", "c0a1e1");
	run_model_sessions("dh_key_confirmation.vp", 1, "c0a0e1");
}
#[test]
fn test_dh_mitm_half_guarded() {
	run_model("dh_mitm_half_guarded.vp", "c0c1");
}
#[test]
fn test_dh_psk_hybrid() {
	run_model("dh_psk_hybrid.vp", "c0c1");
}
#[test]
fn test_dh_pubkey_leak_not_exponent() {
	run_model("dh_pubkey_leak_not_exponent.vp", "c0c0c1");
}
#[test]
fn test_dh_signed_ephemeral() {
	run_model("dh_signed_ephemeral.vp", "a1a1c0c1");
}
#[test]
fn test_dh_three_party_hub() {
	run_model("dh_three_party_hub.vp", "c1c1c0");
}
#[test]
fn test_dh_x3dh_signed_prekey() {
	run_model("dh_x3dh_signed_prekey.vp", "c0a1e1");
}
#[test]
fn test_downgrade_algorithm_choice() {
	run_model("downgrade_algorithm_choice.vp", "c1a1c0a0");
}
#[test]
fn test_eap_tunnel_channel_binding() {
	run_model("eap_tunnel_channel_binding.vp", "e0e1c0");
}
#[test]
fn test_equiv_aead_ad_mismatch() {
	run_model("equiv_aead_ad_mismatch.vp", "e0e1c0");
}
#[test]
fn test_equiv_dh_cross_principal() {
	run_model("equiv_dh_cross_principal.vp", "e0e1");
}
#[test]
fn test_equiv_kem_roundtrip() {
	run_model("equiv_kem_roundtrip.vp", "e0e1c0");
}
#[test]
fn test_equiv_pke_halt_scope() {
	run_model("equiv_pke_halt_scope.vp", "e0c0");
}
#[test]
fn test_equiv_ratchet_desync() {
	run_model("equiv_ratchet_desync.vp", "e0e1");
}
#[test]
fn test_equiv_shamir_all_pairs() {
	run_model("equiv_shamir_all_pairs.vp", "e0e0e1");
}
#[test]
fn test_relay_rewrap_oracle() {
	run_model("relay_rewrap_oracle.vp", "c1");
}
#[test]
fn test_relay_rewrap_no_oracle() {
	run_model("relay_rewrap_no_oracle.vp", "c0");
}
#[test]
fn test_equiv_forged_bundle_projections() {
	run_model("equiv_forged_bundle_projections.vp", "e1");
}
#[test]
fn test_equiv_forged_bundle_far_fields() {
	run_model_sessions("equiv_forged_bundle_far_fields.vp", 1, "e1e1e1");
}
#[test]
fn test_equiv_forged_bundle_far_fields_two_sessions() {
	run_model_sessions("equiv_forged_bundle_far_fields.vp", 2, "e1e1e1");
}
#[test]
fn test_equiv_forged_bundle_leaked_key() {
	run_model("equiv_forged_bundle_leaked_key.vp", "c1e1");
}
#[test]
fn test_equiv_sealed_bundle_holds() {
	run_model("equiv_sealed_bundle_holds.vp", "c0e0");
}
#[test]
fn test_equiv_guarded_bundle_holds() {
	run_model("equiv_guarded_bundle_holds.vp", "e0");
}
#[test]
fn test_unlink_forged_bundle_not_a_link() {
	run_model("unlink_forged_bundle_not_a_link.vp", "u0e1");
}
#[test]
fn test_equiv_three_constants() {
	run_model("equiv_three_constants.vp", "e0e1e0");
}
#[test]
fn test_equiv_unblind_roundtrip() {
	run_model("equiv_unblind_roundtrip.vp", "e0e1");
}
#[test]
fn test_flawed_anonymous_chat() {
	run_model("flawed_anonymous_chat.vp", "c1c1a1a1");
}
#[test]
fn test_flawed_blind_factor_public() {
	run_model("flawed_blind_factor_public.vp", "c1c1u1");
}
#[test]
fn test_flawed_debug_logging() {
	run_model("flawed_debug_logging.vp", "c1c1c1c1");
}
#[test]
fn test_flawed_downgrade_to_plaintext() {
	run_model("flawed_downgrade_to_plaintext.vp", "c1a1a1");
}
#[test]
fn test_flawed_encrypt_only_no_integrity() {
	run_model("flawed_encrypt_only_no_integrity.vp", "a1a1");
}
#[test]
fn test_flawed_escrow_master_key() {
	run_model("flawed_escrow_master_key.vp", "c1c1c1c1");
}
#[test]
fn test_flawed_hash_only_authentication() {
	run_model("flawed_hash_only_authentication.vp", "a1a1a1");
}
#[test]
fn test_flawed_iv_reuse_stream() {
	run_model("flawed_iv_reuse_stream.vp", "c1c1c1");
}
#[test]
fn test_flawed_kem_no_binding() {
	run_model("flawed_kem_no_binding.vp", "c1c1a1");
}
#[test]
fn test_flawed_key_from_public_data() {
	run_model("flawed_key_from_public_data.vp", "c1c1c1");
}
#[test]
fn test_flawed_nested_weak_layers() {
	run_model("flawed_nested_weak_layers.vp", "c1c1c1c1");
}
#[test]
fn test_flawed_pseudonym_reuse() {
	run_model("flawed_pseudonym_reuse.vp", "u1u1u1");
}
#[test]
fn test_flawed_psk_from_serial() {
	run_model("flawed_psk_from_serial.vp", "c1c1a1");
}
#[test]
fn test_flawed_pubkey_directory() {
	run_model("flawed_pubkey_directory.vp", "c1c1a1");
}
#[test]
fn test_flawed_ratchet_no_deletion() {
	run_model("flawed_ratchet_no_deletion.vp", "c1c1c1");
}
#[test]
fn test_flawed_resumption_ticket() {
	run_model("flawed_resumption_ticket.vp", "c1c1a1");
}
#[test]
fn test_flawed_shamir_broadcast() {
	run_model("flawed_shamir_broadcast.vp", "c1c1c1");
}
#[test]
fn test_flawed_shared_secret_broadcast() {
	run_model("flawed_shared_secret_broadcast.vp", "c1c1a1");
}
#[test]
fn test_flawed_signed_public_only() {
	run_model("flawed_signed_public_only.vp", "a1a1");
}
#[test]
fn test_flawed_static_timestamps() {
	run_model("flawed_static_timestamps.vp", "f1f1f1");
}
#[test]
fn test_flawed_trust_on_first_use() {
	run_model("flawed_trust_on_first_use.vp", "c1c1a1");
}
#[test]
fn test_forwarding_without_reencryption() {
	run_model("forwarding_without_reencryption.vp", "c1c0");
}
#[test]
fn test_freshness_concat_fields() {
	run_model("freshness_concat_fields.vp", "f0f1f0");
}
#[test]
fn test_freshness_deep_chain() {
	run_model("freshness_deep_chain.vp", "f1f0");
}
#[test]
fn test_freshness_dh_static() {
	run_model("freshness_dh_static.vp", "f1f0");
}
#[test]
fn test_freshness_hkdf_salt() {
	run_model("freshness_hkdf_salt.vp", "f0f1");
}
#[test]
fn test_freshness_kem_secret() {
	run_model("freshness_kem_secret.vp", "f0f1");
}
#[test]
fn test_freshness_shamir_share() {
	run_model("freshness_shamir_share.vp", "f1f0");
}
#[test]
fn test_freshness_unguarded_wire() {
	run_model("freshness_unguarded_wire.vp", "f0f1");
}
#[test]
fn test_guard_bypass_signverif() {
	run_model("guard_bypass_signverif.vp", "a0a1");
}
#[test]
fn test_hash_arity_distinguishes() {
	run_model("hash_arity_distinguishes.vp", "e1e1c0");
}
#[test]
fn test_hash_five_weak() {
	run_model("hash_five_weak.vp", "c1c1c0c0");
}
#[test]
fn test_hkdf_five_outputs() {
	run_model("hkdf_five_outputs.vp", "c0c1e1");
}
#[test]
fn test_hkdf_salt_swap() {
	run_model("hkdf_salt_swap.vp", "c0a1e1");
}
#[test]
fn test_identity_misbinding_uks() {
	run_model("identity_misbinding_uks.vp", "a1a1");
}
#[test]
fn test_kem_direction_reflection() {
	run_model("kem_direction_reflection.vp", "a1a0");
}
#[test]
fn test_kem_pke_hybrid() {
	run_model("kem_pke_hybrid.vp", "c0c0c1c1");
}
#[test]
fn test_kerberos_kdc_compromise() {
	run_model("kerberos_kdc_compromise.vp", "c1c1c0a1");
}
#[test]
fn test_key_reuse_sign_and_dh() {
	run_model("key_reuse_sign_and_dh.vp", "c1c0");
}
#[test]
fn test_leak_of_derived_not_root() {
	run_model("leak_of_derived_not_root.vp", "c0c1c1c0");
}
#[test]
fn test_mac_then_encrypt_order() {
	run_model("mac_then_encrypt_order.vp", "a1a0");
}
#[test]
fn test_mutual_auth_both_directions() {
	run_model("mutual_auth_both_directions.vp", "a0a1");
}
#[test]
fn test_nil_as_key() {
	run_model("nil_as_key.vp", "c1c0c1");
}
#[test]
fn test_noise_nk_anonymous_initiator() {
	run_model("noise_nk_anonymous_initiator.vp", "c0a1");
}
#[test]
fn test_noise_xx_mutual() {
	run_model("noise_xx_mutual.vp", "c1a1a1");
}
#[test]
fn test_nonce_echo_reflection() {
	run_model("nonce_echo_reflection.vp", "e0e1");
}
#[test]
fn test_oauth_code_interception() {
	run_model("oauth_code_interception.vp", "c1a0a0");
}
#[test]
fn test_otp_counter_freshness() {
	run_model("otp_counter_freshness.vp", "f1f0c0");
}
#[test]
fn test_phase_ad_reuse() {
	run_model("phase_ad_reuse.vp", "a1a0");
}
#[test]
fn test_phase_delayed_use() {
	run_model("phase_delayed_use.vp", "c1c0");
}
#[test]
fn test_phase_equiv_rotation() {
	run_model("phase_equiv_rotation.vp", "e0e1");
}
#[test]
fn test_phase_four_deep() {
	run_model("phase_four_deep.vp", "c0c1c1c1");
}
#[test]
fn test_phase_guard_dropped_later() {
	run_model("phase_guard_dropped_later.vp", "c0c1");
}
#[test]
fn test_phase_kem_harvest_later() {
	run_model("phase_kem_harvest_later.vp", "c1c0");
}
#[test]
fn test_phase_key_rotation() {
	run_model("phase_key_rotation.vp", "c0c1c1");
}
#[test]
fn test_phase_shamir_release() {
	run_model("phase_shamir_release.vp", "c1c0");
}
#[test]
fn test_phase_signing_key_leak() {
	run_model("phase_signing_key_leak.vp", "a0a1");
}
#[test]
fn test_phase_unlink_window() {
	run_model("phase_unlink_window.vp", "u1u0");
}
#[test]
fn test_pke_no_sender_authentication() {
	run_model("pke_no_sender_authentication.vp", "a1a0");
}
#[test]
fn test_pke_onion_two_layers() {
	run_model("pke_onion_two_layers.vp", "c0c1");
}
#[test]
fn test_pke_replay_wrong_recipient() {
	run_model("pke_replay_wrong_recipient.vp", "e0e1c0");
}
#[test]
fn test_pubkey_of_pubkey_rejected() {
	run_model_err(
		"pubkey_of_pubkey_rejected.vp",
		"`PUBKEY` cannot take `PUBKEY` as its first argument",
	);
}
#[test]
fn test_receipt_chain_broken_link() {
	run_model("receipt_chain_broken_link.vp", "a1a0");
}
#[test]
fn test_relay_four_hops() {
	run_model("relay_four_hops.vp", "c0a1a0");
}
#[test]
fn test_ringsign_forgeable_cap() {
	run_model("ringsign_forgeable_cap.vp", "a1a0");
}
#[test]
fn test_ringsign_ring_order() {
	run_model("ringsign_ring_order.vp", "e0e1a0");
}
#[test]
fn test_ringsign_ring_substituted() {
	run_model("ringsign_ring_substituted.vp", "a1");
}
#[test]
fn test_session_ad_binding_one_session() {
	run_model_sessions("session_ad_binding.vp", 1, "e0e0");
}
#[test]
fn test_session_ad_binding_two_sessions() {
	run_model_sessions("session_ad_binding.vp", 2, "e1e0");
}
#[test]
fn test_session_blind_stable_one_session() {
	run_model_sessions("session_blind_stable.vp", 1, "c0a0");
}
#[test]
fn test_session_blind_stable_two_sessions() {
	run_model_sessions("session_blind_stable.vp", 2, "c0a0");
}
#[test]
fn test_session_dh_static_cross_one_session() {
	run_model_sessions("session_dh_static_cross.vp", 1, "c0e0");
}
#[test]
fn test_session_dh_static_cross_two_sessions() {
	run_model_sessions("session_dh_static_cross.vp", 2, "c0e1");
}
#[test]
fn test_session_equiv_stable_one_session() {
	run_model_sessions("session_equiv_stable.vp", 1, "e0");
}
#[test]
fn test_session_equiv_stable_two_sessions() {
	run_model_sessions("session_equiv_stable.vp", 2, "e0");
}
#[test]
fn test_session_guard_stable_one_session() {
	run_model_sessions("session_guard_stable.vp", 1, "c0c1");
}
#[test]
fn test_session_guard_stable_two_sessions() {
	run_model_sessions("session_guard_stable.vp", 2, "c0c1");
}
#[test]
fn test_session_hkdf_cross_feed_one_session() {
	run_model_sessions("session_hkdf_cross_feed.vp", 1, "c0e0");
}
#[test]
fn test_session_hkdf_cross_feed_two_sessions() {
	run_model_sessions("session_hkdf_cross_feed.vp", 2, "c0e1");
}
#[test]
fn test_session_mac_key_rotation_one_session() {
	run_model_sessions("session_mac_key_rotation.vp", 1, "e0e0");
}
#[test]
fn test_session_mac_key_rotation_two_sessions() {
	run_model_sessions("session_mac_key_rotation.vp", 2, "e1e0");
}
#[test]
fn test_session_pke_cross_feed_one_session() {
	run_model_sessions("session_pke_cross_feed.vp", 1, "c0e0");
}
#[test]
fn test_session_pke_cross_feed_two_sessions() {
	run_model_sessions("session_pke_cross_feed.vp", 2, "c0e1");
}
#[test]
fn test_session_ringsign_stable_one_session() {
	run_model_sessions("session_ringsign_stable.vp", 1, "a0");
}
#[test]
fn test_session_ringsign_stable_two_sessions() {
	run_model_sessions("session_ringsign_stable.vp", 2, "a1");
}
#[test]
fn test_session_shamir_dealer_cross_one_session() {
	run_model_sessions("session_shamir_dealer_cross.vp", 1, "c0");
}
#[test]
fn test_session_shamir_dealer_cross_two_sessions() {
	run_model_sessions("session_shamir_dealer_cross.vp", 2, "c0");
}
#[test]
fn test_session_sign_oracle_cross_one_session() {
	run_model_sessions("session_sign_oracle_cross.vp", 1, "a0");
}
#[test]
fn test_session_sign_oracle_cross_two_sessions() {
	run_model_sessions("session_sign_oracle_cross.vp", 2, "a0");
}
#[test]
fn test_session_three_party_relay_one_session() {
	run_model_sessions("session_three_party_relay.vp", 1, "c0a0");
}
#[test]
fn test_session_three_party_relay_two_sessions() {
	run_model_sessions("session_three_party_relay.vp", 2, "c0a1");
}
#[test]
fn test_shamir_cross_dealer_join() {
	run_model("shamir_cross_dealer_join.vp", "c0c0e1");
}
#[test]
fn test_shamir_escrow_dh() {
	run_model("shamir_escrow_dh.vp", "c1c1");
}
#[test]
fn test_shamir_join_same_share() {
	run_model("shamir_join_same_share.vp", "c0c1");
}
#[test]
fn test_shamir_outer_shares() {
	run_model("shamir_outer_shares.vp", "c1c0");
}
#[test]
fn test_sigma_i() {
	run_model("sigma_i.vp", "c0a0a0e1");
}
#[test]
fn test_signverif_unchecked() {
	run_model("signverif_unchecked.vp", "a0a1");
}
#[test]
fn test_split_narrower_than_concat() {
	run_model("split_narrower_than_concat.vp", "e0e0e1c0");
}
#[test]
fn test_split_stuck_halts() {
	run_model("split_stuck_halts.vp", "a0a1");
}
#[test]
fn test_station_to_station() {
	run_model("station_to_station.vp", "c0c0a0a0e1");
}
#[test]
fn test_station_to_station_unsigned() {
	run_model("station_to_station_unsigned.vp", "c1c1a1a1");
}
#[test]
fn test_two_phase_commit_forged_ack() {
	run_model("two_phase_commit_forged_ack.vp", "a1a0");
}
#[test]
fn test_unlink_blind_active() {
	run_model("unlink_blind_active.vp", "u1u0");
}
#[test]
fn test_unlink_kem_decap_identifying() {
	run_model("unlink_kem_decap_identifying.vp", "u1u0");
}
#[test]
fn test_unlink_pke_recipient() {
	run_model("unlink_pke_recipient.vp", "u1u0");
}
#[test]
fn test_unlink_shamir_origin() {
	run_model("unlink_shamir_origin.vp", "u1u0");
}
#[test]
fn test_webauthn_origin_binding() {
	run_model("webauthn_origin_binding.vp", "e0e1");
}
#[test]
fn test_wireguard_static_fetched() {
	run_model("wireguard_static_fetched.vp", "c1a1");
}

#[test]
fn the_json_report_carries_query_ranges_and_step_kinds() {
	let (report, source) =
		crate::verify::verify_report_with_source("examples/test/hmac_ok.vp", 2).expect("verifies");
	let run = crate::report::Run::of(
		"test",
		&[("examples/test/hmac_ok.vp".to_string(), Ok(report))],
		std::slice::from_ref(&source),
	);
	let json = serde_json::to_string(&run).expect("serializes");
	assert!(json.contains(r#""ok":true"#), "{json}");
	assert!(json.contains(r#""range":{"start":"#), "{json}");
	assert!(json.contains(r#""kind":"confidentiality""#), "{json}");
	assert!(
		!json.contains(r#""Query":"#),
		"old capitalised keys are gone: {json}"
	);
}
#[test]
fn test_forged_key_swap_bare() {
	run_model("forged_key_swap_bare.vp", "c1");
}
#[test]
fn test_forged_key_swap_bare_one_session() {
	run_model_sessions("forged_key_swap_bare.vp", 1, "c1");
}
#[test]
fn test_forged_key_swap_bundled() {
	run_model("forged_key_swap_bundled.vp", "c1c0");
}
#[test]
fn test_forged_key_swap_bundled_one_session() {
	run_model_sessions("forged_key_swap_bundled.vp", 1, "c1c0");
}
#[test]
fn test_witness_key_swap_bundled() {
	run_model("witness_key_swap_bundled.vp", "e0");
}
#[test]
fn test_forged_statement_rebuilt() {
	run_model("forged_statement_rebuilt.vp", "c1c1");
}
#[test]
fn test_forged_statement_rebuilt_one_session() {
	run_model_sessions("forged_statement_rebuilt.vp", 1, "c1c1");
}
#[test]
fn test_witness_statement_rebuilt() {
	run_model("witness_statement_rebuilt.vp", "e0");
}
#[test]
fn test_forged_statement_on_wire() {
	run_model("forged_statement_on_wire.vp", "c1c1");
}
#[test]
fn test_relay_halt_before_forward() {
	run_model("relay_halt_before_forward.vp", "a0");
}
#[test]
fn test_relay_halt_before_forward_one_session() {
	run_model_sessions("relay_halt_before_forward.vp", 1, "a0");
}
#[test]
fn test_relay_forward_before_check() {
	run_model("relay_forward_before_check.vp", "a1");
}
#[test]
fn test_relay_forward_before_check_one_session() {
	run_model_sessions("relay_forward_before_check.vp", 1, "a1");
}
#[test]
fn test_relay_halt_before_forward_leaked() {
	run_model("relay_halt_before_forward_leaked.vp", "a1");
}
#[test]
fn test_relay_halt_before_forward_leaked_one_session() {
	run_model_sessions("relay_halt_before_forward_leaked.vp", 1, "a1");
}
