/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::*;
use crate::verify::TraceValue;

#[test]
fn a_report_serializes_to_the_documented_shape() {
	let run = Run {
		version: "1.0.4".to_string(),
		ok: true,
		models: vec![ModelReport {
			file: "examples/simple.vp".to_string(),
			ok: true,
			error: None,
			diagram: Vec::new(),
			source: String::new(),
			tokens: Vec::new(),
			analysis: Some(Analysis {
				model: "simple.vp".to_string(),
				attacker: "active".to_string(),
				sessions: 2,
				code: "c1".to_string(),
				attacks: 1,
				elapsed_ms: 3,
				scenarios: Vec::new(),
				notes: Vec::new(),
				provenance: Vec::new(),
				assumptions: vec![Assumption {
					term: "HASH(m)".to_string(),
					capability: "weak".to_string(),
					from_phase: 0,
				}],
				queries: vec![QueryReport {
					query: "confidentiality? m1".to_string(),
					kind: "confidentiality".to_string(),
					resolved: true,
					envelope: EnvelopeReport {
						sessions: 2,
						truncations: vec![],
						exhausted: true,
						summary: "search exhausted at 2 sessions".to_string(),
					},
					range: SourceRange {
						start: 120,
						end: 141,
						line: 21,
						column: 2,
					},
					summary: "m1 is obtained by Attacker.".to_string(),
					conclusion: "m1 is obtained by Attacker.".to_string(),
					subtype: None,
					steps: vec![
						TraceStep::new(
							"derive",
							"Attacker constructs PUBKEY(nil) from nil.".to_string(),
						),
						TraceStep {
							kind: "mutations",
							text: "Attacker replaces ga with PUBKEY(nil).".to_string(),
							sender: Some("Alice".to_string()),
							recipient: Some("Bob".to_string()),
							principal: None,
							values: vec![TraceValue {
								name: "ga".to_string(),
								installed: Some("PUBKEY(nil)".to_string()),
								was: Some("PUBKEY(a)".to_string()),
								guarded: false,
							}],
						},
					],
					preconditions: vec![],
					generated: false,
					variants: 2,
				}],
			}),
		}],
	};

	let json = serde_json::to_string(&run).expect("serializes");
	let expected = concat!(
		r#"{"version":"1.0.4","ok":true,"models":[{"file":"examples/simple.vp","#,
		r#""ok":true,"analysis":{"model":"simple.vp","attacker":"active","sessions":2,"code":"c1","#,
		r#""attacks":1,"elapsedMs":3,"assumptions":[{"term":"HASH(m)","#,
		r#""capability":"weak","fromPhase":0}],"queries":[{"#,
		r#""query":"confidentiality? m1","kind":"confidentiality","resolved":true,"#,
		r#""envelope":{"sessions":2,"truncations":[],"exhausted":true,"#,
		r#""summary":"search exhausted at 2 sessions"},"#,
		r#""range":{"start":120,"end":141,"line":21,"column":2},"#,
		r#""summary":"m1 is obtained by Attacker.","#,
		r#""conclusion":"m1 is obtained by Attacker.","#,
		r#""steps":[{"kind":"derive","#,
		r#""text":"Attacker constructs PUBKEY(nil) from nil."},"#,
		r#"{"kind":"mutations","text":"Attacker replaces ga with PUBKEY(nil).","#,
		r#""sender":"Alice","recipient":"Bob","values":[{"name":"ga","#,
		r#""installed":"PUBKEY(nil)","was":"PUBKEY(a)"}]}],"#,
		r#""preconditions":[],"variants":2}]}}]}"#,
	);
	assert_eq!(json, expected);
}

#[test]
fn a_query_report_points_at_the_query_in_the_source() {
	let report = crate::verify::verify_report("examples/test/hmac_ok.vp", 2).expect("verifies");
	let source = std::fs::read_to_string("examples/test/hmac_ok.vp").expect("reads");
	let run = Run::of(
		"1.0.4",
		&[("examples/test/hmac_ok.vp".to_string(), Ok(report))],
		std::slice::from_ref(&source),
	);

	let analysis = run.models[0].analysis.as_ref().expect("an analysis");
	assert_eq!(analysis.queries.len(), 2);

	let first = &analysis.queries[0];
	assert_eq!(first.kind, "confidentiality");
	let line = source
		.lines()
		.nth(first.range.line - 1)
		.expect("the reported line exists");
	assert!(
		line.contains("confidentiality?"),
		"range points at {:?}",
		line
	);
	assert!(
		source[first.range.start..first.range.end].starts_with("confidentiality"),
		"span quotes {:?}",
		&source[first.range.start..first.range.end]
	);
}

#[test]
fn a_report_lists_declared_assumptions() {
	let src = "attacker[passive]\n\
		principal Alice[\n\
		knows private rcap_m\n\
		rcap_h = HASH[weak](rcap_m)\n\
		]\n\
		Alice -> Bob: rcap_h\n\
		principal Bob[\n\
		_ = HASH(rcap_h)\n\
		]\n\
		queries[\n\
		confidentiality? rcap_m\n\
		]\n";
	let m = crate::syntax::parser::parse_string("rcap.vp", src).expect("parses");
	let ctx = crate::verify::analyze(&m).expect("analyzes");
	let assumptions = ctx.assumptions();
	assert_eq!(assumptions.len(), 1);
	assert_eq!(assumptions[0].1.name(), "weak");
}

#[test]
fn a_report_lists_each_declared_assumption_once_as_written() {
	let src = "attacker[active]\n\
		principal Carol[\n\
		knows private ronce_c\n\
		ronce_gc = PUBKEY(ronce_c)\n\
		]\n\
		principal Bob[\n\
		knows private ronce_b\n\
		ronce_gb = PUBKEY(ronce_b)\n\
		]\n\
		Carol -> Alice: [ronce_gc]\n\
		Bob -> Alice: [ronce_gb]\n\
		principal Alice[\n\
		knows public ronce_peer\n\
		generates ronce_m\n\
		ronce_h = HASH[weak](ronce_peer, ronce_m)\n\
		ronce_g = HASH[weak from phase 1](HASH(ronce_m, ronce_m))\n\
		]\n\
		Alice -> Bob: ronce_h, ronce_g\n\
		phase[1]\n\
		principal Bob[\n\
		leaks ronce_b\n\
		]\n\
		scenarios[\n\
		Alice[ronce_peer = ronce_gc]\n\
		Alice[ronce_peer = ronce_gb]\n\
		]\n\
		queries[\n\
		confidentiality? ronce_m\n\
		]\n";
	let m = crate::syntax::parser::parse_string("ronce.vp", src).expect("parses");
	let ctx = crate::verify::analyze(&m).expect("analyzes");
	let listed: Vec<(String, &str, i32)> = ctx
		.assumptions()
		.iter()
		.map(|(term, cap, onset)| (term.to_string(), cap.name(), *onset))
		.collect();
	assert_eq!(
		listed,
		vec![
			("HASH[weak](ronce_peer, ronce_m)".to_string(), "weak", 0),
			(
				"HASH[weak from phase 1](HASH(ronce_m, ronce_m))".to_string(),
				"weak",
				1
			),
		]
	);
}

#[test]
fn a_merged_assumption_names_each_capability_at_its_earliest_onset() {
	let listed = |name: &str, body: &str, phases: &str| -> Vec<(String, &'static str, i32)> {
		let src = format!(
			"attacker[passive]\nprincipal Alice[\n\
			 knows private rmerge_k, rmerge_m, rmerge_p\n{body}]\n{phases}\
			 queries[\nconfidentiality? rmerge_p\n]\n"
		);
		let m = crate::syntax::parser::parse_string(name, &src).expect("parses");
		crate::verify::analyze(&m)
			.expect("analyzes")
			.assumptions()
			.iter()
			.map(|(term, cap, onset)| (term.to_string(), cap.name(), *onset))
			.collect()
	};
	let onset = vec![("HASH[weak](rmerge_m)".to_string(), "weak", 0)];
	assert_eq!(
		listed(
			"rmerge1.vp",
			"rmerge_a = HASH[weak from phase 1](rmerge_m)\nrmerge_b = HASH[weak](rmerge_m)\n",
			"phase[1]\n",
		),
		onset
	);
	assert_eq!(
		listed(
			"rmerge2.vp",
			"rmerge_a = HASH[weak](rmerge_m)\nrmerge_b = HASH[weak from phase 1](rmerge_m)\n",
			"phase[1]\n",
		),
		onset
	);
	let capabilities = vec![
		("ENC[weak](rmerge_k, rmerge_m)".to_string(), "weak", 0),
		(
			"ENC[malleable](rmerge_k, rmerge_m)".to_string(),
			"malleable",
			0,
		),
	];
	assert_eq!(
		listed(
			"rmerge3.vp",
			"rmerge_a = ENC[weak](rmerge_k, rmerge_m)\n\
			 rmerge_b = ENC[malleable](rmerge_k, rmerge_m)\n",
			"",
		),
		capabilities
	);
	assert_eq!(
		listed(
			"rmerge4.vp",
			"rmerge_a = ENC[malleable](rmerge_k, rmerge_m)\n\
			 rmerge_b = ENC[weak](rmerge_k, rmerge_m)\n",
			"",
		),
		capabilities
	);
	assert_eq!(
		listed(
			"rmerge5.vp",
			"rmerge_a = ENC[weak](HASH[weak from phase 1](rmerge_k), rmerge_m)\n\
			 rmerge_b = HASH[weak](rmerge_k)\n",
			"phase[1]\n",
		),
		vec![
			("ENC[weak](HASH(rmerge_k), rmerge_m)".to_string(), "weak", 0),
			("HASH[weak](rmerge_k)".to_string(), "weak", 0),
		]
	);
}

#[test]
fn a_report_omits_assumptions_when_none_are_declared() {
	let src = "attacker[passive]\n\
		principal Alice[\n\
		knows private rnoc_m\n\
		rnoc_h = HASH(rnoc_m)\n\
		]\n\
		Alice -> Bob: rnoc_h\n\
		principal Bob[\n\
		_ = HASH(rnoc_h)\n\
		]\n\
		queries[\n\
		confidentiality? rnoc_m\n\
		]\n";
	let m = crate::syntax::parser::parse_string("rnoc.vp", src).expect("parses");
	let ctx = crate::verify::analyze(&m).expect("analyzes");
	assert!(ctx.assumptions().is_empty());
}

#[test]
fn an_analysis_explains_the_session_suffix_its_traces_use() {
	let path = "examples/test/session_replay_breaks_injectivity.vp";
	let report = crate::verify::verify_report(path, 2).expect("verifies");
	let source = std::fs::read_to_string(path).expect("reads");
	let a = Analysis::of(&report, &source);
	assert!(
		a.notes.iter().any(|n| n.contains("#2")),
		"notes were {:?}",
		a.notes
	);
}

#[test]
fn an_analysis_explains_the_scenario_suffix_its_traces_use() {
	let path = "examples/test/spore_ns_pk.vp";
	let report = crate::verify::verify_report(path, 2).expect("verifies");
	let source = std::fs::read_to_string(path).expect("reads");
	let a = Analysis::of(&report, &source);
	assert!(
		a.notes.iter().any(|n| n.contains("@2")),
		"notes were {:?}",
		a.notes
	);
}

#[test]
fn an_analysis_whose_traces_never_use_a_suffix_explains_none() {
	let path = "examples/test/relay_rewrap_oracle.vp";
	let report = crate::verify::verify_report(path, 2).expect("verifies");
	let source = std::fs::read_to_string(path).expect("reads");
	let a = Analysis::of(&report, &source);
	assert!(
		!a.notes.iter().any(|n| n.contains("suffix")),
		"nothing in this report carries a suffix, but it was explained anyway: {:?}",
		a.notes
	);
}

#[test]
fn an_analysis_that_uses_no_suffix_explains_nothing() {
	let path = "examples/test/hmac_ok.vp";
	let report = crate::verify::verify_report(path, 1).expect("verifies");
	let source = std::fs::read_to_string(path).expect("reads");
	let a = Analysis::of(&report, &source);
	assert!(a.notes.is_empty(), "notes were {:?}", a.notes);
}

#[test]
fn an_analysis_reports_a_truncated_search_once_for_the_whole_run() {
	let mut report = crate::verify::verify_report("examples/test/hmac_ok.vp", 1).expect("verifies");
	report.results[0]
		.envelope
		.truncations
		.push(crate::verify::Truncation::TermDepth);
	let a = Analysis::of(&report, "");
	let hits: Vec<&String> = a
		.notes
		.iter()
		.filter(|n| n.contains("term depth"))
		.collect();
	assert_eq!(hits.len(), 1, "notes were {:?}", a.notes);
}

#[test]
fn a_failed_model_reports_its_error_and_no_analysis() {
	let run = Run {
		version: "1.0.4".to_string(),
		ok: false,
		models: vec![ModelReport {
			file: "broken.vp".to_string(),
			ok: false,
			error: Some("parse error: expected `]`".to_string()),
			analysis: None,
			diagram: Vec::new(),
			source: String::new(),
			tokens: Vec::new(),
		}],
	};
	let json = serde_json::to_string(&run).expect("serializes");
	assert_eq!(
		json,
		concat!(
			r#"{"version":"1.0.4","ok":false,"models":[{"file":"broken.vp","#,
			r#""ok":false,"error":"parse error: expected `]`"}]}"#,
		)
	);
}
