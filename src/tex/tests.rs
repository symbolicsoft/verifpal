/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::*;
use crate::report::{
	Assumption, Binding, DiagramRow, DiagramValue, EnvelopeReport, ScenarioReport, SourceRange,
};
use crate::types::TraceValue;

const GOLDEN_SOURCE: &str = concat!(
	"attacker[active]\n\n",
	"principal Alice[\n\tgenerates a\n\tga = PUBKEY(a)\n\tknows private m\n",
	"\te = AEAD_ENC(k, m, ad)\n]\n\n",
	"Alice -> Bob: [ga], e\n\n",
	"phase[1]\n\n",
	"principal Bob[\n\tleaks b\n\td = AEAD_DEC(k, e, ad)?\n]\n\n",
	"queries[\n\tconfidentiality? m\n\tauthentication? Alice -> Bob: e\n]\n"
);

fn envelope(summary: &str, truncations: Vec<String>) -> EnvelopeReport {
	EnvelopeReport {
		sessions: 2,
		exhausted: truncations.is_empty(),
		truncations,
		summary: summary.to_string(),
	}
}

fn step(kind: &str, text: &str) -> ReportStep {
	ReportStep::new(kind.to_string(), text.to_string())
}

fn golden_run() -> Run {
	let mut broken = QueryReport {
		query: "confidentiality? m".to_string(),
		kind: "confidentiality".to_string(),
		resolved: true,
		envelope: envelope("search exhausted at 2 sessions", vec![]),
		range: SourceRange {
			start: 0,
			end: 18,
			line: 15,
			column: 2,
		},
		summary: "m is obtained by Attacker.".to_string(),
		conclusion: "m is obtained by Attacker, so confidentiality? m does not hold.".to_string(),
		steps: vec![],
		preconditions: vec!["Bob sends ack to Alice despite the query failing".to_string()],
		variants: 1,
	};
	broken.steps = vec![
		step("derive", "Attacker constructs PUBKEY(nil) from nil."),
		step("derive", "Attacker obtains ga on the wire."),
		ReportStep {
			kind: "mutations".to_string(),
			text: "Attacker replaces ga with PUBKEY(nil).".to_string(),
			sender: Some("Alice".to_string()),
			recipient: Some("Bob".to_string()),
			principal: None,
			values: vec![
				TraceValue {
					name: "ga".to_string(),
					installed: Some("PUBKEY(nil)".to_string()),
					was: Some("PUBKEY(a)".to_string()),
					guarded: true,
				},
				TraceValue {
					name: "e".to_string(),
					installed: Some("e".to_string()),
					was: Some("e".to_string()),
					guarded: false,
				},
			],
		},
		ReportStep {
			kind: "gate".to_string(),
			text: "Bob's AEAD_DEC(k, e, ad)? check passes on an attacker-controlled key."
				.to_string(),
			sender: None,
			recipient: None,
			principal: Some("Bob".to_string()),
			values: vec![],
		},
		ReportStep {
			kind: "bypass".to_string(),
			text: "Alice's SIGNVERIF check is defeated, accepting PUBKEY(nil).".to_string(),
			sender: None,
			recipient: None,
			principal: Some("Alice".to_string()),
			values: vec![],
		},
		step(
			"derive",
			"Attacker computes DH_KEX(PUBKEY(a), nil), obtaining k.",
		),
		step("derive", "Attacker decrypts e, obtaining m."),
	];
	let holding = QueryReport {
		query: "authentication? Alice -> Bob: e".to_string(),
		kind: "authentication".to_string(),
		resolved: false,
		envelope: envelope(
			"search truncated: term depth",
			vec!["term depth".to_string()],
		),
		range: SourceRange {
			start: 20,
			end: 51,
			line: 16,
			column: 2,
		},
		summary: String::new(),
		conclusion: String::new(),
		steps: vec![],
		preconditions: vec![],
		variants: 1,
	};
	let analysis = Analysis {
		model: "golden.vp".to_string(),
		attacker: "active".to_string(),
		sessions: 2,
		code: "c1a0".to_string(),
		attacks: 1,
		elapsed_ms: 12,
		assumptions: vec![Assumption {
			term: "HASH(m)".to_string(),
			capability: "weak".to_string(),
			from_phase: 2,
		}],
		scenarios: vec![ScenarioReport {
			principal: "Alice".to_string(),
			bindings: vec![Binding {
				target: "gpeer".to_string(),
				value: "gm".to_string(),
			}],
			honest: false,
		}],
		notes: vec!["Per-session values and principals carry the suffix #2.".to_string()],
		provenance: vec![
			"--saturate raised the session count until the verdicts stopped moving.".to_string(),
		],
		queries: vec![broken, holding],
	};
	Run {
		version: "0.0.0".to_string(),
		ok: true,
		models: vec![ModelReport {
			file: "examples/test/golden.vp".to_string(),
			ok: true,
			error: None,
			analysis: Some(analysis),
			diagram: vec![
				DiagramRow::Message {
					hop: 1,
					phase: 0,
					sender: "Alice".to_string(),
					recipient: "Bob".to_string(),
					values: vec![
						DiagramValue {
							name: "ga".to_string(),
							guarded: true,
						},
						DiagramValue {
							name: "e".to_string(),
							guarded: false,
						},
					],
				},
				DiagramRow::Phase { number: 1 },
				DiagramRow::Leak {
					principal: "Bob".to_string(),
					values: vec!["b".to_string()],
				},
			],
			source: GOLDEN_SOURCE.to_string(),
			tokens: Vec::new(),
		}],
	}
}

fn corpus() -> Vec<String> {
	let mut out: Vec<String> = std::fs::read_dir("examples/test")
		.expect("examples/test")
		.filter_map(|e| e.ok())
		.map(|e| e.path())
		.filter(|p| p.extension().is_some_and(|x| x == "vp"))
		.map(|p| p.to_string_lossy().into_owned())
		.collect();
	out.sort();
	out
}

fn run_of(path: &str) -> Run {
	match crate::verify::verify_report_with_source(path, 1) {
		Ok((report, source)) => Run::of(
			"0.0.0",
			&[(path.to_string(), Ok(report))],
			std::slice::from_ref(&source),
		),
		Err(e) => {
			let source = std::fs::read_to_string(path).unwrap_or_default();
			Run::of(
				"0.0.0",
				&[(path.to_string(), Err(e.to_string()))],
				std::slice::from_ref(&source),
			)
		}
	}
}

fn braces_balance(tex: &str) -> bool {
	let bytes = tex.as_bytes();
	let mut depth: i64 = 0;
	for (i, b) in bytes.iter().enumerate() {
		let escaped = i > 0 && bytes[i - 1] == b'\\';
		match b {
			b'{' if !escaped => depth += 1,
			b'}' if !escaped => depth -= 1,
			_ => {}
		}
		if depth < 0 {
			return false;
		}
	}
	depth == 0
}

fn markers_pair(tex: &str) -> bool {
	tex.matches("%% --- BEGIN verifpal").count() == tex.matches("%% --- END verifpal").count()
}

fn labels(tex: &str) -> Vec<String> {
	let mut out = Vec::new();
	for chunk in tex.split("\\label{").skip(1) {
		if let Some(end) = chunk.find('}') {
			out.push(chunk[..end].to_string());
		}
	}
	out
}

#[test]
fn the_rendered_document_matches_its_golden_file() {
	let tex = tex_report(&golden_run());
	let path = "examples/test/golden_tex/report.tex";
	if std::env::var("VERIFPAL_BLESS_TEX").is_ok() {
		std::fs::create_dir_all("examples/test/golden_tex").expect("golden dir");
		std::fs::write(path, &tex).expect("writes the golden file");
	}
	let golden = std::fs::read_to_string(path).expect("the golden document exists");
	assert_eq!(
		tex, golden,
		"the rendered document drifted from its golden file; \
		 re-bless with VERIFPAL_BLESS_TEX=1 once the change is deliberate"
	);
}

#[test]
fn every_model_in_the_corpus_renders_a_sound_document() {
	let paths = corpus();
	assert!(paths.len() > 300, "corpus looks wrong: {}", paths.len());
	for path in &paths {
		let tex = tex_report(&run_of(path));
		assert!(!tex.contains("<<"), "{path} left a placeholder unfilled");
		assert!(braces_balance(&tex), "{path} renders unbalanced braces");
		assert!(markers_pair(&tex), "{path} has an unpaired fragment marker");
		assert_eq!(
			tex.matches("\\begin{document}").count(),
			1,
			"{path} is not one document"
		);
		assert_eq!(
			tex.matches("\\begin{vpdiagram}").count(),
			tex.matches("\\end{vpdiagram}").count(),
			"{path} has an unbalanced diagram"
		);
		assert_eq!(
			tex.matches("\\begin{lstlisting}").count(),
			tex.matches("\\end{lstlisting}").count(),
			"{path} has an unbalanced listing"
		);
		let present = labels(&tex);
		let mut seen = present.clone();
		seen.sort();
		let count = seen.len();
		seen.dedup();
		assert_eq!(count, seen.len(), "{path} repeats a label");
	}
}

#[test]
fn a_whole_run_renders_one_document_with_a_summary_table() {
	let paths: Vec<String> = corpus().into_iter().take(4).collect();
	let mut outcomes = Vec::new();
	let mut sources = Vec::new();
	for path in &paths {
		match crate::verify::verify_report_with_source(path, 1) {
			Ok((report, source)) => {
				outcomes.push((path.clone(), Ok(report)));
				sources.push(source);
			}
			Err(e) => {
				outcomes.push((path.clone(), Err(e.to_string())));
				sources.push(String::new());
			}
		}
	}
	let tex = tex_report(&Run::of("0.0.0", &outcomes, &sources));
	assert!(tex.contains("\\section{Summary}"), "no summary section");
	assert!(tex.contains("\\label{tab:summary}"), "no summary table");
	assert_eq!(tex.matches("\\begin{document}").count(), 1);
	assert!(braces_balance(&tex));
}

#[test]
fn no_latex_is_written_in_rust() {
	for file in ["mod.rs", "math.rs"] {
		let source = std::fs::read_to_string(format!("src/tex/{file}")).expect("reads");
		for (n, line) in source.lines().enumerate() {
			if line.trim_start().starts_with("//") {
				continue;
			}
			for banned in [
				"\\\\begin{",
				"\\\\end{",
				"\\\\usepackage",
				"\\\\documentclass",
			] {
				assert!(
					!line.contains(banned),
					"src/tex/{file}:{} writes {banned} in Rust; it belongs in a template",
					n + 1
				);
			}
		}
	}
}

#[test]
fn the_document_never_claims_a_proof() {
	let tex = tex_report(&golden_run());
	let prose = tex
		.lines()
		.filter(|line| !line.trim_start().starts_with('%'))
		.collect::<Vec<&str>>()
		.join("\n")
		.to_lowercase();
	for banned in [
		"proven",
		"is verified",
		"is complete",
		"proof of correctness",
	] {
		assert!(
			!prose.contains(banned),
			"the document claims '{banned}', which Verifpal does not establish"
		);
	}
	assert!(
		prose.contains("not a proof that none exists"),
		"the soundness disclaimer went missing"
	);
}

#[test]
fn every_term_in_the_corpus_round_trips_through_the_math_parser() {
	let mut seen = 0usize;
	for path in corpus().into_iter().take(80) {
		let run = run_of(&path);
		let Some(a) = run.models[0].analysis.as_ref() else {
			continue;
		};
		for q in &a.queries {
			for s in &q.steps {
				for v in &s.values {
					for text in [Some(&v.name), v.installed.as_ref(), v.was.as_ref()]
						.into_iter()
						.flatten()
					{
						seen += 1;
						assert!(
							math::parse(text).is_some(),
							"{path}: the math parser cannot read {text:?}"
						);
					}
				}
			}
		}
	}
	assert!(seen > 100, "only {seen} terms were exercised");
}

#[test]
fn every_non_ascii_character_the_engine_emits_has_a_tex_spelling() {
	for path in corpus().into_iter().take(120) {
		let tex = tex_report(&run_of(&path));
		for c in tex.chars() {
			assert!(
				c.is_ascii() || crate::template::tex_spelling(c).is_some(),
				"{path} emits {c:?} (U+{:04X}), which has no TeX spelling",
				c as u32
			);
		}
	}
}

#[test]
fn every_shipped_template_parses_to_something() {
	for template in every_template() {
		assert!(
			!template.is_empty(),
			"{} parsed to nothing",
			template.name()
		);
	}
}

#[test]
fn every_partial_reference_names_a_template_that_exists() {
	for template in every_template() {
		for name in template.partials() {
			assert!(
				partial(name).is_some(),
				"{} includes unknown partial '{name}'",
				template.name()
			);
		}
	}
}

#[test]
fn a_failed_model_is_reported_inside_the_document() {
	let run = Run::of(
		"0.0.0",
		&[("broken.vp".to_string(), Err("parse error: 100% bad".into()))],
		&[String::new()],
	);
	let tex = tex_report(&run);
	assert!(tex.contains("parse error: 100\\% bad"), "{tex}");
	assert!(braces_balance(&tex));
}

#[test]
fn the_golden_document_compiles_under_tectonic() {
	if std::env::var("VERIFPAL_TECTONIC").is_err() {
		return;
	}
	let tectonic = which_tectonic().expect(
		"VERIFPAL_TECTONIC is set but no tectonic binary was found on PATH; \
		 this test does not skip silently",
	);
	let dir = std::env::temp_dir().join(format!("verifpal-tex-{}", std::process::id()));
	std::fs::create_dir_all(&dir).expect("scratch dir");
	let mut documents: Vec<(String, String)> =
		vec![("golden".to_string(), tex_report(&golden_run()))];
	for path in [
		"examples/test/hmac_ok.vp",
		"examples/test/spore_ns_pk.vp",
		"examples/test/junglegym_threshold_ring.vp",
		"examples/simple.vp",
	] {
		documents.push((path.replace(['/', '.'], "_"), tex_report(&run_of(path))));
	}
	for (name, tex) in documents {
		let file = dir.join(format!("{name}.tex"));
		std::fs::write(&file, &tex).expect("writes the document");
		let out = std::process::Command::new(&tectonic)
			.arg("-X")
			.arg("compile")
			.arg("--outdir")
			.arg(&dir)
			.arg(&file)
			.output()
			.expect("runs tectonic");
		assert!(
			out.status.success(),
			"{name}.tex did not compile:\n{}",
			String::from_utf8_lossy(&out.stderr)
				.lines()
				.rev()
				.take(30)
				.collect::<Vec<&str>>()
				.join("\n")
		);
	}
}

fn which_tectonic() -> Option<String> {
	let path = std::env::var("PATH").ok()?;
	for dir in path.split(':') {
		let candidate = std::path::Path::new(dir).join("tectonic");
		if candidate.is_file() {
			return Some(candidate.to_string_lossy().into_owned());
		}
	}
	None
}
