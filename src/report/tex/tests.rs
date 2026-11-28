/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::*;
use crate::report::{
	Assumption, Binding, Computation, DiagramRow, DiagramValue, EnvelopeReport, ScenarioReport,
	SourceRange,
};
use crate::verify::StepKind;
use crate::verify::TraceValue;

const GOLDEN_SOURCE: &str = concat!(
	"attacker[active]\n\n",
	"principal Alice[\n\tgenerates a\n\tga = PUBKEY(a)\n\tknows private m\n",
	"\tknows private n\n\te = AEAD_ENC(k, n, m, ad)\n]\n\n",
	"Alice -> Bob: [ga], e\n\n",
	"phase[1]\n\n",
	"principal Bob[\n\tleaks b\n\td = AEAD_DEC(k, n, e, ad)?\n]\n\n",
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

fn step(text: &str) -> TraceStep {
	TraceStep::new(StepKind::Derive, text.to_string())
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
		subtype: None,
		steps: vec![],
		preconditions: vec!["Bob still sends ack to Alice, so the failure counts.".to_string()],
		generated: false,
		variants: 1,
	};
	broken.steps = vec![
		step("Attacker constructs PUBKEY(nil) from nil."),
		TraceStep {
			principal: Some("Bob".to_string()),
			values: vec![TraceValue {
				name: "b".to_string(),
				installed: None,
				was: None,
				guarded: false,
			}],
			..step("Attacker is handed b by a leaks declaration in Bob.")
		},
		step("Attacker obtains ga on the wire."),
		TraceStep {
			kind: StepKind::Mutations,
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
		TraceStep {
			kind: StepKind::Gate,
			text: "Bob's AEAD_DEC(k, n, e, ad)? check passes on an attacker-controlled key."
				.to_string(),
			sender: None,
			recipient: None,
			principal: Some("Bob".to_string()),
			values: vec![],
		},
		step("Attacker computes DH_KEX(PUBKEY(a), nil), obtaining k."),
		step("Attacker decrypts e, obtaining m."),
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
		subtype: None,
		steps: vec![],
		preconditions: vec![],
		generated: false,
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
			corrupt_from: Some(0),
		}],
		notes: vec!["Per-session values and principals carry the suffix #2.".to_string()],
		provenance: vec!["The model's own queries block was replaced by the set --auto-queries derives from the protocol; these are generated claims, not the author's.".to_string()],
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
					values: vec![DiagramValue {
						name: "b".to_string(),
						guarded: false,
					}],
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

fn figure<'a>(tex: &'a str, figid: &str) -> &'a str {
	let begin = format!("%% --- BEGIN verifpal figure: {figid} ---");
	let end = format!("%% --- END verifpal figure: {figid} ---");
	let from = tex.find(&begin).expect("the figure begins");
	let to = tex[from..].find(&end).expect("the figure ends") + from;
	&tex[from..to]
}

fn tall_run() -> Run {
	let mut run = golden_run();
	let computes = (0..160)
		.map(|i| Computation {
			names: vec![format!("tall{i}")],
			primitive: None,
			expression: Some("HASH(m)".to_string()),
			checked: false,
		})
		.collect();
	run.models[0].diagram.insert(
		0,
		DiagramRow::Activity {
			principal: "Alice".to_string(),
			phase: 0,
			generates: vec![],
			computes,
		},
	);
	run
}

#[test]
fn a_chart_taller_than_a_page_is_one_column_for_the_preamble_to_break() {
	let tex = tex_report(&tall_run());
	let chart = figure(&tex, "golden-vp-0-protocol");
	assert_eq!(chart.matches("\\begin{vpdiagram}").count(), 1);
	assert!(
		chart.contains("\\begin{vpdiagram}[fig:golden-vp-0-protocol]"),
		"the column names its figure, so a continued piece can refer to it:\n{chart}"
	);
	assert_eq!(chart.matches("\\captionof{figure}").count(), 1);
	assert_eq!(chart.matches("\\label{fig:").count(), 1);
	for i in 0..160 {
		assert_eq!(
			chart.matches(&format!("\\vpconst{{tall{i}}}")).count(),
			1,
			"tall{i} is drawn exactly once"
		);
	}
}

fn dropped_run() -> Run {
	let mut run = golden_run();
	let analysis = run.models[0].analysis.as_mut().expect("analysed");
	analysis.queries[0].steps = vec![
		TraceStep {
			principal: Some("Bob".to_string()),
			..TraceStep::new(
				StepKind::Idle,
				"Bob never starts a session in this execution.".to_string(),
			)
		},
		TraceStep {
			sender: Some("Alice".to_string()),
			recipient: Some("Bob".to_string()),
			principal: Some("Bob".to_string()),
			values: vec![TraceValue {
				name: "e".to_string(),
				installed: None,
				was: None,
				guarded: false,
			}],
			..TraceStep::new(
				StepKind::Drop,
				"Attacker drops e (Alice to Bob), and Bob continues without it.".to_string(),
			)
		},
		TraceStep {
			sender: Some("Alice".to_string()),
			recipient: Some("Bob".to_string()),
			values: vec![TraceValue {
				name: "e".to_string(),
				installed: Some("e".to_string()),
				was: None,
				guarded: false,
			}],
			..TraceStep::new(
				StepKind::Replay,
				"Attacker replays e (Alice to Bob) from another session, where it is e."
					.to_string(),
			)
		},
	];
	run
}

#[test]
fn a_dropped_value_ends_at_the_attacker_and_an_unstarted_run_is_marked_on_its_lane() {
	let tex = tex_report(&dropped_run());
	let chart = figure(&tex, "golden-vp-0-attack-0");
	assert!(
		chart.contains("\\vpmark{0}{vpnote}{vpnumadv}{1}{never starts}"),
		"{chart}"
	);
	assert!(
		chart.contains(
			"\\vphopforged{1}{-1}{2}{vpdropped}{vpnumadv}{2}\
			 {\\vpterm{\\vpconst{e}} \\vpwirenote{dropped}}"
		),
		"the arrow runs from Alice to the attacker and no further: {chart}"
	);
	assert!(
		chart.contains(
			"\\vphopforged{1}{2}{0}{vpreplay}{vpnumadv}{3}\
			 {\\vpdagger{\\vpterm{\\vpconst{e}}} \\vpwirenote{replayed}}"
		),
		"{chart}"
	);
	assert!(
		!chart.contains("\\vprun"),
		"nothing here is computed: {chart}"
	);
	assert!(PREAMBLE.contains("vpdropped/.style="));
	assert!(
		tex.contains("and \\vpactor{Bob} continues without it.\\vpon{Alice}{Bob}"),
		"the step names the message it acts on: {tex}"
	);
}

#[test]
fn preconditions_are_split_from_the_query_they_restrict() {
	assert_eq!(
		split_options(
			"confidentiality? k[precondition[Alice -> Bob: m] precondition[Bob -> Alice: n]]"
		),
		(
			"confidentiality? k",
			vec!["Alice -> Bob: m", "Bob -> Alice: n"]
		)
	);
	assert_eq!(
		split_options("authentication? Alice -> Bob: e"),
		("authentication? Alice -> Bob: e", vec![])
	);
	let tex = tex_report(&golden_run());
	assert!(
		!tex.contains("precondition["),
		"an option is typeset, never printed as source"
	);
}

#[test]
fn every_attacked_query_links_to_its_trace() {
	let tex = tex_report(&golden_run());
	assert!(tex.contains("\\label{atk:golden-vp-0-0}"), "{tex}");
	assert!(tex.contains("\\ref{atk:golden-vp-0-0}"), "{tex}");
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
			tex.matches("\\begin{vplisting}").count(),
			tex.matches("\\end{vplisting}").count(),
			"{path} has an unbalanced listing"
		);
		assert!(
			tex.chars()
				.all(|c| !c.is_ascii_control() || c == '\n' || c == '\t'),
			"{path} writes a control character XeTeX refuses"
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

fn unanalysed(source: &str, error: &str) -> Run {
	Run::of(
		"0.0.0",
		&[("hostile.vp".to_string(), Err(error.to_string()))],
		&[source.to_string()],
	)
}

fn listing(tex: &str) -> Vec<&str> {
	let from = tex.find("\\begin{vplisting}").expect("a listing begins");
	let to = tex.find("\\end{vplisting}").expect("a listing ends");
	tex[from..to].lines().skip(1).collect()
}

fn error_block(tex: &str) -> Vec<&str> {
	let from = tex.find("Verifpal reported:").expect("an error block");
	let to = tex[from..].find("\n}}\n").expect("the block ends") + from + 1;
	tex[from..to]
		.lines()
		.filter(|line| line.contains("\\vpline{"))
		.map(|line| &line[line.find("\\vpline{").unwrap_or(0)..])
		.collect()
}

const HOSTILE: &str = concat!(
	"attacker[passive]\n",
	"// \\end{vplisting}\n",
	"// \\typeout{pwned} } { % $x$ #1 ^^M ~ & _\n",
	"principal Alice[\n\tknows private m\n\th = HASH(m)\n]\n",
	"Alice -> Bob: h\nprincipal Bob[\n\t_ = HASH(h)\n]\n",
	"queries[\n\tconfidentiality? m\n]\n"
);

#[test]
fn a_model_cannot_write_tex_into_the_listing_it_is_set_in() {
	let tex = tex_report(&unanalysed(HOSTILE, "no"));
	assert_eq!(tex.matches("\\end{vplisting}").count(), 1, "{tex}");
	assert!(!tex.contains("\\typeout"), "{tex}");
	assert!(braces_balance(&tex));
	let lines = listing(&tex);
	assert_eq!(
		lines.len(),
		HOSTILE.lines().count(),
		"every line of the source is set, none withheld"
	);
	assert_eq!(
		lines[1],
		"\\vpline{0}{\\vpsrccomment{// \\textbackslash{}end\\{vplisting\\}}}"
	);
	assert_eq!(
		lines[2],
		"\\vpline{0}{\\vpsrccomment{// \\textbackslash{}typeout\\{pwned\\} \\} \\{ \\% \\$x\\$ \\#1 \\textasciicircum{}\\textasciicircum{}M \\textasciitilde{} \\& \\_}}"
	);
	for line in lines {
		assert!(
			line.starts_with("\\vpline{") && line.ends_with('}'),
			"{line}"
		);
	}
}

#[test]
fn the_listing_keeps_every_character_of_the_source_in_its_place() {
	let comment = "// Alice\u{2019}s key\u{2014}Bob\u{2019}s \u{201c}nonce\u{201d} is na\u{ef}ve; \
		caf\u{e9}, Dvo\u{159}\u{e1}k, 100\u{20ac}, x\u{2260}y, k\u{2081}, a\u{2192}b, \u{3b1}\u{416}\u{4e2d}";
	let source = format!("{comment}\nattacker[passive]\n");
	let tex = tex_report(&unanalysed(&source, "no"));
	assert_eq!(
		listing(&tex)[0],
		format!("\\vpline{{0}}{{\\vpsrccomment{{{comment}}}}}"),
		"a character is neither moved, dropped nor respelled on its way into the listing"
	);
}

#[test]
fn the_listing_keeps_indentation_runs_of_spaces_and_line_ends() {
	let source = "attacker[active]\r\nprincipal Alice[\r\n\tknows private m\r\n    \
		x  =   HASH(m)\t// a\tb\r\n\r\n]\r\nqueries[\r\n\tconfidentiality? m\r\n]\r\n";
	let tex = tex_report(&unanalysed(source, "no"));
	assert_eq!(
		listing(&tex)[..6],
		[
			"\\vpline{0}{\\vpsrckeyword{attacker}[\\vpsrckeyword{active}]}",
			"\\vpline{0}{\\vpsrckeyword{principal} Alice[}",
			"\\vpline{4}{\\vpsrckeyword{knows} \\vpsrckeyword{private} m}",
			"\\vpline{4}{x \\ = \\ \\ \\vpsrcprimitive{HASH}(m) \\ \\vpsrccomment{// a \\ \\ \\ b}}",
			"\\vpline{0}{}",
			"\\vpline{0}{]}",
		],
		"a tab is a stop of four columns, leading whitespace is the line's indentation, \
		 and a carriage return before a line feed is part of the line end"
	);
	assert_eq!(listing(&tex).len(), 9);
}

#[test]
fn a_comment_that_spans_lines_is_tinted_on_each_of_them() {
	let source = "attacker[active] /* one\n\t   two */\n";
	let tex = tex_report(&unanalysed(source, "no"));
	assert_eq!(
		listing(&tex),
		[
			"\\vpline{0}{\\vpsrckeyword{attacker}[\\vpsrckeyword{active}] \\vpsrccomment{/* one}}",
			"\\vpline{7}{\\vpsrccomment{two */}}",
		]
	);
}

#[test]
fn a_control_character_in_the_source_or_the_error_never_reaches_the_document_raw() {
	let source = "// copied from a terminal: \u{1b}[31mFAIL\u{1b}[0m \u{7}\u{b}\u{c}\u{0}\u{7f} a\rb\n\
		attacker[passive]\n";
	let tex = tex_report(&unanalysed(source, "bad \u{1b}[1m byte\u{0}"));
	assert!(
		tex.chars()
			.all(|c| !c.is_ascii_control() || c == '\n' || c == '\t'),
		"XeTeX stops at a line that holds one: {tex}"
	);
	assert_eq!(
		listing(&tex)[0],
		"\\vpline{0}{\\vpsrccomment{// copied from a terminal: \\textasciicircum{}[[31mFAIL\\textasciicircum{}[[0m \
		 \\textasciicircum{}G\\textasciicircum{}K\\textasciicircum{}L\\textasciicircum{}@\\textasciicircum{}? \
		 a\\textasciicircum{}Mb}}"
	);
	assert_eq!(
		error_block(&tex),
		["\\vpline{0}{bad \\textasciicircum{}[[1m byte\\textasciicircum{}@}"]
	);
}

#[test]
fn box_drawing_in_the_source_appendix_keeps_its_shape() {
	let source = "// \u{250c}\u{2500}\u{2510} A \u{25ba} B\n// \u{2502}x\u{2502} caf\u{e9}";
	let tex = tex_report(&unanalysed(source, "no"));
	assert_eq!(
		listing(&tex),
		[
			"\\vpline{0}{\\vpsrccomment{// +-+ A \\textgreater{} B}}",
			"\\vpline{0}{\\vpsrccomment{// \\textbar{}x\\textbar{} caf\u{e9}}}",
		],
		"the listing font has no box-drawing glyphs, which would otherwise vanish"
	);
}

#[test]
fn a_file_name_may_break_at_its_underscores() {
	let run = Run::of(
		"0.0.0",
		&[
			(
				"cap_aead_weak_forgeable_matrix.vp".to_string(),
				Err("no".to_string()),
			),
			("b.vp".to_string(), Err("no".to_string())),
		],
		&[String::new(), String::new()],
	);
	let tex = tex_report(&run);
	assert!(
		tex.contains(
			"\\hyperref[sec:cap-aead-weak-forgeable-matrix-vp-0]\
			 {\\vpfile{cap\\_aead\\_weak\\_forgeable\\_matrix.vp}}"
		),
		"{tex}"
	);
	assert!(
		PREAMBLE.contains("\\def\\_{\\vpfileus\\allowbreak}"),
		"inside a file name an underscore is a place the line may break"
	);
	assert!(!tex.contains("\\texttt{cap"), "{tex}");
}

#[test]
fn no_latex_is_written_in_rust() {
	for file in ["mod.rs", "math.rs"] {
		let source = std::fs::read_to_string(format!("src/report/tex/{file}")).expect("reads");
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
					"src/report/tex/{file}:{} writes {banned} in Rust; it belongs in a template",
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
							math::framed(text).is_some(),
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
				c.is_ascii() || crate::report::template::tex_spelling(c).is_some(),
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
		&[(
			"broken.vp".to_string(),
			Err("parse error: 100% bad\n  |   ^^ here".into()),
		)],
		&[String::new()],
	);
	let tex = tex_report(&run);
	assert_eq!(
		error_block(&tex),
		[
			"\\vpline{0}{parse error: 100\\% bad}",
			"\\vpline{2}{\\textbar{} \\ \\ \\textasciicircum{}\\textasciicircum{} here}",
		],
		"a diagnostic keeps its lines and the spaces that put its caret under the \
		 source: {tex}"
	);
	assert!(braces_balance(&tex));
}

#[test]
fn a_long_diagnostic_line_may_wrap_and_only_its_indentation_is_fixed() {
	let error = "sanity error: unknown constant `n`\n  |\n5 |     c = AEAD_ENC(long_term_key, \
		nonce_never_declared, message_one, HASH(long_term_key, message_one))\n  \
		= note: a constant must be introduced by `knows`, `generates`, or an assignment before \
		anything can refer to it";
	let tex = tex_report(&unanalysed("", error));
	let block = error_block(&tex);
	assert_eq!(block.len(), 4);
	assert!(
		block.iter().all(|line| !line.contains('~')),
		"a line whose every space is unbreakable runs off the page: {block:?}"
	);
	assert_eq!(
		block[2],
		"\\vpline{0}{5 \\textbar{} \\ \\ \\ \\ c = AEAD\\_ENC(long\\_term\\_key, \
		 nonce\\_never\\_declared, message\\_one, HASH(long\\_term\\_key, message\\_one))}"
	);
	assert!(block[3].starts_with("\\vpline{2}{= note: a constant"));
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
	let mut documents: Vec<(String, String)> = vec![
		("golden".to_string(), tex_report(&golden_run())),
		("tall".to_string(), tex_report(&tall_run())),
	];
	for path in [
		"examples/test/hmac_ok.vp",
		"examples/test/spore_ns_pk.vp",
		"examples/simple.vp",
	] {
		documents.push((path.replace(['/', '.'], "_"), tex_report(&run_of(path))));
	}
	let every_ascii: String = (0u8..128).map(char::from).collect();
	let hostile = format!(
		"{HOSTILE}// {every_ascii}\n// na\u{ef}ve \u{2014} \u{201c}x\u{201d} \u{2192} \u{3b1}\n\
		 /* a comment\n\t  over {} lines */\n",
		"long ".repeat(60)
	);
	let error = format!(
		"sanity error: {every_ascii}\n  |\n5 |     {}\n  |     ^^^ here",
		"AEAD_ENC(long_term_key, nonce), ".repeat(12)
	);
	documents.push((
		"hostile".to_string(),
		tex_report(&unanalysed(&hostile, &error)),
	));
	documents.push(("dropped".to_string(), tex_report(&dropped_run())));
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
