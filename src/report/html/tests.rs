/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::*;
use crate::report::msc::{Lanes, Route, Row, Value};
use crate::report::{
	Assumption, Binding, DiagramRow, DiagramValue, EnvelopeReport, ScenarioReport, SourceRange,
};
use crate::verify::TraceValue;

fn envelope(truncations: Vec<String>) -> EnvelopeReport {
	let exhausted = truncations.is_empty();
	EnvelopeReport {
		sessions: 2,
		truncations,
		exhausted,
		summary: if exhausted {
			"search exhausted at 2 sessions".to_string()
		} else {
			"search truncated: term depth".to_string()
		},
	}
}

fn query(kind: &str, text: &str, resolved: bool) -> QueryReport {
	QueryReport {
		query: text.to_string(),
		kind: kind.to_string(),
		resolved,
		envelope: envelope(vec![]),
		range: SourceRange {
			start: 0,
			end: 0,
			line: 9,
			column: 2,
		},
		summary: String::new(),
		conclusion: if resolved {
			"m1 is obtained by Attacker.".to_string()
		} else {
			String::new()
		},
		subtype: None,
		steps: vec![],
		preconditions: vec![],
		generated: false,
		variants: 0,
	}
}

fn derive(text: &str) -> TraceStep {
	TraceStep::new("derive", text.to_string())
}

fn mutation() -> TraceStep {
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
	}
}

fn gate() -> TraceStep {
	TraceStep {
		kind: "gate",
		text: "Bob's AEAD_DEC(k, n, e, ad)? passes.".to_string(),
		sender: None,
		recipient: None,
		principal: Some("Bob".to_string()),
		values: vec![],
	}
}

fn analysis(attacker: &str, code: &str, queries: Vec<QueryReport>) -> Analysis {
	Analysis {
		model: "t.vp".to_string(),
		attacker: attacker.to_string(),
		sessions: 2,
		code: code.to_string(),
		attacks: queries.iter().filter(|q| q.resolved).count(),
		elapsed_ms: 3,
		assumptions: vec![],
		scenarios: vec![],
		notes: vec![],
		provenance: vec![],
		queries,
	}
}

fn wire(hop: usize, sender: &str, recipient: &str, values: &[(&str, bool)]) -> DiagramRow {
	DiagramRow::Message {
		hop,
		phase: 0,
		sender: sender.to_string(),
		recipient: recipient.to_string(),
		values: values
			.iter()
			.map(|(name, guarded)| DiagramValue {
				name: name.to_string(),
				guarded: *guarded,
			})
			.collect(),
	}
}

fn model(analysis: Option<Analysis>) -> ModelReport {
	ModelReport {
		file: "examples/t.vp".to_string(),
		ok: analysis.is_some(),
		error: None,
		analysis,
		diagram: vec![wire(1, "Alice", "Bob", &[("ga", false)])],
		source: String::new(),
		tokens: vec![],
	}
}

fn page(models: Vec<ModelReport>) -> String {
	html_report(&Run {
		version: "1.0.0".to_string(),
		ok: models.iter().all(|m| m.ok),
		models,
	})
}

fn one(analysis: Analysis) -> String {
	page(vec![model(Some(analysis))])
}

fn ids(html: &str) -> Vec<String> {
	let mut out = Vec::new();
	for part in html.split("id=\"").skip(1) {
		if let Some((id, _)) = part.split_once('"') {
			out.push(id.to_string());
		}
	}
	out
}

fn anchors(html: &str) -> Vec<String> {
	let mut out = Vec::new();
	for part in html.split("href=\"#").skip(1) {
		if let Some((id, _)) = part.split_once('"') {
			out.push(id.to_string());
		}
	}
	out
}

#[test]
fn the_report_names_the_attacker_the_verdicts_were_reached_against() {
	let html = one(analysis(
		"passive",
		"c0",
		vec![query("confidentiality", "c? m", false)],
	));
	assert!(html.contains("passive attacker"));
	assert!(html.contains("attackerKind passive"));
	let active = one(analysis(
		"active",
		"c0",
		vec![query("confidentiality", "c? m", false)],
	));
	assert!(active.contains("active attacker"));
}

#[test]
fn every_analysed_model_states_the_scope_of_its_own_result() {
	let html = one(analysis(
		"active",
		"c0",
		vec![query("confidentiality", "c? m", false)],
	));
	assert!(html.contains("Scope of this result"));
	assert!(html.contains("against an active attacker"));
	assert!(html.contains("2 concurrent sessions"));
	for overclaim in ["proved", "proven", "verified correct", "guaranteed"] {
		assert!(!html.contains(overclaim), "the report claims {overclaim}");
	}
}

#[test]
fn a_passive_run_says_so_in_its_scope_note_rather_than_reading_as_active() {
	let html = one(analysis(
		"passive",
		"c0",
		vec![query("confidentiality", "c? m", false)],
	));
	assert!(html.contains("against a passive attacker"));
}

#[test]
fn the_page_always_carries_the_soundness_disclaimer() {
	let html = one(analysis(
		"active",
		"c0",
		vec![query("confidentiality", "c? m", false)],
	));
	assert!(html.contains("sound but incomplete"));
	assert!(html.contains("never a proof that none exists"));
}

#[test]
fn a_hold_reached_under_a_truncated_search_says_so_on_its_own_row() {
	let mut q = query("confidentiality", "c? m", false);
	q.envelope = envelope(vec!["term depth".to_string()]);
	let html = one(analysis("active", "c0", vec![q]));
	assert!(html.contains("search truncated: term depth"));
	assert!(html.contains("class=\"cut\""));
	assert!(html.contains("stopped short even of that (term depth)"));
}

#[test]
fn an_exhausted_hold_carries_no_truncation_badge() {
	let html = one(analysis(
		"active",
		"c0",
		vec![query("confidentiality", "c? m", false)],
	));
	assert!(!html.contains("class=\"cut\""));
	assert!(html.contains("Holds (search exhausted at 2 sessions)"));
}

#[test]
fn a_wide_diagram_scrolls_instead_of_shrinking_below_legibility() {
	let css = strip_header(CSS);
	assert!(css.contains(".scroll {"));
	assert!(css.contains("overflow-x: auto"));
	let block = css.split(".diagram {").nth(1).unwrap_or("");
	let block = block.split('}').next().unwrap_or("");
	assert!(
		!block.contains("max-width"),
		"the diagram must scroll, not scale down"
	);
	let html = one(analysis(
		"active",
		"c0",
		vec![query("confidentiality", "c? m", false)],
	));
	assert!(html.contains("<div class=\"scroll\">"));
}

#[test]
fn columns_are_sized_to_the_widest_thing_they_have_to_hold() {
	let wire = |hop: usize, from: &str, to: &str, name: &str| Row::Wire {
		hop: Some(hop),
		step: None,
		from: from.to_string(),
		to: to.to_string(),
		route: Route::Direct,
		values: vec![Value {
			name: name.to_string(),
			guarded: false,
			queries: vec![],
		}],
	};
	let of = |label: &str| {
		let rows = vec![wire(1, "A", "B", label), wire(2, "C", "D", "y")];
		let chart = Chart {
			lanes: Lanes::of(&rows),
			rows,
		};
		let ctx = diagram::draw(
			diagram::Figure {
				id: "d".to_string(),
				caption: String::new(),
			},
			&chart,
		);
		let html = render(&DIAGRAM, &ctx);
		html.split("width=\"")
			.nth(1)
			.and_then(|s| s.split('"').next())
			.and_then(|s| s.parse::<usize>().ok())
			.unwrap()
	};
	assert!(
		of("a_very_long_constant_name_indeed_much_longer") > of("x"),
		"a long label must widen its column"
	);
}

#[test]
fn a_protocol_diagram_is_described_to_a_screen_reader_and_an_attack_diagram_defers() {
	let mut q = query("confidentiality", "c? m", true);
	q.steps = vec![
		derive("Attacker constructs PUBKEY(nil)."),
		mutation(),
		gate(),
	];
	let html = one(analysis("active", "c1", vec![q]));
	assert!(html.contains("role=\"img\" aria-labelledby=\"m0p-title\""));
	assert!(html.contains("<ol class=\"offscreen\">"));
	assert!(
		html.contains("aria-hidden=\"true\" focusable=\"false\""),
		"the attack diagram repeats the step list and must not be announced twice"
	);
}

#[test]
fn trace_rows_are_real_buttons_with_a_reported_pinned_state() {
	let mut q = query("confidentiality", "c? m", true);
	q.steps = vec![mutation(), gate()];
	let html = one(analysis("active", "c1", vec![q]));
	assert!(html.contains("<button type=\"button\" class=\"traceStep\""));
	assert!(html.contains("aria-pressed=\"false\""));
	assert!(!html.contains("tabindex=\"0\""));
}

#[test]
fn a_run_of_derivations_folds_into_one_group_the_diagram_agrees_with() {
	let mut q = query("confidentiality", "c? m", true);
	q.steps = vec![
		mutation(),
		derive("one"),
		derive("two"),
		derive("three"),
		gate(),
	];
	let html = one(analysis("active", "c1", vec![q]));
	assert!(html.contains("<details class=\"traceGroup\" data-step=\"2-4\">"));
	assert!(html.contains("3 derivation steps"));
	assert!(html.contains("computes (steps 2\u{2013}4)"));
}

#[test]
fn a_lone_derivation_is_not_folded_but_still_correlates() {
	let mut q = query("confidentiality", "c? m", true);
	q.steps = vec![derive("only"), mutation()];
	let html = one(analysis("active", "c1", vec![q]));
	assert!(!html.contains("<details class=\"traceGroup\""));
	assert!(html.contains("computes (step 1)"));
	assert!(html.contains("data-step=\"1\""));
}

#[test]
fn an_attack_wire_names_the_protocol_hop_it_corresponds_to() {
	let mut q = query("authentication", "a? A -> B: ga", true);
	q.steps = vec![mutation()];
	let mut m = model(Some(analysis("active", "a1", vec![q])));
	m.diagram = vec![
		wire(1, "Alice", "Bob", &[("gx", false)]),
		wire(2, "Alice", "Bob", &[("ga", false)]),
	];
	let html = page(vec![m]);
	assert!(
		html.contains("hop 2 &middot; "),
		"the trace must point back at the message it forges"
	);
}

#[test]
fn an_attack_diagram_marks_the_phase_its_traffic_belongs_to() {
	let mut q = query("authentication", "a? A -> B: ga", true);
	q.steps = vec![mutation()];
	let mut m = model(Some(analysis("active", "a1", vec![q])));
	m.diagram = vec![
		DiagramRow::Phase { number: 1 },
		DiagramRow::Message {
			hop: 1,
			phase: 1,
			sender: "Alice".to_string(),
			recipient: "Bob".to_string(),
			values: vec![DiagramValue {
				name: "ga".to_string(),
				guarded: false,
			}],
		},
	];
	let html = page(vec![m]);
	assert_eq!(
		html.matches("PHASE 1").count(),
		2,
		"the phase belongs in the attack diagram as well as the protocol one"
	);
}

#[test]
fn an_attack_diagram_shows_a_leak_the_attacker_actually_used() {
	let mut q = query("confidentiality", "c? m", true);
	q.steps = vec![derive("Attacker learns sk, leaked by Bob."), mutation()];
	let mut m = model(Some(analysis("active", "c1", vec![q])));
	m.diagram = vec![
		wire(1, "Alice", "Bob", &[("ga", false)]),
		DiagramRow::Leak {
			principal: "Bob".to_string(),
			values: vec![DiagramValue {
				name: "sk".to_string(),
				guarded: false,
			}],
		},
	];
	let html = page(vec![m]);
	let attack = html
		.split("class=\"panelSection trace\"")
		.nth(1)
		.unwrap_or("");
	assert!(
		attack.contains("Bob leaks sk"),
		"a leak the trace leans on belongs in the attack diagram"
	);
}

#[test]
fn a_generated_run_says_where_its_shape_came_from() {
	let mut a = analysis(
		"active",
		"c0",
		vec![query("confidentiality", "c? m", false)],
	);
	a.provenance = vec!["--auto-queries replaced the model's queries.".to_string()];
	let html = one(a);
	assert!(html.contains("How this analysis was produced"));
	assert!(html.contains("--auto-queries replaced the model"));
}

#[test]
fn a_run_with_nothing_to_disclose_carries_no_callouts_at_all() {
	let html = one(analysis(
		"active",
		"c0",
		vec![query("confidentiality", "c? m", false)],
	));
	assert!(!html.contains("class=\"callout"));
}

#[test]
fn declared_assumptions_and_scenarios_render_as_callouts() {
	let mut a = analysis(
		"active",
		"c0",
		vec![query("confidentiality", "c? m", false)],
	);
	a.assumptions = vec![Assumption {
		term: "HASH(m)".to_string(),
		capability: "weak".to_string(),
		from_phase: 2,
	}];
	a.scenarios = vec![ScenarioReport {
		principal: "Alice".to_string(),
		bindings: vec![Binding {
			target: "gpeer".to_string(),
			value: "gm".to_string(),
		}],
		honest: false,
		corrupt_from: Some(0),
	}];
	let html = one(a);
	assert!(html.contains("<code>HASH(m)</code> (from phase 2)"));
	assert!(html.contains("<code>Alice[gpeer = gm]</code>"));
	assert!(html.contains("corrupt peer"));
}

#[test]
fn a_failed_model_renders_its_error_escaped_and_claims_no_verdicts() {
	let mut m = model(None);
	m.error = Some("bad <script>alert(1)</script>".to_string());
	m.diagram = vec![];
	let html = page(vec![m]);
	assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
	assert!(!html.contains("<script>alert"));
	assert!(html.contains("not analysed"));
	assert!(!html.contains("Scope of this result"));
}

#[test]
fn every_string_that_reaches_the_page_is_escaped_by_its_type() {
	let mut q = query("confidentiality", "confidentiality? <b>m</b>", true);
	q.conclusion = "\"quoted\" & <angled>".to_string();
	q.steps = vec![derive("<img src=x>")];
	let html = one(analysis("active", "c1", vec![q]));
	assert!(html.contains("confidentiality? &lt;b&gt;m&lt;/b&gt;"));
	assert!(html.contains("&quot;quoted&quot; &amp; &lt;angled&gt;"));
	assert!(html.contains("&lt;img src=x&gt;"));
	assert!(!html.contains("<img"));
}

#[test]
fn the_verdict_table_says_what_each_query_asked_and_where_it_lives() {
	let html = one(analysis(
		"active",
		"c1a0",
		vec![
			query("confidentiality", "confidentiality? m1", true),
			query("authentication", "authentication? A -> B: e", false),
		],
	));
	assert!(html.contains("<span class=\"qkind\">confidentiality</span>"));
	assert!(html.contains("<span class=\"qkind\">authentication</span>"));
	assert!(html.contains("line 9"));
	assert!(html.contains("Contradiction found"));
	assert!(html.contains("1 of 2 queries failed."));
}

#[test]
fn the_result_code_is_split_into_verdict_pairs() {
	let html = one(analysis(
		"active",
		"c1a0",
		vec![
			query("confidentiality", "c? m", true),
			query("authentication", "a? A -> B: e", false),
		],
	));
	assert!(html.contains("<span class=\"fail\">c1</span>"));
	assert!(html.contains("<span class=\"pass\">a0</span>"));
}

#[test]
fn a_mutation_step_renders_every_value_it_lists_as_an_install() {
	let mut step = mutation();
	step.values.push(TraceValue {
		name: "gb".to_string(),
		installed: Some("PUBKEY(b)".to_string()),
		was: Some("PUBKEY(b)".to_string()),
		guarded: true,
	});
	let mut q = query("authentication", "a? A -> B: ga", true);
	q.steps = vec![step];
	let html = one(analysis("active", "a1", vec![q]));
	assert!(html.contains("<span class=\"tvNew\">PUBKEY(nil)</span>"));
	assert!(html.contains("honest value: PUBKEY(a)"));
	assert!(
		html.contains("<span class=\"tvNew\">PUBKEY(b)</span>"),
		"an install equal to the honest value is still an install"
	);
	assert!(!html.contains("relayed unchanged"));
	assert!(html.contains("[gb]"));
	assert!(html.contains("tvGuard"));
}

#[test]
fn a_diagram_tags_attacked_values_with_the_queries_that_reached_them() {
	let mut q = query("authentication", "a? A -> B: ga", true);
	q.steps = vec![mutation()];
	let html = one(analysis("active", "a1", vec![q]));
	assert!(html.contains("data-q=\"0\""));
	assert!(html.contains("msgVal hit"));
	assert!(
		html.contains("ga\u{2020}"),
		"an attacked value must be marked by more than colour"
	);
	assert!(html.contains("a dagger marks"));
}

#[test]
fn a_guarded_value_is_bracketed_in_the_diagram() {
	let mut m = model(Some(analysis(
		"active",
		"c0",
		vec![query("confidentiality", "c? m", false)],
	)));
	m.diagram = vec![wire(1, "Alice", "Bob", &[("ga", true)])];
	let html = page(vec![m]);
	assert!(html.contains(">[ga]</tspan>"));
	assert!(html.contains("msgVal guarded"));
}

#[test]
fn a_model_with_no_messages_gets_no_diagram() {
	let mut m = model(Some(analysis(
		"active",
		"c0",
		vec![query("confidentiality", "c? m", false)],
	)));
	m.diagram = vec![];
	let html = page(vec![m]);
	assert!(!html.contains("<svg"));
}

#[test]
fn a_multi_model_run_gets_an_index_that_can_be_filtered() {
	let clean = analysis(
		"active",
		"c0",
		vec![query("confidentiality", "c? m", false)],
	);
	let broken = analysis("active", "c1", vec![query("confidentiality", "c? m", true)]);
	let html = page(vec![model(Some(clean)), model(Some(broken))]);
	assert!(html.contains("class=\"runIndex\""));
	assert!(html.contains("1 of 2 models have attacks."));
	assert!(html.contains("id=\"onlyFailing\""));
	assert!(html.contains("data-failing=\"no\""));
	assert!(html.contains("data-failing=\"yes\""));
}

#[test]
fn a_single_model_run_gets_no_index() {
	let html = one(analysis(
		"active",
		"c0",
		vec![query("confidentiality", "c? m", false)],
	));
	assert!(!html.contains("class=\"runIndex\""));
}

#[test]
fn the_page_is_self_contained() {
	let html = one(analysis(
		"active",
		"c0",
		vec![query("confidentiality", "c? m", false)],
	));
	assert_eq!(html.matches("<style>").count(), 1);
	assert_eq!(html.matches("<script>").count(), 1);
	assert!(!html.contains("<link"));
	assert!(!html.contains(" src="));
	assert!(!html.contains("@import"));
	assert!(!html.contains("url(http"));
	for scheme in ["http://", "https://"] {
		let fetched: Vec<&str> = html
			.match_indices(scheme)
			.map(|(i, _)| &html[i.saturating_sub(20)..i])
			.filter(|before| !before.ends_with("xmlns=\""))
			.collect();
		assert!(
			fetched.is_empty(),
			"the page reaches for {scheme}{fetched:?}"
		);
	}
}

#[test]
fn the_stylesheet_carries_a_print_rendering() {
	let css = strip_header(CSS);
	assert!(css.contains("@media print"));
	assert!(css.contains("@page"));
	assert!(css.contains("break-inside: avoid"));
	assert!(css.contains("break-before: page"));
}

#[test]
fn the_report_follows_the_readers_color_scheme() {
	let css = strip_header(CSS);
	assert!(css.contains("prefers-color-scheme: dark"));
	for token in [
		"--ink:",
		"--ink-2:",
		"--ink-3:",
		"--ink-4:",
		"--paper:",
		"--surface:",
		"--surface-2:",
		"--line:",
		"--line-soft:",
		"--olive:",
		"--olive-deep:",
		"--olive-tint:",
		"--olive-line:",
		"--azure:",
		"--azure-deep:",
		"--azure-tint:",
		"--azure-line:",
		"--breach:",
		"--breach-deep:",
		"--breach-tint:",
		"--breach-line:",
		"--sienna:",
		"--sienna-tint:",
		"--sienna-line:",
	] {
		assert!(
			css.matches(token).count() >= 2,
			"{token} has no dark counterpart"
		);
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
fn no_markup_is_written_in_rust() {
	for (name, source) in [
		("report/html/mod.rs", include_str!("mod.rs")),
		("report/html/diagram.rs", include_str!("diagram.rs")),
	] {
		let body = crate::testing::shipping_code(name, source);
		for needle in ["\"<", "</", "/>", "<span", "<div", "class=\"", "&amp;"] {
			assert!(
				!body.contains(needle),
				"{name} builds markup ({needle}); markup belongs in src/report/html/tpl/"
			);
		}
	}
}

#[test]
fn the_html_layer_never_reaches_for_the_parser() {
	let body = crate::testing::shipping_code("report/html/mod.rs", include_str!("mod.rs"));
	assert!(
		!body.contains("crate::syntax::parser"),
		"the model is parsed once, in report/mod.rs; the renderer reads the report"
	);
}

#[test]
fn every_anchor_on_the_page_points_at_something_that_exists() {
	let mut resolved = query("confidentiality", "c? m", true);
	resolved.steps = vec![mutation()];
	let holding = query("authentication", "a? A -> B: e", false);
	let html = page(vec![
		model(Some(analysis("active", "c1a0", vec![resolved, holding]))),
		model(Some(analysis(
			"active",
			"c0",
			vec![query("confidentiality", "c? m", false)],
		))),
	]);
	let present = ids(&html);
	for anchor in anchors(&html) {
		assert!(
			present.contains(&anchor),
			"#{anchor} is linked but never defined"
		);
	}
}

#[test]
fn no_element_id_is_used_twice_on_one_page() {
	let mut resolved = query("confidentiality", "c? m", true);
	resolved.steps = vec![mutation(), gate()];
	let html = page(vec![
		model(Some(analysis("active", "c1", vec![resolved]))),
		model(Some(analysis(
			"active",
			"c0",
			vec![query("confidentiality", "c? m", false)],
		))),
	]);
	let mut seen = ids(&html);
	seen.sort();
	let count = seen.len();
	seen.dedup();
	assert_eq!(count, seen.len(), "duplicate id on the page");
}

const GOLDEN_SOURCE: &str = "attacker[active]\n\nprincipal Alice[\n\tgenerates a\n\tga = PUBKEY(a)\n]\n\nAlice -> Bob: ga\n\nprincipal Bob[\n\tknows private m\n\tleaks m\n]\n\nqueries[\n\tconfidentiality? m\n]\n";

fn golden_run() -> Run {
	let (_, index) = crate::syntax::parser::parse_string_indexed("golden.vp", GOLDEN_SOURCE);
	let mut tokens = index.tokens().to_vec();
	tokens.sort_by_key(|t| t.span.start);

	let mut broken = query("confidentiality", "confidentiality? m", true);
	broken.conclusion = "m is obtained by Attacker.".to_string();
	broken.range = SourceRange {
		start: GOLDEN_SOURCE.find("confidentiality? m").unwrap(),
		end: GOLDEN_SOURCE.find("confidentiality? m").unwrap() + 18,
		line: 15,
		column: 2,
	};
	broken.variants = 1;
	broken.preconditions = vec!["Bob still sends ack to Alice, so the failure counts.".to_string()];
	broken.steps = vec![
		derive("Attacker constructs PUBKEY(nil)."),
		derive("Attacker observes ga on the wire."),
		mutation(),
		gate(),
		TraceStep {
			kind: "bypass",
			text: "Alice's SIGNVERIF check is defeated, accepting PUBKEY(nil).".to_string(),
			sender: None,
			recipient: None,
			principal: Some("Alice".to_string()),
			values: vec![],
		},
		TraceStep {
			kind: "replay",
			text: "Attacker replays e1 from another session.".to_string(),
			sender: Some("Bob".to_string()),
			recipient: Some("Alice".to_string()),
			principal: None,
			values: vec![TraceValue {
				name: "e1".to_string(),
				installed: Some("AEAD_ENC(k, n, m, ad)".to_string()),
				was: None,
				guarded: false,
			}],
		},
	];

	let mut holds = query("authentication", "authentication? Alice -> Bob: ga", false);
	holds.envelope = envelope(vec!["term depth".to_string()]);
	holds.range = SourceRange {
		start: 0,
		end: 0,
		line: 16,
		column: 2,
	};

	let mut a = analysis("active", "c1a0", vec![broken, holds]);
	a.assumptions = vec![Assumption {
		term: "HASH(m)".to_string(),
		capability: "weak".to_string(),
		from_phase: 2,
	}];
	a.scenarios = vec![
		ScenarioReport {
			principal: "Alice".to_string(),
			bindings: vec![Binding {
				target: "gpeer".to_string(),
				value: "gb".to_string(),
			}],
			honest: true,
			corrupt_from: None,
		},
		ScenarioReport {
			principal: "Alice".to_string(),
			bindings: vec![Binding {
				target: "gpeer".to_string(),
				value: "gm".to_string(),
			}],
			honest: false,
			corrupt_from: Some(0),
		},
	];
	a.notes = vec!["Per-session values carry the suffix #2.".to_string()];
	a.provenance = vec!["The model's own queries block was replaced by the set --auto-queries derives from the protocol; these are generated claims, not the author's.".to_string()];

	let full = ModelReport {
		file: "examples/golden.vp".to_string(),
		ok: true,
		error: None,
		analysis: Some(a),
		diagram: vec![
			wire(1, "Alice", "Bob", &[("ga", false), ("e1", true)]),
			DiagramRow::Phase { number: 1 },
			wire(2, "Bob", "Alice", &[("gb", false)]),
			DiagramRow::Leak {
				principal: "Bob".to_string(),
				values: vec![DiagramValue {
					name: "m".to_string(),
					guarded: false,
				}],
			},
		],
		source: GOLDEN_SOURCE.to_string(),
		tokens,
	};
	let failed = ModelReport {
		file: "examples/broken.vp".to_string(),
		ok: false,
		error: Some("golden.vp:3:1: syntax error: expected `]`".to_string()),
		analysis: None,
		diagram: vec![],
		source: String::new(),
		tokens: vec![],
	};
	Run {
		version: "0.0.0".to_string(),
		ok: false,
		models: vec![full, failed],
	}
}

#[test]
fn the_rendered_page_matches_its_golden_file() {
	let rendered = html_report(&golden_run());
	let golden = include_str!("../../../examples/test/golden_html/report.html");
	if std::env::var("VERIFPAL_BLESS_HTML").is_ok() {
		std::fs::write("examples/test/golden_html/report.html", &rendered).expect("bless");
		return;
	}
	assert_eq!(
		rendered, golden,
		"the rendered page drifted from examples/test/golden_html/report.html; \
		 re-bless with VERIFPAL_BLESS_HTML=1 once the diff is understood"
	);
}

const VOID: [&str; 12] = [
	"meta", "link", "br", "hr", "img", "input", "path", "line", "circle", "rect", "marker", "use",
];

fn unbalanced(html: &str) -> Option<String> {
	let mut stack: Vec<&str> = Vec::new();
	let mut rest = html;
	while let Some(at) = rest.find('<') {
		rest = &rest[at + 1..];
		let closing = rest.starts_with('/');
		let body = if closing { &rest[1..] } else { rest };
		if !body.starts_with(|c: char| c.is_ascii_alphabetic()) {
			continue;
		}
		let end = body
			.find(|c: char| c.is_whitespace() || c == '>' || c == '/')
			.unwrap_or(body.len());
		let name = &body[..end];
		let selfclosed = body[end..]
			.split_once('>')
			.is_some_and(|(head, _)| head.trim_end().ends_with('/'));
		if VOID.contains(&name) || (!closing && selfclosed) {
			continue;
		}
		if closing {
			match stack.pop() {
				Some(open) if open == name => {}
				Some(open) => return Some(format!("</{name}> closes <{open}>")),
				None => return Some(format!("stray </{name}>")),
			}
		} else {
			stack.push(name);
		}
		if let ("style" | "script", Some(skip)) = (name, rest.find(&format!("</{name}>"))) {
			rest = &rest[skip..];
		}
	}
	stack.pop().map(|open| format!("<{open}> is never closed"))
}

#[test]
fn a_rendered_page_is_well_formed_and_the_check_can_tell() {
	let mut q = query("confidentiality", "c? m", true);
	q.steps = vec![mutation(), derive("a"), derive("b"), gate()];
	assert_eq!(unbalanced(&one(analysis("active", "c1", vec![q]))), None);
	assert_eq!(
		unbalanced("<div><p>x</div>"),
		Some("</div> closes <p>".to_string())
	);
	assert_eq!(
		unbalanced("<div>x"),
		Some("<div> is never closed".to_string())
	);
	assert_eq!(
		unbalanced("<div>x</div></p>"),
		Some("stray </p>".to_string())
	);
	assert_eq!(unbalanced("<svg><path d=\"z\"/><g></g></svg>"), None);
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

#[test]
fn every_model_in_the_corpus_renders_a_sound_page() {
	let paths = corpus();
	assert!(paths.len() > 300, "corpus looks wrong: {}", paths.len());
	let mut outcomes = Vec::new();
	let mut sources = Vec::new();
	for path in &paths {
		let analysed = crate::verify::verify_report_with_source(path, 1);
		match analysed {
			Ok((report, source)) => {
				outcomes.push((path.clone(), Ok(report)));
				sources.push(source);
			}
			Err(e) => {
				outcomes.push((path.clone(), Err(e.to_string())));
				sources.push(std::fs::read_to_string(path).unwrap_or_default());
			}
		}
	}
	for (i, path) in paths.iter().enumerate() {
		let run = Run::of(
			"0.0.0",
			std::slice::from_ref(&outcomes[i]),
			std::slice::from_ref(&sources[i]),
		);
		let html = html_report(&run);
		assert!(!html.contains("{{"), "{path} left a placeholder unfilled");
		assert_eq!(html.matches("<style>").count(), 1, "{path}");
		assert_eq!(html.matches("<script>").count(), 1, "{path}");
		assert!(!html.contains("<link"), "{path}");
		assert!(!html.contains(" src="), "{path}");
		let present = ids(&html);
		for anchor in anchors(&html) {
			assert!(
				present.contains(&anchor),
				"{path} links a dangling #{anchor}"
			);
		}
		let mut seen = present.clone();
		seen.sort();
		let count = seen.len();
		seen.dedup();
		assert_eq!(count, seen.len(), "{path} repeats an element id");
		assert_eq!(
			html.matches("<svg").count(),
			html.matches("</svg>").count(),
			"{path} has an unbalanced diagram"
		);
		assert_eq!(
			html.matches("<details").count(),
			html.matches("</details>").count(),
			"{path} has an unbalanced fold"
		);
		assert_eq!(
			html.matches("<button").count(),
			html.matches("</button>").count(),
			"{path} has an unbalanced trace row"
		);
		assert_eq!(unbalanced(&html), None, "{path} renders malformed markup");
	}
	let run = Run::of("0.0.0", &outcomes, &sources);
	let html = html_report(&run);
	assert!(!html.contains("{{"));
	assert!(html.contains("class=\"runIndex\""));
	let present = ids(&html);
	for anchor in anchors(&html) {
		assert!(
			present.contains(&anchor),
			"the whole-run page dangles #{anchor}"
		);
	}
	let mut seen = present;
	seen.sort();
	let count = seen.len();
	seen.dedup();
	assert_eq!(
		count,
		seen.len(),
		"the whole-run page repeats an element id"
	);
}
