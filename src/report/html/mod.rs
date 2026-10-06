/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

mod diagram;
#[cfg(test)]
mod tests;

use super::msc::{Chart, Group, staged};
use super::template::{Ctx, Dialect, escape_html, render, strip_header, templates};
use super::{Analysis, DISCLAIMER, ModelReport, QueryReport, Run};
use crate::syntax::tokens::{Token, TokenKind};
use crate::util::text::plural;
use crate::verify::TraceStep;

static HTML: Dialect = Dialect {
	open: "{{",
	close: "}}",
	escape: escape_html,
	partial,
};

templates! { HTML,
	PAGE "page" = "tpl/page.html",
	RUN_INDEX "run_index" = "tpl/run_index.html",
	MODEL "model" = "tpl/model.html",
	ERROR "error" = "tpl/error.html",
	SCOPE "scope" = "tpl/scope.html",
	VERDICTS "verdicts" = "tpl/verdicts.html",
	VERDICT "verdict" = "tpl/verdict.html",
	CALLOUTS "callouts" = "tpl/callouts.html",
	TRACE "trace" = "tpl/trace.html",
	TRACE_STEP "trace_step" = "tpl/trace_step.html",
	TRACE_VALUE "trace_value" = "tpl/trace_value.html",
	SOURCE "source" = "tpl/source.html",
	SOURCE_CHUNK "source_chunk" = "tpl/source_chunk.html",
	DIAGRAM "diagram" = "tpl/diagram.html",
	DIAGRAM_ROW "diagram_row" = "tpl/diagram_row.html",
}

const CSS: &str = include_str!("report.css");
const JS: &str = include_str!("report.js");

pub fn html_report(run: &Run) -> String {
	let subject = match run.models.as_slice() {
		[only] => format!(" \u{00b7} {}", only.short_name()),
		_ => String::new(),
	};
	let models = run
		.models
		.iter()
		.enumerate()
		.map(|(i, model)| model_ctx(model, i))
		.collect();
	let ctx = Ctx::new()
		.text("subject", subject)
		.raw("style", strip_header(CSS))
		.raw("script", strip_header(JS))
		.text("version", run.version.as_str())
		.text("disclaimer", DISCLAIMER)
		.list("index", run_index(run))
		.list("models", models);
	let mut out = render(&PAGE, &ctx);
	out.push('\n');
	out
}

fn attacked(model: &ModelReport) -> bool {
	model.analysis.as_ref().is_none_or(|a| a.attacks > 0)
}

fn code_pairs(a: &Analysis) -> Vec<Ctx> {
	a.code_pairs()
		.map(|pair| {
			Ctx::new()
				.text("pclass", if pair.ends_with('0') { "pass" } else { "fail" })
				.text("pair", pair)
		})
		.collect()
}

fn lines<'a>(texts: impl IntoIterator<Item = &'a String>) -> Vec<Ctx> {
	texts
		.into_iter()
		.map(|text| Ctx::new().text("text", text.as_str()))
		.collect()
}

fn run_index(run: &Run) -> Vec<Ctx> {
	if run.models.len() < 2 {
		return Vec::new();
	}
	let tally = run.tally();
	let failed = tally.failed();
	let mut parts: Vec<String> = Vec::new();
	if tally.attacked > 0 {
		parts.push(format!(
			"{} of {} models have attacks.",
			tally.attacked, tally.models
		));
	} else if tally.analysed > 0 {
		parts.push(format!(
			"No attacks found in {} model{}.",
			tally.analysed,
			plural(tally.analysed)
		));
	}
	if failed > 0 {
		parts.push(format!(
			"{failed} model{} failed to analyse.",
			plural(failed)
		));
	}
	let rows = run
		.models
		.iter()
		.enumerate()
		.map(|(i, model)| {
			let meta = match &model.analysis {
				Some(a) => format!(
					"{} \u{00b7} {} session{} \u{00b7} {} ms",
					a.attacker,
					a.sessions,
					plural(a.sessions as usize),
					a.elapsed_ms
				),
				None => String::new(),
			};
			Ctx::new()
				.text("class", if attacked(model) { "fail" } else { "pass" })
				.num("index", i)
				.text("file", model.file.as_str())
				.text("failing", if attacked(model) { "yes" } else { "no" })
				.flag("failed", model.analysis.is_none())
				.list(
					"code",
					model.analysis.as_ref().map(code_pairs).unwrap_or_default(),
				)
				.text("meta", meta)
		})
		.collect();
	vec![
		Ctx::new()
			.text(
				"tally_class",
				if tally.attacked > 0 || failed > 0 {
					"fail"
				} else {
					"pass"
				},
			)
			.text("tally", parts.join(" "))
			.list("rows", rows),
	]
}

fn model_ctx(model: &ModelReport, index: usize) -> Ctx {
	let mut ctx = Ctx::new()
		.num("index", index)
		.text("failing", if attacked(model) { "yes" } else { "no" })
		.text("file", model.file.as_str())
		.flag("analysed", model.analysis.is_some())
		.list("error", lines(&model.error))
		.list("diagram", protocol_diagram(model, index));
	let (pane, marked) = source_pane(model, index);
	ctx = ctx.list("source", pane);
	ctx = match &model.analysis {
		Some(a) => ctx
			.text("attacker", a.attacker.as_str())
			.num("sessions", a.sessions)
			.text("plural", plural(a.sessions as usize))
			.num("elapsed", a.elapsed_ms)
			.list("code", code_pairs(a))
			.list("verdicts", vec![verdicts_ctx(a, index, &marked)])
			.list("traces", traces(a, model, index, &marked))
			.list("scope", vec![Ctx::new().text("text", a.scope())]),
		None => ctx
			.list("code", Vec::new())
			.list("verdicts", Vec::new())
			.list("traces", Vec::new())
			.list("scope", Vec::new()),
	};
	ctx
}

fn verdicts_ctx(a: &Analysis, index: usize, marked: &[usize]) -> Ctx {
	let total = a.queries.len();
	let (class, tally) = if a.attacks == 0 {
		("pass", format!("All {total} queries pass."))
	} else {
		("fail", format!("{} of {total} queries failed.", a.attacks))
	};
	let rows = a
		.queries
		.iter()
		.enumerate()
		.map(|(qi, q)| verdict_ctx(q, index, qi, marked.contains(&qi)))
		.collect();
	Ctx::new()
		.text("tally_class", class)
		.text("tally", tally)
		.list("rows", rows)
		.list("callouts", callouts(a))
}

fn verdict_ctx(q: &QueryReport, model_index: usize, query_index: usize, marked: bool) -> Ctx {
	let (class, mark, ruling) = if q.resolved {
		let ruling = match &q.subtype {
			Some(subtype) => format!("Contradiction found ({subtype})"),
			None => "Contradiction found".to_string(),
		};
		("verdictFail", "\u{00d7}", ruling)
	} else {
		(
			"verdictPass",
			"\u{2713}",
			format!("Holds ({})", q.envelope.summary),
		)
	};
	let target = if q.has_trace() {
		format!("#trace-m{model_index}-q{query_index}")
	} else if marked {
		format!("#src-m{model_index}-q{query_index}")
	} else {
		String::new()
	};
	let variants = if q.variants == 0 {
		String::new()
	} else {
		format!("{} variant{}", q.variants, plural(q.variants))
	};
	Ctx::new()
		.text("class", class)
		.num("model", model_index)
		.num("query_index", query_index)
		.text("mark", mark)
		.text("kind", q.kind.as_str())
		.text("target", target)
		.text("query", q.query.as_str())
		.text(
			"loc",
			if q.generated {
				"generated".to_string()
			} else {
				format!("line {}", q.range.line)
			},
		)
		.text("variants", variants)
		.flag("truncated", !q.envelope.truncations.is_empty())
		.text("truncations", q.envelope.truncations.join(", "))
		.text("ruling", ruling)
		.text(
			"because",
			if q.resolved {
				q.conclusion.clone()
			} else {
				String::new()
			},
		)
		.list("preconditions", lines(&q.preconditions))
}

fn counted(items: Vec<Ctx>) -> Vec<Ctx> {
	if items.is_empty() {
		return Vec::new();
	}
	vec![
		Ctx::new()
			.num("count", items.len())
			.text("plural", plural(items.len()))
			.list("items", items),
	]
}

fn listed(items: Vec<Ctx>) -> Vec<Ctx> {
	if items.is_empty() {
		return Vec::new();
	}
	vec![Ctx::new().list("items", items)]
}

fn callouts(a: &Analysis) -> Vec<Ctx> {
	let assumptions = a
		.assumptions
		.iter()
		.map(|assumption| {
			let onset = if assumption.from_phase > 0 {
				format!(" (from phase {})", assumption.from_phase)
			} else {
				String::new()
			};
			Ctx::new()
				.text("term", assumption.term.as_str())
				.text("onset", onset)
		})
		.collect::<Vec<Ctx>>();
	let scenarios = a
		.scenarios
		.iter()
		.map(|scenario| {
			let bindings: Vec<String> = scenario
				.bindings
				.iter()
				.map(|b| format!("{} = {}", b.target, b.value))
				.collect();
			Ctx::new()
				.text(
					"scenario",
					format!("{}[{}]", scenario.principal, bindings.join(", ")),
				)
				.text(
					"peer_class",
					if scenario.honest {
						"peerHonest"
					} else {
						"peerCorrupt"
					},
				)
				.text(
					"peer",
					crate::verify::result::peer_description(scenario.corrupt_from),
				)
		})
		.collect::<Vec<Ctx>>();
	if assumptions.is_empty()
		&& scenarios.is_empty()
		&& a.provenance.is_empty()
		&& a.notes.is_empty()
	{
		return Vec::new();
	}
	vec![
		Ctx::new()
			.list("assumptions", counted(assumptions))
			.list("scenarios", counted(scenarios))
			.list("provenance", listed(lines(&a.provenance)))
			.list("notes", listed(lines(&a.notes))),
	]
}

fn traces(a: &Analysis, model: &ModelReport, index: usize, marked: &[usize]) -> Vec<Ctx> {
	a.queries
		.iter()
		.enumerate()
		.filter(|(_, q)| q.has_trace())
		.map(|(qi, q)| {
			let back = if marked.contains(&qi) {
				format!("#src-m{index}-q{qi}")
			} else {
				format!("#verdict-m{index}-q{qi}")
			};
			Ctx::new()
				.num("model", index)
				.num("query_index", qi)
				.text("back", back)
				.text("query", q.query.as_str())
				.list("diagram", attack_diagram(q, model, index, qi))
				.list("steps", trace_steps(q))
				.list("notes", lines(&q.notes))
		})
		.collect()
}

fn trace_steps(q: &QueryReport) -> Vec<Ctx> {
	staged(q)
		.iter()
		.map(|group| match group {
			Group::One(n, step) => step_ctx(&n.to_string(), step),
			Group::Run(held) => match held.as_slice() {
				[(n, step)] => step_ctx(&n.to_string(), step),
				_ => Ctx::new()
					.flag("folded", true)
					.text("step", group.step())
					.text("label", format!("{} derivation steps", held.len()))
					.list(
						"steps",
						held.iter()
							.map(|(n, step)| step_ctx(&n.to_string(), step))
							.collect(),
					),
			},
		})
		.collect()
}

fn step_ctx(step: &str, s: &TraceStep) -> Ctx {
	let wire = s.kind == "mutations"
		&& !s.values.is_empty()
		&& s.sender.is_some()
		&& s.recipient.is_some();
	Ctx::new()
		.flag("folded", false)
		.text("step", step)
		.text("kind", s.kind)
		.flag("wire", wire)
		.text("sender", s.sender.clone().unwrap_or_default())
		.text("recipient", s.recipient.clone().unwrap_or_default())
		.text("text", if wire { String::new() } else { s.text.clone() })
		.list("values", if wire { trace_values(s) } else { Vec::new() })
}

fn trace_values(s: &TraceStep) -> Vec<Ctx> {
	s.values
		.iter()
		.map(|v| {
			let name = if v.guarded {
				format!("[{}]", v.name)
			} else {
				v.name.clone()
			};
			Ctx::new()
				.text("gclass", if v.guarded { " tvGuard" } else { "" })
				.text("name", name)
				.text("installed", v.installed.clone().unwrap_or_default())
				.text("was", v.was.clone().unwrap_or_default())
		})
		.collect()
}

fn protocol_diagram(model: &ModelReport, index: usize) -> Vec<Ctx> {
	let hits = model
		.analysis
		.as_ref()
		.map(Analysis::attacked_values)
		.unwrap_or_default();
	let caption = if hits.is_empty() {
		"Protocol sequence. Guarded values are written in brackets.".to_string()
	} else {
		"Protocol sequence. Guarded values are written in brackets; a dagger marks every value \
		 some attack below substitutes or replays."
			.to_string()
	};
	let figure = diagram::Figure {
		id: format!("m{index}p"),
		caption,
	};
	Chart::protocol(model, &hits)
		.map(|chart| diagram::draw(figure, &chart))
		.into_iter()
		.collect()
}

fn attack_diagram(
	q: &QueryReport,
	model: &ModelReport,
	index: usize,
	query_index: usize,
) -> Vec<Ctx> {
	let figure = diagram::Figure {
		id: format!("m{index}t{query_index}"),
		caption: String::new(),
	};
	Chart::attack(q, model)
		.map(|chart| diagram::draw(figure, &chart))
		.into_iter()
		.collect()
}

fn source_pane(model: &ModelReport, index: usize) -> (Vec<Ctx>, Vec<usize>) {
	if model.source.is_empty() {
		return (Vec::new(), Vec::new());
	}
	let source = &model.source;
	let queries = model
		.analysis
		.as_ref()
		.map(|a| a.queries.as_slice())
		.unwrap_or(&[]);
	let mut marks: Vec<(usize, usize, bool, usize)> = queries
		.iter()
		.enumerate()
		.filter(|(_, q)| {
			q.range.start < q.range.end
				&& q.range.end <= source.len()
				&& source.is_char_boundary(q.range.start)
				&& source.is_char_boundary(q.range.end)
		})
		.map(|(i, q)| (q.range.start, q.range.end, q.resolved, i))
		.collect();
	marks.sort_by_key(|&(start, ..)| start);
	let mut chunks: Vec<Ctx> = Vec::new();
	let mut marked: Vec<usize> = Vec::new();
	let mut at = 0usize;
	for (start, end, resolved, i) in marks {
		if start < at {
			continue;
		}
		marked.push(i);
		highlight(source, at, start, &model.tokens, &mut chunks);
		chunks.push(
			chunk("mark")
				.num("model", index)
				.num("query_index", i)
				.text("class", if resolved { "fail" } else { "pass" })
				.text("text", &source[start..end]),
		);
		at = end;
	}
	highlight(source, at, source.len(), &model.tokens, &mut chunks);
	(vec![Ctx::new().list("chunks", chunks)], marked)
}

fn chunk(kind: &str) -> Ctx {
	Ctx::new().one_of(&["mark", "token", "plain"], kind)
}

fn highlight(source: &str, from: usize, to: usize, tokens: &[Token], out: &mut Vec<Ctx>) {
	let mut at = from;
	for t in tokens {
		if t.span.start < at
			|| t.span.end > to
			|| t.span.start >= t.span.end
			|| !source.is_char_boundary(t.span.start)
			|| !source.is_char_boundary(t.span.end)
		{
			continue;
		}
		let Some(class) = token_class(t.kind) else {
			continue;
		};
		if at < t.span.start {
			out.push(chunk("plain").text("text", &source[at..t.span.start]));
		}
		out.push(
			chunk("token")
				.text("class", class)
				.text("text", &source[t.span.start..t.span.end]),
		);
		at = t.span.end;
	}
	if at < to {
		out.push(chunk("plain").text("text", &source[at..to]));
	}
}

fn token_class(kind: TokenKind) -> Option<&'static str> {
	match kind {
		TokenKind::Keyword | TokenKind::Qualifier => Some("k"),
		TokenKind::AttackerMode | TokenKind::Capability => Some("a"),
		TokenKind::PrincipalName => Some("p"),
		TokenKind::PrimitiveName => Some("f"),
		TokenKind::QueryKind => Some("q"),
		TokenKind::Comment => Some("c"),
		TokenKind::ConstantName
		| TokenKind::PhaseNumber
		| TokenKind::Threshold
		| TokenKind::Arrow
		| TokenKind::Assign
		| TokenKind::Check
		| TokenKind::Anonymous => None,
	}
}
