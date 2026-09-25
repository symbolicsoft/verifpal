/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

mod math;

use crate::msc::{ATTACKER, Chart, Lanes, ROW_KINDS, Route, Row, mark_label};
use crate::report::{Analysis, DISCLAIMER, ModelReport, QueryReport, Run};
use crate::template::{Ctx, Dialect, escape_tex, escaped_tex, render, templates};
use crate::types::TraceStep;
use crate::util::{article, plural};
use math::Names;

static TEX: Dialect = Dialect {
	open: "<<",
	close: ">>",
	escape: escape_tex,
	partial,
};

templates! { TEX,
	PAGE "page" = "tpl/page.tex",
	SUMMARY "summary" = "tpl/summary.tex",
	MODEL "model" = "tpl/model.tex",
	FACTS "facts" = "tpl/facts.tex",
	ERROR "error" = "tpl/error.tex",
	DIAGRAM "diagram" = "tpl/diagram.tex",
	ACTOR "actor" = "tpl/actor.tex",
	DIAGRAM_ROW "diagram_row" = "tpl/diagram_row.tex",
	VERDICTS "verdicts" = "tpl/verdicts.tex",
	VERDICT "verdict" = "tpl/verdict.tex",
	TRACE "trace" = "tpl/trace.tex",
	TRACE_STEP "trace_step" = "tpl/trace_step.tex",
	SCOPE "scope" = "tpl/scope.tex",
	CALLOUTS "callouts" = "tpl/callouts.tex",
	SOURCE "source" = "tpl/source.tex",
}

const PREAMBLE: &str = include_str!("preamble.tex");

pub fn tex_report(run: &Run) -> String {
	let multi = run.models.len() > 1;
	let heading = heading(run);
	let ctx = Ctx::new()
		.text("version", run.version.as_str())
		.raw("preamble", PREAMBLE.trim_end())
		.text("title", format!("Verifpal analysis of {heading}"))
		.text("heading", heading)
		.list("stats", stats(run))
		.raw("abstract", abstract_of(run))
		.flag("multi", multi)
		.list("index", index(run))
		.list(
			"models",
			run.models
				.iter()
				.enumerate()
				.map(|(i, model)| model_ctx(model, i))
				.collect(),
		)
		.list(
			"sources",
			run.models
				.iter()
				.enumerate()
				.map(|(i, model)| source_ctx(model, i))
				.collect(),
		)
		.text("disclaimer", DISCLAIMER);
	let mut out = render(&PAGE, &ctx);
	out.push('\n');
	out
}

fn slug(model: &ModelReport, index: usize) -> String {
	let mut out = String::new();
	for c in model.short_name().chars() {
		if c.is_ascii_alphanumeric() {
			out.push(c.to_ascii_lowercase());
		} else if !out.ends_with('-') {
			out.push('-');
		}
	}
	format!("{}-{index}", out.trim_matches('-'))
}

fn heading(run: &Run) -> String {
	match run.models.as_slice() {
		[only] => only.short_name().to_string(),
		models => format!("{} models", models.len()),
	}
}

fn stat(value: impl std::fmt::Display, label: &str, alert: bool) -> Ctx {
	Ctx::new()
		.text("value", value.to_string())
		.text("label", label)
		.flag("alert", alert)
}

fn stats(run: &Run) -> Vec<Ctx> {
	match run.models.as_slice() {
		[only] => match &only.analysis {
			Some(a) => vec![
				stat(a.queries.len(), "queries", false),
				stat(a.attacks, "attacks found", a.attacks > 0),
				stat(
					a.queries.len().saturating_sub(a.attacks),
					"no attack found",
					false,
				),
			],
			None => vec![stat("--", "not analysed", true)],
		},
		_ => {
			let tally = run.tally();
			let mut out = vec![
				stat(tally.models, "models", false),
				stat(tally.queries, "queries", false),
				stat(tally.attacks, "attacks found", tally.attacks > 0),
				stat(tally.attacked, "models attacked", tally.attacked > 0),
			];
			if tally.failed() > 0 {
				out.push(stat(tally.failed(), "not analysed", true));
			}
			out
		}
	}
}

fn abstract_of(run: &Run) -> String {
	let mut out = String::new();
	match run.models.as_slice() {
		[only] => {
			out.push_str(&format!(
				"This report describes the analysis of the Verifpal model {} ",
				math_name(only.short_name())
			));
			match &only.analysis {
				Some(a) => out.push_str(&format!(
					"against {} {} attacker, with each principal running {} concurrent \
					 session{}. Of its {} quer{}, {} {} broken.",
					article(&a.attacker),
					escaped_tex(&a.attacker),
					a.sessions,
					plural(a.sessions as usize),
					a.queries.len(),
					if a.queries.len() == 1 { "y" } else { "ies" },
					a.attacks,
					if a.attacks == 1 { "was" } else { "were" }
				)),
				None => out.push_str("which could not be analysed."),
			}
		}
		_ => {
			let tally = run.tally();
			out.push_str(&format!(
				"This report describes the analysis of {} Verifpal models carrying {} quer{} \
				 between them. Attacks were found against {} of the models, {} in all.",
				tally.models,
				tally.queries,
				if tally.queries == 1 { "y" } else { "ies" },
				tally.attacked,
				tally.attacks
			));
			if tally.failed() > 0 {
				out.push_str(&format!(
					" {} model{} could not be analysed at all.",
					tally.failed(),
					plural(tally.failed())
				));
			}
		}
	}
	out.push_str(" Every attack reported here is a witness against the model as written. ");
	out.push_str(
		"A query reported as holding means that this search found no attack at these \
		 parameters, which is not a proof that none exists.",
	);
	out
}

fn math_name(name: &str) -> String {
	format!("\\texttt{{{}}}", escaped_tex(name))
}

fn result_code(a: &Analysis) -> String {
	let pairs: Vec<String> = a.code_pairs().map(escaped_tex).collect();
	format!("\\vpcode{{{}}}", pairs.join("\\allowbreak{}"))
}

fn elapsed(ms: u128) -> String {
	if ms < 1000 {
		format!("{ms} ms")
	} else {
		format!("{:.1} s", ms as f64 / 1000.0)
	}
}

fn index(run: &Run) -> Vec<Ctx> {
	if run.models.len() < 2 {
		return Vec::new();
	}
	run.models
		.iter()
		.enumerate()
		.map(|(i, model)| {
			let (attacker, sessions, code) = match &model.analysis {
				Some(a) => (a.attacker.clone(), a.sessions.to_string(), result_code(a)),
				None => ("--".to_string(), "--".to_string(), "--".to_string()),
			};
			Ctx::new()
				.raw("file", math_name(model.short_name()))
				.text("slug", slug(model, i))
				.text("attacker", attacker)
				.text("sessions", sessions)
				.raw("code", code)
				.flag("hit", model.attacks() > 0)
				.num("attacks", model.attacks())
		})
		.collect()
}

fn model_ctx(model: &ModelReport, index: usize) -> Ctx {
	let slug = slug(model, index);
	let names = Names::of(model);
	let failed = match &model.error {
		Some(error) => vec![
			Ctx::new().raw(
				"error",
				error
					.lines()
					.map(|line| format!("\\mbox{{}}{}", escaped_tex(line).replace(' ', "~")))
					.collect::<Vec<String>>()
					.join("\\\\\n"),
			),
		],
		None => Vec::new(),
	};
	let ctx = Ctx::new()
		.raw("name", math_name(model.short_name()))
		.text("nameplain", model.short_name())
		.text("slug", slug.clone())
		.list("failed", failed);
	let Some(a) = &model.analysis else {
		return ctx
			.list("facts", Vec::new())
			.list("protocol", Vec::new())
			.list("verdicts", Vec::new())
			.flag("attacked", false)
			.list("traces", Vec::new())
			.list("scope", Vec::new());
	};
	let hits = a.attacked_values();
	let protocol = Chart::protocol(model, &hits)
		.map(|chart| diagram_ctx(&chart, format!("{slug}-protocol"), protocol_caption(&hits)));
	ctx.list("facts", vec![facts_ctx(a)])
		.list("protocol", protocol.into_iter().collect())
		.list("verdicts", vec![verdicts_ctx(a, &slug, &names)])
		.flag("attacked", a.attacks > 0)
		.list("traces", traces(a, model, &slug, &names))
		.list("scope", vec![scope_ctx(a, &names)])
}

fn protocol_caption(hits: &std::collections::HashMap<String, Vec<usize>>) -> String {
	if hits.is_empty() {
		"The protocol as written. Guarded values are bracketed.".to_string()
	} else {
		"The protocol as written. Guarded values are bracketed; a dagger marks every value \
		 an attack below substitutes or replays."
			.to_string()
	}
}

fn facts_ctx(a: &Analysis) -> Ctx {
	let queries = match a.attacks {
		0 => format!("{}, with no attack found", a.queries.len()),
		n => format!("{}, with {} attack{} found", a.queries.len(), n, plural(n)),
	};
	Ctx::new()
		.text("attacker", a.attacker.as_str())
		.text("sessions", format!("{} per principal", a.sessions))
		.text("queries", queries)
		.raw("code", result_code(a))
		.text("elapsed", elapsed(a.elapsed_ms))
		.list(
			"provenance",
			a.provenance
				.iter()
				.map(|sentence| Ctx::new().text("text", sentence.as_str()))
				.collect(),
		)
}

fn diagram_ctx(chart: &Chart, figid: String, caption: String) -> Ctx {
	let actors = chart
		.lanes
		.names()
		.iter()
		.enumerate()
		.map(|(i, name)| {
			Ctx::new()
				.num("index", i)
				.text("name", name.as_str())
				.flag("adversary", name == ATTACKER)
		})
		.collect();
	let drawn = chart
		.rows
		.iter()
		.map(|row| row_ctx(&chart.lanes, row))
		.collect();
	Ctx::new()
		.text("figid", figid)
		.num("lanes", chart.lanes.len())
		.raw("caption", caption)
		.list("actors", actors)
		.list("rows", drawn)
}

fn activity_line(kind: &str, names: String, primitive: &str) -> Ctx {
	let ctx = Ctx::new().one_of(&["fresh", "derived", "checked", "alias", "checkonly"], kind);
	let rendered = if primitive.is_empty() {
		String::new()
	} else {
		math::term(primitive)
	};
	ctx.raw("names", names).raw("primitive", rendered)
}

fn math_list(names: &[String]) -> String {
	names
		.iter()
		.map(|name| math::term(name))
		.collect::<Vec<String>>()
		.join(", ")
}

fn row_ctx(lanes: &Lanes, row: &Row) -> Ctx {
	let ctx = Ctx::new().one_of(&ROW_KINDS, row.kind());
	match row {
		Row::Wire {
			hop,
			step,
			from,
			to,
			route,
			values,
		} => {
			let breach = route.breached();
			let style = match route {
				Route::Replayed => "vpreplay",
				Route::Forged => "vpforged",
				Route::Direct => "vpplain",
			};
			let label = values
				.iter()
				.map(|v| math::label(&v.name, v.guarded, v.hit() || breach))
				.collect::<Vec<String>>()
				.join(", ");
			ctx.flag("breach", breach)
				.text("numstyle", if breach { "vpnumadv" } else { "vpnum" })
				.num("from", lanes.index(from))
				.num(
					"via",
					if breach {
						lanes.index(ATTACKER) as i64
					} else {
						-1
					},
				)
				.num("to", lanes.index(to))
				.text("style", style)
				.text(
					"step",
					step.or(*hop).map(|n| n.to_string()).unwrap_or_default(),
				)
				.raw("label", label)
		}
		Row::Phase { number } => ctx.num("number", *number),
		Row::Leak { principal, values } => ctx
			.num("lane", lanes.index(principal))
			.raw("values", math_list(values)),
		Row::Activity {
			principal,
			generates,
			computes,
		} => {
			let mut lines: Vec<Ctx> = Vec::new();
			if !generates.is_empty() {
				lines.push(activity_line("fresh", math_list(generates), ""));
			}
			for step in computes {
				let named = math_list(&step.names);
				let shown = step.expression.as_deref().or(step.primitive.as_deref());
				lines.push(match (shown, step.checked, step.names.is_empty()) {
					(Some(shown), _, true) => activity_line("checkonly", named, shown),
					(Some(shown), false, _) => activity_line("derived", named, shown),
					(Some(shown), true, _) => activity_line("checked", named, shown),
					(None, _, _) => activity_line("alias", named, ""),
				});
			}
			ctx.num("lane", lanes.index(principal)).list("lines", lines)
		}
		Row::Mark {
			step,
			principal,
			bypass,
		} => ctx
			.num("lane", lanes.index(principal))
			.text("markstyle", if *bypass { "vpnoteadv" } else { "vpnote" })
			.text("numstyle", "vpnumadv")
			.num("step", step)
			.text("text", mark_label(*bypass)),
		Row::Run { first, last } => {
			let (numstyle, step) = if first == last {
				("vpnum", first.to_string())
			} else {
				("vpnumwide", format!("{first}\u{2013}{last}"))
			};
			ctx.num("lane", lanes.index(ATTACKER))
				.text("numstyle", numstyle)
				.text("step", step)
				.text("text", "computes")
		}
	}
}

fn sentence(text: &str, names: &Names) -> String {
	math::prose(&text.replace("->", "\u{2192}"), names)
}

struct Query {
	head: String,
	plain: String,
	options: String,
}

fn split_options(text: &str) -> (&str, Vec<&str>) {
	match text.find("[precondition[") {
		Some(at) if text.ends_with(']') => (
			&text[..at],
			text[at + 1..text.len() - 1]
				.split("precondition[")
				.map(|option| option.trim().trim_end_matches(']').trim())
				.filter(|option| !option.is_empty())
				.collect(),
		),
		_ => (text, Vec::new()),
	}
}

fn query_of(text: &str, names: &Names) -> Query {
	let (head, options) = split_options(text);
	Query {
		head: query_tex(head, names),
		plain: head.to_string(),
		options: options
			.iter()
			.map(|option| format!("\\vpprecondition{{{}}}", operands(option, names)))
			.collect::<Vec<String>>()
			.join("\\newline"),
	}
}

fn query_tex(text: &str, names: &Names) -> String {
	let Some((kind, rest)) = text.split_once("? ") else {
		return sentence(text, names);
	};
	format!(
		"\\textsf{{{}?}}~{}",
		escaped_tex(kind),
		operands(rest, names)
	)
}

fn operands(rest: &str, names: &Names) -> String {
	if let Some((route, value)) = rest.split_once(": ") {
		return format!("{}: {}", sentence(route, names), operands(value, names));
	}
	rest.split(", ")
		.map(|operand| math::framed(operand).unwrap_or_else(|| sentence(operand, names)))
		.collect::<Vec<String>>()
		.join(", ")
}

fn attack_id(slug: &str, qi: usize) -> String {
	format!("{slug}-{qi}")
}

fn verdicts_ctx(a: &Analysis, slug: &str, names: &Names) -> Ctx {
	let queries = a
		.queries
		.iter()
		.enumerate()
		.map(|(qi, q)| {
			let query = query_of(&q.query, names);
			Ctx::new()
				.raw("query", query.head)
				.raw("options", query.options)
				.flag("resolved", q.resolved)
				.raw("envelope", envelope_tex(q, &attack_id(slug, qi)))
				.text("loc", query_location(q))
		})
		.collect();
	Ctx::new()
		.text("tabid", format!("{slug}-verdicts"))
		.text(
			"caption",
			"Every query in the model, with the verdict this run reached.",
		)
		.list("queries", queries)
}

fn envelope_tex(q: &QueryReport, id: &str) -> String {
	if q.resolved {
		let found = format!("witness in \\S\\ref{{atk:{id}}}");
		return match &q.subtype {
			Some(subtype) => format!("{found}; {}", escaped_tex(subtype)),
			None => found,
		};
	}
	escaped_tex(&q.envelope.summary)
}

fn query_location(q: &QueryReport) -> String {
	if q.generated {
		"generated".to_string()
	} else {
		q.range.line.to_string()
	}
}

fn traces(a: &Analysis, model: &ModelReport, slug: &str, names: &Names) -> Vec<Ctx> {
	a.queries
		.iter()
		.enumerate()
		.filter(|(_, q)| q.resolved)
		.map(|(qi, q)| {
			let query = query_of(&q.query, names);
			let diagram = Chart::attack(q, model).map(|chart| {
				diagram_ctx(
					&chart,
					format!("{slug}-attack-{qi}"),
					format!(
						"How the attacker breaks \\textnormal{{{}}}. Substituted values carry a \
						 dagger.",
						query.head
					),
				)
			});
			Ctx::new()
				.raw("query", query.head)
				.text("queryplain", query.plain)
				.text("atkid", attack_id(slug, qi))
				.raw("options", query.options)
				.raw("lead", sentence(&q.conclusion, names))
				.list("diagram", diagram.into_iter().collect())
				.flag("stepped", q.has_trace())
				.list(
					"steps",
					q.steps.iter().map(|step| step_ctx(step, names)).collect(),
				)
				.list("preconditions", prose_lines(&q.preconditions, names))
				.list("notes", prose_lines(&q.notes, names))
		})
		.collect()
}

fn prose_lines(texts: &[String], names: &Names) -> Vec<Ctx> {
	texts
		.iter()
		.map(|text| Ctx::new().raw("text", sentence(text, names)))
		.collect()
}

fn step_ctx(s: &TraceStep, names: &Names) -> Ctx {
	let wire = s.sender.is_some() && s.recipient.is_some();
	Ctx::new()
		.raw("text", sentence(&s.text, names))
		.flag("wire", wire)
		.text("sender", s.sender.clone().unwrap_or_default())
		.text("recipient", s.recipient.clone().unwrap_or_default())
}

fn scope_ctx(a: &Analysis, names: &Names) -> Ctx {
	let callouts = callouts(a, names);
	Ctx::new()
		.text("text", a.scope())
		.flag("hascallouts", !callouts.is_empty())
		.list("callouts", callouts)
}

fn callouts(a: &Analysis, names: &Names) -> Vec<Ctx> {
	let mut out: Vec<String> = Vec::new();
	for assumption in &a.assumptions {
		let onset = if assumption.from_phase > 0 {
			format!(" from phase {} onward", assumption.from_phase)
		} else {
			String::new()
		};
		out.push(format!(
			"The model assumes {} is {}{}, which weakens it deliberately.",
			math::term(&assumption.term),
			escaped_tex(&assumption.capability),
			onset
		));
	}
	for scenario in &a.scenarios {
		let bindings = scenario
			.bindings
			.iter()
			.map(|b| format!("{} as {}", math::term(&b.target), math::term(&b.value)))
			.collect::<Vec<String>>()
			.join(", ");
		let peer = match scenario.corrupt_from {
			None => "an honest peer".to_string(),
			Some(0) => "a compromised peer".to_string(),
			Some(phase) => format!("a peer compromised from phase {phase}"),
		};
		out.push(format!(
			"Scenario: {} runs with {}, {}.",
			escaped_tex(&scenario.principal),
			bindings,
			peer
		));
	}
	for note in &a.notes {
		out.push(sentence(note, names));
	}
	out.into_iter()
		.map(|text| Ctx::new().raw("text", text))
		.collect()
}

fn source_ctx(model: &ModelReport, index: usize) -> Ctx {
	Ctx::new()
		.raw("name", math_name(model.short_name()))
		.text("nameplain", model.short_name())
		.text("slug", slug(model, index))
		.flag("empty", model.source.trim().is_empty())
		.raw("source", listing_safe(model.source.trim_end()))
}

pub(crate) const LISTING: &str = "lstlisting";

const WITHHELD: &str = "// [line withheld: it would have closed this listing]";

pub(crate) fn listing_terminator() -> String {
	["\\", "end{", LISTING, "}"].concat()
}

fn closes_listing(line: &str, terminator: &str) -> bool {
	line.chars()
		.filter(|c| !c.is_whitespace())
		.collect::<String>()
		.contains(terminator)
}

fn listing_safe(source: &str) -> String {
	let terminator = listing_terminator();
	source
		.lines()
		.map(|line| {
			if closes_listing(line, &terminator) {
				WITHHELD.to_string()
			} else {
				line.chars().map(listing_glyph).collect()
			}
		})
		.collect::<Vec<String>>()
		.join("\n")
}

fn listing_glyph(c: char) -> char {
	match c {
		'\u{2500}'..='\u{257f}' => match c {
			'\u{2500}' | '\u{2501}' | '\u{2504}' | '\u{2505}' | '\u{2508}' | '\u{2509}'
			| '\u{254c}' | '\u{254d}' | '\u{2550}' => '-',
			'\u{2502}' | '\u{2503}' | '\u{2506}' | '\u{2507}' | '\u{250a}' | '\u{250b}'
			| '\u{254e}' | '\u{254f}' | '\u{2551}' => '|',
			_ => '+',
		},
		'\u{25b6}' | '\u{25b8}' | '\u{25ba}' => '>',
		'\u{25c0}' | '\u{25c2}' | '\u{25c4}' => '<',
		_ => c,
	}
}

#[cfg(test)]
mod tests;
