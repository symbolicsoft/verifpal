/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

mod math;

use crate::msc::{self, ATTACKER, Lanes, Row};
use crate::report::{Analysis, DISCLAIMER, ModelReport, QueryReport, ReportStep, Run};
use crate::template::{Ctx, Dialect, escape_tex, escaped_tex, render, templates};
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
	let ctx = Ctx::new()
		.text("version", run.version.as_str())
		.raw("preamble", PREAMBLE.trim_end())
		.text("title", title(run))
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

fn short_name(model: &ModelReport) -> &str {
	match &model.analysis {
		Some(a) => &a.model,
		None => model.file.rsplit('/').next().unwrap_or(&model.file),
	}
}

fn slug(model: &ModelReport, index: usize) -> String {
	let mut out = String::new();
	for c in short_name(model).chars() {
		if c.is_ascii_alphanumeric() {
			out.push(c.to_ascii_lowercase());
		} else if !out.ends_with('-') {
			out.push('-');
		}
	}
	format!("{}-{index}", out.trim_matches('-'))
}

fn title(run: &Run) -> String {
	match run.models.as_slice() {
		[only] => format!("Verifpal analysis of {}", short_name(only)),
		models => format!("Verifpal analysis of {} models", models.len()),
	}
}

fn attacks_of(model: &ModelReport) -> usize {
	model.analysis.as_ref().map(|a| a.attacks).unwrap_or(0)
}

fn abstract_of(run: &Run) -> String {
	let analysed: Vec<&Analysis> = run
		.models
		.iter()
		.filter_map(|m| m.analysis.as_ref())
		.collect();
	let broken = run.models.len() - analysed.len();
	let hit: usize = run.models.iter().filter(|m| attacks_of(m) > 0).count();
	let attacks: usize = run.models.iter().map(attacks_of).sum();
	let queries: usize = analysed.iter().map(|a| a.queries.len()).sum();
	let mut out = String::new();
	match run.models.as_slice() {
		[only] => {
			out.push_str(&format!(
				"This report describes the analysis of the Verifpal model {} ",
				math_name(short_name(only))
			));
			match &only.analysis {
				Some(a) => out.push_str(&format!(
					"against {} {} attacker, with each principal running {} concurrent \
					 session{}. Of its {} quer{}, {} {} broken.",
					crate::util::article(&a.attacker),
					escaped_tex(&a.attacker),
					a.sessions,
					crate::util::plural(a.sessions as usize),
					a.queries.len(),
					if a.queries.len() == 1 { "y" } else { "ies" },
					attacks,
					if attacks == 1 { "was" } else { "were" }
				)),
				None => out.push_str("which could not be analysed."),
			}
		}
		models => {
			out.push_str(&format!(
				"This report describes the analysis of {} Verifpal models carrying {} quer{} \
				 between them. Attacks were found against {} of the models, {} in all.",
				models.len(),
				queries,
				if queries == 1 { "y" } else { "ies" },
				hit,
				attacks
			));
			if broken > 0 {
				out.push_str(&format!(
					" {} model{} could not be analysed at all.",
					broken,
					crate::util::plural(broken)
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

fn index(run: &Run) -> Vec<Ctx> {
	if run.models.len() < 2 {
		return Vec::new();
	}
	run.models
		.iter()
		.map(|model| {
			let (attacker, sessions, code) = match &model.analysis {
				Some(a) => (a.attacker.clone(), a.sessions.to_string(), a.code.clone()),
				None => ("--".to_string(), "--".to_string(), "--".to_string()),
			};
			Ctx::new()
				.raw("file", math_name(short_name(model)))
				.text("attacker", attacker)
				.text("sessions", sessions)
				.text("code", code)
				.num("attacks", attacks_of(model))
		})
		.collect()
}

fn model_ctx(model: &ModelReport, index: usize) -> Ctx {
	let slug = slug(model, index);
	let names = Names::of(model, model.analysis.as_ref());
	let failed = match &model.error {
		Some(error) => vec![Ctx::new().text("error", error.as_str())],
		None => Vec::new(),
	};
	let ctx = Ctx::new()
		.raw("name", math_name(short_name(model)))
		.text("nameplain", short_name(model))
		.text("slug", slug.clone())
		.list("failed", failed);
	let Some(a) = &model.analysis else {
		return ctx
			.flag("ok", false)
			.text("intro", String::new())
			.list("protocol", Vec::new())
			.list("verdicts", Vec::new())
			.flag("attacked", false)
			.list("traces", Vec::new())
			.list("scope", Vec::new());
	};
	let hits = attacked_values(a);
	let rows = msc::protocol_rows(model, &hits);
	let protocol = diagram_ctx(
		&rows,
		Lanes::of(&rows),
		format!("{slug}-protocol"),
		protocol_caption(&hits),
		true,
		&names,
	);
	ctx.flag("ok", true)
		.raw("intro", intro(a))
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

fn intro(a: &Analysis) -> String {
	let mut out = format!(
		"Analysed against {} {} attacker at {} session{} per principal, in {} ms. \
		 The result code is \\texttt{{{}}}.",
		crate::util::article(&a.attacker),
		escaped_tex(&a.attacker),
		a.sessions,
		crate::util::plural(a.sessions as usize),
		a.elapsed_ms,
		escaped_tex(&a.code)
	);
	for sentence in &a.provenance {
		out.push(' ');
		out.push_str(&escaped_tex(sentence));
	}
	out
}

fn attacked_values(a: &Analysis) -> std::collections::HashMap<String, Vec<usize>> {
	let mut out: std::collections::HashMap<String, Vec<usize>> = std::collections::HashMap::new();
	for (qi, q) in a.queries.iter().enumerate() {
		if !q.resolved {
			continue;
		}
		for step in &q.steps {
			for value in &step.values {
				let queries = out
					.entry(crate::util::copy_base_name(&value.name).to_string())
					.or_default();
				if !queries.contains(&qi) {
					queries.push(qi);
				}
			}
		}
	}
	out
}

fn diagram_ctx(
	rows: &[Row],
	lanes: Lanes,
	figid: String,
	caption: String,
	floats: bool,
	names: &Names,
) -> Option<Ctx> {
	if lanes.is_empty() || rows.is_empty() {
		return None;
	}
	let actors = lanes
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
	let drawn = rows.iter().map(|row| row_ctx(&lanes, row, names)).collect();
	Some(
		Ctx::new()
			.text("figid", figid)
			.flag("float", floats)
			.num("lanes", lanes.len())
			.raw("caption", caption)
			.list("actors", actors)
			.list("rows", drawn),
	)
}

// The box is one fixed width, so a line longer than it wraps and the row has to
// leave room for the wrapped height. This mirrors the width the preamble
// computes from the lane count; guessing high only adds white space.
const TEXT_CM: f32 = 16.6;
const CHAR_CM: f32 = 0.145;

fn box_chars(lanes: usize) -> usize {
	let lanes = lanes.max(1) as f32;
	let sep = (4.6f32).max((TEXT_CM - 1.4) / (lanes - 1.0).max(1.0));
	let width = (3.2f32).max(((TEXT_CM - 1.2) / lanes - 0.5).min(sep - 0.9));
	((width / CHAR_CM) as usize).max(8)
}

fn wrapped(text: &str, chars: usize) -> usize {
	text.chars().count().div_ceil(chars).max(1)
}

fn activity_line(kind: &str, names: String, primitive: &str) -> Ctx {
	let mut ctx = Ctx::new();
	for name in ["fresh", "derived", "checked", "alias", "checkonly"] {
		ctx = ctx.flag(name, name == kind);
	}
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

fn math_list_str(names: &str) -> String {
	names
		.split(", ")
		.map(math::term)
		.collect::<Vec<String>>()
		.join(", ")
}

fn base(kind: &'static str) -> Ctx {
	let mut ctx = Ctx::new();
	for name in ["wire", "phase", "leak", "activity", "mark", "run"] {
		ctx = ctx.flag(name, name == kind);
	}
	ctx
}

fn row_ctx(lanes: &Lanes, row: &Row, _names: &Names) -> Ctx {
	let chars = box_chars(lanes.len());
	match row {
		Row::Wire {
			num,
			step,
			from,
			to,
			via,
			forged,
			replay,
			values,
			..
		} => {
			let breach = *forged || *replay;
			let style = if *replay {
				"vpreplay"
			} else if *forged {
				"vpforged"
			} else {
				"vpplain"
			};
			let label = values
				.iter()
				.map(|v| math::label(&v.name, v.guarded, v.hit || (breach && v.changed)))
				.collect::<Vec<String>>()
				.join(",\\, ");
			base("wire")
				.flag("breach", breach)
				.text("numstyle", if breach { "vpnumadv" } else { "vpnum" })
				.num("from", lanes.index(from))
				.num(
					"via",
					via.as_ref()
						.map(|name| lanes.index(name) as i64)
						.unwrap_or(-1),
				)
				.num("to", lanes.index(to))
				.text("style", style)
				.text(
					"step",
					step.clone()
						.or(num.map(|n| n.to_string()))
						.unwrap_or_default(),
				)
				.raw("label", label)
		}
		Row::Phase { number } => base("phase").num("number", *number),
		Row::Leak { principal, text } => base("leak")
			.num("lane", lanes.index(principal))
			.num("lines", wrapped(text, chars))
			.text("text", text.as_str()),
		Row::Activity {
			principal,
			generates,
			computes,
		} => {
			let mut lines: Vec<Ctx> = Vec::new();
			let mut count = 0usize;
			if !generates.is_empty() {
				count += wrapped(&format!("new {}", generates.join(", ")), chars);
				lines.push(activity_line("fresh", math_list(generates), ""));
			}
			for step in computes {
				count += wrapped(&step.label(), chars);
				let named = math_list_str(&step.names);
				let bare = step.names.is_empty();
				let shown = step.expression.as_deref().or(step.primitive.as_deref());
				lines.push(match (shown, step.checked, bare) {
					(Some(shown), _, true) => activity_line("checkonly", named, shown),
					(Some(shown), false, _) => activity_line("derived", named, shown),
					(Some(shown), true, _) => activity_line("checked", named, shown),
					(None, _, _) => activity_line("alias", named, ""),
				});
			}
			base("activity")
				.num("lane", lanes.index(principal))
				.num("count", count)
				.list("lines", lines)
		}
		Row::Mark {
			step,
			principal,
			bypass,
			..
		} => base("mark")
			.num("lane", lanes.index(principal))
			.text("markstyle", if *bypass { "vpnoteadv" } else { "vpnote" })
			.text("numstyle", "vpnumadv")
			.text("step", step.clone().unwrap_or_default())
			.text(
				"text",
				if *bypass {
					"check defeated"
				} else {
					"check passes"
				},
			),
		Row::Run { step, .. } => {
			let step = step.replace('-', "\u{2013}");
			let ranged = step.contains('\u{2013}');
			base("run")
				.num(
					"lane",
					if lanes.contains(ATTACKER) {
						lanes.index(ATTACKER)
					} else {
						0
					},
				)
				.text("numstyle", if ranged { "vpnumwide" } else { "vpnum" })
				.text("step", step)
				.text("text", "computes")
		}
	}
}

fn sentence(text: &str, names: &Names) -> String {
	math::prose(&text.replace("->", "\u{2192}"), names)
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
		.map(|operand| match math::parse(operand) {
			Some(parsed) => format!("\\vpterm{{{}}}", math::render(&parsed)),
			None => sentence(operand, names),
		})
		.collect::<Vec<String>>()
		.join(", ")
}

fn verdicts_ctx(a: &Analysis, slug: &str, names: &Names) -> Ctx {
	let queries = a
		.queries
		.iter()
		.map(|q| {
			Ctx::new()
				.raw("query", query_tex(&q.query, names))
				.flag("resolved", q.resolved)
				.text("envelope", envelope_text(q))
				.num("line", q.range.line)
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

fn envelope_text(q: &QueryReport) -> String {
	if q.resolved {
		return "a witness, shown below".to_string();
	}
	q.envelope.summary.clone()
}

fn has_trace(q: &QueryReport) -> bool {
	q.resolved && !q.steps.is_empty()
}

fn traces(a: &Analysis, model: &ModelReport, slug: &str, names: &Names) -> Vec<Ctx> {
	a.queries
		.iter()
		.enumerate()
		.filter(|(_, q)| q.resolved)
		.map(|(qi, q)| {
			let (rows, lanes) = msc::attack_rows(q, model);
			let diagram = diagram_ctx(
				&rows,
				lanes,
				format!("{slug}-attack-{qi}"),
				format!(
					"How the attacker breaks \\textnormal{{{}}}. Substituted values carry a \
					 dagger.",
					query_tex(&q.query, names)
				),
				false,
				names,
			);
			Ctx::new()
				.raw("query", query_tex(&q.query, names))
				.text("queryplain", q.query.as_str())
				.raw("lead", sentence(&q.conclusion, names))
				.list("diagram", diagram.into_iter().collect())
				.flag("stepped", has_trace(q))
				.list("steps", steps(q, names))
				.list(
					"preconditions",
					q.preconditions
						.iter()
						.map(|text| Ctx::new().raw("text", sentence(text, names)))
						.collect(),
				)
		})
		.collect()
}

fn steps(q: &QueryReport, names: &Names) -> Vec<Ctx> {
	q.steps.iter().map(|step| step_ctx(step, names)).collect()
}

fn step_ctx(s: &ReportStep, names: &Names) -> Ctx {
	let wire = s.sender.is_some() && s.recipient.is_some();
	Ctx::new()
		.raw("text", sentence(&s.text, names))
		.flag("wire", wire)
		.text("sender", s.sender.clone().unwrap_or_default())
		.text("recipient", s.recipient.clone().unwrap_or_default())
}

fn scope_ctx(a: &Analysis, names: &Names) -> Ctx {
	let mut reasons: Vec<&str> = Vec::new();
	for q in &a.queries {
		for t in &q.envelope.truncations {
			if !reasons.contains(&t.as_str()) {
				reasons.push(t);
			}
		}
	}
	let mut text = format!(
		"Every verdict above was reached against {} {} attacker, with each principal running \
		 {} concurrent session{}, over exactly the model as written. An attack is a witness \
		 and stands on its own. A query reported as holding says only that this search found \
		 no attack at those parameters: the search space this engine defines was explored, \
		 which is never the space of all attacks.",
		crate::util::article(&a.attacker),
		escaped_tex(&a.attacker),
		a.sessions,
		crate::util::plural(a.sessions as usize)
	);
	if !reasons.is_empty() {
		text.push_str(&format!(
			" Some searches in this run stopped short even of that ({}), so their holds cover \
			 less still.",
			escaped_tex(&reasons.join(", "))
		));
	}
	let callouts = callouts(a, names);
	Ctx::new()
		.raw("text", text)
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
		let peer = if scenario.honest {
			"honest"
		} else {
			"compromised"
		};
		out.push(format!(
			"Scenario: {} runs with {}, {} {} peer.",
			escaped_tex(&scenario.principal),
			bindings,
			crate::util::article(peer),
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
		.raw("name", math_name(short_name(model)))
		.text("nameplain", short_name(model))
		.text("slug", slug(model, index))
		.flag("empty", model.source.trim().is_empty())
		.raw("source", model.source.trim_end())
}

#[cfg(test)]
mod tests;
