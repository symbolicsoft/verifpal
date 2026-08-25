/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashSet;

use crate::report::{Analysis, ModelReport, QueryReport, Run};
use crate::tokens::{Token, TokenKind};
use crate::types::{Block, Constant, Declaration, Message, Model};
use crate::util::base_name;

const CSS: &str = include_str!("report.css");
const JS: &str = include_str!("report.js");
const PAGE: &str = include_str!("tpl/page.html");
const MODEL: &str = include_str!("tpl/model.html");
const META: &str = include_str!("tpl/meta.html");
const META_FAILED: &str = include_str!("tpl/meta_failed.html");
const CODE_PAIR: &str = include_str!("tpl/code_pair.html");
const ERROR: &str = include_str!("tpl/error.html");
const VERDICTS: &str = include_str!("tpl/verdicts.html");
const VERDICT: &str = include_str!("tpl/verdict.html");
const BECAUSE: &str = include_str!("tpl/because.html");
const PRECONDITION: &str = include_str!("tpl/precondition.html");
const ASSUMPTIONS: &str = include_str!("tpl/assumptions.html");
const ASSUMPTION_ITEM: &str = include_str!("tpl/assumption_item.html");
const TRACE: &str = include_str!("tpl/trace.html");
const TRACE_STEP: &str = include_str!("tpl/trace_step.html");
const TRACE_STEP_WIRE: &str = include_str!("tpl/trace_step_wire.html");
const TRACE_VALUE: &str = include_str!("tpl/trace_value.html");
const TRACE_VALUE_WAS: &str = include_str!("tpl/trace_value_was.html");
const TRACE_VALUE_RELAY: &str = include_str!("tpl/trace_value_relay.html");
const SOURCE: &str = include_str!("tpl/source.html");
const SOURCE_MARK: &str = include_str!("tpl/source_mark.html");
const SOURCE_TOKEN: &str = include_str!("tpl/source_token.html");
const DIAGRAM: &str = include_str!("tpl/diagram.html");
const DIAGRAM_ACTOR: &str = include_str!("tpl/diagram_actor.html");
const DIAGRAM_WIRE: &str = include_str!("tpl/diagram_wire.html");
const DIAGRAM_LABEL_VALUE: &str = include_str!("tpl/diagram_label_value.html");
const DIAGRAM_LABEL_SEP: &str = include_str!("tpl/diagram_label_sep.html");
const DIAGRAM_LEAK: &str = include_str!("tpl/diagram_leak.html");
const DIAGRAM_PHASE: &str = include_str!("tpl/diagram_phase.html");
const ATTACK_DIAGRAM: &str = include_str!("tpl/attack_diagram.html");
const ATTACK_ROW: &str = include_str!("tpl/attack_row.html");
const ATTACK_SEG: &str = include_str!("tpl/attack_seg.html");
const ATTACK_NODE: &str = include_str!("tpl/attack_node.html");
const ATTACK_RUN: &str = include_str!("tpl/attack_run.html");

const COL_WIDTH: usize = 220;
const ROW_HEIGHT: usize = 42;
const TOP: usize = 56;
const NUM_X: usize = 22;
const ATTACKER: &str = "Attacker";

pub fn html_report(run: &Run, sources: &[String]) -> String {
	let mut body = String::new();
	for (i, model) in run.models.iter().enumerate() {
		let source = sources.get(i).map(String::as_str).unwrap_or("");
		body.push_str(&model_section(model, source, i));
		body.push('\n');
	}
	let subject = match run.models.as_slice() {
		[only] => format!(" \u{00b7} {}", escape(short_name(only))),
		_ => String::new(),
	};
	let mut out = fill(
		asset(PAGE),
		&[
			("subject", &subject),
			("style", asset(CSS)),
			("script", asset(JS)),
			("version", &escape(&run.version)),
			("body", body.trim_end()),
		],
	);
	out.push('\n');
	out
}

fn short_name(model: &ModelReport) -> &str {
	match &model.analysis {
		Some(a) => &a.model,
		None => model.file.rsplit('/').next().unwrap_or(&model.file),
	}
}

fn model_section(model: &ModelReport, source: &str, index: usize) -> String {
	let body = match (&model.analysis, &model.error) {
		(Some(analysis), _) => analysis_section(analysis, source, index),
		(None, Some(error)) => fill(asset(ERROR), &[("error", &escape(error))]),
		(None, None) => String::new(),
	};
	fill(
		asset(MODEL),
		&[
			("file", &escape(&model.file)),
			("meta", &head_meta(model)),
			("body", &body),
		],
	)
}

fn head_meta(model: &ModelReport) -> String {
	let Some(a) = &model.analysis else {
		return asset(META_FAILED).to_string();
	};
	fill(
		asset(META),
		&[
			("sessions", &a.sessions.to_string()),
			("plural", if a.sessions == 1 { "" } else { "s" }),
			("elapsed", &a.elapsed_ms.to_string()),
			("code", &code_spans(&a.code)),
		],
	)
}

fn code_spans(code: &str) -> String {
	let mut out = String::new();
	let mut chars = code.chars();
	while let (Some(kind), Some(digit)) = (chars.next(), chars.next()) {
		out.push_str(&fill(
			asset(CODE_PAIR),
			&[
				("class", if digit == '0' { "pass" } else { "fail" }),
				("pair", &escape(&format!("{kind}{digit}"))),
			],
		));
	}
	out
}

fn analysis_section(a: &Analysis, source: &str, index: usize) -> String {
	let attacked = attacked_names(a);
	let mut out = String::new();
	let mut tokens: Vec<Token> = Vec::new();
	if !source.is_empty() {
		let (parsed, index_tokens) = crate::parser::parse_string_indexed("report.vp", source);
		tokens = index_tokens.tokens().to_vec();
		tokens.sort_by_key(|t| t.span.start);
		if let Ok(m) = &parsed {
			out.push_str(&diagram_svg(m, &attacked, &format!("m{index}p")));
		}
	}
	out.push_str(&verdicts_section(a, index));
	for (ti, q) in a
		.queries
		.iter()
		.filter(|q| q.resolved && !q.steps.is_empty())
		.enumerate()
	{
		out.push_str(&trace_section(q, &format!("m{index}t{ti}")));
	}
	if !source.is_empty() {
		out.push_str(&source_pane(source, &a.queries, index, &tokens));
	}
	out
}

fn attacked_names(a: &Analysis) -> HashSet<String> {
	let mut out = HashSet::new();
	for q in &a.queries {
		for s in &q.steps {
			let replay = s.kind == "replay";
			if !replay && s.kind != "mutations" {
				continue;
			}
			for v in &s.values {
				if replay || v.was != v.installed {
					out.insert(base_name(&v.name).to_string());
				}
			}
		}
	}
	out
}

fn verdicts_section(a: &Analysis, index: usize) -> String {
	let total = a.queries.len();
	let (tally_class, tally) = if a.attacks == 0 {
		("pass", format!("All {total} queries pass."))
	} else {
		("fail", format!("{} of {total} queries failed.", a.attacks))
	};
	let mut rows = String::new();
	for (qi, q) in a.queries.iter().enumerate() {
		rows.push_str(&verdict_row(q, index, qi));
		rows.push('\n');
	}
	fill(
		asset(VERDICTS),
		&[
			("tally_class", tally_class),
			("tally", &tally),
			("rows", rows.trim_end()),
			("assumptions", &assumptions_callout(a)),
		],
	)
}

fn verdict_row(q: &QueryReport, model_index: usize, query_index: usize) -> String {
	let (class, mark, ruling) = if q.resolved {
		("verdictFail", "\u{00d7}", "Contradiction found")
	} else {
		("verdictPass", "\u{2713}", "Holds")
	};
	let because = if q.resolved && !q.conclusion.is_empty() {
		fill(asset(BECAUSE), &[("text", &escape(&q.conclusion))])
	} else {
		String::new()
	};
	let mut preconditions = String::new();
	for p in &q.preconditions {
		preconditions.push_str(&fill(asset(PRECONDITION), &[("text", &escape(p))]));
	}
	fill(
		asset(VERDICT),
		&[
			("class", class),
			("mark", mark),
			("model", &model_index.to_string()),
			("query_index", &query_index.to_string()),
			("query", &escape(&q.query)),
			("line", &q.range.line.to_string()),
			("ruling", ruling),
			("because", &because),
			("preconditions", &preconditions),
		],
	)
}

fn assumptions_callout(a: &Analysis) -> String {
	if a.assumptions.is_empty() {
		return String::new();
	}
	let mut items = String::new();
	for assumption in &a.assumptions {
		let onset = if assumption.from_phase > 0 {
			format!(" (from phase {})", assumption.from_phase)
		} else {
			String::new()
		};
		items.push_str(&fill(
			asset(ASSUMPTION_ITEM),
			&[
				("term", &escape(&assumption.term)),
				("onset", &escape(&onset)),
			],
		));
		items.push('\n');
	}
	fill(
		asset(ASSUMPTIONS),
		&[
			("count", &a.assumptions.len().to_string()),
			("plural", if a.assumptions.len() == 1 { "" } else { "s" }),
			("items", items.trim_end()),
		],
	)
}

fn trace_section(q: &QueryReport, svgid: &str) -> String {
	let mut steps = String::new();
	for (i, s) in q.steps.iter().enumerate() {
		let n = (i + 1).to_string();
		let structured = s.kind == "mutations"
			&& !s.values.is_empty()
			&& s.sender.is_some()
			&& s.recipient.is_some();
		let rendered = if structured {
			fill(
				asset(TRACE_STEP_WIRE),
				&[
					("n", &n),
					("kind", &escape(&s.kind)),
					("sender", &escape(s.sender.as_deref().unwrap_or(""))),
					("recipient", &escape(s.recipient.as_deref().unwrap_or(""))),
					("vals", &trace_values(q, i)),
				],
			)
		} else {
			fill(
				asset(TRACE_STEP),
				&[
					("n", &n),
					("kind", &escape(&s.kind)),
					("text", &escape(&s.text)),
				],
			)
		};
		steps.push_str(&rendered);
		steps.push('\n');
	}
	fill(
		asset(TRACE),
		&[
			("query", &escape(&q.query)),
			("diagram", &attack_svg(q, svgid)),
			("steps", steps.trim_end()),
		],
	)
}

fn trace_values(q: &QueryReport, step: usize) -> String {
	let mut out = String::new();
	for v in &q.steps[step].values {
		let relayed = v.was.is_some() && v.was == v.installed;
		if relayed {
			out.push_str(&fill(
				asset(TRACE_VALUE_RELAY),
				&[("name", &escape(&v.name))],
			));
			continue;
		}
		let was = match &v.was {
			Some(w) => fill(asset(TRACE_VALUE_WAS), &[("was", &escape(w))]),
			None => String::new(),
		};
		out.push_str(&fill(
			asset(TRACE_VALUE),
			&[
				("name", &escape(&v.name)),
				("installed", &escape(v.installed.as_deref().unwrap_or(""))),
				("was", &was),
			],
		));
	}
	out
}

fn attack_svg(q: &QueryReport, svgid: &str) -> String {
	let mut lanes: Vec<String> = Vec::new();
	for s in &q.steps {
		for name in [&s.sender, &s.recipient, &s.principal]
			.into_iter()
			.flatten()
		{
			if !lanes.iter().any(|l| l == name) {
				lanes.push(name.clone());
			}
		}
	}
	if lanes.is_empty() {
		return String::new();
	}
	lanes.insert(1.min(lanes.len()), ATTACKER.to_string());
	let width = lanes.len() * COL_WIDTH;
	let center =
		|name: &str| lanes.iter().position(|l| l == name).unwrap_or(0) * COL_WIDTH + COL_WIDTH / 2;
	let attacker_x = center(ATTACKER);
	let arrow = format!("{svgid}-arrow");
	let arrow_b = format!("{svgid}-arrowB");

	let mut rows: Vec<String> = Vec::new();
	let mut run: Option<(usize, usize)> = None;
	let flush = |run: &mut Option<(usize, usize)>, rows: &mut Vec<String>| {
		let Some((from, to)) = run.take() else {
			return;
		};
		let y = TOP + rows.len() * ROW_HEIGHT;
		let label = if from == to {
			format!("computes (step {from})")
		} else {
			format!("computes (steps {from}\u{2013}{to})")
		};
		let n = if from == to {
			from.to_string()
		} else {
			format!("{from}-{to}")
		};
		rows.push(fill(
			asset(ATTACK_RUN),
			&[
				("n", &n),
				("x", &(attacker_x.saturating_sub(80)).to_string()),
				("y", &(y.saturating_sub(13)).to_string()),
				("w", "160"),
				("h", "22"),
				("tx", &attacker_x.to_string()),
				("ty", &(y + 2).to_string()),
				("label", &label),
			],
		));
	};
	for (i, s) in q.steps.iter().enumerate() {
		let n = i + 1;
		let names: Vec<String> = s.values.iter().map(|v| v.name.clone()).collect();
		let label = names.join(", ");
		match (s.kind.as_str(), &s.sender, &s.recipient, &s.principal) {
			("mutations", Some(sender), Some(recipient), _) => {
				flush(&mut run, &mut rows);
				let y = TOP + rows.len() * ROW_HEIGHT;
				let forged = s.values.iter().any(|v| v.was != v.installed);
				let (x1, x2) = (center(sender), center(recipient));
				let mut content = fill(
					asset(ATTACK_SEG),
					&[
						("x1", &x1.to_string()),
						("x2", &attacker_x.to_string()),
						("y", &y.to_string()),
						("class", "wireMuted"),
						("marker", &arrow),
					],
				);
				content.push_str(&fill(
					asset(ATTACK_SEG),
					&[
						("x1", &attacker_x.to_string()),
						("x2", &x2.to_string()),
						("y", &y.to_string()),
						("class", if forged { "wireForged" } else { "wireMuted" }),
						("marker", if forged { &arrow_b } else { &arrow }),
					],
				));
				rows.push(fill(
					asset(ATTACK_ROW),
					&[
						("n", &n.to_string()),
						("numx", &NUM_X.to_string()),
						("label_y", &(y - 7).to_string()),
						("content", &content),
						("mid", &((attacker_x + x2) / 2).to_string()),
						("lclass", if forged { "forged" } else { "" }),
						("label", &escape(&label)),
					],
				));
			}
			("replay", _, Some(recipient), _) => {
				flush(&mut run, &mut rows);
				let y = TOP + rows.len() * ROW_HEIGHT;
				let x2 = center(recipient);
				let content = fill(
					asset(ATTACK_SEG),
					&[
						("x1", &attacker_x.to_string()),
						("x2", &x2.to_string()),
						("y", &y.to_string()),
						("class", "wireReplay"),
						("marker", &arrow_b),
					],
				);
				rows.push(fill(
					asset(ATTACK_ROW),
					&[
						("n", &n.to_string()),
						("numx", &NUM_X.to_string()),
						("label_y", &(y - 7).to_string()),
						("content", &content),
						("mid", &((attacker_x + x2) / 2).to_string()),
						("lclass", "forged"),
						("label", &escape(&format!("{label} (replayed)"))),
					],
				));
			}
			("received", Some(sender), Some(recipient), _) => {
				flush(&mut run, &mut rows);
				let y = TOP + rows.len() * ROW_HEIGHT;
				let (x1, x2) = (center(sender), center(recipient));
				let content = fill(
					asset(ATTACK_SEG),
					&[
						("x1", &x1.to_string()),
						("x2", &x2.to_string()),
						("y", &y.to_string()),
						("class", "wire"),
						("marker", &arrow),
					],
				);
				rows.push(fill(
					asset(ATTACK_ROW),
					&[
						("n", &n.to_string()),
						("numx", &NUM_X.to_string()),
						("label_y", &(y - 7).to_string()),
						("content", &content),
						("mid", &((x1 + x2) / 2).to_string()),
						("lclass", ""),
						("label", &escape(&label)),
					],
				));
			}
			("gate", _, _, Some(principal)) | ("bypass", _, _, Some(principal)) => {
				flush(&mut run, &mut rows);
				let y = TOP + rows.len() * ROW_HEIGHT;
				let x = center(principal);
				let bypass = s.kind == "bypass";
				rows.push(fill(
					asset(ATTACK_NODE),
					&[
						("n", &n.to_string()),
						("numx", &NUM_X.to_string()),
						("label_y", &(y + 4).to_string()),
						("x", &x.to_string()),
						("y", &y.to_string()),
						("class", if bypass { "bypassMark" } else { "gateMark" }),
						("tx", &(x + 12).to_string()),
						("lclass", if bypass { "breach" } else { "" }),
						(
							"label",
							if bypass {
								"check defeated"
							} else {
								"check passes"
							},
						),
					],
				));
			}
			_ => {
				run = match run {
					Some((from, _)) => Some((from, n)),
					None => Some((n, n)),
				};
			}
		}
	}
	flush(&mut run, &mut rows);
	if rows.is_empty() {
		return String::new();
	}
	let height = TOP + rows.len() * ROW_HEIGHT + 16;
	let mut content = String::new();
	for lane in &lanes {
		let aclass = if lane == ATTACKER { " attacker" } else { "" };
		content.push_str(&fill(
			asset(DIAGRAM_ACTOR),
			&[
				("x", &center(lane).to_string()),
				("bottom", &(height - 8).to_string()),
				("name", &escape(lane)),
				("aclass", aclass),
			],
		));
		content.push('\n');
	}
	for row in rows {
		content.push_str(&row);
		content.push('\n');
	}
	fill(
		asset(ATTACK_DIAGRAM),
		&[
			("svgid", svgid),
			("width", &width.to_string()),
			("height", &height.to_string()),
			("content", content.trim_end()),
		],
	)
}

enum ProtoRow<'a> {
	Wire(&'a Message),
	Phase(i32),
	Leak(String, String),
}

fn diagram_svg(m: &Model, attacked: &HashSet<String>, svgid: &str) -> String {
	let mut principals: Vec<String> = Vec::new();
	for block in &m.blocks {
		if let Block::Message(msg) = block {
			for name in [msg.sender_name.as_ref(), msg.recipient_name.as_ref()] {
				if !principals.iter().any(|p| p == name) {
					principals.push(name.to_string());
				}
			}
		}
	}
	if principals.is_empty() {
		return String::new();
	}
	let mut rows: Vec<ProtoRow> = Vec::new();
	for block in &m.blocks {
		match block {
			Block::Message(msg) => rows.push(ProtoRow::Wire(msg)),
			Block::Phase(phase) => rows.push(ProtoRow::Phase(phase.number)),
			Block::Principal(p) => {
				if !principals.iter().any(|name| name == &p.name) {
					continue;
				}
				for expr in &p.expressions {
					if expr.kind != Declaration::Leaks {
						continue;
					}
					let names: Vec<&str> = expr.constants.iter().map(|c| c.name.as_ref()).collect();
					rows.push(ProtoRow::Leak(
						p.name.clone(),
						format!("{} leaks {}", p.name, names.join(", ")),
					));
				}
			}
		}
	}
	let width = principals.len() * COL_WIDTH;
	let height = TOP + rows.len() * ROW_HEIGHT + 16;
	let center = |name: &str| {
		principals.iter().position(|p| p == name).unwrap_or(0) * COL_WIDTH + COL_WIDTH / 2
	};
	let arrow = format!("{svgid}-arrow");
	let mut content = String::new();
	for p in &principals {
		content.push_str(&fill(
			asset(DIAGRAM_ACTOR),
			&[
				("x", &center(p).to_string()),
				("bottom", &(height - 8).to_string()),
				("name", &escape(p)),
				("aclass", ""),
			],
		));
		content.push('\n');
	}
	let mut y = TOP;
	let mut hop = 0usize;
	for row in rows {
		match row {
			ProtoRow::Wire(msg) => {
				hop += 1;
				let x1 = center(&msg.sender_name);
				let x2 = center(&msg.recipient_name);
				content.push_str(&fill(
					asset(DIAGRAM_WIRE),
					&[
						("num", &hop.to_string()),
						("numx", &NUM_X.to_string()),
						("x1", &x1.to_string()),
						("x2", &x2.to_string()),
						("y", &y.to_string()),
						("mid", &((x1 + x2) / 2).to_string()),
						("label_y", &(y - 7).to_string()),
						("marker", &arrow),
						("label", &wire_label(&msg.constants, attacked)),
					],
				));
			}
			ProtoRow::Phase(number) => {
				content.push_str(&fill(
					asset(DIAGRAM_PHASE),
					&[
						("y", &y.to_string()),
						("width", &width.to_string()),
						("label_y", &(y - 7).to_string()),
						("number", &number.to_string()),
					],
				));
			}
			ProtoRow::Leak(principal, text) => {
				content.push_str(&fill(
					asset(DIAGRAM_LEAK),
					&[
						("x", &center(&principal).to_string()),
						("y", &(y - 2).to_string()),
						("text", &escape(&text)),
					],
				));
			}
		}
		content.push('\n');
		y += ROW_HEIGHT;
	}
	fill(
		asset(DIAGRAM),
		&[
			("svgid", svgid),
			("width", &width.to_string()),
			("height", &height.to_string()),
			("content", content.trim_end()),
		],
	)
}

fn wire_label(constants: &[Constant], attacked: &HashSet<String>) -> String {
	let mut out = String::new();
	for (i, c) in constants.iter().enumerate() {
		if i > 0 {
			out.push_str(asset(DIAGRAM_LABEL_SEP));
		}
		let hit = attacked.contains(base_name(&c.name));
		let vclass = if hit {
			" hit"
		} else if c.guard {
			" guarded"
		} else {
			""
		};
		let text = if c.guard {
			format!("[{}]", c.name)
		} else {
			c.name.to_string()
		};
		out.push_str(&fill(
			asset(DIAGRAM_LABEL_VALUE),
			&[("vclass", vclass), ("text", &escape(&text))],
		));
	}
	out
}

fn source_pane(
	source: &str,
	queries: &[QueryReport],
	model_index: usize,
	tokens: &[Token],
) -> String {
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
	let mut body = String::new();
	let mut at = 0usize;
	for (start, end, resolved, i) in marks {
		if start < at {
			continue;
		}
		body.push_str(&highlight(source, at, start, tokens));
		body.push_str(&fill(
			asset(SOURCE_MARK),
			&[
				("model", &model_index.to_string()),
				("query_index", &i.to_string()),
				("class", if resolved { "fail" } else { "pass" }),
				("text", &escape(&source[start..end])),
			],
		));
		at = end;
	}
	body.push_str(&highlight(source, at, source.len(), tokens));
	fill(asset(SOURCE), &[("body", &body)])
}

fn highlight(source: &str, from: usize, to: usize, tokens: &[Token]) -> String {
	let mut out = String::new();
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
		out.push_str(&escape(&source[at..t.span.start]));
		out.push_str(&fill(
			asset(SOURCE_TOKEN),
			&[
				("class", class),
				("text", &escape(&source[t.span.start..t.span.end])),
			],
		));
		at = t.span.end;
	}
	out.push_str(&escape(&source[at..to]));
	out
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
		| TokenKind::Arrow
		| TokenKind::Assign
		| TokenKind::Check
		| TokenKind::Anonymous => None,
	}
}

fn fill(template: &str, values: &[(&str, &str)]) -> String {
	let mut out = String::with_capacity(template.len());
	let mut rest = template;
	while let Some(start) = rest.find("{{") {
		out.push_str(&rest[..start]);
		let after = &rest[start + 2..];
		let Some(end) = after.find("}}") else {
			out.push_str(&rest[start..]);
			return out;
		};
		let key = &after[..end];
		match values.iter().find(|(k, _)| *k == key) {
			Some((_, value)) => out.push_str(value),
			None => out.push_str(&rest[start..start + end + 4]),
		}
		rest = &after[end + 2..];
	}
	out.push_str(rest);
	out
}

fn asset(raw: &str) -> &str {
	let trimmed = raw.trim_start();
	let body = if let Some(after) = trimmed.strip_prefix("<!--") {
		after.split_once("-->").map(|(_, tail)| tail)
	} else if let Some(after) = trimmed.strip_prefix("/*") {
		after.split_once("*/").map(|(_, tail)| tail)
	} else {
		None
	};
	body.unwrap_or(raw).trim_ascii()
}

fn escape(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for c in s.chars() {
		match c {
			'&' => out.push_str("&amp;"),
			'<' => out.push_str("&lt;"),
			'>' => out.push_str("&gt;"),
			'"' => out.push_str("&quot;"),
			'\'' => out.push_str("&#39;"),
			_ => out.push(c),
		}
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::report::{Assumption, ReportStep, SourceRange};
	use crate::types::TraceValue;

	fn empty_analysis() -> Analysis {
		Analysis {
			model: "t.vp".to_string(),
			sessions: 2,
			code: "c0".to_string(),
			attacks: 0,
			elapsed_ms: 1,
			assumptions: vec![],
			queries: vec![],
		}
	}

	fn query(resolved: bool, text: &str, conclusion: &str) -> QueryReport {
		QueryReport {
			query: text.to_string(),
			kind: "confidentiality".to_string(),
			resolved,
			range: SourceRange {
				start: 0,
				end: 0,
				line: 9,
				column: 2,
			},
			summary: conclusion.to_string(),
			conclusion: conclusion.to_string(),
			steps: vec![ReportStep::new(
				"derive".to_string(),
				"Attacker constructs PUBKEY(nil) from nil.".to_string(),
			)],
			preconditions: vec![],
			variants: 0,
		}
	}

	fn mutation_step() -> ReportStep {
		ReportStep {
			kind: "mutations".to_string(),
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

	fn gate_step() -> ReportStep {
		ReportStep {
			kind: "gate".to_string(),
			text: "Bob's AEAD_DEC(k, e, ad)? passes.".to_string(),
			sender: None,
			recipient: None,
			principal: Some("Bob".to_string()),
			values: vec![],
		}
	}

	#[test]
	fn html_escapes_every_special_character() {
		assert_eq!(escape("a<b>&\"'z"), "a&lt;b&gt;&amp;&quot;&#39;z");
		assert_eq!(escape("plain"), "plain");
	}

	#[test]
	fn assets_strip_their_license_header() {
		assert!(asset(PAGE).starts_with("<!doctype html>"));
		assert!(asset(CSS).starts_with(":root"));
		assert!(asset(JS).starts_with("(function"));
		assert!(!asset(VERDICT).contains("SPDX"));
	}

	#[test]
	fn fill_replaces_only_template_placeholders() {
		let filled = fill(
			asset(SOURCE),
			&[("body", "literal {{body}} and {{style}} stay put")],
		);
		assert!(filled.contains("literal {{body}} and {{style}} stay put"));
	}

	#[test]
	fn a_page_is_a_complete_standalone_document() {
		let run = Run {
			version: "1.2.1".to_string(),
			ok: true,
			models: vec![ModelReport {
				file: "t.vp".to_string(),
				ok: true,
				error: None,
				analysis: Some(empty_analysis()),
			}],
		};
		let html = html_report(&run, &[String::new()]);
		assert!(
			html.starts_with("<!doctype html>"),
			"{}",
			&html[..40.min(html.len())]
		);
		assert!(html.contains("<style>"));
		assert!(html.contains("t.vp"));
		assert!(html.contains("Verifpal 1.2.1"));
		assert!(html.ends_with("</html>\n"));
		assert_eq!(
			html.matches("<script>").count(),
			1,
			"exactly one inline script"
		);
		assert!(!html.contains("<link"), "no external resources");
		assert!(!html.contains("src="), "no external loads");
	}

	#[test]
	fn a_failed_model_renders_its_error_escaped() {
		let run = Run {
			version: "1.2.1".to_string(),
			ok: false,
			models: vec![ModelReport {
				file: "broken.vp".to_string(),
				ok: false,
				error: Some("parse error: expected `]` near <knows>".to_string()),
				analysis: None,
			}],
		};
		let html = html_report(&run, &[String::new()]);
		assert!(html.contains("parse error: expected `]` near &lt;knows&gt;"));
		assert!(!html.contains("near <knows>"));
		assert!(html.contains("analysis failed"));
	}

	#[test]
	fn verdicts_carry_ruling_conclusion_steps_and_location() {
		let mut a = empty_analysis();
		a.queries = vec![
			query(true, "confidentiality? m", "m is obtained by Attacker."),
			query(false, "confidentiality? k", ""),
		];
		a.attacks = 1;
		a.code = "c1c0".to_string();
		let html = analysis_section(&a, "", 0);
		assert!(html.contains("Contradiction found"));
		assert!(html.contains("Holds"));
		assert!(html.contains("m is obtained by Attacker."));
		assert!(html.contains("Attacker constructs PUBKEY(nil) from nil."));
		assert!(html.contains("1 of 2 queries failed."));
		assert!(html.contains("line 9"));
		assert!(html.contains("verdictFail"));
		assert!(html.contains("verdictPass"));
	}

	#[test]
	fn a_holding_query_gets_no_attack_trace() {
		let mut a = empty_analysis();
		a.queries = vec![query(false, "confidentiality? k", "")];
		let html = analysis_section(&a, "", 0);
		assert!(!html.contains("Attack trace"));
		assert!(html.contains("All 1 queries pass."));
	}

	#[test]
	fn attack_step_text_is_escaped() {
		let mut a = empty_analysis();
		let mut q = query(true, "confidentiality? m", "<script>alert(1)</script>");
		q.steps[0].text = "<img onerror=x>".to_string();
		a.queries = vec![q];
		a.attacks = 1;
		let html = analysis_section(&a, "", 0);
		assert!(!html.contains("<script>alert"));
		assert!(!html.contains("<img onerror"));
		assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
	}

	#[test]
	fn declared_assumptions_render_as_a_callout() {
		let mut a = empty_analysis();
		a.assumptions = vec![Assumption {
			term: "HASH[weak](m)".to_string(),
			capability: "weak".to_string(),
			from_phase: 2,
		}];
		let html = analysis_section(&a, "", 0);
		assert!(html.contains("weakening assumption"));
		assert!(html.contains("HASH[weak](m)"));
		assert!(html.contains("(from phase 2)"));
	}

	#[test]
	fn the_result_code_is_split_into_verdict_pairs() {
		let spans = code_spans("c1a0");
		assert!(spans.contains(">c1</span>"));
		assert!(spans.contains(">a0</span>"));
		assert!(spans.contains("class=\"fail\">c1"));
		assert!(spans.contains("class=\"pass\">a0"));
	}

	#[test]
	fn a_mutation_step_renders_structured_value_rows() {
		let mut q = query(true, "authentication? Alice -> Bob: ga", "");
		q.steps = vec![mutation_step()];
		let html = trace_section(&q, "m0t0");
		assert!(html.contains("Attacker intercepts the message from Alice to Bob"));
		assert!(html.contains("class=\"tvName\">ga</span>"));
		assert!(html.contains("class=\"tvNew\">PUBKEY(nil)</span>"));
		assert!(html.contains("honest value: PUBKEY(a)"));
		assert!(html.contains("data-step=\"1\""));
	}

	#[test]
	fn an_attack_diagram_draws_the_attacker_lane_and_numbered_rows() {
		let mut q = query(true, "authentication? Alice -> Bob: ga", "");
		q.steps = vec![
			ReportStep::new(
				"derive".to_string(),
				"Attacker constructs PUBKEY(nil) from nil.".to_string(),
			),
			mutation_step(),
			gate_step(),
		];
		let html = trace_section(&q, "m0t0");
		assert!(html.contains("diagram attack"));
		assert!(html.contains(">Attacker</text>"));
		assert!(html.contains("computes (step 1)"));
		assert!(html.contains("class=\"wireForged\""));
		assert!(html.contains("class=\"gateMark\""));
		assert!(html.contains("data-step=\"2\""));
		assert!(html.contains("data-step=\"3\""));
	}

	#[test]
	fn a_trace_with_no_wire_story_gets_no_diagram() {
		let q = query(true, "freshness? x", "");
		let html = trace_section(&q, "m0t0");
		assert!(!html.contains("<svg"));
	}

	#[test]
	fn source_pane_marks_query_spans_with_verdict_classes() {
		let source = "queries[\n\tconfidentiality? m\n]\n";
		let start = source.find("confidentiality").expect("query");
		let end = start + "confidentiality? m".len();
		let mut q = query(true, "confidentiality? m", "");
		q.range = SourceRange {
			start,
			end,
			line: 2,
			column: 2,
		};
		let html = source_pane(source, &[q], 0, &[]);
		assert!(html.contains("<mark id=\"src-m0-q0\" class=\"fail\">confidentiality? m</mark>"));
		assert!(html.contains("queries["));
	}

	#[test]
	fn source_pane_survives_bad_ranges() {
		let source = "short\n";
		let mut q = query(false, "confidentiality? m", "");
		q.range = SourceRange {
			start: 100,
			end: 200,
			line: 1,
			column: 1,
		};
		let html = source_pane(source, &[q], 0, &[]);
		assert!(html.contains("short"));
		assert!(!html.contains("<mark"));
	}

	#[test]
	fn source_pane_escapes_the_model_text() {
		let html = source_pane("knows private a<b\n", &[], 0, &[]);
		assert!(html.contains("a&lt;b"));
	}

	#[test]
	fn the_source_pane_is_highlighted_by_the_engines_own_lexer() {
		let src = "// a comment\nattacker[active]\n\nprincipal Alice[\n\tknows private hlt_m\n\thlt_h = HASH(hlt_m)\n]\n\nAlice -> Bob: hlt_h\n\nprincipal Bob[\n\t_ = HASH(hlt_h)\n]\n\nqueries[\n\tconfidentiality? hlt_m\n]\n";
		let (parsed, index_tokens) = crate::parser::parse_string_indexed("report.vp", src);
		assert!(parsed.is_ok());
		let mut tokens = index_tokens.tokens().to_vec();
		tokens.sort_by_key(|t| t.span.start);
		let html = source_pane(src, &[], 0, &tokens);
		assert!(html.contains("class=\"c\">"), "comments are highlighted");
		assert!(
			html.contains("class=\"f\">HASH"),
			"primitives are highlighted"
		);
		assert!(
			html.contains("class=\"p\">Alice"),
			"principals are highlighted"
		);
		assert!(
			html.contains("class=\"q\">confidentiality"),
			"queries are highlighted"
		);
		assert!(
			html.contains("class=\"k\">knows"),
			"keywords are highlighted"
		);
	}

	#[test]
	fn a_diagram_draws_numbered_hops_guards_hits_and_leaks() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private hdg_m\n\tknows private hdg_s\n\thdg_h = HASH(hdg_m)\n]\n\nAlice -> Bob: [hdg_h], hdg_m\n\nphase[1]\n\nprincipal Alice[\n\tleaks hdg_s\n]\n\nprincipal Bob[\n\t_ = HASH(hdg_h)\n]\n\nqueries[\n\tconfidentiality? hdg_m\n]\n";
		let m = crate::parser::parse_string("report.vp", src).expect("parses");
		let mut attacked = HashSet::new();
		attacked.insert("hdg_m".to_string());
		let svg = diagram_svg(&m, &attacked, "m0p");
		assert!(svg.contains("<svg"));
		assert!(svg.contains(">Alice</text>"));
		assert!(svg.contains(">Bob</text>"));
		assert!(svg.contains("class=\"hopNum\">1</text>"));
		assert!(svg.contains("class=\"msgVal guarded\">[hdg_h]</tspan>"));
		assert!(svg.contains("class=\"msgVal hit\">hdg_m</tspan>"));
		assert!(svg.contains("Alice leaks hdg_s"));
		assert!(svg.contains("phase[1]"));
	}

	#[test]
	fn a_model_without_messages_gets_no_diagram() {
		let src = "attacker[passive]\n\nprincipal Alice[\n\tknows private hdn_m\n\t_ = HASH(hdn_m)\n]\n\nqueries[\n\tconfidentiality? hdn_m\n]\n";
		let m = crate::parser::parse_string("report.vp", src).expect("parses");
		assert!(diagram_svg(&m, &HashSet::new(), "m0p").is_empty());
	}

	#[test]
	fn an_end_to_end_report_carries_diagram_marks_and_verdicts() {
		let (report, source) =
			crate::verify::verify_report_with_source("examples/test/hmac_ok.vp", 2)
				.expect("verifies");
		let path = "examples/test/hmac_ok.vp".to_string();
		let run = Run::of(
			"1.2.1",
			&[(path, Ok(report))],
			std::slice::from_ref(&source),
		);
		let html = html_report(&run, std::slice::from_ref(&source));
		assert!(html.contains("<svg"));
		assert!(html.contains("confidentiality?"));
		assert!(html.contains("<mark id=\"src-m0-q0\""));
		assert!(html.contains("verdictPass"));
	}

	#[test]
	fn an_attack_report_narrates_and_draws_the_trace() {
		let (report, source) =
			crate::verify::verify_report_with_source("examples/simple.vp", 2).expect("verifies");
		let path = "examples/simple.vp".to_string();
		let run = Run::of(
			"1.2.1",
			&[(path, Ok(report))],
			std::slice::from_ref(&source),
		);
		let html = html_report(&run, std::slice::from_ref(&source));
		assert!(html.contains("verdictFail"));
		assert!(html.contains("Contradiction found"));
		assert!(html.contains("Attack trace"));
		assert!(html.contains("class=\"traceStep\" data-step="));
		assert!(html.contains("diagram attack"));
		assert!(html.contains(">Attacker</text>"));
		assert!(html.contains("class=\"msgVal hit\""));
	}
}
