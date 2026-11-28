/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::report::msc::{
	ATTACKER, Chart, Lanes, Mark, ROW_KINDS, Route, Row, Value, computation_label, span,
};
use crate::report::template::Ctx;

const COL_MIN: usize = 200;
const COL_MAX: usize = 460;
const COL_TARGET: usize = 910;
const ROW_HEIGHT: usize = 42;
const LABEL_LINE: usize = 14;
const TOP: usize = 56;
const NUM_X: usize = 22;
const LABEL_PAD: usize = 28;
const ACTOR_PAD: usize = 30;
const LABEL_PX: f32 = 11.0;
const ACTOR_PX: f32 = 13.0;
const ADVANCE: f32 = 0.6;
const BOX_PX: f32 = 11.0;
const BOX_PAD: usize = 9;
const BOX_LINE: usize = 16;
const BOX_INSET: usize = 12;
const BOX_COLS: usize = 52;

fn value_label(value: &Value) -> String {
	let mut out = if value.guarded {
		format!("[{}]", value.name)
	} else {
		value.name.clone()
	};
	if value.hit() {
		out.push('\u{2020}');
	}
	out
}

fn wire_label(values: &[Value], route: Route) -> String {
	let joined = values
		.iter()
		.map(value_label)
		.collect::<Vec<String>>()
		.join(", ");
	match route.note() {
		"" => joined,
		note => format!("{joined} ({note})"),
	}
}

fn hop_lead(hop: Option<usize>, step: Option<usize>) -> String {
	match (step, hop) {
		(Some(_), Some(hop)) => format!("hop {hop} \u{b7} "),
		_ => String::new(),
	}
}

fn reach<'a>(route: Route, from: &'a str, to: &'a str) -> (&'a str, &'a str) {
	match route {
		Route::Direct => (from, to),
		Route::Forged | Route::Replayed => (ATTACKER, to),
		Route::Dropped => (from, ATTACKER),
	}
}

fn leak_text(principal: &str, values: &[String]) -> String {
	format!("{principal} leaks {}", values.join(", "))
}

fn run_label(first: usize, last: usize) -> String {
	if first == last {
		format!("computes (step {first})")
	} else {
		format!("computes (steps {first}\u{2013}{last})")
	}
}

#[derive(Clone)]
struct Part {
	text: String,
	class: &'static str,
}

fn box_lines(row: &Row) -> Vec<Vec<Part>> {
	match row {
		Row::Activity {
			generates,
			computes,
			..
		} => {
			let mut lines: Vec<Vec<Part>> = Vec::new();
			if !generates.is_empty() {
				lines.push(vec![
					Part {
						text: "generates ".to_string(),
						class: "actKey",
					},
					Part {
						text: generates.join(", "),
						class: "actFresh",
					},
				]);
			}
			for step in computes {
				let mut parts = Vec::new();
				if !step.names.is_empty() {
					parts.push(Part {
						text: step.names.join(", "),
						class: "actName",
					});
				}
				let shown = step.expression.as_ref().or(step.primitive.as_ref());
				if let Some(shown) = shown {
					if !step.names.is_empty() {
						parts.push(Part {
							text: " \u{2190} ".to_string(),
							class: "actArrow",
						});
					}
					parts.push(Part {
						text: shown.clone(),
						class: if step.checked { "actCheck" } else { "actPrim" },
					});
				}
				lines.push(parts);
			}
			reflow(lines)
		}
		Row::Leak { principal, values } => reflow(vec![vec![Part {
			text: leak_text(principal, values),
			class: "leakText",
		}]]),
		_ => Vec::new(),
	}
}

fn line_text(parts: &[Part]) -> String {
	parts.iter().map(|p| p.text.as_str()).collect()
}

fn reflow(lines: Vec<Vec<Part>>) -> Vec<Vec<Part>> {
	let mut out: Vec<Vec<Part>> = Vec::new();
	for parts in lines {
		if line_text(&parts).chars().count() <= BOX_COLS {
			out.push(parts);
			continue;
		}
		let (head, tail) = parts.split_at(parts.len() - 1);
		let class = tail[0].class;
		let lead: usize = head.iter().map(|p| p.text.chars().count()).sum();
		let mut room = BOX_COLS.saturating_sub(lead).max(12);
		let mut current: Vec<Part> = head.to_vec();
		let mut held = String::new();
		for (i, chunk) in tail[0].text.split_inclusive(", ").enumerate() {
			if i > 0 && held.chars().count() + chunk.chars().count() > room {
				current.push(Part {
					text: std::mem::take(&mut held),
					class,
				});
				out.push(std::mem::take(&mut current));
				current.push(Part {
					text: "    ".to_string(),
					class: "actArrow",
				});
				room = BOX_COLS.saturating_sub(4);
			}
			held.push_str(chunk);
		}
		if !held.is_empty() {
			current.push(Part { text: held, class });
		}
		if !current.is_empty() {
			out.push(current);
		}
	}
	out
}

fn box_width(row: &Row) -> usize {
	box_lines(row)
		.iter()
		.map(|parts| width_of(&line_text(parts), BOX_PX) + BOX_PAD * 2)
		.max()
		.unwrap_or(0)
}

fn width_of(text: &str, size: f32) -> usize {
	(text.chars().count() as f32 * size * ADVANCE).ceil() as usize
}

fn label_width(text: &str) -> usize {
	width_of(text, LABEL_PX) + LABEL_PAD
}

struct Columns<'a> {
	lanes: &'a Lanes,
	column: usize,
	boxw: usize,
}

struct Label<'a> {
	center: usize,
	right: usize,
	values: &'a [Value],
}

impl<'a> Columns<'a> {
	fn of(chart: &'a Chart) -> Columns<'a> {
		let lanes = &chart.lanes;
		let widest = chart.rows.iter().map(box_width).max().unwrap_or(0);
		let actors = lanes
			.names()
			.iter()
			.map(|name| width_of(name, ACTOR_PX) + ACTOR_PAD)
			.fold(COL_MIN, usize::max);
		let mut column = actors;
		for row in &chart.rows {
			let (needed, span) = match row {
				Row::Wire {
					hop,
					step,
					from,
					to,
					route,
					values,
				} => {
					let (start, end) = reach(*route, from, to);
					let label = hop_lead(*hop, *step) + &wire_label(values, *route);
					(
						label_width(&label),
						lanes.index(start).abs_diff(lanes.index(end)).max(1),
					)
				}
				Row::Phase { number } => {
					(label_width(&format!("phase {number}")), lanes.len().max(1))
				}
				Row::Mark { mark, .. } => (label_width(mark.label()), 1),
				Row::Run { first, last } => (label_width(&run_label(*first, *last)), 2),
				Row::Activity { .. } | Row::Leak { .. } => (widest + BOX_INSET, 1),
			};
			column = column.max(needed.div_ceil(span));
		}
		let spread = (COL_TARGET / lanes.len().max(1)).min(COL_MAX);
		let column = column.min(COL_MAX).max(spread).max(actors);
		Columns {
			lanes,
			column,
			boxw: widest.min(column - BOX_INSET),
		}
	}

	fn center(&self, name: &str) -> usize {
		self.lanes.index(name) * self.column + self.column / 2
	}

	fn width(&self) -> usize {
		self.lanes.len() * self.column
	}

	fn labels<'r>(
		&self,
		lead: &str,
		(start, end): (&str, &str),
		route: Route,
		values: &'r [Value],
	) -> Vec<Label<'r>> {
		let (start, end) = (self.center(start), self.center(end));
		let room = start.abs_diff(end).max(self.column) - LABEL_PAD;
		let mut lines: Vec<(usize, &[Value])> = Vec::new();
		let (mut first, mut used) = (0usize, width_of(lead, LABEL_PX));
		for (i, value) in values.iter().enumerate() {
			let piece = width_of(&value_label(value), LABEL_PX) + width_of(", ", LABEL_PX);
			if i > first && used + piece > room {
				lines.push((used, &values[first..i]));
				(first, used) = (i, 0);
			}
			used += piece;
		}
		lines.push((used + width_of(route.note(), LABEL_PX), &values[first..]));
		lines
			.into_iter()
			.map(|(width, values)| {
				let half = width.div_ceil(2);
				let center = ((start + end) / 2).max(half);
				Label {
					center,
					right: center + half,
					values,
				}
			})
			.collect()
	}

	fn note_width(&self, row: &Row) -> usize {
		box_width(row).max(self.boxw)
	}

	fn extent(&self, row: &Row) -> (usize, usize) {
		match row {
			Row::Wire {
				hop,
				step,
				from,
				to,
				route,
				values,
			} => {
				let lead = hop_lead(*hop, *step);
				let labels = self.labels(&lead, reach(*route, from, to), *route, values);
				(
					ROW_HEIGHT + (labels.len() - 1) * LABEL_LINE,
					labels.iter().map(|label| label.right).max().unwrap_or(0),
				)
			}
			Row::Activity { .. } | Row::Leak { .. } => (
				(box_lines(row).len() * BOX_LINE + BOX_PAD * 2 + 18).max(ROW_HEIGHT),
				self.note_width(row),
			),
			Row::Phase { .. } | Row::Mark { .. } | Row::Run { .. } => (ROW_HEIGHT, 0),
		}
	}
}

fn value_ctx(index: usize, value: &Value) -> Ctx {
	let class = if value.hit() {
		"hit"
	} else if value.guarded {
		"guarded"
	} else {
		""
	};
	Ctx::new()
		.flag("first", index == 0)
		.text("text", value_label(value))
		.text("vclass", class)
		.flag("tagged", value.hit())
		.text(
			"queries",
			value
				.queries
				.iter()
				.map(usize::to_string)
				.collect::<Vec<String>>()
				.join(" "),
		)
}

fn segment(x1: usize, x2: usize, class: &str, tip: &str) -> Ctx {
	Ctx::new()
		.num("x1", x1)
		.num("x2", x2)
		.text("segclass", class)
		.text("tip", tip)
}

fn box_ctx(
	ctx: Ctx,
	columns: &Columns,
	canvas: usize,
	y: usize,
	row: &Row,
	principal: &str,
) -> Ctx {
	let lines = box_lines(row);
	let width = columns.note_width(row);
	let height = lines.len() * BOX_LINE + BOX_PAD * 2;
	let x = columns
		.center(principal)
		.saturating_sub(width / 2)
		.min(canvas - width);
	let drawn = lines
		.iter()
		.enumerate()
		.map(|(i, parts)| {
			Ctx::new()
				.num("tx", x + BOX_PAD)
				.num("ly", y + BOX_PAD + i * BOX_LINE + 11)
				.list(
					"parts",
					parts
						.iter()
						.map(|part| {
							Ctx::new()
								.text("pclass", part.class)
								.text("text", part.text.as_str())
						})
						.collect(),
				)
		})
		.collect();
	ctx.num("x", x)
		.num("y", y)
		.num("w", width)
		.num("h", height)
		.list("lines", drawn)
}

fn row_ctx(columns: &Columns, canvas: usize, top: usize, row: &Row) -> Ctx {
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
			let (num, annotated) = match step {
				Some(step) => (Some(*step), *hop),
				None => (*hop, None),
			};
			let lead = hop_lead(*hop, *step);
			let labels = columns.labels(&lead, reach(*route, from, to), *route, values);
			let last = labels.len() - 1;
			let y = top + last * LABEL_LINE;
			let start = columns.center(from);
			let end = columns.center(to);
			let hinge = columns.center(ATTACKER);
			let relayed = |class: &str| {
				vec![
					segment(start, hinge, "wireMuted", "a"),
					segment(hinge, end, class, "b"),
				]
			};
			let segments = match route {
				Route::Direct => vec![segment(start, end, "wire", "a")],
				Route::Forged => relayed("wireForged"),
				Route::Replayed => relayed("wireReplay"),
				Route::Dropped => vec![segment(start, hinge, "wireDropped", "x")],
			};
			let lines = labels
				.iter()
				.enumerate()
				.map(|(i, label)| {
					Ctx::new()
						.num("x", label.center)
						.num("ly", top.saturating_sub(7) + i * LABEL_LINE)
						.flag("hopped", i == 0 && annotated.is_some())
						.num("hop", annotated.unwrap_or_default())
						.list(
							"values",
							label
								.values
								.iter()
								.enumerate()
								.map(|(k, v)| value_ctx(k, v))
								.collect(),
						)
						.flag("more", i < last)
						.text("note", if i == last { route.note() } else { "" })
				})
				.collect();
			ctx.flag("numbered", num.is_some())
				.num("num", num.unwrap_or_default())
				.num("numx", NUM_X)
				.flag("stepped", step.is_some())
				.text("step", step.map(|n| n.to_string()).unwrap_or_default())
				.num("y", y)
				.num("label_y", y.saturating_sub(7))
				.text("lclass", if route.breached() { "forged" } else { "" })
				.list("segments", segments)
				.list("labels", lines)
		}
		Row::Phase { number } => ctx
			.num("y", top)
			.num("label_y", top.saturating_sub(7))
			.num("width", canvas)
			.num("number", *number),
		Row::Leak { principal, .. } | Row::Activity { principal, .. } => {
			box_ctx(ctx, columns, canvas, top, row, principal)
		}
		Row::Mark {
			step,
			principal,
			mark,
		} => {
			let x = columns.center(principal);
			ctx.num("step", step)
				.num("numx", NUM_X)
				.num("x", x)
				.num("y", top)
				.num("tx", x + 12)
				.num("label_y", top + 4)
				.text("label", mark.label())
		}
		Row::Run { first, last } => {
			let x = if columns.lanes.contains(ATTACKER) {
				columns.center(ATTACKER)
			} else {
				columns.width() / 2
			};
			ctx.text("step", span(*first, *last))
				.num("x", x.saturating_sub(84))
				.num("y", top.saturating_sub(13))
				.num("tx", x)
				.num("ty", top + 2)
				.text("label", run_label(*first, *last))
		}
	}
}

pub(crate) struct Figure {
	pub id: String,
	pub caption: String,
}

pub(crate) fn draw(figure: Figure, chart: &Chart) -> Ctx {
	let columns = Columns::of(chart);
	let extents: Vec<(usize, usize)> = chart.rows.iter().map(|row| columns.extent(row)).collect();
	let width = extents
		.iter()
		.map(|&(_, right)| right)
		.fold(columns.width(), usize::max);
	let mut tops: Vec<usize> = Vec::with_capacity(chart.rows.len());
	let mut cursor = TOP;
	for (height, _) in &extents {
		tops.push(cursor);
		cursor += height;
	}
	let height = cursor + 16;
	let actors = chart
		.lanes
		.names()
		.iter()
		.map(|name| {
			Ctx::new()
				.num("x", columns.center(name))
				.num("bottom", height.saturating_sub(8))
				.text("name", name)
				.text("aclass", if name == ATTACKER { " attacker" } else { "" })
		})
		.collect();
	let drawn = chart
		.rows
		.iter()
		.zip(tops)
		.map(|(row, top)| row_ctx(&columns, width, top, row))
		.collect();
	let alt = chart
		.rows
		.iter()
		.map(|row| Ctx::new().text("text", alt_text(row)))
		.collect();
	Ctx::new()
		.text("id", figure.id)
		.num("width", width)
		.num("height", height)
		.flag("described", !figure.caption.is_empty())
		.text("caption", figure.caption)
		.list("actors", actors)
		.list("rows", drawn)
		.list("alt", alt)
}

fn alt_text(row: &Row) -> String {
	match row {
		Row::Wire {
			hop,
			from,
			to,
			route,
			values,
			..
		} => {
			let lead = hop.map(|n| format!("Hop {n}: ")).unwrap_or_default();
			let body = match route {
				Route::Replayed => format!("{from} to {to}, replayed by the attacker"),
				Route::Forged => format!("{from} to {to}, intercepted and forged by the attacker"),
				Route::Dropped => format!("{from} to {to}, dropped by the attacker"),
				Route::Direct => format!("{from} to {to}"),
			};
			format!("{lead}{body}: {}", wire_label(values, *route))
		}
		Row::Phase { number } => format!("Phase {number} begins."),
		Row::Leak { principal, values } => leak_text(principal, values),
		Row::Activity {
			principal,
			generates,
			computes,
		} => {
			let mut out = principal.clone();
			if !generates.is_empty() {
				out.push_str(&format!(" generates {}", generates.join(", ")));
				if !computes.is_empty() {
					out.push(',');
				}
			}
			if !computes.is_empty() {
				let steps: Vec<String> = computes.iter().map(computation_label).collect();
				out.push_str(&format!(" computes {}", steps.join(", ")));
			}
			out.push('.');
			out
		}
		Row::Mark {
			step,
			principal,
			mark,
		} => match mark {
			Mark::Passes => format!("Step {step}: {principal}'s {}.", mark.label()),
			Mark::Idle => format!("Step {step}: {principal} {}.", mark.label()),
		},
		Row::Run { first, last } => format!("The attacker {}.", run_label(*first, *last)),
	}
}
