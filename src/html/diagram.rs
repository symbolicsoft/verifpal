/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::msc::{ATTACKER, Lanes, Row, Step, Value};
use crate::template::Ctx;

const COL_MIN: usize = 200;
const COL_MAX: usize = 460;
// The report's content column, so a diagram with few lanes spreads to fill it
// rather than huddling against the left margin.
const COL_TARGET: usize = 910;
const ROW_HEIGHT: usize = 42;
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

fn value_label(value: &Value) -> String {
	let mut out = if value.guarded {
		format!("[{}]", value.name)
	} else {
		value.name.clone()
	};
	if value.hit {
		out.push('\u{2020}');
	}
	out
}

#[derive(Clone)]
pub(crate) struct Part {
	pub text: String,
	pub class: &'static str,
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
						text: step.names.clone(),
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
		Row::Leak { text, .. } => vec![vec![Part {
			text: text.clone(),
			class: "leakText",
		}]],
		_ => Vec::new(),
	}
}

fn line_text(parts: &[Part]) -> String {
	parts.iter().map(|p| p.text.as_str()).collect()
}

// SVG text does not reflow, so a line wider than the box is broken here. Only
// the trailing term is split, and only at its argument commas, so a
// continuation always begins at something the reader can parse.
const BOX_COLS: usize = 52;

fn reflow(lines: Vec<Vec<Part>>) -> Vec<Vec<Part>> {
	let mut out: Vec<Vec<Part>> = Vec::new();
	for parts in lines {
		if line_text(&parts).chars().count() <= BOX_COLS || parts.len() < 2 {
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

// One width for every box in the diagram, so they line up into a column
// instead of stepping in and out with their content.
fn uniform_box_width(rows: &[Row]) -> usize {
	rows.iter().map(box_width).max().unwrap_or(0)
}

fn row_height(row: &Row) -> usize {
	match row {
		Row::Activity { .. } | Row::Leak { .. } => {
			(box_lines(row).len() * BOX_LINE + BOX_PAD * 2 + 18).max(ROW_HEIGHT)
		}
		_ => ROW_HEIGHT,
	}
}

fn row_label(row: &Row) -> String {
	match row {
		Row::Wire { values, replay, .. } => {
			let joined = values
				.iter()
				.map(value_label)
				.collect::<Vec<String>>()
				.join(", ");
			if *replay {
				format!("{joined} (replayed)")
			} else {
				joined
			}
		}
		Row::Phase { number } => format!("phase {number}"),
		Row::Leak { text, .. } => text.clone(),
		Row::Activity { .. } => box_lines(row)
			.iter()
			.map(|parts| line_text(parts))
			.max_by_key(String::len)
			.unwrap_or_default(),
		Row::Mark { bypass, .. } => mark_label(*bypass).to_string(),
		Row::Run { label, .. } => label.clone(),
	}
}

fn mark_label(bypass: bool) -> &'static str {
	if bypass {
		"check defeated"
	} else {
		"check passes"
	}
}

fn width_of(text: &str, size: f32) -> usize {
	(text.chars().count() as f32 * size * ADVANCE).ceil() as usize
}

pub(crate) struct Columns {
	lanes: Lanes,
	column: usize,
	boxw: usize,
}

impl Columns {
	fn of(lanes: Lanes, rows: &[Row]) -> Columns {
		let mut columns = Columns {
			lanes,
			column: COL_MIN,
			boxw: uniform_box_width(rows),
		};
		columns.measure(rows);
		columns
	}

	fn names(&self) -> &[String] {
		self.lanes.names()
	}

	fn contains(&self, name: &str) -> bool {
		self.lanes.contains(name)
	}

	fn center(&self, name: &str) -> usize {
		self.lanes.index(name) * self.column + self.column / 2
	}

	fn width(&self) -> usize {
		self.lanes.len() * self.column
	}

	fn measure(&mut self, rows: &[Row]) {
		let mut column = COL_MIN;
		for name in self.lanes.names() {
			column = column.max(width_of(name, ACTOR_PX) + ACTOR_PAD);
		}
		for row in rows {
			let text = row_label(row);
			if text.is_empty() {
				continue;
			}
			let needed = match row {
				Row::Activity { .. } | Row::Leak { .. } => self.boxw + BOX_INSET,
				_ => width_of(&text, LABEL_PX) + LABEL_PAD,
			};
			let span = match row {
				Row::Wire { from, to, via, .. } => {
					let start = self.lanes.index(via.as_deref().unwrap_or(from));
					let end = self.lanes.index(to);
					start.abs_diff(end).max(1)
				}
				Row::Run { .. } => 2,
				Row::Activity { .. } | Row::Leak { .. } | Row::Mark { .. } => 1,
				_ => self.lanes.len().max(1),
			};
			column = column.max(needed.div_ceil(span));
		}
		// A box is capped by nothing: it must fit, or it would overlap its
		// neighbour. A wide one widens the diagram, which then scrolls.
		let spread = (COL_TARGET / self.lanes.len().max(1)).min(COL_MAX);
		self.column = column.min(COL_MAX).max(spread);
	}
}

fn base(kind: &'static str) -> Ctx {
	let mut ctx = Ctx::new();
	for name in ["wire", "phase", "leak", "activity", "mark", "run"] {
		ctx = ctx.flag(name, name == kind);
	}
	ctx
}

fn value_ctx(index: usize, value: &Value) -> Ctx {
	let class = if value.hit {
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
		.flag("tagged", !value.queries.is_empty())
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

fn wire_ctx(lanes: &Columns, y: usize, row: &Row) -> Ctx {
	let Row::Wire {
		num,
		hop,
		step,
		from,
		to,
		via,
		forged,
		replay,
		values,
	} = row
	else {
		return base("wire");
	};
	let breached = *forged || *replay;
	let start = lanes.center(from);
	let end = lanes.center(to);
	let hinge = via.as_ref().map(|name| lanes.center(name));
	let carry = hinge.unwrap_or(start);
	let first = Ctx::new()
		.num("x1", start)
		.num("x2", hinge.unwrap_or(end))
		.text(
			"segclass",
			if hinge.is_some() {
				"wireMuted"
			} else if *replay {
				"wireReplay"
			} else {
				"wire"
			},
		)
		.flag("breach", hinge.is_none() && breached);
	let mut segments = vec![first];
	if let Some(hinge) = hinge {
		segments.push(
			Ctx::new()
				.num("x1", hinge)
				.num("x2", end)
				.text(
					"segclass",
					if *replay {
						"wireReplay"
					} else if *forged {
						"wireForged"
					} else {
						"wireMuted"
					},
				)
				.flag("breach", breached),
		);
	}
	base("wire")
		.flag("numbered", num.is_some())
		.num("num", num.unwrap_or_default())
		.flag("hopped", hop.is_some())
		.num("hop", hop.unwrap_or_default())
		.num("numx", NUM_X)
		.flag("stepped", step.is_some())
		.text("step", step.clone().unwrap_or_default())
		.num("y", y)
		.num("label_y", y.saturating_sub(7))
		.num("mid", (carry + end) / 2)
		.text("lclass", if breached { "forged" } else { "" })
		.flag("replayed", *replay)
		.list("segments", segments)
		.list(
			"values",
			values
				.iter()
				.enumerate()
				.map(|(i, v)| value_ctx(i, v))
				.collect(),
		)
}

fn box_ctx(lanes: &Columns, y: usize, row: &Row, principal: &str, kind: &'static str) -> Ctx {
	let lines = box_lines(row);
	let width = lanes.boxw;
	let height = lines.len() * BOX_LINE + BOX_PAD * 2;
	let center = lanes.center(principal);
	let x = center.saturating_sub(width / 2);
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
	base(kind)
		.num("x", x)
		.num("y", y)
		.num("w", width)
		.num("h", height)
		.list("lines", drawn)
}

fn row_ctx(lanes: &Columns, y: usize, row: &Row) -> Ctx {
	match row {
		Row::Wire { .. } => wire_ctx(lanes, y, row),
		Row::Phase { number } => base("phase")
			.num("y", y)
			.num("label_y", y.saturating_sub(7))
			.num("width", lanes.width())
			.num("number", *number),
		Row::Leak { principal, .. } => box_ctx(lanes, y, row, principal, "leak"),
		Row::Activity { principal, .. } => box_ctx(lanes, y, row, principal, "activity"),
		Row::Mark {
			num,
			step,
			principal,
			bypass,
		} => {
			let x = lanes.center(principal);
			base("mark")
				.flag("numbered", num.is_some())
				.num("num", num.unwrap_or_default())
				.num("numx", NUM_X)
				.flag("stepped", step.is_some())
				.text("step", step.clone().unwrap_or_default())
				.num("x", x)
				.num("y", y)
				.num("tx", x + 12)
				.num("label_y", y + 4)
				.text("markclass", if *bypass { "bypassMark" } else { "gateMark" })
				.text("lclass", if *bypass { "breach" } else { "" })
				.text("label", mark_label(*bypass))
		}
		Row::Run { step, label } => {
			let x = if lanes.contains(ATTACKER) {
				lanes.center(ATTACKER)
			} else {
				lanes.width() / 2
			};
			base("run")
				.text("step", step)
				.num("x", x.saturating_sub(84))
				.num("y", y.saturating_sub(13))
				.num("tx", x)
				.num("ty", y + 2)
				.text("label", label)
		}
	}
}

pub(crate) struct Figure {
	pub id: String,
	pub caption: String,
	pub described: bool,
}

pub(crate) fn draw(figure: Figure, lanes: Lanes, rows: &[Row]) -> Option<Ctx> {
	if lanes.is_empty() || rows.is_empty() {
		return None;
	}
	let lanes = Columns::of(lanes, rows);
	let mut tops: Vec<usize> = Vec::with_capacity(rows.len());
	let mut cursor = TOP;
	for row in rows {
		tops.push(cursor);
		cursor += row_height(row);
	}
	let height = cursor + 16;
	let actors = lanes
		.names()
		.iter()
		.map(|name| {
			Ctx::new()
				.num("x", lanes.center(name))
				.num("bottom", height.saturating_sub(8))
				.text("name", name)
				.text("aclass", if name == ATTACKER { " attacker" } else { "" })
		})
		.collect();
	let drawn = rows
		.iter()
		.enumerate()
		.map(|(i, row)| row_ctx(&lanes, tops[i], row))
		.collect();
	let alt = rows
		.iter()
		.map(|row| Ctx::new().text("text", alt_text(row)))
		.collect();
	Some(
		Ctx::new()
			.text("id", figure.id)
			.num("width", lanes.width())
			.num("height", height)
			.flag("described", figure.described)
			.flag("captioned", !figure.caption.is_empty())
			.text("caption", figure.caption)
			.list("actors", actors)
			.list("rows", drawn)
			.list("alt", alt),
	)
}

fn alt_text(row: &Row) -> String {
	match row {
		Row::Wire {
			num,
			from,
			to,
			via,
			forged,
			replay,
			..
		} => {
			let lead = num.map(|n| format!("Hop {n}: ")).unwrap_or_default();
			let body = match (via, forged, replay) {
				(Some(_), _, true) => format!("{from} to {to}, replayed by the attacker"),
				(Some(_), true, _) => {
					format!("{from} to {to}, intercepted and forged by the attacker")
				}
				(Some(_), _, _) => format!("{from} to {to}, relayed through the attacker"),
				(None, _, _) => format!("{from} to {to}"),
			};
			format!("{lead}{body}: {}", row_label(row))
		}
		Row::Phase { number } => format!("Phase {number} begins."),
		Row::Leak { text, .. } => text.clone(),
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
				let steps: Vec<String> = computes.iter().map(Step::label).collect();
				out.push_str(&format!(" computes {}", steps.join(", ")));
			}
			out.push('.');
			out
		}
		Row::Mark {
			num,
			principal,
			bypass,
			..
		} => {
			let step = num.map(|n| format!("Step {n}: ")).unwrap_or_default();
			format!("{step}{principal}'s {}.", mark_label(*bypass))
		}
		Row::Run { label, .. } => format!("The attacker {label}."),
	}
}
