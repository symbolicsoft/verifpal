/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::html::template::Ctx;

pub(crate) const ATTACKER: &str = "Attacker";

const COL_MIN: usize = 200;
const COL_MAX: usize = 460;
const ROW_HEIGHT: usize = 42;
const TOP: usize = 56;
const NUM_X: usize = 22;
const LABEL_PAD: usize = 28;
const ACTOR_PAD: usize = 30;
const LABEL_PX: f32 = 11.0;
const ACTOR_PX: f32 = 13.0;
const ADVANCE: f32 = 0.6;

pub(crate) struct Value {
	pub name: String,
	pub guarded: bool,
	pub hit: bool,
	pub queries: Vec<usize>,
}

impl Value {
	fn label(&self) -> String {
		let mut out = if self.guarded {
			format!("[{}]", self.name)
		} else {
			self.name.clone()
		};
		if self.hit {
			out.push('\u{2020}');
		}
		out
	}
}

pub(crate) enum Row {
	Wire {
		num: Option<usize>,
		hop: Option<usize>,
		step: Option<String>,
		from: String,
		to: String,
		via: Option<String>,
		forged: bool,
		replay: bool,
		values: Vec<Value>,
	},
	Phase {
		number: i32,
	},
	Leak {
		principal: String,
		text: String,
	},
	Mark {
		num: Option<usize>,
		step: Option<String>,
		principal: String,
		bypass: bool,
	},
	Run {
		step: String,
		label: String,
	},
}

impl Row {
	fn lanes(&self) -> Vec<&str> {
		match self {
			Row::Wire { from, to, via, .. } => match via {
				Some(via) => vec![from, via, to],
				None => vec![from, to],
			},
			Row::Leak { principal, .. } | Row::Mark { principal, .. } => vec![principal],
			Row::Phase { .. } | Row::Run { .. } => Vec::new(),
		}
	}

	fn label(&self) -> String {
		match self {
			Row::Wire { values, replay, .. } => {
				let joined = values
					.iter()
					.map(Value::label)
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
			Row::Mark { bypass, .. } => mark_label(*bypass).to_string(),
			Row::Run { label, .. } => label.clone(),
		}
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

#[derive(Default)]
pub(crate) struct Lanes {
	names: Vec<String>,
	column: usize,
}

impl Lanes {
	pub(crate) fn of(rows: &[Row]) -> Lanes {
		let mut lanes = Lanes {
			names: Vec::new(),
			column: COL_MIN,
		};
		for row in rows {
			for name in row.lanes() {
				lanes.add(name);
			}
		}
		lanes
	}

	pub(crate) fn add(&mut self, name: &str) {
		if !self.names.iter().any(|n| n == name) {
			self.names.push(name.to_string());
		}
	}

	pub(crate) fn insert(&mut self, at: usize, name: &str) {
		if self.names.iter().any(|n| n == name) {
			return;
		}
		self.names
			.insert(at.min(self.names.len()), name.to_string());
	}

	pub(crate) fn is_empty(&self) -> bool {
		self.names.is_empty()
	}

	pub(crate) fn contains(&self, name: &str) -> bool {
		self.names.iter().any(|n| n == name)
	}

	fn index(&self, name: &str) -> usize {
		self.names.iter().position(|n| n == name).unwrap_or(0)
	}

	pub(crate) fn center(&self, name: &str) -> usize {
		self.index(name) * self.column + self.column / 2
	}

	pub(crate) fn width(&self) -> usize {
		self.names.len() * self.column
	}

	fn measure(&mut self, rows: &[Row]) {
		let mut column = COL_MIN;
		for name in &self.names {
			column = column.max(width_of(name, ACTOR_PX) + ACTOR_PAD);
		}
		for row in rows {
			let text = row.label();
			if text.is_empty() {
				continue;
			}
			let needed = width_of(&text, LABEL_PX) + LABEL_PAD;
			let span = match row {
				Row::Wire { from, to, via, .. } => {
					let start = self.index(via.as_deref().unwrap_or(from));
					let end = self.index(to);
					start.abs_diff(end).max(1)
				}
				Row::Run { .. } => 2,
				_ => self.names.len().max(1),
			};
			column = column.max(needed.div_ceil(span));
		}
		self.column = column.min(COL_MAX);
	}
}

fn row_y(index: usize) -> usize {
	TOP + index * ROW_HEIGHT
}

fn height_of(rows: usize) -> usize {
	TOP + rows * ROW_HEIGHT + 16
}

fn base(kind: &'static str) -> Ctx {
	let mut ctx = Ctx::new();
	for name in ["wire", "phase", "leak", "mark", "run"] {
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
		.text("text", value.label())
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

fn wire_ctx(lanes: &Lanes, y: usize, row: &Row) -> Ctx {
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

fn row_ctx(lanes: &Lanes, y: usize, row: &Row) -> Ctx {
	match row {
		Row::Wire { .. } => wire_ctx(lanes, y, row),
		Row::Phase { number } => base("phase")
			.num("y", y)
			.num("label_y", y.saturating_sub(7))
			.num("width", lanes.width())
			.num("number", *number),
		Row::Leak { principal, text } => base("leak")
			.num("x", lanes.center(principal))
			.num("y", y.saturating_sub(2))
			.text("text", text),
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

pub(crate) fn draw(figure: Figure, mut lanes: Lanes, rows: &[Row]) -> Option<Ctx> {
	if lanes.is_empty() || rows.is_empty() {
		return None;
	}
	lanes.measure(rows);
	let height = height_of(rows.len());
	let actors = lanes
		.names
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
		.map(|(i, row)| row_ctx(&lanes, row_y(i), row))
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
			format!("{lead}{body}: {}", row.label())
		}
		Row::Phase { number } => format!("Phase {number} begins."),
		Row::Leak { text, .. } => text.clone(),
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
