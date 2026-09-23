/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::exec::{Context, Execution};
use super::knowledge::{Knowledge, Origin};
use super::program::Event;
use crate::primitive::primitive_name;
use crate::types::*;

pub(crate) struct Narrator<'a, 'b> {
	cx: &'a Context<'b>,
	ex: &'a Execution,
	honest: &'a Execution,
	pub(crate) lines: Vec<String>,
	pub(crate) steps: Vec<TraceStep>,
	explained: Vec<Value>,
}

fn prefix(knowledge: &Knowledge, len: usize) -> AttackerState {
	let state = &knowledge.state;
	let len = len.min(state.known.len());
	let mut out = AttackerState::new();
	out.current_phase = state.current_phase;
	out.known = Arc::new(state.known[..len].to_vec());
	let mut map: IdMap<u64, Vec<usize>> = IdMap::default();
	for (i, v) in out.known.iter().enumerate() {
		map.entry(v.hash_value()).or_default().push(i);
	}
	out.known_map = Arc::new(map);
	out.derivations = Arc::new(state.derivations[..len.min(state.derivations.len())].to_vec());
	out.reused = state.reused.clone();
	out
}

fn list(values: &[Value]) -> String {
	values
		.iter()
		.map(|v| v.to_string())
		.collect::<Vec<_>>()
		.join(", ")
}

impl<'a, 'b> Narrator<'a, 'b> {
	pub(crate) fn new(cx: &'a Context<'b>, ex: &'a Execution, honest: &'a Execution) -> Self {
		Narrator {
			cx,
			ex,
			honest,
			lines: Vec::new(),
			steps: Vec::new(),
			explained: Vec::new(),
		}
	}

	fn say(&mut self, line: String) {
		self.push(TraceStep::new("derive", line));
	}

	fn push(&mut self, step: TraceStep) {
		self.lines
			.push(format!("{}. {}", self.lines.len() + 1, step.text));
		self.steps.push(step);
	}

	fn route(
		&self,
		delivery: &super::program::Delivery,
		kind: &'static str,
		text: String,
	) -> TraceStep {
		let runs = &self.cx.program.runs;
		let mut step = TraceStep::new(kind, text);
		step.sender = Some(runs[delivery.sender].name.clone());
		step.recipient = Some(runs[delivery.recipient].name.clone());
		step
	}

	fn done(&mut self, v: &Value) -> bool {
		if self.explained.iter().any(|seen| seen.equivalent(v, true)) {
			return true;
		}
		self.explained.push(v.clone());
		false
	}

	pub(crate) fn explain(&mut self, v: &Value, len: usize) {
		if self.done(v) {
			return;
		}
		let knowledge = &self.ex.knowledge;
		let known = knowledge.knows(v).filter(|&i| i < len);
		let Some(i) = known else {
			let state = prefix(knowledge, len);
			let mut inputs = crate::theory::KnowledgeInputs::new(self.cx.carrier, &state);
			let used: Vec<usize> = inputs
				.of_value(v)
				.map(|found| found.into_iter().map(|idx| idx.get()).collect())
				.unwrap_or_default();
			for idx in used {
				let ingredient = state.known[idx].clone();
				self.explain(&ingredient, len);
			}
			if matches!(v, Value::Primitive(_)) {
				self.say(format!("Attacker constructs {v}."));
			}
			return;
		};
		match knowledge.origin(i).clone() {
			Origin::Initial => {}
			Origin::Wire { run, slot } => {
				let name = &self.cx.km.slots[slot].constant;
				let honest = self.honest.runs[run].held(slot).map(|h| &h.value);
				if honest.is_some_and(|h| h.equivalent(v, true)) && v.as_constant().is_some() {
					self.say(format!("Attacker observes {name} on the wire."));
				} else {
					self.say(format!(
						"Attacker observes {name} on the wire, where it is {v}."
					));
				}
			}
			Origin::Leak { slot, .. } => {
				let name = &self.cx.km.slots[slot].constant;
				self.say(format!("Attacker is handed {name} by a leaks declaration."));
			}
			Origin::Derived(record) => {
				for ingredient in record.ingredients() {
					let ingredient = ingredient.clone();
					self.explain(&ingredient, len);
				}
				let line = match &record {
					DerivationRecord::Decomposed { of, using } => {
						for u in using {
							self.explain(u, len);
						}
						format!("Attacker opens {of} with {}, obtaining {v}.", list(using))
					}
					DerivationRecord::Reconstructed { .. } => format!("Attacker constructs {v}."),
					DerivationRecord::Combined { from } => format!(
						"Attacker combines {v} out of the partial signatures {}.",
						list(from)
					),
					DerivationRecord::Recomposed { using, .. } => format!(
						"Attacker recomposes {v} from enough of its shares ({}).",
						list(using)
					),
					DerivationRecord::Fragment { of } => {
						format!("Attacker splits {of} and takes {v}.")
					}
					DerivationRecord::Rewritten { of, using, .. } => {
						for u in using {
							self.explain(u, len);
						}
						let name = match of {
							Value::Primitive(p) => primitive_name(p.id),
							Value::Constant(_) => "a rewrite",
						};
						format!("Attacker applies {name} to {}, obtaining {v}.", list(using))
					}
					DerivationRecord::Broken { of, capability, .. } => format!(
						"Attacker breaks {of} under the declared `{}` assumption, obtaining {v}.",
						capability.name()
					),
					DerivationRecord::Reused { of, with } => format!(
						"Attacker recovers {v} from {of}: {with} shares its {}.",
						crate::primitive::reuse_fixed_names(of)
					),
					DerivationRecord::ReusedForge { with, .. } => format!(
						"Attacker forges {v} under the {} shared by {} and {}.",
						crate::primitive::reuse_fixed_names(&with[0]),
						with[0],
						with[1]
					),
					DerivationRecord::Initial
					| DerivationRecord::Leaked { .. }
					| DerivationRecord::Obtained { .. } => return,
				};
				self.say(line);
			}
		}
	}

	fn replayed_from(&self, run: usize, slot: usize, value: &Value) -> Option<&'static str> {
		let program = self.cx.program;
		let km = self.cx.km;
		let id = km.slots[slot].constant.id;
		let within = |groups: &IdMap<ValueId, Arc<Vec<ValueId>>>, s: usize| {
			groups
				.get(&id)
				.is_some_and(|group| group.contains(&km.slots[s].constant.id))
		};
		program
			.deliveries
			.iter()
			.enumerate()
			.find_map(|(d, delivery)| {
				if delivery.recipient == run {
					return None;
				}
				let sent = self.ex.sent[d].as_ref()?;
				delivery.slots.iter().zip(sent).find_map(|(&(s, _), v)| {
					if s == slot || !v.equivalent(value, true) {
						return None;
					}
					if within(&km.session_siblings, s) {
						Some("session")
					} else if within(&km.copy_siblings, s) {
						Some("scenario")
					} else {
						None
					}
				})
			})
	}

	pub(crate) fn installs(&mut self) {
		let program = self.cx.program;
		let km = self.cx.km;
		for &(run, step, before) in &self.ex.order {
			let Event::Recv(d) = program.runs[run].steps[step].event else {
				continue;
			};
			let delivery = &program.deliveries[d];
			let route = format!(
				"{} to {}",
				program.runs[delivery.sender].name, program.runs[delivery.recipient].name
			);
			let mut names = Vec::new();
			let mut values = Vec::new();
			let mut was = Vec::new();
			let mut items = Vec::new();
			let mut replays: Vec<(&'static str, String, String)> = Vec::new();
			for (k, &(slot, _)) in delivery.slots.iter().enumerate() {
				let Some(h) = self.ex.runs[run].held(slot) else {
					continue;
				};
				if !h.installed {
					continue;
				}
				let value = h.value.clone();
				let constant = &km.slots[slot].constant;
				if let Some(axis) = self.replayed_from(run, slot, &value) {
					self.done(&value);
					replays.push((axis, constant.to_string(), value.to_string()));
					continue;
				}
				self.explain(&value, before);
				names.push(constant.to_string());
				values.push(value.to_string());
				let previous = self.honest.runs[run].held(slot).map(|honest| &honest.value);
				let shown = previous.filter(|honest| {
					!honest.equivalent(&value, true)
						&& honest.as_constant().is_none_or(|c| c.id != constant.id)
				});
				if let Some(honest) = shown {
					was.push(format!("{constant} was {honest}"));
				} else if previous.is_some_and(|honest| honest.equivalent(&value, true))
					&& let Some(sent) = self.ex.sent[d]
						.as_ref()
						.and_then(|sent| sent.get(k))
						.filter(|sent| !sent.equivalent(&value, true))
				{
					was.push(format!(
						"{} sent {sent} in this execution",
						program.runs[delivery.sender].name
					));
				}
				items.push(TraceValue {
					name: constant.to_string(),
					installed: Some(value.to_string()),
					was: previous.map(|honest| honest.to_string()),
					guarded: false,
				});
			}
			for (axis, name, value) in replays {
				let mut step = self.route(
					delivery,
					"replay",
					format!(
						"Attacker replays {name} ({route}) from another {axis}, where it is {value}."
					),
				);
				step.values = vec![TraceValue {
					name,
					installed: Some(value),
					was: None,
					guarded: false,
				}];
				self.push(step);
			}
			if names.is_empty() {
				continue;
			}
			let note = if was.is_empty() {
				String::new()
			} else {
				format!(" ({})", was.join("; "))
			};
			let mut step = self.route(
				delivery,
				"mutations",
				format!(
					"Attacker replaces {} (sent by {route}) with {}.{note}",
					names.join(", "),
					values.join(", "),
				),
			);
			step.values = items;
			self.push(step);
		}
	}

	pub(crate) fn public(&mut self, v: &Value) {
		if let Some(i) = self.ex.knowledge.knows(v)
			&& matches!(self.ex.knowledge.origin(i), Origin::Initial)
			&& !self.done(v)
		{
			self.say(format!("Attacker knows {v}: it is public."));
		}
	}

	pub(crate) fn received(&mut self, run: usize, slot: usize, sender: usize) {
		let runs = &self.cx.program.runs;
		let name = self.cx.km.slots[slot].constant.to_string();
		let mut step = TraceStep::new(
			"received",
			format!(
				"{} received {name} from {}.",
				runs[run].name, runs[sender].name
			),
		);
		step.sender = Some(runs[sender].name.clone());
		step.recipient = Some(runs[run].name.clone());
		step.values = vec![TraceValue {
			name,
			installed: None,
			was: None,
			guarded: false,
		}];
		self.push(step);
	}

	pub(crate) fn built_from(&mut self, slot: usize, value: &Value) {
		let mut leaves: Vec<String> = Vec::new();
		for c in value.constant_leaves() {
			let name = c.to_string();
			if !leaves.contains(&name) {
				leaves.push(name);
			}
		}
		if leaves.is_empty() {
			return;
		}
		self.push(TraceStep::new(
			"static",
			format!(
				"No value {} is built from is generated fresh: {}.",
				self.cx.km.slots[slot].constant,
				leaves.join(", ")
			),
		));
	}

	pub(crate) fn resolves(&mut self, resolved: &[(Constant, Value)]) {
		for (c, v) in resolved {
			self.push(TraceStep::new(
				"resolves",
				format!("In this state {c} resolves to {v}."),
			));
		}
	}

	pub(crate) fn gate(&mut self, run: usize, slot: usize) {
		let Some(h) = self.ex.runs[run].held(slot) else {
			return;
		};
		let Value::Primitive(p) = &h.pre else {
			return;
		};
		if !p.instance_check {
			return;
		}
		let principal = self.cx.program.runs[run].name.clone();
		let mut step = TraceStep::new(
			"gate",
			format!(
				"{principal}'s {} passes — the attacker controls one of its inputs.",
				h.pre
			),
		);
		step.principal = Some(principal);
		self.push(step);
	}

	pub(crate) fn trace(&self) -> String {
		self.lines.join("\n")
	}
}
