/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::exec::{Context, Execution};
use super::knowledge::{Knowledge, Origin};
use super::program::Event;
use crate::primitive::primitive_name;
use crate::types::*;
use crate::util::copy_base_name;

pub(crate) struct Narrator<'a, 'b> {
	cx: &'a Context<'b>,
	ex: &'a Execution,
	honest: &'a Execution,
	names: Names,
	honest_names: Names,
	cutoff: std::cell::Cell<usize>,
	gated: Vec<(usize, usize)>,
	pub(crate) lines: Vec<String>,
	pub(crate) steps: Vec<TraceStep>,
	explained: Vec<Value>,
}

struct Names {
	entries: IdMap<u64, Vec<(Value, String)>>,
	shaped: Vec<String>,
}

fn excluded(exclude: &[&str], name: &str) -> bool {
	let base = copy_base_name(name);
	exclude
		.iter()
		.any(|e| *e == name || copy_base_name(e) == base)
}

impl Names {
	fn of(cx: &Context, ex: &Execution, honest: &Execution) -> Names {
		let attacker_key = crate::primitive::attacker_public_key();
		let mut names = Names {
			entries: IdMap::default(),
			shaped: Vec::new(),
		};
		for (r, run) in ex.runs.iter().enumerate() {
			for (slot, held) in run.env.iter().enumerate() {
				let Some(h) = held else {
					continue;
				};
				let constant = &cx.km.slots[slot].constant;
				if h.authored || crate::util::is_anonymous_name(&constant.name) {
					continue;
				}
				let name = constant.to_string();
				let unchanged = honest.runs[r]
					.held(slot)
					.is_some_and(|o| o.value.equivalent(&h.value, true));
				if !unchanged && !names.shaped.contains(&name) {
					names.shaped.push(name.clone());
				}
				for form in [&h.value, &h.pre] {
					if matches!(form, Value::Constant(_)) || form.equivalent(&attacker_key, true) {
						continue;
					}
					let bucket = names.entries.entry(form.hash_value()).or_default();
					if bucket
						.iter()
						.any(|(v, n)| *n == name && v.equivalent(form, true))
					{
						continue;
					}
					bucket.push((form.clone(), name.clone()));
				}
			}
		}
		names
	}

	fn shaped(&self, name: &str) -> bool {
		self.shaped.iter().any(|s| s == name)
	}

	fn lookup(&self, v: &Value, exclude: &[&str]) -> Option<&str> {
		let candidates: Vec<&str> = self
			.entries
			.get(&v.hash_value())?
			.iter()
			.filter(|(known, name)| !excluded(exclude, name) && known.equivalent(v, true))
			.map(|(_, name)| name.as_str())
			.collect();
		candidates
			.iter()
			.min_by_key(|name| (self.shaped(name), copy_base_name(name) != **name))
			.copied()
	}
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

fn head(p: &Primitive) -> String {
	match crate::primitive::primitive_threshold(p.id) {
		Some(_) => format!("{}[{}]", primitive_name(p.id), p.threshold),
		None => primitive_name(p.id).to_string(),
	}
}

impl<'a, 'b> Narrator<'a, 'b> {
	pub(crate) fn new(cx: &'a Context<'b>, ex: &'a Execution, honest: &'a Execution) -> Self {
		Narrator {
			cx,
			ex,
			honest,
			names: Names::of(cx, ex, honest),
			honest_names: Names::of(cx, honest, honest),
			cutoff: std::cell::Cell::new(ex.knowledge.len()),
			gated: Vec::new(),
			lines: Vec::new(),
			steps: Vec::new(),
			explained: Vec::new(),
		}
	}

	fn available(&self, v: &Value) -> bool {
		if self
			.ex
			.knowledge
			.knows(v)
			.is_some_and(|i| i < self.cutoff.get())
		{
			return true;
		}
		match v {
			Value::Primitive(p) => self.oriented(p).is_some(),
			Value::Constant(_) => false,
		}
	}

	fn oriented(&self, p: &Arc<Primitive>) -> Option<Arc<Primitive>> {
		if p.arguments.iter().all(|a| self.available(a)) {
			return Some(Arc::clone(p));
		}
		let swapped = crate::primitive::commutativity_swap(p)?;
		swapped
			.arguments
			.iter()
			.all(|a| self.available(a))
			.then(|| Arc::new(swapped))
	}

	fn render(&self, names: &Names, p: &Arc<Primitive>, exclude: &[&str]) -> String {
		let oriented = self.oriented(p).unwrap_or_else(|| Arc::clone(p));
		let args: Vec<String> = oriented
			.arguments
			.iter()
			.map(|a| self.named(names, a, exclude))
			.collect();
		let projection = if crate::primitive::primitive_has_single_output(oriented.id) {
			String::new()
		} else {
			format!("|{}", oriented.output + 1)
		};
		format!(
			"{}({}){}{}",
			head(&oriented),
			args.join(", "),
			projection,
			if oriented.instance_check { "?" } else { "" }
		)
	}

	fn named(&self, names: &Names, v: &Value, exclude: &[&str]) -> String {
		if let Some(name) = names.lookup(v, exclude) {
			return name.to_string();
		}
		match v {
			Value::Constant(c) => c.to_string(),
			Value::Primitive(p) => self.render(names, p, exclude),
		}
	}

	pub(crate) fn term(&self, v: &Value, exclude: &[&str]) -> String {
		self.named(&self.names, v, exclude)
	}

	pub(crate) fn spelled(&self, v: &Value, exclude: &[&str]) -> String {
		match v {
			Value::Constant(c) => c.to_string(),
			Value::Primitive(p) => self.render(&self.names, p, exclude),
		}
	}

	fn delivered(&self, v: &Value, exclude: &[&str]) -> String {
		match self.names.lookup(v, exclude) {
			Some(name) if !self.names.shaped(name) => name.to_string(),
			_ => self.spelled(v, exclude),
		}
	}

	fn spelled_honest(&self, v: &Value, exclude: &[&str]) -> String {
		match v {
			Value::Constant(c) => c.to_string(),
			Value::Primitive(p) => self.render(&self.honest_names, p, exclude),
		}
	}

	fn subject(&self, v: &Value) -> String {
		match self.names.lookup(v, &[]) {
			Some(name) if self.names.shaped(name) => {
				format!("{name}, where it is {}", self.spelled(v, &[name]))
			}
			Some(name) => name.to_string(),
			None => self.spelled(v, &[]),
		}
	}

	fn list(&self, values: &[Value]) -> String {
		values
			.iter()
			.map(|v| self.term(v, &[]))
			.collect::<Vec<_>>()
			.join(", ")
	}

	pub(crate) fn declared(&self, slot: usize) -> String {
		self.cx.km.slots[slot].initial_value.to_string()
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
		let outer = self.cutoff.replace(len);
		self.narrate(v, len);
		self.cutoff.set(outer);
	}

	fn narrate(&mut self, v: &Value, len: usize) {
		let knowledge = &self.ex.knowledge;
		let known = knowledge.knows(v).filter(|&i| i < len);
		if known.is_none()
			&& let Value::Primitive(p) = v
			&& let Some(built) = self.oriented(p)
		{
			for argument in &built.arguments {
				self.explain(argument, len);
			}
			let shown = self.subject(v);
			self.say(format!("Attacker constructs {shown}."));
			return;
		}
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
				let shown = self.subject(v);
				self.say(format!("Attacker constructs {shown}."));
			}
			return;
		};
		match knowledge.origin(i).clone() {
			Origin::Initial => {}
			Origin::Wire { run, slot } => {
				let name = self.cx.km.slots[slot].constant.to_string();
				let honest = self.honest.runs[run].held(slot).map(|h| &h.value);
				if honest.is_some_and(|h| h.equivalent(v, true)) {
					self.say(format!("Attacker observes {name} on the wire."));
				} else {
					let shown = self.term(v, &[&name]);
					self.say(format!(
						"Attacker observes {name} on the wire, where it is {shown}."
					));
				}
			}
			Origin::Leak { run, slot } => {
				let name = &self.cx.km.slots[slot].constant;
				let leaker = &self.cx.program.runs[run].name;
				self.say(format!(
					"Attacker is handed {name} by a leaks declaration in {leaker}."
				));
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
						format!(
							"Attacker opens {} with {}, obtaining {}.",
							self.term(of, &[]),
							self.list(using),
							self.term(v, &[])
						)
					}
					DerivationRecord::Reconstructed { .. } => {
						format!("Attacker constructs {}.", self.subject(v))
					}
					DerivationRecord::Combined { from } => format!(
						"Attacker combines {} out of the partial signatures {}.",
						self.subject(v),
						self.list(from)
					),
					DerivationRecord::Recomposed { using, .. } => format!(
						"Attacker recomposes {} from enough of its shares ({}).",
						self.term(v, &[]),
						self.list(using)
					),
					DerivationRecord::Fragment { of } => format!(
						"Attacker splits {} and takes {}.",
						self.term(of, &[]),
						self.term(v, &[])
					),
					DerivationRecord::Rewritten { of, using, .. } => {
						for u in using {
							self.explain(u, len);
						}
						let name = match of {
							Value::Primitive(p) => primitive_name(p.id),
							Value::Constant(_) => "a rewrite",
						};
						format!(
							"Attacker applies {name} to {}, obtaining {}.",
							self.list(using),
							self.subject(v)
						)
					}
					DerivationRecord::Broken { of, capability, .. } => format!(
						"Attacker breaks {} under the declared `{}` assumption, obtaining {}.",
						self.term(of, &[]),
						capability.name(),
						self.term(v, &[])
					),
					DerivationRecord::Reused { of, with } => format!(
						"Attacker recovers {} from {}: {} shares its {}.",
						self.term(v, &[]),
						self.term(of, &[]),
						self.term(with, &[]),
						crate::primitive::reuse_fixed_names(of)
					),
					DerivationRecord::ReusedForge { with, .. } => format!(
						"Attacker forges {} under the {} shared by {} and {}.",
						self.subject(v),
						crate::primitive::reuse_fixed_names(&with[0]),
						self.term(&with[0], &[]),
						self.term(&with[1], &[])
					),
					DerivationRecord::Initial
					| DerivationRecord::Leaked { .. }
					| DerivationRecord::Obtained { .. } => return,
				};
				self.say(line);
			}
		}
	}

	pub(crate) fn replayed_from(
		&self,
		run: usize,
		slot: usize,
		value: &Value,
	) -> Option<&'static str> {
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
			let d = match program.runs[run].steps[step].event {
				Event::Recv(d) => d,
				Event::Assign(slot) => {
					if self.influenced(run, slot, &mut Vec::new()) {
						self.gate(run, slot);
					}
					continue;
				}
				_ => continue,
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
				let constant = km.slots[slot].constant.to_string();
				let own: [&str; 1] = [&constant];
				if let Some(axis) = self.replayed_from(run, slot, &value) {
					self.done(&value);
					replays.push((axis, constant.clone(), self.spelled(&value, &own)));
					continue;
				}
				self.explain(&value, before);
				let shown = self.delivered(&value, &own);
				names.push(constant.clone());
				values.push(shown.clone());
				let previous = self.honest.runs[run].held(slot).map(|honest| &honest.value);
				let displaced = previous.map(|honest| self.spelled_honest(honest, &own));
				let shown_was = previous.filter(|honest| {
					!honest.equivalent(&value, true)
						&& honest
							.as_constant()
							.is_none_or(|c| c.name.as_ref() != constant)
				});
				if shown_was.is_some()
					&& let Some(honest) = &displaced
				{
					was.push(format!("{constant} was {honest}"));
				} else if previous.is_some_and(|honest| honest.equivalent(&value, true))
					&& let Some(sent) = self.ex.sent[d]
						.as_ref()
						.and_then(|sent| sent.get(k))
						.filter(|sent| !sent.equivalent(&value, true))
				{
					was.push(format!(
						"{} sent {} in this execution",
						program.runs[delivery.sender].name,
						self.spelled(sent, &own)
					));
				}
				items.push(TraceValue {
					name: constant.clone(),
					installed: Some(shown),
					was: displaced,
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
			let shown = self.term(v, &[]);
			self.say(format!("Attacker knows {shown}: it is public."));
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
			let name = c.to_string();
			let shown = self.spelled(v, &[&name]);
			self.push(TraceStep::new(
				"resolves",
				format!("In this state {c} resolves to {shown}."),
			));
		}
	}

	fn influenced(&self, run: usize, slot: usize, seen: &mut Vec<usize>) -> bool {
		if seen.contains(&slot) {
			return false;
		}
		seen.push(slot);
		let Some(h) = self.ex.runs[run].held(slot) else {
			return false;
		};
		if h.authored {
			return true;
		}
		let program = &self.cx.program.runs[run];
		let assigned = program
			.step_of_slot
			.get(&slot)
			.is_some_and(|&at| matches!(program.steps[at].event, Event::Assign(_)));
		assigned
			&& self.cx.km.slots[slot]
				.initial_value
				.constant_leaves()
				.filter_map(|c| self.cx.km.index_of(c))
				.any(|at| at != slot && self.influenced(run, at, seen))
	}

	pub(crate) fn gate(&mut self, run: usize, slot: usize) {
		if self.gated.contains(&(run, slot)) || self.ex.runs[run].halted == Some(slot) {
			return;
		}
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
		let installed: Vec<String> = self.ex.runs[run]
			.env
			.iter()
			.enumerate()
			.filter(|(_, held)| held.as_ref().is_some_and(|h| h.installed))
			.map(|(s, _)| self.cx.km.slots[s].constant.to_string())
			.chain(std::iter::once(self.cx.km.slots[slot].constant.to_string()))
			.collect();
		let hidden: Vec<&str> = installed.iter().map(String::as_str).collect();
		let shown = self.spelled(&h.pre, &hidden);
		let mut step = TraceStep::new(
			"gate",
			format!("{principal}'s {shown} passes — the attacker controls one of its inputs."),
		);
		step.principal = Some(principal);
		self.gated.push((run, slot));
		self.push(step);
	}

	pub(crate) fn trace(&self) -> String {
		self.lines.join("\n")
	}
}
