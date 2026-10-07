/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::exec::{Context, Execution, Taken};
use super::judgment::Violation;
use super::knowledge::Origin;
use super::program::{DeliveryIdx, Event, RunIdx};
use crate::primitive::Capability;
use crate::protocol::{ProtocolTrace, SlotIdx};
use crate::syntax::names::copy_base_name;
use crate::syntax::{PrincipalId, Query, Span};
use crate::term::{Constant, Primitive, Value, ValueId};
use crate::theory::{AttackerState, DerivationRecord};
use crate::util::IdMap;
use crate::verify::{Subtype, TraceStep, TraceValue};

pub(crate) struct Narrator<'a, 'b> {
	cx: &'a Context<'b>,
	ex: &'a Execution,
	honest: &'a Execution,
	names: Names,
	unshaped: Names,
	honest_names: Names,
	cutoff: usize,
	gated: Vec<(RunIdx, SlotIdx)>,
	pub(crate) steps: Vec<TraceStep>,
	explained: crate::term::hashing::TermSet,
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
		for (r, run) in ex.runs.iter_enumerated() {
			for (slot, held) in run.env.iter_enumerated() {
				let Some(h) = held else {
					continue;
				};
				let constant = &cx.km.slots[slot].constant;
				if h.authored || crate::syntax::names::is_anonymous_name(&constant.name) {
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

	fn unshaped(&self) -> Names {
		let entries = self
			.entries
			.iter()
			.map(|(hash, bucket)| {
				let kept = bucket
					.iter()
					.filter(|(_, name)| !self.shaped(name))
					.cloned()
					.collect();
				(*hash, kept)
			})
			.collect();
		Names {
			entries,
			shaped: Vec::new(),
		}
	}

	fn lookup(&self, v: &Value, exclude: &[&str]) -> Option<&str> {
		self.entries
			.get(&v.hash_value())?
			.iter()
			.filter(|(known, name)| !excluded(exclude, name) && known.equivalent(v, true))
			.map(|(_, name)| name.as_str())
			.min_by_key(|name| (self.shaped(name), copy_base_name(name) != *name))
	}
}

fn head(p: &Primitive) -> String {
	match crate::primitive::threshold(p.id) {
		Some(_) => format!("{}[{}]", crate::primitive::name(p.id), p.threshold),
		None => crate::primitive::name(p.id).to_string(),
	}
}

impl<'a, 'b> Narrator<'a, 'b> {
	pub(crate) fn new(cx: &'a Context<'b>, ex: &'a Execution, honest: &'a Execution) -> Self {
		let names = Names::of(cx, ex, honest);
		Narrator {
			cx,
			ex,
			honest,
			unshaped: names.unshaped(),
			names,
			honest_names: Names::of(cx, honest, honest),
			cutoff: ex.order.len(),
			gated: Vec::new(),
			steps: Vec::new(),
			explained: crate::term::hashing::TermSet::default(),
		}
	}

	fn prefix(&self) -> usize {
		self.ex
			.order
			.get(self.cutoff)
			.map_or(self.ex.knowledge.len(), |taken| taken.known)
	}

	fn disclosure(&self, v: &Value) -> Option<Origin> {
		let program = self.cx.program;
		self.ex.order[..self.cutoff]
			.iter()
			.find_map(
				|&Taken { run, step, .. }| match program.runs[run].steps[step].event {
					Event::Leak(slot) => self.ex.runs[run]
						.held(slot)
						.is_some_and(|h| h.value.equivalent(v, true))
						.then_some(Origin::Leak { run, slot }),
					Event::Send(d) => {
						let sent = self.ex.sent[d].as_ref()?;
						program.deliveries[d]
							.slots
							.iter()
							.zip(sent)
							.find(|(_, value)| value.equivalent(v, true))
							.map(|(&(slot, _), _)| Origin::Wire { run, slot })
					}
					_ => None,
				},
			)
	}

	fn available(&self, v: &Value) -> bool {
		if self
			.ex
			.knowledge
			.knows(v)
			.is_some_and(|i| i < self.prefix())
		{
			return true;
		}
		match v {
			Value::Primitive(p) => self.oriented(p).is_some(),
			Value::Constant(_) | Value::Variable(_) => false,
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
		let projection = if crate::primitive::has_single_output(oriented.id) {
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

	fn spell(&self, names: &Names, v: &Value, exclude: &[&str]) -> String {
		match v {
			Value::Constant(_) | Value::Variable(_) => v.to_string(),
			Value::Primitive(p) => self.render(names, p, exclude),
		}
	}

	fn named(&self, names: &Names, v: &Value, exclude: &[&str]) -> String {
		match names.lookup(v, exclude) {
			Some(name) => name.to_string(),
			None => self.spell(names, v, exclude),
		}
	}

	pub(crate) fn term(&self, v: &Value, exclude: &[&str]) -> String {
		self.named(&self.names, v, exclude)
	}

	pub(crate) fn spelled(&self, v: &Value, exclude: &[&str]) -> String {
		self.spell(&self.names, v, exclude)
	}

	fn delivered(&self, v: &Value, exclude: &[&str]) -> String {
		match self.names.lookup(v, exclude) {
			Some(name) if !self.names.shaped(name) => name.to_string(),
			_ => self.spelled(v, exclude),
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

	pub(crate) fn declared(&self, slot: SlotIdx) -> String {
		self.cx.km.slots[slot].initial_value.to_string()
	}

	fn say(&mut self, line: String) {
		self.steps.push(TraceStep::new("derive", line));
	}

	fn say_routed(
		&mut self,
		(sender, recipient): (RunIdx, RunIdx),
		kind: &'static str,
		text: String,
		values: Vec<TraceValue>,
	) {
		let runs = &self.cx.program.runs;
		let mut step = TraceStep::new(kind, text);
		step.sender = Some(runs[sender].name.clone());
		step.recipient = Some(runs[recipient].name.clone());
		step.values = values;
		self.steps.push(step);
	}

	pub(crate) fn explain(&mut self, v: &Value, at: usize) {
		let outer = std::mem::replace(&mut self.cutoff, at);
		self.visit(v);
		self.cutoff = outer;
	}

	fn visit(&mut self, v: &Value) {
		if self.explained.insert(v.clone()) {
			self.narrate(v);
		}
	}

	fn narrate(&mut self, v: &Value) {
		let len = self.prefix();
		let knowledge = &self.ex.knowledge;
		let known = knowledge.knows(v).filter(|&i| i < len);
		if known.is_none()
			&& let Value::Primitive(p) = v
			&& let Some(built) = self.oriented(p)
		{
			for argument in &built.arguments {
				self.visit(argument);
			}
			self.constructs(v);
			return;
		}
		let Some(i) = known else {
			let keep: Vec<bool> = (0..knowledge.len()).map(|k| k < len).collect();
			let restricted = knowledge.state.retaining(&keep);
			let state: &AttackerState = &restricted;
			if let Value::Primitive(p) = v
				&& let Some(built) =
					crate::theory::can_reconstruct_primitive(p, &self.cx.km.capabilities, state)
			{
				for ingredient in built.recipe() {
					self.visit(ingredient);
				}
				self.derives(&built, v);
				return;
			}
			let mut inputs = crate::theory::KnowledgeInputs::new(&self.cx.km.capabilities, state);
			for idx in inputs.of_value(v).unwrap_or_default() {
				let ingredient = state.known[idx.get()].clone();
				self.visit(&ingredient);
			}
			if matches!(v, Value::Primitive(_)) {
				self.constructs(v);
			}
			return;
		};
		let origin = match knowledge.origin(i) {
			Origin::Derived(_) => self
				.disclosure(v)
				.unwrap_or_else(|| knowledge.origin(i).clone()),
			origin => origin.clone(),
		};
		match origin {
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
					self.visit(&ingredient);
				}
				self.derives(&record, v);
			}
		}
	}

	fn constructs(&mut self, v: &Value) {
		let shown = self.subject(v);
		self.say(format!("Attacker constructs {shown}."));
	}

	fn derives(&mut self, record: &DerivationRecord, v: &Value) {
		let line = match record {
			DerivationRecord::Decomposed { of, using } => format!(
				"Attacker opens {} with {}, obtaining {}.",
				self.term(of, &[]),
				self.list(using),
				self.term(v, &[])
			),
			DerivationRecord::Reconstructed { .. } => return self.constructs(v),
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
				let name = match of {
					Value::Primitive(p) => crate::primitive::name(p.id),
					Value::Constant(_) | Value::Variable(_) => "a rewrite",
				};
				format!(
					"Attacker applies {name} to {}, obtaining {}.",
					self.list(using),
					self.subject(v)
				)
			}
			DerivationRecord::Broken { of, capability, .. } => match capability {
				Capability::Weak => format!(
					"Attacker breaks {} under the declared `{}` assumption, obtaining {}.",
					self.term(of, &[]),
					capability.name(),
					self.term(v, &[])
				),
				Capability::Malleable => format!(
					"Under the declared `{}` assumption, Attacker reshapes {} into {}.",
					capability.name(),
					self.term(of, &[]),
					self.subject(v)
				),
				_ => format!(
					"Under the declared `{}` assumption, Attacker forges {}.",
					capability.name(),
					self.subject(v)
				),
			},
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
			DerivationRecord::Initial | DerivationRecord::Leaked | DerivationRecord::Obtained => {
				return;
			}
		};
		self.say(line);
	}

	fn received_at(&self, run: RunIdx, slot: SlotIdx) -> usize {
		let program = self.cx.program;
		program.runs[run]
			.step_of_slot
			.get(&slot)
			.and_then(|&step| {
				self.ex
					.order
					.iter()
					.position(|taken| taken.run == run && taken.step == step)
			})
			.unwrap_or(self.ex.order.len())
	}

	fn sent_before(&self, d: DeliveryIdx, at: usize) -> bool {
		let program = self.cx.program;
		let sender = program.deliveries[d].sender;
		self.ex.order[..at.min(self.ex.order.len())]
			.iter()
			.any(|taken| {
				taken.run == sender
					&& program.runs[taken.run].steps[taken.step].event == Event::Send(d)
			})
	}

	pub(crate) fn replayed_from(
		&self,
		run: RunIdx,
		slot: SlotIdx,
		value: &Value,
	) -> Option<&'static str> {
		let at = self.received_at(run, slot);
		let program = self.cx.program;
		let km = self.cx.km;
		let id = km.slots[slot].constant.id;
		let within = |groups: &IdMap<ValueId, Arc<Vec<ValueId>>>, s: SlotIdx| {
			groups
				.get(&id)
				.is_some_and(|group| group.contains(&km.slots[s].constant.id))
		};
		let sender = program
			.deliveries
			.iter()
			.find(|delivery| {
				delivery.recipient == run && delivery.slots.iter().any(|&(s, _)| s == slot)
			})
			.map(|delivery| delivery.sender);
		let copy_of_sender = |other: RunIdx| {
			sender.is_some_and(|sender| {
				other != sender
					&& km.interchangeable_for(program.runs[other].id, program.runs[sender].id, slot)
			})
		};
		program
			.sends(&self.ex.sent)
			.filter(|&(d, delivery, _, v)| {
				delivery.recipient != run && self.sent_before(d, at) && v.equivalent(value, true)
			})
			.find_map(|(_, delivery, s, _)| {
				if s == slot {
					copy_of_sender(delivery.sender).then_some("run")
				} else if within(&km.session_siblings, s) {
					Some("session")
				} else if within(&km.copy_siblings, s) {
					Some("scenario")
				} else {
					None
				}
			})
	}

	pub(crate) fn installs(&mut self) {
		let program = self.cx.program;
		for (run, state) in self.ex.runs.iter_enumerated() {
			if state.idle {
				let mut step = TraceStep::new(
					"idle",
					format!(
						"{} never starts a session in this execution.",
						program.runs[run].name
					),
				);
				step.principal = Some(program.runs[run].name.clone());
				self.steps.push(step);
			}
		}
		for (at, &Taken { run, step, .. }) in self.ex.order.iter().enumerate() {
			match program.runs[run].steps[step].event {
				Event::Recv(d) => self.delivery(at, run, d),
				Event::Assign(slot) if self.influenced(run, slot, &mut Vec::new()) => {
					self.gate(run, slot);
				}
				_ => {}
			}
		}
	}

	fn delivery(&mut self, at: usize, run: RunIdx, d: DeliveryIdx) {
		let program = self.cx.program;
		let delivery = &program.deliveries[d];
		let route = format!(
			"{} to {}",
			program.runs[delivery.sender].name, program.runs[delivery.recipient].name
		);
		let replayed = self.replays(run, d, &route);
		let mut was = Vec::new();
		let mut items = Vec::new();
		for (k, &(slot, _)) in delivery.slots.iter().enumerate() {
			if replayed.contains(&slot) {
				continue;
			}
			if let Some(item) = self.replacement(at, run, d, k, slot, &mut was) {
				items.push(item);
			}
		}
		if items.is_empty() {
			return;
		}
		let note = if was.is_empty() {
			String::new()
		} else {
			format!(" ({})", was.join("; "))
		};
		let names: Vec<&str> = items.iter().map(|item| item.name.as_str()).collect();
		let values: Vec<&str> = items
			.iter()
			.filter_map(|item| item.installed.as_deref())
			.collect();
		let text = format!(
			"Attacker replaces {} (sent by {route}) with {}.{note}",
			names.join(", "),
			values.join(", "),
		);
		self.say_routed(
			(delivery.sender, delivery.recipient),
			"mutations",
			text,
			items,
		);
	}

	fn replays(&mut self, run: RunIdx, d: DeliveryIdx, route: &str) -> Vec<SlotIdx> {
		let km = self.cx.km;
		let delivery = &self.cx.program.deliveries[d];
		let mut replayed = Vec::new();
		for &(slot, _) in &delivery.slots {
			let Some(h) = self.ex.runs[run].held(slot) else {
				continue;
			};
			if h.installed.is_none() {
				continue;
			}
			let Some(axis) = self.replayed_from(run, slot, &h.value) else {
				continue;
			};
			let value = h.value.clone();
			let name = km.slots[slot].constant.to_string();
			let shown = self.spelled(&value, &[&name]);
			self.explained.insert(value.clone());
			replayed.push(slot);
			self.say_routed(
				(delivery.sender, delivery.recipient),
				"replay",
				format!(
					"Attacker replays {name} ({route}) from another {axis}, where it is {shown}."
				),
				vec![TraceValue {
					name,
					installed: Some(shown),
					was: None,
					guarded: false,
				}],
			);
		}
		replayed
	}

	fn replacement(
		&mut self,
		at: usize,
		run: RunIdx,
		d: DeliveryIdx,
		k: usize,
		slot: SlotIdx,
		was: &mut Vec<String>,
	) -> Option<TraceValue> {
		let program = self.cx.program;
		let km = self.cx.km;
		let h = self.ex.runs[run].held(slot)?;
		h.installed.as_ref()?;
		let value = h.value.clone();
		let constant = km.slots[slot].constant.to_string();
		let own: [&str; 1] = [&constant];
		self.explain(&value, at);
		let previous = self.honest.runs[run].held(slot).map(|honest| &honest.value);
		let displaced = previous.map(|honest| self.spell(&self.honest_names, honest, &own));
		let mut shown = self.delivered(&value, &own);
		if displaced.as_ref() == Some(&shown)
			&& previous.is_some_and(|honest| !honest.equivalent(&value, true))
		{
			shown = self.named(&self.unshaped, &value, &own);
		}
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
		} else if previous.is_some_and(|honest| honest.equivalent(&value, true)) {
			let sender = &program.runs[program.deliveries[d].sender].name;
			match self.ex.sent[d].as_ref().and_then(|sent| sent.get(k)) {
				Some(sent) if !sent.equivalent(&value, true) => was.push(format!(
					"{sender} sent {} in this execution",
					self.spelled(sent, &own)
				)),
				None => {
					let unsent = format!("{sender} does not send this message in this execution");
					if !was.contains(&unsent) {
						was.push(unsent);
					}
				}
				Some(_) => {}
			}
		}
		Some(TraceValue {
			name: constant,
			installed: Some(shown),
			was: displaced,
			guarded: false,
		})
	}

	pub(crate) fn public(&mut self, v: &Value) {
		if let Some(i) = self.ex.knowledge.knows(v)
			&& matches!(self.ex.knowledge.origin(i), Origin::Initial)
			&& self.explained.insert(v.clone())
		{
			let shown = self.term(v, &[]);
			self.say(format!("Attacker knows {shown}: it is public."));
		}
	}

	pub(crate) fn received(&mut self, run: RunIdx, slot: SlotIdx, sender: RunIdx) {
		let runs = &self.cx.program.runs;
		let name = self.cx.km.slots[slot].constant.to_string();
		let text = format!(
			"{} received {name} from {}.",
			runs[run].name, runs[sender].name
		);
		self.say_routed(
			(sender, run),
			"received",
			text,
			vec![TraceValue {
				name,
				installed: None,
				was: None,
				guarded: false,
			}],
		);
	}

	pub(crate) fn built_from(&mut self, slot: SlotIdx, value: &Value) {
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
		self.steps.push(TraceStep::new(
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
			self.steps.push(TraceStep::new(
				"resolves",
				format!("In this state {c} resolves to {shown}."),
			));
		}
	}

	fn influenced(&self, run: RunIdx, slot: SlotIdx, seen: &mut Vec<SlotIdx>) -> bool {
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

	pub(crate) fn gate(&mut self, run: RunIdx, slot: SlotIdx) {
		let span = self.cx.km.slots[slot].declared_span;
		let same_assignment = |&(r, s): &(RunIdx, SlotIdx)| {
			r == run
				&& (s == slot
					|| (span != Span::default() && self.cx.km.slots[s].declared_span == span))
		};
		if self.gated.iter().any(same_assignment) || self.ex.runs[run].halted == Some(slot) {
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
			.iter_enumerated()
			.filter(|(_, held)| held.as_ref().is_some_and(|h| h.installed.is_some()))
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
		self.steps.push(step);
	}

	fn run_name(&self, run: RunIdx) -> &'a str {
		self.cx.program.runs[run].name.as_str()
	}

	fn shown(&self, slot: SlotIdx, value: &Value) -> String {
		let own = self.cx.km.slots[slot].constant.to_string();
		self.spelled(value, &[&own])
	}

	pub(crate) fn conclude(&mut self, q: &Query, v: &Violation) -> (String, Option<Subtype>) {
		let km = self.cx.km;
		let text = match v {
			Violation::Disclosed { run, slot, value } => return self.disclosed(*run, *slot, value),
			Violation::Forged {
				run,
				slot,
				value,
				used,
			} => {
				self.gate(*run, *used);
				format!(
					"{} ({}), sent by Attacker and not by {}, is successfully used in {} within {}'s state.",
					km.slots[*slot].constant,
					self.shown(*slot, value),
					q.message.sender_name,
					self.declared(*used),
					self.run_name(*run)
				)
			}
			Violation::Replayed {
				run,
				slot,
				value,
				used,
				emissions,
				acceptances,
			} => {
				self.gate(*run, *used);
				let subtype =
					if recipient_contributed(&km.slots[*slot].constant, km, q.message.recipient) {
						Subtype::DuplicateAcceptance
					} else {
						Subtype::ReplayableFirstFlight
					};
				let text = self.replayed(q, *run, *slot, value, *used, [*emissions, *acceptances]);
				return (text, Some(subtype));
			}
			Violation::Substituted {
				run,
				slot,
				sender,
				used,
			} => {
				self.received(*run, *slot, *sender);
				format!(
					"{}, sent by {} and not by {}, is successfully used in {} within {}'s state.",
					km.slots[*slot].constant,
					self.run_name(*sender),
					q.message.sender_name,
					self.declared(*used),
					self.run_name(*run)
				)
			}
			Violation::Stale {
				run,
				slot,
				value,
				used,
				repeated,
			} => self.stale(*run, *slot, value, *used, *repeated),
			Violation::Linked { link, resolved } => {
				self.resolves(resolved);
				let [a, b] = [&resolved[0].0, &resolved[1].0].map(ToString::to_string);
				format!(
					"Attacker links {a} and {b} {}.",
					link.describe(|v| self.term(v, &[&a, &b]))
				)
			}
			Violation::Differ { resolved } => {
				self.resolves(resolved);
				format!(
					"{} are not equivalent.",
					q.constants
						.iter()
						.map(|c| c.name.to_string())
						.collect::<Vec<_>>()
						.join(", ")
				)
			}
		};
		(text, None)
	}

	fn stale(
		&mut self,
		run: RunIdx,
		slot: SlotIdx,
		value: &Value,
		used: SlotIdx,
		repeated: Option<RunIdx>,
	) -> String {
		let constant = &self.cx.km.slots[slot].constant;
		let Some(other) = repeated else {
			self.built_from(slot, value);
			return format!(
				"{} ({}) is used by {} in {} despite not being a fresh value.",
				constant,
				self.shown(slot, value),
				self.run_name(run),
				self.declared(used)
			);
		};
		self.gate(run, used);
		format!(
			"{} ({}) is used by {} in {}, and {} accepts the same value: the attacker keeps \
			 it the same across sessions, so it is not fresh.",
			constant,
			self.shown(slot, value),
			self.run_name(run),
			self.declared(used),
			self.run_name(other)
		)
	}

	fn disclosed(
		&mut self,
		run: RunIdx,
		slot: SlotIdx,
		value: &Value,
	) -> (String, Option<Subtype>) {
		let km = self.cx.km;
		self.public(value);
		self.explain(value, self.ex.order.len());
		let constant = &km.slots[slot].constant;
		let value_shown = self.shown(slot, value);
		if !crate::theory::reduce_once(value)
			.equivalent(&super::unlink::honest_reduct(km, slot), true)
			&& !carries_a_secret(value, km)
		{
			let text = format!(
				"{constant} ({value_shown}) is obtained by Attacker, but that is the value the \
				 attacker put there: it carries nothing {} generated or holds privately, so the \
				 honest {constant} is not shown to be disclosed.",
				self.run_name(run)
			);
			return (text, Some(Subtype::AttackerSuppliedValue));
		}
		(
			format!("{constant} ({value_shown}) is obtained by Attacker."),
			None,
		)
	}

	fn replayed(
		&self,
		q: &Query,
		run: RunIdx,
		slot: SlotIdx,
		value: &Value,
		used: SlotIdx,
		[emissions, acceptances]: [usize; 2],
	) -> String {
		let axis = self.replayed_from(run, slot, value).unwrap_or("run");
		let times = |n: usize| match n {
			1 => "once".to_string(),
			2 => "twice".to_string(),
			n => format!("{n} times"),
		};
		format!(
			"{} ({}), which {s} sent in another {axis} and not in this one, is \
			 successfully used in {} within {}'s state: {s} sent it {}, {r} accepts it \
			 {}, so agreement is not injective.",
			self.cx.km.slots[slot].constant,
			self.shown(slot, value),
			self.declared(used),
			self.run_name(run),
			times(emissions),
			times(acceptances),
			s = copy_base_name(&q.message.sender_name),
			r = copy_base_name(&q.message.recipient_name),
		)
	}

	pub(crate) fn trace(&self) -> String {
		self.steps
			.iter()
			.enumerate()
			.map(|(i, step)| format!("{}. {}", i + 1, step.text))
			.collect::<Vec<_>>()
			.join("\n")
	}
}

fn carries_a_secret(v: &Value, km: &ProtocolTrace) -> bool {
	v.constant_leaves()
		.any(|c| super::unlink::declared_secret(c, km))
}

fn recipient_contributed(c: &Constant, km: &ProtocolTrace, recipient: PrincipalId) -> bool {
	crate::protocol::trace::resolve_trace_constant(c, km)
		.constant_leaves()
		.any(|inner| {
			km.index_of(inner).is_some_and(|i| {
				let slot = &km.slots[i];
				slot.constant.fresh && km.same_actor(slot.creator, recipient)
			})
		})
}
