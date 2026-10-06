/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::{Family, Node, Search, Source, compatible_with, normalize, runs_of, same_installs};
use crate::engine::exec::{Installs, install_at};
use crate::engine::program::Event;
use crate::term::Value;
use crate::theory::obtainable;

impl<'a, 'b> Search<'a, 'b> {
	fn fresh_sends(&self, at: usize, node: &Node) -> Vec<(Value, Source)> {
		let mut out = Vec::new();
		for (d, delivery) in self.cx.program.deliveries.iter().enumerate() {
			let Some(sent) = &node.sent[d] else {
				continue;
			};
			let rerouted = self.rerouting && self.replaced(node, d).next().is_some();
			for (k, v) in sent.iter().enumerate() {
				let honest = self.nodes[0].sent[d].as_ref().map(|values| &values[k]);
				if !rerouted && honest.is_some_and(|h| h.equivalent(v, true)) {
					continue;
				}
				let source = Source {
					node: at,
					run: delivery.sender,
					slot: delivery.slots[k].0,
				};
				out.push((v.clone(), source));
			}
		}
		out
	}

	pub(super) fn note_fresh(&mut self, at: usize, node: &Node) -> bool {
		let sends = self.fresh_sends(at, node);
		self.note_sources(sends, runs_of(&node.installs))
	}

	pub(super) fn registered(&self, v: &Value, run: usize, touched: &[usize]) -> bool {
		self.fresh.get(&v.hash_value()).is_some_and(|bucket| {
			bucket
				.iter()
				.any(|(w, held, runs)| held.run == run && w.equivalent(v, true) && runs == touched)
		})
	}

	pub(super) fn note_sources(
		&mut self,
		sends: Vec<(Value, Source)>,
		touched: Vec<usize>,
	) -> bool {
		let mut added = false;
		for (v, source) in sends {
			if self.registered(&v, source.run, &touched) {
				continue;
			}
			self.fresh
				.entry(v.hash_value())
				.or_default()
				.push((v, source, touched.clone()));
			added = true;
		}
		added
	}

	fn fresh_sources(&self, v: &Value) -> Vec<Source> {
		self.fresh
			.get(&v.hash_value())
			.into_iter()
			.flatten()
			.filter(|(w, _, _)| w.equivalent(v, true))
			.map(|(_, source, _)| *source)
			.collect()
	}

	fn cleared(
		&self,
		plan: &Installs,
		stuck: &[(usize, usize)],
		source: Source,
		cone: &[(usize, usize)],
	) -> Option<Installs> {
		let source = &self.nodes[source.node];
		let kept: Installs = plan
			.iter()
			.filter(|(r, s, v)| {
				stuck.contains(&(*r, *s))
					|| !cone.contains(&(*r, *s))
					|| install_at(&source.installs, *r, *s).is_some()
					|| source
						.held(*r, *s)
						.is_none_or(|h| h.value.equivalent(v, true))
			})
			.cloned()
			.collect();
		(kept.len() < plan.len()).then_some(kept)
	}

	pub(super) fn stuck_sources<'v>(
		&self,
		at: usize,
		values: impl Iterator<Item = (&'v Value, Option<(usize, usize)>)>,
	) -> Vec<Source> {
		let stuck = &self.stuck[at];
		let mut sources: Vec<Source> = Vec::new();
		for (value, receive) in values {
			for source in self.fresh_sources(value) {
				let n = source.node;
				if n != 0
					&& !sources.iter().any(|s| s.node == n)
					&& !stuck.tried_with.contains(&n)
					&& compatible_with(&stuck.installs, &self.nodes[n].installs)
					&& receive.is_none_or(|(run, receive)| self.bypasses(source, run, receive))
				{
					sources.push(source);
				}
			}
		}
		sources
	}

	pub(super) fn retry_stuck(&mut self, at: usize) {
		let installs = self.stuck[at].installs.clone();
		let slots = self.stuck[at].slots.clone();
		let mut supply = std::mem::take(&mut self.stuck[at].supply);
		let sources = self.stuck_sources(
			at,
			installs
				.iter()
				.filter(|(run, slot, _)| slots.contains(&(*run, *slot)))
				.map(|(_, _, value)| (value, None)),
		);
		let tried_with = &self.stuck[at].tried_with;
		let mut suppliers: Vec<usize> = Vec::new();
		let context: Vec<&(usize, usize, Value)> = installs
			.iter()
			.filter(|(run, slot, _)| !slots.contains(&(*run, *slot)))
			.collect();
		let rarest = context
			.iter()
			.map(|(run, slot, value)| {
				self.by_install
					.get(&(*run, *slot, value.hash_value()))
					.map_or(&[][..], Vec::as_slice)
			})
			.min_by_key(|posting| posting.len())
			.unwrap_or(&[]);
		for (install, next) in supply.iter_mut() {
			let (run, slot, value) = &installs[*install];
			let program = &self.cx.program.runs[*run];
			let phase = program
				.step_of_slot
				.get(slot)
				.map_or(0, |&step| program.steps[step].phase);
			let start = rarest.partition_point(|&n| n < *next);
			let mut found = false;
			for &n in &rarest[start..] {
				*next = n + 1;
				if sources.iter().any(|s| s.node == n)
					|| suppliers.contains(&n)
					|| tried_with.contains(&n)
				{
					continue;
				}
				let within = context.iter().all(|(run, slot, held)| {
					install_at(&self.nodes[n].installs, *run, *slot)
						.is_some_and(|v| v.equivalent(held, true))
				});
				if within
					&& compatible_with(&installs, &self.nodes[n].installs)
					&& obtainable(value, &self.cx.km.capabilities, self.nodes[n].at(phase))
				{
					suppliers.push(n);
					found = true;
					break;
				}
			}
			if !found {
				*next = self.nodes.len();
			}
		}
		self.stuck[at].supply = supply;
		self.stuck[at].tried_with.extend(
			sources
				.iter()
				.map(|s| s.node)
				.chain(suppliers.iter().copied()),
		);
		for n in suppliers {
			if self.done() {
				return;
			}
			let plan = self.merged(&[n], installs.clone());
			if !same_installs(&plan, &installs) {
				self.as_family(Family::Stuck, |search| search.consider(plan));
			}
		}
		self.try_sources(&installs, &slots, sources);
	}

	pub(super) fn try_sources(
		&mut self,
		installs: &Installs,
		slots: &[(usize, usize)],
		sources: Vec<Source>,
	) {
		for source in sources {
			if self.done() {
				return;
			}
			let mut plan = self.merged(&[source.node], installs.clone());
			let mut cone = Vec::new();
			self.cone(source.run, source.slot, &mut cone);
			for (r, s, v) in &self.nodes[source.node].installs {
				if cone.contains(&(*r, *s)) && install_at(&plan, *r, *s).is_none() {
					plan.push((*r, *s, v.clone()));
				}
			}
			let plan = normalize(plan);
			let cleared = self.cleared(&plan, slots, source, &cone);
			let settled = !same_installs(&plan, installs)
				&& self.as_family(Family::Stuck, |search| search.settles(plan));
			if !settled && let Some(cleared) = cleared {
				self.as_family(Family::Cleared, |search| search.consider(cleared));
			}
		}
	}

	pub(super) fn retry_all_stuck(&mut self) {
		let mut at = 0;
		while at < self.stuck.len() {
			if self.done() {
				return;
			}
			self.retry_stuck(at);
			at += 1;
		}
	}

	pub(super) fn cone(&self, run: usize, slot: usize, out: &mut Vec<(usize, usize)>) {
		if out.contains(&(run, slot)) {
			return;
		}
		out.push((run, slot));
		let program = self.cx.program;
		let km = self.cx.km;
		let Some(&step) = program.runs[run].step_of_slot.get(&slot) else {
			return;
		};
		match program.runs[run].steps[step].event {
			Event::Recv(d) => self.cone(program.deliveries[d].sender, slot, out),
			Event::Assign(_) => {
				for leaf in km.slots[slot].initial_value.constant_leaves() {
					if let Some(at) = km.index_of(leaf) {
						self.cone(run, at, out);
					}
				}
			}
			_ => {}
		}
	}
}
