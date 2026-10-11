/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::{
	Family, HONEST_NODE, Node, NodeIdx, Search, Source, compatible_with, input_key, normalize,
	runs_of, same_installs,
};
use crate::engine::exec::{Execution, Install, Installs, install_at};
use crate::engine::program::{Event, RunIdx, StepIdx};
use crate::protocol::SlotIdx;
use crate::term::Value;
use crate::util::index::Idx;

impl<'a, 'b> Search<'a, 'b> {
	fn fresh_sends(&self, at: NodeIdx, node: &Node) -> Vec<(Value, Source)> {
		let mut out = Vec::new();
		for (d, delivery) in self.cx.program.deliveries.iter_enumerated() {
			let Some(sent) = &node.sent[d] else {
				continue;
			};
			let rerouted = self.retries.rerouting && self.replaced(node, d).next().is_some();
			for (k, v) in sent.iter().enumerate() {
				let honest = self.nodes[HONEST_NODE].sent[d]
					.as_ref()
					.map(|values| &values[k]);
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

	fn fresh_leaks(&self, at: NodeIdx, ex: &Execution) -> Vec<(Value, Source)> {
		let mut out = Vec::new();
		for taken in &ex.order {
			let Event::Leak(slot) = self.cx.program.runs[taken.run].steps[taken.step].event else {
				continue;
			};
			let Some(held) = ex.runs[taken.run].held(slot) else {
				continue;
			};
			let honest = &self.honest.runs[taken.run];
			if honest.reached(taken.step)
				&& honest
					.held(slot)
					.is_some_and(|h| h.value.equivalent(&held.value, true))
			{
				continue;
			}
			let source = Source {
				node: at,
				run: taken.run,
				slot,
			};
			out.push((held.value.clone(), source));
		}
		out
	}

	pub(super) fn note_fresh(&mut self, at: NodeIdx, node: &Node, ex: &Execution) -> bool {
		let mut emitted = self.fresh_sends(at, node);
		emitted.extend(self.fresh_leaks(at, ex));
		self.note_sources(emitted, runs_of(&node.installs))
	}

	pub(super) fn registered(&self, v: &Value, run: RunIdx, touched: &[RunIdx]) -> bool {
		self.retries
			.fresh
			.get(&v.hash_value())
			.is_some_and(|bucket| {
				bucket.iter().any(|(w, held, runs)| {
					held.run == run && w.equivalent(v, true) && runs == touched
				})
			})
	}

	pub(super) fn note_sources(
		&mut self,
		sends: Vec<(Value, Source)>,
		touched: Vec<RunIdx>,
	) -> bool {
		let mut added = false;
		for (v, source) in sends {
			if self.registered(&v, source.run, &touched) {
				continue;
			}
			self.retries.fresh.entry(v.hash_value()).or_default().push((
				v,
				source,
				touched.clone(),
			));
			added = true;
		}
		added
	}

	pub(super) fn fresh_sources(&self, v: &Value) -> Vec<Source> {
		self.retries
			.fresh
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
		stuck: &[(RunIdx, SlotIdx)],
		source: Source,
		cone: &[(RunIdx, SlotIdx)],
	) -> Option<Installs> {
		let source = &self.nodes[source.node];
		let kept: Installs = plan
			.iter()
			.filter(|install| {
				let Install::Value { run, slot, value } = install else {
					return true;
				};
				stuck.contains(&(*run, *slot))
					|| !cone.contains(&(*run, *slot))
					|| install_at(&source.installs, *run, *slot).is_some()
					|| source
						.held(*run, *slot)
						.is_none_or(|h| h.value.equivalent(value, true))
			})
			.cloned()
			.collect();
		(kept.len() < plan.len()).then_some(kept)
	}

	pub(super) fn stuck_sources<'v>(
		&self,
		at: usize,
		values: impl Iterator<Item = (&'v Value, Option<(RunIdx, StepIdx)>)> + Clone,
	) -> Vec<Source> {
		let stuck = &self.retries.stuck[at];
		let candidates = |relaxed: bool| {
			let mut sources: Vec<Source> = Vec::new();
			for (value, receive) in values.clone() {
				for source in self.fresh_sources(value) {
					let n = source.node;
					if n == HONEST_NODE
						|| sources.iter().any(|s| s.node == n)
						|| stuck.tried_with.contains(&n)
						|| !receive.is_none_or(|(run, receive)| self.bypasses(source, run, receive))
					{
						continue;
					}
					let outside = if relaxed {
						self.outside_cone(&stuck.installs, &stuck.slots, source)
					} else {
						stuck.installs.clone()
					};
					if compatible_with(&outside, &self.nodes[n].installs) {
						sources.push(source);
					}
				}
			}
			sources
		};
		let strict = candidates(false);
		if strict.is_empty() {
			candidates(true)
		} else {
			strict
		}
	}

	fn outside_cone(
		&self,
		installs: &Installs,
		stuck: &[(RunIdx, SlotIdx)],
		source: Source,
	) -> Installs {
		let mut cone = Vec::new();
		self.cone(source.run, source.slot, &mut cone);
		let supplied = &self.nodes[source.node].installs;
		installs
			.iter()
			.filter(|install| {
				install.slot().is_none_or(|slot| {
					let at = (install.run(), slot);
					!stuck.contains(&at)
						|| !cone.contains(&at)
						|| install_at(supplied, at.0, at.1).is_none()
				})
			})
			.cloned()
			.collect()
	}

	pub(super) fn retry_stuck(&mut self, at: usize) {
		let installs = self.retries.stuck[at].installs.clone();
		let slots = self.retries.stuck[at].slots.clone();
		let mut supply = std::mem::take(&mut self.retries.stuck[at].supply);
		let stuck_at = |install: &Install| {
			install
				.slot()
				.is_some_and(|slot| slots.contains(&(install.run(), slot)))
		};
		let mut wanted: Vec<&Value> = Vec::new();
		for value in installs
			.iter()
			.filter(|install| stuck_at(install))
			.filter_map(Install::value)
		{
			for w in crate::term::subterms(value) {
				if (w.same_term(value) || !self.derivable_in(HONEST_NODE, w, self.cx.km.max_phase))
					&& !wanted.iter().any(|held| held.equivalent(w, true))
				{
					wanted.push(w);
				}
			}
		}
		let sources = self.stuck_sources(at, wanted.iter().map(|&v| (v, None)));
		let tried_with = &self.retries.stuck[at].tried_with;
		let mut suppliers: Vec<(NodeIdx, Installs)> = Vec::new();
		let context: Vec<&Install> = installs
			.iter()
			.filter(|install| !stuck_at(install))
			.collect();
		let rarest = context
			.iter()
			.map(|install| {
				self.retries
					.by_input
					.get(&input_key(install))
					.map_or(&[][..], Vec::as_slice)
			})
			.min_by_key(|posting| posting.len())
			.unwrap_or(&[]);
		for (install, next) in supply.iter_mut() {
			let Install::Value { run, slot, value } = &installs[*install] else {
				continue;
			};
			let program = &self.cx.program.runs[*run];
			let phase = program
				.step_of_slot
				.get(slot)
				.map_or(0, |&step| program.steps[step].phase);
			let start = rarest.partition_point(|&n| n < *next);
			let mut found = false;
			for &n in &rarest[start..] {
				*next = n.next();
				if sources.iter().any(|s| s.node == n)
					|| suppliers.iter().any(|(m, _)| *m == n)
					|| tried_with.contains(&n)
				{
					continue;
				}
				let within = context.iter().all(|install| {
					self.nodes[n]
						.installs
						.iter()
						.any(|held| held.same_input(install))
				});
				if !within || !self.derivable_in(n, value, phase) {
					continue;
				}
				let plan = self.project(self.merged(&[n], installs.clone()));
				if same_installs(&plan, &installs) || self.attempts.tried.position(&plan).is_some()
				{
					continue;
				}
				suppliers.push((n, plan));
				found = true;
				break;
			}
			if !found {
				*next = self.nodes.next_index();
			}
		}
		self.retries.stuck[at].supply = supply;
		self.retries.stuck[at].tried_with.extend(
			sources
				.iter()
				.map(|s| s.node)
				.chain(suppliers.iter().map(|(n, _)| *n)),
		);
		for (_, plan) in suppliers {
			if self.done() {
				return;
			}
			self.as_family(Family::Stuck, |search| search.consider(plan));
		}
		self.try_sources(&installs, &slots, sources);
	}

	pub(super) fn try_sources(
		&mut self,
		installs: &Installs,
		slots: &[(RunIdx, SlotIdx)],
		sources: Vec<Source>,
	) {
		for source in sources {
			if self.done() {
				return;
			}
			let mut plan = self.merged(&[source.node], self.outside_cone(installs, slots, source));
			let mut cone = Vec::new();
			self.cone(source.run, source.slot, &mut cone);
			for install in &self.nodes[source.node].installs {
				if let Install::Value { run, slot, .. } = install
					&& cone.contains(&(*run, *slot))
					&& install_at(&plan, *run, *slot).is_none()
				{
					plan.push(install.clone());
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
		while at < self.retries.stuck.len() {
			if self.done() {
				return;
			}
			self.retry_stuck(at);
			at += 1;
		}
	}

	pub(super) fn cone(&self, run: RunIdx, slot: SlotIdx, out: &mut Vec<(RunIdx, SlotIdx)>) {
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
