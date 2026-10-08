/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::{Bypassed, Family, HONEST_NODE, Node, NodeIdx, Search, Source, Stuck, runs_of};
use crate::engine::exec::{Install, Installs};
use crate::engine::program::{DeliveryIdx, Event, RunIdx, StepIdx};
use crate::term::Value;
use crate::util::IdMap;
use crate::util::index::{Idx, IndexVec};

type Registration = (Vec<(Value, Source)>, Vec<RunIdx>);

impl<'a, 'b> Search<'a, 'b> {
	fn send_step(&self, d: DeliveryIdx) -> Option<StepIdx> {
		let sender = self.cx.program.deliveries[d].sender;
		self.cx.program.runs[sender]
			.steps
			.position(|step| step.event == Event::Send(d))
	}

	fn honest_sent_at(&self, d: DeliveryIdx) -> Option<usize> {
		let sender = self.cx.program.deliveries[d].sender;
		self.facts
			.honest_at
			.get(&(sender, self.send_step(d)?))
			.copied()
	}

	pub(super) fn replaced<'n>(
		&'n self,
		node: &'n Node,
		d: DeliveryIdx,
	) -> impl Iterator<Item = DeliveryIdx> + 'n {
		let sender = self.cx.program.deliveries[d].sender;
		let run = &self.cx.program.runs[sender];
		let send = self.send_step(d);
		node.held[sender].iter().filter_map(move |held| {
			let step = *run.step_of_slot.get(&held.slot)?;
			let Event::Recv(replaced) = run.steps[step].event else {
				return None;
			};
			(held.installed && send.is_some_and(|send| step < send)).then_some(replaced)
		})
	}

	fn bypassed(&self, node: &Node, d: DeliveryIdx) -> Bypassed {
		self.replaced(node, d)
			.filter_map(|replaced| {
				let sender = self.cx.program.deliveries[replaced].sender;
				Some((sender, self.send_step(replaced)?))
			})
			.collect()
	}

	fn after(&self, run: RunIdx, receive: StepIdx) -> IndexVec<RunIdx, Option<StepIdx>> {
		let program = self.cx.program;
		let mut first: IndexVec<RunIdx, Option<StepIdx>> =
			IndexVec::from_elem(None, program.runs.len());
		first[run] = Some(receive.next());
		let mut changed = true;
		while changed {
			changed = false;
			for (d, delivery) in program.deliveries.iter_enumerated() {
				let Some(from) = first[delivery.sender] else {
					continue;
				};
				if self.send_step(d).is_none_or(|send| send < from) {
					continue;
				}
				let Some(at) = program.runs[delivery.recipient]
					.steps
					.position(|step| step.event == Event::Recv(d))
				else {
					continue;
				};
				if first[delivery.recipient].is_none_or(|held| at < held) {
					first[delivery.recipient] = Some(at);
					changed = true;
				}
			}
		}
		first
	}

	fn reaches(&self, bypassed: &[(RunIdx, StepIdx)], run: RunIdx, receive: StepIdx) -> bool {
		let after = self.after(run, receive);
		bypassed
			.iter()
			.any(|&(sender, send)| after[sender].is_some_and(|first| send >= first))
	}

	pub(super) fn rerouted_sends(
		&self,
		at: NodeIdx,
		node: &Node,
	) -> Vec<(Value, Source, Bypassed)> {
		let mut out = Vec::new();
		for (d, delivery) in self.cx.program.deliveries.iter_enumerated() {
			let Some(sent) = &node.sent[d] else {
				continue;
			};
			let bypassed = self.bypassed(node, d);
			if bypassed.is_empty() {
				continue;
			}
			for (k, v) in sent.iter().enumerate() {
				let source = Source {
					node: at,
					run: delivery.sender,
					slot: delivery.slots[k].0,
				};
				out.push((v.clone(), source, bypassed.clone()));
			}
		}
		out
	}

	fn waiting(&self, stuck: &Stuck) -> Vec<(Value, RunIdx, StepIdx)> {
		let program = self.cx.program;
		stuck
			.installs
			.iter()
			.filter_map(|install| match install {
				Install::Value { run, slot, value } if stuck.slots.contains(&(*run, *slot)) => {
					Some((run, slot, value))
				}
				_ => None,
			})
			.flat_map(|(run, slot, value)| {
				let mut out = Vec::new();
				let Some(&step) = program.runs[*run].step_of_slot.get(slot) else {
					return out;
				};
				let Some(&receive) = self.facts.honest_at.get(&(*run, step)) else {
					return out;
				};
				let sends = |w: &Value| -> Vec<usize> {
					program
						.deliveries
						.indices()
						.filter(|&d| {
							self.nodes[HONEST_NODE].sent[d]
								.as_ref()
								.is_some_and(|sent| sent.iter().any(|v| v.equivalent(w, true)))
						})
						.filter_map(|d| self.honest_sent_at(d))
						.collect()
				};
				if sends(value).iter().all(|&sent| sent >= receive) {
					out.push((value.clone(), *run, step));
				}
				for w in crate::term::subterms(value) {
					if w.same_term(value) || out.iter().any(|(held, _, _)| held.equivalent(w, true))
					{
						continue;
					}
					let sent = sends(w);
					if !sent.is_empty() && sent.iter().all(|&at| at >= receive) {
						out.push((w.clone(), *run, step));
					}
				}
				out
			})
			.collect()
	}

	pub(super) fn bypasses(&self, source: Source, run: RunIdx, receive: StepIdx) -> bool {
		let node = &self.nodes[source.node];
		self.cx
			.program
			.deliveries
			.iter_enumerated()
			.any(|(d, delivery)| {
				delivery.sender == source.run
					&& node.sent[d].is_some()
					&& delivery.slots.iter().any(|&(slot, _)| slot == source.slot)
					&& self.reaches(&self.bypassed(node, d), run, receive)
			})
	}

	pub(super) fn reroute(&mut self) {
		if self.done() {
			return;
		}
		self.retries.rerouting = true;
		let waiting: Vec<Vec<(Value, RunIdx, StepIdx)>> = self
			.retries
			.stuck
			.iter()
			.map(|stuck| self.waiting(stuck))
			.collect();
		let mut earliest: IdMap<u64, Vec<(&Value, RunIdx, StepIdx)>> = IdMap::default();
		for (value, run, receive) in waiting.iter().flatten() {
			let bucket = earliest.entry(value.hash_value()).or_default();
			match bucket
				.iter_mut()
				.find(|(held, r, _)| r == run && held.equivalent(value, true))
			{
				Some((_, _, at)) => *at = (*at).min(*receive),
				None => bucket.push((value, *run, *receive)),
			}
		}
		let wanted = |v: &Value, bypassed: &[(RunIdx, StepIdx)]| {
			earliest.get(&v.hash_value()).is_some_and(|bucket| {
				bucket.iter().any(|&(w, run, receive)| {
					w.equivalent(v, true) && self.reaches(bypassed, run, receive)
				})
			})
		};
		let registered: Vec<Registration> = self
			.nodes
			.iter_enumerated()
			.map(|(n, node)| {
				let sends = self
					.rerouted_sends(n, node)
					.into_iter()
					.filter(|(v, _, bypassed)| wanted(v, bypassed))
					.map(|(v, source, _)| (v, source))
					.collect();
				(sends, runs_of(&node.installs))
			})
			.collect();
		let chosen: Vec<(Installs, Vec<(Value, RunIdx)>)> = self
			.retries
			.routes
			.iter()
			.filter_map(|(installs, sends)| {
				let useful: Vec<(Value, RunIdx)> = sends
					.iter()
					.filter(|(v, _, bypassed)| wanted(v, bypassed))
					.map(|(v, run, _)| (v.clone(), *run))
					.collect();
				(!useful.is_empty()).then(|| (installs.clone(), useful))
			})
			.collect();
		self.retries.routes.clear();
		for (sends, touched) in registered {
			self.note_sources(sends, touched);
		}
		for (installs, useful) in chosen {
			if self.done() {
				return;
			}
			let touched = runs_of(&installs);
			if useful
				.iter()
				.all(|(v, run)| self.registered(v, *run, &touched))
			{
				continue;
			}
			let ex = self.execute_counted(&installs);
			let accepted = self.as_family(Family::Rerouted, |search| search.accept(installs, ex));
			self.tally(Family::Rerouted, accepted);
		}
		for (index, late) in waiting.iter().enumerate() {
			if self.done() {
				return;
			}
			let sources = self.stuck_sources(
				index,
				late.iter()
					.map(|(value, run, receive)| (value, Some((*run, *receive)))),
			);
			if sources.is_empty() {
				continue;
			}
			let installs = self.retries.stuck[index].installs.clone();
			let slots = self.retries.stuck[index].slots.clone();
			self.retries.stuck[index]
				.tried_with
				.extend(sources.iter().map(|s| s.node));
			self.try_sources(&installs, &slots, sources);
		}
		self.drain();
	}
}
