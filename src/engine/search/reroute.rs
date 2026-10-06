/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::{Bypassed, Family, Node, Search, Source, Stuck, runs_of};
use crate::engine::exec::Installs;
use crate::engine::program::Event;
use crate::term::Value;
use crate::util::IdMap;

type Registration = (Vec<(Value, Source)>, Vec<usize>);

fn reaches(bypassed: &[(usize, usize)], run: usize, receive: usize) -> bool {
	bypassed
		.iter()
		.any(|&(sender, sent)| sender == run && sent > receive)
}

impl<'a, 'b> Search<'a, 'b> {
	fn send_step(&self, d: usize) -> Option<usize> {
		let sender = self.cx.program.deliveries[d].sender;
		self.cx.program.runs[sender]
			.steps
			.iter()
			.position(|step| step.event == Event::Send(d))
	}

	fn honest_sent_at(&self, d: usize) -> Option<usize> {
		let sender = self.cx.program.deliveries[d].sender;
		self.honest_at.get(&(sender, self.send_step(d)?)).copied()
	}

	pub(super) fn replaced<'n>(
		&'n self,
		node: &'n Node,
		d: usize,
	) -> impl Iterator<Item = usize> + 'n {
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

	fn bypassed(&self, node: &Node, d: usize) -> Vec<(usize, usize)> {
		self.replaced(node, d)
			.filter_map(|replaced| {
				let sender = self.cx.program.deliveries[replaced].sender;
				Some((sender, self.honest_sent_at(replaced)?))
			})
			.collect()
	}

	pub(super) fn rerouted_sends(&self, at: usize, node: &Node) -> Vec<(Value, Source, Bypassed)> {
		let mut out = Vec::new();
		for (d, delivery) in self.cx.program.deliveries.iter().enumerate() {
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

	fn waiting(&self, stuck: &Stuck) -> Vec<(Value, usize, usize)> {
		let program = self.cx.program;
		stuck
			.installs
			.iter()
			.filter(|(run, slot, _)| stuck.slots.contains(&(*run, *slot)))
			.filter_map(|(run, slot, value)| {
				let step = *program.runs[*run].step_of_slot.get(slot)?;
				let receive = *self.honest_at.get(&(*run, step))?;
				let early = (0..program.deliveries.len()).any(|d| {
					self.nodes[0].sent[d]
						.as_ref()
						.is_some_and(|sent| sent.iter().any(|v| v.equivalent(value, true)))
						&& self.honest_sent_at(d).is_some_and(|sent| sent < receive)
				});
				(!early).then(|| (value.clone(), *run, receive))
			})
			.collect()
	}

	pub(super) fn bypasses(&self, source: Source, run: usize, receive: usize) -> bool {
		let node = &self.nodes[source.node];
		self.cx
			.program
			.deliveries
			.iter()
			.enumerate()
			.any(|(d, delivery)| {
				delivery.sender == source.run
					&& node.sent[d].is_some()
					&& delivery.slots.iter().any(|&(slot, _)| slot == source.slot)
					&& reaches(&self.bypassed(node, d), run, receive)
			})
	}

	pub(super) fn reroute(&mut self) {
		if self.done() {
			return;
		}
		self.rerouting = true;
		let waiting: Vec<Vec<(Value, usize, usize)>> =
			self.stuck.iter().map(|stuck| self.waiting(stuck)).collect();
		let mut earliest: IdMap<(u64, usize), Vec<(&Value, usize)>> = IdMap::default();
		for (value, run, receive) in waiting.iter().flatten() {
			let bucket = earliest.entry((value.hash_value(), *run)).or_default();
			match bucket
				.iter_mut()
				.find(|(held, _)| held.equivalent(value, true))
			{
				Some((_, at)) => *at = (*at).min(*receive),
				None => bucket.push((value, *receive)),
			}
		}
		let wanted = |v: &Value, bypassed: &[(usize, usize)]| {
			bypassed.iter().any(|&(run, sent)| {
				earliest.get(&(v.hash_value(), run)).is_some_and(|bucket| {
					bucket
						.iter()
						.any(|(w, receive)| *receive < sent && w.equivalent(v, true))
				})
			})
		};
		let registered: Vec<Registration> = self
			.nodes
			.iter()
			.enumerate()
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
		let chosen: Vec<(Installs, Vec<(Value, usize)>)> = self
			.routes
			.iter()
			.filter_map(|(installs, sends)| {
				let useful: Vec<(Value, usize)> = sends
					.iter()
					.filter(|(v, _, bypassed)| wanted(v, bypassed))
					.map(|(v, run, _)| (v.clone(), *run))
					.collect();
				(!useful.is_empty()).then(|| (installs.clone(), useful))
			})
			.collect();
		self.routes.clear();
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
			let installs = self.stuck[index].installs.clone();
			let slots = self.stuck[index].slots.clone();
			self.stuck[index]
				.tried_with
				.extend(sources.iter().map(|s| s.node));
			self.try_sources(&installs, &slots, sources);
		}
		self.drain();
	}
}
