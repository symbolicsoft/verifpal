/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::protocol::{ProtocolTrace, SlotIdx};
use crate::syntax::{Block, Declaration, Model, PrincipalId};
use crate::term::Value;
use crate::util::IdMap;
use crate::util::index::{IndexVec, index_type};

index_type!(
	pub(crate) struct RunIdx;
);
index_type!(
	pub(crate) struct StepIdx;
);
index_type!(
	pub(crate) struct DeliveryIdx;
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Event {
	Hold(SlotIdx),
	Assign(SlotIdx),
	Leak(SlotIdx),
	Send(DeliveryIdx),
	Recv(DeliveryIdx),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Step {
	pub(crate) event: Event,
	pub(crate) phase: i32,
}

#[derive(Clone, Debug)]
pub(crate) struct Delivery {
	pub(crate) sender: RunIdx,
	pub(crate) recipient: RunIdx,
	pub(crate) slots: Vec<(SlotIdx, bool)>,
}

#[derive(Clone, Debug)]
pub(crate) struct Run {
	pub(crate) id: PrincipalId,
	pub(crate) name: String,
	pub(crate) steps: IndexVec<StepIdx, Step>,
	pub(crate) step_of_slot: IdMap<SlotIdx, StepIdx>,
}

impl Run {
	fn push(
		&mut self,
		event: Event,
		phase: i32,
		gives: impl IntoIterator<Item = SlotIdx>,
	) -> StepIdx {
		for slot in gives {
			self.step_of_slot
				.entry(slot)
				.or_insert(self.steps.next_index());
		}
		self.steps.push(Step { event, phase })
	}
}

#[derive(Clone, Debug)]
pub(crate) struct Program {
	pub(crate) runs: IndexVec<RunIdx, Run>,
	run_of: IdMap<PrincipalId, RunIdx>,
	pub(crate) deliveries: IndexVec<DeliveryIdx, Delivery>,
	pub(crate) order: Vec<(RunIdx, StepIdx)>,
	receivers: IndexVec<SlotIdx, Vec<RunIdx>>,
	carriers: IndexVec<SlotIdx, Vec<RunIdx>>,
	emitted: IndexVec<SlotIdx, Vec<(RunIdx, bool)>>,
}

impl Program {
	pub(crate) fn of(m: &Model, km: &ProtocolTrace) -> Program {
		let mut runs: IndexVec<RunIdx, Run> = km
			.principal_ids
			.iter()
			.zip(km.principals.iter())
			.map(|(&id, name)| Run {
				id,
				name: name.clone(),
				steps: IndexVec::new(),
				step_of_slot: IdMap::default(),
			})
			.collect();
		let run_of: IdMap<PrincipalId, RunIdx> =
			runs.iter_enumerated().map(|(i, r)| (r.id, i)).collect();
		let mut deliveries = IndexVec::new();
		let mut order = Vec::new();
		let mut phase = 0i32;
		for block in &m.blocks {
			match block {
				Block::Principal(p) => {
					let Some(&run) = run_of.get(&p.id) else {
						continue;
					};
					for expr in &p.expressions {
						for slot in expr.constants.iter().filter_map(|c| km.index_of(c)) {
							let (event, gives) = match expr.kind {
								Declaration::Knows | Declaration::Generates => {
									(Event::Hold(slot), Some(slot))
								}
								Declaration::Assignment => (Event::Assign(slot), Some(slot)),
								Declaration::Leaks => (Event::Leak(slot), None),
							};
							order.push((run, runs[run].push(event, phase, gives)));
						}
					}
				}
				Block::Message(msg) => {
					let (Some(&sender), Some(&recipient)) =
						(run_of.get(&msg.sender), run_of.get(&msg.recipient))
					else {
						continue;
					};
					let slots: Vec<(SlotIdx, bool)> = msg
						.constants
						.iter()
						.filter_map(|c| km.index_of(c).map(|slot| (slot, c.guard)))
						.collect();
					let d = deliveries.next_index();
					order.push((sender, runs[sender].push(Event::Send(d), phase, None)));
					let received = runs[recipient].push(
						Event::Recv(d),
						phase,
						slots.iter().map(|&(slot, _)| slot),
					);
					order.push((recipient, received));
					deliveries.push(Delivery {
						sender,
						recipient,
						slots,
					});
				}
				Block::Phase(ph) => {
					phase = ph.number;
				}
			}
		}
		let mut receivers: IndexVec<SlotIdx, Vec<RunIdx>> =
			IndexVec::from_elem(Vec::new(), km.slots.len());
		let mut carriers = receivers.clone();
		let mut emitted: IndexVec<SlotIdx, Vec<(RunIdx, bool)>> =
			IndexVec::from_elem(Vec::new(), km.slots.len());
		for delivery in &deliveries {
			for &(slot, guarded) in &delivery.slots {
				if !emitted[slot].contains(&(delivery.sender, guarded)) {
					emitted[slot].push((delivery.sender, guarded));
				}
				if !guarded && !receivers[slot].contains(&delivery.recipient) {
					receivers[slot].push(delivery.recipient);
				}
				if (!guarded || carriers[slot].contains(&delivery.sender))
					&& !carriers[slot].contains(&delivery.recipient)
				{
					carriers[slot].push(delivery.recipient);
				}
			}
		}
		Program {
			runs,
			run_of,
			deliveries,
			order,
			receivers,
			carriers,
			emitted,
		}
	}

	pub(crate) fn sends<'a>(
		&'a self,
		sent: &'a IndexVec<DeliveryIdx, Option<Vec<Value>>>,
	) -> impl Iterator<Item = (DeliveryIdx, &'a Delivery, SlotIdx, &'a Value)> + Clone + 'a {
		self.deliveries
			.iter_enumerated()
			.zip(sent)
			.filter_map(|((d, delivery), sent)| Some((d, delivery, sent.as_ref()?)))
			.flat_map(|(d, delivery, sent)| {
				delivery
					.slots
					.iter()
					.zip(sent)
					.map(move |(&(slot, _), v)| (d, delivery, slot, v))
			})
	}

	pub(crate) fn receivers(&self, slot: SlotIdx) -> &[RunIdx] {
		&self.receivers[slot]
	}

	pub(crate) fn carriers(&self, slot: SlotIdx) -> &[RunIdx] {
		&self.carriers[slot]
	}

	pub(crate) fn points(&self, run: RunIdx, slot: SlotIdx) -> Vec<RunIdx> {
		let receivers = self.receivers(slot);
		if receivers.contains(&run) {
			return vec![run];
		}
		let mut reach = vec![run];
		let mut upstream = Vec::new();
		let mut at = 0;
		while at < reach.len() {
			let run = reach[at];
			at += 1;
			let Some((delivery, guarded, _)) = self.receipt(run, slot) else {
				continue;
			};
			if !guarded {
				upstream.push(run);
			} else if !reach.contains(&delivery.sender) {
				reach.push(delivery.sender);
			}
		}
		if upstream.is_empty() {
			return receivers.to_vec();
		}
		upstream
	}

	pub(crate) fn receipt(&self, run: RunIdx, slot: SlotIdx) -> Option<(&Delivery, bool, i32)> {
		let step = self.runs[run].steps[*self.runs[run].step_of_slot.get(&slot)?];
		let Event::Recv(d) = step.event else {
			return None;
		};
		let delivery = &self.deliveries[d];
		let &(_, guarded) = delivery.slots.iter().find(|&&(s, _)| s == slot)?;
		Some((delivery, guarded, step.phase))
	}

	pub(crate) fn install_phase(&self, run: RunIdx, slot: SlotIdx) -> Option<i32> {
		let mut at = run;
		let mut seen = vec![run];
		while let Some((delivery, guarded, phase)) = self.receipt(at, slot) {
			if !guarded {
				return Some(phase);
			}
			at = delivery.sender;
			if seen.contains(&at) {
				break;
			}
			seen.push(at);
		}
		None
	}

	pub(crate) fn first_install_phase(&self, slot: SlotIdx) -> Option<i32> {
		self.receivers[slot]
			.iter()
			.filter_map(|&run| self.receipt(run, slot))
			.map(|(_, _, phase)| phase)
			.min()
	}

	pub(crate) fn emits(&self, run: RunIdx, slot: SlotIdx, guarded: Option<bool>) -> bool {
		self.emitted[slot]
			.iter()
			.any(|&(sender, as_guarded)| sender == run && guarded.is_none_or(|g| g == as_guarded))
	}

	pub(crate) fn run_index(&self, id: PrincipalId) -> Option<RunIdx> {
		self.run_of.get(&id).copied()
	}

	pub(crate) fn phase_of(&self, id: PrincipalId, slot: SlotIdx) -> i32 {
		self.run_index(id)
			.and_then(|r| {
				let run = &self.runs[r];
				run.step_of_slot.get(&slot).map(|&i| run.steps[i].phase)
			})
			.unwrap_or(0)
	}
}
