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
	fn push(&mut self, event: Event, phase: i32, gives: impl IntoIterator<Item = SlotIdx>) {
		for slot in gives {
			self.step_of_slot
				.entry(slot)
				.or_insert(self.steps.next_index());
		}
		self.steps.push(Step { event, phase });
	}
}

#[derive(Clone, Debug)]
pub(crate) struct Program {
	pub(crate) runs: IndexVec<RunIdx, Run>,
	run_of: IdMap<PrincipalId, RunIdx>,
	pub(crate) deliveries: IndexVec<DeliveryIdx, Delivery>,
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
							runs[run].push(event, phase, gives);
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
					runs[sender].push(Event::Send(d), phase, None);
					runs[recipient].push(
						Event::Recv(d),
						phase,
						slots.iter().map(|&(slot, _)| slot),
					);
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
		Program {
			runs,
			run_of,
			deliveries,
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
