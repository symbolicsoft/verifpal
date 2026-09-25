/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Event {
	Hold(usize),
	Assign(usize),
	Leak(usize),
	Send(usize),
	Recv(usize),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Step {
	pub(crate) event: Event,
	pub(crate) phase: i32,
}

#[derive(Clone, Debug)]
pub(crate) struct Delivery {
	pub(crate) sender: usize,
	pub(crate) recipient: usize,
	pub(crate) slots: Vec<(usize, bool)>,
}

#[derive(Clone, Debug)]
pub(crate) struct Run {
	pub(crate) id: PrincipalId,
	pub(crate) name: String,
	pub(crate) steps: Vec<Step>,
	pub(crate) step_of_slot: IdMap<usize, usize>,
}

impl Run {
	fn push(&mut self, event: Event, phase: i32, gives: impl IntoIterator<Item = usize>) {
		for slot in gives {
			self.step_of_slot.entry(slot).or_insert(self.steps.len());
		}
		self.steps.push(Step { event, phase });
	}
}

#[derive(Clone, Debug)]
pub(crate) struct Program {
	pub(crate) runs: Vec<Run>,
	run_of: IdMap<PrincipalId, usize>,
	pub(crate) deliveries: Vec<Delivery>,
}

impl Program {
	pub(crate) fn of(m: &Model, km: &ProtocolTrace) -> Program {
		let mut runs: Vec<Run> = km
			.principal_ids
			.iter()
			.zip(km.principals.iter())
			.map(|(&id, name)| Run {
				id,
				name: name.clone(),
				steps: Vec::new(),
				step_of_slot: IdMap::default(),
			})
			.collect();
		let run_of: IdMap<PrincipalId, usize> =
			runs.iter().enumerate().map(|(i, r)| (r.id, i)).collect();
		let mut deliveries = Vec::new();
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
					let slots: Vec<(usize, bool)> = msg
						.constants
						.iter()
						.filter_map(|c| km.index_of(c).map(|slot| (slot, c.guard)))
						.collect();
					let d = deliveries.len();
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

	pub(crate) fn run_index(&self, id: PrincipalId) -> Option<usize> {
		self.run_of.get(&id).copied()
	}

	pub(crate) fn phase_of(&self, id: PrincipalId, slot: usize) -> i32 {
		self.run_index(id)
			.and_then(|r| {
				let run = &self.runs[r];
				run.step_of_slot.get(&slot).map(|&i| run.steps[i].phase)
			})
			.unwrap_or(0)
	}
}
