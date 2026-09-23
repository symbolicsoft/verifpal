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

#[derive(Clone, Debug)]
pub(crate) struct Program {
	pub(crate) runs: Vec<Run>,
	pub(crate) run_of: IdMap<PrincipalId, usize>,
	pub(crate) deliveries: Vec<Delivery>,
	pub(crate) max_phase: i32,
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
						let event = match expr.kind {
							Declaration::Knows | Declaration::Generates => Event::Hold,
							Declaration::Assignment => Event::Assign,
							Declaration::Leaks => Event::Leak,
						};
						for c in &expr.constants {
							if let Some(slot) = km.index_of(c) {
								runs[run].steps.push(Step {
									event: event(slot),
									phase,
								});
							}
						}
					}
				}
				Block::Message(msg) => {
					let (Some(&sender), Some(&recipient)) =
						(run_of.get(&msg.sender), run_of.get(&msg.recipient))
					else {
						continue;
					};
					let slots = msg
						.constants
						.iter()
						.filter_map(|c| km.index_of(c).map(|slot| (slot, c.guard)))
						.collect();
					let d = deliveries.len();
					deliveries.push(Delivery {
						sender,
						recipient,
						slots,
					});
					runs[sender].steps.push(Step {
						event: Event::Send(d),
						phase,
					});
					runs[recipient].steps.push(Step {
						event: Event::Recv(d),
						phase,
					});
				}
				Block::Phase(ph) => {
					phase = ph.number;
				}
			}
		}
		for run in &mut runs {
			for (i, step) in run.steps.iter().enumerate() {
				match step.event {
					Event::Hold(slot) | Event::Assign(slot) => {
						run.step_of_slot.entry(slot).or_insert(i);
					}
					Event::Recv(d) => {
						for &(slot, _) in &deliveries[d].slots {
							run.step_of_slot.entry(slot).or_insert(i);
						}
					}
					_ => {}
				}
			}
		}
		Program {
			runs,
			run_of,
			deliveries,
			max_phase: km.max_phase,
		}
	}

	pub(crate) fn run_index(&self, id: PrincipalId) -> Option<usize> {
		self.run_of.get(&id).copied()
	}
}
