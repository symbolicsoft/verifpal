/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::exec::{Context, Execution, Held};
use super::program::Event;
use crate::principal::ATTACKER_ID;
use crate::types::*;

fn creator_run(cx: &Context, slot: usize) -> Option<usize> {
	cx.program.run_index(cx.km.slots[slot].creator)
}

fn view_of<'a>(cx: &Context, ex: &'a Execution, r: usize, slot: usize) -> Option<&'a Held> {
	ex.runs[r]
		.held(slot)
		.or_else(|| creator_run(cx, slot).and_then(|c| ex.runs[c].held(slot)))
}

pub(crate) fn executed(cx: &Context, ex: &Execution, r: usize, slot: usize) -> bool {
	creator_run(cx, slot).is_none() || view_of(cx, ex, r, slot).is_some()
}

fn reached_until(cx: &Context, ex: &Execution, r: usize) -> Option<i32> {
	let state = &ex.runs[r];
	if let Some(slot) = state.halted {
		return Some(cx.km.slots[slot].declared_at);
	}
	if !state.frozen {
		return None;
	}
	let Event::Recv(d) = cx.program.runs[r].steps.get(state.pc)?.event else {
		return None;
	};
	let delivery = &cx.program.deliveries[d];
	let (sender, recipient) = (
		cx.program.runs[delivery.sender].id,
		cx.program.runs[delivery.recipient].id,
	);
	delivery.slots.iter().find_map(|&(slot, _)| {
		cx.km.slots[slot]
			.sent_by
			.iter()
			.find(|event| event.sender == sender && event.recipient == recipient)
			.map(|event| event.declared_at - 1)
	})
}

pub(crate) fn project(
	cx: &Context,
	ex: &Execution,
	honest: &Execution,
	pristine: &PrincipalState,
	r: usize,
) -> PrincipalState {
	let km = cx.km;
	let program = cx.program;
	let mut ps = pristine.clone_for_depth(true);
	for slot in 0..ps.values.len().min(km.slots.len()) {
		let honest_held = view_of(cx, honest, r, slot);
		let Some(h) = view_of(cx, ex, r, slot).or(honest_held) else {
			continue;
		};
		let original = if h.authored {
			honest_held
				.map(|o| o.value.clone())
				.unwrap_or_else(|| h.value.clone())
		} else {
			h.value.clone()
		};
		let tainted = h.authored;
		let sv = &mut ps.values[slot];
		sv.value = h.value.clone();
		sv.pre_rewrite = h.pre.clone();
		sv.original = original;
		if h.authored {
			sv.provenance.creator = ATTACKER_ID;
			sv.provenance.sender = ATTACKER_ID;
		} else if let Some(sender) = h.sender
			&& ex.runs[r].held(slot).is_some()
		{
			sv.provenance.sender = program.runs[sender].id;
		}
		sv.provenance.attacker_tainted = tainted;
	}
	let mut foreign = Vec::new();
	for (q, run) in program.runs.iter().enumerate() {
		if q == r {
			continue;
		}
		let Some(reached) = reached_until(cx, ex, q) else {
			continue;
		};
		let state = &ex.runs[q];
		let first_missing = km.slots.iter().enumerate().position(|(slot, s)| {
			s.creator == run.id
				&& matches!(
					s.constant.declaration,
					Some(Declaration::Assignment | Declaration::Generates | Declaration::Knows)
				) && (state.held(slot).is_none() || state.halted == Some(slot))
		});
		foreign.push((run.id, first_missing, reached));
	}
	ps.foreign_halts = foreign;
	ps.halted_at = reached_until(cx, ex, r);
	let state = &ex.runs[r];
	let mut starved = Vec::new();
	for (i, step) in program.runs[r].steps.iter().enumerate() {
		if let Event::Recv(d) = step.event
			&& !state.reached(i)
		{
			for &(slot, _) in &program.deliveries[d].slots {
				starved.push(slot);
			}
		}
	}
	starved.sort_unstable();
	starved.dedup();
	ps.starved = starved;
	if let Some(slot) = state.halted {
		let at = slot + 1;
		Arc::make_mut(&mut ps.meta).truncate(at);
		ps.values.truncate(at);
	}
	ps
}
