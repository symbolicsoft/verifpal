/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::primitive::admissible;
use crate::principal::ATTACKER_ID;
use crate::reexec::{Controllable, TermBound, governing_attacker, reexecute};
use crate::solve::validate::attacker_can_derive;
use crate::theory::reduce_once;
use crate::types::*;
use crate::value::{copy_index_of, copy_value_id, resolve_trace_constant};

pub(crate) fn emitted_by_matching_run(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	slot: usize,
	sender: PrincipalId,
	attacker: &AttackerState,
) -> bool {
	if km.interchangeable.is_empty() || sender == ATTACKER_ID {
		return false;
	}
	let (Some(delivered), Some(claimed)) = (ps.values.get(slot), km.slots.get(slot)) else {
		return false;
	};
	let (run, base) = copy_index_of(claimed.constant.id);
	let target = reduce_once(&delivered.value);
	let bound = TermBound::of(km);
	(0..km.slots.len())
		.filter(|&j| j != slot && corresponds(km, j, base, sender, ps.id))
		.filter(|&j| {
			!reduce_once(&resolve_trace_constant(&km.slots[j].constant, km))
				.equivalent(&target, true)
		})
		.any(|j| run_emits(ctx, km, j, run, &target, attacker, &bound))
}

fn corresponds(
	km: &ProtocolTrace,
	j: usize,
	base: ValueId,
	sender: PrincipalId,
	recipient: PrincipalId,
) -> bool {
	let slot = &km.slots[j];
	if copy_index_of(slot.constant.id).1 != base {
		return false;
	}
	if slot.creator == ATTACKER_ID || !km.interchangeable_with(slot.creator, sender) {
		return false;
	}
	slot.sent_by.iter().any(|event| {
		km.interchangeable_with(event.sender, sender) && km.same_actor(event.recipient, recipient)
	})
}

fn run_emits(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	j: usize,
	run: u32,
	target: &Value,
	attacker: &AttackerState,
	bound: &TermBound,
) -> bool {
	let Some(base) = ctx
		.principal_states()
		.iter()
		.find(|state| state.id == km.slots[j].creator)
	else {
		return false;
	};
	if j >= base.values.len() {
		return false;
	}
	let controllable = Controllable::of(km, base, attacker);
	if controllable.admits(base, attacker, j) {
		return false;
	}
	let mut installs: Vec<(SlotIdx, Value)> = Vec::new();
	for slot in 0..base.values.len() {
		if !controllable.admits(base, attacker, slot)
			|| base.meta[slot].declared_at >= base.meta[j].declared_at
		{
			continue;
		}
		let Some(routed) = run_copy(km, &base.meta[slot].constant, run) else {
			continue;
		};
		if routed.equivalent(&base.values[slot].value, true) {
			continue;
		}
		if !admissible(&routed)
			|| !bound.admits(&routed)
			|| !attacker_can_derive(ctx, km, slot, &routed, base, attacker)
		{
			return false;
		}
		installs.push((SlotIdx(slot), routed));
	}
	if installs.is_empty() {
		return false;
	}
	let governing = governing_attacker(ctx, km, &installs, attacker);
	let Ok(out) = reexecute(&base.clone_for_depth(true), &installs, &governing, km) else {
		return false;
	};
	if j >= out.values.len() || out.slot_unreached(j) {
		return false;
	}
	reduce_once(&out.values[j].value).equivalent(target, true)
}

fn run_copy(km: &ProtocolTrace, constant: &Constant, run: u32) -> Option<Value> {
	let (own, base) = copy_index_of(constant.id);
	if own == run {
		return Some(resolve_trace_constant(constant, km));
	}
	let id = if run == 0 {
		base
	} else {
		copy_value_id(base, run)
	};
	let &slot = km.index.get(&id)?;
	Some(resolve_trace_constant(&km.slots[slot].constant, km))
}
