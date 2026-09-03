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
	if sender == ATTACKER_ID {
		return false;
	}
	let (Some(delivered), Some(claimed)) = (ps.values.get(slot), km.slots.get(slot)) else {
		return false;
	};
	let (run, base) = copy_index_of(claimed.constant.id);
	let target = reduce_once(&delivered.value);
	let candidates: Vec<usize> = (0..km.slots.len())
		.filter(|&j| corresponds(km, j, base, sender, ps.id))
		.filter(|&j| !pristine_is(km, j, &target))
		.collect();
	if candidates.is_empty() {
		return false;
	}
	let bound = TermBound::of(km);
	let driving = driving_installs(attacker, &target);
	candidates.into_iter().any(|j| {
		let Some(origin) = origin_of(ctx, km, j) else {
			return false;
		};
		let controllable = Controllable::of(km, origin, attacker);
		if controllable.admits(origin, attacker, j) {
			return false;
		}
		let guards = Emission {
			ctx,
			km,
			origin,
			controllable: &controllable,
			attacker,
			bound: &bound,
			j,
		};
		guards.emits(&target, |at| delivered_to(ps, at))
			|| driving.as_ref().is_some_and(|(read_at, diffs)| {
				*read_at == j
					&& guards.emits(&target, |at| {
						diffs
							.iter()
							.find(|(slot, _)| *slot == at)
							.map(|(_, value)| value.clone())
					})
			}) || (j != slot
			&& guards.emits(&target, |at| run_copy(km, &origin.meta[at].constant, run)))
	})
}

struct Emission<'a> {
	ctx: &'a VerifyContext,
	km: &'a ProtocolTrace,
	origin: &'a PrincipalState,
	controllable: &'a Controllable,
	attacker: &'a AttackerState,
	bound: &'a TermBound,
	j: usize,
}

impl Emission<'_> {
	fn emits(&self, target: &Value, choose: impl Fn(usize) -> Option<Value>) -> bool {
		let origin = self.origin;
		let mut installs: Vec<(SlotIdx, Value)> = Vec::new();
		for at in 0..origin.values.len() {
			if !self.controllable.admits(origin, self.attacker, at)
				|| origin.meta[at].declared_at >= origin.meta[self.j].declared_at
			{
				continue;
			}
			let Some(value) = choose(at) else {
				continue;
			};
			if value.equivalent(&origin.values[at].value, true) {
				continue;
			}
			if !admissible(&value)
				|| !self.bound.admits_at(origin.id, at, &value)
				|| !attacker_can_derive(self.ctx, self.km, at, &value, origin, self.attacker)
			{
				return false;
			}
			installs.push((SlotIdx(at), value));
		}
		if installs.is_empty() {
			return false;
		}
		let governing = governing_attacker(self.ctx, self.km, &installs, self.attacker);
		let Ok(out) = reexecute(
			&origin.clone_for_depth(true),
			&installs,
			&governing,
			self.km,
		) else {
			return false;
		};
		if self.j >= out.values.len() || out.slot_unreached(self.j) {
			return false;
		}
		reduce_once(&out.values[self.j].value).equivalent(target, true)
	}
}

fn driving_installs(
	attacker: &AttackerState,
	target: &Value,
) -> Option<(usize, Vec<(usize, Value)>)> {
	let idx = attacker.knows(target)?;
	let DerivationRecord::Obtained { slot } = attacker.derivation(idx)? else {
		return None;
	};
	let record = attacker.record(idx)?;
	let diffs: Vec<(usize, Value)> = record
		.diffs
		.iter()
		.filter(|diff| diff.tainted)
		.map(|diff| (diff.index.get(), diff.value.clone()))
		.collect();
	(!diffs.is_empty()).then_some((slot.get(), diffs))
}

fn delivered_to(ps: &PrincipalState, at: usize) -> Option<Value> {
	let sv = ps.values.get(at)?;
	let handed = sv.provenance.attacker_tainted
		&& ps
			.meta
			.get(at)
			.is_some_and(|meta| meta.wire.contains(&ps.id));
	handed.then(|| sv.value.clone())
}

fn corresponds(
	km: &ProtocolTrace,
	j: usize,
	base: ValueId,
	sender: PrincipalId,
	recipient: PrincipalId,
) -> bool {
	let Some(slot) = km.slots.get(j) else {
		return false;
	};
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

fn pristine_is(km: &ProtocolTrace, j: usize, target: &Value) -> bool {
	km.slots.get(j).is_some_and(|slot| {
		reduce_once(&resolve_trace_constant(&slot.constant, km)).equivalent(target, true)
	})
}

fn origin_of<'a>(
	ctx: &'a VerifyContext,
	km: &ProtocolTrace,
	j: usize,
) -> Option<&'a PrincipalState> {
	let creator = km.slots.get(j)?.creator;
	let base = ctx
		.principal_states()
		.iter()
		.find(|state| state.id == creator)?;
	(j < base.values.len()).then_some(base)
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
