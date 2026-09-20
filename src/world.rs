/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::*;
use std::cell::RefCell;
use std::sync::Arc;

const MERGE_BUDGET: usize = 4096;
const MAX_WORLDS: usize = 16;

fn key(need: &Need) -> (PrincipalId, usize) {
	(need.0, need.1.get())
}

fn normalise(mut constraint: Constraint) -> Constraint {
	constraint.sort_by_key(key);
	constraint.dedup_by(|a, b| key(a) == key(b) && a.2.equivalent(&b.2, true));
	constraint
}

fn merge_into(needs: &[Need], union: &mut Constraint) -> bool {
	for need in needs {
		match union.iter().find(|held| key(held) == key(need)) {
			Some(held) => {
				if !held.2.equivalent(&need.2, true) {
					return false;
				}
			}
			None => union.push(need.clone()),
		}
	}
	true
}

fn covers(narrow: &Constraint, wide: &Constraint) -> bool {
	narrow.iter().all(|need| {
		wide.iter()
			.any(|held| key(held) == key(need) && held.2.equivalent(&need.2, true))
	})
}

pub(crate) fn add(set: &mut Vec<Constraint>, new: Constraint) -> bool {
	if set.len() == 1 && set[0].is_empty() {
		return false;
	}
	let new = normalise(new);
	if new.is_empty() {
		set.clear();
		set.push(new);
		return true;
	}
	if set.iter().any(|existing| covers(existing, &new)) {
		return false;
	}
	set.retain(|existing| !covers(&new, existing));
	set.push(new);
	if set.len() > MAX_WORLDS {
		set.clear();
		set.push(Vec::new());
	}
	true
}

pub(crate) fn merge_all(sets: &[Vec<Constraint>]) -> Vec<Constraint> {
	if sets.iter().any(|choices| choices.is_empty()) {
		return Vec::new();
	}
	let mut out: Vec<Constraint> = Vec::new();
	let mut budget = MERGE_BUDGET;
	let mut acc: Constraint = Vec::new();
	descend(sets, 0, &mut acc, &mut out, &mut budget);
	if budget == 0 {
		return vec![Vec::new()];
	}
	out
}

fn descend(
	sets: &[Vec<Constraint>],
	depth: usize,
	acc: &mut Constraint,
	out: &mut Vec<Constraint>,
	budget: &mut usize,
) {
	if *budget == 0 {
		return;
	}
	*budget -= 1;
	let Some(choices) = sets.get(depth) else {
		add(out, acc.clone());
		return;
	};
	if choices.is_empty() {
		descend(sets, depth + 1, acc, out, budget);
		return;
	}
	if out.len() == 1 && out[0].is_empty() {
		return;
	}
	for choice in choices {
		let mark = acc.len();
		if merge_into(choice, acc) {
			descend(sets, depth + 1, acc, out, budget);
		}
		acc.truncate(mark);
	}
}

pub(crate) fn state_world(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	slot: usize,
) -> Vec<Constraint> {
	let key = (
		ps as *const PrincipalState as usize,
		attacker.chain,
		attacker.known.len(),
		attacker.worlds_epoch,
	);
	if let Some(hit) = WORLDS.with(|cell| {
		let cache = cell.borrow();
		cache
			.as_ref()
			.filter(|(seen, _)| *seen == key)
			.and_then(|(_, slots)| slots.get(&slot).cloned())
	}) {
		return hit;
	}
	let owner = match (ps.values.get(slot), km.slots.get(slot)) {
		(Some(sv), _) if sv.provenance.attacker_tainted => ps.id,
		(_, Some(trace_slot)) => trace_slot.creator,
		_ => return vec![Vec::new()],
	};
	let mut memo: IdMap<(PrincipalId, usize), Vec<Constraint>> = IdMap::default();
	let mut active: Vec<(PrincipalId, usize)> = Vec::new();
	let out = walk(km, ps, attacker, slot, owner, &mut memo, &mut active);
	WORLDS.with(|cell| {
		let mut cache = cell.borrow_mut();
		match cache.as_mut() {
			Some((seen, slots)) if *seen == key => {
				slots.insert(slot, out.clone());
			}
			_ => {
				let mut slots: IdMap<usize, Vec<Constraint>> = IdMap::default();
				slots.insert(slot, out.clone());
				*cache = Some((key, slots));
			}
		}
	});
	out
}

fn walk(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	slot: usize,
	owner: PrincipalId,
	memo: &mut IdMap<(PrincipalId, usize), Vec<Constraint>>,
	active: &mut Vec<(PrincipalId, usize)>,
) -> Vec<Constraint> {
	if let Some(hit) = memo.get(&(owner, slot)) {
		return hit.clone();
	}
	if active.contains(&(owner, slot)) {
		return vec![Vec::new()];
	}
	let (Some(sv), Some(trace_slot)) = (ps.values.get(slot), km.slots.get(slot)) else {
		return vec![Vec::new()];
	};
	if pinless(trace_slot, owner) {
		return vec![Vec::new()];
	}
	active.push((owner, slot));
	let out = if owner == ps.id && sv.provenance.attacker_tainted {
		installed(ps, slot, &sv.value, attacker)
	} else if owner == trace_slot.creator {
		let mut sets: Vec<Vec<Constraint>> = Vec::new();
		for &at in crate::deduction::reach_cone(km, owner, slot).iter() {
			let Some(leaf) = km.slots.get(at) else {
				continue;
			};
			if at == slot || leaf.creator == owner || pinless(leaf, owner) {
				continue;
			}
			sets.push(walk(km, ps, attacker, at, owner, memo, active));
		}
		merge_all(&sets)
	} else {
		let pin: Constraint = vec![(owner, SlotIdx(slot), sv.value.clone())];
		let creator = trace_slot.creator;
		merge_all(&[
			vec![pin],
			walk(km, ps, attacker, slot, creator, memo, active),
		])
	};
	active.pop();
	memo.insert((owner, slot), out.clone());
	out
}

fn pinless(trace_slot: &TraceSlot, owner: PrincipalId) -> bool {
	trace_slot.constant.is_nil()
		|| trace_slot.constant.qualifier == Some(Qualifier::Public)
		|| trace_slot
			.known_by
			.iter()
			.any(|&(holder, sender)| holder == owner && sender == owner)
}

pub(crate) fn observable(trace_slot: &TraceSlot) -> bool {
	!trace_slot.sent_by.is_empty() || trace_slot.constant.leaked
}

fn installed(
	ps: &PrincipalState,
	slot: usize,
	value: &Value,
	attacker: &AttackerState,
) -> Vec<Constraint> {
	let pin: Constraint = vec![(ps.id, SlotIdx(slot), value.clone())];
	let mut sets: Vec<Vec<Constraint>> = vec![vec![pin]];
	if let Some(idx) = attacker.knows(value)
		&& let Some(worlds) = attacker.worlds.get(idx.get())
		&& !worlds.is_empty()
	{
		sets.push(worlds.clone());
	}
	merge_all(&sets)
}

pub(crate) fn derived_worlds(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	target: &Value,
	derivation: &DerivationRecord,
) -> Vec<Constraint> {
	let mut out = recorded_worlds(km, ps, attacker, derivation);
	if !out.iter().any(|world| world.is_empty()) && unconditional(ps, attacker, target) {
		add(&mut out, Vec::new());
	}
	out
}

type Everywhere = ((u64, usize, u64), Option<Arc<AttackerState>>);

type WorldCache = ((usize, u64, usize, u64), IdMap<usize, Vec<Constraint>>);

thread_local! {
	static EVERYWHERE: RefCell<Option<Everywhere>> = const { RefCell::new(None) };
	static WORLDS: RefCell<Option<WorldCache>> = const { RefCell::new(None) };
}

fn everywhere_state(attacker: &AttackerState) -> Option<Arc<AttackerState>> {
	let key = (attacker.chain, attacker.known.len(), attacker.worlds_epoch);
	if let Some(hit) = EVERYWHERE.with(|cell| {
		cell.borrow()
			.as_ref()
			.filter(|(seen, _)| *seen == key)
			.map(|(_, state)| state.clone())
	}) {
		return hit;
	}
	let keep: Vec<bool> = (0..attacker.known.len())
		.map(|i| {
			attacker
				.worlds
				.get(i)
				.is_some_and(|worlds| worlds.iter().any(|world| world.is_empty()))
		})
		.collect();
	let built = if keep.iter().any(|&kept| kept) {
		Some(
			attacker
				.retaining(&keep)
				.unwrap_or_else(|| Arc::new(attacker.clone())),
		)
	} else {
		None
	};
	EVERYWHERE.with(|cell| *cell.borrow_mut() = Some((key, built.clone())));
	built
}

fn unconditional(ps: &PrincipalState, attacker: &AttackerState, target: &Value) -> bool {
	let Some(everywhere) = everywhere_state(attacker) else {
		return false;
	};
	crate::theory::obtainable(target, ps, &everywhere)
}

fn recorded_worlds(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	derivation: &DerivationRecord,
) -> Vec<Constraint> {
	match derivation {
		DerivationRecord::Initial => vec![Vec::new()],
		DerivationRecord::Obtained { slot } | DerivationRecord::Leaked { slot } => {
			state_world(km, ps, attacker, slot.get())
		}
		_ => {
			let mut inputs = crate::theory::KnowledgeInputs::new(ps, attacker);
			let mut sets: Vec<Vec<Constraint>> = Vec::new();
			for ingredient in derivation.ingredients() {
				let Some(found) = inputs.of_value(ingredient) else {
					continue;
				};
				for idx in found {
					if let Some(worlds) = attacker.worlds.get(idx.get())
						&& !worlds.is_empty()
					{
						sets.push(worlds.clone());
					}
				}
			}
			merge_all(&sets)
		}
	}
}
