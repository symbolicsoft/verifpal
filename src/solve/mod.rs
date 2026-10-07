/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub(crate) mod control;
pub(crate) mod deduce;
pub(crate) mod diverge;
mod free;
mod goals;
pub(crate) mod matching;
mod propose;
pub(crate) mod symbolic;
#[cfg(test)]
mod tests;
pub(crate) mod vars;

pub(crate) use free::honest_slot_terms;
pub(crate) use propose::{emissions_under, install_signature, leave_honest_slots, propose};

use std::sync::Arc;

use crate::protocol::ProtocolTrace;
use crate::protocol::SlotIdx;
use crate::syntax::PrincipalId;
use crate::term::{Value, VariableId};
use crate::util::IdSet;
use symbolic::SymbolicState;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pass {
	Targeted,
	Constructed,
}

pub(crate) fn directly_unguarded(
	km: &ProtocolTrace,
	principal: PrincipalId,
	slot: SlotIdx,
) -> bool {
	km.slots.get(slot).is_some_and(|trace_slot| {
		trace_slot
			.sent_by
			.iter()
			.any(|event| event.recipient == principal && !event.guarded)
	})
}

pub(crate) fn split_delivered(km: &ProtocolTrace, principal: PrincipalId, slot: SlotIdx) -> bool {
	km.slots.get(slot).is_some_and(|trace_slot| {
		trace_slot
			.sent_by
			.iter()
			.any(|event| event.recipient != principal && event.sender != principal)
			&& trace_slot.mutatable_to.iter().any(|&who| who != principal)
	})
}

pub(crate) fn slots_blocking_reduction(sym: &SymbolicState) -> Vec<Vec<SlotIdx>> {
	let mut out: Vec<Vec<SlotIdx>> = Vec::new();
	let mut seen = IdSet::default();
	for term in &sym.terms {
		collect_blocking_slots(term, &mut out, &mut seen);
	}
	out.sort();
	out.dedup();
	out
}

fn collect_blocking_slots(v: &Value, out: &mut Vec<Vec<SlotIdx>>, seen: &mut IdSet<usize>) {
	let Value::Primitive(p) = v else {
		return;
	};
	if !seen.insert(Arc::as_ptr(p) as usize) {
		return;
	}
	if let Some(rule) = crate::primitive::rewrite_rule(p.id)
		&& !crate::theory::can_rewrite(p).0
	{
		let mut group = Vec::new();
		let mut direct = Vec::new();
		let positions = std::iter::once(rule.from).chain(rule.matching.iter().map(|(o, _)| *o));
		for position in positions {
			if let Some(argument) = p.arguments.get(position) {
				if let Value::Variable(id @ VariableId::Slot(_)) = argument {
					direct.push(vars::slot_of_var_id(id));
				}
				for term in crate::term::subterms(argument) {
					if let Value::Variable(id @ VariableId::Slot(_)) = term {
						group.push(vars::slot_of_var_id(id));
					}
				}
			}
		}
		for mut candidate in [direct, group] {
			candidate.sort();
			candidate.dedup();
			if !candidate.is_empty() {
				out.push(candidate);
			}
		}
	}
	for a in &p.arguments {
		collect_blocking_slots(a, out, seen);
	}
}

pub(crate) fn debugging() -> bool {
	std::env::var_os("VERIFPAL_SOLVE_DEBUG").is_some()
}
