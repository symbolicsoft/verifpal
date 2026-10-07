/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::protocol::trace::{resolve_trace_constant, resolve_trace_term};
use crate::protocol::{ProtocolTrace, SlotIdx, TraceSlot};
use crate::syntax::PrincipalId;
use crate::term::{Value, ValueId, VariableId};
use crate::theory::{AttackerState, reduce_once};
use crate::util::IdMap;
use crate::util::generation::{AnalysisKey, AnalysisLocal};
use crate::util::index::IndexVec;

thread_local! {
	static HONEST_REDUCTS: AnalysisLocal<IdMap<SlotIdx, Value>> = AnalysisLocal::default();
}

pub(crate) struct Controllable {
	principal: PrincipalId,
	phase: i32,
	slots: IndexVec<SlotIdx, bool>,
}

impl Controllable {
	pub(crate) fn of(
		km: &ProtocolTrace,
		principal: PrincipalId,
		attacker: &AttackerState,
	) -> Controllable {
		Controllable {
			principal,
			phase: attacker.current_phase,
			slots: km
				.slots
				.iter()
				.map(|slot| attacker_controllable(slot, km, principal, attacker))
				.collect(),
		}
	}

	pub(crate) fn admits(
		&self,
		principal: PrincipalId,
		attacker: &AttackerState,
		slot: SlotIdx,
	) -> bool {
		self.principal == principal
			&& self.phase == attacker.current_phase
			&& self.slots.get(slot).copied().unwrap_or(false)
	}
}

pub(crate) struct TermBound {
	max_depth: usize,
	deep: Deep,
}

struct Deep {
	protocol: crate::term::hashing::TermSet,
	ids: IndexVec<SlotIdx, ValueId>,
	creators: IndexVec<SlotIdx, PrincipalId>,
	consumes: IndexVec<SlotIdx, Option<ValueId>>,
	peel: std::sync::RwLock<IdMap<(PrincipalId, SlotIdx), usize>>,
}

impl TermBound {
	pub(crate) fn of(km: &ProtocolTrace) -> TermBound {
		let max_depth = km
			.slots
			.iter()
			.map(|slot| term_depth(&resolve_trace_constant(&slot.constant, km)))
			.max()
			.unwrap_or(0);
		let mut protocol = crate::term::hashing::TermSet::default();
		for slot in &km.slots {
			let term = resolve_trace_constant(&slot.constant, km);
			protocol.extend(crate::term::subterms(&term).cloned());
			protocol.extend(crate::term::subterms(&reduce_once(&term)).cloned());
		}
		TermBound {
			max_depth,
			deep: Deep {
				protocol,
				ids: km.slots.iter().map(|slot| slot.constant.id).collect(),
				creators: km.slots.iter().map(|slot| slot.creator).collect(),
				consumes: km
					.slots
					.iter()
					.map(|slot| unwrapped_by(&slot.initial_value))
					.collect(),
				peel: std::sync::RwLock::new(IdMap::default()),
			},
		}
	}

	pub(crate) fn admits_at(&self, principal: PrincipalId, slot: SlotIdx, v: &Value) -> bool {
		let depth = term_depth(v);
		if depth <= self.max_depth {
			return true;
		}
		let deep = &self.deep;
		depth <= self.max_depth + deep.peel_depth(principal, slot)
			&& deep.depth_over_protocol(v) <= self.max_depth
	}

	pub(crate) fn protocol(&self) -> &crate::term::hashing::TermSet {
		&self.deep.protocol
	}

	pub(crate) fn depth(&self) -> usize {
		self.max_depth
	}

	pub(crate) fn maximum_depth(&self, km: &ProtocolTrace, slot: SlotIdx) -> usize {
		self.max_depth
			+ km.principal_ids
				.iter()
				.map(|&principal| self.deep.peel_depth(principal, slot))
				.max()
				.unwrap_or(0)
	}
}

pub(crate) fn minimum_term_depth(v: &Value, s: &super::vars::Substitution) -> usize {
	fn depth(
		v: &Value,
		s: &super::vars::Substitution,
		memo: &mut super::vars::PointerMemo<usize>,
		variables: &mut Vec<VariableId>,
	) -> usize {
		match v {
			Value::Constant(_) => 0,
			Value::Variable(id) => match s.get(id) {
				Some(value) if !variables.contains(id) => {
					variables.push(id.clone());
					let out = depth(value, s, memo, variables);
					variables.pop();
					out
				}
				_ => 0,
			},
			Value::Primitive(p) => {
				let key = Arc::as_ptr(p) as usize;
				if let Some(out) = memo.get(key) {
					return out;
				}
				let rewrites = if crate::primitive::is_core(p.id) {
					crate::primitive::core_spec(p.id).is_ok_and(|spec| spec.core_rule.is_some())
				} else {
					crate::primitive::spec(p.id).is_ok_and(|spec| {
						spec.rewrite.is_some() || spec.rebuild.is_some() || !spec.combine.is_empty()
					})
				};
				let out = if rewrites {
					0
				} else {
					1 + p
						.arguments
						.iter()
						.map(|a| depth(a, s, memo, variables))
						.max()
						.unwrap_or(0)
				};
				memo.insert(key, out);
				out
			}
		}
	}
	depth(v, s, &mut super::vars::PointerMemo::new(), &mut Vec::new())
}

impl Deep {
	fn depth_over_protocol(&self, v: &Value) -> usize {
		term_depth_outside(v, &self.protocol, &mut IdMap::default())
	}

	fn peel_depth(&self, principal: PrincipalId, slot: SlotIdx) -> usize {
		if let Some(&hit) = self
			.peel
			.read()
			.unwrap_or_else(|e| e.into_inner())
			.get(&(principal, slot))
		{
			return hit;
		}
		let mut visiting: Vec<SlotIdx> = Vec::new();
		let depth = self.peel_from(principal, slot, &mut visiting);
		self.peel
			.write()
			.unwrap_or_else(|e| e.into_inner())
			.insert((principal, slot), depth);
		depth
	}

	fn peel_from(
		&self,
		principal: PrincipalId,
		slot: SlotIdx,
		visiting: &mut Vec<SlotIdx>,
	) -> usize {
		let Some(&id) = self.ids.get(slot) else {
			return 0;
		};
		if visiting.contains(&slot) {
			return 0;
		}
		visiting.push(slot);
		let deepest = self
			.ids
			.indices()
			.filter(|&t| self.creators[t] == principal && self.consumes[t] == Some(id))
			.map(|t| 1 + self.peel_from(principal, t, visiting))
			.max()
			.unwrap_or(0);
		visiting.pop();
		deepest
	}
}

fn unwrapped_by(v: &Value) -> Option<ValueId> {
	let Value::Primitive(p) = v else {
		return None;
	};
	let at = crate::primitive::unwraps(p.id)?;
	match p.arguments.get(at) {
		Some(Value::Constant(c)) => Some(c.id),
		_ => None,
	}
}

pub(crate) fn term_depth(v: &Value) -> usize {
	term_depth_outside(
		v,
		&crate::term::hashing::TermSet::default(),
		&mut IdMap::default(),
	)
}

fn term_depth_outside(
	v: &Value,
	basis: &crate::term::hashing::TermSet,
	memo: &mut IdMap<usize, usize>,
) -> usize {
	match v {
		Value::Constant(_) | Value::Variable(_) => 0,
		Value::Primitive(p) => {
			if !basis.is_empty() && basis.contains(v) {
				return 0;
			}
			let key = Arc::as_ptr(p) as usize;
			if let Some(&depth) = memo.get(&key) {
				return depth;
			}
			let depth = 1 + p
				.arguments
				.iter()
				.map(|a| term_depth_outside(a, basis, memo))
				.max()
				.unwrap_or(0);
			memo.insert(key, depth);
			depth
		}
	}
}

fn attacker_controllable(
	slot: &TraceSlot,
	km: &ProtocolTrace,
	principal: PrincipalId,
	attacker: &AttackerState,
) -> bool {
	if slot.constant.is_nil() {
		return false;
	}
	if slot.guarded_for(principal) {
		if !slot.mutation_reaches(slot.sender_to(principal)) {
			return false;
		}
	} else if slot.creator == principal || slot.sent_by.is_empty() {
		return false;
	}
	if !slot
		.delivery_phase
		.is_some_and(|phase| phase <= attacker.current_phase)
	{
		return false;
	}
	if !km.constant_used_by(principal, &slot.constant)
		&& !slot.sent_from(principal)
		&& !km.equivalence_queried.contains(&slot.constant.id)
	{
		return false;
	}
	true
}

pub(crate) fn attacker_authored(ground: &Value, slot: SlotIdx, km: &ProtocolTrace) -> bool {
	let trace_reduct = HONEST_REDUCTS.with_current(|reducts| {
		reducts
			.entry(slot)
			.or_insert_with(|| reduce_once(&resolve_trace_term(&km.slots[slot].initial_value, km)))
			.clone()
	});
	!reduce_once(ground).equivalent(&trace_reduct, true)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::{PRIM_CONCAT, PRIM_DEC, PRIM_ENC, PRIM_HASH, PRIM_SPLIT};
	use crate::solve::vars::{Substitution, apply, attacker_var, attacker_var_id};
	use crate::testing::*;
	use crate::util::index::Idx;

	#[test]
	fn a_partial_depth_bound_preserves_later_reductions() {
		let x = attacker_var(SlotIdx::new(0));
		let y = attacker_var(SlotIdx::new(1));
		let nil = crate::term::value_nil();
		let hash = |v: Value| Value::primitive(PRIM_HASH, vec![v], 0);
		let cipher = Value::primitive(PRIM_ENC, vec![x.clone(), y.clone()], 0);
		let opened = Value::primitive(PRIM_DEC, vec![x.clone(), cipher], 0);
		let tuple = Value::primitive(PRIM_CONCAT, vec![opened.clone(), x.clone()], 0);
		let projected = Value::primitive(PRIM_SPLIT, vec![tuple.clone()], 0);
		let terms = [
			x,
			y,
			opened,
			tuple,
			projected,
			hash(hash(attacker_var(SlotIdx::new(0)))),
		];
		let choices = [nil.clone(), hash(nil.clone()), hash(hash(nil))];
		for a in &choices {
			let partial: Substitution = [(attacker_var_id(SlotIdx::new(0)), a.clone())]
				.into_iter()
				.collect();
			for b in &choices {
				let mut ground = partial.clone();
				ground.insert(attacker_var_id(SlotIdx::new(1)), b.clone());
				for term in &terms {
					let lower = minimum_term_depth(term, &partial);
					let actual = term_depth(&reduce_once(&apply(term, &ground)));
					assert!(lower <= actual, "{term}: {lower} > {actual}");
				}
			}
		}
		assert_eq!(minimum_term_depth(&terms[5], &Substitution::default()), 2);
		assert_eq!(minimum_term_depth(&terms[2], &Substitution::default()), 0);
	}

	#[test]
	fn term_depth_visits_each_shared_node_once() {
		let mut term = make_constant("control_term_depth_seed");
		for _ in 0..256 {
			term = Value::primitive(crate::primitive::PRIM_HASH, vec![term.clone(), term], 0);
		}
		assert_eq!(term_depth(&term), 256);
	}
}
