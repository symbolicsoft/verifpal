/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::theory::reduce_once;
use crate::types::*;
use crate::value::{resolve_trace_constant, resolve_trace_term};

thread_local! {
	static HONEST_REDUCTS: std::cell::RefCell<crate::context::Generational<IdMap<(usize, ValueId), Value>>> =
		std::cell::RefCell::new(crate::context::Generational::default());
}

pub(crate) struct Controllable {
	principal: PrincipalId,
	phase: i32,
	slots: Vec<bool>,
}

impl Controllable {
	pub(crate) fn of(
		km: &ProtocolTrace,
		ps: &PrincipalState,
		attacker: &AttackerState,
	) -> Controllable {
		Controllable {
			principal: ps.id,
			phase: attacker.current_phase,
			slots: (0..ps.values.len())
				.map(|i| attacker_controllable(i, km, ps, attacker))
				.collect(),
		}
	}

	pub(crate) fn admits(
		&self,
		ps: &PrincipalState,
		attacker: &AttackerState,
		slot: usize,
	) -> bool {
		self.principal == ps.id
			&& self.phase == attacker.current_phase
			&& self.slots.get(slot).copied().unwrap_or(false)
	}
}

pub(crate) struct TermBound {
	max_depth: usize,
	deep: std::sync::OnceLock<Deep>,
}

struct Deep {
	protocol: crate::hashing::TermSet,
	ids: Vec<ValueId>,
	creators: Vec<PrincipalId>,
	consumes: Vec<Option<ValueId>>,
	peel: std::sync::RwLock<IdMap<(PrincipalId, usize), usize>>,
}

impl TermBound {
	pub(crate) fn of(km: &ProtocolTrace) -> TermBound {
		let max_depth = km
			.slots
			.iter()
			.map(|slot| term_depth(&resolve_trace_constant(&slot.constant, km)))
			.max()
			.unwrap_or(0);
		TermBound {
			max_depth,
			deep: std::sync::OnceLock::new(),
		}
	}

	fn deep(&self, km: &ProtocolTrace) -> &Deep {
		self.deep.get_or_init(|| {
			let mut protocol = crate::hashing::TermSet::default();
			for slot in &km.slots {
				let term = resolve_trace_constant(&slot.constant, km);
				crate::hashing::collect_subterms(&term, &mut protocol);
				crate::hashing::collect_subterms(&reduce_once(&term), &mut protocol);
			}
			Deep {
				protocol,
				ids: km.slots.iter().map(|slot| slot.constant.id).collect(),
				creators: km.slots.iter().map(|slot| slot.creator).collect(),
				consumes: km
					.slots
					.iter()
					.map(|slot| unwrapped_by(&slot.initial_value))
					.collect(),
				peel: std::sync::RwLock::new(IdMap::default()),
			}
		})
	}

	pub(crate) fn admits_at(
		&self,
		km: &ProtocolTrace,
		principal: PrincipalId,
		slot: usize,
		v: &Value,
	) -> bool {
		let depth = term_depth(v);
		if depth <= self.max_depth {
			return true;
		}
		let deep = self.deep(km);
		depth <= self.max_depth + deep.peel_depth(principal, slot)
			&& deep.depth_over_protocol(v) <= self.max_depth
	}

	pub(crate) fn protocol(&self, km: &ProtocolTrace) -> &crate::hashing::TermSet {
		&self.deep(km).protocol
	}

	pub(crate) fn depth(&self) -> usize {
		self.max_depth
	}
}

impl Deep {
	fn depth_over_protocol(&self, v: &Value) -> usize {
		term_depth_outside(v, &self.protocol, &mut IdMap::default())
	}

	fn peel_depth(&self, principal: PrincipalId, slot: usize) -> usize {
		if let Some(&hit) = self
			.peel
			.read()
			.unwrap_or_else(|e| e.into_inner())
			.get(&(principal, slot))
		{
			return hit;
		}
		let mut visiting: Vec<usize> = Vec::new();
		let depth = self.peel_from(principal, slot, &mut visiting);
		self.peel
			.write()
			.unwrap_or_else(|e| e.into_inner())
			.insert((principal, slot), depth);
		depth
	}

	fn peel_from(&self, principal: PrincipalId, slot: usize, visiting: &mut Vec<usize>) -> usize {
		let Some(&id) = self.ids.get(slot) else {
			return 0;
		};
		if visiting.contains(&slot) {
			return 0;
		}
		visiting.push(slot);
		let deepest = (0..self.ids.len())
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
	let at = crate::primitive::primitive_unwraps(p.id)?;
	match p.arguments.get(at) {
		Some(Value::Constant(c)) => Some(c.id),
		_ => None,
	}
}

fn term_depth(v: &Value) -> usize {
	term_depth_outside(
		v,
		&crate::hashing::TermSet::default(),
		&mut IdMap::default(),
	)
}

fn term_depth_outside(
	v: &Value,
	basis: &crate::hashing::TermSet,
	memo: &mut IdMap<usize, usize>,
) -> usize {
	match v {
		Value::Constant(_) => 0,
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

pub(crate) fn attacker_controllable(
	idx: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> bool {
	let Some(meta) = ps.meta.get(idx) else {
		return false;
	};
	if idx >= ps.values.len() {
		return false;
	}
	if meta.constant.is_nil() {
		return false;
	}
	if meta.guard {
		if !meta
			.mutatable_to
			.contains(&ps.values[idx].provenance.sender)
		{
			return false;
		}
	} else if ps.values[idx].provenance.creator == ps.id || meta.wire.is_empty() {
		return false;
	}
	if !meta
		.delivery_phases
		.iter()
		.map(|&(_, phase)| phase)
		.min()
		.is_some_and(|phase| phase <= attacker.current_phase)
	{
		return false;
	}
	if !km.constant_used_by(ps.id, &meta.constant)
		&& meta.sent_at.is_none()
		&& !km.equivalence_queried.contains(&meta.constant.id)
	{
		return false;
	}
	true
}

pub(crate) fn attacker_authored(
	ground: &Value,
	slot: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> bool {
	let honest = &ps.values[slot].value;
	let trace_reduct = match honest {
		Value::Constant(c) => HONEST_REDUCTS.with(|cache| {
			cache
				.borrow_mut()
				.fresh()
				.entry((slot, c.id))
				.or_insert_with(|| reduce_once(&resolve_trace_term(honest, km)))
				.clone()
		}),
		Value::Primitive(_) => reduce_once(&resolve_trace_term(honest, km)),
	};
	let ground_reduct = reduce_once(ground);
	!ground_reduct.equivalent(&trace_reduct, true)
}
