/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::equivalence::splice_equation;
use crate::theory::can_rewrite;
use crate::types::*;
use crate::value::value_g;

use super::vars::attacker_var;

pub(crate) struct SymbolicState {
	pub terms: Vec<Value>,
	pub var_slots: Vec<usize>,
	pub var_terms: Vec<Option<Value>>,
}

impl SymbolicState {
	pub(crate) fn is_var_slot(&self, slot: usize) -> bool {
		self.var_terms.get(slot).is_some_and(|t| t.is_some())
	}
}

pub(crate) fn is_mutable_slot(
	idx: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> bool {
	let meta = &ps.meta[idx];
	if meta.constant.is_g_or_nil() {
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
	if !meta.phase.iter().any(|&p| p <= attacker.current_phase) {
		return false;
	}
	if !km.constant_used_by(ps.id, &meta.constant) {
		return false;
	}
	true
}

fn shaped_var(slot: usize, honest: &Value, name: &str) -> Value {
	match honest {
		Value::Equation(_) => Value::Equation(Arc::new(Equation {
			values: vec![value_g(), attacker_var(slot, name)],
		})),
		_ => attacker_var(slot, name),
	}
}

pub(crate) fn build(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> SymbolicState {
	let n = ps.values.len();
	let mut var_terms: Vec<Option<Value>> = vec![None; n];
	let mut var_slots = Vec::new();

	for (idx, slot) in var_terms.iter_mut().enumerate() {
		if !is_mutable_slot(idx, km, ps, attacker) {
			continue;
		}
		let name = &ps.meta[idx].constant.name;
		*slot = Some(shaped_var(idx, &ps.values[idx].value, name));
		var_slots.push(idx);
	}

	let mut memo: Vec<Option<Value>> = vec![None; n];
	let mut building: Vec<bool> = vec![false; n];
	let mut terms: Vec<Value> = Vec::with_capacity(n);
	for idx in 0..n {
		terms.push(slot_term(idx, ps, &var_terms, &mut memo, &mut building));
	}

	SymbolicState {
		terms,
		var_slots,
		var_terms,
	}
}

fn reduce(v: &Value, ps: &PrincipalState) -> Value {
	match v {
		Value::Primitive(p) => {
			let (_, reduced) = can_rewrite(p, ps, 0);
			reduced
		}
		_ => v.clone(),
	}
}

fn slot_term(
	idx: usize,
	ps: &PrincipalState,
	var_terms: &[Option<Value>],
	memo: &mut Vec<Option<Value>>,
	building: &mut Vec<bool>,
) -> Value {
	if let Some(cached) = &memo[idx] {
		return cached.clone();
	}
	if let Some(var) = &var_terms[idx] {
		let v = var.clone();
		memo[idx] = Some(v.clone());
		return v;
	}
	if building[idx] {
		return ps.values[idx].value.clone();
	}

	let owner = ps.values[idx].provenance.creator;
	building[idx] = true;
	let inlined = inline(&ps.values[idx].value, ps, var_terms, owner, memo, building);
	building[idx] = false;

	let reduced = reduce(&inlined, ps);
	memo[idx] = Some(reduced.clone());
	reduced
}

fn reaches(ps: &PrincipalState, idx: usize, owner: PrincipalId) -> bool {
	owner == ps.id || ps.meta[idx].mutatable_to.contains(&owner)
}

fn inline(
	v: &Value,
	ps: &PrincipalState,
	var_terms: &[Option<Value>],
	owner: PrincipalId,
	memo: &mut Vec<Option<Value>>,
	building: &mut Vec<bool>,
) -> Value {
	match v {
		Value::Constant(c) => match ps.index_of(c) {
			Some(idx) => {
				if var_terms[idx].is_some() && !reaches(ps, idx, owner) {
					if building[idx] {
						return v.clone();
					}
					building[idx] = true;
					let honest =
						inline(&ps.values[idx].value, ps, var_terms, owner, memo, building);
					building[idx] = false;
					return reduce(&honest, ps);
				}
				slot_term(idx, ps, var_terms, memo, building)
			}
			None => v.clone(),
		},
		Value::Primitive(p) => {
			let args: Vec<Value> = p
				.arguments
				.iter()
				.map(|a| inline(a, ps, var_terms, owner, memo, building))
				.collect();
			Value::Primitive(Arc::new(p.with_arguments(args)))
		}
		Value::Equation(e) => Value::Equation(Arc::new(splice_equation(
			e.values
				.iter()
				.map(|item| inline(item, ps, var_terms, owner, memo, building)),
		))),
	}
}
