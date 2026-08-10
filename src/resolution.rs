/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::types::*;
use crate::value::{find_equivalent, push_unique_value};

pub(crate) fn resolve_trace_constant(c: &Constant, trace: &ProtocolTrace) -> Value {
	resolve_trace_values(&Value::Constant(c.clone()), trace).0
}

pub(crate) fn resolve_trace_values(value: &Value, trace: &ProtocolTrace) -> (Value, Vec<Value>) {
	let mut visited: Vec<Value> = Vec::new();
	let resolved = resolve_trace_value(value, trace, &mut visited);
	(resolved, visited)
}

fn resolve_trace_value(value: &Value, trace: &ProtocolTrace, visited: &mut Vec<Value>) -> Value {
	let resolved = match value {
		Value::Constant(c) => {
			visited.push(value.clone());
			match trace.index_of(c) {
				Some(idx) => trace.slots[idx].initial_value.clone(),
				None => value.clone(),
			}
		}
		_ => value.clone(),
	};
	match &resolved {
		Value::Constant(_) => {
			push_unique_value(visited, resolved.clone());
			resolved
		}
		Value::Primitive(_) => resolve_trace_primitive(&resolved, trace, visited),
	}
}

fn resolve_trace_primitive(
	value: &Value,
	trace: &ProtocolTrace,
	visited: &mut Vec<Value>,
) -> Value {
	let prim = match value.as_primitive() {
		Some(p) => p,
		None => return value.clone(),
	};
	let mapped = prim.map_arguments(|arg| {
		let resolved = resolve_trace_value(arg, trace, visited);
		(!resolved.equivalent(arg, true)).then_some(resolved)
	});
	match mapped {
		Some(mapped) => Value::Primitive(Arc::new(mapped)),
		None => value.clone(),
	}
}

fn compute_visibility(
	slot_idx: usize,
	root_index: usize,
	root_value: &Value,
	ps: &PrincipalState,
	existing_use_original: bool,
) -> bool {
	if slot_idx == root_index {
		if existing_use_original {
			return true;
		}
		return ps.should_use_original(slot_idx);
	}

	let root_from_other = matches!(root_value, Value::Primitive(_))
		&& ps.values[root_index].provenance.creator != ps.id;

	let forced = existing_use_original || root_from_other;
	if forced {
		!ps.meta[slot_idx]
			.mutatable_to
			.contains(&ps.values[root_index].provenance.creator)
	} else {
		ps.should_use_original(slot_idx)
	}
}

pub(crate) fn resolve_ps_values(
	value: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	attacker: &AttackerState,
	use_original: bool,
) -> VResult<Value> {
	let mut resolved = value.clone();
	let mut root_idx = root_index;
	let mut root_val = root_value.clone();
	let mut use_orig = use_original;

	if let Value::Constant(c) = &resolved {
		let slot_idx = match ps.index_of(c) {
			Some(i) => i,
			None => return Err(VerifpalError::resolution("invalid index".into())),
		};

		use_orig = compute_visibility(slot_idx, root_idx, &root_val, ps, use_orig);

		if slot_idx == root_idx {
			resolved = if use_orig {
				ps.values[slot_idx].perceived().clone()
			} else {
				let (val, _) = ps.resolve_constant(c, true);
				val
			};
		} else {
			resolved = if use_orig {
				ps.values[slot_idx].perceived().clone()
			} else {
				ps.values[slot_idx].value.clone()
			};
			root_idx = slot_idx;
			root_val = resolved.clone();
		}
	}

	match &resolved {
		Value::Constant(_) => Ok(resolved),
		Value::Primitive(_) => {
			resolve_ps_primitive(&resolved, &root_val, root_idx, ps, attacker, use_orig)
		}
	}
}

fn resolve_ps_primitive(
	value: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	attacker: &AttackerState,
	use_original: bool,
) -> VResult<Value> {
	let prim = value.try_as_primitive()?;
	let use_orig = if ps.values[root_index].provenance.creator == ps.id {
		false
	} else {
		use_original
	};
	let mapped = prim.try_map_arguments(|arg| {
		let resolved = resolve_ps_values(arg, root_value, root_index, ps, attacker, use_orig)?;
		Ok((!resolved.equivalent(arg, true)).then_some(resolved))
	})?;
	Ok(match mapped {
		Some(mapped) => Value::Primitive(Arc::new(mapped)),
		None => value.clone(),
	})
}
pub(crate) fn constant_used_by_principal(
	trace: &ProtocolTrace,
	principal_id: PrincipalId,
	c: &Constant,
) -> bool {
	if !trace.used_by.is_empty() {
		if let Some(principals) = trace.used_by.get(&c.id)
			&& let Some(&used) = principals.get(&principal_id)
		{
			return used;
		}
		let i = trace.index.get(&c.id).copied();
		if let Some(idx) = i
			&& let Value::Constant(assigned_c) = &trace.slots[idx].initial_value
			&& let Some(principals) = trace.used_by.get(&assigned_c.id)
			&& let Some(&used) = principals.get(&principal_id)
		{
			return used;
		}
		return false;
	}
	let i = trace.index.get(&c.id).copied();
	for slot in &trace.slots {
		if slot.creator != principal_id {
			continue;
		}
		if !matches!(&slot.initial_value, Value::Primitive(_)) {
			continue;
		}
		let (_, v) = resolve_trace_values(&slot.initial_value, trace);
		if let Some(idx) = i
			&& find_equivalent(&trace.slots[idx].initial_value, &v).is_some()
		{
			return true;
		}
		let cv = Value::Constant(c.clone());
		if find_equivalent(&cv, &v).is_some() {
			return true;
		}
	}
	false
}

pub(crate) fn value_constant_contains_fresh_values(
	c: &Constant,
	ps: &PrincipalState,
) -> VResult<bool> {
	let idx = ps
		.index_of(c)
		.ok_or_else(|| VerifpalError::resolution("invalid value".into()))?;
	let mut constants = Vec::new();
	ps.values[idx].value.collect_constants(&mut constants);
	Ok(constants.iter().any(|inner| {
		ps.index_of(inner)
			.is_some_and(|i| ps.meta[i].constant.fresh)
	}))
}
