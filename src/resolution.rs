/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::types::*;

pub(crate) fn resolve_trace_constant(c: &Constant, trace: &ProtocolTrace) -> Value {
	let value = Value::Constant(c.clone());
	resolve_trace_value(&value, trace).unwrap_or(value)
}

pub(crate) fn resolve_trace_term(value: &Value, trace: &ProtocolTrace) -> Value {
	resolve_trace_value(value, trace).unwrap_or_else(|| value.clone())
}

fn resolve_trace_value(value: &Value, trace: &ProtocolTrace) -> Option<Value> {
	let Value::Constant(c) = value else {
		return resolve_trace_primitive(value, trace);
	};
	let idx = trace.index_of(c)?;
	let resolved = &trace.slots[idx].initial_value;
	match resolved {
		Value::Constant(rc) => (rc.id != c.id).then(|| resolved.clone()),
		Value::Primitive(_) => {
			Some(resolve_trace_primitive(resolved, trace).unwrap_or_else(|| resolved.clone()))
		}
	}
}

fn resolve_trace_primitive(value: &Value, trace: &ProtocolTrace) -> Option<Value> {
	let prim = value.as_primitive()?;
	prim.map_arguments(|arg| resolve_trace_value(arg, trace))
		.map(|mapped| Value::Primitive(Arc::new(mapped)))
}

pub(crate) fn trace_mentions(value: &Value, trace: &ProtocolTrace, target: ValueId) -> bool {
	match value {
		Value::Constant(c) => {
			if c.id == target {
				return true;
			}
			let Some(idx) = trace.index_of(c) else {
				return false;
			};
			match &trace.slots[idx].initial_value {
				Value::Constant(rc) => rc.id == target,
				resolved => trace_mentions(resolved, trace, target),
			}
		}
		Value::Primitive(p) => p
			.arguments
			.iter()
			.any(|arg| trace_mentions(arg, trace, target)),
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

pub(crate) type ResolveMemo = Vec<[Option<Value>; 2]>;

pub(crate) fn resolve_ps_values(
	value: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	use_original: bool,
	memo: &mut ResolveMemo,
) -> VResult<Option<Value>> {
	let Value::Constant(c) = value else {
		return resolve_ps_primitive(value, root_value, root_index, ps, use_original, memo);
	};
	let Some(slot_idx) = ps.index_of(c) else {
		return Err(VerifpalError::resolution("invalid index".into()));
	};
	let use_orig = compute_visibility(slot_idx, root_index, root_value, ps, use_original);
	let rerooted = slot_idx != root_index;
	if rerooted && let Some(hit) = &memo[slot_idx][usize::from(use_orig)] {
		return Ok(Some(hit.clone()));
	}
	let resolved = if use_orig {
		ps.values[slot_idx].perceived()
	} else {
		&ps.values[slot_idx].value
	};
	match resolved {
		Value::Constant(rc) => Ok((rc.id != c.id).then(|| resolved.clone())),
		Value::Primitive(_) if !rerooted => {
			let mapped =
				resolve_ps_primitive(resolved, root_value, root_index, ps, use_orig, memo)?;
			Ok(Some(mapped.unwrap_or_else(|| resolved.clone())))
		}
		Value::Primitive(_) => {
			let mapped = resolve_ps_primitive(resolved, resolved, slot_idx, ps, use_orig, memo)?;
			let out = mapped.unwrap_or_else(|| resolved.clone());
			memo[slot_idx][usize::from(use_orig)] = Some(out.clone());
			Ok(Some(out))
		}
	}
}

fn resolve_ps_primitive(
	value: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	use_original: bool,
	memo: &mut ResolveMemo,
) -> VResult<Option<Value>> {
	let prim = value.try_as_primitive()?;
	let use_orig = if ps.values[root_index].provenance.creator == ps.id {
		false
	} else {
		use_original
	};
	let mapped = prim.try_map_arguments(|arg| {
		resolve_ps_values(arg, root_value, root_index, ps, use_orig, memo)
	})?;
	Ok(mapped.map(|mapped| Value::Primitive(Arc::new(mapped))))
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
	let assigned = trace
		.index
		.get(&c.id)
		.and_then(|&idx| trace.slots[idx].initial_value.as_constant())
		.map(|assigned| assigned.id);
	for slot in &trace.slots {
		if slot.creator != principal_id {
			continue;
		}
		if !matches!(&slot.initial_value, Value::Primitive(_)) {
			continue;
		}
		if let Some(assigned) = assigned
			&& trace_mentions(&slot.initial_value, trace, assigned)
		{
			return true;
		}
		if trace_mentions(&slot.initial_value, trace, c.id) {
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
