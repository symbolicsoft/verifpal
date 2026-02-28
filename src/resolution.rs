/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::types::*;
use crate::value::{find_equivalent, push_unique_value};

// ---------------------------------------------------------------------------
// Resolution helpers
// ---------------------------------------------------------------------------

/// Maximum recursion depth for value resolution.  Resolution follows constant
/// chains (a = b, b = c, ...) and recurses into primitive arguments and
/// equation elements.  64 is far beyond what any real protocol model requires
/// (typical depth is < 10) but guards against infinite loops from malformed
/// or circular models without imposing a practical limit.
const MAX_RESOLVE_DEPTH: usize = 64;

// ---------------------------------------------------------------------------
// Resolve internal values from ProtocolTrace
// ---------------------------------------------------------------------------

pub fn resolve_trace_values(value: &Value, trace: &ProtocolTrace) -> (Value, Vec<Value>) {
	let mut visited: Vec<Value> = Vec::new();
	let resolved = resolve_trace_value(value, trace, &mut visited, 0);
	(resolved, visited)
}

fn resolve_trace_value(
	value: &Value,
	trace: &ProtocolTrace,
	visited: &mut Vec<Value>,
	depth: usize,
) -> Value {
	if depth >= MAX_RESOLVE_DEPTH {
		return value.clone();
	}
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
		Value::Primitive(_) => resolve_trace_primitive(&resolved, trace, visited, depth + 1),
		Value::Equation(_) => resolve_trace_equation(&resolved, trace, visited, depth + 1),
	}
}

fn resolve_trace_primitive(
	value: &Value,
	trace: &ProtocolTrace,
	visited: &mut Vec<Value>,
	depth: usize,
) -> Value {
	let prim = match value.as_primitive() {
		Some(p) => p,
		None => return value.clone(),
	};
	if depth >= MAX_RESOLVE_DEPTH {
		return value.clone();
	}
	// COW: only allocate a new Primitive if an argument actually changed
	let mut new_args: Option<Vec<Value>> = None;
	for (i, arg) in prim.arguments.iter().enumerate() {
		let resolved = resolve_trace_value(arg, trace, visited, depth);
		if !resolved.equivalent(arg, true) {
			let args = new_args.get_or_insert_with(|| prim.arguments.clone());
			args[i] = resolved;
		}
	}
	if let Some(args) = new_args {
		Value::Primitive(Arc::new(prim.with_arguments(args)))
	} else {
		value.clone()
	}
}

fn resolve_trace_equation(
	value: &Value,
	trace: &ProtocolTrace,
	visited: &mut Vec<Value>,
	depth: usize,
) -> Value {
	let eq = match value.as_equation() {
		Some(e) => e,
		None => return value.clone(),
	};
	if depth >= MAX_RESOLVE_DEPTH {
		return value.clone();
	}
	let mut result_eq = Equation { values: Vec::new() };
	let mut resolved_elements: Vec<Value> = Vec::new();
	for elem in &eq.values {
		if let Value::Constant(c) = elem {
			if let Some(idx) = trace.index_of(c) {
				resolved_elements.push(trace.slots[idx].initial_value.clone());
			}
			push_unique_value(visited, elem.clone());
		}
	}
	for (i, item) in resolved_elements.iter().enumerate() {
		match item {
			Value::Constant(_) => {
				result_eq.values.push(item.clone());
				push_unique_value(visited, item.clone());
			}
			Value::Primitive(_) => {
				let resolved = resolve_trace_primitive(item, trace, visited, depth);
				result_eq.values.push(resolved);
			}
			Value::Equation(_) => {
				let resolved = resolve_trace_equation(item, trace, visited, depth);
				if let Some(inner) = resolved.as_equation() {
					if i == 0 {
						result_eq.values = inner.values.clone();
					} else {
						result_eq.values.push(resolved.clone());
						if inner.values.len() > 1 {
							result_eq.values.extend(inner.values[1..].iter().cloned());
						}
					}
				} else {
					result_eq.values.push(resolved);
				}
			}
		}
	}
	Value::Equation(Arc::new(result_eq))
}

// ---------------------------------------------------------------------------
// Resolve internal values from PrincipalState
// ---------------------------------------------------------------------------

pub fn resolve_ps_values(
	value: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	attacker: &AttackerState,
	force_before_mutate: bool,
) -> VResult<Value> {
	resolve_ps_values_depth(
		value,
		root_value,
		root_index,
		ps,
		attacker,
		force_before_mutate,
		0,
	)
}

/// Resolve a value within a PrincipalState, following constant chains and
/// recursing into primitives/equations.
///
/// The `force_before_mutate` (fbm) flag controls which value a constant
/// resolves to.  The invariant is:
///
/// - **before_mutate**: the value as originally computed by the protocol,
///   before the attacker tampered with it.  Used when the principal "trusts"
///   this value (created it, hasn't received it over a wire, etc.).
///
/// - **assigned**: the current value, which may have been mutated by the
///   attacker.  Used when the principal received the value from the network
///   and the attacker could have replaced it.
///
/// Determine whether a constant should resolve to its `before_mutate` value
/// (what the principal originally computed) rather than its `assigned` value
/// (which may have been tampered with by the attacker).
///
/// Two cases:
///
/// 1. **Root constant** (`slot_idx == root_index`): use `before_mutate` if
///    already forced, or if `should_use_original()` says so (the
///    principal created it, doesn't know it, didn't receive it on a wire,
///    or it wasn't mutated).
///
/// 2. **Nested constant** (`slot_idx != root_index`): if the root is a
///    primitive received from another principal, force `before_mutate` so
///    the principal sees the original (untampered) inputs — UNLESS this
///    nested constant's `mutatable_to` list includes the root's creator,
///    meaning the attacker could have replaced it before the root was
///    computed, in which case the principal sees the tampered value.
fn compute_visibility(
	slot_idx: usize,
	root_index: usize,
	root_value: &Value,
	ps: &PrincipalState,
	existing_use_original: bool,
) -> bool {
	if slot_idx == root_index {
		// Case 1: root constant.
		if existing_use_original {
			return true;
		}
		return ps.should_use_original(slot_idx);
	}

	// Case 2: nested constant.
	let root_from_other = matches!(root_value, Value::Primitive(_))
		&& ps.values[root_index].provenance.creator != ps.id;

	let forced = existing_use_original || root_from_other;
	if forced {
		// Force original UNLESS this constant is mutable by the root's creator.
		!ps.meta[slot_idx]
			.mutatable_to
			.contains(&ps.values[root_index].provenance.creator)
	} else {
		ps.should_use_original(slot_idx)
	}
}

fn resolve_ps_values_depth(
	value: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	attacker: &AttackerState,
	force_before_mutate: bool,
	depth: usize,
) -> VResult<Value> {
	if depth >= MAX_RESOLVE_DEPTH {
		return Ok(value.clone());
	}

	let mut resolved = value.clone();
	let mut root_idx = root_index;
	let mut root_val = root_value.clone();
	let mut fbm = force_before_mutate;

	if let Value::Constant(c) = &resolved {
		let slot_idx = match ps.index_of(c) {
			Some(i) => i,
			None => return Err(VerifpalError::Resolution("invalid index".into())),
		};

		fbm = compute_visibility(slot_idx, root_idx, &root_val, ps, fbm);

		if slot_idx == root_idx {
			resolved = if fbm {
				ps.values[slot_idx].original.clone()
			} else {
				let (val, _) = ps.resolve_constant(c, true);
				val
			};
		} else {
			resolved = if fbm {
				ps.values[slot_idx].original.clone()
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
			resolve_ps_primitive_depth(&resolved, &root_val, root_idx, ps, attacker, fbm, depth + 1)
		}
		Value::Equation(_) => {
			resolve_ps_equation_depth(&resolved, &root_val, root_idx, ps, attacker, fbm, depth + 1)
		}
	}
}

fn resolve_ps_primitive_depth(
	value: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	attacker: &AttackerState,
	force_before_mutate: bool,
	depth: usize,
) -> VResult<Value> {
	let prim = value.try_as_primitive()?;
	let fbm = if ps.values[root_index].provenance.creator == ps.id {
		false
	} else {
		force_before_mutate
	};
	// COW: only allocate a new Primitive if an argument actually changed
	let mut new_args: Option<Vec<Value>> = None;
	for (i, arg) in prim.arguments.iter().enumerate() {
		let resolved =
			resolve_ps_values_depth(arg, root_value, root_index, ps, attacker, fbm, depth)?;
		if !resolved.equivalent(arg, true) {
			let args = new_args.get_or_insert_with(|| prim.arguments.clone());
			args[i] = resolved;
		}
	}
	if let Some(args) = new_args {
		Ok(Value::Primitive(Arc::new(prim.with_arguments(args))))
	} else {
		Ok(value.clone())
	}
}

fn resolve_ps_equation_depth(
	value: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	attacker: &AttackerState,
	force_before_mutate: bool,
	depth: usize,
) -> VResult<Value> {
	let eq = value.try_as_equation()?;
	let mut result_eq = Equation { values: Vec::new() };
	let mut elements: Vec<Value> = eq.values.clone();
	let fbm = if ps.values[root_index].provenance.creator == ps.id {
		false
	} else {
		force_before_mutate
	};
	for item in &mut elements {
		if let Value::Constant(c) = &*item {
			let (resolved, slot_idx) = ps.resolve_constant(c, true);
			*item = if fbm {
				slot_idx.map_or(resolved, |idx| ps.values[idx].original.clone())
			} else {
				resolved
			};
		}
	}
	for (i, item) in elements.iter().enumerate() {
		match item {
			Value::Constant(_) => {
				result_eq.values.push(item.clone());
			}
			Value::Primitive(_) => {
				let resolved = resolve_ps_primitive_depth(
					item, root_value, root_index, ps, attacker, fbm, depth,
				)?;
				result_eq.values.push(resolved);
			}
			Value::Equation(_) => {
				let resolved = resolve_ps_equation_depth(
					item, root_value, root_index, ps, attacker, fbm, depth,
				)?;
				if i == 0 {
					result_eq.values = resolved.try_as_equation()?.values.clone();
				} else {
					let inner = resolved.try_as_equation()?;
					if inner.values.len() > 1 {
						result_eq.values.extend(inner.values[1..].iter().cloned());
					}
				}
			}
		}
	}
	Ok(Value::Equation(Arc::new(result_eq)))
}

// ---------------------------------------------------------------------------
// Used-by checks
// ---------------------------------------------------------------------------

pub fn constant_used_by_principal(
	trace: &ProtocolTrace,
	principal_id: PrincipalId,
	c: &Constant,
) -> bool {
	if !trace.used_by.is_empty() {
		if let Some(principals) = trace.used_by.get(&c.id) {
			if let Some(&used) = principals.get(&principal_id) {
				return used;
			}
		}
		let i = trace.index.get(&c.id).copied();
		if let Some(idx) = i {
			if let Value::Constant(assigned_c) = &trace.slots[idx].initial_value {
				if let Some(principals) = trace.used_by.get(&assigned_c.id) {
					if let Some(&used) = principals.get(&principal_id) {
						return used;
					}
				}
			}
		}
		return false;
	}
	let i = trace.index.get(&c.id).copied();
	for slot in &trace.slots {
		if slot.creator != principal_id {
			continue;
		}
		if !matches!(
			&slot.initial_value,
			Value::Primitive(_) | Value::Equation(_)
		) {
			continue;
		}
		let (_, v) = resolve_trace_values(&slot.initial_value, trace);
		if let Some(idx) = i {
			if find_equivalent(&trace.slots[idx].initial_value, &v).is_some() {
				return true;
			}
		}
		let cv = Value::Constant(c.clone());
		if find_equivalent(&cv, &v).is_some() {
			return true;
		}
	}
	false
}

// ---------------------------------------------------------------------------
// Fresh value check
// ---------------------------------------------------------------------------

pub fn value_constant_contains_fresh_values(c: &Constant, ps: &PrincipalState) -> VResult<bool> {
	let idx = ps
		.index_of(c)
		.ok_or_else(|| VerifpalError::Resolution("invalid value".into()))?;
	let mut constants = Vec::new();
	ps.values[idx].value.collect_constants(&mut constants);
	Ok(constants.iter().any(|inner| {
		ps.index_of(inner)
			.is_some_and(|i| ps.meta[i].constant.fresh)
	}))
}
