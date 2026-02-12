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

pub(crate) fn resolve_trace_values(
	a: &Value,
	trace: &ProtocolTrace,
) -> (Value, Vec<Value>) {
	let mut v: Vec<Value> = Vec::new();
	let resolved = resolve_trace_value(a, trace, &mut v, 0);
	(resolved, v)
}

fn resolve_trace_value(a: &Value, trace: &ProtocolTrace, v: &mut Vec<Value>, depth: usize) -> Value {
	if depth >= MAX_RESOLVE_DEPTH {
		return a.clone();
	}
	let resolved = match a {
		Value::Constant(c) => {
			v.push(a.clone());
			match trace.index_of(c) {
				Some(idx) => trace.slots[idx].initial_value.clone(),
				None => a.clone(),
			}
		}
		_ => a.clone(),
	};
	match &resolved {
		Value::Constant(_) => {
			push_unique_value(v, resolved.clone());
			resolved
		}
		Value::Primitive(_) => resolve_trace_primitive(&resolved, trace, v, depth + 1),
		Value::Equation(_) => resolve_trace_equation(&resolved, trace, v, depth + 1),
	}
}

fn resolve_trace_primitive(a: &Value, trace: &ProtocolTrace, v: &mut Vec<Value>, depth: usize) -> Value {
	let p = match a.as_primitive() {
		Some(p) => p,
		None => return a.clone(),
	};
	if depth >= MAX_RESOLVE_DEPTH {
		return a.clone();
	}
	// COW: only allocate a new Primitive if an argument actually changed
	let mut new_args: Option<Vec<Value>> = None;
	for (i, arg) in p.arguments.iter().enumerate() {
		let s = resolve_trace_value(arg, trace, v, depth);
		if !s.equivalent(arg, true) {
			let args = new_args.get_or_insert_with(|| p.arguments.clone());
			args[i] = s;
		}
	}
	if let Some(args) = new_args {
		Value::Primitive(Arc::new(p.with_arguments(args)))
	} else {
		a.clone()
	}
}

fn resolve_trace_equation(a: &Value, trace: &ProtocolTrace, v: &mut Vec<Value>, depth: usize) -> Value {
	let e = match a.as_equation() {
		Some(e) => e,
		None => return a.clone(),
	};
	if depth >= MAX_RESOLVE_DEPTH {
		return a.clone();
	}
	let mut r_eq = Equation { values: Vec::new() };
	let mut aa: Vec<Value> = Vec::new();
	for ev in &e.values {
		if let Value::Constant(c) = ev {
			if let Some(idx) = trace.index_of(c) {
				aa.push(trace.slots[idx].initial_value.clone());
			}
			push_unique_value(v, ev.clone());
		}
	}
	for (aai, item) in aa.iter().enumerate() {
		match item {
			Value::Constant(_) => {
				r_eq.values.push(item.clone());
				push_unique_value(v, item.clone());
			}
			Value::Primitive(_) => {
				let aaa = resolve_trace_primitive(item, trace, v, depth);
				r_eq.values.push(aaa);
			}
			Value::Equation(_) => {
				let aaa = resolve_trace_equation(item, trace, v, depth);
				if let Some(inner) = aaa.as_equation() {
					if aai == 0 {
						r_eq.values = inner.values.clone();
					} else {
						r_eq.values.push(aaa.clone());
						if inner.values.len() > 1 {
							r_eq.values.extend(inner.values[1..].iter().cloned());
						}
					}
				} else {
					r_eq.values.push(aaa);
				}
			}
		}
	}
	Value::Equation(Arc::new(r_eq))
}

// ---------------------------------------------------------------------------
// Resolve internal values from PrincipalState
// ---------------------------------------------------------------------------

pub(crate) fn resolve_ps_values(
	a: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	as_: &AttackerState,
	force_before_mutate: bool,
) -> VResult<Value> {
	resolve_ps_values_depth(
		a,
		root_value,
		root_index,
		ps,
		as_,
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
/// The decision tree for fbm has two cases:
///
/// 1. **Root constant** (same slot as the expression being resolved):
///    Use `should_use_before_mutate()` — true when the principal created it,
///    doesn't know it, didn't receive it over a wire, or it wasn't mutated.
///
/// 2. **Nested constant** (referenced inside a primitive/equation argument):
///    If the enclosing root was created by another principal (received over
///    the wire), force before_mutate — UNLESS this nested constant's
///    `mutatable_to` list includes the root's creator, meaning the attacker
///    could have replaced it before the root was computed.
fn resolve_ps_values_depth(
	a: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	as_: &AttackerState,
	force_before_mutate: bool,
	depth: usize,
) -> VResult<Value> {
	if depth >= MAX_RESOLVE_DEPTH {
		return Ok(a.clone());
	}

	let mut a_resolved = a.clone();
	let mut root_idx = root_index;
	let mut root_val = root_value.clone();
	let mut fbm = force_before_mutate;

	if let Value::Constant(c) = &a_resolved {
		let slot_idx = match ps.index_of(c) {
			Some(i) => i,
			None => return Err(VerifpalError::Resolution("invalid index".to_string())),
		};

		if slot_idx == root_idx {
			// Case 1: resolving the root constant itself.
			// Respect any existing fbm override; otherwise ask the principal.
			if !fbm {
				fbm = ps.should_use_before_mutate(slot_idx);
			}
			a_resolved = if fbm {
				ps.values[slot_idx].before_mutate.clone()
			} else {
				let (resolved, _) = ps.resolve_constant(c, true);
				resolved
			};
		} else {
			// Case 2: resolving a nested constant (argument of the root).
			// If the root is a primitive received from another principal,
			// force before_mutate so we see the original (untampered) inputs.
			let root_from_other = matches!(&root_val, Value::Primitive(_))
				&& ps.values[root_idx].creator != ps.id;
			if root_from_other {
				fbm = true;
			}

			// However, if the nested constant was mutable by the root's
			// creator, the attacker could have replaced it before the root
			// was computed — so we should NOT force before_mutate.
			fbm = if fbm {
				!ps.meta[slot_idx]
					.mutatable_to
					.contains(&ps.values[root_idx].creator)
			} else {
				ps.should_use_before_mutate(slot_idx)
			};

			a_resolved = if fbm {
				ps.values[slot_idx].before_mutate.clone()
			} else {
				ps.values[slot_idx].assigned.clone()
			};
			root_idx = slot_idx;
			root_val = a_resolved.clone();
		}
	}

	match &a_resolved {
		Value::Constant(_) => Ok(a_resolved),
		Value::Primitive(_) => resolve_ps_primitive_depth(
			&a_resolved,
			&root_val,
			root_idx,
			ps,
			as_,
			fbm,
			depth + 1,
		),
		Value::Equation(_) => resolve_ps_equation_depth(
			&a_resolved,
			&root_val,
			root_idx,
			ps,
			as_,
			fbm,
			depth + 1,
		),
	}
}

fn resolve_ps_primitive_depth(
	a: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	as_: &AttackerState,
	force_before_mutate: bool,
	depth: usize,
) -> VResult<Value> {
	let p = a.try_as_primitive()?;
	let mut fbm = force_before_mutate;
	if ps.values[root_index].creator == ps.id {
		fbm = false;
	}
	// COW: only allocate a new Primitive if an argument actually changed
	let mut new_args: Option<Vec<Value>> = None;
	for (i, arg) in p.arguments.iter().enumerate() {
		let s = resolve_ps_values_depth(
			arg, root_value, root_index, ps, as_, fbm, depth,
		)?;
		if !s.equivalent(arg, true) {
			let args = new_args.get_or_insert_with(|| p.arguments.clone());
			args[i] = s;
		}
	}
	if let Some(args) = new_args {
		Ok(Value::Primitive(Arc::new(p.with_arguments(args))))
	} else {
		Ok(a.clone())
	}
}

fn resolve_ps_equation_depth(
	a: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	as_: &AttackerState,
	force_before_mutate: bool,
	depth: usize,
) -> VResult<Value> {
	let e = a.try_as_equation()?;
	let mut r_eq = Equation { values: Vec::new() };
	let mut aa: Vec<Value> = e.values.clone();
	let mut fbm = force_before_mutate;
	if ps.values[root_index].creator == ps.id {
		fbm = false;
	}
	for item in &mut aa {
		let new_val = match &*item {
			Value::Constant(c) => {
				let (resolved, i) = ps.resolve_constant(c, true);
				Some(if fbm {
					i.map_or(resolved, |idx| ps.values[idx].before_mutate.clone())
				} else {
					resolved
				})
			}
			_ => None,
		};
		if let Some(v) = new_val {
			*item = v;
		}
	}
	for (aai, item) in aa.iter().enumerate() {
		match item {
			Value::Constant(_) => {
				r_eq.values.push(item.clone());
			}
			Value::Primitive(_) => {
				let aaa = resolve_ps_primitive_depth(
					item, root_value, root_index, ps, as_, fbm, depth,
				)?;
				r_eq.values.push(aaa);
			}
			Value::Equation(_) => {
				let aaa = resolve_ps_equation_depth(
					item, root_value, root_index, ps, as_, fbm, depth,
				)?;
				if aai == 0 {
					r_eq.values = aaa
						.try_as_equation()?
						.values
						.clone();
				} else {
					let inner = aaa.try_as_equation()?;
					if inner.values.len() > 1 {
						r_eq.values.extend(inner.values[1..].iter().cloned());
					}
				}
			}
		}
	}
	Ok(Value::Equation(Arc::new(r_eq)))
}

// ---------------------------------------------------------------------------
// Used-by checks
// ---------------------------------------------------------------------------

pub(crate) fn constant_used_by_principal(
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

pub(crate) fn value_constant_contains_fresh_values(
	c: &Constant,
	ps: &PrincipalState,
) -> VResult<bool> {
	let i = ps.index_of(c);
	let idx = match i {
		Some(idx) => idx,
		None => return Err(VerifpalError::Resolution("invalid value".to_string())),
	};
	let mut cc = Vec::new();
	ps.values[idx].assigned.collect_constants(&mut cc);
	for item in &cc {
		if let Some(ii) = ps.index_of(item) {
			if ps.meta[ii].constant.fresh {
				return Ok(true);
			}
		}
	}
	Ok(false)
}
