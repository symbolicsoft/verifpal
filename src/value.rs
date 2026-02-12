/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use crate::possible::{possible_to_rebuild, possible_to_rewrite};
use crate::primitive::{primitive_has_rewrite_rule, primitive_is_core};
use crate::types::*;

// ---------------------------------------------------------------------------
// Global name map
// ---------------------------------------------------------------------------

struct ValueNamesState {
	map: HashMap<Arc<str>, ValueId>,
	counter: ValueId,
}

static VALUE_NAMES_STATE: LazyLock<Mutex<ValueNamesState>> = LazyLock::new(|| {
	let mut map = HashMap::new();
	map.insert(Arc::from("g"), 0);
	map.insert(Arc::from("nil"), 1);
	Mutex::new(ValueNamesState { map, counter: 2 })
});

// ---------------------------------------------------------------------------
// Canonical values (cached statics — no per-call allocation)
// ---------------------------------------------------------------------------

static STATIC_G: LazyLock<Value> = LazyLock::new(|| {
	Value::Constant(Constant {
		name: Arc::from("g"),
		id: 0,
		guard: false,
		fresh: false,
		leaked: false,
		declaration: Some(Declaration::Knows),
		qualifier: Some(Qualifier::Public),
	})
});

static STATIC_NIL: LazyLock<Value> = LazyLock::new(|| {
	Value::Constant(Constant {
		name: Arc::from("nil"),
		id: 1,
		guard: false,
		fresh: false,
		leaked: false,
		declaration: Some(Declaration::Knows),
		qualifier: Some(Qualifier::Public),
	})
});

static STATIC_G_NIL: LazyLock<Value> = LazyLock::new(|| {
	Value::Equation(Arc::new(Equation {
		values: vec![value_g(), value_nil()],
	}))
});

static STATIC_G_NIL_NIL: LazyLock<Value> = LazyLock::new(|| {
	Value::Equation(Arc::new(Equation {
		values: vec![value_g(), value_nil(), value_nil()],
	}))
});

pub fn value_g() -> Value {
	STATIC_G.clone()
}

pub fn value_nil() -> Value {
	STATIC_NIL.clone()
}

pub fn value_g_nil() -> Value {
	STATIC_G_NIL.clone()
}

pub fn value_g_nil_nil() -> Value {
	STATIC_G_NIL_NIL.clone()
}

// ---------------------------------------------------------------------------
// Name map helpers
// ---------------------------------------------------------------------------

pub fn value_names_map_add(name: &str) -> ValueId {
	let mut state = VALUE_NAMES_STATE.lock().expect("value names lock");
	if let Some(&id) = state.map.get(name) {
		return id;
	}
	let id = state.counter;
	state.map.insert(Arc::from(name), id);
	state.counter += 1;
	id
}

pub fn value_is_g_or_nil(c: &Constant) -> bool {
	c.id == 0 || c.id == 1
}

// ---------------------------------------------------------------------------
// Index lookups
// ---------------------------------------------------------------------------

pub fn value_get_trace_index_from_constant(trace: &ProtocolTrace, c: &Constant) -> Option<usize> {
	trace.index.get(&c.id).copied()
}

pub fn value_get_principal_state_index_from_constant(
	ps: &PrincipalState,
	c: &Constant,
) -> Option<usize> {
	ps.index.get(&c.id).copied().filter(|&i| i < ps.meta.len())
}

// ---------------------------------------------------------------------------
// Extract constants from values
// ---------------------------------------------------------------------------

pub fn value_get_constants_from_value(v: &Value, out: &mut Vec<Constant>) {
	match v {
		Value::Constant(c) => out.push(c.clone()),
		Value::Primitive(p) => {
			for arg in &p.arguments {
				value_get_constants_from_value(arg, out);
			}
		}
		Value::Equation(e) => {
			for ev in &e.values {
				value_get_constants_from_value(ev, out);
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Equivalence checks
// ---------------------------------------------------------------------------

pub fn value_equivalent_values(a1: &Value, a2: &Value, consider_output: bool) -> bool {
	match (a1, a2) {
		(Value::Constant(c1), Value::Constant(c2)) => value_equivalent_constants(c1, c2),
		(Value::Primitive(p1), Value::Primitive(p2)) => {
			let (equiv, _, _) = value_equivalent_primitives(p1, p2, consider_output);
			equiv
		}
		(Value::Equation(e1), Value::Equation(e2)) => value_equivalent_equations(e1, e2),
		_ => false,
	}
}

pub fn value_equivalent_constants(c1: &Constant, c2: &Constant) -> bool {
	c1.id == c2.id
}

pub fn value_equivalent_primitives(
	p1: &Primitive,
	p2: &Primitive,
	consider_output: bool,
) -> (bool, usize, usize) {
	if p1.id != p2.id {
		return (false, 0, 0);
	}
	if consider_output && (p1.output != p2.output) {
		return (false, 0, 0);
	}
	if p1.arguments.len() != p2.arguments.len() {
		return (false, 0, 0);
	}
	for (a1, a2) in p1.arguments.iter().zip(p2.arguments.iter()) {
		if !value_equivalent_values(a1, a2, true) {
			return (false, 0, 0);
		}
	}
	(true, p1.output, p2.output)
}

pub fn value_equivalent_equations(e1: &Equation, e2: &Equation) -> bool {
	if e1.values.is_empty() || e2.values.is_empty() {
		return false;
	}
	let (e1f, e2f): (Equation, Equation);
	let (e1_ref, e2_ref): (&Equation, &Equation);
	if value_equation_is_flat(e1) && value_equation_is_flat(e2) {
		e1_ref = e1;
		e2_ref = e2;
	} else {
		e1f = value_flatten_equation(e1);
		e2f = value_flatten_equation(e2);
		e1_ref = &e1f;
		e2_ref = &e2f;
	}
	if e1_ref.values.len() != e2_ref.values.len() {
		return false;
	}
	match e1_ref.values.len() {
		1 => value_equivalent_values(&e1_ref.values[0], &e2_ref.values[0], true),
		2 => {
			value_equivalent_values(&e1_ref.values[0], &e2_ref.values[0], true)
				&& value_equivalent_values(&e1_ref.values[1], &e2_ref.values[1], true)
		}
		3 => {
			value_equivalent_equations_rule(
				&e1_ref.values[1],
				&e2_ref.values[1],
				&e1_ref.values[2],
				&e2_ref.values[2],
			) || value_equivalent_equations_rule(
				&e1_ref.values[1],
				&e2_ref.values[2],
				&e1_ref.values[2],
				&e2_ref.values[1],
			)
		}
		_ => {
			// >3 elements: base must match, exponents are commutative
			if !value_equivalent_values(&e1_ref.values[0], &e2_ref.values[0], true) {
				return false;
			}
			// Check that exponents [1..] are a permutation of each other
			let n = e1_ref.values.len();
			let mut matched = vec![false; n];
			for i in 1..n {
				let mut found = false;
				for (j, m) in matched.iter_mut().enumerate().skip(1) {
					if !*m && value_equivalent_values(&e1_ref.values[i], &e2_ref.values[j], true) {
						*m = true;
						found = true;
						break;
					}
				}
				if !found {
					return false;
				}
			}
			true
		}
	}
}

fn value_equivalent_equations_rule(
	base1: &Value,
	base2: &Value,
	exp1: &Value,
	exp2: &Value,
) -> bool {
	value_equivalent_values(base1, exp2, true) && value_equivalent_values(exp1, base2, true)
}

// ---------------------------------------------------------------------------
// Equation flattening
// ---------------------------------------------------------------------------

fn value_equation_is_flat(e: &Equation) -> bool {
	e.values.iter().all(|v| !matches!(v, Value::Equation(_)))
}

fn value_flatten_equation(e: &Equation) -> Equation {
	let mut ef = Equation {
		values: Vec::with_capacity(e.values.len()),
	};
	for v in &e.values {
		if let Value::Equation(inner) = v {
			let eff = value_flatten_equation(inner);
			ef.values.extend(eff.values);
		} else {
			ef.values.push(v.clone());
		}
	}
	ef
}

// ---------------------------------------------------------------------------
// Find constant in primitive from protocol trace
// ---------------------------------------------------------------------------

pub fn value_find_constant_in_primitive_from_protocol_trace(
	c: &Constant,
	a: &Value,
	trace: &ProtocolTrace,
) -> bool {
	let v = Value::Constant(c.clone());
	let (_, vv) = value_resolve_value_internal_values_from_protocol_trace(a, trace);
	value_equivalent_value_in_values(&v, &vv).is_some()
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

pub fn value_hash(v: &Value) -> u64 {
	match v {
		Value::Constant(c) => c.id as u64,
		Value::Primitive(p) => value_primitive_hash(p),
		Value::Equation(e) => value_equation_hash(e),
	}
}

fn value_primitive_hash(p: &Primitive) -> u64 {
	let mut h = (p.id as u64).wrapping_mul(2654435761) ^ (p.output as u64).wrapping_mul(97);
	for a in &p.arguments {
		h = h.wrapping_mul(31).wrapping_add(value_hash(a));
	}
	h
}

fn value_equation_hash(e: &Equation) -> u64 {
	if value_equation_is_flat(e) {
		return value_equation_hash_inner(e);
	}
	let ef = value_flatten_equation(e);
	value_equation_hash_inner(&ef)
}

fn value_equation_hash_inner(e: &Equation) -> u64 {
	match e.values.len() {
		0 => 0,
		1 => value_hash(&e.values[0]),
		2 => value_hash(&e.values[0])
			.wrapping_mul(31)
			.wrapping_add(value_hash(&e.values[1])),
		3 => {
			let mut h1 = value_hash(&e.values[1]);
			let mut h2 = value_hash(&e.values[2]);
			// Commutative hash for 3-element DH equations
			if h1 > h2 {
				std::mem::swap(&mut h1, &mut h2);
			}
			value_hash(&e.values[0])
				.wrapping_mul(31)
				.wrapping_add(h1.wrapping_mul(17))
				.wrapping_add(h2)
		}
		_ => {
			// >3 elements: commutative hash for exponents (same as DH equivalence)
			let base_h = value_hash(&e.values[0]);
			let mut exp_hashes: Vec<u64> = e.values[1..].iter().map(value_hash).collect();
			exp_hashes.sort_unstable();
			let mut h = base_h;
			for eh in exp_hashes {
				h = h.wrapping_mul(31).wrapping_add(eh);
			}
			h
		}
	}
}

// ---------------------------------------------------------------------------
// Search in value slices
// ---------------------------------------------------------------------------

pub fn value_equivalent_value_in_values_map(
	v: &Value,
	a: &[Value],
	m: &HashMap<u64, Vec<usize>>,
) -> Option<usize> {
	let h = value_hash(v);
	if let Some(indices) = m.get(&h) {
		for &i in indices {
			if value_equivalent_values(v, &a[i], true) {
				return Some(i);
			}
		}
	}
	None
}

pub fn value_equivalent_value_in_values(v: &Value, a: &[Value]) -> Option<usize> {
	a.iter().position(|av| value_equivalent_values(v, av, true))
}

/// Push `v` into `a` if no equivalent value already exists. Returns true if pushed.
pub fn push_unique_value(a: &mut Vec<Value>, v: Value) -> bool {
	if value_equivalent_value_in_values(&v, a).is_none() {
		a.push(v);
		true
	} else {
		false
	}
}

pub fn value_equivalent_constant_in_constants(c: &Constant, a: &[Constant]) -> Option<usize> {
	a.iter().position(|ac| value_equivalent_constants(c, ac))
}

// ---------------------------------------------------------------------------
// Rewrite: primitives
// ---------------------------------------------------------------------------

pub fn value_perform_primitive_rewrite(
	p: &Primitive,
	pi: Option<usize>,
	ps: &mut PrincipalState,
) -> (Vec<Primitive>, bool, Value) {
	let (mut rewrite, mut failed_rewrites, rewritten) =
		value_perform_primitive_arguments_rewrite(p, ps);
	let (rebuilt, rebuild) =
		possible_to_rebuild(rewrite.as_primitive().expect("rewrite is Primitive"));
	if rebuilt {
		if let Some(idx) = pi {
			ps.values[idx].set_assigned(rebuild.clone());
		}
		rewrite = rebuild;
		match rewrite {
			Value::Constant(_) | Value::Equation(_) => {
				return (failed_rewrites, rewritten, rewrite);
			}
			_ => {}
		}
	}
	let (rewritten_root, rewritten_values) =
		possible_to_rewrite(rewrite.as_primitive().expect("rewrite is Primitive"), ps, 0);
	if !rewritten_root {
		failed_rewrites.push(
			rewritten_values[0]
				.as_primitive()
				.expect("rewrite result is Primitive")
				.clone(),
		);
	}
	let r_index = if rewritten_root && primitive_is_core(p.id) {
		p.output
	} else {
		0
	};
	if r_index >= rewritten_values.len() {
		if let Some(idx) = pi {
			ps.values[idx].set_assigned(value_nil());
		}
		return (failed_rewrites, rewritten || rewritten_root, value_nil());
	}
	if let Some(idx) = pi {
		if rewritten || rewritten_root {
			ps.values[idx].rewritten = true;
			ps.values[idx].set_assigned(rewritten_values[r_index].clone());
		}
	}
	(
		failed_rewrites,
		rewritten || rewritten_root,
		rewritten_values[r_index].clone(),
	)
}

// ---------------------------------------------------------------------------
// Rewrite: primitive arguments
// ---------------------------------------------------------------------------

pub fn value_perform_primitive_arguments_rewrite(
	p: &Primitive,
	ps: &mut PrincipalState,
) -> (Value, Vec<Primitive>, bool) {
	let mut failed_rewrites: Vec<Primitive> = Vec::new();
	let mut rewritten = false;
	// COW: only allocate new arguments vec if something actually changes
	let mut new_args: Option<Vec<Value>> = None;
	for (i, a) in p.arguments.iter().enumerate() {
		match a {
			Value::Constant(_) => {}
			Value::Primitive(inner_p) => {
				let (p_failed, p_rewritten, p_rewrite) =
					value_perform_primitive_rewrite(inner_p, None, ps);
				if p_rewritten {
					rewritten = true;
					let args = new_args.get_or_insert_with(|| p.arguments.clone());
					args[i] = p_rewrite;
				} else {
					failed_rewrites.extend(p_failed);
				}
			}
			Value::Equation(inner_e) => {
				let (e_failed, e_rewritten, e_rewrite) =
					value_perform_equation_rewrite(inner_e, None, ps);
				if e_rewritten {
					rewritten = true;
					let args = new_args.get_or_insert_with(|| p.arguments.clone());
					args[i] = e_rewrite;
				} else {
					failed_rewrites.extend(e_failed);
				}
			}
		}
	}
	let result = if let Some(args) = new_args {
		Value::Primitive(Arc::new(p.with_arguments(args)))
	} else {
		Value::Primitive(Arc::new(p.clone()))
	};
	(result, failed_rewrites, rewritten)
}

// ---------------------------------------------------------------------------
// Rewrite: equations
// ---------------------------------------------------------------------------

pub fn value_perform_equation_rewrite(
	e: &Equation,
	pi: Option<usize>,
	ps: &mut PrincipalState,
) -> (Vec<Primitive>, bool, Value) {
	let mut rewritten = false;
	let mut failed_rewrites: Vec<Primitive> = Vec::new();
	let mut rewrite_eq = Equation { values: Vec::new() };
	for (i, a) in e.values.iter().enumerate() {
		match a {
			Value::Constant(_) => {
				rewrite_eq.values.push(a.clone());
			}
			Value::Primitive(inner_p) => {
				if !primitive_has_rewrite_rule(inner_p.id) {
					continue;
				}
				let (p_failed, p_rewritten, p_rewrite) =
					value_perform_primitive_rewrite(inner_p, None, ps);
				if !p_rewritten {
					rewrite_eq.values.push(e.values[i].clone());
					failed_rewrites.extend(p_failed);
					continue;
				}
				rewritten = true;
				match &p_rewrite {
					Value::Constant(_) | Value::Primitive(_) => {
						rewrite_eq.values.push(p_rewrite);
					}
					Value::Equation(inner_e) => {
						rewrite_eq.values.extend(inner_e.values.iter().cloned());
					}
				}
			}
			Value::Equation(inner_e) => {
				let (e_failed, e_rewritten, e_rewrite) =
					value_perform_equation_rewrite(inner_e, None, ps);
				if !e_rewritten {
					rewrite_eq.values.push(e.values[i].clone());
					failed_rewrites.extend(e_failed);
					continue;
				}
				rewritten = true;
				rewrite_eq.values.push(e_rewrite);
			}
		}
	}
	let rewrite = Value::Equation(Arc::new(rewrite_eq));
	if let Some(idx) = pi {
		if rewritten {
			ps.values[idx].rewritten = true;
			ps.values[idx].set_assigned(rewrite.clone());
		}
	}
	(failed_rewrites, rewritten, rewrite)
}

// ---------------------------------------------------------------------------
// Perform all rewrites
// ---------------------------------------------------------------------------

pub fn value_perform_all_rewrites(ps: &mut PrincipalState) -> Vec<(Primitive, usize)> {
	let mut failures: Vec<(Primitive, usize)> = Vec::new();
	let len = ps.values.len();
	for i in 0..len {
		match &ps.values[i].assigned {
			Value::Primitive(p) => {
				let p_clone = p.clone();
				let (failed, _, _) = value_perform_primitive_rewrite(&p_clone, Some(i), ps);
				failures.extend(failed.into_iter().map(|p| (p, i)));
			}
			Value::Equation(e) => {
				let e_clone = e.clone();
				let (failed, _, _) = value_perform_equation_rewrite(&e_clone, Some(i), ps);
				failures.extend(failed.into_iter().map(|p| (p, i)));
			}
			_ => {}
		}
	}
	failures
}

// ---------------------------------------------------------------------------
// Resolution helpers
// ---------------------------------------------------------------------------

pub fn value_resolve_constant(
	c: &Constant,
	ps: &PrincipalState,
	allow_before_mutate: bool,
) -> (Value, Option<usize>) {
	let i = value_get_principal_state_index_from_constant(ps, c);
	match i {
		None => (Value::Constant(c.clone()), None),
		Some(idx) => {
			let value = if allow_before_mutate {
				ps.effective_value(idx)
			} else {
				&ps.values[idx].assigned
			};
			(value.clone(), Some(idx))
		}
	}
}

const MAX_RESOLVE_DEPTH: usize = 64;

// ---------------------------------------------------------------------------
// Resolve internal values from ProtocolTrace
// ---------------------------------------------------------------------------

pub fn value_resolve_value_internal_values_from_protocol_trace(
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
			match value_get_trace_index_from_constant(trace, c) {
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
	let p = a.as_primitive().expect("value is Primitive");
	if depth >= MAX_RESOLVE_DEPTH {
		return a.clone();
	}
	// COW: only allocate a new Primitive if an argument actually changed
	let mut new_args: Option<Vec<Value>> = None;
	for (i, arg) in p.arguments.iter().enumerate() {
		let s = resolve_trace_value(arg, trace, v, depth);
		if !value_equivalent_values(&s, arg, true) {
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
	let e = a.as_equation().expect("value is Equation");
	if depth >= MAX_RESOLVE_DEPTH {
		return a.clone();
	}
	let mut r_eq = Equation { values: Vec::new() };
	let mut aa: Vec<Value> = Vec::new();
	for ev in &e.values {
		if let Value::Constant(c) = ev {
			if let Some(idx) = value_get_trace_index_from_constant(trace, c) {
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
				let inner = aaa.as_equation().expect("resolved equation is Equation");
				if aai == 0 {
					r_eq.values = inner.values.clone();
				} else {
					r_eq.values.push(aaa.clone());
					if inner.values.len() > 1 {
						r_eq.values.extend(inner.values[1..].iter().cloned());
					}
				}
			}
		}
	}
	Value::Equation(Arc::new(r_eq))
}

// ---------------------------------------------------------------------------
// Resolve internal values from PrincipalState
// ---------------------------------------------------------------------------

pub fn value_resolve_value_internal_values_from_principal_state(
	a: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	as_: &AttackerState,
	force_before_mutate: bool,
) -> Result<Value, String> {
	value_resolve_value_internal_values_from_principal_state_depth(
		a,
		root_value,
		root_index,
		ps,
		as_,
		force_before_mutate,
		0,
	)
}

fn value_resolve_value_internal_values_from_principal_state_depth(
	a: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	as_: &AttackerState,
	force_before_mutate: bool,
	depth: usize,
) -> Result<Value, String> {
	if depth >= MAX_RESOLVE_DEPTH {
		return Ok(a.clone());
	}

	let mut a_resolved = a.clone();
	let mut root_idx = root_index;
	let mut root_val = root_value.clone();
	let mut fbm = force_before_mutate;

	if let Value::Constant(c) = &a_resolved {
		let nri = match value_get_principal_state_index_from_constant(ps, c) {
			Some(i) => i,
			None => return Err("invalid index".to_string()),
		};
		if nri == root_idx {
			if !fbm {
				fbm = ps.should_use_before_mutate(nri);
			}
			if fbm {
				a_resolved = ps.values[nri].before_mutate.clone();
			} else {
				let (resolved, _) = value_resolve_constant(c, ps, true);
				a_resolved = resolved;
			}
		} else {
			if let Value::Primitive(_) = &root_val {
				if ps.values[root_idx].creator != ps.id {
					fbm = true;
				}
			}
			if fbm {
				fbm = !ps.meta[nri]
					.mutatable_to
					.contains(&ps.values[root_idx].creator);
			} else {
				fbm = ps.should_use_before_mutate(nri);
			}
			if fbm {
				a_resolved = ps.values[nri].before_mutate.clone();
			} else {
				a_resolved = ps.values[nri].assigned.clone();
			}
			root_idx = nri;
			root_val = a_resolved.clone();
		}
	}

	match &a_resolved {
		Value::Constant(_) => Ok(a_resolved),
		Value::Primitive(_) => value_resolve_primitive_internal_values_from_principal_state_depth(
			&a_resolved,
			&root_val,
			root_idx,
			ps,
			as_,
			fbm,
			depth + 1,
		),
		Value::Equation(_) => value_resolve_equation_internal_values_from_principal_state_depth(
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

fn value_resolve_primitive_internal_values_from_principal_state_depth(
	a: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	as_: &AttackerState,
	force_before_mutate: bool,
	depth: usize,
) -> Result<Value, String> {
	let p = a.as_primitive().expect("value is Primitive");
	let mut fbm = force_before_mutate;
	if ps.values[root_index].creator == ps.id {
		fbm = false;
	}
	// COW: only allocate a new Primitive if an argument actually changed
	let mut new_args: Option<Vec<Value>> = None;
	for (i, arg) in p.arguments.iter().enumerate() {
		let s = value_resolve_value_internal_values_from_principal_state_depth(
			arg, root_value, root_index, ps, as_, fbm, depth,
		)?;
		if !value_equivalent_values(&s, arg, true) {
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

fn value_resolve_equation_internal_values_from_principal_state_depth(
	a: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	as_: &AttackerState,
	force_before_mutate: bool,
	depth: usize,
) -> Result<Value, String> {
	let e = a.as_equation().expect("value is Equation");
	let mut r_eq = Equation { values: Vec::new() };
	let mut aa: Vec<Value> = e.values.clone();
	let mut fbm = force_before_mutate;
	if ps.values[root_index].creator == ps.id {
		fbm = false;
	}
	for item in &mut aa {
		let new_val = match &*item {
			Value::Constant(c) => {
				let (resolved, i) = value_resolve_constant(c, ps, true);
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
				let aaa = value_resolve_primitive_internal_values_from_principal_state_depth(
					item, root_value, root_index, ps, as_, fbm, depth,
				)?;
				r_eq.values.push(aaa);
			}
			Value::Equation(_) => {
				let aaa = value_resolve_equation_internal_values_from_principal_state_depth(
					item, root_value, root_index, ps, as_, fbm, depth,
				)?;
				if aai == 0 {
					r_eq.values = aaa
						.as_equation()
						.expect("resolved equation is Equation")
						.values
						.clone();
				} else {
					let inner = aaa.as_equation().expect("resolved equation is Equation");
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

pub fn value_constant_is_used_by_principal_in_protocol_trace(
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
		let i = value_get_trace_index_from_constant(trace, c);
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
	let i = value_get_trace_index_from_constant(trace, c);
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
		let (_, v) =
			value_resolve_value_internal_values_from_protocol_trace(&slot.initial_value, trace);
		if let Some(idx) = i {
			if value_equivalent_value_in_values(&trace.slots[idx].initial_value, &v).is_some() {
				return true;
			}
		}
		let cv = Value::Constant(c.clone());
		if value_equivalent_value_in_values(&cv, &v).is_some() {
			return true;
		}
	}
	false
}

pub fn value_constant_is_used_by_at_least_one_principal(
	trace: &ProtocolTrace,
	c: &Constant,
) -> bool {
	if &*c.name == "nil" {
		return true;
	}
	trace
		.principal_ids
		.iter()
		.any(|&pid| value_constant_is_used_by_principal_in_protocol_trace(trace, pid, c))
}

// ---------------------------------------------------------------------------
// Resolve all principal state values
// ---------------------------------------------------------------------------

pub fn value_resolve_all_principal_state_values(
	ps: &mut PrincipalState,
	as_: &AttackerState,
) -> Result<(), String> {
	let n = ps.values.len();
	let mut new_assigned = Vec::with_capacity(n);
	let mut new_before_rewrite = Vec::with_capacity(n);
	// Borrow ps immutably for the resolution loop
	let ps_ref: &PrincipalState = &*ps;
	for i in 0..n {
		let fbm = ps_ref.should_use_before_mutate(i);
		new_assigned.push(value_resolve_value_internal_values_from_principal_state(
			&ps_ref.values[i].assigned,
			&ps_ref.values[i].assigned,
			i,
			ps_ref,
			as_,
			fbm,
		)?);
		new_before_rewrite.push(value_resolve_value_internal_values_from_principal_state(
			&ps_ref.values[i].before_rewrite,
			&ps_ref.values[i].before_rewrite,
			i,
			ps_ref,
			as_,
			fbm,
		)?);
	}
	for ((sv, assigned), before_rewrite) in ps
		.values
		.iter_mut()
		.zip(new_assigned)
		.zip(new_before_rewrite)
	{
		sv.assigned = assigned;
		sv.before_rewrite = before_rewrite;
		sv.rewritten = false;
	}
	Ok(())
}

// ---------------------------------------------------------------------------
// Fresh value check
// ---------------------------------------------------------------------------

pub fn value_constant_contains_fresh_values(
	c: &Constant,
	ps: &PrincipalState,
) -> Result<bool, String> {
	let i = value_get_principal_state_index_from_constant(ps, c);
	let idx = match i {
		Some(idx) => idx,
		None => return Err("invalid value".to_string()),
	};
	let mut cc = Vec::new();
	value_get_constants_from_value(&ps.values[idx].assigned, &mut cc);
	for item in &cc {
		if let Some(ii) = value_get_principal_state_index_from_constant(ps, item) {
			if ps.meta[ii].constant.fresh {
				return Ok(true);
			}
		}
	}
	Ok(false)
}

// ---------------------------------------------------------------------------
// Mutation record computation
// ---------------------------------------------------------------------------

/// Build a compact forensic record of which PrincipalState slots differ
/// from the protocol trace initial values. Only changed slots are recorded.
pub fn compute_slot_diffs(ps: &PrincipalState, trace: &ProtocolTrace) -> MutationRecord {
	let diffs = ps
		.values
		.iter()
		.zip(ps.meta.iter())
		.zip(trace.slots.iter())
		.enumerate()
		.filter_map(|(i, ((sv, sm), slot))| {
			if value_equivalent_values(&sv.before_rewrite, &slot.initial_value, false) {
				None
			} else {
				Some(SlotDiff {
					index: i,
					constant: sm.constant.clone(),
					assigned: sv.assigned.clone(),
					mutated: sv.mutated,
				})
			}
		})
		.collect();
	MutationRecord { diffs }
}
