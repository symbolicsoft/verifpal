/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use crate::equivalence::{equivalent_equations, equivalent_primitives, PrimitiveMatch};
use crate::hashing::{equation_hash, primitive_hash};
use crate::resolution::constant_used_by_principal;
use crate::rewrite::{perform_equation_rewrite, perform_primitive_rewrite};
use crate::types::*;

// Re-exports for backwards compatibility (many modules use `use crate::value::*`)
pub(crate) use crate::equivalence::find_constant_in_trace_primitive;
pub(crate) use crate::resolution::{
	resolve_ps_values, resolve_trace_values, value_constant_contains_fresh_values,
};

// ---------------------------------------------------------------------------
// Global name map
// ---------------------------------------------------------------------------

struct ValueNamesState {
	map: HashMap<Arc<str>, ValueId>,
	counter: ValueId,
}

/// Global because value IDs must be unique across the entire process and are
/// referenced by ID (`u32`) everywhere. Moving this into a context would
/// cascade through every function that creates or looks up a value.
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

pub(crate) fn value_g() -> Value {
	STATIC_G.clone()
}

pub(crate) fn value_nil() -> Value {
	STATIC_NIL.clone()
}

pub(crate) fn value_g_nil() -> Value {
	STATIC_G_NIL.clone()
}

pub(crate) fn value_g_nil_nil() -> Value {
	STATIC_G_NIL_NIL.clone()
}

// ---------------------------------------------------------------------------
// Name map helpers
// ---------------------------------------------------------------------------

pub(crate) fn value_names_map_add(name: &str) -> ValueId {
	let mut state = VALUE_NAMES_STATE.lock().unwrap_or_else(|e| e.into_inner());
	if let Some(&id) = state.map.get(name) {
		return id;
	}
	let id = state.counter;
	state.map.insert(Arc::from(name), id);
	state.counter += 1;
	id
}

// ---------------------------------------------------------------------------
// Search in value slices
// ---------------------------------------------------------------------------

pub(crate) fn find_equivalent(v: &Value, a: &[Value]) -> Option<usize> {
	a.iter().position(|av| v.equivalent(av, true))
}

/// Push `v` into `a` if no equivalent value already exists. Returns true if pushed.
pub(crate) fn push_unique_value(a: &mut Vec<Value>, v: Value) -> bool {
	if find_equivalent(&v, a).is_none() {
		a.push(v);
		true
	} else {
		false
	}
}

pub(crate) fn find_equivalent_constant(c: &Constant, a: &[Constant]) -> Option<usize> {
	a.iter().position(|ac| c.equivalent(ac))
}

// ---------------------------------------------------------------------------
// Mutation record computation
// ---------------------------------------------------------------------------

/// Build a compact forensic record of which PrincipalState slots differ
/// from the protocol trace initial values. Only changed slots are recorded.
pub(crate) fn compute_slot_diffs(ps: &PrincipalState, trace: &ProtocolTrace) -> MutationRecord {
	let diffs = ps
		.values
		.iter()
		.zip(ps.meta.iter())
		.zip(trace.slots.iter())
		.enumerate()
		.filter_map(|(i, ((sv, sm), slot))| {
			if sv.before_rewrite.equivalent(&slot.initial_value, false) {
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

// ---------------------------------------------------------------------------
// Public re-export of equivalent_primitives for inject.rs and possible.rs
// ---------------------------------------------------------------------------

pub(crate) fn value_equivalent_primitives(
	p1: &Primitive,
	p2: &Primitive,
	consider_output: bool,
) -> PrimitiveMatch {
	equivalent_primitives(p1, p2, consider_output)
}

// ---------------------------------------------------------------------------
// Impl methods on core types
// ---------------------------------------------------------------------------

impl Value {
	pub(crate) fn equivalent(&self, other: &Value, consider_output: bool) -> bool {
		match (self, other) {
			(Value::Constant(c1), Value::Constant(c2)) => c1.id == c2.id,
			(Value::Primitive(p1), Value::Primitive(p2)) => {
				equivalent_primitives(p1, p2, consider_output).equivalent
			}
			(Value::Equation(e1), Value::Equation(e2)) => equivalent_equations(e1, e2),
			_ => false,
		}
	}
	pub(crate) fn hash_value(&self) -> u64 {
		match self {
			Value::Constant(c) => c.id as u64,
			Value::Primitive(p) => primitive_hash(p),
			Value::Equation(e) => equation_hash(e),
		}
	}
	pub(crate) fn collect_constants(&self, out: &mut Vec<Constant>) {
		match self {
			Value::Constant(c) => out.push(c.clone()),
			Value::Primitive(p) => {
				for arg in &p.arguments {
					arg.collect_constants(out);
				}
			}
			Value::Equation(e) => {
				for ev in &e.values {
					ev.collect_constants(out);
				}
			}
		}
	}
}

impl Constant {
	pub(crate) fn equivalent(&self, other: &Constant) -> bool {
		self.id == other.id
	}
	pub(crate) fn is_g_or_nil(&self) -> bool {
		self.id == 0 || self.id == 1
	}
}

impl PrincipalState {
	pub(crate) fn index_of(&self, c: &Constant) -> Option<usize> {
		self.index.get(&c.id).copied().filter(|&i| i < self.meta.len())
	}
	pub(crate) fn resolve_constant(&self, c: &Constant, allow_before_mutate: bool) -> (Value, Option<usize>) {
		let i = self.index_of(c);
		match i {
			None => (Value::Constant(c.clone()), None),
			Some(idx) => {
				let value = if allow_before_mutate {
					self.effective_value(idx)
				} else {
					&self.values[idx].assigned
				};
				(value.clone(), Some(idx))
			}
		}
	}
	pub(crate) fn perform_all_rewrites(&mut self) -> Vec<(Primitive, usize)> {
		let mut failures: Vec<(Primitive, usize)> = Vec::new();
		let len = self.values.len();
		for i in 0..len {
			match &self.values[i].assigned {
				Value::Primitive(p) => {
					let p_clone = p.clone();
					let (failed, _, _) = perform_primitive_rewrite(&p_clone, Some(i), self);
					failures.extend(failed.into_iter().map(|p| (p, i)));
				}
				Value::Equation(e) => {
					let e_clone = e.clone();
					let (failed, _, _) = perform_equation_rewrite(&e_clone, Some(i), self);
					failures.extend(failed.into_iter().map(|p| (p, i)));
				}
				_ => {}
			}
		}
		failures
	}
	pub(crate) fn resolve_all_values(&mut self, as_: &AttackerState) -> VResult<()> {
		let n = self.values.len();
		let mut new_assigned = Vec::with_capacity(n);
		let mut new_before_rewrite = Vec::with_capacity(n);
		// Borrow self immutably for the resolution loop
		let ps_ref: &PrincipalState = &*self;
		for i in 0..n {
			let fbm = ps_ref.should_use_before_mutate(i);
			new_assigned.push(resolve_ps_values(
				&ps_ref.values[i].assigned,
				&ps_ref.values[i].assigned,
				i,
				ps_ref,
				as_,
				fbm,
			)?);
			new_before_rewrite.push(resolve_ps_values(
				&ps_ref.values[i].before_rewrite,
				&ps_ref.values[i].before_rewrite,
				i,
				ps_ref,
				as_,
				fbm,
			)?);
		}
		for ((sv, assigned), before_rewrite) in self
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
}

impl ProtocolTrace {
	pub(crate) fn index_of(&self, c: &Constant) -> Option<usize> {
		self.index.get(&c.id).copied()
	}
	pub(crate) fn constant_used_by(&self, principal_id: PrincipalId, c: &Constant) -> bool {
		constant_used_by_principal(self, principal_id, c)
	}
	pub(crate) fn constant_used_by_any(&self, c: &Constant) -> bool {
		if &*c.name == "nil" {
			return true;
		}
		self.principal_ids
			.iter()
			.any(|&pid| constant_used_by_principal(self, pid, c))
	}
}

impl AttackerState {
	pub(crate) fn knows(&self, v: &Value) -> Option<usize> {
		let h = v.hash_value();
		if let Some(indices) = self.known_map.get(&h) {
			for &i in indices {
				if v.equivalent(&self.known[i], true) {
					return Some(i);
				}
			}
		}
		None
	}
}
