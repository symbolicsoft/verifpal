/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use crate::equivalence::{equivalent_equations, equivalent_primitives};
use crate::hashing::{equation_hash, primitive_hash};
use crate::resolution::constant_used_by_principal;
use crate::rewrite::{perform_equation_rewrite, perform_primitive_rewrite};
use crate::types::*;

pub use crate::equivalence::find_constant_in_trace_primitive;
pub use crate::resolution::{
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
	let mut state = VALUE_NAMES_STATE.lock().unwrap_or_else(|e| e.into_inner());
	if let Some(&id) = state.map.get(name) {
		return id;
	}
	let id = state.counter;
	state.map.insert(Arc::from(name), id);
	state.counter += 1;
	id
}

pub fn value_names_reset() {
	let mut state = VALUE_NAMES_STATE.lock().unwrap_or_else(|e| e.into_inner());
	state.map.clear();
	state.map.insert(Arc::from("g"), 0);
	state.map.insert(Arc::from("nil"), 1);
	state.counter = 2;
}

// ---------------------------------------------------------------------------
// Search in value slices
// ---------------------------------------------------------------------------

pub fn find_equivalent(v: &Value, values: &[Value]) -> Option<usize> {
	values
		.iter()
		.position(|existing| v.equivalent(existing, true))
}

/// Push `v` into `values` if no equivalent value already exists. Returns true if pushed.
pub fn push_unique_value(values: &mut Vec<Value>, v: Value) -> bool {
	if find_equivalent(&v, values).is_none() {
		values.push(v);
		true
	} else {
		false
	}
}

pub fn find_equivalent_constant(c: &Constant, constants: &[Constant]) -> Option<usize> {
	constants.iter().position(|existing| c.equivalent(existing))
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
			if sv.pre_rewrite.equivalent(&slot.initial_value, false) {
				None
			} else {
				Some(SlotDiff {
					index: i,
					constant: sm.constant.clone(),
					value: sv.value.clone(),
					tainted: sv.provenance.attacker_tainted,
				})
			}
		})
		.collect();
	MutationRecord { diffs }
}

// ---------------------------------------------------------------------------
// Impl methods on core types
// ---------------------------------------------------------------------------

impl Value {
	pub fn equivalent(&self, other: &Value, consider_output: bool) -> bool {
		match (self, other) {
			(Value::Constant(c1), Value::Constant(c2)) => c1.id == c2.id,
			(Value::Primitive(p1), Value::Primitive(p2)) => {
				equivalent_primitives(p1, p2, consider_output).equivalent
			}
			(Value::Equation(e1), Value::Equation(e2)) => equivalent_equations(e1, e2),
			_ => false,
		}
	}
	pub fn hash_value(&self) -> u64 {
		match self {
			Value::Constant(c) => c.id as u64,
			Value::Primitive(p) => primitive_hash(p),
			Value::Equation(e) => equation_hash(e),
		}
	}
	pub fn collect_constants(&self, out: &mut Vec<Constant>) {
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
	pub fn equivalent(&self, other: &Constant) -> bool {
		self.id == other.id
	}
	pub fn is_g_or_nil(&self) -> bool {
		self.id == 0 || self.id == 1
	}
}

impl PrincipalState {
	pub fn index_of(&self, c: &Constant) -> Option<usize> {
		self.index
			.get(&c.id)
			.copied()
			.filter(|&i| i < self.meta.len())
	}
	pub fn resolve_constant(
		&self,
		c: &Constant,
		allow_original: bool,
	) -> (Value, Option<usize>) {
		let i = self.index_of(c);
		match i {
			None => (Value::Constant(c.clone()), None),
			Some(idx) => {
				let value = if allow_original {
					self.effective_value(idx)
				} else {
					&self.values[idx].value
				};
				(value.clone(), Some(idx))
			}
		}
	}
	pub fn perform_all_rewrites(&mut self) -> Vec<(Primitive, usize)> {
		let mut failures: Vec<(Primitive, usize)> = Vec::new();
		let len = self.values.len();
		for i in 0..len {
			match &self.values[i].value {
				Value::Primitive(p) => {
					let p_clone = p.clone();
					let r = perform_primitive_rewrite(&p_clone, Some(i), self);
					failures.extend(r.failed_rewrites.into_iter().map(|p| (p, i)));
				}
				Value::Equation(e) => {
					let e_clone = e.clone();
					let r = perform_equation_rewrite(&e_clone, Some(i), self);
					failures.extend(r.failed_rewrites.into_iter().map(|p| (p, i)));
				}
				_ => {}
			}
		}
		failures
	}
	pub fn resolve_all_values(&mut self, attacker: &AttackerState) -> VResult<()> {
		let n = self.values.len();
		let mut new_value = Vec::with_capacity(n);
		let mut new_pre_rewrite = Vec::with_capacity(n);
		// Borrow self immutably for the resolution loop
		let ps_ref: &PrincipalState = &*self;
		for i in 0..n {
			let use_original = ps_ref.should_use_original(i);
			new_value.push(resolve_ps_values(
				&ps_ref.values[i].value,
				&ps_ref.values[i].value,
				i,
				ps_ref,
				attacker,
				use_original,
			)?);
			new_pre_rewrite.push(resolve_ps_values(
				&ps_ref.values[i].pre_rewrite,
				&ps_ref.values[i].pre_rewrite,
				i,
				ps_ref,
				attacker,
				use_original,
			)?);
		}
		for ((sv, value), pre_rewrite) in self
			.values
			.iter_mut()
			.zip(new_value)
			.zip(new_pre_rewrite)
		{
			sv.value = value;
			sv.pre_rewrite = pre_rewrite;
			sv.rewritten = false;
		}
		Ok(())
	}
}

impl ProtocolTrace {
	pub fn index_of(&self, c: &Constant) -> Option<usize> {
		self.index.get(&c.id).copied()
	}
	pub fn constant_used_by(&self, principal_id: PrincipalId, c: &Constant) -> bool {
		constant_used_by_principal(self, principal_id, c)
	}
	pub fn constant_used_by_any(&self, c: &Constant) -> bool {
		if &*c.name == "nil" {
			return true;
		}
		self.principal_ids
			.iter()
			.any(|&pid| constant_used_by_principal(self, pid, c))
	}
}

impl AttackerState {
	pub fn knows(&self, v: &Value) -> Option<usize> {
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
