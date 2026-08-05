/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use crate::equivalence::{equivalent_equations, equivalent_primitives};
use crate::hashing::{equation_hash, primitive_hash};
use crate::resolution::constant_used_by_principal;
use crate::rewrite::{perform_equation_rewrite, perform_primitive_rewrite};
use crate::types::*;

pub(crate) use crate::equivalence::find_constant_in_trace_primitive;
pub(crate) use crate::resolution::{
	resolve_ps_values, resolve_trace_values, value_constant_contains_fresh_values,
};

/// Per-model constant name to [`ValueId`] table, owned by the parser.
///
/// Ids only ever need to be unique *within* one model, since every comparison
/// happens between values of the same run. Interning per model also keeps the
/// ids small and makes analyses independent of each other.
pub(crate) struct ValueNames {
	map: HashMap<Arc<str>, ValueId>,
	counter: ValueId,
}

impl Default for ValueNames {
	fn default() -> Self {
		Self::new()
	}
}

impl ValueNames {
	pub(crate) fn new() -> Self {
		let mut map = HashMap::new();
		map.insert(Arc::from("g"), 0);
		map.insert(Arc::from("nil"), 1);
		ValueNames { map, counter: 2 }
	}

	/// Ids must stay below the ranges `solve::vars` reserves for its variables.
	pub(crate) fn intern(&mut self, name: &str) -> VResult<ValueId> {
		if let Some(&id) = self.map.get(name) {
			return Ok(id);
		}
		if self.counter >= crate::solve::vars::ATTACKER_VAR_BASE {
			return Err(VerifpalError::sanity(
				"model declares too many distinct constants".into(),
			));
		}
		let id = self.counter;
		self.map.insert(Arc::from(name), id);
		self.counter += 1;
		Ok(id)
	}
}

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

pub(crate) fn value_g() -> Value {
	STATIC_G.clone()
}

pub(crate) fn value_nil() -> Value {
	STATIC_NIL.clone()
}

pub(crate) fn value_g_nil() -> Value {
	STATIC_G_NIL.clone()
}

pub(crate) fn find_equivalent(v: &Value, values: &[Value]) -> Option<usize> {
	values
		.iter()
		.position(|existing| v.equivalent(existing, true))
}

pub(crate) fn push_unique_value(values: &mut Vec<Value>, v: Value) -> bool {
	if find_equivalent(&v, values).is_none() {
		values.push(v);
		true
	} else {
		false
	}
}

pub(crate) fn find_equivalent_constant(c: &Constant, constants: &[Constant]) -> Option<usize> {
	constants.iter().position(|existing| c.equivalent(existing))
}

/// The slots that differ from the protocol trace, for the forensic record.
pub(crate) fn compute_slot_diffs(
	ps: &PrincipalState,
	trace: &ProtocolTrace,
	phase: i32,
) -> Arc<MutationRecord> {
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
					index: SlotIdx(i),
					constant: sm.constant.clone(),
					value: sv.value.clone(),
					tainted: sv.provenance.attacker_tainted || sv.provenance.bypass_injected,
				})
			}
		})
		.collect();
	Arc::new(MutationRecord {
		diffs,
		principal_id: ps.id,
		phase,
	})
}

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
	pub fn resolve_constant(&self, c: &Constant, allow_original: bool) -> (Value, Option<usize>) {
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
		for ((sv, value), pre_rewrite) in self.values.iter_mut().zip(new_value).zip(new_pre_rewrite)
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
	pub fn principal_name(&self, id: PrincipalId) -> &str {
		if id == crate::principal::ATTACKER_ID {
			return crate::principal::ATTACKER_NAME;
		}
		self.principal_ids
			.iter()
			.position(|&p| p == id)
			.and_then(|i| self.principals.get(i))
			.map(String::as_str)
			.unwrap_or("")
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
	pub fn derivation(&self, idx: KnownIdx) -> Option<&DerivationRecord> {
		self.derivations.get(idx.get())
	}
	pub fn record(&self, idx: KnownIdx) -> Option<&Arc<MutationRecord>> {
		self.mutation_records.get(idx.get())
	}
	pub fn value(&self, idx: KnownIdx) -> Option<&Value> {
		self.known.get(idx.get())
	}
	pub fn knows(&self, v: &Value) -> Option<KnownIdx> {
		let h = v.hash_value();
		if let Some(indices) = self.known_map.get(&h) {
			for &i in indices {
				if v.equivalent(&self.known[i], true) {
					return Some(KnownIdx(i));
				}
			}
		}
		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::*;
	use crate::testutil::*;
	use std::sync::Arc;

	#[test]
	fn name_map_idempotent() {
		let id1 = test_value_id("name_map_test_xyz");
		let id2 = test_value_id("name_map_test_xyz");
		assert_eq!(id1, id2);
	}

	#[test]
	fn name_map_unique() {
		let id1 = test_value_id("name_map_unique_a");
		let id2 = test_value_id("name_map_unique_b");
		assert_ne!(id1, id2);
	}

	#[test]
	fn find_equivalent_in_slice() {
		let a = make_constant("find_a");
		let b = make_constant("find_b");
		let c = make_constant("find_a"); // same as a
		let slice = vec![a.clone(), b.clone()];
		assert_eq!(find_equivalent(&c, &slice), Some(0));
		let d = make_constant("find_d");
		assert_eq!(find_equivalent(&d, &slice), None);
	}

	#[test]
	fn push_unique_no_duplicates() {
		let a = make_constant("push_a");
		let b = make_constant("push_b");
		let mut v = vec![];
		assert!(push_unique_value(&mut v, a.clone()));
		assert!(push_unique_value(&mut v, b));
		assert!(!push_unique_value(&mut v, a)); // duplicate
		assert_eq!(v.len(), 2);
	}

	#[test]
	fn constant_is_g_or_nil() {
		let g = value_g();
		let nil = value_nil();
		let other = make_constant("not_g_or_nil");
		assert!(g.as_constant().unwrap().is_g_or_nil());
		assert!(nil.as_constant().unwrap().is_g_or_nil());
		assert!(!other.as_constant().unwrap().is_g_or_nil());
	}

	#[test]
	fn attacker_knows_value() {
		let a = make_constant("ak_a");
		let b = make_constant("ak_b");
		let c = make_constant("ak_c");
		let attacker = make_attacker_state(vec![a.clone(), b.clone()]);
		assert!(attacker.knows(&a).is_some());
		assert!(attacker.knows(&b).is_some());
		assert!(attacker.knows(&c).is_none());
	}

	#[test]
	fn attacker_knows_equation() {
		let a = make_constant("ake_a");
		let eq = make_equation(vec![value_g(), a]);
		let attacker = make_attacker_state(vec![eq.clone()]);
		assert!(attacker.knows(&eq).is_some());
	}

	#[test]
	fn principal_state_index_of() {
		let c = Constant {
			name: Arc::from("ps_idx_a"),
			id: test_value_id("ps_idx_a"),
			..Constant::default()
		};
		let meta = vec![make_slot_meta(&c, true)];
		let values = vec![make_slot_values(&make_constant("ps_idx_a"), 0)];
		let ps = make_principal_state("Alice", 0, meta, values);
		assert_eq!(ps.index_of(&c), Some(0));

		let other = Constant {
			name: Arc::from("ps_idx_b"),
			id: test_value_id("ps_idx_b"),
			..Constant::default()
		};
		assert_eq!(ps.index_of(&other), None);
	}

	#[test]
	fn collect_constants_from_primitive() {
		let a = make_constant("cc_a");
		let b = make_constant("cc_b");
		let p = make_primitive(PRIM_ENC, vec![a, b], 0);
		let mut out = Vec::new();
		p.collect_constants(&mut out);
		assert_eq!(out.len(), 2);
	}

	#[test]
	fn collect_constants_from_equation() {
		let a = make_constant("cce_a");
		let eq = make_equation(vec![value_g(), a]);
		let mut out = Vec::new();
		eq.collect_constants(&mut out);
		assert_eq!(out.len(), 2); // g and a
	}

	#[test]
	fn compute_slot_diffs_no_changes() {
		let c = Constant {
			name: Arc::from("csd_a"),
			id: test_value_id("csd_a"),
			..Constant::default()
		};
		let val = make_constant("csd_a");
		let trace = ProtocolTrace {
			principals: vec!["Alice".to_string()],
			principal_ids: vec![0],
			slots: vec![TraceSlot {
				constant: c.clone(),
				initial_value: val.clone(),
				creator: 0,
				known_by: vec![],
				declared_at: 0,
				phases: vec![0],
			}],
			index: {
				let mut m = HashMap::new();
				m.insert(c.id, 0);
				m
			},
			max_declared_at: 0,
			max_phase: 0,
			used_by: HashMap::new(),
			leaks: Arc::new(Vec::new()),
		};
		let meta = vec![make_slot_meta(&c, true)];
		let values = vec![make_slot_values(&val, 0)];
		let ps = make_principal_state("Alice", 0, meta, values);
		let record = compute_slot_diffs(&ps, &trace, 0);
		assert!(record.diffs.is_empty());
	}

	#[test]
	fn compute_slot_diffs_with_changes() {
		let c = Constant {
			name: Arc::from("csd2_a"),
			id: test_value_id("csd2_a"),
			..Constant::default()
		};
		let original = make_constant("csd2_a");
		let mutated = make_constant("csd2_mutated");
		let trace = ProtocolTrace {
			principals: vec!["Alice".to_string()],
			principal_ids: vec![0],
			slots: vec![TraceSlot {
				constant: c.clone(),
				initial_value: original.clone(),
				creator: 0,
				known_by: vec![],
				declared_at: 0,
				phases: vec![0],
			}],
			index: {
				let mut m = HashMap::new();
				m.insert(c.id, 0);
				m
			},
			max_declared_at: 0,
			max_phase: 0,
			used_by: HashMap::new(),
			leaks: Arc::new(Vec::new()),
		};
		let meta = vec![make_slot_meta(&c, true)];
		let mut sv = make_slot_values(&mutated, 0);
		sv.provenance.attacker_tainted = true;
		let ps = make_principal_state("Alice", 0, meta, vec![sv]);
		let record = compute_slot_diffs(&ps, &trace, 0);
		assert_eq!(record.diffs.len(), 1);
		assert_eq!(record.diffs[0].index, SlotIdx(0));
		assert!(record.diffs[0].tainted);
	}

	#[test]
	fn slot_diffs_record_principal_and_phase() {
		let c = Constant {
			name: Arc::from("mrp_a"),
			id: test_value_id("mrp_a"),
			..Constant::default()
		};
		let val = make_constant("mrp_a");
		let trace = ProtocolTrace {
			principals: vec!["Bob".to_string()],
			principal_ids: vec![3],
			slots: vec![TraceSlot {
				constant: c.clone(),
				initial_value: val.clone(),
				creator: 3,
				known_by: vec![],
				declared_at: 0,
				phases: vec![0],
			}],
			index: {
				let mut m = HashMap::new();
				m.insert(c.id, 0);
				m
			},
			max_declared_at: 0,
			max_phase: 0,
			used_by: HashMap::new(),
			leaks: Arc::new(Vec::new()),
		};
		let meta = vec![make_slot_meta(&c, true)];
		let values = vec![make_slot_values(&val, 3)];
		let ps = make_principal_state("Bob", 3, meta, values);
		let record = compute_slot_diffs(&ps, &trace, 2);
		assert_eq!(record.principal_id, 3);
		assert_eq!(record.phase, 2);
	}
}
