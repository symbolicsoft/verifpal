/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use crate::equivalence::{equivalent_primitives, memoised_pair};
use crate::hashing::primitive_hash;
use crate::resolution::constant_used_by_principal;
use crate::rewrite::perform_primitive_rewrite;
use crate::types::*;

pub(crate) use crate::resolution::{
	ResolveMemo, resolve_ps_values, resolve_trace_constant, resolve_trace_term,
	value_constant_contains_fresh_values,
};

pub(crate) fn subterms(v: &Value) -> impl Iterator<Item = &Value> {
	let mut seen = IdSet::default();
	let mut pending = vec![v];
	std::iter::from_fn(move || {
		loop {
			let value = pending.pop()?;
			if let Value::Primitive(p) = value {
				if !seen.insert(Arc::as_ptr(p) as usize) {
					continue;
				}
				pending.extend(p.arguments.iter().rev());
			}
			return Some(value);
		}
	})
}

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
		map.insert(Arc::from("nil"), 1);
		ValueNames { map, counter: 2 }
	}

	pub(crate) fn intern(&mut self, name: &str) -> VResult<ValueId> {
		if let Some(&id) = self.map.get(name) {
			return Ok(id);
		}
		if self.counter >= COPY_STRIDE {
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

pub(crate) const COPY_BASE: ValueId = 0x0400_0000;

pub(crate) const COPY_STRIDE: ValueId = 0x0400_0000;

pub(crate) const MAX_COPIES: u32 = 30;

const MINIMIZER_BAND: ValueId = 30;

pub(crate) fn copy_value_id(base: ValueId, copy: u32) -> ValueId {
	debug_assert!((1..=MAX_COPIES).contains(&copy));
	debug_assert!(base < COPY_STRIDE);
	COPY_BASE + (copy as ValueId - 1) * COPY_STRIDE + base
}

pub(crate) fn copy_index_of(id: ValueId) -> (u32, ValueId) {
	if id < COPY_BASE {
		(0, id)
	} else {
		(
			(id - COPY_BASE) / COPY_STRIDE + 1,
			(id - COPY_BASE) % COPY_STRIDE,
		)
	}
}

pub(crate) fn session_copy(c: &Constant) -> Value {
	let base = if c.id >= COPY_BASE {
		(c.id - COPY_BASE) % COPY_STRIDE
	} else {
		c.id
	};
	Value::Constant(Constant {
		name: Arc::from(format!("{}#other", c.name)),
		id: COPY_BASE + MINIMIZER_BAND * COPY_STRIDE + base,
		..c.clone()
	})
}

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

pub(crate) fn value_nil() -> Value {
	STATIC_NIL.clone()
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
			if sv.pre_rewrite.equivalent(&slot.initial_value, true) {
				None
			} else {
				Some(SlotDiff {
					index: SlotIdx(i),
					constant: sm.constant.clone(),
					value: sv.value.clone(),
					tainted: sv.provenance.attacker_tainted || sv.provenance.bypass_injected,
					state: ps.id,
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
				if Arc::ptr_eq(p1, p2) {
					return true;
				}
				if consider_output && primitive_hash(p1) != primitive_hash(p2) {
					return false;
				}
				memoised_pair(u8::from(consider_output), p1, p2, || {
					equivalent_primitives(p1, p2, consider_output)
				})
			}
			_ => false,
		}
	}
	pub fn same_term(&self, other: &Value) -> bool {
		match (self, other) {
			(Value::Constant(c1), Value::Constant(c2)) => c1.id == c2.id,
			(Value::Primitive(p1), Value::Primitive(p2)) => Arc::ptr_eq(p1, p2),
			_ => false,
		}
	}
	pub fn hash_value(&self) -> u64 {
		match self {
			Value::Constant(c) => c.id as u64,
			Value::Primitive(p) => primitive_hash(p),
		}
	}
	pub(crate) fn constant_leaves(&self) -> impl Iterator<Item = &Constant> {
		subterms(self).filter_map(Value::as_constant)
	}
	pub fn collect_constants(&self, out: &mut Vec<Constant>) {
		match self {
			Value::Constant(c) => out.push(c.clone()),
			Value::Primitive(p) => {
				for arg in &p.arguments {
					arg.collect_constants(out);
				}
			}
		}
	}
}

impl Constant {
	pub fn equivalent(&self, other: &Constant) -> bool {
		self.id == other.id
	}
	pub fn is_nil(&self) -> bool {
		self.id == 1
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
			if let Value::Primitive(p) = &self.values[i].value {
				let p_clone = p.clone();
				let failed = perform_primitive_rewrite(&p_clone, i, self);
				failures.extend(failed.map(|p| (p, i)));
			}
		}
		failures
	}
	pub fn resolve_all_values(&mut self) -> VResult<()> {
		let n = self.values.len();
		let mut resolved = Vec::with_capacity(n);
		let mut memo = ResolveMemo::new(n);
		let ps_ref: &PrincipalState = &*self;
		for i in 0..n {
			let use_original = ps_ref.should_use_original(i);
			let sv = &ps_ref.values[i];
			let value =
				resolve_ps_values(&sv.value, &sv.value, i, ps_ref, use_original, &mut memo)?;
			let pre_rewrite = if sv.value.same_term(&sv.pre_rewrite) {
				value.clone()
			} else {
				resolve_ps_values(
					&sv.pre_rewrite,
					&sv.pre_rewrite,
					i,
					ps_ref,
					use_original,
					&mut memo,
				)?
			};
			resolved.push((value, pre_rewrite));
		}
		for (sv, (value, pre_rewrite)) in self.values.iter_mut().zip(resolved) {
			if let Some(value) = value {
				sv.value = value;
			}
			if let Some(pre_rewrite) = pre_rewrite {
				sv.pre_rewrite = pre_rewrite;
			}
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
	pub(crate) fn retaining(&self, keep: &[bool]) -> Option<Arc<AttackerState>> {
		assert_eq!(keep.len(), self.known.len());
		if keep.iter().all(|&keep| keep) {
			return None;
		}
		let known: Vec<Value> = self
			.known
			.iter()
			.zip(keep.iter())
			.filter(|&(_, &keep)| keep)
			.map(|(v, _)| v.clone())
			.collect();
		let mut known_map: IdMap<u64, Vec<usize>> = IdMap::default();
		for (i, v) in known.iter().enumerate() {
			known_map.entry(v.hash_value()).or_default().push(i);
		}
		let mutation_records = self
			.mutation_records
			.iter()
			.zip(keep.iter())
			.filter(|&(_, &keep)| keep)
			.map(|(r, _)| Arc::clone(r))
			.collect();
		let derivations = self
			.derivations
			.iter()
			.zip(keep.iter())
			.filter(|&(_, &keep)| keep)
			.map(|(d, _)| d.clone())
			.collect();
		let alternates = self
			.alternates
			.iter()
			.zip(keep.iter())
			.filter(|&(_, &keep)| keep)
			.map(|(d, _)| d.clone())
			.collect();
		Some(Arc::new(AttackerState {
			current_phase: self.current_phase,
			mutation_records: Arc::new(mutation_records),
			derivations: Arc::new(derivations),
			alternates: Arc::new(alternates),
			reused: Arc::clone(&self.reused),
			known: Arc::new(known),
			known_map: Arc::new(known_map),
			routes_epoch: self.routes_epoch,
			chain: crate::types::next_chain(),
		}))
	}

	pub fn derivation(&self, idx: KnownIdx) -> Option<&DerivationRecord> {
		self.derivations.get(idx.get())
	}

	pub fn routes(
		&self,
		idx: KnownIdx,
	) -> impl Iterator<Item = (&DerivationRecord, Option<&Arc<MutationRecord>>)> {
		self.derivations
			.get(idx.get())
			.map(|primary| (primary, self.mutation_records.get(idx.get())))
			.into_iter()
			.chain(
				self.alternates
					.get(idx.get())
					.into_iter()
					.flatten()
					.map(|(route, record)| (route, Some(record))),
			)
	}
	pub fn record(&self, idx: KnownIdx) -> Option<&Arc<MutationRecord>> {
		self.mutation_records.get(idx.get())
	}
	pub fn knows(&self, v: &Value) -> Option<KnownIdx> {
		self.knows_hashed(v, v.hash_value())
	}

	pub fn knows_hashed(&self, v: &Value, h: u64) -> Option<KnownIdx> {
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
	fn filtering_knowledge_preserves_routes_and_invalidates_its_chain() {
		let values: Vec<Value> = ["retained_a", "retained_b", "retained_c"]
			.map(make_constant)
			.into();
		let mut attacker = make_attacker_state(values.clone());
		attacker.current_phase = 3;
		attacker.routes_epoch = 7;
		for i in 0..values.len() {
			let derivation = DerivationRecord::Obtained {
				slot: SlotIdx(i + 4),
			};
			Arc::make_mut(&mut attacker.derivations)[i] = derivation.clone();
			Arc::make_mut(&mut attacker.alternates)[i]
				.push((derivation, Arc::clone(&attacker.mutation_records[i])));
		}
		Arc::make_mut(&mut attacker.reused).push([values[0].clone(), values[2].clone()]);
		assert!(attacker.retaining(&[true; 3]).is_none());
		let retained = attacker.retaining(&[false, true, true]).unwrap();
		assert_eq!(retained.current_phase, 3);
		assert_eq!(retained.routes_epoch, 7);
		assert_ne!(retained.chain, attacker.chain);
		assert!(retained.knows(&values[0]).is_none());
		assert!(Arc::ptr_eq(&retained.reused, &attacker.reused));
		for (i, value) in values.iter().enumerate().skip(1) {
			let idx = retained.knows(value).unwrap();
			assert_eq!(idx.get(), i - 1);
			assert!(
				matches!(retained.derivation(idx), Some(DerivationRecord::Obtained { slot }) if slot.get() == i + 4)
			);
			assert!(Arc::ptr_eq(
				retained.record(idx).unwrap(),
				attacker.record(KnownIdx(i)).unwrap()
			));
			assert_eq!(retained.routes(idx).count(), 2);
		}
		let empty = attacker.retaining(&[false; 3]).unwrap();
		assert!(empty.known.is_empty());
		assert!(empty.known_map.is_empty());
		assert!(empty.derivations.is_empty());
		assert!(empty.mutation_records.is_empty());
		assert!(empty.alternates.is_empty());
	}

	#[test]
	fn session_bands_stay_below_the_solver_ranges() {
		let worst = COPY_BASE + MINIMIZER_BAND * COPY_STRIDE + (COPY_STRIDE - 1);
		assert!(worst < crate::solve::vars::ATTACKER_VAR_BASE);
	}

	#[test]
	fn every_expansion_copy_id_is_distinct_and_below_the_solver_ranges() {
		let bases: [ValueId; 4] = [2, 3, 4096, COPY_STRIDE - 1];
		let mut seen: std::collections::HashSet<ValueId> = std::collections::HashSet::new();
		for base in bases {
			assert!(seen.insert(base), "interned base {base} repeated");
		}
		for copy in 1..=MAX_COPIES {
			for base in bases {
				let id = copy_value_id(base, copy);
				assert!(seen.insert(id), "copy {copy} of {base} collides");
				assert!(
					id < crate::solve::vars::ATTACKER_VAR_BASE,
					"copy {copy} of {base} reaches the solver ranges"
				);
			}
		}
		for base in bases {
			let c = Constant {
				name: Arc::from("cpy_x"),
				id: base,
				..Constant::default()
			};
			let id = session_copy(&c).as_constant().expect("constant").id;
			assert!(seen.insert(id), "minimizer copy of {base} collides");
			assert!(id < crate::solve::vars::ATTACKER_VAR_BASE);
		}
	}

	#[test]
	fn session_copy_of_a_session_clone_stays_out_of_solver_ranges() {
		let clone_id = copy_value_id(42, 4);
		let c = Constant {
			name: Arc::from("scb_x#5"),
			id: clone_id,
			..Constant::default()
		};
		let copied = session_copy(&c);
		let id = copied.as_constant().expect("constant").id;
		assert!(id < crate::solve::vars::ATTACKER_VAR_BASE);
		assert_eq!(id, COPY_BASE + MINIMIZER_BAND * COPY_STRIDE + 42);
	}

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
		let c = make_constant("find_a");
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
		assert!(!push_unique_value(&mut v, a));
		assert_eq!(v.len(), 2);
	}

	#[test]
	fn constant_is_nil() {
		let nil = value_nil();
		let other = make_constant("not_nil");
		assert!(nil.as_constant().unwrap().is_nil());
		assert!(!other.as_constant().unwrap().is_nil());
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
	fn constant_leaves_preserve_order_without_expanding_shared_subtrees() {
		let a = make_constant("constant_leaves_a");
		let b = make_constant("constant_leaves_b");
		let mut term = make_primitive(PRIM_HASH, vec![a.clone(), a.clone(), b.clone()], 0);
		let mut occurrences = Vec::new();
		term.collect_constants(&mut occurrences);
		assert_eq!(occurrences.len(), 3);
		for _ in 0..40 {
			term = make_primitive(PRIM_HASH, vec![term.clone(), term.clone(), term], 0);
		}
		let leaves: Vec<_> = term.constant_leaves().map(|c| c.id).collect();
		assert_eq!(
			leaves,
			vec![
				a.as_constant().unwrap().id,
				a.as_constant().unwrap().id,
				b.as_constant().unwrap().id
			]
		);
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
				declared_span: Span::default(),
				constant: c.clone(),
				initial_value: val.clone(),
				creator: 0,
				known_by: vec![],
				sent_by: vec![],
				declared_at: 0,
				phases: vec![0],
			}],
			index: {
				let mut m = IdMap::default();
				m.insert(c.id, 0);
				m
			},
			max_phase: 0,
			used_by: IdMap::default(),
			leaks: Arc::new(Vec::new()),
			session_siblings: IdMap::default(),
			copy_siblings: IdMap::default(),
			interchangeable: IdMap::default(),
			actors: IdMap::default(),
			scenario_bound: IdSet::default(),
			equivalence_queried: IdSet::default(),
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
				declared_span: Span::default(),
				constant: c.clone(),
				initial_value: original.clone(),
				creator: 0,
				known_by: vec![],
				sent_by: vec![],
				declared_at: 0,
				phases: vec![0],
			}],
			index: {
				let mut m = IdMap::default();
				m.insert(c.id, 0);
				m
			},
			max_phase: 0,
			used_by: IdMap::default(),
			leaks: Arc::new(Vec::new()),
			session_siblings: IdMap::default(),
			copy_siblings: IdMap::default(),
			interchangeable: IdMap::default(),
			actors: IdMap::default(),
			scenario_bound: IdSet::default(),
			equivalence_queried: IdSet::default(),
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
				declared_span: Span::default(),
				constant: c.clone(),
				initial_value: val.clone(),
				creator: 3,
				known_by: vec![],
				sent_by: vec![],
				declared_at: 0,
				phases: vec![0],
			}],
			index: {
				let mut m = IdMap::default();
				m.insert(c.id, 0);
				m
			},
			max_phase: 0,
			used_by: IdMap::default(),
			leaks: Arc::new(Vec::new()),
			session_siblings: IdMap::default(),
			copy_siblings: IdMap::default(),
			interchangeable: IdMap::default(),
			actors: IdMap::default(),
			scenario_bound: IdSet::default(),
			equivalence_queried: IdSet::default(),
		};
		let meta = vec![make_slot_meta(&c, true)];
		let values = vec![make_slot_values(&val, 3)];
		let ps = make_principal_state("Bob", 3, meta, values);
		let record = compute_slot_diffs(&ps, &trace, 2);
		assert_eq!(record.principal_id, 3);
		assert_eq!(record.phase, 2);
	}
}
