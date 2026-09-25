/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use crate::equivalence::{equivalent_primitives, memoised_pair};
use crate::hashing::primitive_hash;
use crate::types::*;

pub(crate) use crate::resolution::{resolve_trace_constant, resolve_trace_term};

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

const COPY_STRIDE: ValueId = 0x0400_0000;

pub(crate) const MAX_COPIES: u32 = 30;

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

pub(crate) fn push_unique_value(values: &mut Vec<Value>, v: Value) {
	if !values.iter().any(|existing| v.equivalent(existing, true)) {
		values.push(v);
	}
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
}

impl Constant {
	pub fn equivalent(&self, other: &Constant) -> bool {
		self.id == other.id
	}
	pub fn is_nil(&self) -> bool {
		self.id == 1
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
		let derivations = self
			.derivations
			.iter()
			.zip(keep.iter())
			.filter(|&(_, &keep)| keep)
			.map(|(d, _)| d.clone())
			.collect();
		Some(Arc::new(AttackerState {
			current_phase: self.current_phase,
			derivations: Arc::new(derivations),
			reused: Arc::clone(&self.reused),
			known: Arc::new(known),
			known_map: Arc::new(known_map),
			chain: crate::types::next_chain(),
		}))
	}

	pub fn derivation(&self, idx: KnownIdx) -> Option<&DerivationRecord> {
		self.derivations.get(idx.get())
	}

	pub fn knows(&self, v: &Value) -> Option<KnownIdx> {
		self.knows_hashed(v, v.hash_value())
	}

	pub fn knows_hashed(&self, v: &Value, h: u64) -> Option<KnownIdx> {
		self.known_map
			.get(&h)?
			.iter()
			.find(|&&i| v.equivalent(&self.known[i], true))
			.map(|&i| KnownIdx(i))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::*;
	use crate::testutil::*;

	#[test]
	fn session_bands_stay_below_the_solver_ranges() {
		let worst = COPY_BASE + MAX_COPIES * COPY_STRIDE + (COPY_STRIDE - 1);
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
	fn push_unique_no_duplicates() {
		let a = make_constant("push_a");
		let b = make_constant("push_b");
		let mut v = vec![];
		push_unique_value(&mut v, a.clone());
		push_unique_value(&mut v, b);
		push_unique_value(&mut v, make_constant("push_a"));
		assert_eq!(v.len(), 2);
		assert!(v[0].equivalent(&a, true));
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
	fn trace_index_of() {
		let a = make_constant("ps_idx_a");
		let km = make_trace(vec![make_trace_slot(&a, &a, 0)]);
		assert_eq!(km.index_of(a.as_constant().unwrap()), Some(0));
		let other = make_constant("ps_idx_b");
		assert_eq!(km.index_of(other.as_constant().unwrap()), None);
	}

	#[test]
	fn constant_leaves_preserve_order_without_expanding_shared_subtrees() {
		let a = make_constant("constant_leaves_a");
		let b = make_constant("constant_leaves_b");
		let mut term = make_primitive(PRIM_HASH, vec![a.clone(), a.clone(), b.clone()], 0);
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
}
