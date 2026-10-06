/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub(crate) mod equivalence;
pub(crate) mod hashing;

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use crate::primitive::Capabilities;
use crate::syntax::{Declaration, Qualifier};
use crate::util::{IdHasher, IdSet};
use equivalence::{equivalent_primitives, memoised_pair};
use hashing::primitive_hash;

pub type ValueId = u32;

pub type PrimitiveId = u8;

#[derive(Clone, Debug)]
pub enum Value {
	Constant(Constant),
	Primitive(Arc<Primitive>),
	Variable(VariableId),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VariableId {
	Slot(usize),
	Free(Arc<str>),
}

impl Value {
	pub fn primitive(id: PrimitiveId, arguments: Vec<Value>, output: usize) -> Value {
		Value::Primitive(Arc::new(Primitive::new(id, arguments, output)))
	}

	pub fn as_constant(&self) -> Option<&Constant> {
		match self {
			Value::Constant(c) => Some(c),
			_ => None,
		}
	}

	pub fn as_primitive(&self) -> Option<&Primitive> {
		match self {
			Value::Primitive(p) => Some(p),
			_ => None,
		}
	}

	pub fn equivalent(&self, other: &Value, consider_output: bool) -> bool {
		match (self, other) {
			(Value::Constant(c1), Value::Constant(c2)) => c1.id == c2.id,
			(Value::Variable(a), Value::Variable(b)) => a == b,
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
			(Value::Variable(a), Value::Variable(b)) => a == b,
			(Value::Primitive(p1), Value::Primitive(p2)) => Arc::ptr_eq(p1, p2),
			_ => false,
		}
	}

	pub fn hash_value(&self) -> u64 {
		match self {
			Value::Constant(c) => c.id as u64,
			Value::Primitive(p) => primitive_hash(p),
			Value::Variable(id) => {
				use std::hash::{Hash, Hasher};
				let mut hash = IdHasher::default();
				id.hash(&mut hash);
				hash.finish()
			}
		}
	}

	pub(crate) fn constant_leaves(&self) -> impl Iterator<Item = &Constant> {
		subterms(self).filter_map(Value::as_constant)
	}
}

#[derive(Clone, Debug, Default)]
pub struct Constant {
	pub name: Arc<str>,
	pub id: ValueId,
	pub guard: bool,
	pub fresh: bool,
	pub leaked: bool,
	pub declaration: Option<Declaration>,
	pub qualifier: Option<Qualifier>,
}

impl Constant {
	pub fn equivalent(&self, other: &Constant) -> bool {
		self.id == other.id
	}

	pub fn is_nil(&self) -> bool {
		self.id == 1
	}
}

#[derive(Debug, Default)]
pub struct HashCell(
	AtomicU64,
	AtomicU8,
	std::sync::OnceLock<Box<(bool, Option<Value>)>>,
);

impl Clone for HashCell {
	fn clone(&self) -> Self {
		HashCell(
			AtomicU64::new(self.0.load(Ordering::Relaxed)),
			AtomicU8::new(self.1.load(Ordering::Relaxed)),
			std::sync::OnceLock::new(),
		)
	}
}

impl HashCell {
	pub fn get(&self) -> Option<u64> {
		match self.0.load(Ordering::Relaxed) {
			0 => None,
			cached => Some(cached),
		}
	}

	pub fn set(&self, hash: u64) {
		self.0.store(hash, Ordering::Relaxed);
	}

	pub(crate) fn reduct(&self) -> Option<&(bool, Option<Value>)> {
		self.2.get().map(AsRef::as_ref)
	}

	pub(crate) fn set_reduct(&self, reduct: (bool, Option<Value>)) -> &(bool, Option<Value>) {
		self.2.get_or_init(|| Box::new(reduct))
	}

	pub fn has_variables(&self) -> Option<bool> {
		match self.1.load(Ordering::Relaxed) {
			0 => None,
			1 => Some(false),
			_ => Some(true),
		}
	}

	pub fn set_has_variables(&self, has: bool) {
		self.1.store(if has { 2 } else { 1 }, Ordering::Relaxed);
	}
}

#[derive(Clone, Debug)]
pub struct Primitive {
	pub id: PrimitiveId,
	pub arguments: Vec<Value>,
	pub output: usize,
	pub threshold: usize,
	pub instance: ValueId,
	pub instance_check: bool,
	pub capabilities: Capabilities,
	pub hash: HashCell,
}

impl Primitive {
	pub fn new(id: PrimitiveId, arguments: Vec<Value>, output: usize) -> Self {
		Primitive {
			id,
			arguments,
			output,
			threshold: 0,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		}
	}

	pub fn with_arguments(&self, arguments: Vec<Value>) -> Self {
		Primitive {
			id: self.id,
			arguments,
			output: self.output,
			threshold: self.threshold,
			instance: self.instance,
			instance_check: self.instance_check,
			capabilities: self.capabilities,
			hash: HashCell::default(),
		}
	}

	pub fn with_output(&self, output: usize) -> Self {
		Primitive {
			id: self.id,
			arguments: self.arguments.clone(),
			output,
			threshold: self.threshold,
			instance: self.instance,
			instance_check: self.instance_check,
			capabilities: self.capabilities,
			hash: HashCell::default(),
		}
	}

	pub fn map_arguments(&self, mut f: impl FnMut(&Value) -> Option<Value>) -> Option<Primitive> {
		let mut changed: Option<Vec<Value>> = None;
		for (i, a) in self.arguments.iter().enumerate() {
			if let Some(mapped) = f(a) {
				changed.get_or_insert_with(|| self.arguments.clone())[i] = mapped;
			}
		}
		changed.map(|arguments| self.with_arguments(arguments))
	}
}

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

pub(crate) const COPY_BASE: ValueId = 0x0400_0000;

pub(crate) const COPY_STRIDE: ValueId = 0x0400_0000;

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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::*;
	use crate::testing::*;

	#[test]
	fn value_accessors() {
		let c = make_constant("acc_c");
		let p = make_primitive(PRIM_HASH, vec![c.clone()], 0);

		assert!(c.as_constant().is_some());
		assert!(c.as_primitive().is_none());

		assert!(p.as_primitive().is_some());
		assert!(p.as_constant().is_none());
	}

	#[test]
	fn primitive_with_arguments() {
		let a = make_constant("pwa_a");
		let b = make_constant("pwa_b");
		let p = Primitive {
			id: PRIM_ENC,
			arguments: vec![a],
			output: 0,
			instance: 0,
			instance_check: true,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let p2 = p.with_arguments(vec![b.clone()]);
		assert_eq!(p2.id, PRIM_ENC);
		assert_eq!(p2.output, 0);
		assert!(p2.instance_check);
		assert!(p2.arguments[0].equivalent(&b, true));
	}

	#[test]
	fn every_expansion_copy_id_is_distinct() {
		let bases: [ValueId; 4] = [2, 3, 4096, COPY_STRIDE - 1];
		let mut seen: std::collections::HashSet<ValueId> = std::collections::HashSet::new();
		for base in bases {
			assert!(seen.insert(base), "interned base {base} repeated");
		}
		for copy in 1..=MAX_COPIES {
			for base in bases {
				let id = copy_value_id(base, copy);
				assert!(seen.insert(id), "copy {copy} of {base} collides");
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
