/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::{Constant, Primitive, Value};
use crate::util::IdMap;
use crate::util::generation::{AnalysisKey, AnalysisLocal};

pub(crate) fn primitive_hash(p: &Primitive) -> u64 {
	if let Some(cached) = p.cache().get() {
		return cached;
	}
	let computed = primitive_hash_at_output(p, p.output);
	p.cache().set(computed);
	computed
}

pub(crate) fn primitive_hash_at_output(p: &Primitive, output: usize) -> u64 {
	let base = (p.id as u64).wrapping_mul(2654435761)
		^ (output as u64).wrapping_mul(97)
		^ (p.threshold as u64).wrapping_mul(1000003)
		^ (p.instance as u64).wrapping_mul(0x9E37_79B1);
	if let Some((inner, bare)) = crate::primitive::commutativity_parts_ref(p) {
		let mut h1 = inner.hash_value();
		let mut h2 = bare.hash_value();
		if h1 > h2 {
			std::mem::swap(&mut h1, &mut h2);
		}
		return base
			.wrapping_mul(31)
			.wrapping_add(h1.wrapping_mul(17))
			.wrapping_add(h2);
	}
	let mut h = base;
	for a in &p.arguments {
		h = h.wrapping_mul(31).wrapping_add(a.hash_value());
	}
	h
}

thread_local! {
	static TERMS: AnalysisLocal<Interner> = AnalysisLocal::default();
}

pub(crate) fn hashcons(v: &Value) -> Value {
	match v {
		Value::Primitive(_) => TERMS.with_current(|terms| terms.intern(v)),
		Value::Constant(_) | Value::Variable(_) => v.clone(),
	}
}

pub(crate) fn hashconsed(p: &std::sync::Arc<Primitive>) -> bool {
	TERMS.with_current(|terms| terms.holds(p))
}

#[derive(Default)]
struct Interner {
	table: IdMap<u64, Vec<std::sync::Arc<Primitive>>>,
}

fn same_constant(a: &Constant, b: &Constant) -> bool {
	a.id == b.id
		&& a.name == b.name
		&& a.guard == b.guard
		&& a.fresh == b.fresh
		&& a.leaked == b.leaked
		&& a.declaration == b.declaration
		&& a.qualifier == b.qualifier
}

fn same_leaf(a: &Value, b: &Value) -> bool {
	match (a, b) {
		(Value::Constant(x), Value::Constant(y)) => same_constant(x, y),
		(Value::Variable(x), Value::Variable(y)) => x == y,
		(Value::Primitive(x), Value::Primitive(y)) => std::sync::Arc::ptr_eq(x, y),
		_ => false,
	}
}

impl Interner {
	fn holds(&self, p: &std::sync::Arc<Primitive>) -> bool {
		self.table
			.get(&primitive_hash(p))
			.is_some_and(|bucket| bucket.iter().any(|held| std::sync::Arc::ptr_eq(held, p)))
	}

	fn intern(&mut self, v: &Value) -> Value {
		self.intern_with(v, &mut crate::solve::vars::PointerMemo::new())
	}

	fn intern_with(
		&mut self,
		v: &Value,
		memo: &mut crate::solve::vars::PointerMemo<Value>,
	) -> Value {
		let Value::Primitive(p) = v else {
			return v.clone();
		};
		let key = std::sync::Arc::as_ptr(p) as usize;
		if let Some(hit) = memo.get(key) {
			return hit;
		}
		if self.holds(p) {
			return v.clone();
		}
		let arguments: Vec<Value> = p
			.arguments
			.iter()
			.map(|a| self.intern_with(a, memo))
			.collect();
		let bucket = self.table.entry(primitive_hash(p)).or_default();
		let found = bucket.iter().find(|held| {
			held.id == p.id
				&& held.output == p.output
				&& held.threshold == p.threshold
				&& held.instance == p.instance
				&& held.instance_check == p.instance_check
				&& held.capabilities == p.capabilities
				&& held.arguments.len() == arguments.len()
				&& held
					.arguments
					.iter()
					.zip(&arguments)
					.all(|(a, b)| same_leaf(a, b))
		});
		let canonical = match found {
			Some(held) => std::sync::Arc::clone(held),
			None => {
				let canonical = if arguments
					.iter()
					.zip(&p.arguments)
					.all(|(a, b)| a.same_term(b))
				{
					std::sync::Arc::clone(p)
				} else {
					std::sync::Arc::new(p.with_arguments(arguments))
				};
				bucket.push(std::sync::Arc::clone(&canonical));
				canonical
			}
		};
		let out = Value::Primitive(canonical);
		memo.insert(key, out.clone());
		out
	}
}

#[derive(Clone, Default)]
pub(crate) struct TermSet(IdMap<u64, Vec<Value>>);

impl TermSet {
	pub(crate) fn iter(&self) -> impl Iterator<Item = &Value> {
		self.0.values().flatten()
	}

	pub(crate) fn insert(&mut self, value: Value) -> bool {
		let bucket = self.0.entry(value.hash_value()).or_default();
		let fresh = !bucket.iter().any(|held| held.equivalent(&value, true));
		if fresh {
			bucket.push(value);
		}
		fresh
	}

	pub(crate) fn contains(&self, value: &Value) -> bool {
		self.0
			.get(&value.hash_value())
			.is_some_and(|bucket| bucket.iter().any(|held| held.equivalent(value, true)))
	}

	pub(crate) fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
}

impl Extend<Value> for TermSet {
	fn extend<T: IntoIterator<Item = Value>>(&mut self, iter: T) {
		for value in iter {
			self.insert(value);
		}
	}
}

impl FromIterator<Value> for TermSet {
	fn from_iter<T: IntoIterator<Item = Value>>(iter: T) -> Self {
		let mut out = Self::default();
		out.extend(iter);
		out
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::*;
	use crate::testing::*;
	use crate::util::IdSet;

	#[test]
	fn collecting_a_shared_transcript_keeps_every_subterm() {
		let mut term = make_constant("shared_transcript_seed");
		let mut expected = IdSet::from_iter([term.hash_value()]);
		for _ in 0..40 {
			term = make_primitive(PRIM_HASH, vec![term.clone(), term.clone(), term], 0);
			expected.insert(term.hash_value());
		}
		let mut found = TermSet::default();
		found.extend(crate::term::subterms(&term).cloned());
		assert_eq!(
			found.iter().map(Value::hash_value).collect::<IdSet<_>>(),
			expected
		);
	}

	#[test]
	fn equivalent_terms_can_have_different_subterms() {
		let x = make_constant("subterms_dh_x");
		let y = make_constant("subterms_dh_y");
		let left = dh_kex(x.clone(), y.clone());
		let right = dh_kex(y, x);
		assert!(left.equivalent(&right, true));
		let root = make_primitive(PRIM_HASH, vec![left.clone(), right.clone()], 0);
		let mut found = TermSet::default();
		found.extend(crate::term::subterms(&root).cloned());
		for term in [&left, &right] {
			let key = &term.as_primitive().unwrap().arguments[0];
			assert!(found.contains(key));
		}
	}

	#[test]
	fn term_membership_confirms_equality_after_a_hash_collision() {
		let left = make_primitive(PRIM_HASH, vec![make_constant("collision_left")], 0);
		let right = make_primitive(PRIM_HASH, vec![make_constant("collision_right")], 0);
		right.as_primitive().unwrap().cache().set(left.hash_value());
		let mut set = TermSet::default();
		set.insert(left.clone());
		assert!(set.contains(&left));
		assert!(!set.contains(&right));
		set.insert(right.clone());
		assert!(set.contains(&left));
		assert!(set.contains(&right));
		assert_eq!(set.iter().count(), 2);
	}

	fn dh_kex(pubkey_inner: Value, bare: Value) -> Value {
		let pk = make_primitive(
			crate::primitive::id_of("PUBKEY").unwrap(),
			vec![pubkey_inner],
			0,
		);
		make_primitive(
			crate::primitive::id_of("DH_KEX").unwrap(),
			vec![pk, bare],
			0,
		)
	}

	#[test]
	fn dh_kex_hash_is_commutative() {
		let x = make_constant("hcm_x");
		let y = make_constant("hcm_y");
		let a = dh_kex(x.clone(), y.clone());
		let b = dh_kex(y, x);
		assert!(a.equivalent(&b, true));
		assert_eq!(a.hash_value(), b.hash_value());
	}

	#[test]
	fn dh_kex_hash_distinguishes_different_pairs() {
		let x = make_constant("hcn_x");
		let y = make_constant("hcn_y");
		let z = make_constant("hcn_z");
		assert_ne!(dh_kex(x.clone(), y).hash_value(), dh_kex(x, z).hash_value());
	}

	#[test]
	fn hash_equal_constants() {
		let a = make_constant("hash_eq_a");
		let b = make_constant("hash_eq_a");
		assert_eq!(a.hash_value(), b.hash_value());
	}

	#[test]
	fn hash_different_values() {
		let a = make_constant("hash_d_a");
		let b = make_constant("hash_d_b");
		assert_ne!(a.hash_value(), b.hash_value());
	}

	#[test]
	fn hash_primitive_includes_output() {
		let a = make_constant("hash_po_a");
		let p1 = make_primitive(PRIM_HKDF, vec![a.clone(), a.clone(), a.clone()], 0);
		let p2 = make_primitive(PRIM_HKDF, vec![a.clone(), a.clone(), a], 1);
		assert_ne!(p1.hash_value(), p2.hash_value());
	}
}
