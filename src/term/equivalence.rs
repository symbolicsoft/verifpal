/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::{Arc, Weak};

use super::{Primitive, Value};
use crate::util::{IdMap, IdSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Pairing {
	Equivalent,
	EquivalentAtOutput,
	Identical,
}

impl Pairing {
	pub(crate) fn equivalence(consider_output: bool) -> Pairing {
		if consider_output {
			Pairing::EquivalentAtOutput
		} else {
			Pairing::Equivalent
		}
	}
}

const RECENT_IDENTICAL_PAIRS: usize = 8192;

type PairKey = (usize, usize, Pairing);

#[derive(Default)]
struct PairMemo {
	depth: usize,
	equal: IdSet<PairKey>,
	recent: IdMap<PairKey, [Weak<Primitive>; 2]>,
	order: VecDeque<PairKey>,
}

thread_local! {
	static PAIRS: RefCell<PairMemo> = RefCell::new(PairMemo::default());
}

pub(crate) fn memoised_pair(
	kind: Pairing,
	a: &Arc<Primitive>,
	b: &Arc<Primitive>,
	compute: impl FnOnce() -> bool,
) -> bool {
	let (x, y) = (Arc::as_ptr(a) as usize, Arc::as_ptr(b) as usize);
	let key = if x <= y { (x, y, kind) } else { (y, x, kind) };
	let (known, nested) = PAIRS.with(|memo| {
		let mut memo = memo.borrow_mut();
		memo.depth += 1;
		let nested = memo.depth > 1;
		(
			(nested && memo.equal.contains(&key))
				|| (kind == Pairing::Identical && memo.recent.contains_key(&key)),
			nested,
		)
	});
	let result = known || compute();
	PAIRS.with(|memo| {
		let mut memo = memo.borrow_mut();
		if result && nested && !known {
			memo.equal.insert(key);
		}
		if result && kind == Pairing::Identical && !known {
			if memo.recent.len() >= RECENT_IDENTICAL_PAIRS
				&& let Some(oldest) = memo.order.pop_front()
			{
				memo.recent.remove(&oldest);
			}
			memo.recent
				.insert(key, [Arc::downgrade(a), Arc::downgrade(b)]);
			memo.order.push_back(key);
		}
		memo.depth -= 1;
		if memo.depth == 0 && !memo.equal.is_empty() {
			memo.equal = IdSet::default();
		}
	});
	result
}

pub(crate) fn equivalent_primitives(p1: &Primitive, p2: &Primitive, consider_output: bool) -> bool {
	if p1.instance != p2.instance {
		return false;
	}
	if p1.id != p2.id || p1.threshold != p2.threshold {
		return false;
	}
	if consider_output && (p1.output != p2.output) {
		return false;
	}
	if p1.arguments.len() != p2.arguments.len() {
		return false;
	}
	let pairwise = p1
		.arguments
		.iter()
		.zip(p2.arguments.iter())
		.all(|(a1, a2)| a1.equivalent(a2, true));
	pairwise || commutative_match(p1, p2)
}

pub(crate) fn structurally_identical_primitive(x: &Primitive, y: &Primitive) -> bool {
	x.id == y.id
		&& x.output == y.output
		&& x.threshold == y.threshold
		&& x.instance == y.instance
		&& x.instance_check == y.instance_check
		&& x.arguments.len() == y.arguments.len()
		&& x.arguments
			.iter()
			.zip(y.arguments.iter())
			.all(|(p, q)| structurally_identical(p, q))
}

pub(crate) fn structurally_identical(a: &Value, b: &Value) -> bool {
	match (a, b) {
		(Value::Constant(x), Value::Constant(y)) => x.id == y.id,
		(Value::Variable(x), Value::Variable(y)) => x == y,
		(Value::Primitive(x), Value::Primitive(y)) => {
			Arc::ptr_eq(x, y)
				|| memoised_pair(Pairing::Identical, x, y, || {
					structurally_identical_primitive(x, y)
				})
		}
		_ => false,
	}
}

fn commutative_match(p1: &Primitive, p2: &Primitive) -> bool {
	let (Some((u1, v1)), Some((u2, v2))) = (
		crate::primitive::commutativity_parts_ref(p1),
		crate::primitive::commutativity_parts_ref(p2),
	) else {
		return false;
	};
	u1.equivalent(v2, true) && u2.equivalent(v1, true)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::Capabilities;
	use crate::primitive::*;
	use crate::term::{Application, Value};
	use crate::testing::*;

	#[test]
	fn transient_checked_terms_remain_structurally_distinct_after_cache_eviction() {
		let a = make_constant("transient_checked_left");
		let b = make_constant("transient_checked_right");
		for i in 0..8300 {
			let primitive = Primitive::new(PRIM_ASSERT, vec![a.clone(), b.clone()], 0)
				.with(|application| application.instance_check = i % 2 == 0);
			let left = Value::Primitive(Arc::new(primitive.clone()));
			let right = Value::Primitive(Arc::new(primitive.clone()));
			assert!(structurally_identical(&left, &right));
			let different = Value::Primitive(Arc::new(primitive.with(|application| {
				application.instance_check = !application.instance_check;
			})));
			assert!(left.equivalent(&different, true));
			assert!(!structurally_identical(&left, &different));
		}
	}

	#[test]
	fn splits_of_one_secret_under_different_thresholds_are_different_values() {
		let k = make_constant("eqt_k");
		let split = |t: usize| {
			let p = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![k.clone()], 1)
				.with(|application| application.threshold = t);
			Value::Primitive(std::sync::Arc::new(p))
		};
		assert!(split(2).equivalent(&split(2), true));
		assert!(!split(2).equivalent(&split(3), true));
		assert_ne!(split(2).hash_value(), split(3).hash_value());
		let Value::Primitive(a) = split(2) else {
			panic!("a primitive");
		};
		let Value::Primitive(b) = split(3) else {
			panic!("a primitive");
		};
		assert!(!structurally_identical_primitive(&a, &b));
		assert!(a.with_output(0).threshold == 2 && a.with_arguments(vec![k]).threshold == 2);
	}

	fn pubkey(inner: Value) -> Value {
		make_primitive(crate::primitive::id_of("PUBKEY").unwrap(), vec![inner], 0)
	}

	fn dh_kex(pubkey_inner: Value, bare: Value) -> Value {
		make_primitive(
			crate::primitive::id_of("DH_KEX").unwrap(),
			vec![pubkey(pubkey_inner), bare],
			0,
		)
	}

	fn dh_kex_raw(first: Value, bare: Value) -> Value {
		make_primitive(
			crate::primitive::id_of("DH_KEX").unwrap(),
			vec![first, bare],
			0,
		)
	}

	#[test]
	fn dh_kex_is_commutative() {
		let x = make_constant("cmt_x");
		let y = make_constant("cmt_y");
		let a = dh_kex(x.clone(), y.clone());
		let b = dh_kex(y, x);
		assert!(a.equivalent(&b, true));
	}

	#[test]
	fn dh_kex_distinguishes_different_pairs() {
		let x = make_constant("cmu_x");
		let y = make_constant("cmu_y");
		let z = make_constant("cmu_z");
		let a = dh_kex(x.clone(), y);
		let b = dh_kex(x, z);
		assert!(!a.equivalent(&b, true));
	}

	#[test]
	fn dh_kex_of_two_public_keys_is_not_the_shared_secret() {
		let x = make_constant("cmv_x");
		let y = make_constant("cmv_y");
		let honest = dh_kex(x.clone(), y.clone());
		let junk = dh_kex_raw(pubkey(x), pubkey(y));
		assert!(!honest.equivalent(&junk, true));
	}

	#[test]
	fn constant_equivalence_same_id() {
		let a = make_constant("test_const_a");
		let b = make_constant("test_const_a");
		assert!(a.equivalent(&b, true));
	}

	#[test]
	fn constant_equivalence_different_id() {
		let a = make_constant("eq_const_x");
		let b = make_constant("eq_const_y");
		assert!(!a.equivalent(&b, true));
	}

	#[test]
	fn primitive_equivalence_same() {
		let a = make_constant("peq_a");
		let b = make_constant("peq_b");
		let p1 = Primitive::from(Application {
			id: PRIM_ENC,
			arguments: vec![a.clone(), b.clone()],
			output: 0,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
		});
		let p2 = Primitive::from(Application {
			id: PRIM_ENC,
			arguments: vec![a, b],
			output: 0,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
		});
		assert!(equivalent_primitives(&p1, &p2, true));
	}

	#[test]
	fn primitive_equivalence_different_id() {
		let a = make_constant("pdiff_a");
		let b = make_constant("pdiff_b");
		let p1 = Primitive::from(Application {
			id: PRIM_ENC,
			arguments: vec![a.clone(), b.clone()],
			output: 0,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
		});
		let p2 = Primitive::from(Application {
			id: PRIM_DEC,
			arguments: vec![a, b],
			output: 0,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
		});
		assert!(!equivalent_primitives(&p1, &p2, true));
	}

	#[test]
	fn primitive_equivalence_different_output() {
		let a = make_constant("pout_a");
		let p1 = Primitive::from(Application {
			id: PRIM_HKDF,
			arguments: vec![a.clone(), a.clone(), a.clone()],
			output: 0,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
		});
		let p2 = Primitive::from(Application {
			id: PRIM_HKDF,
			arguments: vec![a.clone(), a.clone(), a],
			output: 1,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
		});
		assert!(!equivalent_primitives(&p1, &p2, true));
		assert!(equivalent_primitives(&p1, &p2, false));
	}
}
