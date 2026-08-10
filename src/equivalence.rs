/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::*;

pub(crate) fn equivalent_primitives(p1: &Primitive, p2: &Primitive, consider_output: bool) -> bool {
	if p1.id != p2.id {
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
	use crate::primitive::*;
	use crate::testutil::*;

	fn pubkey(inner: Value) -> Value {
		make_primitive(primitive_get_enum("PUBKEY").unwrap(), vec![inner], 0)
	}

	fn dh_kex(pubkey_inner: Value, bare: Value) -> Value {
		make_primitive(
			primitive_get_enum("DH_KEX").unwrap(),
			vec![pubkey(pubkey_inner), bare],
			0,
		)
	}

	fn dh_kex_raw(first: Value, bare: Value) -> Value {
		make_primitive(primitive_get_enum("DH_KEX").unwrap(), vec![first, bare], 0)
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
		let p1 = Primitive {
			id: PRIM_ENC,
			arguments: vec![a.clone(), b.clone()],
			output: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		};
		let p2 = Primitive {
			id: PRIM_ENC,
			arguments: vec![a, b],
			output: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		};
		assert!(equivalent_primitives(&p1, &p2, true));
	}

	#[test]
	fn primitive_equivalence_different_id() {
		let a = make_constant("pdiff_a");
		let b = make_constant("pdiff_b");
		let p1 = Primitive {
			id: PRIM_ENC,
			arguments: vec![a.clone(), b.clone()],
			output: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		};
		let p2 = Primitive {
			id: PRIM_DEC,
			arguments: vec![a, b],
			output: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		};
		assert!(!equivalent_primitives(&p1, &p2, true));
	}

	#[test]
	fn primitive_equivalence_different_output() {
		let a = make_constant("pout_a");
		let p1 = Primitive {
			id: PRIM_HKDF,
			arguments: vec![a.clone(), a.clone(), a.clone()],
			output: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		};
		let p2 = Primitive {
			id: PRIM_HKDF,
			arguments: vec![a.clone(), a.clone(), a],
			output: 1,
			instance_check: false,
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		};
		assert!(!equivalent_primitives(&p1, &p2, true));
		assert!(equivalent_primitives(&p1, &p2, false));
	}
}
