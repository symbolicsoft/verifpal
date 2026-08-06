/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashSet;

use crate::types::*;

pub(crate) fn primitive_hash(p: &Primitive) -> u64 {
	if let Some(cached) = p.hash.get() {
		return cached;
	}
	let computed = primitive_hash_uncached(p);
	p.hash.set(computed);
	computed
}

fn primitive_hash_uncached(p: &Primitive) -> u64 {
	let base = (p.id as u64).wrapping_mul(2654435761) ^ (p.output as u64).wrapping_mul(97);
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

pub(crate) fn collect_subterm_hashes(v: &Value, out: &mut HashSet<u64>) {
	out.insert(v.hash_value());
	match v {
		Value::Primitive(p) => {
			for a in &p.arguments {
				collect_subterm_hashes(a, out);
			}
		}
		Value::Constant(_) => {}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::*;
	use crate::testutil::*;

	fn dh_kex(pubkey_inner: Value, bare: Value) -> Value {
		let pk = make_primitive(primitive_get_enum("PUBKEY").unwrap(), vec![pubkey_inner], 0);
		make_primitive(primitive_get_enum("DH_KEX").unwrap(), vec![pk, bare], 0)
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
