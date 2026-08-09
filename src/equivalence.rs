/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::*;

pub(crate) struct PrimitiveMatch {
	pub equivalent: bool,
	pub output_left: usize,
	pub output_right: usize,
}

impl PrimitiveMatch {
	fn no_match() -> Self {
		PrimitiveMatch {
			equivalent: false,
			output_left: 0,
			output_right: 0,
		}
	}
}

pub(crate) fn equivalent_primitives(
	p1: &Primitive,
	p2: &Primitive,
	consider_output: bool,
) -> PrimitiveMatch {
	if p1.id != p2.id {
		return PrimitiveMatch::no_match();
	}
	if consider_output && (p1.output != p2.output) {
		return PrimitiveMatch::no_match();
	}
	if p1.arguments.len() != p2.arguments.len() {
		return PrimitiveMatch::no_match();
	}
	let pairwise = p1
		.arguments
		.iter()
		.zip(p2.arguments.iter())
		.all(|(a1, a2)| a1.equivalent(a2, true));
	if !pairwise && !commutative_match(p1, p2) {
		return PrimitiveMatch::no_match();
	}
	PrimitiveMatch {
		equivalent: true,
		output_left: p1.output,
		output_right: p2.output,
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

/// Homeomorphic embedding: `small` is recoverable from `large` by deleting
/// subterms. Used as a termination whistle, where it earns its keep over a
/// depth bound by Kruskal's tree theorem — over a finite signature every
/// infinite sequence of terms contains an earlier term embedded in a later one,
/// so a search cut on this relation cannot run away.
///
/// Deliberately structural, ignoring the commutativity [`equivalent_primitives`]
/// honours: reporting fewer embeddings costs search effort, never an attack.
pub(crate) fn homeomorphically_embeds(small: &Value, large: &Value) -> bool {
	embeds_at(small, large, 0)
}

const MAX_EMBED_DEPTH: usize = 64;

fn embeds_at(small: &Value, large: &Value, depth: usize) -> bool {
	if depth > MAX_EMBED_DEPTH {
		return false;
	}
	// Coupling.
	let coupled = match (small, large) {
		(Value::Constant(a), Value::Constant(b)) => a.id == b.id,
		(Value::Primitive(s), Value::Primitive(l)) => {
			s.id == l.id
				&& s.output == l.output
				&& s.arguments.len() == l.arguments.len()
				&& s.arguments
					.iter()
					.zip(l.arguments.iter())
					.all(|(a, b)| embeds_at(a, b, depth + 1))
		}
		_ => false,
	};
	if coupled {
		return true;
	}
	// Diving.
	match large {
		Value::Primitive(l) => l
			.arguments
			.iter()
			.any(|arg| embeds_at(small, arg, depth + 1)),
		Value::Constant(_) => false,
	}
}

pub(crate) fn find_constant_in_trace_primitive(
	c: &Constant,
	value: &Value,
	trace: &ProtocolTrace,
) -> bool {
	let target = Value::Constant(c.clone());
	let (_, resolved_values) = crate::resolution::resolve_trace_values(value, trace);
	crate::value::find_equivalent(&target, &resolved_values).is_some()
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
		assert!(equivalent_primitives(&p1, &p2, true).equivalent);
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
		assert!(!equivalent_primitives(&p1, &p2, true).equivalent);
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
		assert!(!equivalent_primitives(&p1, &p2, true).equivalent);
		let pm = equivalent_primitives(&p1, &p2, false);
		assert!(pm.equivalent);
		assert_eq!(pm.output_left, 0);
		assert_eq!(pm.output_right, 1);
	}

	fn hash_of(inner: Value) -> Value {
		make_primitive(primitive_get_enum("HASH").unwrap(), vec![inner], 0)
	}

	fn enc(key: Value, plaintext: Value) -> Value {
		make_primitive(primitive_get_enum("ENC").unwrap(), vec![key, plaintext], 0)
	}

	#[test]
	fn embedding_is_reflexive() {
		let x = make_constant("emb_x");
		assert!(homeomorphically_embeds(&x, &x));
		let h = hash_of(x);
		assert!(homeomorphically_embeds(&h, &h));
	}

	#[test]
	fn embedding_dives_into_arguments() {
		let x = make_constant("emb_dive_x");
		let h = hash_of(x.clone());
		// x is recovered from HASH(x) by deleting the HASH.
		assert!(homeomorphically_embeds(&x, &h));
		assert!(!homeomorphically_embeds(&h, &x));
	}

	#[test]
	fn embedding_detects_the_self_feeding_pump() {
		// This is the exact relation the solver cuts on: rung n of a replay
		// ladder embeds in rung n+1, for every n.
		let k = make_constant("emb_pump_k");
		let n = make_constant("emb_pump_n");
		let rung1 = enc(k.clone(), hash_of(n.clone()));
		let rung2 = enc(k.clone(), hash_of(hash_of(n.clone())));
		let rung3 = enc(k.clone(), hash_of(hash_of(hash_of(n))));
		assert!(homeomorphically_embeds(&rung1, &rung2));
		assert!(homeomorphically_embeds(&rung2, &rung3));
		assert!(homeomorphically_embeds(&rung1, &rung3));
		// The ladder only grows one way.
		assert!(!homeomorphically_embeds(&rung2, &rung1));
		assert!(!homeomorphically_embeds(&rung3, &rung2));
	}

	#[test]
	fn embedding_rejects_unrelated_terms() {
		let k = make_constant("emb_unrel_k");
		let m = make_constant("emb_unrel_m");
		let other = make_constant("emb_unrel_other");
		assert!(!homeomorphically_embeds(&enc(k.clone(), m), &enc(k, other)));
	}

	#[test]
	fn embedding_distinguishes_multi_output_positions() {
		let a = make_constant("emb_out_a");
		let p1 = make_primitive(PRIM_HKDF, vec![a.clone(), a.clone(), a.clone()], 0);
		let p2 = make_primitive(PRIM_HKDF, vec![a.clone(), a.clone(), a], 1);
		assert!(!homeomorphically_embeds(&p1, &p2));
	}
}
