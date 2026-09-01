/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::*;
use crate::types::*;
use crate::value::value_nil;

pub(crate) const PRIM_ASSERT: PrimitiveId = 1;
pub(crate) const PRIM_CONCAT: PrimitiveId = 2;
pub(crate) const PRIM_SPLIT: PrimitiveId = 3;
pub(crate) const PRIM_PWHASH: PrimitiveId = 4;
pub(crate) const PRIM_HASH: PrimitiveId = 5;
pub(crate) const PRIM_HKDF: PrimitiveId = 6;
pub(crate) const PRIM_AEAD_ENC: PrimitiveId = 7;
pub(crate) const PRIM_AEAD_DEC: PrimitiveId = 8;
pub(crate) const PRIM_ENC: PrimitiveId = 9;
pub(crate) const PRIM_DEC: PrimitiveId = 10;
pub(crate) const PRIM_MAC: PrimitiveId = 11;
pub(crate) const PRIM_SIGN: PrimitiveId = 12;
pub(crate) const PRIM_SIGNVERIF: PrimitiveId = 13;
pub(crate) const PRIM_PKE_ENC: PrimitiveId = 14;
pub(crate) const PRIM_PKE_DEC: PrimitiveId = 15;
pub(crate) const PRIM_SHAMIR_SPLIT: PrimitiveId = 16;
pub(crate) const PRIM_SHAMIR_JOIN: PrimitiveId = 17;
pub(crate) const PRIM_RINGSIGN: PrimitiveId = 18;
pub(crate) const PRIM_RINGSIGNVERIF: PrimitiveId = 19;
pub(crate) const PRIM_BLIND: PrimitiveId = 20;
pub(crate) const PRIM_UNBLIND: PrimitiveId = 21;
pub(crate) const PRIM_PUBKEY: PrimitiveId = 22;
pub(crate) const PRIM_DH_KEX: PrimitiveId = 23;
pub(crate) const PRIM_KEM_ENCAP: PrimitiveId = 24;
pub(crate) const PRIM_KEM_DECAP: PrimitiveId = 25;

fn filter_identity(_p: &Primitive, x: &Value, _i: usize) -> (Value, bool) {
	(x.clone(), true)
}

fn filter_extract_dh_exponent(_p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
	match i {
		0 => match x {
			Value::Primitive(p)
				if super::primitive_is_key_derivation(p.id) && p.arguments.len() == 1 =>
			{
				(p.arguments[0].clone(), true)
			}
			Value::Constant(_) | Value::Primitive(_) => (x.clone(), false),
		},
		1 => (x.clone(), true),
		_ => (x.clone(), false),
	}
}

fn filter_derived_key_rewrite(_p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
	match i {
		0 => match super::key_derivation_of(x.clone()) {
			Some(k) => (k, true),
			None => (x.clone(), false),
		},
		_ => (x.clone(), false),
	}
}

fn filter_aead_dec_rewrite(_p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
	match i {
		0 | 2 => (x.clone(), true),
		_ => (x.clone(), false),
	}
}

fn filter_dec_rewrite(_p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
	match i {
		0 => (x.clone(), true),
		_ => (x.clone(), false),
	}
}

fn filter_ringsignverif_rewrite(_p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
	match i {
		0 => match x {
			Value::Primitive(p)
				if super::primitive_is_key_derivation(p.id) && p.arguments.len() == 1 =>
			{
				(p.arguments[0].clone(), true)
			}
			Value::Constant(_) | Value::Primitive(_) => (x.clone(), false),
		},
		1..=4 => (x.clone(), true),
		_ => (x.clone(), false),
	}
}

fn filter_unblind_rewrite(p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
	match i {
		1 => {
			let blind_prim = Value::primitive(
				PRIM_BLIND,
				vec![p.arguments[0].clone(), p.arguments[1].clone()],
				0,
			);
			(blind_prim, true)
		}
		_ => (x.clone(), false),
	}
}

fn core_rule_assert(p: &Primitive) -> (bool, Value) {
	let v = Value::Primitive(Arc::new(p.clone()));
	if p.arguments[0].equivalent(&p.arguments[1], true) {
		(true, v)
	} else {
		(false, v)
	}
}

fn core_rule_split(p: &Primitive) -> (bool, Value) {
	match &p.arguments[0] {
		Value::Primitive(pp) if pp.id == PRIM_CONCAT => match pp.arguments.get(p.output) {
			Some(field) => (true, field.clone()),
			None => (false, Value::Primitive(Arc::new(p.clone()))),
		},
		_ => (false, Value::Primitive(Arc::new(p.clone()))),
	}
}

fn rewrite_to_arg1(p: &Primitive) -> Value {
	p.arguments[1].clone()
}

fn rewrite_to_kem_secret(p: &Primitive) -> Value {
	Value::Primitive(Arc::new(p.with_output(0)))
}

fn rewrite_to_nil(_p: &Primitive) -> Value {
	value_nil()
}

fn rewrite_to_unblind(p: &Primitive) -> Value {
	let inner = match &p.arguments[1] {
		Value::Primitive(inner_p) => inner_p.arguments[1].clone(),
		_ => value_nil(),
	};
	Value::primitive(PRIM_SIGN, vec![p.arguments[0].clone(), inner], 0)
}

pub(super) fn build_core_specs() -> Vec<PrimitiveCoreSpec> {
	vec![
		PrimitiveCoreSpec {
			id: PRIM_ASSERT,
			name: "ASSERT",
			arity: vec![2],
			output: vec![1],
			core_rule: Some(core_rule_assert),
			definition_check: true,
			reveals_args: false,
			arg_names: vec!["value1", "value2"],
		},
		PrimitiveCoreSpec {
			id: PRIM_CONCAT,
			name: "CONCAT",
			arity: vec![2, 3, 4, 5],
			output: vec![1],
			core_rule: None,
			definition_check: false,
			reveals_args: true,
			arg_names: vec!["value1", "value2", "value3", "value4", "value5"],
		},
		PrimitiveCoreSpec {
			id: PRIM_SPLIT,
			name: "SPLIT",
			arity: vec![1],
			output: vec![1, 2, 3, 4, 5],
			core_rule: Some(core_rule_split),
			definition_check: true,
			reveals_args: false,
			arg_names: vec!["concatenation"],
		},
	]
}

pub(super) fn build_primitive_specs() -> Vec<PrimitiveSpec> {
	vec![
		PrimitiveSpec {
			id: PRIM_PWHASH,
			arg_names: vec!["value1", "value2", "value3", "value4", "value5"],
			name: "PW_HASH",
			arity: vec![1, 2, 3, 4, 5],
			output: vec![1],
			password_hashing: vec![0, 1, 2, 3, 4],
			weak_reveals: vec![0, 1, 2, 3, 4],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_HASH,
			arg_names: vec!["value1", "value2", "value3", "value4", "value5"],
			name: "HASH",
			arity: vec![1, 2, 3, 4, 5],
			output: vec![1],
			weak_reveals: vec![0, 1, 2, 3, 4],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_HKDF,
			arg_names: vec!["salt", "ikm", "info"],
			name: "HKDF",
			arity: vec![3],
			output: vec![1, 2, 3, 4, 5],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_AEAD_ENC,
			arg_names: vec!["key", "plaintext", "ad"],
			name: "AEAD_ENC",
			arity: vec![3],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0],
				reveals: vec![Reveal::Argument(1)],
				filter: filter_identity,
			}),
			weak_reveals: vec![1],
			forgeable_secret: Some(0),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_AEAD_DEC,
			arg_names: vec!["key", "ciphertext", "ad"],
			name: "AEAD_DEC",
			arity: vec![3],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0],
				reveals: vec![Reveal::Argument(1)],
				filter: filter_identity,
			}),
			rewrite: Some(RewriteRule {
				id: PRIM_AEAD_ENC,
				from: 1,
				to: rewrite_to_arg1,
				matching: vec![(0, vec![0]), (2, vec![2])],
				filter: filter_aead_dec_rewrite,
			}),
			definition_check: true,
			bypass_key: Some(BypassKeyKind::Direct(0)),
			identifying_positions: vec![0],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_ENC,
			arg_names: vec!["key", "plaintext"],
			name: "ENC",
			arity: vec![2],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0],
				reveals: vec![Reveal::Argument(1)],
				filter: filter_identity,
			}),
			weak_reveals: vec![1],
			malleable_vary: vec![1],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_DEC,
			arg_names: vec!["key", "ciphertext"],
			name: "DEC",
			arity: vec![2],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0],
				reveals: vec![Reveal::Argument(1)],
				filter: filter_identity,
			}),
			rewrite: Some(RewriteRule {
				id: PRIM_ENC,
				from: 1,
				to: rewrite_to_arg1,
				matching: vec![(0, vec![0])],
				filter: filter_dec_rewrite,
			}),
			bypass_key: Some(BypassKeyKind::Direct(0)),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_MAC,
			arg_names: vec!["key", "message"],
			name: "MAC",
			arity: vec![2],
			output: vec![1],
			forgeable_secret: Some(0),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_PUBKEY,
			arg_names: vec!["private_key"],
			name: "PUBKEY",
			arity: vec![1],
			output: vec![1],
			key_derivation: true,
			argument_restrictions: vec![(0, vec![PRIM_PUBKEY, PRIM_DH_KEX])],
			weak_reveals: vec![0],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_DH_KEX,
			arg_names: vec!["public_key", "private_key"],
			name: "DH_KEX",
			arity: vec![2],
			output: vec![1],
			commutativity: Some(CommutativityRule {
				wrapped: 0,
				constructor: PRIM_PUBKEY,
				bare: 1,
			}),
			argument_restrictions: vec![
				(0, vec![PRIM_DH_KEX]),
				(1, vec![PRIM_PUBKEY, PRIM_DH_KEX]),
			],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_SIGN,
			arg_names: vec!["private_key", "message"],
			name: "SIGN",
			arity: vec![2],
			output: vec![1],
			forgeable_secret: Some(0),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_SIGNVERIF,
			arg_names: vec!["public_key", "message", "signature"],
			name: "SIGNVERIF",
			arity: vec![3],
			output: vec![1],
			rewrite: Some(RewriteRule {
				id: PRIM_SIGN,
				from: 2,
				to: rewrite_to_nil,
				matching: vec![(0, vec![0]), (1, vec![1])],
				filter: filter_extract_dh_exponent,
			}),
			definition_check: true,
			bypass_key: Some(BypassKeyKind::Derived {
				arg: 0,
				constructor: PRIM_PUBKEY,
			}),
			identifying_positions: vec![0],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_PKE_ENC,
			arg_names: vec!["public_key", "plaintext"],
			name: "PKE_ENC",
			arity: vec![2],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0],
				reveals: vec![Reveal::Argument(1)],
				filter: filter_extract_dh_exponent,
			}),
			weak_reveals: vec![1],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_PKE_DEC,
			arg_names: vec!["private_key", "ciphertext"],
			name: "PKE_DEC",
			arity: vec![2],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0],
				reveals: vec![Reveal::Argument(1)],
				filter: filter_identity,
			}),
			rewrite: Some(RewriteRule {
				id: PRIM_PKE_ENC,
				from: 1,
				to: rewrite_to_arg1,
				matching: vec![(0, vec![0])],
				filter: filter_derived_key_rewrite,
			}),
			bypass_key: Some(BypassKeyKind::Direct(0)),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_SHAMIR_SPLIT,
			arg_names: vec!["secret"],
			name: "SHAMIR_SPLIT",
			arity: vec![1],
			output: vec![3],
			recompose: Some(RecomposeRule {
				given: vec![vec![0, 1], vec![0, 2], vec![1, 2]],
				reveal: 0,
			}),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_SHAMIR_JOIN,
			arg_names: vec!["share_a", "share_b"],
			name: "SHAMIR_JOIN",
			arity: vec![2],
			output: vec![1],
			rebuild: Some(RebuildRule {
				id: PRIM_SHAMIR_SPLIT,
				given: vec![vec![0, 1], vec![1, 0]],
				reveal: 0,
			}),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_RINGSIGN,
			arg_names: vec!["signer_key", "public_key_b", "public_key_c", "message"],
			name: "RINGSIGN",
			arity: vec![4],
			output: vec![1],
			forgeable_secret: Some(0),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_RINGSIGNVERIF,
			arg_names: vec![
				"public_key_a",
				"public_key_b",
				"public_key_c",
				"message",
				"signature",
			],
			name: "RINGSIGNVERIF",
			arity: vec![5],
			output: vec![1],
			rewrite: Some(RewriteRule {
				id: PRIM_RINGSIGN,
				from: 4,
				to: rewrite_to_nil,
				matching: vec![
					(0, vec![0, 1, 2]),
					(1, vec![0, 1, 2]),
					(2, vec![0, 1, 2]),
					(3, vec![3]),
				],
				filter: filter_ringsignverif_rewrite,
			}),
			definition_check: true,
			bypass_key: Some(BypassKeyKind::Derived {
				arg: 0,
				constructor: PRIM_PUBKEY,
			}),
			identifying_positions: vec![],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_BLIND,
			arg_names: vec!["blinding_factor", "message"],
			name: "BLIND",
			arity: vec![2],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0],
				reveals: vec![Reveal::Argument(1)],
				filter: filter_identity,
			}),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_UNBLIND,
			arg_names: vec!["blinding_factor", "message", "blinded_signature"],
			name: "UNBLIND",
			arity: vec![3],
			output: vec![1],
			rewrite: Some(RewriteRule {
				id: PRIM_SIGN,
				from: 2,
				to: rewrite_to_unblind,
				matching: vec![(0, vec![1])],
				filter: filter_unblind_rewrite,
			}),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_KEM_ENCAP,
			arg_names: vec!["public_key", "seed"],
			name: "KEM_ENCAP",
			arity: vec![2],
			output: vec![2],
			decompose: Some(DecomposeRule {
				given: vec![0],
				reveals: vec![Reveal::Output(0), Reveal::Argument(1)],
				filter: filter_extract_dh_exponent,
			}),
			argument_restrictions: vec![
				(0, vec![PRIM_DH_KEX, PRIM_KEM_ENCAP, PRIM_KEM_DECAP]),
				(1, vec![PRIM_PUBKEY, PRIM_DH_KEX]),
			],
			weak_reveals_output: Some(0),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_KEM_DECAP,
			arg_names: vec!["private_key", "ciphertext"],
			name: "KEM_DECAP",
			arity: vec![2],
			output: vec![1],
			rewrite: Some(RewriteRule {
				id: PRIM_KEM_ENCAP,
				from: 1,
				to: rewrite_to_kem_secret,
				matching: vec![(0, vec![0])],
				filter: filter_derived_key_rewrite,
			}),
			definition_check: true,
			bypass_key: Some(BypassKeyKind::Direct(0)),
			argument_restrictions: vec![(0, vec![PRIM_PUBKEY, PRIM_DH_KEX])],
			identifying_positions: vec![0],
			..PrimitiveSpec::default()
		},
	]
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testutil::*;

	#[test]
	fn extract_exponent_rejects_a_bare_constant() {
		let k = make_constant("fey_k");
		let p = Primitive {
			id: PRIM_SIGNVERIF,
			arguments: vec![k.clone()],
			output: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		};
		let (_, ok) = filter_extract_dh_exponent(&p, &k, 0);
		assert!(!ok, "a bare constant is not a public key");
	}

	#[test]
	fn extract_exponent_rejects_a_non_key_primitive() {
		let k = make_constant("fez_k");
		let hashed = make_primitive(PRIM_HASH, vec![k], 0);
		let p = Primitive {
			id: PRIM_SIGNVERIF,
			arguments: vec![hashed.clone()],
			output: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		};
		let (_, ok) = filter_extract_dh_exponent(&p, &hashed, 0);
		assert!(!ok, "only the key-derivation constructor may be peeled");
	}
}
