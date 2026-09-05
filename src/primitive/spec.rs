/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::*;
use crate::types::*;
use crate::value::value_nil;

pub(crate) const PRIM_ASSERT: PrimitiveId = 1;
pub(crate) const PRIM_CONCAT: PrimitiveId = 2;
pub(crate) const PRIM_SPLIT: PrimitiveId = 3;
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

const AEAD_NONCE_HELP: &str = "`AEAD_ENC` and `AEAD_DEC` take a nonce as their second argument: \
                               `AEAD_ENC(key, nonce, plaintext, ad)` and \
                               `AEAD_DEC(key, nonce, ciphertext, ad)`";

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
		0 | 1 | 3 => (x.clone(), true),
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

fn rewrite_to_arg2(p: &Primitive) -> Value {
	p.arguments[2].clone()
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
			doc: PrimitiveDoc {
				example: "ASSERT(MAC(key, message), MAC(key, message)): unused",
				help: "Checks the equality of two values, and especially useful for checking MAC equality. Output value is not used. May be suffixed with `?` to halt the principal if the check fails.",
			},
			arity: vec![2],
			output: vec![1],
			core_rule: Some(core_rule_assert),
			definition_check: true,
			reveals_args: false,
			projection_of: None,
			equality: true,
			unwraps: None,
			arg_names: vec!["value1", "value2"],
		},
		PrimitiveCoreSpec {
			id: PRIM_CONCAT,
			name: "CONCAT",
			doc: PrimitiveDoc {
				example: "CONCAT(a, b...): c",
				help: "Concatenates between two and five values into one value. For example, the concatenation of the strings `cat` and `dog` would be `catdog`.",
			},
			arity: vec![2, 3, 4, 5],
			output: vec![1],
			core_rule: None,
			definition_check: false,
			reveals_args: true,
			projection_of: None,
			equality: false,
			unwraps: None,
			arg_names: vec!["value1", "value2", "value3", "value4", "value5"],
		},
		PrimitiveCoreSpec {
			id: PRIM_SPLIT,
			name: "SPLIT",
			doc: PrimitiveDoc {
				example: "SPLIT(CONCAT(a, b)): a, b",
				help: "Splits a concatenation back to its component values, producing between one and five outputs. Must contain a CONCAT primitive as input; otherwise, Verifpal will output an error. May be suffixed with `?` to halt the principal if the check fails.",
			},
			arity: vec![1],
			output: vec![1, 2, 3, 4, 5],
			core_rule: Some(core_rule_split),
			definition_check: true,
			reveals_args: false,
			projection_of: Some(PRIM_CONCAT),
			equality: false,
			unwraps: Some(0),
			arg_names: vec!["concatenation"],
		},
	]
}

pub(super) fn build_primitive_specs() -> Vec<PrimitiveSpec> {
	vec![
		PrimitiveSpec {
			id: PRIM_HASH,
			arg_names: vec!["value1", "value2", "value3", "value4", "value5"],
			name: "HASH",
			doc: PrimitiveDoc {
				example: "HASH(a, b...): x",
				help: "Secure hash function, similar in practice to, for example, BLAKE2s. Takes between one and five input arguments, and returns one output.",
			},
			arity: vec![1, 2, 3, 4, 5],
			output: vec![1],
			weak_reveals: vec![0, 1, 2, 3, 4],
			divergence_filler: true,
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_HKDF,
			arg_names: vec!["salt", "ikm", "info"],
			name: "HKDF",
			doc: PrimitiveDoc {
				example: "HKDF(salt, ikm, info): a, b...",
				help: "Hash-based key derivation function inspired by the Krawczyk HKDF scheme. Essentially, HKDF is used to extract more than one key out a single secret value. salt and info help contextualize derived keys. Takes exactly three arguments and produces between one and five outputs.",
			},
			arity: vec![3],
			output: vec![1, 2, 3, 4, 5],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_AEAD_ENC,
			arg_names: vec!["key", "nonce", "plaintext", "ad"],
			name: "AEAD_ENC",
			doc: PrimitiveDoc {
				example: "AEAD_ENC(key, nonce, plaintext, ad): ciphertext",
				help: "Authenticated encryption with associated data, similar for example to AES-GCM or to ChaCha20-Poly1305. `nonce` must be unique per key: two encryptions under one key and nonce that differ in plaintext or in `ad` reveal both plaintexts to the attacker and let it forge any ciphertext under that key and nonce. `ad` represents an additional payload that is not encrypted, but that must be provided exactly in the decryption function for authenticated decryption to succeed. Decrypting needs the key and the nonce.",
			},
			arity: vec![4],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0, 1],
				output: None,
				reveals: vec![Reveal::Argument(2)],
				filter: filter_identity,
			}),
			weak_reveals: vec![2],
			forgeable_secret: Some(0),
			reuse: Some(ReuseRule {
				fixed: vec![0, 1],
				reveals: vec![Reveal::Argument(2)],
				forgeable: vec![0, 1],
			}),
			arity_help: Some((3, AEAD_NONCE_HELP)),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_AEAD_DEC,
			arg_names: vec!["key", "nonce", "ciphertext", "ad"],
			name: "AEAD_DEC",
			doc: PrimitiveDoc {
				example: "AEAD_DEC(key, nonce, AEAD_ENC(key, nonce, plaintext, ad), ad): plaintext",
				help: "Authenticated decryption with associated data. Fails under the wrong key, nonce or `ad`. May be suffixed with `?` to halt the principal if decryption fails.",
			},
			arity: vec![4],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0, 1],
				output: None,
				reveals: vec![Reveal::Argument(2)],
				filter: filter_identity,
			}),
			rewrite: Some(RewriteRule {
				id: PRIM_AEAD_ENC,
				from: 2,
				from_output: None,
				to: rewrite_to_arg2,
				matching: vec![(0, vec![0]), (1, vec![1]), (3, vec![3])],
				filter: filter_aead_dec_rewrite,
			}),
			definition_check: true,
			bypass_key: Some(BypassKeyKind::Direct(0)),
			identifying_positions: vec![0],
			arity_help: Some((3, AEAD_NONCE_HELP)),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_ENC,
			arg_names: vec!["key", "plaintext"],
			name: "ENC",
			doc: PrimitiveDoc {
				example: "ENC(key, plaintext): ciphertext",
				help: "Symmetric encryption, similar for example to AES-CBC or to ChaCha20. Unauthenticated, which is why it is the one primitive that accepts `malleable`.",
			},
			arity: vec![2],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0],
				output: None,
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
			doc: PrimitiveDoc {
				example: "DEC(key, ENC(key, plaintext)): plaintext",
				help: "Symmetric decryption.",
			},
			arity: vec![2],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0],
				output: None,
				reveals: vec![Reveal::Argument(1)],
				filter: filter_identity,
			}),
			rewrite: Some(RewriteRule {
				id: PRIM_ENC,
				from: 1,
				from_output: None,
				to: rewrite_to_arg1,
				matching: vec![(0, vec![0])],
				filter: filter_dec_rewrite,
			}),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_MAC,
			arg_names: vec!["key", "message"],
			name: "MAC",
			doc: PrimitiveDoc {
				example: "MAC(key, message): h",
				help: "Keyed hash function. Useful for message authentication and for some other protocol constructions.",
			},
			arity: vec![2],
			output: vec![1],
			forgeable_secret: Some(0),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_PUBKEY,
			arg_names: vec!["private_key"],
			name: "PUBKEY",
			doc: PrimitiveDoc {
				example: "PUBKEY(private_key): public_key",
				help: "Derives the public key corresponding to a private key. The same constructor is used for Diffie-Hellman, signatures, public-key encryption and ring signatures. Its argument may not itself be a public key or a shared secret.",
			},
			arity: vec![1],
			output: vec![1],
			key_derivation: true,
			argument_restrictions: vec![ArgumentRestriction {
				position: 0,
				banned: vec![PRIM_PUBKEY, PRIM_DH_KEX],
				note: "`PUBKEY` derives a public value from a private one, so its argument cannot already be public",
			}],
			weak_reveals: vec![0],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_DH_KEX,
			arg_names: vec!["public_key", "private_key"],
			name: "DH_KEX",
			doc: PrimitiveDoc {
				example: "DH_KEX(PUBKEY(a), b): shared_secret",
				help: "Diffie-Hellman key exchange. DH_KEX(PUBKEY(a), b) and DH_KEX(PUBKEY(b), a) yield the same shared secret. The first argument is the peer's public key and the second is your own private value: the second argument may not be a public key, and neither argument may itself be a DH_KEX, since the attacker cannot compute a shared secret from two public keys.",
			},
			arity: vec![2],
			output: vec![1],
			commutativity: Some(CommutativityRule {
				wrapped: 0,
				constructor: PRIM_PUBKEY,
				bare: 1,
			}),
			argument_restrictions: vec![
				ArgumentRestriction {
					position: 0,
					banned: vec![PRIM_DH_KEX],
					note: "",
				},
				ArgumentRestriction {
					position: 1,
					banned: vec![PRIM_PUBKEY, PRIM_DH_KEX],
					note: "the second argument to `DH_KEX` is a private exponent, not a public value; keeping it that way is what makes the Diffie-Hellman assumption structural rather than a special rule",
				},
			],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_SIGN,
			arg_names: vec!["private_key", "message"],
			name: "SIGN",
			doc: PrimitiveDoc {
				example: "SIGN(key, message): signature",
				help: "Classic signature primitive. Here, `key` is a private key, for example `a`.",
			},
			arity: vec![2],
			output: vec![1],
			forgeable_secret: Some(0),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_SIGNVERIF,
			arg_names: vec!["public_key", "message", "signature"],
			name: "SIGNVERIF",
			doc: PrimitiveDoc {
				example: "SIGNVERIF(PUBKEY(key), message, SIGN(key, message)): verified",
				help: "Verifies if signature can be authenticated. If key a was used for SIGN, then SIGNVERIF will expect `PUBKEY(a)` as the key value. May be suffixed with `?` to halt the principal if verification fails.",
			},
			arity: vec![3],
			output: vec![1],
			rewrite: Some(RewriteRule {
				id: PRIM_SIGN,
				from: 2,
				from_output: None,
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
			doc: PrimitiveDoc {
				example: "PKE_ENC(PUBKEY(key), plaintext): ciphertext",
				help: "Public-key encryption.",
			},
			arity: vec![2],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0],
				output: None,
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
			doc: PrimitiveDoc {
				example: "PKE_DEC(key, PKE_ENC(PUBKEY(key), plaintext)): plaintext",
				help: "Public-key decryption.",
			},
			arity: vec![2],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0],
				output: None,
				reveals: vec![Reveal::Argument(1)],
				filter: filter_identity,
			}),
			rewrite: Some(RewriteRule {
				id: PRIM_PKE_ENC,
				from: 1,
				from_output: None,
				to: rewrite_to_arg1,
				matching: vec![(0, vec![0])],
				filter: filter_derived_key_rewrite,
			}),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_SHAMIR_SPLIT,
			arg_names: vec!["secret"],
			name: "SHAMIR_SPLIT",
			doc: PrimitiveDoc {
				example: "SHAMIR_SPLIT(k): s1, s2, s3",
				help: "In Verifpal, we allow splitting the key into three shares such that only two shares are required to reconstitute it.",
			},
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
			doc: PrimitiveDoc {
				example: "SHAMIR_JOIN(sa, sb): k",
				help: "Here, sa and sb must be two distinct elements out of the set (s1, s2, s3) in order to obtain k.",
			},
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
			doc: PrimitiveDoc {
				example: "RINGSIGN(key_a, PUBKEY(key_b), PUBKEY(key_c), message): signature",
				help: "Ring signature. In ring signatures, one of three parties (Alice, Bob and Charlie) signs a message. The resulting signature can be verified using the public key of any of the three parties, and the signature does not reveal the signatory, only that they are a member of the signing ring (Alice, Bob or Charlie). The first key must be the private key of the actual signer, while the subsequent two keys must be the public keys of the other potential signers.",
			},
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
			doc: PrimitiveDoc {
				example: "RINGSIGNVERIF(PUBKEY(a), PUBKEY(b), PUBKEY(c), m, RINGSIGN(a, PUBKEY(b), PUBKEY(c), m)): verified",
				help: "Verifies if a ring signature can be authenticated. The signer's public key must match one or more of the public keys provided, but the public keys may be provided in any order and not necessarily in the order used during the RINGSIGN operation. May be suffixed with `?` to halt the principal if verification fails.",
			},
			arity: vec![5],
			output: vec![1],
			rewrite: Some(RewriteRule {
				id: PRIM_RINGSIGN,
				from: 4,
				from_output: None,
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
			doc: PrimitiveDoc {
				example: "BLIND(k, m): b",
				help: "Message blinding primitive, useful for the implementation of blind signatures. Here, the sender uses the secret blinding factor `k` in order to blind message `m`, which can then be sent to the signer, who will be able to produce a signature on `m` without knowing `m`. Used in conjunction with UNBLIND -- see UNBLIND's documentation for more information.",
			},
			arity: vec![2],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0],
				output: None,
				reveals: vec![Reveal::Argument(1)],
				filter: filter_identity,
			}),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_UNBLIND,
			arg_names: vec!["blinding_factor", "message", "blinded_signature"],
			name: "UNBLIND",
			doc: PrimitiveDoc {
				example: "UNBLIND(k, m, SIGN(a, BLIND(k, m))): SIGN(a, m)",
				help: "Once `BLIND(k, m)` is signed by the signer, the sender can convert `SIGN(a, BLIND(k, m))` to `SIGN(a, m)` by unblinding the message using their secret blinding factor `k`. The resulting unblinded signature can then be used as if it were a regular signature by `a` over `m`.",
			},
			arity: vec![3],
			output: vec![1],
			rewrite: Some(RewriteRule {
				id: PRIM_SIGN,
				from: 2,
				from_output: None,
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
			doc: PrimitiveDoc {
				example: "ss, ct = KEM_ENCAP(PUBKEY(dk), r)",
				help: "Key encapsulation, as in a post-quantum KEM such as ML-KEM. Takes the recipient's encapsulation key `PUBKEY(dk)` and a random value, and binds two outputs: the shared secret and the encapsulation ciphertext that transports it. The random value should be freshly generated, since encapsulating twice under the same randomness yields the same shared secret. The random value may not be a public key, and the encapsulation key may not itself be a shared secret. A KEM says nothing about who performed the encapsulation: authenticate the ciphertext separately if the recipient needs to know who it came from.",
			},
			arity: vec![2],
			output: vec![2],
			decompose: Some(DecomposeRule {
				given: vec![0],
				output: Some(1),
				reveals: vec![Reveal::Output(0), Reveal::Argument(1)],
				filter: filter_extract_dh_exponent,
			}),
			argument_restrictions: vec![
				ArgumentRestriction {
					position: 0,
					banned: vec![PRIM_DH_KEX, PRIM_KEM_ENCAP, PRIM_KEM_DECAP],
					note: "",
				},
				ArgumentRestriction {
					position: 1,
					banned: vec![PRIM_PUBKEY, PRIM_DH_KEX],
					note: "",
				},
			],
			weak_reveals_output: Some(0),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_KEM_DECAP,
			arg_names: vec!["private_key", "ciphertext"],
			name: "KEM_DECAP",
			doc: PrimitiveDoc {
				example: "KEM_DECAP(dk, ct): ss",
				help: "Key decapsulation. Recovers the shared secret from an encapsulation ciphertext using the private decapsulation key `dk` matching the `PUBKEY(dk)` used to encapsulate. May be suffixed with `?` to halt the principal if decapsulation fails.",
			},
			arity: vec![2],
			output: vec![1],
			rewrite: Some(RewriteRule {
				id: PRIM_KEM_ENCAP,
				from: 1,
				from_output: Some(1),
				to: rewrite_to_kem_secret,
				matching: vec![(0, vec![0])],
				filter: filter_derived_key_rewrite,
			}),
			definition_check: true,
			bypass_key: Some(BypassKeyKind::Direct(0)),
			argument_restrictions: vec![ArgumentRestriction {
				position: 0,
				banned: vec![PRIM_PUBKEY, PRIM_DH_KEX],
				note: "",
			}],
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
