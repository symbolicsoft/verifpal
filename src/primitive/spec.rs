/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::*;
use crate::term::{Primitive, PrimitiveId, Value, value_nil};

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
pub(crate) const PRIM_THRESHOLD_SPLIT: PrimitiveId = 16;
pub(crate) const PRIM_THRESHOLD_JOIN: PrimitiveId = 17;
pub(crate) const PRIM_RINGSIGN: PrimitiveId = 18;
pub(crate) const PRIM_RINGSIGNVERIF: PrimitiveId = 19;
pub(crate) const PRIM_BLIND: PrimitiveId = 20;
pub(crate) const PRIM_UNBLIND: PrimitiveId = 21;
pub(crate) const PRIM_PUBKEY: PrimitiveId = 22;
pub(crate) const PRIM_DH_KEX: PrimitiveId = 23;
pub(crate) const PRIM_KEM_ENCAP: PrimitiveId = 24;
pub(crate) const PRIM_KEM_DECAP: PrimitiveId = 25;
pub(crate) const PRIM_THRESHOLD_SIGN: PrimitiveId = 26;

pub(super) const RENAMED: &[(&str, &str)] = &[
	("SHAMIR_SPLIT", "THRESHOLD_SPLIT"),
	("SHAMIR_JOIN", "THRESHOLD_JOIN"),
];

const AEAD_NONCE_HELP: &str = "`AEAD_ENC` and `AEAD_DEC` take a nonce as their second argument: \
                               `AEAD_ENC(key, nonce, plaintext, ad)` and \
                               `AEAD_DEC(key, nonce, ciphertext, ad)`";

fn filter_identity(_p: &Primitive, x: &Value, _i: usize) -> (Value, bool) {
	(x.clone(), true)
}

fn peel_key_derivation(x: &Value) -> (Value, bool) {
	match super::key_derivation_inner(x) {
		Some(inner) => (inner.clone(), true),
		None => (x.clone(), false),
	}
}

fn filter_extract_dh_exponent(_p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
	match i {
		0 => peel_key_derivation(x),
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
		0 => peel_key_derivation(x),
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

fn rewrite_to_unblind(p: &Primitive) -> Value {
	let inner = match &p.arguments[1] {
		Value::Primitive(inner_p) => inner_p.arguments.get(1).cloned().unwrap_or_else(value_nil),
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
				help: "Checks that two values are equal, for example two MACs. Its output is the assertion term itself, which anyone holding both inputs can build, and is usually discarded with `_`. May be suffixed with `?` to halt the principal if the check fails.",
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
				help: "Concatenates two to five values into one. For example, concatenating the strings `cat` and `dog` gives `catdog`.",
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
				help: "Splits a CONCAT back into its values, producing one to five outputs. Applied to anything but a CONCAT, it halts the principal when suffixed with `?`, and otherwise leaves the term unreduced.",
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
				help: "Secure hash function, for example BLAKE2s. Takes one to five arguments and returns one output.",
			},
			arity: vec![1, 2, 3, 4, 5],
			output: vec![1],
			weak_reveals: (0..5).map(Reveal::Argument).collect(),
			divergence_filler: true,
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_HKDF,
			arg_names: vec!["salt", "ikm", "info"],
			name: "HKDF",
			doc: PrimitiveDoc {
				example: "HKDF(salt, ikm, info): a, b...",
				help: "Hash-based key derivation, modelled on Krawczyk's HKDF. Derives one to five keys from the secret `ikm`; `salt` and `info` give the derivation its context. Takes exactly three arguments.",
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
				help: "Authenticated encryption with associated data, for example AES-GCM or ChaCha20-Poly1305. `ad` is authenticated but not encrypted, and decryption needs the same key, nonce and `ad`. `nonce` must be unique per key. If two ciphertexts share a key and nonce, the attacker can re-tag either one under any `ad`. Knowing one plaintext, or some fields of a `CONCAT` plaintext, also reveals the matching fields of the other and lets the attacker write its own values there.",
			},
			arity: vec![4],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0, 1],
				output: None,
				reveals: vec![Reveal::Argument(2)],
				filter: filter_identity,
			}),
			weak_reveals: vec![Reveal::Argument(2)],
			forgeable_secret: Some(0),
			reuse: Some(ReuseRule {
				fixed: vec![0, 1],
				reveals: vec![Reveal::Argument(2)],
				forgeable: vec![0, 1],
				masked: Some(2),
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
			rewrite: Some(RewriteRule {
				id: PRIM_AEAD_ENC,
				from: 2,
				from_output: None,
				to: RewriteTo::Computed(rewrite_to_arg2),
				matching: vec![(0, vec![0]), (1, vec![1]), (3, vec![3])],
				filter: filter_aead_dec_rewrite,
			}),
			definition_check: true,
			check_key: Some(CheckKeyKind::Direct(0)),
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
				help: "Symmetric encryption without authentication, for example AES-CBC or ChaCha20. Because it is unauthenticated, it is the only primitive that accepts `malleable`.",
			},
			arity: vec![2],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![0],
				output: None,
				reveals: vec![Reveal::Argument(1)],
				filter: filter_identity,
			}),
			weak_reveals: vec![Reveal::Argument(1)],
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
				to: RewriteTo::Computed(rewrite_to_arg1),
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
				help: "Keyed hash function, used for message authentication and in other constructions.",
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
			weak_reveals: vec![Reveal::Argument(0)],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_DH_KEX,
			arg_names: vec!["public_key", "private_key"],
			name: "DH_KEX",
			doc: PrimitiveDoc {
				example: "DH_KEX(PUBKEY(a), b): shared_secret",
				help: "Diffie-Hellman key exchange: `DH_KEX(PUBKEY(a), b)` and `DH_KEX(PUBKEY(b), a)` give the same shared secret. The first argument is the peer's public key and the second is your own private value, which may not be a public key. Neither argument may itself be a DH_KEX.",
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
				help: "Digital signature with the private key `key`, verified by SIGNVERIF under `PUBKEY(key)`.",
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
				help: "Verifies a signature: `SIGN(a, message)` verifies under `PUBKEY(a)`. May be suffixed with `?` to halt the principal if verification fails.",
			},
			arity: vec![3],
			output: vec![1],
			rewrite: Some(RewriteRule {
				id: PRIM_SIGN,
				from: 2,
				from_output: None,
				to: RewriteTo::Fixed(value_nil()),
				matching: vec![(0, vec![0]), (1, vec![1])],
				filter: filter_extract_dh_exponent,
			}),
			definition_check: true,
			check_key: Some(CheckKeyKind::Derived {
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
			weak_reveals: vec![Reveal::Argument(1)],
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
			rewrite: Some(RewriteRule {
				id: PRIM_PKE_ENC,
				from: 1,
				from_output: None,
				to: RewriteTo::Computed(rewrite_to_arg1),
				matching: vec![(0, vec![0])],
				filter: filter_derived_key_rewrite,
			}),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_THRESHOLD_SPLIT,
			arg_names: vec!["secret"],
			name: "THRESHOLD_SPLIT",
			doc: PrimitiveDoc {
				example: "THRESHOLD_SPLIT[t](k): s1, …, sn",
				help: "Splits a secret `k` into n shares, one per constant bound on the left, so that any t of them recover `k` through THRESHOLD_JOIN and fewer reveal nothing. The threshold t goes in the brackets, from 2 to n. The shares are also the signing shares of THRESHOLD_SIGN.",
			},
			arity: vec![1],
			output: (2..=MAX_SHARES as i32).collect(),
			recompose: Some(RecomposeRule { reveal: 0 }),
			threshold: Some(ThresholdSpec { min: 2 }),
			distinct_per_assignment: true,
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_THRESHOLD_JOIN,
			arg_names: vec![
				"piece1", "piece2", "piece3", "piece4", "piece5", "piece6", "piece7", "piece8",
				"piece9", "piece10", "piece11", "piece12", "piece13", "piece14", "piece15",
				"piece16",
			],
			name: "THRESHOLD_JOIN",
			doc: PrimitiveDoc {
				example: "THRESHOLD_JOIN(s1, s2, ...): k",
				help: "Combines at least t pieces of one THRESHOLD_SPLIT by Lagrange interpolation: t distinct shares give `k`, t `PUBKEY(share)` values give `PUBKEY(k)`, and t THRESHOLD_SIGN partials over distinct shares, the same commitments and the same message give `SIGN(k, message)`. Fewer pieces, a repeated share, a nonce missing from the commitments, or partials that disagree leave the term unreduced.",
			},
			arity: (2..=MAX_SHARES as i32).collect(),
			output: vec![1],
			rebuild: Some(RebuildRule {
				id: PRIM_THRESHOLD_SPLIT,
				reveal: 0,
			}),
			combine: vec![
				CombineRule {
					partial: PRIM_THRESHOLD_SIGN,
					split: PRIM_THRESHOLD_SPLIT,
					share: 0,
					agree: vec![2, 3],
					carry: vec![3],
					whole: PRIM_SIGN,
					bindings: vec![CombineBinding {
						argument: 1,
						list: 2,
						wrapper: PRIM_PUBKEY,
						sequence: PRIM_CONCAT,
					}],
				},
				CombineRule {
					partial: PRIM_PUBKEY,
					split: PRIM_THRESHOLD_SPLIT,
					share: 0,
					agree: vec![],
					carry: vec![],
					whole: PRIM_PUBKEY,
					bindings: vec![],
				},
			],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_THRESHOLD_SIGN,
			arg_names: vec!["share", "nonce", "commitments", "message"],
			name: "THRESHOLD_SIGN",
			doc: PrimitiveDoc {
				example: "THRESHOLD_SIGN(share, nonce, commitments, message): partial",
				help: "One signer's partial signature, as in FROST's second round. `share` is an output of THRESHOLD_SPLIT, `nonce` is the signer's fresh secret nonce, `commitments` is the session's list of `PUBKEY(nonce)` commitments, usually a CONCAT, and `message` is what is signed. THRESHOLD_JOIN combines t partials into `SIGN(k, message)`. A partial gives away its share when its nonce, commitments and message are all known, or when its nonce is reused under the same share.",
			},
			arity: vec![4],
			output: vec![1],
			decompose: Some(DecomposeRule {
				given: vec![1, 2, 3],
				output: None,
				reveals: vec![Reveal::Argument(0)],
				filter: filter_identity,
			}),
			forgeable_secret: Some(0),
			reuse: Some(ReuseRule {
				fixed: vec![0, 1],
				reveals: vec![Reveal::Argument(0)],
				forgeable: vec![],
				masked: None,
			}),
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_RINGSIGN,
			arg_names: vec!["signer_key", "public_key_b", "public_key_c", "message"],
			name: "RINGSIGN",
			doc: PrimitiveDoc {
				example: "RINGSIGN(key_a, PUBKEY(key_b), PUBKEY(key_c), message): signature",
				help: "Ring signature over a ring of three. The first key is the signer's private key and the other two are the other members' public keys. The signature shows that one of the three signed, not which one.",
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
				help: "Verifies a ring signature. The three public keys may come in any order, and the signer's must be among them. May be suffixed with `?` to halt the principal if verification fails.",
			},
			arity: vec![5],
			output: vec![1],
			rewrite: Some(RewriteRule {
				id: PRIM_RINGSIGN,
				from: 4,
				from_output: None,
				to: RewriteTo::Fixed(value_nil()),
				matching: vec![
					(0, vec![0, 1, 2]),
					(1, vec![0, 1, 2]),
					(2, vec![0, 1, 2]),
					(3, vec![3]),
				],
				filter: filter_ringsignverif_rewrite,
			}),
			definition_check: true,
			check_key: Some(CheckKeyKind::Derived {
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
				help: "Blinds the message `m` with the secret factor `k`, for blind signatures: a signer can sign `BLIND(k, m)` without learning `m`, and UNBLIND turns that signature into one over `m`.",
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
				help: "Removes the blinding from a signature: with the blinding factor `k`, `SIGN(a, BLIND(k, m))` becomes `SIGN(a, m)`, an ordinary signature by `a` over `m`.",
			},
			arity: vec![3],
			output: vec![1],
			rewrite: Some(RewriteRule {
				id: PRIM_SIGN,
				from: 2,
				from_output: None,
				to: RewriteTo::Computed(rewrite_to_unblind),
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
				help: "Key encapsulation, as in ML-KEM. Takes the recipient's encapsulation key `PUBKEY(dk)` and a random value, and outputs a shared secret and the ciphertext that carries it. Generate the random value fresh, since the same randomness gives the same shared secret. A KEM does not say who encapsulated, so authenticate the ciphertext separately when the recipient needs to know.",
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
			weak_reveals: vec![Reveal::Output(0)],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_KEM_DECAP,
			arg_names: vec!["private_key", "ciphertext"],
			name: "KEM_DECAP",
			doc: PrimitiveDoc {
				example: "KEM_DECAP(dk, ct): ss",
				help: "Key decapsulation: recovers the shared secret from a ciphertext with the private key `dk` whose `PUBKEY(dk)` it was encapsulated to. May be suffixed with `?` to halt the principal if decapsulation fails.",
			},
			arity: vec![2],
			output: vec![1],
			rewrite: Some(RewriteRule {
				id: PRIM_KEM_ENCAP,
				from: 1,
				from_output: Some(1),
				to: RewriteTo::Computed(rewrite_to_kem_secret),
				matching: vec![(0, vec![0])],
				filter: filter_derived_key_rewrite,
			}),
			definition_check: true,
			check_key: Some(CheckKeyKind::Direct(0)),
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
	use crate::primitive::Capabilities;
	use crate::term::Application;
	use crate::testing::*;

	#[test]
	fn extract_exponent_rejects_a_bare_constant() {
		let k = make_constant("fey_k");
		let p = Primitive::from(Application {
			id: PRIM_SIGNVERIF,
			arguments: vec![k.clone()],
			output: 0,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
		});
		let (_, ok) = filter_extract_dh_exponent(&p, &k, 0);
		assert!(!ok, "a bare constant is not a public key");
	}

	#[test]
	fn extract_exponent_rejects_a_non_key_primitive() {
		let k = make_constant("fez_k");
		let hashed = make_primitive(PRIM_HASH, vec![k], 0);
		let p = Primitive::from(Application {
			id: PRIM_SIGNVERIF,
			arguments: vec![hashed.clone()],
			output: 0,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
		});
		let (_, ok) = filter_extract_dh_exponent(&p, &hashed, 0);
		assert!(!ok, "only the key-derivation constructor may be peeled");
	}
}
