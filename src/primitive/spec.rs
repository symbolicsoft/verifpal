/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! Primitive specifications.
//!
//! To add a new primitive to Verifpal, this is the only file you need to edit:
//!   1. Add a new `PRIM_*` constant.
//!   2. If it is a core primitive, add a `PrimitiveCoreSpec` to `build_core_specs()`.
//!      Otherwise add a `PrimitiveSpec` to `build_primitive_specs()`.
//!   3. If the primitive needs custom filter, core-rule, or rewrite-to logic,
//!      define the function in this file and reference it from the spec.

use std::sync::Arc;

use super::*;
use crate::types::*;
use crate::value::{value_g, value_nil};

// ---------------------------------------------------------------------------
// Primitive ID constants
// ---------------------------------------------------------------------------

pub const PRIM_ASSERT: PrimitiveId = 1;
pub const PRIM_CONCAT: PrimitiveId = 2;
pub const PRIM_SPLIT: PrimitiveId = 3;
pub const PRIM_PWHASH: PrimitiveId = 4;
pub const PRIM_HASH: PrimitiveId = 5;
pub const PRIM_HKDF: PrimitiveId = 6;
pub const PRIM_AEAD_ENC: PrimitiveId = 7;
pub const PRIM_AEAD_DEC: PrimitiveId = 8;
pub const PRIM_ENC: PrimitiveId = 9;
pub const PRIM_DEC: PrimitiveId = 10;
pub const PRIM_MAC: PrimitiveId = 11;
pub const PRIM_SIGN: PrimitiveId = 12;
pub const PRIM_SIGNVERIF: PrimitiveId = 13;
pub const PRIM_PKE_ENC: PrimitiveId = 14;
pub const PRIM_PKE_DEC: PrimitiveId = 15;
pub const PRIM_SHAMIR_SPLIT: PrimitiveId = 16;
pub const PRIM_SHAMIR_JOIN: PrimitiveId = 17;
pub const PRIM_RINGSIGN: PrimitiveId = 18;
pub const PRIM_RINGSIGNVERIF: PrimitiveId = 19;
pub const PRIM_BLIND: PrimitiveId = 20;
pub const PRIM_UNBLIND: PrimitiveId = 21;

// ---------------------------------------------------------------------------
// Filter functions
// ---------------------------------------------------------------------------

fn filter_identity(_p: &Primitive, x: &Value, _i: usize) -> (Value, bool) {
	(x.clone(), true)
}

fn filter_extract_dh_exponent(_p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
	match i {
		0 => match x {
			Value::Constant(_) | Value::Primitive(_) => (x.clone(), false),
			Value::Equation(e) => {
				if e.values.len() != 2 {
					return (x.clone(), false);
				}
				if !e.values[0].equivalent(&value_g(), true) {
					return (x.clone(), false);
				}
				(e.values[1].clone(), true)
			}
		},
		1 => (x.clone(), true),
		_ => (x.clone(), false),
	}
}

fn filter_pke_dec_rewrite(_p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
	match i {
		0 => match x {
			Value::Constant(_) | Value::Primitive(_) => {
				let eq = Value::Equation(Arc::new(Equation {
					values: vec![value_g(), x.clone()],
				}));
				(eq, true)
			}
			Value::Equation(_) => (x.clone(), false),
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
			Value::Constant(_) | Value::Primitive(_) => (x.clone(), false),
			Value::Equation(e) => {
				if e.values.len() == 2 {
					(e.values[1].clone(), true)
				} else {
					(x.clone(), false)
				}
			}
		},
		1..=4 => (x.clone(), true),
		_ => (x.clone(), false),
	}
}

fn filter_unblind_rewrite(p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
	match i {
		1 => {
			let blind_prim = Value::Primitive(Arc::new(Primitive {
				id: PRIM_BLIND,
				arguments: vec![p.arguments[0].clone(), p.arguments[1].clone()],
				output: 0,
				instance_check: false,
			}));
			(blind_prim, true)
		}
		_ => (x.clone(), false),
	}
}

// ---------------------------------------------------------------------------
// Core rule functions
// ---------------------------------------------------------------------------

fn core_rule_assert(p: &Primitive) -> (bool, Vec<Value>) {
	let v = vec![Value::Primitive(Arc::new(p.clone()))];
	if p.arguments[0].equivalent(&p.arguments[1], true) {
		(true, v)
	} else {
		(false, v)
	}
}

fn core_rule_split(p: &Primitive) -> (bool, Vec<Value>) {
	let v = vec![Value::Primitive(Arc::new(p.clone()))];
	match &p.arguments[0] {
		Value::Constant(_) => (false, v),
		Value::Primitive(pp) => {
			if pp.id == PRIM_CONCAT {
				(true, pp.arguments.clone())
			} else {
				(false, v)
			}
		}
		Value::Equation(_) => (false, v),
	}
}

// ---------------------------------------------------------------------------
// Rewrite-to functions
// ---------------------------------------------------------------------------

/// Rewrite returns the second argument (ciphertext -> plaintext).
/// Used by AEAD_DEC, DEC, PKE_DEC.
fn rewrite_to_arg1(p: &Primitive) -> Value {
	p.arguments[1].clone()
}

/// Rewrite returns nil (verification-only primitives).
/// Used by SIGNVERIF, RINGSIGNVERIF.
fn rewrite_to_nil(_p: &Primitive) -> Value {
	value_nil()
}

fn rewrite_to_unblind(p: &Primitive) -> Value {
	let inner = match &p.arguments[1] {
		Value::Primitive(inner_p) => inner_p.arguments[1].clone(),
		_ => value_nil(),
	};
	Value::Primitive(Arc::new(Primitive {
		id: PRIM_SIGN,
		arguments: vec![p.arguments[0].clone(), inner],
		output: 0,
		instance_check: false,
	}))
}

// ---------------------------------------------------------------------------
// Core primitive specifications
// ---------------------------------------------------------------------------

pub(super) fn build_core_specs() -> Vec<PrimitiveCoreSpec> {
	vec![
		PrimitiveCoreSpec {
			id: PRIM_ASSERT,
			name: "ASSERT",
			arity: vec![2],
			output: vec![1],
			has_rule: true,
			core_rule: Some(core_rule_assert),
			definition_check: true,
			explosive: false,
			reveals_args: false,
		},
		PrimitiveCoreSpec {
			id: PRIM_CONCAT,
			name: "CONCAT",
			arity: vec![2, 3, 4, 5],
			output: vec![1],
			has_rule: false,
			core_rule: None,
			definition_check: false,
			explosive: true,
			reveals_args: true,
		},
		PrimitiveCoreSpec {
			id: PRIM_SPLIT,
			name: "SPLIT",
			arity: vec![1],
			output: vec![1, 2, 3, 4, 5],
			has_rule: true,
			core_rule: Some(core_rule_split),
			definition_check: true,
			explosive: false,
			reveals_args: false,
		},
	]
}

// ---------------------------------------------------------------------------
// Primitive specifications
// ---------------------------------------------------------------------------
//
// # How to add a new primitive
//
// 1. Define a `PRIM_*` constant with a unique ID (above).
// 2. Add a `PrimitiveSpec { .. }` entry to the vec returned below.
// 3. If your primitive needs custom filter, core-rule, or rewrite-to
//    behavior, write the function in this file and reference it.
//
// That's it. The rest of the engine picks up the spec automatically.
//
//
// # PrimitiveSpec field reference
//
// ## Identity
//
// `id`:    Unique numeric ID (the `PRIM_*` constant).
// `name`:  Name as it appears in Verifpal models (e.g. "AEAD_ENC").
//
// ## Shape
//
// `arity`:  Allowed argument counts. `vec![3]` means exactly 3 arguments;
//           `vec![1,2,3,4,5]` means 1 through 5 are all valid arities.
// `output`: Allowed output counts. `vec![1]` means one output value;
//           `vec![3]` (SHAMIR_SPLIT) means it always produces 3 shares;
//           `vec![1,2,3,4,5]` (HKDF) means the caller picks how many
//           outputs to bind, and any count from 1 to 5 is valid.
//
// ## Decompose rule
//
// Models active decryption: "if the attacker knows the key, they can
// open the ciphertext." Set `decompose.has_rule = true` to enable.
//
// `decompose.given`:   Argument indices the attacker must already know.
//                      For ENC(key, pt), `given: vec![0]` means the
//                      attacker needs the key (argument 0).
// `decompose.reveal`:  Argument index revealed on success.
//                      For ENC(key, pt), `reveal: 1` gives the plaintext.
// `decompose.filter`:  Optional per-argument transform applied during
//                      active decomposition.  `filter_identity` passes
//                      arguments through unchanged.
//                      `filter_extract_dh_exponent` extracts `sk` from
//                      a public key of the form `G^sk`, which is needed
//                      for PKE_ENC where the "key" the attacker must
//                      possess is not the public key itself but the
//                      private exponent.
// `decompose.passive_reveal`:
//                      Argument indices leaked even without the key.
//                      For AEAD_ENC, `passive_reveal: vec![2]` means the
//                      associated data (argument 2) is always visible to
//                      the attacker on the wire, even without knowing the
//                      encryption key.
//
// ## Recompose rule
//
// Models threshold reconstruction: "if the attacker has enough shares,
// they can recover the secret." Only relevant for primitives with
// multiple outputs (e.g. SHAMIR_SPLIT). Set `recompose.has_rule = true`.
//
// `recompose.given`:   Each inner vec is an alternative sufficient set
//                      of output indices. For SHAMIR_SPLIT:
//                      `given: vec![vec![0,1], vec![0,2], vec![1,2]]`
//                      means any 2-of-3 shares suffice.
// `recompose.reveal`:  Index of the original input to recover.
//                      `reveal: 0` means the secret (argument 0 of the
//                      SHAMIR_SPLIT that produced the shares).
//
// ## Rewrite rule
//
// Models inverse operations: "DEC undoes ENC when the keys match."
// This is the core mechanism for symbolic reduction of paired
// primitives (encrypt/decrypt, sign/verify). Set `rewrite.has_rule`.
//
// `rewrite.id`:        The primitive this one inverts.
//                      For DEC, `id: PRIM_ENC` — DEC undoes ENC.
//                      For SIGNVERIF, `id: PRIM_SIGN`.
// `rewrite.from`:      Which argument of *this* primitive is expected to
//                      contain the inverse primitive. For DEC(key, ct),
//                      `from: 1` means argument 1 (the ciphertext) should
//                      be an ENC(...) for the rewrite to fire.
// `rewrite.to`:        Function producing the rewritten output value.
//                      `rewrite_to_arg1` returns the plaintext (argument 1
//                      of the inner ENC). `rewrite_to_nil` returns nil
//                      (for verification-only primitives like SIGNVERIF,
//                      whose output is just "verified" with no data).
// `rewrite.matching`:  Constraints that must hold between *this* primitive's
//                      arguments and the inner primitive's arguments.
//                      Each entry `(my_arg, inner_args)` means: argument
//                      `my_arg` of *this* primitive must be equivalent to
//                      at least one of the `inner_args` of the inner
//                      primitive.
//                      Example — DEC(key, ENC(k2, pt)):
//                        `matching: vec![(0, vec![0])]`
//                        means DEC.arg[0] (key) must equal ENC.arg[0] (k2).
//                      Example — RINGSIGNVERIF(pk1, pk2, pk3, msg, sig):
//                        `matching: vec![(0,vec![0,1,2]), (1,vec![0,1,2]),
//                                        (2,vec![0,1,2]), (3,vec![3])]`
//                        means each of the three public keys can match any
//                        of the three RINGSIGN key slots, but the message
//                        (arg 3) must match exactly.
// `rewrite.filter`:    Optional per-argument transform applied during
//                      rewrite matching. Similar to decompose.filter but
//                      used during the rewrite-specific matching pass.
//                      For AEAD_DEC, `filter_aead_dec_rewrite` allows
//                      matching on arguments 0 and 2 (key and AD).
//                      For SIGNVERIF, `filter_extract_dh_exponent`
//                      extracts the private key from a DH public key.
//
// ## Rebuild rule
//
// Models join operations that eagerly reconstruct a split value during
// symbolic rewriting (rather than during attacker analysis). This is
// used for SHAMIR_JOIN, where the engine can simplify the protocol
// state by recognizing that two shares from the same SHAMIR_SPLIT
// recover the original secret. Set `rebuild.has_rule = true`.
//
// `rebuild.id`:        The split primitive being reconstructed.
//                      For SHAMIR_JOIN, `id: PRIM_SHAMIR_SPLIT`.
// `rebuild.given`:     Each inner vec lists argument indices of *this*
//                      primitive that must all contain inner primitives
//                      matching `rebuild.id`, with the same inputs but
//                      different outputs.
//                      For SHAMIR_JOIN(a, b):
//                        `vec![vec![0,1], vec![1,0]]`
//                        means arguments 0 and 1 must both be shares
//                        from the same SHAMIR_SPLIT.
//                      (Entries referencing out-of-bounds indices are
//                      harmlessly skipped.)
// `rebuild.reveal`:    Index of the original input (of the inner split
//                      primitive) to recover. `reveal: 0` recovers
//                      the secret that was passed to SHAMIR_SPLIT.
//
// ## Behavioral flags
//
// `definition_check`:  When true, this is a *checked* primitive: in a
//                      well-formed protocol, its rewrite rule must
//                      succeed. AEAD_DEC must actually decrypt; SIGNVERIF
//                      must actually verify. If the rule fails, the
//                      engine treats it as a protocol error. When false
//                      (the default), the primitive can appear without
//                      its rewrite succeeding.
//
// `explosive`:         When true, the primitive generates many candidate
//                      values during attacker injection, so the engine
//                      defers exploring it until later proof stages.
//                      Set this for hash-like primitives (HASH, HKDF)
//                      where the attacker could wrap any known value
//                      in the primitive to produce a candidate.
//
// `password_hashing`:  Argument indices where password values are
//                      cryptographically protected. The attacker can
//                      only attempt offline password guessing against
//                      arguments *not* in this list. For ENC(key, pt),
//                      `password_hashing: vec![1]` means the plaintext
//                      (arg 1) is protected; the key (arg 0) is the
//                      attackable surface.
//
// `bypass_key`:        How the active attacker extracts the secret needed
//                      to forge an input that bypasses a failed guard.
//                      `None` means no bypass is possible.
//                      `Some(BypassKeyKind::Direct(i))` takes argument i
//                      directly (e.g. the decryption key in DEC).
//                      `Some(BypassKeyKind::DhExponent(i))` extracts the
//                      last DH exponent from an equation at argument i
//                      (e.g. the signing key `sk` from a public key
//                      `G^sk` in SIGNVERIF).
//
//
// # Example: a simple encryption primitive
//
// Suppose you wanted to add a primitive called STREAM_ENC(key, plaintext)
// with a corresponding STREAM_DEC(key, ciphertext). You would:
//
//   const PRIM_STREAM_ENC: PrimitiveId = 22;
//   const PRIM_STREAM_DEC: PrimitiveId = 23;
//
// Then add two PrimitiveSpec entries:
//
//   PrimitiveSpec {
//       id: PRIM_STREAM_ENC,
//       name: "STREAM_ENC",
//       arity: vec![2],              // takes key + plaintext
//       output: vec![1],             // produces one ciphertext
//       decompose: DecomposeRule {
//           has_rule: true,
//           given: vec![0],          // attacker needs the key
//           reveal: 1,               // to learn the plaintext
//           filter: Some(filter_identity),
//           ..DecomposeRule::default()
//       },
//       password_hashing: vec![1],   // plaintext is protected
//       ..PrimitiveSpec::default()
//   },
//   PrimitiveSpec {
//       id: PRIM_STREAM_DEC,
//       name: "STREAM_DEC",
//       arity: vec![2],              // takes key + ciphertext
//       output: vec![1],             // produces one plaintext
//       decompose: DecomposeRule {
//           has_rule: true,
//           given: vec![0],
//           reveal: 1,
//           filter: Some(filter_identity),
//           ..DecomposeRule::default()
//       },
//       rewrite: RewriteRule {
//           has_rule: true,
//           id: PRIM_STREAM_ENC,     // STREAM_DEC undoes STREAM_ENC
//           from: 1,                 // arg 1 should be a STREAM_ENC(...)
//           to: Some(rewrite_to_arg1), // result = inner plaintext
//           matching: vec![(0, vec![0])], // keys must match
//           filter: Some(filter_dec_rewrite),
//       },
//       definition_check: true,      // decryption must succeed
//       bypass_key: Some(BypassKeyKind::Direct(0)), // key is arg 0
//       ..PrimitiveSpec::default()
//   },

pub(super) fn build_primitive_specs() -> Vec<PrimitiveSpec> {
	vec![
		// PW_HASH
		PrimitiveSpec {
			id: PRIM_PWHASH,
			name: "PW_HASH",
			arity: vec![1, 2, 3, 4, 5],
			output: vec![1],
			password_hashing: vec![0, 1, 2, 3, 4],
			..PrimitiveSpec::default()
		},
		// HASH
		PrimitiveSpec {
			id: PRIM_HASH,
			name: "HASH",
			arity: vec![1, 2, 3, 4, 5],
			output: vec![1],
			explosive: true,
			..PrimitiveSpec::default()
		},
		// HKDF
		PrimitiveSpec {
			id: PRIM_HKDF,
			name: "HKDF",
			arity: vec![3],
			output: vec![1, 2, 3, 4, 5],
			explosive: true,
			..PrimitiveSpec::default()
		},
		// AEAD_ENC
		PrimitiveSpec {
			id: PRIM_AEAD_ENC,
			name: "AEAD_ENC",
			arity: vec![3],
			output: vec![1],
			decompose: DecomposeRule {
				has_rule: true,
				given: vec![0],
				reveal: 1,
				filter: Some(filter_identity),
				passive_reveal: vec![2],
			},
			password_hashing: vec![1],
			..PrimitiveSpec::default()
		},
		// AEAD_DEC
		PrimitiveSpec {
			id: PRIM_AEAD_DEC,
			name: "AEAD_DEC",
			arity: vec![3],
			output: vec![1],
			decompose: DecomposeRule {
				has_rule: true,
				given: vec![0],
				reveal: 1,
				filter: Some(filter_identity),
				..DecomposeRule::default()
			},
			rewrite: RewriteRule {
				has_rule: true,
				id: PRIM_AEAD_ENC,
				from: 1,
				to: Some(rewrite_to_arg1),
				matching: vec![(0, vec![0]), (2, vec![2])],
				filter: Some(filter_aead_dec_rewrite),
			},
			definition_check: true,
			bypass_key: Some(BypassKeyKind::Direct(0)),
			..PrimitiveSpec::default()
		},
		// ENC
		PrimitiveSpec {
			id: PRIM_ENC,
			name: "ENC",
			arity: vec![2],
			output: vec![1],
			decompose: DecomposeRule {
				has_rule: true,
				given: vec![0],
				reveal: 1,
				filter: Some(filter_identity),
				..DecomposeRule::default()
			},
			password_hashing: vec![1],
			..PrimitiveSpec::default()
		},
		// DEC
		PrimitiveSpec {
			id: PRIM_DEC,
			name: "DEC",
			arity: vec![2],
			output: vec![1],
			decompose: DecomposeRule {
				has_rule: true,
				given: vec![0],
				reveal: 1,
				filter: Some(filter_identity),
				..DecomposeRule::default()
			},
			rewrite: RewriteRule {
				has_rule: true,
				id: PRIM_ENC,
				from: 1,
				to: Some(rewrite_to_arg1),
				matching: vec![(0, vec![0])],
				filter: Some(filter_dec_rewrite),
			},
			bypass_key: Some(BypassKeyKind::Direct(0)),
			..PrimitiveSpec::default()
		},
		// MAC
		PrimitiveSpec {
			id: PRIM_MAC,
			name: "MAC",
			arity: vec![2],
			output: vec![1],
			password_hashing: vec![1],
			..PrimitiveSpec::default()
		},
		// SIGN
		PrimitiveSpec {
			id: PRIM_SIGN,
			name: "SIGN",
			arity: vec![2],
			output: vec![1],
			password_hashing: vec![1],
			..PrimitiveSpec::default()
		},
		// SIGNVERIF
		PrimitiveSpec {
			id: PRIM_SIGNVERIF,
			name: "SIGNVERIF",
			arity: vec![3],
			output: vec![1],
			rewrite: RewriteRule {
				has_rule: true,
				id: PRIM_SIGN,
				from: 2,
				to: Some(rewrite_to_nil),
				matching: vec![(0, vec![0]), (1, vec![1])],
				filter: Some(filter_extract_dh_exponent),
			},
			definition_check: true,
			bypass_key: Some(BypassKeyKind::DhExponent(0)),
			..PrimitiveSpec::default()
		},
		// PKE_ENC
		PrimitiveSpec {
			id: PRIM_PKE_ENC,
			name: "PKE_ENC",
			arity: vec![2],
			output: vec![1],
			decompose: DecomposeRule {
				has_rule: true,
				given: vec![0],
				reveal: 1,
				filter: Some(filter_extract_dh_exponent),
				..DecomposeRule::default()
			},
			password_hashing: vec![1],
			..PrimitiveSpec::default()
		},
		// PKE_DEC
		PrimitiveSpec {
			id: PRIM_PKE_DEC,
			name: "PKE_DEC",
			arity: vec![2],
			output: vec![1],
			decompose: DecomposeRule {
				has_rule: true,
				given: vec![0],
				reveal: 1,
				filter: Some(filter_identity),
				..DecomposeRule::default()
			},
			rewrite: RewriteRule {
				has_rule: true,
				id: PRIM_PKE_ENC,
				from: 1,
				to: Some(rewrite_to_arg1),
				matching: vec![(0, vec![0])],
				filter: Some(filter_pke_dec_rewrite),
			},
			bypass_key: Some(BypassKeyKind::Direct(0)),
			..PrimitiveSpec::default()
		},
		// SHAMIR_SPLIT
		PrimitiveSpec {
			id: PRIM_SHAMIR_SPLIT,
			name: "SHAMIR_SPLIT",
			arity: vec![1],
			output: vec![3],
			recompose: RecomposeRule {
				has_rule: true,
				given: vec![vec![0, 1], vec![0, 2], vec![1, 2]],
				reveal: 0,
			},
			..PrimitiveSpec::default()
		},
		// SHAMIR_JOIN
		PrimitiveSpec {
			id: PRIM_SHAMIR_JOIN,
			name: "SHAMIR_JOIN",
			arity: vec![2],
			output: vec![1],
			rebuild: RebuildRule {
				has_rule: true,
				id: PRIM_SHAMIR_SPLIT,
				given: vec![
					vec![0, 1],
					vec![1, 0],
					vec![0, 2],
					vec![2, 0],
					vec![1, 2],
					vec![2, 1],
				],
				reveal: 0,
			},
			..PrimitiveSpec::default()
		},
		// RINGSIGN
		PrimitiveSpec {
			id: PRIM_RINGSIGN,
			name: "RINGSIGN",
			arity: vec![4],
			output: vec![1],
			password_hashing: vec![3],
			..PrimitiveSpec::default()
		},
		// RINGSIGNVERIF
		PrimitiveSpec {
			id: PRIM_RINGSIGNVERIF,
			name: "RINGSIGNVERIF",
			arity: vec![5],
			output: vec![1],
			rewrite: RewriteRule {
				has_rule: true,
				id: PRIM_RINGSIGN,
				from: 4,
				to: Some(rewrite_to_nil),
				matching: vec![
					(0, vec![0, 1, 2]),
					(1, vec![0, 1, 2]),
					(2, vec![0, 1, 2]),
					(3, vec![3]),
				],
				filter: Some(filter_ringsignverif_rewrite),
			},
			definition_check: true,
			bypass_key: Some(BypassKeyKind::DhExponent(0)),
			..PrimitiveSpec::default()
		},
		// BLIND
		PrimitiveSpec {
			id: PRIM_BLIND,
			name: "BLIND",
			arity: vec![2],
			output: vec![1],
			decompose: DecomposeRule {
				has_rule: true,
				given: vec![0],
				reveal: 1,
				filter: Some(filter_identity),
				..DecomposeRule::default()
			},
			password_hashing: vec![1],
			..PrimitiveSpec::default()
		},
		// UNBLIND
		PrimitiveSpec {
			id: PRIM_UNBLIND,
			name: "UNBLIND",
			arity: vec![3],
			output: vec![1],
			rewrite: RewriteRule {
				has_rule: true,
				id: PRIM_SIGN,
				from: 2,
				to: Some(rewrite_to_unblind),
				matching: vec![(0, vec![1])],
				filter: Some(filter_unblind_rewrite),
			},
			..PrimitiveSpec::default()
		},
	]
}
