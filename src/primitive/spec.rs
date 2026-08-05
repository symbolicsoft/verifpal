/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::*;
use crate::types::*;
use crate::value::{value_g, value_nil};

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
		Value::Primitive(pp) if pp.id == PRIM_CONCAT => (
			true,
			pp.arguments
				.get(p.output)
				.cloned()
				.unwrap_or_else(value_nil),
		),
		_ => (false, Value::Primitive(Arc::new(p.clone()))),
	}
}

fn rewrite_to_arg1(p: &Primitive) -> Value {
	p.arguments[1].clone()
}

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
			reveals_args: false,
		},
	]
}

pub(super) fn build_primitive_specs() -> Vec<PrimitiveSpec> {
	vec![
		PrimitiveSpec {
			id: PRIM_PWHASH,
			name: "PW_HASH",
			arity: vec![1, 2, 3, 4, 5],
			output: vec![1],
			password_hashing: vec![0, 1, 2, 3, 4],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_HASH,
			name: "HASH",
			arity: vec![1, 2, 3, 4, 5],
			output: vec![1],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_HKDF,
			name: "HKDF",
			arity: vec![3],
			output: vec![1, 2, 3, 4, 5],
			..PrimitiveSpec::default()
		},
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
			},
			..PrimitiveSpec::default()
		},
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
			},
			..PrimitiveSpec::default()
		},
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
		PrimitiveSpec {
			id: PRIM_MAC,
			name: "MAC",
			arity: vec![2],
			output: vec![1],
			..PrimitiveSpec::default()
		},
		PrimitiveSpec {
			id: PRIM_SIGN,
			name: "SIGN",
			arity: vec![2],
			output: vec![1],
			..PrimitiveSpec::default()
		},
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
			},
			..PrimitiveSpec::default()
		},
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
		PrimitiveSpec {
			id: PRIM_RINGSIGN,
			name: "RINGSIGN",
			arity: vec![4],
			output: vec![1],
			..PrimitiveSpec::default()
		},
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
			},
			..PrimitiveSpec::default()
		},
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
