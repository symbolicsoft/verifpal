/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use crate::types::*;
use crate::value::{value_g, value_nil};

// Primitive ID constants
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

type FilterFn = fn(&Primitive, &Value, usize) -> (Value, bool);
type CoreRuleFn = fn(&Primitive) -> (bool, Vec<Value>);
type RewriteToFn = fn(&Primitive) -> Value;

#[derive(Clone, Default)]
pub(crate) struct DecomposeRule {
	pub has_rule: bool,
	pub given: Vec<usize>,
	pub reveal: usize,
	pub filter: Option<FilterFn>,
	pub passive_reveal: Vec<usize>,
}

#[derive(Clone, Default)]
pub(crate) struct RecomposeRule {
	pub has_rule: bool,
	pub given: Vec<Vec<usize>>,
	pub reveal: usize,
}

#[derive(Clone, Default)]
pub(crate) struct RewriteRule {
	pub has_rule: bool,
	pub id: PrimitiveId,
	pub from: usize,
	pub to: Option<RewriteToFn>,
	pub matching: Vec<(usize, Vec<usize>)>,
	pub filter: Option<FilterFn>,
}

#[derive(Clone, Default)]
pub(crate) struct RebuildRule {
	pub has_rule: bool,
	pub id: PrimitiveId,
	pub given: Vec<Vec<usize>>,
	pub reveal: usize,
}

#[derive(Clone)]
pub(crate) struct PrimitiveCoreSpec {
	pub name: &'static str,
	pub id: PrimitiveId,
	pub arity: Vec<i32>,
	pub output: Vec<i32>,
	pub has_rule: bool,
	pub core_rule: Option<CoreRuleFn>,
	pub definition_check: bool,
	pub explosive: bool,
}

#[derive(Clone, Default)]
pub(crate) struct PrimitiveSpec {
	pub name: &'static str,
	pub id: PrimitiveId,
	pub arity: Vec<i32>,
	pub output: Vec<i32>,
	pub decompose: DecomposeRule,
	pub recompose: RecomposeRule,
	pub rewrite: RewriteRule,
	pub rebuild: RebuildRule,
	pub definition_check: bool,
	pub explosive: bool,
	pub password_hashing: Vec<usize>,
}

// Filter functions
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

// Core rule functions
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

// Rewrite To functions

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
	// Get the inner SIGN primitive's argument[1] from p.arguments[1] which should be SIGN
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

fn build_core_specs() -> Vec<PrimitiveCoreSpec> {
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
		},
	]
}

fn build_primitive_specs() -> Vec<PrimitiveSpec> {
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

static CORE_SPECS: LazyLock<HashMap<PrimitiveId, PrimitiveCoreSpec>> = LazyLock::new(|| {
	let specs = build_core_specs();
	specs.into_iter().map(|s| (s.id, s)).collect()
});

static PRIM_SPECS: LazyLock<HashMap<PrimitiveId, PrimitiveSpec>> = LazyLock::new(|| {
	let specs = build_primitive_specs();
	specs.into_iter().map(|s| (s.id, s)).collect()
});

pub(crate) trait PrimitiveDefinition {
	fn name(&self) -> &'static str;
	fn arity(&self) -> &[i32];
	fn output(&self) -> &[i32];
	fn definition_check(&self) -> bool;
	fn is_explosive(&self) -> bool;
	fn has_rewrite_rule(&self) -> bool;
	fn has_single_output(&self) -> bool {
		self.output().len() == 1 && self.output()[0] == 1
	}
}

impl PrimitiveDefinition for PrimitiveCoreSpec {
	fn name(&self) -> &'static str {
		self.name
	}
	fn arity(&self) -> &[i32] {
		&self.arity
	}
	fn output(&self) -> &[i32] {
		&self.output
	}
	fn definition_check(&self) -> bool {
		self.definition_check
	}
	fn is_explosive(&self) -> bool {
		self.explosive
	}
	fn has_rewrite_rule(&self) -> bool {
		self.has_rule
	}
}

impl PrimitiveDefinition for PrimitiveSpec {
	fn name(&self) -> &'static str {
		self.name
	}
	fn arity(&self) -> &[i32] {
		&self.arity
	}
	fn output(&self) -> &[i32] {
		&self.output
	}
	fn definition_check(&self) -> bool {
		self.definition_check
	}
	fn is_explosive(&self) -> bool {
		self.explosive
	}
	fn has_rewrite_rule(&self) -> bool {
		self.rewrite.has_rule
	}
}

pub(crate) fn primitive_def(id: PrimitiveId) -> VResult<&'static dyn PrimitiveDefinition> {
	if primitive_is_core(id) {
		Ok(primitive_core_get(id)? as &dyn PrimitiveDefinition)
	} else {
		Ok(primitive_get(id)? as &dyn PrimitiveDefinition)
	}
}

pub(crate) fn primitive_is_core(id: PrimitiveId) -> bool {
	matches!(id, PRIM_ASSERT | PRIM_CONCAT | PRIM_SPLIT)
}

pub(crate) fn primitive_core_get(id: PrimitiveId) -> VResult<&'static PrimitiveCoreSpec> {
	CORE_SPECS
		.get(&id)
		.ok_or_else(|| VerifpalError::Internal("unknown primitive".into()))
}

pub(crate) fn primitive_get(id: PrimitiveId) -> VResult<&'static PrimitiveSpec> {
	PRIM_SPECS
		.get(&id)
		.ok_or_else(|| VerifpalError::Internal("unknown primitive".into()))
}

pub(crate) fn primitive_has_rewrite_rule(id: PrimitiveId) -> bool {
	primitive_def(id)
		.map(|d| d.has_rewrite_rule())
		.unwrap_or(false)
}

pub(crate) fn primitive_name(id: PrimitiveId) -> &'static str {
	primitive_def(id).map(|d| d.name()).unwrap_or("")
}

pub(crate) fn primitive_is_explosive(id: PrimitiveId) -> bool {
	primitive_def(id).map(|d| d.is_explosive()).unwrap_or(false)
}

pub(crate) fn primitive_has_single_output(id: PrimitiveId) -> bool {
	primitive_def(id)
		.map(|d| d.has_single_output())
		.unwrap_or(false)
}

pub(crate) fn primitive_output_spec(id: PrimitiveId) -> VResult<(&'static [i32], bool)> {
	let d = primitive_def(id)?;
	Ok((d.output(), d.definition_check()))
}

pub(crate) fn primitive_get_enum(name: &str) -> VResult<PrimitiveId> {
	CORE_SPECS
		.values()
		.find(|s| s.name == name)
		.map(|s| s.id)
		.or_else(|| PRIM_SPECS.values().find(|s| s.name == name).map(|s| s.id))
		.ok_or_else(|| VerifpalError::Internal("unknown primitive".into()))
}

pub(crate) fn primitive_get_arity(p: &Primitive) -> VResult<&'static [i32]> {
	Ok(primitive_def(p.id)?.arity())
}
