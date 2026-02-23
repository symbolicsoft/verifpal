/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::LazyLock;

mod spec;

use self::spec::{build_core_specs, build_primitive_specs};
use crate::types::*;

// Re-export everything from spec so callers use `crate::primitive::PRIM_*`.
#[allow(unused_imports)]
pub(crate) use self::spec::*;

// ---------------------------------------------------------------------------
// Function pointer type aliases
// ---------------------------------------------------------------------------

pub(crate) type FilterFn = fn(&Primitive, &Value, usize) -> (Value, bool);
pub(crate) type CoreRuleFn = fn(&Primitive) -> (bool, Vec<Value>);
pub(crate) type RewriteToFn = fn(&Primitive) -> Value;

// ---------------------------------------------------------------------------
// Rule structs
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Spec structs
// ---------------------------------------------------------------------------

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
	/// When true, attacker knowledge of this primitive's output reveals all arguments.
	pub reveals_args: bool,
}

/// How to extract the bypass key from a guarded primitive's arguments.
#[derive(Clone, Copy)]
pub(crate) enum BypassKeyKind {
	/// Take the argument at this index directly.
	Direct(usize),
	/// Extract the last DH exponent from the equation at this index.
	DhExponent(usize),
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
	/// How to extract the bypass key for active attacker guard bypass.
	pub bypass_key: Option<BypassKeyKind>,
}

// ---------------------------------------------------------------------------
// Registries
// ---------------------------------------------------------------------------

static CORE_SPECS: LazyLock<HashMap<PrimitiveId, PrimitiveCoreSpec>> = LazyLock::new(|| {
	let specs = build_core_specs();
	specs.into_iter().map(|s| (s.id, s)).collect()
});

static PRIM_SPECS: LazyLock<HashMap<PrimitiveId, PrimitiveSpec>> = LazyLock::new(|| {
	let specs = build_primitive_specs();
	specs.into_iter().map(|s| (s.id, s)).collect()
});

// ---------------------------------------------------------------------------
// Trait + impls
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Accessor functions
// ---------------------------------------------------------------------------

pub(crate) fn primitive_def(id: PrimitiveId) -> VResult<&'static dyn PrimitiveDefinition> {
	if primitive_is_core(id) {
		Ok(primitive_core_get(id)? as &dyn PrimitiveDefinition)
	} else {
		Ok(primitive_get(id)? as &dyn PrimitiveDefinition)
	}
}

pub(crate) fn primitive_is_core(id: PrimitiveId) -> bool {
	CORE_SPECS.contains_key(&id)
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

pub(crate) fn primitive_core_reveals_args(id: PrimitiveId) -> bool {
	CORE_SPECS.get(&id).is_some_and(|s| s.reveals_args)
}

pub(crate) fn primitive_extract_bypass_key(prim: &Primitive) -> Option<Value> {
	if primitive_is_core(prim.id) {
		return None;
	}
	let spec = primitive_get(prim.id).ok()?;
	match spec.bypass_key {
		Some(BypassKeyKind::Direct(i)) => Some(prim.arguments[i].clone()),
		Some(BypassKeyKind::DhExponent(i)) => {
			if let Value::Equation(e) = &prim.arguments[i] {
				if e.values.len() >= 2 {
					return Some(e.values[e.values.len() - 1].clone());
				}
			}
			None
		}
		None => None,
	}
}
