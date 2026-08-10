/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::LazyLock;

mod spec;

use self::spec::{build_core_specs, build_primitive_specs};
use crate::types::*;

#[allow(unused_imports)]
pub(crate) use self::spec::*;

pub(crate) type FilterFn = fn(&Primitive, &Value, usize) -> (Value, bool);
pub(crate) type CoreRuleFn = fn(&Primitive) -> (bool, Value);
pub(crate) type RewriteToFn = fn(&Primitive) -> Value;

#[derive(Clone, Default)]
pub(crate) struct DecomposeRule {
	pub has_rule: bool,
	pub given: Vec<usize>,
	pub reveal: usize,
	pub reveal_output: Option<usize>,
	pub filter: Option<FilterFn>,
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
	pub reveals_args: bool,
}

#[derive(Clone, Copy)]
pub(crate) enum BypassKeyKind {
	Direct(usize),
	Derived {
		arg: usize,
		constructor: PrimitiveId,
	},
}

#[derive(Clone, Copy)]
pub(crate) struct CommutativityRule {
	pub wrapped: usize,
	pub constructor: PrimitiveId,
	pub bare: usize,
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
	pub password_hashing: Vec<usize>,
	pub bypass_key: Option<BypassKeyKind>,
	pub commutativity: Option<CommutativityRule>,
	pub argument_restrictions: Vec<(usize, Vec<PrimitiveId>)>,
	pub key_derivation: bool,
	pub identifying_positions: Vec<usize>,
	pub weak_reveals: Vec<usize>,
	pub weak_reveals_output: Option<usize>,
	pub forgeable_secret: Option<usize>,
	pub malleable_vary: Vec<usize>,
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
	CORE_SPECS.contains_key(&id)
}

pub(crate) fn primitive_core_get(id: PrimitiveId) -> VResult<&'static PrimitiveCoreSpec> {
	CORE_SPECS
		.get(&id)
		.ok_or_else(|| VerifpalError::internal("unknown primitive".into()))
}

pub(crate) fn primitive_get(id: PrimitiveId) -> VResult<&'static PrimitiveSpec> {
	PRIM_SPECS
		.get(&id)
		.ok_or_else(|| VerifpalError::internal("unknown primitive".into()))
}

pub(crate) fn primitive_check_undoing(id: PrimitiveId) -> Option<&'static PrimitiveSpec> {
	PRIM_SPECS
		.values()
		.filter(|s| s.definition_check && s.rewrite.has_rule && s.rewrite.id == id)
		.min_by_key(|s| s.id)
}

pub(crate) fn primitive_has_rewrite_rule(id: PrimitiveId) -> bool {
	primitive_def(id)
		.map(|d| d.has_rewrite_rule())
		.unwrap_or(false)
}

pub(crate) fn primitive_name(id: PrimitiveId) -> &'static str {
	primitive_def(id).map(|d| d.name()).unwrap_or("")
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
		.ok_or_else(|| VerifpalError::internal("unknown primitive".into()))
}

pub(crate) fn primitive_get_arity(p: &Primitive) -> VResult<&'static [i32]> {
	Ok(primitive_def(p.id)?.arity())
}

static COMMUTATIVITY_TABLE: LazyLock<[Option<CommutativityRule>; 256]> = LazyLock::new(|| {
	let mut table = [None; 256];
	for spec in PRIM_SPECS.values() {
		table[spec.id as usize] = spec.commutativity;
	}
	table
});

static KEY_DERIVATION_TABLE: LazyLock<[bool; 256]> = LazyLock::new(|| {
	let mut table = [false; 256];
	for spec in PRIM_SPECS.values() {
		table[spec.id as usize] = spec.key_derivation;
	}
	table
});

pub(crate) fn commutativity_rule(id: PrimitiveId) -> Option<&'static CommutativityRule> {
	COMMUTATIVITY_TABLE[id as usize].as_ref()
}

pub(crate) fn commutativity_parts_ref(p: &Primitive) -> Option<(&Value, &Value)> {
	let rule = commutativity_rule(p.id)?;
	let wrapped = p.arguments.get(rule.wrapped)?;
	let bare = p.arguments.get(rule.bare)?;
	let Value::Primitive(w) = wrapped else {
		return None;
	};
	if w.id != rule.constructor || w.arguments.len() != 1 {
		return None;
	}
	Some((&w.arguments[0], bare))
}

pub(crate) fn commutativity_parts(p: &Primitive) -> Option<(Value, Value)> {
	commutativity_parts_ref(p).map(|(inner, bare)| (inner.clone(), bare.clone()))
}

pub(crate) fn commutativity_swap(p: &Primitive) -> Option<Primitive> {
	let rule = commutativity_rule(p.id)?;
	let (inner, bare) = commutativity_parts(p)?;
	let mut arguments = p.arguments.clone();
	arguments[rule.wrapped] = Value::primitive(rule.constructor, vec![bare], 0);
	arguments[rule.bare] = inner;
	Some(p.with_arguments(arguments))
}

pub(crate) fn key_derivation_of(inner: Value) -> Option<Value> {
	let id = PRIM_SPECS
		.values()
		.find(|s| s.key_derivation)
		.map(|s| s.id)?;
	Some(Value::primitive(id, vec![inner], 0))
}

pub(crate) fn attacker_public_key() -> Value {
	key_derivation_of(crate::value::value_nil()).unwrap_or_else(crate::value::value_nil)
}

pub(crate) fn value_is_key_derivation(v: &Value) -> bool {
	matches!(v, Value::Primitive(p) if primitive_is_key_derivation(p.id))
}

pub(crate) fn normalise_arguments(id: PrimitiveId, mut arguments: Vec<Value>) -> Vec<Value> {
	for (position, banned) in argument_restrictions(id) {
		while let Some(Value::Primitive(inner)) = arguments.get(*position) {
			if !banned.contains(&inner.id)
				|| !primitive_is_key_derivation(inner.id)
				|| inner.arguments.len() != 1
			{
				break;
			}
			let unwrapped = inner.arguments[0].clone();
			arguments[*position] = unwrapped;
		}
	}
	arguments
}

pub(crate) fn admissible(v: &Value) -> bool {
	let Value::Primitive(p) = v else {
		return true;
	};
	for (position, banned) in argument_restrictions(p.id) {
		if let Some(Value::Primitive(inner)) = p.arguments.get(*position)
			&& banned.contains(&inner.id)
		{
			return false;
		}
	}
	p.arguments.iter().all(admissible)
}

pub(crate) fn argument_restrictions(id: PrimitiveId) -> &'static [(usize, Vec<PrimitiveId>)] {
	primitive_get(id)
		.map(|s| s.argument_restrictions.as_slice())
		.unwrap_or(&[])
}

pub(crate) fn primitive_is_key_derivation(id: PrimitiveId) -> bool {
	KEY_DERIVATION_TABLE[id as usize]
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
		Some(BypassKeyKind::Derived { arg, constructor }) => match &prim.arguments[arg] {
			Value::Primitive(p) if p.id == constructor && p.arguments.len() == 1 => {
				Some(p.arguments[0].clone())
			}
			_ => None,
		},
		None => None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn pubkey_and_dh_kex_resolve_by_name() {
		assert!(primitive_get_enum("PUBKEY").is_ok());
		assert!(primitive_get_enum("DH_KEX").is_ok());
	}

	#[test]
	fn identifying_positions_table() {
		assert_eq!(
			primitive_get(PRIM_SIGNVERIF).unwrap().identifying_positions,
			vec![0]
		);
		assert_eq!(
			primitive_get(PRIM_AEAD_DEC).unwrap().identifying_positions,
			vec![0]
		);
		assert_eq!(
			primitive_get(PRIM_KEM_DECAP).unwrap().identifying_positions,
			vec![0]
		);
		assert!(
			primitive_get(PRIM_RINGSIGNVERIF)
				.unwrap()
				.identifying_positions
				.is_empty()
		);
	}

	#[test]
	fn pubkey_is_the_key_derivation_constructor() {
		assert!(primitive_is_key_derivation(
			primitive_get_enum("PUBKEY").unwrap()
		));
		assert!(!primitive_is_key_derivation(
			primitive_get_enum("DH_KEX").unwrap()
		));
		assert!(!primitive_is_key_derivation(PRIM_HASH));
	}

	#[test]
	fn neither_new_primitive_may_be_checked() {
		for name in ["PUBKEY", "DH_KEX"] {
			let id = primitive_get_enum(name).unwrap();
			assert!(!primitive_def(id).unwrap().definition_check());
		}
	}

	#[test]
	fn new_primitive_arities_come_from_the_spec() {
		let pk = primitive_def(primitive_get_enum("PUBKEY").unwrap()).unwrap();
		assert_eq!(pk.arity(), &[1]);
		let dh = primitive_def(primitive_get_enum("DH_KEX").unwrap()).unwrap();
		assert_eq!(dh.arity(), &[2]);
	}

	#[test]
	fn primitive_def_core() {
		let def = primitive_def(PRIM_ASSERT).unwrap();
		assert_eq!(def.name(), "ASSERT");
		assert!(def.definition_check());
		assert!(def.has_rewrite_rule());
	}

	#[test]
	fn primitive_def_non_core() {
		let def = primitive_def(PRIM_AEAD_ENC).unwrap();
		assert_eq!(def.name(), "AEAD_ENC");
		assert!(!def.definition_check());
		assert!(!def.has_rewrite_rule());
	}

	#[test]
	fn primitive_def_check_property() {
		let dec = primitive_def(PRIM_AEAD_DEC).unwrap();
		assert!(dec.definition_check());
		let enc = primitive_def(PRIM_ENC).unwrap();
		assert!(!enc.definition_check());
	}

	#[test]
	fn primitive_is_core_check() {
		assert!(primitive_is_core(PRIM_ASSERT));
		assert!(primitive_is_core(PRIM_CONCAT));
		assert!(primitive_is_core(PRIM_SPLIT));
		assert!(!primitive_is_core(PRIM_HASH));
		assert!(!primitive_is_core(PRIM_AEAD_ENC));
	}

	#[test]
	fn primitive_name_lookup() {
		assert_eq!(primitive_name(PRIM_HASH), "HASH");
		assert_eq!(primitive_name(PRIM_SIGN), "SIGN");
		assert_eq!(primitive_name(PRIM_CONCAT), "CONCAT");
	}

	#[test]
	fn primitive_get_enum_roundtrip() {
		let id = primitive_get_enum("AEAD_ENC").unwrap();
		assert_eq!(id, PRIM_AEAD_ENC);
		let id2 = primitive_get_enum("SPLIT").unwrap();
		assert_eq!(id2, PRIM_SPLIT);
		assert!(primitive_get_enum("NONEXISTENT").is_err());
	}

	#[test]
	fn primitive_single_output() {
		assert!(primitive_has_single_output(PRIM_HASH));
		assert!(primitive_has_single_output(PRIM_ENC));
		assert!(!primitive_has_single_output(PRIM_SPLIT));
		assert!(!primitive_has_single_output(PRIM_HKDF));
	}

	#[test]
	fn normalisation_collapses_an_exchange_of_two_public_keys() {
		use crate::testutil::*;
		let a = make_constant("nrm_a");
		let b = make_constant("nrm_b");
		let ga = make_primitive(PRIM_PUBKEY, vec![a], 0);
		let gb = make_primitive(PRIM_PUBKEY, vec![b.clone()], 0);
		let normalised = normalise_arguments(PRIM_DH_KEX, vec![ga.clone(), gb]);
		assert!(normalised[0].equivalent(&ga, true));
		assert!(
			normalised[1].equivalent(&b, true),
			"the forbidden PUBKEY at the bare position is peeled away"
		);
		let twice = normalise_arguments(PRIM_DH_KEX, normalised.clone());
		assert!(twice[0].equivalent(&normalised[0], true));
		assert!(twice[1].equivalent(&normalised[1], true));
		let gga = normalise_arguments(PRIM_PUBKEY, vec![ga.clone()]);
		assert!(gga[0].equivalent(&make_constant("nrm_a"), true));
	}

	#[test]
	fn a_commutativity_rule_exchanges_positions_with_equal_restrictions() {
		for spec in PRIM_SPECS.values() {
			let Some(rule) = &spec.commutativity else {
				continue;
			};
			let bare: Vec<PrimitiveId> = argument_restrictions(spec.id)
				.iter()
				.find(|(position, _)| *position == rule.bare)
				.map(|(_, banned)| banned.clone())
				.unwrap_or_default();
			let wrapped: Vec<PrimitiveId> = argument_restrictions(rule.constructor)
				.iter()
				.find(|(position, _)| *position == 0)
				.map(|(_, banned)| banned.clone())
				.unwrap_or_default();
			let mut bare = bare;
			let mut wrapped = wrapped;
			bare.sort_unstable();
			wrapped.sort_unstable();
			assert_eq!(
				bare,
				wrapped,
				"{}'s bare position and {}'s argument must forbid the same heads",
				spec.name,
				primitive_name(rule.constructor)
			);
		}
	}

	#[test]
	fn normalisation_does_not_enforce_the_unpeelable_restrictions() {
		use crate::testutil::*;
		let a = make_constant("adm_a");
		let b = make_constant("adm_b");
		let ga = make_primitive(PRIM_PUBKEY, vec![a.clone()], 0);
		let shared = make_primitive(PRIM_DH_KEX, vec![ga.clone(), b.clone()], 0);
		let nested = normalise_arguments(PRIM_PUBKEY, vec![shared.clone()]);
		assert!(nested[0].equivalent(&shared, true), "not peeled");
		let violating = make_primitive(PRIM_PUBKEY, vec![shared.clone()], 0);
		assert!(!admissible(&violating));
		let stacked = make_primitive(PRIM_DH_KEX, vec![shared.clone(), b], 0);
		assert!(!admissible(&stacked));
		assert!(admissible(&shared));
		assert!(admissible(&ga));
		assert!(admissible(&a));
	}

	#[test]
	fn primitive_has_rewrite_rule_checks() {
		assert!(primitive_has_rewrite_rule(PRIM_AEAD_DEC));
		assert!(primitive_has_rewrite_rule(PRIM_DEC));
		assert!(primitive_has_rewrite_rule(PRIM_SIGNVERIF));
		assert!(primitive_has_rewrite_rule(PRIM_PKE_DEC));
		assert!(primitive_has_rewrite_rule(PRIM_ASSERT));
		assert!(primitive_has_rewrite_rule(PRIM_SPLIT));
		assert!(!primitive_has_rewrite_rule(PRIM_HASH));
		assert!(!primitive_has_rewrite_rule(PRIM_ENC));
		assert!(!primitive_has_rewrite_rule(PRIM_SIGN));
		assert!(!primitive_has_rewrite_rule(PRIM_MAC));
	}
}
