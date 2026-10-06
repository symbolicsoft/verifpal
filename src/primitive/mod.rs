/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub(crate) mod capability;
mod spec;
#[cfg(test)]
mod tests;

pub use capability::{Capabilities, Capability, CapabilityIndex, Reach};

use std::sync::LazyLock;

use crate::syntax::{VResult, VerifpalError};
use crate::term::{Primitive, PrimitiveId, Value};
use spec::{build_core_specs, build_primitive_specs};

#[cfg(test)]
pub(crate) use self::spec::*;

pub(crate) type FilterFn = fn(&Primitive, &Value, usize) -> (Value, bool);
pub(crate) type CoreRuleFn = fn(&Primitive) -> (bool, Value);
pub(crate) type RewriteToFn = fn(&Primitive) -> Value;

#[derive(Clone, Copy)]
pub(crate) enum Reveal {
	Argument(usize),
	Output(usize),
}

#[derive(Clone, Copy, Default)]
#[cfg_attr(not(feature = "language"), allow(dead_code))]
pub(crate) struct PrimitiveDoc {
	pub example: &'static str,
	pub help: &'static str,
}

pub(crate) const MAX_SHARES: usize = 16;

#[derive(Clone, Copy)]
pub(crate) struct ThresholdSpec {
	pub min: usize,
}

#[derive(Clone)]
pub(crate) struct ReuseRule {
	pub fixed: Vec<usize>,
	pub reveals: Vec<Reveal>,
	pub forgeable: Vec<usize>,
}

#[derive(Clone)]
pub(crate) struct ArgumentRestriction {
	pub position: usize,
	pub banned: Vec<PrimitiveId>,
	pub note: &'static str,
}

#[derive(Clone)]
pub(crate) struct DecomposeRule {
	pub given: Vec<usize>,
	pub output: Option<usize>,
	pub reveals: Vec<Reveal>,
	pub filter: FilterFn,
}

#[derive(Clone)]
pub(crate) struct RecomposeRule {
	pub reveal: usize,
}

#[derive(Clone)]
pub(crate) enum RewriteTo {
	Fixed(Value),
	Computed(RewriteToFn),
}

impl RewriteTo {
	pub(crate) fn apply(&self, inner: &Primitive) -> Value {
		match self {
			Self::Fixed(value) => value.clone(),
			Self::Computed(compute) => compute(inner),
		}
	}
}

#[derive(Clone)]
pub(crate) struct RewriteRule {
	pub id: PrimitiveId,
	pub from: usize,
	pub from_output: Option<usize>,
	pub to: RewriteTo,
	pub matching: Vec<(usize, Vec<usize>)>,
	pub filter: FilterFn,
}

#[derive(Clone)]
pub(crate) struct CombineBinding {
	pub argument: usize,
	pub list: usize,
	pub wrapper: PrimitiveId,
	pub sequence: PrimitiveId,
}

#[derive(Clone)]
pub(crate) struct CombineRule {
	pub partial: PrimitiveId,
	pub split: PrimitiveId,
	pub share: usize,
	pub agree: Vec<usize>,
	pub carry: Vec<usize>,
	pub whole: PrimitiveId,
	pub bindings: Vec<CombineBinding>,
}

#[derive(Clone)]
pub(crate) struct RebuildRule {
	pub id: PrimitiveId,
	pub reveal: usize,
}

#[derive(Clone)]
pub(crate) struct PrimitiveCoreSpec {
	pub name: &'static str,
	pub id: PrimitiveId,
	pub arity: Vec<i32>,
	pub output: Vec<i32>,
	pub core_rule: Option<CoreRuleFn>,
	pub definition_check: bool,
	pub reveals_args: bool,
	pub projection_of: Option<PrimitiveId>,
	pub equality: bool,
	pub unwraps: Option<usize>,
	pub arg_names: Vec<&'static str>,
	#[cfg_attr(not(feature = "language"), allow(dead_code))]
	pub doc: PrimitiveDoc,
}

#[derive(Clone, Copy)]
pub(crate) enum CheckKeyKind {
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
	pub decompose: Option<DecomposeRule>,
	pub recompose: Option<RecomposeRule>,
	pub rewrite: Option<RewriteRule>,
	pub rebuild: Option<RebuildRule>,
	pub combine: Vec<CombineRule>,
	pub definition_check: bool,
	pub check_key: Option<CheckKeyKind>,
	pub commutativity: Option<CommutativityRule>,
	pub argument_restrictions: Vec<ArgumentRestriction>,
	pub key_derivation: bool,
	pub distinct_per_assignment: bool,
	pub identifying_positions: Vec<usize>,
	pub weak_reveals: Vec<Reveal>,
	pub forgeable_secret: Option<usize>,
	pub malleable_vary: Vec<usize>,
	pub reuse: Option<ReuseRule>,
	pub threshold: Option<ThresholdSpec>,
	pub divergence_filler: bool,
	pub arity_help: Option<(i32, &'static str)>,
	pub arg_names: Vec<&'static str>,
	#[cfg_attr(not(feature = "language"), allow(dead_code))]
	pub doc: PrimitiveDoc,
}

static CORE_SPECS: LazyLock<[Option<PrimitiveCoreSpec>; 256]> = LazyLock::new(|| {
	let mut table = [const { None }; 256];
	for spec in build_core_specs() {
		let id = spec.id as usize;
		table[id] = Some(spec);
	}
	table
});

static PRIM_SPECS: LazyLock<[Option<PrimitiveSpec>; 256]> = LazyLock::new(|| {
	let mut table = [const { None }; 256];
	for spec in build_primitive_specs() {
		let id = spec.id as usize;
		table[id] = Some(spec);
	}
	table
});

fn core_spec(id: PrimitiveId) -> Option<&'static PrimitiveCoreSpec> {
	CORE_SPECS[id as usize].as_ref()
}

fn prim_spec(id: PrimitiveId) -> Option<&'static PrimitiveSpec> {
	PRIM_SPECS[id as usize].as_ref()
}

fn core_specs() -> impl Iterator<Item = &'static PrimitiveCoreSpec> {
	CORE_SPECS.iter().flatten()
}

fn prim_specs() -> impl Iterator<Item = &'static PrimitiveSpec> {
	PRIM_SPECS.iter().flatten()
}

pub(crate) trait PrimitiveDefinition {
	fn name(&self) -> &'static str;
	fn arity(&self) -> &[i32];
	fn output(&self) -> &[i32];
	fn definition_check(&self) -> bool;
	fn arg_names(&self) -> &[&'static str];
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
	fn arg_names(&self) -> &[&'static str] {
		&self.arg_names
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
	fn arg_names(&self) -> &[&'static str] {
		&self.arg_names
	}
}

pub(crate) fn primitive_def(id: PrimitiveId) -> VResult<&'static dyn PrimitiveDefinition> {
	match core_spec(id) {
		Some(core) => Ok(core),
		None => Ok(primitive_get(id)?),
	}
}

pub(crate) fn primitive_is_core(id: PrimitiveId) -> bool {
	core_spec(id).is_some()
}

pub(crate) fn primitive_core_get(id: PrimitiveId) -> VResult<&'static PrimitiveCoreSpec> {
	core_spec(id).ok_or_else(|| VerifpalError::internal("unknown primitive".into()))
}

pub(crate) fn primitive_get(id: PrimitiveId) -> VResult<&'static PrimitiveSpec> {
	prim_spec(id).ok_or_else(|| VerifpalError::internal("unknown primitive".into()))
}

pub(crate) fn primitive_check_undoing(
	id: PrimitiveId,
) -> Option<(&'static PrimitiveSpec, &'static RewriteRule)> {
	primitives_rewriting(id)
		.filter(|(spec, _)| spec.definition_check)
		.min_by_key(|(spec, _)| spec.id)
}

pub(crate) fn primitives_rewriting(
	id: PrimitiveId,
) -> impl Iterator<Item = (&'static PrimitiveSpec, &'static RewriteRule)> {
	prim_specs().filter_map(move |spec| {
		let rule = spec.rewrite.as_ref().filter(|rule| rule.id == id)?;
		Some((spec, rule))
	})
}

pub(crate) fn primitive_name(id: PrimitiveId) -> &'static str {
	primitive_def(id).map(|d| d.name()).unwrap_or("")
}

pub(crate) fn primitive_names() -> Vec<&'static str> {
	let mut names: Vec<&'static str> = core_specs()
		.map(|s| s.name)
		.chain(prim_specs().map(|s| s.name))
		.collect();
	names.sort_unstable();
	names
}

pub(crate) fn primitive_checkable_names() -> Vec<String> {
	let mut names: Vec<String> = core_specs()
		.filter(|s| s.definition_check)
		.map(|s| s.name.to_string())
		.chain(
			prim_specs()
				.filter(|s| s.definition_check)
				.map(|s| s.name.to_string()),
		)
		.collect();
	names.sort();
	names
}

pub(crate) fn primitive_signature(id: PrimitiveId) -> String {
	let Ok(def) = primitive_def(id) else {
		return String::new();
	};
	let names = def.arg_names();
	let name = def.name();
	if names.is_empty() {
		return format!("{}(…)", name);
	}
	let arity = def.arity();
	if arity.len() > 1 {
		let widest = *arity.last().unwrap_or(&1) as usize;
		let last = names.get(widest.saturating_sub(1)).copied().unwrap_or("…");
		return format!("{}({}, …, {})", name, names[0], last);
	}
	format!("{}({})", name, names.join(", "))
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
	core_specs()
		.find(|s| s.name == name)
		.map(|s| s.id)
		.or_else(|| prim_specs().find(|s| s.name == name).map(|s| s.id))
		.ok_or_else(|| VerifpalError::internal("unknown primitive".into()))
}

pub(crate) fn commutativity_rule(id: PrimitiveId) -> Option<&'static CommutativityRule> {
	prim_spec(id)?.commutativity.as_ref()
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

pub(crate) fn commutativity_swap(p: &Primitive) -> Option<Primitive> {
	let rule = commutativity_rule(p.id)?;
	let (inner, bare) = commutativity_parts_ref(p)?;
	let (inner, bare) = (inner.clone(), bare.clone());
	let mut arguments = p.arguments.clone();
	arguments[rule.wrapped] = Value::primitive(rule.constructor, vec![bare], 0);
	arguments[rule.bare] = inner;
	Some(p.with_arguments(arguments))
}

static KEY_DERIVATION: LazyLock<Option<PrimitiveId>> =
	LazyLock::new(|| prim_specs().find(|s| s.key_derivation).map(|s| s.id));

pub(crate) fn secret_positions(id: PrimitiveId) -> Vec<usize> {
	let Some(spec) = prim_spec(id) else {
		return Vec::new();
	};
	let mut out: Vec<usize> = Vec::new();
	if spec.key_derivation {
		out.push(0);
	}
	if let Some(at) = spec.forgeable_secret {
		out.push(at);
	}
	if let Some(&opening) = spec.decompose.as_ref().and_then(|rule| rule.given.first()) {
		out.push(opening);
	}
	out.sort_unstable();
	out.dedup();
	out
}

pub(crate) fn key_derivation_of(inner: Value) -> Option<Value> {
	let id = (*KEY_DERIVATION)?;
	Some(Value::primitive(id, vec![inner], 0))
}

pub(crate) fn attacker_public_key() -> Value {
	key_derivation_of(crate::term::value_nil()).unwrap_or_else(crate::term::value_nil)
}

pub(crate) fn key_derivation_inner(v: &Value) -> Option<&Value> {
	match v {
		Value::Primitive(p) if primitive_is_key_derivation(p.id) && p.arguments.len() == 1 => {
			p.arguments.first()
		}
		_ => None,
	}
}

pub(crate) fn value_is_key_derivation(v: &Value) -> bool {
	matches!(v, Value::Primitive(p) if primitive_is_key_derivation(p.id))
}

pub(crate) fn normalise_arguments(id: PrimitiveId, mut arguments: Vec<Value>) -> Vec<Value> {
	for restriction in argument_restrictions(id) {
		while let Some(argument @ Value::Primitive(inner)) = arguments.get(restriction.position)
			&& restriction.banned.contains(&inner.id)
			&& let Some(unwrapped) = key_derivation_inner(argument)
		{
			let unwrapped = unwrapped.clone();
			arguments[restriction.position] = unwrapped;
		}
	}
	arguments
}

pub(crate) fn admissible(v: &Value) -> bool {
	crate::term::subterms(v).all(|term| {
		let Value::Primitive(p) = term else {
			return matches!(term, Value::Constant(_));
		};
		for restriction in argument_restrictions(p.id) {
			if let Some(Value::Primitive(inner)) = p.arguments.get(restriction.position)
				&& restriction.banned.contains(&inner.id)
			{
				return false;
			}
		}
		true
	})
}

pub(crate) fn argument_restrictions(id: PrimitiveId) -> &'static [ArgumentRestriction] {
	prim_spec(id).map_or(&[], |s| s.argument_restrictions.as_slice())
}

pub(crate) fn primitive_is_key_derivation(id: PrimitiveId) -> bool {
	prim_spec(id).is_some_and(|s| s.key_derivation)
}

pub(crate) fn primitive_core_reveals_args(id: PrimitiveId) -> bool {
	core_spec(id).is_some_and(|s| s.reveals_args)
}

pub(crate) fn primitive_projects(id: PrimitiveId) -> Option<PrimitiveId> {
	core_spec(id)?.projection_of
}

pub(crate) fn primitive_is_projection(id: PrimitiveId) -> bool {
	primitive_projects(id).is_some()
}

pub(crate) fn primitive_is_equality(id: PrimitiveId) -> bool {
	core_spec(id).is_some_and(|s| s.equality)
}

pub(crate) fn primitive_unwraps(id: PrimitiveId) -> Option<usize> {
	match core_spec(id) {
		Some(core) => core.unwraps,
		None => rewrite_rule(id).map(|rule| rule.from),
	}
}

pub(crate) fn filler_primitive() -> Option<PrimitiveId> {
	prim_specs().find(|s| s.divergence_filler).map(|s| s.id)
}

pub(crate) fn combine_rules(id: PrimitiveId) -> &'static [CombineRule] {
	prim_spec(id).map_or(&[], |s| s.combine.as_slice())
}

pub(crate) fn combines_from(partial: PrimitiveId) -> impl Iterator<Item = &'static CombineRule> {
	prim_specs().flat_map(move |spec| spec.combine.iter().filter(move |r| r.partial == partial))
}

pub(crate) fn combines_into(
	whole: PrimitiveId,
) -> impl Iterator<Item = (PrimitiveId, &'static CombineRule)> {
	prim_specs().flat_map(move |spec| {
		spec.combine
			.iter()
			.filter(move |rule| rule.whole == whole)
			.map(move |rule| (spec.id, rule))
	})
}

pub(crate) fn primitive_threshold(id: PrimitiveId) -> Option<ThresholdSpec> {
	prim_spec(id)?.threshold
}

pub(crate) fn primitives_with_threshold() -> Vec<&'static str> {
	prim_specs()
		.filter(|s| s.threshold.is_some())
		.map(|s| s.name)
		.collect()
}

pub(crate) fn primitive_renamed(name: &str) -> Option<&'static str> {
	spec::RENAMED
		.iter()
		.find(|(old, _)| old.eq_ignore_ascii_case(name))
		.map(|(_, new)| *new)
}

pub(crate) fn reuse_rule(id: PrimitiveId) -> Option<&'static ReuseRule> {
	prim_spec(id)?.reuse.as_ref()
}

pub(crate) fn rewrite_rule(id: PrimitiveId) -> Option<&'static RewriteRule> {
	prim_spec(id)?.rewrite.as_ref()
}

pub(crate) fn recompose_rule(id: PrimitiveId) -> Option<&'static RecomposeRule> {
	prim_spec(id)?.recompose.as_ref()
}

pub(crate) fn reuse_fixed_names(v: &Value) -> String {
	let Value::Primitive(p) = v else {
		return String::new();
	};
	let (Some(rule), Some(spec)) = (reuse_rule(p.id), prim_spec(p.id)) else {
		return String::new();
	};
	let names: Vec<&str> = rule
		.fixed
		.iter()
		.filter_map(|&at| spec.arg_names.get(at).copied())
		.collect();
	crate::util::text::and_list(&names)
}

pub(crate) fn primitive_arity_help(id: PrimitiveId, given: i32) -> Option<&'static str> {
	let (arity, help) = prim_spec(id)?.arity_help?;
	(arity == given).then_some(help)
}

#[cfg_attr(not(feature = "language"), allow(dead_code))]
pub(crate) fn primitive_docs() -> Vec<(&'static str, PrimitiveDoc)> {
	core_specs()
		.map(|s| (s.name, s.doc))
		.chain(prim_specs().map(|s| (s.name, s.doc)))
		.collect()
}

#[cfg_attr(not(feature = "language"), allow(dead_code))]
pub(crate) fn primitives_supporting(
	supports: impl Fn(PrimitiveId) -> bool,
) -> Vec<&'static PrimitiveSpec> {
	prim_specs().filter(|s| supports(s.id)).collect()
}

pub(crate) fn primitive_extract_check_key(prim: &Primitive) -> Option<Value> {
	match prim_spec(prim.id)?.check_key {
		Some(CheckKeyKind::Direct(i)) => Some(prim.arguments[i].clone()),
		Some(CheckKeyKind::Derived { arg, constructor }) => match &prim.arguments[arg] {
			Value::Primitive(p) if p.id == constructor && p.arguments.len() == 1 => {
				Some(p.arguments[0].clone())
			}
			_ => None,
		},
		None => None,
	}
}
