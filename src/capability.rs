/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::primitive::{primitive_get, primitive_is_core, primitive_name};
use crate::types::{IdMap, Primitive, PrimitiveId, TraceSlot, Value};

fn assumption_key(text: &str) -> String {
	let mut out = String::with_capacity(text.len());
	let mut chars = text.chars().peekable();
	while let Some(c) = chars.next() {
		if c == '#' || c == '@' {
			while chars.peek().is_some_and(|d| d.is_ascii_digit()) {
				chars.next();
			}
			continue;
		}
		out.push(c);
	}
	out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Capability {
	Weak,
	Forgeable,
	Malleable,
}

impl Capability {
	pub const ALL: [Capability; 3] = [
		Capability::Weak,
		Capability::Forgeable,
		Capability::Malleable,
	];

	pub fn index(self) -> usize {
		match self {
			Capability::Weak => 0,
			Capability::Forgeable => 1,
			Capability::Malleable => 2,
		}
	}

	pub fn name(self) -> &'static str {
		match self {
			Capability::Weak => "weak",
			Capability::Forgeable => "forgeable",
			Capability::Malleable => "malleable",
		}
	}

	pub fn from_name(s: &str) -> Option<Capability> {
		Capability::ALL
			.into_iter()
			.find(|c| c.name().eq_ignore_ascii_case(s))
	}
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Capabilities {
	onset: [i32; 3],
}

const ABSENT: i32 = -1;

impl Default for Capabilities {
	fn default() -> Self {
		Capabilities { onset: [ABSENT; 3] }
	}
}

impl Capabilities {
	pub fn is_empty(&self) -> bool {
		self.onset.iter().all(|&o| o == ABSENT)
	}

	pub fn set(&mut self, cap: Capability, from_phase: i32) {
		self.onset[cap.index()] = from_phase.max(0);
	}

	pub fn has(&self, cap: Capability) -> bool {
		self.onset[cap.index()] != ABSENT
	}

	pub fn onset(&self, cap: Capability) -> Option<i32> {
		match self.onset[cap.index()] {
			ABSENT => None,
			o => Some(o),
		}
	}

	pub fn in_force(&self, cap: Capability, phase: i32) -> bool {
		match self.onset(cap) {
			Some(o) => phase >= o,
			None => false,
		}
	}

	pub fn iter(&self) -> impl Iterator<Item = (Capability, i32)> + '_ {
		Capability::ALL
			.into_iter()
			.filter_map(|c| self.onset(c).map(|o| (c, o)))
	}

	pub fn merge(&mut self, other: &Capabilities) {
		for (cap, onset) in other.iter() {
			match self.onset(cap) {
				Some(existing) if existing <= onset => {}
				_ => self.set(cap, onset),
			}
		}
	}
}

fn forgeable_secret_of(p: &Primitive) -> Option<&Value> {
	let position = primitive_get(p.id).ok()?.forgeable_secret?;
	p.arguments.get(position)
}

pub(crate) fn supports(id: PrimitiveId, cap: Capability) -> bool {
	if primitive_is_core(id) {
		return false;
	}
	let Ok(spec) = primitive_get(id) else {
		return false;
	};
	match cap {
		Capability::Weak => !spec.weak_reveals.is_empty() || spec.weak_reveals_output.is_some(),
		Capability::Forgeable => spec.forgeable_secret.is_some(),
		Capability::Malleable => !spec.malleable_vary.is_empty(),
	}
}

pub(crate) fn unsupported_message(id: PrimitiveId, cap: Capability) -> String {
	let name = primitive_name(id);
	let exchange_key =
		crate::primitive::commutativity_rule(id).map(|rule| primitive_name(rule.constructor));
	if primitive_is_core(id) {
		return format!(
			"{} is a core primitive and carries no cryptographic guarantee to weaken",
			name
		);
	}
	match cap {
		Capability::Weak if supports(id, Capability::Forgeable) => format!(
			"{} provides authenticity, not confidentiality; did you mean `{}[forgeable]`?",
			name, name
		),
		Capability::Weak if exchange_key.is_some() => format!(
			"the secret `{}` derives is only as hidden as the key it is built on; \
			 did you mean `{}[weak]`?",
			name,
			exchange_key.unwrap_or_default()
		),
		Capability::Forgeable => format!(
			"{} has no secret argument; anyone who knows its inputs can compute it",
			name
		),
		Capability::Malleable if supports(id, Capability::Forgeable) => format!(
			"malleability of an authenticated primitive is an authenticity break; \
			 did you mean `{}[forgeable]`?",
			name
		),
		_ => format!("{} does not support the `{}` parameter", name, cap.name()),
	}
}

#[derive(Clone, Debug)]
pub enum Reach {
	SameTerm(Value),
	SameSecret(Value),
}

#[derive(Clone, Debug, Default)]
pub struct CapabilityIndex {
	buckets: IdMap<u64, Vec<(Value, Capabilities)>>,
	secrets: IdMap<(PrimitiveId, u64), Vec<(Value, Capabilities)>>,
}

impl CapabilityIndex {
	pub fn is_empty(&self) -> bool {
		self.buckets.is_empty()
	}

	pub fn insert(&mut self, v: &Value) {
		for term in crate::value::subterms(v) {
			let Value::Primitive(p) = term else {
				continue;
			};
			if p.capabilities.is_empty() {
				continue;
			}
			let normalized = p
				.map_arguments(|arg| {
					let reduced = crate::theory::reduce_once(arg);
					(!reduced.equivalent(arg, true)).then_some(reduced)
				})
				.map(|p| Value::Primitive(Arc::new(p)));
			for value in std::iter::once(term).chain(normalized.as_ref()) {
				let Value::Primitive(p) = value else {
					continue;
				};
				self.insert_secret(p);
				let bucket = self.buckets.entry(value.hash_value()).or_default();
				if let Some((_, caps)) = bucket
					.iter_mut()
					.find(|(existing, _)| existing.equivalent(value, true))
				{
					caps.merge(&p.capabilities);
				} else {
					bucket.push((value.clone(), p.capabilities));
				}
			}
		}
	}

	fn insert_secret(&mut self, p: &Primitive) {
		if !p.capabilities.has(Capability::Forgeable) {
			return;
		}
		let Some(secret) = forgeable_secret_of(p) else {
			return;
		};
		let key = (p.id, secret.hash_value());
		let bucket = self.secrets.entry(key).or_default();
		for (existing, caps) in bucket.iter_mut() {
			if existing.equivalent(secret, true) {
				caps.merge(&p.capabilities);
				return;
			}
		}
		bucket.push((secret.clone(), p.capabilities));
	}

	pub fn forgeable_secret_position(&self, p: &Primitive, phase: i32) -> Option<usize> {
		let position = primitive_get(p.id).ok()?.forgeable_secret?;
		if self.secrets.is_empty() {
			return None;
		}
		let secret = p.arguments.get(position)?;
		let bucket = self.secrets.get(&(p.id, secret.hash_value()))?;
		bucket
			.iter()
			.any(|(annotated, caps)| {
				caps.in_force(Capability::Forgeable, phase) && annotated.equivalent(secret, true)
			})
			.then_some(position)
	}

	pub fn forgeable_secrets(&self, id: PrimitiveId, phase: i32) -> impl Iterator<Item = &Value> {
		self.secrets
			.iter()
			.filter(move |((primitive, _), _)| *primitive == id)
			.flat_map(|(_, bucket)| bucket)
			.filter(move |(_, caps)| caps.in_force(Capability::Forgeable, phase))
			.map(|(secret, _)| secret)
	}

	pub fn lookup(&self, p: &Primitive) -> Capabilities {
		if self.buckets.is_empty() {
			return Capabilities::default();
		}
		let hash = crate::hashing::primitive_hash(p);
		let Some(bucket) = self.buckets.get(&hash) else {
			return Capabilities::default();
		};
		for (existing, caps) in bucket {
			if existing
				.as_primitive()
				.is_some_and(|q| crate::equivalence::equivalent_primitives(q, p, true))
			{
				return *caps;
			}
		}
		Capabilities::default()
	}

	pub fn in_force(&self, p: &Primitive, cap: Capability, phase: i32) -> bool {
		if self.buckets.is_empty() {
			return false;
		}
		self.lookup(p).in_force(cap, phase)
	}

	pub fn annotated_terms(&self) -> impl Iterator<Item = (&Value, &Capabilities)> {
		self.buckets
			.values()
			.flat_map(|b| b.iter().map(|(v, caps)| (v, caps)))
	}

	pub fn assumption_terms(&self) -> Vec<Value> {
		let mut out: Vec<Value> = self
			.buckets
			.values()
			.flatten()
			.map(|(v, _)| v.clone())
			.collect();
		out.sort_by_cached_key(|v| {
			let text = v.to_string();
			(assumption_key(&text), text.len(), v.hash_value(), text)
		});
		out.dedup_by_key(|v| assumption_key(&v.to_string()));
		out.sort_by_cached_key(|v| (v.hash_value(), v.to_string()));
		out
	}

	pub fn governed_occurrences(&self, slots: &[TraceSlot]) -> Vec<(String, Reach)> {
		if self.buckets.is_empty() {
			return Vec::new();
		}
		fn walk(index: &CapabilityIndex, name: &str, v: &Value, out: &mut Vec<(String, Reach)>) {
			let Value::Primitive(p) = v else {
				return;
			};
			for arg in &p.arguments {
				walk(index, name, arg, out);
			}
			if !p.capabilities.is_empty() {
				return;
			}
			let probe = Value::Primitive(Arc::new((**p).clone()));
			if let Some(bucket) = index.buckets.get(&probe.hash_value())
				&& let Some((annotated, _)) = bucket
					.iter()
					.find(|(a, caps)| !caps.is_empty() && a.equivalent(&probe, true))
			{
				out.push((name.to_string(), Reach::SameTerm(annotated.clone())));
				return;
			}
			// The secret-keyed reach: this occurrence is not the annotated term,
			// but a `forgeable` assumption on the same secret licenses forging it.
			if index.forgeable_secret_position(p, i32::MAX).is_some()
				&& let Some(secret) = forgeable_secret_of(p)
			{
				out.push((name.to_string(), Reach::SameSecret(secret.clone())));
			}
		}
		let mut out = Vec::new();
		for slot in slots {
			walk(self, &slot.constant.name, &slot.initial_value, &mut out);
		}
		out
	}

	pub fn assumptions(&self) -> Vec<(Value, Capability, i32)> {
		let mut out = Vec::new();
		for bucket in self.buckets.values() {
			for (v, caps) in bucket {
				for (cap, onset) in caps.iter() {
					out.push((v.clone(), cap, onset));
				}
			}
		}
		out.sort_by_cached_key(|(v, cap, onset)| {
			(v.hash_value(), v.to_string(), cap.index(), *onset)
		});
		out
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::{PRIM_THRESHOLD_SIGN, PRIM_THRESHOLD_SPLIT};

	#[test]
	fn normalized_annotations_survive_erasure_and_cached_unannotated_twins() {
		use crate::primitive::*;
		use crate::testutil::make_private;
		use crate::value::value_nil;

		let k = make_private("normalized_cap_key");
		let m = make_private("normalized_cap_message");
		let reducible = |value: Value| {
			Value::primitive(
				PRIM_SPLIT,
				vec![Value::primitive(PRIM_CONCAT, vec![value, value_nil()], 0)],
				0,
			)
		};
		for cap in Capability::ALL {
			for spec in primitives_supporting(|id| supports(id, cap)) {
				let id = spec.id;
				for output in 0..*spec.output.iter().max().unwrap() as usize {
					let arguments = (0..spec.arity[0])
						.map(|i| if i == 0 { k.clone() } else { m.clone() })
						.collect::<Vec<_>>();
					crate::context::enter_generation(crate::context::next_generation());
					let target = Value::primitive(id, arguments.clone(), output);
					let original = Value::primitive(
						id,
						arguments.into_iter().map(reducible).collect(),
						output,
					);
					assert!(crate::theory::reduce_once(&original).equivalent(&target, true));
					let declared = annotated(original.clone(), cap, 2);
					let erased = Value::primitive(
						PRIM_SPLIT,
						vec![Value::primitive(
							PRIM_CONCAT,
							vec![value_nil(), declared],
							0,
						)],
						0,
					);
					assert!(crate::theory::reduce_once(&erased).equivalent(&value_nil(), true));
					let mut index = CapabilityIndex::default();
					index.insert(&erased);
					for value in [&original, &target] {
						let p = value.as_primitive().unwrap();
						assert!(!index.in_force(p, cap, 1));
						assert!(index.in_force(p, cap, 2));
						for other in Capability::ALL.into_iter().filter(|other| *other != cap) {
							assert!(!index.in_force(p, other, i32::MAX));
						}
					}
					if cap == Capability::Forgeable {
						let p = target.as_primitive().unwrap();
						let mut arguments = p.arguments.clone();
						*arguments.last_mut().unwrap() = value_nil();
						let changed = Value::primitive(id, arguments, output);
						let p = changed.as_primitive().unwrap();
						assert!(index.forgeable_secret_position(p, 1).is_none());
						assert_eq!(index.forgeable_secret_position(p, 2), spec.forgeable_secret);
					}
					let mut empty = CapabilityIndex::default();
					empty.insert(&original);
					assert!(empty.is_empty());
				}
			}
		}
	}

	#[test]
	fn forgeable_secret_search_visits_each_key_once_at_its_earliest_phase() {
		use crate::primitive::{PRIM_MAC, PRIM_SIGN};
		let key = crate::testutil::make_private("forge_index_shared_key");
		let later = crate::testutil::make_private("forge_index_later_key");
		let mut index = CapabilityIndex::default();
		for i in 0..128 {
			let message = crate::testutil::make_private(&format!("forge_index_message_{i}"));
			index.insert(&annotated(
				Value::primitive(PRIM_SIGN, vec![key.clone(), message], 0),
				Capability::Forgeable,
				2 + i,
			));
		}
		index.insert(&annotated(
			Value::primitive(PRIM_SIGN, vec![later.clone(), crate::value::value_nil()], 0),
			Capability::Forgeable,
			4,
		));
		index.insert(&annotated(
			Value::primitive(PRIM_MAC, vec![key.clone(), crate::value::value_nil()], 0),
			Capability::Forgeable,
			0,
		));
		for (phase, count) in [(1, 0), (2, 1), (3, 1), (4, 2)] {
			let keys: Vec<_> = index.forgeable_secrets(PRIM_SIGN, phase).collect();
			assert_eq!(keys.len(), count);
			for secret in [&key, &later] {
				let target = Value::primitive(
					PRIM_SIGN,
					vec![secret.clone(), crate::value::value_nil()],
					0,
				);
				assert_eq!(
					index
						.forgeable_secret_position(target.as_primitive().unwrap(), phase)
						.is_some(),
					keys.iter().any(|found| found.equivalent(secret, true)),
				);
			}
		}
		assert_eq!(index.forgeable_secrets(PRIM_MAC, 0).count(), 1);
	}

	#[test]
	fn capability_collection_visits_shared_subtrees_once() {
		let seed = crate::testutil::make_private("capability_dag_seed");
		let leaf = annotated(
			Value::primitive(crate::primitive::PRIM_HASH, vec![seed], 0),
			Capability::Weak,
			2,
		);
		let mut term = leaf.clone();
		for _ in 0..40 {
			term = Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![term.clone(), term.clone(), term],
				0,
			);
		}
		let mut index = CapabilityIndex::default();
		index.insert(&term);
		let p = leaf.as_primitive().unwrap();
		assert!(!index.in_force(p, Capability::Weak, 1));
		assert!(index.in_force(p, Capability::Weak, 2));
		assert!(!index.in_force(term.as_primitive().unwrap(), Capability::Weak, 2));
	}
	#[test]
	fn a_partial_signature_is_forgeable_without_its_share() {
		assert!(supports(PRIM_THRESHOLD_SIGN, Capability::Forgeable));
		assert!(!supports(PRIM_THRESHOLD_SIGN, Capability::Weak));
		assert!(!supports(PRIM_THRESHOLD_SPLIT, Capability::Forgeable));
	}

	#[test]
	fn default_capabilities_are_empty() {
		let c = Capabilities::default();
		assert!(c.is_empty());
		for cap in Capability::ALL {
			assert!(!c.has(cap));
			assert_eq!(c.onset(cap), None);
			assert!(!c.in_force(cap, 0));
			assert!(!c.in_force(cap, 99));
		}
	}

	#[test]
	fn phase_zero_capability_is_in_force_everywhere() {
		let mut c = Capabilities::default();
		c.set(Capability::Weak, 0);
		assert!(c.in_force(Capability::Weak, 0));
		assert!(c.in_force(Capability::Weak, 3));
		assert!(!c.in_force(Capability::Forgeable, 0));
	}

	#[test]
	fn delayed_capability_is_in_force_from_onset_onward() {
		let mut c = Capabilities::default();
		c.set(Capability::Weak, 2);
		assert!(!c.in_force(Capability::Weak, 0));
		assert!(!c.in_force(Capability::Weak, 1));
		assert!(c.in_force(Capability::Weak, 2));
		assert!(c.in_force(Capability::Weak, 7));
	}

	#[test]
	fn merge_takes_the_earlier_onset() {
		let mut a = Capabilities::default();
		a.set(Capability::Weak, 5);
		let mut b = Capabilities::default();
		b.set(Capability::Weak, 2);
		b.set(Capability::Forgeable, 1);
		a.merge(&b);
		assert_eq!(a.onset(Capability::Weak), Some(2));
		assert_eq!(a.onset(Capability::Forgeable), Some(1));
	}

	#[test]
	fn iter_yields_only_declared_capabilities_in_order() {
		let mut c = Capabilities::default();
		c.set(Capability::Malleable, 3);
		c.set(Capability::Weak, 0);
		let got: Vec<_> = c.iter().collect();
		assert_eq!(got, vec![(Capability::Weak, 0), (Capability::Malleable, 3)]);
	}

	fn annotated(v: Value, cap: Capability, onset: i32) -> Value {
		let Value::Primitive(p) = v else {
			panic!("expected a primitive");
		};
		let mut p = (*p).clone();
		p.capabilities.set(cap, onset);
		Value::Primitive(Arc::new(p))
	}

	#[test]
	fn index_answers_for_an_equivalent_but_unannotated_term() {
		use crate::primitive::*;
		use crate::testutil::*;
		let k = make_constant("cidx_k");
		let m = make_constant("cidx_m");
		let ad = make_constant("cidx_ad");
		let plain = make_primitive(PRIM_AEAD_ENC, vec![k, make_constant("cidx_n"), m, ad], 0);

		let mut index = CapabilityIndex::default();
		index.insert(&annotated(plain.clone(), Capability::Weak, 0));

		let Value::Primitive(plain_p) = &plain else {
			panic!("expected a primitive");
		};
		assert!(
			index.in_force(plain_p, Capability::Weak, 0),
			"equivalent terms must share the annotation"
		);
	}

	#[test]
	fn index_records_nested_annotations() {
		use crate::primitive::*;
		use crate::testutil::*;
		let a = make_constant("cnest_a");
		let b = make_constant("cnest_b");
		let inner = make_primitive(PRIM_PUBKEY, vec![a], 0);
		let outer = make_primitive(
			PRIM_DH_KEX,
			vec![annotated(inner.clone(), Capability::Weak, 3), b],
			0,
		);

		let mut index = CapabilityIndex::default();
		index.insert(&outer);

		let Value::Primitive(inner_p) = &inner else {
			panic!("expected a primitive");
		};
		assert!(!index.in_force(inner_p, Capability::Weak, 2));
		assert!(index.in_force(inner_p, Capability::Weak, 3));
	}

	#[test]
	fn empty_index_grants_nothing() {
		use crate::primitive::*;
		use crate::testutil::*;
		let a = make_constant("cempty_a");
		let h = make_primitive(PRIM_HASH, vec![a], 0);
		let Value::Primitive(p) = &h else {
			panic!("expected a primitive");
		};
		let index = CapabilityIndex::default();
		assert!(index.is_empty());
		for cap in Capability::ALL {
			assert!(!index.in_force(p, cap, 0));
		}
	}

	#[test]
	fn colliding_assumptions_have_a_stable_order() {
		use crate::primitive::*;
		use crate::testutil::make_primitive;
		use crate::types::{Constant, ValueId};

		fn constant(name: &str, id: ValueId) -> Value {
			Value::Constant(Constant {
				name: Arc::from(name),
				id,
				..Default::default()
			})
		}

		let left = make_primitive(
			PRIM_HASH,
			vec![constant("cap_order_a", 10), constant("cap_order_b", 100)],
			0,
		);
		let right = make_primitive(
			PRIM_HASH,
			vec![constant("cap_order_c", 11), constant("cap_order_d", 69)],
			0,
		);
		assert_eq!(left.hash_value(), right.hash_value());
		let left = annotated(left, Capability::Weak, 0);
		let right = annotated(right, Capability::Weak, 0);
		let ordered = |values: &[Value]| {
			let mut index = CapabilityIndex::default();
			for value in values {
				index.insert(value);
			}
			index
				.assumptions()
				.into_iter()
				.map(|(value, _, _)| value.to_string())
				.collect::<Vec<_>>()
		};
		assert_eq!(
			ordered(&[left.clone(), right.clone()]),
			ordered(&[right, left])
		);
	}

	#[test]
	fn colliding_copy_terms_choose_the_same_assumption_representative() {
		use crate::primitive::*;
		use crate::testutil::make_primitive;
		use crate::types::{Constant, ValueId};

		fn constant(name: &str, id: ValueId) -> Value {
			Value::Constant(Constant {
				name: Arc::from(name),
				id,
				..Default::default()
			})
		}

		let left = make_primitive(
			PRIM_HASH,
			vec![constant("copy_a#1", 10), constant("copy_b#1", 100)],
			0,
		);
		let right = make_primitive(
			PRIM_HASH,
			vec![constant("copy_a#2", 11), constant("copy_b#2", 69)],
			0,
		);
		assert_eq!(left.hash_value(), right.hash_value());
		let left = annotated(left, Capability::Weak, 0);
		let right = annotated(right, Capability::Weak, 0);
		let chosen = |values: &[Value]| {
			let mut index = CapabilityIndex::default();
			for value in values {
				index.insert(value);
			}
			index.assumption_terms()[0].to_string()
		};
		assert_eq!(
			chosen(&[left.clone(), right.clone()]),
			chosen(&[right, left])
		);
	}

	#[test]
	fn from_name_is_case_insensitive_and_rejects_unknown() {
		assert_eq!(Capability::from_name("weak"), Some(Capability::Weak));
		assert_eq!(
			Capability::from_name("FORGEABLE"),
			Some(Capability::Forgeable)
		);
		assert_eq!(Capability::from_name("nonsense"), None);
	}
}
