/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::RefCell;
use std::collections::VecDeque;
use std::hash::Hasher;
use std::sync::Arc;

use crate::types::*;

type TraceMemo = IdMap<usize, Option<Value>>;

#[derive(Default)]
struct ResolvedTerms {
	entries: IdMap<u64, Vec<Arc<Primitive>>>,
	order: VecDeque<(u64, usize)>,
}

thread_local! {
	static RESOLVED: RefCell<crate::context::Generational<ResolvedTerms>> = RefCell::new(crate::context::Generational::default());
}

fn same_resolved_argument(left: &Value, right: &Value) -> bool {
	match (left, right) {
		(Value::Primitive(left), Value::Primitive(right)) => Arc::ptr_eq(left, right),
		(Value::Constant(left), Value::Constant(right)) => {
			left.id == right.id
				&& left.name == right.name
				&& left.guard == right.guard
				&& left.fresh == right.fresh
				&& left.leaked == right.leaked
				&& left.declaration == right.declaration
				&& left.qualifier == right.qualifier
		}
		_ => false,
	}
}

fn resolved_primitive(mapped: Primitive) -> Value {
	let mut hash = IdHasher::default();
	hash.write_u8(mapped.id);
	hash.write_usize(mapped.output);
	hash.write_usize(mapped.threshold);
	hash.write_u32(mapped.instance);
	hash.write_u8(u8::from(mapped.instance_check));
	for argument in &mapped.arguments {
		match argument {
			Value::Constant(c) => {
				hash.write_u8(0);
				hash.write_u32(c.id);
			}
			Value::Primitive(p) => {
				hash.write_u8(1);
				hash.write_usize(Arc::as_ptr(p) as usize);
			}
		}
	}
	let key = hash.finish();
	RESOLVED.with(|cell| {
		let mut cache = cell.borrow_mut();
		let cache = cache.fresh();
		let bucket = cache.entries.entry(key).or_default();
		if let Some(entry) = bucket.iter().find(|entry| {
			entry.id == mapped.id
				&& entry.output == mapped.output
				&& entry.threshold == mapped.threshold
				&& entry.instance == mapped.instance
				&& entry.instance_check == mapped.instance_check
				&& entry.capabilities == mapped.capabilities
				&& entry.arguments.len() == mapped.arguments.len()
				&& entry
					.arguments
					.iter()
					.zip(&mapped.arguments)
					.all(|(left, right)| same_resolved_argument(left, right))
		}) {
			return Value::Primitive(entry.clone());
		}
		let value = Arc::new(mapped);
		bucket.push(value.clone());
		cache.order.push_back((key, Arc::as_ptr(&value) as usize));
		if cache.order.len() > 8192
			&& let Some((hash, pointer)) = cache.order.pop_front()
		{
			let bucket = cache.entries.get_mut(&hash).unwrap();
			bucket.retain(|entry| Arc::as_ptr(entry) as usize != pointer);
			if bucket.is_empty() {
				cache.entries.remove(&hash);
			}
		}
		Value::Primitive(value)
	})
}

pub(crate) fn resolve_trace_constant(c: &Constant, trace: &ProtocolTrace) -> Value {
	let value = Value::Constant(c.clone());
	resolve_trace_value(&value, trace, &mut TraceMemo::default()).unwrap_or(value)
}

pub(crate) fn resolve_trace_term(value: &Value, trace: &ProtocolTrace) -> Value {
	resolve_trace_value(value, trace, &mut TraceMemo::default()).unwrap_or_else(|| value.clone())
}

fn resolve_trace_value(
	value: &Value,
	trace: &ProtocolTrace,
	memo: &mut TraceMemo,
) -> Option<Value> {
	let Value::Constant(c) = value else {
		return resolve_trace_primitive(value, trace, memo);
	};
	let idx = trace.index_of(c)?;
	if let Some(hit) = memo.get(&idx) {
		return hit.clone();
	}
	let resolved = &trace.slots[idx].initial_value;
	let out = match resolved {
		Value::Constant(rc) => (rc.id != c.id).then(|| resolved.clone()),
		Value::Primitive(_) => {
			Some(resolve_trace_primitive(resolved, trace, memo).unwrap_or_else(|| resolved.clone()))
		}
	};
	memo.insert(idx, out.clone());
	out
}

fn resolve_trace_primitive(
	value: &Value,
	trace: &ProtocolTrace,
	memo: &mut TraceMemo,
) -> Option<Value> {
	let Value::Primitive(prim) = value else {
		return None;
	};
	prim.map_arguments(|arg| resolve_trace_value(arg, trace, memo))
		.map(resolved_primitive)
}

pub(crate) fn mentions_across_principals(
	value: &Value,
	trace: &ProtocolTrace,
	principal: PrincipalId,
	target: ValueId,
) -> bool {
	let mut pending = vec![(value, principal)];
	let mut seen = IdSet::default();
	while let Some((value, owner)) = pending.pop() {
		match value {
			Value::Constant(c) => {
				if c.id == target {
					if trace.index_of(c).is_some_and(|idx| {
						owner == principal || trace.slots[idx].mutation_reaches(owner)
					}) {
						return true;
					}
					continue;
				}
				let Some(slot) = trace.index_of(c).map(|idx| &trace.slots[idx]) else {
					continue;
				};
				if matches!(slot.initial_value, Value::Primitive(_)) {
					pending.push((&slot.initial_value, slot.creator));
				}
			}
			Value::Primitive(p) => {
				if seen.insert((Arc::as_ptr(p) as usize, owner)) {
					pending.extend(p.arguments.iter().rev().map(|arg| (arg, owner)));
				}
			}
		}
	}
	false
}

pub(crate) fn principal_uses_constant(
	trace: &ProtocolTrace,
	principal: PrincipalId,
	c: &Constant,
) -> bool {
	trace.slots.iter().any(|slot| {
		slot.creator == principal
			&& matches!(&slot.initial_value, Value::Primitive(_))
			&& mentions_across_principals(&slot.initial_value, trace, principal, c.id)
	})
}

pub(crate) fn constant_used_by_any_principal(trace: &ProtocolTrace, c: &Constant) -> bool {
	trace
		.principal_ids
		.iter()
		.any(|&principal| principal_uses_constant(trace, principal, c))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testutil::*;

	#[test]
	fn repeated_resolution_shares_ground_terms_and_tracks_changed_inputs() {
		let model = crate::parser::parse_string("resolved.vp", "attacker[active]\nprincipal Sender[generates a, b]\nSender -> Reader: a, b\nprincipal Reader[x = HASH(a)\ny = HASH(x)\nz = HASH(b)]\nqueries[confidentiality? y]\n").unwrap();
		let trace = crate::sanity::sanity(&model).unwrap();
		let y = trace_constant(&trace, "y");
		let first = resolve_trace_term(&y, &trace);
		let second = resolve_trace_term(&y, &trace);
		assert!(first.same_term(&second));
		let changed = resolve_trace_term(
			&Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![trace_constant(&trace, "z")],
				0,
			),
			&trace,
		);
		assert!(!first.equivalent(&changed, true));
	}

	#[test]
	fn resolved_terms_preserve_annotations_checks_and_constant_metadata() {
		let input = make_constant("resolution_metadata_input");
		let source = Arc::new(Primitive::new(
			crate::primitive::PRIM_ENC,
			vec![input.clone(), input.clone()],
			0,
		));
		let output = make_constant("resolution_metadata_output");
		let plain = resolved_primitive(source.with_arguments(vec![input.clone(), output.clone()]));
		let mut annotated = source.as_ref().clone();
		annotated.capabilities.set(Capability::Weak, 2);
		annotated.instance_check = true;
		let annotated = Arc::new(annotated);
		let checked =
			resolved_primitive(annotated.with_arguments(vec![input.clone(), output.clone()]));
		assert!(checked.as_primitive().unwrap().instance_check);
		assert_eq!(
			checked.as_primitive().unwrap().capabilities,
			annotated.capabilities
		);
		assert!(!plain.as_primitive().unwrap().instance_check);
		let parent = Arc::new(Primitive::new(
			crate::primitive::PRIM_HASH,
			vec![input.clone()],
			0,
		));
		let plain_parent = resolved_primitive(parent.with_arguments(vec![plain.clone()]));
		let checked_parent = resolved_primitive(parent.with_arguments(vec![checked]));
		assert!(
			!plain_parent.as_primitive().unwrap().arguments[0]
				.as_primitive()
				.unwrap()
				.instance_check
		);
		assert!(
			checked_parent.as_primitive().unwrap().arguments[0]
				.as_primitive()
				.unwrap()
				.instance_check
		);
		let mut fresh = output.as_constant().unwrap().clone();
		fresh.fresh = true;
		let changed =
			resolved_primitive(source.with_arguments(vec![input, Value::Constant(fresh)]));
		assert!(
			changed.as_primitive().unwrap().arguments[1]
				.as_constant()
				.unwrap()
				.fresh
		);
		assert!(
			!plain.as_primitive().unwrap().arguments[1]
				.as_constant()
				.unwrap()
				.fresh
		);
	}

	#[test]
	fn evicting_resolved_terms_only_recomputes_the_same_value() {
		let input = make_constant("resolution_eviction_input");
		let source = Arc::new(Primitive::new(crate::primitive::PRIM_HASH, vec![input], 0));
		let output = make_constant("resolution_eviction_output");
		let before = resolved_primitive(source.with_arguments(vec![output.clone()]));
		RESOLVED.with(|cell| *cell.borrow_mut().fresh() = ResolvedTerms::default());
		let after = resolved_primitive(source.with_arguments(vec![output]));
		assert!(!before.same_term(&after));
		assert!(crate::theory::structurally_identical(&before, &after));
	}

	#[test]
	fn use_checks_visit_shared_terms_without_expanding_their_occurrences() {
		let target = make_constant("mentions_dag_target");
		let seed = make_constant("mentions_dag_seed");
		let trace = make_trace(vec![make_trace_slot(&target, &target, 1)]);
		let mut term = seed;
		for _ in 0..40 {
			term = Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![term.clone(), term.clone(), term],
				0,
			);
		}
		let id = target.as_constant().unwrap().id;
		assert!(!mentions_across_principals(&term, &trace, 1, id));
		let used = Value::primitive(crate::primitive::PRIM_HASH, vec![term, target], 0);
		assert!(mentions_across_principals(&used, &trace, 1, id));
	}

	#[test]
	fn use_checks_keep_distinct_owners_of_a_shared_term() {
		let model = crate::parser::parse_string(
			"mentions_owner.vp",
			"attacker[passive]\n\
			principal Alice[generates target\n sealed = HASH(target)]\n\
			Alice -> Bob: target, sealed\n\
			principal Bob[local = HASH(target)]\n\
			queries[confidentiality? target]\n",
		)
		.unwrap();
		let trace = crate::sanity::sanity(&model).unwrap();
		let bob = trace.principal_ids[trace.principals.iter().position(|p| p == "Bob").unwrap()];
		let target = trace_constant(&trace, "target");
		let sealed = trace_constant(&trace, "sealed");
		let slot = trace.index_of(sealed.as_constant().unwrap()).unwrap();
		let shared = trace.slots[slot].initial_value.clone();
		let id = target.as_constant().unwrap().id;
		assert!(!mentions_across_principals(&sealed, &trace, bob, id));
		let both = Value::primitive(crate::primitive::PRIM_HASH, vec![sealed, shared], 0);
		assert!(mentions_across_principals(&both, &trace, bob, id));
	}
}
