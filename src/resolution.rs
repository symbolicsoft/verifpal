/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::types::*;

pub(crate) fn resolve_trace_constant(c: &Constant, trace: &ProtocolTrace) -> Value {
	let value = Value::Constant(c.clone());
	resolve_trace_value(&value, trace).unwrap_or(value)
}

pub(crate) fn resolve_trace_term(value: &Value, trace: &ProtocolTrace) -> Value {
	resolve_trace_value(value, trace).unwrap_or_else(|| value.clone())
}

fn resolve_trace_value(value: &Value, trace: &ProtocolTrace) -> Option<Value> {
	let Value::Constant(c) = value else {
		return resolve_trace_primitive(value, trace);
	};
	let idx = trace.index_of(c)?;
	let resolved = &trace.slots[idx].initial_value;
	match resolved {
		Value::Constant(rc) => (rc.id != c.id).then(|| resolved.clone()),
		Value::Primitive(_) => {
			Some(resolve_trace_primitive(resolved, trace).unwrap_or_else(|| resolved.clone()))
		}
	}
}

fn resolve_trace_primitive(value: &Value, trace: &ProtocolTrace) -> Option<Value> {
	let prim = value.as_primitive()?;
	prim.map_arguments(|arg| resolve_trace_value(arg, trace))
		.map(|mapped| Value::Primitive(Arc::new(mapped)))
}

pub(crate) fn state_mentions(
	value: &Value,
	trace: &ProtocolTrace,
	ps: &PrincipalState,
	owner: PrincipalId,
	target: ValueId,
) -> bool {
	match value {
		Value::Constant(c) => {
			if c.id == target {
				return match ps.index_of(c) {
					Some(idx) => owner == ps.id || ps.meta[idx].mutatable_to.contains(&owner),
					None => false,
				};
			}
			let Some(idx) = trace.index_of(c) else {
				return false;
			};
			let inner = &trace.slots[idx].initial_value;
			if !matches!(inner, Value::Primitive(_)) {
				return false;
			}
			let next = ps
				.index_of(c)
				.map(|i| ps.values[i].provenance.creator)
				.unwrap_or(trace.slots[idx].creator);
			state_mentions(inner, trace, ps, next, target)
		}
		Value::Primitive(p) => p
			.arguments
			.iter()
			.any(|arg| state_mentions(arg, trace, ps, owner, target)),
	}
}

fn compute_visibility(
	slot_idx: usize,
	root_index: usize,
	root_value: &Value,
	ps: &PrincipalState,
	existing_use_original: bool,
) -> bool {
	if slot_idx == root_index {
		if existing_use_original {
			return true;
		}
		return ps.should_use_original(slot_idx);
	}

	let root_from_other = matches!(root_value, Value::Primitive(_))
		&& ps.values[root_index].provenance.creator != ps.id;

	let forced = existing_use_original || root_from_other;
	if forced {
		!ps.meta[slot_idx]
			.mutatable_to
			.contains(&ps.values[root_index].provenance.creator)
	} else {
		ps.should_use_original(slot_idx)
	}
}

pub(crate) type ResolveMemo = Vec<[Option<Value>; 2]>;

pub(crate) fn resolve_ps_values(
	value: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	use_original: bool,
	memo: &mut ResolveMemo,
) -> VResult<Option<Value>> {
	let Value::Constant(c) = value else {
		return resolve_ps_primitive(value, root_value, root_index, ps, use_original, memo);
	};
	let Some(slot_idx) = ps.index_of(c) else {
		return Err(VerifpalError::resolution("invalid index".into()));
	};
	let use_orig = compute_visibility(slot_idx, root_index, root_value, ps, use_original);
	let rerooted = slot_idx != root_index;
	if rerooted && let Some(hit) = &memo[slot_idx][usize::from(use_orig)] {
		return Ok(Some(hit.clone()));
	}
	let resolved = if use_orig {
		ps.values[slot_idx].perceived()
	} else {
		&ps.values[slot_idx].value
	};
	match resolved {
		Value::Constant(rc) => Ok((rc.id != c.id).then(|| resolved.clone())),
		Value::Primitive(_) if !rerooted => {
			let mapped =
				resolve_ps_primitive(resolved, root_value, root_index, ps, use_orig, memo)?;
			Ok(Some(mapped.unwrap_or_else(|| resolved.clone())))
		}
		Value::Primitive(_) => {
			let mapped = resolve_ps_primitive(resolved, resolved, slot_idx, ps, use_orig, memo)?;
			let out = mapped.unwrap_or_else(|| resolved.clone());
			memo[slot_idx][usize::from(use_orig)] = Some(out.clone());
			Ok(Some(out))
		}
	}
}

fn resolve_ps_primitive(
	value: &Value,
	root_value: &Value,
	root_index: usize,
	ps: &PrincipalState,
	use_original: bool,
	memo: &mut ResolveMemo,
) -> VResult<Option<Value>> {
	let prim = value.try_as_primitive()?;
	let use_orig = if ps.values[root_index].provenance.creator == ps.id {
		false
	} else {
		use_original
	};
	let mapped = prim.try_map_arguments(|arg| {
		resolve_ps_values(arg, root_value, root_index, ps, use_orig, memo)
	})?;
	Ok(mapped.map(|mapped| Value::Primitive(Arc::new(mapped))))
}

pub(crate) fn principal_uses_constant(
	trace: &ProtocolTrace,
	states: &[PrincipalState],
	principal_id: PrincipalId,
	c: &Constant,
) -> bool {
	let Some(ps) = states.iter().find(|state| state.id == principal_id) else {
		return false;
	};
	trace.slots.iter().any(|slot| {
		slot.creator == principal_id
			&& matches!(&slot.initial_value, Value::Primitive(_))
			&& state_mentions(&slot.initial_value, trace, ps, ps.id, c.id)
	})
}

pub(crate) fn constant_used_by_any_principal(
	trace: &ProtocolTrace,
	states: &[PrincipalState],
	c: &Constant,
) -> bool {
	states
		.iter()
		.any(|ps| principal_uses_constant(trace, states, ps.id, c))
}

pub(crate) fn constant_used_by_principal(
	trace: &ProtocolTrace,
	principal_id: PrincipalId,
	c: &Constant,
) -> bool {
	trace
		.used_by
		.get(&c.id)
		.is_some_and(|principals| principals.contains(&principal_id))
}

pub(crate) fn value_constant_contains_fresh_values(
	c: &Constant,
	ps: &PrincipalState,
) -> VResult<bool> {
	let idx = ps
		.index_of(c)
		.ok_or_else(|| VerifpalError::resolution("invalid value".into()))?;
	let mut constants = Vec::new();
	ps.values[idx].value.collect_constants(&mut constants);
	Ok(constants.iter().any(|inner| {
		ps.index_of(inner)
			.is_some_and(|i| ps.meta[i].constant.fresh)
	}))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testutil::*;

	fn two_slot_state(mutatable_to: Vec<PrincipalId>, root_creator: PrincipalId) -> PrincipalState {
		let wire = make_constant("cv_wire");
		let term_name = make_constant("cv_term");
		let mutated = make_constant("cv_mutated");
		let (wire_c, term_c) = (
			wire.as_constant().expect("constant").clone(),
			term_name.as_constant().expect("constant").clone(),
		);

		let mut wire_meta = make_slot_meta(&wire_c, false);
		wire_meta.wire = vec![1];
		wire_meta.known = true;
		wire_meta.mutatable_to = mutatable_to;
		let term_meta = make_slot_meta(&term_c, true);

		let mut wire_values = make_slot_values(&mutated, 2);
		wire_values.original = wire.clone();
		wire_values.provenance.attacker_tainted = true;
		let term_values = make_slot_values(
			&make_primitive(crate::primitive::PRIM_HASH, vec![wire], 0),
			root_creator,
		);

		make_principal_state(
			"Bob",
			1,
			vec![wire_meta, term_meta],
			vec![wire_values, term_values],
		)
	}

	fn visibility(ps: &PrincipalState, slot: usize, root: usize, forced: bool) -> bool {
		let root_value = ps.values[root].value.clone();
		compute_visibility(slot, root, &root_value, ps, forced)
	}

	#[test]
	fn the_root_slot_takes_the_visibility_it_was_asked_for() {
		let ps = two_slot_state(vec![], 1);
		assert!(visibility(&ps, 1, 1, true));
		assert_eq!(visibility(&ps, 1, 1, false), ps.should_use_original(1));
	}

	#[test]
	fn a_term_of_this_principals_own_sees_the_mutation_it_was_handed() {
		let ps = two_slot_state(vec![2], 1);
		assert!(
			!visibility(&ps, 0, 1, false),
			"Bob computed this term himself out of a wire value the attacker replaced, \
			 so he computes with what he was handed"
		);
	}

	#[test]
	fn a_term_of_another_principals_keeps_its_own_value_unless_the_attacker_reached_it() {
		let unreachable = two_slot_state(vec![], 2);
		assert!(
			visibility(&unreachable, 0, 1, false),
			"the root belongs to another principal and no unguarded delivery carried \
			 this value to it, so its resolution is the honest one"
		);
		let reachable = two_slot_state(vec![2], 2);
		assert!(
			!visibility(&reachable, 0, 1, false),
			"the same value reached that principal unguarded, so the attacker's choice \
			 does appear inside what it computed"
		);
	}

	#[test]
	fn an_inherited_original_view_still_asks_whether_the_attacker_reached_the_slot() {
		let unreachable = two_slot_state(vec![], 1);
		assert!(visibility(&unreachable, 0, 1, true));
		let reachable = two_slot_state(vec![1], 1);
		assert!(
			!visibility(&reachable, 0, 1, true),
			"an outer original view does not survive into a slot the attacker could \
			 replace on its way to the term's creator"
		);
	}

	#[test]
	fn a_constant_rooted_term_is_never_forced_by_its_root() {
		let mut ps = two_slot_state(vec![2], 2);
		ps.values[1] = make_slot_values(&make_constant("cv_plain"), 2);
		assert_eq!(
			visibility(&ps, 0, 1, false),
			ps.should_use_original(0),
			"only a primitive root can impose another principal's view"
		);
	}
}
