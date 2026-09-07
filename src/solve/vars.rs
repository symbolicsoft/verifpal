/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::types::*;
use crate::value::value_nil;

pub(crate) const ATTACKER_VAR_BASE: ValueId = 0x8000_0000;

pub(crate) const FREE_VAR_BASE: ValueId = 0xC000_0000;

pub(crate) const FREE_LANE_STRIDE: u32 = 1 << 16;

pub(crate) const FREE_LANES: u32 = 1 << 13;

pub(crate) fn free_lane_bounds(lane: u32) -> (u32, u32) {
	assert!(
		lane <= FREE_LANES,
		"free-variable lane {lane} is beyond the {FREE_LANES} available"
	);
	let top = u32::MAX - FREE_VAR_BASE + 1;
	if lane == 0 {
		(0, top - FREE_LANES * FREE_LANE_STRIDE)
	} else {
		let start = top - lane * FREE_LANE_STRIDE;
		(start, start + FREE_LANE_STRIDE)
	}
}

pub(crate) fn is_free_var_id(id: ValueId) -> bool {
	id >= FREE_VAR_BASE
}

pub(crate) fn free_var(n: u32) -> Value {
	Value::Constant(Constant {
		name: Arc::from(format!("$free{n}")),
		id: FREE_VAR_BASE + n,
		..Default::default()
	})
}

pub(crate) type Substitution = IdMap<ValueId, Value>;

pub(crate) fn attacker_var_id(slot: usize) -> ValueId {
	ATTACKER_VAR_BASE + slot as ValueId
}

pub(crate) fn is_var_id(id: ValueId) -> bool {
	id >= ATTACKER_VAR_BASE
}

pub(crate) fn is_slot_var_id(id: ValueId) -> bool {
	(ATTACKER_VAR_BASE..FREE_VAR_BASE).contains(&id)
}

pub(crate) fn slot_of_var_id(id: ValueId) -> usize {
	(id - ATTACKER_VAR_BASE) as usize
}

pub(crate) fn attacker_var(slot: usize, hint: &str) -> Value {
	Value::Constant(Constant {
		name: Arc::from(format!("${hint}")),
		id: attacker_var_id(slot),
		..Default::default()
	})
}

pub(crate) fn as_var(v: &Value) -> Option<ValueId> {
	match v {
		Value::Constant(c) if is_var_id(c.id) => Some(c.id),
		_ => None,
	}
}

pub(crate) fn contains_var(v: &Value) -> bool {
	match v {
		Value::Constant(c) => is_var_id(c.id),
		Value::Primitive(p) => {
			if let Some(has) = p.hash.has_variables() {
				return has;
			}
			let has = p.arguments.iter().any(contains_var);
			p.hash.set_has_variables(has);
			has
		}
	}
}

pub(crate) fn collect_free_vars(v: &Value, out: &mut Vec<ValueId>) {
	collect_var_ids(v, out, is_free_var_id);
}

pub(crate) fn collect_vars(v: &Value, out: &mut Vec<ValueId>) {
	collect_var_ids(v, out, is_var_id);
}

fn collect_var_ids(v: &Value, out: &mut Vec<ValueId>, include: fn(ValueId) -> bool) {
	if !contains_var(v) {
		return;
	}
	for term in crate::value::subterms(v) {
		if let Value::Constant(c) = term
			&& include(c.id)
			&& !out.contains(&c.id)
		{
			out.push(c.id);
		}
	}
}

pub(crate) fn apply(v: &Value, s: &Substitution) -> Value {
	if s.is_empty() || !contains_var(v) {
		return v.clone();
	}
	let mut shared: IdMap<usize, Value> = IdMap::default();
	apply_shared(v, s, &mut shared)
}

fn apply_shared(v: &Value, s: &Substitution, shared: &mut IdMap<usize, Value>) -> Value {
	if !contains_var(v) {
		return v.clone();
	}
	match v {
		Value::Constant(c) => match s.get(&c.id) {
			Some(bound) => apply_shared(bound, s, shared),
			None => v.clone(),
		},
		Value::Primitive(p) => {
			let key = Arc::as_ptr(p) as usize;
			if let Some(hit) = shared.get(&key) {
				return hit.clone();
			}
			let args: Vec<Value> = p
				.arguments
				.iter()
				.map(|a| apply_shared(a, s, shared))
				.collect();
			let args = crate::primitive::normalise_arguments(p.id, args);
			let out = Value::Primitive(Arc::new(p.with_arguments(args)));
			shared.insert(key, out.clone());
			out
		}
	}
}

pub(crate) fn occurs(id: ValueId, v: &Value, s: &Substitution) -> bool {
	if is_var_id(id) && !contains_var(v) {
		return false;
	}
	let mut variables = IdSet::default();
	let mut primitives = IdSet::default();
	let mut pending = vec![v];
	while let Some(term) = pending.pop() {
		match term {
			Value::Constant(c) => {
				if c.id == id {
					return true;
				}
				if is_var_id(c.id)
					&& let Some(bound) = s.get(&c.id)
					&& variables.insert(c.id)
				{
					pending.push(bound);
				}
			}
			Value::Primitive(p) => {
				if primitives.insert(Arc::as_ptr(p) as usize) {
					pending.extend(p.arguments.iter().rev());
				}
			}
		}
	}
	false
}

pub(crate) fn bind(s: &mut Substitution, id: ValueId, v: Value) -> bool {
	match s.get(&id) {
		Some(existing) => existing.equivalent(&v, true),
		None => {
			if occurs(id, &v, s) {
				return false;
			}
			s.insert(id, v);
			true
		}
	}
}

pub(crate) fn ground_free(v: &Value) -> Value {
	ground_free_as(v, &value_nil())
}

pub(crate) fn ground_free_as(v: &Value, filler: &Value) -> Value {
	let mut shared: IdMap<usize, Value> = IdMap::default();
	ground_free_shared(v, filler, &mut shared)
}

fn ground_free_shared(v: &Value, filler: &Value, shared: &mut IdMap<usize, Value>) -> Value {
	match v {
		Value::Constant(c) => {
			if is_free_var_id(c.id) {
				filler.clone()
			} else {
				v.clone()
			}
		}
		Value::Primitive(p) => {
			let key = Arc::as_ptr(p) as usize;
			if let Some(hit) = shared.get(&key) {
				return hit.clone();
			}
			let args: Vec<Value> = p
				.arguments
				.iter()
				.map(|a| ground_free_shared(a, filler, shared))
				.collect();
			let args = crate::primitive::normalise_arguments(p.id, args);
			let out = Value::Primitive(Arc::new(p.with_arguments(args)));
			shared.insert(key, out.clone());
			out
		}
	}
}

pub(crate) fn ground_remaining(v: &Value, s: &mut Substitution) {
	let mut free = Vec::new();
	collect_vars(v, &mut free);
	for id in free {
		s.entry(id).or_insert_with(value_nil);
	}
}

pub(crate) fn remove_local_bindings(mut s: Substitution, ids: &[ValueId]) -> Substitution {
	let local: Substitution = ids
		.iter()
		.filter_map(|id| s.remove(id).map(|value| (*id, value)))
		.collect();
	if !local.is_empty() {
		for value in s.values_mut() {
			*value = apply(value, &local);
		}
	}
	s
}

pub(crate) fn same_substitution(a: &Substitution, b: &Substitution) -> bool {
	a.len() == b.len()
		&& a.iter().all(|(id, v)| match b.get(id) {
			Some(other) => v.equivalent(other, true),
			None => false,
		})
}

pub(crate) fn canonical_slots(s: &Substitution) -> Substitution {
	fn rename(
		v: &Value,
		names: &mut IdMap<ValueId, Value>,
		shared: &mut IdMap<usize, Value>,
	) -> Value {
		if !contains_var(v) {
			return v.clone();
		}
		match v {
			Value::Constant(c) if is_free_var_id(c.id) => {
				let next = names.len() as u32;
				names.entry(c.id).or_insert_with(|| free_var(next)).clone()
			}
			Value::Constant(_) => v.clone(),
			Value::Primitive(p) => {
				let key = Arc::as_ptr(p) as usize;
				if let Some(hit) = shared.get(&key) {
					return hit.clone();
				}
				let args = p
					.arguments
					.iter()
					.map(|a| rename(a, names, shared))
					.collect();
				let out = Value::Primitive(Arc::new(p.with_arguments(args)));
				shared.insert(key, out.clone());
				out
			}
		}
	}

	let mut slots: Vec<_> = s.keys().copied().filter(|id| is_slot_var_id(*id)).collect();
	slots.sort_unstable();
	let values: Vec<_> = slots.iter().map(|id| apply(&s[id], s)).collect();
	let mut names = IdMap::default();
	let mut shared = IdMap::default();
	slots
		.into_iter()
		.zip(values.iter().map(|v| rename(v, &mut names, &mut shared)))
		.collect()
}

pub(crate) fn dedupe_slots(mut candidates: Vec<Substitution>) -> Vec<Substitution> {
	let mut seen = SeenSubstitutions::default();
	let mut keys = Vec::new();
	candidates.retain(|s| {
		let key = canonical_slots(s);
		if seen.contains(&keys, &key) {
			return false;
		}
		keys.push(key);
		seen.absorb(&keys);
		true
	});
	candidates
}

pub(crate) fn substitution_hash(s: &Substitution) -> u64 {
	let mut acc: u64 = s.len() as u64;
	for (id, v) in s {
		let mut entry = (*id as u64)
			.wrapping_mul(0x9E37_79B9_7F4A_7C15)
			.rotate_left(17)
			^ v.hash_value().wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
		entry ^= entry >> 31;
		entry = entry.wrapping_mul(0xD6E8_FEB8_6659_FD93);
		entry ^= entry >> 32;
		acc ^= entry;
	}
	acc
}

#[derive(Default)]
pub(crate) struct SeenSubstitutions {
	index: IdMap<u64, Vec<usize>>,
	absorbed: usize,
}

impl SeenSubstitutions {
	pub(crate) fn absorb(&mut self, items: &[Substitution]) {
		for (i, candidate) in items.iter().enumerate().skip(self.absorbed) {
			self.index
				.entry(substitution_hash(candidate))
				.or_default()
				.push(i);
		}
		self.absorbed = items.len();
	}

	pub(crate) fn contains(&self, items: &[Substitution], candidate: &Substitution) -> bool {
		self.index
			.get(&substitution_hash(candidate))
			.is_some_and(|bucket| {
				bucket
					.iter()
					.any(|&i| same_substitution(&items[i], candidate))
			})
	}
}

pub(crate) fn dedupe(candidates: Vec<Substitution>) -> Vec<Substitution> {
	let mut out: Vec<Substitution> = Vec::with_capacity(candidates.len());
	let mut seen: IdMap<u64, Vec<usize>> = IdMap::default();
	for candidate in candidates {
		let hash = substitution_hash(&candidate);
		let duplicate = seen.get(&hash).is_some_and(|bucket| {
			bucket
				.iter()
				.any(|&i| same_substitution(&out[i], &candidate))
		});
		if duplicate {
			continue;
		}
		seen.entry(hash).or_default().push(out.len());
		out.push(candidate);
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testutil::test_value_id;

	#[test]
	fn canonical_slots_ignore_existential_names_and_unused_bindings() {
		let slot = attacker_var_id(0);
		let tuple =
			|a: Value, b: Value| Value::primitive(crate::primitive::PRIM_CONCAT, vec![a, b], 0);
		let left = Substitution::from_iter([
			(slot, tuple(free_var(10), free_var(11))),
			(FREE_VAR_BASE + 11, free_var(10)),
			(FREE_VAR_BASE + 12, value_nil()),
		]);
		let right = Substitution::from_iter([(slot, tuple(free_var(20), free_var(20)))]);
		assert!(same_substitution(
			&canonical_slots(&left),
			&canonical_slots(&right)
		));
		let distinct = Substitution::from_iter([(slot, tuple(free_var(20), free_var(21)))]);
		assert!(!same_substitution(
			&canonical_slots(&left),
			&canonical_slots(&distinct)
		));
	}

	#[test]
	fn canonical_slots_preserve_shared_graphs() {
		let make = |id| {
			let mut term = free_var(id);
			for _ in 0..40 {
				term = Value::primitive(
					crate::primitive::PRIM_HASH,
					vec![term.clone(), term.clone(), term],
					0,
				);
			}
			Substitution::from_iter([(attacker_var_id(0), term)])
		};
		let left = canonical_slots(&make(10));
		let right = canonical_slots(&make(100));
		assert!(same_substitution(&left, &right));
		assert_eq!(
			crate::value::subterms(&left[&attacker_var_id(0)])
				.filter(|v| matches!(v, Value::Primitive(_)))
				.count(),
			40
		);
	}

	#[test]
	fn canonical_slots_preserve_sharing_between_receives() {
		let make = |first, second| {
			Substitution::from_iter([
				(attacker_var_id(0), free_var(first)),
				(attacker_var_id(1), free_var(second)),
			])
		};
		assert!(same_substitution(
			&canonical_slots(&make(10, 10)),
			&canonical_slots(&make(20, 20))
		));
		assert!(!same_substitution(
			&canonical_slots(&make(10, 10)),
			&canonical_slots(&make(20, 21))
		));
		let unbound_slot =
			Substitution::from_iter([(attacker_var_id(0), attacker_var(1, "unbound"))]);
		assert!(!same_substitution(
			&canonical_slots(&make(10, 10)),
			&canonical_slots(&unbound_slot)
		));
	}

	#[test]
	fn removing_local_bindings_preserves_the_remaining_choices() {
		let slot = attacker_var(0, "local_projection_slot");
		let first = free_var(0);
		let second = free_var(1);
		let kept = free_var(2);
		let atom = solver_constant("local_projection_atom");
		let term = Value::primitive(
			crate::primitive::PRIM_HASH,
			vec![first.clone(), kept.clone()],
			0,
		);
		let original = Substitution::from_iter([
			(as_var(&slot).unwrap(), term),
			(as_var(&first).unwrap(), second.clone()),
			(as_var(&second).unwrap(), atom),
		]);
		let removed = [as_var(&first).unwrap(), as_var(&second).unwrap()];
		let projected = remove_local_bindings(original.clone(), &removed);
		assert_eq!(projected.len(), 1);
		assert!(apply(&slot, &original).equivalent(&apply(&slot, &projected), true));
		assert!(occurs(
			as_var(&kept).unwrap(),
			&apply(&slot, &projected),
			&projected
		));
		assert_eq!(original.len(), 3);
	}
	#[test]
	fn variable_walks_visit_shared_terms_without_expanding_them() {
		let slot = attacker_var(0, "dag_slot");
		let free = free_var(0);
		let mut term = Value::primitive(
			crate::primitive::PRIM_HASH,
			vec![slot.clone(), free.clone()],
			0,
		);
		for _ in 0..40 {
			term = Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![term.clone(), term.clone(), term],
				0,
			);
		}
		let mut vars = Vec::new();
		collect_vars(&term, &mut vars);
		assert_eq!(vars, vec![as_var(&slot).unwrap(), as_var(&free).unwrap()]);
		let mut frees = Vec::new();
		collect_free_vars(&term, &mut frees);
		assert_eq!(frees, vec![as_var(&free).unwrap()]);
		let missing = attacker_var_id(1);
		let mut bindings = Substitution::default();
		assert!(!occurs(missing, &term, &bindings));
		bindings.insert(as_var(&free).unwrap(), attacker_var(1, "dag_missing"));
		assert!(occurs(missing, &term, &bindings));
		assert!(!occurs(attacker_var_id(2), &term, &bindings));
	}

	fn solver_constant(name: &str) -> Value {
		Value::Constant(Constant {
			name: std::sync::Arc::from(name),
			id: test_value_id(name),
			..Default::default()
		})
	}

	#[test]
	fn solver_var_ids_are_disjoint_from_interned_names() {
		let interned = test_value_id("solver_disjoint_a");
		assert!(interned < crate::solve::vars::ATTACKER_VAR_BASE);
		assert!(crate::solve::vars::is_var_id(
			crate::solve::vars::attacker_var_id(0)
		));
		assert!(!crate::solve::vars::is_var_id(interned));
	}

	#[test]
	fn a_free_variable_is_a_variable_but_not_a_slot() {
		let slot = crate::solve::vars::attacker_var_id(3);
		let free = crate::solve::vars::FREE_VAR_BASE + 3;
		assert!(is_var_id(slot) && is_var_id(free));
		assert!(is_slot_var_id(slot));
		assert!(
			!is_slot_var_id(free),
			"a free position is an attacker choice, not a wire slot: reading one as \
			 a slot index would install into slot {} of a state that may not have it",
			slot_of_var_id(free)
		);
		assert_eq!(slot_of_var_id(slot), 3);
	}

	#[test]
	fn solver_merge_unifies_partial_solutions() {
		let a = solver_constant("solver_merge_a");
		let b = solver_constant("solver_merge_b");
		let slot = crate::solve::vars::attacker_var_id(0);
		let concat = |x: Value, y: Value| {
			Value::Primitive(std::sync::Arc::new(Primitive {
				id: 2,
				arguments: vec![x, y],
				output: 0,
				instance_check: false,
				capabilities: Capabilities::default(),
				threshold: 0,
				hash: HashCell::default(),
			}))
		};

		let mut left = crate::solve::vars::Substitution::default();
		left.insert(slot, concat(a.clone(), crate::solve::vars::free_var(0)));
		let mut right = crate::solve::vars::Substitution::default();
		right.insert(slot, concat(crate::solve::vars::free_var(1), b.clone()));

		let merged = crate::solve::matching::merge(&left, &right).expect("should unify");
		let value = merged.get(&slot).expect("slot bound");
		assert!(value.equivalent(&concat(a, b), true));
	}

	#[test]
	fn solver_occurs_check_refuses_a_cyclic_binding() {
		let k = solver_constant("solver_occurs_k");
		let slot = crate::solve::vars::attacker_var_id(0);
		let var = crate::solve::vars::attacker_var(0, "occurs");
		let enc = |x: Value, y: Value| {
			Value::Primitive(std::sync::Arc::new(Primitive {
				id: crate::primitive::PRIM_ENC,
				arguments: vec![x, y],
				output: 0,
				instance_check: false,
				capabilities: Capabilities::default(),
				threshold: 0,
				hash: HashCell::default(),
			}))
		};

		let mut s = crate::solve::vars::Substitution::default();
		assert!(!bind(&mut s, slot, enc(k.clone(), var.clone())));
		assert!(s.is_empty());
		// The same binding without the self-reference is fine.
		assert!(bind(
			&mut s,
			slot,
			enc(k, solver_constant("solver_occurs_m"))
		));
	}

	#[test]
	fn solver_occurs_check_sees_through_a_chain() {
		// $0 -> HASH($1) and $1 -> $2 already bound, so binding $2 to anything
		// mentioning $0 closes a cycle two hops away.
		let a = crate::solve::vars::attacker_var_id(0);
		let b = crate::solve::vars::attacker_var_id(1);
		let c = crate::solve::vars::attacker_var_id(2);
		let hash = |x: Value| {
			Value::Primitive(std::sync::Arc::new(Primitive {
				id: crate::primitive::PRIM_HASH,
				arguments: vec![x],
				output: 0,
				instance_check: false,
				capabilities: Capabilities::default(),
				threshold: 0,
				hash: HashCell::default(),
			}))
		};

		let mut s = crate::solve::vars::Substitution::default();
		assert!(bind(
			&mut s,
			a,
			hash(crate::solve::vars::attacker_var(1, "b"))
		));
		assert!(bind(&mut s, b, crate::solve::vars::attacker_var(2, "c")));
		assert!(occurs(a, &crate::solve::vars::attacker_var(0, "a"), &s));
		assert!(!bind(
			&mut s,
			c,
			hash(crate::solve::vars::attacker_var(0, "a"))
		));
		assert!(bind(&mut s, c, hash(solver_constant("solver_chain_m"))));
		// With the cycle refused, applying the substitution terminates.
		let applied = crate::solve::vars::apply(&crate::solve::vars::attacker_var(0, "a"), &s);
		assert!(!crate::solve::vars::contains_var(&applied));
	}

	#[test]
	fn solver_free_positions_become_nil() {
		let free = crate::solve::vars::free_var(7);
		assert!(crate::solve::vars::is_free_var_id(
			crate::solve::vars::as_var(&free).expect("is a variable")
		));
		let grounded = crate::solve::vars::ground_free(&free);
		assert!(grounded.equivalent(&crate::value::value_nil(), true));
	}
}
