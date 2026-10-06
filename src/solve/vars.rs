/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::types::*;
use crate::value::value_nil;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FreshVariables {
	scope: Arc<str>,
	next: Vec<u8>,
}

impl FreshVariables {
	pub(crate) fn new(scope: Arc<str>) -> Self {
		Self {
			scope,
			next: vec![b'0'],
		}
	}

	pub(crate) fn fresh(&mut self) -> VariableId {
		let serial = std::str::from_utf8(&self.next).expect("decimal identifier");
		let id = VariableId::Free(Arc::from(format!("{}/{serial}", self.scope)));
		for digit in self.next.iter_mut().rev() {
			if *digit < b'9' {
				*digit += 1;
				return id;
			}
			*digit = b'0';
		}
		self.next.insert(0, b'1');
		id
	}
}

pub(crate) fn is_free_var_id(id: &VariableId) -> bool {
	matches!(id, VariableId::Free(_))
}

pub(crate) fn free_var(n: usize) -> Value {
	Value::Variable(VariableId::Free(Arc::from(format!("root/{n}"))))
}

pub(crate) type Substitution = IdMap<VariableId, Value>;

pub(crate) fn attacker_var_id(slot: usize) -> VariableId {
	VariableId::Slot(slot)
}

pub(crate) fn is_slot_var_id(id: &VariableId) -> bool {
	matches!(id, VariableId::Slot(_))
}

pub(crate) fn slot_of_var_id(id: &VariableId) -> usize {
	let VariableId::Slot(slot) = id else {
		panic!("a wire slot variable")
	};
	*slot
}

pub(crate) fn attacker_var(slot: usize) -> Value {
	Value::Variable(attacker_var_id(slot))
}

pub(crate) fn as_var(v: &Value) -> Option<VariableId> {
	match v {
		Value::Variable(id) => Some(id.clone()),
		_ => None,
	}
}

pub(crate) fn contains_var(v: &Value) -> bool {
	match v {
		Value::Constant(_) => false,
		Value::Variable(_) => true,
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

pub(crate) fn collect_free_vars(v: &Value, out: &mut Vec<VariableId>) {
	collect_var_ids(v, out, is_free_var_id);
}

pub(crate) fn collect_vars(v: &Value, out: &mut Vec<VariableId>) {
	collect_var_ids(v, out, |_| true);
}

fn collect_var_ids(v: &Value, out: &mut Vec<VariableId>, include: fn(&VariableId) -> bool) {
	if !contains_var(v) {
		return;
	}
	for term in crate::value::subterms(v) {
		if let Value::Variable(id) = term
			&& include(id)
			&& !out.contains(id)
		{
			out.push(id.clone());
		}
	}
}

pub(crate) struct PointerMemo<T> {
	few: Vec<(usize, T)>,
	many: IdMap<usize, T>,
}

impl<T: Clone> PointerMemo<T> {
	pub(crate) fn new() -> Self {
		Self {
			few: Vec::new(),
			many: IdMap::default(),
		}
	}

	pub(crate) fn get(&self, key: usize) -> Option<T> {
		if self.many.is_empty() {
			return self
				.few
				.iter()
				.find(|(held, _)| *held == key)
				.map(|(_, value)| value.clone());
		}
		self.many.get(&key).cloned()
	}

	pub(crate) fn insert(&mut self, key: usize, value: T) {
		if self.many.is_empty() && self.few.len() < 32 {
			self.few.push((key, value));
			return;
		}
		self.many.extend(self.few.drain(..));
		self.many.insert(key, value);
	}
}

pub(crate) fn apply(v: &Value, s: &Substitution) -> Value {
	if s.is_empty() || !contains_var(v) {
		return v.clone();
	}
	apply_shared(v, s, &mut PointerMemo::new())
}

fn apply_shared(v: &Value, s: &Substitution, shared: &mut PointerMemo<Value>) -> Value {
	if !contains_var(v) {
		return v.clone();
	}
	match v {
		Value::Constant(_) => v.clone(),
		Value::Variable(id) => match s.get(id) {
			Some(bound) => apply_shared(bound, s, shared),
			None => v.clone(),
		},
		Value::Primitive(p) => {
			let key = Arc::as_ptr(p) as usize;
			if let Some(hit) = shared.get(key) {
				return hit;
			}
			let mut args: Option<Vec<Value>> = None;
			for (at, a) in p.arguments.iter().enumerate() {
				let applied = apply_shared(a, s, shared);
				let unchanged = match (&applied, a) {
					(Value::Primitive(x), Value::Primitive(y)) => Arc::ptr_eq(x, y),
					(Value::Constant(x), Value::Constant(y)) => x.id == y.id,
					(Value::Variable(x), Value::Variable(y)) => x == y,
					_ => false,
				};
				if let Some(args) = args.as_mut() {
					args.push(applied);
				} else if !unchanged {
					let mut changed = Vec::with_capacity(p.arguments.len());
					changed.extend(p.arguments[..at].iter().cloned());
					changed.push(applied);
					args = Some(changed);
				}
			}
			let out = match args {
				None => v.clone(),
				Some(args) => {
					let args = crate::primitive::normalise_arguments(p.id, args);
					Value::Primitive(Arc::new(p.with_arguments(args)))
				}
			};
			shared.insert(key, out.clone());
			out
		}
	}
}

pub(crate) fn occurs(id: &VariableId, v: &Value, s: &Substitution) -> bool {
	if !contains_var(v) {
		return false;
	}
	let mut variables = IdSet::default();
	let mut primitives = IdSet::default();
	let mut pending = vec![v];
	while let Some(term) = pending.pop() {
		match term {
			Value::Constant(_) => {}
			Value::Variable(variable) => {
				if variable == id {
					return true;
				}
				if let Some(bound) = s.get(variable)
					&& variables.insert(variable)
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

pub(crate) fn bind(s: &mut Substitution, id: VariableId, v: Value) -> bool {
	match s.get(&id) {
		Some(existing) => existing.equivalent(&v, true),
		None => {
			if occurs(&id, &v, s) {
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
	if !contains_var(v) {
		return v.clone();
	}
	match v {
		Value::Constant(_) => v.clone(),
		Value::Variable(id) => {
			if is_free_var_id(id) {
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

pub(crate) fn remove_local_bindings(mut s: Substitution, ids: &[VariableId]) -> Substitution {
	let local: Substitution = ids
		.iter()
		.filter_map(|id| s.remove(id).map(|value| (id.clone(), value)))
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
		names: &mut IdMap<VariableId, Value>,
		shared: &mut IdMap<usize, Value>,
	) -> Value {
		if !contains_var(v) {
			return v.clone();
		}
		match v {
			Value::Variable(id) if is_free_var_id(id) => {
				let next = names.len();
				names
					.entry(id.clone())
					.or_insert_with(|| free_var(next))
					.clone()
			}
			Value::Constant(_) | Value::Variable(_) => v.clone(),
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

	let mut slots: Vec<_> = s.keys().filter(|id| is_slot_var_id(id)).cloned().collect();
	slots.sort_unstable();
	let values: Vec<_> = slots.iter().map(|id| apply(&s[id], s)).collect();
	let mut names = IdMap::default();
	let mut shared = IdMap::default();
	slots
		.into_iter()
		.zip(values.iter().map(|v| rename(v, &mut names, &mut shared)))
		.collect()
}

pub(crate) fn dedupe_slots(candidates: Vec<Substitution>) -> Vec<Substitution> {
	let mut seen = Distinct::default();
	candidates
		.into_iter()
		.filter_map(|candidate| {
			let mut shared = PointerMemo::new();
			let slots = candidate
				.iter()
				.filter(|(id, _)| is_slot_var_id(id))
				.map(|(id, value)| (id.clone(), apply_shared(value, &candidate, &mut shared)))
				.collect();
			seen.insert(canonical_slots(&slots), ()).then_some(slots)
		})
		.collect()
}

pub(crate) fn substitution_hash(s: &Substitution) -> u64 {
	let mut acc: u64 = s.len() as u64;
	for (id, v) in s {
		let mut hash = IdHasher::default();
		id.hash(&mut hash);
		let mut entry = hash
			.finish()
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

pub(crate) struct Distinct<T> {
	items: Vec<(Substitution, T)>,
	index: IdMap<(u64, T), Vec<usize>>,
}

impl<T> Default for Distinct<T> {
	fn default() -> Self {
		Distinct {
			items: Vec::new(),
			index: IdMap::default(),
		}
	}
}

impl<T: Copy + Eq + std::hash::Hash> Distinct<T> {
	pub(crate) fn insert(&mut self, s: Substitution, tag: T) -> bool {
		let bucket = self.index.entry((substitution_hash(&s), tag)).or_default();
		if bucket
			.iter()
			.any(|&at| same_substitution(&self.items[at].0, &s))
		{
			return false;
		}
		bucket.push(self.items.len());
		self.items.push((s, tag));
		true
	}

	pub(crate) fn into_items(self) -> Vec<(Substitution, T)> {
		self.items
	}
}

pub(crate) fn dedupe(candidates: Vec<Substitution>) -> Vec<Substitution> {
	let mut distinct = Distinct::default();
	for candidate in candidates {
		distinct.insert(candidate, ());
	}
	distinct.items.into_iter().map(|(s, ())| s).collect()
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
			(slot.clone(), tuple(free_var(10), free_var(11))),
			(as_var(&free_var(11)).unwrap(), free_var(10)),
			(as_var(&free_var(12)).unwrap(), value_nil()),
		]);
		let right = Substitution::from_iter([(slot.clone(), tuple(free_var(20), free_var(20)))]);
		assert!(same_substitution(
			&canonical_slots(&left),
			&canonical_slots(&right)
		));
		let distinct = Substitution::from_iter([(slot.clone(), tuple(free_var(20), free_var(21)))]);
		assert!(!same_substitution(
			&canonical_slots(&left),
			&canonical_slots(&distinct)
		));
	}

	#[test]
	fn grounding_reuses_ground_subgraphs_between_proposals() {
		let mut ground = value_nil();
		for _ in 0..40 {
			ground = Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![ground.clone(), ground.clone(), ground],
				0,
			);
		}
		let template = Value::primitive(
			crate::primitive::PRIM_HASH,
			vec![ground.clone(), free_var(0), attacker_var(0)],
			0,
		);
		for filler in [value_nil(), crate::primitive::attacker_public_key()] {
			let instantiated = ground_free_as(&template, &filler);
			let args = &instantiated.as_primitive().unwrap().arguments;
			let (Value::Primitive(original), Value::Primitive(retained)) = (&ground, &args[0])
			else {
				panic!("the transcript is a primitive");
			};
			assert!(Arc::ptr_eq(original, retained));
			assert!(args[1].equivalent(&filler, true));
			assert_eq!(as_var(&args[2]), Some(attacker_var_id(0)));
			assert!(crate::theory::structurally_identical(
				&ground_free_as(&ground, &filler),
				&ground
			));
		}
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
		let unbound_slot = Substitution::from_iter([(attacker_var_id(0), attacker_var(1))]);
		assert!(!same_substitution(
			&canonical_slots(&make(10, 10)),
			&canonical_slots(&unbound_slot)
		));
	}

	#[test]
	fn removing_local_bindings_preserves_the_remaining_choices() {
		let slot = attacker_var(0);
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
			&as_var(&kept).unwrap(),
			&apply(&slot, &projected),
			&projected
		));
		assert_eq!(original.len(), 3);
	}
	#[test]
	fn variable_walks_visit_shared_terms_without_expanding_them() {
		let slot = attacker_var(0);
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
		assert!(!occurs(&missing, &term, &bindings));
		bindings.insert(as_var(&free).unwrap(), attacker_var(1));
		assert!(occurs(&missing, &term, &bindings));
		assert!(!occurs(&attacker_var_id(2), &term, &bindings));
	}

	fn solver_constant(name: &str) -> Value {
		Value::Constant(Constant {
			name: std::sync::Arc::from(name),
			id: test_value_id(name),
			..Default::default()
		})
	}

	#[test]
	fn variables_never_alias_constants_or_slots() {
		let slot = attacker_var(3);
		let free = free_var(3);
		let constant = Value::Constant(Constant {
			id: u32::MAX,
			name: Arc::from("root/3"),
			..Default::default()
		});
		for (a, b) in [(&slot, &free), (&slot, &constant), (&free, &constant)] {
			assert!(!a.same_term(b));
			assert!(!a.equivalent(b, true));
		}
		assert!(is_slot_var_id(&as_var(&slot).unwrap()));
		assert!(is_free_var_id(&as_var(&free).unwrap()));
		assert_eq!(slot_of_var_id(&as_var(&slot).unwrap()), 3);
		assert!(!contains_var(&constant));
	}

	#[test]
	fn fresh_identifiers_grow_past_machine_integer_sizes() {
		for width in [1, 10, 20, 40, 100] {
			let mut variables = FreshVariables {
				scope: Arc::from("rollover"),
				next: vec![b'9'; width],
			};
			let before = Value::Variable(variables.fresh());
			let after = Value::Variable(variables.fresh());
			let following = Value::Variable(variables.fresh());
			assert_eq!(
				after.to_string(),
				format!("$freerollover/1{}", "0".repeat(width))
			);
			assert!(!before.equivalent(&after, true));
			assert!(!after.equivalent(&following, true));
			let mut binding = Substitution::default();
			assert!(bind(&mut binding, as_var(&before).unwrap(), value_nil()));
			assert!(contains_var(&apply(&after, &binding)));
			assert!(contains_var(&apply(&following, &binding)));
		}
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
				instance: 0,
				instance_check: false,
				capabilities: Capabilities::default(),
				threshold: 0,
				hash: HashCell::default(),
			}))
		};

		let mut left = crate::solve::vars::Substitution::default();
		left.insert(
			slot.clone(),
			concat(a.clone(), crate::solve::vars::free_var(0)),
		);
		let mut right = crate::solve::vars::Substitution::default();
		right.insert(
			slot.clone(),
			concat(crate::solve::vars::free_var(1), b.clone()),
		);

		let merged = crate::solve::matching::merge(&left, &right)
			.next()
			.expect("should unify");
		let value = merged.get(&slot).expect("slot bound");
		assert!(value.equivalent(&concat(a, b), true));
	}

	#[test]
	fn solver_occurs_check_refuses_a_cyclic_binding() {
		let k = solver_constant("solver_occurs_k");
		let slot = crate::solve::vars::attacker_var_id(0);
		let var = crate::solve::vars::attacker_var(0);
		let enc = |x: Value, y: Value| {
			Value::Primitive(std::sync::Arc::new(Primitive {
				id: crate::primitive::PRIM_ENC,
				arguments: vec![x, y],
				output: 0,
				instance: 0,
				instance_check: false,
				capabilities: Capabilities::default(),
				threshold: 0,
				hash: HashCell::default(),
			}))
		};

		let mut s = crate::solve::vars::Substitution::default();
		assert!(!bind(&mut s, slot.clone(), enc(k.clone(), var.clone())));
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
				instance: 0,
				instance_check: false,
				capabilities: Capabilities::default(),
				threshold: 0,
				hash: HashCell::default(),
			}))
		};

		let mut s = crate::solve::vars::Substitution::default();
		assert!(bind(
			&mut s,
			a.clone(),
			hash(crate::solve::vars::attacker_var(1))
		));
		assert!(bind(&mut s, b, crate::solve::vars::attacker_var(2)));
		assert!(occurs(&a, &crate::solve::vars::attacker_var(0), &s));
		assert!(!bind(
			&mut s,
			c.clone(),
			hash(crate::solve::vars::attacker_var(0))
		));
		assert!(bind(&mut s, c, hash(solver_constant("solver_chain_m"))));
		// With the cycle refused, applying the substitution terminates.
		let applied = crate::solve::vars::apply(&crate::solve::vars::attacker_var(0), &s);
		assert!(!crate::solve::vars::contains_var(&applied));
	}

	#[test]
	fn solver_free_positions_become_nil() {
		let free = crate::solve::vars::free_var(7);
		assert!(crate::solve::vars::is_free_var_id(
			&crate::solve::vars::as_var(&free).expect("is a variable")
		));
		let grounded = crate::solve::vars::ground_free(&free);
		assert!(grounded.equivalent(&crate::value::value_nil(), true));
	}
}
