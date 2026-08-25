/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::types::*;
use crate::value::value_nil;

pub(crate) const ATTACKER_VAR_BASE: ValueId = 0x8000_0000;

pub(crate) const FREE_VAR_BASE: ValueId = 0xC000_0000;

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

pub(crate) fn is_attacker_var_id(id: ValueId) -> bool {
	id >= ATTACKER_VAR_BASE
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
		Value::Constant(c) if is_attacker_var_id(c.id) => Some(c.id),
		_ => None,
	}
}

pub(crate) fn contains_var(v: &Value) -> bool {
	match v {
		Value::Constant(c) => is_attacker_var_id(c.id),
		Value::Primitive(p) => p.arguments.iter().any(contains_var),
	}
}

pub(crate) fn collect_free_vars(v: &Value, out: &mut Vec<ValueId>) {
	match v {
		Value::Constant(c) => {
			if is_free_var_id(c.id) && !out.contains(&c.id) {
				out.push(c.id);
			}
		}
		Value::Primitive(p) => {
			for a in &p.arguments {
				collect_free_vars(a, out);
			}
		}
	}
}

pub(crate) fn collect_vars(v: &Value, out: &mut Vec<ValueId>) {
	match v {
		Value::Constant(c) => {
			if is_attacker_var_id(c.id) && !out.contains(&c.id) {
				out.push(c.id);
			}
		}
		Value::Primitive(p) => {
			for a in &p.arguments {
				collect_vars(a, out);
			}
		}
	}
}

/// Apply `s` throughout `v`, chasing a bound variable into its own binding.
///
/// That chase needs no bound because [`bind`] and `matching::unify_bind` both
/// refuse a binding whose variable occurs in what it is bound to, so the chain
/// of variables walked here is a DAG over finitely many variables. Descent into
/// arguments is structural. Break the occurs check and this is where it shows:
/// the chase never returns.
pub(crate) fn apply(v: &Value, s: &Substitution) -> Value {
	if s.is_empty() || !contains_var(v) {
		return v.clone();
	}
	match v {
		Value::Constant(c) => match s.get(&c.id) {
			Some(bound) => apply(bound, s),
			None => v.clone(),
		},
		Value::Primitive(p) => {
			let args: Vec<Value> = p.arguments.iter().map(|a| apply(a, s)).collect();
			let args = crate::primitive::normalise_arguments(p.id, args);
			Value::Primitive(Arc::new(p.with_arguments(args)))
		}
	}
}

pub(crate) fn occurs(id: ValueId, v: &Value, s: &Substitution) -> bool {
	let mut chasing = Vec::new();
	occurs_in(id, v, s, &mut chasing)
}

fn occurs_in(id: ValueId, v: &Value, s: &Substitution, chasing: &mut Vec<ValueId>) -> bool {
	match v {
		Value::Constant(c) => {
			if c.id == id {
				return true;
			}
			if !is_attacker_var_id(c.id) || chasing.contains(&c.id) {
				return false;
			}
			let Some(bound) = s.get(&c.id) else {
				return false;
			};
			chasing.push(c.id);
			let found = occurs_in(id, bound, s, chasing);
			chasing.pop();
			found
		}
		Value::Primitive(p) => p.arguments.iter().any(|a| occurs_in(id, a, s, chasing)),
	}
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

pub(crate) fn compose(a: &Substitution, b: &Substitution) -> Option<Substitution> {
	let mut out = a.clone();
	for (id, v) in b {
		if !bind(&mut out, *id, v.clone()) {
			return None;
		}
	}
	Some(out)
}

pub(crate) fn ground_free(v: &Value) -> Value {
	ground_free_as(v, &value_nil())
}

pub(crate) fn ground_free_as(v: &Value, filler: &Value) -> Value {
	match v {
		Value::Constant(c) => {
			if is_free_var_id(c.id) {
				filler.clone()
			} else {
				v.clone()
			}
		}
		Value::Primitive(p) => {
			let args: Vec<Value> = p
				.arguments
				.iter()
				.map(|a| ground_free_as(a, filler))
				.collect();
			let args = crate::primitive::normalise_arguments(p.id, args);
			Value::Primitive(Arc::new(p.with_arguments(args)))
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

pub(crate) fn same_substitution(a: &Substitution, b: &Substitution) -> bool {
	a.len() == b.len()
		&& a.iter().all(|(id, v)| match b.get(id) {
			Some(other) => v.equivalent(other, true),
			None => false,
		})
}

fn substitution_hash(s: &Substitution) -> u64 {
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
		assert!(crate::solve::vars::is_attacker_var_id(
			crate::solve::vars::attacker_var_id(0)
		));
		assert!(!crate::solve::vars::is_attacker_var_id(interned));
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
