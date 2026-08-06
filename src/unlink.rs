/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::Arc;

use crate::theory::{can_recompose, can_reconstruct_primitive};
use crate::types::*;

pub(crate) fn depends_on_secret(v: &Value, ps: &PrincipalState) -> bool {
	let mut constants = Vec::new();
	v.collect_constants(&mut constants);
	constants.iter().any(|c| constant_is_secret(c, ps))
}

pub(crate) fn is_observable(c: &Constant, ps: &PrincipalState) -> bool {
	if c.leaked {
		return true;
	}
	ps.index_of(c)
		.is_some_and(|i| !ps.meta[i].wire.is_empty() || ps.meta[i].constant.leaked)
}

fn constant_is_secret(c: &Constant, ps: &PrincipalState) -> bool {
	if c.fresh || matches!(c.qualifier, Some(Qualifier::Private | Qualifier::Password)) {
		return true;
	}
	ps.index_of(c).is_some_and(|i| {
		let m = &ps.meta[i].constant;
		m.fresh || matches!(m.qualifier, Some(Qualifier::Private | Qualifier::Password))
	})
}

fn attacker_without(attacker: &AttackerState, v: &Value) -> AttackerState {
	let h = v.hash_value();
	let known: Vec<Value> = attacker
		.known
		.iter()
		.filter(|k| !(k.hash_value() == h && k.equivalent(v, true)))
		.cloned()
		.collect();
	let mut known_map: HashMap<u64, Vec<usize>> = HashMap::new();
	for (i, k) in known.iter().enumerate() {
		known_map.entry(k.hash_value()).or_default().push(i);
	}
	AttackerState {
		current_phase: attacker.current_phase,
		known: Arc::new(known),
		known_map: Arc::new(known_map),
		skeleton_hashes: attacker.skeleton_hashes.clone(),
		mutation_records: Arc::new(vec![]),
		derivations: Arc::new(vec![]),
	}
}

const MAX_LEAF_DEPTH: usize = 16;

pub(crate) fn origin_leaves(
	v: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<Vec<Value>> {
	let without_self = attacker_without(attacker, v);
	let mut out = Vec::new();
	collect_leaves(v, ps, &without_self, 0, &mut out).then_some(out)
}

fn collect_leaves(
	v: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	depth: usize,
	out: &mut Vec<Value>,
) -> bool {
	if depth > MAX_LEAF_DEPTH {
		return false;
	}
	let held = attacker.knows(v).is_some();
	if held {
		push_leaf(out, v);
	}
	let Value::Primitive(p) = v else {
		return held;
	};
	let used = can_reconstruct_primitive(p, ps, attacker, 0)
		.or_else(|| can_recompose(p, attacker).map(|r| r.used));
	let Some(used) = used else {
		return held;
	};
	for arg in &used {
		collect_leaves(arg, ps, attacker, depth + 1, out);
	}
	true
}

fn push_leaf(out: &mut Vec<Value>, v: &Value) {
	if !out.iter().any(|k| k.equivalent(v, true)) {
		out.push(v.clone());
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::PRIM_HASH;
	use crate::testutil::*;

	fn state_from(values: &[Value]) -> PrincipalState {
		let mut meta = Vec::new();
		let mut slots = Vec::new();
		for v in values {
			let Value::Constant(c) = v else {
				continue;
			};
			meta.push(make_slot_meta(c, false));
			slots.push(make_slot_values(v, 1));
		}
		make_principal_state("Tester", 1, meta, slots)
	}

	#[test]
	fn secret_dependence() {
		let pub_c = make_constant("ul_pub");
		let secret = make_password("ul_pw");
		let ps = state_from(&[pub_c.clone(), secret.clone()]);
		assert!(!depends_on_secret(&pub_c, &ps));
		assert!(depends_on_secret(&secret, &ps));

		let mixed = make_primitive(PRIM_HASH, vec![secret, pub_c.clone()], 0);
		assert!(depends_on_secret(&mixed, &ps));
		let neither = make_primitive(PRIM_HASH, vec![pub_c.clone(), pub_c], 0);
		assert!(!depends_on_secret(&neither, &ps));
	}

	#[test]
	fn origin_leaves_excludes_the_value_itself() {
		let seed = make_password("ul_seed");
		let label = make_constant("ul_label");
		let tok = make_primitive(PRIM_HASH, vec![seed.clone(), label.clone()], 0);
		let ps = state_from(&[seed.clone(), label.clone()]);

		let attacker = make_attacker_state(vec![tok.clone(), seed.clone(), label.clone()]);
		let leaves = origin_leaves(&tok, &ps, &attacker).expect("reconstructible");
		assert!(leaves.iter().any(|v| v.equivalent(&seed, true)));
		assert!(!leaves.iter().any(|v| v.equivalent(&tok, true)));

		let attacker = make_attacker_state(vec![tok.clone()]);
		assert!(origin_leaves(&tok, &ps, &attacker).is_none());
	}

	#[test]
	fn observability_keys_on_the_wire() {
		let travelled = make_constant("ul_wire");
		let ps = state_from(std::slice::from_ref(&travelled));
		let Value::Constant(c) = &travelled else {
			unreachable!()
		};
		assert!(is_observable(c, &ps));

		let Value::Constant(absent) = make_constant("ul_absent") else {
			unreachable!()
		};
		assert!(!is_observable(&absent, &ps));
	}
}
