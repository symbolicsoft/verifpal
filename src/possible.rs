/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::primitive::*;
use crate::types::*;
use crate::value::*;

const MAX_POSSIBLE_DEPTH: usize = 16;

pub(crate) fn passively_decompose(p: &Primitive) -> Vec<Value> {
	if primitive_is_core(p.id) {
		return vec![];
	}
	let Ok(prim) = primitive_get(p.id) else {
		return vec![];
	};
	if !prim.decompose.has_rule {
		return vec![];
	}
	prim.decompose
		.passive_reveal
		.iter()
		.filter_map(|&i| p.arguments.get(i).cloned())
		.collect()
}

pub(crate) fn can_decompose(
	p: &Primitive,
	ps: &PrincipalState,
	attacker: &AttackerState,
	depth: usize,
) -> (bool, Value, Vec<Value>) {
	let empty = value_nil();
	if depth > MAX_POSSIBLE_DEPTH || primitive_is_core(p.id) {
		return (false, empty, vec![]);
	}
	let Ok(prim) = primitive_get(p.id) else {
		return (false, empty, vec![]);
	};
	if !prim.decompose.has_rule {
		return (false, empty, vec![]);
	}
	let Some(filter_fn) = prim.decompose.filter else {
		return (false, empty, vec![]);
	};
	let mut has = Vec::new();
	for (filter_i, &idx) in prim.decompose.given.iter().enumerate() {
		if idx >= p.arguments.len() {
			continue;
		}
		let a = &p.arguments[idx];
		let (filtered, valid) = filter_fn(p, a, filter_i);
		if !valid {
			continue;
		}
		if attacker.knows(&filtered).is_some() {
			has.push(filtered);
			continue;
		}
		match &filtered {
			Value::Primitive(inner_p) => {
				let (r, _) = can_reconstruct_primitive(inner_p, ps, attacker, depth + 1);
				if r {
					has.push(filtered.clone());
					continue;
				}
				let (r2, _, _) = can_decompose(inner_p, ps, attacker, depth + 1);
				if r2 {
					has.push(filtered.clone());
				}
			}
			Value::Equation(inner_e) => {
				let (r, _) = can_reconstruct_equation(inner_e, attacker);
				if r {
					has.push(filtered.clone());
				}
			}
			_ => {}
		}
	}
	if has.len() >= prim.decompose.given.len() {
		(true, p.arguments[prim.decompose.reveal].clone(), has)
	} else {
		(false, empty, has)
	}
}

pub(crate) fn can_recompose(
	p: &Primitive,
	attacker: &AttackerState,
) -> (bool, Value, Vec<Value>) {
	let empty = value_nil();
	if primitive_is_core(p.id) {
		return (false, empty, vec![]);
	}
	let Ok(prim) = primitive_get(p.id) else {
		return (false, empty, vec![]);
	};
	if !prim.recompose.has_rule {
		return (false, empty, vec![]);
	}
	for given_set in &prim.recompose.given {
		let mut candidates = Vec::new();
		for &output_idx in given_set {
			for known in attacker.known.iter() {
				if let Value::Primitive(known_prim) = known {
					let pm = value_equivalent_primitives(known_prim, p, false);
					if !pm.equivalent || pm.output_left != output_idx {
						continue;
					}
					candidates.push(known.clone());
					if candidates.len() < given_set.len() {
						continue;
					}
					return (true, p.arguments[prim.recompose.reveal].clone(), candidates);
				}
			}
		}
	}
	(false, empty, vec![])
}

pub(crate) fn can_reconstruct_primitive(
	p: &Primitive,
	ps: &PrincipalState,
	attacker: &AttackerState,
	depth: usize,
) -> (bool, Vec<Value>) {
	if depth > MAX_POSSIBLE_DEPTH {
		return (false, vec![]);
	}
	let (rewritten, rewrite_values) = can_rewrite(p, ps, 0);
	if !rewritten {
		return (false, vec![]);
	}
	let Value::Primitive(rewritten_prim) = &rewrite_values[0] else {
		return (false, vec![]);
	};
	let mut has = Vec::new();
	for a in &rewritten_prim.arguments {
		if attacker.knows(a).is_some() {
			has.push(a.clone());
			continue;
		}
		match a {
			Value::Primitive(inner_p) => {
				let (r2, _, _) = can_decompose(inner_p, ps, attacker, depth + 1);
				if r2 {
					has.push(a.clone());
					continue;
				}
				let (r3, _) = can_reconstruct_primitive(inner_p, ps, attacker, depth + 1);
				if r3 {
					has.push(a.clone());
					continue;
				}
			}
			Value::Equation(inner_e) => {
				let (r2, _) = can_reconstruct_equation(inner_e, attacker);
				if r2 {
					has.push(a.clone());
					continue;
				}
			}
			_ => {}
		}
	}
	if has.len() < rewritten_prim.arguments.len() {
		return (false, vec![]);
	}
	(true, has)
}

pub(crate) fn can_reconstruct_equation(e: &Equation, attacker: &AttackerState) -> (bool, Vec<Value>) {
	if e.values.len() < 2 {
		return (false, vec![]);
	}
	if e.values.len() == 2 {
		if attacker.knows(&e.values[1]).is_some() {
			return (true, vec![e.values[1].clone()]);
		}
		return (false, vec![]);
	}
	let s0 = &e.values[1];
	let s1 = &e.values[2];
	let hs0 = attacker.knows(s0).is_some();
	let hs1 = attacker.knows(s1).is_some();
	if hs0 && hs1 {
		return (true, vec![s0.clone(), s1.clone()]);
	}
	let p0 = Value::Equation(Arc::new(Equation {
		values: vec![e.values[0].clone(), e.values[1].clone()],
	}));
	let p1 = Value::Equation(Arc::new(Equation {
		values: vec![e.values[0].clone(), e.values[2].clone()],
	}));
	let hp1 = attacker.knows(&p1).is_some();
	if hs0 && hp1 {
		return (true, vec![s0.clone(), p1]);
	}
	let hp0 = attacker.knows(&p0).is_some();
	if hp0 && hs1 {
		return (true, vec![p0, s1.clone()]);
	}
	(false, vec![])
}

pub(crate) fn can_rewrite(p: &Primitive, ps: &PrincipalState, depth: usize) -> (bool, Vec<Value>) {
	if depth > MAX_POSSIBLE_DEPTH {
		return (false, vec![Value::Primitive(Arc::new(p.clone()))]);
	}
	// COW: only clone arguments if a child rewrite actually changed something
	let mut new_args: Option<Vec<Value>> = None;
	for (i, a) in p.arguments.iter().enumerate() {
		if let Value::Primitive(inner_p) = a {
			let (_, pp) = can_rewrite(inner_p, ps, depth + 1);
			if !pp[0].equivalent(a, true) {
				let args = new_args.get_or_insert_with(|| p.arguments.clone());
				args[i] = pp[0].clone();
			}
		}
	}
	// pc_ref points to either the original or the modified primitive
	let pc_owned: Primitive;
	let pc_ref: &Primitive;
	if let Some(args) = new_args {
		pc_owned = p.with_arguments(args);
		pc_ref = &pc_owned;
	} else {
		pc_ref = p;
	}
	let wrap = |pr: &Primitive| vec![Value::Primitive(Arc::new(pr.clone()))];
	if primitive_is_core(pc_ref.id) {
		let prim = match primitive_core_get(pc_ref.id) {
			Ok(s) => s,
			Err(_) => return (false, wrap(pc_ref)),
		};
		if prim.has_rule {
			if let Some(rule) = prim.core_rule {
				return rule(pc_ref);
			}
		}
		return (!prim.definition_check, wrap(pc_ref));
	}
	let prim = match primitive_get(pc_ref.id) {
		Ok(s) => s,
		Err(_) => return (false, wrap(pc_ref)),
	};
	if !prim.rewrite.has_rule {
		return (true, wrap(pc_ref));
	}
	let from = &pc_ref.arguments[prim.rewrite.from];
	if let Value::Primitive(from_p) = from {
		if from_p.id != prim.rewrite.id {
			return (!prim.definition_check, wrap(pc_ref));
		}
		if !can_rewrite_primitive(pc_ref, ps, depth) {
			return (!prim.definition_check, wrap(pc_ref));
		}
		if let Some(to_fn) = prim.rewrite.to {
			let rewrite = to_fn(from_p);
			return (true, vec![rewrite]);
		}
	}
	(!prim.definition_check, wrap(pc_ref))
}

fn can_rewrite_primitive(p: &Primitive, ps: &PrincipalState, depth: usize) -> bool {
	let Ok(prim) = primitive_get(p.id) else {
		return false;
	};
	let from = &p.arguments[prim.rewrite.from];
	let Value::Primitive(from_p) = from else {
		return false;
	};
	let Some(filter_fn) = prim.rewrite.filter else {
		return false;
	};
	for &(a_idx, ref m_vec) in &prim.rewrite.matching {
		let mut valid = false;
		for &mm in m_vec {
			if a_idx >= p.arguments.len() || mm >= from_p.arguments.len() {
				continue;
			}
			let mut ax = [p.arguments[a_idx].clone(), from_p.arguments[mm].clone()];
			let (filtered, fvalid) = filter_fn(p, &ax[0], mm);
			if !fvalid {
				continue;
			}
			ax[0] = filtered;
			// Rewrite primitives in ax
			for item in &mut ax {
				let replacement = match &*item {
					Value::Primitive(inner_p) => {
						let (r, v) = can_rewrite(inner_p, ps, depth + 1);
						if r { v.into_iter().next() } else { None }
					}
					Value::Equation(inner_e) => {
						let mut new_values: Option<Vec<Value>> = None;
						for (ii, ev) in inner_e.values.iter().enumerate() {
							if let Value::Primitive(ep) = ev {
								let (r, v) = can_rewrite(ep, ps, depth + 1);
								if r {
									let vals =
										new_values.get_or_insert_with(|| inner_e.values.clone());
									vals[ii] = v[0].clone();
								}
							}
						}
						new_values.map(|vals| Value::Equation(Arc::new(Equation { values: vals })))
					}
					_ => None,
				};
				if let Some(new_val) = replacement {
					*item = new_val;
				}
			}
			valid = ax[0].equivalent(&ax[1], true);
			if valid {
				break;
			}
		}
		if !valid {
			return false;
		}
	}
	true
}

pub(crate) fn can_rebuild(p: &Primitive) -> (bool, Value) {
	let empty = value_nil();
	if primitive_is_core(p.id) {
		return (false, empty);
	}
	let Ok(prim) = primitive_get(p.id) else {
		return (false, empty);
	};
	if !prim.rebuild.has_rule {
		return (false, empty);
	}
	for given_set in &prim.rebuild.given {
		let mut has = Vec::new();
		for &arg_idx in given_set {
			if arg_idx >= p.arguments.len() {
				continue;
			}
			if let Value::Primitive(arg_p) = &p.arguments[arg_idx] {
				if arg_p.id == prim.rebuild.id {
					has.push(&p.arguments[arg_idx]);
				}
			}
		}
		if has.len() < given_set.len() {
			continue;
		}
		// Check that all has entries are equivalent but with different outputs
		let all_ok = has[1..].iter().all(|has_p| {
			if let (Value::Primitive(h0), Value::Primitive(hp)) = (has[0], has_p) {
				let pm = value_equivalent_primitives(h0, hp, false);
				pm.equivalent && pm.output_left != pm.output_right
			} else {
				false
			}
		});
		if !all_ok {
			continue;
		}
		if let Value::Primitive(h0) = has[0] {
			return (true, h0.arguments[prim.rebuild.reveal].clone());
		}
	}
	(false, empty)
}

pub(crate) fn find_obtainable_passwords(
	a: &Value,
	a_parent: &Value,
	a_index: Option<usize>,
	ps: &PrincipalState,
	out: &mut Vec<Value>,
) {
	match a {
		Value::Constant(c) => {
			let (resolved, _) = ps.resolve_constant(c, true);
			let is_password =
				matches!(&resolved, Value::Constant(rc) if rc.qualifier == Some(Qualifier::Password));
			if is_password {
				let is_hashed = a_index.is_some_and(|idx| {
					matches!(a_parent, Value::Primitive(pp) if !primitive_is_core(pp.id)
						&& primitive_get(pp.id).is_ok_and(|prim| prim.password_hashing.contains(&idx)))
				});
				if !is_hashed {
					out.push(resolved);
				}
			}
		}
		Value::Primitive(p) => {
			let is_hashing = !primitive_is_core(p.id)
				&& a_index.is_some_and(|idx| {
					primitive_get(p.id).is_ok_and(|prim| prim.password_hashing.contains(&idx))
				});
			let parent_owned;
			let parent = if is_hashing {
				parent_owned = a.clone();
				&parent_owned
			} else {
				a_parent
			};
			for (i, arg) in p.arguments.iter().enumerate() {
				find_obtainable_passwords(arg, parent, Some(i), ps, out);
			}
		}
		Value::Equation(e) => {
			for v in &e.values {
				find_obtainable_passwords(v, a, None, ps, out);
			}
		}
	}
}
