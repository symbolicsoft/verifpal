/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::types::*;
use crate::value::*;
use crate::primitive::*;

const MAX_POSSIBLE_DEPTH: usize = 16;

pub fn possible_to_passively_decompose_primitive(p: &Primitive) -> Vec<Value> {
    if primitive_is_core(p.id) { return vec![]; }
    let prim = match primitive_get(p.id) { Ok(s) => s, Err(_) => return vec![] };
    if !prim.decompose.has_rule { return vec![]; }
    prim.decompose.passive_reveal.iter()
        .filter_map(|&i| p.arguments.get(i).cloned())
        .collect()
}

pub fn possible_to_decompose_primitive(
    p: &Primitive, ps: &PrincipalState, as_: &AttackerState, depth: usize,
) -> (bool, Value, Vec<Value>) {
    let empty = value_nil();
    if depth > MAX_POSSIBLE_DEPTH { return (false, empty, vec![]); }
    if primitive_is_core(p.id) { return (false, empty, vec![]); }
    let prim = match primitive_get(p.id) { Ok(s) => s, Err(_) => return (false, empty, vec![]) };
    if !prim.decompose.has_rule { return (false, empty, vec![]); }
    let filter_fn = match prim.decompose.filter { Some(f) => f, None => return (false, empty, vec![]) };
    let mut has = Vec::new();
    for (filter_i, &idx) in prim.decompose.given.iter().enumerate() {
        if idx >= p.arguments.len() { continue; }
        let a = &p.arguments[idx];
        let (filtered, valid) = filter_fn(p, a, filter_i);
        if !valid { continue; }
        if value_equivalent_value_in_values_map(&filtered, &as_.known, &as_.known_map) >= 0 {
            has.push(filtered);
            continue;
        }
        match &filtered {
            Value::Primitive(inner_p) => {
                let (r, _) = possible_to_reconstruct_primitive(inner_p, ps, as_, depth + 1);
                if r { has.push(filtered.clone()); continue; }
                let (r2, _, _) = possible_to_decompose_primitive(inner_p, ps, as_, depth + 1);
                if r2 { has.push(filtered.clone()); }
            }
            Value::Equation(inner_e) => {
                let (r, _) = possible_to_reconstruct_equation(inner_e, as_);
                if r { has.push(filtered.clone()); }
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

pub fn possible_to_recompose_primitive(
    p: &Primitive, as_: &AttackerState,
) -> (bool, Value, Vec<Value>) {
    let empty = value_nil();
    if primitive_is_core(p.id) { return (false, empty, vec![]); }
    let prim = match primitive_get(p.id) { Ok(s) => s, Err(_) => return (false, empty, vec![]) };
    if !prim.recompose.has_rule { return (false, empty, vec![]); }
    for given_set in &prim.recompose.given {
        let mut ar = Vec::new();
        for &ii in given_set {
            for v in as_.known.iter() {
                if let Value::Primitive(vp) = v {
                    let (equiv, vo, _) = value_equivalent_primitives(vp, p, false);
                    if !equiv || vo != ii { continue; }
                    ar.push(v.clone());
                    if ar.len() < given_set.len() { continue; }
                    return (true, p.arguments[prim.recompose.reveal].clone(), ar);
                }
            }
        }
    }
    (false, empty, vec![])
}

pub fn possible_to_reconstruct_primitive(
    p: &Primitive, ps: &PrincipalState, as_: &AttackerState, depth: usize,
) -> (bool, Vec<Value>) {
    if depth > MAX_POSSIBLE_DEPTH { return (false, vec![]); }
    let (r, rv) = possible_to_rewrite(p, ps, 0);
    if !r { return (false, vec![]); }
    let rp = match &rv[0] { Value::Primitive(p) => p, _ => return (false, vec![]) };
    let mut has = Vec::new();
    for a in &rp.arguments {
        if value_equivalent_value_in_values_map(a, &as_.known, &as_.known_map) >= 0 {
            has.push(a.clone());
            continue;
        }
        match a {
            Value::Primitive(inner_p) => {
                let (r2, _, _) = possible_to_decompose_primitive(inner_p, ps, as_, depth + 1);
                if r2 { has.push(a.clone()); continue; }
                let (r3, _) = possible_to_reconstruct_primitive(inner_p, ps, as_, depth + 1);
                if r3 { has.push(a.clone()); continue; }
            }
            Value::Equation(inner_e) => {
                let (r2, _) = possible_to_reconstruct_equation(inner_e, as_);
                if r2 { has.push(a.clone()); continue; }
            }
            _ => {}
        }
    }
    if has.len() < rp.arguments.len() { return (false, vec![]); }
    (true, has)
}

pub fn possible_to_reconstruct_equation(e: &Equation, as_: &AttackerState) -> (bool, Vec<Value>) {
    if e.values.len() < 2 { return (false, vec![]); }
    if e.values.len() == 2 {
        if value_equivalent_value_in_values_map(&e.values[1], &as_.known, &as_.known_map) >= 0 {
            return (true, vec![e.values[1].clone()]);
        }
        return (false, vec![]);
    }
    let s0 = &e.values[1];
    let s1 = &e.values[2];
    let hs0 = value_equivalent_value_in_values_map(s0, &as_.known, &as_.known_map) >= 0;
    let hs1 = value_equivalent_value_in_values_map(s1, &as_.known, &as_.known_map) >= 0;
    if hs0 && hs1 { return (true, vec![s0.clone(), s1.clone()]); }
    let p0 = Value::Equation(Arc::new(Equation { values: vec![e.values[0].clone(), e.values[1].clone()] }));
    let p1 = Value::Equation(Arc::new(Equation { values: vec![e.values[0].clone(), e.values[2].clone()] }));
    let hp1 = value_equivalent_value_in_values_map(&p1, &as_.known, &as_.known_map) >= 0;
    if hs0 && hp1 { return (true, vec![s0.clone(), p1]); }
    let hp0 = value_equivalent_value_in_values_map(&p0, &as_.known, &as_.known_map) >= 0;
    if hp0 && hs1 { return (true, vec![p0, s1.clone()]); }
    (false, vec![])
}

pub fn possible_to_rewrite(
    p: &Primitive, ps: &PrincipalState, depth: usize,
) -> (bool, Vec<Value>) {
    if depth > MAX_POSSIBLE_DEPTH {
        return (false, vec![Value::Primitive(Arc::new(p.clone()))]);
    }
    // COW: only clone arguments if a child rewrite actually changed something
    let mut new_args: Option<Vec<Value>> = None;
    for (i, a) in p.arguments.iter().enumerate() {
        if let Value::Primitive(inner_p) = a {
            let (_, pp) = possible_to_rewrite(inner_p, ps, depth + 1);
            if !value_equivalent_values(&pp[0], a, true) {
                let args = new_args.get_or_insert_with(|| p.arguments.clone());
                args[i] = pp[0].clone();
            }
        }
    }
    // pc_ref points to either the original or the modified primitive
    let pc_owned: Primitive;
    let pc_ref: &Primitive;
    if let Some(args) = new_args {
        pc_owned = Primitive { id: p.id, arguments: args, output: p.output, check: p.check };
        pc_ref = &pc_owned;
    } else {
        pc_ref = p;
    }
    let wrap = |pr: &Primitive| vec![Value::Primitive(Arc::new(pr.clone()))];
    if primitive_is_core(pc_ref.id) {
        let prim = match primitive_core_get(pc_ref.id) { Ok(s) => s, Err(_) => return (false, wrap(pc_ref)) };
        if prim.has_rule {
            if let Some(rule) = prim.core_rule {
                return rule(pc_ref);
            }
        }
        return (!prim.check, wrap(pc_ref));
    }
    let prim = match primitive_get(pc_ref.id) { Ok(s) => s, Err(_) => return (false, wrap(pc_ref)) };
    if !prim.rewrite.has_rule { return (true, wrap(pc_ref)); }
    let from = &pc_ref.arguments[prim.rewrite.from];
    if let Value::Primitive(from_p) = from {
        if from_p.id != prim.rewrite.id {
            return (!prim.check, wrap(pc_ref));
        }
        if !possible_to_rewrite_primitive(pc_ref, ps, depth) {
            return (!prim.check, wrap(pc_ref));
        }
        if let Some(to_fn) = prim.rewrite.to {
            let rewrite = to_fn(from_p);
            return (true, vec![rewrite]);
        }
    }
    (!prim.check, wrap(pc_ref))
}

fn possible_to_rewrite_primitive(p: &Primitive, ps: &PrincipalState, depth: usize) -> bool {
    let prim = match primitive_get(p.id) { Ok(s) => s, Err(_) => return false };
    let from = &p.arguments[prim.rewrite.from];
    let from_p = match from { Value::Primitive(p) => p, _ => return false };
    let filter_fn = match prim.rewrite.filter { Some(f) => f, None => return false };
    for &(a_idx, ref m_vec) in &prim.rewrite.matching {
        let mut valid = false;
        for &mm in m_vec {
            if a_idx >= p.arguments.len() || mm >= from_p.arguments.len() { continue; }
            let mut ax = [p.arguments[a_idx].clone(), from_p.arguments[mm].clone()];
            let (filtered, fvalid) = filter_fn(p, &ax[0], mm);
            if !fvalid { continue; }
            ax[0] = filtered;
            // Rewrite primitives in ax
            for j in 0..2 {
                match &ax[j].clone() {
                    Value::Primitive(inner_p) => {
                        let (r, v) = possible_to_rewrite(inner_p, ps, depth + 1);
                        if r { ax[j] = v[0].clone(); }
                    }
                    Value::Equation(inner_e) => {
                        let mut new_eq = Equation { values: inner_e.values.clone() };
                        for (ii, ev) in inner_e.values.iter().enumerate() {
                            if let Value::Primitive(ep) = ev {
                                let (r, v) = possible_to_rewrite(ep, ps, depth + 1);
                                if r { new_eq.values[ii] = v[0].clone(); }
                            }
                        }
                        ax[j] = Value::Equation(Arc::new(new_eq));
                    }
                    _ => {}
                }
            }
            valid = value_equivalent_values(&ax[0], &ax[1], true);
            if valid { break; }
        }
        if !valid { return false; }
    }
    true
}

pub fn possible_to_rebuild(p: &Primitive) -> (bool, Value) {
    let empty = value_nil();
    if primitive_is_core(p.id) { return (false, empty); }
    let prim = match primitive_get(p.id) { Ok(s) => s, Err(_) => return (false, empty) };
    if !prim.rebuild.has_rule { return (false, empty); }
    for g in &prim.rebuild.given {
        let mut has = Vec::new();
        for &gg in g {
            if gg >= p.arguments.len() { continue; }
            if let Value::Primitive(arg_p) = &p.arguments[gg] {
                if arg_p.id == prim.rebuild.id {
                    has.push(&p.arguments[gg]);
                }
            }
        }
        if has.len() < g.len() { continue; }
        // Check that all has entries are equivalent but with different outputs
        let mut all_ok = true;
        for has_p_idx in 1..has.len() {
            if let (Value::Primitive(h0), Value::Primitive(hp)) = (has[0], has[has_p_idx]) {
                let (equiv, o1, o2) = value_equivalent_primitives(h0, hp, false);
                if !equiv || o1 == o2 { all_ok = false; break; }
            } else {
                all_ok = false; break;
            }
        }
        if !all_ok { continue; }
        if let Value::Primitive(h0) = has[0] {
            return (true, h0.arguments[prim.rebuild.reveal].clone());
        }
    }
    (false, empty)
}

pub fn possible_to_obtain_passwords(
    a: &Value, a_parent: &Value, a_index: i32, ps: &PrincipalState,
) -> Vec<Value> {
    let mut passwords = Vec::new();
    match a {
        Value::Constant(c) => {
            let (aa, _) = value_resolve_constant(c, ps, true);
            if let Value::Constant(ac) = &aa {
                if ac.qualifier == TypesEnum::Password {
                    if a_index >= 0 {
                        if let Value::Primitive(parent_p) = a_parent {
                            if !primitive_is_core(parent_p.id) {
                                if let Ok(prim) = primitive_get(parent_p.id) {
                                    if prim.password_hashing.contains(&(a_index as usize)) {
                                        return passwords;
                                    }
                                }
                            }
                        }
                    }
                    passwords.push(aa);
                }
            }
        }
        Value::Primitive(p) => {
            let mut parent = a_parent;
            let parent_owned;
            if !primitive_is_core(p.id) {
                if let Ok(prim) = primitive_get(p.id) {
                    if a_index >= 0 && prim.password_hashing.contains(&(a_index as usize)) {
                        parent_owned = a.clone();
                        parent = &parent_owned;
                    }
                }
            }
            for (i, arg) in p.arguments.iter().enumerate() {
                passwords.extend(possible_to_obtain_passwords(arg, parent, i as i32, ps));
            }
        }
        Value::Equation(e) => {
            for v in &e.values {
                passwords.extend(possible_to_obtain_passwords(v, a, -1, ps));
            }
        }
    }
    passwords
}
