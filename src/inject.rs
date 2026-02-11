/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::types::*;
use crate::value::*;
use crate::primitive::*;
use crate::verifyresults::verify_results_all_resolved;
use crate::attackerstate::attacker_state_put_write;
use crate::info::info_message;
use crate::pretty::*;

const MAX_INJECTIONS_PER_PRIMITIVE: usize = 500;
const STAGE_RECURSIVE_INJECTION: i32 = 5;

pub fn inject(
    p: &Primitive, inject_depth: usize,
    ps: &PrincipalState, as_: &AttackerState, stage: i32,
) -> Vec<Value> {
    if verify_results_all_resolved() { return vec![]; }
    inject_primitive(p, ps, as_, inject_depth, stage)
}

fn inject_value_rules(k: &Value, arg: usize, p: &Primitive, stage: i32) -> bool {
    match k {
        Value::Constant(c) => inject_constant_rules(c, arg, p),
        Value::Primitive(kp) => inject_primitive_rules(kp, arg, p, stage),
        Value::Equation(e) => inject_equation_rules(e, arg, p),
    }
}

fn inject_constant_rules(c: &Constant, arg: usize, p: &Primitive) -> bool {
    if !matches!(&p.arguments[arg], Value::Constant(_)) { return false; }
    if value_equivalent_constants(c, value_g().as_constant().expect("g is Constant")) { return false; }
    true
}

fn inject_primitive_rules(k: &Primitive, arg: usize, p: &Primitive, stage: i32) -> bool {
    if !matches!(&p.arguments[arg], Value::Primitive(_)) { return false; }
    if inject_primitive_stage_restricted(k, stage) { return false; }
    if let Value::Primitive(ref_p) = &p.arguments[arg] {
        inject_skeleton_equivalent(k, ref_p)
    } else {
        false
    }
}

fn inject_equation_rules(e: &Equation, arg: usize, p: &Primitive) -> bool {
    match &p.arguments[arg] {
        Value::Equation(pe) => e.values.len() == pe.values.len(),
        _ => false,
    }
}

fn inject_primitive_stage_restricted(p: &Primitive, stage: i32) -> bool {
    match stage {
        0 | 1 => true,
        2 => {
            if primitive_is_core(p.id) {
                primitive_core_get(p.id).map(|s| s.explosive).unwrap_or(false)
            } else {
                primitive_get(p.id).map(|s| s.explosive).unwrap_or(false)
            }
        }
        _ => false,
    }
}

fn inject_primitive_skeleton(p: &Primitive, depth: usize) -> (Primitive, usize) {
    let mut skeleton = Primitive {
        id: p.id,
        arguments: Vec::with_capacity(p.arguments.len()),
        output: p.output,
        check: false,
    };
    let mut d = depth;
    for a in &p.arguments {
        match a {
            Value::Constant(_) => skeleton.arguments.push(value_nil()),
            Value::Primitive(pp) => {
                let (child, new_d) = inject_primitive_skeleton(pp, d + 1);
                d = new_d;
                skeleton.arguments.push(Value::Primitive(Arc::new(child)));
            }
            Value::Equation(e) => {
                if e.values.len() <= 1 {
                    skeleton.arguments.push(value_g());
                } else {
                    skeleton.arguments.push(value_g_nil());
                }
            }
        }
    }
    (skeleton, d + 1)
}

fn primitive_skeleton_depth(p: &Primitive, depth: usize) -> usize {
    let mut max_child = depth;
    for a in &p.arguments {
        if let Value::Primitive(pp) = a {
            let cd = primitive_skeleton_depth(pp, depth + 1);
            if cd > max_child { max_child = cd; }
        }
    }
    max_child + 1
}

pub fn primitive_skeleton_hash(p: &Primitive) -> u64 {
    let mut h = (p.id as u64).wrapping_mul(2654435761);
    for a in &p.arguments {
        match a {
            Value::Constant(_) => h = h.wrapping_mul(31).wrapping_add(1),
            Value::Primitive(pp) => h = h.wrapping_mul(31).wrapping_add(primitive_skeleton_hash(pp)),
            Value::Equation(e) => h = h.wrapping_mul(31).wrapping_add((e.values.len() as u64).wrapping_mul(97)),
        }
    }
    h
}

/// Compute the skeleton hash of a primitive (hash of its skeleton form).
/// This normalizes equations the same way inject_primitive_skeleton does.
pub fn primitive_skeleton_hash_of(p: &Primitive) -> u64 {
    let (skel, _) = inject_primitive_skeleton(p, 0);
    primitive_skeleton_hash(&skel)
}

fn inject_skeleton_equivalent(p: &Primitive, reference: &Primitive) -> bool {
    if p.id != reference.id { return false; }
    let pd = primitive_skeleton_depth(p, 0);
    let sd = primitive_skeleton_depth(reference, 0);
    if sd > pd { return false; }
    if primitive_skeleton_hash(p) != primitive_skeleton_hash(reference) { return false; }
    let (p1, _) = inject_primitive_skeleton(p, 0);
    let (p2, _) = inject_primitive_skeleton(reference, 0);
    let (e, _, _) = value_equivalent_primitives(&p1, &p2, false);
    e
}

pub fn inject_missing_skeletons(p: &Primitive, ps: &PrincipalState, as_: &AttackerState) {
    let (skeleton, _) = inject_primitive_skeleton(p, 0);
    let sh = primitive_skeleton_hash(&skeleton);
    if !as_.skeleton_hashes.contains(&sh) {
        let known = Value::Primitive(Arc::new(skeleton.clone()));
        if attacker_state_put_write(&known, ps) {
            info_message(
                &format!("Constructed skeleton {} based on {}.", pretty_primitive(&skeleton), pretty_primitive(p)),
                "analysis", true,
            );
        }
    }
    for a in &p.arguments {
        if let Value::Primitive(pp) = a {
            inject_missing_skeletons(pp, ps, as_);
        }
    }
}

fn inject_primitive(
    p: &Primitive, ps: &PrincipalState, as_: &AttackerState,
    inject_depth: usize, stage: i32,
) -> Vec<Value> {
    if inject_primitive_stage_restricted(p, stage) { return vec![]; }
    let n = p.arguments.len();
    let mut kinjectants: Vec<Vec<Value>> = vec![vec![]; n];
    let mut uinjectants: Vec<Vec<Value>> = vec![vec![]; n];
    for arg in 0..n {
        if verify_results_all_resolved() { return vec![]; }
        for k in as_.known.iter() {
            let resolved = match k {
                Value::Constant(c) => {
                    let (v, _) = value_resolve_constant(c, ps, true);
                    v
                }
                _ => k.clone(),
            };
            if !inject_value_rules(&resolved, arg, p, stage) { continue; }
            if value_equivalent_value_in_values(&resolved, &uinjectants[arg]) < 0 {
                uinjectants[arg].push(resolved.clone());
                kinjectants[arg].push(resolved.clone());
            }
            if let Value::Primitive(kp) = &resolved {
                if stage >= STAGE_RECURSIVE_INJECTION && inject_depth as i32 <= stage - STAGE_RECURSIVE_INJECTION {
                    let kp_inj = inject(kp, inject_depth + 1, ps, as_, stage);
                    for kkp in kp_inj {
                        if value_equivalent_value_in_values(&kkp, &uinjectants[arg]) < 0 {
                            uinjectants[arg].push(kkp.clone());
                            kinjectants[arg].push(kkp);
                        }
                    }
                }
            }
        }
    }
    inject_loop_n(p, &kinjectants)
}

fn inject_loop_n(p: &Primitive, kinjectants: &[Vec<Value>]) -> Vec<Value> {
    if verify_results_all_resolved() { return vec![]; }
    let n = kinjectants.len();
    if n == 0 { return vec![]; }
    for k in kinjectants {
        if k.is_empty() { return vec![]; }
    }
    let mut total_size: usize = 1;
    for k in kinjectants {
        if total_size > MAX_INJECTIONS_PER_PRIMITIVE / k.len() {
            total_size = MAX_INJECTIONS_PER_PRIMITIVE;
            break;
        }
        total_size *= k.len();
    }
    total_size = total_size.min(MAX_INJECTIONS_PER_PRIMITIVE);
    let mut injectants = Vec::with_capacity(total_size);
    let mut indices = vec![0usize; n];
    loop {
        if verify_results_all_resolved() { return injectants; }
        let args: Vec<Value> = (0..n).map(|j| kinjectants[j][indices[j]].clone()).collect();
        injectants.push(Value::Primitive(Arc::new(Primitive {
            id: p.id, arguments: args, output: p.output, check: p.check,
        })));
        if injectants.len() >= MAX_INJECTIONS_PER_PRIMITIVE { break; }
        let mut carry = true;
        for j in (0..n).rev() {
            if !carry { break; }
            indices[j] += 1;
            if indices[j] < kinjectants[j].len() {
                carry = false;
            } else {
                indices[j] = 0;
            }
        }
        if carry { break; }
    }
    injectants
}
