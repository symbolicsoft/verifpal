/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::*;
use crate::value::*;
use crate::inject::*;
use crate::info::info_message;
use crate::util::*;

pub fn mutation_map_init(
    km: &KnowledgeMap, ps: &PrincipalState, as_: &AttackerState, stage: i32,
) -> Result<MutationMap, String> {
    let mut mm = MutationMap {
        out_of_mutations: false,
        constants: vec![],
        mutations: vec![],
        combination: vec![],
        depth_index: vec![],
    };
    info_message(
        &format!("Initializing Stage {} mutation map for {}...", stage, ps.name),
        "analysis", false,
    );
    for v in as_.known.iter() {
        let c = match v {
            Value::Constant(c) => c,
            _ => continue,
        };
        let (a, i) = value_resolve_constant(c, ps, true);
        if mutation_map_skip_value(v, i, km, ps, as_) { continue; }
        let r = mutation_map_replace_value(&a, i as usize, stage, ps, as_)?;
        if r.is_empty() { continue; }
        mm.constants.push(c.clone());
        mm.mutations.push(r);
    }
    mm.combination = vec![value_nil(); mm.constants.len()];
    mm.depth_index = vec![0; mm.constants.len()];
    if !mm.constants.is_empty() {
        let mut_sizes: Vec<usize> = mm.mutations.iter().map(|m| m.len()).collect();
        info_message(
            &format!("Mutation map for {} at stage {}: {} constants, mutations: {:?}",
                ps.name, stage, mm.constants.len(), mut_sizes),
            "analysis", false,
        );
    }
    Ok(mm)
}

fn mutation_map_skip_value(
    v: &Value, i: i32, km: &KnowledgeMap, ps: &PrincipalState, as_: &AttackerState,
) -> bool {
    if i < 0 { return true; }
    let idx = i as usize;
    if ps.guard[idx] {
        if !principal_enum_in_slice(ps.sender[idx], &ps.mutatable_to[idx]) {
            return true;
        }
    } else if ps.creator[idx] == ps.id {
        return true;
    }
    if !int_in_slice(as_.current_phase, &ps.phase[idx]) { return true; }
    if let Value::Constant(c) = v {
        if !value_constant_is_used_by_principal_in_knowledge_map(km, ps.id, c) {
            return true;
        }
    }
    false
}

fn mutation_map_replace_value(
    a: &Value, root_index: usize, stage: i32,
    ps: &PrincipalState, as_: &AttackerState,
) -> Result<Vec<Value>, String> {
    let a = value_resolve_value_internal_values_from_principal_state(
        a, a, root_index as i32, ps, as_, false,
    )?;
    match &a {
        Value::Constant(_) => Ok(mutation_map_replace_constant(&a, stage, ps, as_)),
        Value::Primitive(_) => Ok(mutation_map_replace_primitive(&a, stage, ps, as_)),
        Value::Equation(_) => Ok(mutation_map_replace_equation(&a, stage, as_)),
    }
}

fn mutation_map_replace_constant(
    a: &Value, stage: i32, ps: &PrincipalState, as_: &AttackerState,
) -> Vec<Value> {
    let mut mutations = vec![];
    if let Value::Constant(c) = a {
        if value_is_g_or_nil(c) { return mutations; }
    }
    mutations.push(value_nil());
    if stage <= 3 { return mutations; } // stageMutationExpansion = 3
    for v in as_.known.iter() {
        if let Value::Constant(vc) = v {
            if value_is_g_or_nil(vc) { continue; }
            let (c, _) = value_resolve_constant(vc, ps, true);
            if let Value::Constant(_) = &c {
                if value_equivalent_value_in_values(&c, &mutations) < 0 {
                    mutations.push(c);
                }
            }
        }
    }
    mutations
}

fn mutation_map_replace_primitive(
    a: &Value, stage: i32, ps: &PrincipalState, as_: &AttackerState,
) -> Vec<Value> {
    let mut mutations = vec![];
    let a_prim = match a { Value::Primitive(p) => p, _ => return mutations };
    for v in as_.known.iter() {
        match v {
            Value::Constant(vc) => {
                if value_is_g_or_nil(vc) { continue; }
                let (c, _) = value_resolve_constant(vc, ps, true);
                if let Value::Constant(_) = &c {
                    if value_equivalent_value_in_values(&c, &mutations) < 0 {
                        mutations.push(c);
                    }
                }
            }
            Value::Primitive(vp) => {
                if !inject_skeleton_not_deeper_pub(vp, a_prim) { continue; }
                if value_equivalent_value_in_values(v, &mutations) < 0 {
                    mutations.push(v.clone());
                }
            }
            _ => {}
        }
    }
    let injectants = inject(a_prim, 0, ps, as_, stage);
    for inj in injectants {
        if value_equivalent_value_in_values(&inj, &mutations) < 0 {
            mutations.push(inj);
        }
    }
    mutations
}

fn mutation_map_replace_equation(
    a: &Value, stage: i32, as_: &AttackerState,
) -> Vec<Value> {
    let mut mutations = vec![];
    if let Value::Equation(e) = a {
        match e.values.len() {
            1 => mutations.push(value_g()),
            2 => mutations.push(value_g_nil()),
            3 => mutations.push(value_g_nil_nil()),
            _ => {}
        }
        if stage <= 3 { return mutations; }
        for v in as_.known.iter() {
            if let Value::Equation(ve) = v {
                if ve.values.len() == e.values.len()
                    && value_equivalent_value_in_values(v, &mutations) < 0 {
                        mutations.push(v.clone());
                    }
            }
        }
    }
    mutations
}

pub fn mutation_map_subset(full_map: &MutationMap, indices: &[usize]) -> MutationMap {
    MutationMap {
        out_of_mutations: false,
        constants: indices.iter().map(|&i| full_map.constants[i].clone()).collect(),
        mutations: indices.iter().map(|&i| full_map.mutations[i].clone()).collect(),
        combination: vec![value_nil(); indices.len()],
        depth_index: vec![0; indices.len()],
    }
}

pub fn mutation_map_subset_capped(full_map: &MutationMap, indices: &[usize], max_product: usize) -> MutationMap {
    let mut sub = mutation_map_subset(full_map, indices);
    let n = indices.len();
    if n == 0 { return sub; }
    let mut product: usize = 1;
    let mut overflow = false;
    for i in 0..n {
        let m = sub.mutations[i].len();
        if m > 0 && product > max_product / m { overflow = true; break; }
        product *= m;
    }
    if !overflow && product <= max_product { return sub; }
    let per_dim = int_nth_root(max_product as i32, n as i32).max(1) as usize;
    for i in 0..n {
        if sub.mutations[i].len() > per_dim {
            sub.mutations[i].truncate(per_dim);
        }
    }
    sub
}

pub fn mutation_map_next(mut mm: MutationMap) -> MutationMap {
    if mm.combination.is_empty() {
        mm.out_of_mutations = true;
        return mm;
    }
    let n = mm.combination.len();
    for i in 0..n {
        mm.combination[i] = mm.mutations[i][mm.depth_index[i]].clone();
        if i != n - 1 { continue; }
        mm.depth_index[i] += 1;
        let mut ii = i as i32;
        while ii >= 0 {
            if mm.depth_index[ii as usize] != mm.mutations[ii as usize].len() { break; }
            if ii <= 0 {
                mm.out_of_mutations = true;
                break;
            }
            mm.depth_index[ii as usize] = 0;
            mm.depth_index[(ii - 1) as usize] += 1;
            ii -= 1;
        }
    }
    mm
}

// Public wrapper for inject_skeleton_not_deeper used by mutationmap
pub fn inject_skeleton_not_deeper_pub(p: &Primitive, reference: &Primitive) -> bool {
    if p.id != reference.id { return false; }
    fn skeleton_depth(p: &Primitive, depth: usize) -> usize {
        let mut max_child = depth;
        for a in &p.arguments {
            if let Value::Primitive(pp) = a {
                let cd = skeleton_depth(pp, depth + 1);
                if cd > max_child { max_child = cd; }
            }
        }
        max_child + 1
    }
    skeleton_depth(p, 0) <= skeleton_depth(reference, 0)
}
