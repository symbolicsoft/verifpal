/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use crate::possible::{possible_to_rebuild, possible_to_rewrite};
use crate::primitive::{primitive_core_get, primitive_get, primitive_is_core};
use crate::types::*;
use crate::util::principal_enum_in_slice;

// ---------------------------------------------------------------------------
// Global name map
// ---------------------------------------------------------------------------

struct ValueNamesState {
    map: HashMap<Arc<str>, ValueId>,
    counter: ValueId,
}

static VALUE_NAMES_STATE: LazyLock<Mutex<ValueNamesState>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    map.insert(Arc::from("g"), 0);
    map.insert(Arc::from("nil"), 1);
    Mutex::new(ValueNamesState { map, counter: 2 })
});

// ---------------------------------------------------------------------------
// Canonical values (cached statics — no per-call allocation)
// ---------------------------------------------------------------------------

static STATIC_G: LazyLock<Value> = LazyLock::new(|| {
    Value::Constant(Constant {
        name: Arc::from("g"),
        id: 0,
        guard: false,
        fresh: false,
        leaked: false,
        declaration: TypesEnum::Knows,
        qualifier: TypesEnum::Public,
    })
});

static STATIC_NIL: LazyLock<Value> = LazyLock::new(|| {
    Value::Constant(Constant {
        name: Arc::from("nil"),
        id: 1,
        guard: false,
        fresh: false,
        leaked: false,
        declaration: TypesEnum::Knows,
        qualifier: TypesEnum::Public,
    })
});

static STATIC_G_NIL: LazyLock<Value> = LazyLock::new(|| {
    Value::Equation(Arc::new(Equation {
        values: vec![value_g(), value_nil()],
    }))
});

static STATIC_G_NIL_NIL: LazyLock<Value> = LazyLock::new(|| {
    Value::Equation(Arc::new(Equation {
        values: vec![value_g(), value_nil(), value_nil()],
    }))
});

pub fn value_g() -> Value {
    STATIC_G.clone()
}

pub fn value_nil() -> Value {
    STATIC_NIL.clone()
}

pub fn value_g_nil() -> Value {
    STATIC_G_NIL.clone()
}

pub fn value_g_nil_nil() -> Value {
    STATIC_G_NIL_NIL.clone()
}

// ---------------------------------------------------------------------------
// Name map helpers
// ---------------------------------------------------------------------------

pub fn value_names_map_add(name: &str) -> ValueId {
    let mut state = VALUE_NAMES_STATE.lock().expect("value names lock");
    if let Some(&id) = state.map.get(name) {
        return id;
    }
    let id = state.counter;
    state.map.insert(Arc::from(name), id);
    state.counter += 1;
    id
}

pub fn value_is_g_or_nil(c: &Constant) -> bool {
    c.id == 0 || c.id == 1
}

// ---------------------------------------------------------------------------
// Index lookups
// ---------------------------------------------------------------------------

pub fn value_get_knowledge_map_index_from_constant(
    km: &KnowledgeMap,
    c: &Constant,
) -> Option<usize> {
    if !km.constant_index.is_empty() {
        return km.constant_index.get(&c.id).copied();
    }
    for (i, kc) in km.constants.iter().enumerate() {
        if value_equivalent_constants(kc, c) {
            return Some(i);
        }
    }
    None
}

pub fn value_get_principal_state_index_from_constant(
    ps: &PrincipalState,
    c: &Constant,
) -> Option<usize> {
    if !ps.constant_index.is_empty() {
        if let Some(&i) = ps.constant_index.get(&c.id) {
            if i < ps.constants.len() {
                return Some(i);
            }
        }
        return None;
    }
    for (i, pc) in ps.constants.iter().enumerate() {
        if value_equivalent_constants(pc, c) {
            return Some(i);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Extract constants from values
// ---------------------------------------------------------------------------

pub fn value_get_constants_from_value(v: &Value) -> Vec<Constant> {
    match v {
        Value::Constant(c) => vec![c.clone()],
        Value::Primitive(p) => {
            let mut result = Vec::new();
            for a in &p.arguments {
                result.extend(value_get_constants_from_value(a));
            }
            result
        }
        Value::Equation(e) => {
            let mut result = Vec::new();
            for a in &e.values {
                result.extend(value_get_constants_from_value(a));
            }
            result
        }
    }
}

// ---------------------------------------------------------------------------
// Equivalence checks
// ---------------------------------------------------------------------------

pub fn value_equivalent_values(a1: &Value, a2: &Value, consider_output: bool) -> bool {
    match (a1, a2) {
        (Value::Constant(c1), Value::Constant(c2)) => value_equivalent_constants(c1, c2),
        (Value::Primitive(p1), Value::Primitive(p2)) => {
            let (equiv, _, _) = value_equivalent_primitives(p1, p2, consider_output);
            equiv
        }
        (Value::Equation(e1), Value::Equation(e2)) => value_equivalent_equations(e1, e2),
        _ => false,
    }
}

pub fn value_equivalent_constants(c1: &Constant, c2: &Constant) -> bool {
    c1.id == c2.id
}

pub fn value_equivalent_primitives(
    p1: &Primitive,
    p2: &Primitive,
    consider_output: bool,
) -> (bool, usize, usize) {
    if p1.id != p2.id {
        return (false, 0, 0);
    }
    if consider_output && (p1.output != p2.output) {
        return (false, 0, 0);
    }
    if p1.arguments.len() != p2.arguments.len() {
        return (false, 0, 0);
    }
    for i in 0..p1.arguments.len() {
        if !value_equivalent_values(&p1.arguments[i], &p2.arguments[i], true) {
            return (false, 0, 0);
        }
    }
    (true, p1.output, p2.output)
}

pub fn value_equivalent_equations(e1: &Equation, e2: &Equation) -> bool {
    if e1.values.is_empty() || e2.values.is_empty() {
        return false;
    }
    let (e1f, e2f): (Equation, Equation);
    let (e1_ref, e2_ref): (&Equation, &Equation);
    if value_equation_is_flat(e1) && value_equation_is_flat(e2) {
        e1_ref = e1;
        e2_ref = e2;
    } else {
        e1f = value_flatten_equation(e1);
        e2f = value_flatten_equation(e2);
        e1_ref = &e1f;
        e2_ref = &e2f;
    }
    if e1_ref.values.len() != e2_ref.values.len() {
        return false;
    }
    match e1_ref.values.len() {
        1 => value_equivalent_values(&e1_ref.values[0], &e2_ref.values[0], true),
        2 => {
            value_equivalent_values(&e1_ref.values[0], &e2_ref.values[0], true)
                && value_equivalent_values(&e1_ref.values[1], &e2_ref.values[1], true)
        }
        3 => {
            value_equivalent_equations_rule(
                &e1_ref.values[1],
                &e2_ref.values[1],
                &e1_ref.values[2],
                &e2_ref.values[2],
            ) || value_equivalent_equations_rule(
                &e1_ref.values[1],
                &e2_ref.values[2],
                &e1_ref.values[2],
                &e2_ref.values[1],
            )
        }
        _ => {
            // >3 elements: base must match, exponents are commutative
            if !value_equivalent_values(&e1_ref.values[0], &e2_ref.values[0], true) {
                return false;
            }
            // Check that exponents [1..] are a permutation of each other
            let n = e1_ref.values.len();
            let mut matched = vec![false; n];
            for i in 1..n {
                let mut found = false;
                for j in 1..n {
                    if !matched[j] && value_equivalent_values(&e1_ref.values[i], &e2_ref.values[j], true) {
                        matched[j] = true;
                        found = true;
                        break;
                    }
                }
                if !found { return false; }
            }
            true
        }
    }
}

pub fn value_equivalent_equations_rule(
    base1: &Value,
    base2: &Value,
    exp1: &Value,
    exp2: &Value,
) -> bool {
    value_equivalent_values(base1, exp2, true) && value_equivalent_values(exp1, base2, true)
}

// ---------------------------------------------------------------------------
// Equation flattening
// ---------------------------------------------------------------------------

pub fn value_equation_is_flat(e: &Equation) -> bool {
    for v in &e.values {
        if matches!(v, Value::Equation(_)) {
            return false;
        }
    }
    true
}

pub fn value_flatten_equation(e: &Equation) -> Equation {
    let mut ef = Equation {
        values: Vec::with_capacity(e.values.len()),
    };
    for v in &e.values {
        if let Value::Equation(inner) = v {
            let eff = value_flatten_equation(inner);
            ef.values.extend(eff.values);
        } else {
            ef.values.push(v.clone());
        }
    }
    ef
}

// ---------------------------------------------------------------------------
// Find constant in primitive from knowledge map
// ---------------------------------------------------------------------------

pub fn value_find_constant_in_primitive_from_knowledge_map(
    c: &Constant,
    a: &Value,
    km: &KnowledgeMap,
) -> bool {
    let v = Value::Constant(c.clone());
    let (_, vv) = value_resolve_value_internal_values_from_knowledge_map(a, km);
    value_equivalent_value_in_values(&v, &vv) >= 0
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

pub fn value_hash(v: &Value) -> u64 {
    match v {
        Value::Constant(c) => c.id as u64,
        Value::Primitive(p) => value_primitive_hash(p),
        Value::Equation(e) => value_equation_hash(e),
    }
}

pub fn value_primitive_hash(p: &Primitive) -> u64 {
    let mut h = (p.id as u64).wrapping_mul(2654435761) ^ (p.output as u64).wrapping_mul(97);
    for a in &p.arguments {
        h = h.wrapping_mul(31).wrapping_add(value_hash(a));
    }
    h
}

pub fn value_equation_hash(e: &Equation) -> u64 {
    if value_equation_is_flat(e) {
        return value_equation_hash_inner(e);
    }
    let ef = value_flatten_equation(e);
    value_equation_hash_inner(&ef)
}

pub fn value_equation_hash_inner(e: &Equation) -> u64 {
    match e.values.len() {
        0 => 0,
        1 => value_hash(&e.values[0]),
        2 => value_hash(&e.values[0])
            .wrapping_mul(31)
            .wrapping_add(value_hash(&e.values[1])),
        3 => {
            let mut h1 = value_hash(&e.values[1]);
            let mut h2 = value_hash(&e.values[2]);
            // Commutative hash for 3-element DH equations
            if h1 > h2 {
                std::mem::swap(&mut h1, &mut h2);
            }
            value_hash(&e.values[0])
                .wrapping_mul(31)
                .wrapping_add(h1.wrapping_mul(17))
                .wrapping_add(h2)
        }
        _ => {
            // >3 elements: commutative hash for exponents (same as DH equivalence)
            let base_h = value_hash(&e.values[0]);
            let mut exp_hashes: Vec<u64> = e.values[1..].iter().map(value_hash).collect();
            exp_hashes.sort_unstable();
            let mut h = base_h;
            for eh in exp_hashes {
                h = h.wrapping_mul(31).wrapping_add(eh);
            }
            h
        }
    }
}

// ---------------------------------------------------------------------------
// Search in value slices
// ---------------------------------------------------------------------------

pub fn value_equivalent_value_in_values_map(
    v: &Value,
    a: &[Value],
    m: &HashMap<u64, Vec<usize>>,
) -> i32 {
    let h = value_hash(v);
    if let Some(indices) = m.get(&h) {
        for &i in indices {
            if value_equivalent_values(v, &a[i], true) {
                return i as i32;
            }
        }
    }
    -1
}

pub fn value_equivalent_value_in_values(v: &Value, a: &[Value]) -> i32 {
    for (i, av) in a.iter().enumerate() {
        if value_equivalent_values(v, av, true) {
            return i as i32;
        }
    }
    -1
}

pub fn value_equivalent_constant_in_constants(c: &Constant, a: &[Constant]) -> i32 {
    for (i, ac) in a.iter().enumerate() {
        if value_equivalent_constants(c, ac) {
            return i as i32;
        }
    }
    -1
}

// ---------------------------------------------------------------------------
// Rewrite: primitives
// ---------------------------------------------------------------------------

pub fn value_perform_primitive_rewrite(
    p: &Primitive,
    pi: i32,
    ps: &mut PrincipalState,
) -> (Vec<Primitive>, bool, Value) {
    let r_index;
    let (mut rewrite, mut failed_rewrites, rewritten) =
        value_perform_primitive_arguments_rewrite(p, ps);
    let (rebuilt, rebuild) = possible_to_rebuild(rewrite.as_primitive().expect("rewrite is Primitive"));
    if rebuilt {
        rewrite = rebuild.clone();
        if pi >= 0 {
            let idx = pi as usize;
            ps.assigned[idx] = rebuild.clone();
            if !ps.mutated[idx] {
                ps.before_mutate[idx] = rebuild.clone();
            }
        }
        match rewrite {
            Value::Constant(_) | Value::Equation(_) => {
                return (failed_rewrites, rewritten, rewrite);
            }
            _ => {}
        }
    }
    let (rewritten_root, rewritten_values) =
        possible_to_rewrite(rewrite.as_primitive().expect("rewrite is Primitive"), ps, 0);
    if !rewritten_root {
        failed_rewrites.push(rewritten_values[0].as_primitive().expect("rewrite result is Primitive").clone());
        r_index = 0;
    } else if primitive_is_core(p.id) {
        r_index = p.output;
    } else {
        r_index = 0;
    }
    if r_index >= rewritten_values.len() {
        if pi >= 0 {
            let idx = pi as usize;
            let nil = value_nil();
            ps.assigned[idx] = nil.clone();
            if !ps.mutated[idx] {
                ps.before_mutate[idx] = nil.clone();
            }
        }
        return (failed_rewrites, rewritten || rewritten_root, value_nil());
    }
    if rewritten || rewritten_root {
        if pi >= 0 {
            let idx = pi as usize;
            ps.rewritten[idx] = true;
            ps.assigned[idx] = rewritten_values[r_index].clone();
            if !ps.mutated[idx] {
                ps.before_mutate[idx] = rewritten_values[r_index].clone();
            }
        }
    }
    (
        failed_rewrites,
        rewritten || rewritten_root,
        rewritten_values[r_index].clone(),
    )
}

// ---------------------------------------------------------------------------
// Rewrite: primitive arguments
// ---------------------------------------------------------------------------

pub fn value_perform_primitive_arguments_rewrite(
    p: &Primitive,
    ps: &mut PrincipalState,
) -> (Value, Vec<Primitive>, bool) {
    let mut failed_rewrites: Vec<Primitive> = Vec::new();
    let mut rewritten = false;
    // COW: only allocate new arguments vec if something actually changes
    let mut new_args: Option<Vec<Value>> = None;
    for (i, a) in p.arguments.iter().enumerate() {
        match a {
            Value::Constant(_) => {}
            Value::Primitive(inner_p) => {
                let (p_failed, p_rewritten, p_rewrite) =
                    value_perform_primitive_rewrite(inner_p, -1, ps);
                if p_rewritten {
                    rewritten = true;
                    let args = new_args.get_or_insert_with(|| p.arguments.clone());
                    args[i] = p_rewrite;
                } else {
                    failed_rewrites.extend(p_failed);
                }
            }
            Value::Equation(inner_e) => {
                let (e_failed, e_rewritten, e_rewrite) =
                    value_perform_equation_rewrite(inner_e, -1, ps);
                if e_rewritten {
                    rewritten = true;
                    let args = new_args.get_or_insert_with(|| p.arguments.clone());
                    args[i] = e_rewrite;
                } else {
                    failed_rewrites.extend(e_failed);
                }
            }
        }
    }
    let result = if let Some(args) = new_args {
        Value::Primitive(Arc::new(Primitive {
            id: p.id, arguments: args, output: p.output, check: p.check,
        }))
    } else {
        Value::Primitive(Arc::new(p.clone()))
    };
    (result, failed_rewrites, rewritten)
}

// ---------------------------------------------------------------------------
// Rewrite: equations
// ---------------------------------------------------------------------------

pub fn value_perform_equation_rewrite(
    e: &Equation,
    pi: i32,
    ps: &mut PrincipalState,
) -> (Vec<Primitive>, bool, Value) {
    let mut rewritten = false;
    let mut failed_rewrites: Vec<Primitive> = Vec::new();
    let mut rewrite_eq = Equation {
        values: Vec::new(),
    };
    for (i, a) in e.values.iter().enumerate() {
        match a {
            Value::Constant(_) => {
                rewrite_eq.values.push(a.clone());
            }
            Value::Primitive(inner_p) => {
                let has_rule = if primitive_is_core(inner_p.id) {
                    if let Ok(prim) = primitive_core_get(inner_p.id) {
                        prim.has_rule
                    } else {
                        false
                    }
                } else if let Ok(prim) = primitive_get(inner_p.id) {
                    prim.rewrite.has_rule
                } else {
                    false
                };
                if !has_rule {
                    continue;
                }
                let (p_failed, p_rewritten, p_rewrite) =
                    value_perform_primitive_rewrite(inner_p, -1, ps);
                if !p_rewritten {
                    rewrite_eq.values.push(e.values[i].clone());
                    failed_rewrites.extend(p_failed);
                    continue;
                }
                rewritten = true;
                match &p_rewrite {
                    Value::Constant(_) | Value::Primitive(_) => {
                        rewrite_eq.values.push(p_rewrite);
                    }
                    Value::Equation(inner_e) => {
                        rewrite_eq.values.extend(inner_e.values.iter().cloned());
                    }
                }
            }
            Value::Equation(inner_e) => {
                let (e_failed, e_rewritten, e_rewrite) =
                    value_perform_equation_rewrite(inner_e, -1, ps);
                if !e_rewritten {
                    rewrite_eq.values.push(e.values[i].clone());
                    failed_rewrites.extend(e_failed);
                    continue;
                }
                rewritten = true;
                rewrite_eq.values.push(e_rewrite);
            }
        }
    }
    let rewrite = Value::Equation(Arc::new(rewrite_eq));
    if rewritten && pi >= 0 {
        let idx = pi as usize;
        ps.rewritten[idx] = true;
        ps.assigned[idx] = rewrite.clone();
        if !ps.mutated[idx] {
            ps.before_mutate[idx] = rewrite.clone();
        }
    }
    (failed_rewrites, rewritten, rewrite)
}

// ---------------------------------------------------------------------------
// Perform all rewrites
// ---------------------------------------------------------------------------

pub fn value_perform_all_rewrites(
    ps: &mut PrincipalState,
) -> (Vec<Primitive>, Vec<usize>) {
    let mut failed_rewrites: Vec<Primitive> = Vec::new();
    let mut failed_rewrite_indices: Vec<usize> = Vec::new();
    let len = ps.assigned.len();
    for i in 0..len {
        match &ps.assigned[i] {
            Value::Primitive(p) => {
                let p_clone = p.clone();
                let (failed, _, _) = value_perform_primitive_rewrite(&p_clone, i as i32, ps);
                if failed.is_empty() {
                    continue;
                }
                let count = failed.len();
                failed_rewrites.extend(failed);
                for _ in 0..count {
                    failed_rewrite_indices.push(i);
                }
            }
            Value::Equation(e) => {
                let e_clone = e.clone();
                let (failed, _, _) = value_perform_equation_rewrite(&e_clone, i as i32, ps);
                if failed.is_empty() {
                    continue;
                }
                let count = failed.len();
                failed_rewrites.extend(failed);
                for _ in 0..count {
                    failed_rewrite_indices.push(i);
                }
            }
            _ => {}
        }
    }
    (failed_rewrites, failed_rewrite_indices)
}

// ---------------------------------------------------------------------------
// Resolution helpers
// ---------------------------------------------------------------------------

pub fn value_should_resolve_to_before_mutate(i: usize, ps: &PrincipalState) -> bool {
    if ps.creator[i] == ps.id {
        return true;
    }
    if !ps.known[i] {
        return true;
    }
    if !principal_enum_in_slice(ps.id, &ps.wire[i]) {
        return true;
    }
    if !ps.mutated[i] {
        return true;
    }
    false
}

pub fn value_resolve_constant(
    c: &Constant,
    ps: &PrincipalState,
    allow_before_mutate: bool,
) -> (Value, i32) {
    let i = value_get_principal_state_index_from_constant(ps, c);
    match i {
        None => (Value::Constant(c.clone()), -1),
        Some(idx) => {
            if allow_before_mutate && value_should_resolve_to_before_mutate(idx, ps) {
                (ps.before_mutate[idx].clone(), idx as i32)
            } else {
                (ps.assigned[idx].clone(), idx as i32)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Resolve internal values from KnowledgeMap
// ---------------------------------------------------------------------------

pub fn value_resolve_value_internal_values_from_knowledge_map(
    a: &Value,
    km: &KnowledgeMap,
) -> (Value, Vec<Value>) {
    let mut v: Vec<Value> = Vec::new();
    let resolved = match a {
        Value::Constant(c) => {
            if value_equivalent_value_in_values(a, &v) < 0 {
                v.push(a.clone());
            }
            let i = value_get_knowledge_map_index_from_constant(km, c);
            match i {
                Some(idx) => km.assigned[idx].clone(),
                None => a.clone(),
            }
        }
        _ => a.clone(),
    };
    match &resolved {
        Value::Constant(_) => {
            if value_equivalent_value_in_values(&resolved, &v) < 0 {
                v.push(resolved.clone());
            }
            (resolved, v)
        }
        Value::Primitive(_) => {
            value_resolve_primitive_internal_values_from_knowledge_map(&resolved, v, km)
        }
        Value::Equation(_) => {
            value_resolve_equation_internal_values_from_knowledge_map(&resolved, v, km)
        }
    }
}

pub fn value_resolve_primitive_internal_values_from_knowledge_map(
    a: &Value,
    mut v: Vec<Value>,
    km: &KnowledgeMap,
) -> (Value, Vec<Value>) {
    let p = a.as_primitive().expect("value is Primitive");
    // COW: only allocate a new Primitive if an argument actually changed
    let mut new_args: Option<Vec<Value>> = None;
    for (i, arg) in p.arguments.iter().enumerate() {
        let (s, vv) = value_resolve_value_internal_values_from_knowledge_map(arg, km);
        if !value_equivalent_values(&s, arg, true) {
            let args = new_args.get_or_insert_with(|| p.arguments.clone());
            args[i] = s;
        }
        for vvv in vv {
            if value_equivalent_value_in_values(&vvv, &v) < 0 {
                v.push(vvv);
            }
        }
    }
    if let Some(args) = new_args {
        (Value::Primitive(Arc::new(Primitive {
            id: p.id, arguments: args, output: p.output, check: p.check,
        })), v)
    } else {
        (a.clone(), v)
    }
}

pub fn value_resolve_equation_internal_values_from_knowledge_map(
    a: &Value,
    mut v: Vec<Value>,
    km: &KnowledgeMap,
) -> (Value, Vec<Value>) {
    let e = a.as_equation().expect("value is Equation");
    let mut r_eq = Equation {
        values: Vec::new(),
    };
    let mut aa: Vec<Value> = Vec::new();
    for ai in 0..e.values.len() {
        if let Value::Constant(c) = &e.values[ai] {
            let i = value_get_knowledge_map_index_from_constant(km, c);
            if let Some(idx) = i {
                aa.push(km.assigned[idx].clone());
            }
            if value_equivalent_value_in_values(&e.values[ai], &v) < 0 {
                v.push(e.values[ai].clone());
            }
        }
    }
    for (aai, item) in aa.iter().enumerate() {
        match item {
            Value::Constant(_) => {
                r_eq.values.push(item.clone());
                if value_equivalent_value_in_values(item, &v) < 0 {
                    v.push(item.clone());
                }
            }
            Value::Primitive(_) => {
                let (aaa, vv) = value_resolve_primitive_internal_values_from_knowledge_map(
                    item,
                    v.clone(),
                    km,
                );
                r_eq.values.push(aaa);
                for vvv in vv {
                    if value_equivalent_value_in_values(&vvv, &v) < 0 {
                        v.push(vvv);
                    }
                }
            }
            Value::Equation(_) => {
                let (aaa, vv) = value_resolve_equation_internal_values_from_knowledge_map(
                    item,
                    v.clone(),
                    km,
                );
                // Go: r.Values = append(r.Values, aaa)
                r_eq.values.push(aaa.clone());
                let inner = aaa.as_equation().expect("resolved equation is Equation");
                if aai == 0 {
                    // Go: r.Values = aaa.Data.(*Equation).Values
                    // Completely replaces r.Values (discarding the append above)
                    r_eq.values = inner.values.clone();
                } else {
                    // Go: r.Values = append(r.Values, aaa.Data.(*Equation).Values[1:]...)
                    // Keeps existing r.Values (including aaa) and appends inner[1:]
                    if inner.values.len() > 1 {
                        r_eq.values
                            .extend(inner.values[1..].iter().cloned());
                    }
                }
                for vvv in vv {
                    if value_equivalent_value_in_values(&vvv, &v) < 0 {
                        v.push(vvv);
                    }
                }
            }
        }
    }
    (Value::Equation(Arc::new(r_eq)), v)
}

// ---------------------------------------------------------------------------
// Resolve internal values from PrincipalState
// ---------------------------------------------------------------------------

const MAX_RESOLVE_DEPTH: usize = 64;

pub fn value_resolve_value_internal_values_from_principal_state(
    a: &Value,
    root_value: &Value,
    root_index: i32,
    ps: &PrincipalState,
    as_: &AttackerState,
    force_before_mutate: bool,
) -> Result<Value, String> {
    value_resolve_value_internal_values_from_principal_state_depth(
        a, root_value, root_index, ps, as_, force_before_mutate, 0,
    )
}

fn value_resolve_value_internal_values_from_principal_state_depth(
    a: &Value,
    root_value: &Value,
    root_index: i32,
    ps: &PrincipalState,
    as_: &AttackerState,
    force_before_mutate: bool,
    depth: usize,
) -> Result<Value, String> {
    if depth >= MAX_RESOLVE_DEPTH {
        return Ok(a.clone());
    }

    let mut a_resolved = a.clone();
    let mut root_idx = root_index;
    let mut root_val = root_value.clone();
    let mut fbm = force_before_mutate;

    if let Value::Constant(c) = &a_resolved {
        let next_root_index = value_get_principal_state_index_from_constant(ps, c);
        let nri = match next_root_index {
            Some(i) => i as i32,
            None => return Err("invalid index".to_string()),
        };
        let nri_usize = nri as usize;
        if nri == root_idx {
            if !fbm {
                fbm = value_should_resolve_to_before_mutate(nri_usize, ps);
            }
            if fbm {
                a_resolved = ps.before_mutate[nri_usize].clone();
            } else {
                let (resolved, _) = value_resolve_constant(c, ps, true);
                a_resolved = resolved;
            }
        } else {
            if let Value::Primitive(_) = &root_val {
                if root_idx >= 0 && ps.creator[root_idx as usize] != ps.id {
                    fbm = true;
                }
            }
            if fbm {
                fbm = !principal_enum_in_slice(
                    ps.creator[root_idx as usize],
                    &ps.mutatable_to[nri_usize],
                );
            } else {
                fbm = value_should_resolve_to_before_mutate(nri_usize, ps);
            }
            if fbm {
                a_resolved = ps.before_mutate[nri_usize].clone();
            } else {
                a_resolved = ps.assigned[nri_usize].clone();
            }
            root_idx = nri;
            root_val = a_resolved.clone();
        }
    }

    match &a_resolved {
        Value::Constant(_) => Ok(a_resolved),
        Value::Primitive(_) => value_resolve_primitive_internal_values_from_principal_state_depth(
            &a_resolved, &root_val, root_idx, ps, as_, fbm, depth + 1,
        ),
        Value::Equation(_) => value_resolve_equation_internal_values_from_principal_state_depth(
            &a_resolved, &root_val, root_idx, ps, as_, fbm, depth + 1,
        ),
    }
}

fn value_resolve_primitive_internal_values_from_principal_state_depth(
    a: &Value,
    root_value: &Value,
    root_index: i32,
    ps: &PrincipalState,
    as_: &AttackerState,
    force_before_mutate: bool,
    depth: usize,
) -> Result<Value, String> {
    let p = a.as_primitive().expect("value is Primitive");
    let mut fbm = force_before_mutate;
    if root_index >= 0 && ps.creator[root_index as usize] == ps.id {
        fbm = false;
    }
    // COW: only allocate a new Primitive if an argument actually changed
    let mut new_args: Option<Vec<Value>> = None;
    for (i, arg) in p.arguments.iter().enumerate() {
        let s = value_resolve_value_internal_values_from_principal_state_depth(
            arg, root_value, root_index, ps, as_, fbm, depth,
        )?;
        if !value_equivalent_values(&s, arg, true) {
            let args = new_args.get_or_insert_with(|| p.arguments.clone());
            args[i] = s;
        }
    }
    if let Some(args) = new_args {
        Ok(Value::Primitive(Arc::new(Primitive {
            id: p.id, arguments: args, output: p.output, check: p.check,
        })))
    } else {
        Ok(a.clone())
    }
}

fn value_resolve_equation_internal_values_from_principal_state_depth(
    a: &Value,
    root_value: &Value,
    root_index: i32,
    ps: &PrincipalState,
    as_: &AttackerState,
    force_before_mutate: bool,
    depth: usize,
) -> Result<Value, String> {
    let e = a.as_equation().expect("value is Equation");
    let mut r_eq = Equation {
        values: Vec::new(),
    };
    let mut aa: Vec<Value> = e.values.clone();
    let mut fbm = force_before_mutate;
    if root_index >= 0 && ps.creator[root_index as usize] == ps.id {
        fbm = false;
    }
    for aai in 0..aa.len() {
        if let Value::Constant(c) = &aa[aai].clone() {
            let (resolved, i) = value_resolve_constant(c, ps, true);
            aa[aai] = resolved;
            if fbm && i >= 0 {
                aa[aai] = ps.before_mutate[i as usize].clone();
            }
        }
    }
    for (aai, item) in aa.iter().enumerate() {
        match item {
            Value::Constant(_) => {
                r_eq.values.push(item.clone());
            }
            Value::Primitive(_) => {
                let aaa = value_resolve_primitive_internal_values_from_principal_state_depth(
                    item,
                    root_value,
                    root_index,
                    ps,
                    as_,
                    fbm,
                    depth,
                )?;
                r_eq.values.push(aaa);
            }
            Value::Equation(_) => {
                let aaa = value_resolve_equation_internal_values_from_principal_state_depth(
                    item,
                    root_value,
                    root_index,
                    ps,
                    as_,
                    fbm,
                    depth,
                )?;
                if aai == 0 {
                    r_eq.values = aaa.as_equation().expect("resolved equation is Equation").values.clone();
                } else {
                    let inner = aaa.as_equation().expect("resolved equation is Equation");
                    if inner.values.len() > 1 {
                        r_eq.values
                            .extend(inner.values[1..].iter().cloned());
                    }
                }
            }
        }
    }
    Ok(Value::Equation(Arc::new(r_eq)))
}

// ---------------------------------------------------------------------------
// Used-by checks
// ---------------------------------------------------------------------------

pub fn value_constant_is_used_by_principal_in_knowledge_map(
    km: &KnowledgeMap,
    principal_id: PrincipalId,
    c: &Constant,
) -> bool {
    if !km.used_by.is_empty() {
        if let Some(principals) = km.used_by.get(&c.id) {
            if let Some(&used) = principals.get(&principal_id) {
                return used;
            }
        }
        let i = value_get_knowledge_map_index_from_constant(km, c);
        if let Some(idx) = i {
            if let Value::Constant(assigned_c) = &km.assigned[idx] {
                if let Some(principals) = km.used_by.get(&assigned_c.id) {
                    if let Some(&used) = principals.get(&principal_id) {
                        return used;
                    }
                }
            }
        }
        return false;
    }
    let i = value_get_knowledge_map_index_from_constant(km, c);
    for (ii, a) in km.assigned.iter().enumerate() {
        if km.creator[ii] != principal_id {
            continue;
        }
        match a {
            Value::Primitive(_) | Value::Equation(_) => {
                let (_, v) = value_resolve_value_internal_values_from_knowledge_map(a, km);
                if let Some(idx) = i {
                    if value_equivalent_value_in_values(&km.assigned[idx], &v) >= 0 {
                        return true;
                    }
                }
                let cv = Value::Constant(c.clone());
                if value_equivalent_value_in_values(&cv, &v) >= 0 {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

pub fn value_constant_is_used_by_at_least_one_principal(
    km: &KnowledgeMap,
    c: &Constant,
) -> bool {
    if &*c.name == "nil" {
        return true;
    }
    for pid in &km.principal_ids {
        if value_constant_is_used_by_principal_in_knowledge_map(km, *pid, c) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Resolve all principal state values
// ---------------------------------------------------------------------------

pub fn value_resolve_all_principal_state_values(
    ps: &mut PrincipalState,
    as_: &AttackerState,
) -> Result<(), String> {
    let n = ps.assigned.len();
    let mut new_assigned = Vec::with_capacity(n);
    let mut new_before_rewrite = Vec::with_capacity(n);
    // Borrow ps immutably for the resolution loop
    let ps_ref: &PrincipalState = &*ps;
    for i in 0..n {
        let fbm = value_should_resolve_to_before_mutate(i, ps_ref);
        new_assigned.push(value_resolve_value_internal_values_from_principal_state(
            &ps_ref.assigned[i],
            &ps_ref.assigned[i],
            i as i32,
            ps_ref,
            as_,
            fbm,
        )?);
        new_before_rewrite.push(value_resolve_value_internal_values_from_principal_state(
            &ps_ref.before_rewrite[i],
            &ps_ref.before_rewrite[i],
            i as i32,
            ps_ref,
            as_,
            fbm,
        )?);
    }
    ps.assigned = new_assigned;
    ps.before_rewrite = new_before_rewrite;
    ps.rewritten.fill(false);
    Ok(())
}

// ---------------------------------------------------------------------------
// Fresh value check
// ---------------------------------------------------------------------------

pub fn value_constant_contains_fresh_values(
    c: &Constant,
    ps: &PrincipalState,
) -> Result<bool, String> {
    let i = value_get_principal_state_index_from_constant(ps, c);
    let idx = match i {
        Some(idx) => idx,
        None => return Err("invalid value".to_string()),
    };
    let mut cc = value_get_constants_from_value(&ps.assigned[idx]);
    for j in 0..cc.len() {
        if let Some(ii) = value_get_principal_state_index_from_constant(ps, &cc[j]) {
            cc[j] = ps.constants[ii].clone();
            if cc[j].fresh {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

