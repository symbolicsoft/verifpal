/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use crate::types::*;
use crate::value::{value_equivalent_values, value_g, value_nil};

// Primitive ID constants
pub const PRIM_ASSERT: PrimitiveId = 1;
pub const PRIM_CONCAT: PrimitiveId = 2;
pub const PRIM_SPLIT: PrimitiveId = 3;
pub const PRIM_PWHASH: PrimitiveId = 4;
pub const PRIM_HASH: PrimitiveId = 5;
pub const PRIM_HKDF: PrimitiveId = 6;
pub const PRIM_AEAD_ENC: PrimitiveId = 7;
pub const PRIM_AEAD_DEC: PrimitiveId = 8;
pub const PRIM_ENC: PrimitiveId = 9;
pub const PRIM_DEC: PrimitiveId = 10;
pub const PRIM_MAC: PrimitiveId = 11;
pub const PRIM_SIGN: PrimitiveId = 12;
pub const PRIM_SIGNVERIF: PrimitiveId = 13;
pub const PRIM_PKE_ENC: PrimitiveId = 14;
pub const PRIM_PKE_DEC: PrimitiveId = 15;
pub const PRIM_SHAMIR_SPLIT: PrimitiveId = 16;
pub const PRIM_SHAMIR_JOIN: PrimitiveId = 17;
pub const PRIM_RINGSIGN: PrimitiveId = 18;
pub const PRIM_RINGSIGNVERIF: PrimitiveId = 19;
pub const PRIM_BLIND: PrimitiveId = 20;
pub const PRIM_UNBLIND: PrimitiveId = 21;

type FilterFn = fn(&Primitive, &Value, usize) -> (Value, bool);
type CoreRuleFn = fn(&Primitive) -> (bool, Vec<Value>);
type RewriteToFn = fn(&Primitive) -> Value;

#[derive(Clone)]
pub struct DecomposeRule {
    pub has_rule: bool,
    pub given: Vec<usize>,
    pub reveal: usize,
    pub filter: Option<FilterFn>,
    pub passive_reveal: Vec<usize>,
}

#[derive(Clone)]
pub struct RecomposeRule {
    pub has_rule: bool,
    pub given: Vec<Vec<usize>>,
    pub reveal: usize,
}

#[derive(Clone)]
pub struct RewriteRule {
    pub has_rule: bool,
    pub id: PrimitiveId,
    pub from: usize,
    pub to: Option<RewriteToFn>,
    pub matching: Vec<(usize, Vec<usize>)>,
    pub filter: Option<FilterFn>,
}

#[derive(Clone)]
pub struct RebuildRule {
    pub has_rule: bool,
    pub id: PrimitiveId,
    pub given: Vec<Vec<usize>>,
    pub reveal: usize,
}

#[derive(Clone)]
pub struct PrimitiveCoreSpec {
    pub name: String,
    pub id: PrimitiveId,
    pub arity: Vec<i32>,
    pub output: Vec<i32>,
    pub has_rule: bool,
    pub core_rule: Option<CoreRuleFn>,
    pub check: bool,
    pub explosive: bool,
}

#[derive(Clone)]
pub struct PrimitiveSpec {
    pub name: String,
    pub id: PrimitiveId,
    pub arity: Vec<i32>,
    pub output: Vec<i32>,
    pub decompose: DecomposeRule,
    pub recompose: RecomposeRule,
    pub rewrite: RewriteRule,
    pub rebuild: RebuildRule,
    pub check: bool,
    pub explosive: bool,
    pub password_hashing: Vec<usize>,
}

// Filter functions
fn filter_identity(_p: &Primitive, x: &Value, _i: usize) -> (Value, bool) {
    (x.clone(), true)
}

fn filter_signverif_rewrite(_p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
    match i {
        0 => {
            match x {
                Value::Constant(_) | Value::Primitive(_) => (x.clone(), false),
                Value::Equation(e) => {
                    if e.values.len() != 2 {
                        return (x.clone(), false);
                    }
                    if !value_equivalent_values(&e.values[0], &value_g(), true) {
                        return (x.clone(), false);
                    }
                    (e.values[1].clone(), true)
                }
            }
        }
        1 => (x.clone(), true),
        _ => (x.clone(), false),
    }
}

fn filter_pke_enc_decompose(_p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
    match i {
        0 => {
            match x {
                Value::Constant(_) | Value::Primitive(_) => (x.clone(), false),
                Value::Equation(e) => {
                    if e.values.len() != 2 {
                        return (x.clone(), false);
                    }
                    if !value_equivalent_values(&e.values[0], &value_g(), true) {
                        return (x.clone(), false);
                    }
                    (e.values[1].clone(), true)
                }
            }
        }
        1 => (x.clone(), true),
        _ => (x.clone(), false),
    }
}

fn filter_pke_dec_rewrite(_p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
    match i {
        0 => {
            match x {
                Value::Constant(_) | Value::Primitive(_) => {
                    let eq = Value::Equation(Arc::new(Equation {
                        values: vec![value_g(), x.clone()],
                    }));
                    (eq, true)
                }
                Value::Equation(_) => (x.clone(), false),
            }
        }
        _ => (x.clone(), false),
    }
}

fn filter_aead_dec_rewrite(_p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
    match i {
        0 | 2 => (x.clone(), true),
        _ => (x.clone(), false),
    }
}

fn filter_dec_rewrite(_p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
    match i {
        0 => (x.clone(), true),
        _ => (x.clone(), false),
    }
}

fn filter_ringsignverif_rewrite(_p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
    match i {
        0 => {
            match x {
                Value::Constant(_) | Value::Primitive(_) => (x.clone(), false),
                Value::Equation(e) => {
                    if e.values.len() == 2 {
                        (e.values[1].clone(), true)
                    } else {
                        (x.clone(), false)
                    }
                }
            }
        }
        1..=4 => (x.clone(), true),
        _ => (x.clone(), false),
    }
}

fn filter_unblind_rewrite(p: &Primitive, x: &Value, i: usize) -> (Value, bool) {
    match i {
        1 => {
            let blind_prim = Value::Primitive(Arc::new(Primitive {
                id: PRIM_BLIND,
                arguments: vec![
                    p.arguments[0].clone(),
                    p.arguments[1].clone(),
                ],
                output: 0,
                check: false,
            }));
            (blind_prim, true)
        }
        _ => (x.clone(), false),
    }
}

// Core rule functions
fn core_rule_assert(p: &Primitive) -> (bool, Vec<Value>) {
    let v = vec![Value::Primitive(Arc::new(p.clone()))];
    if value_equivalent_values(&p.arguments[0], &p.arguments[1], true) {
        (true, v)
    } else {
        (false, v)
    }
}

fn core_rule_concat(p: &Primitive) -> (bool, Vec<Value>) {
    let v = vec![Value::Primitive(Arc::new(p.clone()))];
    (false, v)
}

fn core_rule_split(p: &Primitive) -> (bool, Vec<Value>) {
    let v = vec![Value::Primitive(Arc::new(p.clone()))];
    match &p.arguments[0] {
        Value::Constant(_) => (false, v),
        Value::Primitive(pp) => {
            if pp.id == PRIM_CONCAT {
                (true, pp.arguments.clone())
            } else {
                (false, v)
            }
        }
        Value::Equation(_) => (false, v),
    }
}

// Rewrite To functions
fn rewrite_to_aead_dec(p: &Primitive) -> Value {
    p.arguments[1].clone()
}

fn rewrite_to_dec(p: &Primitive) -> Value {
    p.arguments[1].clone()
}

fn rewrite_to_signverif(_p: &Primitive) -> Value {
    value_nil()
}

fn rewrite_to_pke_dec(p: &Primitive) -> Value {
    p.arguments[1].clone()
}

fn rewrite_to_ringsignverif(_p: &Primitive) -> Value {
    value_nil()
}

fn rewrite_to_unblind(p: &Primitive) -> Value {
    // Get the inner SIGN primitive's argument[1] from p.arguments[1] which should be SIGN
    let inner = match &p.arguments[1] {
        Value::Primitive(inner_p) => inner_p.arguments[1].clone(),
        _ => value_nil(),
    };
    Value::Primitive(Arc::new(Primitive {
        id: PRIM_SIGN,
        arguments: vec![
            p.arguments[0].clone(),
            inner,
        ],
        output: 0,
        check: false,
    }))
}

fn build_core_specs() -> Vec<PrimitiveCoreSpec> {
    vec![
        PrimitiveCoreSpec {
            id: PRIM_ASSERT,
            name: "ASSERT".to_string(),
            arity: vec![2],
            output: vec![1],
            has_rule: true,
            core_rule: Some(core_rule_assert),
            check: true,
            explosive: false,
        },
        PrimitiveCoreSpec {
            id: PRIM_CONCAT,
            name: "CONCAT".to_string(),
            arity: vec![2, 3, 4, 5],
            output: vec![1],
            has_rule: false,
            core_rule: Some(core_rule_concat),
            check: false,
            explosive: true,
        },
        PrimitiveCoreSpec {
            id: PRIM_SPLIT,
            name: "SPLIT".to_string(),
            arity: vec![1],
            output: vec![1, 2, 3, 4, 5],
            has_rule: true,
            core_rule: Some(core_rule_split),
            check: true,
            explosive: false,
        },
    ]
}

fn build_primitive_specs() -> Vec<PrimitiveSpec> {
    vec![
        // PW_HASH
        PrimitiveSpec {
            id: PRIM_PWHASH, name: "PW_HASH".to_string(),
            arity: vec![1, 2, 3, 4, 5], output: vec![1],
            decompose: DecomposeRule { has_rule: false, given: vec![], reveal: 0, filter: None, passive_reveal: vec![] },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule { has_rule: false, id: 0, from: 0, to: None, matching: vec![], filter: None },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: false, explosive: false, password_hashing: vec![0, 1, 2, 3, 4],
        },
        // HASH
        PrimitiveSpec {
            id: PRIM_HASH, name: "HASH".to_string(),
            arity: vec![1, 2, 3, 4, 5], output: vec![1],
            decompose: DecomposeRule { has_rule: false, given: vec![], reveal: 0, filter: None, passive_reveal: vec![] },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule { has_rule: false, id: 0, from: 0, to: None, matching: vec![], filter: None },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: false, explosive: true, password_hashing: vec![],
        },
        // HKDF
        PrimitiveSpec {
            id: PRIM_HKDF, name: "HKDF".to_string(),
            arity: vec![3], output: vec![1, 2, 3, 4, 5],
            decompose: DecomposeRule { has_rule: false, given: vec![], reveal: 0, filter: None, passive_reveal: vec![] },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule { has_rule: false, id: 0, from: 0, to: None, matching: vec![], filter: None },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: false, explosive: true, password_hashing: vec![],
        },
        // AEAD_ENC
        PrimitiveSpec {
            id: PRIM_AEAD_ENC, name: "AEAD_ENC".to_string(),
            arity: vec![3], output: vec![1],
            decompose: DecomposeRule {
                has_rule: true, given: vec![0], reveal: 1,
                filter: Some(filter_identity), passive_reveal: vec![2],
            },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule { has_rule: false, id: 0, from: 0, to: None, matching: vec![], filter: None },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: false, explosive: false, password_hashing: vec![1],
        },
        // AEAD_DEC
        PrimitiveSpec {
            id: PRIM_AEAD_DEC, name: "AEAD_DEC".to_string(),
            arity: vec![3], output: vec![1],
            decompose: DecomposeRule {
                has_rule: true, given: vec![0], reveal: 1,
                filter: Some(filter_identity), passive_reveal: vec![],
            },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule {
                has_rule: true, id: PRIM_AEAD_ENC, from: 1,
                to: Some(rewrite_to_aead_dec),
                matching: vec![(0, vec![0]), (2, vec![2])],
                filter: Some(filter_aead_dec_rewrite),
            },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: true, explosive: false, password_hashing: vec![],
        },
        // ENC
        PrimitiveSpec {
            id: PRIM_ENC, name: "ENC".to_string(),
            arity: vec![2], output: vec![1],
            decompose: DecomposeRule {
                has_rule: true, given: vec![0], reveal: 1,
                filter: Some(filter_identity), passive_reveal: vec![],
            },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule { has_rule: false, id: 0, from: 0, to: None, matching: vec![], filter: None },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: false, explosive: false, password_hashing: vec![1],
        },
        // DEC
        PrimitiveSpec {
            id: PRIM_DEC, name: "DEC".to_string(),
            arity: vec![2], output: vec![1],
            decompose: DecomposeRule {
                has_rule: true, given: vec![0], reveal: 1,
                filter: Some(filter_identity), passive_reveal: vec![],
            },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule {
                has_rule: true, id: PRIM_ENC, from: 1,
                to: Some(rewrite_to_dec),
                matching: vec![(0, vec![0])],
                filter: Some(filter_dec_rewrite),
            },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: false, explosive: false, password_hashing: vec![],
        },
        // MAC
        PrimitiveSpec {
            id: PRIM_MAC, name: "MAC".to_string(),
            arity: vec![2], output: vec![1],
            decompose: DecomposeRule { has_rule: false, given: vec![], reveal: 0, filter: None, passive_reveal: vec![] },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule { has_rule: false, id: 0, from: 0, to: None, matching: vec![], filter: None },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: false, explosive: false, password_hashing: vec![1],
        },
        // SIGN
        PrimitiveSpec {
            id: PRIM_SIGN, name: "SIGN".to_string(),
            arity: vec![2], output: vec![1],
            decompose: DecomposeRule { has_rule: false, given: vec![], reveal: 0, filter: None, passive_reveal: vec![] },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule { has_rule: false, id: 0, from: 0, to: None, matching: vec![], filter: None },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: false, explosive: false, password_hashing: vec![1],
        },
        // SIGNVERIF
        PrimitiveSpec {
            id: PRIM_SIGNVERIF, name: "SIGNVERIF".to_string(),
            arity: vec![3], output: vec![1],
            decompose: DecomposeRule { has_rule: false, given: vec![], reveal: 0, filter: None, passive_reveal: vec![] },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule {
                has_rule: true, id: PRIM_SIGN, from: 2,
                to: Some(rewrite_to_signverif),
                matching: vec![(0, vec![0]), (1, vec![1])],
                filter: Some(filter_signverif_rewrite),
            },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: true, explosive: false, password_hashing: vec![],
        },
        // PKE_ENC
        PrimitiveSpec {
            id: PRIM_PKE_ENC, name: "PKE_ENC".to_string(),
            arity: vec![2], output: vec![1],
            decompose: DecomposeRule {
                has_rule: true, given: vec![0], reveal: 1,
                filter: Some(filter_pke_enc_decompose), passive_reveal: vec![],
            },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule { has_rule: false, id: 0, from: 0, to: None, matching: vec![], filter: None },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: false, explosive: false, password_hashing: vec![1],
        },
        // PKE_DEC
        PrimitiveSpec {
            id: PRIM_PKE_DEC, name: "PKE_DEC".to_string(),
            arity: vec![2], output: vec![1],
            decompose: DecomposeRule {
                has_rule: true, given: vec![0], reveal: 1,
                filter: Some(filter_identity), passive_reveal: vec![],
            },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule {
                has_rule: true, id: PRIM_PKE_ENC, from: 1,
                to: Some(rewrite_to_pke_dec),
                matching: vec![(0, vec![0])],
                filter: Some(filter_pke_dec_rewrite),
            },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: false, explosive: false, password_hashing: vec![],
        },
        // SHAMIR_SPLIT
        PrimitiveSpec {
            id: PRIM_SHAMIR_SPLIT, name: "SHAMIR_SPLIT".to_string(),
            arity: vec![1], output: vec![3],
            decompose: DecomposeRule { has_rule: false, given: vec![], reveal: 0, filter: None, passive_reveal: vec![] },
            recompose: RecomposeRule {
                has_rule: true,
                given: vec![vec![0, 1], vec![0, 2], vec![1, 2]],
                reveal: 0,
            },
            rewrite: RewriteRule { has_rule: false, id: 0, from: 0, to: None, matching: vec![], filter: None },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: false, explosive: false, password_hashing: vec![],
        },
        // SHAMIR_JOIN
        PrimitiveSpec {
            id: PRIM_SHAMIR_JOIN, name: "SHAMIR_JOIN".to_string(),
            arity: vec![2], output: vec![1],
            decompose: DecomposeRule { has_rule: false, given: vec![], reveal: 0, filter: None, passive_reveal: vec![] },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule { has_rule: false, id: 0, from: 0, to: None, matching: vec![], filter: None },
            rebuild: RebuildRule {
                has_rule: true, id: PRIM_SHAMIR_SPLIT,
                given: vec![vec![0, 1], vec![1, 0], vec![0, 2], vec![2, 0], vec![1, 2], vec![2, 1]],
                reveal: 0,
            },
            check: false, explosive: false, password_hashing: vec![],
        },
        // RINGSIGN
        PrimitiveSpec {
            id: PRIM_RINGSIGN, name: "RINGSIGN".to_string(),
            arity: vec![4], output: vec![1],
            decompose: DecomposeRule { has_rule: false, given: vec![], reveal: 0, filter: None, passive_reveal: vec![] },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule { has_rule: false, id: 0, from: 0, to: None, matching: vec![], filter: None },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: false, explosive: false, password_hashing: vec![3],
        },
        // RINGSIGNVERIF
        PrimitiveSpec {
            id: PRIM_RINGSIGNVERIF, name: "RINGSIGNVERIF".to_string(),
            arity: vec![5], output: vec![1],
            decompose: DecomposeRule { has_rule: false, given: vec![], reveal: 0, filter: None, passive_reveal: vec![] },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule {
                has_rule: true, id: PRIM_RINGSIGN, from: 4,
                to: Some(rewrite_to_ringsignverif),
                matching: vec![(0, vec![0, 1, 2]), (1, vec![0, 1, 2]), (2, vec![0, 1, 2]), (3, vec![3])],
                filter: Some(filter_ringsignverif_rewrite),
            },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: true, explosive: false, password_hashing: vec![],
        },
        // BLIND
        PrimitiveSpec {
            id: PRIM_BLIND, name: "BLIND".to_string(),
            arity: vec![2], output: vec![1],
            decompose: DecomposeRule {
                has_rule: true, given: vec![0], reveal: 1,
                filter: Some(filter_identity), passive_reveal: vec![],
            },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule { has_rule: false, id: 0, from: 0, to: None, matching: vec![], filter: None },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: false, explosive: false, password_hashing: vec![1],
        },
        // UNBLIND
        PrimitiveSpec {
            id: PRIM_UNBLIND, name: "UNBLIND".to_string(),
            arity: vec![3], output: vec![1],
            decompose: DecomposeRule { has_rule: false, given: vec![], reveal: 0, filter: None, passive_reveal: vec![] },
            recompose: RecomposeRule { has_rule: false, given: vec![], reveal: 0 },
            rewrite: RewriteRule {
                has_rule: true, id: PRIM_SIGN, from: 2,
                to: Some(rewrite_to_unblind),
                matching: vec![(0, vec![1])],
                filter: Some(filter_unblind_rewrite),
            },
            rebuild: RebuildRule { has_rule: false, id: 0, given: vec![], reveal: 0 },
            check: false, explosive: false, password_hashing: vec![],
        },
    ]
}

static CORE_SPECS: LazyLock<HashMap<PrimitiveId, PrimitiveCoreSpec>> = LazyLock::new(|| {
    let specs = build_core_specs();
    specs.into_iter().map(|s| (s.id, s)).collect()
});

static PRIM_SPECS: LazyLock<HashMap<PrimitiveId, PrimitiveSpec>> = LazyLock::new(|| {
    let specs = build_primitive_specs();
    specs.into_iter().map(|s| (s.id, s)).collect()
});

pub fn primitive_is_core(id: PrimitiveId) -> bool {
    matches!(id, PRIM_ASSERT | PRIM_CONCAT | PRIM_SPLIT)
}

pub fn primitive_core_get(id: PrimitiveId) -> Result<&'static PrimitiveCoreSpec, String> {
    CORE_SPECS.get(&id).ok_or_else(|| "unknown primitive".to_string())
}

pub fn primitive_get(id: PrimitiveId) -> Result<&'static PrimitiveSpec, String> {
    PRIM_SPECS.get(&id).ok_or_else(|| "unknown primitive".to_string())
}

pub fn primitive_get_enum(name: &str) -> Result<PrimitiveId, String> {
    for spec in CORE_SPECS.values() {
        if spec.name == name {
            return Ok(spec.id);
        }
    }
    for spec in PRIM_SPECS.values() {
        if spec.name == name {
            return Ok(spec.id);
        }
    }
    Err("unknown primitive".to_string())
}

pub fn primitive_get_arity(p: &Primitive) -> Result<Vec<i32>, String> {
    if primitive_is_core(p.id) {
        let prim = primitive_core_get(p.id)?;
        Ok(prim.arity.clone())
    } else {
        let prim = primitive_get(p.id)?;
        Ok(prim.arity.clone())
    }
}
