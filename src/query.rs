/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::types::*;
use crate::value::*;
use crate::possible::*;
use crate::info::*;
use crate::pretty::*;
use crate::principal::*;
use crate::primitive::*;
use crate::verifyresults::verify_results_put_write;
use crate::attackerstate::attacker_state_get_read;

pub fn query_start(
    query: &Query, query_index: usize, km: &KnowledgeMap, ps: &PrincipalState,
) -> Result<(), String> {
    let as_ = attacker_state_get_read();
    match query.kind {
        TypesEnum::Confidentiality => { query_confidentiality(query, query_index, km, ps, &as_); }
        TypesEnum::Authentication => { query_authentication(query, query_index, km, ps, &as_); }
        TypesEnum::Freshness => { query_freshness(query, query_index, km, ps, &as_)?; }
        TypesEnum::Unlinkability => { query_unlinkability(query, query_index, km, ps, &as_)?; }
        TypesEnum::Equivalence => { query_equivalence(query, query_index, km, ps, &as_); }
        _ => {}
    }
    Ok(())
}

fn query_confidentiality(
    query: &Query, query_index: usize, km: &KnowledgeMap, ps: &PrincipalState, as_: &AttackerState,
) -> VerifyResult {
    let mut result = VerifyResult {
        query: query.clone(), query_index, resolved: false, summary: String::new(), options: vec![],
    };
    let i = match value_get_principal_state_index_from_constant(ps, &query.constants[0]) {
        Some(idx) => idx,
        None => return result,
    };
    let resolved_value = &ps.assigned[i];
    let ii = value_equivalent_value_in_values_map(resolved_value, &as_.known, &as_.known_map);
    if ii < 0 { return result; }
    let mutated_info = info_query_mutated_values(
        km, &as_.principal_state[ii as usize], as_, resolved_value, 0,
    );
    result.resolved = true;
    result.summary = info_verify_result_summary(&mutated_info, &format!(
        "{} ({}) is obtained by Attacker.",
        pretty_constant(&query.constants[0]),
        pretty_value(&as_.known[ii as usize]),
    ), &result.options);
    result = query_precondition(result, ps);
    let written = verify_results_put_write(&result);
    if written {
        info_message(&format!("{}{}", pretty_query(&query), result.summary), "result", true);
    }
    result
}

fn query_authentication(
    query: &Query, query_index: usize, km: &KnowledgeMap, ps: &PrincipalState, as_: &AttackerState,
) -> VerifyResult {
    let mut result = VerifyResult {
        query: query.clone(), query_index, resolved: false, summary: String::new(), options: vec![],
    };
    if query.message.recipient != ps.id { return result; }
    let (indices, sender, c) = query_authentication_get_pass_indices(query, km, ps);
    for &index in &indices {
        if query.message.sender == sender { continue; }
        result.resolved = true;
        let a = &ps.assigned[index];
        let b = &ps.before_rewrite[index];
        let mutated_info = info_query_mutated_values(km, ps, as_, a, 0);
        result = query_precondition(result, ps);
        return query_authentication_handle_pass(result, &c, b, &mutated_info, sender, ps);
    }
    result
}

fn query_authentication_get_pass_indices(
    query: &Query, km: &KnowledgeMap, ps: &PrincipalState,
) -> (Vec<usize>, PrincipalId, Constant) {
    let empty_c = Constant { name: Arc::from(""), id: 0, guard: false, fresh: false, leaked: false, declaration: TypesEnum::Empty, qualifier: TypesEnum::Empty };
    let mut indices = Vec::new();
    let (_, i) = value_resolve_constant(&query.message.constants[0], ps, true);
    if i < 0 { return (indices, 0, empty_c); }
    let idx = i as usize;
    let c = km.constants[idx].clone();
    let sender = ps.sender[idx];
    if sender == principal_get_attacker_id() {
        let v = &ps.before_mutate[idx];
        if value_equivalent_values(v, &ps.assigned[idx], true) {
            return (indices, sender, c);
        }
    }
    for iii in 0..km.constants.len() {
        if km.creator[iii] != ps.id { continue; }
        let a = &km.assigned[iii];
        match a {
            Value::Constant(_) | Value::Equation(_) => continue,
            _ => {}
        }
        if !value_find_constant_in_primitive_from_knowledge_map(&c, a, km) { continue; }
        let (_, iiii) = value_resolve_constant(&km.constants[iii], ps, true);
        if iiii < 0 { return (indices, sender, c); }
        let iiii_idx = iiii as usize;
        let b = &ps.before_rewrite[iiii_idx];
        let b_prim = match b { Value::Primitive(p) => p, _ => continue };
        let mut has_rule = false;
        if primitive_is_core(b_prim.id) {
            if let Ok(prim) = primitive_core_get(b_prim.id) { has_rule = prim.has_rule; }
        } else {
            if let Ok(prim) = primitive_get(b_prim.id) { has_rule = prim.rewrite.has_rule; }
        }
        if !has_rule {
            indices.push(iiii_idx);
            continue;
        }
        let (pass, _) = possible_to_rewrite(b_prim, ps, 0);
        if pass || !b_prim.check {
            indices.push(iiii_idx);
        }
    }
    (indices, sender, c)
}

fn query_authentication_handle_pass(
    mut result: VerifyResult, c: &Constant, b: &Value, mutated_info: &str,
    sender: PrincipalId, ps: &PrincipalState,
) -> VerifyResult {
    let (cc, _) = value_resolve_constant(c, ps, true);
    result.summary = info_verify_result_summary(mutated_info, &format!(
        "{} ({}), sent by {} and not by {}, is successfully used in {} within {}'s state.",
        pretty_constant(c), pretty_value(&cc),
        principal_get_name_from_id(sender),
        principal_get_name_from_id(result.query.message.sender),
        pretty_value(b),
        principal_get_name_from_id(result.query.message.recipient),
    ), &result.options);
    let written = verify_results_put_write(&result);
    if written {
        info_message(&format!("{}{}", pretty_query(&result.query), result.summary), "result", true);
    }
    result
}

fn query_freshness(
    query: &Query, query_index: usize, km: &KnowledgeMap, ps: &PrincipalState, as_: &AttackerState,
) -> Result<VerifyResult, String> {
    let mut result = VerifyResult {
        query: query.clone(), query_index, resolved: false, summary: String::new(), options: vec![],
    };
    let mut indices = Vec::new();
    let freshness_found = value_constant_contains_fresh_values(&query.constants[0], ps)?;
    if freshness_found { return Ok(result); }
    for i in 0..km.constants.len() {
        if km.creator[i] != ps.id { continue; }
        let a = &km.assigned[i];
        match a { Value::Constant(_) | Value::Equation(_) => continue, _ => {} }
        if !value_find_constant_in_primitive_from_knowledge_map(&query.constants[0], a, km) { continue; }
        let (_, ii) = value_resolve_constant(&km.constants[i], ps, true);
        if ii < 0 { return Ok(result); }
        let ii_idx = ii as usize;
        let b = &ps.before_rewrite[ii_idx];
        let b_prim = match b { Value::Primitive(p) => p, _ => continue };
        let mut has_rule = false;
        if primitive_is_core(b_prim.id) {
            if let Ok(prim) = primitive_core_get(b_prim.id) { has_rule = prim.has_rule; }
        } else {
            if let Ok(prim) = primitive_get(b_prim.id) { has_rule = prim.rewrite.has_rule; }
        }
        if !has_rule { indices.push(ii_idx); continue; }
        let (pass, _) = possible_to_rewrite(b_prim, ps, 0);
        if pass || !b_prim.check { indices.push(ii_idx); }
    }
    if indices.is_empty() { return Ok(result); }
    let (resolved, _) = value_resolve_constant(&query.constants[0], ps, true);
    let mutated_info = info_query_mutated_values(km, ps, as_, &resolved, 0);
    result.resolved = true;
    result.summary = info_verify_result_summary(&mutated_info, &format!(
        "{} ({}) is used by {} in {} despite not being a fresh value.",
        pretty_constant(&query.constants[0]), pretty_value(&resolved),
        ps.name, pretty_value(&ps.before_rewrite[indices[0]]),
    ), &result.options);
    result = query_precondition(result, ps);
    let written = verify_results_put_write(&result);
    if written {
        info_message(&format!("{}{}", pretty_query(&query), result.summary), "result", true);
    }
    Ok(result)
}

fn query_unlinkability(
    query: &Query, query_index: usize, km: &KnowledgeMap, ps: &PrincipalState, as_: &AttackerState,
) -> Result<VerifyResult, String> {
    let mut result = VerifyResult {
        query: query.clone(), query_index, resolved: false, summary: String::new(), options: vec![],
    };
    let mut no_freshness = Vec::new();
    for c in &query.constants {
        let found = value_constant_contains_fresh_values(c, ps)?;
        if !found { no_freshness.push(c.clone()); }
    }
    if !no_freshness.is_empty() {
        let (resolved, _) = value_resolve_constant(&no_freshness[0], ps, true);
        let mutated_info = info_query_mutated_values(km, ps, as_, &resolved, 0);
        result.resolved = true;
        result.summary = info_verify_result_summary(&mutated_info, &format!(
            "{} ({}) cannot be a suitable unlinkability candidate since it does not satisfy freshness.",
            pretty_constant(&no_freshness[0]), pretty_value(&resolved),
        ), &result.options);
        result = query_precondition(result, ps);
        let written = verify_results_put_write(&result);
        if written {
            info_message(&format!("{}{}", pretty_query(&query), result.summary), "result", true);
        }
        return Ok(result);
    }
    let mut assigneds = Vec::new();
    for c in &query.constants {
        let (v, _) = value_resolve_constant(c, ps, true);
        assigneds.push(v);
    }
    for i in 0..assigneds.len() {
        for ii in 0..assigneds.len() {
            if i == ii { continue; }
            if !value_equivalent_values(&assigneds[i], &assigneds[ii], false) { continue; }
            let mut obtainable = false;
            if let Value::Primitive(p) = &assigneds[i] {
                let (ok0, _) = possible_to_reconstruct_primitive(p, ps, as_, 0);
                let (ok1, _, _) = possible_to_recompose_primitive(p, as_);
                obtainable = ok0 || ok1;
            }
            if !obtainable { continue; }
            let empty = Value::Constant(Constant { name: Arc::from(""), id: 0, guard: false, fresh: false, leaked: false, declaration: TypesEnum::Empty, qualifier: TypesEnum::Empty });
            let mutated_info = info_query_mutated_values(km, ps, as_, &empty, 0);
            result.resolved = true;
            result.summary = info_verify_result_summary(&mutated_info, &format!(
                "{} and {} are not unlinkable since they are the output of the same primitive ({}), which can be obtained by Attacker",
                pretty_constant(&query.constants[i]), pretty_constant(&query.constants[ii]),
                pretty_value(&assigneds[i]),
            ), &result.options);
            result = query_precondition(result, ps);
            let written = verify_results_put_write(&result);
            if written {
                info_message(&format!("{}{}", pretty_query(&query), result.summary), "result", true);
            }
            return Ok(result);
        }
    }
    Ok(result)
}

fn query_equivalence(
    query: &Query, query_index: usize, km: &KnowledgeMap, ps: &PrincipalState, as_: &AttackerState,
) -> VerifyResult {
    let mut result = VerifyResult {
        query: query.clone(), query_index, resolved: false, summary: String::new(), options: vec![],
    };
    let values: Vec<Value> = query.constants.iter()
        .map(|c| value_resolve_constant(c, ps, false).0)
        .collect();
    let mut broken = false;
    'outer: for (i, v) in values.iter().enumerate() {
        for (ii, vv) in values.iter().enumerate() {
            if i == ii { continue; }
            if !value_equivalent_values(v, vv, true) {
                broken = true;
                break 'outer;
            }
        }
    }
    if !broken { return result; }
    let empty = Value::Constant(Constant { name: Arc::from(""), id: 0, guard: false, fresh: false, leaked: false, declaration: TypesEnum::Empty, qualifier: TypesEnum::Empty });
    let mutated_info = info_query_mutated_values(km, ps, as_, &empty, 0);
    result.resolved = true;
    result.summary = info_verify_result_summary(&mutated_info, &format!(
        "{} are not equivalent.", pretty_values(&values),
    ), &result.options);
    result = query_precondition(result, ps);
    let written = verify_results_put_write(&result);
    if written {
        info_message(&format!("{}{}", pretty_query(&query), result.summary), "result", true);
    }
    result
}

fn query_precondition(mut result: VerifyResult, ps: &PrincipalState) -> VerifyResult {
    if !result.resolved { return result; }
    for option in &result.query.options {
        let mut o_result = QueryOptionResult {
            resolved: false, summary: String::new(),
        };
        let (_, i) = value_resolve_constant(&option.message.constants[0], ps, true);
        if i < 0 {
            result.options.push(o_result);
            continue;
        }
        let idx = i as usize;
        let mut sender = 0;
        let mut recipient_knows = false;
        for m in &ps.known_by[idx] {
            if let Some(&s) = m.get(&option.message.recipient) {
                sender = s;
                recipient_knows = true;
                break;
            }
        }
        if sender == option.message.sender && recipient_knows {
            o_result.resolved = true;
            o_result.summary = format!(
                "{} sends {} to {} despite the query failing.",
                principal_get_name_from_id(option.message.sender),
                pretty_constant(&option.message.constants[0]),
                principal_get_name_from_id(option.message.recipient),
            );
        }
        result.options.push(o_result);
    }
    result
}
