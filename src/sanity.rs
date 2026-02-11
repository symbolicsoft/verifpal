/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::*;
use crate::value::*;
use crate::construct::*;
use crate::pretty::*;
use crate::principal::*;
use crate::primitive::*;
use crate::util::*;

pub fn sanity(m: &Model) -> Result<(KnowledgeMap, Vec<PrincipalState>), String> {
    sanity_phases(m)?;
    let (principals, principal_ids) = sanity_declared_principals(m)?;
    let km = construct_knowledge_map(m, &principals, &principal_ids)?;
    sanity_queries(m, &km)?;
    let ps = construct_principal_states(m, &km);
    Ok((km, ps))
}

fn sanity_phases(m: &Model) -> Result<(), String> {
    let mut phase = 0;
    for blck in &m.blocks {
        if blck.kind == "phase" {
            if blck.phase.number <= phase {
                return Err(format!("phase being declared ({}) must be superior to last declared phase ({})",
                    blck.phase.number, phase));
            }
            if blck.phase.number != phase + 1 {
                return Err(format!("phase being declared ({}) skips phases since last declared phase ({})",
                    blck.phase.number, phase));
            }
            phase = blck.phase.number;
        }
    }
    Ok(())
}

#[allow(clippy::only_used_in_recursion)]
pub fn sanity_assignment_constants(
    right: &Value, existing: &[Constant], km: &KnowledgeMap,
) -> Result<Vec<Constant>, String> {
    let mut constants: Vec<Constant> = existing.to_vec();
    match right {
        Value::Constant(c) => {
            if !constants.iter().any(|x| value_equivalent_constants(c, x)) {
                constants.push(c.clone());
            }
        }
        Value::Primitive(p) => {
            let arity = primitive_get_arity(p)?;
            let n = p.arguments.len() as i32;
            if n == 0 { return Err("primitive has no inputs".to_string()); }
            if !arity.contains(&n) {
                return Err(format!("primitive has {} inputs, expecting {}", n, pretty_arity(&arity)));
            }
            for a in &p.arguments {
                constants = sanity_assignment_constants(a, &constants, km)?;
            }
        }
        Value::Equation(e) => {
            for v in &e.values {
                if let Value::Constant(c) = v {
                    if !constants.iter().any(|x| value_equivalent_constants(c, x)) {
                        constants.push(c.clone());
                    }
                }
            }
        }
    }
    Ok(constants)
}

pub fn sanity_primitive(p: &Primitive, outputs: &[Constant]) -> Result<(), String> {
    let (output, check) = if primitive_is_core(p.id) {
        let prim = primitive_core_get(p.id)?;
        (prim.output.clone(), prim.check)
    } else {
        let prim = primitive_get(p.id)?;
        (prim.output.clone(), prim.check)
    };
    if !output.contains(&(outputs.len() as i32)) {
        return Err(format!("primitive has {} outputs, expecting {}", outputs.len(), pretty_arity(&output)));
    }
    if p.check && !check {
        return Err("primitive is checked but does not support checking".to_string());
    }
    sanity_check_primitive_argument_outputs(p)
}

fn sanity_queries(m: &Model, km: &KnowledgeMap) -> Result<(), String> {
    for query in &m.queries {
        match query.kind {
            TypesEnum::Confidentiality => sanity_queries_confidentiality(query, km)?,
            TypesEnum::Authentication => sanity_queries_authentication(query, km)?,
            TypesEnum::Freshness => sanity_queries_freshness(query, km)?,
            TypesEnum::Unlinkability => sanity_queries_unlinkability(query, km)?,
            TypesEnum::Equivalence => sanity_queries_equivalence(query, km)?,
            _ => return Err("invalid query kind".to_string()),
        }
        sanity_query_options(query, km)?;
    }
    Ok(())
}

fn sanity_queries_confidentiality(query: &Query, km: &KnowledgeMap) -> Result<(), String> {
    let i = value_get_knowledge_map_index_from_constant(km, &query.constants[0]);
    if i.is_none() {
        return Err(format!("confidentiality query ({}) refers to unknown constant ({})",
            pretty_query(query), pretty_constant(&query.constants[0])));
    }
    Ok(())
}

fn sanity_queries_authentication(query: &Query, km: &KnowledgeMap) -> Result<(), String> {
    let i = value_get_knowledge_map_index_from_constant(km, &query.message.constants[0]);
    if i.is_none() {
        return Err(format!("authentication query ({}) refers to unknown constant ({})",
            pretty_query(query), pretty_constant(&query.message.constants[0])));
    }
    if query.message.constants.len() != 1 {
        return Err(format!("authentication query ({}) has more than one constant", pretty_query(query)));
    }
    let c = &query.message.constants[0];
    sanity_queries_check_message_principals(&query.message)?;
    sanity_queries_check_known(query, &query.message, c, km)
}

fn sanity_queries_freshness(query: &Query, km: &KnowledgeMap) -> Result<(), String> {
    let i = value_get_knowledge_map_index_from_constant(km, &query.constants[0]);
    if i.is_none() {
        return Err(format!("freshness query ({}) refers to unknown constant ({})",
            pretty_query(query), pretty_constant(&query.constants[0])));
    }
    Ok(())
}

fn sanity_queries_unlinkability(query: &Query, km: &KnowledgeMap) -> Result<(), String> {
    if query.constants.len() < 2 {
        return Err(format!("unlinkability query ({}) must specify at least two constants", pretty_query(query)));
    }
    for (i, c) in query.constants.iter().enumerate() {
        if value_get_knowledge_map_index_from_constant(km, c).is_none() {
            return Err(format!("unlinkability query ({}) refers to unknown constant ({})",
                pretty_query(query), pretty_constant(c)));
        }
        if value_equivalent_constant_in_constants(c, &query.constants[..i]) >= 0 {
            return Err(format!("unlinkability query ({}) refers to same constant more than once ({})",
                pretty_query(query), pretty_constant(c)));
        }
    }
    Ok(())
}

fn sanity_queries_equivalence(query: &Query, km: &KnowledgeMap) -> Result<(), String> {
    if query.constants.len() < 2 {
        return Err(format!("equivalence query ({}) must specify at least two constants", pretty_query(query)));
    }
    for (i, c) in query.constants.iter().enumerate() {
        if value_get_knowledge_map_index_from_constant(km, c).is_none() {
            return Err(format!("equivalence query ({}) refers to unknown constant ({})",
                pretty_query(query), pretty_constant(c)));
        }
        if value_equivalent_constant_in_constants(c, &query.constants[..i]) >= 0 {
            return Err(format!("equivalence query ({}) refers to same constant more than once ({})",
                pretty_query(query), pretty_constant(c)));
        }
    }
    Ok(())
}

fn sanity_query_options(query: &Query, km: &KnowledgeMap) -> Result<(), String> {
    for option in &query.options {
        match option.kind {
            TypesEnum::Precondition => {
                if option.message.constants.len() != 1 {
                    return Err(format!("precondition option message ({}) has more than one constant", pretty_query(query)));
                }
                let c = &option.message.constants[0];
                sanity_queries_check_message_principals(&option.message)?;
                sanity_queries_check_known(query, &option.message, c, km)?;
            }
            _ => return Err("invalid query option kind".to_string()),
        }
    }
    Ok(())
}

fn sanity_queries_check_message_principals(message: &Message) -> Result<(), String> {
    if message.sender == message.recipient {
        return Err(format!("query with message ({} -> {}: {}) has identical sender and recipient",
            principal_get_name_from_id(message.sender),
            principal_get_name_from_id(message.recipient),
            pretty_constants(&message.constants)));
    }
    Ok(())
}

fn sanity_queries_check_known(query: &Query, m: &Message, c: &Constant, km: &KnowledgeMap) -> Result<(), String> {
    let i = value_get_knowledge_map_index_from_constant(km, &m.constants[0]);
    if i.is_none() {
        return Err(format!("query ({}) refers to unknown constant ({})",
            pretty_query(query), pretty_constant(&m.constants[0])));
    }
    let idx = i.expect("constant exists in knowledge map");
    let mut sender_knows = km.creator[idx] == m.sender;
    let mut recipient_knows = km.creator[idx] == m.recipient;
    for kb in &km.known_by[idx] {
        if kb.contains_key(&m.sender) { sender_knows = true; }
        if kb.contains_key(&m.recipient) { recipient_knows = true; }
    }
    let used = value_constant_is_used_by_principal_in_knowledge_map(km, m.recipient, &m.constants[0]);
    if !sender_knows {
        return Err(format!("authentication query ({}) depends on {} sending a constant ({}) that they do not know",
            pretty_query(query), principal_get_name_from_id(m.sender), pretty_constant(c)));
    }
    if !recipient_knows {
        return Err(format!("authentication query ({}) depends on {} receiving a constant ({}) that they never receive",
            pretty_query(query), principal_get_name_from_id(m.recipient), pretty_constant(c)));
    }
    if !used {
        return Err(format!("authentication query ({}) depends on {} using a constant ({}) in a primitive, but this never happens",
            pretty_query(query), principal_get_name_from_id(m.recipient), pretty_constant(c)));
    }
    Ok(())
}

fn sanity_declared_principals(m: &Model) -> Result<(Vec<String>, Vec<PrincipalId>), String> {
    let mut declared_names: Vec<String> = vec![];
    let mut declared_ids: Vec<PrincipalId> = vec![];
    let mut principals: Vec<PrincipalId> = vec![];
    for block in &m.blocks {
        if block.kind == "principal" {
            append_unique_principal_enum(&mut principals, block.principal.id);
            append_unique_string(&mut declared_names, block.principal.name.clone());
            append_unique_principal_enum(&mut declared_ids, block.principal.id);
        }
    }
    for block in &m.blocks {
        if block.kind == "message" {
            append_unique_principal_enum(&mut principals, block.message.sender);
            append_unique_principal_enum(&mut principals, block.message.recipient);
        }
    }
    for query in &m.queries {
        if query.kind == TypesEnum::Authentication {
            append_unique_principal_enum(&mut principals, query.message.sender);
            append_unique_principal_enum(&mut principals, query.message.recipient);
        }
    }
    for &p in &principals {
        if !principal_enum_in_slice(p, &declared_ids) {
            return Err("principal does not exist".to_string());
        }
    }
    if declared_names.len() > 64 {
        return Err(format!("more than 64 principals ({}) declared", declared_names.len()));
    }
    Ok((declared_names, declared_ids))
}

pub fn sanity_fail_on_failed_checked_primitive_rewrite(failed_rewrites: &[Primitive]) -> Result<(), String> {
    for p in failed_rewrites {
        if p.check {
            return Err(format!("checked primitive fails: {}", pretty_primitive(p)));
        }
    }
    Ok(())
}

fn sanity_check_primitive_argument_outputs(p: &Primitive) -> Result<(), String> {
    for arg in &p.arguments {
        if let Value::Primitive(arg_prim) = arg {
            let output = if primitive_is_core(arg_prim.id) {
                primitive_core_get(arg_prim.id)?.output.clone()
            } else {
                primitive_get(arg_prim.id)?.output.clone()
            };
            if !output.contains(&1) {
                return Err(format!("primitive {} cannot have {} as an argument, since {} necessarily produces more than one output",
                    pretty_primitive(p), pretty_primitive(arg_prim), pretty_primitive(arg_prim)));
            }
        }
    }
    Ok(())
}

pub fn sanity_check_equation_root_generator(e: &Equation) -> Result<(), String> {
    if e.values.len() > 3 {
        return Err(format!("too many layers in equation ({}), maximum is 2", pretty_equation(e)));
    }
    for (i, c) in e.values.iter().enumerate() {
        if let Value::Constant(con) = c {
            if i == 0 && con.id != value_g().as_constant().expect("g is Constant").id {
                return Err(format!("equation ({}) does not use 'g' as generator", pretty_equation(e)));
            }
            if i > 0 && value_equivalent_constants(con, value_g().as_constant().expect("g is Constant")) {
                return Err(format!("equation ({}) uses 'g' not as a generator", pretty_equation(e)));
            }
        }
    }
    Ok(())
}

pub fn sanity_check_equation_generators(a: &Value) -> Result<(), String> {
    match a {
        Value::Primitive(p) => {
            for va in &p.arguments {
                match va {
                    Value::Primitive(_) => sanity_check_equation_generators(va)?,
                    Value::Equation(e) => sanity_check_equation_root_generator(e)?,
                    _ => {}
                }
            }
        }
        Value::Equation(e) => {
            sanity_check_equation_root_generator(e)?;
        }
        _ => {}
    }
    Ok(())
}
