/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::*;
use crate::primitive::{primitive_is_core, primitive_core_get, primitive_get};
use crate::principal::principal_get_name_from_id;
use crate::parser::parse_file;
use crate::sanity::sanity;

pub fn pretty_print(model_file: &str) -> Result<String, String> {
    let m = parse_file(model_file)?;
    pretty_model(&m)
}

pub fn pretty_constant(c: &Constant) -> String {
    if c.guard {
        return format!("[{}]", c.name);
    }
    if &*c.name == "g" {
        return "G".to_string();
    }
    c.name.to_string()
}

pub fn pretty_constants(c: &[Constant]) -> String {
    c.iter()
        .map(|v| pretty_constant(v))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn pretty_primitive(p: &Primitive) -> String {
    let name = if primitive_is_core(p.id) {
        primitive_core_get(p.id).map(|s| s.name.clone()).unwrap_or_default()
    } else {
        primitive_get(p.id).map(|s| s.name.clone()).unwrap_or_default()
    };
    let args: Vec<String> = p.arguments.iter().map(|a| pretty_value(a)).collect();
    let check_str = if p.check { "?" } else { "" };
    format!("{}({}){}", name, args.join(", "), check_str)
}

pub fn pretty_equation(e: &Equation) -> String {
    e.values.iter()
        .map(|v| pretty_value(v))
        .collect::<Vec<_>>()
        .join("^")
}

pub fn pretty_value(a: &Value) -> String {
    match a {
        Value::Constant(c) => pretty_constant(c),
        Value::Primitive(p) => pretty_primitive(p),
        Value::Equation(e) => pretty_equation(e),
    }
}

pub fn pretty_values(a: &[Value]) -> String {
    a.iter()
        .map(|v| pretty_value(v))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn pretty_query(query: &Query) -> String {
    let mut output = match query.kind {
        TypesEnum::Confidentiality => {
            format!("confidentiality? {}", pretty_constants(&query.constants))
        }
        TypesEnum::Authentication => {
            format!(
                "authentication? {} -> {}: {}",
                principal_get_name_from_id(query.message.sender),
                principal_get_name_from_id(query.message.recipient),
                pretty_constants(&query.message.constants),
            )
        }
        TypesEnum::Freshness => {
            format!("freshness? {}", pretty_constants(&query.constants))
        }
        TypesEnum::Unlinkability => {
            format!("unlinkability? {}", pretty_constants(&query.constants))
        }
        TypesEnum::Equivalence => {
            format!("equivalence? {}", pretty_constants(&query.constants))
        }
        _ => String::new(),
    };
    if !query.options.is_empty() {
        output.push('[');
        for option in &query.options {
            if option.kind == TypesEnum::Precondition {
                output.push_str(&format!(
                    "\n\t\tprecondition[{} -> {}: {}]",
                    principal_get_name_from_id(option.message.sender),
                    principal_get_name_from_id(option.message.recipient),
                    pretty_constants(&option.message.constants),
                ));
            }
        }
        output.push_str("\n\t]");
    }
    output
}

pub fn pretty_principal(block: &Block) -> String {
    let mut output = format!("principal {}[\n", block.principal.name);
    for expression in &block.principal.expressions {
        output.push_str(&format!("\t{}\n", pretty_expression(expression)));
    }
    output.push_str("]\n\n");
    output
}

pub fn pretty_expression(expression: &Expression) -> String {
    match expression.kind {
        TypesEnum::Knows => {
            let qualifier = match expression.qualifier {
                TypesEnum::Private => "private",
                TypesEnum::Public => "public",
                TypesEnum::Password => "password",
                _ => "private",
            };
            format!("knows {} {}", qualifier, pretty_constants(&expression.constants))
        }
        TypesEnum::Generates => {
            format!("generates {}", pretty_constants(&expression.constants))
        }
        TypesEnum::Leaks => {
            format!("leaks {}", pretty_constants(&expression.constants))
        }
        TypesEnum::Assignment => {
            let right = match &expression.assigned {
                Some(v) => pretty_value(v),
                None => String::new(),
            };
            let left: Vec<String> = expression.constants.iter().map(|c| {
                if c.name.starts_with("unnamed") {
                    "_".to_string()
                } else {
                    pretty_constant(c)
                }
            }).collect();
            format!("{} = {}", left.join(", "), right)
        }
        _ => String::new(),
    }
}

pub fn pretty_message(block: &Block) -> String {
    format!(
        "{} -> {}: {}",
        principal_get_name_from_id(block.message.sender),
        principal_get_name_from_id(block.message.recipient),
        pretty_constants(&block.message.constants),
    )
}

pub fn pretty_phase(block: &Block) -> String {
    format!("phase[{}]\n\n", block.phase.number)
}

pub fn pretty_model(m: &Model) -> Result<String, String> {
    sanity(m)?;
    let mut output = format!("attacker[{}]\n\n", m.attacker);
    for block in &m.blocks {
        match block.kind.as_str() {
            "principal" => output.push_str(&pretty_principal(block)),
            "message" => {
                output.push_str(&pretty_message(block));
                output.push_str("\n\n");
            }
            "phase" => output.push_str(&pretty_phase(block)),
            _ => {}
        }
    }
    output.push_str("queries[\n");
    for query in &m.queries {
        output.push_str(&format!("\t{}\n", pretty_query(query)));
    }
    output.push_str("]\n");
    Ok(output)
}

pub fn pretty_arity(spec_arity: &[i32]) -> String {
    if spec_arity.len() == 1 {
        return format!("{}", spec_arity[0]);
    }
    let mut parts = Vec::new();
    for (i, &a) in spec_arity.iter().enumerate() {
        if i != spec_arity.len() - 1 {
            parts.push(format!("{}, ", a));
        } else {
            parts.push(format!("or {}", a));
        }
    }
    parts.concat()
}
