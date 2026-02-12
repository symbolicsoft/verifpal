/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::parser::parse_file;
use crate::primitive::{primitive_core_get, primitive_get, primitive_is_core};
use crate::principal::principal_get_name_from_id;
use crate::sanity::sanity;
use crate::types::*;

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
	c.iter().map(pretty_constant).collect::<Vec<_>>().join(", ")
}

pub fn pretty_primitive(p: &Primitive) -> String {
	let name = if primitive_is_core(p.id) {
		primitive_core_get(p.id)
			.map(|s| s.name.clone())
			.unwrap_or_default()
	} else {
		primitive_get(p.id)
			.map(|s| s.name.clone())
			.unwrap_or_default()
	};
	let args: Vec<String> = p.arguments.iter().map(pretty_value).collect();
	let check_str = if p.check { "?" } else { "" };
	format!("{}({}){}", name, args.join(", "), check_str)
}

pub fn pretty_equation(e: &Equation) -> String {
	e.values
		.iter()
		.map(pretty_value)
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
	a.iter().map(pretty_value).collect::<Vec<_>>().join(", ")
}

pub fn pretty_query(query: &Query) -> String {
	let mut output = match query.kind {
		QueryKind::Confidentiality => {
			format!("confidentiality? {}", pretty_constants(&query.constants))
		}
		QueryKind::Authentication => {
			format!(
				"authentication? {} -> {}: {}",
				principal_get_name_from_id(query.message.sender),
				principal_get_name_from_id(query.message.recipient),
				pretty_constants(&query.message.constants),
			)
		}
		QueryKind::Freshness => {
			format!("freshness? {}", pretty_constants(&query.constants))
		}
		QueryKind::Unlinkability => {
			format!("unlinkability? {}", pretty_constants(&query.constants))
		}
		QueryKind::Equivalence => {
			format!("equivalence? {}", pretty_constants(&query.constants))
		}
	};
	if !query.options.is_empty() {
		output.push('[');
		for option in &query.options {
			match option.kind {
				QueryOptionKind::Precondition => {
					output.push_str(&format!(
						"\n\t\tprecondition[{} -> {}: {}]",
						principal_get_name_from_id(option.message.sender),
						principal_get_name_from_id(option.message.recipient),
						pretty_constants(&option.message.constants),
					));
				}
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
		Declaration::Knows => {
			let qualifier = match expression.qualifier {
				Some(Qualifier::Private) => "private",
				Some(Qualifier::Public) => "public",
				Some(Qualifier::Password) => "password",
				None => "private",
			};
			format!(
				"knows {} {}",
				qualifier,
				pretty_constants(&expression.constants)
			)
		}
		Declaration::Generates => {
			format!("generates {}", pretty_constants(&expression.constants))
		}
		Declaration::Leaks => {
			format!("leaks {}", pretty_constants(&expression.constants))
		}
		Declaration::Assignment => {
			let right = match &expression.assigned {
				Some(v) => pretty_value(v),
				None => String::new(),
			};
			let left: Vec<String> = expression
				.constants
				.iter()
				.map(|c| {
					if c.name.starts_with("unnamed") {
						"_".to_string()
					} else {
						pretty_constant(c)
					}
				})
				.collect();
			format!("{} = {}", left.join(", "), right)
		}
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
		match block.kind {
			BlockKind::Principal => output.push_str(&pretty_principal(block)),
			BlockKind::Message => {
				output.push_str(&pretty_message(block));
				output.push_str("\n\n");
			}
			BlockKind::Phase => output.push_str(&pretty_phase(block)),
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
