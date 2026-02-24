/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::fmt;

use crate::parser::parse_file;
use crate::primitive::primitive_name;
use crate::principal::principal_get_name_from_id;
use crate::sanity::sanity;
use crate::types::*;

pub fn pretty_print(model_file: &str) -> VResult<String> {
	let m = parse_file(model_file)?;
	pretty_model(&m)
}

impl fmt::Display for Constant {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		if self.guard {
			return write!(f, "[{}]", self.name);
		}
		if &*self.name == "g" {
			return write!(f, "G");
		}
		write!(f, "{}", self.name)
	}
}

impl fmt::Display for Primitive {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let name = primitive_name(self.id);
		write!(f, "{}(", name)?;
		for (i, arg) in self.arguments.iter().enumerate() {
			if i > 0 {
				write!(f, ", ")?;
			}
			write!(f, "{}", arg)?;
		}
		write!(f, ")")?;
		if self.instance_check {
			write!(f, "?")?;
		}
		Ok(())
	}
}

impl fmt::Display for Equation {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		for (i, v) in self.values.iter().enumerate() {
			if i > 0 {
				write!(f, "^")?;
			}
			write!(f, "{}", v)?;
		}
		Ok(())
	}
}

impl fmt::Display for Value {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Value::Constant(c) => write!(f, "{}", c),
			Value::Primitive(p) => write!(f, "{}", p),
			Value::Equation(e) => write!(f, "{}", e),
		}
	}
}

impl fmt::Display for Query {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self.kind {
			QueryKind::Authentication => {
				write!(
					f,
					"authentication? {} -> {}: {}",
					principal_get_name_from_id(self.message.sender),
					principal_get_name_from_id(self.message.recipient),
					pretty_constants(&self.message.constants),
				)?;
			}
			_ => {
				write!(
					f,
					"{}? {}",
					self.kind.name(),
					pretty_constants(&self.constants)
				)?;
			}
		}
		if !self.options.is_empty() {
			write!(f, "[")?;
			for option in &self.options {
				match option.kind {
					QueryOptionKind::Precondition => {
						write!(
							f,
							"\n\t\tprecondition[{} -> {}: {}]",
							principal_get_name_from_id(option.message.sender),
							principal_get_name_from_id(option.message.recipient),
							pretty_constants(&option.message.constants),
						)?;
					}
				}
			}
			write!(f, "\n\t]")?;
		}
		Ok(())
	}
}

impl fmt::Display for Expression {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self.kind {
			Declaration::Knows => {
				let qualifier = self.qualifier.unwrap_or(Qualifier::Private);
				write!(
					f,
					"knows {} {}",
					qualifier,
					pretty_constants(&self.constants)
				)
			}
			Declaration::Generates => {
				write!(f, "generates {}", pretty_constants(&self.constants))
			}
			Declaration::Leaks => {
				write!(f, "leaks {}", pretty_constants(&self.constants))
			}
			Declaration::Assignment => {
				let right = match &self.assigned {
					Some(v) => v.to_string(),
					None => String::new(),
				};
				let left: Vec<String> = self
					.constants
					.iter()
					.map(|c| {
						if c.name.starts_with("unnamed") {
							"_".to_string()
						} else {
							c.to_string()
						}
					})
					.collect();
				write!(f, "{} = {}", left.join(", "), right)
			}
		}
	}
}

pub fn pretty_constants(constants: &[Constant]) -> String {
	constants
		.iter()
		.map(|c| c.to_string())
		.collect::<Vec<_>>()
		.join(", ")
}

pub fn pretty_values(values: &[Value]) -> String {
	values
		.iter()
		.map(|v| v.to_string())
		.collect::<Vec<_>>()
		.join(", ")
}

pub fn pretty_principal(principal: &Principal) -> String {
	let mut output = format!("principal {}[\n", principal.name);
	for expression in &principal.expressions {
		output.push_str(&format!("\t{}\n", expression));
	}
	output.push_str("]\n\n");
	output
}

pub fn pretty_message(message: &Message) -> String {
	format!(
		"{} -> {}: {}",
		principal_get_name_from_id(message.sender),
		principal_get_name_from_id(message.recipient),
		pretty_constants(&message.constants),
	)
}

pub fn pretty_phase(phase: &Phase) -> String {
	format!("phase[{}]\n\n", phase.number)
}

pub fn pretty_model(m: &Model) -> VResult<String> {
	sanity(m)?;
	let mut output = format!("attacker[{}]\n\n", m.attacker);
	for block in &m.blocks {
		match block {
			Block::Principal(p) => output.push_str(&pretty_principal(p)),
			Block::Message(msg) => {
				output.push_str(&pretty_message(msg));
				output.push_str("\n\n");
			}
			Block::Phase(phase) => output.push_str(&pretty_phase(phase)),
		}
	}
	output.push_str("queries[\n");
	for query in &m.queries {
		output.push_str(&format!("\t{}\n", query));
	}
	output.push_str("]\n");
	Ok(output)
}

pub fn pretty_arity(spec_arity: &[i32]) -> String {
	match spec_arity.len() {
		0 => String::new(),
		1 => spec_arity[0].to_string(),
		_ => {
			let (init, last) = spec_arity.split_at(spec_arity.len() - 1);
			let init_str: Vec<String> = init.iter().map(|n| n.to_string()).collect();
			format!("{}, or {}", init_str.join(", "), last[0])
		}
	}
}
