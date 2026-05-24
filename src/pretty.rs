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

/// Render a single comment without surrounding context.
/// For a Line comment: returns "// <text>".
/// For a single-line Block comment: returns "/* <text> */".
/// For a multi-line Block comment: returns "/* <text> */" with original
/// line breaks preserved; continuation lines are re-indented to align
/// after the opening "/* ".
fn render_comment(c: &Comment, indent: &str) -> String {
	match c.style {
		CommentStyle::Line => format!("//{}", c.text),
		CommentStyle::Block => {
			if !c.text.contains('\n') {
				format!("/*{}*/", c.text)
			} else {
				// Re-indent continuation lines.
				let cont_indent: String = format!("{}   ", indent);
				let mut out = String::from("/*");
				for (i, line) in c.text.split('\n').enumerate() {
					if i == 0 {
						out.push_str(line);
					} else {
						out.push('\n');
						out.push_str(&cont_indent);
						out.push_str(line.trim_start());
					}
				}
				out.push_str("*/");
				out
			}
		}
	}
}

/// Render a slice of leading comments, each on its own line at the
/// given indent. Returns "" if the slice is empty.
fn render_leading(comments: &[Comment], indent: &str) -> String {
	if comments.is_empty() {
		return String::new();
	}
	let mut s = String::new();
	for c in comments {
		s.push_str(indent);
		s.push_str(&render_comment(c, indent));
		s.push('\n');
	}
	s
}

/// Render a trailing comment with one leading space. Returns "" if None.
fn render_trailing(comment: Option<&Comment>) -> String {
	match comment {
		Some(c) => format!(" {}", render_comment(c, "")),
		None => String::new(),
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
	let mut output = format!("principal {}[", principal.name);
	output.push_str(&render_trailing(principal.header_trailing.as_ref()));
	output.push('\n');
	for expression in &principal.expressions {
		output.push_str(&render_leading(&expression.leading_comments, "\t"));
		output.push_str(&format!(
			"\t{}{}\n",
			expression,
			render_trailing(expression.trailing_comment.as_ref())
		));
	}
	output.push_str(&render_leading(&principal.tail_comments, "\t"));
	output.push(']');
	output.push_str(&render_trailing(principal.closing_trailing.as_ref()));
	output.push_str("\n\n");
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

pub fn pretty_model(m: &Model) -> VResult<String> {
	sanity(m)?;
	let mut output = String::new();

	// 1. pre-attacker header comments
	if !m.pre_attacker_comments.is_empty() {
		output.push_str(&render_leading(&m.pre_attacker_comments, ""));
		output.push('\n');
	}

	// 2-3. attacker line (with optional trailing) + blank line
	output.push_str(&format!(
		"attacker[{}]{}\n\n",
		m.attacker,
		render_trailing(m.attacker_trailing.as_ref())
	));

	// 4. each block: leading_comments (no indent) + block + \n\n
	for block in &m.blocks {
		match block {
			Block::Principal(p) => {
				output.push_str(&render_leading(&p.leading_comments, ""));
				output.push_str(&pretty_principal(p));
			}
			Block::Message(msg) => {
				output.push_str(&render_leading(&msg.leading_comments, ""));
				output.push_str(&pretty_message(msg));
				output.push_str(&render_trailing(msg.trailing_comment.as_ref()));
				output.push_str("\n\n");
			}
			Block::Phase(ph) => {
				output.push_str(&render_leading(&ph.leading_comments, ""));
				output.push_str(&format!(
					"phase[{}]{}\n\n",
					ph.number,
					render_trailing(ph.trailing_comment.as_ref())
				));
			}
		}
	}

	// 5-6. queries leading + header line + optional header trailing
	output.push_str(&render_leading(&m.queries_leading_comments, ""));
	output.push_str("queries[");
	output.push_str(&render_trailing(m.queries_header_trailing.as_ref()));
	output.push('\n');

	// 7. each query: leading + query + optional trailing
	for query in &m.queries {
		output.push_str(&render_leading(&query.leading_comments, "\t"));
		output.push_str(&format!(
			"\t{}{}\n",
			query,
			render_trailing(query.trailing_comment.as_ref())
		));
	}

	// 8-9. queries tail comments + closing ] + optional closing trailing
	output.push_str(&render_leading(&m.queries_tail_comments, "\t"));
	output.push(']');
	output.push_str(&render_trailing(m.queries_closing_trailing.as_ref()));
	output.push('\n');

	// 10. EOF tail comments — blank line then one comment per line
	if !m.tail_comments.is_empty() {
		output.push('\n');
		for c in &m.tail_comments {
			output.push_str(&render_comment(c, ""));
			output.push('\n');
		}
	}

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
