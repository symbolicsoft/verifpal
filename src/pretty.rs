/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::fmt;

use crate::parser::parse_file;
use crate::primitive::primitive_name;
use crate::sanity::sanity;
use crate::types::*;

pub fn pretty_print(model_file: &str) -> VResult<String> {
	let m = parse_file(model_file)?;
	pretty_model(&m).map_err(|e| e.located(&m.file_name, &m.source))
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

impl fmt::Display for Value {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Value::Constant(c) => write!(f, "{}", c),
			Value::Primitive(p) => write!(f, "{}", p),
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
					self.message.sender_name,
					self.message.recipient_name,
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
							option.message.sender_name,
							option.message.recipient_name,
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

fn render_comment(c: &Comment, indent: &str) -> String {
	match c.style {
		CommentStyle::Line => format!("//{}", c.text),
		CommentStyle::Block => {
			if !c.text.contains('\n') {
				format!("/*{}*/", c.text)
			} else {
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

fn render_trailing(comment: Option<&Comment>) -> String {
	match comment {
		Some(c) => format!(" {}", render_comment(c, "")),
		None => String::new(),
	}
}

pub(crate) fn pretty_constants(constants: &[Constant]) -> String {
	constants
		.iter()
		.map(|c| c.to_string())
		.collect::<Vec<_>>()
		.join(", ")
}

pub(crate) fn pretty_values(values: &[Value]) -> String {
	values
		.iter()
		.map(|v| v.to_string())
		.collect::<Vec<_>>()
		.join(", ")
}

pub(crate) fn pretty_principal(principal: &Principal) -> String {
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

pub(crate) fn pretty_message(message: &Message) -> String {
	format!(
		"{} -> {}: {}",
		message.sender_name,
		message.recipient_name,
		pretty_constants(&message.constants),
	)
}

pub(crate) fn pretty_model(m: &Model) -> VResult<String> {
	sanity(m)?;
	let mut output = String::new();

	if !m.pre_attacker_comments.is_empty() {
		output.push_str(&render_leading(&m.pre_attacker_comments, ""));
		output.push('\n');
	}

	output.push_str(&format!(
		"attacker[{}]{}\n\n",
		m.attacker,
		render_trailing(m.attacker_trailing.as_ref())
	));

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

	output.push_str(&render_leading(&m.queries_leading_comments, ""));
	output.push_str("queries[");
	output.push_str(&render_trailing(m.queries_header_trailing.as_ref()));
	output.push('\n');

	for query in &m.queries {
		output.push_str(&render_leading(&query.leading_comments, "\t"));
		output.push_str(&format!(
			"\t{}{}\n",
			query,
			render_trailing(query.trailing_comment.as_ref())
		));
	}

	output.push_str(&render_leading(&m.queries_tail_comments, "\t"));
	output.push(']');
	output.push_str(&render_trailing(m.queries_closing_trailing.as_ref()));
	output.push('\n');

	if !m.tail_comments.is_empty() {
		output.push('\n');
		for c in &m.tail_comments {
			output.push_str(&render_comment(c, ""));
			output.push('\n');
		}
	}

	Ok(output)
}

pub(crate) fn pretty_arity(spec_arity: &[i32]) -> String {
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::parser::parse_string;

	#[test]
	fn pretty_round_trips_dh_to_new_syntax() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private dsz_a\n\tknows private dsz_b\n\tdsz_ga = PUBKEY(dsz_a)\n\tdsz_k = DH_KEX(dsz_ga, dsz_b)\n]\n\nqueries[\n\tconfidentiality? dsz_k\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let once = pretty_model(&m).expect("pretty");
		let m2 = parse_string("t.vp", &once).expect("reparse");
		let twice = pretty_model(&m2).expect("pretty again");
		assert_eq!(once, twice);
		assert!(once.contains("dsz_ga = PUBKEY(dsz_a)"), "got: {}", once);
		assert!(
			once.contains("dsz_k = DH_KEX(dsz_ga, dsz_b)"),
			"got: {}",
			once
		);
		assert!(!once.contains('^'), "got: {}", once);
	}

	#[test]
	fn pretty_emits_pre_attacker_comments() {
		let src = "// hello\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(
			out.starts_with("// hello\n\nattacker[active]"),
			"got: {}",
			out
		);
	}

	#[test]
	fn pretty_emits_leading_on_block() {
		let src = "attacker[active]\n\n// before alice\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(
			out.contains("// before alice\nprincipal Alice["),
			"got: {}",
			out
		);
	}

	#[test]
	fn pretty_emits_trailing_on_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a // lt\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(out.contains("knows private a // lt"), "got: {}", out);
	}

	#[test]
	fn pretty_emits_block_comment_inline() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a /* lt */\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(out.contains("knows private a /* lt */"), "got: {}", out);
	}

	#[test]
	fn pretty_emits_block_comment_multiline() {
		let src = "/* line1\n   line2 */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(out.contains("/* line1"), "missing /* line1 in:\n{}", out);
		assert!(out.contains("line2 */"), "missing 'line2 */':\n{}", out);
	}

	fn assert_round_trip_idempotent(src: &str) {
		let m1 = parse_string("rt.vp", src).expect("parse 1");
		let s1 = pretty_model(&m1).expect("pretty 1");
		let m2 = parse_string("rt.vp", &s1).expect("parse 2");
		let s2 = pretty_model(&m2).expect("pretty 2");
		assert_eq!(
			s1, s2,
			"not idempotent\n--- s1 ---\n{}\n--- s2 ---\n{}",
			s1, s2
		);
	}

	#[test]
	fn round_trip_simple() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_pre_attacker_comment() {
		let src = "// SPDX header\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_leading_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\t// long-term\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_trailing_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a // long-term\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_leading_block() {
		let src = "attacker[active]\n\n// initiator\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_principal_tail() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n\t// TODO\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_block_comment_pre_attacker() {
		let src = "/* SPDX header */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_block_comment_multiline() {
		let src = "/* multi\n   line\n   header */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn block_comment_unterminated_errors_with_position() {
		let src = "/* never closed\nattacker[active]\n";
		let err = parse_string("t.vp", src).unwrap_err();
		let msg = err.to_string();
		assert!(msg.contains("unterminated block comment"), "got: {}", msg);
	}

	#[test]
	fn block_comment_nested_first_close_wins() {
		let src = "/* /* */ */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let result = parse_string("t.vp", src);
		assert!(result.is_err(), "expected parse error from stray */");
	}

	#[test]
	fn block_comment_multiline_in_leading_position_renders() {
		let src = "attacker[active]\n\n/* multi\n   line\n   header */\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert!(out.contains("/* multi"), "missing /* multi in:\n{}", out);
		assert!(out.contains("line"), "missing 'line':\n{}", out);
		assert!(out.contains("header */"), "missing 'header */':\n{}", out);
		let m2 = parse_string("t.vp", &out).expect("re-parse");
		match &m2.blocks[0] {
			Block::Principal(p) => {
				assert_eq!(p.leading_comments.len(), 1);
				assert!(matches!(p.leading_comments[0].style, CommentStyle::Block));
			}
			_ => panic!(),
		}
	}

	#[test]
	fn round_trip_message_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nAlice -> Bob: a // flight 1\n\nprincipal Bob[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_query_trailing_and_leading() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\t// primary goal\n\tconfidentiality? a // payload only\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_phase_with_leading_and_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\n// handshake done\nphase[1] // post-handshake\n\nprincipal Bob[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_principal_closing_and_header_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[ // header\n\tknows private a\n] // closing\n\nqueries[\n\tconfidentiality? a\n]\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_queries_header_and_closing_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[ // start\n\tconfidentiality? a\n] // end\n";
		assert_round_trip_idempotent(src);
	}

	#[test]
	fn round_trip_eof_tail() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n\n// EOF\n";
		assert_round_trip_idempotent(src);
	}

	fn assert_golden(input: &str, golden: &str) {
		let m = parse_string("g.vp", input).expect("parse");
		let out = pretty_model(&m).expect("pretty");
		assert_eq!(
			out, golden,
			"golden mismatch\n--- expected ---\n{}\n--- got ---\n{}",
			golden, out
		);
	}

	#[test]
	fn golden_aead_leak() {
		assert_golden(
			include_str!("../examples/test/aead_leak.vp"),
			include_str!("../examples/test/golden_pretty/aead_leak.vp"),
		);
	}

	#[test]
	fn golden_assert_junglegym() {
		assert_golden(
			include_str!("../examples/test/assert_junglegym.vp"),
			include_str!("../examples/test/golden_pretty/assert_junglegym.vp"),
		);
	}

	#[test]
	fn golden_auth_with_signing() {
		assert_golden(
			include_str!("../examples/test/auth_with_signing.vp"),
			include_str!("../examples/test/golden_pretty/auth_with_signing.vp"),
		);
	}

	#[test]
	fn golden_concat_bomb() {
		assert_golden(
			include_str!("../examples/test/concat_bomb.vp"),
			include_str!("../examples/test/golden_pretty/concat_bomb.vp"),
		);
	}

	#[test]
	fn golden_simple() {
		assert_golden(
			include_str!("../examples/simple.vp"),
			include_str!("../examples/test/golden_pretty/simple.vp"),
		);
	}
}
