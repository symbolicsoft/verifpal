/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::fmt;

use crate::parser::parse_file;
use crate::primitive::{primitive_name, primitive_threshold};
use crate::types::*;

pub fn pretty_print(model_file: &str) -> VResult<String> {
	Ok(pretty_model(&parse_file(model_file)?))
}

impl fmt::Display for Constant {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		if self.guard {
			return write!(f, "[{}]", self.name);
		}
		write!(f, "{}", self.name)
	}
}

impl fmt::Display for Primitive {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", primitive_name(self.id))?;
		let threshold = primitive_threshold(self.id).map(|_| self.threshold);
		if threshold.is_some() || !self.capabilities.is_empty() {
			let mut separator = "[";
			if let Some(t) = threshold {
				write!(f, "{}{}", separator, t)?;
				separator = ", ";
			}
			for (cap, onset) in self.capabilities.iter() {
				write!(f, "{}{}", separator, cap.name())?;
				if onset > 0 {
					write!(f, " from phase {}", onset)?;
				}
				separator = ", ";
			}
			write!(f, "]")?;
		}
		write!(f, "(")?;
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
		write!(f, "{}", query_display(self))?;
		if self.options.is_empty() {
			return Ok(());
		}
		write!(f, "[")?;
		for option in &self.options {
			write!(
				f,
				"\n{}",
				render_line(&option.comments, "\t\t", pretty_option(option))
			)?;
		}
		write!(f, "\n\t]")
	}
}

impl fmt::Display for Expression {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self.kind {
			Declaration::Knows => write!(
				f,
				"knows {} {}",
				self.qualifier.unwrap_or(Qualifier::Private),
				pretty_constants(&self.constants)
			),
			Declaration::Generates => write!(f, "generates {}", pretty_constants(&self.constants)),
			Declaration::Leaks => write!(f, "leaks {}", pretty_constants(&self.constants)),
			Declaration::Assignment => {
				let outputs: Vec<String> = self
					.constants
					.iter()
					.map(|c| {
						if crate::util::is_anonymous_name(&c.name) {
							"_".to_string()
						} else {
							c.to_string()
						}
					})
					.collect();
				write!(f, "{} = ", outputs.join(", "))?;
				match &self.assigned {
					Some(value) => write!(f, "{}", value),
					None => Ok(()),
				}
			}
		}
	}
}

fn render_comment(c: &Comment, indent: &str) -> String {
	match c.style {
		CommentStyle::Line => format!("//{}", c.text),
		CommentStyle::Block if !c.text.contains('\n') => format!("/*{}*/", c.text),
		CommentStyle::Block => {
			let mut lines = c.text.split('\n');
			let mut out = format!("/*{}", lines.next().unwrap_or_default());
			let rest: Vec<&str> = lines.collect();
			let margin = rest
				.iter()
				.filter(|line| !line.trim().is_empty())
				.map(|line| line.len() - line.trim_start_matches([' ', '\t']).len())
				.min()
				.unwrap_or(0);
			for line in rest {
				out.push('\n');
				out.push_str(indent);
				out.push_str("   ");
				if !line.trim().is_empty() {
					out.push_str(&line[margin..]);
				}
			}
			out.push_str("*/");
			out
		}
	}
}

fn render_leading(comments: &[Comment], indent: &str) -> String {
	comments
		.iter()
		.map(|c| format!("{}{}\n", indent, render_comment(c, indent)))
		.collect()
}

fn render_trailing(comment: Option<&Comment>) -> String {
	comment
		.map(|c| format!(" {}", render_comment(c, "")))
		.unwrap_or_default()
}

fn render_line(comments: &LineComments, indent: &str, line: impl fmt::Display) -> String {
	format!(
		"{}{indent}{line}{}",
		render_leading(&comments.leading, indent),
		render_trailing(comments.trailing.as_ref())
	)
}

fn render_bracketed<'m>(
	head: &str,
	comments: &BracketComments,
	items: impl Iterator<Item = (&'m LineComments, impl fmt::Display)>,
) -> String {
	let mut out = render_leading(&comments.leading, "");
	out.push_str(&format!(
		"{}[{}\n",
		head,
		render_trailing(comments.opening.as_ref())
	));
	for (item, line) in items {
		out.push_str(&render_line(item, "\t", line));
		out.push('\n');
	}
	out.push_str(&render_leading(&comments.tail, "\t"));
	out.push(']');
	out.push_str(&render_trailing(comments.closing.as_ref()));
	out
}

pub(crate) fn query_display(q: &Query) -> String {
	let subject = match q.kind {
		QueryKind::Authentication => pretty_message(&q.message),
		_ => pretty_constants(&q.constants),
	};
	format!("{}? {}", q.kind.name(), subject)
}

pub(crate) fn query_line(q: &Query) -> String {
	let head = query_display(q);
	if q.options.is_empty() {
		return head;
	}
	let options: Vec<String> = q.options.iter().map(pretty_option).collect();
	format!("{}[{}]", head, options.join(" "))
}

fn pretty_option(option: &QueryOption) -> String {
	match option.kind {
		QueryOptionKind::Precondition => {
			format!("precondition[{}]", pretty_message(&option.message))
		}
	}
}

pub(crate) fn pretty_constants(constants: &[Constant]) -> String {
	constants
		.iter()
		.map(Constant::to_string)
		.collect::<Vec<_>>()
		.join(", ")
}

fn pretty_message(message: &Message) -> String {
	format!(
		"{} -> {}: {}",
		message.sender_name,
		message.recipient_name,
		pretty_constants(&message.constants),
	)
}

fn pretty_scenario(scenario: &Scenario) -> String {
	let bindings: Vec<String> = scenario
		.bindings
		.iter()
		.map(|(target, value)| format!("{} = {}", target, value))
		.collect();
	format!("{}[{}]", scenario.principal_name, bindings.join(", "))
}

pub(crate) fn pretty_model(m: &Model) -> String {
	let mut output = String::new();
	if !m.attacker_comments.leading.is_empty() {
		output.push_str(&render_leading(&m.attacker_comments.leading, ""));
		output.push('\n');
	}
	output.push_str(&format!(
		"attacker[{}]{}\n\n",
		m.attacker,
		render_trailing(m.attacker_comments.trailing.as_ref())
	));
	for block in &m.blocks {
		output.push_str(&match block {
			Block::Principal(p) => render_bracketed(
				&format!("principal {}", p.name),
				&p.comments,
				p.expressions.iter().map(|e| (&e.comments, e)),
			),
			Block::Message(msg) => render_line(&msg.comments, "", pretty_message(msg)),
			Block::Phase(ph) => render_line(&ph.comments, "", format!("phase[{}]", ph.number)),
		});
		output.push_str("\n\n");
	}
	if !m.scenarios.is_empty() || !m.scenarios_comments.is_empty() {
		output.push_str(&render_bracketed(
			"scenarios",
			&m.scenarios_comments,
			m.scenarios
				.iter()
				.map(|s| (&s.comments, pretty_scenario(s))),
		));
		output.push_str("\n\n");
	}
	output.push_str(&render_bracketed(
		"queries",
		&m.queries_comments,
		m.queries.iter().map(|q| (&q.comments, q)),
	));
	output.push('\n');
	if !m.tail_comments.is_empty() {
		output.push('\n');
		output.push_str(&render_leading(&m.tail_comments, ""));
	}
	output
}

pub(crate) fn pretty_arity(spec_arity: &[i32]) -> String {
	match spec_arity {
		[] => String::new(),
		[only] => only.to_string(),
		[init @ .., last] => {
			let init: Vec<String> = init.iter().map(i32::to_string).collect();
			format!("{}, or {}", init.join(", "), last)
		}
	}
}

pub fn diagram(model_file: &str) -> VResult<String> {
	Ok(mermaid_of(&parse_file(model_file)?))
}

pub(crate) fn mermaid_of(m: &Model) -> String {
	let mut principals: Vec<&str> = Vec::new();
	for block in &m.blocks {
		let names = match block {
			Block::Principal(p) => vec![p.name.as_str()],
			Block::Message(msg) => vec![&*msg.sender_name, &*msg.recipient_name],
			Block::Phase(_) => Vec::new(),
		};
		for name in names {
			if !principals.contains(&name) {
				principals.push(name);
			}
		}
	}
	let id = |name: &str| {
		let at = principals.iter().position(|n| *n == name).unwrap_or(0);
		format!("p{at}")
	};
	let mut out = String::from("sequenceDiagram\n");
	for (at, name) in principals.iter().enumerate() {
		out.push_str(&format!("    participant p{at} as {name}\n"));
	}
	for line in diagram_body(m, &id).lines() {
		out.push_str("    ");
		out.push_str(line);
		out.push('\n');
	}
	out
}

#[cfg_attr(not(feature = "lsp"), allow(dead_code))]
pub(crate) fn pretty_diagram(m: &Model) -> String {
	diagram_body(m, &|name: &str| name.to_string())
}

fn diagram_body(m: &Model, id: &dyn Fn(&str) -> String) -> String {
	let anchor = m.blocks.iter().find_map(|block| match block {
		Block::Principal(p) => Some(p.name.as_str()),
		Block::Message(msg) => Some(&*msg.sender_name),
		Block::Phase(_) => None,
	});
	let mut output = String::new();
	for block in &m.blocks {
		match block {
			Block::Principal(p) => {
				for expr in &p.expressions {
					output.push_str(&format!("Note over {}: {}\n", id(&p.name), expr));
				}
			}
			Block::Message(msg) => {
				output.push_str(&format!(
					"{}->{}:{}\n",
					id(&msg.sender_name),
					id(&msg.recipient_name),
					pretty_constants(&msg.constants),
				));
			}
			Block::Phase(phase) => {
				if let Some(anchor) = anchor {
					output.push_str(&format!(
						"Note right of {}: phase[{}]\n",
						id(anchor),
						phase.number
					));
				}
			}
		}
	}
	output
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::parser::parse_string;

	#[test]
	fn comments_inside_brackets_and_arguments_survive_formatting() {
		let src = "attacker[/* mode */ active]\n\nprincipal Alice[\n\tknows private pc_m\n\tpc_x = HASH(/* inner */ pc_m)\n\tpc_y = HASH[weak /* cap */](pc_x)\n]\n\nAlice -> Bob: pc_y\n\nprincipal Bob[\n\t_ = HASH(pc_y)\n]\n\nphase[/* p */ 1]\n\nprincipal Alice[\n\tknows private pc_z\n]\n\nqueries[\n\tconfidentiality? pc_m[\n\t\t// note inside options\n\t\tprecondition[Alice -> Bob: pc_y] // trailing on option\n\t]\n]\n";
		let m = parse_string("pc.vp", src).expect("parse");
		let once = pretty_model(&m);
		for text in [
			"/* mode */",
			"/* inner */",
			"/* cap */",
			"/* p */",
			"// note inside options",
			"// trailing on option",
		] {
			assert!(once.contains(text), "{text} was dropped:\n{once}");
		}
		let m2 = parse_string("pc.vp", &once).expect("reparse");
		assert_eq!(pretty_model(&m2), once, "formatting is not stable");
	}

	#[test]
	fn repeated_carriage_returns_end_no_comment() {
		let src = "attacker[active] // a\r\r\n// b\r\r\nprincipal Alice[\n\tknows private rcr_a // c\r\r\n]\nqueries[\n\tconfidentiality? rcr_a\n]\n";
		let once = pretty_model(&parse_string("rcr.vp", src).expect("parse"));
		assert!(!once.contains('\r'), "{once:?}");
		for text in ["// a", "// b", "// c"] {
			assert!(once.contains(text), "{text} was dropped:\n{once}");
		}
	}

	#[test]
	fn a_crlf_trailing_comment_leaves_no_carriage_return() {
		let src = "attacker[active] // a\r\n\r\nprincipal Alice[\r\n\tknows private crt_a // b\r\n]\r\n\r\nqueries[\r\n\tconfidentiality? crt_a // c\r\n]\r\n";
		let once = pretty_model(&parse_string("crt.vp", src).expect("parse"));
		assert!(!once.contains('\r'), "{once:?}");
		for text in ["// a", "// b", "// c"] {
			assert!(once.contains(text), "{text} was dropped:\n{once}");
		}
	}

	#[test]
	fn an_empty_scenarios_block_keeps_its_comments() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private esc_a\n]\n\n// before\nscenarios[ // header\n\t// inside\n] // closing\n\nqueries[\n\tconfidentiality? esc_a\n]\n";
		let once = pretty_model(&parse_string("esc.vp", src).expect("parse"));
		for text in ["// before", "// header", "// inside", "// closing"] {
			assert!(once.contains(text), "{text} was dropped:\n{once}");
		}
		let m2 = parse_string("esc.vp", &once).expect("reparse");
		assert_eq!(pretty_model(&m2), once, "formatting is not stable");
	}

	#[test]
	fn a_guard_may_pad_its_constant() {
		let src = "attacker[active]\nprincipal Alice[\n\tknows private gp_a\n]\nAlice -> Bob: [ gp_a ]\nprincipal Bob[\n\t_ = HASH(gp_a)\n]\nqueries[\n\tconfidentiality? gp_a\n]\n";
		let once = pretty_model(&parse_string("gp.vp", src).expect("parse"));
		assert!(once.contains("Alice -> Bob: [gp_a]"), "{once}");
	}

	#[test]
	fn a_block_comment_keeps_its_relative_indentation() {
		let src = "attacker[active]\n\n/*\nAlice   Bob\n  |--ga-->|\n    |<-gb-|\n*/\nprincipal Alice[\n\tknows private bci_a\n]\n\nqueries[\n\tconfidentiality? bci_a\n]\n";
		let once = pretty_model(&parse_string("bci.vp", src).expect("parse"));
		assert!(
			once.contains("/*\n   Alice   Bob\n     |--ga-->|\n       |<-gb-|\n   */"),
			"{once}"
		);
		let m2 = parse_string("bci.vp", &once).expect("reparse");
		assert_eq!(pretty_model(&m2), once, "formatting is not stable");
	}

	#[test]
	fn a_scenarios_block_round_trips() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows public prs_gpeer\n\tknows private prs_a\n\tprs_e = ENC(prs_gpeer, prs_a)\n]\n\nscenarios[\n\tAlice[prs_gpeer = prs_gb]\n\tAlice[prs_gpeer = prs_gm]\n]\n\nqueries[\n\tconfidentiality? prs_a\n]\n";
		let m = crate::parser::parse_string("prs.vp", src).expect("parse");
		let once = pretty_model(&m);
		assert_eq!(once, src);
		let m2 = crate::parser::parse_string("prs.vp", &once).expect("reparse");
		assert_eq!(pretty_model(&m2), once);
	}

	#[test]
	fn pretty_round_trips_primitive_capabilities() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private prc_k\n\tknows private prc_m\n\tknows private prc_ad\n\tknows private prc_n\n\tprc_e = AEAD_ENC[weak, forgeable from phase 2](prc_k, prc_n, prc_m, prc_ad)\n]\n\nphase[1]\n\nphase[2]\n\nqueries[\n\tconfidentiality? prc_m\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let once = pretty_model(&m);
		let m2 = parse_string("t.vp", &once).expect("reparse");
		let twice = pretty_model(&m2);
		assert_eq!(once, twice);
		assert!(
			once.contains("AEAD_ENC[weak, forgeable from phase 2](prc_k, prc_n, prc_m, prc_ad)"),
			"got: {}",
			once
		);
	}

	#[test]
	fn pretty_round_trips_a_threshold_parameter() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private prt_k\n\tprt_a, prt_b, prt_c, prt_d, prt_e = THRESHOLD_SPLIT[3](prt_k)\n\tprt_j = THRESHOLD_JOIN(prt_a, prt_c, prt_e)\n]\n\nqueries[\n\tconfidentiality? prt_k\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let once = pretty_model(&m);
		let m2 = parse_string("t.vp", &once).expect("reparse");
		let twice = pretty_model(&m2);
		assert_eq!(once, twice);
		assert!(once.contains("THRESHOLD_SPLIT[3](prt_k)"), "got: {}", once);
	}

	#[test]
	fn pretty_round_trips_dh_to_new_syntax() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private dsz_a\n\tknows private dsz_b\n\tdsz_ga = PUBKEY(dsz_a)\n\tdsz_k = DH_KEX(dsz_ga, dsz_b)\n]\n\nqueries[\n\tconfidentiality? dsz_k\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let once = pretty_model(&m);
		let m2 = parse_string("t.vp", &once).expect("reparse");
		let twice = pretty_model(&m2);
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
		let out = pretty_model(&m);
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
		let out = pretty_model(&m);
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
		let out = pretty_model(&m);
		assert!(out.contains("knows private a // lt"), "got: {}", out);
	}

	#[test]
	fn pretty_emits_block_comment_inline() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a /* lt */\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m);
		assert!(out.contains("knows private a /* lt */"), "got: {}", out);
	}

	#[test]
	fn pretty_emits_block_comment_multiline() {
		let src = "/* line1\n   line2 */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let out = pretty_model(&m);
		assert!(out.contains("/* line1"), "missing /* line1 in:\n{}", out);
		assert!(out.contains("line2 */"), "missing 'line2 */':\n{}", out);
	}

	fn assert_round_trip_idempotent(src: &str) {
		let m1 = parse_string("rt.vp", src).expect("parse 1");
		let s1 = pretty_model(&m1);
		let m2 = parse_string("rt.vp", &s1).expect("parse 2");
		let s2 = pretty_model(&m2);
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
		let out = pretty_model(&m);
		assert!(out.contains("/* multi"), "missing /* multi in:\n{}", out);
		assert!(out.contains("line"), "missing 'line':\n{}", out);
		assert!(out.contains("header */"), "missing 'header */':\n{}", out);
		let m2 = parse_string("t.vp", &out).expect("re-parse");
		match &m2.blocks[0] {
			Block::Principal(p) => {
				assert_eq!(p.comments.leading.len(), 1);
				assert!(matches!(p.comments.leading[0].style, CommentStyle::Block));
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
		let out = pretty_model(&m);
		assert_eq!(
			out, golden,
			"golden mismatch\n--- expected ---\n{}\n--- got ---\n{}",
			golden, out
		);
	}

	#[test]
	fn golden_cap_multi_annotation() {
		assert_golden(
			include_str!("../examples/test/cap_multi_annotation.vp"),
			include_str!("../examples/test/golden_pretty/cap_multi_annotation.vp"),
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
	#[test]
	fn phase_notes_name_a_participant() {
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private pd_x\n\
			]\n\
			phase[1]\n\
			principal Alice[\n\
			leaks pd_x\n\
			]\n\
			queries[\n\
			confidentiality? pd_x\n\
			]\n";
		let m = parse_string("pd.vp", src).expect("parse");
		let out = pretty_diagram(&m);
		assert!(out.contains("Note right of Alice: phase[1]"), "{out}");
		assert!(!out.contains("of :"), "{out}");
	}
}
