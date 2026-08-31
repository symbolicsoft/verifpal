/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::primitive::primitive_names;
use crate::report::{Analysis, DiagramRow, ModelReport};
use crate::template::escaped_tex;
use crate::tokens::TokenKind;

pub(crate) enum Term {
	Const {
		name: String,
		session: Option<String>,
		scenario: Option<String>,
		guarded: bool,
	},
	App {
		name: String,
		capabilities: Vec<String>,
		checked: bool,
		arguments: Vec<Term>,
	},
}

struct Scan<'a> {
	src: &'a [u8],
	at: usize,
}

impl<'a> Scan<'a> {
	fn new(src: &'a str) -> Scan<'a> {
		Scan {
			src: src.as_bytes(),
			at: 0,
		}
	}

	fn peek(&self) -> Option<u8> {
		self.src.get(self.at).copied()
	}

	fn eat(&mut self, c: u8) -> bool {
		if self.peek() == Some(c) {
			self.at += 1;
			return true;
		}
		false
	}

	fn skip_spaces(&mut self) {
		while self.peek() == Some(b' ') {
			self.at += 1;
		}
	}

	fn word(&mut self) -> Option<String> {
		let start = self.at;
		while matches!(self.peek(), Some(c) if is_name_byte(c)) {
			self.at += 1;
		}
		(self.at > start).then(|| String::from_utf8_lossy(&self.src[start..self.at]).into_owned())
	}

	fn done(&self) -> bool {
		self.at >= self.src.len()
	}
}

fn is_name_byte(c: u8) -> bool {
	c.is_ascii_alphanumeric() || c == b'_'
}

pub(crate) fn is_primitive(name: &str) -> bool {
	primitive_names()
		.iter()
		.any(|known| known.eq_ignore_ascii_case(name))
}

pub(crate) fn parse(text: &str) -> Option<Term> {
	let mut scan = Scan::new(text.trim());
	let term = parse_term(&mut scan)?;
	scan.done().then_some(term)
}

fn parse_term(scan: &mut Scan) -> Option<Term> {
	if scan.eat(b'[') {
		let inner = parse_term(scan)?;
		if !scan.eat(b']') {
			return None;
		}
		return match inner {
			Term::Const {
				name,
				session,
				scenario,
				..
			} => Some(Term::Const {
				name,
				session,
				scenario,
				guarded: true,
			}),
			Term::App { .. } => None,
		};
	}
	let name = scan.word()?;
	if scan.peek() != Some(b'(') && scan.peek() != Some(b'[') {
		return Some(constant(name, scan));
	}
	if !is_primitive(&name) {
		return None;
	}
	let capabilities = parse_capabilities(scan)?;
	if !scan.eat(b'(') {
		return None;
	}
	let mut arguments = Vec::new();
	if !scan.eat(b')') {
		loop {
			arguments.push(parse_term(scan)?);
			scan.skip_spaces();
			if scan.eat(b')') {
				break;
			}
			if !scan.eat(b',') {
				return None;
			}
			scan.skip_spaces();
		}
	}
	let checked = scan.eat(b'?');
	Some(Term::App {
		name,
		capabilities,
		checked,
		arguments,
	})
}

fn parse_capabilities(scan: &mut Scan) -> Option<Vec<String>> {
	if !scan.eat(b'[') {
		return Some(Vec::new());
	}
	let mut out = Vec::new();
	loop {
		scan.skip_spaces();
		let mut text = scan.word()?;
		scan.skip_spaces();
		while matches!(scan.peek(), Some(c) if is_name_byte(c)) {
			let word = scan.word()?;
			text.push(' ');
			text.push_str(&word);
			scan.skip_spaces();
		}
		out.push(text);
		if scan.eat(b']') {
			return Some(out);
		}
		if !scan.eat(b',') {
			return None;
		}
	}
}

fn constant(name: String, scan: &mut Scan) -> Term {
	let mut base = name;
	let mut session = None;
	let mut scenario = None;
	loop {
		match scan.peek() {
			Some(b'#') => {
				scan.at += 1;
				session = scan.word().or(Some(String::new()));
			}
			Some(b'@') => {
				scan.at += 1;
				scenario = scan.word().or(Some(String::new()));
			}
			_ => break,
		}
	}
	if base == "G" {
		base = "G".to_string();
	}
	Term::Const {
		name: base,
		session,
		scenario,
		guarded: false,
	}
}

fn split_name(name: &str) -> String {
	name.split('_')
		.map(escaped_tex)
		.collect::<Vec<String>>()
		.join("\\vpus ")
}

pub(crate) fn render(term: &Term) -> String {
	match term {
		Term::Const {
			name,
			session,
			scenario,
			guarded,
		} => {
			let mut out = format!("\\vpconst{{{}}}", split_name(name));
			if let Some(scenario) = scenario {
				out = format!("\\vpscenario{{{out}}}{{{}}}", escaped_tex(scenario));
			}
			if let Some(session) = session {
				out = format!("\\vpsession{{{out}}}{{{}}}", escaped_tex(session));
			}
			if *guarded {
				out = format!("\\vpguard{{{out}}}");
			}
			out
		}
		Term::App {
			name,
			capabilities,
			checked,
			arguments,
		} => {
			let head = match name.split_once('_') {
				Some((lead, tail)) => {
					format!("\\vpprim{{{}}}{{{}}}", escaped_tex(lead), escaped_tex(tail))
				}
				None => format!("\\vpprimo{{{}}}", escaped_tex(name)),
			};
			let caps = if capabilities.is_empty() {
				String::new()
			} else {
				format!(
					"\\vpcaps{{{}}}",
					capabilities
						.iter()
						.map(|c| escaped_tex(c))
						.collect::<Vec<String>>()
						.join(", ")
				)
			};
			let check = if *checked { "\\vpchecked{}" } else { "" };
			let args = arguments
				.iter()
				.map(render)
				.collect::<Vec<String>>()
				.join(",\\vpsep ");
			format!("{head}{caps}{check}({args})")
		}
	}
}

pub(crate) fn term(text: &str) -> String {
	match parse(text) {
		Some(parsed) => format!("\\vpterm{{{}}}", render(&parsed)),
		None => format!("\\vpliteral{{{}}}", escaped_tex(text)),
	}
}

pub(crate) fn label(name: &str, guarded: bool, forged: bool) -> String {
	let mut out = term(name);
	if guarded {
		out = format!("\\vpguarded{{{out}}}");
	}
	if forged {
		out = format!("\\vpdagger{{{out}}}");
	}
	out
}

#[derive(Default)]
pub(crate) struct Names {
	constants: Vec<String>,
	principals: Vec<String>,
}

impl Names {
	pub(crate) fn of(model: &ModelReport, analysis: Option<&Analysis>) -> Names {
		let mut names = Names::default();
		for token in &model.tokens {
			match token.kind {
				TokenKind::ConstantName => names.constant(&token.text),
				TokenKind::PrincipalName => names.principal(&token.text),
				_ => {}
			}
		}
		for row in &model.diagram {
			match row {
				DiagramRow::Message {
					sender,
					recipient,
					values,
					..
				} => {
					names.principal(sender);
					names.principal(recipient);
					for value in values {
						names.constant(&value.name);
					}
				}
				DiagramRow::Leak { principal, values } => {
					names.principal(principal);
					for value in values {
						names.constant(value);
					}
				}
				DiagramRow::Activity {
					principal,
					generates,
					computes,
					..
				} => {
					names.principal(principal);
					for value in generates {
						names.constant(value);
					}
					for step in computes {
						for value in &step.names {
							names.constant(value);
						}
					}
				}
				DiagramRow::Phase { .. } => {}
			}
		}
		names.principal("Attacker");
		let Some(analysis) = analysis else {
			return names;
		};
		for query in &analysis.queries {
			for step in &query.steps {
				for who in [&step.sender, &step.recipient, &step.principal]
					.into_iter()
					.flatten()
				{
					names.principal(who);
				}
				for value in &step.values {
					names.constant(&value.name);
				}
			}
		}
		names
	}

	fn principal(&mut self, name: &str) {
		let name = name.to_string();
		if !self.principals.contains(&name) {
			self.principals.push(name);
		}
	}

	fn constant(&mut self, name: &str) {
		let name = name.to_string();
		if !self.constants.contains(&name) {
			self.constants.push(name);
		}
	}

	fn holds_constant(&self, name: &str) -> bool {
		self.constants.iter().any(|known| known == name)
	}

	fn holds_principal(&self, name: &str) -> bool {
		self.principals.iter().any(|known| known == name)
	}
}

pub(crate) fn prose(text: &str, names: &Names) -> String {
	let bytes = text.as_bytes();
	let mut out = String::with_capacity(text.len());
	let mut at = 0usize;
	while at < bytes.len() {
		if !is_name_byte(bytes[at]) {
			let end = at + utf8_width(bytes[at]);
			out.push_str(&escaped_tex(&text[at..end.min(text.len())]));
			at = end;
			continue;
		}
		let start = at;
		while at < bytes.len() && is_name_byte(bytes[at]) {
			at += 1;
		}
		let mut word_end = at;
		while word_end < bytes.len() && matches!(bytes[word_end], b'#' | b'@') {
			word_end += 1;
			while word_end < bytes.len() && is_name_byte(bytes[word_end]) {
				word_end += 1;
			}
		}
		let word = &text[start..word_end];
		if bytes.get(word_end) == Some(&b'(')
			&& is_primitive(&text[start..at])
			&& let Some(end) = balanced(bytes, word_end)
			&& let Some(parsed) = parse(&text[start..end])
		{
			out.push_str(&format!("\\vpterm{{{}}}", render(&parsed)));
			at = end;
			continue;
		}
		at = word_end;
		if names.holds_constant(word)
			&& let Some(parsed) = parse(word)
		{
			out.push_str(&format!("\\vpterm{{{}}}", render(&parsed)));
			continue;
		}
		if names.holds_principal(word) {
			out.push_str(&format!("\\vpactor{{{}}}", escaped_tex(word)));
			continue;
		}
		out.push_str(&escaped_tex(word));
	}
	out
}

fn utf8_width(lead: u8) -> usize {
	match lead {
		0x00..=0x7f => 1,
		0xc0..=0xdf => 2,
		0xe0..=0xef => 3,
		_ => 4,
	}
}

fn balanced(bytes: &[u8], open: usize) -> Option<usize> {
	let mut depth = 0usize;
	for (at, byte) in bytes.iter().enumerate().skip(open) {
		match byte {
			b'(' => depth += 1,
			b')' => {
				depth -= 1;
				if depth == 0 {
					let end = at + 1;
					return Some(if bytes.get(end) == Some(&b'?') {
						end + 1
					} else {
						end
					});
				}
			}
			_ => {}
		}
	}
	None
}

#[cfg(test)]
mod tests {
	use super::*;

	fn back(term: &Term) -> String {
		match term {
			Term::Const {
				name,
				session,
				scenario,
				guarded,
			} => {
				let mut out = name.clone();
				if let Some(scenario) = scenario {
					out = format!("{out}@{scenario}");
				}
				if let Some(session) = session {
					out = format!("{out}#{session}");
				}
				if *guarded {
					out = format!("[{out}]");
				}
				out
			}
			Term::App {
				name,
				capabilities,
				checked,
				arguments,
			} => {
				let caps = if capabilities.is_empty() {
					String::new()
				} else {
					format!("[{}]", capabilities.join(", "))
				};
				let args = arguments
					.iter()
					.map(back)
					.collect::<Vec<String>>()
					.join(", ");
				format!("{name}{caps}({args}){}", if *checked { "?" } else { "" })
			}
		}
	}

	#[test]
	fn a_constant_carries_its_session_and_scenario_as_superscripts() {
		let out = term("na#2");
		assert!(out.contains("\\vpsession"), "{out}");
		let out = term("gb@2");
		assert!(out.contains("\\vpscenario"), "{out}");
	}

	#[test]
	fn a_primitive_name_splits_at_its_underscore() {
		let out = term("AEAD_ENC(k, m, ad)");
		assert!(out.contains("\\vpprim{AEAD}{ENC}"), "{out}");
		let out = term("HASH(m)");
		assert!(out.contains("\\vpprimo{HASH}"), "{out}");
	}

	#[test]
	fn a_constant_underscore_stays_an_underscore_rather_than_a_subscript() {
		let out = term("g_file_key");
		assert!(out.contains("g\\vpus file\\vpus key"), "{out}");
		assert!(!out.contains("\\vpprim"), "{out}");
	}

	#[test]
	fn a_nested_term_round_trips_through_the_parser() {
		for text in [
			"nil",
			"[ga]",
			"HASH(m)",
			"AEAD_ENC(DH_KEX(PUBKEY(nil), b), m, ad)",
			"AEAD_DEC(k, e, ad)?",
			"HASH[weak](m)",
			"AEAD_ENC[weak, forgeable from phase 2](k, m, ad)",
			"SPLIT(CONCAT(a, b))",
			"na#2",
			"gb@2",
			"g_file_alice_a_key",
		] {
			let parsed = parse(text).unwrap_or_else(|| panic!("{text} did not parse"));
			assert_eq!(back(&parsed), text);
		}
	}

	#[test]
	fn text_the_parser_cannot_read_falls_back_to_escaped_prose() {
		let out = term("not a term at all!");
		assert!(out.starts_with("\\vpliteral{"), "{out}");
		assert!(!out.contains("\\vpconst"), "{out}");
	}

	#[test]
	fn an_unknown_head_is_not_treated_as_a_primitive() {
		assert!(parse("NOTAPRIM(x)").is_none());
	}

	#[test]
	fn prose_sets_terms_in_math_and_leaves_ordinary_words_alone() {
		let mut names = Names::default();
		names.constant("ga");
		names.principal("Alice");
		let out = prose("Alice replaces ga with PUBKEY(nil).", &names);
		assert!(out.contains("\\vpactor{Alice}"), "{out}");
		assert!(out.contains("\\vpprimo{PUBKEY}"), "{out}");
		assert!(out.starts_with("\\vpactor{Alice} replaces"), "{out}");
		assert!(out.ends_with('.'), "{out}");
	}

	#[test]
	fn prose_escapes_what_it_does_not_recognise() {
		let names = Names::default();
		assert_eq!(
			prose("100% of $x_1 & more", &names),
			"100\\% of \\$x\\_1 \\& more"
		);
	}

	#[test]
	fn prose_leaves_a_word_that_merely_looks_like_a_constant_alone() {
		let names = Names::default();
		let out = prose("the attacker obtains it", &names);
		assert_eq!(out, "the attacker obtains it");
	}
}
