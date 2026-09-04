/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::primitive::{primitive_get_enum, primitive_names};
use crate::principal::PrincipalNames;
use crate::types::*;
use crate::util::did_you_mean;
use crate::value::ValueNames;
use std::sync::Arc;

const RESERVED: &[&str] = &[
	"attacker",
	"passive",
	"active",
	"principal",
	"knows",
	"generates",
	"leaks",
	"phase",
	"public",
	"private",
	"confidentiality",
	"authentication",
	"freshness",
	"unlinkability",
	"equivalence",
	"precondition",
	"ringsign",
	"ringsignverif",
	"primitive",
	"hash",
	"hkdf",
	"aead_enc",
	"aead_dec",
	"enc",
	"dec",
	"mac",
	"assert",
	"sign",
	"signverif",
	"pke_enc",
	"pke_dec",
	"shamir_split",
	"shamir_join",
	"concat",
	"split",
	crate::util::ANONYMOUS_PREFIX,
	"blind",
	"unblind",
	"pubkey",
	"dh_kex",
	"kem_encap",
	"kem_decap",
	"g",
	"queries",
	"scenarios",
];

pub(crate) fn check_reserved(s: &str) -> VResult<()> {
	let lower = s.to_lowercase();
	if RESERVED.contains(&lower.as_str())
		|| lower.starts_with("attacker")
		|| lower.starts_with(crate::util::ANONYMOUS_PREFIX)
	{
		return Err(VerifpalError::parse(
			format!("`{}` is a reserved word and cannot name a constant", s).into(),
		)
		.narrow(s.to_string())
		.note(
			"the language keywords, and any name beginning with `attacker` or \
			 `unnamed`, are reserved so that a model cannot shadow them",
		)
		.help(format!("rename it, for example to `{}_value`", s)));
	}
	Ok(())
}

fn title_case(s: &str) -> String {
	let mut result = String::with_capacity(s.len());
	let mut chars = s.chars();
	if let Some(first) = chars.next() {
		for c in first.to_uppercase() {
			result.push(c);
		}
		for c in chars {
			for lc in c.to_lowercase() {
				result.push(lc);
			}
		}
	}
	result
}

fn starts_with_keyword(s: &str, keyword: &str) -> bool {
	if !starts_with_ignoring_case(s, keyword) {
		return false;
	}
	s.as_bytes()
		.get(keyword.len())
		.is_none_or(|&b| !b.is_ascii_alphanumeric() && b != b'_')
}

fn starts_with_ignoring_case(s: &str, keyword: &str) -> bool {
	let (bytes, kw) = (s.as_bytes(), keyword.as_bytes());
	bytes.len() >= kw.len() && bytes[..kw.len()].eq_ignore_ascii_case(kw)
}

struct Parser<'a> {
	input: &'a [u8],
	source: &'a str,
	tokens: Option<crate::tokens::TokenIndex>,
	pos: usize,
	pending_leading: Vec<Comment>,
	unterminated_block_at: Option<usize>,
	values: ValueNames,
	principals: PrincipalNames,
	unnamed_counter: usize,
	last_ident: Span,
	value_end: usize,
	depth: usize,
	anonymous_ok: bool,
}

const MAX_NESTING: usize = 64;

impl<'a> Parser<'a> {
	fn new(input: &'a str) -> Self {
		Parser {
			input: input.as_bytes(),
			source: input,
			tokens: None,
			pos: 0,
			last_ident: Span::default(),
			value_end: 0,
			depth: 0,
			anonymous_ok: false,
			pending_leading: Vec::new(),
			unterminated_block_at: None,
			values: ValueNames::new(),
			principals: PrincipalNames::new(),
			unnamed_counter: 0,
		}
	}

	fn principal_id(&mut self, name: &str) -> VResult<(PrincipalId, Arc<str>)> {
		let id = self.principals.intern(name)?;
		Ok((id, self.principals.name_of(id)))
	}

	fn record_principal_name(&mut self) -> VResult<()> {
		let span = self.last_ident;
		let name = std::str::from_utf8(&self.input[span.start..span.end]).unwrap_or("");
		let lower = name.to_lowercase();
		if lower != "attacker" && RESERVED.contains(&lower.as_str()) {
			return Err(VerifpalError::parse(
				format!("`{}` is a reserved word and cannot name a principal", name).into(),
			)
			.at(span)
			.narrow(name.to_string())
			.note("the language keywords are reserved so that a model cannot shadow them")
			.help("pick a different name"));
		}
		self.record(span, crate::tokens::TokenKind::PrincipalName);
		Ok(())
	}

	fn remaining(&self) -> &str {
		std::str::from_utf8(&self.input[self.pos..]).unwrap_or("")
	}

	fn at_end(&self) -> bool {
		self.pos >= self.input.len()
	}

	fn peek(&self) -> Option<u8> {
		if self.pos < self.input.len() {
			Some(self.input[self.pos])
		} else {
			None
		}
	}

	fn advance(&mut self) -> Option<u8> {
		if self.pos < self.input.len() {
			let c = self.input[self.pos];
			self.pos += 1;
			Some(c)
		} else {
			None
		}
	}

	fn skip_whitespace(&mut self) {
		while self.pos < self.input.len() {
			let c = self.input[self.pos];
			if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
				self.pos += 1;
			} else {
				break;
			}
		}
	}

	fn consume_trivia(&mut self) {
		loop {
			self.skip_whitespace();
			let two = if self.pos + 1 < self.input.len() {
				(self.input[self.pos], self.input[self.pos + 1])
			} else {
				(0, 0)
			};
			if two == (b'/', b'/') {
				let at = self.pos;
				let start = self.pos + 2;
				while self.pos < self.input.len() && self.input[self.pos] != b'\n' {
					self.pos += 1;
				}
				let end = if self.pos > at && self.input[self.pos - 1] == b'\r' {
					self.pos - 1
				} else {
					self.pos
				};
				self.record(Span::new(at, end), crate::tokens::TokenKind::Comment);
				let text = std::str::from_utf8(&self.input[start..self.pos])
					.unwrap_or("")
					.trim_end_matches('\r')
					.to_string();
				self.pending_leading.push(Comment {
					text,
					style: CommentStyle::Line,
				});
			} else if two == (b'/', b'*') {
				let open = self.pos;
				self.pos += 2;
				let start = self.pos;
				loop {
					if self.pos + 1 >= self.input.len() {
						self.pos = self.input.len();
						self.unterminated_block_at = Some(open);
						return;
					}
					if self.input[self.pos] == b'*' && self.input[self.pos + 1] == b'/' {
						let end = self.pos;
						self.pos += 2;
						self.record(Span::new(open, self.pos), crate::tokens::TokenKind::Comment);
						let text = std::str::from_utf8(&self.input[start..end])
							.unwrap_or("")
							.replace("\r\n", "\n");
						self.pending_leading.push(Comment {
							text,
							style: CommentStyle::Block,
						});
						break;
					}
					self.pos += 1;
				}
			} else {
				break;
			}
		}
	}

	fn take_leading(&mut self) -> Vec<Comment> {
		std::mem::take(&mut self.pending_leading)
	}

	fn trimmed_pos(&self) -> usize {
		let mut p = self.pos;
		while p > 0 && matches!(self.input[p - 1], b' ' | b'\t') {
			p -= 1;
		}
		p
	}

	fn snapshot(&self) -> (usize, usize, usize) {
		let tokens = self.tokens.as_ref().map_or(0, |t| t.len());
		(self.pos, self.pending_leading.len(), tokens)
	}

	fn restore(&mut self, (pos, leading_len, tokens): (usize, usize, usize)) {
		self.pos = pos;
		self.pending_leading.truncate(leading_len);
		if let Some(index) = self.tokens.as_mut() {
			index.truncate(tokens);
		}
	}

	fn record(&mut self, span: Span, kind: crate::tokens::TokenKind) {
		if let Some(index) = self.tokens.as_mut() {
			index.push(span, kind, self.source);
		}
	}

	fn record_from(&mut self, start: usize, kind: crate::tokens::TokenKind) {
		self.record(Span::new(start, self.pos), kind);
	}

	fn check_unterminated_block(&self) -> VResult<()> {
		if let Some(pos) = self.unterminated_block_at {
			return Err(VerifpalError::parse("unterminated block comment".into())
				.at(Span::at(pos))
				.labelled("this `/*` is never closed")
				.help("add the missing `*/`"));
		}
		Ok(())
	}

	fn try_take_trailing(&mut self) -> Option<Comment> {
		let saved = self.snapshot();
		self.skip_inline_whitespace();
		if self.pos + 1 >= self.input.len() {
			self.restore(saved);
			return None;
		}
		let two = (self.input[self.pos], self.input[self.pos + 1]);
		if two == (b'/', b'/') {
			let at = self.pos;
			let start = self.pos + 2;
			self.pos += 2;
			while self.pos < self.input.len() && self.input[self.pos] != b'\n' {
				self.pos += 1;
			}
			self.record_from(at, crate::tokens::TokenKind::Comment);
			let text = std::str::from_utf8(&self.input[start..self.pos])
				.unwrap_or("")
				.to_string();
			Some(Comment {
				text,
				style: CommentStyle::Line,
			})
		} else if two == (b'/', b'*') {
			let at = self.pos;
			let probe_start = self.pos + 2;
			let mut probe = probe_start;
			loop {
				if probe + 1 >= self.input.len() {
					self.restore(saved);
					return None;
				}
				let c = self.input[probe];
				if c == b'\n' {
					self.restore(saved);
					return None;
				}
				if c == b'*' && self.input[probe + 1] == b'/' {
					let text = std::str::from_utf8(&self.input[probe_start..probe])
						.unwrap_or("")
						.to_string();
					self.pos = probe + 2;
					self.record_from(at, crate::tokens::TokenKind::Comment);
					return Some(Comment {
						text,
						style: CommentStyle::Block,
					});
				}
				probe += 1;
			}
		} else {
			self.restore(saved);
			None
		}
	}

	fn expect(&mut self, s: &str) -> VResult<()> {
		self.expect_where(s, "")
	}

	fn expect_where(&mut self, s: &str, context: &str) -> VResult<()> {
		let bytes = s.as_bytes();
		if self.pos + bytes.len() <= self.input.len()
			&& &self.input[self.pos..self.pos + bytes.len()] == bytes
		{
			self.pos += bytes.len();
			return Ok(());
		}
		let message = if context.is_empty() {
			format!("expected `{}`", s)
		} else {
			format!("expected `{}` {}", s, context)
		};
		Err(VerifpalError::parse(message.into())
			.at(self.here())
			.labelled(self.found_here()))
	}

	fn unclosed_hint(&self, error: VerifpalError, opened_at: usize) -> VerifpalError {
		if error.has_labels() || self.delimiter_is_closed(opened_at) {
			return error;
		}
		let opener = self.input.get(opened_at).copied().unwrap_or(b'(');
		let closer = if opener == b'[' { b']' } else { b')' };
		error
			.label(
				Span::at(opened_at),
				format!("this `{}` is never closed", opener as char),
			)
			.help(format!("add the missing `{}`", closer as char))
	}

	fn delimiter_is_closed(&self, opened_at: usize) -> bool {
		let opener = match self.input.get(opened_at).copied() {
			Some(b) if b == b'[' || b == b'(' => b,
			_ => return true,
		};
		let closer = if opener == b'[' { b']' } else { b')' };
		let mut depth = 0usize;
		let mut at = opened_at;
		while at < self.input.len() {
			match self.input[at] {
				b'/' if self.input.get(at + 1) == Some(&b'/') => {
					while at < self.input.len() && self.input[at] != b'\n' {
						at += 1;
					}
					continue;
				}
				b'/' if self.input.get(at + 1) == Some(&b'*') => {
					at += 2;
					while at + 1 < self.input.len()
						&& !(self.input[at] == b'*' && self.input[at + 1] == b'/')
					{
						at += 1;
					}
					at += 2;
					continue;
				}
				b if b == opener => depth += 1,
				b if b == closer => {
					depth -= 1;
					if depth == 0 {
						return true;
					}
				}
				_ => {}
			}
			at += 1;
		}
		false
	}

	fn here(&self) -> Span {
		let rest = self.remaining();
		let Some(first) = rest.chars().next() else {
			return Span::at(self.pos);
		};
		let word: String = rest
			.chars()
			.take_while(|c| c.is_alphanumeric() || *c == '_')
			.collect();
		let width = if word.is_empty() {
			first.len_utf8()
		} else {
			word.len()
		};
		Span::new(self.pos, self.pos + width)
	}

	fn found_here(&self) -> String {
		let rest = self.remaining();
		let Some(first) = rest.chars().next() else {
			return "end of file".to_string();
		};
		let word: String = rest
			.chars()
			.take_while(|c| c.is_alphanumeric() || *c == '_')
			.collect();
		if !word.is_empty() {
			return format!("found `{}`", word);
		}
		match first {
			'\n' => "end of line".to_string(),
			c => format!("found `{}`", c),
		}
	}

	fn matches_keyword(&self, keyword: &str) -> bool {
		let kw = keyword.as_bytes();
		self.pos + kw.len() <= self.input.len()
			&& self.input[self.pos..self.pos + kw.len()].eq_ignore_ascii_case(kw)
	}

	fn expect_keyword(&mut self, keyword: &str) -> VResult<()> {
		if self.matches_keyword(keyword) {
			self.pos += keyword.len();
			return Ok(());
		}
		Err(
			VerifpalError::parse(format!("expected `{}`", keyword).into())
				.at(self.here())
				.labelled(self.found_here()),
		)
	}

	fn try_expect_keyword(&mut self, keyword: &str) -> bool {
		if self.matches_keyword(keyword) {
			self.pos += keyword.len();
			return true;
		}
		false
	}

	fn try_expect(&mut self, s: &str) -> bool {
		let bytes = s.as_bytes();
		if self.pos + bytes.len() <= self.input.len()
			&& &self.input[self.pos..self.pos + bytes.len()] == bytes
		{
			self.pos += bytes.len();
			true
		} else {
			false
		}
	}

	fn parse_identifier(&mut self) -> VResult<String> {
		let start = self.pos;
		self.last_ident = Span::at(start);
		while self.pos < self.input.len() {
			let c = self.input[self.pos];
			if c.is_ascii_alphanumeric() || c == b'_' {
				self.pos += 1;
			} else {
				break;
			}
		}
		if self.pos == start {
			return Err(VerifpalError::parse("expected a name".into())
				.at(self.here())
				.labelled(self.found_here())
				.note("a name is made of letters, digits and underscores"));
		}
		self.last_ident = Span::new(start, self.pos);
		let s = std::str::from_utf8(&self.input[start..self.pos])
			.map_err(|_| VerifpalError::parse("invalid UTF-8 in identifier".into()))?;
		Ok(s.to_lowercase())
	}

	fn parse_model(&mut self) -> VResult<Model> {
		if self.input.starts_with(&[0xEF, 0xBB, 0xBF]) {
			self.pos = 3;
		}
		self.consume_trivia();
		self.check_unterminated_block()?;
		let mut pre_attacker_comments = self.take_leading();

		let attacker_kw = self.pos;
		if !self.try_expect_keyword("attacker") {
			return Err(VerifpalError::parse(
				"model does not open with an `attacker` block".into(),
			)
			.at(self.here())
			.labelled(self.found_here())
			.note("every model states which attacker it is analyzed against, before anything else")
			.help("add `attacker[active]` or `attacker[passive]` as the first line"));
		}
		self.record_from(attacker_kw, crate::tokens::TokenKind::Keyword);
		self.consume_trivia();
		self.expect("[")?;
		self.consume_trivia();
		let attacker_str = self.parse_identifier()?;
		self.record(self.last_ident, crate::tokens::TokenKind::AttackerMode);
		let attacker_type = match attacker_str.as_str() {
			"active" => AttackerKind::Active,
			"passive" => AttackerKind::Passive,
			_ => {
				return Err(VerifpalError::parse(
					format!("unknown attacker type `{}`", attacker_str).into(),
				)
				.at(self.last_ident)
				.narrow(attacker_str.clone())
				.note("an attacker is either `active` or `passive`")
				.suggest(did_you_mean(&attacker_str, ["active", "passive"])));
			}
		};
		self.consume_trivia();
		self.expect("]")?;
		pre_attacker_comments.extend(self.take_leading());
		let attacker_trailing = self.try_take_trailing();
		self.consume_trivia();

		let mut blocks = Vec::new();
		while !self.at_end() {
			self.consume_trivia();
			if self.at_end() {
				break;
			}

			if starts_with_keyword(self.remaining(), "queries")
				|| starts_with_keyword(self.remaining(), "scenarios")
			{
				break;
			}

			let block = self.parse_block()?;
			blocks.push(block);
			self.consume_trivia();
		}

		self.check_unterminated_block()?;
		if blocks.is_empty() {
			return Err(VerifpalError::parse(
				"model declares no principals and no messages".into(),
			)
			.at(self.here())
			.note("a model describes principals computing values and sending them to each other")
			.help("add a principal block, e.g. `principal Alice[ knows private m ]`"));
		}

		self.consume_trivia();
		let (
			scenarios,
			scenarios_leading_comments,
			scenarios_header_trailing,
			scenarios_tail_comments,
			scenarios_closing_trailing,
		) = self.parse_scenarios()?;

		self.consume_trivia();
		if starts_with_keyword(self.remaining(), "scenarios") {
			return Err(VerifpalError::parse(
				"a model declares at most one `scenarios` block".into(),
			)
			.at(self.here())
			.labelled("a second `scenarios` block")
			.note(
				"one block lists every peer instantiation to analyze, and each entry is \
				 a whole-model configuration; a second block would silently replace the \
				 first rather than add to it",
			)
			.help("move these entries into the block above"));
		}
		let queries_leading_comments = self.take_leading();
		let queries_kw = self.pos;
		if !self.try_expect_keyword("queries") {
			if !scenarios.is_empty() {
				return Err(VerifpalError::parse(
					"the `scenarios` block must come directly before `queries`".into(),
				)
				.at(self.here())
				.labelled(self.found_here())
				.note(
					"a scenario names constants the model has already declared, and \
					 `queries` closes the model, so the only place the block can go is \
					 between the two",
				)
				.help("move this above the `scenarios` block"));
			}
			return Err(VerifpalError::parse("model has no `queries` block".into())
				.at(self.here())
				.labelled(self.found_here())
				.note("a model must ask at least one question, or there is nothing to verify")
				.help("add `queries[ confidentiality? m ]` at the end of the model"));
		}
		self.record_from(queries_kw, crate::tokens::TokenKind::Keyword);
		self.skip_whitespace();
		let queries_bracket = self.pos;
		self.expect("[")?;
		let queries_header_trailing = self.try_take_trailing();
		self.consume_trivia();
		let mut queries = Vec::new();
		loop {
			self.consume_trivia();
			if self.peek() == Some(b']') {
				break;
			}
			if self.at_end() {
				if queries.is_empty() {
					break;
				}
				return Err(self.unclosed_hint(
					VerifpalError::parse("the `queries` block is never closed".into())
						.at(self.here())
						.labelled(self.found_here()),
					queries_bracket,
				));
			}
			let mut leading = self.take_leading();
			let mut query = self.parse_query()?;
			leading.extend(self.take_leading());
			query.leading_comments = leading;
			query.trailing_comment = self.try_take_trailing();
			queries.push(query);
			self.consume_trivia();
		}
		if queries.is_empty() {
			return Err(VerifpalError::parse("`queries` block is empty".into())
				.at(Span::new(queries_kw, queries_kw + "queries".len()))
				.labelled("no queries here")
				.note("a model must ask at least one question, or there is nothing to verify")
				.help("add a query, for example `confidentiality? m`"));
		}
		let queries_tail_comments = self.take_leading();
		let queries_closing_trailing = if self.peek() == Some(b']') {
			self.advance();
			self.try_take_trailing()
		} else {
			None
		};
		self.consume_trivia();
		let tail_comments = self.take_leading();
		self.check_unterminated_block()?;
		if !self.at_end() {
			let trailing = if starts_with_keyword(self.remaining(), "scenarios") {
				"the `scenarios` block must come directly before `queries`"
			} else {
				"content appears after the `queries` block"
			};
			return Err(VerifpalError::parse(trailing.into())
				.at(self.here())
				.labelled(self.found_here())
				.note(
					"`queries` closes the model, so anything after it would never be \
				 analyzed; this is rejected rather than ignored, because a principal \
				 written down here would silently not be checked",
				)
				.help("move this above the `queries` block"));
		}
		Ok(Model {
			file_name: String::new(),
			source: Source::default(),
			attacker: attacker_type,
			blocks,
			scenarios,
			scenarios_leading_comments,
			scenarios_header_trailing,
			scenarios_tail_comments,
			scenarios_closing_trailing,
			queries,
			pre_attacker_comments,
			attacker_trailing,
			queries_leading_comments,
			queries_header_trailing,
			queries_tail_comments,
			queries_closing_trailing,
			tail_comments,
		})
	}

	#[allow(clippy::type_complexity)]
	fn parse_scenarios(
		&mut self,
	) -> VResult<(
		Vec<Scenario>,
		Vec<Comment>,
		Option<Comment>,
		Vec<Comment>,
		Option<Comment>,
	)> {
		if !starts_with_keyword(self.remaining(), "scenarios") {
			return Ok((Vec::new(), Vec::new(), None, Vec::new(), None));
		}
		let leading = self.take_leading();
		let keyword = self.pos;
		self.expect_keyword("scenarios")?;
		self.record_from(keyword, crate::tokens::TokenKind::Keyword);
		self.skip_whitespace();
		let open_bracket = self.pos;
		self.expect_where("[", "after `scenarios`")?;
		let header_trailing = self.try_take_trailing();
		self.consume_trivia();
		let mut scenarios = Vec::new();
		loop {
			self.consume_trivia();
			if self.peek() == Some(b']') {
				break;
			}
			let rem = self.remaining();
			if self.at_end()
				|| starts_with_keyword(rem, "queries")
				|| starts_with_keyword(rem, "principal")
				|| starts_with_keyword(rem, "phase")
			{
				return Err(self.unclosed_hint(
					VerifpalError::parse("the `scenarios` block is never closed".into())
						.at(self.here())
						.labelled(self.found_here()),
					open_bracket,
				));
			}
			let mut entry_leading = self.take_leading();
			let mut scenario = self.parse_scenario()?;
			entry_leading.extend(self.take_leading());
			scenario.leading_comments = entry_leading;
			scenario.trailing_comment = self.try_take_trailing();
			scenarios.push(scenario);
			self.consume_trivia();
		}
		let tail_comments = self.take_leading();
		let closing_trailing = if self.peek() == Some(b']') {
			self.advance();
			self.try_take_trailing()
		} else {
			None
		};
		Ok((
			scenarios,
			leading,
			header_trailing,
			tail_comments,
			closing_trailing,
		))
	}

	fn parse_scenario(&mut self) -> VResult<Scenario> {
		let start = self.pos;
		let name = self.parse_identifier()?;
		self.record_principal_name()?;
		let name = title_case(&name);
		let (principal, principal_name) = self.principal_id(&name)?;
		self.skip_whitespace();
		self.expect_where("[", &format!("after `{}` in the `scenarios` block", name))?;
		self.consume_trivia();
		let mut bindings = Vec::new();
		loop {
			self.consume_trivia();
			if self.peek() == Some(b']') {
				self.advance();
				break;
			}
			if self.at_end() {
				return Err(VerifpalError::parse(
					format!("`{}`'s scenario bindings are never closed", name).into(),
				)
				.at(self.here()));
			}
			let target = self.parse_constant()?;
			self.consume_trivia();
			self.expect_where("=", "in a scenario binding")?;
			self.consume_trivia();
			let value = self.parse_constant()?;
			bindings.push((target, value));
			self.consume_trivia();
			if self.peek() == Some(b',') {
				self.advance();
			}
		}
		if bindings.is_empty() {
			return Err(VerifpalError::parse(
				format!("`{}` names no bindings in this scenario", name).into(),
			)
			.at(Span::new(start, self.pos))
			.note("a scenario binds at least one constant to the value that instance uses")
			.help(format!("write it as `{}[gpeer = gb]`", name)));
		}
		Ok(Scenario {
			span: Span::new(start, self.pos),
			principal,
			principal_name,
			bindings,
			leading_comments: Vec::new(),
			trailing_comment: None,
		})
	}

	fn parse_block(&mut self) -> VResult<Block> {
		self.consume_trivia();
		let leading = self.take_leading();

		let mut block = if starts_with_keyword(self.remaining(), "phase") {
			self.parse_phase()?
		} else if starts_with_keyword(self.remaining(), "principal") {
			self.parse_principal()?
		} else {
			self.parse_message_block()?
		};
		// A block may already hold comments found inside its own brackets; the
		// ones that preceded it come first.
		let prepend = |own: &mut Vec<Comment>| {
			let mut all = leading;
			all.append(own);
			*own = all;
		};
		match &mut block {
			Block::Principal(p) => prepend(&mut p.leading_comments),
			Block::Message(m) => prepend(&mut m.leading_comments),
			Block::Phase(p) => prepend(&mut p.leading_comments),
		}
		Ok(block)
	}

	fn parse_principal(&mut self) -> VResult<Block> {
		let start = self.pos;
		self.expect_keyword("principal")?;
		self.record_from(start, crate::tokens::TokenKind::Keyword);
		self.skip_whitespace();
		let name = self.parse_identifier()?;
		self.record_principal_name()?;
		let name = title_case(&name);
		self.skip_whitespace();
		let open_bracket = self.pos;
		self.expect_where("[", &format!("after `principal {}`", name))?;
		let header_trailing = self.try_take_trailing();
		self.consume_trivia();
		let mut expressions = Vec::new();
		while self.peek() != Some(b']') {
			self.consume_trivia();
			if self.peek() == Some(b']') {
				break;
			}
			if self.at_end() {
				return Err(self.unclosed_hint(
					VerifpalError::parse(format!("`{}`'s block is never closed", name).into())
						.at(self.here()),
					open_bracket,
				));
			}
			let leading = self.take_leading();
			let mut expr = self
				.parse_expression()
				.map_err(|e| self.unclosed_hint(e, open_bracket))?;
			expr.leading_comments = leading;
			expr.leading_comments.extend(self.take_leading());
			expr.trailing_comment = self.try_take_trailing();
			expressions.push(expr);
			self.consume_trivia();
		}
		let tail_comments = self.take_leading();
		self.expect("]")?;
		let end = self.pos;
		let closing_trailing = self.try_take_trailing();
		self.consume_trivia();
		let id = self.principals.intern(&name)?;
		Ok(Block::Principal(Principal {
			name,
			id,
			span: Span::new(start, end),
			expressions,
			leading_comments: Vec::new(),
			header_trailing,
			tail_comments,
			closing_trailing,
		}))
	}

	fn expect_arrow(&mut self, note: &'static str) -> VResult<()> {
		let arrow_at = self.pos;
		if self.try_expect("->") || self.try_expect("\u{2192}") {
			self.record_from(arrow_at, crate::tokens::TokenKind::Arrow);
			return Ok(());
		}
		Err(
			VerifpalError::parse("expected `->` after the sender's name".into())
				.at(self.here())
				.labelled(self.found_here())
				.note(note),
		)
	}

	fn parse_message_block(&mut self) -> VResult<Block> {
		let start = self.pos;
		let sender_name = self.parse_identifier()?;
		self.record_principal_name()?;
		let sender_name = title_case(&sender_name);
		self.skip_whitespace();
		self.expect_arrow("a message is written `Sender -> Recipient: constant, ...`")?;
		self.skip_whitespace();
		let recipient_name = self.parse_identifier()?;
		self.record_principal_name()?;
		let recipient_name = title_case(&recipient_name);
		self.skip_whitespace();
		self.expect_where(":", "after the recipient's name")
			.map_err(|e| e.note("a message is written `Sender -> Recipient: constant, ...`"))?;
		self.skip_whitespace();
		let constants = self.parse_message_constants()?;
		let end = self.trimmed_pos();
		let trailing = self.try_take_trailing();
		self.consume_trivia();
		let (sender, sender_name) = self.principal_id(&sender_name)?;
		let (recipient, recipient_name) = self.principal_id(&recipient_name)?;
		Ok(Block::Message(Message {
			span: Span::new(start, end),
			sender,
			sender_name,
			recipient,
			recipient_name,
			constants,
			leading_comments: Vec::new(),
			trailing_comment: trailing,
		}))
	}

	fn parse_message_constants(&mut self) -> VResult<Vec<Constant>> {
		let mut constants = Vec::new();
		loop {
			self.skip_inline_whitespace();
			if self.at_end() || self.peek() == Some(b'\n') || self.peek() == Some(b'\r') {
				break;
			}
			let rem = self.remaining();
			if starts_with_keyword(rem, "principal")
				|| starts_with_keyword(rem, "phase")
				|| starts_with_keyword(rem, "queries")
				|| rem.starts_with("//")
				|| rem.starts_with("/*")
			{
				break;
			}
			let saved = self.snapshot();
			let starts_next_message = self.parse_identifier().is_ok() && {
				self.skip_whitespace();
				let rem = self.remaining();
				rem.starts_with("->") || rem.starts_with("\u{2192}")
			};
			self.restore(saved);
			if starts_next_message {
				break;
			}

			let constant = if self.peek() == Some(b'[') {
				self.parse_guarded_constant()?
			} else {
				self.parse_constant()?
			};
			constants.push(constant);
			self.skip_inline_whitespace();
			if self.peek() == Some(b',') {
				self.advance();
			}
		}
		if constants.is_empty() {
			return Err(VerifpalError::parse("message carries no constants".into())
				.at(self.here())
				.labelled(self.found_here())
				.note("a message has to carry at least one value")
				.help("name the values being sent, e.g. `Alice -> Bob: ga, e`"));
		}
		Ok(constants)
	}

	fn parse_guarded_constant(&mut self) -> VResult<Constant> {
		self.expect("[")?;
		let mut c = self.parse_constant()?;
		self.skip_whitespace();
		self.expect("]")?;
		self.skip_inline_whitespace();
		if self.peek() == Some(b',') {
			self.advance();
		}
		c.guard = true;
		Ok(c)
	}

	fn parse_expression(&mut self) -> VResult<Expression> {
		self.consume_trivia();
		let rem = self.remaining();
		if starts_with_keyword(rem, "knows") {
			self.parse_knows()
		} else if starts_with_keyword(rem, "generates") {
			self.parse_simple_expression("generates", Declaration::Generates)
		} else if starts_with_keyword(rem, "leaks") {
			self.parse_simple_expression("leaks", Declaration::Leaks)
		} else {
			self.parse_assignment()
		}
	}

	fn parse_knows(&mut self) -> VResult<Expression> {
		let start = self.pos;
		self.expect_keyword("knows")?;
		self.record_from(start, crate::tokens::TokenKind::Keyword);
		self.skip_whitespace();
		let qualifier_str = self.parse_identifier()?;
		let qualifier = match qualifier_str.as_str() {
			"private" => Qualifier::Private,
			"public" => Qualifier::Public,
			_ => {
				return Err(VerifpalError::parse(
					format!("unknown qualifier `{}`", qualifier_str).into(),
				)
				.at(self.last_ident)
				.narrow(qualifier_str.clone())
				.note("`knows` takes one of `private` or `public`")
				.suggest(did_you_mean(&qualifier_str, ["private", "public"])));
			}
		};
		self.record(self.last_ident, crate::tokens::TokenKind::Qualifier);
		self.skip_whitespace();
		let constants = self.parse_constants()?;
		Ok(Expression {
			span: Span::new(start, self.trimmed_pos()),
			kind: Declaration::Knows,
			qualifier: Some(qualifier),
			constants,
			assigned: None,
			leading_comments: Vec::new(),
			trailing_comment: None,
		})
	}

	fn parse_simple_expression(&mut self, keyword: &str, kind: Declaration) -> VResult<Expression> {
		let start = self.pos;
		self.expect_keyword(keyword)?;
		self.record_from(start, crate::tokens::TokenKind::Keyword);
		self.skip_whitespace();
		let constants = self.parse_constants()?;
		Ok(Expression {
			span: Span::new(start, self.trimmed_pos()),
			kind,
			qualifier: None,
			constants,
			assigned: None,
			leading_comments: Vec::new(),
			trailing_comment: None,
		})
	}

	fn parse_assignment(&mut self) -> VResult<Expression> {
		let start = self.pos;
		self.anonymous_ok = true;
		let constants = self.parse_constants();
		self.anonymous_ok = false;
		let constants = constants?;
		self.skip_whitespace();
		let assign_at = self.pos;
		self.expect("=")?;
		self.record_from(assign_at, crate::tokens::TokenKind::Assign);
		self.skip_whitespace();
		let value = self.parse_value()?;
		if let Value::Constant(c) = &value {
			return Err(VerifpalError::parse(
				"the right of an `=` must be a primitive, not a constant".into(),
			)
			.at(Span::new(start, self.pos))
			.narrow(c.name.to_string())
			.labelled("this is just another name for an existing value")
			.note(
				"assignment in Verifpal names the result of a computation; renaming \
				 a value would give the same value two names and make queries ambiguous",
			)
			.help(format!("compute something, e.g. `= HASH({})`", c)));
		}
		Ok(Expression {
			span: Span::new(start, self.value_end),
			kind: Declaration::Assignment,
			qualifier: None,
			constants,
			assigned: Some(value),
			leading_comments: Vec::new(),
			trailing_comment: None,
		})
	}

	fn skip_inline_whitespace(&mut self) {
		while self.pos < self.input.len() {
			let c = self.input[self.pos];
			if c == b' ' || c == b'\t' {
				self.pos += 1;
			} else {
				break;
			}
		}
	}

	fn parse_constants(&mut self) -> VResult<Vec<Constant>> {
		let mut constants = Vec::new();
		loop {
			self.skip_inline_whitespace();
			if self.at_end() {
				break;
			}
			let c = self.peek();
			if c == Some(b'=')
				|| c == Some(b']')
				|| c == Some(b')')
				|| c == Some(b'\n')
				|| c == Some(b'\r')
			{
				break;
			}
			let rem = self.remaining();
			if starts_with_keyword(rem, "knows")
				|| starts_with_keyword(rem, "generates")
				|| starts_with_keyword(rem, "leaks")
				|| rem.starts_with("//")
				|| rem.starts_with("/*")
			{
				break;
			}
			constants.push(self.parse_constant()?);
			self.skip_inline_whitespace();
			if self.peek() == Some(b',') {
				self.advance();
			}
		}
		if constants.is_empty() {
			return Err(
				VerifpalError::parse("expected at least one constant".into())
					.at(self.here())
					.labelled(self.found_here()),
			);
		}
		Ok(constants)
	}

	fn parse_constant(&mut self) -> VResult<Constant> {
		let name = self.parse_identifier()?;
		check_reserved(&name).map_err(|e| e.at(self.last_ident))?;
		if name == "_" && !self.anonymous_ok {
			return Err(VerifpalError::parse(
				"`_` can only name the output of an assignment".into(),
			)
			.at(self.last_ident)
			.note("an anonymous constant is a value the model computes and never uses again, so it has no place in a declaration, a message or a query")
			.help("give the constant a name"));
		}
		self.record(
			self.last_ident,
			if name == "_" {
				crate::tokens::TokenKind::Anonymous
			} else {
				crate::tokens::TokenKind::ConstantName
			},
		);
		let actual_name: Arc<str> = if name == "_" {
			let n = self.unnamed_counter;
			self.unnamed_counter += 1;
			Arc::from(format!("{}_{}", crate::util::ANONYMOUS_PREFIX, n))
		} else {
			Arc::from(name)
		};
		let id = self.values.intern(&actual_name)?;
		Ok(Constant {
			name: actual_name,
			id,
			guard: false,
			fresh: false,
			leaked: false,
			declaration: None,
			qualifier: None,
		})
	}

	fn parse_constant_value(&mut self) -> VResult<Value> {
		let constant = self.parse_constant()?;
		self.value_end = self.pos;
		Ok(Value::Constant(constant))
	}

	fn parse_value(&mut self) -> VResult<Value> {
		self.skip_whitespace();
		let saved = self.snapshot();
		if let Ok(name) = self.parse_identifier() {
			self.skip_whitespace();
			if self.peek() == Some(b'(')
				|| (self.peek() == Some(b'[') && primitive_get_enum(&name.to_uppercase()).is_ok())
			{
				self.restore(saved);
				return self.parse_primitive();
			}
			self.restore(saved);
			return self.parse_constant_value();
		}
		self.restore(saved);
		Err(VerifpalError::parse("expected a value".into())
			.at(self.here())
			.labelled(self.found_here())
			.note("a value is a constant, or a primitive such as `HASH(m)`"))
	}

	fn parse_capability_onset(&mut self) -> VResult<i32> {
		let saved = self.snapshot();
		let Ok(word) = self.parse_identifier() else {
			self.restore(saved);
			return Ok(0);
		};
		if !word.eq_ignore_ascii_case("from") {
			self.restore(saved);
			return Ok(0);
		}
		self.record(self.last_ident, crate::tokens::TokenKind::Capability);
		self.consume_trivia();
		let kw = self.parse_identifier()?;
		if !kw.eq_ignore_ascii_case("phase") {
			return Err(VerifpalError::parse("expected `phase` after `from`".into())
				.at(self.last_ident)
				.labelled(format!("found `{}`", kw))
				.note("an assumption that starts later is written `from phase N`")
				.help("write it as `from phase 1`"));
		}
		self.record(self.last_ident, crate::tokens::TokenKind::Capability);
		self.consume_trivia();
		let start = self.pos;
		while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
			self.pos += 1;
		}
		self.record_from(start, crate::tokens::TokenKind::PhaseNumber);
		if start == self.pos {
			return Err(
				VerifpalError::parse("expected a phase number after `from phase`".into())
					.at(self.here())
					.labelled(self.found_here())
					.note("`from phase N` means the assumption holds from phase N onward"),
			);
		}
		std::str::from_utf8(&self.input[start..self.pos])
			.ok()
			.and_then(|s| s.parse::<i32>().ok())
			.ok_or_else(|| {
				VerifpalError::parse("invalid phase number in primitive parameter".into())
					.at(Span::at(start))
			})
	}

	fn parse_capabilities(&mut self) -> VResult<Capabilities> {
		let start = self.pos;
		self.expect("[")?;
		let mut caps = Capabilities::default();
		loop {
			self.consume_trivia();
			let word = self.parse_identifier()?;
			let word_span = self.last_ident;
			let cap = Capability::from_name(&word).ok_or_else(|| {
				VerifpalError::parse(format!("unknown weakening assumption `{}`", word).into())
					.at(Span::new(start, self.pos))
					.narrow(word.clone())
					.note(
						"an assumption names a property the primitive loses: `weak` \
						 (confidentiality), `forgeable` (authenticity) or `malleable` \
						 (a ciphertext can be reshaped)",
					)
					.suggest(did_you_mean(&word, ["weak", "forgeable", "malleable"]))
			})?;
			if caps.has(cap) {
				return Err(VerifpalError::parse(
					format!("`{}` is declared twice on this primitive", cap.name()).into(),
				)
				.at(Span::new(start, self.pos))
				.narrow_occurrence(cap.name(), 1)
				.labelled("declared again here")
				.help("remove the duplicate"));
			}
			self.record(word_span, crate::tokens::TokenKind::Capability);
			self.consume_trivia();
			let onset = self.parse_capability_onset()?;
			caps.set(cap, onset);
			self.consume_trivia();
			if self.peek() == Some(b',') {
				self.advance();
				continue;
			}
			break;
		}
		self.consume_trivia();
		self.expect("]")?;
		Ok(caps)
	}

	fn parse_primitive(&mut self) -> VResult<Value> {
		if self.depth >= MAX_NESTING {
			return Err(VerifpalError::parse(
				format!("primitives nest deeper than {MAX_NESTING} levels").into(),
			)
			.at(self.here())
			.note("a protocol computes nothing this deep, so a term this deep is almost certainly generated by mistake")
			.help("name an intermediate value and build on it instead"));
		}
		self.depth += 1;
		let parsed = self.parse_primitive_nested();
		self.depth -= 1;
		parsed
	}

	fn parse_primitive_nested(&mut self) -> VResult<Value> {
		let name_start = self.pos;
		let name = self.parse_identifier()?;
		let name_end = self.pos;
		self.record(
			Span::new(name_start, name_end),
			crate::tokens::TokenKind::PrimitiveName,
		);
		let prim_name = name.to_uppercase();
		self.skip_whitespace();
		let capabilities = if self.peek() == Some(b'[') {
			self.parse_capabilities()?
		} else {
			Capabilities::default()
		};
		self.skip_whitespace();
		let open_paren = self.pos;
		self.expect_where("(", &format!("after `{}`", prim_name))?;
		self.consume_trivia();
		let mut arguments = Vec::new();
		while self.peek() != Some(b')') {
			if self.at_end() {
				return Err(VerifpalError::parse(
					format!("unterminated arguments to `{}`", prim_name).into(),
				)
				.at(self.here())
				.label(Span::at(open_paren), "this `(` is never closed")
				.help("add the missing `)`"));
			}
			let arg = self
				.parse_value()
				.map_err(|e| self.unclosed_hint(e, open_paren))?;
			arguments.push(arg);
			self.consume_trivia();
			if self.peek() == Some(b',') {
				self.advance();
				self.consume_trivia();
			}
		}
		self.expect(")")?;
		let check_at = self.pos;
		let check = self.try_expect("?");
		if check {
			self.record_from(check_at, crate::tokens::TokenKind::Check);
		}
		self.value_end = self.pos;
		// Stay on this line: crossing the newline here would let a comment on
		// the next line be taken as this expression's trailing comment.
		self.skip_inline_whitespace();
		if self.peek() == Some(b',') {
			self.advance();
		}
		let prim_id = primitive_get_enum(&prim_name).map_err(|_| {
			VerifpalError::parse(format!("unknown primitive `{}`", prim_name).into())
				.at(Span::new(name_start, name_end))
				.labelled("not a Verifpal primitive")
				.suggest(did_you_mean(&prim_name, primitive_names()))
		})?;
		Ok(Value::Primitive(Arc::new(Primitive {
			id: prim_id,
			arguments,
			output: 0,
			instance_check: check,
			capabilities,
			hash: HashCell::default(),
		})))
	}

	fn parse_phase(&mut self) -> VResult<Block> {
		let block_start = self.pos;
		self.expect_keyword("phase")?;
		self.record_from(block_start, crate::tokens::TokenKind::Keyword);
		self.consume_trivia();
		self.expect("[")?;
		self.consume_trivia();
		let start = self.pos;
		while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
			self.pos += 1;
		}
		self.record_from(start, crate::tokens::TokenKind::PhaseNumber);
		let num_str = std::str::from_utf8(&self.input[start..self.pos])
			.map_err(|_| VerifpalError::parse("invalid UTF-8 in phase number".into()))?;
		let number: i32 = num_str.parse().map_err(|_| {
			VerifpalError::parse("expected a phase number".into())
				.at(self.here())
				.labelled(self.found_here())
				.note("a phase is written `phase[1]`, `phase[2]`, and so on")
		})?;
		self.consume_trivia();
		self.expect("]")?;
		let block_end = self.pos;
		let inner_comments = self.take_leading();
		let trailing = self.try_take_trailing();
		self.consume_trivia();
		Ok(Block::Phase(Phase {
			span: Span::new(block_start, block_end),
			number,
			leading_comments: inner_comments,
			trailing_comment: trailing,
		}))
	}

	fn parse_query(&mut self) -> VResult<Query> {
		self.consume_trivia();
		let rem = self.remaining();
		if starts_with_ignoring_case(rem, "confidentiality?") {
			self.parse_query_single_constant("confidentiality?", QueryKind::Confidentiality)
		} else if starts_with_ignoring_case(rem, "authentication?") {
			self.parse_query_authentication()
		} else if starts_with_ignoring_case(rem, "freshness?") {
			self.parse_query_single_constant("freshness?", QueryKind::Freshness)
		} else if starts_with_ignoring_case(rem, "unlinkability?") {
			self.parse_query_multi_constant("unlinkability?", QueryKind::Unlinkability)
		} else if starts_with_ignoring_case(rem, "equivalence?") {
			self.parse_query_multi_constant("equivalence?", QueryKind::Equivalence)
		} else {
			{
				let word: String = rem
					.chars()
					.take_while(|c| c.is_alphanumeric() || *c == '_')
					.collect();
				Err(VerifpalError::parse(
					if word.is_empty() {
						"expected a query".to_string()
					} else {
						format!("unknown query type `{}`", word)
					}
					.into(),
				)
				.at(Span::new(self.pos, self.pos + word.len().max(1)))
				.note(
					"a query is one of `confidentiality?`, `authentication?`, \
					 `freshness?`, `unlinkability?` or `equivalence?`",
				)
				.suggest(did_you_mean(
					&word,
					[
						"confidentiality",
						"authentication",
						"freshness",
						"unlinkability",
						"equivalence",
					],
				)))
			}
		}
	}

	fn parse_query_single_constant(&mut self, keyword: &str, kind: QueryKind) -> VResult<Query> {
		let start = self.pos;
		self.expect_keyword(keyword)?;
		self.record_from(start, crate::tokens::TokenKind::QueryKind);
		self.skip_whitespace();
		let constant = self.parse_constant()?;
		self.skip_inline_whitespace();
		let options = self.try_parse_query_options()?;
		Ok(Query {
			span: Span::new(start, self.trimmed_pos()),
			kind,
			constants: vec![constant],
			message: Message::default(),
			options,
			leading_comments: Vec::new(),
			trailing_comment: None,
		})
	}

	fn parse_query_authentication(&mut self) -> VResult<Query> {
		let start = self.pos;
		self.expect_keyword("authentication?")?;
		self.record_from(start, crate::tokens::TokenKind::QueryKind);
		self.skip_whitespace();
		let sender_name = title_case(&self.parse_identifier()?);
		self.record_principal_name()?;
		self.skip_whitespace();
		self.expect_arrow("an authentication query is written `authentication? Alice -> Bob: m`")?;
		self.skip_whitespace();
		let recipient_name = title_case(&self.parse_identifier()?);
		self.record_principal_name()?;
		self.skip_whitespace();
		self.expect(":")?;
		self.skip_whitespace();
		let constant = self.parse_constant()?;
		self.skip_inline_whitespace();
		let (sender, sender_name) = self.principal_id(&sender_name)?;
		let (recipient, recipient_name) = self.principal_id(&recipient_name)?;
		let options = self.try_parse_query_options()?;
		let end = self.trimmed_pos();
		Ok(Query {
			span: Span::new(start, end),
			kind: QueryKind::Authentication,
			constants: vec![],
			message: Message {
				span: Span::new(start, end),
				sender,
				sender_name,
				recipient,
				recipient_name,
				constants: vec![constant],
				leading_comments: Vec::new(),
				trailing_comment: None,
			},
			options,
			leading_comments: Vec::new(),
			trailing_comment: None,
		})
	}

	fn parse_query_multi_constant(&mut self, keyword: &str, kind: QueryKind) -> VResult<Query> {
		let start = self.pos;
		self.expect_keyword(keyword)?;
		self.record_from(start, crate::tokens::TokenKind::QueryKind);
		self.skip_whitespace();
		let constants = self.parse_query_constant_list()?;
		self.skip_inline_whitespace();
		let options = self.try_parse_query_options()?;
		Ok(Query {
			span: Span::new(start, self.trimmed_pos()),
			kind,
			constants,
			message: Message::default(),
			options,
			leading_comments: Vec::new(),
			trailing_comment: None,
		})
	}

	fn parse_query_constant_list(&mut self) -> VResult<Vec<Constant>> {
		let mut constants = Vec::new();
		loop {
			// Look past the whitespace without keeping it: the query's span
			// must end at its last constant, not at whatever follows.
			let before = self.pos;
			self.skip_whitespace();
			if self.peek() == Some(b'[') {
				break;
			}
			let rem = self.remaining();
			if self.at_end()
				|| self.peek() == Some(b']')
				|| starts_with_keyword(rem, "confidentiality")
				|| starts_with_keyword(rem, "authentication")
				|| starts_with_keyword(rem, "freshness")
				|| starts_with_keyword(rem, "unlinkability")
				|| starts_with_keyword(rem, "equivalence")
				|| rem.starts_with("//")
				|| rem.starts_with("/*")
			{
				self.pos = before;
				break;
			}
			constants.push(self.parse_constant()?);
			self.skip_inline_whitespace();
			if self.peek() == Some(b',') {
				self.advance();
			}
		}
		Ok(constants)
	}

	fn try_parse_query_options(&mut self) -> VResult<Vec<QueryOption>> {
		self.skip_inline_whitespace();
		if self.peek() != Some(b'[') {
			return Ok(vec![]);
		}
		self.advance();
		self.consume_trivia();
		let mut options = Vec::new();
		while self.peek() != Some(b']') {
			if self.at_end() {
				break;
			}
			self.consume_trivia();
			if self.peek() == Some(b']') {
				break;
			}
			let option_start = self.pos;
			let mut leading = self.take_leading();
			let option_name = self.parse_identifier()?;
			self.record(self.last_ident, crate::tokens::TokenKind::Keyword);
			self.consume_trivia();
			self.expect("[")?;
			self.consume_trivia();
			let sender_name = title_case(&self.parse_identifier()?);
			self.record_principal_name()?;
			self.consume_trivia();
			self.expect_arrow("a precondition is written `precondition[ Bob -> Alice: ack ]`")?;
			self.consume_trivia();
			let recipient_name = title_case(&self.parse_identifier()?);
			self.record_principal_name()?;
			self.consume_trivia();
			self.expect(":")?;
			self.consume_trivia();
			let constant = self.parse_constant()?;
			self.consume_trivia();
			self.expect("]")?;
			leading.extend(self.take_leading());
			let trailing = self.try_take_trailing();
			self.consume_trivia();

			let option_kind = match option_name.as_str() {
				"precondition" => QueryOptionKind::Precondition,
				_ => {
					return Err(VerifpalError::parse(
						format!("unknown query option `{}`", option_name).into(),
					)
					.at(self.last_ident)
					.narrow(option_name.clone())
					.note("the only query option is `precondition`")
					.suggest(did_you_mean(&option_name, ["precondition"])));
				}
			};
			let (sender, sender_name) = self.principal_id(&sender_name)?;
			let (recipient, recipient_name) = self.principal_id(&recipient_name)?;
			options.push(QueryOption {
				kind: option_kind,
				message: Message {
					span: Span::new(option_start, self.pos),
					sender,
					sender_name,
					recipient,
					recipient_name,
					constants: vec![constant],
					leading_comments: Vec::new(),
					trailing_comment: None,
				},
				leading_comments: leading,
				trailing_comment: trailing,
			});
		}
		if self.peek() == Some(b']') {
			self.advance();
		}
		Ok(options)
	}
}

fn validate_file_name(file_path: &str, file_name: &str) -> VResult<()> {
	if file_name.is_empty() {
		return Err(
			VerifpalError::parse(format!("`{}` does not name a file", file_path).into())
				.note("Verifpal reads a single model file, whose name ends in a `.vp` extension"),
		);
	}
	let length = file_name.chars().count();
	if length > 64 {
		return Err(VerifpalError::parse(
			format!(
				"model file name is {} characters long, and must be 64 or less",
				length
			)
			.into(),
		)
		.help("rename the file to something shorter"));
	}
	if !file_name.ends_with(".vp") {
		return Err(VerifpalError::parse(
			format!("`{}` is not a Verifpal model file name", file_name).into(),
		)
		.note("Verifpal models are named with a `.vp` extension")
		.help(format!("rename it to `{}.vp`", file_name)));
	}
	Ok(())
}

pub(crate) fn parse_file(file_path: &str) -> VResult<Model> {
	let path = std::path::Path::new(file_path);
	let file_name = path
		.file_name()
		.and_then(|n| n.to_str())
		.unwrap_or("")
		.to_string();
	validate_file_name(file_path, &file_name)?;

	let content = std::fs::read_to_string(file_path)
		.map_err(|e| VerifpalError::parse(format!("cannot read `{}`: {}", file_path, e).into()))?;

	parse_string(&file_name, &content)
}

#[cfg_attr(not(any(test, feature = "lsp")), allow(dead_code))]
pub(crate) fn parse_string_indexed(
	file_name: &str,
	input: &str,
) -> (VResult<Model>, crate::tokens::TokenIndex) {
	let mut parser = Parser::new(input);
	parser.tokens = Some(crate::tokens::TokenIndex::default());
	let parsed = parser
		.parse_model()
		.map_err(|e| e.or_span(Span::at(parser.pos)).located(file_name, input));
	let index = parser.tokens.take().unwrap_or_default();
	let model = parsed.map(|mut model| {
		model.file_name = file_name.to_string();
		model.source = Source::from(input);
		model
	});
	(model, index)
}

pub(crate) fn parse_string(file_name: &str, input: &str) -> VResult<Model> {
	let mut parser = Parser::new(input);
	let mut model = parser
		.parse_model()
		.map_err(|e| e.or_span(Span::at(parser.pos)).located(file_name, input))?;
	model.file_name = file_name.to_string();
	model.source = Source::from(input);
	Ok(model)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn spans_end_at_their_last_character() {
		let src = "attacker[passive]\n\nprincipal Alice[\n\tknows private sp_a\n\tsp_ga = PUBKEY(sp_a)\n]\n\nAlice -> Bob: sp_ga\n\nprincipal Bob[\n\tknows private sp_b\n\t_ = HASH(sp_ga)\n]\n\nqueries[\n\tconfidentiality? sp_a\n\tequivalence? sp_a, sp_b\n\tconfidentiality? sp_b[\n\t\tprecondition[Alice -> Bob: sp_ga]\n\t]\n]\n";
		let m = parse_string("sp.vp", src).expect("parses");
		let text = |span: Span| &src[span.start..span.end];
		let Block::Principal(alice) = &m.blocks[0] else {
			panic!("Alice comes first");
		};
		assert!(text(alice.span).ends_with(']'), "{:?}", text(alice.span));
		assert_eq!(text(alice.expressions[0].span), "knows private sp_a");
		assert_eq!(text(alice.expressions[1].span), "sp_ga = PUBKEY(sp_a)");
		let Block::Message(message) = &m.blocks[1] else {
			panic!("then the message");
		};
		assert_eq!(text(message.span), "Alice -> Bob: sp_ga");
		assert_eq!(text(m.queries[0].span), "confidentiality? sp_a");
		assert_eq!(text(m.queries[1].span), "equivalence? sp_a, sp_b");
		assert_eq!(
			text(m.queries[2].span),
			"confidentiality? sp_b[\n\t\tprecondition[Alice -> Bob: sp_ga]\n\t]"
		);
	}

	#[test]
	fn a_scenarios_block_binds_a_constant_per_principal_instance() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows public scn_gpeer\n\
			knows private scn_a\n\
			scn_e = ENC(scn_gpeer, scn_a)\n\
			]\n\
			scenarios[\n\
			Alice[scn_gpeer = scn_gb]\n\
			Alice[scn_gpeer = scn_gm]\n\
			]\n\
			queries[\n\
			confidentiality? scn_a\n\
			]\n";
		let m = parse_string("scn.vp", src).expect("parses");
		assert_eq!(m.scenarios.len(), 2);
		assert_eq!(m.scenarios[0].bindings.len(), 1);
		assert_eq!(&*m.scenarios[0].principal_name, "Alice");
		assert_eq!(&*m.scenarios[0].bindings[0].0.name, "scn_gpeer");
		assert_eq!(&*m.scenarios[0].bindings[0].1.name, "scn_gb");
		assert_eq!(&*m.scenarios[1].bindings[0].1.name, "scn_gm");
	}

	#[test]
	fn a_model_without_scenarios_has_none() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private nsc_a\n\
			]\n\
			queries[\n\
			confidentiality? nsc_a\n\
			]\n";
		let m = parse_string("nsc.vp", src).expect("parses");
		assert!(m.scenarios.is_empty());
	}

	fn first_assigned(m: &Model) -> String {
		let Block::Principal(p) = &m.blocks[0] else {
			panic!("expected a principal block");
		};
		format!(
			"{:?}",
			p.expressions
				.iter()
				.find_map(|e| e.assigned.as_ref())
				.expect("an assignment")
		)
	}

	fn first_primitive(m: &Model) -> Option<Primitive> {
		let Block::Principal(p) = &m.blocks[0] else {
			return None;
		};
		p.expressions
			.iter()
			.find_map(|e| match e.assigned.as_ref() {
				Some(Value::Primitive(p)) => Some((**p).clone()),
				_ => None,
			})
	}

	#[test]
	fn parses_primitive_capabilities() {
		let src = "attacker[active]\nprincipal Alice[\n\tknows private cap1_sk\n\tknows private cap1_m\n\tcap1_s = SIGN[forgeable](cap1_sk, cap1_m)\n]\nqueries[\n\tconfidentiality? cap1_m\n]\n";
		let m = parse_string("cap1.vp", src).expect("parses");
		let p = first_primitive(&m).expect("a primitive");
		assert!(p.capabilities.has(Capability::Forgeable));
		assert_eq!(p.capabilities.onset(Capability::Forgeable), Some(0));
		assert!(!p.capabilities.has(Capability::Weak));
	}

	#[test]
	fn parses_capability_with_phase_onset() {
		let src = "attacker[active]\nprincipal Alice[\n\tknows private cap2_k\n\tknows private cap2_m\n\tknows private cap2_ad\n\tcap2_e = AEAD_ENC[forgeable, weak from phase 2](cap2_k, cap2_m, cap2_ad)\n]\nqueries[\n\tconfidentiality? cap2_m\n]\n";
		let m = parse_string("cap2.vp", src).expect("parses");
		let p = first_primitive(&m).expect("a primitive");
		assert_eq!(p.capabilities.onset(Capability::Forgeable), Some(0));
		assert_eq!(p.capabilities.onset(Capability::Weak), Some(2));
	}

	#[test]
	fn rejects_unknown_capability() {
		let src = "attacker[active]\nprincipal Alice[\n\tknows private cap3_m\n\tcap3_h = HASH[bogus](cap3_m)\n]\nqueries[\n\tconfidentiality? cap3_m\n]\n";
		let err = parse_string("cap3.vp", src).expect_err("should reject");
		assert!(
			format!("{}", err).contains("unknown weakening assumption"),
			"got: {}",
			err
		);
	}

	#[test]
	fn rejects_duplicate_capability() {
		let src = "attacker[active]\nprincipal Alice[\n\tknows private cap4_m\n\tcap4_h = HASH[weak, weak](cap4_m)\n]\nqueries[\n\tconfidentiality? cap4_m\n]\n";
		let err = parse_string("cap4.vp", src).expect_err("should reject");
		assert!(
			format!("{}", err).contains("is declared twice on this primitive"),
			"got: {}",
			err
		);
	}

	#[test]
	fn pubkey_parses_to_a_primitive() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private brg_a\n\tbrg_ga = PUBKEY(brg_a)\n]\n\nqueries[\n\tconfidentiality? brg_a\n]\n";
		let m = parse_string("new.vp", src).expect("parses");
		assert!(first_assigned(&m).starts_with("Primitive"));
	}

	#[test]
	fn nested_dh_kex_parses_as_a_nested_primitive() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private brn_a\n\tknows private brn_b\n\tbrn_k = DH_KEX(PUBKEY(brn_a), brn_b)\n]\n\nqueries[\n\tconfidentiality? brn_k\n]\n";
		let m = parse_string("new.vp", src).expect("new parses");
		let Block::Principal(p) = &m.blocks[0] else {
			panic!("expected a principal block");
		};
		let assigned = p
			.expressions
			.iter()
			.find_map(|e| e.assigned.as_ref())
			.expect("an assignment");
		let Value::Primitive(outer) = assigned else {
			panic!("expected a primitive, got {:?}", assigned);
		};
		assert_eq!(outer.id, primitive_get_enum("DH_KEX").unwrap());
		assert_eq!(outer.arguments.len(), 2);
		let Value::Primitive(inner) = &outer.arguments[0] else {
			panic!("expected PUBKEY in argument 0");
		};
		assert_eq!(inner.id, primitive_get_enum("PUBKEY").unwrap());
	}

	fn model_error(src: &str) -> String {
		let m = match parse_string("diag.vp", src) {
			Ok(m) => m,
			Err(e) => return e.to_string(),
		};
		crate::sanity::sanity(&m)
			.err()
			.map(|e| e.located(&m.file_name, &m.source).to_string())
			.unwrap_or_default()
	}

	#[test]
	fn a_mistyped_primitive_is_a_parse_error_that_suggests_the_real_one() {
		let text = model_error(
			"attacker[active]\nprincipal Alice[\n\tknows private dm_m\n\tdm_e = AEAD_ENCC(dm_m, dm_m, dm_m)\n]\nqueries[\n\tconfidentiality? dm_m\n]\n",
		);
		assert!(
			text.contains("parse error: unknown primitive `AEAD_ENCC`"),
			"{text}"
		);
		assert!(text.contains("diag.vp:4:9"), "{text}");
		assert!(text.contains("did you mean `AEAD_ENC`?"), "{text}");
	}

	#[test]
	fn a_wrong_arity_names_the_primitive_signature() {
		let text = model_error(
			"attacker[active]\nprincipal Alice[\n\tknows private wa_m\n\twa_e = AEAD_ENC(wa_m, wa_m)\n]\nqueries[\n\tconfidentiality? wa_m\n]\n",
		);
		assert!(
			text.contains("`AEAD_ENC` takes 3 arguments, but 2 were given"),
			"{text}"
		);
		assert!(
			text.contains("its signature is `AEAD_ENC(key, plaintext, ad)`"),
			"{text}"
		);
	}

	fn scenario_model(tail: &str) -> String {
		format!(
			"attacker[active]\n\
			 principal Bob[\n\
			 knows private sb_b\n\
			 sb_gb = PUBKEY(sb_b)\n\
			 ]\n\
			 Bob -> Alice: [sb_gb]\n\
			 principal Alice[\n\
			 knows public sb_gpeer\n\
			 knows private sb_m\n\
			 sb_e = PKE_ENC(sb_gpeer, sb_m)\n\
			 ]\n\
			 Alice -> Bob: sb_e\n\
			 principal Bob[\n\
			 _ = HASH(sb_e)\n\
			 ]\n{tail}"
		)
	}

	#[test]
	fn a_model_declares_at_most_one_scenarios_block() {
		let src = scenario_model(
			"scenarios[\nAlice[sb_gpeer = sb_gb]\n]\n\
			 scenarios[\nAlice[sb_gpeer = sb_gb]\n]\n\
			 queries[\nconfidentiality? sb_m\n]\n",
		);
		let error = parse_string("sb.vp", &src).expect_err("two blocks are refused");
		assert!(
			error.message.contains("at most one `scenarios` block"),
			"got: {}",
			error.message
		);
	}

	#[test]
	fn a_scenarios_block_comes_directly_before_queries() {
		for tail in [
			// Something between the block and `queries`.
			"scenarios[\nAlice[sb_gpeer = sb_gb]\n]\n\
			 principal Bob[\n_ = HASH(sb_gb)\n]\n\
			 queries[\nconfidentiality? sb_m\n]\n",
			// The block after `queries`, which closes the model.
			"queries[\nconfidentiality? sb_m\n]\n\
			 scenarios[\nAlice[sb_gpeer = sb_gb]\n]\n",
		] {
			let error = parse_string("sb.vp", &scenario_model(tail)).expect_err("misplaced block");
			assert!(
				error
					.message
					.contains("must come directly before `queries`"),
				"got: {}",
				error.message
			);
		}
	}

	#[test]
	fn one_scenarios_block_directly_before_queries_is_accepted() {
		let src = scenario_model(
			"scenarios[\nAlice[sb_gpeer = sb_gb]\n]\n\
			 queries[\nconfidentiality? sb_m\n]\n",
		);
		let m = parse_string("sb.vp", &src).expect("the one legal placement");
		assert_eq!(m.scenarios.len(), 1);
	}

	#[test]
	fn a_block_comment_may_follow_a_multi_constant_query() {
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private bc_k1\n\
			knows private bc_k2\n\
			_ = HASH(bc_k1, bc_k2)\n\
			]\n\
			queries[\n\
			equivalence? bc_k1, bc_k2\n\
			/* between two queries */\n\
			freshness? bc_k1\n\
			]\n";
		let m = parse_string("bc.vp", src).expect("a block comment ends a query's constant list");
		assert_eq!(m.queries.len(), 2);
	}

	#[test]
	fn every_keyword_is_recognised_whatever_its_case() {
		let src = "ATTACKER[passive]\n\
			PRINCIPAL Alice[\n\
			KNOWS private ci_m\n\
			GENERATES ci_n\n\
			ci_h = HASH(ci_m, ci_n)\n\
			LEAKS ci_m\n\
			]\n\
			Alice -> Bob: ci_h\n\
			PRINCIPAL Bob[\n\
			_ = HASH(ci_h)\n\
			]\n\
			PHASE[1]\n\
			PRINCIPAL Bob[\n\
			_ = HASH(nil)\n\
			]\n\
			QUERIES[\n\
			CONFIDENTIALITY? ci_m\n\
			FRESHNESS? ci_n\n\
			AUTHENTICATION? Alice -> Bob: ci_h\n\
			]\n";
		let m = parse_string("ci.vp", src)
			.expect("identifiers are case-insensitive, and so are the keywords around them");
		assert_eq!(m.queries.len(), 3);
		assert_eq!(m.attacker, AttackerKind::Passive);
		assert!(
			m.blocks
				.iter()
				.any(|b| matches!(b, Block::Phase(p) if p.number == 1)),
			"`PHASE[1]` declares a phase"
		);
		let declarations: Vec<Declaration> = m
			.blocks
			.iter()
			.filter_map(|b| match b {
				Block::Principal(p) => Some(p.expressions.iter().map(|e| e.kind)),
				_ => None,
			})
			.flatten()
			.collect();
		assert!(declarations.contains(&Declaration::Knows));
		assert!(declarations.contains(&Declaration::Generates));
		assert!(declarations.contains(&Declaration::Leaks));
	}

	#[test]
	fn every_primitive_name_is_reserved() {
		let missing: Vec<&str> = crate::primitive::primitive_names()
			.into_iter()
			.filter(|name| !RESERVED.contains(&name.to_lowercase().as_str()))
			.collect();
		assert!(
			missing.is_empty(),
			"a primitive whose name is not reserved can be shadowed by a constant, \
			 so the same identifier means one thing at a call site and another as a \
			 value. Adding a primitive means adding its lowercase name to RESERVED: \
			 {missing:?}"
		);
	}

	#[test]
	fn a_mistyped_constant_suggests_one_that_exists() {
		let text = model_error(
			"attacker[active]\nprincipal Alice[\n\tknows private mc_secret\n\tmc_x = HASH(mc_secret)\n]\nqueries[\n\tconfidentiality? mc_secrt\n]\n",
		);
		assert!(text.contains("unknown constant `mc_secrt`"), "{text}");
		assert!(text.contains("did you mean `mc_secret`?"), "{text}");
	}

	#[test]
	fn a_rebound_constant_points_at_both_assignments() {
		let text = model_error(
			"attacker[active]\nprincipal Alice[\n\tknows private rb_m\n\trb_x = HASH(rb_m)\n\trb_x = HASH(rb_x)\n]\nqueries[\n\tconfidentiality? rb_m\n]\n",
		);
		assert!(text.contains("`rb_x` is assigned twice"), "{text}");
		assert!(text.contains("already assigned here"), "{text}");
		assert!(text.contains("assigned again here"), "{text}");
		assert!(text.contains("\n4 |"), "{text}");
		assert!(text.contains("\n5 |"), "{text}");
	}

	#[test]
	fn an_unclosed_delimiter_is_pointed_at_from_where_parsing_failed() {
		let text = model_error(
			"attacker[active]\nprincipal Alice[\n\tknows private ud_m\n\tud_x = HASH(ud_m\n]\nqueries[\n\tconfidentiality? ud_m\n]\n",
		);
		assert!(text.contains("this `(` is never closed"), "{text}");
		assert!(text.contains("add the missing `)`"), "{text}");
	}

	#[test]
	fn an_unterminated_block_comment_is_named_rather_than_its_consequence() {
		let text = model_error(
			"attacker[active]\n/* never closed\nprincipal Alice[\n\tknows private ub_m\n]\n",
		);
		assert!(text.contains("unterminated block comment"), "{text}");
		assert!(text.contains("this `/*` is never closed"), "{text}");
	}

	#[test]
	fn a_message_a_principal_sends_to_itself_names_that_rule() {
		let text = model_error(
			"attacker[active]\nprincipal Alice[\n\tknows private sm_m\n]\nAlice -> Alice: sm_m\nqueries[\n\tconfidentiality? sm_m\n]\n",
		);
		assert!(
			text.contains("Alice both sends and receives this message"),
			"{text}"
		);
		assert!(
			text.contains("a message travels between two different principals"),
			"{text}"
		);
	}

	#[test]
	fn a_closed_delimiter_is_never_reported_as_unclosed() {
		let text = model_error(
			"attacker[active]\nprincipal Alice[\n\tknows private cd_m\n\tcd_x = NOTAPRIM(cd_m)\n]\nqueries[\n\tconfidentiality? cd_m\n]\n",
		);
		assert!(text.contains("unknown primitive `NOTAPRIM`"), "{text}");
		assert!(!text.contains("is never closed"), "{text}");
	}

	#[test]
	fn an_undeclared_principal_is_named_where_it_is_used() {
		let text = model_error(
			"attacker[active]\nprincipal Alice[\n\tknows private up_m\n\tup_x = HASH(up_m)\n]\nAlice -> Bobb: up_x\nqueries[\n\tconfidentiality? up_m\n]\n",
		);
		assert!(
			text.contains("`Bobb` is never declared as a principal"),
			"{text}"
		);
		assert!(text.contains("no block declares this principal"), "{text}");
	}

	fn sanity_error_for(assignment: &str) -> String {
		let src = format!(
			"attacker[active]\n\nprincipal Alice[\n\tknows private brc_a\n\t{}\n]\n\nqueries[\n\tconfidentiality? brc_a\n]\n",
			assignment
		);
		let m = parse_string("bad.vp", &src).expect("parses");
		crate::sanity::sanity(&m)
			.err()
			.map(|e| e.to_string())
			.unwrap_or_default()
	}

	#[test]
	fn bridged_primitives_reject_checking_like_any_other() {
		for assignment in [
			"brc_x = HASH(brc_a)?",
			"brc_x = PUBKEY(brc_a)?",
			"brc_x = DH_KEX(brc_a, brc_a)?",
		] {
			let error = sanity_error_for(assignment);
			assert!(
				error.contains("cannot be checked with `?`"),
				"got: {}",
				error
			);
		}
	}

	#[test]
	fn bridged_primitives_reject_bad_arity_from_the_spec() {
		assert!(
			sanity_error_for("brc_x = PUBKEY(brc_a, brc_a)")
				.contains("takes 1 argument, but 2 were given")
		);
		assert!(
			sanity_error_for("brc_x = DH_KEX(brc_a)")
				.contains("takes 2 arguments, but 1 was given")
		);
	}

	#[test]
	fn parse_rejects_content_after_queries() {
		let model = concat!(
			"attacker[active]\n",
			"principal Alice[ knows private x ]\n",
			"Alice -> Bob: x\n",
			"principal Bob[]\n",
			"queries[ confidentiality? x ]\n",
			"phase[1]\n",
			"principal Alice[ leaks x ]\n",
		);
		assert!(crate::parser::parse_string("after_queries.vp", model).is_err());
	}

	#[test]
	fn parse_accepts_phase_before_queries() {
		let model = concat!(
			"attacker[active]\n",
			"principal Alice[ knows private x ]\n",
			"Alice -> Bob: x\n",
			"principal Bob[]\n",
			"phase[1]\n",
			"principal Alice[ leaks x ]\n",
			"queries[ confidentiality? x ]\n",
		);
		assert!(crate::parser::parse_string("before_queries.vp", model).is_ok());
	}

	#[test]
	fn comment_capture_pre_attacker_line() {
		let src = "// hello\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(
			m.pre_attacker_comments.len(),
			1,
			"expected 1 pre-attacker comment"
		);
		assert_eq!(m.pre_attacker_comments[0].text, " hello");
		assert!(matches!(
			m.pre_attacker_comments[0].style,
			CommentStyle::Line
		));
	}

	#[test]
	fn comment_capture_leading_on_block() {
		let src = "attacker[active]\n\n// before alice\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.blocks.len(), 1);
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert_eq!(p.leading_comments.len(), 1);
				assert_eq!(p.leading_comments[0].text, " before alice");
			}
			_ => panic!("expected Principal block"),
		}
	}

	#[test]
	fn comment_capture_leading_on_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\t// long-term key\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert_eq!(p.expressions.len(), 1);
				assert_eq!(p.expressions[0].leading_comments.len(), 1);
				assert_eq!(p.expressions[0].leading_comments[0].text, " long-term key");
			}
			_ => panic!("expected Principal block"),
		}
	}

	#[test]
	fn comment_capture_leading_on_query() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\t// primary goal\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.queries.len(), 1);
		assert_eq!(m.queries[0].leading_comments.len(), 1);
		assert_eq!(m.queries[0].leading_comments[0].text, " primary goal");
	}

	#[test]
	fn comment_capture_leading_on_queries_keyword() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\n// verify these\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.queries_leading_comments.len(), 1);
		assert_eq!(m.queries_leading_comments[0].text, " verify these");
	}

	#[test]
	fn comment_capture_multiple_lines() {
		let src = "// line 1\n// line 2\n// line 3\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.pre_attacker_comments.len(), 3);
		assert_eq!(m.pre_attacker_comments[0].text, " line 1");
		assert_eq!(m.pre_attacker_comments[1].text, " line 2");
		assert_eq!(m.pre_attacker_comments[2].text, " line 3");
	}

	#[test]
	fn comment_capture_block_pre_attacker() {
		let src = "/* hello */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.pre_attacker_comments.len(), 1);
		assert_eq!(m.pre_attacker_comments[0].text, " hello ");
		assert!(matches!(
			m.pre_attacker_comments[0].style,
			CommentStyle::Block
		));
	}

	#[test]
	fn comment_capture_block_multiline() {
		let src = "/* line1\n   line2\n   line3 */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.pre_attacker_comments.len(), 1);
		assert_eq!(
			m.pre_attacker_comments[0].text,
			" line1\n   line2\n   line3 "
		);
	}

	#[test]
	fn comment_capture_block_unterminated_errors() {
		let src = "/* never closed\nattacker[active]\n";
		assert!(parse_string("t.vp", src).is_err());
	}

	#[test]
	fn comment_capture_trailing_on_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a // long-term key\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert!(p.expressions[0].trailing_comment.is_some());
				assert_eq!(
					p.expressions[0].trailing_comment.as_ref().unwrap().text,
					" long-term key"
				);
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_trailing_on_attacker() {
		let src = "attacker[active] // active model\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert!(m.attacker_trailing.is_some());
		assert_eq!(m.attacker_trailing.as_ref().unwrap().text, " active model");
	}

	#[test]
	fn comment_capture_trailing_on_message() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nAlice -> Bob: a // initial flight\n\nprincipal Bob[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let msg = m
			.blocks
			.iter()
			.find_map(|b| match b {
				Block::Message(m) => Some(m),
				_ => None,
			})
			.expect("message");
		assert!(msg.trailing_comment.is_some());
		assert_eq!(
			msg.trailing_comment.as_ref().unwrap().text,
			" initial flight"
		);
	}

	#[test]
	fn comment_capture_trailing_on_query() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a // primary\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert!(m.queries[0].trailing_comment.is_some());
		assert_eq!(
			m.queries[0].trailing_comment.as_ref().unwrap().text,
			" primary"
		);
	}

	#[test]
	fn comment_capture_block_trailing_inline() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a /* lt */\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				let t = p.expressions[0]
					.trailing_comment
					.as_ref()
					.expect("trailing");
				assert_eq!(t.text, " lt ");
				assert!(matches!(t.style, CommentStyle::Block));
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_block_trailing_multiline_promoted_to_leading() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a /* multi\n\tline */\n\tknows private b\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert!(p.expressions[0].trailing_comment.is_none());
				assert_eq!(p.expressions[1].leading_comments.len(), 1);
				assert_eq!(p.expressions[1].leading_comments[0].text, " multi\n\tline ");
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_tail_in_principal() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n\t// TODO add more\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert_eq!(p.tail_comments.len(), 1);
				assert_eq!(p.tail_comments[0].text, " TODO add more");
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_closing_trailing_on_principal() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n] // end of Alice\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert!(p.closing_trailing.is_some());
				assert_eq!(p.closing_trailing.as_ref().unwrap().text, " end of Alice");
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_header_trailing_on_principal() {
		let src = "attacker[active]\n\nprincipal Alice[ // initiator\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		match &m.blocks[0] {
			Block::Principal(p) => {
				assert!(p.header_trailing.is_some());
				assert_eq!(p.header_trailing.as_ref().unwrap().text, " initiator");
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_tail_in_queries() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n\t// done\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.queries_tail_comments.len(), 1);
		assert_eq!(m.queries_tail_comments[0].text, " done");
	}

	#[test]
	fn comment_capture_queries_closing_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n] // end\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert!(m.queries_closing_trailing.is_some());
		assert_eq!(m.queries_closing_trailing.as_ref().unwrap().text, " end");
	}

	#[test]
	fn comment_capture_eof_tail() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n\n// EOF tail\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.tail_comments.len(), 1);
		assert_eq!(m.tail_comments[0].text, " EOF tail");
	}

	#[test]
	fn comment_capture_queries_header_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[ // start\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert!(m.queries_header_trailing.is_some());
		assert_eq!(m.queries_header_trailing.as_ref().unwrap().text, " start");
	}

	#[test]
	fn comment_lookahead_does_not_leak() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nAlice -> Bob: a\n// next block\n\nprincipal Bob[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let msg = m
			.blocks
			.iter()
			.find_map(|b| match b {
				Block::Message(m) => Some(m),
				_ => None,
			})
			.expect("message");
		assert!(msg.trailing_comment.is_none());
		let bob = m
			.blocks
			.iter()
			.find_map(|b| match b {
				Block::Principal(p) if p.name == "Bob" => Some(p),
				_ => None,
			})
			.expect("bob");
		assert_eq!(bob.leading_comments.len(), 1);
		assert_eq!(bob.leading_comments[0].text, " next block");
	}

	#[test]
	fn comment_in_primitive_args_is_kept_on_the_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n\tx = ENC(/* secret */ a, a)\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let Block::Principal(alice) = &m.blocks[0] else {
			panic!("Alice's block");
		};
		let comments = &alice.expressions[1].leading_comments;
		assert_eq!(comments.len(), 1, "{comments:?}");
		assert_eq!(comments[0].text.trim(), "secret");
	}

	#[test]
	fn caret_is_rejected() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private crj_a\n\tcrj_ga = G^crj_a\n]\n\nqueries[\n\tconfidentiality? crj_a\n]\n";
		assert!(parse_string("old.vp", src).is_err());
	}

	#[test]
	fn kem_primitive_names_are_reserved() {
		for name in ["kem_encap", "kem_decap"] {
			let src = format!(
				"attacker[active]\n\nprincipal Alice[\n\tknows private {}\n]\n\nqueries[\n\tconfidentiality? {}\n]\n",
				name, name
			);
			assert!(parse_string("reserved.vp", &src).is_err());
		}
	}

	#[test]
	fn bare_generator_is_rejected() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private crk_a\n\tcrk_x = HASH(G)\n]\n\nqueries[\n\tconfidentiality? crk_a\n]\n";
		assert!(parse_string("old.vp", src).is_err());
	}

	#[test]
	fn file_name_limit_counts_characters_instead_of_bytes() {
		let accepted = format!("{}.vp", "é".repeat(61));
		let rejected = format!("{}.vp", "é".repeat(62));
		assert_eq!(accepted.chars().count(), 64);
		assert!(accepted.len() > 64);
		assert!(validate_file_name(&accepted, &accepted).is_ok());
		assert!(validate_file_name(&rejected, &rejected).is_err());
	}

	#[test]
	fn a_line_comment_token_stops_before_a_carriage_return() {
		let src = "// note\r\nattacker[active]\r\nprincipal Alice[\r\n\tknows public pc_crlf\r\n]\r\n\
		           queries[\r\n\tconfidentiality? pc_crlf\r\n]\r\n";
		let (model, index) = parse_string_indexed("crlf.vp", src);
		model.expect("parses");
		let token = index.at(0).expect("the comment token");
		assert_eq!(&src[token.span.start..token.span.end], "// note");
	}

	#[test]
	fn a_leading_byte_order_mark_is_skipped() {
		let src = "\u{FEFF}attacker[active]\nprincipal Alice[\n\tknows public pc_bom\n]\n\
		           queries[\n\tconfidentiality? pc_bom\n]\n";
		parse_string("bom.vp", src).expect("a BOM is not part of the model");
	}
}
