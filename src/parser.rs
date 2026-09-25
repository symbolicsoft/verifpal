/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::primitive::{
	primitive_get_enum, primitive_names, primitive_renamed, primitive_threshold,
	primitives_with_threshold,
};
use crate::principal::PrincipalNames;
use crate::tokens::{TokenIndex, TokenKind};
use crate::types::*;
use crate::util::did_you_mean;
use crate::value::ValueNames;
use std::borrow::Cow;
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
	"primitive",
	crate::util::ANONYMOUS_PREFIX,
	"g",
	"queries",
	"scenarios",
];

const DECLARATIONS: [(&str, Declaration); 3] = [
	("knows", Declaration::Knows),
	("generates", Declaration::Generates),
	("leaks", Declaration::Leaks),
];

const MAX_NESTING: usize = 64;

fn names_a_primitive(lower: &str) -> bool {
	primitive_get_enum(&lower.to_uppercase()).is_ok()
}

pub(crate) fn check_reserved(s: &str) -> VResult<()> {
	let lower = s.to_lowercase();
	if is_reserved_word(&lower)
		|| lower.starts_with("attacker")
		|| lower.starts_with(crate::util::ANONYMOUS_PREFIX)
	{
		return Err(VerifpalError::parse(
			format!("`{}` is a reserved word and cannot name a constant", s).into(),
		)
		.narrow(s.to_string())
		.note(
			"the language keywords, the primitive names, and any name beginning with \
			 `attacker` or `unnamed` are reserved so that a model cannot shadow them",
		)
		.help(format!("rename it, for example to `{}_value`", s)));
	}
	Ok(())
}

pub(crate) fn is_reserved_word(lower: &str) -> bool {
	RESERVED.contains(&lower) || names_a_primitive(lower)
}

fn title_case(s: &str) -> String {
	let mut chars = s.chars();
	let first = chars.next().into_iter().flat_map(char::to_uppercase);
	first.chain(chars.flat_map(char::to_lowercase)).collect()
}

fn starts_with_ignoring_case(s: &str, prefix: &str) -> bool {
	s.as_bytes()
		.get(..prefix.len())
		.is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn starts_with_keyword(s: &str, keyword: &str) -> bool {
	starts_with_ignoring_case(s, keyword)
		&& s.as_bytes()
			.get(keyword.len())
			.is_none_or(|&b| !b.is_ascii_alphanumeric() && b != b'_')
}

fn starts_with_comment(s: &str) -> bool {
	s.starts_with("//") || s.starts_with("/*")
}

fn line_end(bytes: &[u8], from: usize) -> usize {
	bytes[from..]
		.iter()
		.position(|&b| b == b'\n')
		.map_or(bytes.len(), |i| from + i)
}

fn block_comment_close(bytes: &[u8], from: usize) -> Option<usize> {
	bytes[from..]
		.windows(2)
		.position(|pair| pair == b"*/")
		.map(|i| from + i)
}

struct Parser<'a> {
	source: &'a str,
	pos: usize,
	tokens: TokenIndex,
	pending_leading: Vec<Comment>,
	unterminated_block_at: Option<usize>,
	values: ValueNames,
	principals: PrincipalNames,
	unnamed_counter: usize,
	last_ident: Span,
	primitive_end: usize,
	depth: usize,
	queries_optional: bool,
}

impl<'a> Parser<'a> {
	fn new(source: &'a str, queries_optional: bool) -> Self {
		Parser {
			source,
			pos: 0,
			tokens: TokenIndex::default(),
			pending_leading: Vec::new(),
			unterminated_block_at: None,
			values: ValueNames::new(),
			principals: PrincipalNames::new(),
			unnamed_counter: 0,
			last_ident: Span::default(),
			primitive_end: 0,
			depth: 0,
			queries_optional,
		}
	}

	fn bytes(&self) -> &'a [u8] {
		self.source.as_bytes()
	}

	fn remaining(&self) -> &'a str {
		self.source.get(self.pos..).unwrap_or("")
	}

	fn at_end(&self) -> bool {
		self.pos >= self.source.len()
	}

	fn peek(&self) -> Option<u8> {
		self.bytes().get(self.pos).copied()
	}

	fn skip_while(&mut self, accept: impl Fn(u8) -> bool) {
		while self.peek().is_some_and(&accept) {
			self.pos += 1;
		}
	}

	fn skip_whitespace(&mut self) {
		self.skip_while(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r'));
	}

	fn skip_inline_whitespace(&mut self) {
		self.skip_while(|c| matches!(c, b' ' | b'\t'));
	}

	fn digits(&mut self) -> Span {
		let start = self.pos;
		self.skip_while(|c| c.is_ascii_digit());
		Span::new(start, self.pos)
	}

	fn text(&self, span: Span) -> &'a str {
		&self.source[span.start..span.end]
	}

	fn trimmed_pos(&self) -> usize {
		self.source[..self.pos].trim_end_matches([' ', '\t']).len()
	}

	fn record(&mut self, span: Span, kind: TokenKind) {
		self.tokens.push(span, kind, self.source);
	}

	fn record_from(&mut self, start: usize, kind: TokenKind) {
		self.record(Span::new(start, self.pos), kind);
	}

	fn eat(&mut self, text: &str) -> bool {
		let found = starts_with_ignoring_case(self.remaining(), text);
		if found {
			self.pos += text.len();
		}
		found
	}

	fn eat_token(&mut self, text: &str, kind: TokenKind) -> bool {
		let start = self.pos;
		let found = self.eat(text);
		if found {
			self.record_from(start, kind);
		}
		found
	}

	fn expect_where(&mut self, text: &str, context: &str) -> VResult<()> {
		if self.eat(text) {
			return Ok(());
		}
		Err(self.unexpected(if context.is_empty() {
			format!("expected `{}`", text)
		} else {
			format!("expected `{}` {}", text, context)
		}))
	}

	fn expect(&mut self, text: &str) -> VResult<()> {
		self.expect_where(text, "")
	}

	fn expect_token(&mut self, text: &str, kind: TokenKind) -> VResult<()> {
		let start = self.pos;
		self.expect(text)?;
		self.record_from(start, kind);
		Ok(())
	}

	fn word_here(&self) -> &'a str {
		let rest = self.remaining();
		let end = rest
			.find(|c: char| !c.is_alphanumeric() && c != '_')
			.unwrap_or(rest.len());
		&rest[..end]
	}

	fn here(&self) -> Span {
		let width = match self.word_here() {
			"" => self.remaining().chars().next().map_or(0, char::len_utf8),
			word => word.len(),
		};
		Span::new(self.pos, self.pos + width)
	}

	fn found_here(&self) -> String {
		match (self.word_here(), self.remaining().chars().next()) {
			(_, None) => "end of file".to_string(),
			("", Some('\n')) => "end of line".to_string(),
			("", Some(c)) => format!("found `{}`", c),
			(word, _) => format!("found `{}`", word),
		}
	}

	fn unexpected(&self, message: impl Into<Cow<'static, str>>) -> VerifpalError {
		VerifpalError::parse(message.into())
			.at(self.here())
			.labelled(self.found_here())
	}

	fn unclosed_hint(&self, error: VerifpalError, opened_at: usize) -> VerifpalError {
		let (opener, closer) = match self.bytes().get(opened_at) {
			Some(b'[') => (b'[', b']'),
			Some(b'(') => (b'(', b')'),
			_ => return error,
		};
		if error.has_labels() || self.is_closed(opened_at, opener, closer) {
			return error;
		}
		error
			.label(
				Span::at(opened_at),
				format!("this `{}` is never closed", opener as char),
			)
			.help(format!("add the missing `{}`", closer as char))
	}

	fn is_closed(&self, opened_at: usize, opener: u8, closer: u8) -> bool {
		let bytes = self.bytes();
		let mut depth = 0usize;
		let mut at = opened_at;
		while at < bytes.len() {
			match &bytes[at..] {
				[b'/', b'/', ..] => {
					at = line_end(bytes, at);
					continue;
				}
				[b'/', b'*', ..] => {
					at = block_comment_close(bytes, at + 2).map_or(bytes.len(), |close| close + 2);
					continue;
				}
				[b, ..] if *b == opener => depth += 1,
				[b, ..] if *b == closer => {
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

	fn consume_trivia(&mut self) {
		loop {
			self.skip_whitespace();
			let comment = if self.remaining().starts_with("//") {
				self.line_comment()
			} else if self.remaining().starts_with("/*") {
				let Some(comment) = self.block_comment(false) else {
					self.unterminated_block_at = Some(self.pos);
					self.pos = self.source.len();
					return;
				};
				comment
			} else {
				return;
			};
			self.pending_leading.push(comment);
		}
	}

	fn try_take_trailing(&mut self) -> Option<Comment> {
		let before = self.pos;
		self.skip_inline_whitespace();
		let comment = if self.remaining().starts_with("//") {
			Some(self.line_comment())
		} else if self.remaining().starts_with("/*") {
			self.block_comment(true)
		} else {
			None
		};
		if comment.is_none() {
			self.pos = before;
		}
		comment
	}

	fn line_comment(&mut self) -> Comment {
		let open = self.pos;
		self.pos = line_end(self.bytes(), open);
		let end = open + 2 + self.source[open + 2..self.pos].trim_end_matches('\r').len();
		self.record(Span::new(open, end), TokenKind::Comment);
		Comment {
			text: self.source[open + 2..end].to_string(),
			style: CommentStyle::Line,
		}
	}

	fn block_comment(&mut self, within_line: bool) -> Option<Comment> {
		let open = self.pos;
		let close = block_comment_close(self.bytes(), open + 2)?;
		let text = &self.remaining()[2..close - open];
		if within_line && text.contains('\n') {
			return None;
		}
		self.pos = close + 2;
		self.record_from(open, TokenKind::Comment);
		Some(Comment {
			text: text.replace("\r\n", "\n"),
			style: CommentStyle::Block,
		})
	}

	fn take_leading(&mut self) -> Vec<Comment> {
		std::mem::take(&mut self.pending_leading)
	}

	fn line_comments(&mut self, mut leading: Vec<Comment>) -> LineComments {
		leading.extend(self.take_leading());
		LineComments {
			leading,
			trailing: self.try_take_trailing(),
		}
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

	fn parse_identifier(&mut self) -> VResult<String> {
		let start = self.pos;
		self.skip_while(|c| c.is_ascii_alphanumeric() || c == b'_');
		self.last_ident = Span::new(start, self.pos);
		if self.pos == start {
			return Err(self
				.unexpected("expected a name")
				.note("a name is made of letters, digits and underscores"));
		}
		Ok(self.text(self.last_ident).to_lowercase())
	}

	fn parse_principal_name(&mut self) -> VResult<String> {
		let name = self.parse_identifier()?;
		let span = self.last_ident;
		if name != "attacker" && is_reserved_word(&name) {
			let written = self.text(span);
			return Err(VerifpalError::parse(
				format!(
					"`{}` is a reserved word and cannot name a principal",
					written
				)
				.into(),
			)
			.at(span)
			.narrow(written.to_string())
			.note("the language keywords are reserved so that a model cannot shadow them")
			.help("pick a different name"));
		}
		self.record(span, TokenKind::PrincipalName);
		Ok(title_case(&name))
	}

	fn principal_id(&mut self, name: &str) -> VResult<(PrincipalId, Arc<str>)> {
		let id = self.principals.intern(name)?;
		Ok((id, self.principals.name_of(id)))
	}

	fn message(
		&mut self,
		span: Span,
		sender: &str,
		recipient: &str,
		constants: Vec<Constant>,
	) -> VResult<Message> {
		let (sender, sender_name) = self.principal_id(sender)?;
		let (recipient, recipient_name) = self.principal_id(recipient)?;
		Ok(Message {
			span,
			sender,
			sender_name,
			recipient,
			recipient_name,
			constants,
			comments: LineComments::default(),
		})
	}

	fn parse_route(
		&mut self,
		gap: fn(&mut Self),
		usage: &'static str,
	) -> VResult<(String, String)> {
		let sender = self.parse_principal_name()?;
		gap(self);
		if !(self.eat_token("->", TokenKind::Arrow) || self.eat_token("\u{2192}", TokenKind::Arrow))
		{
			return Err(self
				.unexpected("expected `->` after the sender's name")
				.note(usage));
		}
		gap(self);
		let recipient = self.parse_principal_name()?;
		gap(self);
		Ok((sender, recipient))
	}

	fn starts_next_message(&self) -> bool {
		let rest = self.remaining();
		let after_name = rest.trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
		let after_gap = after_name.trim_start_matches([' ', '\t', '\n', '\r']);
		after_name.len() < rest.len()
			&& (after_gap.starts_with("->") || after_gap.starts_with('\u{2192}'))
	}

	fn parse_model(&mut self) -> VResult<Model> {
		if self.source.starts_with('\u{FEFF}') {
			self.pos = '\u{FEFF}'.len_utf8();
		}
		self.consume_trivia();
		self.check_unterminated_block()?;
		let (attacker, attacker_comments) = self.parse_attacker()?;
		let mut blocks = Vec::new();
		loop {
			self.consume_trivia();
			let rest = self.remaining();
			if rest.is_empty()
				|| starts_with_keyword(rest, "queries")
				|| starts_with_keyword(rest, "scenarios")
			{
				break;
			}
			blocks.push(self.parse_block()?);
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

		let (scenarios_comments, scenarios) = self.parse_scenarios()?;
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
		let (queries_comments, queries) = self.parse_queries(!scenarios.is_empty())?;
		self.consume_trivia();
		let tail_comments = self.take_leading();
		self.check_unterminated_block()?;
		if !self.at_end() {
			let trailing = if starts_with_keyword(self.remaining(), "scenarios") {
				"the `scenarios` block must come directly before `queries`"
			} else {
				"content appears after the `queries` block"
			};
			return Err(self
				.unexpected(trailing)
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
			attacker,
			attacker_comments,
			blocks,
			scenarios,
			scenarios_comments,
			queries,
			queries_comments,
			tail_comments,
		})
	}

	fn parse_attacker(&mut self) -> VResult<(AttackerKind, LineComments)> {
		let leading = self.take_leading();
		if !self.eat_token("attacker", TokenKind::Keyword) {
			return Err(self
				.unexpected("model does not open with an `attacker` block")
				.note(
					"every model states which attacker it is analyzed against, before anything else",
				)
				.help("add `attacker[active]` or `attacker[passive]` as the first line"));
		}
		self.consume_trivia();
		self.expect("[")?;
		self.consume_trivia();
		let mode = self.parse_identifier()?;
		self.record(self.last_ident, TokenKind::AttackerMode);
		let attacker = match mode.as_str() {
			"active" => AttackerKind::Active,
			"passive" => AttackerKind::Passive,
			_ => {
				return Err(VerifpalError::parse(
					format!("unknown attacker type `{}`", mode).into(),
				)
				.at(self.last_ident)
				.narrow(mode.clone())
				.note("an attacker is either `active` or `passive`")
				.suggest(did_you_mean(&mode, ["active", "passive"])));
			}
		};
		self.consume_trivia();
		self.expect("]")?;
		Ok((attacker, self.line_comments(leading)))
	}

	fn parse_queries(&mut self, after_scenarios: bool) -> VResult<(BracketComments, Vec<Query>)> {
		let leading = self.take_leading();
		if self.queries_optional && self.at_end() {
			let comments = BracketComments {
				leading,
				..BracketComments::default()
			};
			return Ok((comments, Vec::new()));
		}
		let keyword = Span::new(self.pos, self.pos + "queries".len());
		if !self.eat_token("queries", TokenKind::Keyword) {
			if after_scenarios {
				return Err(self
					.unexpected("the `scenarios` block must come directly before `queries`")
					.note(
						"a scenario names constants the model has already declared, and \
						 `queries` closes the model, so the only place the block can go is \
						 between the two",
					)
					.help("move this above the `scenarios` block"));
			}
			return Err(self
				.unexpected("model has no `queries` block")
				.note("a model must ask at least one question, or there is nothing to verify")
				.help("add `queries[ confidentiality? m ]` at the end of the model"));
		}
		self.skip_whitespace();
		let bracket = self.pos;
		self.expect("[")?;
		let opening = self.try_take_trailing();
		let mut items = Vec::new();
		loop {
			self.consume_trivia();
			if self.peek() == Some(b']') {
				break;
			}
			if self.at_end() {
				if items.is_empty() && !self.queries_optional {
					break;
				}
				return Err(self.unclosed_hint(
					self.unexpected("the `queries` block is never closed"),
					bracket,
				));
			}
			items.push(self.parse_query()?);
		}
		if items.is_empty() && !self.queries_optional {
			return Err(VerifpalError::parse("`queries` block is empty".into())
				.at(keyword)
				.labelled("no queries here")
				.note("a model must ask at least one question, or there is nothing to verify")
				.help("add a query, for example `confidentiality? m`"));
		}
		let tail = self.take_leading();
		self.expect("]")?;
		let comments = BracketComments {
			leading,
			opening,
			tail,
			closing: self.try_take_trailing(),
		};
		Ok((comments, items))
	}

	fn parse_scenarios(&mut self) -> VResult<(BracketComments, Vec<Scenario>)> {
		if !starts_with_keyword(self.remaining(), "scenarios") {
			return Ok((BracketComments::default(), Vec::new()));
		}
		let leading = self.take_leading();
		self.expect_token("scenarios", TokenKind::Keyword)?;
		self.skip_whitespace();
		let bracket = self.pos;
		self.expect_where("[", "after `scenarios`")?;
		let opening = self.try_take_trailing();
		let mut items = Vec::new();
		loop {
			self.consume_trivia();
			if self.peek() == Some(b']') {
				break;
			}
			let rest = self.remaining();
			if rest.is_empty()
				|| ["queries", "principal", "phase"]
					.iter()
					.any(|keyword| starts_with_keyword(rest, keyword))
			{
				return Err(self.unclosed_hint(
					self.unexpected("the `scenarios` block is never closed"),
					bracket,
				));
			}
			items.push(self.parse_scenario()?);
		}
		let tail = self.take_leading();
		self.expect("]")?;
		let comments = BracketComments {
			leading,
			opening,
			tail,
			closing: self.try_take_trailing(),
		};
		Ok((comments, items))
	}

	fn parse_scenario(&mut self) -> VResult<Scenario> {
		let leading = self.take_leading();
		let start = self.pos;
		let name = self.parse_principal_name()?;
		let (principal, principal_name) = self.principal_id(&name)?;
		self.skip_whitespace();
		self.expect_where("[", &format!("after `{}` in the `scenarios` block", name))?;
		let mut bindings = Vec::new();
		loop {
			self.consume_trivia();
			if self.eat("]") {
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
			self.eat(",");
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
			comments: self.line_comments(leading),
		})
	}

	fn parse_block(&mut self) -> VResult<Block> {
		let rest = self.remaining();
		if starts_with_keyword(rest, "phase") {
			self.parse_phase().map(Block::Phase)
		} else if starts_with_keyword(rest, "principal") {
			self.parse_principal().map(Block::Principal)
		} else {
			self.parse_message().map(Block::Message)
		}
	}

	fn parse_principal(&mut self) -> VResult<Principal> {
		let leading = self.take_leading();
		let start = self.pos;
		self.expect_token("principal", TokenKind::Keyword)?;
		self.skip_whitespace();
		let name = self.parse_principal_name()?;
		self.skip_whitespace();
		let bracket = self.pos;
		self.expect_where("[", &format!("after `principal {}`", name))?;
		let opening = self.try_take_trailing();
		let mut expressions = Vec::new();
		loop {
			self.consume_trivia();
			if self.peek() == Some(b']') {
				break;
			}
			if self.at_end() {
				return Err(self.unclosed_hint(
					VerifpalError::parse(format!("`{}`'s block is never closed", name).into())
						.at(self.here()),
					bracket,
				));
			}
			expressions.push(
				self.parse_expression()
					.map_err(|e| self.unclosed_hint(e, bracket))?,
			);
		}
		let tail = self.take_leading();
		self.expect("]")?;
		let end = self.pos;
		let closing = self.try_take_trailing();
		self.consume_trivia();
		let id = self.principals.intern(&name)?;
		Ok(Principal {
			name,
			id,
			span: Span::new(start, end),
			expressions,
			comments: BracketComments {
				leading,
				opening,
				tail,
				closing,
			},
		})
	}

	fn parse_message(&mut self) -> VResult<Message> {
		const USAGE: &str = "a message is written `Sender -> Recipient: constant, ...`";
		let leading = self.take_leading();
		let start = self.pos;
		let (sender, recipient) = self.parse_route(Self::skip_whitespace, USAGE)?;
		self.expect_where(":", "after the recipient's name")
			.map_err(|e| e.note(USAGE))?;
		self.skip_whitespace();
		let constants = self.parse_message_constants()?;
		let span = Span::new(start, self.trimmed_pos());
		let comments = self.line_comments(leading);
		self.consume_trivia();
		Ok(Message {
			comments,
			..self.message(span, &sender, &recipient, constants)?
		})
	}

	fn parse_message_constants(&mut self) -> VResult<Vec<Constant>> {
		let mut constants = Vec::new();
		loop {
			self.skip_inline_whitespace();
			let rest = self.remaining();
			if rest.is_empty()
				|| rest.starts_with(['\n', '\r'])
				|| ["principal", "phase", "queries"]
					.iter()
					.any(|keyword| starts_with_keyword(rest, keyword))
				|| starts_with_comment(rest)
				|| self.starts_next_message()
			{
				break;
			}
			constants.push(if self.peek() == Some(b'[') {
				self.parse_guarded_constant()?
			} else {
				self.parse_constant()?
			});
			self.skip_inline_whitespace();
			self.eat(",");
		}
		if constants.is_empty() {
			return Err(self
				.unexpected("message carries no constants")
				.note("a message has to carry at least one value")
				.help("name the values being sent, e.g. `Alice -> Bob: ga, e`"));
		}
		Ok(constants)
	}

	fn parse_guarded_constant(&mut self) -> VResult<Constant> {
		self.expect("[")?;
		self.skip_whitespace();
		let constant = self.parse_constant()?;
		self.skip_whitespace();
		self.expect("]")?;
		self.skip_inline_whitespace();
		self.eat(",");
		Ok(Constant {
			guard: true,
			..constant
		})
	}

	fn parse_expression(&mut self) -> VResult<Expression> {
		let leading = self.take_leading();
		let rest = self.remaining();
		match DECLARATIONS
			.into_iter()
			.find(|(keyword, _)| starts_with_keyword(rest, keyword))
		{
			Some((keyword, kind)) => self.parse_declaration(keyword, kind, leading),
			None => self.parse_assignment(leading),
		}
	}

	fn parse_declaration(
		&mut self,
		keyword: &str,
		kind: Declaration,
		leading: Vec<Comment>,
	) -> VResult<Expression> {
		let start = self.pos;
		self.expect_token(keyword, TokenKind::Keyword)?;
		self.skip_whitespace();
		let qualifier = match kind {
			Declaration::Knows => Some(self.parse_qualifier()?),
			_ => None,
		};
		let constants = self.parse_constants(false)?;
		Ok(Expression {
			span: Span::new(start, self.trimmed_pos()),
			kind,
			qualifier,
			constants,
			assigned: None,
			comments: self.line_comments(leading),
		})
	}

	fn parse_qualifier(&mut self) -> VResult<Qualifier> {
		let word = self.parse_identifier()?;
		let qualifier = match word.as_str() {
			"private" => Qualifier::Private,
			"public" => Qualifier::Public,
			_ => {
				return Err(
					VerifpalError::parse(format!("unknown qualifier `{}`", word).into())
						.at(self.last_ident)
						.narrow(word.clone())
						.note("`knows` takes one of `private` or `public`")
						.suggest(did_you_mean(&word, ["private", "public"])),
				);
			}
		};
		self.record(self.last_ident, TokenKind::Qualifier);
		self.skip_whitespace();
		Ok(qualifier)
	}

	fn parse_assignment(&mut self, leading: Vec<Comment>) -> VResult<Expression> {
		let start = self.pos;
		let constants = self.parse_constants(true)?;
		self.skip_whitespace();
		self.expect_token("=", TokenKind::Assign)?;
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
			span: Span::new(start, self.primitive_end),
			kind: Declaration::Assignment,
			qualifier: None,
			constants,
			assigned: Some(value),
			comments: self.line_comments(leading),
		})
	}

	fn parse_constants(&mut self, anonymous_ok: bool) -> VResult<Vec<Constant>> {
		let mut constants = Vec::new();
		loop {
			self.skip_inline_whitespace();
			let rest = self.remaining();
			if rest.is_empty()
				|| rest.starts_with(['=', ']', ')', '\n', '\r'])
				|| DECLARATIONS
					.iter()
					.any(|(keyword, _)| starts_with_keyword(rest, keyword))
				|| starts_with_comment(rest)
			{
				break;
			}
			constants.push(self.parse_constant_or_anonymous(anonymous_ok)?);
			self.skip_inline_whitespace();
			self.eat(",");
		}
		if constants.is_empty() {
			return Err(self.unexpected("expected at least one constant"));
		}
		Ok(constants)
	}

	fn parse_constant(&mut self) -> VResult<Constant> {
		self.parse_constant_or_anonymous(false)
	}

	fn parse_constant_or_anonymous(&mut self, anonymous_ok: bool) -> VResult<Constant> {
		let name = self.parse_identifier()?;
		check_reserved(&name).map_err(|e| e.at(self.last_ident))?;
		let anonymous = name == "_";
		if anonymous && !anonymous_ok {
			return Err(VerifpalError::parse(
				"`_` can only name the output of an assignment".into(),
			)
			.at(self.last_ident)
			.note("an anonymous constant is a value the model computes and never uses again, so it has no place in a declaration, a message or a query")
			.help("give the constant a name"));
		}
		self.record(
			self.last_ident,
			if anonymous {
				TokenKind::Anonymous
			} else {
				TokenKind::ConstantName
			},
		);
		let name: Arc<str> = if anonymous {
			let index = self.unnamed_counter;
			self.unnamed_counter += 1;
			Arc::from(format!("{}_{}", crate::util::ANONYMOUS_PREFIX, index))
		} else {
			Arc::from(name)
		};
		let id = self.values.intern(&name)?;
		Ok(Constant {
			name,
			id,
			guard: false,
			fresh: false,
			leaked: false,
			declaration: None,
			qualifier: None,
		})
	}

	fn parse_value(&mut self) -> VResult<Value> {
		self.skip_whitespace();
		let start = self.pos;
		let Ok(name) = self.parse_identifier() else {
			return Err(self
				.unexpected("expected a value")
				.note("a value is a constant, or a primitive such as `HASH(m)`"));
		};
		self.skip_whitespace();
		let primitive =
			self.peek() == Some(b'(') || (self.peek() == Some(b'[') && names_a_primitive(&name));
		self.pos = start;
		if primitive {
			self.parse_primitive()
		} else {
			Ok(Value::Constant(self.parse_constant()?))
		}
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
		let prim_name = self.parse_identifier()?.to_uppercase();
		let name_span = self.last_ident;
		self.record(name_span, TokenKind::PrimitiveName);
		self.skip_whitespace();
		let (capabilities, threshold) = if self.peek() == Some(b'[') {
			self.parse_bracket()?
		} else {
			(Capabilities::default(), None)
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
			arguments.push(
				self.parse_value()
					.map_err(|e| self.unclosed_hint(e, open_paren))?,
			);
			self.consume_trivia();
			if self.eat(",") {
				self.consume_trivia();
			}
		}
		self.expect(")")?;
		let instance_check = self.eat_token("?", TokenKind::Check);
		self.primitive_end = self.pos;
		self.skip_inline_whitespace();
		self.eat(",");
		let id = primitive_get_enum(&prim_name).map_err(|_| {
			let unknown = VerifpalError::parse(format!("unknown primitive `{}`", prim_name).into())
				.at(name_span);
			match primitive_renamed(&prim_name) {
				Some(new_name) => unknown
					.labelled(format!("now called `{}`", new_name))
					.note(format!(
						"`{}` was renamed `{}`; a split now carries its threshold in a bracket, e.g. `{}[2](…)` for two-of-n",
						prim_name,
						new_name,
						primitives_with_threshold().first().copied().unwrap_or(new_name)
					))
					.help(format!("write `{}` instead", new_name)),
				None => unknown
					.labelled("not a Verifpal primitive")
					.suggest(did_you_mean(&prim_name, primitive_names())),
			}
		})?;
		let threshold = match (primitive_threshold(id), threshold) {
			(Some(_), None) => {
				return Err(VerifpalError::parse(
					format!("`{}` needs a threshold", prim_name).into(),
				)
				.at(name_span)
				.note(
					"the number in the bracket is how many of the bound shares recover the secret",
				)
				.help(format!(
					"write `{}[2](…)` for a scheme where any two shares suffice",
					prim_name
				)));
			}
			(None, Some((_, span))) => {
				return Err(VerifpalError::parse(
					format!("`{}` takes no threshold", prim_name).into(),
				)
				.at(span)
				.note(format!(
					"a threshold belongs on a primitive that shares a secret: {}",
					crate::util::quoted_list(
						&primitives_with_threshold()
							.iter()
							.map(|s| s.to_string())
							.collect::<Vec<String>>()
					)
				))
				.help("remove the number from the bracket"));
			}
			(Some(rule), Some((t, span))) if t < rule.min => {
				return Err(VerifpalError::parse(
					format!("a threshold of {} makes every share the secret", t).into(),
				)
				.at(span)
				.note(format!("the smallest threshold is {}", rule.min))
				.help(format!("write `{}[{}](…)`", prim_name, rule.min)));
			}
			(Some(_), Some((t, _))) => t,
			(None, None) => 0,
		};
		Ok(Value::Primitive(Arc::new(Primitive {
			id,
			arguments,
			output: 0,
			threshold,
			instance: 0,
			instance_check,
			capabilities,
			hash: HashCell::default(),
		})))
	}

	fn parse_bracket(&mut self) -> VResult<(Capabilities, Option<(usize, Span)>)> {
		let start = self.pos;
		self.expect("[")?;
		let mut capabilities = Capabilities::default();
		let mut threshold: Option<(usize, Span)> = None;
		loop {
			self.consume_trivia();
			if self.peek().is_some_and(|c| c.is_ascii_digit()) {
				let span = self.digits();
				let text = self.text(span);
				let value = text.parse().map_err(|_| {
					VerifpalError::parse(format!("`{}` is not a threshold", text).into())
						.at(span)
						.help("a threshold is a small whole number, e.g. `[2]`")
				})?;
				if threshold.is_some() {
					return Err(VerifpalError::parse(
						"the threshold is declared twice on this primitive".into(),
					)
					.at(span)
					.labelled("declared again here")
					.help("keep one threshold in the bracket"));
				}
				self.record(span, TokenKind::Threshold);
				threshold = Some((value, span));
			} else {
				let word = self.parse_identifier()?;
				let word_span = self.last_ident;
				let capability = Capability::from_name(&word).ok_or_else(|| {
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
				if capabilities.has(capability) {
					return Err(VerifpalError::parse(
						format!(
							"`{}` is declared twice on this primitive",
							capability.name()
						)
						.into(),
					)
					.at(Span::new(start, self.pos))
					.narrow_occurrence(capability.name(), 1)
					.labelled("declared again here")
					.help("remove the duplicate"));
				}
				self.record(word_span, TokenKind::Capability);
				self.consume_trivia();
				let onset = self.parse_capability_onset()?;
				capabilities.set(capability, onset);
			}
			self.consume_trivia();
			if !self.eat(",") {
				break;
			}
		}
		self.expect("]")?;
		Ok((capabilities, threshold))
	}

	fn parse_capability_onset(&mut self) -> VResult<i32> {
		if !starts_with_keyword(self.remaining(), "from") {
			return Ok(0);
		}
		self.expect_token("from", TokenKind::Capability)?;
		self.consume_trivia();
		let word = self.parse_identifier()?;
		if word != "phase" {
			return Err(VerifpalError::parse("expected `phase` after `from`".into())
				.at(self.last_ident)
				.labelled(format!("found `{}`", word))
				.note("an assumption that starts later is written `from phase N`")
				.help("write it as `from phase 1`"));
		}
		self.record(self.last_ident, TokenKind::Capability);
		self.consume_trivia();
		let digits = self.digits();
		self.record(digits, TokenKind::PhaseNumber);
		if digits.start == digits.end {
			return Err(self
				.unexpected("expected a phase number after `from phase`")
				.note("`from phase N` means the assumption holds from phase N onward"));
		}
		self.text(digits).parse().map_err(|_| {
			VerifpalError::parse("invalid phase number in primitive parameter".into())
				.at(Span::at(digits.start))
		})
	}

	fn parse_phase(&mut self) -> VResult<Phase> {
		let leading = self.take_leading();
		let start = self.pos;
		self.expect_token("phase", TokenKind::Keyword)?;
		self.consume_trivia();
		self.expect("[")?;
		self.consume_trivia();
		let digits = self.digits();
		self.record(digits, TokenKind::PhaseNumber);
		let number = self.text(digits).parse().map_err(|_| {
			self.unexpected("expected a phase number")
				.note("a phase is written `phase[1]`, `phase[2]`, and so on")
		})?;
		self.consume_trivia();
		self.expect("]")?;
		Ok(Phase {
			span: Span::new(start, self.pos),
			number,
			comments: self.line_comments(leading),
		})
	}

	fn parse_query(&mut self) -> VResult<Query> {
		let leading = self.take_leading();
		let start = self.pos;
		let Some(kind) = QueryKind::ALL
			.into_iter()
			.find(|kind| self.eat(&format!("{}?", kind.name())))
		else {
			let word = self.word_here();
			return Err(VerifpalError::parse(if word.is_empty() {
				"expected a query".into()
			} else {
				format!("unknown query type `{}`", word).into()
			})
			.at(self.here())
			.note(
				"a query is one of `confidentiality?`, `authentication?`, \
				 `freshness?`, `unlinkability?` or `equivalence?`",
			)
			.suggest(did_you_mean(word, QueryKind::ALL.map(QueryKind::name))));
		};
		self.record_from(start, TokenKind::QueryKind);
		self.skip_whitespace();
		let (constants, message) = match kind {
			QueryKind::Authentication => {
				let (sender, recipient) = self.parse_route(
					Self::skip_whitespace,
					"an authentication query is written `authentication? Alice -> Bob: m`",
				)?;
				self.expect(":")?;
				self.skip_whitespace();
				let constant = self.parse_constant()?;
				let message = self.message(Span::default(), &sender, &recipient, vec![constant])?;
				(Vec::new(), message)
			}
			QueryKind::Confidentiality | QueryKind::Freshness => {
				(vec![self.parse_constant()?], Message::default())
			}
			QueryKind::Unlinkability | QueryKind::Equivalence => {
				(self.parse_query_constant_list()?, Message::default())
			}
		};
		let options = self.parse_query_options()?;
		let span = Span::new(start, self.trimmed_pos());
		Ok(Query {
			span,
			kind,
			constants,
			message: match kind {
				QueryKind::Authentication => Message { span, ..message },
				_ => message,
			},
			options,
			comments: self.line_comments(leading),
		})
	}

	fn parse_query_constant_list(&mut self) -> VResult<Vec<Constant>> {
		let mut constants = Vec::new();
		loop {
			let before = self.pos;
			self.skip_whitespace();
			if self.peek() == Some(b'[') {
				break;
			}
			let rest = self.remaining();
			if rest.is_empty()
				|| rest.starts_with(']')
				|| QueryKind::ALL
					.iter()
					.any(|kind| starts_with_keyword(rest, kind.name()))
				|| starts_with_comment(rest)
			{
				self.pos = before;
				break;
			}
			constants.push(self.parse_constant()?);
			self.skip_inline_whitespace();
			self.eat(",");
		}
		Ok(constants)
	}

	fn parse_query_options(&mut self) -> VResult<Vec<QueryOption>> {
		self.skip_inline_whitespace();
		let mut options = Vec::new();
		if !self.eat("[") {
			return Ok(options);
		}
		self.consume_trivia();
		while self.peek() != Some(b']') && !self.at_end() {
			options.push(self.parse_query_option()?);
		}
		self.eat("]");
		Ok(options)
	}

	fn parse_query_option(&mut self) -> VResult<QueryOption> {
		let leading = self.take_leading();
		let start = self.pos;
		let name = self.parse_identifier()?;
		self.record(self.last_ident, TokenKind::Keyword);
		self.consume_trivia();
		self.expect("[")?;
		self.consume_trivia();
		let (sender, recipient) = self.parse_route(
			Self::consume_trivia,
			"a precondition is written `precondition[ Bob -> Alice: ack ]`",
		)?;
		self.expect(":")?;
		self.consume_trivia();
		let constant = self.parse_constant()?;
		self.consume_trivia();
		self.expect("]")?;
		let comments = self.line_comments(leading);
		self.consume_trivia();
		let kind = match name.as_str() {
			"precondition" => QueryOptionKind::Precondition,
			_ => {
				return Err(VerifpalError::parse(
					format!("unknown query option `{}`", name).into(),
				)
				.at(self.last_ident)
				.narrow(name.clone())
				.note("the only query option is `precondition`")
				.suggest(did_you_mean(&name, ["precondition"])));
			}
		};
		let message = self.message(
			Span::new(start, self.pos),
			&sender,
			&recipient,
			vec![constant],
		)?;
		Ok(QueryOption {
			kind,
			message,
			comments,
		})
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
	let file_name = std::path::Path::new(file_path)
		.file_name()
		.and_then(|n| n.to_str())
		.unwrap_or("");
	validate_file_name(file_path, file_name)?;
	let content = std::fs::read_to_string(file_path)
		.map_err(|e| VerifpalError::parse(format!("cannot read `{}`: {}", file_path, e).into()))?;
	parse_string(file_name, &content)
}

fn parse(file_name: &str, input: &str, queries_optional: bool) -> (VResult<Model>, TokenIndex) {
	let mut parser = Parser::new(input, queries_optional);
	let model = match parser.parse_model() {
		Ok(model) => Ok(Model {
			file_name: file_name.to_string(),
			source: Source::from(input),
			..model
		}),
		Err(e) => Err(e.or_span(Span::at(parser.pos)).located(file_name, input)),
	};
	(model, parser.tokens)
}

pub(crate) fn parse_string_indexed(file_name: &str, input: &str) -> (VResult<Model>, TokenIndex) {
	parse(file_name, input, false)
}

pub(crate) fn parse_string(file_name: &str, input: &str) -> VResult<Model> {
	parse(file_name, input, false).0
}

#[cfg_attr(not(any(test, feature = "wasm")), allow(dead_code))]
pub(crate) fn parse_string_queries_optional(file_name: &str, input: &str) -> VResult<Model> {
	parse(file_name, input, true).0
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn only_the_optional_parse_accepts_a_model_without_queries() {
		let body = "attacker[passive]\nprincipal Alice[\n\tknows private oq_m\n]\n";
		for source in [
			body.to_string(),
			format!("{body}queries[]\n"),
			format!("{body}queries[\n\t// none yet\n]\n"),
		] {
			assert!(parse_string("oq.vp", &source).is_err(), "{source:?}");
			let m = parse_string_queries_optional("oq.vp", &source).expect("parses");
			assert!(m.queries.is_empty());
		}
		for source in [
			format!("{body}queries[\n"),
			format!("{body}queries[]\nphase[1]\n"),
			"attacker[passive]\nqueries[]\n".to_string(),
		] {
			assert!(
				parse_string_queries_optional("oq.vp", &source).is_err(),
				"{source:?}"
			);
		}
		let asked = format!("{body}queries[\n\tconfidentiality? oq_m\n]\n");
		assert_eq!(
			parse_string_queries_optional("oq.vp", &asked)
				.expect("parses")
				.queries
				.len(),
			1
		);
	}

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
	fn parses_a_threshold_parameter() {
		let src = "attacker[active]\nprincipal Alice[\n\tknows private thp_k\n\tthp_a, thp_b, thp_c, thp_d, thp_e = THRESHOLD_SPLIT[3](thp_k)\n]\nqueries[\n\tconfidentiality? thp_k\n]\n";
		let m = parse_string("thp.vp", src).expect("parses");
		let p = first_primitive(&m).expect("a primitive");
		assert_eq!(p.threshold, 3);
		assert!(p.capabilities.is_empty());
	}

	#[test]
	fn a_threshold_may_share_its_bracket_with_a_capability() {
		let src = "attacker[active]\nprincipal Alice[\n\tknows private thc_k\n\tknows private thc_n\n\tknows private thc_c\n\tknows private thc_m\n\tthc_a, thc_b, thc_c2 = THRESHOLD_SPLIT[2](thc_k)\n\tthc_p = THRESHOLD_SIGN[forgeable](thc_a, thc_n, thc_c, thc_m)\n]\nqueries[\n\tconfidentiality? thc_k\n]\n";
		let m = parse_string("thc.vp", src).expect("parses");
		let Block::Principal(principal) = &m.blocks[0] else {
			panic!("a principal");
		};
		let Some(Value::Primitive(p)) = principal.expressions[5].assigned.as_ref() else {
			panic!("a primitive");
		};
		assert!(p.capabilities.has(Capability::Forgeable));
		assert_eq!(p.threshold, 0);
	}

	#[test]
	fn a_split_without_a_threshold_is_refused() {
		let src = "attacker[active]\nprincipal Alice[\n\tknows private thm_k\n\tthm_a, thm_b, thm_c = THRESHOLD_SPLIT(thm_k)\n]\nqueries[\n\tconfidentiality? thm_k\n]\n";
		let err = parse_string("thm.vp", src).expect_err("should reject");
		let text = format!("{}", err);
		assert!(text.contains("threshold"), "got: {}", text);
		assert!(text.contains("THRESHOLD_SPLIT[2]"), "got: {}", text);
	}

	#[test]
	fn a_threshold_on_a_primitive_that_takes_none_is_refused() {
		let src = "attacker[active]\nprincipal Alice[\n\tknows private thn_m\n\tthn_h = HASH[3](thn_m)\n]\nqueries[\n\tconfidentiality? thn_m\n]\n";
		let err = parse_string("thn.vp", src).expect_err("should reject");
		let text = format!("{}", err);
		assert!(
			text.contains("HASH") && text.contains("threshold"),
			"got: {}",
			text
		);
	}

	#[test]
	fn a_threshold_declared_twice_is_refused() {
		let src = "attacker[active]\nprincipal Alice[\n\tknows private tht_k\n\ttht_a, tht_b, tht_c = THRESHOLD_SPLIT[2, 3](tht_k)\n]\nqueries[\n\tconfidentiality? tht_k\n]\n";
		let err = parse_string("tht.vp", src).expect_err("should reject");
		let text = format!("{}", err);
		assert!(text.contains("twice"), "got: {}", text);
	}

	#[test]
	fn the_old_shamir_names_point_at_their_replacements() {
		let src = "attacker[active]\nprincipal Alice[\n\tknows private ths_k\n\tths_a, ths_b, ths_c = SHAMIR_SPLIT(ths_k)\n]\nqueries[\n\tconfidentiality? ths_k\n]\n";
		let err = parse_string("ths.vp", src).expect_err("should reject");
		let text = format!("{}", err);
		assert!(text.contains("THRESHOLD_SPLIT"), "got: {}", text);
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
		let src = "attacker[active]\nprincipal Alice[\n\tknows private cap2_k\n\tknows private cap2_m\n\tknows private cap2_ad\n\tknows private cap2_n\n\tcap2_e = AEAD_ENC[forgeable, weak from phase 2](cap2_k, cap2_n, cap2_m, cap2_ad)\n]\nqueries[\n\tconfidentiality? cap2_m\n]\n";
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
	fn an_error_narrows_to_a_name_written_in_another_case() {
		let text = model_error(
			"attacker[active]\nprincipal Alice[\n\tknows private nc_m\n]\nqueries[\n\tconfidentiality? NC_UNKNOWN\n]\n",
		);
		assert!(text.contains("diag.vp:6:19"), "{text}");
	}

	#[test]
	fn a_query_line_opening_with_a_multibyte_character_is_a_parse_error() {
		let src = "attacker[active]\nprincipal Alice[\n\tknows private mb_m\n]\nqueries[\n\t€x? mb_m\n]\n";
		let error = parse_string("mb.vp", src).expect_err("not a query");
		let text = error.render("mb.vp", src);
		assert!(text.contains("expected a query"), "{text}");
		assert!(text.contains("mb.vp:6:2"), "{text}");
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
			"attacker[active]\nprincipal Alice[\n\tknows private wa_m\n\twa_e = AEAD_ENC(wa_m, wa_m, wa_m)\n]\nqueries[\n\tconfidentiality? wa_m\n]\n",
		);
		assert!(
			text.contains("`AEAD_ENC` takes 4 arguments, but 3 were given"),
			"{text}"
		);
		assert!(
			text.contains("its signature is `AEAD_ENC(key, nonce, plaintext, ad)`"),
			"{text}"
		);
		assert!(
			text.contains("take a nonce as their second argument"),
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
		let shadowable: Vec<&str> = crate::primitive::primitive_names()
			.into_iter()
			.filter(|name| check_reserved(&name.to_lowercase()).is_ok())
			.collect();
		assert!(
			shadowable.is_empty(),
			"a primitive whose name is not reserved can be shadowed by a constant, \
			 so the same identifier means one thing at a call site and another as a \
			 value; the reserved check reads the registry, so a new primitive is \
			 reserved by declaring it: {shadowable:?}"
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
			m.attacker_comments.leading.len(),
			1,
			"expected 1 pre-attacker comment"
		);
		assert_eq!(m.attacker_comments.leading[0].text, " hello");
		assert!(matches!(
			m.attacker_comments.leading[0].style,
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
				assert_eq!(p.comments.leading.len(), 1);
				assert_eq!(p.comments.leading[0].text, " before alice");
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
				assert_eq!(p.expressions[0].comments.leading.len(), 1);
				assert_eq!(p.expressions[0].comments.leading[0].text, " long-term key");
			}
			_ => panic!("expected Principal block"),
		}
	}

	#[test]
	fn comment_capture_leading_on_query() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\t// primary goal\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.queries.len(), 1);
		assert_eq!(m.queries[0].comments.leading.len(), 1);
		assert_eq!(m.queries[0].comments.leading[0].text, " primary goal");
	}

	#[test]
	fn comment_capture_leading_on_queries_keyword() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\n// verify these\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.queries_comments.leading.len(), 1);
		assert_eq!(m.queries_comments.leading[0].text, " verify these");
	}

	#[test]
	fn comment_capture_multiple_lines() {
		let src = "// line 1\n// line 2\n// line 3\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.attacker_comments.leading.len(), 3);
		assert_eq!(m.attacker_comments.leading[0].text, " line 1");
		assert_eq!(m.attacker_comments.leading[1].text, " line 2");
		assert_eq!(m.attacker_comments.leading[2].text, " line 3");
	}

	#[test]
	fn comment_capture_block_pre_attacker() {
		let src = "/* hello */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.attacker_comments.leading.len(), 1);
		assert_eq!(m.attacker_comments.leading[0].text, " hello ");
		assert!(matches!(
			m.attacker_comments.leading[0].style,
			CommentStyle::Block
		));
	}

	#[test]
	fn comment_capture_block_multiline() {
		let src = "/* line1\n   line2\n   line3 */\nattacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.attacker_comments.leading.len(), 1);
		assert_eq!(
			m.attacker_comments.leading[0].text,
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
				assert!(p.expressions[0].comments.trailing.is_some());
				assert_eq!(
					p.expressions[0].comments.trailing.as_ref().unwrap().text,
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
		assert!(m.attacker_comments.trailing.is_some());
		assert_eq!(
			m.attacker_comments.trailing.as_ref().unwrap().text,
			" active model"
		);
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
		assert!(msg.comments.trailing.is_some());
		assert_eq!(
			msg.comments.trailing.as_ref().unwrap().text,
			" initial flight"
		);
	}

	#[test]
	fn comment_capture_trailing_on_query() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a // primary\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert!(m.queries[0].comments.trailing.is_some());
		assert_eq!(
			m.queries[0].comments.trailing.as_ref().unwrap().text,
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
					.comments
					.trailing
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
				assert!(p.expressions[0].comments.trailing.is_none());
				assert_eq!(p.expressions[1].comments.leading.len(), 1);
				assert_eq!(p.expressions[1].comments.leading[0].text, " multi\n\tline ");
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
				assert_eq!(p.comments.tail.len(), 1);
				assert_eq!(p.comments.tail[0].text, " TODO add more");
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
				assert!(p.comments.closing.is_some());
				assert_eq!(p.comments.closing.as_ref().unwrap().text, " end of Alice");
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
				assert!(p.comments.opening.is_some());
				assert_eq!(p.comments.opening.as_ref().unwrap().text, " initiator");
			}
			_ => panic!(),
		}
	}

	#[test]
	fn comment_capture_tail_in_queries() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n\t// done\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert_eq!(m.queries_comments.tail.len(), 1);
		assert_eq!(m.queries_comments.tail[0].text, " done");
	}

	#[test]
	fn comment_capture_queries_closing_trailing() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n]\n\nqueries[\n\tconfidentiality? a\n] // end\n";
		let m = parse_string("t.vp", src).expect("parse");
		assert!(m.queries_comments.closing.is_some());
		assert_eq!(m.queries_comments.closing.as_ref().unwrap().text, " end");
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
		assert!(m.queries_comments.opening.is_some());
		assert_eq!(m.queries_comments.opening.as_ref().unwrap().text, " start");
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
		assert!(msg.comments.trailing.is_none());
		let bob = m
			.blocks
			.iter()
			.find_map(|b| match b {
				Block::Principal(p) if p.name == "Bob" => Some(p),
				_ => None,
			})
			.expect("bob");
		assert_eq!(bob.comments.leading.len(), 1);
		assert_eq!(bob.comments.leading[0].text, " next block");
	}

	#[test]
	fn comment_in_primitive_args_is_kept_on_the_expression() {
		let src = "attacker[active]\n\nprincipal Alice[\n\tknows private a\n\tx = ENC(/* secret */ a, a)\n]\n\nqueries[\n\tconfidentiality? a\n]\n";
		let m = parse_string("t.vp", src).expect("parse");
		let Block::Principal(alice) = &m.blocks[0] else {
			panic!("Alice's block");
		};
		let comments = &alice.expressions[1].comments.leading;
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
