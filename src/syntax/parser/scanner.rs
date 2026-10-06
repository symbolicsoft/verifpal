/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::borrow::Cow;

use super::Parser;
use crate::syntax::tokens::TokenKind;
use crate::syntax::{Comment, CommentStyle, LineComments, Span, VResult, VerifpalError};

fn starts_with_ignoring_case(s: &str, prefix: &str) -> bool {
	s.as_bytes()
		.get(..prefix.len())
		.is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

pub(super) fn starts_with_keyword(s: &str, keyword: &str) -> bool {
	starts_with_ignoring_case(s, keyword)
		&& s.as_bytes()
			.get(keyword.len())
			.is_none_or(|&b| !b.is_ascii_alphanumeric() && b != b'_')
}

pub(super) fn starts_with_comment(s: &str) -> bool {
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

impl<'a> Parser<'a> {
	fn bytes(&self) -> &'a [u8] {
		self.source.as_bytes()
	}

	pub(super) fn remaining(&self) -> &'a str {
		self.source.get(self.pos..).unwrap_or("")
	}

	pub(super) fn at_end(&self) -> bool {
		self.pos >= self.source.len()
	}

	pub(super) fn peek(&self) -> Option<u8> {
		self.bytes().get(self.pos).copied()
	}

	fn skip_while(&mut self, accept: impl Fn(u8) -> bool) {
		while self.peek().is_some_and(&accept) {
			self.pos += 1;
		}
	}

	pub(super) fn skip_whitespace(&mut self) {
		self.skip_while(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r'));
	}

	pub(super) fn skip_inline_whitespace(&mut self) {
		self.skip_while(|c| matches!(c, b' ' | b'\t'));
	}

	pub(super) fn digits(&mut self) -> Span {
		let start = self.pos;
		self.skip_while(|c| c.is_ascii_digit());
		Span::new(start, self.pos)
	}

	pub(super) fn text(&self, span: Span) -> &'a str {
		&self.source[span.start..span.end]
	}

	pub(super) fn trimmed_pos(&self) -> usize {
		self.source[..self.pos].trim_end_matches([' ', '\t']).len()
	}

	pub(super) fn record(&mut self, span: Span, kind: TokenKind) {
		self.tokens.push(span, kind, self.source);
	}

	pub(super) fn record_from(&mut self, start: usize, kind: TokenKind) {
		self.record(Span::new(start, self.pos), kind);
	}

	pub(super) fn eat(&mut self, text: &str) -> bool {
		let found = starts_with_ignoring_case(self.remaining(), text);
		if found {
			self.pos += text.len();
		}
		found
	}

	pub(super) fn eat_token(&mut self, text: &str, kind: TokenKind) -> bool {
		let start = self.pos;
		let found = self.eat(text);
		if found {
			self.record_from(start, kind);
		}
		found
	}

	pub(super) fn expect_where(&mut self, text: &str, context: &str) -> VResult<()> {
		if self.eat(text) {
			return Ok(());
		}
		Err(self.unexpected(if context.is_empty() {
			format!("expected `{}`", text)
		} else {
			format!("expected `{}` {}", text, context)
		}))
	}

	pub(super) fn expect(&mut self, text: &str) -> VResult<()> {
		self.expect_where(text, "")
	}

	pub(super) fn expect_token(&mut self, text: &str, kind: TokenKind) -> VResult<()> {
		let start = self.pos;
		self.expect(text)?;
		self.record_from(start, kind);
		Ok(())
	}

	pub(super) fn word_here(&self) -> &'a str {
		let rest = self.remaining();
		let end = rest
			.find(|c: char| !c.is_alphanumeric() && c != '_')
			.unwrap_or(rest.len());
		&rest[..end]
	}

	pub(super) fn here(&self) -> Span {
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

	pub(super) fn unexpected(&self, message: impl Into<Cow<'static, str>>) -> VerifpalError {
		VerifpalError::parse(message.into())
			.at(self.here())
			.labelled(self.found_here())
	}

	pub(super) fn unclosed_hint(&self, error: VerifpalError, opened_at: usize) -> VerifpalError {
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

	pub(super) fn consume_trivia(&mut self) {
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

	pub(super) fn try_take_trailing(&mut self) -> Option<Comment> {
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

	pub(super) fn take_leading(&mut self) -> Vec<Comment> {
		std::mem::take(&mut self.pending_leading)
	}

	pub(super) fn line_comments(&mut self, mut leading: Vec<Comment>) -> LineComments {
		leading.extend(self.take_leading());
		LineComments {
			leading,
			trailing: self.try_take_trailing(),
		}
	}

	pub(super) fn check_unterminated_block(&self) -> VResult<()> {
		if let Some(pos) = self.unterminated_block_at {
			return Err(VerifpalError::parse("unterminated block comment".into())
				.at(Span::at(pos))
				.labelled("this `/*` is never closed")
				.help("add the missing `*/`"));
		}
		Ok(())
	}

	pub(super) fn parse_identifier(&mut self) -> VResult<String> {
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
}
