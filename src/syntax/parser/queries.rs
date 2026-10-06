/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::Parser;
use super::scanner::{starts_with_comment, starts_with_keyword};
use crate::syntax::tokens::TokenKind;
use crate::syntax::{
	BracketComments, Message, Query, QueryKind, QueryOption, QueryOptionKind, Span, VResult,
	VerifpalError,
};
use crate::term::Constant;
use crate::util::text::did_you_mean;

impl<'a> Parser<'a> {
	pub(super) fn parse_queries(
		&mut self,
		after_scenarios: bool,
	) -> VResult<(BracketComments, Vec<Query>)> {
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
