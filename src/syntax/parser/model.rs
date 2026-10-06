/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::scanner::{starts_with_comment, starts_with_keyword};
use super::{Parser, is_reserved_word, title_case};
use crate::syntax::tokens::TokenKind;
use crate::syntax::{
	AttackerKind, Block, BracketComments, LineComments, Message, Model, Phase, Principal,
	PrincipalId, Scenario, Source, Span, VResult, VerifpalError,
};
use crate::term::Constant;
use crate::util::text::did_you_mean;

impl<'a> Parser<'a> {
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

	pub(super) fn message(
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

	pub(super) fn parse_route(
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

	pub(super) fn parse_model(&mut self) -> VResult<Model> {
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
}
