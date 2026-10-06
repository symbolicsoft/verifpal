/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::scanner::{starts_with_comment, starts_with_keyword};
use super::{DECLARATIONS, MAX_NESTING, Parser, check_reserved, names_a_primitive};
use crate::primitive::{
	Capabilities, Capability, primitive_get_enum, primitive_names, primitive_renamed,
	primitive_threshold, primitives_with_threshold,
};
use crate::syntax::tokens::TokenKind;
use crate::syntax::{Comment, Declaration, Expression, Qualifier, Span, VResult, VerifpalError};
use crate::term::{Constant, HashCell, Primitive, Value};
use crate::util::text::did_you_mean;

impl<'a> Parser<'a> {
	pub(super) fn parse_expression(&mut self) -> VResult<Expression> {
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

	pub(super) fn parse_constant(&mut self) -> VResult<Constant> {
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
			Arc::from(format!(
				"{}_{}",
				crate::syntax::names::ANONYMOUS_PREFIX,
				index
			))
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
					crate::util::text::quoted_list(
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
}
