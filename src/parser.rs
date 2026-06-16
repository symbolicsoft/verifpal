/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::primitive::primitive_get_enum;
use crate::principal::principal_names_map_add;
use crate::types::*;
use crate::value::value_names_map_add;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Global counter for generating unique unnamed constant names during parsing.
/// Must be process-wide so that unnamed constants never collide across models
/// parsed in the same process (e.g. during parallel test runs).
static UNNAMED_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub fn unnamed_counter_reset() {
	UNNAMED_COUNTER.store(0, Ordering::SeqCst);
}

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
	"password",
	"confidentiality",
	"authentication",
	"freshness",
	"unlinkability",
	"equivalence",
	"precondition",
	"ringsign",
	"ringsignverif",
	"primitive",
	"pw_hash",
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
	"unnamed",
	"blind",
	"unblind",
	"queries",
];

fn check_reserved(s: &str) -> VResult<()> {
	let lower = s.to_lowercase();
	if RESERVED.contains(&lower.as_str())
		|| lower.starts_with("attacker")
		|| lower.starts_with("unnamed")
	{
		return Err(VerifpalError::Parse(
			format!("cannot use reserved keyword in name: {}", s).into(),
		));
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

/// Check if `s` starts with `keyword` followed by a non-identifier character
/// (or end of string). This prevents "phaseshift" from matching "phase".
fn starts_with_keyword(s: &str, keyword: &str) -> bool {
	if !s.starts_with(keyword) {
		return false;
	}
	s.as_bytes()
		.get(keyword.len())
		.is_none_or(|&b| !b.is_ascii_alphanumeric() && b != b'_')
}

struct Parser<'a> {
	input: &'a [u8],
	pos: usize,
	pending_leading: Vec<Comment>,
	unterminated_block_at: Option<usize>,
}

impl<'a> Parser<'a> {
	fn new(input: &'a str) -> Self {
		Parser {
			input: input.as_bytes(),
			pos: 0,
			pending_leading: Vec::new(),
			unterminated_block_at: None,
		}
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

	/// Consume whitespace and comments. Captures comments into
	/// `pending_leading` so they can be attached to the next AST node
	/// via `take_leading`.
	fn consume_trivia(&mut self) {
		self.consume_trivia_inner(true);
	}

	/// Same as `consume_trivia`, but discards any comments encountered
	/// rather than buffering them. Used in disallowed-comment positions
	/// (inside primitive args, equation halves, attacker[]/phase[]
	/// brackets, inner query option brackets).
	fn consume_trivia_nocapture(&mut self) {
		self.consume_trivia_inner(false);
	}

	/// Internal trivia consumer. When `capture` is false, comments are
	/// recognized and skipped but not stored — used for positions where
	/// comments are disallowed (inside primitive args, etc.).
	fn consume_trivia_inner(&mut self, capture: bool) {
		loop {
			self.skip_whitespace();
			let two = if self.pos + 1 < self.input.len() {
				(self.input[self.pos], self.input[self.pos + 1])
			} else {
				(0, 0)
			};
			if two == (b'/', b'/') {
				let start = self.pos + 2;
				while self.pos < self.input.len() && self.input[self.pos] != b'\n' {
					self.pos += 1;
				}
				if capture {
					let text = std::str::from_utf8(&self.input[start..self.pos])
						.unwrap_or("")
						.to_string();
					self.pending_leading.push(Comment {
						text,
						style: CommentStyle::Line,
					});
				}
			} else if two == (b'/', b'*') {
				let open = self.pos;
				self.pos += 2;
				let start = self.pos;
				loop {
					if self.pos + 1 >= self.input.len() {
						// Unterminated block comment.
						self.pos = self.input.len();
						self.unterminated_block_at = Some(open);
						return;
					}
					if self.input[self.pos] == b'*' && self.input[self.pos + 1] == b'/' {
						let end = self.pos;
						self.pos += 2;
						if capture {
							let text = std::str::from_utf8(&self.input[start..end])
								.unwrap_or("")
								.to_string();
							self.pending_leading.push(Comment {
								text,
								style: CommentStyle::Block,
							});
						}
						break;
					}
					self.pos += 1;
				}
			} else {
				break;
			}
		}
	}

	/// Drain and return any pending leading comments. Called at the
	/// start of building each AST node.
	fn take_leading(&mut self) -> Vec<Comment> {
		std::mem::take(&mut self.pending_leading)
	}

	/// Snapshot the parser state for a potentially-aborted lookahead.
	fn snapshot(&self) -> (usize, usize) {
		(self.pos, self.pending_leading.len())
	}

	/// Restore parser state from a snapshot, discarding any comments
	/// captured during the rolled-back lookahead.
	fn restore(&mut self, (pos, leading_len): (usize, usize)) {
		self.pos = pos;
		self.pending_leading.truncate(leading_len);
	}

	fn check_unterminated_block(&self) -> VResult<()> {
		if let Some(pos) = self.unterminated_block_at {
			return Err(VerifpalError::Parse(
				format!("unterminated block comment starting at byte {}", pos).into(),
			));
		}
		Ok(())
	}

	/// Try to capture a same-line trailing comment after the node's
	/// last token. Skips inline whitespace (spaces/tabs only) and
	/// returns a Comment if one opens and (for block style) closes
	/// before the next newline. Leaves `self.pos` past the comment
	/// if captured, or unchanged if not.
	fn try_take_trailing(&mut self) -> Option<Comment> {
		let saved = self.snapshot();
		self.skip_inline_whitespace();
		if self.pos + 1 >= self.input.len() {
			self.restore(saved);
			return None;
		}
		let two = (self.input[self.pos], self.input[self.pos + 1]);
		if two == (b'/', b'/') {
			let start = self.pos + 2;
			self.pos += 2;
			while self.pos < self.input.len() && self.input[self.pos] != b'\n' {
				self.pos += 1;
			}
			let text = std::str::from_utf8(&self.input[start..self.pos])
				.unwrap_or("")
				.to_string();
			Some(Comment {
				text,
				style: CommentStyle::Line,
			})
		} else if two == (b'/', b'*') {
			// Scan for `*/` BEFORE the next newline. If we hit a newline
			// first, this is NOT a trailing comment — restore pos and
			// return None so the next consume_trivia picks it up as a
			// leading comment of the next node.
			let probe_start = self.pos + 2;
			let mut probe = probe_start;
			loop {
				if probe + 1 >= self.input.len() {
					// Unterminated — leave for consume_trivia to flag.
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
		let bytes = s.as_bytes();
		if self.pos + bytes.len() <= self.input.len()
			&& &self.input[self.pos..self.pos + bytes.len()] == bytes
		{
			self.pos += bytes.len();
			Ok(())
		} else {
			Err(VerifpalError::Parse(
				format!("expected '{}' at position {}", s, self.pos).into(),
			))
		}
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
		while self.pos < self.input.len() {
			let c = self.input[self.pos];
			if c.is_ascii_alphanumeric() || c == b'_' {
				self.pos += 1;
			} else {
				break;
			}
		}
		if self.pos == start {
			return Err(VerifpalError::Parse(
				format!("expected identifier at position {}", self.pos).into(),
			));
		}
		let s = std::str::from_utf8(&self.input[start..self.pos])
			.map_err(|_| VerifpalError::Parse("invalid UTF-8 in identifier".into()))?;
		Ok(s.to_lowercase())
	}

	fn parse_model(&mut self) -> VResult<Model> {
		self.consume_trivia();
		self.check_unterminated_block()?;
		let pre_attacker_comments = self.take_leading();

		// Parse attacker
		if !self.try_expect("attacker") {
			return Err(VerifpalError::Parse("no `attacker` block defined".into()));
		}
		self.consume_trivia_nocapture();
		self.expect("[")?;
		self.consume_trivia_nocapture();
		let attacker_str = self.parse_identifier()?;
		let attacker_type = match attacker_str.as_str() {
			"active" => AttackerKind::Active,
			"passive" => AttackerKind::Passive,
			_ => {
				return Err(VerifpalError::Parse(
					format!("invalid attacker type: {}", attacker_str).into(),
				));
			}
		};
		self.consume_trivia_nocapture();
		self.expect("]")?;
		let attacker_trailing = self.try_take_trailing();
		self.consume_trivia();

		// Parse blocks
		let mut blocks = Vec::new();
		while !self.at_end() {
			self.consume_trivia();
			if self.at_end() {
				break;
			}

			// Check for queries block
			if starts_with_keyword(self.remaining(), "queries") {
				break;
			}

			let block = self.parse_block()?;
			blocks.push(block);
			self.consume_trivia();
		}

		if blocks.is_empty() {
			return Err(VerifpalError::Parse(
				"no principal or message blocks defined".into(),
			));
		}

		// Parse queries
		self.consume_trivia();
		let queries_leading_comments = self.take_leading();
		if !self.try_expect("queries") {
			return Err(VerifpalError::Parse("no `queries` block defined".into()));
		}
		self.skip_whitespace();
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
				break;
			}
			let leading = self.take_leading();
			let mut query = self.parse_query()?;
			query.leading_comments = leading;
			query.trailing_comment = self.try_take_trailing();
			queries.push(query);
			self.consume_trivia();
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
			return Err(VerifpalError::Parse(
				"the `queries` block must be at the end of the model; found content after `queries`"
					.into(),
			));
		}
		Ok(Model {
			file_name: String::new(),
			attacker: attacker_type,
			blocks,
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
		match &mut block {
			Block::Principal(p) => p.leading_comments = leading,
			Block::Message(m) => m.leading_comments = leading,
			Block::Phase(p) => p.leading_comments = leading,
		}
		Ok(block)
	}

	fn parse_principal(&mut self) -> VResult<Block> {
		self.expect("principal")?;
		self.skip_whitespace();
		let name = self.parse_identifier()?;
		let name = title_case(&name);
		self.skip_whitespace();
		self.expect("[")?;
		let header_trailing = self.try_take_trailing();
		self.consume_trivia();
		let mut expressions = Vec::new();
		while self.peek() != Some(b']') {
			self.consume_trivia();
			if self.peek() == Some(b']') {
				break;
			}
			let leading = self.take_leading();
			let mut expr = self.parse_expression()?;
			expr.leading_comments = leading;
			expr.trailing_comment = self.try_take_trailing();
			expressions.push(expr);
			self.consume_trivia();
		}
		let tail_comments = self.take_leading();
		self.expect("]")?;
		let closing_trailing = self.try_take_trailing();
		self.consume_trivia();
		let id = principal_names_map_add(&name);
		Ok(Block::Principal(Principal {
			name,
			id,
			expressions,
			leading_comments: Vec::new(),
			header_trailing,
			tail_comments,
			closing_trailing,
		}))
	}

	fn parse_message_block(&mut self) -> VResult<Block> {
		let sender_name = self.parse_identifier()?;
		let sender_name = title_case(&sender_name);
		self.skip_whitespace();
		// Accept -> or →
		if self.try_expect("->") || self.try_expect("\u{2192}") {
			// ok
		} else {
			return Err(VerifpalError::Parse(
				format!("expected '->' in message at position {}", self.pos).into(),
			));
		}
		self.skip_whitespace();
		let recipient_name = self.parse_identifier()?;
		let recipient_name = title_case(&recipient_name);
		self.skip_whitespace();
		self.expect(":")?;
		self.skip_whitespace();
		let constants = self.parse_message_constants()?;
		let trailing = self.try_take_trailing();
		self.consume_trivia();
		let sender_id = principal_names_map_add(&sender_name);
		let recipient_id = principal_names_map_add(&recipient_name);
		Ok(Block::Message(Message {
			sender: sender_id,
			recipient: recipient_id,
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
			// Check for end markers
			let rem = self.remaining();
			if starts_with_keyword(rem, "principal")
				|| starts_with_keyword(rem, "phase")
				|| starts_with_keyword(rem, "queries")
				|| rem.starts_with("//")
				|| rem.starts_with("/*")
			{
				break;
			}
			// Check for next message or block
			// Heuristic: if we see an identifier followed by ->, this is a new message
			let saved = self.snapshot();
			if let Ok(_id) = self.parse_identifier() {
				self.skip_whitespace();
				if self.remaining().starts_with("->") || self.remaining().starts_with("\u{2192}") {
					self.restore(saved);
					break;
				}
				self.restore(saved);
			} else {
				self.restore(saved);
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
			return Err(VerifpalError::Parse(
				"message constants are not defined".into(),
			));
		}
		Ok(constants)
	}

	fn parse_guarded_constant(&mut self) -> VResult<Constant> {
		self.expect("[")?;
		let mut c = self.parse_constant()?; // check_reserved already called inside parse_constant
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
		self.expect("knows")?;
		self.skip_whitespace();
		let qualifier_str = self.parse_identifier()?;
		let qualifier = match qualifier_str.as_str() {
			"private" => Qualifier::Private,
			"public" => Qualifier::Public,
			"password" => Qualifier::Password,
			_ => {
				return Err(VerifpalError::Parse(
					format!("invalid qualifier: {}", qualifier_str).into(),
				));
			}
		};
		self.skip_whitespace();
		let constants = self.parse_constants()?;
		Ok(Expression {
			kind: Declaration::Knows,
			qualifier: Some(qualifier),
			constants,
			assigned: None,
			leading_comments: Vec::new(),
			trailing_comment: None,
		})
	}

	fn parse_simple_expression(&mut self, keyword: &str, kind: Declaration) -> VResult<Expression> {
		self.expect(keyword)?;
		self.skip_whitespace();
		let constants = self.parse_constants()?;
		Ok(Expression {
			kind,
			qualifier: None,
			constants,
			assigned: None,
			leading_comments: Vec::new(),
			trailing_comment: None,
		})
	}

	fn parse_assignment(&mut self) -> VResult<Expression> {
		let constants = self.parse_constants()?;
		self.skip_whitespace();
		self.expect("=")?;
		self.skip_whitespace();
		let value = self.parse_value()?;
		if let Value::Constant(_) = &value {
			return Err(VerifpalError::Parse("cannot assign value to value".into()));
		}
		Ok(Expression {
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
			// Check for keywords that end the constant list
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
			return Err(VerifpalError::Parse(
				"expected at least one constant".into(),
			));
		}
		Ok(constants)
	}

	fn parse_constant(&mut self) -> VResult<Constant> {
		let name = self.parse_identifier()?;
		check_reserved(&name)?;
		let actual_name: Arc<str> = if name == "_" {
			let n = UNNAMED_COUNTER.fetch_add(1, Ordering::Relaxed);
			Arc::from(format!("unnamed_{}", n))
		} else {
			Arc::from(name)
		};
		let id = value_names_map_add(&actual_name);
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
		Ok(Value::Constant(self.parse_constant()?))
	}

	fn parse_value(&mut self) -> VResult<Value> {
		self.skip_whitespace();
		// Try primitive first (identifier followed by '(')
		let saved = self.snapshot();
		if let Ok(_name) = self.parse_identifier() {
			self.skip_whitespace();
			if self.peek() == Some(b'(') {
				// It's a primitive
				self.restore(saved);
				return self.parse_primitive();
			}
			// Check for equation (constant ^ constant)
			self.skip_whitespace();
			if self.peek() == Some(b'^') {
				// It's an equation
				self.restore(saved);
				return self.parse_equation();
			}
			// It's a constant
			self.restore(saved);
			return self.parse_constant_value();
		}
		self.restore(saved);
		Err(VerifpalError::Parse(
			format!("expected value at position {}", self.pos).into(),
		))
	}

	fn parse_primitive(&mut self) -> VResult<Value> {
		let name = self.parse_identifier()?;
		let prim_name = name.to_uppercase();
		self.skip_whitespace();
		self.expect("(")?;
		self.consume_trivia_nocapture();
		let mut arguments = Vec::new();
		while self.peek() != Some(b')') {
			if self.at_end() {
				return Err(VerifpalError::Parse("unterminated primitive".into()));
			}
			let arg = self.parse_value()?;
			arguments.push(arg);
			self.consume_trivia_nocapture();
			if self.peek() == Some(b',') {
				self.advance();
				self.consume_trivia_nocapture();
			}
		}
		self.expect(")")?;
		let check = self.try_expect("?");
		// Consume optional comma — outside the args list.
		self.skip_whitespace();
		if self.peek() == Some(b',') {
			self.advance();
		}
		let prim_id = primitive_get_enum(&prim_name)?;
		Ok(Value::Primitive(Arc::new(Primitive {
			id: prim_id,
			arguments,
			output: 0,
			instance_check: check,
		})))
	}

	fn parse_equation(&mut self) -> VResult<Value> {
		let first = self.parse_constant_value()?;
		self.consume_trivia_nocapture();
		self.expect("^")?;
		self.consume_trivia_nocapture();
		let second = self.parse_constant_value()?;
		Ok(Value::Equation(Arc::new(Equation {
			values: vec![first, second],
		})))
	}

	fn parse_phase(&mut self) -> VResult<Block> {
		self.expect("phase")?;
		self.consume_trivia_nocapture();
		self.expect("[")?;
		self.consume_trivia_nocapture();
		let start = self.pos;
		while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
			self.pos += 1;
		}
		let num_str = std::str::from_utf8(&self.input[start..self.pos])
			.map_err(|_| VerifpalError::Parse("invalid UTF-8 in phase number".into()))?;
		let number: i32 = num_str
			.parse()
			.map_err(|_| VerifpalError::Parse("invalid phase number".into()))?;
		self.consume_trivia_nocapture();
		self.expect("]")?;
		let trailing = self.try_take_trailing();
		self.consume_trivia();
		Ok(Block::Phase(Phase {
			number,
			leading_comments: Vec::new(),
			trailing_comment: trailing,
		}))
	}

	fn parse_query(&mut self) -> VResult<Query> {
		self.consume_trivia();
		let rem = self.remaining();
		if rem.starts_with("confidentiality?") {
			self.parse_query_single_constant("confidentiality?", QueryKind::Confidentiality)
		} else if rem.starts_with("authentication?") {
			self.parse_query_authentication()
		} else if rem.starts_with("freshness?") {
			self.parse_query_single_constant("freshness?", QueryKind::Freshness)
		} else if rem.starts_with("unlinkability?") {
			self.parse_query_multi_constant("unlinkability?", QueryKind::Unlinkability)
		} else if rem.starts_with("equivalence?") {
			self.parse_query_multi_constant("equivalence?", QueryKind::Equivalence)
		} else {
			Err(VerifpalError::Parse(
				format!("unknown query type at position {}", self.pos).into(),
			))
		}
	}

	fn parse_query_single_constant(&mut self, keyword: &str, kind: QueryKind) -> VResult<Query> {
		self.expect(keyword)?;
		self.skip_whitespace();
		let constant = self.parse_constant()?;
		self.skip_inline_whitespace();
		let options = self.try_parse_query_options()?;
		Ok(Query {
			kind,
			constants: vec![constant],
			message: Message::default(),
			options,
			leading_comments: Vec::new(),
			trailing_comment: None,
		})
	}

	fn parse_query_authentication(&mut self) -> VResult<Query> {
		self.expect("authentication?")?;
		self.skip_whitespace();
		// Parse message: Sender -> Recipient: constant
		let sender_name = title_case(&self.parse_identifier()?);
		self.skip_whitespace();
		if !self.try_expect("->") && !self.try_expect("\u{2192}") {
			return Err(VerifpalError::Parse(
				"expected '->' in authentication query".into(),
			));
		}
		self.skip_whitespace();
		let recipient_name = title_case(&self.parse_identifier()?);
		self.skip_whitespace();
		self.expect(":")?;
		self.skip_whitespace();
		let constant = self.parse_constant()?;
		self.skip_inline_whitespace();
		let sender_id = principal_names_map_add(&sender_name);
		let recipient_id = principal_names_map_add(&recipient_name);
		let options = self.try_parse_query_options()?;
		Ok(Query {
			kind: QueryKind::Authentication,
			constants: vec![],
			message: Message {
				sender: sender_id,
				recipient: recipient_id,
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
		self.expect(keyword)?;
		self.skip_whitespace();
		let constants = self.parse_query_constant_list()?;
		self.skip_inline_whitespace();
		let options = self.try_parse_query_options()?;
		Ok(Query {
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
			self.skip_whitespace();
			if self.at_end() || self.peek() == Some(b']') || self.peek() == Some(b'[') {
				break;
			}
			// Check for end of query list
			let rem = self.remaining();
			if starts_with_keyword(rem, "confidentiality")
				|| starts_with_keyword(rem, "authentication")
				|| starts_with_keyword(rem, "freshness")
				|| starts_with_keyword(rem, "unlinkability")
				|| starts_with_keyword(rem, "equivalence")
				|| rem.starts_with("//")
			{
				break;
			}
			constants.push(self.parse_constant()?);
			self.skip_whitespace();
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
		self.advance(); // [
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
			let leading = self.take_leading();
			let option_name = self.parse_identifier()?;
			self.skip_whitespace();
			self.expect("[")?;
			self.skip_whitespace();
			let sender_name = title_case(&self.parse_identifier()?);
			self.skip_whitespace();
			if !self.try_expect("->") && !self.try_expect("\u{2192}") {
				return Err(VerifpalError::Parse("expected '->' in query option".into()));
			}
			self.skip_whitespace();
			let recipient_name = title_case(&self.parse_identifier()?);
			self.skip_whitespace();
			self.expect(":")?;
			self.skip_whitespace();
			let constant = self.parse_constant()?;
			self.skip_whitespace();
			self.expect("]")?;
			let trailing = self.try_take_trailing();
			self.consume_trivia();

			let option_kind = match option_name.as_str() {
				"precondition" => QueryOptionKind::Precondition,
				_ => {
					return Err(VerifpalError::Parse(
						format!("unknown query option: {}", option_name).into(),
					));
				}
			};
			let sender_id = principal_names_map_add(&sender_name);
			let recipient_id = principal_names_map_add(&recipient_name);
			options.push(QueryOption {
				kind: option_kind,
				message: Message {
					sender: sender_id,
					recipient: recipient_id,
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
		self.skip_whitespace();
		Ok(options)
	}
}

pub fn parse_file(file_path: &str) -> VResult<Model> {
	let path = std::path::Path::new(file_path);
	let file_name = path
		.file_name()
		.and_then(|n| n.to_str())
		.unwrap_or("")
		.to_string();

	if file_name.len() > 64 {
		return Err(VerifpalError::Parse(
			"model file name must be 64 characters or less".into(),
		));
	}
	if !file_name.ends_with(".vp") {
		return Err(VerifpalError::Parse(
			"model file name must have a '.vp' extension".into(),
		));
	}

	let content = std::fs::read_to_string(file_path)
		.map_err(|e| VerifpalError::Parse(format!("failed to read file: {}", e).into()))?;

	parse_string(&file_name, &content)
}

pub fn parse_string(file_name: &str, input: &str) -> VResult<Model> {
	let mut parser = Parser::new(input);
	let mut model = parser.parse_model()?;
	model.file_name = file_name.to_string();
	Ok(model)
}
