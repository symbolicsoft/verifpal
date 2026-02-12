/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::primitive::primitive_get_enum;
use crate::principal::principal_names_map_add;
use crate::types::*;
use crate::value::value_names_map_add;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

static UNNAMED_COUNTER: AtomicUsize = AtomicUsize::new(0);

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

fn check_reserved(s: &str) -> Result<(), String> {
	let lower = s.to_lowercase();
	if RESERVED.contains(&lower.as_str())
		|| lower.starts_with("attacker")
		|| lower.starts_with("unnamed")
	{
		return Err(format!("cannot use reserved keyword in name: {}", s));
	}
	Ok(())
}

fn title_case(s: &str) -> String {
	let mut chars = s.chars();
	match chars.next() {
		None => String::new(),
		Some(c) => c.to_uppercase().to_string() + &chars.as_str().to_lowercase(),
	}
}

/// Check if `s` starts with `keyword` followed by a non-identifier character
/// (or end of string). This prevents "phaseshift" from matching "phase".
fn starts_with_keyword(s: &str, keyword: &str) -> bool {
	if !s.starts_with(keyword) {
		return false;
	}
	s.as_bytes()
		.get(keyword.len())
		.map_or(true, |&b| !b.is_ascii_alphanumeric() && b != b'_')
}

struct Parser<'a> {
	input: &'a [u8],
	pos: usize,
}

impl<'a> Parser<'a> {
	fn new(input: &'a str) -> Self {
		Parser {
			input: input.as_bytes(),
			pos: 0,
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

	fn skip_whitespace_and_comments(&mut self) {
		loop {
			self.skip_whitespace();
			if self.pos + 1 < self.input.len()
				&& self.input[self.pos] == b'/'
				&& self.input[self.pos + 1] == b'/'
			{
				// Skip to end of line
				while self.pos < self.input.len() && self.input[self.pos] != b'\n' {
					self.pos += 1;
				}
			} else {
				break;
			}
		}
	}

	fn expect(&mut self, s: &str) -> Result<(), String> {
		let bytes = s.as_bytes();
		if self.pos + bytes.len() <= self.input.len()
			&& &self.input[self.pos..self.pos + bytes.len()] == bytes
		{
			self.pos += bytes.len();
			Ok(())
		} else {
			Err(format!("expected '{}' at position {}", s, self.pos))
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

	fn parse_identifier(&mut self) -> Result<String, String> {
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
			return Err(format!("expected identifier at position {}", self.pos));
		}
		let s =
			std::str::from_utf8(&self.input[start..self.pos]).expect("identifier is valid UTF-8");
		Ok(s.to_lowercase())
	}

	fn parse_model(&mut self) -> Result<Model, String> {
		self.skip_whitespace_and_comments();

		// Parse attacker
		if !self.try_expect("attacker") {
			return Err("no `attacker` block defined".to_string());
		}
		self.skip_whitespace();
		self.expect("[")?;
		self.skip_whitespace();
		let attacker_str = self.parse_identifier()?;
		let attacker_type = match attacker_str.as_str() {
			"active" => AttackerKind::Active,
			"passive" => AttackerKind::Passive,
			_ => return Err(format!("invalid attacker type: {}", attacker_str)),
		};
		self.skip_whitespace();
		self.expect("]")?;
		self.skip_whitespace_and_comments();

		// Parse blocks
		let mut blocks = Vec::new();
		while !self.at_end() {
			self.skip_whitespace_and_comments();
			if self.at_end() {
				break;
			}

			// Check for queries block
			if starts_with_keyword(self.remaining(), "queries") {
				break;
			}

			let block = self.parse_block()?;
			blocks.push(block);
			self.skip_whitespace_and_comments();
		}

		if blocks.is_empty() {
			return Err("no principal or message blocks defined".to_string());
		}

		// Parse queries
		self.skip_whitespace_and_comments();
		if !self.try_expect("queries") {
			return Err("no `queries` block defined".to_string());
		}
		self.skip_whitespace();
		self.expect("[")?;
		self.skip_whitespace_and_comments();
		let mut queries = Vec::new();
		while !self.at_end() {
			self.skip_whitespace_and_comments();
			if self.peek() == Some(b']') {
				self.advance();
				break;
			}
			let query = self.parse_query()?;
			queries.push(query);
			self.skip_whitespace_and_comments();
		}

		Ok(Model {
			file_name: String::new(),
			attacker: attacker_type,
			blocks,
			queries,
		})
	}

	fn parse_block(&mut self) -> Result<Block, String> {
		self.skip_whitespace_and_comments();

		if starts_with_keyword(self.remaining(), "phase") {
			return self.parse_phase();
		}

		// Try to determine if this is a principal or message
		// A principal starts with "principal", a message has "->" or "→"
		if starts_with_keyword(self.remaining(), "principal") {
			return self.parse_principal();
		}

		// Must be a message: Sender -> Recipient: constants
		self.parse_message_block()
	}

	fn parse_principal(&mut self) -> Result<Block, String> {
		self.expect("principal")?;
		self.skip_whitespace();
		let name = self.parse_identifier()?;
		let name = title_case(&name);
		self.skip_whitespace();
		self.expect("[")?;
		self.skip_whitespace_and_comments();
		let mut expressions = Vec::new();
		while self.peek() != Some(b']') {
			self.skip_whitespace_and_comments();
			if self.peek() == Some(b']') {
				break;
			}
			let expr = self.parse_expression()?;
			expressions.push(expr);
			self.skip_whitespace_and_comments();
		}
		self.expect("]")?;
		self.skip_whitespace_and_comments();
		let id = principal_names_map_add(&name);
		Ok(Block {
			kind: BlockKind::Principal,
			principal: Principal {
				name,
				id,
				expressions,
			},
			message: Message::default(),
			phase: Phase::default(),
		})
	}

	fn parse_message_block(&mut self) -> Result<Block, String> {
		let sender_name = self.parse_identifier()?;
		let sender_name = title_case(&sender_name);
		self.skip_whitespace();
		// Accept -> or →
		if self.try_expect("->") || self.try_expect("\u{2192}") {
			// ok
		} else {
			return Err(format!("expected '->' in message at position {}", self.pos));
		}
		self.skip_whitespace();
		let recipient_name = self.parse_identifier()?;
		let recipient_name = title_case(&recipient_name);
		self.skip_whitespace();
		self.expect(":")?;
		self.skip_whitespace();
		let constants = self.parse_message_constants()?;
		self.skip_whitespace_and_comments();
		let sender_id = principal_names_map_add(&sender_name);
		let recipient_id = principal_names_map_add(&recipient_name);
		Ok(Block {
			kind: BlockKind::Message,
			principal: Principal::default(),
			message: Message {
				sender: sender_id,
				recipient: recipient_id,
				constants,
			},
			phase: Phase::default(),
		})
	}

	fn parse_message_constants(&mut self) -> Result<Vec<Constant>, String> {
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
			{
				break;
			}
			// Check for next message or block
			// Heuristic: if we see an identifier followed by ->, this is a new message
			let saved = self.pos;
			if let Ok(_id) = self.parse_identifier() {
				self.skip_whitespace();
				if self.remaining().starts_with("->") || self.remaining().starts_with("\u{2192}") {
					self.pos = saved;
					break;
				}
				self.pos = saved;
			} else {
				self.pos = saved;
			}

			let constant = if self.peek() == Some(b'[') {
				self.parse_guarded_constant()?
			} else {
				self.parse_constant()?
			};
			constants.push(constant);
			self.skip_whitespace();
			if self.peek() == Some(b',') {
				self.advance();
			}
		}
		if constants.is_empty() {
			return Err("message constants are not defined".to_string());
		}
		Ok(constants)
	}

	fn parse_guarded_constant(&mut self) -> Result<Constant, String> {
		self.expect("[")?;
		let mut c = self.parse_constant()?; // check_reserved already called inside parse_constant
		// Consume trailing comma if present inside brackets
		self.skip_whitespace();
		self.expect("]")?;
		self.skip_whitespace();
		if self.peek() == Some(b',') {
			self.advance();
		}
		c.guard = true;
		Ok(c)
	}

	fn parse_expression(&mut self) -> Result<Expression, String> {
		self.skip_whitespace_and_comments();
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

	fn parse_knows(&mut self) -> Result<Expression, String> {
		self.expect("knows")?;
		self.skip_whitespace();
		let qualifier_str = self.parse_identifier()?;
		let qualifier = match qualifier_str.as_str() {
			"private" => Qualifier::Private,
			"public" => Qualifier::Public,
			"password" => Qualifier::Password,
			_ => return Err(format!("invalid qualifier: {}", qualifier_str)),
		};
		self.skip_whitespace();
		let constants = self.parse_constants()?;
		Ok(Expression {
			kind: Declaration::Knows,
			qualifier: Some(qualifier),
			constants,
			assigned: None,
		})
	}

	fn parse_simple_expression(
		&mut self,
		keyword: &str,
		kind: Declaration,
	) -> Result<Expression, String> {
		self.expect(keyword)?;
		self.skip_whitespace();
		let constants = self.parse_constants()?;
		Ok(Expression {
			kind,
			qualifier: None,
			constants,
			assigned: None,
		})
	}

	fn parse_assignment(&mut self) -> Result<Expression, String> {
		let constants = self.parse_constants()?;
		self.skip_whitespace();
		self.expect("=")?;
		self.skip_whitespace();
		let value = self.parse_value()?;
		if let Value::Constant(_) = &value {
			return Err("cannot assign value to value".to_string());
		}
		Ok(Expression {
			kind: Declaration::Assignment,
			qualifier: None,
			constants,
			assigned: Some(value),
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

	fn parse_constants(&mut self) -> Result<Vec<Constant>, String> {
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
			return Err("expected at least one constant".to_string());
		}
		Ok(constants)
	}

	fn parse_constant(&mut self) -> Result<Constant, String> {
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

	fn parse_constant_value(&mut self) -> Result<Value, String> {
		Ok(Value::Constant(self.parse_constant()?))
	}

	fn parse_value(&mut self) -> Result<Value, String> {
		self.skip_whitespace();
		// Try primitive first (identifier followed by '(')
		let saved = self.pos;
		if let Ok(_name) = self.parse_identifier() {
			self.skip_whitespace();
			if self.peek() == Some(b'(') {
				// It's a primitive
				self.pos = saved;
				return self.parse_primitive();
			}
			// Check for equation (constant ^ constant)
			self.skip_whitespace();
			if self.peek() == Some(b'^') {
				// It's an equation
				self.pos = saved;
				return self.parse_equation();
			}
			// It's a constant
			self.pos = saved;
			return self.parse_constant_value();
		}
		self.pos = saved;
		Err(format!("expected value at position {}", self.pos))
	}

	fn parse_primitive(&mut self) -> Result<Value, String> {
		let name = self.parse_identifier()?;
		let prim_name = name.to_uppercase();
		self.skip_whitespace();
		self.expect("(")?;
		self.skip_whitespace();
		let mut arguments = Vec::new();
		while self.peek() != Some(b')') {
			if self.at_end() {
				return Err("unterminated primitive".to_string());
			}
			let arg = self.parse_value()?;
			arguments.push(arg);
			self.skip_whitespace();
			if self.peek() == Some(b',') {
				self.advance();
				self.skip_whitespace();
			}
		}
		self.expect(")")?;
		let check = self.try_expect("?");
		// Consume optional comma
		self.skip_whitespace();
		if self.peek() == Some(b',') {
			self.advance();
		}
		let prim_id = primitive_get_enum(&prim_name)?;
		Ok(Value::Primitive(Arc::new(Primitive {
			id: prim_id,
			arguments,
			output: 0,
			check,
		})))
	}

	fn parse_equation(&mut self) -> Result<Value, String> {
		let first = self.parse_constant_value()?;
		self.skip_whitespace();
		self.expect("^")?;
		self.skip_whitespace();
		let second = self.parse_constant_value()?;
		Ok(Value::Equation(Arc::new(Equation {
			values: vec![first, second],
		})))
	}

	fn parse_phase(&mut self) -> Result<Block, String> {
		self.expect("phase")?;
		self.skip_whitespace();
		self.expect("[")?;
		self.skip_whitespace();
		let start = self.pos;
		while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
			self.pos += 1;
		}
		let num_str =
			std::str::from_utf8(&self.input[start..self.pos]).expect("phase number is valid UTF-8");
		let number: i32 = num_str
			.parse()
			.map_err(|_| "invalid phase number".to_string())?;
		self.skip_whitespace();
		self.expect("]")?;
		self.skip_whitespace_and_comments();
		Ok(Block {
			kind: BlockKind::Phase,
			principal: Principal::default(),
			message: Message::default(),
			phase: Phase { number },
		})
	}

	fn parse_query(&mut self) -> Result<Query, String> {
		self.skip_whitespace_and_comments();
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
			Err(format!("unknown query type at position {}", self.pos))
		}
	}

	fn parse_query_single_constant(
		&mut self,
		keyword: &str,
		kind: QueryKind,
	) -> Result<Query, String> {
		self.expect(keyword)?;
		self.skip_whitespace();
		let constant = self.parse_constant()?;
		self.skip_whitespace();
		let options = self.try_parse_query_options()?;
		Ok(Query {
			kind,
			constants: vec![constant],
			message: Message::default(),
			options,
		})
	}

	fn parse_query_authentication(&mut self) -> Result<Query, String> {
		self.expect("authentication?")?;
		self.skip_whitespace();
		// Parse message: Sender -> Recipient: constant
		let sender_name = title_case(&self.parse_identifier()?);
		self.skip_whitespace();
		if !self.try_expect("->") && !self.try_expect("\u{2192}") {
			return Err("expected '->' in authentication query".to_string());
		}
		self.skip_whitespace();
		let recipient_name = title_case(&self.parse_identifier()?);
		self.skip_whitespace();
		self.expect(":")?;
		self.skip_whitespace();
		let constant = self.parse_constant()?;
		self.skip_whitespace();
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
			},
			options,
		})
	}

	fn parse_query_multi_constant(
		&mut self,
		keyword: &str,
		kind: QueryKind,
	) -> Result<Query, String> {
		self.expect(keyword)?;
		self.skip_whitespace();
		let constants = self.parse_query_constant_list()?;
		self.skip_whitespace();
		let options = self.try_parse_query_options()?;
		Ok(Query {
			kind,
			constants,
			message: Message::default(),
			options,
		})
	}

	fn parse_query_constant_list(&mut self) -> Result<Vec<Constant>, String> {
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

	fn try_parse_query_options(&mut self) -> Result<Vec<QueryOption>, String> {
		self.skip_whitespace_and_comments();
		if self.peek() != Some(b'[') {
			return Ok(vec![]);
		}
		self.advance(); // [
		self.skip_whitespace_and_comments();
		let mut options = Vec::new();
		while self.peek() != Some(b']') {
			if self.at_end() {
				break;
			}
			self.skip_whitespace_and_comments();
			if self.peek() == Some(b']') {
				break;
			}
			let option_name = self.parse_identifier()?;
			self.skip_whitespace();
			self.expect("[")?;
			self.skip_whitespace();
			// Parse inner message
			let sender_name = title_case(&self.parse_identifier()?);
			self.skip_whitespace();
			if !self.try_expect("->") && !self.try_expect("\u{2192}") {
				return Err("expected '->' in query option".to_string());
			}
			self.skip_whitespace();
			let recipient_name = title_case(&self.parse_identifier()?);
			self.skip_whitespace();
			self.expect(":")?;
			self.skip_whitespace();
			let constant = self.parse_constant()?;
			self.skip_whitespace();
			self.expect("]")?;
			self.skip_whitespace_and_comments();

			let option_kind = match option_name.as_str() {
				"precondition" => QueryOptionKind::Precondition,
				_ => {
					return Err(format!("unknown query option: {}", option_name));
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
				},
			});
		}
		if self.peek() == Some(b']') {
			self.advance();
		}
		self.skip_whitespace();
		Ok(options)
	}
}

pub fn parse_file(file_path: &str) -> Result<Model, String> {
	let path = std::path::Path::new(file_path);
	let file_name = path
		.file_name()
		.and_then(|n| n.to_str())
		.unwrap_or("")
		.to_string();

	if file_name.len() > 64 {
		return Err("model file name must be 64 characters or less".to_string());
	}
	if !file_name.ends_with(".vp") {
		return Err("model file name must have a '.vp' extension".to_string());
	}

	let content =
		std::fs::read_to_string(file_path).map_err(|e| format!("failed to read file: {}", e))?;

	parse_string(&file_name, &content)
}

pub fn parse_string(file_name: &str, input: &str) -> Result<Model, String> {
	let mut parser = Parser::new(input);
	let mut model = parser.parse_model()?;
	model.file_name = file_name.to_string();
	Ok(model)
}
