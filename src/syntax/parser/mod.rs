/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

mod expressions;
mod model;
mod queries;
mod scanner;
#[cfg(test)]
mod tests;

use super::names::{PrincipalNames, ValueNames};
use super::tokens::TokenIndex;
use super::{Comment, Declaration, Model, Source, Span, VResult, VerifpalError};

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
	crate::syntax::names::ANONYMOUS_PREFIX,
	"g",
	"queries",
	"scenarios",
];

const DECLARATIONS: [(&str, Declaration); 3] = [
	("knows", Declaration::Knows),
	("generates", Declaration::Generates),
	("leaks", Declaration::Leaks),
];

const MAX_NESTING: usize = 128;

fn names_a_primitive(lower: &str) -> bool {
	crate::primitive::id_of(&lower.to_uppercase()).is_ok()
}

pub(crate) fn check_reserved(s: &str) -> VResult<()> {
	let lower = s.to_lowercase();
	if is_reserved_word(&lower)
		|| lower.starts_with("attacker")
		|| lower.starts_with(crate::syntax::names::ANONYMOUS_PREFIX)
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
