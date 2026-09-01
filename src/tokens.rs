/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::types::{ProtocolTrace, Span};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TokenKind {
	Keyword,
	AttackerMode,
	Qualifier,
	PrincipalName,
	ConstantName,
	PrimitiveName,
	QueryKind,
	Capability,
	PhaseNumber,
	Arrow,
	Assign,
	Check,
	Anonymous,
	Comment,
}

#[cfg_attr(not(any(test, feature = "lsp")), allow(dead_code))]
#[derive(Clone, Debug)]
pub(crate) struct Token {
	pub span: Span,
	pub kind: TokenKind,
	pub text: Arc<str>,
}

#[cfg_attr(not(any(test, feature = "lsp")), allow(dead_code))]
#[derive(Clone, Debug)]
pub(crate) struct Symbol {
	pub name: Arc<str>,
	pub creator: Option<Arc<str>>,
	pub assigned: Option<String>,
	pub known_by: Vec<(Arc<str>, Arc<str>)>,
	pub phases: Vec<i32>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TokenIndex {
	tokens: Vec<Token>,
}

impl TokenIndex {
	pub(crate) fn push(&mut self, span: Span, kind: TokenKind, source: &str) {
		if span.start >= span.end || span.end > source.len() {
			return;
		}
		self.tokens.push(Token {
			span,
			kind,
			text: Arc::from(&source[span.start..span.end]),
		});
	}

	#[cfg_attr(not(any(test, feature = "lsp")), allow(dead_code))]
	pub(crate) fn tokens(&self) -> &[Token] {
		&self.tokens
	}

	pub(crate) fn len(&self) -> usize {
		self.tokens.len()
	}

	pub(crate) fn truncate(&mut self, len: usize) {
		self.tokens.truncate(len);
	}

	#[cfg_attr(not(any(test, feature = "lsp")), allow(dead_code))]
	pub(crate) fn references(&self, token: &Token) -> Vec<Span> {
		self.tokens
			.iter()
			.filter(|t| t.kind == token.kind && t.text.eq_ignore_ascii_case(token.text.as_ref()))
			.map(|t| t.span)
			.collect()
	}

	#[cfg_attr(not(any(test, feature = "lsp")), allow(dead_code))]
	pub(crate) fn declaration_of(&self, token: &Token) -> Option<Span> {
		if token.kind == TokenKind::PrincipalName {
			return self.tokens.windows(2).find_map(|pair| {
				let keyword = &pair[0];
				let candidate = &pair[1];
				(keyword.kind == TokenKind::Keyword
					&& keyword.text.eq_ignore_ascii_case("principal")
					&& candidate.kind == token.kind
					&& candidate.text.eq_ignore_ascii_case(token.text.as_ref()))
				.then_some(candidate.span)
			});
		}
		self.references(token).first().copied()
	}

	#[cfg_attr(not(any(test, feature = "lsp")), allow(dead_code))]
	pub(crate) fn resolve(&self, token: &Token, trace: &ProtocolTrace) -> Option<Symbol> {
		if token.kind != TokenKind::ConstantName && token.kind != TokenKind::Anonymous {
			return None;
		}
		let slot = trace
			.slots
			.iter()
			.find(|slot| slot.constant.name.eq_ignore_ascii_case(token.text.as_ref()))?;
		Some(Symbol {
			name: Arc::clone(&slot.constant.name),
			creator: Some(Arc::from(trace.principal_name(slot.creator))),
			assigned: Some(slot.initial_value.to_string()),
			known_by: slot
				.known_by
				.iter()
				.map(|&(recipient, sender)| {
					(
						Arc::from(trace.principal_name(recipient)),
						Arc::from(trace.principal_name(sender)),
					)
				})
				.collect(),
			phases: slot.phases.clone(),
		})
	}

	#[cfg_attr(not(any(test, feature = "lsp")), allow(dead_code))]
	pub(crate) fn at(&self, offset: usize) -> Option<&Token> {
		let i = self
			.tokens
			.partition_point(|t| t.span.start <= offset)
			.checked_sub(1)?;
		let token = &self.tokens[i];
		(offset < token.span.end).then_some(token)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const SRC: &str = "attacker[active]\n\
		principal Alice[\n\
		\tknows private tk_a\n\
		\ttk_ga = PUBKEY(tk_a)\n\
		]\n\
		Alice -> Bob: tk_ga\n\
		principal Bob[\n\
		\t_ = HASH(tk_ga)\n\
		]\n\
		queries[\n\
		\tconfidentiality? tk_a\n\
		]\n";

	fn index_of(src: &str) -> TokenIndex {
		let (model, index) = crate::parser::parse_string_indexed("tk.vp", src);
		model.expect("parses");
		index
	}

	const RESOLVE_SRC: &str = "attacker[passive]\n\
		principal Alice[\n\
		\tknows private tr_a\n\
		\ttr_ga = PUBKEY(tr_a)\n\
		]\n\
		Alice -> Bob: tr_ga\n\
		principal Bob[\n\
		\t_ = HASH(tr_ga)\n\
		]\n\
		queries[\n\
		\tconfidentiality? tr_a\n\
		]\n";

	fn resolve_fixture() -> (crate::types::ProtocolTrace, TokenIndex) {
		let (model, index) = crate::parser::parse_string_indexed("tr.vp", RESOLVE_SRC);
		let model = model.expect("parses");
		let (trace, _) = crate::sanity::sanity(&model).expect("passes sanity");
		(trace, index)
	}

	#[test]
	fn a_constants_declaration_is_where_it_was_assigned() {
		let (_, index) = resolve_fixture();
		let at = RESOLVE_SRC
			.find("tr_ga = PUBKEY")
			.expect("the assignment is in the source");
		let token = index.at(at).expect("tr_ga is indexed");
		let declaration = index.declaration_of(token).expect("tr_ga is declared");
		assert_eq!(declaration.start, at);
	}

	#[test]
	fn a_knowns_declaration_is_the_knows_line() {
		let (_, index) = resolve_fixture();
		let at = RESOLVE_SRC
			.find("tr_a\n")
			.expect("the knows line is in the source");
		let token = index.at(at).expect("tr_a is indexed");
		let declaration = index.declaration_of(token).expect("tr_a is declared");
		assert_eq!(declaration.start, at);
	}

	#[test]
	fn a_principals_declaration_is_its_block_not_its_first_reference() {
		let (_, index) = resolve_fixture();
		let reference = RESOLVE_SRC.find("Bob: tr_ga").expect("Bob is a recipient");
		let token = index.at(reference).expect("Bob is indexed");
		let declaration = index.declaration_of(token).expect("Bob is declared");
		let expected = RESOLVE_SRC
			.find("Bob[\n")
			.expect("Bob's declaration is in the source");
		assert_eq!(declaration.start, expected);
	}

	#[test]
	fn references_finds_every_occurrence_including_the_declaration() {
		let (_, index) = resolve_fixture();
		let tr_ga = index
			.at(RESOLVE_SRC.find("tr_ga").expect("tr_ga is present"))
			.expect("tr_ga is indexed");
		let tr_a = index
			.at(RESOLVE_SRC.find("tr_a").expect("tr_a is present"))
			.expect("tr_a is indexed");
		assert_eq!(index.references(tr_ga).len(), 3);
		assert_eq!(index.references(tr_a).len(), 3);
	}

	#[test]
	fn references_is_case_insensitive_because_the_language_is() {
		let (_, index) = resolve_fixture();
		let mut token = index
			.at(RESOLVE_SRC.find("tr_ga").expect("tr_ga is present"))
			.expect("tr_ga is indexed")
			.clone();
		token.text = Arc::from("TR_GA");
		assert_eq!(index.references(&token).len(), 3);
	}

	#[test]
	fn resolving_a_constant_names_its_creator_and_assignment() {
		let (trace, index) = resolve_fixture();
		let at = RESOLVE_SRC.find("HASH(tr_ga)").expect("in the source") + "HASH(".len();
		let token = index.at(at).expect("a token at the HASH argument");
		let symbol = index.resolve(token, &trace).expect("resolves");

		assert_eq!(&*symbol.name, "tr_ga");
		assert_eq!(symbol.creator.as_deref(), Some("Alice"));
		assert_eq!(symbol.assigned.as_deref(), Some("PUBKEY(tr_a)"));
		assert!(
			symbol
				.known_by
				.iter()
				.any(|(recipient, sender)| &**recipient == "Bob" && &**sender == "Alice"),
			"Bob knows tr_ga from Alice: {:?}",
			symbol.known_by
		);
	}

	#[test]
	fn a_primitive_token_resolves_to_nothing() {
		let (trace, index) = resolve_fixture();
		let at = RESOLVE_SRC.find("PUBKEY").expect("in the source");
		let token = index.at(at).expect("a token at PUBKEY");
		assert!(index.resolve(token, &trace).is_none());
	}

	#[test]
	fn every_token_span_quotes_its_own_text() {
		let index = index_of(SRC);
		assert!(!index.tokens().is_empty());
		for token in index.tokens() {
			assert_eq!(
				&SRC[token.span.start..token.span.end],
				&*token.text,
				"{:?} does not quote its span",
				token
			);
		}
	}

	#[test]
	fn tokens_are_sorted_and_non_overlapping() {
		let index = index_of(SRC);
		let mut previous = 0usize;
		for token in index.tokens() {
			assert!(
				token.span.start >= previous,
				"{:?} starts before the previous token ended",
				token
			);
			previous = token.span.end;
		}
	}

	#[test]
	fn a_constant_is_recorded_as_a_constant() {
		let index = index_of(SRC);
		let at = SRC
			.find("tk_ga = PUBKEY")
			.expect("the assignment is in the source");
		let token = index.at(at).expect("a token at the assignment");
		assert_eq!(token.kind, TokenKind::ConstantName);
		assert_eq!(&*token.text, "tk_ga");
	}

	#[test]
	fn a_primitive_is_recorded_as_a_primitive() {
		let index = index_of(SRC);
		let at = SRC.find("PUBKEY").expect("PUBKEY is in the source");
		let token = index.at(at).expect("a token at PUBKEY");
		assert_eq!(token.kind, TokenKind::PrimitiveName);
		assert_eq!(&*token.text, "PUBKEY");
	}

	#[test]
	fn a_principal_is_recorded_as_a_principal() {
		let index = index_of(SRC);
		let at = SRC.find("Alice").expect("Alice is in the source");
		let token = index.at(at).expect("a token at Alice");
		assert_eq!(token.kind, TokenKind::PrincipalName);
		assert_eq!(&*token.text, "Alice");
	}

	#[test]
	fn an_index_survives_a_parse_failure() {
		let broken = "attacker[active]\n\
			principal Alice[\n\
			\tknows private tb_a\n\
			\ttb_ga = PUBKEY(tb_a)\n";
		let (model, index) = crate::parser::parse_string_indexed("tb.vp", broken);
		assert!(model.is_err(), "this model must not parse");
		let at = broken.find("PUBKEY").expect("PUBKEY is in the source");
		let token = index
			.at(at)
			.expect("tokens up to the failure are still recorded");
		assert_eq!(token.kind, TokenKind::PrimitiveName);
	}

	#[test]
	fn at_returns_nothing_between_tokens() {
		let index = index_of(SRC);
		let arrow = SRC.find("->").expect("the arrow is in the source");
		assert!(index.at(arrow + 2).is_none());
	}

	#[test]
	fn every_model_in_the_tree_indexes_coherently() {
		fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
			let Ok(entries) = std::fs::read_dir(dir) else {
				return;
			};
			for entry in entries.flatten() {
				let path = entry.path();
				if path.is_dir() {
					walk(&path, out);
				} else if path.extension().is_some_and(|e| e == "vp") {
					out.push(path);
				}
			}
		}

		let mut models = Vec::new();
		walk(std::path::Path::new("examples"), &mut models);
		models.sort();
		assert!(models.len() > 100, "found only {} models", models.len());

		let mut total = 0usize;
		for path in &models {
			let Ok(source) = std::fs::read_to_string(path) else {
				continue;
			};
			let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("m.vp");
			let (_, index) = crate::parser::parse_string_indexed(name, &source);
			let mut previous = 0usize;
			for token in index.tokens() {
				assert_eq!(
					&source[token.span.start..token.span.end],
					&*token.text,
					"{}: {:?} does not quote its span",
					path.display(),
					token
				);
				assert!(
					token.span.start >= previous,
					"{}: {:?} overlaps the token before it",
					path.display(),
					token
				);
				previous = token.span.end;
				let found = index.at(token.span.start).expect("at() finds each token");
				assert_eq!(found.span.start, token.span.start);
			}
			total += index.tokens().len();
		}
		assert!(total > 10_000, "only {total} tokens across the corpus");
	}

	#[test]
	fn comments_are_recorded_in_both_forms() {
		let src = "// leading\n\
			attacker[active] // trailing\n\
			principal Alice[\n\
			\t/* block */ knows private tc_a\n\
			\ttc_h = HASH(tc_a)\n\
			]\n\
			Alice -> Bob: tc_h\n\
			principal Bob[\n\
			\t_ = HASH(tc_h)\n\
			]\n\
			queries[\n\
			\tconfidentiality? tc_a\n\
			]\n";
		let index = index_of(src);
		let comments: Vec<&Token> = index
			.tokens()
			.iter()
			.filter(|t| t.kind == TokenKind::Comment)
			.collect();
		assert_eq!(comments.len(), 3, "{:?}", comments);
		assert!(comments.iter().any(|t| &*t.text == "// leading"));
		assert!(comments.iter().any(|t| &*t.text == "// trailing"));
		assert!(comments.iter().any(|t| &*t.text == "/* block */"));
	}
}
