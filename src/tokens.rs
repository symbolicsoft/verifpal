/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

// Every consumer of this module is `src/lsp/`, which lands next. Until then
// the only callers are the tests below. Remove this attribute when the server
// arrives; it should start failing the moment it is no longer needed.
#![allow(dead_code)]

//! Source spans for individual tokens.
//!
//! `Constant` carries no `Span` and must not gain one: it is half of `Value`,
//! the term type the solver clones, hashes and compares throughout, and its
//! size is load-bearing. Spans therefore come from the parser, which already
//! walks the bytes and already knows what each one is.
//!
//! This is emitted *by* the parser rather than by a second scanner. A second
//! scanner would drift from the first, which is the exact failure this whole
//! effort exists to end.

use std::sync::Arc;

use crate::types::Span;

/// What the parser decided a token was, lexically.
///
/// This is the *lexical* role. Whether a `ConstantName` is a declaration or a
/// use, and what it resolves to, is answered by cross-referencing the `Model`
/// and `ProtocolTrace`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TokenKind {
	/// `attacker`, `principal`, `knows`, `generates`, `leaks`, `phase`, `queries`
	Keyword,
	/// `active` or `passive`
	AttackerMode,
	/// `public`, `private`, `password`
	Qualifier,
	PrincipalName,
	ConstantName,
	PrimitiveName,
	/// `confidentiality?`, `authentication?`, `freshness?`, `unlinkability?`,
	/// `equivalence?` — the `?` is part of the keyword, not a check marker.
	QueryKind,
	/// `weak`, `forgeable`, `malleable`, and the `from`/`phase` of an onset
	Capability,
	/// The integer in `phase[N]` or `from phase N`
	PhaseNumber,
	/// `->` or `→`
	Arrow,
	/// `=`
	Assign,
	/// `?` marking a checked primitive
	Check,
	/// The `_` anonymous constant
	Anonymous,
	Comment,
}

#[derive(Clone, Debug)]
pub(crate) struct Token {
	pub span: Span,
	pub kind: TokenKind,
	/// The text exactly as written, before the parser case-folds it.
	pub text: Arc<str>,
}

/// Every token the parser recognised, in source order.
#[derive(Clone, Debug, Default)]
pub(crate) struct TokenIndex {
	tokens: Vec<Token>,
}

impl TokenIndex {
	pub(crate) fn push(&mut self, span: Span, kind: TokenKind, source: &str) {
		// A zero-width or out-of-bounds span records nothing: it would quote
		// text it does not cover, and every consumer here slices by span.
		if span.start >= span.end || span.end > source.len() {
			return;
		}
		self.tokens.push(Token {
			span,
			kind,
			text: Arc::from(&source[span.start..span.end]),
		});
	}

	pub(crate) fn tokens(&self) -> &[Token] {
		&self.tokens
	}

	pub(crate) fn is_empty(&self) -> bool {
		self.tokens.is_empty()
	}

	pub(crate) fn len(&self) -> usize {
		self.tokens.len()
	}

	pub(crate) fn truncate(&mut self, len: usize) {
		self.tokens.truncate(len);
	}

	/// The token covering `offset`, if any. `offset` is a byte offset into the
	/// same source the index was built from.
	///
	/// A position at a token's very end belongs to no token, which is what an
	/// editor wants: the caret after `PUBKEY` is not inside `PUBKEY`.
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

	#[test]
	fn every_token_span_quotes_its_own_text() {
		let index = index_of(SRC);
		assert!(!index.is_empty());
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
		// `PUBKEY` is fine; the missing `]` is not.
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
		// The space just past `->`.
		let arrow = SRC.find("->").expect("the arrow is in the source");
		assert!(index.at(arrow + 2).is_none());
	}

	/// Walks every model in the tree, not one hand-written source.
	///
	/// A recording site that captures the wrong span is the mistake this whole
	/// mechanism is prone to, and it shows up as a token whose text does not
	/// match the bytes it claims. One malformed site anywhere in the corpus
	/// fails this.
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
				// `at` must find every token the index holds.
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
