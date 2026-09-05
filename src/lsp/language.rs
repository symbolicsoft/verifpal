/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use lsp_types::{
	CompletionItem, CompletionItemKind, DocumentHighlight, DocumentHighlightKind, DocumentSymbol,
	Documentation, FoldingRange, FoldingRangeKind, InlayHint, InlayHintLabel, Location,
	MarkupContent, MarkupKind, ParameterInformation, ParameterLabel, Position, Range,
	SignatureHelp, SignatureInformation, SymbolKind, TextEdit, Uri,
};

use crate::lsp::docs;
use crate::lsp::state::Document;
use crate::tokens::{Token, TokenKind};
use crate::types::{Block, Declaration, Span};

pub(crate) const TOKEN_TYPES: &[&str] = &[
	"namespace",
	"variable",
	"function",
	"keyword",
	"parameter",
	"type",
	"decorator",
	"number",
	"operator",
	"comment",
];

pub(crate) const TOKEN_MODIFIERS: &[&str] = &["declaration", "defaultLibrary"];

fn token_type(kind: TokenKind) -> Option<u32> {
	let name = match kind {
		TokenKind::PrincipalName => "namespace",
		TokenKind::ConstantName | TokenKind::Anonymous => "variable",
		TokenKind::PrimitiveName => "function",
		TokenKind::Keyword | TokenKind::AttackerMode => "keyword",
		TokenKind::Qualifier => "parameter",
		TokenKind::QueryKind => "type",
		TokenKind::Capability => "decorator",
		TokenKind::PhaseNumber => "number",
		TokenKind::Arrow | TokenKind::Assign | TokenKind::Check => "operator",
		TokenKind::Comment => "comment",
	};
	TOKEN_TYPES
		.iter()
		.position(|t| *t == name)
		.map(|i| i as u32)
}

pub(crate) fn semantic_tokens(doc: &Document) -> Vec<u32> {
	let mut data = Vec::new();
	let mut previous = Position::new(0, 0);
	for token in doc.tokens.tokens() {
		let Some(ty) = token_type(token.kind) else {
			continue;
		};
		let mut modifiers = 0u32;
		if token.kind == TokenKind::PrimitiveName {
			modifiers |= 1 << 1;
		}
		if matches!(
			token.kind,
			TokenKind::ConstantName | TokenKind::PrincipalName
		) && !is_nil(&token.text)
			&& doc
				.tokens
				.declaration_of(token)
				.is_some_and(|d| d.start == token.span.start)
		{
			modifiers |= 1 << 0;
		}
		// A semantic token cannot span lines, so a block comment that does is
		// emitted one line at a time.
		for (from, to) in line_segments(&doc.text, token.span) {
			let start = doc.line.position(from);
			let end = doc.line.position(to);
			if start.line != end.line {
				continue;
			}
			let delta_line = start.line - previous.line;
			let delta_start = if delta_line == 0 {
				start.character - previous.character
			} else {
				start.character
			};
			data.extend_from_slice(&[
				delta_line,
				delta_start,
				end.character.saturating_sub(start.character),
				ty,
				modifiers,
			]);
			previous = start;
		}
	}
	data
}

fn line_segments(text: &str, span: Span) -> Vec<(usize, usize)> {
	let end = span.end.min(text.len());
	let start = span.start.min(end);
	let mut segments = Vec::new();
	let mut from = start;
	for (i, byte) in text.as_bytes()[start..end].iter().enumerate() {
		if *byte == b'\n' {
			segments.push((from, start + i));
			from = start + i + 1;
		}
	}
	segments.push((from, end.max(from)));
	segments
}

fn is_nil(text: &str) -> bool {
	text.eq_ignore_ascii_case("nil")
}

pub(crate) fn token_at(doc: &Document, position: Position) -> Option<&Token> {
	doc.tokens.at(doc.line.offset(position))
}

fn markdown(value: String) -> Documentation {
	Documentation::MarkupContent(MarkupContent {
		kind: MarkupKind::Markdown,
		value,
	})
}

fn primitive_facts(name: &str) -> Option<String> {
	let id = crate::primitive::primitive_get_enum(&name.to_uppercase()).ok()?;
	let def = crate::primitive::primitive_def(id).ok()?;
	let arity = def.arity();
	let output = def.output();
	let args = if arity.len() == 1 {
		format!(
			"{} argument{}",
			arity[0],
			if arity[0] == 1 { "" } else { "s" }
		)
	} else {
		format!("{}\u{2013}{} arguments", arity[0], arity[arity.len() - 1])
	};
	let outs = if output.len() == 1 {
		format!(
			"{} output{}",
			output[0],
			if output[0] == 1 { "" } else { "s" }
		)
	} else {
		format!("{}\u{2013}{} outputs", output[0], output[output.len() - 1])
	};
	let mut notes = vec![format!("{args}, {outs}")];
	if def.definition_check() {
		notes.push("may be checked with `?`".to_string());
	}
	let accepted: Vec<&str> = crate::types::Capability::ALL
		.iter()
		.filter(|c| crate::capability::supports(id, **c))
		.map(|c| c.name())
		.collect();
	if !accepted.is_empty() {
		notes.push(format!("accepts [{}]", accepted.join(", ")));
	}
	Some(notes.join("; "))
}

pub(crate) fn hover(doc: &Document, position: Position) -> Option<lsp_types::Hover> {
	let token = token_at(doc, position)?;
	let range = doc.line.range(token.span);
	let value = match token.kind {
		TokenKind::ConstantName if is_nil(&token.text) => {
			let entry = docs::keyword("nil")?;
			format!("```verifpal\n{}\n```\n\n{}", entry.eg, entry.help)
		}
		TokenKind::ConstantName | TokenKind::Anonymous => constant_hover(doc, token)?,
		TokenKind::Capability => {
			// `phase` inside `[weak from phase 1]` is part of the onset, not a phase block.
			let word = if token.text.eq_ignore_ascii_case("phase") {
				"from"
			} else {
				&token.text
			};
			let entry = docs::capability(word)?;
			format!("```verifpal\n{}\n```\n\n{}", entry.eg, entry.help)
		}
		TokenKind::PrimitiveName => {
			let entry = docs::primitive(&token.text)?;
			let mut out = format!("```verifpal\n{}\n```\n\n{}", entry.eg, entry.help);
			if let Some(facts) = primitive_facts(&token.text) {
				out.push_str("\n\n");
				out.push_str(&facts);
			}
			out
		}
		TokenKind::PrincipalName => format!("**{}**\n\nA principal in this model.", token.text),
		TokenKind::QueryKind => {
			// The token spans the whole `confidentiality?`; the table is keyed without the `?`.
			let entry = docs::query(token.text.trim_end_matches('?'))?;
			format!("```verifpal\n{}\n```\n\n{}", entry.eg, entry.help)
		}
		_ => {
			let entry = docs::any(&token.text)?;
			format!("```verifpal\n{}\n```\n\n{}", entry.eg, entry.help)
		}
	};
	Some(lsp_types::Hover {
		contents: lsp_types::HoverContents::Markup(MarkupContent {
			kind: MarkupKind::Markdown,
			value,
		}),
		range: Some(range),
	})
}

fn constant_hover(doc: &Document, token: &Token) -> Option<String> {
	let trace = doc.trace.as_ref()?;
	let symbol = doc.tokens.resolve(token, trace)?;
	let mut out = format!("```verifpal\n{}\n```", symbol.name);
	if let Some(assigned) = &symbol.assigned {
		out.push_str(&format!("\n\nAssigned: `{assigned}`"));
	}
	if let Some(creator) = &symbol.creator {
		out.push_str(&format!("\n\nCreated by **{creator}**"));
	}
	if !symbol.known_by.is_empty() {
		let known: Vec<String> = symbol
			.known_by
			.iter()
			.map(|(recipient, sender)| format!("{recipient} (from {sender})"))
			.collect();
		out.push_str(&format!("\n\nKnown by: {}", known.join(", ")));
	}
	if !symbol.phases.is_empty() {
		let phases: Vec<String> = symbol.phases.iter().map(|p| p.to_string()).collect();
		out.push_str(&format!("\n\nPhases: {}", phases.join(", ")));
	}
	Some(out)
}

pub(crate) fn definition(doc: &Document, position: Position, uri: &Uri) -> Option<Location> {
	let token = token_at(doc, position)?;
	if !matches!(
		token.kind,
		TokenKind::ConstantName | TokenKind::PrincipalName
	) {
		return None;
	}
	let span = doc.tokens.declaration_of(token)?;
	Some(Location {
		uri: uri.clone(),
		range: doc.line.range(span),
	})
}

pub(crate) fn references(doc: &Document, position: Position, uri: &Uri) -> Vec<Location> {
	let Some(token) = token_at(doc, position) else {
		return Vec::new();
	};
	if !matches!(
		token.kind,
		TokenKind::ConstantName | TokenKind::PrincipalName
	) {
		return Vec::new();
	}
	doc.tokens
		.references(token)
		.into_iter()
		.map(|span| Location {
			uri: uri.clone(),
			range: doc.line.range(span),
		})
		.collect()
}

pub(crate) fn highlights(doc: &Document, position: Position) -> Vec<DocumentHighlight> {
	let Some(token) = token_at(doc, position) else {
		return Vec::new();
	};
	if !matches!(
		token.kind,
		TokenKind::ConstantName | TokenKind::PrincipalName
	) {
		return Vec::new();
	}
	let declaration = doc.tokens.declaration_of(token);
	doc.tokens
		.references(token)
		.into_iter()
		.map(|span| DocumentHighlight {
			range: doc.line.range(span),
			kind: Some(if declaration.is_some_and(|d| d.start == span.start) {
				DocumentHighlightKind::WRITE
			} else {
				DocumentHighlightKind::READ
			}),
		})
		.collect()
}

pub(crate) fn rename(doc: &Document, position: Position, new_name: &str) -> Option<Vec<TextEdit>> {
	let token = token_at(doc, position)?;
	if !renameable(token) || !valid_rename(doc, token, new_name) {
		return None;
	}
	Some(
		doc.tokens
			.references(token)
			.into_iter()
			.map(|span| TextEdit {
				range: doc.line.range(span),
				new_text: new_name.to_string(),
			})
			.collect(),
	)
}

fn renameable(token: &Token) -> bool {
	matches!(
		token.kind,
		TokenKind::ConstantName | TokenKind::PrincipalName
	) && !(token.kind == TokenKind::ConstantName && token.text.eq_ignore_ascii_case("nil"))
}

fn valid_rename(doc: &Document, token: &Token, new_name: &str) -> bool {
	if new_name.is_empty()
		|| !new_name
			.bytes()
			.all(|c| c.is_ascii_alphanumeric() || c == b'_')
	{
		return false;
	}
	match token.kind {
		TokenKind::ConstantName => {
			if new_name == "_"
				|| new_name.eq_ignore_ascii_case("nil")
				|| crate::parser::check_reserved(new_name).is_err()
			{
				return false;
			}
		}
		TokenKind::PrincipalName => {
			if new_name.eq_ignore_ascii_case(crate::principal::ATTACKER_NAME)
				|| ["phase", "principal", "queries", "scenarios"]
					.iter()
					.any(|word| new_name.eq_ignore_ascii_case(word))
			{
				return false;
			}
		}
		_ => return false,
	}
	!doc.tokens.tokens().iter().any(|other| {
		other.kind == token.kind
			&& !other.text.eq_ignore_ascii_case(token.text.as_ref())
			&& other.text.eq_ignore_ascii_case(new_name)
	})
}

pub(crate) fn folding_ranges(doc: &Document) -> Vec<FoldingRange> {
	let mut ranges = Vec::new();
	if let Ok(model) = &doc.model {
		for block in &model.blocks {
			if let Block::Principal(p) = block {
				push_fold(&mut ranges, doc, p.span, None);
			}
		}
	}
	for token in doc.tokens.tokens() {
		if token.kind == TokenKind::Comment && token.text.starts_with("/*") {
			push_fold(
				&mut ranges,
				doc,
				token.span,
				Some(FoldingRangeKind::Comment),
			);
		}
		if token.kind == TokenKind::Keyword
			&& (token.text.eq_ignore_ascii_case("queries")
				|| token.text.eq_ignore_ascii_case("scenarios"))
			&& let Some(close) = block_close(&doc.text, token.span.end)
		{
			push_fold(&mut ranges, doc, Span::new(token.span.start, close), None);
		}
	}
	ranges
}

fn block_close(text: &str, from: usize) -> Option<usize> {
	let bytes = text.as_bytes();
	let mut i = from;
	let mut depth = 0usize;
	while i < bytes.len() {
		match bytes[i] {
			b'/' if bytes.get(i + 1) == Some(&b'/') => {
				while i < bytes.len() && bytes[i] != b'\n' {
					i += 1;
				}
			}
			b'/' if bytes.get(i + 1) == Some(&b'*') => {
				i += 2;
				while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
					i += 1;
				}
				i += 1;
			}
			b'[' => depth += 1,
			b']' => {
				depth = depth.checked_sub(1)?;
				if depth == 0 {
					return Some(i + 1);
				}
			}
			_ => {}
		}
		i += 1;
	}
	None
}

fn push_fold(
	out: &mut Vec<FoldingRange>,
	doc: &Document,
	span: Span,
	kind: Option<FoldingRangeKind>,
) {
	let text = &doc.text[span.start.min(doc.text.len())..span.end.min(doc.text.len())];
	let trimmed = span.start + text.trim_end().len();
	let start = doc.line.position(span.start);
	let end = doc.line.position(trimmed);
	if end.line <= start.line {
		return;
	}
	out.push(FoldingRange {
		start_line: start.line,
		end_line: end.line,
		kind,
		..Default::default()
	});
}

pub(crate) fn document_symbols(doc: &Document) -> Vec<DocumentSymbol> {
	let Ok(model) = &doc.model else {
		return Vec::new();
	};
	let mut symbols = Vec::new();
	for block in &model.blocks {
		match block {
			Block::Principal(p) => {
				let children: Vec<DocumentSymbol> = p
					.expressions
					.iter()
					.map(|e| {
						let names: Vec<String> =
							e.constants.iter().map(|c| c.name.to_string()).collect();
						symbol(
							names.join(", "),
							expression_detail(e),
							match e.kind {
								Declaration::Assignment => SymbolKind::VARIABLE,
								_ => SymbolKind::CONSTANT,
							},
							doc.line.range(e.span),
							Vec::new(),
						)
					})
					.collect();
				symbols.push(symbol(
					p.name.clone(),
					String::new(),
					SymbolKind::NAMESPACE,
					doc.line.range(p.span),
					children,
				));
			}
			Block::Message(m) => symbols.push(symbol(
				format!("{} \u{2192} {}", m.sender_name, m.recipient_name),
				crate::pretty::pretty_constants(&m.constants),
				SymbolKind::EVENT,
				doc.line.range(m.span),
				Vec::new(),
			)),
			Block::Phase(p) => symbols.push(symbol(
				format!("phase[{}]", p.number),
				String::new(),
				SymbolKind::NUMBER,
				doc.line.range(p.span),
				Vec::new(),
			)),
		}
	}
	let queries: Vec<DocumentSymbol> = model
		.queries
		.iter()
		.map(|q| {
			symbol(
				crate::pretty::query_display(q),
				String::new(),
				SymbolKind::BOOLEAN,
				doc.line.range(q.span),
				Vec::new(),
			)
		})
		.collect();
	if let Some(first) = model.queries.first() {
		let last = model.queries.last().unwrap_or(first);
		symbols.push(symbol(
			"queries".to_string(),
			String::new(),
			SymbolKind::INTERFACE,
			doc.line.range(Span::new(first.span.start, last.span.end)),
			queries,
		));
	}
	symbols
}

fn expression_detail(e: &crate::types::Expression) -> String {
	match (&e.kind, &e.assigned) {
		(Declaration::Assignment, Some(v)) => v.to_string(),
		(Declaration::Knows, _) => match &e.qualifier {
			Some(q) => format!("knows {q}"),
			None => "knows".to_string(),
		},
		(Declaration::Generates, _) => "generates".to_string(),
		(Declaration::Leaks, _) => "leaks".to_string(),
		_ => String::new(),
	}
}

#[allow(deprecated)]
fn symbol(
	name: String,
	detail: String,
	kind: SymbolKind,
	range: Range,
	children: Vec<DocumentSymbol>,
) -> DocumentSymbol {
	DocumentSymbol {
		name,
		detail: (!detail.is_empty()).then_some(detail),
		kind,
		tags: None,
		deprecated: None,
		range,
		selection_range: range,
		children: (!children.is_empty()).then_some(children),
	}
}

fn item(label: &str, kind: CompletionItemKind, entry: Option<&docs::Entry>) -> CompletionItem {
	CompletionItem {
		label: label.to_string(),
		kind: Some(kind),
		detail: entry.map(|e| e.eg.to_string()),
		documentation: entry.map(|e| markdown(e.help.to_string())),
		..Default::default()
	}
}

pub(crate) fn completions(doc: &Document, position: Position) -> Vec<CompletionItem> {
	let offset = doc.line.offset(position);
	let before = &doc.text[..offset.min(doc.text.len())];

	if in_capability_brackets(doc, offset) {
		return docs::CAPABILITIES
			.iter()
			.filter(|e| e.name != "from")
			.map(|e| item(e.name, CompletionItemKind::ENUM_MEMBER, Some(e)))
			.collect();
	}

	let trimmed = before.trim_end_matches(|c: char| c.is_alphanumeric() || c == '_');
	let head = trimmed.trim_end();
	let after_knows = head
		.len()
		.checked_sub("knows".len())
		.filter(|&at| head.is_char_boundary(at))
		.is_some_and(|at| {
			head[at..].eq_ignore_ascii_case("knows")
				&& head[..at]
					.chars()
					.next_back()
					.is_none_or(|c| !c.is_alphanumeric() && c != '_')
		});
	if after_knows {
		return ["public", "private"]
			.iter()
			.map(|q| item(q, CompletionItemKind::KEYWORD, docs::keyword(q)))
			.collect();
	}

	if in_queries_block(doc, offset) {
		// Once the line names its query kind, what follows are the constants
		// the query is about and, for `authentication?`, the principals.
		let line = &before[before.rfind('\n').map_or(0, |i| i + 1)..];
		if line.contains('?') || line.trim_start().starts_with("precondition") {
			return names(doc, true);
		}
		return docs::QUERIES
			.iter()
			.filter(|e| e.name != "precondition")
			.map(|e| {
				let mut c = item(e.name, CompletionItemKind::EVENT, Some(e));
				c.insert_text = Some(format!("{}? ", e.name));
				c
			})
			.collect();
	}

	let mut out: Vec<CompletionItem> = crate::primitive::primitive_names()
		.into_iter()
		.map(|name| item(name, CompletionItemKind::FUNCTION, docs::primitive(name)))
		.collect();
	for e in docs::KEYWORDS {
		out.push(item(e.name, CompletionItemKind::KEYWORD, Some(e)));
	}
	out.extend(names(doc, false));
	out
}

fn names(doc: &Document, principals: bool) -> Vec<CompletionItem> {
	let mut out = Vec::new();
	let mut seen: Vec<&str> = Vec::new();
	for token in doc.tokens.tokens() {
		let kind = match token.kind {
			TokenKind::ConstantName if !is_nil(&token.text) => CompletionItemKind::VARIABLE,
			TokenKind::PrincipalName if principals => CompletionItemKind::CLASS,
			_ => continue,
		};
		if seen.contains(&&*token.text) {
			continue;
		}
		seen.push(&token.text);
		out.push(item(&token.text, kind, None));
	}
	out
}

fn in_capability_brackets(doc: &Document, offset: usize) -> bool {
	let before = &doc.text[..offset.min(doc.text.len())];
	let Some(open) = before.rfind('[') else {
		return false;
	};
	if before[open..].contains(']') || before[open..].contains('\n') {
		return false;
	}
	let head = before[..open].trim_end();
	let name: String = head
		.chars()
		.rev()
		.take_while(|c| c.is_alphanumeric() || *c == '_')
		.collect();
	let name: String = name.chars().rev().collect();
	!name.is_empty() && crate::primitive::primitive_get_enum(&name.to_uppercase()).is_ok()
}

fn in_queries_block(doc: &Document, offset: usize) -> bool {
	doc.tokens.tokens().iter().any(|t| {
		t.kind == TokenKind::Keyword
			&& t.text.eq_ignore_ascii_case("queries")
			&& t.span.start < offset
	})
}

pub(crate) fn signature_help(doc: &Document, position: Position) -> Option<SignatureHelp> {
	let offset = doc.line.offset(position);
	let before = &doc.text[..offset.min(doc.text.len())];
	let (name, active) = enclosing_call(before)?;
	let entry = docs::primitive(&name)?;
	let id = crate::primitive::primitive_get_enum(&name.to_uppercase()).ok()?;
	let def = crate::primitive::primitive_def(id).ok()?;
	let args = def.arg_names();
	let widest = *def.arity().last()? as usize;
	let shown: Vec<String> = (0..widest)
		.map(|i| {
			args.get(i)
				.map(|s| s.to_string())
				.unwrap_or_else(|| format!("value{}", i + 1))
		})
		.collect();
	let label = format!("{}({})", name.to_uppercase(), shown.join(", "));
	Some(SignatureHelp {
		signatures: vec![SignatureInformation {
			label,
			documentation: Some(markdown(entry.help.to_string())),
			parameters: Some(
				shown
					.iter()
					.map(|p| ParameterInformation {
						label: ParameterLabel::Simple(p.clone()),
						documentation: None,
					})
					.collect(),
			),
			active_parameter: Some(active as u32),
		}],
		active_signature: Some(0),
		active_parameter: Some(active as u32),
	})
}

fn enclosing_call(before: &str) -> Option<(String, usize)> {
	let bytes = before.as_bytes();
	let mut depth = 0i32;
	let mut commas = 0usize;
	let mut i = bytes.len();
	while i > 0 {
		i -= 1;
		match bytes[i] {
			b')' => depth += 1,
			b'(' => {
				if depth == 0 {
					return Some((callee(&before[..i])?, commas));
				}
				depth -= 1;
			}
			b',' if depth == 0 => commas += 1,
			_ => {}
		}
	}
	None
}

fn callee(head: &str) -> Option<String> {
	let mut head = head.trim_end();
	if let Some(inner) = head.strip_suffix(']') {
		head = inner[..inner.rfind('[')?].trim_end();
	}
	let name: String = head
		.chars()
		.rev()
		.take_while(|c| c.is_alphanumeric() || *c == '_')
		.collect();
	(!name.is_empty()).then(|| name.chars().rev().collect())
}

pub(crate) fn inlay_hints(doc: &Document, range: Range) -> Vec<InlayHint> {
	let from = doc.line.offset(range.start);
	let to = doc.line.offset(range.end);
	let mut hints = Vec::new();
	for token in doc.tokens.tokens() {
		if token.kind != TokenKind::PrimitiveName
			|| token.span.start < from
			|| token.span.start > to
		{
			continue;
		}
		let Ok(id) = crate::primitive::primitive_get_enum(&token.text.to_uppercase()) else {
			continue;
		};
		let Ok(def) = crate::primitive::primitive_def(id) else {
			continue;
		};
		for (i, at) in argument_offsets(&doc.text, token.span.end)
			.into_iter()
			.enumerate()
		{
			let Some(name) = def.arg_names().get(i) else {
				break;
			};
			if is_placeholder_name(name) {
				continue;
			}
			let written: String = doc.text[at..]
				.chars()
				.take_while(|c| c.is_alphanumeric() || *c == '_')
				.collect();
			if written.eq_ignore_ascii_case(name) {
				continue;
			}
			hints.push(InlayHint {
				position: doc.line.position(at),
				label: InlayHintLabel::String(format!("{name}: ")),
				kind: Some(lsp_types::InlayHintKind::PARAMETER),
				text_edits: None,
				tooltip: None,
				padding_left: None,
				padding_right: None,
				data: None,
			});
		}
	}
	hints
}

fn is_placeholder_name(name: &str) -> bool {
	name.strip_prefix("value")
		.is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

fn argument_offsets(text: &str, after_name: usize) -> Vec<usize> {
	let bytes = text.as_bytes();
	let mut i = after_name;
	while i < bytes.len() && (bytes[i] as char).is_whitespace() {
		i += 1;
	}
	if i < bytes.len() && bytes[i] == b'[' {
		while i < bytes.len() && bytes[i] != b']' {
			i += 1;
		}
		i += 1;
		while i < bytes.len() && (bytes[i] as char).is_whitespace() {
			i += 1;
		}
	}
	if i >= bytes.len() || bytes[i] != b'(' {
		return Vec::new();
	}
	i += 1;
	let mut starts = Vec::new();
	let mut depth = 0i32;
	let mut expecting = true;
	while i < bytes.len() {
		match bytes[i] {
			b'(' => depth += 1,
			b')' => {
				if depth == 0 {
					break;
				}
				depth -= 1;
			}
			b',' if depth == 0 => expecting = true,
			c if (c as char).is_whitespace() => {}
			_ => {
				if expecting {
					starts.push(i);
					expecting = false;
				}
			}
		}
		i += 1;
	}
	starts
}

pub(crate) fn prepare_rename(doc: &Document, position: Position) -> Option<Range> {
	let token = token_at(doc, position)?;
	renameable(token).then(|| doc.line.range(token.span))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::lsp::state::Documents;
	use lsp_types::PositionEncodingKind;
	use std::str::FromStr;

	const SRC: &str = "attacker[passive]\n\
principal Alice[\n\
\tknows private lg_a\n\
\tlg_ga = PUBKEY(lg_a)\n\
]\n\
Alice -> Bob: lg_ga\n\
principal Bob[\n\
\t_ = HASH(lg_ga)\n\
]\n\
queries[\n\
\tconfidentiality? lg_a\n\
]\n";

	fn doc() -> Documents {
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		docs.open(
			"file:///l.vp".to_string(),
			"l.vp".to_string(),
			1,
			SRC.to_string(),
		);
		docs
	}

	fn at(needle: &str) -> Position {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		d.line.position(SRC.find(needle).expect("in the source"))
	}

	fn uri() -> Uri {
		Uri::from_str("file:///l.vp").expect("a uri")
	}

	#[test]
	fn hovering_a_primitive_shows_its_signature_and_arity() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		let h = hover(d, at("PUBKEY")).expect("a hover");
		let lsp_types::HoverContents::Markup(m) = h.contents else {
			panic!("expected markup");
		};
		assert!(m.value.contains("PUBKEY(private_key)"), "{}", m.value);
		assert!(m.value.contains("1 argument, 1 output"), "{}", m.value);
		assert!(m.value.contains("accepts [weak]"), "{}", m.value);
	}

	#[test]
	fn hovering_a_constant_shows_what_the_trace_records() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		let h = hover(d, at("lg_ga = PUBKEY")).expect("a hover");
		let lsp_types::HoverContents::Markup(m) = h.contents else {
			panic!("expected markup");
		};
		assert!(m.value.contains("PUBKEY(lg_a)"), "{}", m.value);
		assert!(m.value.contains("Alice"), "{}", m.value);
	}

	#[test]
	fn hovering_a_query_kind_shows_what_it_checks() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		let h = hover(d, at("confidentiality?")).expect("a hover");
		let lsp_types::HoverContents::Markup(m) = h.contents else {
			panic!("expected markup");
		};
		assert!(m.value.contains("confidentiality? a"), "{}", m.value);
		assert!(m.value.contains("obtained by the attacker"), "{}", m.value);
	}

	#[test]
	fn definition_jumps_to_the_assignment() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		let loc = definition(d, at("HASH(lg_ga)"), &uri());
		assert!(loc.is_none(), "HASH is a primitive, not a constant");
		let loc = definition(d, at("lg_ga)"), &uri()).expect("a definition");
		let want = d
			.line
			.position(SRC.find("lg_ga = PUBKEY").expect("in the source"));
		assert_eq!(loc.range.start, want);
	}

	#[test]
	fn principal_definition_jumps_past_an_earlier_reference_to_its_block() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		let loc = definition(d, at("Bob: lg_ga"), &uri()).expect("a definition");
		let want = d.line.position(SRC.find("Bob[\n").expect("in the source"));
		assert_eq!(loc.range.start, want);
	}

	#[test]
	fn references_finds_all_three_occurrences() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		assert_eq!(references(d, at("lg_ga = PUBKEY"), &uri()).len(), 3);
	}

	#[test]
	fn the_declaration_highlights_as_a_write() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		let hs = highlights(d, at("lg_ga = PUBKEY"));
		assert_eq!(hs.len(), 3);
		assert_eq!(hs[0].kind, Some(DocumentHighlightKind::WRITE));
		assert_eq!(hs[1].kind, Some(DocumentHighlightKind::READ));
	}

	#[test]
	fn rename_rewrites_every_occurrence() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		let edits = rename(d, at("lg_ga = PUBKEY"), "renamed").expect("edits");
		assert_eq!(edits.len(), 3);
		assert!(edits.iter().all(|e| e.new_text == "renamed"));
	}

	#[test]
	fn rename_refuses_a_primitive() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		assert!(rename(d, at("PUBKEY"), "nope").is_none());
		assert!(prepare_rename(d, at("PUBKEY")).is_none());
	}

	#[test]
	fn rename_refuses_names_that_would_break_or_merge_the_model() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		let constant = at("lg_ga = PUBKEY");
		for name in [
			"",
			"two words",
			"é",
			"_",
			"HASH",
			"nil",
			"attacker_value",
			"unnamed_value",
			"lg_a",
		] {
			assert!(rename(d, constant, name).is_none(), "accepted {name:?}");
		}
		let principal = at("Alice[");
		for name in [
			"",
			"two words",
			"é",
			"Attacker",
			"Bob",
			"phase",
			"principal",
			"queries",
			"scenarios",
			"Phase",
			"Principal",
			"Queries",
			"Scenarios",
			"ATTACKER",
		] {
			assert!(rename(d, principal, name).is_none(), "accepted {name:?}");
		}
	}

	#[test]
	fn a_principal_and_constant_with_the_same_spelling_are_distinct_symbols() {
		let source = "attacker[passive]\nprincipal Alice[\n\tknows private alice\n]\nAlice -> Bob: alice\nprincipal Bob[\n\t_ = HASH(alice)\n]\nqueries[\n\tconfidentiality? alice\n]\n";
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		docs.open(
			"file:///overlap.vp".to_string(),
			"overlap.vp".to_string(),
			1,
			source.to_string(),
		);
		let d = docs.get("file:///overlap.vp").expect("open");
		let principal_at = d
			.line
			.position(source.find("Alice").expect("principal is present"));
		let constant_offset = source.find("alice").expect("constant is present");
		let constant_at = d.line.position(constant_offset);
		let principal_edits = rename(d, principal_at, "Carol").expect("principal edits");
		let constant_edits = rename(d, constant_at, "value").expect("constant edits");
		assert_eq!(principal_edits.len(), 2);
		assert_eq!(constant_edits.len(), 4);
		let location = definition(d, constant_at, &uri()).expect("constant definition");
		assert_eq!(location.range.start, d.line.position(constant_offset));
	}

	#[test]
	fn the_builtin_nil_value_cannot_be_renamed() {
		let source = "attacker[passive]\nprincipal Alice[\n\t_ = HASH(nil)\n]\nqueries[\n\tconfidentiality? nil\n]\n";
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		docs.open(
			"file:///nil.vp".to_string(),
			"nil.vp".to_string(),
			1,
			source.to_string(),
		);
		let d = docs.get("file:///nil.vp").expect("open");
		let position = d.line.position(source.find("nil").expect("nil is present"));
		assert!(prepare_rename(d, position).is_none());
		assert!(rename(d, position, "replacement").is_none());
	}

	#[test]
	fn folding_covers_each_principal_block() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		let folds = folding_ranges(d);
		assert!(folds.len() >= 2, "{folds:?}");
		assert!(
			folds.iter().any(|f| f.start_line == 1 && f.end_line == 4),
			"{folds:?}"
		);
	}

	#[test]
	fn document_symbols_nest_expressions_under_principals() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		let symbols = document_symbols(d);
		let alice = symbols.iter().find(|s| s.name == "Alice").expect("Alice");
		assert_eq!(alice.kind, SymbolKind::NAMESPACE);
		assert_eq!(alice.children.as_ref().expect("children").len(), 2);
		assert!(symbols.iter().any(|s| s.name == "queries"));
	}

	#[test]
	fn completion_offers_query_kinds_inside_the_queries_block() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		let items = completions(d, at("confidentiality? lg_a"));
		assert!(items.iter().any(|i| i.label == "equivalence"), "{items:?}");
		assert!(!items.iter().any(|i| i.label == "PUBKEY"), "{items:?}");
	}

	#[test]
	fn completion_offers_constants_and_principals_after_a_query_kind() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		let items = completions(d, at("lg_a\n]"));
		let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
		assert!(labels.contains(&"lg_a"), "{labels:?}");
		assert!(labels.contains(&"lg_ga"), "{labels:?}");
		assert!(labels.contains(&"Bob"), "{labels:?}");
		assert!(!labels.contains(&"equivalence"), "{labels:?}");
	}

	#[test]
	fn completion_offers_qualifiers_after_knows_in_any_case() {
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		let src = "attacker[passive]\nprincipal Alice[\n\tKNOWS ";
		docs.open(
			"file:///ku.vp".to_string(),
			"ku.vp".to_string(),
			1,
			src.to_string(),
		);
		let d = docs.get("file:///ku.vp").expect("open");
		let labels: Vec<String> = completions(d, d.line.position(src.len()))
			.into_iter()
			.map(|i| i.label)
			.collect();
		assert_eq!(labels, vec!["public", "private"]);
	}

	#[test]
	fn nil_is_documented_as_a_keyword_and_offered_once() {
		let source = "attacker[passive]\nprincipal Alice[\n\tknows private nl_k\n\t_ = AEAD_ENC(nl_k, nl_k, nl_k, nil)\n]\nqueries[\n\tconfidentiality? nl_k\n]\n";
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		docs.open(
			"file:///nl.vp".to_string(),
			"nl.vp".to_string(),
			1,
			source.to_string(),
		);
		let d = docs.get("file:///nl.vp").expect("open");
		let h = hover(d, d.line.position(source.find("nil)").expect("nil"))).expect("a hover");
		let lsp_types::HoverContents::Markup(m) = h.contents else {
			panic!("expected markup");
		};
		assert!(m.value.contains("The empty value"), "{}", m.value);
		let offered = completions(d, d.line.position(source.find("knows").expect("knows")))
			.into_iter()
			.filter(|i| i.label == "nil")
			.count();
		assert_eq!(offered, 1);
	}

	#[test]
	fn hovering_a_precondition_explains_the_option_and_names_its_principals() {
		let source = "attacker[passive]\nprincipal Alice[\n\tknows private pr_m\n\tpr_h = HASH(pr_m)\n]\nAlice -> Bob: pr_h\nprincipal Bob[\n\t_ = HASH(pr_h)\n]\nqueries[\n\tconfidentiality? pr_m[\n\t\tprecondition[Alice -> Bob: pr_h]\n\t]\n]\n";
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		docs.open(
			"file:///pr.vp".to_string(),
			"pr.vp".to_string(),
			1,
			source.to_string(),
		);
		let d = docs.get("file:///pr.vp").expect("open");
		let option = source.find("precondition[").expect("the option");
		let h = hover(d, d.line.position(option)).expect("a hover");
		let lsp_types::HoverContents::Markup(m) = h.contents else {
			panic!("expected markup");
		};
		assert!(m.value.contains("attached to any query"), "{}", m.value);
		// The principals inside the option are references like any other, so
		// a rename reaches them.
		let bob = source[option..].find("Bob").expect("the recipient") + option;
		let edits = rename(d, d.line.position(bob), "Carol").expect("edits");
		assert_eq!(edits.len(), 3, "{edits:?}");
	}

	#[test]
	fn hovering_phase_inside_a_capability_bracket_explains_the_onset() {
		let source = "attacker[passive]\nprincipal Alice[\n\tknows private cp_a\n\tcp_ga = PUBKEY[weak from phase 1](cp_a)\n]\nqueries[\n\tconfidentiality? cp_a\n]\n";
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		docs.open(
			"file:///cp.vp".to_string(),
			"cp.vp".to_string(),
			1,
			source.to_string(),
		);
		let d = docs.get("file:///cp.vp").expect("open");
		let at = d.line.position(source.find("phase 1").expect("the onset"));
		let h = hover(d, at).expect("a hover");
		let lsp_types::HoverContents::Markup(m) = h.contents else {
			panic!("expected markup");
		};
		let from = docs::capability("from").expect("documented");
		assert!(m.value.contains(from.help), "{}", m.value);
	}

	#[test]
	fn signature_help_looks_past_a_capability_bracket_and_a_line_break() {
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		let src = "attacker[passive]\nprincipal Alice[\n\tknows private sb_k\n\tsb_e = AEAD_ENC[forgeable from phase 1](sb_k,\n\t\t";
		docs.open(
			"file:///sb.vp".to_string(),
			"sb.vp".to_string(),
			1,
			src.to_string(),
		);
		let d = docs.get("file:///sb.vp").expect("open");
		let help = signature_help(d, d.line.position(src.len())).expect("help");
		assert_eq!(
			help.signatures[0].label,
			"AEAD_ENC(key, nonce, plaintext, ad)"
		);
		assert_eq!(help.active_parameter, Some(1));
	}

	#[test]
	fn folding_covers_scenarios_and_stops_at_the_closing_bracket() {
		let src = "attacker[active]\nprincipal Alice[\n\tknows public fs_gpeer\n\tknows private fs_a\n\tfs_e = ENC(fs_gpeer, fs_a)\n]\nscenarios[\n\tAlice[fs_gpeer = fs_gb]\n]\nqueries[\n\tconfidentiality? fs_a // see [1]\n]\n// tail\n";
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		docs.open(
			"file:///fs.vp".to_string(),
			"fs.vp".to_string(),
			1,
			src.to_string(),
		);
		let d = docs.get("file:///fs.vp").expect("open");
		let folds = folding_ranges(d);
		assert!(
			folds.iter().any(|f| f.start_line == 6 && f.end_line == 8),
			"no scenarios fold: {folds:?}"
		);
		assert!(
			folds.iter().any(|f| f.start_line == 9 && f.end_line == 11),
			"the queries fold must end at its bracket: {folds:?}"
		);
	}

	#[test]
	fn a_block_comment_spanning_lines_gets_a_token_per_line() {
		let src = "attacker[passive]\n/* one\n   two */\nprincipal Alice[\n\tknows private bc_a\n]\nqueries[\n\tconfidentiality? bc_a\n]\n";
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		docs.open(
			"file:///bc.vp".to_string(),
			"bc.vp".to_string(),
			1,
			src.to_string(),
		);
		let d = docs.get("file:///bc.vp").expect("open");
		let comment = TOKEN_TYPES
			.iter()
			.position(|t| *t == "comment")
			.expect("comment") as u32;
		let data = semantic_tokens(d);
		let comments = data.chunks(5).filter(|c| c[3] == comment).count();
		assert_eq!(comments, 2, "{data:?}");
	}

	#[test]
	fn inlay_hints_skip_placeholder_argument_names() {
		let src = "attacker[passive]\nprincipal Alice[\n\tknows private ih_a\n\t_ = HASH(ih_a, ih_a)\n]\nqueries[\n\tconfidentiality? ih_a\n]\n";
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		docs.open(
			"file:///ih.vp".to_string(),
			"ih.vp".to_string(),
			1,
			src.to_string(),
		);
		let d = docs.get("file:///ih.vp").expect("open");
		let whole = Range::new(Position::new(0, 0), d.line.end());
		assert!(inlay_hints(d, whole).is_empty());
	}

	#[test]
	fn completion_offers_qualifiers_after_knows() {
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		let src = "attacker[passive]\nprincipal Alice[\n\tknows ";
		docs.open(
			"file:///k.vp".to_string(),
			"k.vp".to_string(),
			1,
			src.to_string(),
		);
		let d = docs.get("file:///k.vp").expect("open");
		let items = completions(d, d.line.position(src.len()));
		let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
		assert_eq!(labels, vec!["public", "private"]);
	}

	#[test]
	fn completion_offers_capabilities_inside_primitive_brackets() {
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		let src = "attacker[passive]\nprincipal Alice[\n\tknows private c_m\n\tc_h = HASH[";
		docs.open(
			"file:///c.vp".to_string(),
			"c.vp".to_string(),
			1,
			src.to_string(),
		);
		let d = docs.get("file:///c.vp").expect("open");
		let items = completions(d, d.line.position(src.len()));
		let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
		assert_eq!(labels, vec!["weak", "forgeable", "malleable"]);
	}

	#[test]
	fn signature_help_names_the_active_argument() {
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		let src =
			"attacker[passive]\nprincipal Alice[\n\tknows private s_k\n\ts_e = AEAD_ENC(s_k, ";
		docs.open(
			"file:///s.vp".to_string(),
			"s.vp".to_string(),
			1,
			src.to_string(),
		);
		let d = docs.get("file:///s.vp").expect("open");
		let help = signature_help(d, d.line.position(src.len())).expect("help");
		assert_eq!(
			help.signatures[0].label,
			"AEAD_ENC(key, nonce, plaintext, ad)"
		);
		assert_eq!(help.active_parameter, Some(1));
	}

	#[test]
	fn semantic_tokens_are_five_tuples_in_source_order() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		let data = semantic_tokens(d);
		assert!(!data.is_empty());
		assert_eq!(data.len() % 5, 0);
		for chunk in data.chunks(5) {
			assert!((chunk[3] as usize) < TOKEN_TYPES.len());
		}
	}

	#[test]
	fn a_primitive_is_tagged_as_a_default_library_function() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		let data = semantic_tokens(d);
		let function = TOKEN_TYPES
			.iter()
			.position(|t| *t == "function")
			.expect("function") as u32;
		assert!(
			data.chunks(5).any(|c| c[3] == function && c[4] & 0b10 != 0),
			"no primitive carries defaultLibrary"
		);
	}

	#[test]
	fn inlay_hints_name_primitive_arguments() {
		let docs = doc();
		let d = docs.get("file:///l.vp").expect("open");
		let whole = Range::new(Position::new(0, 0), d.line.end());
		let hints = inlay_hints(d, whole);
		assert!(
			hints
				.iter()
				.any(|h| matches!(&h.label, InlayHintLabel::String(s) if s == "private_key: ")),
			"{hints:?}"
		);
	}
}
