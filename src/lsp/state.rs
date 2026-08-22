/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;

use lsp_types::{PositionEncodingKind, Uri};

use crate::lsp::line::LineIndex;
use crate::tokens::TokenIndex;
use crate::types::{Model, ProtocolTrace, VResult, VerifpalError};

pub(crate) struct Document {
	pub text: String,
	pub version: i32,
	pub name: String,
	pub line: LineIndex,
	pub model: VResult<Model>,
	pub tokens: TokenIndex,
	pub trace: Option<ProtocolTrace>,
	pub sanity: Option<VerifpalError>,
}

pub(crate) struct Documents {
	encoding: PositionEncodingKind,
	open: HashMap<String, Document>,
}

impl Documents {
	pub(crate) fn new(encoding: PositionEncodingKind) -> Documents {
		Documents {
			encoding,
			open: HashMap::new(),
		}
	}

	pub(crate) fn open(&mut self, uri: String, name: String, version: i32, text: String) {
		let doc = self.build(name, version, text);
		self.open.insert(uri, doc);
	}

	pub(crate) fn change(&mut self, uri: &str, version: i32, text: String) {
		let Some(name) = self.open.get(uri).map(|d| d.name.clone()) else {
			return;
		};
		let doc = self.build(name, version, text);
		self.open.insert(uri.to_string(), doc);
	}

	pub(crate) fn close(&mut self, uri: &str) {
		self.open.remove(uri);
	}

	pub(crate) fn get(&self, uri: &str) -> Option<&Document> {
		self.open.get(uri)
	}

	fn build(&self, name: String, version: i32, text: String) -> Document {
		let line = LineIndex::new(&text, &self.encoding);
		let (model, tokens) = crate::parser::parse_string_indexed(&name, &text);
		let mut trace = None;
		let mut sanity = None;
		if let Ok(m) = &model {
			match crate::sanity::sanity(m) {
				Ok((t, _)) => trace = Some(t),
				Err(e) => sanity = Some(e.located(&m.file_name, &m.source)),
			}
		}
		Document {
			text,
			version,
			name,
			line,
			model,
			tokens,
			trace,
			sanity,
		}
	}
}

pub(crate) fn file_name(uri: &Uri) -> String {
	let path = uri.path().as_str();
	let last = path.rsplit('/').next().unwrap_or("");
	let decoded = percent_decode(last);
	if decoded.ends_with(".vp") {
		decoded
	} else {
		"model.vp".to_string()
	}
}

fn percent_decode(s: &str) -> String {
	let bytes = s.as_bytes();
	let mut out = Vec::with_capacity(bytes.len());
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] == b'%' && i + 2 < bytes.len() {
			let hi = (bytes[i + 1] as char).to_digit(16);
			let lo = (bytes[i + 2] as char).to_digit(16);
			if let (Some(hi), Some(lo)) = (hi, lo) {
				out.push((hi * 16 + lo) as u8);
				i += 3;
				continue;
			}
		}
		out.push(bytes[i]);
		i += 1;
	}
	String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;

	const GOOD: &str = "attacker[passive]\n\
		principal Alice[\n\
		knows private st_m\n\
		st_h = HASH(st_m)\n\
		]\n\
		Alice -> Bob: st_h\n\
		principal Bob[\n\
		_ = HASH(st_h)\n\
		]\n\
		queries[\n\
		confidentiality? st_m\n\
		]\n";

	fn uri(s: &str) -> Uri {
		Uri::from_str(s).expect("a uri")
	}

	#[test]
	fn a_file_name_comes_from_the_last_path_segment() {
		assert_eq!(file_name(&uri("file:///home/nadim/simple.vp")), "simple.vp");
		assert_eq!(file_name(&uri("file:///c%3A/tmp/a%20b.vp")), "a b.vp");
		assert_eq!(file_name(&uri("untitled:Untitled-1")), "model.vp");
	}

	#[test]
	fn an_opened_document_is_parsed_and_indexed() {
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		docs.open(
			"file:///m.vp".to_string(),
			"m.vp".to_string(),
			1,
			GOOD.to_string(),
		);
		let doc = docs.get("file:///m.vp").expect("the document is open");
		assert_eq!(doc.version, 1);
		assert!(doc.model.is_ok());
		assert!(doc.trace.is_some(), "a valid model gets a trace");
		assert!(!doc.tokens.tokens().is_empty());
	}

	#[test]
	fn a_changed_document_is_reparsed_at_the_new_version() {
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		docs.open(
			"file:///m.vp".to_string(),
			"m.vp".to_string(),
			1,
			GOOD.to_string(),
		);
		docs.change("file:///m.vp", 2, "attacker[passive]\n".to_string());
		let doc = docs.get("file:///m.vp").expect("still open");
		assert_eq!(doc.version, 2);
		assert!(doc.model.is_err(), "a truncated model does not parse");
		assert!(doc.trace.is_none(), "no trace without a model");
		assert!(
			!doc.tokens.tokens().is_empty(),
			"tokens survive a parse failure"
		);
	}

	#[test]
	fn a_model_that_parses_but_fails_sanity_has_tokens_and_no_trace() {
		let broken = "attacker[passive]\n\
			principal Alice[\n\
			knows private sf_m\n\
			]\n\
			queries[\n\
			confidentiality? sf_nothing\n\
			]\n";
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		docs.open(
			"file:///b.vp".to_string(),
			"b.vp".to_string(),
			1,
			broken.to_string(),
		);
		let doc = docs.get("file:///b.vp").expect("open");
		assert!(doc.model.is_ok(), "it parses");
		assert!(doc.trace.is_none(), "but it does not pass sanity");
		assert!(doc.sanity.is_some(), "and the sanity error is kept");
	}

	#[test]
	fn a_closed_document_is_forgotten() {
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		docs.open(
			"file:///m.vp".to_string(),
			"m.vp".to_string(),
			1,
			GOOD.to_string(),
		);
		docs.close("file:///m.vp");
		assert!(docs.get("file:///m.vp").is_none());
	}
}
