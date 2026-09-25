/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use lsp_types::{PositionEncodingKind, Uri};

use crate::lsp::line::LineIndex;
use crate::tokens::TokenIndex;
use crate::types::{Model, ProtocolTrace, VerifpalError};

pub(crate) struct Document {
	pub uri: Uri,
	#[cfg_attr(not(feature = "lsp"), allow(dead_code))]
	pub version: i32,
	pub line: LineIndex,
	pub model: Option<Model>,
	pub tokens: TokenIndex,
	pub trace: Option<ProtocolTrace>,
	pub error: Option<VerifpalError>,
}

impl Document {
	pub(crate) fn new(
		uri: Uri,
		version: i32,
		text: String,
		encoding: &PositionEncodingKind,
	) -> Document {
		let line = LineIndex::new(&text, encoding);
		let (parsed, tokens) = crate::parser::parse_string_indexed(&file_name(&uri), &text);
		let (model, trace, error) = match parsed {
			Err(e) => (None, None, Some(e)),
			Ok(m) => {
				let (trace, error) = match crate::sanity::sanity(&m) {
					Ok(t) => (
						Some(t),
						crate::verify::expand(&m, crate::sessions::DEFAULT_SESSIONS)
							.and_then(|e| crate::sanity::sanity(&e.model))
							.err(),
					),
					Err(e) => (None, Some(e)),
				};
				let error = error.map(|e| e.located(&m.file_name, &m.source));
				(Some(m), trace, error)
			}
		};
		Document {
			uri,
			version,
			line,
			model,
			tokens,
			trace,
			error,
		}
	}

	pub(crate) fn text(&self) -> &str {
		self.line.text()
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

	fn document(name: &str, version: i32, text: &str) -> Document {
		Document::new(
			uri(&format!("file:///{name}")),
			version,
			text.to_string(),
			&PositionEncodingKind::UTF8,
		)
	}

	#[test]
	fn a_file_name_comes_from_the_last_path_segment() {
		assert_eq!(file_name(&uri("file:///home/nadim/simple.vp")), "simple.vp");
		assert_eq!(file_name(&uri("file:///c%3A/tmp/a%20b.vp")), "a b.vp");
		assert_eq!(file_name(&uri("untitled:Untitled-1")), "model.vp");
	}

	#[test]
	fn an_opened_document_is_parsed_and_indexed() {
		let doc = document("m.vp", 1, GOOD);
		assert_eq!(doc.version, 1);
		assert!(doc.model.is_some());
		assert!(doc.error.is_none());
		assert!(doc.trace.is_some(), "a valid model gets a trace");
		assert!(!doc.tokens.tokens().is_empty());
		assert_eq!(doc.model.expect("parsed").file_name, "m.vp");
	}

	#[test]
	fn a_document_that_does_not_parse_keeps_its_tokens() {
		let doc = document("m.vp", 2, "attacker[passive]\n");
		assert_eq!(doc.version, 2);
		assert!(doc.model.is_none(), "a truncated model does not parse");
		assert!(doc.error.is_some(), "and the parse error is kept");
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
		let doc = document("b.vp", 1, broken);
		assert!(doc.model.is_some(), "it parses");
		assert!(doc.trace.is_none(), "but it does not pass sanity");
		assert!(doc.error.is_some(), "and the sanity error is kept");
	}

	#[test]
	fn a_scenario_binding_the_principal_never_receives_fails_sanity_live() {
		let broken = "attacker[active]\n\
			principal Bob[\n\
			knows private sb_b\n\
			sb_gb = PUBKEY(sb_b)\n\
			]\n\
			principal Alice[\n\
			knows public sb_gpeer\n\
			generates sb_m\n\
			sb_e = PKE_ENC(sb_gpeer, sb_m)\n\
			]\n\
			Alice -> Bob: sb_e\n\
			principal Bob[\n\
			_ = PKE_DEC(sb_b, sb_e)\n\
			]\n\
			scenarios[\n\
			Alice[sb_gpeer = sb_gb]\n\
			]\n\
			queries[\n\
			confidentiality? sb_m\n\
			]\n";
		let doc = document("sb.vp", 1, broken);
		assert!(doc.model.is_some(), "it parses");
		assert!(
			doc.error.is_some(),
			"the analysis would reject this binding, so the live check must too"
		);
		let fine = broken.replace(
			"principal Alice[\n",
			"Bob -> Alice: [sb_gb]\nprincipal Alice[\n",
		);
		let doc = document("sb.vp", 2, &fine);
		assert!(doc.error.is_none(), "{:?}", doc.error);
	}

	#[test]
	fn a_model_the_default_sessions_would_overflow_fails_sanity_live() {
		let model = |count: usize| {
			let mut src = String::from("attacker[passive]\n");
			for i in 0..count {
				src.push_str(&format!("principal Pc{i}[\n\tknows private pc_{i}\n]\n"));
			}
			src.push_str("queries[\n\tconfidentiality? pc_0\n]\n");
			src
		};
		let doc = document("pc.vp", 1, &model(65));
		assert!(
			doc.error.is_some(),
			"two sessions of 65 principals exceed the cap `verify` enforces, so the live \
			 check must report it too"
		);
		let doc = document("pc.vp", 2, &model(64));
		assert!(doc.error.is_none(), "{:?}", doc.error);
	}
}
