/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use lsp_types::{
	Diagnostic, DiagnosticRelatedInformation, DiagnosticSeverity, Location, NumberOrString, Uri,
};

use crate::lsp::line::LineIndex;
use crate::lsp::state::Document;
use crate::types::VerifpalError;

pub(crate) fn for_document(doc: &Document, uri: &Uri) -> Vec<Diagnostic> {
	if let Err(e) = &doc.model {
		return vec![of_error(e, &doc.text, &doc.line, uri)];
	}
	match &doc.sanity {
		Some(e) => vec![of_error(e, &doc.text, &doc.line, uri)],
		None => Vec::new(),
	}
}

pub(crate) fn of_error(e: &VerifpalError, source: &str, line: &LineIndex, uri: &Uri) -> Diagnostic {
	let range = match e.narrowed_span(source) {
		Some(span) if span.end > span.start => line.range(span),
		Some(span) => {
			let start = line.position(span.start);
			lsp_types::Range::new(start, lsp_types::Position::new(start.line, u32::MAX))
		}
		None => lsp_types::Range::new(lsp_types::Position::new(0, 0), line.end()),
	};
	let mut message = e.message.to_string();
	for note in e.notes() {
		message.push_str("\n\nnote: ");
		message.push_str(note);
	}
	for help in e.helps() {
		message.push_str("\n\nhelp: ");
		message.push_str(help);
	}
	let related: Vec<DiagnosticRelatedInformation> = e
		.labels()
		.iter()
		.map(|(span, text)| DiagnosticRelatedInformation {
			location: Location {
				uri: uri.clone(),
				range: line.range(*span),
			},
			message: text.to_string(),
		})
		.collect();
	Diagnostic {
		range,
		severity: Some(DiagnosticSeverity::ERROR),
		code: Some(NumberOrString::String(e.kind.label().to_string())),
		source: Some("verifpal".to_string()),
		message,
		related_information: (!related.is_empty()).then_some(related),
		..Default::default()
	}
}

pub(crate) fn of_verdicts(analysis: &crate::report::Analysis, line: &LineIndex) -> Vec<Diagnostic> {
	analysis
		.queries
		.iter()
		.map(|q| {
			let mut message = if q.conclusion.is_empty() {
				format!("{} — {}", q.query, q.envelope.summary)
			} else {
				q.conclusion.clone()
			};
			for step in &q.steps {
				message.push('\n');
				message.push_str(&step.text);
			}
			Diagnostic {
				range: line.range(crate::types::Span::new(q.range.start, q.range.end)),
				severity: Some(if q.resolved {
					DiagnosticSeverity::ERROR
				} else {
					DiagnosticSeverity::INFORMATION
				}),
				code: Some(NumberOrString::String(q.kind.clone())),
				source: Some("verifpal".to_string()),
				message,
				..Default::default()
			}
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::lsp::state::Documents;
	use lsp_types::PositionEncodingKind;
	use std::str::FromStr;

	fn uri() -> Uri {
		Uri::from_str("file:///d.vp").expect("a uri")
	}

	fn diagnose(src: &str) -> Vec<Diagnostic> {
		let mut docs = Documents::new(PositionEncodingKind::UTF8);
		docs.open(
			"file:///d.vp".to_string(),
			"d.vp".to_string(),
			1,
			src.to_string(),
		);
		let doc = docs.get("file:///d.vp").expect("open");
		for_document(doc, &uri())
	}

	#[test]
	fn a_valid_model_reports_nothing() {
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private dg_m\n\
			dg_h = HASH(dg_m)\n\
			]\n\
			Alice -> Bob: dg_h\n\
			principal Bob[\n\
			_ = HASH(dg_h)\n\
			]\n\
			queries[\n\
			confidentiality? dg_m\n\
			]\n";
		assert!(diagnose(src).is_empty());
	}

	#[test]
	fn a_parse_error_lands_on_the_offending_line() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private dp_a\n";
		let diagnostics = diagnose(src);
		assert_eq!(diagnostics.len(), 1);
		let d = &diagnostics[0];
		assert_eq!(d.severity, Some(DiagnosticSeverity::ERROR));
		assert_eq!(d.source.as_deref(), Some("verifpal"));
		assert!(
			matches!(&d.code, Some(NumberOrString::String(s)) if s == "parse error"),
			"{:?}",
			d.code
		);
	}

	#[test]
	fn a_sanity_error_points_at_the_query_it_is_about() {
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private ds_m\n\
			]\n\
			queries[\n\
			confidentiality? ds_absent\n\
			]\n";
		let diagnostics = diagnose(src);
		assert_eq!(diagnostics.len(), 1);
		let d = &diagnostics[0];
		assert_eq!(d.range.start.line, 5, "{:?}", d.range);
		assert!(
			matches!(&d.code, Some(NumberOrString::String(s)) if s == "sanity error"),
			"{:?}",
			d.code
		);
	}

	#[test]
	fn a_secondary_label_becomes_related_information() {
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private dl_m\n\
			dl_x = HASH(dl_m)\n\
			dl_x = HASH(dl_x)\n\
			]\n\
			queries[\n\
			confidentiality? dl_m\n\
			]\n";
		let diagnostics = diagnose(src);
		assert_eq!(diagnostics.len(), 1);
		let related = diagnostics[0]
			.related_information
			.as_ref()
			.expect("a rebound constant points at both assignments");
		assert!(!related.is_empty());
	}

	#[test]
	fn a_note_is_carried_into_the_message() {
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private dn_m\n\
			]\n";
		let diagnostics = diagnose(src);
		assert_eq!(diagnostics.len(), 1);
		assert!(
			diagnostics[0].message.contains("queries"),
			"{}",
			diagnostics[0].message
		);
	}
}
