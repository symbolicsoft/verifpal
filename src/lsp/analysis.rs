/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use lsp_server::{Message, Notification};
use lsp_types::PositionEncodingKind;

use crate::report::Analysis;
use crate::types::VResult;

pub(crate) fn analyze(
	name: &str,
	text: &str,
	sessions: u8,
	cancel: &Arc<AtomicBool>,
) -> VResult<Analysis> {
	let model = crate::parser::parse_string(name, text)?;
	let started = std::time::Instant::now();
	let ctx = crate::verify::analyze_sessions_cancellable(&model, sessions, Arc::clone(cancel))
		.map_err(|e| e.located(&model.file_name, &model.source))?;
	let results = ctx.results_get();
	let report = crate::verify::VerifyReport {
		file_name: name.to_string(),
		sessions,
		code: crate::types::VerifyResult::results_code(&results),
		results,
		elapsed: Some(started.elapsed()),
		assumptions: ctx.capability_assumptions(),
		scenarios: ctx.scenarios().to_vec(),
	};
	Ok(Analysis::of(&report, text))
}

struct Live {
	cancel: Arc<AtomicBool>,
	finished: AtomicBool,
}

impl Live {
	fn is_running(&self) -> bool {
		!self.finished.load(Ordering::Relaxed)
	}
}

pub(crate) struct Runner {
	sender: crossbeam_channel::Sender<Message>,
	running: HashMap<String, Arc<Live>>,
}

impl Runner {
	pub(crate) fn new(sender: crossbeam_channel::Sender<Message>) -> Runner {
		Runner {
			sender,
			running: HashMap::new(),
		}
	}

	pub(crate) fn cancel(&mut self, uri: &str) -> bool {
		let Some(live) = self.running.remove(uri) else {
			return false;
		};
		if !live.is_running() {
			return false;
		}
		live.cancel.store(true, Ordering::Relaxed);
		true
	}

	pub(crate) fn cancel_all(&mut self) {
		for (_, live) in self.running.drain() {
			live.cancel.store(true, Ordering::Relaxed);
		}
	}

	#[allow(clippy::too_many_arguments)]
	pub(crate) fn start(
		&mut self,
		uri: String,
		name: String,
		text: String,
		version: i32,
		sessions: u8,
		token: String,
		encoding: PositionEncodingKind,
	) {
		self.cancel(&uri);
		self.running.retain(|_, live| live.is_running());
		let cancel = Arc::new(AtomicBool::new(false));
		let live = Arc::new(Live {
			cancel: Arc::clone(&cancel),
			finished: AtomicBool::new(false),
		});
		self.running.insert(uri.clone(), Arc::clone(&live));
		let sender = self.sender.clone();
		std::thread::spawn(move || {
			let _done = Finished(live);
			crate::info::set_verbosity(crate::info::Verbosity::Silent);
			progress(
				&sender,
				&token,
				serde_json::json!({
					"kind": "begin",
					"title": format!("Analyzing {name}"),
					"cancellable": true,
				}),
			);
			let outcome = analyze(&name, &text, sessions, &cancel);
			progress(&sender, &token, serde_json::json!({"kind": "end"}));
			if let Ok(analysis) = &outcome
				&& let Ok(parsed) = <lsp_types::Uri as std::str::FromStr>::from_str(&uri)
			{
				let line = crate::lsp::line::LineIndex::new(&text, &encoding);
				let _ = sender.send(Message::Notification(Notification::new(
					"textDocument/publishDiagnostics".to_string(),
					lsp_types::PublishDiagnosticsParams {
						uri: parsed,
						diagnostics: crate::lsp::diagnostics::of_verdicts(analysis, &line),
						version: Some(version),
					},
				)));
			}
			let report = match outcome {
				Ok(analysis) => crate::lsp::proto::AnalysisReport {
					uri,
					version,
					ok: true,
					cancelled: false,
					error: None,
					analysis: Some(analysis),
				},
				Err(e) => {
					let cancelled = e.kind == crate::types::ErrorKind::Cancelled;
					crate::lsp::proto::AnalysisReport {
						uri,
						version,
						ok: false,
						cancelled,
						error: (!cancelled).then(|| e.to_string()),
						analysis: None,
					}
				}
			};
			let _ = sender.send(Message::Notification(Notification::new(
				"verifpal/analysisReport".to_string(),
				report,
			)));
		});
	}
}

struct Finished(Arc<Live>);

impl Drop for Finished {
	fn drop(&mut self) {
		self.0.finished.store(true, Ordering::Relaxed);
	}
}

fn progress(sender: &crossbeam_channel::Sender<Message>, token: &str, value: serde_json::Value) {
	let _ = sender.send(Message::Notification(Notification::new(
		"$/progress".to_string(),
		serde_json::json!({"token": token, "value": value}),
	)));
}

#[cfg(test)]
mod tests {
	use super::*;

	const ATTACKED: &str = "attacker[active]\n\
		principal Alice[\n\
		knows private an_a\n\
		an_ga = PUBKEY(an_a)\n\
		]\n\
		Alice -> Bob: an_ga\n\
		principal Bob[\n\
		knows private an_b\n\
		an_gb = PUBKEY(an_b)\n\
		an_k = DH_KEX(an_ga, an_b)\n\
		generates an_m\n\
		an_e = AEAD_ENC(an_k, an_m, nil)\n\
		]\n\
		Bob -> Alice: an_gb, an_e\n\
		queries[\n\
		confidentiality? an_m\n\
		]\n";

	#[test]
	fn an_analysis_produces_a_report_with_a_resolved_query() {
		let quiet = Arc::new(AtomicBool::new(false));
		let outcome = analyze("an.vp", ATTACKED, 1, &quiet).expect("analyzes");
		assert_eq!(outcome.code, "c1");
		assert_eq!(outcome.queries.len(), 1);
		assert!(outcome.queries[0].resolved);
		assert!(!outcome.queries[0].steps.is_empty());
	}

	#[test]
	fn a_cancelled_analysis_reports_no_queries() {
		let cancel = Arc::new(AtomicBool::new(true));
		assert!(analyze("an.vp", ATTACKED, 1, &cancel).is_err());
	}

	#[test]
	fn a_model_that_does_not_parse_is_an_error_not_a_panic() {
		let quiet = Arc::new(AtomicBool::new(false));
		assert!(analyze("an.vp", "attacker[active]\nprincipal Alice[\n", 1, &quiet).is_err());
	}

	#[test]
	fn an_analysis_that_already_finished_is_not_cancellable() {
		let (sender, receiver) = crossbeam_channel::unbounded();
		let mut runner = Runner::new(sender);
		let uri = "file:///an.vp".to_string();
		runner.start(
			uri.clone(),
			"an.vp".to_string(),
			ATTACKED.to_string(),
			1,
			1,
			"t1".to_string(),
			PositionEncodingKind::UTF8,
		);

		let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
		let mut reported = false;
		while std::time::Instant::now() < deadline {
			let Ok(Message::Notification(note)) =
				receiver.recv_timeout(std::time::Duration::from_secs(30))
			else {
				break;
			};
			if note.method == "verifpal/analysisReport" {
				reported = true;
				break;
			}
		}
		assert!(reported, "the worker sent its report");

		let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
		while std::time::Instant::now() < deadline
			&& runner
				.running
				.get(&uri)
				.is_some_and(|live| live.is_running())
		{
			std::thread::yield_now();
		}

		assert!(
			!runner.cancel(&uri),
			"a completed analysis must not report itself as cancelled"
		);
		assert!(
			!runner.running.contains_key(&uri),
			"and its entry must not be kept"
		);
	}

	#[test]
	fn cancelling_an_unknown_document_reports_nothing_cancelled() {
		let (sender, _receiver) = crossbeam_channel::unbounded();
		let mut runner = Runner::new(sender);
		assert!(!runner.cancel("file:///never-started.vp"));
	}
}
