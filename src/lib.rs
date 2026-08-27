/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

#![warn(unreachable_pub)]
// The soundness argument of the paper is an argument about what the code can
// reach, and `unsafe` would let any of it reach anything. There is none, and
// this keeps it that way.
#![forbid(unsafe_code)]

pub(crate) mod autoquery;
pub(crate) mod capability;
pub(crate) mod construct;
pub(crate) mod context;
pub(crate) mod deduction;
pub(crate) mod equivalence;
pub(crate) mod hashing;
pub(crate) mod html;
pub(crate) mod info;
#[cfg(feature = "lsp")]
pub(crate) mod lsp;
#[cfg(test)]
mod metamorphic;
#[cfg(test)]
mod model_tests;
pub(crate) mod narrate;
pub(crate) mod parser;
pub(crate) mod pretty;
pub(crate) mod primitive;
pub(crate) mod principal;
pub(crate) mod query;
pub(crate) mod reexec;
pub(crate) mod report;
pub(crate) mod resolution;
pub(crate) mod rewrite;
pub(crate) mod sanity;
pub(crate) mod scenario;
pub(crate) mod sessions;
pub(crate) mod solve;
#[cfg(test)]
mod testutil;
pub(crate) mod theory;
pub(crate) mod tokens;
#[cfg(test)]
mod tracecheck;
pub mod types;
pub(crate) mod unlink;
#[cfg(feature = "cli")]
pub(crate) mod update;
pub(crate) mod util;
pub(crate) mod value;
pub(crate) mod verify;
pub(crate) mod witness;

pub use html::html_report;
pub use info::{Verbosity, info_banner, info_message, info_replay, set_verbosity};
#[cfg(feature = "lsp")]
pub use lsp::run as lsp_run;
pub use pretty::{diagram, pretty_print};
pub use report::Run;
pub use types::*;
#[cfg(feature = "cli")]
pub use update::{UpdateCheck, update_check_report, update_check_start};
#[cfg(feature = "cli")]
pub use util::{ColorChoice, set_color_choice};
pub use verify::{
	SATURATE_MAX, Saturation, VerifyReport, saturation_sessions, verify, verify_auto_queries,
	verify_report, verify_report_with_source, verify_report_with_source_opts, verify_saturating,
	verify_with_sessions,
};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
#[derive(serde::Serialize)]
struct WasmVerify {
	ok: bool,
	error: String,
	results: Vec<WasmResult>,
	code: String,
	assumptions: Vec<WasmAssumption>,
	messages: Vec<String>,
}

#[cfg(feature = "wasm")]
#[derive(serde::Serialize)]
struct WasmResult {
	query: String,
	resolved: bool,
	kind: String,
	summary: String,
	envelope: String,
}

#[cfg(feature = "wasm")]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct WasmAssumption {
	term: String,
	capability: String,
	from_phase: i32,
}

#[cfg(feature = "wasm")]
#[derive(serde::Serialize)]
struct WasmPretty {
	ok: bool,
	error: String,
	output: String,
}

#[cfg(feature = "wasm")]
fn wasm_verify_inner(input: &str) -> VResult<WasmVerify> {
	let m = parser::parse_string("workbench.vp", input)?;
	let ctx = verify::analyze(&m).map_err(|e| e.located(&m.file_name, &m.source))?;
	let results = ctx.results_get();
	Ok(WasmVerify {
		ok: true,
		error: String::new(),
		code: types::VerifyResult::results_code(&results),
		results: results
			.iter()
			.map(|r| WasmResult {
				query: r.query.to_string(),
				resolved: r.resolved,
				kind: r.query.kind.name().to_string(),
				summary: r.summary.clone(),
				envelope: r.envelope.summary(),
			})
			.collect(),
		assumptions: ctx
			.capability_assumptions()
			.iter()
			.map(|(term, capability, onset)| WasmAssumption {
				term: term.to_string(),
				capability: capability.name().to_string(),
				from_phase: *onset,
			})
			.collect(),
		messages: info::wasm_messages_drain(),
	})
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_verify(input: &str) -> String {
	info::wasm_messages_init();
	let payload = wasm_verify_inner(input).unwrap_or_else(|e| WasmVerify {
		ok: false,
		error: e.to_string(),
		results: vec![],
		code: String::new(),
		assumptions: vec![],
		messages: info::wasm_messages_drain(),
	});
	serde_json::to_string(&payload).unwrap_or_else(|_| {
		r#"{"ok":false,"error":"could not serialize the result","results":[],"code":"","assumptions":[],"messages":[]}"#
			.to_string()
	})
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_pretty(input: &str) -> String {
	let payload =
		match parser::parse_string("workbench.vp", input).map(|m| pretty::pretty_model(&m)) {
			Ok(output) => WasmPretty {
				ok: true,
				error: String::new(),
				output,
			},
			Err(e) => WasmPretty {
				ok: false,
				error: e.to_string(),
				output: String::new(),
			},
		};
	serde_json::to_string(&payload)
		.unwrap_or_else(|_| r#"{"ok":false,"error":"could not serialize","output":""}"#.to_string())
}
