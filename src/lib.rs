/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

#![warn(unreachable_pub)]
// The soundness argument of the paper is an argument about what the code can
// reach, and `unsafe` would let any of it reach anything. There is none, and
// this keeps it that way.
#![forbid(unsafe_code)]

pub(crate) mod capability;
pub(crate) mod construct;
pub(crate) mod context;
pub(crate) mod deduction;
pub(crate) mod equivalence;
pub(crate) mod hashing;
pub(crate) mod info;
pub(crate) mod json;
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
pub(crate) mod sessions;
pub(crate) mod skeleton;
pub(crate) mod solve;
#[cfg(test)]
mod testutil;
pub(crate) mod theory;
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

pub use info::{Verbosity, info_banner, info_message, set_verbosity};
pub use json::{diagram, handle_internal_json, json_report};
pub use pretty::pretty_print;
pub use report::Run;
pub use types::*;
#[cfg(feature = "cli")]
pub use update::{UpdateCheck, update_check_report, update_check_start};
#[cfg(feature = "cli")]
pub use util::{ColorChoice, set_color_choice};
pub use verify::{VerifyReport, verify, verify_report, verify_with_sessions};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use json::{json_escape, json_string_array};

#[cfg(feature = "wasm")]
fn wasm_verify_error(e: &VerifpalError, messages: &[String]) -> String {
	format!(
		r#"{{"ok":false,"error":"{}","results":[],"code":"","messages":{}}}"#,
		json_escape(&e.to_string()),
		json_string_array(messages),
	)
}

#[cfg(feature = "wasm")]
fn wasm_pretty_error(e: &VerifpalError) -> String {
	format!(
		r#"{{"ok":false,"error":"{}","output":""}}"#,
		json_escape(&e.to_string())
	)
}

#[cfg(feature = "wasm")]
fn wasm_verify_inner(input: &str) -> VResult<String> {
	let m = parser::parse_string("workbench.vp", input)?;
	let ctx = verify::analyze(&m).map_err(|e| e.located(&m.file_name, &m.source))?;
	let results = ctx.results_get();
	let results_json = json::json_array(results.iter(), |r| {
		format!(
			r#"{{"query":"{}","resolved":{},"kind":"{}","summary":"{}"}}"#,
			json_escape(&r.query.to_string()),
			r.resolved,
			r.query.kind.name(),
			json_escape(&r.summary),
		)
	});
	let assumptions = ctx.capability_assumptions();
	let assumptions_json = json::json_array(assumptions.iter(), |(term, capability, onset)| {
		format!(
			r#"{{"term":"{}","capability":"{}","fromPhase":{}}}"#,
			json_escape(&term.to_string()),
			capability.name(),
			onset,
		)
	});
	Ok(format!(
		r#"{{"ok":true,"results":{},"code":"{}","assumptions":{},"messages":{}}}"#,
		results_json,
		json_escape(&types::VerifyResult::results_code(&results)),
		assumptions_json,
		json_string_array(&info::wasm_messages_drain()),
	))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_verify(input: &str) -> String {
	info::wasm_messages_init();
	wasm_verify_inner(input).unwrap_or_else(|e| wasm_verify_error(&e, &info::wasm_messages_drain()))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_pretty(input: &str) -> String {
	let rendered =
		parser::parse_string("workbench.vp", input).and_then(|m| pretty::pretty_model(&m));
	match rendered {
		Ok(output) => format!(
			r#"{{"ok":true,"error":"","output":"{}"}}"#,
			json_escape(&output)
		),
		Err(e) => wasm_pretty_error(&e),
	}
}
