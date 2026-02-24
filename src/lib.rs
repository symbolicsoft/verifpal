/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub mod construct;
pub mod context;
pub mod equivalence;
pub mod hashing;
pub mod info;
pub mod inject;
pub mod mutationmap;
pub mod narrative;
pub mod parser;
pub mod possible;
pub mod pretty;
pub mod primitive;
pub mod principal;
pub mod query;
pub mod resolution;
pub mod rewrite;
pub mod sanity;
pub mod tui;
pub mod types;
pub mod util;
pub mod value;
pub mod verifhub;
pub mod verify;
pub mod verifyactive;
pub mod verifyanalysis;

// ---------------------------------------------------------------------------
// Public re-exports for the binary crate
// ---------------------------------------------------------------------------

pub use info::{info_banner, info_message};
pub use narrative::set_character;
pub use pretty::pretty_print;
pub use tui::set_tui_mode;
pub use types::*;
pub use verify::verify;

// ---------------------------------------------------------------------------
// WASM API
// ---------------------------------------------------------------------------

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
fn wasm_reset_global_state() {
	principal::principal_names_reset();
	value::value_names_reset();
	parser::unnamed_counter_reset();
	tui::set_tui_mode(false);
	narrative::reset();
}

#[cfg(feature = "wasm")]
fn json_escape(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for c in s.chars() {
		match c {
			'"' => out.push_str("\\\""),
			'\\' => out.push_str("\\\\"),
			'\n' => out.push_str("\\n"),
			'\r' => out.push_str("\\r"),
			'\t' => out.push_str("\\t"),
			c if c < '\u{20}' => out.push_str(&format!("\\u{:04x}", c as u32)),
			c => out.push(c),
		}
	}
	out
}

#[cfg(feature = "wasm")]
fn json_string_array(arr: &[String]) -> String {
	let mut out = String::from("[");
	for (i, s) in arr.iter().enumerate() {
		if i > 0 {
			out.push(',');
		}
		out.push('"');
		out.push_str(&json_escape(s));
		out.push('"');
	}
	out.push(']');
	out
}

/// Verify a Verifpal model from source text. Returns JSON.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_verify(input: &str) -> String {
	wasm_reset_global_state();
	info::wasm_messages_init();

	let m = match parser::parse_string("workbench.vp", input) {
		Ok(m) => m,
		Err(e) => {
			return format!(
				r#"{{"ok":false,"error":"{}","results":[],"code":"","messages":[]}}"#,
				json_escape(&e.to_string())
			)
		}
	};

	let (km, ps) = match sanity::sanity(&m) {
		Ok(v) => v,
		Err(e) => {
			return format!(
				r#"{{"ok":false,"error":"{}","results":[],"code":"","messages":[]}}"#,
				json_escape(&e.to_string())
			)
		}
	};

	let ctx = context::VerifyContext::new(&m);

	let result = match m.attacker {
		types::AttackerKind::Passive => wasm_verify_passive(&ctx, &km, &ps),
		types::AttackerKind::Active => verifyactive::verify_active(&ctx, &km, &ps),
	};

	if let Err(e) = result {
		let messages = info::wasm_messages_drain();
		return format!(
			r#"{{"ok":false,"error":"{}","results":[],"code":"","messages":{}}}"#,
			json_escape(&e.to_string()),
			json_string_array(&messages),
		);
	}

	let results = ctx.results_get();
	let code = wasm_results_code(&results);
	let messages = info::wasm_messages_drain();

	let mut rj = String::from("[");
	for (i, r) in results.iter().enumerate() {
		if i > 0 {
			rj.push(',');
		}
		rj.push_str(&format!(
			r#"{{"query":"{}","resolved":{},"kind":"{}","summary":"{}"}}"#,
			json_escape(&r.query.to_string()),
			r.resolved,
			r.query.kind.name(),
			json_escape(&r.summary),
		));
	}
	rj.push(']');

	format!(
		r#"{{"ok":true,"results":{},"code":"{}","messages":{}}}"#,
		rj,
		json_escape(&code),
		json_string_array(&messages),
	)
}

/// Pretty-print a Verifpal model from source text. Returns JSON.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn wasm_pretty(input: &str) -> String {
	wasm_reset_global_state();

	let m = match parser::parse_string("workbench.vp", input) {
		Ok(m) => m,
		Err(e) => {
			return format!(
				r#"{{"ok":false,"error":"{}","output":""}}"#,
				json_escape(&e.to_string())
			)
		}
	};

	match pretty::pretty_model(&m) {
		Ok(output) => format!(
			r#"{{"ok":true,"error":"","output":"{}"}}"#,
			json_escape(&output)
		),
		Err(e) => format!(
			r#"{{"ok":false,"error":"{}","output":""}}"#,
			json_escape(&e.to_string())
		),
	}
}

#[cfg(feature = "wasm")]
fn wasm_verify_passive(
	ctx: &context::VerifyContext,
	km: &types::ProtocolTrace,
	principal_states: &[types::PrincipalState],
) -> types::VResult<()> {
	for phase in 0..=km.max_phase {
		ctx.attacker_init();
		let mut ps_pure = principal_states[0].clone_for_stage(true);
		ps_pure.resolve_all_values(&ctx.attacker_snapshot())?;
		ctx.attacker_phase_update(km, &ps_pure, phase)?;
		verify::verify_standard_run(ctx, km, principal_states, 0)?;
	}
	Ok(())
}

#[cfg(feature = "wasm")]
fn wasm_results_code(results: &[types::VerifyResult]) -> String {
	let mut code = String::with_capacity(results.len() * 2);
	for r in results {
		code.push(match r.query.kind {
			types::QueryKind::Confidentiality => 'c',
			types::QueryKind::Authentication => 'a',
			types::QueryKind::Freshness => 'f',
			types::QueryKind::Unlinkability => 'u',
			types::QueryKind::Equivalence => 'e',
		});
		code.push(if r.resolved { '1' } else { '0' });
	}
	code
}
