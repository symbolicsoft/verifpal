/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

#![warn(unreachable_pub)]
#![forbid(unsafe_code)]

pub(crate) mod console;
pub(crate) mod engine;
#[cfg(feature = "language")]
pub(crate) mod lsp;
pub(crate) mod primitive;
pub(crate) mod protocol;
pub(crate) mod report;
pub(crate) mod solve;
pub(crate) mod syntax;
pub(crate) mod term;
#[cfg(test)]
mod testing;
pub(crate) mod theory;
pub(crate) mod util;
pub(crate) mod verify;
#[cfg(feature = "wasm")]
pub(crate) mod wasm;

#[cfg(feature = "cli")]
pub use console::terminal::{ColorChoice, set_color_choice};
#[cfg(feature = "cli")]
pub use console::update::UpdateCheck;
pub use console::{Verbosity, banner, set_verbosity};
#[cfg(feature = "lsp")]
pub use lsp::run as lsp_run;
pub use report::Run;
pub use report::html::html_report;
pub use report::tex::tex_report;
pub use syntax::pretty::{diagram, pretty_print};
pub use verify::{VerifyReport, verify_report_with_source_opts};
#[cfg(feature = "wasm")]
pub use wasm::{
	wasm_analyze, wasm_check, wasm_language, wasm_pretty, wasm_suggest_queries, wasm_verify,
};
