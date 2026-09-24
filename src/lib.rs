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
pub(crate) mod engine;
pub(crate) mod equivalence;
pub(crate) mod hashing;
pub(crate) mod html;
pub(crate) mod info;
#[cfg(feature = "language")]
pub(crate) mod lsp;
#[cfg(test)]
mod metamorphic;
#[cfg(test)]
mod model_tests;
pub(crate) mod msc;
pub(crate) mod parallel;
pub(crate) mod parser;
pub(crate) mod pretty;
pub(crate) mod primitive;
pub(crate) mod principal;
pub(crate) mod query;
pub(crate) mod report;
pub(crate) mod resolution;
pub(crate) mod rewrite;
pub(crate) mod sanity;
pub(crate) mod scenario;
pub(crate) mod sessions;
pub(crate) mod solve;
pub(crate) mod template;
#[cfg(test)]
mod testutil;
pub(crate) mod tex;
pub(crate) mod theory;
pub(crate) mod tokens;
pub mod types;
pub(crate) mod unlink;
#[cfg(feature = "cli")]
pub(crate) mod update;
pub(crate) mod util;
pub(crate) mod value;
pub(crate) mod verify;
#[cfg(feature = "wasm")]
pub(crate) mod wasm;

pub use html::html_report;
pub use info::{Verbosity, info_banner, info_message, set_verbosity};
#[cfg(feature = "lsp")]
pub use lsp::run as lsp_run;
pub use pretty::{diagram, pretty_print};
pub use report::Run;
pub use tex::tex_report;
pub use types::*;
#[cfg(feature = "cli")]
pub use update::{UpdateCheck, update_check_report, update_check_start};
#[cfg(feature = "cli")]
pub use util::{ColorChoice, set_color_choice};
pub use verify::{
	VerifyReport, verify, verify_auto_queries, verify_report, verify_report_with_source,
	verify_report_with_source_opts, verify_with_sessions,
};
#[cfg(feature = "wasm")]
pub use wasm::{
	wasm_analyze, wasm_check, wasm_language, wasm_pretty, wasm_suggest_queries, wasm_verify,
};
