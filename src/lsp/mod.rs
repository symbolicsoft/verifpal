/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

#[cfg(feature = "lsp")]
pub(crate) mod analysis;
pub(crate) mod diagnostics;
pub(crate) mod docs;
pub(crate) mod language;
pub(crate) mod line;
#[cfg(feature = "lsp")]
pub(crate) mod proto;
#[cfg(feature = "lsp")]
pub(crate) mod server;
pub(crate) mod state;

#[cfg(feature = "lsp")]
pub use server::run;
