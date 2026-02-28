/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! Re-exports from [`crate::theory`] for backwards compatibility.
//!
//! All equational theory operations (decompose, recompose, rewrite, rebuild,
//! reconstruct, password extraction) are defined in [`crate::theory`].
//! This module re-exports them so existing callers continue to compile
//! without import changes.

pub use crate::theory::{
	can_decompose, can_rebuild, can_recompose, can_reconstruct_equation,
	can_reconstruct_primitive, can_rewrite, find_obtainable_passwords, passively_decompose,
};
