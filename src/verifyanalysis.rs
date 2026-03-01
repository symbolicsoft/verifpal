/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! Deduction analysis entry point.
//!
//! Delegates to [`crate::deduction::compute_knowledge_closure`] which
//! implements the fixed-point computation over deduction rules.

use crate::context::VerifyContext;
use crate::deduction::compute_knowledge_closure;
use crate::types::*;

/// Run the deduction analysis loop for a single principal state.
///
/// Computes the least fixed point of the attacker's knowledge under the
/// deduction rules defined in [`crate::deduction`]. See that module's
/// documentation for the convergence argument and rule priority.
pub fn verify_analysis(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	depth: i32,
) -> VResult<()> {
	compute_knowledge_closure(ctx, km, ps, depth)
}
