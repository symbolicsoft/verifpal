/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Propose and dispose
//!
//! The solver only ever proposes.  Nothing it concludes is trusted: every
//! candidate substitution is materialised into a concrete [`PrincipalState`],
//! re-executed through the existing pipeline, and re-checked against real
//! attacker knowledge before any query result can be emitted.
//!
//! This is what makes the engine sound *structurally* rather than by argument.
//! A bug anywhere in `deduce.rs`, `diverge.rs`, `matching.rs` or `symbolic.rs`
//! can only cause a **missed** attack, never a false one, because none of those
//! modules can write a result.  The three models that exist purely to pin past
//! false attacks — `auth_with_signing_false-attack.vp`, `concat_split_replay.vp`
//! and `wire_projection_replay.vp` — are protected by exactly the same code
//! path that protects them today.
//!
//! Re-execution itself lives in [`crate::reexec`], shared with the trace
//! minimizer so that a minimized witness is executed exactly the way the
//! proposal that found it was.

use crate::context::VerifyContext;
use crate::deduction::compute_knowledge_closure;
use crate::reexec::attacker_authored;
use crate::types::*;
use crate::verify::verify_resolve_queries;

use super::symbolic::SymbolicState;
use super::vars::{Substitution, apply};

/// Materialise `subst`, re-execute the principal, and re-check every pending
/// query against the resulting attacker knowledge.
///
/// Returns `true` if the substitution was worth executing at all.  A return of
/// `false` means every binding reduced to the honest value, so the "mutation"
/// was a replay indistinguishable from the real message — see
/// [`is_worthwhile`].
pub(crate) fn validate(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps_base: &PrincipalState,
	sym: &SymbolicState,
	attacker: &AttackerState,
	subst: &Substitution,
) -> VResult<bool> {
	let ps = ps_base.clone_for_depth(true);
	let mut installs: Vec<(SlotIdx, Value)> = Vec::new();
	let mut worthwhile = false;

	for &slot in &sym.var_slots {
		let Some(var_term) = &sym.var_terms[slot] else {
			continue;
		};
		// A slot whose own variable was never bound is one the attacker has no
		// reason to touch, so the honest message is forwarded unchanged.
		if !subst.contains_key(&super::vars::attacker_var_id(slot)) {
			continue;
		}
		// Within a bound value, positions no rule constrained are the attacker's
		// free choice and become `nil`.
		let ground = super::vars::ground_free(&apply(var_term, subst));
		if super::vars::contains_var(&ground) {
			continue;
		}
		if slot >= ps.values.len() {
			continue;
		}
		if attacker_authored(&ground, slot, km, &ps) {
			worthwhile = true;
		}
		installs.push((SlotIdx(slot), ground));
	}

	if !worthwhile {
		return Ok(false);
	}

	let ps = crate::reexec::reexecute(&ps, &installs, attacker, km)?;

	// Errors from analysing a *hypothetical* state are not errors in the run.
	//
	// A proposal that halts a principal truncates its state, and a query naming
	// a value the principal never reached then has no slot to look at — which
	// `value_constant_contains_fresh_values` reports as a resolution error.
	// That says only that this particular substitution answers nothing, so it is
	// discarded rather than propagated; letting it escape would abort
	// verification of the whole model over one speculative branch.  The mutation
	// engine discards these for the same reason.
	let _ = compute_knowledge_closure(ctx, km, &ps);
	let _ = verify_resolve_queries(ctx, km, &ps);
	Ok(true)
}
