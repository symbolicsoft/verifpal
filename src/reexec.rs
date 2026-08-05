/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Faithful re-execution of a hypothetical principal state
//!
//! Installing attacker-chosen values into a principal and running it forward
//! is needed in two places: the goal-directed solver validating a proposal
//! ([`crate::solve::validate`]) and the trace minimizer deciding whether a
//! mutation is load-bearing ([`crate::witness`]).  Both must agree exactly —
//! a minimizer that re-executed differently could drop a mutation the real
//! engine needs, and report an attack trace that does not reproduce.
//!
//! So the logic lives here once: install, resolve, rewrite, then either
//! bypass guards the attacker can defeat or truncate at the checked primitive
//! that halts the principal.

use std::sync::Arc;

use crate::primitive::primitive_extract_bypass_key;
use crate::principal::ATTACKER_ID;
use crate::theory::{can_reconstruct_equation, can_reconstruct_primitive};
use crate::types::*;
use crate::value::value_g_nil;

/// Install `installs` into a copy of `ps_base` and run it forward through the
/// ordinary pipeline.
///
/// The returned state is what the principal actually computes under those
/// substitutions, with guard bypass and halt truncation already applied.
pub fn reexecute(
	ps_base: &PrincipalState,
	installs: &[(usize, Value)],
	attacker: &AttackerState,
) -> VResult<PrincipalState> {
	let mut ps = ps_base.clone();
	for (slot, ground) in installs {
		if *slot < ps.values.len() {
			install(&mut ps, *slot, ground.clone());
		}
	}

	// Keep the pre-resolution form: guard bypass has to inject into it and
	// re-resolve, because once values are inlined an injection no longer
	// propagates to the slots that referenced the constant.
	let ps_pre = ps.clone();
	ps.resolve_all_values(attacker)?;
	let failures = ps.perform_all_rewrites();

	if let Some(bypassed) = try_guard_bypass(&ps_pre, &ps, &failures, attacker)? {
		ps = bypassed;
	} else if let Some((truncate_at, halted_at)) = truncation_point(&ps, &failures) {
		// A checked primitive that still fails halts the principal.  Everything
		// it would have computed afterwards never existed, so the state is
		// truncated there rather than handing later values to the attacker.
		ps = drop_after_index(ps, truncate_at);
		ps.halted_at = Some(halted_at);
	}
	Ok(ps)
}

/// Maximum cascade rounds when bypassing guards.  Bypassing one guard can make
/// a later one bypassable, because the key it depended on has become derivable.
/// Chains longer than this do not occur in practice.
const MAX_BYPASS_ROUNDS: usize = 5;

/// A checked primitive that fails does not always halt the principal.
///
/// If the attacker can obtain the value the check is really testing — the
/// decryption key for `AEAD_DEC?`, the private exponent behind the public key
/// for `SIGNVERIF?` — then it could have produced an input that passes.  This
/// is the decisive case for man-in-the-middle: substituting `G^nil` for an
/// identity key fails the signature check, but the attacker *knows the private
/// key for `G^nil`*, so it can present a signature that verifies.  Treating
/// that as a halt would discard the entire attack.
///
/// This has to work from the pre-resolution state: injecting into an
/// already-inlined state would not propagate to the slots that referenced the
/// guard's output.
///
/// Returns `None` when no guard is bypassable, leaving the caller to truncate.
fn try_guard_bypass(
	ps_pre: &PrincipalState,
	ps_resolved: &PrincipalState,
	failures: &[(Primitive, usize)],
	attacker: &AttackerState,
) -> VResult<Option<PrincipalState>> {
	let bypassable: Vec<usize> = failures
		.iter()
		.filter(|(prim, idx)| {
			prim.instance_check
				&& ps_resolved.values[*idx].provenance.creator == ps_resolved.id
				&& primitive_extract_bypass_key(prim)
					.is_some_and(|key| can_obtain(&key, ps_resolved, attacker))
		})
		.map(|(_, idx)| *idx)
		.collect();

	if bypassable.is_empty() {
		return Ok(None);
	}

	let mut ps = ps_pre.clone();
	for idx in bypassable {
		if idx < ps.values.len() {
			ps.values[idx].override_all_bypassed(value_g_nil());
		}
	}

	for _ in 0..MAX_BYPASS_ROUNDS {
		ps.resolve_all_values(attacker)?;
		let round = ps.perform_all_rewrites();
		let mut injected = false;
		for (prim, idx) in &round {
			if !prim.instance_check || ps.values[*idx].provenance.creator != ps.id {
				continue;
			}
			if primitive_extract_bypass_key(prim).is_some_and(|key| can_obtain(&key, &ps, attacker))
			{
				ps.values[*idx].override_all_bypassed(value_g_nil());
				injected = true;
			}
		}
		if !injected {
			break;
		}
	}

	// Whatever still fails after all bypasses really does halt the principal.
	ps.resolve_all_values(attacker)?;
	let remaining = ps.perform_all_rewrites();
	if let Some((truncate_at, halted_at)) = truncation_point(&ps, &remaining) {
		ps = drop_after_index(ps, truncate_at);
		ps.halted_at = Some(halted_at);
	}
	Ok(Some(ps))
}

/// Whether the attacker holds `v` outright or can rebuild it from what it holds.
fn can_obtain(v: &Value, ps: &PrincipalState, attacker: &AttackerState) -> bool {
	if attacker.knows(v).is_some() {
		return true;
	}
	match v {
		Value::Primitive(p) => can_reconstruct_primitive(p, ps, attacker, 0).is_some(),
		Value::Equation(e) => can_reconstruct_equation(e, attacker).is_some(),
		_ => false,
	}
}

/// Install an attacker-chosen value in a slot, with the provenance the rest of
/// the engine expects.
///
/// `original` keeps the value the principal believes it received.  Losing that
/// distinction is what causes false authentication attacks, because principals
/// would then "see" the attacker's tampering inside their own computations.
pub fn install(ps: &mut PrincipalState, slot: usize, ground: Value) {
	let previous = ps.values[slot].value.clone();
	let sv = &mut ps.values[slot];
	sv.original = previous;
	sv.provenance.creator = ATTACKER_ID;
	sv.provenance.sender = ATTACKER_ID;
	sv.provenance.attacker_tainted = true;
	sv.pre_rewrite = ground.clone();
	sv.value = ground;
}

/// The slot index to truncate at, and the `declared_at` to record as the halt
/// point, given the failures reported by `perform_all_rewrites`.
///
/// Only checked primitives (`?`) this principal computed itself can halt it.
fn truncation_point(ps: &PrincipalState, failures: &[(Primitive, usize)]) -> Option<(usize, i32)> {
	for (prim, idx) in failures {
		if !prim.instance_check || ps.values[*idx].provenance.creator != ps.id {
			continue;
		}
		let declared_at = ps.meta[*idx].declared_at;
		let truncate_at = if declared_at == ps.max_declared_at {
			idx + 1
		} else {
			match ps.meta.iter().position(|m| m.declared_at == declared_at) {
				Some(pos) => pos + 1,
				None => idx + 1,
			}
		};
		return Some((truncate_at, declared_at));
	}
	None
}

fn drop_after_index(mut ps: PrincipalState, at: usize) -> PrincipalState {
	Arc::make_mut(&mut ps.meta).truncate(at);
	ps.values.truncate(at);
	ps
}
