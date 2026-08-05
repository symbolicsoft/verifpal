/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Minimizing a discovered attack to the mutations it actually needs
//!
//! A state that resolves a query is a witness, but rarely a small one.  The
//! solver installs the union of the bindings for every goal it was pursuing at
//! once, so a trace for one query routinely shows substitutions that only
//! another query needed.
//!
//! This module drops them.  For each attacker mutation in turn it builds a
//! state without that mutation, re-executes it through [`crate::reexec`] —
//! the same code path the engine used to find the attack — and re-checks the
//! query.  If the query still resolves, the mutation was never load-bearing.
//!
//! ## Soundness
//!
//! Nothing here can record a query result.  Probes run against a scratch
//! [`VerifyContext`] whose attacker knowledge is a snapshot and whose results
//! are discarded, so a bug in this module can only produce a *larger* witness
//! than necessary, never a witness for an attack that does not exist.  The
//! reported state is one that was re-executed and re-checked, not an edited
//! transcript of one.
//!
//! Seeding probes with end-of-search attacker knowledge is sound for the same
//! reason: every value in that set carries its own independently verified
//! derivation.  At worst the minimizer finds a simpler attack than the one
//! discovery found, which is the point.

use std::cell::Cell;

use crate::context::VerifyContext;
use crate::deduction::compute_knowledge_closure;
use crate::info::InfoQuiet;
use crate::reexec::reexecute;
use crate::types::*;
use crate::value::value_g_nil;
use crate::verify::verify_resolve_queries;

thread_local! {
	static MINIMIZING: Cell<bool> = const { Cell::new(false) };
}

/// Whether this thread is currently inside a minimization probe.
///
/// A probe re-checks the query, which runs the ordinary query evaluation,
/// which would otherwise minimize again — forever.  Callers of
/// [`minimize_witness`] use this to take the plain path instead.
pub(crate) fn in_minimization() -> bool {
	MINIMIZING.with(|f| f.get())
}

struct MinimizingGuard;

impl MinimizingGuard {
	fn new() -> MinimizingGuard {
		MINIMIZING.with(|f| f.set(true));
		MinimizingGuard
	}
}

impl Drop for MinimizingGuard {
	fn drop(&mut self) {
		MINIMIZING.with(|f| f.set(false));
	}
}

/// A re-verified attack: the state to narrate and the attacker knowledge it
/// produced, including the derivation records that explain it.
pub(crate) struct Witness {
	pub ps: PrincipalState,
	pub attacker: AttackerState,
}

/// Reduce the attack to the mutations query `query_index` actually needs.
///
/// `seed` carries mutations recorded against the *value* rather than against
/// `ps`.  Attacker knowledge is monotone and global, so a query often resolves
/// against a state that never carried the substitutions that made the value
/// derivable — they were applied in the run that first learned it, and survive
/// only in that value's [`MutationRecord`].  Narrating `ps` alone would then
/// report an attack with no attacker actions in it.  Slot indices are shared
/// across principal states (every state is built from the same trace slots in
/// the same order), so a recorded diff installs at the same index here.
pub(crate) fn minimize_witness(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	query_index: usize,
	seed: &[(SlotIdx, Value)],
) -> Witness {
	// The attack as the real run already knows it.  Passing `false` means no
	// substitutions are claimed — used when no candidate replayed from here,
	// because showing the recorded ones anyway would be worse than showing none:
	// they can name a slot the attack never turned on, and a reader has no way
	// to tell.
	let unminimized = || Witness {
		ps: ps.clone(),
		attacker: ctx.attacker_snapshot(),
	};

	// A probe's own query evaluation must not recurse back into here.
	if in_minimization() {
		return unminimized();
	}

	// `seed` is the value's own provenance: the substitutions that earned it.
	// `ps` is whatever run happened to re-answer the query afterwards, which is
	// usually a different attack, so the two are never merged.
	let mut mutations: Vec<(SlotIdx, Value)> = if seed.is_empty() {
		ps.values
			.iter()
			.enumerate()
			.filter(|(_, sv)| sv.provenance.attacker_tainted)
			.map(|(i, sv)| (SlotIdx(i), sv.pre_rewrite.clone()))
			.collect()
	} else {
		seed.iter()
			.filter(|(slot, _)| slot.get() < ps.values.len())
			.cloned()
			.collect()
	};
	mutations.sort_by_key(|(slot, _)| *slot);

	// A passive result, or one the attacker reached without touching the
	// wire, is already as small as it gets.
	if mutations.is_empty() {
		return unminimized();
	}

	let _guard = MinimizingGuard::new();
	let _quiet = InfoQuiet::new();
	let base = ps.clone_for_depth(true);
	let phase = ctx.attacker_snapshot().current_phase;

	// The canonical man-in-the-middle: the attacker puts its own key on the
	// wire wherever a principal received someone else's.
	//
	// Tried first, ahead of anything the records suggest, because it is the
	// explanation a reader needs — and because records are unreliable here in
	// a way no amount of care fixes.  The search reaches a value by many
	// routes, and which run's substitutions end up attached to it depends on
	// arrival order rather than on what made the attack work.  A candidate
	// that replays is a real attack for this query whatever the search
	// happened to try, so preferring the comprehensible one costs nothing.
	//
	// The session matters as much as the substitution.  A query is answered by
	// whichever principal reaches it first, which is rarely the one whose run
	// was compromised: Alice's message is read because of what Alice received,
	// but the query is resolved while walking Bob.  So every principal's
	// session is a candidate, starting with the one in hand.
	// Sessions come from the context's pristine states, never from `ps`.
	// `ps` has been through a run, and a guard bypass writes its injected key
	// into `original` — the field purification restores from — so a state that
	// has been bypassed cannot be cleaned by purifying it.  Replaying against
	// such a base would find the attack already present and conclude that no
	// substitution was needed, which is how a trace loses the very step it
	// exists to show.
	let mut sessions: Vec<PrincipalState> = Vec::new();
	for state in ctx.principal_states() {
		let session = state.clone_for_depth(true);
		if state.id == ps.id {
			sessions.insert(0, session);
		} else {
			sessions.push(session);
		}
	}
	if sessions.is_empty() {
		sessions.push(base.clone());
	}

	let mitm_for = |session: &PrincipalState| -> Vec<(SlotIdx, Value)> {
		session
			.meta
			.iter()
			.enumerate()
			.filter(|(i, sm)| {
				sm.wire.contains(&session.id)
					&& km.slots.get(*i).is_some_and(|slot| {
						slot.creator != session.id && slot.initial_value.as_equation().is_some()
					})
			})
			.map(|(i, _)| (SlotIdx(i), value_g_nil()))
			.collect()
	};

	// Candidates in order of how well they explain, not how they were found.
	// Every one is re-executed before it is believed, so the worst a bad guess
	// costs is a probe.
	let recorded_as_gnil: Vec<(SlotIdx, Value)> = mutations
		.iter()
		.map(|(slot, value)| {
			let replacement = match value {
				Value::Equation(_) => value_g_nil(),
				other => other.clone(),
			};
			(*slot, replacement)
		})
		.collect();

	let mut chosen: Option<(PrincipalState, Vec<(SlotIdx, Value)>)> = None;
	'search: for session in &sessions {
		for candidate in [
			mitm_for(session),
			mutations.clone(),
			recorded_as_gnil.clone(),
		] {
			if candidate.is_empty() {
				continue;
			}
			if probe(ctx, km, session, &candidate, query_index, phase).is_some() {
				chosen = Some((session.clone(), candidate));
				break 'search;
			}
		}
	}
	let Some((base, mutations)) = chosen else {
		// Nothing replayed in any session.  Report the derivation without
		// claiming attacker actions we could not verify.
		return unminimized();
	};

	let mut keep: Vec<(SlotIdx, Value)> = mutations.clone();
	for (slot, _) in &mutations {
		let trial: Vec<(SlotIdx, Value)> =
			keep.iter().filter(|(s, _)| s != slot).cloned().collect();
		if trial.len() == keep.len() {
			continue;
		}
		if probe(ctx, km, &base, &trial, query_index, phase).is_some() {
			keep = trial;
		}
	}

	// `keep` was accepted by the probe that shrank to it, so this reproduces.
	match probe(ctx, km, &base, &keep, query_index, phase) {
		Some(witness) => witness,
		None => unminimized(),
	}
}

/// Re-execute `base` with `installs` from the passive baseline and re-check
/// the single query.  Returns the witness when the query still resolves.
///
/// The baseline matters more than anything else here.  Probing against
/// end-of-search knowledge would be worthless: attacker knowledge is monotone,
/// so a confidentiality query — "does the attacker hold this value" — is
/// already answered yes by the snapshot, and every mutation would look
/// droppable.  So each probe starts from an empty attacker reseeded with only
/// what is public and on the wire, and has to earn the value again.
fn probe(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	query_index: usize,
	phase: i32,
) -> Option<Witness> {
	let scratch = ctx.scratch_for_query(query_index);
	scratch.attacker_init();
	let mut pure = base.clone();
	pure.resolve_all_values(&scratch.attacker_snapshot()).ok()?;
	scratch.attacker_phase_update(km, &pure, phase).ok()?;

	let ps = reexecute(base, installs, &scratch.attacker_snapshot(), km).ok()?;
	// As in `solve/validate.rs`: a hypothetical state that cannot be analysed
	// answers nothing, which is a "no" and not a run-level error.
	let _ = compute_knowledge_closure(&scratch, km, &ps);
	let _ = verify_resolve_queries(&scratch, km, &ps);
	if !scratch.query_is_resolved(query_index) {
		return None;
	}
	Some(Witness {
		ps,
		attacker: scratch.attacker_snapshot(),
	})
}

#[cfg(test)]
mod tests {
	use crate::parser::parse_string;

	#[test]
	fn minimize_witness_is_identity_without_mutations() {
		use crate::context::VerifyContext;
		use crate::witness::minimize_witness;
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private mw_m\n\
			leaks mw_m\n\
			]\n\
			queries[\n\
			confidentiality? mw_m\n\
			]\n";
		let m = parse_string("mw.vp", src).expect("parse");
		let (km, states) = crate::sanity::sanity(&m).expect("sanity");
		let ctx = VerifyContext::new(&m, &states);
		let mut pure = states[0].clone_for_depth(true);
		pure.resolve_all_values(&ctx.attacker_snapshot())
			.expect("resolve");
		ctx.attacker_phase_update(&km, &pure, 0).expect("phase");

		// No slot is attacker-tainted in a passive run, so there is nothing to
		// drop and the witness is the state it was given.
		let w = minimize_witness(&ctx, &km, &pure, 0, &[]);
		assert_eq!(w.ps.values.len(), pure.values.len());
	}

	#[test]
	fn minimize_witness_is_not_reentrant() {
		use crate::witness::in_minimization;
		// Outside minimization the flag is clear; the guard is what stops a
		// probe's own query evaluation from minimizing again forever.
		assert!(!in_minimization());
	}
}
