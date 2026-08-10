/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::Cell;

use crate::context::VerifyContext;
use crate::deduction::compute_knowledge_closure;
use crate::info::InfoQuiet;
use crate::reexec::{governing_attacker, reexecute};
use crate::types::*;
use crate::verify::verify_resolve_queries;

fn attacker_public_key() -> Option<Value> {
	crate::primitive::nil_key_derivation()
}

thread_local! {
	static MINIMIZING: Cell<bool> = const { Cell::new(false) };
}

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

pub(crate) struct Witness {
	pub ps: PrincipalState,
	pub attacker: AttackerState,
	pub reproduced: bool,
	pub shares: Vec<String>,
}

pub(crate) fn minimize_witness(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	query_index: usize,
	seed: &[(SlotIdx, Value)],
) -> Witness {
	let unminimized = |reproduced: bool| Witness {
		ps: ps.clone(),
		attacker: ctx.attacker_snapshot(),
		reproduced,
		shares: Vec::new(),
	};

	if in_minimization() {
		return unminimized(true);
	}

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

	if mutations.is_empty() {
		// A violation reached with no attacker substitution at all: the trace is
		// a derivation over the honest run, and there is nothing to minimize.
		return unminimized(true);
	}

	let _guard = MinimizingGuard::new();
	let _quiet = InfoQuiet::new();
	let base = ps.clone_for_depth(true);
	let phase = ctx.attacker_snapshot().current_phase;

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
						slot.creator != session.id
							&& crate::primitive::value_is_key_derivation(&slot.initial_value)
					})
			})
			.filter_map(|(i, _)| attacker_public_key().map(|v| (SlotIdx(i), v)))
			.collect()
	};

	let recorded_as_gnil: Vec<(SlotIdx, Value)> = mutations
		.iter()
		.map(|(slot, value)| {
			let replacement = match value {
				Value::Primitive(p) if crate::primitive::primitive_is_key_derivation(p.id) => {
					attacker_public_key().unwrap_or_else(|| value.clone())
				}
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
		return unminimized(false);
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

	match probe(ctx, km, &base, &keep, query_index, phase) {
		Some(mut witness) => {
			witness.shares = shared_freshness(ctx, km, &base, &keep, query_index, phase);
			witness
		}
		None => unminimized(false),
	}
}

fn shared_freshness(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	query_index: usize,
	phase: i32,
) -> Vec<String> {
	let mut shared: Vec<String> = Vec::new();
	let renamed: Vec<(SlotIdx, Value)> = installs
		.iter()
		.map(|(slot, v)| (*slot, rename_own_fresh(v, base, &mut shared)))
		.collect();
	if shared.is_empty() {
		return shared;
	}
	if probe(ctx, km, base, &renamed, query_index, phase).is_some() {
		return Vec::new();
	}
	shared.sort();
	shared.dedup();
	shared
}

/// `v` with every constant that `ps` itself generates replaced by the copy a
/// different session of `ps` would hold, recording which ones those were.
fn rename_own_fresh(v: &Value, ps: &PrincipalState, seen: &mut Vec<String>) -> Value {
	match v {
		Value::Constant(c) => {
			// Read freshness off the slot rather than off the occurrence: a
			// constant reached by inlining carries the identifier but not
			// necessarily the declaration flags.
			//
			// A fresh value that travels on the wire or is leaked is one the
			// attacker actually observes, so injecting it is a real capability,
			// not two sessions coincidentally drawing the same nonce. Renaming
			// it would model a counterfactual the attacker never needs — and on
			// a genuine cross-session attack, where the attacker deliberately
			// carries one session's wire nonce into another, that renaming
			// misfires and stamps the trace with a spurious shared-freshness
			// caveat. Only truly internal fresh values — the ones a reflection
			// artifact would actually require — are renamed.
			let own = ps.index_of(c).is_some_and(|i| {
				ps.meta[i].constant.fresh
					&& ps.values[i].provenance.creator == ps.id
					&& ps.meta[i].wire.is_empty()
					&& !ps.meta[i].constant.leaked
			});
			if own {
				seen.push(c.name.to_string());
				crate::value::session_copy(c)
			} else {
				v.clone()
			}
		}
		Value::Primitive(p) => {
			let arguments = p
				.arguments
				.iter()
				.map(|a| rename_own_fresh(a, ps, seen))
				.collect();
			Value::Primitive(std::sync::Arc::new(p.with_arguments(arguments)))
		}
	}
}

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

	let ambient = scratch.attacker_snapshot();
	let governing = governing_attacker(&scratch, installs, base, &ambient);
	let ps = reexecute(base, installs, &governing, km).ok()?;
	let _ = compute_knowledge_closure(&scratch, km, &ps);
	let _ = verify_resolve_queries(&scratch, km, &ps);
	if !scratch.query_is_resolved(query_index) {
		return None;
	}
	Some(Witness {
		ps,
		attacker: scratch.attacker_snapshot(),
		// A probe returns only when the re-executed state resolved the query.
		reproduced: true,
		// Decided by the caller, which knows whether this probe is the witness
		// or the separated-freshness re-check of it.
		shares: Vec::new(),
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
		let ctx = VerifyContext::new(&m, &states, Vec::new());
		let mut pure = states[0].clone_for_depth(true);
		pure.resolve_all_values(&ctx.attacker_snapshot())
			.expect("resolve");
		ctx.attacker_phase_update(&km, &pure, 0).expect("phase");

		let w = minimize_witness(&ctx, &km, &pure, 0, &[]);
		assert_eq!(w.ps.values.len(), pure.values.len());
	}

	#[test]
	fn minimize_witness_is_not_reentrant() {
		use crate::witness::in_minimization;
		assert!(!in_minimization());
	}
}
