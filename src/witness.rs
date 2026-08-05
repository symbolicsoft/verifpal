/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::Cell;

use crate::context::VerifyContext;
use crate::deduction::compute_knowledge_closure;
use crate::info::InfoQuiet;
use crate::reexec::{governing_attacker, reexecute};
use crate::types::*;
use crate::value::value_g_nil;
use crate::verify::verify_resolve_queries;

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
}

pub(crate) fn minimize_witness(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	query_index: usize,
	seed: &[(SlotIdx, Value)],
) -> Witness {
	let unminimized = || Witness {
		ps: ps.clone(),
		attacker: ctx.attacker_snapshot(),
	};

	if in_minimization() {
		return unminimized();
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
		return unminimized();
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
						slot.creator != session.id && slot.initial_value.as_equation().is_some()
					})
			})
			.map(|(i, _)| (SlotIdx(i), value_g_nil()))
			.collect()
	};

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

	match probe(ctx, km, &base, &keep, query_index, phase) {
		Some(witness) => witness,
		None => unminimized(),
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

		let w = minimize_witness(&ctx, &km, &pure, 0, &[]);
		assert_eq!(w.ps.values.len(), pure.values.len());
	}

	#[test]
	fn minimize_witness_is_not_reentrant() {
		use crate::witness::in_minimization;
		assert!(!in_minimization());
	}
}
