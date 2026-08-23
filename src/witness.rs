/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::Cell;

use crate::context::VerifyContext;
use crate::deduction::compute_knowledge_closure;
use crate::info::InfoQuiet;
use crate::primitive::attacker_public_key;
use crate::reexec::{governing_attacker, reexecute};
use crate::types::*;
use crate::value::value_nil;
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
	pub reproduced: bool,
	pub shares: Vec<String>,
	#[cfg(test)]
	pub installs: Vec<(SlotIdx, Value)>,
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
		#[cfg(test)]
		installs: Vec::new(),
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
	let ambient = ctx.attacker_snapshot();
	let phase = ambient.current_phase;

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
		sessions.push(ps.clone_for_depth(true));
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
			.map(|(i, _)| (SlotIdx(i), attacker_public_key()))
			.collect()
	};

	let forged_from =
		|session: &PrincipalState, base: Vec<(SlotIdx, Value)>| -> Vec<Vec<(SlotIdx, Value)>> {
			let keys = controlled_installs(km, session, &ambient, base);
			if keys.is_empty() {
				return Vec::new();
			}
			let shapes = shapes_the_checks_wanted(session, &keys);
			if shapes.is_empty() {
				return Vec::new();
			}
			let mut out = Vec::new();
			for i in forgeable_slots(km, session) {
				for shape in &shapes {
					let mut candidate: Vec<(SlotIdx, Value)> =
						keys.iter().filter(|(s, _)| s.get() != i).cloned().collect();
					candidate.push((SlotIdx(i), shape.clone()));
					out.push(candidate);
				}
			}
			out
		};

	let forged_alone = |session: &PrincipalState| -> Vec<Vec<(SlotIdx, Value)>> {
		let mut out = Vec::new();
		for i in forgeable_slots(km, session) {
			let blanked = vec![(SlotIdx(i), value_nil())];
			if controlled_installs(km, session, &ambient, blanked.clone()).is_empty() {
				continue;
			}
			for shape in shapes_the_checks_wanted(session, &blanked) {
				out.push(vec![(SlotIdx(i), shape)]);
			}
		}
		out
	};

	let recorded_as_gnil: Vec<(SlotIdx, Value)> = mutations
		.iter()
		.map(|(slot, value)| {
			let replacement = match value {
				Value::Primitive(p) if crate::primitive::primitive_is_key_derivation(p.id) => {
					attacker_public_key()
				}
				other => other.clone(),
			};
			(*slot, replacement)
		})
		.collect();

	let replayed_from = |session: &PrincipalState| -> Vec<Vec<(SlotIdx, Value)>> {
		let mut every: Vec<(SlotIdx, Value)> = Vec::new();
		let mut singles: Vec<Vec<(SlotIdx, Value)>> = Vec::new();
		for (i, sm) in session.meta.iter().enumerate() {
			if sm.wire.is_empty() {
				continue;
			}
			let Some(sibling) = crate::query::session_sibling_values(&sm.constant, km)
				.into_iter()
				.next()
			else {
				continue;
			};
			every.push((SlotIdx(i), sibling.clone()));
			singles.push(vec![(SlotIdx(i), sibling)]);
		}
		if every.len() > 1 {
			singles.insert(0, every);
		}
		singles
	};

	let mut chosen: Option<(PrincipalState, Vec<(SlotIdx, Value)>)> = None;
	let mut fallback: Option<(PrincipalState, Vec<(SlotIdx, Value)>)> = None;
	'search: for session in &sessions {
		let mut families = vec![
			mitm_for(session),
			mutations.clone(),
			recorded_as_gnil.clone(),
		];
		families.extend(forged_from(session, mitm_for(session)));
		families.extend(forged_from(session, mutations.clone()));
		families.extend(forged_alone(session));
		families.extend(replayed_from(session));
		for candidate in families {
			let candidate = controlled_installs(km, session, &ambient, candidate);
			if candidate.is_empty() {
				continue;
			}
			let Some(witness) = probe(ctx, km, session, &candidate, query_index, phase) else {
				continue;
			};
			if !needs_guard_bypass(&witness.ps) {
				chosen = Some((session.clone(), candidate));
				break 'search;
			}
			if fallback.is_none() {
				fallback = Some((session.clone(), candidate));
			}
		}
	}
	let explanatory = chosen.is_some();
	let Some((base, mutations)) = chosen.or(fallback) else {
		return unminimized(false);
	};

	let mut keep: Vec<(SlotIdx, Value)> = mutations.clone();
	for (slot, _) in &mutations {
		let trial: Vec<(SlotIdx, Value)> =
			keep.iter().filter(|(s, _)| s != slot).cloned().collect();
		if trial.len() == keep.len() {
			continue;
		}
		let Some(witness) = probe(ctx, km, &base, &trial, query_index, phase) else {
			continue;
		};
		if explanatory && needs_guard_bypass(&witness.ps) {
			continue;
		}
		keep = trial;
	}

	match probe(ctx, km, &base, &keep, query_index, phase) {
		Some(mut witness) => {
			witness.shares = shared_freshness(ctx, km, &base, &keep, query_index, phase);
			#[cfg(test)]
			{
				witness.installs = keep;
			}
			witness
		}
		None => unminimized(false),
	}
}

fn forgeable_slots(km: &ProtocolTrace, session: &PrincipalState) -> Vec<usize> {
	session
		.meta
		.iter()
		.enumerate()
		.filter(|(i, sm)| {
			sm.wire.contains(&session.id)
				&& km.slots.get(*i).is_some_and(|slot| {
					slot.creator != session.id
						&& !crate::primitive::value_is_key_derivation(&slot.initial_value)
				})
		})
		.map(|(i, _)| i)
		.collect()
}

fn shapes_the_checks_wanted(session: &PrincipalState, installs: &[(SlotIdx, Value)]) -> Vec<Value> {
	let mut staged = session.clone();
	for (slot, value) in installs {
		crate::reexec::install(&mut staged, slot.get(), value.clone(), true);
	}
	if staged.resolve_all_values().is_err() {
		return Vec::new();
	}
	let mut shapes: Vec<Value> = Vec::new();
	for (prim, _) in staged.perform_all_rewrites() {
		let Ok(spec) = crate::primitive::primitive_get(prim.id) else {
			continue;
		};
		if !spec.rewrite.has_rule {
			continue;
		}
		for shape in crate::solve::deduce::build_rewrite_shapes_with(&prim, spec, value_nil) {
			if !shapes.iter().any(|s| s.equivalent(&shape, true)) {
				shapes.push(shape);
			}
		}
	}
	shapes
}

fn needs_guard_bypass(ps: &PrincipalState) -> bool {
	ps.values.iter().any(|sv| sv.bypassed.is_some())
}

fn controlled_installs(
	km: &ProtocolTrace,
	session: &PrincipalState,
	attacker: &AttackerState,
	candidate: Vec<(SlotIdx, Value)>,
) -> Vec<(SlotIdx, Value)> {
	let controllable = crate::reexec::Controllable::of(km, session, attacker);
	candidate
		.into_iter()
		.filter(|(slot, _)| controllable.admits(session, attacker, slot.get()))
		.collect()
}

fn shared_freshness(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	query_index: usize,
	phase: i32,
) -> Vec<String> {
	let ambient = ctx.attacker_snapshot();
	let mut shared: Vec<String> = Vec::new();
	let renamed: Vec<(SlotIdx, Value)> = installs
		.iter()
		.map(|(slot, v)| {
			let strict = produced_by_target(km, &ambient, base.id, v);
			(*slot, rename_own_fresh(v, base, strict, &mut shared))
		})
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

fn produced_by_target(
	km: &ProtocolTrace,
	ambient: &AttackerState,
	target: PrincipalId,
	v: &Value,
) -> bool {
	match ambient.knows(v).and_then(|idx| ambient.derivation(idx)) {
		Some(DerivationRecord::Obtained { slot }) | Some(DerivationRecord::Leaked { slot }) => km
			.slots
			.get(slot.get())
			.is_some_and(|s| s.creator == target),
		_ => true,
	}
}

/// `v` with every constant that `ps` itself generates replaced by the copy a
/// different session of `ps` would hold, recording which ones those were.
fn rename_own_fresh(v: &Value, ps: &PrincipalState, strict: bool, seen: &mut Vec<String>) -> Value {
	match v {
		Value::Constant(c) => {
			// Read freshness off the slot rather than off the occurrence: a
			// constant reached by inlining carries the identifier but not
			// necessarily the declaration flags.
			let own = ps.index_of(c).is_some_and(|i| {
				ps.meta[i].constant.fresh
					&& ps.values[i].provenance.creator == ps.id
					&& (strict || (ps.meta[i].wire.is_empty() && !ps.meta[i].constant.leaked))
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
				.map(|a| rename_own_fresh(a, ps, strict, seen))
				.collect();
			Value::Primitive(std::sync::Arc::new(p.with_arguments(arguments)))
		}
	}
}

#[cfg(test)]
pub(crate) fn assert_reported_attacks_replay(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	file_name: &str,
) {
	for result in ctx.results_get() {
		if !result.resolved {
			continue;
		}
		let Some(witness) = ctx.witness_get(result.query_index) else {
			continue;
		};
		if !witness.reproduced {
			continue;
		}
		let Some(base) = ctx
			.principal_states()
			.iter()
			.find(|s| s.id == witness.principal)
			.map(|s| s.clone_for_depth(true))
		else {
			continue;
		};
		let name_of = |slot: &SlotIdx| {
			base.meta
				.get(slot.get())
				.map(|sm| sm.constant.name.to_string())
				.unwrap_or_else(|| format!("slot {slot}"))
		};
		let listing: Vec<String> = witness
			.installs
			.iter()
			.map(|(slot, value)| format!("      {} := {}", name_of(slot), value))
			.collect();
		let caveat = if witness.shares.is_empty() {
			String::new()
		} else {
			format!(
				"\n    and on sessions sharing: {}",
				witness.shares.join(", ")
			)
		};
		assert!(
			replays(
				ctx,
				km,
				&base,
				&witness.installs,
				result.query_index,
				witness.phase,
			),
			"WITNESS • {} query {} ({}) reports an attack that its own minimized \
			 witness does not reproduce. Re-executing {}'s session at phase {} with \
			 exactly these substitutions left the query unresolved, so the verdict \
			 and the reason recorded for it disagree.\n\n{}{}\n",
			file_name,
			result.query_index,
			result.query,
			base.name,
			witness.phase,
			listing.join("\n"),
			caveat,
		);
		let missing: Vec<String> = witness
			.installs
			.iter()
			.map(|(slot, _)| *slot)
			.filter(|slot| !witness.narrated.contains(slot))
			.map(|slot| name_of(&slot))
			.collect();
		assert!(
			missing.is_empty(),
			"WITNESS • {} query {} ({}) prints a trace that omits {} substitution(s) \
			 the witness needed: {}. A reader following the trace cannot reach the \
			 verdict it reports.\n\n{}{}\n",
			file_name,
			result.query_index,
			result.query,
			missing.len(),
			missing.join(", "),
			listing.join("\n"),
			caveat,
		);
	}
}

#[cfg(test)]
pub(crate) fn minimization_guard() -> impl Drop {
	MinimizingGuard::new()
}

#[cfg(test)]
pub(crate) fn replays(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	query_index: usize,
	phase: i32,
) -> bool {
	let _guard = MinimizingGuard::new();
	let _quiet = InfoQuiet::new();
	probe(ctx, km, base, installs, query_index, phase).is_some()
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
	crate::verify::attacker_seed_phase(&scratch, km, base, phase).ok()?;
	for state in ctx.principal_states() {
		let mut honest = state.clone_for_depth(true);
		if honest.resolve_all_values().is_err() {
			continue;
		}
		if scratch.attacker_phase_update(km, &honest, phase).is_err() {
			continue;
		}
		let _ = compute_knowledge_closure(&scratch, km, &honest);
	}

	let ambient = scratch.attacker_snapshot();
	let governing = governing_attacker(&scratch, installs, base, &ambient);
	let ps = reexecute(base, installs, &governing, km).ok()?;
	let _ = compute_knowledge_closure(&scratch, km, &ps);
	let _ = verify_resolve_queries(&scratch, km, &ps);
	if !scratch.query_is_resolved(query_index) {
		return None;
	}
	Some(Witness {
		#[cfg(test)]
		installs: installs.to_vec(),
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
		pure.resolve_all_values().expect("resolve");
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
