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

pub(crate) struct MinimizingGuard;

impl MinimizingGuard {
	pub(crate) fn new() -> MinimizingGuard {
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
	pub out_of_order: Vec<String>,
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
		out_of_order: Vec::new(),
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
			let checks = checks_wanting_shapes(session, &keys);
			let blank = shapes_the_checks_wanted(&checks, &mut |_| value_nil());
			let mut carrying = Vec::new();
			let mut hollow = Vec::new();
			for i in forgeable_slots(km, session) {
				let candidate = |shape: &Value| -> Vec<(SlotIdx, Value)> {
					let mut c: Vec<(SlotIdx, Value)> =
						keys.iter().filter(|(s, _)| s.get() != i).cloned().collect();
					c.push((SlotIdx(i), shape.clone()));
					c
				};
				for shape in payload_shapes(km, &ambient, &checks, i) {
					carrying.push(candidate(&shape));
				}
				for shape in &blank {
					hollow.push(candidate(shape));
				}
			}
			carrying.extend(hollow);
			carrying
		};

	let forged_alone = |session: &PrincipalState| -> Vec<Vec<(SlotIdx, Value)>> {
		let mut carrying = Vec::new();
		let mut hollow = Vec::new();
		for i in forgeable_slots(km, session) {
			let blanked = vec![(SlotIdx(i), value_nil())];
			if controlled_installs(km, session, &ambient, blanked.clone()).is_empty() {
				continue;
			}
			let checks = checks_wanting_shapes(session, &blanked);
			for shape in payload_shapes(km, &ambient, &checks, i) {
				carrying.push(vec![(SlotIdx(i), shape)]);
			}
			for shape in shapes_the_checks_wanted(&checks, &mut |_| value_nil()) {
				hollow.push(vec![(SlotIdx(i), shape)]);
			}
		}
		carrying.extend(hollow);
		carrying
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
		let mut flights: Vec<Vec<(SlotIdx, Value)>> = Vec::new();
		let mut singles: Vec<Vec<(SlotIdx, Value)>> = Vec::new();
		for (i, sm) in session.meta.iter().enumerate() {
			if sm.wire.is_empty() {
				continue;
			}
			let siblings = crate::query::session_sibling_values(&sm.constant, km);
			for (n, sibling) in siblings.into_iter().enumerate() {
				if flights.len() <= n {
					flights.push(Vec::new());
				}
				flights[n].push((SlotIdx(i), sibling.clone()));
				singles.push(vec![(SlotIdx(i), sibling)]);
			}
		}
		let mut out: Vec<Vec<(SlotIdx, Value)>> =
			flights.into_iter().filter(|f| f.len() > 1).collect();
		out.extend(singles);
		out
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
			witness.out_of_order = out_of_order_harvest(ctx, km, &base, &keep, query_index, phase);
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

type WantedCheck = (Primitive, &'static crate::primitive::PrimitiveSpec);

fn checks_wanting_shapes(
	session: &PrincipalState,
	installs: &[(SlotIdx, Value)],
) -> Vec<WantedCheck> {
	let mut staged = session.clone();
	for (slot, value) in installs {
		crate::reexec::install(&mut staged, slot.get(), value.clone(), true);
	}
	if staged.resolve_all_values().is_err() {
		return Vec::new();
	}
	staged
		.perform_all_rewrites()
		.into_iter()
		.filter_map(|(prim, _)| {
			let spec = crate::primitive::primitive_get(prim.id).ok()?;
			spec.rewrite.has_rule.then_some((prim, spec))
		})
		.collect()
}

fn shapes_the_checks_wanted(
	checks: &[WantedCheck],
	fill: &mut dyn FnMut(usize) -> Value,
) -> Vec<Value> {
	let mut shapes: Vec<Value> = Vec::new();
	for (prim, spec) in checks {
		let mut at = 0usize;
		let filler = || {
			let position = at;
			at += 1;
			fill(position)
		};
		for shape in crate::solve::deduce::build_rewrite_shapes_with(prim, spec, filler) {
			if !shapes.iter().any(|s| s.equivalent(&shape, true)) {
				shapes.push(shape);
			}
		}
	}
	shapes
}

/// The forgeries for slot `i` that carry what the protocol itself put there.
///
/// `build_rewrite_shapes_with` fixes the positions the recipient's rewrite rule
/// matches on — the key, the associated data — and leaves the rest to a filler.
/// Filling those with `nil` always type-checks and always resolves an
/// authentication query, which is exactly why it explains nothing: "Bob accepted
/// an empty record" is a weaker claim than "Bob accepted the real file, resealed
/// under a key the attacker owns", and both resolve the same `a1`. So whenever
/// the attacker holds the honest term's own argument for a free position, offer
/// that first and let `nil` be the fallback it was meant to be.
fn payload_shapes(
	km: &ProtocolTrace,
	attacker: &AttackerState,
	checks: &[WantedCheck],
	slot: usize,
) -> Vec<Value> {
	if checks.is_empty() {
		return Vec::new();
	}
	let Some(honest) = km.slots.get(slot) else {
		return Vec::new();
	};
	let resolved = crate::resolution::resolve_trace_term(&honest.initial_value, km);
	let Value::Primitive(carried) = resolved else {
		return Vec::new();
	};
	let usable = |v: &Value| !v.equivalent(&value_nil(), true) && attacker.knows(v).is_some();
	if !carried.arguments.iter().any(usable) {
		return Vec::new();
	}
	let mut meaningful = false;
	let mut fill = |position: usize| -> Value {
		match carried.arguments.get(position) {
			Some(argument) if usable(argument) => {
				meaningful = true;
				argument.clone()
			}
			_ => value_nil(),
		}
	};
	let shapes = shapes_the_checks_wanted(checks, &mut fill);
	if !meaningful {
		return Vec::new();
	}
	shapes
		.into_iter()
		.filter(|shape| attacker_can_build(shape, attacker))
		.collect()
}

/// A forged term is only an explanation if the attacker could have produced it.
/// The minimizer never records a verdict, so this cannot cost an attack — but a
/// witness naming a term nothing derives is a trace a reader cannot follow.
fn attacker_can_build(shape: &Value, attacker: &AttackerState) -> bool {
	if attacker.knows(shape).is_some() {
		return true;
	}
	match shape {
		Value::Constant(_) => false,
		Value::Primitive(p) => p.arguments.iter().all(|a| attacker_can_build(a, attacker)),
	}
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

fn out_of_order_harvest(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	query_index: usize,
	phase: i32,
) -> Vec<String> {
	let ambient = ctx.attacker_snapshot();
	let mut harvested: Vec<String> = Vec::new();
	let renamed: Vec<(SlotIdx, Value)> = installs
		.iter()
		.map(
			|(slot, v)| match harvested_late(km, &ambient, base.id, *slot, v) {
				true => (*slot, rename_own_fresh(v, base, &mut harvested)),
				false => (*slot, v.clone()),
			},
		)
		.collect();
	if harvested.is_empty() {
		return harvested;
	}
	if probe(ctx, km, base, &renamed, query_index, phase).is_some() {
		return Vec::new();
	}
	harvested.sort();
	harvested.dedup();
	harvested
}

/// Was `v` lifted straight out of `target`'s own state, from a slot `target`
/// only reaches at or after the one being overwritten? A value the principal
/// published earlier is available to the attacker in the same run, so
/// reflecting it back is an ordinary attack; a value it only computes later is
/// one the run cannot supply in time, and only the atemporal within-phase
/// knowledge model admits it. Terms the attacker built itself are excluded the
/// way `solve::validate::replays_own_freshness` excludes them: their shape says
/// nothing about which run they came from.
fn harvested_late(
	km: &ProtocolTrace,
	ambient: &AttackerState,
	target: PrincipalId,
	into: SlotIdx,
	v: &Value,
) -> bool {
	match ambient.knows(v).and_then(|idx| ambient.derivation(idx)) {
		Some(DerivationRecord::Obtained { slot }) | Some(DerivationRecord::Leaked { slot }) => {
			slot.get() >= into.get()
				&& km
					.slots
					.get(slot.get())
					.is_some_and(|s| s.creator == target)
		}
		_ => false,
	}
}

/// `v` with every constant that `ps` itself generates replaced by the copy a
/// different session of `ps` would hold, recording which ones those were.
fn rename_own_fresh(v: &Value, ps: &PrincipalState, seen: &mut Vec<String>) -> Value {
	match v {
		Value::Constant(c) => {
			// Read freshness off the slot rather than off the occurrence: a
			// constant reached by inlining carries the identifier but not
			// necessarily the declaration flags.
			let own = ps.index_of(c).is_some_and(|i| {
				ps.meta[i].constant.fresh && ps.values[i].provenance.creator == ps.id
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
		let caveat = if witness.out_of_order.is_empty() {
			String::new()
		} else {
			format!(
				"\n    and on {} being fed a value it only computes later, built from {}",
				base.name,
				witness.out_of_order.join(", ")
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
		// or the out-of-order re-check of it.
		out_of_order: Vec::new(),
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
		let ctx = VerifyContext::new(&m, &states, Vec::new(), 2, crate::types::IdSet::default());
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
