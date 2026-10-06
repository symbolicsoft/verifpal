/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::deduce::Deducer;
use super::free::{aligned_held_free, honest_slot_terms, keyed_free, preserved_free, swapped_free};
use super::goals::{goals_for_query, oracle_input_goals};
use super::symbolic::SymbolicState;
use super::vars::Substitution;
use super::{Pass, debugging, diverge, vars};
use crate::protocol::ProtocolTrace;
use crate::protocol::trace::resolve_trace_constant;
use crate::syntax::{PrincipalId, QueryKind};
use crate::term::{Value, VariableId, push_unique_value};
use crate::theory::AttackerState;
use crate::verify::Truncation;
use crate::verify::context::VerifyContext;

pub(crate) fn propose(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	principal: PrincipalId,
	pass: Pass,
	attacker: &AttackerState,
	sym: &SymbolicState,
	deducer: Deducer,
) -> (Vec<Substitution>, Vec<Substitution>) {
	let mut proposals: Vec<Substitution> = Vec::new();
	let debug = debugging();

	let open = ctx.open_queries();
	let protocol = ctx.term_bound(km).protocol();
	if pass == Pass::Targeted {
		let lanes = deducer.lanes(open.len()).into_iter().zip(&open).collect();
		let goals = crate::util::parallel::map_ordered(lanes, |(deducer, query)| {
			let started = debug.then(std::time::Instant::now);
			if debug {
				eprintln!("[search] goals {principal} {:?}: start", query.kind);
			}
			let goals = goals_for_query(query, km, principal, sym, &deducer);
			if let Some(started) = started {
				eprintln!(
					"[search] goals {principal} {:?}: {} in {:?}",
					query.kind,
					goals.len(),
					started.elapsed()
				);
			}
			goals
		});
		proposals.extend(goals.into_iter().flatten());
		if debug {
			eprintln!("[search] constraints {principal}: start");
		}
		proposals.extend(deducer.constraint_goals(&ctx.queries(), km, sym));
		if debug {
			eprintln!("[search] oracles {principal}: start");
		}
		proposals.extend(oracle_input_goals(km, principal, sym, attacker, &deducer));
	}

	let blanket = blanket_substitution(sym);
	if pass == Pass::Targeted && !blanket.is_empty() {
		proposals.push(blanket.clone());

		for &slot in &sym.var_slots {
			let single = slot_substitution(sym, slot);
			if !single.is_empty() {
				proposals.push(single);
			}
		}
	}

	if pass == Pass::Constructed {
		proposals.extend(sibling_flight_substitutions(km, sym));
		let lanes = deducer
			.lanes(sym.var_slots.len())
			.into_iter()
			.zip(sym.var_slots.iter().copied())
			.collect();
		let candidates = crate::util::parallel::map_ordered(lanes, |(deducer, slot)| {
			let Some(trace_slot) = km.slots.get(slot) else {
				return Vec::new();
			};
			let honest = resolve_trace_constant(&trace_slot.constant, km);
			slot_candidates(attacker, sym, &deducer, protocol, &honest, &blanket, slot)
		});
		for (&slot, candidates) in sym.var_slots.iter().zip(candidates) {
			for candidate in candidates {
				let var_id = vars::attacker_var_id(slot);
				let mut alone = Substitution::default();
				alone.insert(var_id.clone(), candidate.clone());
				proposals.push(alone);
				if !blanket.is_empty() {
					let mut combined = blanket.clone();
					combined.insert(var_id, candidate);
					proposals.push(combined);
				}
			}
		}
	}

	proposals = vars::dedupe_slots(proposals);
	let honest = honest_slot_terms(km, sym);
	let keyed: Vec<Substitution> =
		crate::util::parallel::map_ordered((0..proposals.len()).collect(), |at| {
			let proposal = &proposals[at];
			[
				keyed_free(&honest, sym, proposal),
				preserved_free(&honest, sym, proposal, attacker, &km.capabilities),
			]
		})
		.into_iter()
		.flatten()
		.flatten()
		.collect();
	proposals.extend(keyed);

	let aligned = aligned_held_free(&honest, sym, &proposals, attacker, protocol);
	proposals.extend(aligned);

	let swapped = swapped_free(&honest, sym, &proposals, attacker, protocol);
	proposals.extend(swapped);

	if open.iter().any(|q| q.kind == QueryKind::Equivalence) {
		let distinguished: Vec<Substitution> =
			crate::util::parallel::map_ordered((0..proposals.len()).collect(), |at| {
				diverge::distinguish(sym, &proposals[at])
			})
			.into_iter()
			.flatten()
			.collect();
		proposals.extend(distinguished);
	}

	if deducer.declined_bound() {
		ctx.note_truncation(Truncation::TermDepth);
	}
	let (replays, others): (Vec<Substitution>, Vec<Substitution>) = proposals
		.into_iter()
		.partition(|proposal| sibling_replay(km, sym, proposal));
	let mut proposals = others;
	match pass {
		Pass::Targeted => (proposals, replays),
		Pass::Constructed => {
			proposals.extend(replays);
			(proposals, Vec::new())
		}
	}
}

fn sibling_replay(km: &ProtocolTrace, sym: &SymbolicState, proposal: &Substitution) -> bool {
	let mut slots = 0usize;
	for (id, value) in proposal.iter() {
		if !vars::is_slot_var_id(id) {
			continue;
		}
		let slot = vars::slot_of_var_id(id);
		let Some(trace_slot) = km.slots.get(slot) else {
			return false;
		};
		let installed = match sym.var_terms.get(slot) {
			Some(Some(term)) => vars::apply(term, proposal),
			_ => value.clone(),
		};
		let siblings = km.session_sibling_values(&trace_slot.constant);
		if !siblings
			.iter()
			.any(|sibling| sibling.equivalent(&installed, true))
		{
			return false;
		}
		slots += 1;
	}
	slots > 0
}

pub(crate) fn emissions_under(
	km: &ProtocolTrace,
	sym: &SymbolicState,
	binding: &Substitution,
) -> Vec<Value> {
	(0..km.slots.len())
		.filter(|&e| {
			!sym.is_var_slot(e) && km.slots[e].disclosed() && vars::contains_var(&sym.terms[e])
		})
		.map(|e| {
			crate::theory::reduce_once(&vars::ground_free(&vars::apply(&sym.terms[e], binding)))
		})
		.filter(|emitted| !vars::contains_var(emitted))
		.collect()
}

pub(crate) fn leave_honest_slots(
	km: &ProtocolTrace,
	sym: &SymbolicState,
	proposal: Substitution,
) -> Substitution {
	let mut dropped: Vec<VariableId> = Vec::new();
	for &slot in &sym.var_slots {
		let id = vars::attacker_var_id(slot);
		let Some(term) = &sym.var_terms[slot] else {
			continue;
		};
		if !proposal.contains_key(&id) || slot >= km.slots.len() {
			continue;
		}
		let ground = vars::ground_free(&vars::apply(term, &proposal));
		if vars::contains_var(&ground)
			|| crate::solve::control::attacker_authored(&ground, slot, km)
		{
			continue;
		}
		let referenced = proposal
			.iter()
			.any(|(other, value)| *other != id && vars::occurs(&id, value, &proposal));
		if !referenced {
			dropped.push(id);
		}
	}
	if dropped.is_empty() {
		return proposal;
	}
	proposal
		.into_iter()
		.filter(|(id, _)| !dropped.contains(id))
		.collect()
}

pub(crate) fn install_signature(
	sym: &SymbolicState,
	proposal: &Substitution,
) -> Vec<(usize, Value)> {
	let mut out = Vec::new();
	for &slot in &sym.var_slots {
		let Some(term) = &sym.var_terms[slot] else {
			continue;
		};
		if !proposal.contains_key(&vars::attacker_var_id(slot)) {
			continue;
		}
		let ground = crate::theory::reduce_once(&vars::ground_free(&vars::apply(term, proposal)));
		if vars::contains_var(&ground) {
			continue;
		}
		out.push((slot, ground));
	}
	out
}

fn slot_substitution(sym: &SymbolicState, slot: usize) -> Substitution {
	let mut out = Substitution::default();
	if let Some(term) = &sym.var_terms[slot] {
		vars::ground_remaining(term, &mut out);
	}
	out
}

fn blanket_substitution(sym: &SymbolicState) -> Substitution {
	let mut out = Substitution::default();
	for &slot in &sym.var_slots {
		out.extend(slot_substitution(sym, slot));
	}
	out
}

fn sibling_flight_substitutions(km: &ProtocolTrace, sym: &SymbolicState) -> Vec<Substitution> {
	let siblings: Vec<(usize, Vec<Value>)> = sym
		.var_slots
		.iter()
		.filter_map(|&slot| {
			let trace_slot = km.slots.get(slot)?;
			Some((slot, km.session_sibling_values(&trace_slot.constant)))
		})
		.collect();
	let widest = siblings
		.iter()
		.map(|(_, values)| values.len())
		.max()
		.unwrap_or(0);
	let mut out = Vec::new();
	for i in 0..widest {
		let mut flight = Substitution::default();
		for (slot, values) in &siblings {
			if let Some(v) = values.get(i) {
				flight.insert(vars::attacker_var_id(*slot), v.clone());
			}
		}
		if !flight.is_empty() {
			out.push(flight);
		}
	}
	out
}

fn slot_candidates(
	attacker: &AttackerState,
	sym: &SymbolicState,
	deducer: &Deducer,
	protocol: &crate::term::hashing::TermSet,
	honest: &Value,
	blanket: &Substitution,
	slot: usize,
) -> Vec<Value> {
	let mut out = Vec::new();

	for candidate in attacker.known.iter() {
		if !protocol.contains(candidate) || candidate.equivalent(honest, true) {
			continue;
		}
		let compatible = match (honest, candidate) {
			(Value::Primitive(h), Value::Primitive(k)) => k.id == h.id,
			(Value::Constant(_), Value::Constant(k)) => !k.is_nil(),
			_ => false,
		};
		if compatible {
			out.push(candidate.clone());
		}
	}

	let mut contexts = vec![Substitution::default()];
	if !blanket.is_empty() {
		contexts.push(blanket.clone());
	}
	for shape in deducer.forgeable_shapes(sym, &vars::attacker_var_id(slot)) {
		for context in &contexts {
			for solution in deducer.solve(&shape, context) {
				let applied = vars::apply(&shape, &solution);
				for filler in [
					crate::term::value_nil(),
					crate::primitive::attacker_public_key(),
				] {
					let built = vars::ground_free_as(&applied, &filler);
					if !vars::contains_var(&built) {
						push_unique_value(&mut out, built);
					}
				}
			}
		}
	}
	out
}
