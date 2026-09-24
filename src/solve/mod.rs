/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub(crate) mod control;
pub(crate) mod deduce;
pub(crate) mod diverge;
pub(crate) mod matching;
pub(crate) mod symbolic;
pub(crate) mod vars;

use std::sync::Arc;

use crate::context::VerifyContext;
use crate::types::*;
use crate::value::{push_unique_value, resolve_trace_constant};

use deduce::Deducer;
use matching::unifiers;
use symbolic::SymbolicState;
use vars::Substitution;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pass {
	Targeted,
	Constructed,
}

pub(crate) fn directly_unguarded(km: &ProtocolTrace, ps: &PrincipalState, slot: usize) -> bool {
	km.slots.get(slot).is_some_and(|trace_slot| {
		trace_slot
			.sent_by
			.iter()
			.any(|event| event.recipient == ps.id && !event.guarded)
	})
}

pub(crate) fn split_delivered(km: &ProtocolTrace, ps: &PrincipalState, slot: usize) -> bool {
	km.slots.get(slot).is_some_and(|trace_slot| {
		trace_slot
			.sent_by
			.iter()
			.any(|event| event.recipient != ps.id && event.sender != ps.id)
	}) && ps
		.meta
		.get(slot)
		.is_some_and(|meta| meta.mutatable_to.iter().any(|&who| who != ps.id))
}

pub(crate) fn slots_blocking_reduction(sym: &SymbolicState) -> Vec<Vec<usize>> {
	let mut out: Vec<Vec<usize>> = Vec::new();
	let mut seen = IdSet::default();
	for term in &sym.terms {
		collect_blocking_slots(term, &mut out, &mut seen);
	}
	out.sort();
	out.dedup();
	out
}

fn collect_blocking_slots(v: &Value, out: &mut Vec<Vec<usize>>, seen: &mut IdSet<usize>) {
	let Value::Primitive(p) = v else {
		return;
	};
	if !seen.insert(Arc::as_ptr(p) as usize) {
		return;
	}
	if let Some(rule) = crate::primitive::primitive_get(p.id)
		.ok()
		.and_then(|s| s.rewrite.as_ref())
		&& !crate::theory::can_rewrite(p).0
	{
		let mut group = Vec::new();
		let mut direct = Vec::new();
		let positions = std::iter::once(rule.from).chain(rule.matching.iter().map(|(o, _)| *o));
		for position in positions {
			if let Some(argument) = p.arguments.get(position) {
				if let Value::Constant(c) = argument
					&& vars::is_slot_var_id(c.id)
				{
					direct.push(vars::slot_of_var_id(c.id));
				}
				for c in argument.constant_leaves() {
					if vars::is_slot_var_id(c.id) {
						group.push(vars::slot_of_var_id(c.id));
					}
				}
			}
		}
		for mut candidate in [direct, group] {
			candidate.sort();
			candidate.dedup();
			if !candidate.is_empty() {
				out.push(candidate);
			}
		}
	}
	for a in &p.arguments {
		collect_blocking_slots(a, out, seen);
	}
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn propose(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	pass: Pass,
	attacker: &AttackerState,
	sym: &SymbolicState,
	mut deducer: Deducer,
	taken: Vec<Vec<(ValueId, Value)>>,
) -> (Vec<Substitution>, Vec<Vec<(ValueId, Value)>>) {
	let empty = Substitution::default();
	let mut proposals: Vec<Substitution> = Vec::new();

	let results = ctx.results_get();
	let protocol = ctx.term_bound(km).protocol(km);
	if pass == Pass::Targeted {
		let mut pending: Vec<&Query> = Vec::new();
		for result in &results {
			if result.resolved {
				continue;
			}
			for query in std::iter::once(&result.query).chain(result.variants.iter()) {
				pending.push(query);
			}
		}
		let goals = {
			let in_lane = deducer.lane_factory();
			observed(lanes(pending.len()), |(lane, range)| {
				let deducer = in_lane(lane);
				range
					.flat_map(|at| goals_for_query(pending[at], km, ps, sym, &deducer, &empty))
					.collect::<Vec<_>>()
			})
		};
		proposals.extend(goals.into_iter().flatten());
		proposals.extend(deducer.constraint_goals(ctx, km, ps, sym));
		proposals.extend(oracle_input_goals(ctx, km, ps, sym, attacker));
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
		proposals.extend(sibling_flight_substitutions(km, ps, sym));
		let in_lane = deducer.lane_factory();
		let candidates = observed(lanes(sym.var_slots.len()), |(lane, range)| {
			let deducer = in_lane(lane);
			range
				.map(|at| {
					let slot = sym.var_slots[at];
					let Some(meta) = ps.meta.get(slot) else {
						return Vec::new();
					};
					let honest = resolve_trace_constant(&meta.constant, km);
					slot_candidates(attacker, sym, &deducer, protocol, &honest, &blanket, slot)
				})
				.collect::<Vec<_>>()
		});
		for (&slot, candidates) in sym.var_slots.iter().zip(candidates.into_iter().flatten()) {
			for candidate in candidates {
				let var_id = vars::attacker_var_id(slot);
				let mut alone = Substitution::default();
				alone.insert(var_id, candidate.clone());
				proposals.push(alone);
				if !blanket.is_empty() {
					let mut combined = blanket.clone();
					combined.insert(var_id, candidate);
					proposals.push(combined);
				}
			}
		}
	}

	let honest = honest_slot_terms(km, ps, sym);
	let keyed: Vec<Substitution> = observed((0..proposals.len()).collect(), |at| {
		let proposal = &proposals[at];
		[
			keyed_free(&honest, sym, proposal),
			preserved_free(&honest, sym, proposal, attacker),
		]
	})
	.into_iter()
	.flatten()
	.flatten()
	.collect();
	proposals.extend(keyed);

	let aligned = aligned_held_free(&honest, sym, &proposals, attacker, protocol);
	proposals.extend(aligned);

	if results
		.iter()
		.any(|r| !r.resolved && r.query.kind == QueryKind::Equivalence)
	{
		let distinguished: Vec<Substitution> =
			crate::parallel::map_ordered((0..proposals.len()).collect(), |at| {
				diverge::distinguish(sym, &proposals[at])
			})
			.into_iter()
			.flatten()
			.collect();
		proposals.extend(distinguished);
	}

	let (replays, others): (Vec<Substitution>, Vec<Substitution>) = proposals
		.into_iter()
		.partition(|proposal| sibling_replay(km, ps, sym, proposal));
	let mut proposals = others;
	match pass {
		Pass::Targeted => (
			proposals,
			replays
				.into_iter()
				.map(|replay| replay.into_iter().collect())
				.collect(),
		),
		Pass::Constructed => {
			proposals.extend(replays);
			proposals.extend(
				taken
					.into_iter()
					.map(|bindings| bindings.into_iter().collect::<Substitution>()),
			);
			(proposals, Vec::new())
		}
	}
}

fn oracle_input_goals(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
	attacker: &AttackerState,
) -> Vec<Substitution> {
	let emissions: Vec<&Value> = (0..ps.values.len())
		.filter(|&e| {
			ps.values[e].provenance.creator == ps.id
				&& (ps.meta[e].sent_at.is_some() || ps.meta[e].constant.leaked)
		})
		.map(|e| &sym.terms[e])
		.filter(|term| vars::contains_var(term))
		.collect();
	if emissions.is_empty() {
		return Vec::new();
	}
	let mut fresh = vars::free_lane_bounds(vars::FREE_LANES).0;
	let mut wanted: Vec<(Value, Option<ValueId>)> = Vec::new();
	let mut foreign: Substitution = Substitution::default();
	let slot_var = |v: &Value| vars::as_var(v).filter(|&id| vars::is_slot_var_id(id));
	for state in ctx.principal_states() {
		let controllable = crate::solve::control::Controllable::of(km, state, attacker);
		let other = symbolic::build(&controllable, state, attacker);
		for &slot in &other.var_slots {
			if sym.var_slots.contains(&slot) {
				continue;
			}
			let honest = resolve_trace_constant(&state.meta[slot].constant, km);
			let filler = if crate::primitive::value_is_key_derivation(&honest) {
				crate::primitive::attacker_public_key()
			} else {
				crate::value::value_nil()
			};
			foreign.insert(vars::attacker_var_id(slot), filler);
		}
		for c in 0..state.values.len() {
			if state.values[c].provenance.creator != state.id {
				continue;
			}
			let Value::Primitive(prim) = &other.terms[c] else {
				continue;
			};
			if !prim.instance_check || !vars::contains_var(&other.terms[c]) {
				continue;
			}
			let shapes: Vec<(Value, Option<ValueId>)> =
				match crate::primitive::primitive_get(prim.id) {
					Ok(spec) => match spec.rewrite.as_ref() {
						Some(rule) => {
							let target = prim.arguments.get(rule.from).and_then(slot_var);
							deduce::build_rewrite_shapes_with(prim, rule, |_| {
								let v = vars::free_var(fresh);
								fresh += 1;
								v
							})
							.into_iter()
							.map(|shape| (shape, target))
							.collect()
						}
						None => Vec::new(),
					},
					Err(_) => {
						if crate::primitive::primitive_is_core(prim.id) && prim.arguments.len() == 2
						{
							vec![
								(prim.arguments[0].clone(), slot_var(&prim.arguments[1])),
								(prim.arguments[1].clone(), slot_var(&prim.arguments[0])),
							]
						} else {
							Vec::new()
						}
					}
				};
			for (shape, target) in shapes {
				if vars::contains_var(&shape)
					&& !wanted
						.iter()
						.any(|(w, t)| *t == target && w.equivalent(&shape, true))
				{
					wanted.push((shape, target));
				}
			}
		}
	}
	let heads: Vec<(PrimitiveId, usize)> = emissions
		.iter()
		.filter_map(|emitted| match emitted {
			Value::Primitive(p) => Some((p.id, p.arguments.len())),
			Value::Constant(_) => None,
		})
		.collect();
	let mut nested: Vec<(Value, Option<ValueId>)> = Vec::new();
	for (shape, _) in &wanted {
		let Value::Primitive(p) = shape else {
			continue;
		};
		for inner in p.arguments.iter() {
			let Value::Primitive(q) = inner else {
				continue;
			};
			if !vars::contains_var(inner)
				|| !heads
					.iter()
					.any(|&(id, arity)| id == q.id && arity == q.arguments.len())
			{
				continue;
			}
			if wanted
				.iter()
				.chain(nested.iter())
				.any(|(seen, _)| seen.equivalent(inner, true))
			{
				continue;
			}
			nested.push((inner.clone(), None));
		}
	}
	wanted.extend(nested);
	let empty = Substitution::default();
	let mut out: Vec<Substitution> = Vec::new();
	for emission in emissions {
		for (shape, target) in &wanted {
			for bound in unifiers(emission, shape, &empty) {
				let mut proposal = Substitution::default();
				for &slot in &sym.var_slots {
					let id = vars::attacker_var_id(slot);
					if !bound.contains_key(&id) {
						continue;
					}
					let value = vars::apply(&vars::attacker_var(slot, ""), &bound);
					if vars::as_var(&value) == Some(id) || vars::occurs(id, &value, &empty) {
						continue;
					}
					proposal.insert(id, vars::ground_free(&vars::apply(&value, &foreign)));
				}
				if proposal.is_empty() {
					continue;
				}
				if let Some(target) = target
					&& sym.var_slots.contains(&vars::slot_of_var_id(*target))
					&& !proposal.contains_key(target)
				{
					let value = vars::apply(emission, &bound);
					if !vars::occurs(*target, &value, &proposal) {
						proposal.insert(*target, vars::ground_free(&vars::apply(&value, &foreign)));
					}
				}
				out.push(proposal);
			}
		}
	}
	out
}

fn sibling_replay(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
	proposal: &Substitution,
) -> bool {
	let mut slots = 0usize;
	for (id, value) in proposal.iter() {
		if !vars::is_slot_var_id(*id) {
			continue;
		}
		let slot = vars::slot_of_var_id(*id);
		let Some(meta) = ps.meta.get(slot) else {
			return false;
		};
		let installed = match sym.var_terms.get(slot) {
			Some(Some(term)) => vars::apply(term, proposal),
			_ => value.clone(),
		};
		let siblings = crate::query::session_sibling_values(&meta.constant, km);
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
	ps: &PrincipalState,
	sym: &SymbolicState,
	binding: &Substitution,
) -> Vec<Value> {
	(0..ps.values.len())
		.filter(|&e| {
			!sym.is_var_slot(e)
				&& (!ps.meta[e].wire.is_empty() || ps.meta[e].constant.leaked)
				&& vars::contains_var(&sym.terms[e])
		})
		.map(|e| {
			crate::theory::reduce_once(&vars::ground_free(&vars::apply(&sym.terms[e], binding)))
		})
		.filter(|emitted| !vars::contains_var(emitted))
		.collect()
}

fn keyed_free(
	honest: &[Value],
	sym: &SymbolicState,
	proposal: &Substitution,
) -> Option<Substitution> {
	fill_aligned_with(honest, sym, proposal, &|honest| {
		crate::primitive::value_is_key_derivation(honest)
			.then(crate::primitive::attacker_public_key)
	})
}

fn preserved_free(
	honest: &[Value],
	sym: &SymbolicState,
	proposal: &Substitution,
	attacker: &AttackerState,
) -> Option<Substitution> {
	fill_aligned_with(honest, sym, proposal, &|honest| {
		if crate::primitive::value_is_key_derivation(honest) {
			return Some(crate::primitive::attacker_public_key());
		}
		let held = !honest.equivalent(&crate::value::value_nil(), true)
			&& attacker.knows(honest).is_some();
		held.then(|| honest.clone())
	})
}

type HeldShape = (PrimitiveId, usize, usize, u64);

fn held_shape(p: &Primitive) -> Option<HeldShape> {
	let first = p.arguments.first()?;
	Some((p.id, p.output, p.arguments.len(), first.hash_value()))
}

fn aligned_held_free(
	honest: &[Value],
	sym: &SymbolicState,
	proposals: &[Substitution],
	attacker: &AttackerState,
	protocol: &crate::hashing::TermSet,
) -> Vec<Substitution> {
	let mut index: IdMap<HeldShape, Vec<usize>> = IdMap::default();
	for (i, held) in attacker.known.iter().enumerate() {
		let Value::Primitive(h) = held else {
			continue;
		};
		if crate::primitive::primitive_is_core(h.id)
			|| h.arguments.len() < 2
			|| !protocol.contains(held)
		{
			continue;
		}
		if let Some(shape) = held_shape(h) {
			index.entry(shape).or_default().push(i);
		}
	}
	if index.is_empty() {
		return Vec::new();
	}
	let aligned = |occupant: &Value, held: &Value| -> bool {
		let (Value::Primitive(p), Value::Primitive(h)) = (occupant, held) else {
			return false;
		};
		p.id == h.id
			&& p.output == h.output
			&& p.arguments.len() == h.arguments.len()
			&& p.arguments
				.first()
				.zip(h.arguments.first())
				.is_some_and(|(a, b)| a.equivalent(b, true))
			&& !held.equivalent(occupant, true)
	};
	crate::parallel::map_ordered((0..proposals.len()).collect(), |at| {
		let proposal = &proposals[at];
		let positions = free_positions(honest, sym, proposal);
		let mut candidates: Vec<usize> = Vec::new();
		for (_, occupant) in &positions {
			let Value::Primitive(p) = occupant else {
				continue;
			};
			if let Some(bucket) = held_shape(p).and_then(|shape| index.get(&shape)) {
				candidates.extend(bucket);
			}
		}
		candidates.sort_unstable();
		candidates.dedup();
		let mut out = Vec::new();
		for i in candidates {
			let held = &attacker.known[i];
			if !positions
				.iter()
				.any(|(_, occupant)| aligned(occupant, held))
			{
				continue;
			}
			let mut filled = proposal.clone();
			for (var, occupant) in &positions {
				if !filled.contains_key(var) && aligned(occupant, held) {
					filled.insert(*var, held.clone());
				}
			}
			out.push(filled);
		}
		out
	})
	.into_iter()
	.flatten()
	.collect()
}

fn free_positions<'a>(
	honest: &'a [Value],
	sym: &SymbolicState,
	proposal: &Substitution,
) -> Vec<(ValueId, &'a Value)> {
	let mut out = Vec::new();
	for (at, &slot) in sym.var_slots.iter().enumerate() {
		if !proposal.contains_key(&vars::attacker_var_id(slot)) {
			continue;
		}
		let Some(term) = sym.var_terms.get(slot).and_then(Option::as_ref) else {
			continue;
		};
		let Some(honest) = honest.get(at) else {
			continue;
		};
		collect_free_positions(&vars::apply(term, proposal), honest, proposal, &mut out);
	}
	out
}

fn collect_free_positions<'a>(
	proposed: &Value,
	honest: &'a Value,
	proposal: &Substitution,
	out: &mut Vec<(ValueId, &'a Value)>,
) {
	out.extend(
		aligned_free_positions(proposed, honest).filter(|(id, _)| !proposal.contains_key(id)),
	);
}

fn aligned_free_positions<'a>(
	proposed: &Value,
	honest: &'a Value,
) -> impl Iterator<Item = (ValueId, &'a Value)> {
	let mut pending = vec![(proposed, honest)];
	let mut seen = IdSet::default();
	std::iter::from_fn(move || {
		while let Some((proposed, honest)) = pending.pop() {
			if !vars::contains_var(proposed) {
				continue;
			}
			match (proposed, honest) {
				(Value::Constant(c), _) if vars::is_free_var_id(c.id) => {
					return Some((c.id, honest));
				}
				(Value::Primitive(p), Value::Primitive(h))
					if p.id == h.id
						&& seen.insert((Arc::as_ptr(p) as usize, Arc::as_ptr(h) as usize)) =>
				{
					pending.extend(p.arguments.iter().zip(h.arguments.iter()).rev());
				}
				_ => {}
			}
		}
		None
	})
}

/// The honest term behind each variable slot, resolved once. `fill_aligned_with` is
/// called for every proposal and, for the aligned family, for every held term
/// besides, so resolving the whole trace inside that loop is the difference
/// between a constant factor and a multiplicative one.
pub(crate) fn honest_slot_terms(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
) -> Vec<Value> {
	sym.var_slots
		.iter()
		.map(|&slot| match ps.meta.get(slot) {
			Some(meta) => resolve_trace_constant(&meta.constant, km),
			None => crate::value::value_nil(),
		})
		.collect()
}

fn fill_aligned_with(
	honest: &[Value],
	sym: &SymbolicState,
	proposal: &Substitution,
	filler: &dyn Fn(&Value) -> Option<Value>,
) -> Option<Substitution> {
	let mut out = proposal.clone();
	let mut filled = false;
	for (at, &slot) in sym.var_slots.iter().enumerate() {
		if !proposal.contains_key(&vars::attacker_var_id(slot)) {
			continue;
		}
		let Some(term) = sym.var_terms.get(slot).and_then(Option::as_ref) else {
			continue;
		};
		let Some(honest) = honest.get(at) else {
			continue;
		};
		filled |= fill_free_positions(&vars::apply(term, proposal), honest, filler, &mut out);
	}
	filled.then_some(out)
}

fn fill_free_positions(
	proposed: &Value,
	honest: &Value,
	filler: &dyn Fn(&Value) -> Option<Value>,
	out: &mut Substitution,
) -> bool {
	let mut filled = false;
	for (id, honest) in aligned_free_positions(proposed, honest) {
		if !out.contains_key(&id)
			&& let Some(value) = filler(honest)
		{
			out.insert(id, value);
			filled = true;
		}
	}
	filled
}

pub(crate) fn leave_honest_slots(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
	proposal: Substitution,
) -> Substitution {
	let mut dropped: Vec<ValueId> = Vec::new();
	for &slot in &sym.var_slots {
		let id = vars::attacker_var_id(slot);
		let Some(term) = &sym.var_terms[slot] else {
			continue;
		};
		if !proposal.contains_key(&id) || slot >= ps.values.len() {
			continue;
		}
		let ground = vars::ground_free(&vars::apply(term, &proposal));
		if vars::contains_var(&ground)
			|| crate::solve::control::attacker_authored(&ground, slot, km, ps)
		{
			continue;
		}
		let referenced = proposal
			.iter()
			.any(|(other, value)| *other != id && vars::occurs(id, value, &proposal));
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

pub(crate) fn same_install_signature(left: &[(usize, Value)], right: &[(usize, Value)]) -> bool {
	left.len() == right.len()
		&& left
			.iter()
			.zip(right)
			.all(|((left_slot, left_value), (right_slot, right_value))| {
				left_slot == right_slot && left_value.equivalent(right_value, true)
			})
}

pub(crate) fn signature_hash(signature: &[(usize, Value)]) -> u64 {
	let mut acc: u64 = 0x9E37_79B9_7F4A_7C15;
	for (slot, value) in signature {
		acc = acc
			.rotate_left(13)
			.wrapping_add((*slot as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F))
			^ value.hash_value();
	}
	acc
}

fn goals_for_query(
	query: &Query,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
	deducer: &Deducer,
	base: &Substitution,
) -> Vec<Substitution> {
	match query.kind {
		QueryKind::Confidentiality => match slot_term(query.constants.first(), ps, sym) {
			Some(term) => deducer.solve(&term, base),
			None => Vec::new(),
		},
		QueryKind::Authentication => authentication_goals(query, km, ps, sym, deducer, base),
		QueryKind::Unlinkability => {
			let mut out = Vec::new();
			for c in &query.constants {
				let Some(term) = slot_term(Some(c), ps, sym) else {
					continue;
				};
				let Value::Primitive(p) = &term else {
					continue;
				};
				for arg in &p.arguments {
					if !crate::engine::unlink::depends_on_secret(arg, km) {
						continue;
					}
					out.extend(deducer.solve(arg, base));
				}
			}
			out
		}
		QueryKind::Equivalence => {
			let mut out = Vec::new();
			let terms: Vec<Value> = query
				.constants
				.iter()
				.filter_map(|c| slot_term(Some(c), ps, sym))
				.collect();
			for pair in terms.windows(2) {
				out.extend(diverge::solve_divergent(&pair[0], &pair[1], base));
			}
			out
		}
		QueryKind::Freshness => Vec::new(),
	}
}

fn authentication_goals(
	query: &Query,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
	deducer: &Deducer,
	base: &Substitution,
) -> Vec<Substitution> {
	if query.message.recipient != ps.id {
		return Vec::new();
	}
	let Some(c) = query.message.constants.first() else {
		return Vec::new();
	};
	let Some(slot) = ps.index_of(c) else {
		return Vec::new();
	};
	if !sym.is_var_slot(slot) {
		return Vec::new();
	}
	let Some(var_term) = &sym.var_terms[slot] else {
		return Vec::new();
	};
	let mut out = Vec::new();

	for shape in deducer.forgeable_shapes(sym, vars::attacker_var_id(slot)) {
		for candidate in deducer.solve(&shape, base) {
			let forged = vars::apply(&shape, &candidate);
			if vars::contains_var(&forged) {
				continue;
			}
			if let Some(bound) = matching::match_value(var_term, &forged, &candidate) {
				out.push(bound);
			}
		}
	}

	let honest = resolve_trace_constant(c, km);
	for candidate in deducer.solve(&honest, base) {
		if let Some(bound) = matching::match_value(var_term, &honest, &candidate) {
			out.push(bound);
		}
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

fn observed<T: Send, R: Send>(items: Vec<T>, f: impl Fn(T) -> R + Sync + Send) -> Vec<R> {
	crate::parallel::map_ordered(items, f)
}

fn sibling_flight_substitutions(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
) -> Vec<Substitution> {
	let mut widest = 0;
	for &slot in &sym.var_slots {
		if let Some(meta) = ps.meta.get(slot) {
			widest = widest.max(crate::query::session_sibling_values(&meta.constant, km).len());
		}
	}
	let mut out = Vec::new();
	for i in 0..widest {
		let mut flight = Substitution::default();
		for &slot in &sym.var_slots {
			let Some(meta) = ps.meta.get(slot) else {
				continue;
			};
			let siblings = crate::query::session_sibling_values(&meta.constant, km);
			if let Some(v) = siblings.get(i) {
				flight.insert(vars::attacker_var_id(slot), v.clone());
			}
		}
		if !flight.is_empty() {
			out.push(flight);
		}
	}
	out
}

fn lanes(count: usize) -> Vec<(u32, std::ops::Range<usize>)> {
	let width = vars::FREE_LANES as usize;
	let size = count.div_ceil(width).max(1);
	(0..count.div_ceil(size))
		.map(|lane| (lane as u32 + 1, lane * size..((lane + 1) * size).min(count)))
		.collect()
}

fn slot_candidates(
	attacker: &AttackerState,
	sym: &SymbolicState,
	deducer: &Deducer,
	protocol: &crate::hashing::TermSet,
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
			push_unique_value(&mut out, candidate.clone());
		}
	}

	let mut contexts = vec![Substitution::default()];
	if !blanket.is_empty() {
		contexts.push(blanket.clone());
	}
	for shape in deducer.forgeable_shapes(sym, vars::attacker_var_id(slot)) {
		for context in &contexts {
			for solution in deducer.solve(&shape, context) {
				let applied = vars::apply(&shape, &solution);
				for filler in [
					crate::value::value_nil(),
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

fn slot_term(c: Option<&Constant>, ps: &PrincipalState, sym: &SymbolicState) -> Option<Value> {
	let c = c?;
	let slot = ps.index_of(c)?;
	sym.terms.get(slot).cloned()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::{
		PRIM_CONCAT, PRIM_HASH, PRIM_PUBKEY, attacker_public_key, value_is_key_derivation,
	};
	use crate::testutil::{make_attacker_state, make_constant};
	use crate::value::value_nil;
	use vars::free_var;

	#[test]
	fn free_position_walks_visit_shared_term_pairs_once() {
		let mut proposed = free_var(0);
		let key = Value::primitive(PRIM_PUBKEY, vec![make_constant("free_dag_key")], 0);
		let mut honest = key.clone();
		for _ in 0..40 {
			proposed = Value::primitive(
				PRIM_HASH,
				vec![proposed.clone(), proposed.clone(), proposed],
				0,
			);
			honest = Value::primitive(PRIM_HASH, vec![honest.clone(), honest.clone(), honest], 0);
		}
		let mut positions = Vec::new();
		collect_free_positions(&proposed, &honest, &Substitution::default(), &mut positions);
		assert_eq!(positions.len(), 3);
		assert!(
			positions
				.iter()
				.all(|(id, value)| *id == free_var_id(0) && value.equivalent(&key, true))
		);
		let filled = keyed_positions(&proposed, &honest);
		assert_eq!(filled.len(), 1);
		assert!(filled[&free_var_id(0)].equivalent(&attacker_public_key(), true));
		assert_eq!(aligned_free_positions(&honest, &honest).count(), 0);
	}

	#[test]
	fn a_shared_proposal_keeps_distinct_honest_contexts() {
		let proposal = Value::primitive(PRIM_HASH, vec![free_var(0)], 0);
		let plain = make_constant("free_context_plain");
		let public = Value::primitive(PRIM_PUBKEY, vec![make_constant("free_context_key")], 0);
		let honest = Value::primitive(
			PRIM_CONCAT,
			vec![
				Value::primitive(PRIM_HASH, vec![plain.clone()], 0),
				Value::primitive(PRIM_HASH, vec![public.clone()], 0),
			],
			0,
		);
		let proposed = Value::primitive(PRIM_CONCAT, vec![proposal.clone(), proposal], 0);
		let positions: Vec<_> = aligned_free_positions(&proposed, &honest).collect();
		assert_eq!(positions.len(), 2);
		assert!(positions[0].1.equivalent(&plain, true));
		assert!(positions[1].1.equivalent(&public, true));
		let filled = keyed_positions(&proposed, &honest);
		assert!(filled[&free_var_id(0)].equivalent(&attacker_public_key(), true));
	}

	#[test]
	fn blocking_slot_collection_visits_shared_checks_once() {
		let x = vars::attacker_var(0, "dag_block_x");
		let y = vars::attacker_var(1, "dag_block_y");
		let check = Value::primitive(
			crate::primitive::PRIM_AEAD_DEC,
			vec![x, value_nil(), y, value_nil()],
			0,
		);
		let mut term = check.clone();
		for _ in 0..40 {
			term = Value::primitive(PRIM_HASH, vec![term.clone(), term.clone(), term], 0);
		}
		let sym = SymbolicState {
			terms: vec![term.clone(), check, term],
			var_slots: vec![0, 1],
			var_terms: vec![],
		};
		assert_eq!(slots_blocking_reduction(&sym), vec![vec![0, 1]]);
	}

	fn bundle(second: Value) -> Value {
		Value::primitive(PRIM_CONCAT, vec![make_constant("kfp_tag"), second], 0)
	}

	fn keyed_positions(proposed: &Value, honest: &Value) -> Substitution {
		let mut out = Substitution::default();
		fill_free_positions(
			proposed,
			honest,
			&|honest| value_is_key_derivation(honest).then(attacker_public_key),
			&mut out,
		);
		out
	}

	fn preserved_positions(proposed: &Value, honest: &Value, held: Vec<Value>) -> Substitution {
		let attacker = make_attacker_state(held);
		let mut out = Substitution::default();
		fill_free_positions(
			proposed,
			honest,
			&|honest| {
				if value_is_key_derivation(honest) {
					return Some(attacker_public_key());
				}
				let held =
					!honest.equivalent(&value_nil(), true) && attacker.knows(honest).is_some();
				held.then(|| honest.clone())
			},
			&mut out,
		);
		out
	}

	#[test]
	fn a_free_position_beside_a_swapped_key_can_keep_the_honest_value() {
		let nonce = make_constant("kfp_nonce");
		let honest = Value::primitive(
			PRIM_CONCAT,
			vec![
				make_constant("kfp_tag2"),
				Value::primitive(PRIM_PUBKEY, vec![make_constant("kfp_x")], 0),
				nonce.clone(),
			],
			0,
		);
		let proposed = Value::primitive(
			PRIM_CONCAT,
			vec![make_constant("kfp_tag2"), free_var(0), free_var(1)],
			0,
		);
		let out = preserved_positions(&proposed, &honest, vec![nonce.clone()]);
		assert!(
			out[&free_var_id(0)].equivalent(&attacker_public_key(), true),
			"the key position is still the attacker's own"
		);
		assert!(
			out[&free_var_id(1)].equivalent(&nonce, true),
			"a forgery that must preserve one field while replacing its sibling is only \
			 expressible if the honest value the attacker holds is offered at the position \
			 beside the swapped key"
		);
	}

	#[test]
	fn a_free_position_whose_honest_value_the_attacker_lacks_is_left_alone() {
		let secret = make_constant("kfp_secret");
		let honest = bundle(secret);
		assert!(
			preserved_positions(&bundle(free_var(0)), &honest, vec![]).is_empty(),
			"preserving a value the attacker cannot build would propose a term it has no \
			 way to construct, which the validator would reject anyway"
		);
	}

	#[test]
	fn a_free_position_the_protocol_fills_with_a_key_gets_the_attackers_own() {
		let honest = bundle(Value::primitive(
			PRIM_PUBKEY,
			vec![make_constant("kfp_a")],
			0,
		));
		let out = keyed_positions(&bundle(free_var(0)), &honest);
		assert!(
			out[&free_var_id(0)].equivalent(&attacker_public_key(), true),
			"the protocol puts a public key in this position, so the attacker must be \
			 offered its own there and not only nil"
		);
	}

	#[test]
	fn a_free_position_the_protocol_fills_with_a_constant_is_left_alone() {
		let honest = bundle(make_constant("kfp_plain"));
		assert!(
			keyed_positions(&bundle(free_var(0)), &honest).is_empty(),
			"keying a position the protocol fills with a plain value overwrites the tag a \
			 recipient asserts on, which halts it before the attack it is meant to reach"
		);
	}

	#[test]
	fn a_bound_position_is_never_rekeyed() {
		let honest = bundle(Value::primitive(
			PRIM_PUBKEY,
			vec![make_constant("kfp_b")],
			0,
		));
		assert!(keyed_positions(&bundle(value_nil()), &honest).is_empty());
	}

	#[test]
	fn a_proposal_shaped_unlike_the_honest_term_is_declined() {
		let honest = Value::primitive(PRIM_PUBKEY, vec![make_constant("kfp_c")], 0);
		assert!(keyed_positions(&bundle(free_var(0)), &honest).is_empty());
	}

	#[test]
	fn colliding_terms_have_distinct_install_signatures() {
		fn constant(name: &str, id: ValueId) -> Value {
			Value::Constant(Constant {
				name: std::sync::Arc::from(name),
				id,
				..Default::default()
			})
		}

		let left = Value::primitive(
			PRIM_HASH,
			vec![constant("sig_a", 10), constant("sig_b", 100)],
			0,
		);
		let right = Value::primitive(
			PRIM_HASH,
			vec![constant("sig_c", 11), constant("sig_d", 69)],
			0,
		);
		let left = vec![(7, left)];
		let right = vec![(7, right)];
		assert_eq!(signature_hash(&left), signature_hash(&right));
		assert!(!same_install_signature(&left, &right));
	}

	fn free_var_id(n: u32) -> ValueId {
		let Value::Constant(c) = free_var(n) else {
			unreachable!()
		};
		c.id
	}
}
