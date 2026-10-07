/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::symbolic::SymbolicState;
use super::vars;
use super::vars::Substitution;
use crate::primitive::CapabilityIndex;
use crate::protocol::ProtocolTrace;
use crate::protocol::trace::resolve_trace_constant;
use crate::term::{Constant, Primitive, PrimitiveId, Value, ValueId, VariableId};
use crate::theory::AttackerState;
use crate::util::{IdMap, IdSet};

pub(super) fn keyed_free(
	honest: &[Value],
	sym: &SymbolicState,
	proposal: &Substitution,
) -> Option<Substitution> {
	fill_aligned_with(honest, sym, proposal, &|honest| {
		crate::primitive::value_is_key_derivation(honest)
			.then(crate::primitive::attacker_public_key)
	})
}

pub(super) fn preserved_free(
	honest: &[Value],
	sym: &SymbolicState,
	proposal: &Substitution,
	attacker: &AttackerState,
	capabilities: &CapabilityIndex,
) -> Option<Substitution> {
	fill_aligned_with(honest, sym, proposal, &|honest| {
		let held = !honest.equivalent(&crate::term::value_nil(), true)
			&& (attacker.knows(honest).is_some()
				|| crate::theory::obtainable(honest, capabilities, attacker));
		if held {
			return Some(honest.clone());
		}
		crate::primitive::value_is_key_derivation(honest)
			.then(crate::primitive::attacker_public_key)
	})
}

type HeldShape = (PrimitiveId, usize, usize, u64);

fn held_shape(p: &Primitive) -> Option<HeldShape> {
	let first = p.arguments.first()?;
	Some((p.id, p.output, p.arguments.len(), first.hash_value()))
}

pub(super) fn aligned_held_free(
	honest: &[Value],
	sym: &SymbolicState,
	proposals: &[Substitution],
	attacker: &AttackerState,
	protocol: &crate::term::hashing::TermSet,
) -> Vec<Substitution> {
	let mut index: IdMap<HeldShape, Vec<usize>> = IdMap::default();
	for (i, held) in attacker.known.iter().enumerate() {
		let Value::Primitive(h) = held else {
			continue;
		};
		if crate::primitive::is_core(h.id) || h.arguments.len() < 2 || !protocol.contains(held) {
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
	crate::util::parallel::map_ordered((0..proposals.len()).collect(), |at| {
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
					filled.insert(var.clone(), held.clone());
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

/// Positions a reuse rule pins, as the protocol actually fills them: the pairs
/// `(primitive, argument, constant)` where a collision between two applications
/// is what the rule's `fixed` list is about. Offering a held constant anywhere
/// else is what makes this family a combinatorial blow-up rather than a search.
fn reuse_slots(protocol: &crate::term::hashing::TermSet) -> Vec<(PrimitiveId, usize, ValueId)> {
	let mut out: Vec<(PrimitiveId, usize, ValueId)> = Vec::new();
	for term in protocol.iter() {
		for sub in crate::term::subterms(term) {
			let Value::Primitive(p) = sub else {
				continue;
			};
			let Some(rule) = crate::primitive::reuse_rule(p.id) else {
				continue;
			};
			for &at in &rule.fixed {
				if let Some(Value::Constant(c)) = p.arguments.get(at) {
					out.push((p.id, at, c.id));
				}
			}
		}
	}
	out.sort_unstable();
	out.dedup();
	out
}

pub(super) fn swapped_free(
	honest: &[Value],
	sym: &SymbolicState,
	proposals: &[Substitution],
	attacker: &AttackerState,
	protocol: &crate::term::hashing::TermSet,
) -> Vec<Substitution> {
	let slots = reuse_slots(protocol);
	if slots.is_empty() {
		return Vec::new();
	}
	let held: Vec<&Value> = attacker
		.known
		.iter()
		.filter(|v| match v {
			Value::Constant(c) => !c.is_nil() && slots.iter().any(|(_, _, id)| *id == c.id),
			_ => false,
		})
		.collect();
	if held.is_empty() {
		return Vec::new();
	}
	let collides = |a: &Constant, b: &Constant| {
		slots.iter().any(|(p, at, id)| {
			*id == a.id
				&& slots
					.iter()
					.any(|(q, other, id)| id == &b.id && q == p && other == at)
		})
	};
	crate::util::parallel::map_ordered((0..proposals.len()).collect(), |at| {
		let proposal = &proposals[at];
		let mut out = Vec::new();
		for (var, occupant) in free_positions(honest, sym, proposal) {
			let Value::Constant(occupant) = occupant else {
				continue;
			};
			if occupant.is_nil() {
				continue;
			}
			for candidate in &held {
				let Value::Constant(c) = candidate else {
					continue;
				};
				if c.id == occupant.id || !collides(c, occupant) {
					continue;
				}
				let mut filled = proposal.clone();
				filled.insert(var.clone(), (*candidate).clone());
				out.push(filled);
			}
		}
		out
	})
	.into_iter()
	.flatten()
	.collect()
}

fn proposed_terms<'h, 's>(
	honest: &'h [Value],
	sym: &'s SymbolicState,
	proposal: &'s Substitution,
) -> impl Iterator<Item = (Value, &'h Value)> {
	sym.variables()
		.zip(honest)
		.filter(|((slot, _), _)| proposal.contains_key(&vars::attacker_var_id(*slot)))
		.map(|((_, term), honest)| (vars::apply(term, proposal), honest))
}

fn free_positions<'a>(
	honest: &'a [Value],
	sym: &SymbolicState,
	proposal: &Substitution,
) -> Vec<(VariableId, &'a Value)> {
	let mut out = Vec::new();
	for (proposed, honest) in proposed_terms(honest, sym, proposal) {
		collect_free_positions(&proposed, honest, proposal, &mut out);
	}
	out
}

pub(super) fn collect_free_positions<'a>(
	proposed: &Value,
	honest: &'a Value,
	proposal: &Substitution,
	out: &mut Vec<(VariableId, &'a Value)>,
) {
	out.extend(
		aligned_free_positions(proposed, honest).filter(|(id, _)| !proposal.contains_key(id)),
	);
}

pub(super) fn aligned_free_positions<'a>(
	proposed: &Value,
	honest: &'a Value,
) -> impl Iterator<Item = (VariableId, &'a Value)> {
	let mut pending = vec![(proposed, honest)];
	let mut seen = IdSet::default();
	std::iter::from_fn(move || {
		while let Some((proposed, honest)) = pending.pop() {
			if !vars::contains_var(proposed) {
				continue;
			}
			match (proposed, honest) {
				(Value::Variable(id), _) if vars::is_free_var_id(id) => {
					return Some((id.clone(), honest));
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
pub(crate) fn honest_slot_terms(km: &ProtocolTrace, sym: &SymbolicState) -> Vec<Value> {
	sym.var_slots()
		.map(|slot| match km.slots.get(slot) {
			Some(trace_slot) => resolve_trace_constant(&trace_slot.constant, km),
			None => crate::term::value_nil(),
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
	for (proposed, honest) in proposed_terms(honest, sym, proposal) {
		filled |= fill_free_positions(&proposed, honest, filler, &mut out);
	}
	filled.then_some(out)
}

pub(super) fn fill_free_positions(
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
