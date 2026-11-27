/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::deduce::Deducer;
use super::matching::unifiers;
use super::symbolic::SymbolicState;
use super::vars::Substitution;
use super::{deduce, diverge, matching, symbolic, vars};
use crate::engine::program::Program;
use crate::protocol::trace::resolve_trace_constant;
use crate::protocol::{ProtocolTrace, SlotIdx};
use crate::syntax::{PrincipalId, Query, QueryKind};
use crate::term::{Constant, PrimitiveId, Value, VariableId};

type Wanted = Vec<(Value, Option<VariableId>)>;

pub(super) fn oracle_input_goals(
	program: &Program,
	km: &ProtocolTrace,
	principal: PrincipalId,
	sym: &SymbolicState,
	deducer: &Deducer,
) -> Vec<Substitution> {
	let emissions: Vec<&Value> = km
		.slots
		.indices()
		.filter(|&e| {
			let slot = &km.slots[e];
			slot.creator == principal && (slot.sent_from(principal) || slot.constant.leaked)
		})
		.map(|e| &sym.terms[e])
		.filter(|term| vars::contains_var(term))
		.collect();
	if emissions.is_empty() {
		return Vec::new();
	}
	let mut wanted: Wanted = Vec::new();
	let mut foreign: Substitution = Substitution::default();
	let mut kept: Substitution = Substitution::default();
	let mut pins: Vec<Substitution> = Vec::new();
	for &other in &km.principal_ids {
		pins.extend(check_shapes(
			program,
			km,
			other,
			sym,
			deducer,
			&mut wanted,
			(&mut foreign, &mut kept),
		));
	}
	if !kept.is_empty() {
		pins.push(kept);
	}
	let foreign = vars::dedupe(
		std::iter::once(foreign.clone())
			.chain(pins.into_iter().map(|pin| {
				let mut pinned = foreign.clone();
				pinned.extend(pin);
				pinned
			}))
			.collect(),
	);
	let nested = nested_shapes(&wanted, &emissions);
	wanted.extend(nested);
	let empty = Substitution::default();
	let mut out: Vec<Substitution> = Vec::new();
	for emission in emissions {
		for (shape, target) in &wanted {
			let mut bounds: Vec<Substitution> = unifiers(emission, shape, &empty).collect();
			if bounds.is_empty() {
				bounds = deducer.invert_into_revealed(emission, shape);
			}
			for bound in &bounds {
				for bound in completed(program, km, sym, deducer, bound) {
					out.extend(foreign.iter().filter_map(|foreign| {
						oracle_proposal(sym, emission, target.as_ref(), &bound, foreign)
					}));
				}
			}
		}
	}
	out
}

fn completed(
	program: &Program,
	km: &ProtocolTrace,
	sym: &SymbolicState,
	deducer: &Deducer,
	bound: &Substitution,
) -> Vec<Substitution> {
	let nil = unbound_inputs(sym, bound);
	let empty = Substitution::default();
	let mut out = vec![bound.clone()];
	for (id, value) in bound {
		if sym.term_of(id).is_none()
			|| !(nil.keys().any(|local| vars::occurs(local, value, &empty))
				|| tied(&vars::apply(value, bound)))
		{
			continue;
		}
		let filled = vars::ground_free(&vars::apply(&vars::apply(value, bound), &nil));
		let late = sym.installed_at(id).iter().any(|&run| {
			disclosed_after(km, program.runs[run].id, vars::slot_of_var_id(id), &filled)
		});
		if !deducer.holds(&filled) || late {
			out.extend(deducer.held_matches(value, bound));
		}
	}
	out
}

fn unbound_inputs(sym: &SymbolicState, bound: &Substitution) -> Substitution {
	let empty = Substitution::default();
	sym.inputs()
		.map(|(id, _, _)| id)
		.filter(|id| {
			!bound.contains_key(id) && bound.values().any(|value| vars::occurs(id, value, &empty))
		})
		.map(|id| (id, crate::term::value_nil()))
		.collect()
}

fn disclosed_after(km: &ProtocolTrace, principal: PrincipalId, slot: SlotIdx, v: &Value) -> bool {
	let Some(at) = km.slots[slot]
		.sent_by
		.iter()
		.filter(|event| event.recipient == principal)
		.map(|event| event.declared_at)
		.min()
	else {
		return false;
	};
	v.constant_leaves().any(|leaf| {
		let sends = km.index_of(leaf).into_iter().flat_map(|disclosed| {
			km.slots[disclosed]
				.sent_by
				.iter()
				.map(|event| (event.sender, event.declared_at))
		});
		let leaks = km
			.leaks
			.iter()
			.filter(|event| event.constant_id == leaf.id)
			.map(|event| (event.principal_id, event.declared_at));
		let mut disclosures = sends.chain(leaks).peekable();
		disclosures.peek().is_some()
			&& disclosures.all(|(by, declared)| by == principal && declared > at)
	})
}

fn push_wanted(wanted: &mut Wanted, shape: Value, target: Option<VariableId>) {
	if !wanted
		.iter()
		.any(|(w, t)| *t == target && w.equivalent(&shape, true))
	{
		wanted.push((shape, target));
	}
}

fn check_shapes(
	program: &Program,
	km: &ProtocolTrace,
	principal: PrincipalId,
	sym: &SymbolicState,
	deducer: &Deducer,
	wanted: &mut Wanted,
	(foreign, kept): (&mut Substitution, &mut Substitution),
) -> Vec<Substitution> {
	let attacker = deducer.attacker();
	let mut pins = Vec::new();
	let slot_var = |v: &Value| vars::as_var(v).filter(vars::is_slot_var_id);
	let other = symbolic::View::of(program, km, principal, attacker.current_phase)
		.within(sym)
		.build();
	for (id, slot, _) in other.inputs() {
		if sym.term_of(&id).is_some() {
			continue;
		}
		let honest = resolve_trace_constant(&km.slots[slot].constant, km);
		let filler = if crate::primitive::value_is_key_derivation(&honest) {
			crate::primitive::attacker_public_key()
		} else {
			crate::term::value_nil()
		};
		foreign.insert(id, filler);
	}
	let inverter = deduce::Deducer::with_basis(
		km,
		deducer.capabilities(),
		attacker,
		&other,
		&deduce::Arities::default(),
		Substitution::default(),
	)
	.in_scope(deducer.fresh_scope());
	for c in km.slots.indices() {
		if km.slots[c].creator != principal {
			continue;
		}
		let Value::Primitive(prim) = &other.terms[c] else {
			continue;
		};
		let opened = crate::primitive::rewrite_rule(prim.id).is_some_and(|rule| {
			prim.arguments
				.get(rule.from)
				.is_some_and(vars::contains_var)
		});
		if !(prim.instance_check || opened) || !vars::contains_var(&other.terms[c]) {
			continue;
		}
		for bound in inverter.equality_shapes(prim) {
			let mut pin = Substitution::default();
			for (id, _, _) in other.inputs() {
				let Some(value) = bound.get(&id) else {
					continue;
				};
				let shape = vars::apply(value, &bound);
				if sym.term_of(&id).is_none() && !vars::contains_var(&shape) {
					pin.insert(id.clone(), shape.clone());
				}
				if matches!(shape, Value::Primitive(_)) {
					push_wanted(wanted, shape, Some(id));
				}
			}
			if !pin.is_empty() {
				pins.push(pin);
			}
		}
		let shapes: Wanted = match crate::primitive::rewrite_rule(prim.id) {
			Some(rule) => {
				let target = prim.arguments.get(rule.from).and_then(slot_var);
				let shapes = deduce::rewrite_shapes_from(prim, rule, |_| deducer.fresh_var(), true);
				if prim.instance_check
					&& shapes
						.iter()
						.any(|shape| !deducer.holds(&grounded(&vars::apply(shape, foreign))))
				{
					let mut read = Vec::new();
					vars::collect_vars(&other.terms[c], &mut read);
					for id in read {
						if other.term_of(&id).is_none() || sym.term_of(&id).is_some() {
							continue;
						}
						let slot = vars::slot_of_var_id(&id);
						let honest = resolve_trace_constant(&km.slots[slot].constant, km);
						if !crate::primitive::value_is_key_derivation(&honest)
							&& deducer.holds(&honest)
						{
							kept.insert(id, honest);
						}
					}
				}
				shapes
					.into_iter()
					.map(|shape| (shape, target.clone()))
					.collect()
			}
			None if prim.instance_check
				&& crate::primitive::is_core(prim.id)
				&& prim.arguments.len() == 2 =>
			{
				vec![
					(prim.arguments[0].clone(), slot_var(&prim.arguments[1])),
					(prim.arguments[1].clone(), slot_var(&prim.arguments[0])),
				]
			}
			None => Vec::new(),
		};
		for (shape, target) in shapes {
			push_wanted(wanted, shape, target);
		}
	}
	pins
}

fn tied(v: &Value) -> bool {
	let mut seen: Vec<&VariableId> = Vec::new();
	crate::term::subterms(v).any(|term| match term {
		Value::Variable(id) if vars::is_free_var_id(id) => {
			let again = seen.contains(&id);
			seen.push(id);
			again
		}
		_ => false,
	})
}

fn grounded(v: &Value) -> Value {
	let mut ids = Vec::new();
	vars::collect_vars(v, &mut ids);
	let nil: Substitution = ids
		.into_iter()
		.map(|id| (id, crate::term::value_nil()))
		.collect();
	vars::apply(v, &nil)
}

fn nested_shapes(wanted: &Wanted, emissions: &[&Value]) -> Wanted {
	let heads: Vec<(PrimitiveId, usize)> = emissions
		.iter()
		.filter_map(|emitted| match emitted {
			Value::Primitive(p) => Some((p.id, p.arguments.len())),
			Value::Constant(_) | Value::Variable(_) => None,
		})
		.collect();
	let mut nested: Wanted = Vec::new();
	for (shape, _) in wanted {
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
	nested
}

fn oracle_proposal(
	sym: &SymbolicState,
	emission: &Value,
	target: Option<&VariableId>,
	bound: &Substitution,
	foreign: &Substitution,
) -> Option<Substitution> {
	let empty = Substitution::default();
	let local = unbound_inputs(sym, bound);
	let mut proposal = Substitution::default();
	for (id, _, _) in sym.inputs() {
		if !bound.contains_key(&id) && !local.contains_key(&id) {
			continue;
		}
		let value = vars::apply(&Value::Variable(id.clone()), bound);
		let value = vars::apply(&value, &local);
		if vars::as_var(&value).as_ref() == Some(&id) || vars::occurs(&id, &value, &empty) {
			continue;
		}
		proposal.insert(id, vars::apply(&value, foreign));
	}
	if proposal.is_empty() {
		return None;
	}
	if let Some(target) = target
		&& sym.term_of(target).is_some()
		&& !proposal.contains_key(target)
	{
		let value = vars::apply(emission, bound);
		if !vars::occurs(target, &value, &proposal) {
			proposal.insert(target.clone(), vars::apply(&value, foreign));
		}
	}
	Some(proposal)
}

pub(super) fn goals_for_query(
	query: &Query,
	km: &ProtocolTrace,
	principal: PrincipalId,
	sym: &SymbolicState,
	deducer: &Deducer,
	base: &Substitution,
) -> Vec<Substitution> {
	match query.kind {
		QueryKind::Confidentiality => match slot_term(query.constants.first(), km, sym) {
			Some(term) => deducer.solve(&term, base),
			None => Vec::new(),
		},
		QueryKind::Authentication => authentication_goals(query, km, principal, sym, deducer, base),
		QueryKind::Unlinkability => {
			let mut out = Vec::new();
			for c in &query.constants {
				let Some(term) = slot_term(Some(c), km, sym) else {
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
				.filter_map(|c| slot_term(Some(c), km, sym))
				.collect();
			for pair in terms.windows(2) {
				out.extend(diverge::solve_divergent(km, sym, &pair[0], &pair[1], base));
			}
			out
		}
		QueryKind::Freshness => Vec::new(),
	}
}

fn authentication_goals(
	query: &Query,
	km: &ProtocolTrace,
	principal: PrincipalId,
	sym: &SymbolicState,
	deducer: &Deducer,
	base: &Substitution,
) -> Vec<Substitution> {
	if query.message.recipient != principal {
		return Vec::new();
	}
	let Some(c) = query.message.constants.first() else {
		return Vec::new();
	};
	let Some(slot) = km.index_of(c) else {
		return Vec::new();
	};
	if !sym.is_var_slot(slot) {
		return Vec::new();
	}
	let Some(var_term) = &sym.var_terms[slot] else {
		return Vec::new();
	};
	let mut out = Vec::new();

	for shape in deducer.forgeable_shapes(sym, &vars::attacker_var_id(slot)) {
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

fn slot_term(c: Option<&Constant>, km: &ProtocolTrace, sym: &SymbolicState) -> Option<Value> {
	let c = c?;
	let slot = km.index_of(c)?;
	sym.terms.get(slot).cloned()
}
