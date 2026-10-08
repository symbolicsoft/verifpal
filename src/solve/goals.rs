/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::deduce::Deducer;
use super::matching::unifiers;
use super::symbolic::SymbolicState;
use super::vars::Substitution;
use super::{deduce, diverge, matching, symbolic, vars};
use crate::protocol::ProtocolTrace;
use crate::protocol::trace::resolve_trace_constant;
use crate::syntax::{PrincipalId, Query, QueryKind};
use crate::term::{Constant, PrimitiveId, Value, VariableId};
use crate::theory::AttackerState;

type Wanted = Vec<(Value, Option<VariableId>)>;

pub(super) fn oracle_input_goals(
	km: &ProtocolTrace,
	principal: PrincipalId,
	sym: &SymbolicState,
	attacker: &AttackerState,
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
	for &other in &km.principal_ids {
		check_shapes(km, other, sym, attacker, deducer, &mut wanted, &mut foreign);
	}
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
			out.extend(bounds.iter().filter_map(|bound| {
				oracle_proposal(sym, emission, target.as_ref(), bound, &foreign)
			}));
		}
	}
	out
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
	km: &ProtocolTrace,
	principal: PrincipalId,
	sym: &SymbolicState,
	attacker: &AttackerState,
	deducer: &Deducer,
	wanted: &mut Wanted,
	foreign: &mut Substitution,
) {
	let slot_var = |v: &Value| vars::as_var(v).filter(vars::is_slot_var_id);
	let controllable = crate::solve::control::Controllable::of(km, principal, attacker);
	let other = symbolic::build(&controllable, km, principal, attacker);
	for slot in other.var_slots() {
		if sym.is_var_slot(slot) {
			continue;
		}
		let honest = resolve_trace_constant(&km.slots[slot].constant, km);
		let filler = if crate::primitive::value_is_key_derivation(&honest) {
			crate::primitive::attacker_public_key()
		} else {
			crate::term::value_nil()
		};
		foreign.insert(vars::attacker_var_id(slot), filler);
	}
	let inverter = deduce::Deducer::with_basis(
		km,
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
		if !prim.instance_check || !vars::contains_var(&other.terms[c]) {
			continue;
		}
		for bound in inverter.equality_shapes(prim) {
			for slot in other.var_slots() {
				let id = vars::attacker_var_id(slot);
				let Some(value) = bound.get(&id) else {
					continue;
				};
				let shape = vars::apply(value, &bound);
				if matches!(shape, Value::Primitive(_)) {
					push_wanted(wanted, shape, Some(id));
				}
			}
		}
		let shapes: Wanted = match crate::primitive::rewrite_rule(prim.id) {
			Some(rule) => {
				let target = prim.arguments.get(rule.from).and_then(slot_var);
				deduce::rewrite_shapes_from(prim, rule, |_| deducer.fresh_var(), true)
					.into_iter()
					.map(|shape| (shape, target.clone()))
					.collect()
			}
			None if crate::primitive::is_core(prim.id) && prim.arguments.len() == 2 => {
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
	let mut local: Substitution = Substitution::default();
	for slot in sym.var_slots() {
		let id = vars::attacker_var_id(slot);
		if bound.contains_key(&id) {
			continue;
		}
		if bound.values().any(|value| vars::occurs(&id, value, &empty)) {
			local.insert(id, crate::term::value_nil());
		}
	}
	let mut proposal = Substitution::default();
	for slot in sym.var_slots() {
		let id = vars::attacker_var_id(slot);
		if !bound.contains_key(&id) && !local.contains_key(&id) {
			continue;
		}
		let value = vars::apply(&vars::attacker_var(slot), bound);
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
		&& sym.is_var_slot(vars::slot_of_var_id(target))
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
) -> Vec<Substitution> {
	let base = &Substitution::default();
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
