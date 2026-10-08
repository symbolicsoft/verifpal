/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::{Deducer, check_passes, refine_check};
use crate::primitive::{RewriteRule, rewrite_rule};
use crate::protocol::ProtocolTrace;
use crate::protocol::SlotIdx;
use crate::solve::symbolic::SymbolicState;
use crate::solve::vars::{Distinct, Substitution, apply, as_var, contains_var, dedupe};
use crate::syntax::{PrincipalId, Query, QueryKind};
use crate::term::equivalence::equivalent_primitives;
use crate::term::{Primitive, Value};
use crate::util::{IdMap, IdSet};

pub(super) fn constraint_sets(
	queries: &[Query],
	km: &ProtocolTrace,
	sym: &SymbolicState,
) -> Vec<Vec<SlotIdx>> {
	let mut checks: IdMap<PrincipalId, Vec<SlotIdx>> = IdMap::default();
	for (slot, trace_slot) in km.slots.iter_enumerated() {
		if let Value::Primitive(p) = &trace_slot.initial_value
			&& p.instance_check
		{
			checks.entry(trace_slot.creator).or_default().push(slot);
		}
	}
	let mut endpoints: Vec<_> = checks
		.iter()
		.filter_map(|(owner, slots)| {
			slots.last().map(|slot| {
				(
					*owner,
					(km.slots[*slot].declared_at, Some(*slot)),
					Some(*slot),
				)
			})
		})
		.collect();
	for (index, slot) in km.slots.iter_enumerated() {
		endpoints.extend(
			slot.sent_by
				.iter()
				.map(|event| (event.sender, (event.declared_at, None), Some(index))),
		);
	}
	endpoints.extend(km.leaks.iter().map(|event| {
		(
			event.principal_id,
			(event.declared_at, None),
			km.index.get(&event.constant_id).copied(),
		)
	}));
	for query in queries {
		for constant in query.constants.iter().chain(&query.message.constants) {
			if let Some(slot) = km.index_of(constant) {
				endpoints.push((
					km.slots[slot].creator,
					(km.slots[slot].declared_at, Some(slot)),
					Some(slot),
				));
				if !matches!(query.kind, QueryKind::Authentication | QueryKind::Freshness) {
					continue;
				}
				for (&owner, owned) in &checks {
					if owner == km.slots[slot].creator {
						continue;
					}
					for &check in owned {
						if crate::engine::judgment::mentions(
							km,
							&km.slots[check].initial_value,
							constant.id,
							owner,
							&mut Vec::new(),
						) {
							endpoints.push((
								owner,
								(km.slots[check].declared_at, Some(check)),
								Some(check),
							));
						}
					}
				}
			}
		}
	}
	endpoints.sort_unstable();
	endpoints.dedup();
	let mut groups = Vec::new();
	for (owner, at, target) in endpoints {
		let mut pending: Vec<_> = checks
			.get(&owner)
			.into_iter()
			.flatten()
			.copied()
			.filter(|slot| (km.slots[*slot].declared_at, Some(*slot)) <= at)
			.collect();
		pending.extend(target);
		let mut visited = IdSet::default();
		let mut needed = IdSet::default();
		while let Some(slot) = pending.pop() {
			if !visited.insert(slot) || sym.is_var_slot(slot) {
				continue;
			}
			let trace_slot = &km.slots[slot];
			if let Value::Primitive(p) = &trace_slot.initial_value
				&& crate::primitive::is_projection(p.id)
			{
				needed.insert(slot);
			}
			for &check in checks.get(&trace_slot.creator).into_iter().flatten() {
				if check <= slot {
					needed.insert(check);
					if check != slot {
						pending.push(check);
					}
				}
			}
			for constant in trace_slot.initial_value.constant_leaves() {
				if let Some(dependency) = km.index_of(constant) {
					pending.push(dependency);
				}
			}
		}
		let mut needed: Vec<_> = needed.into_iter().filter(|&slot| {
			matches!(&sym.terms[slot], Value::Primitive(p) if (p.instance_check || crate::primitive::is_projection(p.id)) && p.arguments.iter().any(contains_var))
		}).collect();
		needed.sort_unstable();
		if !needed.is_empty() && !groups.contains(&needed) {
			groups.push(needed);
		}
	}
	groups
}

fn widest_checked_projections(mut checked: Vec<Primitive>) -> Vec<Primitive> {
	let mut widest: Vec<Primitive> = Vec::new();
	for p in checked
		.iter()
		.filter(|p| crate::primitive::is_projection(p.id))
	{
		match widest.iter_mut().find(|q| {
			q.arguments
				.first()
				.zip(p.arguments.first())
				.is_some_and(|(a, b)| a.equivalent(b, true))
		}) {
			Some(existing) => {
				if p.output > existing.output {
					*existing = p.clone();
				}
			}
			None => widest.push(p.clone()),
		}
	}
	checked.retain(|p| {
		!crate::primitive::is_projection(p.id)
			|| widest.iter().any(|q| equivalent_primitives(q, p, true))
	});
	checked
}

pub(super) fn combine(left: &[Substitution], right: &[Substitution]) -> Vec<Substitution> {
	let mut out = Vec::new();
	for a in left {
		for b in right {
			out.extend(crate::solve::matching::merge(a, b));
		}
	}
	dedupe(out)
}

impl<'a> Deducer<'a> {
	pub(crate) fn constraint_goals(
		&self,
		queries: &[Query],
		km: &ProtocolTrace,
		sym: &SymbolicState,
	) -> Vec<Substitution> {
		let base = &Substitution::default();
		let groups = constraint_sets(queries, km, sym);
		let debug = crate::solve::debugging();
		let mut out = Vec::new();
		let mut combined = vec![base.clone()];
		for slots in groups {
			if debug {
				eprintln!("[search] constraints {:?}", slots);
			}
			let checked: Vec<_> = slots
				.iter()
				.filter_map(|&slot| sym.terms[slot].as_primitive().cloned())
				.collect();
			let checked = widest_checked_projections(checked);
			let mut frontier = vec![base.clone()];
			let mut seen = Distinct::default();
			loop {
				let mut changed = false;
				for (index, p) in checked.iter().enumerate() {
					if debug {
						eprintln!("[search] constraint {index}: {} bindings", frontier.len());
					}
					let mut next = Vec::new();
					for candidate in frontier {
						let refined = refine_check(p, &candidate);
						if check_passes(&refined) {
							next.push(candidate);
							continue;
						}
						if !refined.arguments.iter().any(contains_var) {
							if crate::primitive::check_key(&refined)
								.is_some_and(|key| self.obtainable(&key))
							{
								next.push(candidate);
							}
							continue;
						}
						let solutions = self.check_equations(&refined, &candidate);
						if solutions.is_empty() {
							next.push(candidate);
							continue;
						}
						for solution in &solutions {
							changed |=
								seen.insert(crate::solve::vars::canonical_slots(solution), ());
						}
						next.extend(solutions);
					}
					frontier = crate::solve::vars::dedupe_slots(next);
				}
				if !changed {
					break;
				}
			}
			frontier.retain(|candidate| {
				checked.iter().all(|p| {
					let refined = refine_check(p, candidate);
					check_passes(&refined)
						|| crate::primitive::check_key(&refined)
							.is_some_and(|key| contains_var(&key) || self.obtainable(&key))
				})
			});
			frontier = frontier
				.iter()
				.flat_map(|candidate| {
					let solutions = self.require_constructible(candidate, base, true);
					self.memo.borrow_mut().clear();
					solutions
				})
				.collect();
			let frontier = crate::solve::vars::dedupe_slots(frontier);
			combined = combine(&combined, &frontier);
			out.extend(frontier);
		}
		out.extend(combined);
		crate::solve::vars::dedupe_slots(out)
	}

	fn check_equations(&self, p: &Primitive, base: &Substitution) -> Vec<Substitution> {
		if crate::primitive::is_equality(p.id) && p.arguments.len() == 2 {
			let mut out = self.invert(&p.arguments[0], &p.arguments[1], base);
			out.extend(self.invert(&p.arguments[1], &p.arguments[0], base));
			return dedupe(out);
		}
		if crate::primitive::is_projection(p.id)
			&& let Some(inner) = p.arguments.first()
		{
			return self
				.tuple_shapes(p, None)
				.iter()
				.flat_map(|shape| self.invert(inner, shape, base))
				.collect();
		}
		let Some(rule) = rewrite_rule(p.id) else {
			return Vec::new();
		};
		let Some(from) = p.arguments.get(rule.from) else {
			return Vec::new();
		};
		let mut out: Vec<_> = self
			.rewrite_shapes(p, rule)
			.iter()
			.flat_map(|shape| self.invert(from, shape, base))
			.collect();
		if out.is_empty() {
			for (refined, bound) in self.shape_check_inputs(p, rule, base) {
				out.extend(self.check_equations(&refined, &bound));
			}
		}
		dedupe(out)
	}

	pub(crate) fn equality_shapes(&self, p: &Primitive) -> Vec<Substitution> {
		if !(crate::primitive::is_equality(p.id) && p.arguments.len() == 2) {
			return Vec::new();
		}
		self.check_equations(p, &Substitution::default())
	}

	pub(crate) fn repair_check(&self, p: &Primitive, base: &Substitution) -> Vec<Substitution> {
		let refined = refine_check(p, base);
		if check_passes(&refined) {
			return Vec::new();
		}
		let solutions = self.satisfy_check_shaped(&refined, base, true);
		self.memo.borrow_mut().clear();
		solutions
	}

	pub(super) fn satisfy_check_shaped(
		&self,
		p: &Primitive,
		base: &Substitution,
		may_shape: bool,
	) -> Vec<Substitution> {
		if (crate::primitive::is_equality(p.id) && p.arguments.len() == 2)
			|| crate::primitive::is_projection(p.id)
		{
			let out = self
				.check_equations(p, base)
				.iter()
				.flat_map(|bound| self.require_constructible(bound, base, false))
				.collect();
			return dedupe(out);
		}

		let Some(rule) = rewrite_rule(p.id) else {
			return Vec::new();
		};
		let Some(from) = p.arguments.get(rule.from) else {
			return Vec::new();
		};
		let shapes = self.rewrite_shapes(p, rule);
		let mut out = Vec::new();
		if let Some(var_id) = as_var(from) {
			for shape in &shapes {
				self.bind_from_shape(shape, &var_id, base, true, &mut out);
			}
		} else {
			for shape in &shapes {
				for solved in self.solve(shape, base) {
					let target = crate::theory::reduce_once(&apply(shape, &solved));
					for bound in self.invert(from, &target, &solved) {
						out.extend(self.require_constructible(&bound, base, false));
					}
				}
				for bound in self.invert(from, shape, base) {
					out.extend(self.require_constructible(&bound, base, false));
				}
			}
		}
		if out.is_empty() && may_shape {
			for (refined, bound) in self.shape_check_inputs(p, rule, base) {
				out.extend(self.satisfy_check_shaped(&refined, &bound, false));
			}
		}
		dedupe(out)
	}

	fn shape_check_inputs(
		&self,
		p: &Primitive,
		rule: &RewriteRule,
		base: &Substitution,
	) -> Vec<(Primitive, Substitution)> {
		let filter = rule.filter;
		let mut out = Vec::new();
		for (outer_idx, inner_idxs) in &rule.matching {
			let Some(outer_arg) = p.arguments.get(*outer_idx) else {
				continue;
			};
			if !contains_var(outer_arg) {
				continue;
			}
			let Some(required) = crate::primitive::key_derivation_of(self.fresh_var()) else {
				continue;
			};
			if !inner_idxs
				.iter()
				.any(|&i| filter(p, &required, i).1 && !filter(p, outer_arg, i).1)
			{
				continue;
			}
			for bound in self.invert(outer_arg, &required, base) {
				let refined = refine_check(p, &bound);
				if equivalent_primitives(&refined, p, true) {
					continue;
				}
				out.push((refined, bound));
			}
		}
		out
	}
}
