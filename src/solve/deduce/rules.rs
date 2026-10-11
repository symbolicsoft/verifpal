/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::decomposition::inverts_through;
use super::shapes::rewrite_shapes_from;
use super::{Deducer, match_each, refine_check};
use crate::primitive::{
	Capability, RewriteRule, commutativity_rule, commutativity_swap, reuse_rule, rewrite_rule,
};
use crate::solve::matching::{match_values, unifiers};
use crate::solve::vars::{
	Substitution, apply, as_var, contains_var, dedupe, remove_local_bindings,
};
use crate::term::{Primitive, Value, VariableId};
use crate::theory::{forgeable_by_reuse, same_fixed};
use crate::util::IdMap;

fn shapes_a_variable(v: &Value) -> bool {
	crate::term::subterms(v).any(|term| match term {
		Value::Primitive(p) => {
			(rewrite_rule(p.id).is_some()
				|| commutativity_rule(p.id).is_some()
				|| crate::primitive::is_projection(p.id)
				|| crate::primitive::is_equality(p.id))
				&& p.arguments.iter().any(contains_var)
		}
		Value::Constant(_) | Value::Variable(_) => false,
	})
}

fn may_yield(term: &Value, goal: &Value) -> bool {
	let Value::Primitive(p) = term else {
		return true;
	};
	if rewrite_rule(p.id).is_some() || crate::primitive::is_projection(p.id) {
		return true;
	}
	match goal {
		Value::Variable(_) => true,
		Value::Constant(_) => false,
		Value::Primitive(q) => {
			crate::primitive::is_projection(q.id) || (q.id == p.id && q.output == p.output)
		}
	}
}

fn abstract_oracles(
	v: &Value,
	oracles: &[(Arc<Primitive>, Value)],
	memo: &mut IdMap<usize, Value>,
) -> Value {
	let Value::Primitive(p) = v else {
		return v.clone();
	};
	if let Some((_, placeholder)) = oracles.iter().find(|(oracle, _)| Arc::ptr_eq(oracle, p)) {
		return placeholder.clone();
	}
	let key = Arc::as_ptr(p) as usize;
	if let Some(hit) = memo.get(&key) {
		return hit.clone();
	}
	let arguments = p
		.arguments
		.iter()
		.map(|argument| abstract_oracles(argument, oracles, memo))
		.collect();
	let out = Value::Primitive(Arc::new(p.with_arguments(arguments)));
	memo.insert(key, out.clone());
	out
}

impl<'a> Deducer<'a> {
	pub(super) fn solve_by_reuse(
		&self,
		target: &Primitive,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let Some(rule) = reuse_rule(target.id) else {
			return;
		};
		let supplied: Vec<usize> = (0..target.arguments.len())
			.filter(|i| !rule.forgeable.contains(i))
			.collect();
		let mut offered: Vec<&Value> = Vec::new();
		for pair in self.attacker.reused.iter() {
			let Value::Primitive(held) = &pair[0] else {
				continue;
			};
			if held.id != target.id || held.arguments.len() != target.arguments.len() {
				continue;
			}
			if self.attacker.knows(&pair[0]).is_none() || self.attacker.knows(&pair[1]).is_none() {
				continue;
			}
			if offered.iter().any(|seen| same_fixed(seen, &pair[0])) {
				continue;
			}
			offered.push(&pair[0]);
			out.extend(self.reshape(target, held, &rule.fixed, &supplied, s));
		}
	}

	pub(super) fn solve_by_malleability(
		&self,
		target: &Primitive,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		if self.shared.capabilities.is_empty() {
			return;
		}
		let Ok(spec) = crate::primitive::spec(target.id) else {
			return;
		};
		if spec.malleable_vary.is_empty() {
			return;
		}
		let kept: Vec<usize> = (0..target.arguments.len())
			.filter(|i| !spec.malleable_vary.contains(i))
			.collect();
		for held in self.held_like(target) {
			let Value::Primitive(held) = held else {
				continue;
			};
			if held.output != target.output || held.threshold != target.threshold {
				continue;
			}
			if !self.shared.capabilities.in_force(
				held,
				Capability::Malleable,
				self.attacker.current_phase,
			) {
				continue;
			}
			out.extend(self.reshape(target, held, &kept, &spec.malleable_vary, s));
		}
	}

	fn reshape(
		&self,
		target: &Primitive,
		held: &Primitive,
		kept: &[usize],
		supplied: &[usize],
		s: &Substitution,
	) -> Vec<Substitution> {
		let mut frontier = vec![s.clone()];
		for &at in kept {
			frontier = match_each(&target.arguments[at], &held.arguments[at], &frontier);
		}
		for &at in supplied {
			let Some(want) = target.arguments.get(at) else {
				continue;
			};
			frontier = self.solve_each(want, &frontier);
			if frontier.is_empty() {
				break;
			}
		}
		frontier
	}

	pub(super) fn solve_by_wire(
		&self,
		goal: &Value,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		for term in self.shared.wire_terms.iter() {
			if contains_var(term) {
				self.solve_through(term, goal, s, out);
			}
		}
		let oracles = self
			.shared
			.revealed_oracles
			.get_or_init(|| super::decomposition::revealed_oracles(&self.shared.wire_terms));
		for (term, given) in oracles {
			if !may_yield(term, &apply(goal, s)) {
				continue;
			}
			let mut opened = vec![s.clone()];
			for required in given {
				if opened.is_empty() {
					break;
				}
				opened = self.solve_each(required, &opened);
			}
			for candidate in &opened {
				self.solve_by_oracles(term, goal, candidate, out);
			}
		}
	}

	fn solve_through(
		&self,
		term: &Value,
		goal: &Value,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		for bound in unifiers(term, goal, s) {
			out.extend(self.require_constructible(&bound, s, false));
		}
		self.solve_by_oracles(term, goal, s, out);
	}

	fn solve_by_oracles(
		&self,
		term: &Value,
		goal: &Value,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		if let Value::Primitive(p) = term
			&& let Some(rule) = rewrite_rule(p.id)
		{
			self.solve_by_oracle(p, rule, goal, s, out);
			self.solve_by_rewrite_match(p, rule, goal, s, out);
		}
		if inverts_through(term) {
			for bound in self.invert(term, goal, s) {
				out.extend(self.require_constructible(&bound, s, false));
			}
		}
		self.solve_by_nested_oracles(term, goal, s, out);
	}

	fn solve_by_nested_oracles(
		&self,
		term: &Value,
		goal: &Value,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let Value::Primitive(top) = term else {
			return;
		};
		let mut oracles: Vec<(Arc<Primitive>, Value)> = Vec::new();
		for argument in &top.arguments {
			for sub in crate::term::subterms(argument) {
				if let Value::Primitive(p) = sub
					&& rewrite_rule(p.id)
						.is_some_and(|rule| p.arguments.get(rule.from).and_then(as_var).is_some())
					&& !oracles.iter().any(|(seen, _)| Arc::ptr_eq(seen, p))
				{
					oracles.push((Arc::clone(p), self.fresh_var()));
				}
			}
		}
		if oracles.is_empty() {
			return;
		}
		let abstracted = abstract_oracles(term, &oracles, &mut IdMap::default());
		let locals: Vec<VariableId> = oracles
			.iter()
			.filter_map(|(_, placeholder)| as_var(placeholder))
			.collect();
		for bound in unifiers(&abstracted, goal, s) {
			let mut frontier = vec![bound];
			for (p, placeholder) in &oracles {
				let Some(rule) = rewrite_rule(p.id) else {
					continue;
				};
				let Some(var_id) = p.arguments.get(rule.from).and_then(as_var) else {
					continue;
				};
				let mut next = Vec::new();
				for candidate in &frontier {
					let wanted = apply(placeholder, candidate);
					if as_var(&wanted).is_some() {
						next.extend(unifiers(
							placeholder,
							&Value::Primitive(Arc::clone(p)),
							candidate,
						));
						continue;
					}
					for (shape, shaped) in self.rewrite_shapes_yielding(p, rule, &wanted, candidate)
					{
						self.bind_from_shape(&shape, &var_id, &shaped, false, &mut next);
					}
				}
				frontier = dedupe(next);
			}
			for candidate in frontier {
				let candidate = remove_local_bindings(candidate, &locals);
				out.extend(self.require_constructible(&candidate, s, false));
			}
		}
	}

	pub(super) fn solve_by_rewrite_match(
		&self,
		p: &Primitive,
		rule: &RewriteRule,
		goal: &Value,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let Some(Value::Primitive(inner)) = p.arguments.get(rule.from) else {
			return;
		};
		if inner.id != rule.id
			|| rule
				.from_output
				.is_some_and(|output| inner.output != output)
		{
			return;
		}
		for current in match_values(&rule.to.apply(inner), goal, s) {
			let refined = refine_check(p, &current);
			for shape in
				rewrite_shapes_from(&refined, rule, |at| inner.arguments[at].clone(), false)
			{
				for bound in unifiers(&p.arguments[rule.from], &shape, &current) {
					out.extend(self.require_constructible(&bound, s, false));
				}
			}
		}
	}

	fn solve_by_oracle(
		&self,
		p: &Primitive,
		rule: &RewriteRule,
		goal: &Value,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let Some(var_id) = p.arguments.get(rule.from).and_then(as_var) else {
			return;
		};
		for (shape, bound) in self.rewrite_shapes_yielding(p, rule, goal, s) {
			self.bind_from_shape(&shape, &var_id, &bound, false, out);
		}
	}

	pub(super) fn solve_primitive(
		&self,
		p: &Primitive,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let before = out.len();
		self.solve_primitive_arguments(p, s, out);
		match commutativity_swap(p) {
			Some(swapped) => self.solve_primitive_arguments(&swapped, s, out),
			None if out.len() == before => self.solve_by_commuting(p, s, out),
			None => {}
		}
		if p.arguments.iter().any(contains_var) {
			let term = Value::Primitive(Arc::new(p.clone()));
			for bound in self.satisfy_check_shaped(p, s, true) {
				let applied = apply(&term, &bound);
				let reduced = crate::theory::reduce_once(&applied);
				if !applied.equivalent(&reduced, true) {
					self.solve_into(&reduced, &bound, out);
				}
			}
		}
	}

	fn solve_by_commuting(&self, p: &Primitive, s: &Substitution, out: &mut Vec<Substitution>) {
		let Some(rule) = commutativity_rule(p.id) else {
			return;
		};
		let Some(wrapped) = p.arguments.get(rule.wrapped) else {
			return;
		};
		if !contains_var(wrapped) {
			return;
		}
		let required = Value::primitive(rule.constructor, vec![self.fresh_var()], 0);
		let term = Value::Primitive(Arc::new(p.clone()));
		for bound in self.invert(wrapped, &required, s) {
			for shaped in self.require_constructible(&bound, s, false) {
				let reduced = crate::theory::reduce_once(&apply(&term, &shaped));
				if let Value::Primitive(q) = &reduced
					&& let Some(swapped) = commutativity_swap(q)
				{
					self.solve_primitive_arguments(&swapped, &shaped, out);
				}
			}
		}
	}

	fn solve_primitive_arguments(
		&self,
		p: &Primitive,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let capabilities = self.shared.capabilities;
		let forgeable_secret =
			capabilities.forgeable_secret_position(p, self.attacker.current_phase);
		let secret_position = crate::primitive::spec(p.id)
			.ok()
			.and_then(|spec| spec.forgeable_secret);
		let by_reuse = forgeable_by_reuse(p, self.attacker);
		let (shaping, carried): (Vec<usize>, Vec<usize>) =
			(0..p.arguments.len()).partition(|&i| shapes_a_variable(&p.arguments[i]));
		let mut frontier = vec![s.clone()];
		for i in shaping.into_iter().chain(carried) {
			let arg = &p.arguments[i];
			let exempt = Some(i) == forgeable_secret || by_reuse.contains(&i);
			let mut next = Vec::new();
			for candidate in &frontier {
				self.solve_into(arg, candidate, &mut next);
			}
			if exempt {
				next.extend(frontier.iter().cloned());
			} else if Some(i) == secret_position && !capabilities.is_empty() {
				for secret in capabilities.forgeable_secrets(p.id, self.attacker.current_phase) {
					for candidate in &frontier {
						next.extend(match_values(arg, secret, candidate));
					}
				}
			}
			if next.is_empty() {
				return;
			}
			frontier = dedupe(next);
		}
		out.extend(frontier);
	}
}
