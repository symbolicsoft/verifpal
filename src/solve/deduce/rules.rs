/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::shapes::rewrite_shapes_from;
use super::{Deducer, match_each, refine_check};
use crate::primitive::{
	Capability, RewriteRule, commutativity_rule, commutativity_swap, reuse_rule, rewrite_rule,
};
use crate::solve::matching::{match_values, unifiers};
use crate::solve::vars::{Substitution, apply, as_var, contains_var, dedupe};
use crate::term::{Primitive, Value};
use crate::theory::{forgeable_by_reuse, same_fixed};

/// A projection whose tuple is still open is the one shape plain unification
/// cannot see through: `unifiers` matches congruently, and rewrites already
/// have their own routes, so this is the only case worth inverting a wire term
/// for. Without the test the fallback runs for every wire term and every goal.
fn projects_a_variable(v: &Value) -> bool {
	crate::term::subterms(v).any(|term| match term {
		Value::Primitive(p) => {
			crate::primitive::is_projection(p.id) && p.arguments.first().is_some_and(contains_var)
		}
		Value::Constant(_) | Value::Variable(_) => false,
	})
}

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
			if !contains_var(term) {
				continue;
			}
			for bound in unifiers(term, goal, s) {
				out.extend(self.require_constructible(&bound, s, false));
			}
			if let Value::Primitive(p) = term
				&& let Some(rule) = rewrite_rule(p.id)
			{
				self.solve_by_oracle(p, rule, goal, s, out);
				self.solve_by_rewrite_match(p, rule, goal, s, out);
			}
			if projects_a_variable(term) {
				for bound in self.invert(term, goal, s) {
					out.extend(self.require_constructible(&bound, s, false));
				}
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
