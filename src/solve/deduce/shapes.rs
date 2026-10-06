/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::Deducer;
use crate::primitive::{
	RewriteRule, primitive_def, primitive_get, primitive_projects, rewrite_rule,
};
use crate::solve::matching::unifiers;
use crate::solve::symbolic::SymbolicState;
use crate::solve::vars::{Substitution, apply, as_var, contains_var};
use crate::term::{Primitive, Value, VariableId};
use crate::util::IdSet;

pub(crate) fn rewrite_shapes_from(
	outer: &Primitive,
	rule: &RewriteRule,
	mut fill: impl FnMut(usize) -> Value,
	leave_free: bool,
) -> Vec<Value> {
	let Ok(inner_spec) = primitive_get(rule.id) else {
		return Vec::new();
	};
	let Some(&arity) = inner_spec.arity.first() else {
		return Vec::new();
	};
	let arity = arity as usize;
	let filter = rule.filter;

	let mut partials: Vec<(Vec<Value>, Vec<usize>)> =
		vec![((0..arity).map(&mut fill).collect(), Vec::new())];
	for (outer_idx, inner_idxs) in &rule.matching {
		let Some(outer_arg) = outer.arguments.get(*outer_idx) else {
			return Vec::new();
		};
		let mut next = Vec::new();
		for (base, taken) in &partials {
			for &inner_idx in inner_idxs {
				if inner_idx >= arity || taken.contains(&inner_idx) {
					continue;
				}
				let (filtered, valid) = filter(outer, outer_arg, inner_idx);
				if !valid {
					continue;
				}
				let mut candidate = base.clone();
				candidate[inner_idx] = filtered;
				let mut claimed = taken.clone();
				claimed.push(inner_idx);
				next.push((candidate, claimed));
			}
		}
		if next.is_empty() {
			if leave_free {
				continue;
			}
			return Vec::new();
		}
		partials = next;
	}

	let output = rule.from_output.unwrap_or(0);
	partials
		.into_iter()
		.map(|(arguments, _)| Value::primitive(rule.id, arguments, output))
		.collect()
}

impl<'a> Deducer<'a> {
	pub(super) fn rewrite_shapes(&self, outer: &Primitive, rule: &RewriteRule) -> Vec<Value> {
		rewrite_shapes_from(outer, rule, |_| self.fresh_var(), false)
	}

	pub(super) fn rewrite_shapes_yielding(
		&self,
		outer: &Primitive,
		rule: &RewriteRule,
		target: &Value,
		s: &Substitution,
	) -> Vec<(Value, Substitution)> {
		let mut out = Vec::new();
		let mut locals = Vec::new();
		let shapes = rewrite_shapes_from(
			outer,
			rule,
			|_| {
				let variable = self.fresh_var();
				locals.push(as_var(&variable).expect("a fresh variable"));
				variable
			},
			false,
		);
		for shape in shapes {
			let Value::Primitive(inner) = &shape else {
				continue;
			};
			for bound in unifiers(&rule.to.apply(inner), target, s) {
				let bindings = bound
					.iter()
					.filter(|(id, _)| !locals.contains(id))
					.map(|(id, value)| (id.clone(), apply(value, &bound)))
					.collect();
				out.push((apply(&shape, &bound), bindings));
			}
		}
		out
	}

	pub(super) fn tuple_shapes(&self, p: &Primitive, at_output: Option<&Value>) -> Vec<Value> {
		let Some(tuple) = primitive_projects(p.id) else {
			return Vec::new();
		};
		let Ok(tuple_spec) = primitive_def(tuple) else {
			return Vec::new();
		};
		let mut arities: Vec<usize> = tuple_spec
			.arity()
			.iter()
			.map(|a| *a as usize)
			.find(|&arity| p.output < arity)
			.into_iter()
			.collect();
		if let Some(inner) = p.arguments.first()
			&& let Value::Primitive(honest) =
				crate::theory::reduce_once(&apply(inner, &self.shared.honest))
			&& honest.id == tuple
			&& p.output < honest.arguments.len()
			&& !arities.contains(&honest.arguments.len())
		{
			arities.push(honest.arguments.len());
		}
		let seen: Vec<usize> = self
			.shared
			.arities
			.get(&tuple)
			.into_iter()
			.flatten()
			.copied()
			.filter(|arity| *arity > p.output && !arities.contains(arity))
			.collect();
		arities.extend(seen);
		arities
			.into_iter()
			.map(|arity| {
				let mut arguments: Vec<Value> = (0..arity).map(|_| self.fresh_var()).collect();
				if let Some(target) = at_output {
					arguments[p.output] = target.clone();
				}
				Value::primitive(tuple, arguments, 0)
			})
			.collect()
	}

	pub(super) fn bind_from_shape(
		&self,
		shape: &Value,
		var_id: &VariableId,
		s: &Substitution,
		defer_free: bool,
		out: &mut Vec<Substitution>,
	) {
		for fixed in unifiers(&Value::Variable(var_id.clone()), shape, s) {
			for mut extended in self.solve(shape, &fixed) {
				let ground = apply(shape, &extended);
				if (!defer_free && contains_var(&ground))
					|| crate::term::subterms(&ground).any(|term| {
						as_var(term)
							.as_ref()
							.is_some_and(crate::solve::vars::is_slot_var_id)
					}) {
					continue;
				}
				extended.insert(var_id.clone(), ground);
				out.push(extended);
			}
		}
	}

	pub(crate) fn forgeable_shapes(&self, sym: &SymbolicState, var_id: &VariableId) -> Vec<Value> {
		let mut out = Vec::new();
		let mut seen = IdSet::default();
		for term in &sym.terms {
			self.collect_forgeable(term, var_id, &mut out, &mut seen);
		}
		out
	}

	fn collect_forgeable(
		&self,
		v: &Value,
		var_id: &VariableId,
		out: &mut Vec<Value>,
		seen: &mut IdSet<usize>,
	) {
		let Value::Primitive(p) = v else {
			return;
		};
		if !seen.insert(Arc::as_ptr(p) as usize) {
			return;
		}
		if let Some(rule) = rewrite_rule(p.id)
			&& p.arguments.get(rule.from).and_then(as_var).as_ref() == Some(var_id)
		{
			for shape in self.rewrite_shapes(p, rule) {
				if !out.iter().any(|existing| existing.equivalent(&shape, true)) {
					out.push(shape);
				}
			}
		}
		for a in &p.arguments {
			self.collect_forgeable(a, var_id, out, seen);
		}
	}
}
