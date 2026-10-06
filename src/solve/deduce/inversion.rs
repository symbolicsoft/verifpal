/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::decomposition::decomposition_targets;
use super::{Deducer, advance};
use crate::primitive::{primitive_is_projection, rewrite_rule};
use crate::solve::matching::unifiers;
use crate::solve::vars::{Substitution, apply, contains_var, dedupe};
use crate::term::Value;
use crate::term::hashing::TermSet;

impl<'a> Deducer<'a> {
	pub(super) fn invert(
		&self,
		term: &Value,
		target: &Value,
		s: &Substitution,
	) -> Vec<Substitution> {
		let term = crate::theory::reduce_once(&apply(term, s));
		let target = crate::theory::reduce_once(&apply(target, s));
		let mut out: Vec<_> = unifiers(&term, &target, s).collect();

		let Value::Primitive(p) = &term else {
			return dedupe(out);
		};
		if out.is_empty()
			&& let Value::Primitive(q) = &target
			&& p.id == q.id
			&& p.output == q.output
			&& p.threshold == q.threshold
			&& p.arguments.len() == q.arguments.len()
		{
			let aligned = p
				.arguments
				.iter()
				.cloned()
				.zip(q.arguments.iter().cloned())
				.collect::<Vec<_>>();
			let swapped = crate::solve::matching::commutative_equations::<true>(p, q);
			for equations in std::iter::once(aligned).chain(swapped) {
				let mut frontier = vec![s.clone()];
				for (a, b) in equations {
					frontier = advance(&frontier, |bindings, next| {
						next.extend(self.invert(&a, &b, bindings))
					});
					if frontier.is_empty() {
						break;
					}
				}
				out.extend(frontier);
			}
		}

		if let Some(rule) = rewrite_rule(p.id)
			&& let Some(from) = p.arguments.get(rule.from)
		{
			for (shape, bound) in self.rewrite_shapes_yielding(p, rule, &target, s) {
				out.extend(self.invert(from, &shape, &bound));
			}
		}

		if primitive_is_projection(p.id)
			&& let Some(inner) = p.arguments.first()
		{
			for candidate in self.tuple_shapes(p, Some(&target)) {
				out.extend(self.invert(inner, &candidate, s));
			}
		}

		dedupe(out)
	}

	pub(crate) fn invert_into_revealed(
		&self,
		emission: &Value,
		shape: &Value,
	) -> Vec<Substitution> {
		let empty = Substitution::default();
		let mut out = Vec::new();
		let mut pending = vec![emission.clone()];
		let mut seen = TermSet::default();
		while let Some(term) = pending.pop() {
			let Value::Primitive(p) = &term else {
				continue;
			};
			let Some((revealed, _)) = decomposition_targets(p) else {
				continue;
			};
			for inner in revealed {
				if seen.contains(&inner) {
					continue;
				}
				seen.insert(inner.clone());
				if contains_var(&inner) {
					out.extend(self.invert(&inner, shape, &empty));
				}
				pending.push(inner);
			}
		}
		crate::solve::vars::dedupe(out)
	}
}
