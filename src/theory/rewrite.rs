/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::primitive::{CombineBinding, CombineRule, RewriteRule, combine_rules, recompose_rule};
use crate::term::equivalence::equivalent_primitives;
use crate::term::{Primitive, PrimitiveId, Value};
use crate::util::IdSet;

pub(crate) fn combine_binding_values(partial: &Primitive, binding: &CombineBinding) -> Vec<Value> {
	let Some(list) = partial.arguments.get(binding.list) else {
		return Vec::new();
	};
	let mut pending = vec![list];
	let mut seen = IdSet::default();
	let mut out = Vec::new();
	while let Some(term) = pending.pop() {
		let Value::Primitive(p) = term else {
			continue;
		};
		if !seen.insert(Arc::as_ptr(p) as usize) {
			continue;
		}
		if p.id == binding.sequence {
			pending.extend(p.arguments.iter().rev());
		} else if p.id == binding.wrapper && p.arguments.len() == 1 {
			crate::term::push_unique_value(&mut out, p.arguments[0].clone());
		}
	}
	out
}

pub(crate) fn combine_bindings_hold(partial: &Primitive, rule: &CombineRule) -> bool {
	rule.bindings.iter().all(|binding| {
		partial
			.arguments
			.get(binding.argument)
			.is_some_and(|argument| {
				combine_binding_values(partial, binding)
					.iter()
					.any(|candidate| candidate.equivalent(argument, true))
			})
	})
}

pub(crate) fn reduce_once(v: &Value) -> Value {
	match v {
		Value::Primitive(p) => can_rewrite(p).1,
		Value::Constant(_) | Value::Variable(_) => v.clone(),
	}
}

pub(crate) fn can_rewrite(p: &Arc<Primitive>) -> (bool, Value) {
	let (rewritten, value) = match p.cache().reduct() {
		Some(hit) => hit,
		None => {
			let (rewritten, value) = can_rewrite_uncached(p);
			let value = match value {
				Value::Primitive(output) if Arc::ptr_eq(p, &output) => None,
				value => Some(value),
			};
			p.cache().set_reduct((rewritten, value))
		}
	};
	(
		*rewritten,
		value
			.clone()
			.unwrap_or_else(|| Value::Primitive(Arc::clone(p))),
	)
}

fn can_rewrite_uncached(p: &Arc<Primitive>) -> (bool, Value) {
	let reduced = p
		.map_arguments(|a| match a {
			Value::Primitive(inner_p) => {
				let (_, replacement) = can_rewrite(inner_p);
				(!replacement.equivalent(a, true)).then_some(replacement)
			}
			_ => None,
		})
		.map(Arc::new);
	let pc: &Arc<Primitive> = reduced.as_ref().unwrap_or(p);
	if let Some(rebuilt) = can_rebuild(pc) {
		return (true, rewritten_or_original(&rebuilt));
	}
	if let Some(combined) = can_combine(pc) {
		return (true, rewritten_or_original(&combined));
	}
	let wrap = || Value::Primitive(Arc::clone(pc));
	if crate::primitive::is_core(pc.id) {
		let prim = match crate::primitive::core_spec(pc.id) {
			Ok(s) => s,
			Err(_) => return (false, wrap()),
		};
		if let Some(rule) = prim.core_rule {
			return rule(pc);
		}
		return (!prim.definition_check, wrap());
	}
	let prim = match crate::primitive::spec(pc.id) {
		Ok(s) => s,
		Err(_) => return (false, wrap()),
	};
	let Some(rule) = &prim.rewrite else {
		return (true, wrap());
	};
	if let Value::Primitive(from_p) = &pc.arguments[rule.from]
		&& from_p.id == rule.id
		&& rule
			.from_output
			.is_none_or(|output| from_p.output == output)
		&& matching_is_injective(pc, from_p, rule, 0, &mut Vec::new())
	{
		return (true, rule.to.apply(from_p));
	}
	(!prim.definition_check, wrap())
}

fn rewritten_or_original(v: &Value) -> Value {
	match v {
		Value::Primitive(inner_p) => {
			let (rewritten, replacement) = can_rewrite(inner_p);
			if rewritten { replacement } else { v.clone() }
		}
		_ => v.clone(),
	}
}

fn matching_is_injective(
	p: &Primitive,
	from_p: &Primitive,
	rule: &RewriteRule,
	at: usize,
	claimed: &mut Vec<usize>,
) -> bool {
	let Some((a_idx, m_vec)) = rule.matching.get(at) else {
		return true;
	};
	if *a_idx >= p.arguments.len() {
		return false;
	}
	for &mm in m_vec {
		if mm >= from_p.arguments.len() || claimed.contains(&mm) {
			continue;
		}
		let (filtered, fvalid) = (rule.filter)(p, &p.arguments[*a_idx], mm);
		if !fvalid
			|| !rewritten_or_original(&filtered)
				.equivalent(&rewritten_or_original(&from_p.arguments[mm]), true)
		{
			continue;
		}
		claimed.push(mm);
		if matching_is_injective(p, from_p, rule, at + 1, claimed) {
			return true;
		}
		claimed.pop();
	}
	false
}

pub(super) fn can_combine(p: &Primitive) -> Option<Value> {
	combine_rules(p.id)
		.iter()
		.find_map(|rule| combine_with(p, rule))
}

pub(super) fn combine_with(p: &Primitive, rule: &CombineRule) -> Option<Value> {
	let reveal = recompose_rule(rule.split)?.reveal;
	let mut partials: Vec<&Primitive> = Vec::with_capacity(p.arguments.len());
	for a in &p.arguments {
		let Value::Primitive(q) = a else {
			return None;
		};
		if q.id != rule.partial || !combine_bindings_hold(q, rule) {
			return None;
		}
		partials.push(q);
	}
	let first = *partials.first()?;
	for q in &partials[1..] {
		if q.arguments.len() != first.arguments.len() {
			return None;
		}
		for &i in &rule.agree {
			if !q
				.arguments
				.get(i)?
				.equivalent(first.arguments.get(i)?, true)
			{
				return None;
			}
		}
	}
	let shares: Vec<Value> = partials
		.iter()
		.map(|q| q.arguments.get(rule.share).cloned())
		.collect::<Option<Vec<Value>>>()?;
	let shares = shares_of_one_split(&shares, rule.split)?;
	let mut arguments = vec![shares[0].arguments.get(reveal)?.clone()];
	for &i in &rule.carry {
		arguments.push(first.arguments.get(i)?.clone());
	}
	Some(Value::primitive(rule.whole, arguments, 0))
}

fn can_rebuild(p: &Primitive) -> Option<Value> {
	if crate::primitive::is_core(p.id) {
		return None;
	}
	let rule = crate::primitive::spec(p.id).ok()?.rebuild.as_ref()?;
	let shares = shares_of_one_split(&p.arguments, rule.id)?;
	Some(shares[0].arguments[rule.reveal].clone())
}

fn shares_of_one_split(arguments: &[Value], split: PrimitiveId) -> Option<Vec<&Primitive>> {
	let mut shares: Vec<&Primitive> = Vec::with_capacity(arguments.len());
	for a in arguments {
		let Value::Primitive(share) = a else {
			return None;
		};
		if share.id != split {
			return None;
		}
		shares.push(share);
	}
	let first = *shares.first()?;
	if first.threshold == 0
		|| !shares
			.iter()
			.all(|s| equivalent_primitives(s, first, false))
	{
		return None;
	}
	let mut outputs: Vec<usize> = shares.iter().map(|s| s.output).collect();
	outputs.sort_unstable();
	outputs.dedup();
	(outputs.len() >= first.threshold).then_some(shares)
}
