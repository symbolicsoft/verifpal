/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::attacker::AttackerState;
use super::obtain::obtainable;
use crate::primitive::{CapabilityIndex, ReuseRule, reuse_rule};
use crate::term::equivalence::equivalent_primitives;
use crate::term::{Primitive, Value};

pub(crate) struct Forgery {
	pub(crate) pair: [Value; 2],
	pub(crate) exempt: Vec<usize>,
	pub(crate) known: Option<Value>,
}

fn fixed_alike(a: &Primitive, b: &Primitive, rule: &ReuseRule) -> bool {
	a.id == b.id
		&& a.arguments.len() == b.arguments.len()
		&& rule
			.fixed
			.iter()
			.all(|&at| match (a.arguments.get(at), b.arguments.get(at)) {
				(Some(x), Some(y)) => x.equivalent(y, true),
				_ => false,
			})
}

pub(crate) fn same_fixed(a: &Value, b: &Value) -> bool {
	let (Value::Primitive(a), Value::Primitive(b)) = (a, b) else {
		return false;
	};
	reuse_rule(a.id).is_some_and(|rule| fixed_alike(a, b, rule))
}

pub(crate) fn reused_pair(a: &Value, b: &Value) -> bool {
	same_fixed(a, b) && !a.equivalent(b, true)
}

pub(crate) fn masked(member: &Value) -> Option<&Value> {
	let Value::Primitive(p) = member else {
		return None;
	};
	p.arguments.get(reuse_rule(p.id)?.masked?)
}

pub(crate) fn unmasks(
	member: &Value,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<Vec<Value>> {
	let Value::Primitive(p) = member else {
		return None;
	};
	let Some(at) = reuse_rule(p.id)?.masked else {
		return Some(Vec::new());
	};
	let known = p.arguments.get(at)?;
	obtainable(known, capabilities, attacker).then(|| vec![known.clone()])
}

fn pairs_of<'a>(
	p: &'a Primitive,
	attacker: &'a AttackerState,
) -> impl Iterator<Item = &'a [Value; 2]> {
	let rule = reuse_rule(p.id);
	attacker.reused.iter().filter(move |pair| {
		rule.is_some_and(
			|rule| matches!(&pair[0], Value::Primitive(held) if fixed_alike(held, p, rule)),
		) && pair.iter().all(|member| attacker.knows(member).is_some())
	})
}

fn is(member: &Value, p: &Primitive) -> bool {
	matches!(member, Value::Primitive(q) if equivalent_primitives(q, p, true))
}

pub(crate) fn opens(
	p: &Primitive,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> bool {
	pairs_of(p, attacker)
		.flatten()
		.any(|member| !is(member, p) && unmasks(member, capabilities, attacker).is_some())
}

pub(crate) fn keystream(p: &Primitive, attacker: &AttackerState) -> Option<Value> {
	reuse_rule(p.id)?.masked?;
	pairs_of(p, attacker)
		.flatten()
		.filter_map(masked)
		.find(|known| attacker.knows(known).is_some())
		.cloned()
}

pub(crate) fn forgery(p: &Primitive, attacker: &AttackerState) -> Option<Forgery> {
	let rule = reuse_rule(p.id)?;
	let usable: Vec<&[Value; 2]> = pairs_of(p, attacker)
		.filter(|pair| pair.iter().all(|member| !is(member, p)))
		.collect();
	let first = *usable.first()?;
	let Some(at) = rule.masked else {
		return Some(Forgery {
			pair: first.clone(),
			exempt: rule.forgeable.clone(),
			known: None,
		});
	};
	if let Some(known) = keystream(p, attacker) {
		return Some(Forgery {
			pair: first.clone(),
			exempt: rule.forgeable.clone(),
			known: Some(known),
		});
	}
	let wanted = p.arguments.get(at)?;
	let kept = usable
		.into_iter()
		.find(|pair| masked(&pair[0]).is_some_and(|kept| kept.equivalent(wanted, true)))?;
	Some(Forgery {
		pair: kept.clone(),
		exempt: rule.forgeable.iter().copied().chain([at]).collect(),
		known: None,
	})
}
