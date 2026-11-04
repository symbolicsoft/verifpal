/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::attacker::AttackerState;
use super::decompose::revealed;
use super::obtain::obtainable;
use crate::primitive::{CapabilityIndex, ReuseRule, is_tuple, reuse_rule};
use crate::term::equivalence::equivalent_primitives;
use crate::term::{Primitive, PrimitiveId, Value};

pub(crate) struct Forgery {
	pub(crate) pair: [Value; 2],
	pub(crate) exempt: Vec<usize>,
	pub(crate) base: Option<Value>,
	pub(crate) using: Vec<Value>,
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

pub(crate) fn fields<'a>(v: &'a Value, like: &Value) -> Option<&'a [Value]> {
	match (v, like) {
		(Value::Primitive(p), Value::Primitive(q)) if p.id == q.id && is_tuple(p.id) => {
			Some(&p.arguments)
		}
		_ => None,
	}
}

pub(crate) type Keystream = Vec<(Vec<(PrimitiveId, usize)>, Value)>;

fn readable(
	v: &Value,
	path: &mut Vec<(PrimitiveId, usize)>,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
	out: &mut Keystream,
) {
	if obtainable(v, capabilities, attacker) {
		out.push((path.clone(), v.clone()));
		return;
	}
	if let Value::Primitive(tuple) = v
		&& is_tuple(tuple.id)
	{
		for (i, field) in tuple.arguments.iter().enumerate() {
			path.push((tuple.id, i));
			readable(field, path, capabilities, attacker, out);
			path.pop();
		}
	}
}

pub(crate) fn keystream_of(
	member: &Value,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Keystream {
	let mut out = Vec::new();
	if let Some(plaintext) = masked(member) {
		readable(plaintext, &mut Vec::new(), capabilities, attacker, &mut out);
	}
	out
}

fn beneath<'a>(v: &'a Value, path: &[(PrimitiveId, usize)]) -> Option<&'a Value> {
	path.iter().try_fold(v, |v, &(id, i)| match v {
		Value::Primitive(tuple) if tuple.id == id => tuple.arguments.get(i),
		_ => None,
	})
}

pub(crate) fn opened_with(of: &Primitive, keystream: &Keystream) -> Vec<(Value, Vec<Value>)> {
	let Some(rule) = reuse_rule(of.id) else {
		return Vec::new();
	};
	let Some(at) = rule.masked else {
		return revealed(of, &rule.reveals)
			.into_iter()
			.map(|v| (v, Vec::new()))
			.collect();
	};
	let Some(plaintext) = of.arguments.get(at) else {
		return Vec::new();
	};
	keystream
		.iter()
		.filter_map(|(path, known)| Some((beneath(plaintext, path)?.clone(), vec![known.clone()])))
		.collect()
}

fn opened_by(
	of: &Primitive,
	partner: &Value,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Vec<(Value, Vec<Value>)> {
	opened_with(of, &keystream_of(partner, capabilities, attacker))
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

pub(crate) fn opened(
	p: &Primitive,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Vec<Value> {
	let mut out: Vec<Value> = Vec::new();
	for member in pairs_of(p, attacker).flatten() {
		if is(member, p) {
			continue;
		}
		for (field, _) in opened_by(p, member, capabilities, attacker) {
			if !out.iter().any(|seen| seen.equivalent(&field, true)) {
				out.push(field);
			}
		}
	}
	out
}

#[derive(Default)]
struct Cover {
	base: Option<Value>,
	using: Vec<Value>,
}

fn covers(
	want: &Value,
	under: &[(&Value, &Value)],
	written: bool,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
	cover: &mut Cover,
) -> bool {
	if let Some((_, known)) = under
		.iter()
		.find(|(_, field)| attacker.knows(field).is_some())
		&& obtainable(want, capabilities, attacker)
	{
		cover.using.push((*known).clone());
		if written {
			cover.using.push(want.clone());
		}
		return true;
	}
	if let Some((member, _)) = under.iter().find(|(_, field)| field.equivalent(want, true)) {
		match &cover.base {
			None => cover.base = Some((*member).clone()),
			Some(base) if !base.equivalent(member, true) => cover.using.push((*member).clone()),
			Some(_) => {}
		}
		return true;
	}
	let Value::Primitive(tuple) = want else {
		return false;
	};
	if !is_tuple(tuple.id) {
		return false;
	}
	tuple.arguments.iter().enumerate().all(|(i, field)| {
		let inner: Vec<(&Value, &Value)> = under
			.iter()
			.filter_map(|&(member, v)| Some((member, fields(v, want)?.get(i)?)))
			.collect();
		!inner.is_empty() && covers(field, &inner, true, capabilities, attacker, cover)
	})
}

pub(crate) fn forgery(
	p: &Primitive,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<Forgery> {
	let rule = reuse_rule(p.id)?;
	let usable: Vec<&[Value; 2]> = pairs_of(p, attacker)
		.filter(|pair| pair.iter().all(|member| !is(member, p)))
		.collect();
	let first = *usable.first()?;
	let Some(at) = rule.masked else {
		return Some(Forgery {
			pair: first.clone(),
			exempt: rule.forgeable.clone(),
			base: None,
			using: Vec::new(),
		});
	};
	let under: Vec<(&Value, &Value)> = usable
		.iter()
		.copied()
		.flatten()
		.filter_map(|member| Some((member, masked(member)?)))
		.collect();
	let wanted = p.arguments.get(at)?;
	let mut cover = Cover::default();
	if covers(wanted, &under, false, capabilities, attacker, &mut cover) {
		let pair = cover
			.base
			.as_ref()
			.and_then(|base| {
				usable
					.iter()
					.find(|pair| pair.iter().any(|member| member.equivalent(base, true)))
			})
			.copied()
			.unwrap_or(first);
		return Some(Forgery {
			pair: pair.clone(),
			exempt: rule.forgeable.iter().copied().chain([at]).collect(),
			base: cover.base,
			using: cover.using,
		});
	}
	Some(Forgery {
		pair: first.clone(),
		exempt: rule.forgeable.clone(),
		base: None,
		using: vec![keystream(p, attacker)?],
	})
}

pub(crate) fn keystream(p: &Primitive, attacker: &AttackerState) -> Option<Value> {
	reuse_rule(p.id)?.masked?;
	pairs_of(p, attacker)
		.flatten()
		.filter_map(masked)
		.find(|known| attacker.knows(known).is_some())
		.cloned()
}
