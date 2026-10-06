/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::attacker::AttackerState;
use crate::primitive::{ReuseRule, reuse_rule};
use crate::term::{Primitive, Value};

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

pub(crate) fn reused(p: &Primitive, attacker: &AttackerState) -> Option<[Value; 2]> {
	let rule = reuse_rule(p.id)?;
	attacker
		.reused
		.iter()
		.find(|pair| {
			matches!(&pair[0], Value::Primitive(held) if fixed_alike(held, p, rule))
				&& attacker.knows(&pair[0]).is_some()
				&& attacker.knows(&pair[1]).is_some()
		})
		.cloned()
}

pub(crate) fn forgeable_by_reuse(p: &Primitive, attacker: &AttackerState) -> &'static [usize] {
	match reuse_rule(p.id) {
		Some(rule) if reused(p, attacker).is_some() => &rule.forgeable,
		_ => &[],
	}
}
