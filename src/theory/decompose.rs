/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::attacker::{AttackerState, DecomposeResult};
use super::obtain::obtainable;
use super::rewrite::reduce_once;
use crate::primitive::{Capability, CapabilityIndex, DecomposeRule, Reveal};
use crate::term::{Primitive, Value};

pub(crate) fn decompose_rule(p: &Primitive) -> Option<&'static DecomposeRule> {
	if crate::primitive::is_core(p.id) {
		return None;
	}
	let rule = crate::primitive::spec(p.id).ok()?.decompose.as_ref()?;
	rule.output
		.is_none_or(|output| p.output == output)
		.then_some(rule)
}

pub(crate) fn decomposition_reveals(p: &Primitive) -> Option<Vec<Value>> {
	Some(revealed(p, &decompose_rule(p)?.reveals))
}

pub(crate) fn can_decompose(
	p: &Primitive,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<DecomposeResult> {
	let rule = decompose_rule(p)?;
	let used = rule
		.given
		.iter()
		.map(|&idx| {
			let (filtered, valid) = (rule.filter)(p, p.arguments.get(idx)?, idx);
			(valid && obtainable(&filtered, capabilities, attacker)).then_some(filtered)
		})
		.collect::<Option<Vec<Value>>>()?;
	let revealed = revealed(p, &rule.reveals);
	(!revealed.is_empty()).then_some(DecomposeResult { revealed, used })
}

pub(crate) fn can_break_weak(
	p: &Primitive,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<Vec<Value>> {
	if crate::primitive::is_core(p.id) {
		return None;
	}
	if !capabilities.in_force(p, Capability::Weak, attacker.current_phase) {
		return None;
	}
	let revealed = revealed(p, &crate::primitive::spec(p.id).ok()?.weak_reveals);
	(!revealed.is_empty()).then_some(revealed)
}

pub(crate) fn revealed(p: &Primitive, reveals: &[Reveal]) -> Vec<Value> {
	reveals
		.iter()
		.filter_map(|reveal| match *reveal {
			Reveal::Argument(index) => p.arguments.get(index).map(reduce_once),
			Reveal::Output(output) => Some(crate::term::hashing::hashcons(&Value::Primitive(
				Arc::new(p.with_output(output)),
			))),
		})
		.collect()
}
