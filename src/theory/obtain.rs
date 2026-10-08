/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::attacker::{AttackerState, DerivationRecord, KnownIdx, RecomposeResult};
use super::decompose::can_decompose;
use super::memo::{DeductionMemo, with_memo};
use super::reuse::reused;
use super::rewrite::{can_rewrite, combine_binding_values, combine_bindings_hold};
use crate::primitive::{
	Capability, CapabilityIndex, CombineRule, MAX_SHARES, Reveal, combines_into,
	commutativity_swap, recompose_rule, reuse_rule,
};
use crate::term::equivalence::{equivalent_primitives, structurally_identical};
use crate::term::{Primitive, Value};
use crate::util::{IdMap, IdSet};

pub(crate) fn obtainable(
	v: &Value,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> bool {
	let hash = v.hash_value();
	if attacker.knows_hashed(v, hash).is_some() {
		return true;
	}
	let Value::Primitive(p) = v else {
		return false;
	};
	let _memo = DeductionMemo::ensure(capabilities, attacker);
	let pointer = Arc::as_ptr(p) as usize;
	let remembered = with_memo(capabilities, attacker, |memo| {
		if let Some(&(_, hit)) = memo.pointers.get(&pointer) {
			return Some(hit);
		}
		let hit = memo
			.entries
			.get(&hash)?
			.iter()
			.find(|(candidate, _)| structurally_identical(candidate, v))
			.map(|(_, hit)| *hit)?;
		memo.pointers.insert(pointer, (Arc::clone(p), hit));
		Some(hit)
	});
	if let Some(hit) = remembered.flatten() {
		return hit;
	}
	let result = construction_inputs(p, capabilities, attacker).is_some();
	with_memo(capabilities, attacker, |memo| {
		memo.pointers.insert(pointer, (Arc::clone(p), result));
		memo.entries
			.entry(hash)
			.or_default()
			.push((v.clone(), result))
	});
	result
}

fn construction_inputs(
	p: &Arc<Primitive>,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<Vec<Value>> {
	if let Some(built) = can_reconstruct_primitive(p, capabilities, attacker) {
		return Some(built.recipe().cloned().collect());
	}
	let Ok(spec) = crate::primitive::spec(p.id) else {
		return None;
	};
	let projects_output = spec.decompose.as_ref().is_some_and(|rule| {
		rule.reveals
			.iter()
			.any(|reveal| matches!(*reveal, Reveal::Output(output) if output == p.output))
	});
	if !projects_output {
		return None;
	}
	let &outputs = spec.output.iter().max()?;
	(0..outputs.max(0) as usize)
		.filter(|&j| j != p.output)
		.find_map(|j| {
			let sibling = Arc::new(p.with_output(j));
			let projected = Value::Primitive(Arc::clone(&sibling));
			attacker.knows(&projected)?;
			let mut inputs = can_decompose(&sibling, capabilities, attacker)?.used;
			inputs.insert(0, projected);
			Some(inputs)
		})
}

pub(crate) struct KnowledgeInputs<'a> {
	capabilities: &'a CapabilityIndex,
	attacker: &'a AttackerState,
	built: IdMap<usize, (Arc<Primitive>, Option<Vec<KnownIdx>>)>,
	_memo: DeductionMemo<'a>,
}

impl<'a> KnowledgeInputs<'a> {
	pub(crate) fn new(capabilities: &'a CapabilityIndex, attacker: &'a AttackerState) -> Self {
		Self {
			capabilities,
			attacker,
			built: IdMap::default(),
			_memo: DeductionMemo::ensure(capabilities, attacker),
		}
	}

	pub(crate) fn of_value(&mut self, value: &Value) -> Option<Vec<KnownIdx>> {
		if let Some(idx) = self.attacker.knows(value) {
			return Some(vec![idx]);
		}
		let Value::Primitive(p) = value else {
			return value
				.as_constant()
				.is_some_and(|c| c.is_nil())
				.then(Vec::new);
		};
		let key = Arc::as_ptr(p) as usize;
		if let Some((_, found)) = self.built.get(&key) {
			return found.clone();
		}
		let remembered = with_memo(self.capabilities, self.attacker, |memo| {
			memo.inputs.get(&key).map(|(_, found)| found.clone())
		});
		if let Some(found) = remembered.flatten() {
			return found;
		}
		self.built.insert(key, (Arc::clone(p), None));
		let found = self.build(p);
		self.built.insert(key, (Arc::clone(p), found.clone()));
		with_memo(self.capabilities, self.attacker, |memo| {
			memo.inputs.insert(key, (Arc::clone(p), found.clone()))
		});
		found
	}

	fn build(&mut self, p: &Arc<Primitive>) -> Option<Vec<KnownIdx>> {
		let inputs = construction_inputs(p, self.capabilities, self.attacker)?;
		let mut known = Vec::new();
		let mut seen = IdSet::default();
		for input in inputs {
			for idx in self.of_value(&input)? {
				if seen.insert(idx.get()) {
					known.push(idx);
				}
			}
		}
		Some(known)
	}
}

pub(crate) fn can_recompose(p: &Primitive, attacker: &AttackerState) -> Option<RecomposeResult> {
	let rule = recompose_rule(p.id)?;
	if p.threshold == 0 {
		return None;
	}
	let used = held_shares(p, attacker, None, p.threshold);
	(used.len() == p.threshold).then(|| RecomposeResult {
		revealed: p.arguments[rule.reveal].clone(),
		used,
	})
}

fn held_shares(
	p: &Primitive,
	attacker: &AttackerState,
	except: Option<usize>,
	enough: usize,
) -> Vec<Value> {
	let mut held = Vec::new();
	for output_idx in 0..MAX_SHARES {
		if held.len() == enough {
			break;
		}
		if except == Some(output_idx) {
			continue;
		}
		let hash = crate::term::hashing::primitive_hash_at_output(p, output_idx);
		let Some(indices) = attacker.known_map.get(&hash) else {
			continue;
		};
		if let Some(known) = indices.iter().find_map(|&i| match attacker.known.get(i) {
			Some(known @ Value::Primitive(known_prim))
				if equivalent_primitives(known_prim, p, false)
					&& known_prim.output == output_idx =>
			{
				Some(known.clone())
			}
			_ => None,
		}) {
			held.push(known);
		}
	}
	held
}

fn can_interpolate(
	p: &Primitive,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<DerivationRecord> {
	let rule = recompose_rule(p.id)?;
	let secret = p.arguments.get(rule.reveal)?;
	if p.threshold == 0 {
		return None;
	}
	if obtainable(secret, capabilities, attacker) {
		let others = held_shares(p, attacker, Some(p.output), p.threshold - 1);
		return (others.len() + 1 == p.threshold).then(|| DerivationRecord::Reconstructed {
			from: vec![secret.clone()],
		});
	}
	let using = held_shares(p, attacker, Some(p.output), p.threshold);
	(using.len() == p.threshold).then_some(DerivationRecord::Recomposed { using })
}

pub(crate) fn can_reconstruct_primitive(
	p: &Arc<Primitive>,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<DerivationRecord> {
	if p.instance != 0
		&& crate::primitive::spec(p.id).is_ok_and(|spec| spec.distinct_per_assignment)
	{
		return can_interpolate(p, capabilities, attacker);
	}
	can_reconstruct_primitive_directly(p, capabilities, attacker).or_else(|| {
		let Value::Primitive(swapped) =
			crate::term::hashing::hashcons(&Value::Primitive(Arc::new(commutativity_swap(p)?)))
		else {
			return None;
		};
		can_reconstruct_primitive_directly(&swapped, capabilities, attacker)
	})
}

fn can_reconstruct_primitive_directly(
	p: &Arc<Primitive>,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<DerivationRecord> {
	let (rewritten, rewrite_value) = can_rewrite(p);
	if !rewritten {
		let Value::Primitive(failed) = &rewrite_value else {
			return None;
		};
		return (!crate::primitive::is_core(p.id)
			&& !p.instance_check
			&& failed
				.arguments
				.iter()
				.all(|a| obtainable(a, capabilities, attacker)))
		.then(|| DerivationRecord::Reconstructed {
			from: failed.arguments.clone(),
		});
	}
	if crate::primitive::is_core(p.id)
		&& crate::primitive::core_spec(p.id).is_ok_and(|s| s.definition_check)
		&& rewrite_value.equivalent(&Value::Primitive(Arc::clone(p)), true)
	{
		return None;
	}
	let Value::Primitive(rewritten_prim) = &rewrite_value else {
		return None;
	};
	let forgeable_secret =
		capabilities.forgeable_secret_position(rewritten_prim, attacker.current_phase);
	let reused = reused(rewritten_prim, attacker);
	let by_reuse: &[usize] = match reuse_rule(rewritten_prim.id) {
		Some(rule) if reused.is_some() => &rule.forgeable,
		_ => &[],
	};
	let exempt = |i: usize| Some(i) == forgeable_secret || by_reuse.contains(&i);
	let mut has = Vec::new();
	let mut skipped = 0usize;
	for (i, a) in rewritten_prim.arguments.iter().enumerate() {
		if exempt(i) {
			skipped += 1;
			continue;
		}
		if obtainable(a, capabilities, attacker) {
			has.push(a.clone());
		}
	}
	if has.len() + skipped < rewritten_prim.arguments.len() {
		if let Some(reshaped) = can_reshape(rewritten_prim, capabilities, attacker) {
			return Some(reshaped);
		}
		let from = combinable(rewritten_prim, capabilities, attacker)?;
		return Some(DerivationRecord::Combined { from });
	}
	Some(match (skipped, reused) {
		(0, _) => DerivationRecord::Reconstructed { from: has },
		(_, Some(with)) => DerivationRecord::ReusedForge { with, using: has },
		(_, None) => DerivationRecord::Broken {
			of: rewrite_value.clone(),
			capability: Capability::Forgeable,
			using: has,
		},
	})
}

fn can_reshape(
	p: &Primitive,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<DerivationRecord> {
	let (of, vary) = malleable_source(p, capabilities, attacker)?;
	let from: Vec<Value> = vary
		.iter()
		.filter_map(|&i| p.arguments.get(i).cloned())
		.collect();
	if !from.iter().all(|v| obtainable(v, capabilities, attacker)) {
		return None;
	}
	Some(DerivationRecord::Broken {
		of,
		capability: Capability::Malleable,
		using: from,
	})
}

fn malleable_source(
	p: &Primitive,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<(Value, &'static [usize])> {
	if capabilities.is_empty() {
		return None;
	}
	let vary = &crate::primitive::spec(p.id).ok()?.malleable_vary;
	if vary.is_empty() {
		return None;
	}
	let mut source: Option<KnownIdx> = None;
	for (annotated, caps) in capabilities.annotated_terms() {
		if !caps.in_force(Capability::Malleable, attacker.current_phase) {
			continue;
		}
		let Value::Primitive(held) = annotated else {
			continue;
		};
		if held.id != p.id
			|| held.output != p.output
			|| held.threshold != p.threshold
			|| held.arguments.len() != p.arguments.len()
			|| crate::term::equivalence::equivalent_primitives(held, p, true)
			|| !p
				.arguments
				.iter()
				.zip(&held.arguments)
				.enumerate()
				.all(|(i, (a, b))| vary.contains(&i) || a.equivalent(b, true))
		{
			continue;
		}
		let Some(known) = attacker.knows(annotated) else {
			continue;
		};
		if source.is_none_or(|first| known.get() < first.get()) {
			source = Some(known);
		}
	}
	source.map(|known| (attacker.known[known.get()].clone(), vary.as_slice()))
}

struct PartialGroup {
	split: Arc<Primitive>,
	agree: Vec<Value>,
	arity: usize,
	held: Vec<(usize, Value)>,
}

fn bound_partials(partial: &Primitive, rule: &CombineRule) -> Vec<Value> {
	let mut choices = vec![partial.arguments.clone()];
	for binding in &rule.bindings {
		let values = combine_binding_values(partial, binding);
		choices = choices
			.into_iter()
			.flat_map(|arguments| {
				values.iter().filter_map(move |value| {
					let mut bound = arguments.clone();
					*bound.get_mut(binding.argument)? = value.clone();
					Some(bound)
				})
			})
			.collect();
	}
	choices
		.into_iter()
		.map(|arguments| Value::Primitive(Arc::new(partial.with_arguments(arguments))))
		.collect()
}

fn partial_groups(
	target: &Primitive,
	rule: &CombineRule,
	attacker: &AttackerState,
) -> Vec<PartialGroup> {
	let Some(reveal) = recompose_rule(rule.split).map(|r| r.reveal) else {
		return Vec::new();
	};
	let secret = &target.arguments[0];
	let mut groups: Vec<PartialGroup> = Vec::new();
	for known in attacker.known.iter() {
		let Value::Primitive(q) = known else {
			continue;
		};
		if q.id != rule.partial || !combine_bindings_hold(q, rule) {
			continue;
		}
		let Some(Value::Primitive(share)) = q.arguments.get(rule.share) else {
			continue;
		};
		if share.id != rule.split
			|| share.threshold == 0
			|| !share
				.arguments
				.get(reveal)
				.is_some_and(|s| s.equivalent(secret, true))
		{
			continue;
		}
		let carried = rule.carry.iter().enumerate().all(|(c, &pos)| {
			match (q.arguments.get(pos), target.arguments.get(1 + c)) {
				(Some(a), Some(b)) => a.equivalent(b, true),
				_ => false,
			}
		});
		if !carried {
			continue;
		}
		let Some(agree) = rule
			.agree
			.iter()
			.map(|&i| q.arguments.get(i).cloned())
			.collect::<Option<Vec<Value>>>()
		else {
			continue;
		};
		let group = groups.iter_mut().find(|g| {
			equivalent_primitives(&g.split, share, false)
				&& g.arity == q.arguments.len()
				&& g.agree
					.iter()
					.zip(agree.iter())
					.all(|(a, b)| a.equivalent(b, true))
		});
		match group {
			Some(g) => {
				if !g.held.iter().any(|(o, _)| *o == share.output) {
					g.held.push((share.output, known.clone()));
				}
			}
			None => groups.push(PartialGroup {
				split: Arc::clone(share),
				agree,
				arity: q.arguments.len(),
				held: vec![(share.output, known.clone())],
			}),
		}
	}
	groups
}

fn combinable(
	target: &Primitive,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<Vec<Value>> {
	for (_, rule) in combines_into(target.id) {
		if target.arguments.len() != 1 + rule.carry.len() {
			continue;
		}
		for group in partial_groups(target, rule, attacker) {
			let threshold = group.split.threshold;
			let mut used: Vec<Value> = group.held.iter().map(|(_, v)| v.clone()).collect();
			if used.len() >= threshold {
				used.truncate(threshold);
				return Some(used);
			}
			for output in 0..MAX_SHARES {
				if group.held.iter().any(|(o, _)| *o == output) {
					continue;
				}
				let share = Value::Primitive(Arc::new(group.split.with_output(output)));
				let arguments: Vec<Value> = (0..group.arity)
					.map(|i| {
						if i == rule.share {
							share.clone()
						} else if let Some(at) = rule.agree.iter().position(|&a| a == i) {
							group.agree[at].clone()
						} else if let Some(at) = rule.carry.iter().position(|&c| c == i) {
							target.arguments[1 + at].clone()
						} else {
							crate::term::value_nil()
						}
					})
					.collect();
				let candidate = Primitive::new(rule.partial, arguments, 0);
				let Some(candidate) = bound_partials(&candidate, rule)
					.into_iter()
					.find(|candidate| obtainable(candidate, capabilities, attacker))
				else {
					continue;
				};
				used.push(candidate);
				if used.len() >= threshold {
					return Some(used);
				}
			}
		}
	}
	None
}
