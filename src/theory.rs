/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::RefCell;
use std::sync::Arc;

use crate::context::Generational;
use crate::equivalence::{equivalent_primitives, memoised_pair};
use crate::primitive::*;
use crate::types::*;

#[derive(Default)]
struct RewriteCache {
	entries: IdMap<u64, Vec<RewriteEntry>>,
	pointers: IdMap<usize, RewriteEntry>,
	order: std::collections::VecDeque<usize>,
	inserted: usize,
	recent: std::collections::VecDeque<Arc<Primitive>>,
}

struct RewriteEntry {
	input: std::sync::Weak<Primitive>,
	result: bool,
	value: Option<Value>,
}

impl RewriteEntry {
	fn new(p: &Arc<Primitive>, result: bool, value: Value) -> RewriteEntry {
		let value = match value {
			Value::Primitive(output) if Arc::ptr_eq(p, &output) => None,
			value => Some(value),
		};
		RewriteEntry {
			input: Arc::downgrade(p),
			result,
			value,
		}
	}
}

const TERM_MEMO_SWEEP: usize = 65536;
const TERM_MEMO_RECENT: usize = 1024;
const TERM_MEMO_POINTERS: usize = 8192;

impl RewriteCache {
	fn get(&mut self, key: u64, p: &Arc<Primitive>) -> Option<(bool, Value)> {
		if let Some(entry) = self.pointers.get(&(Arc::as_ptr(p) as usize)) {
			return Some((
				entry.result,
				entry
					.value
					.clone()
					.unwrap_or_else(|| Value::Primitive(Arc::clone(p))),
			));
		}
		let hit = self.entries.get(&key)?.iter().find_map(|entry| {
			let held = entry.input.upgrade()?;
			(Arc::ptr_eq(&held, p) || structurally_identical_primitive(&held, p)).then(|| {
				(
					entry.result,
					entry.value.clone().unwrap_or(Value::Primitive(held)),
				)
			})
		});
		if let Some((result, value)) = &hit {
			self.remember_pointer(p, *result, value.clone());
		}
		hit
	}

	fn put(&mut self, key: u64, p: &Arc<Primitive>, result: bool, value: Value) {
		self.remember_pointer(p, result, value.clone());
		if self.recent.len() == TERM_MEMO_RECENT {
			self.recent.pop_front();
		}
		self.recent.push_back(Arc::clone(p));
		self.inserted += 1;
		if self.inserted >= TERM_MEMO_SWEEP {
			self.inserted = 0;
			self.sweep();
		}
		let bucket = self.entries.entry(key).or_default();
		bucket.retain(|entry| entry.input.strong_count() > 0);
		bucket.push(RewriteEntry::new(p, result, value));
	}

	fn remember_pointer(&mut self, p: &Arc<Primitive>, result: bool, value: Value) {
		let key = Arc::as_ptr(p) as usize;
		if self
			.pointers
			.insert(key, RewriteEntry::new(p, result, value))
			.is_none()
		{
			self.order.push_back(key);
			if self.pointers.len() > TERM_MEMO_POINTERS
				&& let Some(oldest) = self.order.pop_front()
			{
				self.pointers.remove(&oldest);
			}
		}
	}

	fn sweep(&mut self) {
		self.pointers
			.retain(|_, entry| entry.input.strong_count() > 0);
		self.order.retain(|key| self.pointers.contains_key(key));
		self.entries.retain(|_, bucket| {
			bucket.retain(|entry| entry.input.strong_count() > 0);
			!bucket.is_empty()
		});
	}
}

struct ObtainableMemo {
	owner: (*const CapabilityIndex, *const AttackerState),
	entries: IdMap<u64, Vec<(Value, bool)>>,
	inputs: IdMap<usize, (Arc<Primitive>, Option<Vec<KnownIdx>>)>,
}

impl ObtainableMemo {
	fn is_for(&self, capabilities: &CapabilityIndex, attacker: &AttackerState) -> bool {
		std::ptr::eq(self.owner.0, capabilities) && std::ptr::eq(self.owner.1, attacker)
	}
}

fn with_memo<R>(
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
	f: impl FnOnce(&mut ObtainableMemo) -> R,
) -> Option<R> {
	MEMO.with(|m| {
		m.borrow_mut()
			.as_mut()
			.filter(|memo| memo.is_for(capabilities, attacker))
			.map(f)
	})
}

pub(crate) fn structurally_identical_primitive(x: &Primitive, y: &Primitive) -> bool {
	x.id == y.id
		&& x.output == y.output
		&& x.threshold == y.threshold
		&& x.instance == y.instance
		&& x.instance_check == y.instance_check
		&& x.arguments.len() == y.arguments.len()
		&& x.arguments
			.iter()
			.zip(y.arguments.iter())
			.all(|(p, q)| structurally_identical(p, q))
}

pub(crate) fn structurally_identical(a: &Value, b: &Value) -> bool {
	match (a, b) {
		(Value::Constant(x), Value::Constant(y)) => x.id == y.id,
		(Value::Primitive(x), Value::Primitive(y)) => {
			Arc::ptr_eq(x, y) || memoised_pair(2, x, y, || structurally_identical_primitive(x, y))
		}
		_ => false,
	}
}

thread_local! {
	static MEMO: RefCell<Option<ObtainableMemo>> = const { RefCell::new(None) };
	static REWRITE_CACHE: RefCell<Generational<RewriteCache>> = RefCell::new(Generational::default());
}

fn rewrite_cache_get(key: u64, p: &Arc<Primitive>) -> Option<(bool, Value)> {
	REWRITE_CACHE.with(|c| c.borrow_mut().fresh().get(key, p))
}

fn rewrite_cache_put(key: u64, p: &Arc<Primitive>, result: &(bool, Value)) {
	REWRITE_CACHE.with(|c| {
		c.borrow_mut()
			.fresh()
			.put(key, p, result.0, result.1.clone())
	});
}

pub(crate) struct DeductionMemo<'a> {
	previous: Option<Option<ObtainableMemo>>,
	borrowed: std::marker::PhantomData<(&'a CapabilityIndex, &'a AttackerState)>,
}

impl<'a> DeductionMemo<'a> {
	pub(crate) fn ensure(
		capabilities: &'a CapabilityIndex,
		attacker: &'a AttackerState,
	) -> DeductionMemo<'a> {
		if with_memo(capabilities, attacker, |_| ()).is_some() {
			return DeductionMemo {
				previous: None,
				borrowed: std::marker::PhantomData,
			};
		}
		Self::scoped(capabilities, attacker)
	}

	pub(crate) fn scoped(
		capabilities: &'a CapabilityIndex,
		attacker: &'a AttackerState,
	) -> DeductionMemo<'a> {
		let installed = ObtainableMemo {
			owner: (capabilities as *const _, attacker as *const _),
			entries: IdMap::default(),
			inputs: IdMap::default(),
		};
		let previous = MEMO.with(|m| m.borrow_mut().replace(installed));
		DeductionMemo {
			previous: Some(previous),
			borrowed: std::marker::PhantomData,
		}
	}
}

impl Drop for DeductionMemo<'_> {
	fn drop(&mut self) {
		if let Some(previous) = self.previous.take() {
			MEMO.with(|m| *m.borrow_mut() = previous);
		}
	}
}

pub(crate) fn same_fixed(a: &Value, b: &Value) -> bool {
	let (Value::Primitive(a), Value::Primitive(b)) = (a, b) else {
		return false;
	};
	let Some(rule) = reuse_rule(a.id) else {
		return false;
	};
	a.id == b.id
		&& a.arguments.len() == b.arguments.len()
		&& rule
			.fixed
			.iter()
			.all(|&at| match (a.arguments.get(at), b.arguments.get(at)) {
				(Some(x), Some(y)) => x.hash_value() == y.hash_value() && x.equivalent(y, true),
				_ => false,
			})
}

pub(crate) fn reused_pair(a: &Value, b: &Value) -> bool {
	same_fixed(a, b) && !a.equivalent(b, true)
}

pub(crate) fn reused(p: &Primitive, attacker: &AttackerState) -> Option<[Value; 2]> {
	reuse_rule(p.id)?;
	let probe = Value::Primitive(Arc::new(p.clone()));
	attacker
		.reused
		.iter()
		.find(|pair| {
			same_fixed(&pair[0], &probe)
				&& attacker.knows(&pair[0]).is_some()
				&& attacker.knows(&pair[1]).is_some()
		})
		.cloned()
}

pub(crate) fn forgeable_by_reuse(p: &Primitive, attacker: &AttackerState) -> &'static [usize] {
	match (reused(p, attacker), reuse_rule(p.id)) {
		(Some(_), Some(rule)) => &rule.forgeable,
		_ => &[],
	}
}

pub(crate) fn can_decompose(
	p: &Primitive,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<DecomposeResult> {
	if primitive_is_core(p.id) {
		return None;
	}
	let rule = primitive_get(p.id).ok()?.decompose.as_ref()?;
	if rule.output.is_some_and(|output| p.output != output) {
		return None;
	}
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
	if primitive_is_core(p.id) {
		return None;
	}
	if !capabilities.in_force(p, Capability::Weak, attacker.current_phase) {
		return None;
	}
	let revealed = revealed(p, &primitive_get(p.id).ok()?.weak_reveals);
	(!revealed.is_empty()).then_some(revealed)
}

pub(crate) fn revealed(p: &Primitive, reveals: &[Reveal]) -> Vec<Value> {
	reveals
		.iter()
		.filter_map(|reveal| match *reveal {
			Reveal::Argument(index) => p.arguments.get(index).map(reduce_once),
			Reveal::Output(output) => Some(Value::Primitive(Arc::new(p.with_output(output)))),
		})
		.collect()
}

pub(crate) fn obtainable(
	v: &Value,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> bool {
	let hash = v.hash_value();
	if attacker.knows_hashed(v, hash).is_some() {
		return true;
	}
	if matches!(v, Value::Constant(_)) {
		return false;
	}
	let _memo = DeductionMemo::ensure(capabilities, attacker);
	let remembered = with_memo(capabilities, attacker, |memo| {
		memo.entries
			.get(&hash)?
			.iter()
			.find(|(candidate, _)| structurally_identical(candidate, v))
			.map(|(_, hit)| *hit)
	});
	if let Some(hit) = remembered.flatten() {
		return hit;
	}
	let result = match v {
		Value::Primitive(p) => construction_inputs(p, capabilities, attacker).is_some(),
		Value::Constant(_) => false,
	};
	with_memo(capabilities, attacker, |memo| {
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
		return Some(built.ingredients().cloned().collect());
	}
	let Ok(spec) = primitive_get(p.id) else {
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

impl ReconstructResult {
	pub(crate) fn ingredients(&self) -> impl Iterator<Item = &Value> {
		let source: &[Value] = match &self.forged {
			Some(Forged::Reuse(pair)) => pair,
			Some(Forged::Assumption {
				capability: Capability::Malleable,
				of,
			}) => std::slice::from_ref(of),
			_ => &[],
		};
		self.from.iter().chain(source)
	}
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
	let mut candidates = Vec::new();
	for output_idx in 0..MAX_SHARES {
		let probe = p.with_output(output_idx);
		let hash = crate::hashing::primitive_hash(&probe);
		let Some(indices) = attacker.known_map.get(&hash) else {
			continue;
		};
		let held = indices.iter().find_map(|&i| match attacker.known.get(i) {
			Some(known @ Value::Primitive(known_prim))
				if equivalent_primitives(known_prim, p, false)
					&& known_prim.output == output_idx =>
			{
				Some(known.clone())
			}
			_ => None,
		});
		let Some(known) = held else {
			continue;
		};
		candidates.push(known);
		if candidates.len() == p.threshold {
			return Some(RecomposeResult {
				revealed: p.arguments[rule.reveal].clone(),
				used: candidates,
			});
		}
	}
	None
}

pub(crate) fn can_reconstruct_primitive(
	p: &Arc<Primitive>,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<ReconstructResult> {
	can_reconstruct_primitive_directly(p, capabilities, attacker).or_else(|| {
		let swapped = Arc::new(commutativity_swap(p)?);
		can_reconstruct_primitive_directly(&swapped, capabilities, attacker)
	})
}

fn can_reconstruct_primitive_directly(
	p: &Arc<Primitive>,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<ReconstructResult> {
	let (rewritten, rewrite_value) = can_rewrite(p);
	if !rewritten {
		let Value::Primitive(failed) = &rewrite_value else {
			return None;
		};
		return (!primitive_is_core(p.id)
			&& !p.instance_check
			&& failed
				.arguments
				.iter()
				.all(|a| obtainable(a, capabilities, attacker)))
		.then(|| ReconstructResult {
			from: failed.arguments.clone(),
			forged: None,
			combined: false,
		});
	}
	if primitive_is_core(p.id)
		&& primitive_core_get(p.id).is_ok_and(|s| s.definition_check)
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
	let by_reuse = forgeable_by_reuse(rewritten_prim, attacker);
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
		return Some(ReconstructResult {
			from,
			forged: None,
			combined: true,
		});
	}
	let forged = match (skipped, reused) {
		(0, _) => None,
		(_, Some(pair)) => Some(Forged::Reuse(pair)),
		(_, None) => Some(Forged::Assumption {
			capability: Capability::Forgeable,
			of: rewrite_value.clone(),
		}),
	};
	Some(ReconstructResult {
		from: has,
		forged,
		combined: false,
	})
}

fn can_reshape(
	p: &Primitive,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<ReconstructResult> {
	let (of, vary) = malleable_source(p, capabilities, attacker)?;
	let from: Vec<Value> = vary
		.iter()
		.filter_map(|&i| p.arguments.get(i).cloned())
		.collect();
	if !from.iter().all(|v| obtainable(v, capabilities, attacker)) {
		return None;
	}
	Some(ReconstructResult {
		from,
		forged: Some(Forged::Assumption {
			capability: Capability::Malleable,
			of,
		}),
		combined: false,
	})
}

pub(crate) fn malleable_source(
	p: &Primitive,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<(Value, &'static [usize])> {
	if capabilities.is_empty() {
		return None;
	}
	let vary = &primitive_get(p.id).ok()?.malleable_vary;
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
			|| crate::equivalence::equivalent_primitives(held, p, true)
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
			crate::value::push_unique_value(&mut out, p.arguments[0].clone());
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
							crate::value::value_nil()
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

pub(crate) fn reduce_once(v: &Value) -> Value {
	match v {
		Value::Primitive(p) => can_rewrite(p).1,
		Value::Constant(_) => v.clone(),
	}
}

pub(crate) fn can_rewrite(p: &Arc<Primitive>) -> (bool, Value) {
	let key = crate::hashing::primitive_hash(p);
	if let Some(hit) = rewrite_cache_get(key, p) {
		return hit;
	}
	let result = can_rewrite_uncached(p);
	rewrite_cache_put(key, p, &result);
	result
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
	if primitive_is_core(pc.id) {
		let prim = match primitive_core_get(pc.id) {
			Ok(s) => s,
			Err(_) => return (false, wrap()),
		};
		if let Some(rule) = prim.core_rule {
			return rule(pc);
		}
		return (!prim.definition_check, wrap());
	}
	let prim = match primitive_get(pc.id) {
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

pub(crate) fn can_combine(p: &Primitive) -> Option<Value> {
	combine_rules(p.id)
		.iter()
		.find_map(|rule| combine_with(p, rule))
}

fn combine_with(p: &Primitive, rule: &CombineRule) -> Option<Value> {
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

pub(crate) fn can_rebuild(p: &Primitive) -> Option<Value> {
	if primitive_is_core(p.id) {
		return None;
	}
	let rule = primitive_get(p.id).ok()?.rebuild.as_ref()?;
	let shares = shares_of_one_split(&p.arguments, rule.id)?;
	Some(shares[0].arguments[rule.reveal].clone())
}

pub(crate) fn shares_of_one_split(
	arguments: &[Value],
	split: PrimitiveId,
) -> Option<Vec<&Primitive>> {
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testutil::*;
	use crate::value::*;
	use std::sync::Arc;

	#[test]
	fn malleability_deduction_requires_its_source_phase_key_and_payload() {
		let key = make_private("maul_deduction_key");
		let other = make_private("maul_deduction_other");
		let hidden = make_private("maul_deduction_hidden");
		let mut source = Primitive::new(PRIM_ENC, vec![key.clone(), hidden.clone()], 0);
		source.capabilities.set(Capability::Malleable, 2);
		let source = Value::Primitive(Arc::new(source));
		let target = Value::primitive(PRIM_ENC, vec![key.clone(), value_nil()], 0);
		let mut capabilities = CapabilityIndex::default();
		capabilities.insert(&source);
		for held in [false, true] {
			for phase in [1, 2] {
				let mut attacker = make_attacker_state(vec![value_nil()]);
				if held {
					attacker = make_attacker_state(vec![value_nil(), source.clone()]);
				}
				attacker.current_phase = phase;
				for (term, expected) in [
					(target.clone(), held && phase == 2),
					(
						Value::primitive(PRIM_HASH, vec![target.clone()], 0),
						held && phase == 2,
					),
					(
						Value::primitive(PRIM_ENC, vec![other.clone(), value_nil()], 0),
						false,
					),
					(
						Value::primitive(
							PRIM_ENC,
							vec![
								key.clone(),
								Value::primitive(PRIM_HASH, vec![hidden.clone()], 0),
							],
							0,
						),
						false,
					),
				] {
					assert_eq!(obtainable(&term, &capabilities, &attacker), expected);
					assert_eq!(obtainable(&term, &capabilities, &attacker), expected);
				}
				if held && phase == 2 {
					let inputs = KnowledgeInputs::new(&capabilities, &attacker)
						.of_value(&target)
						.unwrap();
					assert!(inputs.contains(&attacker.knows(&source).unwrap()));
					assert!(
						can_reconstruct_primitive(
							&Arc::new(source.as_primitive().unwrap().clone()),
							&capabilities,
							&attacker
						)
						.is_none()
					);
				}
			}
		}
	}

	#[test]
	fn an_unscoped_deduction_walks_a_shared_term_once() {
		let leaf = make_constant("unscoped_deduction_leaf");
		let capabilities = CapabilityIndex::default();
		let known = make_attacker_state(vec![leaf.clone()]);
		let unknown = make_attacker_state(vec![]);
		let mut term = leaf;
		for _ in 0..40 {
			term = make_primitive(PRIM_HASH, vec![term.clone(), term.clone(), term], 0);
		}
		assert!(MEMO.with(|memo| memo.borrow().is_none()));
		assert!(obtainable(&term, &capabilities, &known));
		assert!(!obtainable(&term, &capabilities, &unknown));
		assert!(MEMO.with(|memo| memo.borrow().is_none()));
		let _scope = DeductionMemo::scoped(&capabilities, &unknown);
		assert!(!obtainable(&term, &capabilities, &unknown));
		assert!(obtainable(&term, &capabilities, &known));
		assert!(!obtainable(&term, &capabilities, &unknown));
		assert!(MEMO.with(|memo| {
			memo.borrow()
				.as_ref()
				.unwrap()
				.is_for(&capabilities, &unknown)
		}));
	}

	#[test]
	fn a_rewrite_cache_releases_discarded_inputs_after_eviction() {
		crate::context::enter_generation(crate::context::next_generation());
		let p = Arc::new(Primitive::new(
			PRIM_HASH,
			vec![make_constant("cache_lifetime")],
			0,
		));
		let weak = Arc::downgrade(&p);
		assert!(can_rewrite(&p).0);
		assert!(rewrite_cache_get(crate::hashing::primitive_hash(&p), &p).is_some());
		drop(p);
		for index in 0..TERM_MEMO_RECENT {
			let next = Arc::new(Primitive::new(
				PRIM_HASH,
				vec![make_constant(&format!("rewrite_eviction_{index}"))],
				0,
			));
			rewrite_cache_put(
				crate::hashing::primitive_hash(&next),
				&next,
				&(true, Value::Primitive(Arc::clone(&next))),
			);
		}
		assert!(weak.upgrade().is_none());
	}

	#[test]
	fn rewrite_pointer_aliases_release_their_results_after_eviction() {
		let mut cache = RewriteCache::default();
		let original = Arc::new(Primitive::new(
			PRIM_HASH,
			vec![make_constant("pointer_alias_original")],
			0,
		));
		let observed = Arc::downgrade(&original);
		let twin = Arc::new((*original).clone());
		let hash = crate::hashing::primitive_hash(&original);
		cache.put(
			hash,
			&original,
			true,
			Value::Primitive(Arc::clone(&original)),
		);
		assert!(cache.get(hash, &twin).is_some());
		assert!(cache.get(hash, &twin).is_some());
		drop((original, twin));
		for i in 0..TERM_MEMO_POINTERS {
			let next = Arc::new(Primitive::new(
				PRIM_HASH,
				vec![make_constant(&format!("pointer_alias_eviction_{i}"))],
				0,
			));
			cache.put(
				crate::hashing::primitive_hash(&next),
				&next,
				true,
				Value::Primitive(Arc::clone(&next)),
			);
		}
		assert!(observed.upgrade().is_none());
	}

	#[test]
	fn rewrite_pointer_hits_preserve_collisions_and_checked_instances() {
		let a = make_constant("pointer_collision_a");
		let b = make_constant("pointer_collision_b");
		let pass = Arc::new(Primitive::new(PRIM_ASSERT, vec![a.clone(), a.clone()], 0));
		let fail = Arc::new(Primitive::new(PRIM_ASSERT, vec![a, b], 0));
		fail.hash.set(crate::hashing::primitive_hash(&pass));
		let mut checked = (*fail).clone();
		checked.instance_check = true;
		let checked = Arc::new(checked);
		for _ in 0..3 {
			assert!(can_rewrite(&pass).0);
			let (succeeded, value) = can_rewrite(&fail);
			assert!(!succeeded);
			assert!(!value.as_primitive().unwrap().instance_check);
			let (succeeded, value) = can_rewrite(&checked);
			assert!(!succeeded);
			assert!(value.as_primitive().unwrap().instance_check);
		}
	}

	#[test]
	fn a_rewrite_cached_under_one_generation_is_not_served_under_the_next() {
		crate::context::enter_generation(crate::context::next_generation());
		let k = make_constant("tgen_k");
		let m = make_constant("tgen_m");
		let enc = make_primitive(primitive_get_enum("ENC").unwrap(), vec![k.clone(), m], 0);
		let dec = make_primitive(primitive_get_enum("DEC").unwrap(), vec![k, enc], 0);
		let Value::Primitive(p) = &dec else {
			panic!("expected a primitive");
		};
		let key = crate::hashing::primitive_hash(p);
		assert!(can_rewrite(p).0);
		assert!(rewrite_cache_get(key, p).is_some());
		crate::context::enter_generation(crate::context::next_generation());
		assert!(rewrite_cache_get(key, p).is_none());
	}

	fn weak_index(v: &Value, onset: i32) -> CapabilityIndex {
		let Value::Primitive(p) = v else {
			panic!("expected a primitive");
		};
		let mut annotated = (**p).clone();
		annotated.capabilities.set(Capability::Weak, onset);
		let mut index = CapabilityIndex::default();
		index.insert(&Value::Primitive(Arc::new(annotated)));
		index
	}

	#[test]
	fn a_reused_nonce_needs_two_distinct_terms_under_one_key_and_nonce() {
		let k = make_constant("rn_k");
		let n = make_constant("rn_n");
		let ad = make_constant("rn_ad");
		let m1 = make_constant("rn_m1");
		let m2 = make_constant("rn_m2");
		let e1 = make_primitive(PRIM_AEAD_ENC, vec![k.clone(), n.clone(), m1, ad.clone()], 0);
		let e2 = make_primitive(
			PRIM_AEAD_ENC,
			vec![k.clone(), n.clone(), m2.clone(), ad.clone()],
			0,
		);
		let other_nonce = make_primitive(
			PRIM_AEAD_ENC,
			vec![k.clone(), make_constant("rn_n2"), m2.clone(), ad.clone()],
			0,
		);
		let other_key = make_primitive(PRIM_AEAD_ENC, vec![make_constant("rn_k2"), n, m2, ad], 0);
		let Value::Primitive(p1) = &e1 else {
			panic!("expected a primitive");
		};
		let Value::Primitive(p_other) = &other_nonce else {
			panic!("expected a primitive");
		};
		let confirmed = |known: Vec<Value>, pair: [Value; 2]| {
			let mut attacker = make_attacker_state(known);
			attacker.reused = Arc::new(vec![pair]);
			attacker
		};
		assert!(reused_pair(&e1, &e2));
		assert!(!reused_pair(&e1, &e1));
		assert!(!reused_pair(&e1, &other_nonce));
		assert!(!reused_pair(&e1, &other_key));
		let pair = [e1.clone(), e2.clone()];
		assert!(reused(p1, &confirmed(vec![e1.clone(), e2.clone()], pair.clone())).is_some());
		assert!(reused(p1, &confirmed(vec![e1.clone()], pair.clone())).is_none());
		assert!(reused(p_other, &confirmed(vec![e1.clone(), e2.clone()], pair)).is_none());
		assert!(reused(p1, &make_attacker_state(vec![e1.clone(), e2.clone()])).is_none());
	}

	#[test]
	fn a_reused_nonce_makes_a_ciphertext_buildable_without_its_key_or_nonce() {
		let k = make_constant("rf_k");
		let n = make_constant("rf_n");
		let ad = make_constant("rf_ad");
		let e1 = make_primitive(
			PRIM_AEAD_ENC,
			vec![k.clone(), n.clone(), make_constant("rf_m1"), ad.clone()],
			0,
		);
		let e2 = make_primitive(
			PRIM_AEAD_ENC,
			vec![k.clone(), n.clone(), make_constant("rf_m2"), ad.clone()],
			0,
		);
		let m3 = make_constant("rf_m3");
		let Value::Primitive(target) =
			make_primitive(PRIM_AEAD_ENC, vec![k, n, m3.clone(), ad.clone()], 0)
		else {
			panic!("expected a primitive");
		};
		let capabilities = CapabilityIndex::default();
		let mut with_pair =
			make_attacker_state(vec![e1.clone(), e2.clone(), m3.clone(), ad.clone()]);
		with_pair.reused = Arc::new(vec![[e1.clone(), e2]]);
		let result = can_reconstruct_primitive(&target, &capabilities, &with_pair)
			.expect("forgeable under reuse");
		assert!(matches!(result.forged, Some(Forged::Reuse(_))));
		assert_eq!(result.from.len(), 2);
		let without_pair = make_attacker_state(vec![e1, m3, ad]);
		assert!(can_reconstruct_primitive(&target, &capabilities, &without_pair).is_none());
	}

	#[test]
	fn can_break_weak_reveals_every_in_range_argument() {
		let m = make_constant("cbw_m");
		let n = make_constant("cbw_n");
		let h = make_primitive(PRIM_HASH, vec![m.clone(), n.clone()], 0);
		let Value::Primitive(hp) = &h else {
			panic!("expected a primitive");
		};
		let capabilities = weak_index(&h, 0);
		let attacker = make_attacker_state(vec![h.clone()]);

		let revealed = can_break_weak(hp, &capabilities, &attacker).expect("weak is in force");
		assert_eq!(revealed.len(), 2);
		assert!(revealed.iter().any(|v| v.equivalent(&m, true)));
		assert!(revealed.iter().any(|v| v.equivalent(&n, true)));
	}

	#[test]
	fn can_break_weak_is_none_before_its_onset_phase() {
		let m = make_constant("cbwp_m");
		let h = make_primitive(PRIM_HASH, vec![m], 0);
		let Value::Primitive(hp) = &h else {
			panic!("expected a primitive");
		};
		let capabilities = weak_index(&h, 2);
		let mut attacker = make_attacker_state(vec![h.clone()]);

		attacker.current_phase = 0;
		assert!(can_break_weak(hp, &capabilities, &attacker).is_none());
		attacker.current_phase = 1;
		assert!(can_break_weak(hp, &capabilities, &attacker).is_none());
		attacker.current_phase = 2;
		assert!(can_break_weak(hp, &capabilities, &attacker).is_some());
		attacker.current_phase = 3;
		assert!(can_break_weak(hp, &capabilities, &attacker).is_some());
	}

	#[test]
	fn can_break_weak_is_none_without_an_annotation() {
		let m = make_constant("cbwn_m");
		let h = make_primitive(PRIM_HASH, vec![m], 0);
		let Value::Primitive(hp) = &h else {
			panic!("expected a primitive");
		};
		let capabilities = CapabilityIndex::default();
		let attacker = make_attacker_state(vec![h.clone()]);
		assert!(can_break_weak(hp, &capabilities, &attacker).is_none());
	}

	#[test]
	fn can_rewrite_split_concat() {
		let a = make_constant("cr_a");
		let b = make_constant("cr_b");
		let concat = make_primitive(PRIM_CONCAT, vec![a.clone(), b.clone()], 0);
		let split_at = |output: usize| {
			Arc::new(Primitive {
				id: PRIM_SPLIT,
				arguments: vec![concat.clone()],
				output,
				instance: 0,
				instance_check: false,
				capabilities: Capabilities::default(),
				threshold: 0,
				hash: HashCell::default(),
			})
		};
		for (output, expected) in [(0, a), (1, b)] {
			let (rewritten, value) = can_rewrite(&split_at(output));
			assert!(rewritten);
			assert!(value.equivalent(&expected, true));
		}
		let beyond = split_at(2);
		let (rewritten, value) = can_rewrite(&beyond);
		assert!(!rewritten);
		assert!(value.equivalent(&Value::Primitive(beyond), true));
	}

	#[test]
	fn can_rewrite_pke_dec_with_projected_key() {
		let sk1 = make_constant("crpk_sk1");
		let sk2 = make_constant("crpk_sk2");
		let m = make_constant("crpk_m");
		let pair = make_primitive(PRIM_CONCAT, vec![sk1, sk2.clone()], 0);
		let proj = make_primitive(PRIM_SPLIT, vec![pair], 1);
		let pk = make_primitive(PRIM_PUBKEY, vec![proj], 0);
		let enc = make_primitive(PRIM_PKE_ENC, vec![pk, m.clone()], 0);
		let dec = Primitive {
			id: PRIM_PKE_DEC,
			arguments: vec![sk2, enc],
			output: 0,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let (rewritten, value) = can_rewrite(&Arc::new(dec));
		assert!(rewritten);
		assert!(value.equivalent(&m, true));
	}

	#[test]
	fn can_reconstruct_primitive_projection() {
		let a = make_constant("crproj_a");
		let b = make_constant("crproj_b");
		let hash_a = make_primitive(PRIM_HASH, vec![a], 0);
		let hash_b = make_primitive(PRIM_HASH, vec![b.clone()], 0);
		let pair = make_primitive(PRIM_CONCAT, vec![hash_a, hash_b], 0);
		let proj = Primitive {
			id: PRIM_SPLIT,
			arguments: vec![pair],
			output: 1,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let capabilities = CapabilityIndex::default();
		let attacker = make_attacker_state(vec![b]);
		assert!(can_reconstruct_primitive(&Arc::new(proj), &capabilities, &attacker).is_some());
	}

	fn ring(members: [&Value; 3], message: &Value, signature: &Value) -> Arc<Primitive> {
		Arc::new(Primitive {
			id: PRIM_RINGSIGNVERIF,
			arguments: vec![
				members[0].clone(),
				members[1].clone(),
				members[2].clone(),
				message.clone(),
				signature.clone(),
			],
			output: 0,
			instance: 0,
			instance_check: true,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		})
	}

	#[test]
	fn a_ring_signature_verifies_only_against_the_ring_it_was_made_over() {
		let (a, b, c) = (
			make_constant("rsv_a"),
			make_constant("rsv_b"),
			make_constant("rsv_c"),
		);
		let m = make_constant("rsv_m");
		let ga = make_primitive(PRIM_PUBKEY, vec![a.clone()], 0);
		let gb = make_primitive(PRIM_PUBKEY, vec![b], 0);
		let gc = make_primitive(PRIM_PUBKEY, vec![c], 0);
		let sig = make_primitive(PRIM_RINGSIGN, vec![a, gb.clone(), gc.clone(), m.clone()], 0);

		assert!(
			can_rewrite(&ring([&ga, &gb, &gc], &m, &sig)).0,
			"the ring it was made over verifies"
		);
		assert!(
			can_rewrite(&ring([&gb, &ga, &gc], &m, &sig)).0,
			"a ring names a set, so its order does not matter"
		);
		assert!(
			!can_rewrite(&ring([&ga, &ga, &ga], &m, &sig)).0,
			"a ring signature binds the whole ring, so a verifier whose ring collapsed \
			 onto one member must not accept it: each verifier position has to claim a \
			 distinct position of the signature's own ring"
		);
		assert!(
			!can_rewrite(&ring([&ga, &gb, &gb], &m, &sig)).0,
			"nor one whose ring repeats a member the signature names once"
		);
		assert!(
			!can_rewrite(&ring([&ga, &gb, &ga], &m, &sig)).0,
			"nor one that drops a member in favour of a duplicate"
		);
	}

	#[test]
	fn can_rewrite_assert_matching() {
		let a = make_constant("cra_a");
		let assert_prim = Primitive {
			id: PRIM_ASSERT,
			arguments: vec![a.clone(), a.clone()],
			output: 0,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let (rewritten, _) = can_rewrite(&Arc::new(assert_prim));
		assert!(rewritten);
	}

	#[test]
	fn can_rewrite_assert_mismatch() {
		let a = make_constant("cram_a");
		let b = make_constant("cram_b");
		let assert_prim = Primitive {
			id: PRIM_ASSERT,
			arguments: vec![a, b],
			output: 0,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let (rewritten, _) = can_rewrite(&Arc::new(assert_prim));
		assert!(!rewritten);
	}

	#[test]
	fn recompose_counts_distinct_held_shares_against_the_threshold() {
		let secret = make_constant("rct_secret");
		let split = |t: usize| {
			let mut p = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], 0);
			p.threshold = t;
			p
		};
		let share =
			|t: usize, output: usize| Value::Primitive(Arc::new(split(t).with_output(output)));
		let two_of_five = make_attacker_state(vec![share(2, 1), share(2, 4)]);
		let opened = can_recompose(&split(2), &two_of_five).expect("any two shares recover");
		assert!(opened.revealed.equivalent(&secret, true));
		let short = make_attacker_state(vec![share(3, 1), share(3, 2), share(3, 2)]);
		assert!(can_recompose(&split(3), &short).is_none());
		let enough = make_attacker_state(vec![share(3, 1), share(3, 2), share(3, 4)]);
		assert!(can_recompose(&split(3), &enough).is_some());
		let wrong_threshold = make_attacker_state(vec![share(2, 1), share(2, 2), share(3, 4)]);
		assert!(can_recompose(&split(3), &wrong_threshold).is_none());
	}

	fn tsh_share(secret: &Value, t: usize, output: usize) -> Value {
		let mut p = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], output);
		p.threshold = t;
		Value::Primitive(Arc::new(p))
	}

	fn tsh_commitments(nonces: &[&str]) -> Value {
		Value::primitive(
			PRIM_CONCAT,
			nonces
				.iter()
				.map(|name| {
					let nonce = if *name == "nil" {
						value_nil()
					} else {
						make_constant(name)
					};
					Value::primitive(PRIM_PUBKEY, vec![nonce], 0)
				})
				.collect(),
			0,
		)
	}

	fn tsh_partial(share: Value, nonce: &str, commitments: &Value, message: &Value) -> Value {
		make_primitive(
			PRIM_THRESHOLD_SIGN,
			vec![
				share,
				make_constant(nonce),
				commitments.clone(),
				message.clone(),
			],
			0,
		)
	}

	#[test]
	fn a_join_of_partials_over_distinct_shares_is_the_plain_signature() {
		let k = make_constant("cmb_k");
		let m = make_constant("cmb_m");
		let c = tsh_commitments(&["cmb_n1", "cmb_n2"]);
		let join = make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![
				tsh_partial(tsh_share(&k, 2, 0), "cmb_n1", &c, &m),
				tsh_partial(tsh_share(&k, 2, 2), "cmb_n2", &c, &m),
			],
			0,
		);
		let (ok, reduced) = rewrite(&join);
		assert!(ok);
		assert!(reduced.equivalent(&make_primitive(PRIM_SIGN, vec![k, m], 0), true));
	}

	#[test]
	fn partials_that_disagree_or_repeat_a_share_do_not_combine() {
		let k = make_constant("cmd_k");
		let m = make_constant("cmd_m");
		let c = tsh_commitments(&["cmd_n1", "cmd_n2", "cmd_n3"]);
		let other = tsh_commitments(&["cmd_n2", "cmd_other"]);
		let sig = make_primitive(PRIM_SIGN, vec![k.clone(), m.clone()], 0);
		let mixed = make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![
				tsh_partial(tsh_share(&k, 2, 0), "cmd_n1", &c, &m),
				tsh_partial(tsh_share(&k, 2, 1), "cmd_n2", &other, &m),
			],
			0,
		);
		assert!(!rewrite(&mixed).1.equivalent(&sig, true));
		let repeated = make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![
				tsh_partial(tsh_share(&k, 2, 1), "cmd_n1", &c, &m),
				tsh_partial(tsh_share(&k, 2, 1), "cmd_n2", &c, &m),
			],
			0,
		);
		assert!(!rewrite(&repeated).1.equivalent(&sig, true));
		let short = make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![
				tsh_partial(tsh_share(&k, 3, 0), "cmd_n1", &c, &m),
				tsh_partial(tsh_share(&k, 3, 1), "cmd_n2", &c, &m),
			],
			0,
		);
		assert!(!rewrite(&short).1.equivalent(&sig, true));
		let enough = make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![
				tsh_partial(tsh_share(&k, 3, 0), "cmd_n1", &c, &m),
				tsh_partial(tsh_share(&k, 3, 1), "cmd_n2", &c, &m),
				tsh_partial(tsh_share(&k, 3, 4), "cmd_n3", &c, &m),
			],
			0,
		);
		assert!(rewrite(&enough).1.equivalent(&sig, true));
	}

	#[test]
	fn a_join_of_verification_shares_is_the_group_key() {
		let k = make_constant("cmp_k");
		let join = make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![
				make_primitive(PRIM_PUBKEY, vec![tsh_share(&k, 2, 1)], 0),
				make_primitive(PRIM_PUBKEY, vec![tsh_share(&k, 2, 2)], 0),
			],
			0,
		);
		let (ok, reduced) = rewrite(&join);
		assert!(ok);
		assert!(reduced.equivalent(&make_primitive(PRIM_PUBKEY, vec![k], 0), true));
	}

	#[test]
	fn a_signature_is_reconstructed_from_a_held_partial_and_a_held_share() {
		let k = make_constant("cmr_k");
		let m = make_constant("cmr_m");
		let c = tsh_commitments(&["cmr_n1", "nil"]);
		let capabilities = CapabilityIndex::default();
		let sig = make_primitive(PRIM_SIGN, vec![k.clone(), m.clone()], 0);
		let Value::Primitive(sig_p) = &sig else {
			panic!("a primitive");
		};
		let partial = tsh_partial(tsh_share(&k, 2, 0), "cmr_n1", &c, &m);
		let with_share = make_attacker_state(vec![
			partial.clone(),
			tsh_share(&k, 2, 2),
			value_nil(),
			c.clone(),
			m.clone(),
		]);
		let built =
			can_reconstruct_primitive(sig_p, &capabilities, &with_share).expect("t pieces suffice");
		assert_eq!(built.from.len(), 2);
		assert!(built.from.iter().any(|f| f.equivalent(&partial, true)));
		assert!(built.forged.is_none());
		let same_share = make_attacker_state(vec![
			partial.clone(),
			tsh_share(&k, 2, 0),
			value_nil(),
			c.clone(),
			m.clone(),
		]);
		assert!(can_reconstruct_primitive(sig_p, &capabilities, &same_share).is_none());
		let partial_only = make_attacker_state(vec![partial, value_nil(), c, m]);
		assert!(can_reconstruct_primitive(sig_p, &capabilities, &partial_only).is_none());
	}

	#[test]
	fn partials_under_different_commitments_do_not_reconstruct_a_signature() {
		let k = make_constant("cmz_k");
		let m = make_constant("cmz_m");
		let capabilities = CapabilityIndex::default();
		let sig = make_primitive(PRIM_SIGN, vec![k.clone(), m.clone()], 0);
		let Value::Primitive(sig_p) = &sig else {
			panic!("a primitive");
		};
		let attacker = make_attacker_state(vec![
			tsh_partial(
				tsh_share(&k, 2, 0),
				"cmz_n1",
				&tsh_commitments(&["cmz_n1", "cmz_n2"]),
				&m,
			),
			tsh_partial(
				tsh_share(&k, 2, 1),
				"cmz_n2",
				&tsh_commitments(&["cmz_n1", "cmz_n2", "cmz_other"]),
				&m,
			),
			value_nil(),
		]);
		assert!(can_reconstruct_primitive(sig_p, &capabilities, &attacker).is_none());
		let agreeing = make_attacker_state(vec![
			tsh_partial(
				tsh_share(&k, 2, 0),
				"cmz_n1",
				&tsh_commitments(&["cmz_n1", "cmz_n2"]),
				&m,
			),
			tsh_partial(
				tsh_share(&k, 2, 1),
				"cmz_n2",
				&tsh_commitments(&["cmz_n1", "cmz_n2"]),
				&m,
			),
			value_nil(),
		]);
		assert!(can_reconstruct_primitive(sig_p, &capabilities, &agreeing).is_some());
	}

	#[test]
	fn combining_partials_binds_every_nonce_to_the_shared_commitments() {
		let k = make_private("binding_key");
		let m = make_constant("binding_message");
		let commitments = tsh_commitments(&["binding_nonce_a", "binding_nonce_b"]);
		let first = tsh_partial(tsh_share(&k, 2, 0), "binding_nonce_a", &commitments, &m);
		let second = tsh_partial(tsh_share(&k, 2, 1), "binding_nonce_b", &commitments, &m);
		let invalid = tsh_partial(tsh_share(&k, 2, 1), "binding_wrong_nonce", &commitments, &m);
		let valid = Primitive::new(PRIM_THRESHOLD_JOIN, vec![first.clone(), second], 0);
		assert!(can_combine(&valid).is_some());
		let invalid = Primitive::new(PRIM_THRESHOLD_JOIN, vec![first, invalid], 0);
		assert!(can_combine(&invalid).is_none());
		let attacker = make_attacker_state(invalid.arguments.clone());
		let signature = Arc::new(Primitive::new(PRIM_SIGN, vec![k, m], 0));
		assert!(
			can_reconstruct_primitive(&signature, &CapabilityIndex::default(), &attacker).is_none()
		);
	}

	fn combination_holds(target: &Primitive, from: &[Value]) -> bool {
		combines_into(target.id).any(|(join, rule)| {
			let joined = Primitive::new(join, from.to_vec(), 0);
			combine_with(&joined, rule).is_some_and(|built| {
				built.equivalent(&Value::Primitive(Arc::new(target.clone())), true)
			})
		})
	}

	#[test]
	fn a_leaked_share_uses_a_known_nonce_from_the_committed_session() {
		let k = make_private("binding_reconstruct_key");
		let m = make_constant("binding_reconstruct_message");
		let commitments = tsh_commitments(&["binding_honest_nonce", "binding_attacker_nonce"]);
		let partial = tsh_partial(
			tsh_share(&k, 2, 1),
			"binding_honest_nonce",
			&commitments,
			&m,
		);
		let nonce = make_constant("binding_attacker_nonce");
		let attacker = make_attacker_state(vec![
			partial,
			tsh_share(&k, 2, 0),
			nonce,
			commitments,
			m.clone(),
		]);
		let signature = Arc::new(Primitive::new(PRIM_SIGN, vec![k, m], 0));
		let built =
			can_reconstruct_primitive(&signature, &CapabilityIndex::default(), &attacker).unwrap();
		assert!(combination_holds(&signature, &built.from));
	}

	#[test]
	fn threshold_sign_nonce_disclosure_needs_the_signing_context() {
		let k = make_constant("tsnd_k");
		let share = tsh_share(&k, 2, 0);
		let nonce = make_constant("tsnd_nonce");
		let commitments = make_constant("tsnd_commitments");
		let message = make_constant("tsnd_message");
		let partial = tsh_partial(share.clone(), "tsnd_nonce", &commitments, &message);
		let Value::Primitive(p) = &partial else {
			panic!("a partial signature");
		};
		let capabilities = CapabilityIndex::default();
		let context = [nonce, commitments, message];
		let mut known = vec![partial.clone()];
		known.extend(context.iter().cloned());
		let attacker = make_attacker_state(known);
		let result =
			can_decompose(p, &capabilities, &attacker).expect("the nonce exposes the share");
		assert_eq!(result.revealed.len(), 1);
		assert!(result.revealed[0].equivalent(&share, true));
		assert!(
			!obtainable(&k, &capabilities, &attacker),
			"one share is not the key"
		);

		for missing in 0..context.len() {
			let mut known = vec![partial.clone()];
			known.extend(
				context
					.iter()
					.enumerate()
					.filter(|(i, _)| *i != missing)
					.map(|(_, value)| value.clone()),
			);
			if missing == 0 {
				known.push(make_primitive(PRIM_PUBKEY, vec![context[0].clone()], 0));
			}
			assert!(
				can_decompose(p, &capabilities, &make_attacker_state(known)).is_none(),
				"missing input {missing} must prevent share recovery; a commitment is not the nonce"
			);
		}
	}

	#[test]
	fn can_decompose_enc_with_key() {
		let key = make_constant("cd_key");
		let msg = make_constant("cd_msg");
		let p = Primitive {
			id: PRIM_ENC,
			arguments: vec![key.clone(), msg.clone()],
			output: 0,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let capabilities = CapabilityIndex::default();
		let attacker = make_attacker_state(vec![key]);
		let result = can_decompose(&p, &capabilities, &attacker);
		assert!(result.is_some());
		assert!(
			result
				.unwrap()
				.revealed
				.iter()
				.any(|v| v.equivalent(&msg, true))
		);
	}

	#[test]
	fn can_decompose_kem_with_private_key_reveals_shared_secret_and_randomness() {
		let dk = make_constant("kd_dk");
		let r = make_constant("kd_r");
		let ek = make_primitive(PRIM_PUBKEY, vec![dk.clone()], 0);
		let ct = Primitive {
			id: PRIM_KEM_ENCAP,
			arguments: vec![ek.clone(), r.clone()],
			output: 1,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let capabilities = CapabilityIndex::default();
		let attacker = make_attacker_state(vec![dk]);
		let revealed = can_decompose(&ct, &capabilities, &attacker)
			.expect("holder of the private key can decapsulate")
			.revealed;
		let expected = make_primitive(PRIM_KEM_ENCAP, vec![ek, r.clone()], 0);
		assert!(revealed.iter().any(|v| v.equivalent(&expected, true)));
		assert!(revealed.iter().any(|v| v.equivalent(&r, true)));
		let ciphertext = Value::Primitive(Arc::new(ct)).hash_value();
		assert!(!revealed.iter().any(|v| v.hash_value() == ciphertext));
	}

	#[test]
	fn can_decompose_kem_without_private_key() {
		let dk = make_constant("kn_dk");
		let r = make_constant("kn_r");
		let ek = make_primitive(PRIM_PUBKEY, vec![dk], 0);
		let ct = Primitive {
			id: PRIM_KEM_ENCAP,
			arguments: vec![ek.clone(), r],
			output: 1,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let capabilities = CapabilityIndex::default();
		let attacker = make_attacker_state(vec![ek]);
		assert!(can_decompose(&ct, &capabilities, &attacker).is_none());
	}

	#[test]
	fn kem_decap_rewrites_to_the_shared_secret() {
		let dk = make_constant("kr_dk");
		let r = make_constant("kr_r");
		let ek = make_primitive(PRIM_PUBKEY, vec![dk.clone()], 0);
		let ct = make_primitive(PRIM_KEM_ENCAP, vec![ek.clone(), r.clone()], 1);
		let decap = Primitive {
			id: PRIM_KEM_DECAP,
			arguments: vec![dk, ct],
			output: 0,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let (rewritten, value) = can_rewrite(&Arc::new(decap));
		assert!(rewritten);
		let expected = make_primitive(PRIM_KEM_ENCAP, vec![ek, r], 0);
		assert!(value.equivalent(&expected, true));
	}

	#[test]
	fn kem_decap_does_not_rewrite_under_the_wrong_key() {
		let dk = make_constant("kw_dk");
		let other = make_constant("kw_other");
		let r = make_constant("kw_r");
		let ek = make_primitive(PRIM_PUBKEY, vec![dk], 0);
		let ct = make_primitive(PRIM_KEM_ENCAP, vec![ek, r], 1);
		let decap = Primitive {
			id: PRIM_KEM_DECAP,
			arguments: vec![other, ct],
			output: 0,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let (rewritten, _) = can_rewrite(&Arc::new(decap));
		assert!(!rewritten);
	}

	#[test]
	fn can_decompose_enc_without_key() {
		let key = make_constant("cd_nk_key");
		let msg = make_constant("cd_nk_msg");
		let p = Primitive {
			id: PRIM_ENC,
			arguments: vec![key, msg],
			output: 0,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let capabilities = CapabilityIndex::default();
		let attacker = make_attacker_state(vec![]);
		assert!(can_decompose(&p, &capabilities, &attacker).is_none());
	}

	fn rewrite(value: &Value) -> (bool, Value) {
		crate::context::enter_generation(crate::context::next_generation());
		let Value::Primitive(p) = value else {
			panic!("expected a primitive");
		};
		can_rewrite(p)
	}

	#[test]
	fn failed_checks_report_the_term_with_its_arguments_reduced() {
		let left = make_constant("rw_failure_left");
		let right = make_constant("rw_failure_right");
		let check = |a, b| make_primitive(PRIM_ASSERT, vec![a, b], 0);
		let failed = check(left.clone(), right.clone());
		let unchanged = make_primitive(PRIM_HASH, vec![left.clone()], 0);
		let reduced = make_primitive(
			PRIM_DEC,
			vec![
				left.clone(),
				make_primitive(PRIM_ENC, vec![left.clone(), right.clone()], 0),
			],
			0,
		);
		for (term, expected) in [
			(failed.clone(), failed.clone()),
			(
				check(failed.clone(), right.clone()),
				check(failed, right.clone()),
			),
			(
				check(unchanged.clone(), right.clone()),
				check(unchanged, right.clone()),
			),
			(check(reduced, left.clone()), check(right, left)),
		] {
			for _ in 0..2 {
				let (ok, value) = rewrite(&term);
				assert!(!ok);
				assert!(crate::theory::structurally_identical(&value, &expected));
			}
		}
	}

	#[test]
	fn unchanged_shared_terms_keep_their_nodes_during_rewriting() {
		let mut term = make_constant("rw_shared_unchanged");
		for _ in 0..40 {
			term = make_primitive(PRIM_HASH, vec![term.clone(), term.clone(), term], 0);
		}
		let (ok, value) = rewrite(&term);
		assert!(ok);
		assert!(value.same_term(&term));
	}

	#[test]
	fn a_decryption_that_undoes_its_encryption_rewrites_to_the_plaintext() {
		let k = make_constant("rw_k");
		let m = make_constant("rw_m");
		let enc = make_primitive(PRIM_ENC, vec![k.clone(), m.clone()], 0);
		let (ok, value) = rewrite(&make_primitive(PRIM_DEC, vec![k, enc], 0));
		assert!(ok);
		assert!(value.equivalent(&m, true));
	}

	#[test]
	fn a_checked_decryption_under_the_wrong_key_is_reported_as_a_failure() {
		let k = make_constant("rwf_k");
		let other = make_constant("rwf_other");
		let m = make_constant("rwf_m");
		let ad = make_constant("rwf_ad");
		let n = make_constant("rwf_n");
		let sealed = make_primitive(PRIM_AEAD_ENC, vec![k, n.clone(), m, ad.clone()], 0);
		let dec = Value::Primitive(Arc::new(Primitive {
			id: PRIM_AEAD_DEC,
			arguments: vec![other, n, sealed, ad],
			output: 0,
			instance: 0,
			instance_check: true,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		}));
		let (ok, value) = rewrite(&dec);
		assert!(!ok);
		let failed = value
			.as_primitive()
			.expect("the check fails as a primitive");
		assert_eq!(failed.id, PRIM_AEAD_DEC);
		assert!(failed.instance_check);
		assert!(
			value.equivalent(&dec, true),
			"a failed check leaves the term that did not reduce"
		);
	}

	#[test]
	fn an_inner_rewrite_is_applied_before_the_outer_one_is_tried() {
		let k = make_constant("rwi_k");
		let m = make_constant("rwi_m");
		let inner = make_primitive(
			PRIM_DEC,
			vec![k.clone(), make_primitive(PRIM_ENC, vec![k, m.clone()], 0)],
			0,
		);
		let (ok, value) = rewrite(&make_primitive(PRIM_HASH, vec![inner], 0));
		assert!(ok);
		assert!(value.equivalent(&make_primitive(PRIM_HASH, vec![m], 0), true));
	}

	#[test]
	fn threshold_join_rebuilds_the_secret_from_two_distinct_shares() {
		let secret = make_constant("rws_secret");
		let share = |output: usize| {
			let mut p = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], output);
			p.threshold = 2;
			Value::Primitive(Arc::new(p))
		};
		let (ok, value) = rewrite(&make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![share(0), share(1)],
			0,
		));
		assert!(ok);
		assert!(value.equivalent(&secret, true));
	}

	#[test]
	fn a_three_of_five_join_needs_three_distinct_shares() {
		let secret = make_constant("rw35_secret");
		let share = |output: usize| {
			let mut p = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], output);
			p.threshold = 3;
			Value::Primitive(Arc::new(p))
		};
		let join = |shares: Vec<Value>| make_primitive(PRIM_THRESHOLD_JOIN, shares, 0);
		let (_, value) = rewrite(&join(vec![share(0), share(2), share(4)]));
		assert!(value.equivalent(&secret, true));
		let two = join(vec![share(0), share(4)]);
		let (_, value) = rewrite(&two);
		assert!(value.equivalent(&two, true));
		let repeated = join(vec![share(0), share(0), share(2)]);
		let (_, value) = rewrite(&repeated);
		assert!(value.equivalent(&repeated, true));
	}

	#[test]
	fn a_two_of_n_join_accepts_any_two_shares() {
		let secret = make_constant("rw2n_secret");
		let share = |output: usize| {
			let mut p = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], output);
			p.threshold = 2;
			Value::Primitive(Arc::new(p))
		};
		let (_, value) = rewrite(&make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![share(4), share(3)],
			0,
		));
		assert!(value.equivalent(&secret, true));
		let (_, value) = rewrite(&make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![share(1), share(3), share(0)],
			0,
		));
		assert!(value.equivalent(&secret, true));
	}

	#[test]
	fn two_shares_of_the_same_output_do_not_rebuild_anything() {
		let secret = make_constant("rwd_secret");
		let mut split = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], 0);
		split.threshold = 2;
		let share = Value::Primitive(Arc::new(split));
		let join = make_primitive(PRIM_THRESHOLD_JOIN, vec![share.clone(), share], 0);
		let (_, value) = rewrite(&join);
		assert!(
			value.equivalent(&join, true),
			"a threshold scheme needs distinct shares, so the join stays unreduced"
		);
	}

	#[test]
	fn rewriting_accepts_a_structurally_identical_cached_term() {
		let k = make_constant("rwc_k");
		let m = make_constant("rwc_m");
		let build = || {
			make_primitive(
				PRIM_DEC,
				vec![
					k.clone(),
					make_primitive(PRIM_ENC, vec![k.clone(), m.clone()], 0),
				],
				0,
			)
		};
		crate::context::enter_generation(crate::context::next_generation());
		let (Value::Primitive(p), Value::Primitive(q)) = (build(), build()) else {
			unreachable!()
		};
		assert!(!Arc::ptr_eq(&p, &q), "two separately built terms");
		can_rewrite(&p);
		assert!(can_rewrite(&q).1.equivalent(&m, true));
	}
}
