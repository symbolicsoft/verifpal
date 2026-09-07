/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::RefCell;
use std::sync::Arc;

use crate::context::Generational;
use crate::equivalence::{equivalent_primitives, memoised_pair};
use crate::primitive::*;
use crate::types::*;

pub(crate) struct TermMemo<R> {
	entries: IdMap<u64, Vec<TermMemoEntry<R>>>,
	inserted: usize,
	recent: std::collections::VecDeque<Arc<Primitive>>,
}

struct TermMemoEntry<R> {
	input: std::sync::Weak<Primitive>,
	result: R,
	value: Option<Value>,
}

const TERM_MEMO_SWEEP: usize = 65536;
const TERM_MEMO_RECENT: usize = 1024;

impl<R> Default for TermMemo<R> {
	fn default() -> Self {
		TermMemo {
			entries: IdMap::default(),
			inserted: 0,
			recent: std::collections::VecDeque::new(),
		}
	}
}

impl<R: Clone> TermMemo<R> {
	pub(crate) fn get(&self, key: u64, p: &Arc<Primitive>) -> Option<(R, Value)> {
		self.entries.get(&key)?.iter().find_map(|entry| {
			let held = entry.input.upgrade()?;
			(Arc::ptr_eq(&held, p) || structurally_identical_primitive(&held, p)).then(|| {
				(
					entry.result.clone(),
					entry.value.clone().unwrap_or(Value::Primitive(held)),
				)
			})
		})
	}

	pub(crate) fn put(&mut self, key: u64, p: &Arc<Primitive>, result: R, value: Value) {
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
		let value = match &value {
			Value::Primitive(output) if Arc::ptr_eq(p, output) => None,
			_ => Some(value),
		};
		bucket.push(TermMemoEntry {
			input: Arc::downgrade(p),
			result,
			value,
		});
	}

	fn sweep(&mut self) {
		self.entries.retain(|_, bucket| {
			bucket.retain(|entry| entry.input.strong_count() > 0);
			!bucket.is_empty()
		});
	}
}

type RewriteCache = TermMemo<bool>;

struct ObtainableMemo {
	owner: (*const PrincipalState, *const AttackerState),
	entries: IdMap<u64, Vec<(Value, bool)>>,
	index: Arc<StateIndex>,
}

impl ObtainableMemo {
	fn is_for_state(&self, ps: &PrincipalState) -> bool {
		std::ptr::eq(self.owner.0, ps)
	}

	fn is_for(&self, ps: &PrincipalState, attacker: &AttackerState) -> bool {
		self.is_for_state(ps) && std::ptr::eq(self.owner.1, attacker)
	}
}

pub(crate) struct StateIndex {
	slots_by_hash: IdMap<u64, Vec<usize>>,
}

impl StateIndex {
	pub(crate) fn of(ps: &PrincipalState) -> Arc<Self> {
		Arc::new(StateIndex {
			slots_by_hash: index_slots_by_hash(ps),
		})
	}
}

pub(crate) fn slots_equivalent_to(ps: &PrincipalState, value: &Value) -> Vec<usize> {
	let hash = value.hash_value();
	let indexed = MEMO.with(|m| {
		let borrowed = m.borrow();
		let memo = borrowed.as_ref()?;
		if !memo.is_for_state(ps) {
			return None;
		}
		Some(
			memo.index
				.slots_by_hash
				.get(&hash)
				.map(|candidates| {
					candidates
						.iter()
						.copied()
						.filter(|&i| value.equivalent(&ps.values[i].value, true))
						.collect()
				})
				.unwrap_or_default(),
		)
	});
	indexed.unwrap_or_else(|| {
		ps.values
			.iter()
			.enumerate()
			.filter(|(_, sv)| value.equivalent(&sv.value, true))
			.map(|(i, _)| i)
			.collect()
	})
}

fn index_slots_by_hash(ps: &PrincipalState) -> IdMap<u64, Vec<usize>> {
	let mut index: IdMap<u64, Vec<usize>> = IdMap::default();
	for (i, sv) in ps.values.iter().enumerate() {
		index.entry(sv.value.hash_value()).or_default().push(i);
	}
	index
}

pub(crate) fn structurally_identical_primitive(x: &Primitive, y: &Primitive) -> bool {
	x.id == y.id
		&& x.output == y.output
		&& x.threshold == y.threshold
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
	borrowed: std::marker::PhantomData<(&'a PrincipalState, &'a AttackerState)>,
}

impl<'a> DeductionMemo<'a> {
	fn ensure(ps: &'a PrincipalState, attacker: &'a AttackerState) -> DeductionMemo<'a> {
		let present = MEMO.with(|memo| {
			memo.borrow()
				.as_ref()
				.is_some_and(|memo| memo.is_for(ps, attacker))
		});
		if present {
			return DeductionMemo {
				previous: None,
				borrowed: std::marker::PhantomData,
			};
		}
		Self::scoped(ps, attacker, &StateIndex::of(ps))
	}

	pub(crate) fn scoped(
		ps: &'a PrincipalState,
		attacker: &'a AttackerState,
		index: &Arc<StateIndex>,
	) -> DeductionMemo<'a> {
		let installed = ObtainableMemo {
			owner: (ps as *const _, attacker as *const _),
			entries: IdMap::default(),
			index: Arc::clone(index),
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

fn memo_obtainable_get(
	key: u64,
	v: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<bool> {
	MEMO.with(|m| {
		let borrowed = m.borrow();
		let memo = borrowed.as_ref()?;
		if !memo.is_for(ps, attacker) {
			return None;
		}
		memo.entries
			.get(&key)?
			.iter()
			.find(|(candidate, _)| structurally_identical(candidate, v))
			.map(|(_, hit)| *hit)
	})
}

fn memo_obtainable_put(
	key: u64,
	v: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	result: bool,
) {
	MEMO.with(|m| {
		if let Some(memo) = m.borrow_mut().as_mut()
			&& memo.is_for(ps, attacker)
		{
			memo.entries
				.entry(key)
				.or_default()
				.push((v.clone(), result));
		}
	});
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

fn read_values(
	attacker: &AttackerState,
	value: &Value,
	out: &mut Vec<(SlotIdx, Value)>,
	seen: &mut Vec<Value>,
) {
	if seen.iter().any(|s| s.equivalent(value, true)) {
		return;
	}
	seen.push(value.clone());
	let Some(idx) = attacker.knows(value) else {
		return;
	};
	let Some(record) = attacker.derivation(idx) else {
		return;
	};
	match record {
		DerivationRecord::Obtained { slot } | DerivationRecord::Leaked { slot } => {
			out.push((*slot, value.clone()));
		}
		_ => {
			for ingredient in record.ingredients() {
				read_values(attacker, ingredient, out, seen);
			}
		}
	}
}

pub(crate) fn one_execution(attacker: &AttackerState, a: &Value, b: &Value) -> bool {
	let mut reads_a = Vec::new();
	let mut reads_b = Vec::new();
	read_values(attacker, a, &mut reads_a, &mut Vec::new());
	read_values(attacker, b, &mut reads_b, &mut Vec::new());
	reads_a.iter().all(|(slot_a, value_a)| {
		reads_b
			.iter()
			.all(|(slot_b, value_b)| slot_a != slot_b || value_a.equivalent(value_b, true))
	})
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
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<DecomposeResult> {
	if primitive_is_core(p.id) {
		return None;
	}
	let rule = primitive_get(p.id).ok()?.decompose.as_ref()?;
	if rule.output.is_some_and(|output| p.output != output) {
		return None;
	}
	let mut has = Vec::new();
	for &idx in rule.given.iter() {
		if idx >= p.arguments.len() {
			continue;
		}
		let a = &p.arguments[idx];
		let (filtered, valid) = (rule.filter)(p, a, idx);
		if !valid {
			continue;
		}
		if obtainable(&filtered, ps, attacker) {
			has.push(filtered);
		}
	}
	if has.len() >= rule.given.len() {
		let mut revealed = Vec::new();
		for reveal in &rule.reveals {
			match *reveal {
				Reveal::Output(output) => {
					revealed.push(Value::Primitive(Arc::new(p.with_output(output))));
				}
				Reveal::Argument(index) => {
					if let Some(argument) = p.arguments.get(index) {
						revealed.push(reduce_once(argument));
					}
				}
			}
		}
		if revealed.is_empty() {
			return None;
		}
		Some(DecomposeResult {
			revealed,
			used: has,
		})
	} else {
		None
	}
}

pub(crate) fn can_break_weak(
	p: &Primitive,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<Vec<Value>> {
	if primitive_is_core(p.id) {
		return None;
	}
	if !ps
		.capabilities
		.in_force(p, Capability::Weak, attacker.current_phase)
	{
		return None;
	}
	let spec = primitive_get(p.id).ok()?;
	let mut revealed = Vec::new();
	for &idx in &spec.weak_reveals {
		if let Some(a) = p.arguments.get(idx) {
			revealed.push(reduce_once(a));
		}
	}
	if let Some(output) = spec.weak_reveals_output {
		revealed.push(Value::Primitive(Arc::new(p.with_output(output))));
	}
	if revealed.is_empty() {
		return None;
	}
	Some(revealed)
}

pub(crate) fn obtainable(v: &Value, ps: &PrincipalState, attacker: &AttackerState) -> bool {
	let hash = v.hash_value();
	if attacker.knows_hashed(v, hash).is_some() {
		return true;
	}
	if matches!(v, Value::Constant(_)) {
		return false;
	}
	if let Some(hit) = memo_obtainable_get(hash, v, ps, attacker) {
		return hit;
	}
	let result = match v {
		Value::Primitive(p) => construction_inputs(p, ps, attacker).is_some(),
		Value::Constant(_) => false,
	};
	memo_obtainable_put(hash, v, ps, attacker, result);
	result
}

fn construction_inputs(
	p: &Arc<Primitive>,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<Vec<Value>> {
	if let Some(mut built) = can_reconstruct_primitive(p, ps, attacker) {
		if let Some(Forged::Reuse(pair)) = built.forged {
			built.from.extend(pair);
		}
		return Some(built.from);
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
			let mut inputs = can_decompose(&sibling, ps, attacker)?.used;
			inputs.insert(0, projected);
			Some(inputs)
		})
}

pub(crate) struct KnowledgeInputs<'a> {
	ps: &'a PrincipalState,
	attacker: &'a AttackerState,
	built: IdMap<usize, (Arc<Primitive>, Option<Vec<KnownIdx>>)>,
	_memo: DeductionMemo<'a>,
}

impl<'a> KnowledgeInputs<'a> {
	pub(crate) fn new(ps: &'a PrincipalState, attacker: &'a AttackerState) -> Self {
		Self {
			ps,
			attacker,
			built: IdMap::default(),
			_memo: DeductionMemo::ensure(ps, attacker),
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
		self.built.insert(key, (Arc::clone(p), None));
		let inputs = construction_inputs(p, self.ps, self.attacker)?;
		let mut known = Vec::new();
		let mut seen = IdSet::default();
		for input in inputs {
			for idx in self.of_value(&input)? {
				if seen.insert(idx.get()) {
					known.push(idx);
				}
			}
		}
		self.built.insert(key, (Arc::clone(p), Some(known.clone())));
		Some(known)
	}
}

pub(crate) fn can_recompose(p: &Primitive, attacker: &AttackerState) -> Option<RecomposeResult> {
	if primitive_is_core(p.id) {
		return None;
	}
	let rule = primitive_get(p.id).ok()?.recompose.as_ref()?;
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
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<ReconstructResult> {
	can_reconstruct_primitive_directly(p, ps, attacker).or_else(|| {
		let swapped = Arc::new(commutativity_swap(p)?);
		can_reconstruct_primitive_directly(&swapped, ps, attacker)
	})
}

fn can_reconstruct_primitive_directly(
	p: &Arc<Primitive>,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<ReconstructResult> {
	let (rewritten, rewrite_value) = can_rewrite(p);
	if !rewritten {
		return None;
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
	let forgeable_secret = ps
		.capabilities
		.forgeable_secret_position(rewritten_prim, attacker.current_phase);
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
		if obtainable(a, ps, attacker) {
			has.push(a.clone());
		}
	}
	if has.len() + skipped < rewritten_prim.arguments.len() {
		let from = combinable(rewritten_prim, ps, attacker)?;
		return Some(ReconstructResult {
			from,
			forged: None,
			combined: true,
		});
	}
	let forged = match (skipped, reused) {
		(0, _) => None,
		(_, Some(pair)) => Some(Forged::Reuse(pair)),
		(_, None) => Some(Forged::Assumption(Capability::Forgeable)),
	};
	Some(ReconstructResult {
		from: has,
		forged,
		combined: false,
	})
}

struct PartialGroup {
	split: Arc<Primitive>,
	agree: Vec<Value>,
	arity: usize,
	held: Vec<(usize, Value)>,
}

fn partial_groups(
	target: &Primitive,
	rule: &CombineRule,
	attacker: &AttackerState,
) -> Vec<PartialGroup> {
	let Some(reveal) = primitive_get(rule.split)
		.ok()
		.and_then(|s| s.recompose.as_ref())
		.map(|r| r.reveal)
	else {
		return Vec::new();
	};
	let secret = &target.arguments[0];
	let mut groups: Vec<PartialGroup> = Vec::new();
	for known in attacker.known.iter() {
		let Value::Primitive(q) = known else {
			continue;
		};
		if q.id != rule.partial {
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
	ps: &PrincipalState,
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
				let candidate = Value::primitive(rule.partial, arguments, 0);
				if !obtainable(&candidate, ps, attacker) {
					continue;
				}
				used.push(candidate);
				if used.len() >= threshold {
					return Some(used);
				}
			}
		}
	}
	None
}

#[cfg(test)]
pub(crate) fn combination_holds(target: &Primitive, from: &[Value]) -> bool {
	combines_into(target.id).any(|(join, rule)| {
		let joined = Primitive::new(join, from.to_vec(), 0);
		combine_with(&joined, rule).is_some_and(|built| {
			built.equivalent(&Value::Primitive(Arc::new(target.clone())), true)
		})
	})
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
		return (true, reduced_once(&rebuilt));
	}
	if let Some(combined) = can_combine(pc) {
		return (true, reduced_once(&combined));
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
	let from = &pc.arguments[rule.from];
	if let Value::Primitive(from_p) = from {
		if from_p.id != rule.id {
			return (!prim.definition_check, wrap());
		}
		if rule
			.from_output
			.is_some_and(|output| from_p.output != output)
		{
			return (!prim.definition_check, wrap());
		}
		if !can_rewrite_primitive(pc) {
			return (!prim.definition_check, wrap());
		}
		return (true, rule.to.apply(from_p));
	}
	(!prim.definition_check, wrap())
}

fn reduced_once(v: &Value) -> Value {
	match v {
		Value::Primitive(inner_p) => {
			let (rewritten, replacement) = can_rewrite(inner_p);
			if rewritten { replacement } else { v.clone() }
		}
		_ => v.clone(),
	}
}

fn can_rewrite_primitive(p: &Primitive) -> bool {
	let Some(rule) = primitive_get(p.id).ok().and_then(|s| s.rewrite.as_ref()) else {
		return false;
	};
	let Value::Primitive(from_p) = &p.arguments[rule.from] else {
		return false;
	};
	matching_is_injective(p, from_p, rule, 0, &mut Vec::new())
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
			|| !reduced_once(&filtered).equivalent(&reduced_once(&from_p.arguments[mm]), true)
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
	if primitive_is_core(p.id) {
		return None;
	}
	combine_rules(p.id)
		.iter()
		.find_map(|rule| combine_with(p, rule))
}

fn combine_with(p: &Primitive, rule: &CombineRule) -> Option<Value> {
	let reveal = primitive_get(rule.split).ok()?.recompose.as_ref()?.reveal;
	let mut partials: Vec<&Primitive> = Vec::with_capacity(p.arguments.len());
	for a in &p.arguments {
		let Value::Primitive(q) = a else {
			return None;
		};
		if q.id != rule.partial {
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

	fn weak_index(v: &Value, onset: i32) -> Arc<CapabilityIndex> {
		let Value::Primitive(p) = v else {
			panic!("expected a primitive");
		};
		let mut annotated = (**p).clone();
		annotated.capabilities.set(Capability::Weak, onset);
		let mut index = CapabilityIndex::default();
		index.insert(&Value::Primitive(Arc::new(annotated)));
		Arc::new(index)
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
	fn two_values_of_one_slot_are_not_a_reused() {
		let k = make_constant("tvo_k");
		let n = make_constant("tvo_n");
		let ad = make_constant("tvo_ad");
		let e1 = make_primitive(
			PRIM_AEAD_ENC,
			vec![k.clone(), n.clone(), make_constant("tvo_m1"), ad.clone()],
			0,
		);
		let e2 = make_primitive(
			PRIM_AEAD_ENC,
			vec![k.clone(), n.clone(), make_constant("tvo_m2"), ad.clone()],
			0,
		);
		let Value::Primitive(p1) = &e1 else {
			panic!("expected a primitive");
		};
		let read_from = |slots: [usize; 2]| {
			let mut attacker = make_attacker_state(vec![e1.clone(), e2.clone()]);
			attacker.derivations = Arc::new(vec![
				DerivationRecord::Obtained {
					slot: SlotIdx(slots[0]),
				},
				DerivationRecord::Obtained {
					slot: SlotIdx(slots[1]),
				},
			]);
			attacker
		};
		let _ = p1;
		assert!(!one_execution(&read_from([3, 3]), &e1, &e2));
		assert!(one_execution(&read_from([3, 4]), &e1, &e2));
		let opened = make_primitive(PRIM_AEAD_ENC, vec![k, n, e1.clone(), ad], 0);
		let mut attacker = make_attacker_state(vec![e1.clone(), e2.clone(), opened.clone()]);
		attacker.derivations = Arc::new(vec![
			DerivationRecord::Decomposed {
				of: opened.clone(),
				using: vec![],
			},
			DerivationRecord::Obtained { slot: SlotIdx(7) },
			DerivationRecord::Obtained { slot: SlotIdx(7) },
		]);
		assert!(!one_execution(&attacker, &e1, &e2));
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
		let ps = make_principal_state("Theory", 0, vec![], vec![]);
		let mut with_pair =
			make_attacker_state(vec![e1.clone(), e2.clone(), m3.clone(), ad.clone()]);
		with_pair.reused = Arc::new(vec![[e1.clone(), e2]]);
		let result =
			can_reconstruct_primitive(&target, &ps, &with_pair).expect("forgeable under reuse");
		assert!(matches!(result.forged, Some(Forged::Reuse(_))));
		assert_eq!(result.from.len(), 2);
		let without_pair = make_attacker_state(vec![e1, m3, ad]);
		assert!(can_reconstruct_primitive(&target, &ps, &without_pair).is_none());
	}

	#[test]
	fn a_memo_installed_for_one_session_is_not_consulted_for_another() {
		let k = make_constant("memo_k");
		let m = make_constant("memo_m");
		let sealed = make_primitive(PRIM_ENC, vec![k.clone(), m.clone()], 0);
		let ps = make_principal_state("Alice", 1, vec![], vec![]);
		let index = StateIndex::of(&ps);

		let poor = make_attacker_state(vec![]);
		let rich = make_attacker_state(vec![k, m]);

		let _scope = DeductionMemo::scoped(&ps, &poor, &index);
		assert!(
			!obtainable(&sealed, &ps, &poor),
			"an attacker holding nothing cannot build it"
		);
		assert!(
			obtainable(&sealed, &ps, &rich),
			"the memo is installed for one attacker state, and answering a \
			 different one out of it would let a cached `no` outlive the \
			 knowledge that justified it"
		);
	}

	#[test]
	fn can_break_weak_reveals_every_in_range_argument() {
		let m = make_constant("cbw_m");
		let n = make_constant("cbw_n");
		let h = make_primitive(PRIM_HASH, vec![m.clone(), n.clone()], 0);
		let Value::Primitive(hp) = &h else {
			panic!("expected a primitive");
		};
		let mut ps = make_principal_state("Alice", 1, vec![], vec![]);
		ps.capabilities = weak_index(&h, 0);
		let attacker = make_attacker_state(vec![h.clone()]);

		let revealed = can_break_weak(hp, &ps, &attacker).expect("weak is in force");
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
		let mut ps = make_principal_state("Alice", 1, vec![], vec![]);
		ps.capabilities = weak_index(&h, 2);
		let mut attacker = make_attacker_state(vec![h.clone()]);

		attacker.current_phase = 0;
		assert!(can_break_weak(hp, &ps, &attacker).is_none());
		attacker.current_phase = 1;
		assert!(can_break_weak(hp, &ps, &attacker).is_none());
		attacker.current_phase = 2;
		assert!(can_break_weak(hp, &ps, &attacker).is_some());
		attacker.current_phase = 3;
		assert!(can_break_weak(hp, &ps, &attacker).is_some());
	}

	#[test]
	fn can_break_weak_is_none_without_an_annotation() {
		let m = make_constant("cbwn_m");
		let h = make_primitive(PRIM_HASH, vec![m], 0);
		let Value::Primitive(hp) = &h else {
			panic!("expected a primitive");
		};
		let ps = make_principal_state("Alice", 1, vec![], vec![]);
		let attacker = make_attacker_state(vec![h.clone()]);
		assert!(can_break_weak(hp, &ps, &attacker).is_none());
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
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let c_dummy = Constant {
			name: Arc::from("crproj_dummy"),
			id: test_value_id("crproj_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		let attacker = make_attacker_state(vec![b]);
		assert!(can_reconstruct_primitive(&Arc::new(proj), &ps, &attacker).is_some());
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

	fn tsh_reduce(v: &Value) -> (bool, Value) {
		crate::context::enter_generation(crate::context::next_generation());
		let Value::Primitive(p) = v else {
			panic!("a primitive");
		};
		can_rewrite(p)
	}

	fn tsh_state(name: &str) -> PrincipalState {
		let dummy = Constant {
			name: Arc::from(name),
			id: test_value_id(name),
			..Constant::default()
		};
		make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		)
	}

	#[test]
	fn a_join_of_partials_over_distinct_shares_is_the_plain_signature() {
		let k = make_constant("cmb_k");
		let m = make_constant("cmb_m");
		let c = make_constant("cmb_c");
		let join = make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![
				tsh_partial(tsh_share(&k, 2, 0), "cmb_n1", &c, &m),
				tsh_partial(tsh_share(&k, 2, 2), "cmb_n2", &c, &m),
			],
			0,
		);
		let (ok, reduced) = tsh_reduce(&join);
		assert!(ok);
		assert!(reduced.equivalent(&make_primitive(PRIM_SIGN, vec![k, m], 0), true));
	}

	#[test]
	fn partials_that_disagree_or_repeat_a_share_do_not_combine() {
		let k = make_constant("cmd_k");
		let m = make_constant("cmd_m");
		let c = make_constant("cmd_c");
		let other = make_constant("cmd_other");
		let sig = make_primitive(PRIM_SIGN, vec![k.clone(), m.clone()], 0);
		let mixed = make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![
				tsh_partial(tsh_share(&k, 2, 0), "cmd_n1", &c, &m),
				tsh_partial(tsh_share(&k, 2, 1), "cmd_n2", &other, &m),
			],
			0,
		);
		assert!(!tsh_reduce(&mixed).1.equivalent(&sig, true));
		let repeated = make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![
				tsh_partial(tsh_share(&k, 2, 1), "cmd_n1", &c, &m),
				tsh_partial(tsh_share(&k, 2, 1), "cmd_n2", &c, &m),
			],
			0,
		);
		assert!(!tsh_reduce(&repeated).1.equivalent(&sig, true));
		let short = make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![
				tsh_partial(tsh_share(&k, 3, 0), "cmd_n1", &c, &m),
				tsh_partial(tsh_share(&k, 3, 1), "cmd_n2", &c, &m),
			],
			0,
		);
		assert!(!tsh_reduce(&short).1.equivalent(&sig, true));
		let enough = make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![
				tsh_partial(tsh_share(&k, 3, 0), "cmd_n1", &c, &m),
				tsh_partial(tsh_share(&k, 3, 1), "cmd_n2", &c, &m),
				tsh_partial(tsh_share(&k, 3, 4), "cmd_n3", &c, &m),
			],
			0,
		);
		assert!(tsh_reduce(&enough).1.equivalent(&sig, true));
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
		let (ok, reduced) = tsh_reduce(&join);
		assert!(ok);
		assert!(reduced.equivalent(&make_primitive(PRIM_PUBKEY, vec![k], 0), true));
	}

	#[test]
	fn a_signature_is_reconstructed_from_a_held_partial_and_a_held_share() {
		let k = make_constant("cmr_k");
		let m = make_constant("cmr_m");
		let c = make_constant("cmr_c");
		let ps = tsh_state("cmr_dummy");
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
		let built = can_reconstruct_primitive(sig_p, &ps, &with_share).expect("t pieces suffice");
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
		assert!(can_reconstruct_primitive(sig_p, &ps, &same_share).is_none());
		let partial_only = make_attacker_state(vec![partial, value_nil(), c, m]);
		assert!(can_reconstruct_primitive(sig_p, &ps, &partial_only).is_none());
	}

	#[test]
	fn partials_under_different_commitments_do_not_reconstruct_a_signature() {
		let k = make_constant("cmz_k");
		let m = make_constant("cmz_m");
		let ps = tsh_state("cmz_dummy");
		let sig = make_primitive(PRIM_SIGN, vec![k.clone(), m.clone()], 0);
		let Value::Primitive(sig_p) = &sig else {
			panic!("a primitive");
		};
		let attacker = make_attacker_state(vec![
			tsh_partial(tsh_share(&k, 2, 0), "cmz_n1", &make_constant("cmz_c1"), &m),
			tsh_partial(tsh_share(&k, 2, 1), "cmz_n2", &make_constant("cmz_c2"), &m),
			value_nil(),
		]);
		assert!(can_reconstruct_primitive(sig_p, &ps, &attacker).is_none());
		let agreeing = make_attacker_state(vec![
			tsh_partial(tsh_share(&k, 2, 0), "cmz_n1", &make_constant("cmz_c1"), &m),
			tsh_partial(tsh_share(&k, 2, 1), "cmz_n2", &make_constant("cmz_c1"), &m),
			value_nil(),
		]);
		assert!(can_reconstruct_primitive(sig_p, &ps, &agreeing).is_some());
	}

	#[test]
	fn can_decompose_enc_with_key() {
		let key = make_constant("cd_key");
		let msg = make_constant("cd_msg");
		let p = Primitive {
			id: PRIM_ENC,
			arguments: vec![key.clone(), msg.clone()],
			output: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let c_dummy = Constant {
			name: Arc::from("cd_dummy"),
			id: test_value_id("cd_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		let attacker = make_attacker_state(vec![key]);
		let result = can_decompose(&p, &ps, &attacker);
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
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let c_dummy = Constant {
			name: Arc::from("kd_dummy"),
			id: test_value_id("kd_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		let attacker = make_attacker_state(vec![dk]);
		let revealed = can_decompose(&ct, &ps, &attacker)
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
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let c_dummy = Constant {
			name: Arc::from("kn_dummy"),
			id: test_value_id("kn_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		let attacker = make_attacker_state(vec![ek]);
		assert!(can_decompose(&ct, &ps, &attacker).is_none());
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
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
			hash: HashCell::default(),
		};
		let c_dummy = Constant {
			name: Arc::from("cd_nk_dummy"),
			id: test_value_id("cd_nk_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		let attacker = make_attacker_state(vec![]);
		assert!(can_decompose(&p, &ps, &attacker).is_none());
	}
}
