/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::RefCell;
use std::sync::Arc;

use crate::equivalence::equivalent_primitives;
use crate::primitive::*;
use crate::types::*;

type RewriteCache = IdMap<u64, Vec<(Arc<Primitive>, (bool, Value))>>;

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
	has_passwords: bool,
	slots_by_hash: IdMap<u64, Vec<usize>>,
}

impl StateIndex {
	pub(crate) fn of(ps: &PrincipalState) -> Arc<Self> {
		Arc::new(StateIndex {
			has_passwords: scan_for_passwords(ps),
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

pub(crate) fn state_declares_passwords(ps: &PrincipalState) -> bool {
	MEMO.with(|m| {
		if let Some(memo) = m.borrow().as_ref()
			&& memo.is_for_state(ps)
		{
			return Some(memo.index.has_passwords);
		}
		None
	})
	.unwrap_or_else(|| scan_for_passwords(ps))
}

fn scan_for_passwords(ps: &PrincipalState) -> bool {
	ps.meta
		.iter()
		.any(|m| m.constant.qualifier == Some(Qualifier::Password))
		|| ps.values.iter().any(
			|sv| matches!(&sv.value, Value::Constant(c) if c.qualifier == Some(Qualifier::Password)),
		)
}

pub(crate) fn structurally_identical_primitive(x: &Primitive, y: &Primitive) -> bool {
	x.id == y.id
		&& x.output == y.output
		&& x.instance_check == y.instance_check
		&& x.arguments.len() == y.arguments.len()
		&& x.arguments
			.iter()
			.zip(y.arguments.iter())
			.all(|(p, q)| structurally_identical(p, q))
}

fn structurally_identical(a: &Value, b: &Value) -> bool {
	match (a, b) {
		(Value::Constant(x), Value::Constant(y)) => x.id == y.id,
		(Value::Primitive(x), Value::Primitive(y)) => {
			Arc::ptr_eq(x, y) || structurally_identical_primitive(x, y)
		}
		_ => false,
	}
}

thread_local! {
	static MEMO: RefCell<Option<ObtainableMemo>> = const { RefCell::new(None) };
	static REWRITE_CACHE: RefCell<RewriteCache> = RefCell::new(IdMap::default());
}

pub(crate) fn rewrite_cache_reset() {
	REWRITE_CACHE.with(|c| c.borrow_mut().clear());
}

fn rewrite_cache_get(key: u64, p: &Arc<Primitive>) -> Option<(bool, Value)> {
	REWRITE_CACHE.with(|c| {
		c.borrow()
			.get(&key)?
			.iter()
			.find(|(candidate, _)| {
				Arc::ptr_eq(candidate, p) || structurally_identical_primitive(candidate, p)
			})
			.map(|(_, hit)| hit.clone())
	})
}

fn rewrite_cache_put(key: u64, p: &Arc<Primitive>, result: &(bool, Value)) {
	REWRITE_CACHE.with(|c| {
		c.borrow_mut()
			.entry(key)
			.or_default()
			.push((Arc::clone(p), result.clone()));
	});
}

pub(crate) struct DeductionMemo<'a> {
	previous: Option<Option<ObtainableMemo>>,
	borrowed: std::marker::PhantomData<(&'a PrincipalState, &'a AttackerState)>,
}

impl<'a> DeductionMemo<'a> {
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

pub(crate) fn can_decompose(
	p: &Primitive,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<DecomposeResult> {
	if primitive_is_core(p.id) {
		return None;
	}
	let rule = primitive_get(p.id).ok()?.decompose.as_ref()?;
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
						revealed.push(argument.clone());
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
			revealed.push(a.clone());
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
		Value::Primitive(p) => {
			can_reconstruct_primitive(p, ps, attacker).is_some()
				|| obtainable_by_output_projection(p, ps, attacker)
		}
		Value::Constant(_) => false,
	};
	memo_obtainable_put(hash, v, ps, attacker, result);
	result
}

fn obtainable_by_output_projection(
	p: &Primitive,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> bool {
	let Ok(spec) = primitive_get(p.id) else {
		return false;
	};
	let projects_output = spec.decompose.as_ref().is_some_and(|rule| {
		rule.reveals
			.iter()
			.any(|reveal| matches!(*reveal, Reveal::Output(output) if output == p.output))
	});
	if !projects_output {
		return false;
	}
	let Some(&outputs) = spec.output.iter().max() else {
		return false;
	};
	(0..outputs.max(0) as usize)
		.filter(|&j| j != p.output)
		.any(|j| {
			let sibling = Arc::new(p.with_output(j));
			attacker
				.knows(&Value::Primitive(Arc::clone(&sibling)))
				.is_some() && can_decompose(&sibling, ps, attacker).is_some()
		})
}

pub(crate) fn can_recompose(p: &Primitive, attacker: &AttackerState) -> Option<RecomposeResult> {
	if primitive_is_core(p.id) {
		return None;
	}
	let rule = primitive_get(p.id).ok()?.recompose.as_ref()?;
	for given_set in &rule.given {
		let mut candidates = Vec::new();
		for &output_idx in given_set {
			let probe = p.with_output(output_idx);
			let hash = crate::hashing::primitive_hash(&probe);
			let Some(indices) = attacker.known_map.get(&hash) else {
				continue;
			};
			for &i in indices {
				let Some(known @ Value::Primitive(known_prim)) = attacker.known.get(i) else {
					continue;
				};
				if !equivalent_primitives(known_prim, p, false) || known_prim.output != output_idx {
					continue;
				}
				candidates.push(known.clone());
				if candidates.len() < given_set.len() {
					continue;
				}
				return Some(RecomposeResult {
					revealed: p.arguments[rule.reveal].clone(),
					used: candidates,
				});
			}
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
	let mut has = Vec::new();
	let mut skipped = 0usize;
	for (i, a) in rewritten_prim.arguments.iter().enumerate() {
		if Some(i) == forgeable_secret {
			skipped += 1;
			continue;
		}
		if obtainable(a, ps, attacker) {
			has.push(a.clone());
		}
	}
	if has.len() + skipped < rewritten_prim.arguments.len() {
		return None;
	}
	Some(ReconstructResult {
		from: has,
		forged: (skipped > 0).then_some(Capability::Forgeable),
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
		if !can_rewrite_primitive(pc) {
			return (!prim.definition_check, wrap());
		}
		return (true, (rule.to)(from_p));
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

pub(crate) fn can_rebuild(p: &Primitive) -> Option<Value> {
	if primitive_is_core(p.id) {
		return None;
	}
	let rule = primitive_get(p.id).ok()?.rebuild.as_ref()?;
	for given_set in &rule.given {
		let mut has = Vec::new();
		for &arg_idx in given_set {
			if arg_idx >= p.arguments.len() {
				continue;
			}
			if let Value::Primitive(arg_p) = &p.arguments[arg_idx]
				&& arg_p.id == rule.id
			{
				has.push(&p.arguments[arg_idx]);
			}
		}
		if has.len() < given_set.len() {
			continue;
		}
		let all_ok = has[1..].iter().all(|has_p| {
			if let (Value::Primitive(h0), Value::Primitive(hp)) = (has[0], has_p) {
				equivalent_primitives(h0, hp, false) && h0.output != hp.output
			} else {
				false
			}
		});
		if !all_ok {
			continue;
		}
		if let Value::Primitive(h0) = has[0] {
			return Some(h0.arguments[rule.reveal].clone());
		}
	}
	None
}

pub(crate) fn find_obtainable_passwords(
	a: &Value,
	protected: bool,
	can_verify: bool,
	attacker: &AttackerState,
	ps: &PrincipalState,
	out: &mut Vec<Value>,
) {
	if protected || !can_verify {
		return;
	}
	match a {
		Value::Constant(c) => {
			let (resolved, _) = ps.resolve_constant(c, true);
			if matches!(&resolved, Value::Constant(rc) if rc.qualifier == Some(Qualifier::Password))
			{
				out.push(resolved);
			}
		}
		Value::Primitive(p) => {
			let arity = p.arguments.len();
			let known_count = p
				.arguments
				.iter()
				.filter(|arg| attacker.knows(arg).is_some())
				.count();
			if known_count + 1 < arity {
				return;
			}
			let hashing: &[usize] = if primitive_is_core(p.id) {
				&[]
			} else {
				primitive_get(p.id).map_or(&[][..], |prim| prim.password_hashing.as_slice())
			};
			for (i, arg) in p.arguments.iter().enumerate() {
				let siblings_known = known_count == arity
					|| (known_count + 1 == arity && attacker.knows(arg).is_none());
				find_obtainable_passwords(
					arg,
					hashing.contains(&i),
					siblings_known,
					attacker,
					ps,
					out,
				);
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testutil::*;
	use crate::value::*;
	use std::sync::Arc;

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
			hash: HashCell::default(),
		};
		let (rewritten, _) = can_rewrite(&Arc::new(assert_prim));
		assert!(!rewritten);
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

	#[test]
	fn find_obtainable_passwords_direct() {
		let pw = make_password("fop_pw");
		let pw_c = pw.as_constant().unwrap().clone();
		let meta = vec![make_slot_meta(&pw_c, true)];
		let values = vec![make_slot_values(&pw, 0)];
		let ps = make_principal_state("Test", 0, meta, values);
		let attacker = make_attacker_state(vec![]);
		let mut out = Vec::new();
		find_obtainable_passwords(&pw, false, true, &attacker, &ps, &mut out);
		assert_eq!(out.len(), 1);
	}

	#[test]
	fn find_obtainable_passwords_known_sibling() {
		let pw = make_password("fop2_pw");
		let msg = make_constant("fop2_msg");
		let pw_c = pw.as_constant().unwrap().clone();
		let msg_c = msg.as_constant().unwrap().clone();
		let enc = make_primitive(PRIM_ENC, vec![pw.clone(), msg.clone()], 0);
		let meta = vec![make_slot_meta(&pw_c, true), make_slot_meta(&msg_c, false)];
		let values = vec![make_slot_values(&pw, 0), make_slot_values(&msg, 0)];
		let ps = make_principal_state("Test", 0, meta, values);
		let attacker = make_attacker_state(vec![msg]);
		let mut out = Vec::new();
		find_obtainable_passwords(&enc, false, true, &attacker, &ps, &mut out);
		assert_eq!(out.len(), 1);
	}

	#[test]
	fn find_obtainable_passwords_unknown_sibling() {
		let pw = make_password("fop3_pw");
		let secret = make_constant("fop3_secret");
		let pw_c = pw.as_constant().unwrap().clone();
		let secret_c = secret.as_constant().unwrap().clone();
		let enc = make_primitive(PRIM_ENC, vec![pw.clone(), secret.clone()], 0);
		let meta = vec![
			make_slot_meta(&pw_c, true),
			make_slot_meta(&secret_c, false),
		];
		let values = vec![make_slot_values(&pw, 0), make_slot_values(&secret, 0)];
		let ps = make_principal_state("Test", 0, meta, values);
		let attacker = make_attacker_state(vec![]);
		let mut out = Vec::new();
		find_obtainable_passwords(&enc, false, true, &attacker, &ps, &mut out);
		assert_eq!(out.len(), 0);
	}
}
