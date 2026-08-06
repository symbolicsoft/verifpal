/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use crate::equivalence::equivalent_primitives;
use crate::primitive::*;
use crate::types::*;

const MAX_DEPTH: usize = 16;

type RewriteCache = HashMap<(u64, usize), Vec<(Primitive, (bool, Value))>>;

struct ObtainableMemo {
	owner: (*const PrincipalState, *const AttackerState),
	entries: HashMap<(u64, usize), Vec<(Value, bool)>>,
	has_passwords: bool,
	slots_by_hash: HashMap<u64, Vec<usize>>,
}

pub(crate) fn slots_equivalent_to(ps: &PrincipalState, value: &Value) -> Vec<usize> {
	let hash = value.hash_value();
	let indexed: Option<Vec<usize>> = MEMO.with(|m| {
		let borrowed = m.borrow();
		let memo = borrowed.as_ref()?;
		if !std::ptr::eq(memo.owner.0, ps) {
			return None;
		}
		Some(memo.slots_by_hash.get(&hash).cloned().unwrap_or_default())
	});
	match indexed {
		Some(candidates) => candidates
			.into_iter()
			.filter(|&i| value.equivalent(&ps.values[i].value, true))
			.collect(),
		None => ps
			.values
			.iter()
			.enumerate()
			.filter(|(_, sv)| value.equivalent(&sv.value, true))
			.map(|(i, _)| i)
			.collect(),
	}
}

fn index_slots_by_hash(ps: &PrincipalState) -> HashMap<u64, Vec<usize>> {
	let mut index: HashMap<u64, Vec<usize>> = HashMap::new();
	for (i, sv) in ps.values.iter().enumerate() {
		index.entry(sv.value.hash_value()).or_default().push(i);
	}
	index
}

pub(crate) fn state_declares_passwords(ps: &PrincipalState) -> bool {
	MEMO.with(|m| {
		if let Some(memo) = m.borrow().as_ref()
			&& std::ptr::eq(memo.owner.0, ps)
		{
			return Some(memo.has_passwords);
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

fn structurally_identical_primitive(x: &Primitive, y: &Primitive) -> bool {
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
	static REWRITE_CACHE: RefCell<RewriteCache> = RefCell::new(HashMap::new());
}

pub(crate) fn rewrite_cache_reset() {
	REWRITE_CACHE.with(|c| c.borrow_mut().clear());
}

fn rewrite_cache_get(key: (u64, usize), p: &Primitive) -> Option<(bool, Value)> {
	REWRITE_CACHE.with(|c| {
		c.borrow()
			.get(&key)?
			.iter()
			.find(|(candidate, _)| structurally_identical_primitive(candidate, p))
			.map(|(_, hit)| hit.clone())
	})
}

fn rewrite_cache_put(key: (u64, usize), p: &Primitive, result: &(bool, Value)) {
	REWRITE_CACHE.with(|c| {
		c.borrow_mut()
			.entry(key)
			.or_default()
			.push((p.clone(), result.clone()));
	});
}

pub(crate) struct DeductionMemo {
	previous: Option<Option<ObtainableMemo>>,
}

impl DeductionMemo {
	pub(crate) fn scoped(ps: &PrincipalState, attacker: &AttackerState) -> Self {
		let installed = ObtainableMemo {
			owner: (ps as *const _, attacker as *const _),
			entries: HashMap::new(),
			has_passwords: scan_for_passwords(ps),
			slots_by_hash: index_slots_by_hash(ps),
		};
		let previous = MEMO.with(|m| m.borrow_mut().replace(installed));
		DeductionMemo {
			previous: Some(previous),
		}
	}
}

impl Drop for DeductionMemo {
	fn drop(&mut self) {
		if let Some(previous) = self.previous.take() {
			MEMO.with(|m| *m.borrow_mut() = previous);
		}
	}
}

fn memo_owner_matches(
	memo: &ObtainableMemo,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> bool {
	memo.owner == (ps as *const _, attacker as *const _)
}

fn memo_obtainable_get(
	key: (u64, usize),
	v: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<bool> {
	MEMO.with(|m| {
		let borrowed = m.borrow();
		let memo = borrowed.as_ref()?;
		if !memo_owner_matches(memo, ps, attacker) {
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
	key: (u64, usize),
	v: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	result: bool,
) {
	MEMO.with(|m| {
		if let Some(memo) = m.borrow_mut().as_mut()
			&& memo_owner_matches(memo, ps, attacker)
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
	depth: usize,
) -> Option<DecomposeResult> {
	if depth > MAX_DEPTH || primitive_is_core(p.id) {
		return None;
	}
	let Ok(prim) = primitive_get(p.id) else {
		return None;
	};
	if !prim.decompose.has_rule {
		return None;
	}
	let filter_fn = prim.decompose.filter?;
	let mut has = Vec::new();
	for (filter_i, &idx) in prim.decompose.given.iter().enumerate() {
		if idx >= p.arguments.len() {
			continue;
		}
		let a = &p.arguments[idx];
		let (filtered, valid) = filter_fn(p, a, filter_i);
		if !valid {
			continue;
		}
		if obtainable(&filtered, ps, attacker, depth) {
			has.push(filtered);
		}
	}
	if has.len() >= prim.decompose.given.len() {
		let revealed = match prim.decompose.reveal_output {
			Some(output) => Value::Primitive(Arc::new(p.with_output(output))),
			None => p.arguments[prim.decompose.reveal].clone(),
		};
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

pub(crate) fn obtainable(
	v: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	depth: usize,
) -> bool {
	let hash = v.hash_value();
	if attacker.knows_hashed(v, hash).is_some() {
		return true;
	}
	if matches!(v, Value::Constant(_)) {
		return false;
	}
	let key = (hash, depth);
	if let Some(hit) = memo_obtainable_get(key, v, ps, attacker) {
		return hit;
	}
	let result = match v {
		Value::Primitive(p) => {
			can_decompose(p, ps, attacker, depth + 1).is_some()
				|| can_reconstruct_primitive(p, ps, attacker, depth + 1).is_some()
		}
		Value::Constant(_) => false,
	};
	memo_obtainable_put(key, v, ps, attacker, result);
	result
}

pub(crate) fn can_recompose(p: &Primitive, attacker: &AttackerState) -> Option<RecomposeResult> {
	if primitive_is_core(p.id) {
		return None;
	}
	let Ok(prim) = primitive_get(p.id) else {
		return None;
	};
	if !prim.recompose.has_rule {
		return None;
	}
	for given_set in &prim.recompose.given {
		let mut candidates = Vec::new();
		for &output_idx in given_set {
			let probe = Primitive {
				id: p.id,
				arguments: p.arguments.clone(),
				output: output_idx,
				instance_check: p.instance_check,
				capabilities: p.capabilities,
				hash: HashCell::default(),
			};
			let hash = crate::hashing::primitive_hash(&probe);
			let Some(indices) = attacker.known_map.get(&hash) else {
				continue;
			};
			for &i in indices {
				let Some(known @ Value::Primitive(known_prim)) = attacker.known.get(i) else {
					continue;
				};
				let pm = equivalent_primitives(known_prim, p, false);
				if !pm.equivalent || pm.output_left != output_idx {
					continue;
				}
				candidates.push(known.clone());
				if candidates.len() < given_set.len() {
					continue;
				}
				return Some(RecomposeResult {
					revealed: p.arguments[prim.recompose.reveal].clone(),
					used: candidates,
				});
			}
		}
	}
	None
}

pub(crate) fn can_reconstruct_primitive(
	p: &Primitive,
	ps: &PrincipalState,
	attacker: &AttackerState,
	depth: usize,
) -> Option<Vec<Value>> {
	can_reconstruct_primitive_directly(p, ps, attacker, depth).or_else(|| {
		let swapped = commutativity_swap(p)?;
		can_reconstruct_primitive_directly(&swapped, ps, attacker, depth)
	})
}

fn can_reconstruct_primitive_directly(
	p: &Primitive,
	ps: &PrincipalState,
	attacker: &AttackerState,
	depth: usize,
) -> Option<Vec<Value>> {
	if depth > MAX_DEPTH {
		return None;
	}
	let (rewritten, rewrite_value) = can_rewrite(p, ps, 0);
	if !rewritten {
		return None;
	}
	let Value::Primitive(rewritten_prim) = &rewrite_value else {
		return None;
	};
	let mut has = Vec::new();
	for a in &rewritten_prim.arguments {
		if obtainable(a, ps, attacker, depth) {
			has.push(a.clone());
		}
	}
	if has.len() < rewritten_prim.arguments.len() {
		return None;
	}
	Some(has)
}

pub(crate) fn can_rewrite(p: &Primitive, ps: &PrincipalState, depth: usize) -> (bool, Value) {
	if depth > MAX_DEPTH {
		return (false, Value::Primitive(Arc::new(p.clone())));
	}
	let key = (crate::hashing::primitive_hash(p), depth);
	if let Some(hit) = rewrite_cache_get(key, p) {
		return hit;
	}
	let result = can_rewrite_uncached(p, ps, depth);
	rewrite_cache_put(key, p, &result);
	result
}

fn can_rewrite_uncached(p: &Primitive, ps: &PrincipalState, depth: usize) -> (bool, Value) {
	let reduced = p.map_arguments(|a| match a {
		Value::Primitive(inner_p) => {
			let (_, replacement) = can_rewrite(inner_p, ps, depth + 1);
			(!replacement.equivalent(a, true)).then_some(replacement)
		}
		_ => None,
	});
	let pc_ref: &Primitive = reduced.as_ref().unwrap_or(p);
	let wrap = |pr: &Primitive| Value::Primitive(Arc::new(pr.clone()));
	if primitive_is_core(pc_ref.id) {
		let prim = match primitive_core_get(pc_ref.id) {
			Ok(s) => s,
			Err(_) => return (false, wrap(pc_ref)),
		};
		if prim.has_rule
			&& let Some(rule) = prim.core_rule
		{
			return rule(pc_ref);
		}
		return (!prim.definition_check, wrap(pc_ref));
	}
	let prim = match primitive_get(pc_ref.id) {
		Ok(s) => s,
		Err(_) => return (false, wrap(pc_ref)),
	};
	if !prim.rewrite.has_rule {
		return (true, wrap(pc_ref));
	}
	let from = &pc_ref.arguments[prim.rewrite.from];
	if let Value::Primitive(from_p) = from {
		if from_p.id != prim.rewrite.id {
			return (!prim.definition_check, wrap(pc_ref));
		}
		if !can_rewrite_primitive(pc_ref, ps, depth) {
			return (!prim.definition_check, wrap(pc_ref));
		}
		if let Some(to_fn) = prim.rewrite.to {
			let rewrite = to_fn(from_p);
			return (true, rewrite);
		}
	}
	(!prim.definition_check, wrap(pc_ref))
}

fn can_rewrite_primitive(p: &Primitive, ps: &PrincipalState, depth: usize) -> bool {
	let Ok(prim) = primitive_get(p.id) else {
		return false;
	};
	let from = &p.arguments[prim.rewrite.from];
	let Value::Primitive(from_p) = from else {
		return false;
	};
	let Some(filter_fn) = prim.rewrite.filter else {
		return false;
	};
	for &(a_idx, ref m_vec) in &prim.rewrite.matching {
		let mut valid = false;
		for &mm in m_vec {
			if a_idx >= p.arguments.len() || mm >= from_p.arguments.len() {
				continue;
			}
			let mut ax = [p.arguments[a_idx].clone(), from_p.arguments[mm].clone()];
			let (filtered, fvalid) = filter_fn(p, &ax[0], mm);
			if !fvalid {
				continue;
			}
			ax[0] = filtered;
			for item in &mut ax {
				let replacement = match &*item {
					Value::Primitive(inner_p) => {
						let (r, v) = can_rewrite(inner_p, ps, depth + 1);
						if r { Some(v) } else { None }
					}
					_ => None,
				};
				if let Some(new_val) = replacement {
					*item = new_val;
				}
			}
			valid = ax[0].equivalent(&ax[1], true);
			if valid {
				break;
			}
		}
		if !valid {
			return false;
		}
	}
	true
}

pub(crate) fn can_rebuild(p: &Primitive) -> Option<Value> {
	if primitive_is_core(p.id) {
		return None;
	}
	let prim = primitive_get(p.id).ok()?;
	if !prim.rebuild.has_rule {
		return None;
	}
	for given_set in &prim.rebuild.given {
		let mut has = Vec::new();
		for &arg_idx in given_set {
			if arg_idx >= p.arguments.len() {
				continue;
			}
			if let Value::Primitive(arg_p) = &p.arguments[arg_idx]
				&& arg_p.id == prim.rebuild.id
			{
				has.push(&p.arguments[arg_idx]);
			}
		}
		if has.len() < given_set.len() {
			continue;
		}
		let all_ok = has[1..].iter().all(|has_p| {
			if let (Value::Primitive(h0), Value::Primitive(hp)) = (has[0], has_p) {
				let pm = equivalent_primitives(h0, hp, false);
				pm.equivalent && pm.output_left != pm.output_right
			} else {
				false
			}
		});
		if !all_ok {
			continue;
		}
		if let Value::Primitive(h0) = has[0] {
			return Some(h0.arguments[prim.rebuild.reveal].clone());
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
	match a {
		Value::Constant(c) => {
			let (resolved, _) = ps.resolve_constant(c, true);
			let is_password = matches!(&resolved, Value::Constant(rc) if rc.qualifier == Some(Qualifier::Password));
			if is_password && !protected && can_verify {
				out.push(resolved);
			}
		}
		Value::Primitive(p) => {
			let is_core = primitive_is_core(p.id);
			let known: Vec<bool> = p
				.arguments
				.iter()
				.map(|arg| attacker.knows(arg).is_some())
				.collect();
			let known_count = known.iter().filter(|k| **k).count();
			for (i, arg) in p.arguments.iter().enumerate() {
				let inherently_protected = !is_core
					&& primitive_get(p.id).is_ok_and(|prim| prim.password_hashing.contains(&i));
				let siblings_known = known_count == known.len() - usize::from(!known[i]);
				find_obtainable_passwords(
					arg,
					protected || inherently_protected,
					can_verify && siblings_known,
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
		let c_dummy = Constant {
			name: Arc::from("cr_dummy"),
			id: test_value_id("cr_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		for (output, expected) in [(0, a), (1, b), (2, value_nil())] {
			let split = Primitive {
				id: PRIM_SPLIT,
				arguments: vec![concat.clone()],
				output,
				instance_check: false,
				capabilities: Capabilities::default(),
				hash: HashCell::default(),
			};
			let (rewritten, value) = can_rewrite(&split, &ps, 0);
			assert!(rewritten);
			assert!(value.equivalent(&expected, true));
		}
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
		let c_dummy = Constant {
			name: Arc::from("crpk_dummy"),
			id: test_value_id("crpk_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		let (rewritten, value) = can_rewrite(&dec, &ps, 0);
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
		assert!(can_reconstruct_primitive(&proj, &ps, &attacker, 0).is_some());
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
		let c_dummy = Constant {
			name: Arc::from("cra_dummy"),
			id: test_value_id("cra_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		let (rewritten, _) = can_rewrite(&assert_prim, &ps, 0);
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
		let c_dummy = Constant {
			name: Arc::from("cram_dummy"),
			id: test_value_id("cram_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		let (rewritten, _) = can_rewrite(&assert_prim, &ps, 0);
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
		let result = can_decompose(&p, &ps, &attacker, 0);
		assert!(result.is_some());
		assert!(result.unwrap().revealed.equivalent(&msg, true));
	}

	#[test]
	fn can_decompose_kem_with_private_key_reveals_shared_secret() {
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
		let revealed = can_decompose(&ct, &ps, &attacker, 0)
			.expect("holder of the private key can decapsulate")
			.revealed;
		let expected = make_primitive(PRIM_KEM_ENCAP, vec![ek, r], 0);
		assert!(revealed.equivalent(&expected, true));
		assert_ne!(
			revealed.hash_value(),
			Value::Primitive(Arc::new(ct)).hash_value()
		);
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
		assert!(can_decompose(&ct, &ps, &attacker, 0).is_none());
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
		let c_dummy = Constant {
			name: Arc::from("kr_dummy"),
			id: test_value_id("kr_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		let (rewritten, value) = can_rewrite(&decap, &ps, 0);
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
		let c_dummy = Constant {
			name: Arc::from("kw_dummy"),
			id: test_value_id("kw_dummy"),
			..Constant::default()
		};
		let ps = make_principal_state(
			"Test",
			0,
			vec![make_slot_meta(&c_dummy, true)],
			vec![make_slot_values(&value_nil(), 0)],
		);
		let (rewritten, _) = can_rewrite(&decap, &ps, 0);
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
		assert!(can_decompose(&p, &ps, &attacker, 0).is_none());
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
