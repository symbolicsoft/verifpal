/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::equivalence::equivalent_primitives;
use crate::primitive::*;
use crate::types::*;

const MAX_DEPTH: usize = 16;

pub(crate) fn passively_decompose(p: &Primitive) -> Vec<Value> {
	if primitive_is_core(p.id) {
		return vec![];
	}
	let Ok(prim) = primitive_get(p.id) else {
		return vec![];
	};
	if !prim.decompose.has_rule {
		return vec![];
	}
	prim.decompose
		.passive_reveal
		.iter()
		.filter_map(|&i| p.arguments.get(i).cloned())
		.collect()
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
		Some(DecomposeResult {
			revealed: p.arguments[prim.decompose.reveal].clone(),
			used: has,
		})
	} else {
		None
	}
}

fn obtainable(v: &Value, ps: &PrincipalState, attacker: &AttackerState, depth: usize) -> bool {
	if attacker.knows(v).is_some() {
		return true;
	}
	match v {
		Value::Primitive(p) => {
			can_decompose(p, ps, attacker, depth + 1).is_some()
				|| can_reconstruct_primitive(p, ps, attacker, depth + 1).is_some()
		}
		Value::Equation(e) => can_reconstruct_equation(e, attacker).is_some(),
		Value::Constant(_) => false,
	}
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
			for known in attacker.known.iter() {
				if let Value::Primitive(known_prim) = known {
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
	}
	None
}

pub(crate) fn can_reconstruct_primitive(
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

pub(crate) fn can_reconstruct_equation(
	e: &Equation,
	attacker: &AttackerState,
) -> Option<Vec<Value>> {
	if e.values.len() < 2 {
		return None;
	}
	if e.values.len() == 2 {
		if attacker.knows(&e.values[1]).is_some() {
			return Some(vec![e.values[1].clone()]);
		}
		return None;
	}
	let s0 = &e.values[1];
	let s1 = &e.values[2];
	let hs0 = attacker.knows(s0).is_some();
	let hs1 = attacker.knows(s1).is_some();
	if hs0 && hs1 {
		return Some(vec![s0.clone(), s1.clone()]);
	}
	let p0 = Value::Equation(Arc::new(Equation {
		values: vec![e.values[0].clone(), e.values[1].clone()],
	}));
	let p1 = Value::Equation(Arc::new(Equation {
		values: vec![e.values[0].clone(), e.values[2].clone()],
	}));
	let hp1 = attacker.knows(&p1).is_some();
	if hs0 && hp1 {
		return Some(vec![s0.clone(), p1]);
	}
	let hp0 = attacker.knows(&p0).is_some();
	if hp0 && hs1 {
		return Some(vec![p0, s1.clone()]);
	}
	None
}

pub(crate) fn can_rewrite(p: &Primitive, ps: &PrincipalState, depth: usize) -> (bool, Value) {
	if depth > MAX_DEPTH {
		return (false, Value::Primitive(Arc::new(p.clone())));
	}
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
					Value::Equation(inner_e) => {
						let mut new_values: Option<Vec<Value>> = None;
						for (ii, ev) in inner_e.values.iter().enumerate() {
							if let Value::Primitive(ep) = ev {
								let (r, v) = can_rewrite(ep, ps, depth + 1);
								if r {
									let vals =
										new_values.get_or_insert_with(|| inner_e.values.clone());
									vals[ii] = v;
								}
							}
						}
						new_values.map(|vals| Value::Equation(Arc::new(Equation { values: vals })))
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
			for (i, arg) in p.arguments.iter().enumerate() {
				let inherently_protected = !is_core
					&& primitive_get(p.id).is_ok_and(|prim| prim.password_hashing.contains(&i));
				let siblings_known = p
					.arguments
					.iter()
					.enumerate()
					.filter(|(j, _)| *j != i)
					.all(|(_, sibling)| attacker.knows(sibling).is_some());
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
		Value::Equation(e) => {
			for v in &e.values {
				find_obtainable_passwords(v, protected, can_verify, attacker, ps, out);
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
		let pk = make_equation(vec![value_g(), proj]);
		let enc = make_primitive(PRIM_PKE_ENC, vec![pk, m.clone()], 0);
		let dec = Primitive {
			id: PRIM_PKE_DEC,
			arguments: vec![sk2, enc],
			output: 0,
			instance_check: false,
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
	fn can_reconstruct_equation_2_element() {
		let a = make_constant("cre_a");
		let eq = Equation {
			values: vec![value_g(), a.clone()],
		};
		let attacker = make_attacker_state(vec![a]);
		let result = can_reconstruct_equation(&eq, &attacker);
		assert!(result.is_some());
		assert_eq!(result.unwrap().len(), 1);
	}

	#[test]
	fn can_reconstruct_equation_3_element_both_exponents() {
		let a = make_constant("cre3_a");
		let b = make_constant("cre3_b");
		let eq = Equation {
			values: vec![value_g(), a.clone(), b.clone()],
		};
		let attacker = make_attacker_state(vec![a, b]);
		let result = can_reconstruct_equation(&eq, &attacker);
		assert!(result.is_some());
		assert_eq!(result.unwrap().len(), 2);
	}

	#[test]
	fn can_reconstruct_equation_missing_exponent() {
		let a = make_constant("crem_a");
		let b = make_constant("crem_b");
		let eq = Equation {
			values: vec![value_g(), a.clone(), b],
		};
		let attacker = make_attacker_state(vec![a]);
		assert!(can_reconstruct_equation(&eq, &attacker).is_none());
	}

	#[test]
	fn passive_decompose_aead_enc() {
		let key = make_constant("pd_key");
		let msg = make_constant("pd_msg");
		let ad = make_constant("pd_ad");
		let p = Primitive {
			id: PRIM_AEAD_ENC,
			arguments: vec![key, msg, ad.clone()],
			output: 0,
			instance_check: false,
		};
		let revealed = passively_decompose(&p);
		assert_eq!(revealed.len(), 0);
	}

	#[test]
	fn passive_decompose_hash_no_rule() {
		let a = make_constant("pd_hash_a");
		let p = Primitive {
			id: PRIM_HASH,
			arguments: vec![a],
			output: 0,
			instance_check: false,
		};
		let revealed = passively_decompose(&p);
		assert!(revealed.is_empty());
	}

	#[test]
	fn passive_decompose_core_primitive() {
		let a = make_constant("pd_core_a");
		let b = make_constant("pd_core_b");
		let p = Primitive {
			id: PRIM_CONCAT,
			arguments: vec![a, b],
			output: 0,
			instance_check: false,
		};
		let revealed = passively_decompose(&p);
		assert!(revealed.is_empty());
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
	fn can_decompose_enc_without_key() {
		let key = make_constant("cd_nk_key");
		let msg = make_constant("cd_nk_msg");
		let p = Primitive {
			id: PRIM_ENC,
			arguments: vec![key, msg],
			output: 0,
			instance_check: false,
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
