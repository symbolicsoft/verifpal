/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::primitive::{BypassKeyKind, PrimitiveSpec, primitive_check_undoing};
use crate::theory::{can_recompose, can_reconstruct_primitive};
use crate::types::*;

pub(crate) enum LinkWitnessKind {
	SharedSecret,
	IdentifyingCheck(PrimitiveId),
	ObservedEquality,
	RecognizedSecret(PrimitiveId),
}

pub(crate) struct LinkWitness {
	pub kind: LinkWitnessKind,
	pub value: Value,
}

pub(crate) fn find_link_witness(
	a: &Constant,
	b: &Constant,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<LinkWitness> {
	if !is_observable(a, ps, attacker) || !is_observable(b, ps, attacker) {
		return None;
	}
	if attacker_authored_slot(a, ps) || attacker_authored_slot(b, ps) {
		return None;
	}
	let (av, _) = ps.resolve_constant(a, true);
	let (bv, _) = ps.resolve_constant(b, true);
	witness_observed_equality(&av, &bv, ps, attacker)
		.or_else(|| witness_identifying_check(&av, &bv, ps, attacker))
		.or_else(|| witness_shared_secret(&av, &bv, ps, attacker))
		.or_else(|| witness_recognized_secret(&av, &bv, ps, attacker))
}

impl LinkWitness {
	pub(crate) fn describe(&self, term: &str) -> String {
		match self.kind {
			LinkWitnessKind::SharedSecret => format!("via {term}"),
			LinkWitnessKind::IdentifyingCheck(id) => format!(
				"because {} succeeds for both under {term}",
				crate::primitive::primitive_name(id)
			),
			LinkWitnessKind::ObservedEquality => {
				format!("because both are the same value ({term})")
			}
			LinkWitnessKind::RecognizedSecret(id) => format!(
				"via {term}, which {} confirms",
				crate::primitive::primitive_name(id)
			),
		}
	}
}

fn witness_identifying_check(
	av: &Value,
	bv: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<LinkWitness> {
	let (Value::Primitive(ap), Value::Primitive(bp)) = (av, bv) else {
		return None;
	};
	if ap.id != bp.id {
		return None;
	}
	let check = primitive_check_undoing(ap.id)?;
	let identifying = *check.identifying_positions.first()?;
	let (_, targets) = check
		.rewrite
		.as_ref()?
		.matching
		.iter()
		.find(|(position, _)| *position == identifying)?;
	let key_arg = *targets.first()?;
	if key_arg >= ap.arguments.len() || key_arg >= bp.arguments.len() {
		return None;
	}
	if !ap.arguments[key_arg].equivalent(&bp.arguments[key_arg], true) {
		return None;
	}
	let identifier = match check.bypass_key {
		Some(BypassKeyKind::Derived { constructor, .. }) => {
			Value::primitive(constructor, vec![ap.arguments[key_arg].clone()], 0)
		}
		_ => ap.arguments[key_arg].clone(),
	};
	if !crate::theory::obtainable(&identifier, ps, attacker) {
		return None;
	}
	Some(LinkWitness {
		kind: LinkWitnessKind::IdentifyingCheck(check.id),
		value: identifier,
	})
}

fn witness_shared_secret(
	av: &Value,
	bv: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<LinkWitness> {
	let a_leaves = origin_leaves(av, ps, attacker)?;
	let b_leaves = origin_leaves(bv, ps, attacker)?;
	for w in &a_leaves {
		if !depends_on_secret(w, ps) {
			continue;
		}
		if w.equivalent(av, true) || w.equivalent(bv, true) {
			continue;
		}
		if b_leaves.iter().any(|x| x.equivalent(w, true)) {
			return Some(LinkWitness {
				kind: LinkWitnessKind::SharedSecret,
				value: w.clone(),
			});
		}
	}
	None
}

fn witness_recognized_secret(
	av: &Value,
	bv: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<LinkWitness> {
	let a_recognized = recognized_secrets(av, ps, attacker);
	let b_recognized = recognized_secrets(bv, ps, attacker);
	if a_recognized.is_empty() && b_recognized.is_empty() {
		return None;
	}
	let a_tied = tied_values(av, &a_recognized, ps, attacker);
	let b_tied = tied_values(bv, &b_recognized, ps, attacker);
	for (w, id) in a_recognized.iter().chain(b_recognized.iter()) {
		if !depends_on_secret(w, ps) {
			continue;
		}
		if w.equivalent(av, true) || w.equivalent(bv, true) {
			continue;
		}
		if a_tied.iter().any(|x| x.equivalent(w, true))
			&& b_tied.iter().any(|x| x.equivalent(w, true))
		{
			return Some(LinkWitness {
				kind: LinkWitnessKind::RecognizedSecret(*id),
				value: w.clone(),
			});
		}
	}
	None
}

fn tied_values(
	v: &Value,
	recognized: &[(Value, PrimitiveId)],
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Vec<Value> {
	let mut out = origin_leaves(v, ps, attacker).unwrap_or_default();
	for (w, _) in recognized {
		push_leaf(&mut out, w);
	}
	out
}

fn recognized_secrets(
	v: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Vec<(Value, PrimitiveId)> {
	let Value::Primitive(p) = v else {
		return Vec::new();
	};
	if attacker.knows(v).is_none() {
		return Vec::new();
	}
	let Some(check) = primitive_check_undoing(p.id) else {
		return Vec::new();
	};
	let Some(rewrite) = check.rewrite.as_ref() else {
		return Vec::new();
	};
	let runnable = rewrite
		.matching
		.iter()
		.all(|(position, targets)| check_input_held(check, *position, targets, p, ps, attacker));
	if !runnable {
		return Vec::new();
	}
	let mut out: Vec<Value> = Vec::new();
	for (_, targets) in &rewrite.matching {
		for t in targets {
			let Some(arg) = p.arguments.get(*t) else {
				continue;
			};
			if is_key_derivation(check, arg) {
				continue;
			}
			if !crate::theory::obtainable(arg, ps, attacker) {
				continue;
			}
			push_leaf(&mut out, arg);
		}
	}
	out.into_iter().map(|w| (w, check.id)).collect()
}

fn check_input_held(
	check: &PrimitiveSpec,
	position: usize,
	targets: &[usize],
	p: &Primitive,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> bool {
	targets.iter().any(|t| {
		let Some(arg) = p.arguments.get(*t) else {
			return false;
		};
		if crate::theory::obtainable(arg, ps, attacker) {
			return true;
		}
		match check.bypass_key {
			Some(BypassKeyKind::Derived {
				arg: key,
				constructor,
			}) if key == position => {
				let derived = Value::primitive(constructor, vec![arg.clone()], 0);
				crate::theory::obtainable(&derived, ps, attacker)
			}
			_ => false,
		}
	})
}

fn is_key_derivation(check: &PrimitiveSpec, v: &Value) -> bool {
	let Some(BypassKeyKind::Derived { constructor, .. }) = check.bypass_key else {
		return false;
	};
	matches!(v, Value::Primitive(p) if p.id == constructor)
}

fn witness_observed_equality(
	av: &Value,
	bv: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<LinkWitness> {
	if !av.equivalent(bv, true) {
		return None;
	}
	if attacker.knows(av).is_none() || attacker.knows(bv).is_none() {
		return None;
	}
	if !depends_on_secret(av, ps) {
		return None;
	}
	Some(LinkWitness {
		kind: LinkWitnessKind::ObservedEquality,
		value: av.clone(),
	})
}

pub(crate) fn depends_on_secret(v: &Value, ps: &PrincipalState) -> bool {
	let mut constants = Vec::new();
	v.collect_constants(&mut constants);
	constants.iter().any(|c| constant_is_secret(c, ps))
}

fn attacker_authored_slot(c: &Constant, ps: &PrincipalState) -> bool {
	ps.index_of(c).is_some_and(|i| {
		let p = &ps.values[i].provenance;
		p.attacker_tainted || p.creator == crate::principal::ATTACKER_ID
	})
}

pub(crate) fn is_observable(c: &Constant, ps: &PrincipalState, attacker: &AttackerState) -> bool {
	if c.leaked {
		return true;
	}
	if ps
		.index_of(c)
		.is_some_and(|i| !ps.meta[i].wire.is_empty() || ps.meta[i].constant.leaked)
	{
		return true;
	}
	carried_observably(c, ps, attacker)
}

fn carried_observably(c: &Constant, ps: &PrincipalState, attacker: &AttackerState) -> bool {
	let Some(i) = ps.index_of(c) else {
		return false;
	};
	let (target, _) = ps.resolve_constant(c, true);
	if attacker.knows(&target).is_none() {
		return false;
	}
	let target_hash = target.hash_value();
	for (j, meta) in ps.meta.iter().enumerate() {
		if j == i || (meta.wire.is_empty() && !meta.constant.leaked) {
			continue;
		}
		let (carrier, _) = ps.resolve_constant(&meta.constant, true);
		if contains_equivalent_subterm(&carrier, &target, target_hash) {
			return true;
		}
	}
	false
}

fn contains_equivalent_subterm(value: &Value, target: &Value, target_hash: u64) -> bool {
	if value.hash_value() == target_hash && value.equivalent(target, true) {
		return true;
	}
	match value {
		Value::Constant(_) => false,
		Value::Primitive(p) => p
			.arguments
			.iter()
			.any(|arg| contains_equivalent_subterm(arg, target, target_hash)),
	}
}

fn constant_is_secret(c: &Constant, ps: &PrincipalState) -> bool {
	if c.fresh || matches!(c.qualifier, Some(Qualifier::Private | Qualifier::Password)) {
		return true;
	}
	ps.index_of(c).is_some_and(|i| {
		let m = &ps.meta[i].constant;
		m.fresh || matches!(m.qualifier, Some(Qualifier::Private | Qualifier::Password))
	})
}

fn attacker_without(attacker: &AttackerState, v: &Value) -> AttackerState {
	let h = v.hash_value();
	let size = attacker.known.len();
	let mut known: Vec<Value> = Vec::with_capacity(size);
	let mut mutation_records: Vec<Arc<MutationRecord>> = Vec::with_capacity(size);
	let mut derivations: Vec<DerivationRecord> = Vec::with_capacity(size);
	let mut known_map: IdMap<u64, Vec<usize>> = IdMap::default();
	let entries = attacker
		.known
		.iter()
		.zip(attacker.mutation_records.iter())
		.zip(attacker.derivations.iter());
	for ((k, record), derivation) in entries {
		if k.hash_value() == h && k.equivalent(v, true) {
			continue;
		}
		known_map
			.entry(k.hash_value())
			.or_default()
			.push(known.len());
		known.push(k.clone());
		mutation_records.push(Arc::clone(record));
		derivations.push(derivation.clone());
	}
	AttackerState {
		current_phase: attacker.current_phase,
		known: Arc::new(known),
		known_map: Arc::new(known_map),
		mutation_records: Arc::new(mutation_records),
		derivations: Arc::new(derivations),
	}
}

pub(crate) fn origin_leaves(
	v: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<Vec<Value>> {
	let without_self = attacker_without(attacker, v);
	let mut out = Vec::new();
	let mut expanded = Vec::new();
	collect_leaves(v, ps, &without_self, &mut expanded, &mut out).then_some(out)
}

fn collect_leaves(
	v: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	expanded: &mut Vec<Value>,
	out: &mut Vec<Value>,
) -> bool {
	let held = attacker.knows(v).is_some();
	if held {
		push_leaf(out, v);
	}
	let Value::Primitive(p) = v else {
		return held;
	};
	if expanded.iter().any(|seen| seen.equivalent(v, true)) {
		return held;
	}
	expanded.push(v.clone());
	let used = can_reconstruct_primitive(p, ps, attacker)
		.map(|r| r.from)
		.or_else(|| can_recompose(p, attacker).map(|r| r.used));
	let Some(used) = used else {
		return held;
	};
	for arg in &used {
		collect_leaves(arg, ps, attacker, expanded, out);
	}
	true
}

fn push_leaf(out: &mut Vec<Value>, v: &Value) {
	if !out.iter().any(|k| k.equivalent(v, true)) {
		out.push(v.clone());
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::{
		PRIM_HASH, PRIM_MAC, PRIM_PUBKEY, PRIM_RINGSIGN, PRIM_RINGSIGNVERIF, PRIM_SIGN,
	};
	use crate::testutil::*;

	fn state_from(values: &[Value]) -> PrincipalState {
		let mut meta = Vec::new();
		let mut slots = Vec::new();
		for v in values {
			let Value::Constant(c) = v else {
				continue;
			};
			meta.push(make_slot_meta(c, false));
			slots.push(make_slot_values(v, 1));
		}
		make_principal_state("Tester", 1, meta, slots)
	}

	#[test]
	fn secret_dependence() {
		let pub_c = make_constant("ul_pub");
		let secret = make_password("ul_pw");
		let ps = state_from(&[pub_c.clone(), secret.clone()]);
		assert!(!depends_on_secret(&pub_c, &ps));
		assert!(depends_on_secret(&secret, &ps));

		let mixed = make_primitive(PRIM_HASH, vec![secret, pub_c.clone()], 0);
		assert!(depends_on_secret(&mixed, &ps));
		let neither = make_primitive(PRIM_HASH, vec![pub_c.clone(), pub_c], 0);
		assert!(!depends_on_secret(&neither, &ps));
	}

	#[test]
	fn origin_leaves_excludes_the_value_itself() {
		let seed = make_password("ul_seed");
		let label = make_constant("ul_label");
		let tok = make_primitive(PRIM_HASH, vec![seed.clone(), label.clone()], 0);
		let ps = state_from(&[seed.clone(), label.clone()]);

		let attacker = make_attacker_state(vec![tok.clone(), seed.clone(), label.clone()]);
		let leaves = origin_leaves(&tok, &ps, &attacker).expect("reconstructible");
		assert!(leaves.iter().any(|v| v.equivalent(&seed, true)));
		assert!(!leaves.iter().any(|v| v.equivalent(&tok, true)));

		let attacker = make_attacker_state(vec![tok.clone()]);
		assert!(origin_leaves(&tok, &ps, &attacker).is_none());
	}

	#[test]
	fn withholding_a_value_keeps_knowledge_and_its_explanation_in_step() {
		let seed = make_password("ulw_seed");
		let label = make_constant("ulw_label");
		let tok = make_primitive(PRIM_HASH, vec![seed.clone(), label.clone()], 0);
		let attacker = make_attacker_state(vec![tok.clone(), seed.clone(), label.clone()]);

		let without = attacker_without(&attacker, &tok);

		assert_eq!(without.known.len(), 2);
		assert!(without.knows(&tok).is_none());
		assert_eq!(without.mutation_records.len(), without.known.len());
		assert_eq!(without.derivations.len(), without.known.len());
		for value in [&seed, &label] {
			let idx = without.knows(value).expect("still known");
			assert!(
				without.derivation(idx).is_some() && without.record(idx).is_some(),
				"a value the attacker still holds must still carry the derivation \
				 that explains it"
			);
		}
	}

	#[test]
	fn signatures_link_but_ring_signatures_do_not() {
		let sk = make_password("w2_sk");
		let gb = make_constant("w2_gb");
		let gc = make_constant("w2_gc");
		let m1 = make_constant("w2_m1");
		let m2 = make_constant("w2_m2");
		let ga = make_primitive(PRIM_PUBKEY, vec![sk.clone()], 0);
		let s1 = make_primitive(PRIM_SIGN, vec![sk.clone(), m1.clone()], 0);
		let s2 = make_primitive(PRIM_SIGN, vec![sk.clone(), m2.clone()], 0);
		let ps = state_from(&[gb.clone(), gc.clone(), m1.clone(), m2.clone()]);
		let attacker = make_attacker_state(vec![
			ga.clone(),
			m1.clone(),
			m2.clone(),
			s1.clone(),
			s2.clone(),
		]);
		let w = witness_identifying_check(&s1, &s2, &ps, &attacker).expect("signatures link");
		assert!(w.value.equivalent(&ga, true));

		let r1 = make_primitive(
			PRIM_RINGSIGN,
			vec![sk.clone(), gb.clone(), gc.clone(), m1],
			0,
		);
		let r2 = make_primitive(PRIM_RINGSIGN, vec![sk, gb, gc, m2], 0);
		let attacker = make_attacker_state(vec![r1.clone(), r2.clone(), ga]);
		let undoing =
			primitive_check_undoing(PRIM_RINGSIGN).expect("RINGSIGNVERIF undoes RINGSIGN");
		assert_eq!(undoing.id, PRIM_RINGSIGNVERIF);
		assert!(undoing.identifying_positions.is_empty());
		assert!(witness_identifying_check(&r1, &r2, &ps, &attacker).is_none());
	}

	#[test]
	fn shared_secret_links_across_different_applications() {
		let seed = make_password("w1_seed");
		let c1 = make_constant("w1_c1");
		let c2 = make_constant("w1_c2");
		let tok1 = make_primitive(PRIM_HASH, vec![seed.clone(), c1.clone()], 0);
		let tok2 = make_primitive(PRIM_HASH, vec![seed.clone(), c2.clone()], 0);
		let ps = state_from(&[seed.clone(), c1.clone(), c2.clone()]);

		let attacker = make_attacker_state(vec![
			tok1.clone(),
			tok2.clone(),
			seed.clone(),
			c1.clone(),
			c2.clone(),
		]);
		let w = witness_shared_secret(&tok1, &tok2, &ps, &attacker).expect("linked");
		assert!(w.value.equivalent(&seed, true));

		let attacker = make_attacker_state(vec![tok1.clone(), tok2.clone(), c1, c2]);
		assert!(witness_shared_secret(&tok1, &tok2, &ps, &attacker).is_none());
	}

	#[test]
	fn observed_equality_needs_a_secret() {
		let k = make_password("w3_k");
		let n = make_constant("w3_n");
		let tok = make_primitive(PRIM_MAC, vec![k.clone(), n.clone()], 0);
		let ps = state_from(&[k, n]);
		let attacker = make_attacker_state(vec![tok.clone()]);
		assert!(witness_observed_equality(&tok, &tok, &ps, &attacker).is_some());

		let pub_c = make_constant("w3_pub");
		let pub_tok = make_primitive(PRIM_MAC, vec![pub_c.clone(), pub_c.clone()], 0);
		let ps = state_from(std::slice::from_ref(&pub_c));
		let attacker = make_attacker_state(vec![pub_tok.clone()]);
		assert!(witness_observed_equality(&pub_tok, &pub_tok, &ps, &attacker).is_none());
	}

	#[test]
	fn observability_keys_on_the_wire() {
		let travelled = make_constant("ul_wire");
		let ps = state_from(std::slice::from_ref(&travelled));
		let Value::Constant(c) = &travelled else {
			unreachable!()
		};
		let attacker = make_attacker_state(vec![travelled.clone()]);
		assert!(is_observable(c, &ps, &attacker));

		let Value::Constant(absent) = make_constant("ul_absent") else {
			unreachable!()
		};
		assert!(!is_observable(&absent, &ps, &attacker));
	}

	#[test]
	fn a_term_hash_collision_does_not_make_a_value_observable() {
		fn constant(name: &str, id: ValueId) -> Value {
			Value::Constant(Constant {
				name: Arc::from(name),
				id,
				guard: false,
				fresh: false,
				leaked: false,
				declaration: Some(Declaration::Knows),
				qualifier: Some(Qualifier::Public),
			})
		}

		let target_name = constant("ul_collision_target", 1000);
		let carrier_name = constant("ul_collision_carrier", 1001);
		let target = make_primitive(
			PRIM_HASH,
			vec![
				constant("ul_collision_a", 10),
				constant("ul_collision_b", 100),
			],
			0,
		);
		let carrier = make_primitive(
			PRIM_HASH,
			vec![
				constant("ul_collision_c", 11),
				constant("ul_collision_d", 69),
			],
			0,
		);
		assert_eq!(target.hash_value(), carrier.hash_value());
		assert!(!target.equivalent(&carrier, true));

		let Value::Constant(target_constant) = &target_name else {
			unreachable!()
		};
		let Value::Constant(carrier_constant) = &carrier_name else {
			unreachable!()
		};
		let ps = make_principal_state(
			"Tester",
			1,
			vec![
				make_slot_meta(target_constant, true),
				make_slot_meta(carrier_constant, false),
			],
			vec![make_slot_values(&target, 1), make_slot_values(&carrier, 1)],
		);
		let attacker = make_attacker_state(vec![target]);
		assert!(!carried_observably(target_constant, &ps, &attacker));
	}
}
