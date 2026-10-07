/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::rewrite::{can_combine, combine_with};
use super::*;
use crate::primitive::*;
use crate::term::{Application, Primitive, Value, value_nil};
use crate::testing::*;

#[test]
fn malleability_deduction_requires_its_source_phase_key_and_payload() {
	let key = make_private("maul_deduction_key");
	let other = make_private("maul_deduction_other");
	let hidden = make_private("maul_deduction_hidden");
	let source = Primitive::new(PRIM_ENC, vec![key.clone(), hidden.clone()], 0)
		.with(|application| application.capabilities.set(Capability::Malleable, 2));
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
fn rewrite_pointer_hits_preserve_collisions_and_checked_instances() {
	let a = make_constant("pointer_collision_a");
	let b = make_constant("pointer_collision_b");
	let pass = Arc::new(Primitive::new(PRIM_ASSERT, vec![a.clone(), a.clone()], 0));
	let fail = Arc::new(Primitive::new(PRIM_ASSERT, vec![a, b], 0));
	fail.cache()
		.set(crate::term::hashing::primitive_hash(&pass));
	let checked = fail.with(|application| application.instance_check = true);
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

fn weak_index(v: &Value, onset: i32) -> CapabilityIndex {
	let Value::Primitive(p) = v else {
		panic!("expected a primitive");
	};
	let annotated = p.with(|application| application.capabilities.set(Capability::Weak, onset));
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
	let mut with_pair = make_attacker_state(vec![e1.clone(), e2.clone(), m3.clone(), ad.clone()]);
	with_pair.reused = Arc::new(vec![[e1.clone(), e2]]);
	let result = can_reconstruct_primitive(&target, &capabilities, &with_pair)
		.expect("forgeable under reuse");
	assert!(matches!(result, DerivationRecord::ReusedForge { .. }));
	assert_eq!(result.supplied().len(), 2);
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
		Arc::new(Primitive::from(Application {
			id: PRIM_SPLIT,
			arguments: vec![concat.clone()],
			output,
			instance: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			threshold: 0,
		}))
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
	let dec = Primitive::from(Application {
		id: PRIM_PKE_DEC,
		arguments: vec![sk2, enc],
		output: 0,
		instance: 0,
		instance_check: false,
		capabilities: Capabilities::default(),
		threshold: 0,
	});
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
	let proj = Primitive::from(Application {
		id: PRIM_SPLIT,
		arguments: vec![pair],
		output: 1,
		instance: 0,
		instance_check: false,
		capabilities: Capabilities::default(),
		threshold: 0,
	});
	let capabilities = CapabilityIndex::default();
	let attacker = make_attacker_state(vec![b]);
	assert!(can_reconstruct_primitive(&Arc::new(proj), &capabilities, &attacker).is_some());
}

fn ring(members: [&Value; 3], message: &Value, signature: &Value) -> Arc<Primitive> {
	Arc::new(Primitive::from(Application {
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
	}))
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
	let assert_prim = Primitive::from(Application {
		id: PRIM_ASSERT,
		arguments: vec![a.clone(), a.clone()],
		output: 0,
		instance: 0,
		instance_check: false,
		capabilities: Capabilities::default(),
		threshold: 0,
	});
	let (rewritten, _) = can_rewrite(&Arc::new(assert_prim));
	assert!(rewritten);
}

#[test]
fn can_rewrite_assert_mismatch() {
	let a = make_constant("cram_a");
	let b = make_constant("cram_b");
	let assert_prim = Primitive::from(Application {
		id: PRIM_ASSERT,
		arguments: vec![a, b],
		output: 0,
		instance: 0,
		instance_check: false,
		capabilities: Capabilities::default(),
		threshold: 0,
	});
	let (rewritten, _) = can_rewrite(&Arc::new(assert_prim));
	assert!(!rewritten);
}

#[test]
fn recompose_counts_distinct_held_shares_against_the_threshold() {
	let secret = make_constant("rct_secret");
	let split = |t: usize| {
		Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], 0)
			.with(|application| application.threshold = t)
	};
	let share = |t: usize, output: usize| Value::Primitive(Arc::new(split(t).with_output(output)));
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
	let p = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], output)
		.with(|application| application.threshold = t);
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
	assert_eq!(built.supplied().len(), 2);
	assert!(
		built
			.supplied()
			.iter()
			.any(|f| f.equivalent(&partial, true))
	);
	assert!(!built.forged());
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
	assert!(combination_holds(&signature, built.supplied()));
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
	let result = can_decompose(p, &capabilities, &attacker).expect("the nonce exposes the share");
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
	let p = Primitive::from(Application {
		id: PRIM_ENC,
		arguments: vec![key.clone(), msg.clone()],
		output: 0,
		instance: 0,
		instance_check: false,
		capabilities: Capabilities::default(),
		threshold: 0,
	});
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
	let ct = Primitive::from(Application {
		id: PRIM_KEM_ENCAP,
		arguments: vec![ek.clone(), r.clone()],
		output: 1,
		instance: 0,
		instance_check: false,
		capabilities: Capabilities::default(),
		threshold: 0,
	});
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
	let ct = Primitive::from(Application {
		id: PRIM_KEM_ENCAP,
		arguments: vec![ek.clone(), r],
		output: 1,
		instance: 0,
		instance_check: false,
		capabilities: Capabilities::default(),
		threshold: 0,
	});
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
	let decap = Primitive::from(Application {
		id: PRIM_KEM_DECAP,
		arguments: vec![dk, ct],
		output: 0,
		instance: 0,
		instance_check: false,
		capabilities: Capabilities::default(),
		threshold: 0,
	});
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
	let decap = Primitive::from(Application {
		id: PRIM_KEM_DECAP,
		arguments: vec![other, ct],
		output: 0,
		instance: 0,
		instance_check: false,
		capabilities: Capabilities::default(),
		threshold: 0,
	});
	let (rewritten, _) = can_rewrite(&Arc::new(decap));
	assert!(!rewritten);
}

#[test]
fn can_decompose_enc_without_key() {
	let key = make_constant("cd_nk_key");
	let msg = make_constant("cd_nk_msg");
	let p = Primitive::from(Application {
		id: PRIM_ENC,
		arguments: vec![key, msg],
		output: 0,
		instance: 0,
		instance_check: false,
		capabilities: Capabilities::default(),
		threshold: 0,
	});
	let capabilities = CapabilityIndex::default();
	let attacker = make_attacker_state(vec![]);
	assert!(can_decompose(&p, &capabilities, &attacker).is_none());
}

fn rewrite(value: &Value) -> (bool, Value) {
	crate::util::generation::enter_generation(crate::util::generation::next_generation());
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
			assert!(crate::term::equivalence::structurally_identical(
				&value, &expected
			));
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
	let dec = Value::Primitive(Arc::new(Primitive::from(Application {
		id: PRIM_AEAD_DEC,
		arguments: vec![other, n, sealed, ad],
		output: 0,
		instance: 0,
		instance_check: true,
		capabilities: Capabilities::default(),
		threshold: 0,
	})));
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
		let p = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], output)
			.with(|application| application.threshold = 2);
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
		let p = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], output)
			.with(|application| application.threshold = 3);
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
		let p = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], output)
			.with(|application| application.threshold = 2);
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
	let split = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], 0)
		.with(|application| application.threshold = 2);
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
	crate::util::generation::enter_generation(crate::util::generation::next_generation());
	let (Value::Primitive(p), Value::Primitive(q)) = (build(), build()) else {
		unreachable!()
	};
	assert!(!Arc::ptr_eq(&p, &q), "two separately built terms");
	can_rewrite(&p);
	assert!(can_rewrite(&q).1.equivalent(&m, true));
}
