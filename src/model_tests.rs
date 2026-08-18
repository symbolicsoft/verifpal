/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

fn run_model(model: &str, expected: &str) {
	run_model_at(&format!("examples/test/{}", model), model, expected);
}

fn run_model_at(path: &str, model: &str, expected: &str) {
	let (_, results_code) =
		crate::verify::verify(path).unwrap_or_else(|e| panic!("ERROR • {} ({})", model, e));
	assert_eq!(
		results_code, expected,
		"FAIL • {} (expected {}, got {})",
		model, expected, results_code
	);
}

fn run_model_sessions(model: &str, sessions: u8, expected: &str) {
	let path = format!("examples/test/{}", model);
	let (_, results_code) = crate::verify::verify_with_sessions(&path, sessions)
		.unwrap_or_else(|e| panic!("ERROR • {} ({})", model, e));
	assert_eq!(
		results_code, expected,
		"FAIL • {} at {} sessions (expected {}, got {})",
		model, sessions, expected, results_code
	);
}

fn run_model_err(model: &str, expected_substring: &str) {
	let path = format!("examples/test/{}", model);
	match crate::verify::verify(&path) {
		Ok((_, code)) => panic!(
			"FAIL • {} (expected an error containing {:?}, got result code {})",
			model, expected_substring, code
		),
		Err(e) => {
			let text = format!("{}", e);
			assert!(
				text.contains(expected_substring),
				"FAIL • {} (expected an error containing {:?}, got: {})",
				model,
				expected_substring,
				text
			);
		}
	}
}

#[test]
fn test_cap_err_sign_weak() {
	run_model_err("cap_err_sign_weak.vp", "did you mean `SIGN[forgeable]`");
}
#[test]
fn test_cap_err_dh_kex_weak() {
	run_model_err("cap_err_dh_kex_weak.vp", "did you mean `PUBKEY[weak]`");
}
#[test]
fn test_cap_err_hash_forgeable() {
	run_model_err("cap_err_hash_forgeable.vp", "has no secret argument");
}
#[test]
fn test_cap_err_aead_malleable() {
	run_model_err(
		"cap_err_aead_malleable.vp",
		"did you mean `AEAD_ENC[forgeable]`",
	);
}
#[test]
fn test_cap_err_core_primitive() {
	run_model_err("cap_err_core_primitive.vp", "no cryptographic guarantee");
}
#[test]
fn test_cap_err_phase_unreached() {
	run_model_err("cap_err_phase_unreached.vp", "is never reached");
}

#[test]
fn test_cap_reach_notice() {
	run_model("cap_reach_notice.vp", "a1");
}
#[test]
fn test_cap_reach_secret() {
	run_model("cap_reach_secret.vp", "a1");
}
#[test]
fn test_cap_weak_hash() {
	run_model("cap_weak_hash.vp", "c1c1");
}
#[test]
fn test_cap_weak_pubkey_dh() {
	run_model("cap_weak_pubkey_dh.vp", "c1");
}
#[test]
fn test_cap_malleable_enc() {
	run_model("cap_malleable_enc.vp", "a1");
}
#[test]
fn test_cap_malleable_absent() {
	run_model("cap_malleable_absent.vp", "a0");
}
#[test]
fn test_cap_weak_kem_resolved() {
	run_model("cap_weak_kem_resolved.vp", "c1c1");
}
#[test]
fn test_cap_weak_phase_delayed() {
	run_model("cap_weak_phase_delayed.vp", "c0c1");
}

#[test]
fn test_cap_forgeable_sign() {
	run_model("cap_forgeable_sign.vp", "a1");
}
#[test]
fn test_cap_forgeable_aead() {
	run_model("cap_forgeable_aead.vp", "c0a1");
}

#[test]
fn test_cap_err_malleable_unsupported() {
	run_model_err(
		"cap_err_malleable_unsupported.vp",
		"HASH does not support the `malleable` parameter",
	);
}

#[test]
fn test_cap_multi_annotation() {
	run_model("cap_multi_annotation.vp", "c1c1");
}
#[test]
fn test_cap_noop_annotated() {
	run_model("cap_noop_annotated.vp", "c0a0");
}

#[test]
fn test_pqxdh_weak() {
	run_model_at("examples/messaging/pqxdh-weak.vp", "pqxdh-weak.vp", "c0a0");
}

#[test]
fn test_junglegym_hybrid_pq() {
	run_model("junglegym_hybrid_pq.vp", "c1c1c0a0a1f0f1e1e1");
}
#[test]
fn test_junglegym_threshold_ring() {
	run_model("junglegym_threshold_ring.vp", "c1c0c0a1a1a0u0u0u1f0f1e1e1");
}
#[test]
fn test_junglegym_password_maze() {
	run_model("junglegym_password_maze.vp", "c0c1c0c0c1a0a0a0f0f1e1e1u0");
}
#[test]
fn test_junglegym_phase_cascade() {
	run_model(
		"junglegym_phase_cascade.vp",
		"c1c1c0c1a0a0a0a0a1a1a0f0f1e0e0u1",
	);
}
#[test]
fn test_junglegym_deep_ratchet() {
	run_model(
		"junglegym_deep_ratchet.vp",
		"c0c0c0c0c0a0a0a0a0f0f1e1e1e0u0u0",
	);
}

#[test]
fn test_challengeresponse() {
	run_model("challengeresponse.vp", "a0a1");
}
#[test]
fn test_checked_aead() {
	run_model("checked_aead.vp", "c0a0a0");
}
#[test]
fn test_ephemerals_sign() {
	run_model("ephemerals_sign.vp", "c1a1");
}
#[test]
fn test_hmac_ok() {
	run_model("hmac_ok.vp", "c0a0");
}
#[test]
fn test_session_nonce_cross_one_session() {
	// One session: the only forgery route replays Bob's honest m1, so
	// authentication holds. This is the pre-sessions behavior, kept.
	run_model_sessions("session_nonce_cross.vp", 1, "a0");
}
#[test]
fn test_session_nonce_cross_two_sessions() {
	run_model_sessions("session_nonce_cross.vp", 2, "a1");
}
#[test]
fn test_session_replay_not_attack_one_session() {
	run_model_sessions("session_replay_not_attack.vp", 1, "a0");
}
#[test]
fn test_session_replay_not_attack_two_sessions() {
	run_model_sessions("session_replay_not_attack.vp", 2, "a0");
}
#[test]
fn test_session_concat_bomb_cross_feed() {
	run_model_sessions("concat_bomb_equiv.vp", 2, "e1e1e1e1e1f0");
}
#[test]
fn test_session_hmac_ok_stable_two_sessions() {
	run_model_sessions("hmac_ok.vp", 2, "c0a0");
}
#[test]
fn test_session_pke_stable_two_sessions() {
	run_model_sessions("pke.vp", 2, "c0a0");
}
#[test]
fn test_session_psk_cross_feed_one_session() {
	run_model_sessions("session_psk_cross_feed.vp", 1, "c0e0");
}
#[test]
fn test_session_psk_cross_feed() {
	run_model("session_psk_cross_feed.vp", "c0e1");
}
#[test]
fn test_session_dh_no_cross_feed_one_session() {
	run_model_sessions("session_dh_no_cross_feed.vp", 1, "c0e0");
}
#[test]
fn test_session_dh_no_cross_feed() {
	run_model("session_dh_no_cross_feed.vp", "c0e0");
}
#[test]
fn test_session_shamir_no_phantom_shares_one_session() {
	run_model_sessions("session_shamir_no_phantom_shares.vp", 1, "c0");
}
#[test]
fn test_session_shamir_no_phantom_shares() {
	run_model("session_shamir_no_phantom_shares.vp", "c0");
}
#[test]
fn test_session_mac_replay_not_attack_one_session() {
	run_model_sessions("session_mac_replay_not_attack.vp", 1, "a0");
}
#[test]
fn test_session_mac_replay_not_attack() {
	run_model("session_mac_replay_not_attack.vp", "a0");
}
#[test]
fn test_session_forward_secrecy_one_session() {
	run_model_sessions("session_forward_secrecy.vp", 1, "c0");
}
#[test]
fn test_session_forward_secrecy() {
	run_model("session_forward_secrecy.vp", "c0");
}
#[test]
fn test_session_freshness_stable_one_session() {
	run_model_sessions("session_freshness_stable.vp", 1, "f0f1");
}
#[test]
fn test_session_freshness_stable() {
	run_model("session_freshness_stable.vp", "f0f1");
}
#[test]
fn test_session_unlink_stable_one_session() {
	run_model_sessions("session_unlink_stable.vp", 1, "u0");
}
#[test]
fn test_session_unlink_stable() {
	run_model("session_unlink_stable.vp", "u0");
}
#[test]
fn test_session_signed_challenge_one_session() {
	run_model_sessions("session_signed_challenge.vp", 1, "a0");
}
#[test]
fn test_session_signed_challenge() {
	run_model("session_signed_challenge.vp", "a0");
}
#[test]
fn test_session_kem_cross_decap_one_session() {
	run_model_sessions("session_kem_cross_decap.vp", 1, "c0e0");
}
#[test]
fn test_session_kem_cross_decap() {
	run_model("session_kem_cross_decap.vp", "c0e1");
}
#[test]
fn test_session_password_no_leverage_one_session() {
	run_model_sessions("session_password_no_leverage.vp", 1, "c0c0");
}
#[test]
fn test_session_password_no_leverage() {
	run_model("session_password_no_leverage.vp", "c0c0");
}
#[test]
fn test_session_unguarded_mitm_one_session() {
	run_model_sessions("session_unguarded_mitm.vp", 1, "c1");
}
#[test]
fn test_session_unguarded_mitm() {
	run_model("session_unguarded_mitm.vp", "c1");
}
#[test]
fn test_session_three_sessions_one_session() {
	run_model_sessions("session_three_sessions.vp", 1, "c0");
}
#[test]
fn test_session_three_sessions() {
	run_model("session_three_sessions.vp", "c0");
}
#[test]
fn test_session_three_sessions_three() {
	run_model_sessions("session_three_sessions.vp", 3, "c0");
}
#[test]
fn test_foreign_halt_no_oracle_one_session() {
	run_model_sessions("foreign_halt_no_oracle.vp", 1, "a0");
}
#[test]
fn test_foreign_halt_no_oracle() {
	run_model("foreign_halt_no_oracle.vp", "a0");
}
#[test]
fn test_equivalence_halt_at_slot_one_session() {
	run_model_sessions("equivalence_halt_at_slot.vp", 1, "e0");
}
#[test]
fn test_equivalence_halt_at_slot() {
	run_model("equivalence_halt_at_slot.vp", "e1");
}
#[test]
fn test_hmac_unchecked_assert() {
	run_model("hmac_unchecked_assert.vp", "c0a1");
}
#[test]
fn test_hmac_unguarded_alice() {
	run_model("hmac_unguarded_alice.vp", "c0a1");
}
#[test]
fn test_hmac_unguarded_bob() {
	run_model("hmac_unguarded_bob.vp", "c1a0");
}
#[test]
fn test_concat_split_replay() {
	run_model("concat_split_replay.vp", "a0");
}
#[test]
fn test_wire_projection_replay() {
	run_model("wire_projection_replay.vp", "a0");
}
#[test]
fn test_forged_flight_mitm() {
	run_model("forged_flight_mitm.vp", "a1");
}
#[test]
fn test_aead_replay_not_forgery() {
	run_model("aead_replay_not_forgery.vp", "a0c0");
}
#[test]
fn test_deep_nesting_reconstruct() {
	run_model("deep_nesting_reconstruct.vp", "c1");
}
#[test]
fn test_dh_exponent_not_dropped() {
	run_model("dh_exponent_not_dropped.vp", "c0c0");
}
#[test]
fn test_ok() {
	run_model("ok.vp", "c0a0a0");
}
#[test]
fn test_pke() {
	run_model("pke.vp", "c0a0");
}
#[test]
fn test_pke_unguarded_alice() {
	run_model("pke_unguarded_alice.vp", "c0a1");
}
#[test]
fn test_pke_unguarded_bob() {
	run_model("pke_unguarded_bob.vp", "c1a0");
}
#[test]
fn test_pke_unchecked_assert() {
	run_model("pke_unchecked_assert.vp", "c0a1");
}
#[test]
fn test_assert_junglegym() {
	run_model("assert_junglegym.vp", "c0");
}
#[test]
fn test_pw_hash() {
	run_model("pw_hash.vp", "c0c0c0c0c0c0");
}
#[test]
fn test_pw_hash2() {
	run_model("pw_hash2.vp", "c0");
}
#[test]
fn test_shamir() {
	run_model("shamir.vp", "c1");
}
#[test]
fn test_subkey() {
	run_model("subkey.vp", "c1");
}
#[test]
fn test_subkey_hash() {
	run_model("subkey_hash.vp", "c1");
}
#[test]
fn test_subkey_hkdf() {
	run_model("subkey_hkdf.vp", "c1");
}
#[test]
fn test_trivial() {
	run_model("trivial.vp", "c1a1");
}
#[test]
fn test_unchecked_aead() {
	run_model("unchecked_aead.vp", "c0a1a1");
}
#[test]
fn test_unguarded_alice() {
	run_model("unguarded_alice.vp", "c0a1a1");
}
#[test]
fn test_unguarded_bob() {
	run_model("unguarded_bob.vp", "c1a0a0e1");
}
#[test]
fn test_signal_small_nophase() {
	run_model("signal_small_nophase.vp", "c1a1");
}
#[test]
fn test_signal_small_unguarded() {
	run_model("signal_small_unguarded.vp", "c1a1");
}
#[test]
fn test_signal_small_unguarded_alice() {
	run_model("signal_small_unguarded_alice.vp", "c0a1");
}
#[test]
fn test_signal_small_unguarded_bob() {
	run_model("signal_small_unguarded_bob.vp", "c1a1");
}
#[test]
fn test_signal_small_leaks() {
	run_model("signal_small_leaks.vp", "c1a1");
}
#[test]
fn test_signal_small_leaks_alice() {
	run_model("signal_small_leaks_alice.vp", "c0a1");
}
#[test]
fn test_signal_small_leaks_bob() {
	run_model("signal_small_leaks_bob.vp", "c1a1");
}
#[test]
fn test_auth_with_signing() {
	run_model("auth_with_signing.vp", "c1a1a1");
}
#[test]
fn test_auth_with_signing_false_attack() {
	run_model("auth_with_signing_false-attack.vp", "c0a1a0");
}
#[test]
fn test_halted_principal_false_attack() {
	run_model("halted_principal_false-attack.vp", "c0");
}
#[test]
fn test_shared_freshness_not_replication() {
	run_model("shared_freshness_not_replication.vp", "a1");
}
#[test]
fn test_dh_nested_rejected() {
	run_model_err(
		"dh_nested_rejected.vp",
		"PUBKEY cannot take DH_KEX as argument",
	);
}
#[test]
fn test_dh_two_public_keys() {
	run_model("dh_two_public_keys.vp", "c0c0");
}
#[test]
fn test_decompose_is_not_construct() {
	run_model("decompose_is_not_construct.vp", "c0c0c0");
}
#[test]
fn test_hmac_verif() {
	run_model("hmac_verif.vp", "a1a1");
}
#[test]
fn test_sign_ciphertext() {
	run_model("sign_ciphertext.vp", "c0a0");
}
#[test]
fn test_signature() {
	run_model("signature.vp", "c0a0a0");
}
#[test]
fn test_precondition() {
	run_model("precondition.vp", "a1");
}
#[test]
fn test_e_collection_key() {
	run_model("e_collection_key.vp", "c0a1");
}
#[test]
fn test_ringsign() {
	run_model("ringsign.vp", "a0");
}
#[test]
fn test_ringsign_substitute() {
	run_model("ringsign_substitute.vp", "a1a0a1a1");
}
#[test]
fn test_ringsign_unguarded() {
	run_model("ringsign_unguarded.vp", "a1");
}
#[test]
fn test_saltchannel() {
	run_model("saltchannel.vp", "c1");
}
#[test]
fn test_concat1() {
	run_model("concat1.vp", "c1");
}
#[test]
fn test_concat2() {
	run_model("concat2.vp", "c0");
}
#[test]
fn test_freshness() {
	run_model("freshness.vp", "f1f0");
}
#[test]
fn test_unlinkability() {
	run_model("unlinkability.vp", "u0u1u1");
}
#[test]
fn test_unlink_seed_leaked() {
	run_model("unlink_seed_leaked.vp", "u1");
}
#[test]
fn test_unlink_active_links() {
	run_model("unlink_active_links.vp", "u1");
}
#[test]
fn test_unlink_passive_holds() {
	run_model("unlink_passive_holds.vp", "u0");
}
#[test]
fn test_unlink_identical_values() {
	run_model("unlink_identical_values.vp", "u1");
}
#[test]
fn test_unlink_independent_origins() {
	run_model("unlink_independent_origins.vp", "u0");
}
#[test]
fn test_unlink_both_values_known() {
	run_model("unlink_both_values_known.vp", "u0");
}
#[test]
fn test_unlink_seed_secret() {
	run_model("unlink_seed_secret.vp", "u0");
}
#[test]
fn test_unlink_chain_forward() {
	run_model("unlink_chain_forward.vp", "u0");
}
#[test]
fn test_unlink_chain_root() {
	run_model("unlink_chain_root.vp", "u1");
}
#[test]
fn test_unlink_no_shared_ancestor() {
	run_model("unlink_no_shared_ancestor.vp", "u0");
}
#[test]
fn test_unlink_never_sent() {
	run_model("unlink_never_sent.vp", "u0");
}
#[test]
fn test_unlink_sealed() {
	run_model("unlink_sealed.vp", "u0");
}
#[test]
fn test_unlink_sealed_opened() {
	run_model("unlink_sealed_opened.vp", "u1");
}
#[test]
fn test_unlink_nonfresh_public() {
	run_model("unlink_nonfresh_public.vp", "u0");
}
#[test]
fn test_unlink_nonfresh_secret() {
	run_model("unlink_nonfresh_secret.vp", "u0");
}
#[test]
fn test_unlink_signature_links() {
	run_model("unlink_signature_links.vp", "u1");
}
#[test]
fn test_unlink_ringsign() {
	run_model("unlink_ringsign.vp", "u0");
}
#[test]
fn test_unlink_aead_probe() {
	run_model("unlink_aead_probe.vp", "u1");
}
#[test]
fn test_unlink_blind_signature() {
	run_model("unlink_blind_signature.vp", "u0");
}
#[test]
fn test_unlink_pubkey_pseudonym() {
	run_model("unlink_pubkey_pseudonym.vp", "u1");
}
#[test]
fn test_unlink_split_concat() {
	run_model("unlink_split_concat.vp", "u1");
}
#[test]
fn test_unlink_dh_mitm() {
	run_model("unlink_dh_mitm.vp", "u1");
}
#[test]
fn test_unlink_kem_leak() {
	run_model("unlink_kem_leak.vp", "u1");
}
#[test]
fn test_unlink_phase_compromise() {
	run_model("unlink_phase_compromise.vp", "u1");
}
#[test]
fn test_unlink_phase_holds() {
	run_model("unlink_phase_holds.vp", "u0");
}
#[test]
fn test_unlink_nary_one_pair() {
	run_model("unlink_nary_one_pair.vp", "u1");
}
#[test]
fn test_unlink_kdf_outputs() {
	run_model("unlink_kdf_outputs.vp", "u0");
}
#[test]
fn test_unlink_kdf_outputs_leaked() {
	run_model("unlink_kdf_outputs_leaked.vp", "u1");
}
#[test]
fn test_unlink_injected_equality() {
	run_model("unlink_injected_equality.vp", "u0");
}
#[test]
fn test_dp3t_root_leaked() {
	run_model("dp3t_root_leaked.vp", "c1a1u1");
}
#[test]
fn test_lc_dp_3t() {
	run_model_at(
		"examples/contact-tracing/lc-dp-3t.vp",
		"lc-dp-3t.vp",
		"c0a1u0",
	);
}
#[test]
fn test_needham_schroeder_pk() {
	run_model("needham-schroeder-pk.vp", "a1a1c1c1");
}
#[test]
fn test_needham_schroeder_pk_withfix() {
	run_model("needham-schroeder-pk-withfix.vp", "a1a1c1c0");
}
#[test]
fn test_needham_schroeder_symmetric() {
	run_model_at(
		"examples/transport-layer/needham-schroeder.vp",
		"needham-schroeder.vp",
		"c1c1a1a1a1",
	);
}
#[test]
fn test_replay_pump_reflection() {
	run_model("replay_pump_reflection.vp", "c0a1");
}
#[test]
fn test_fullresolution() {
	run_model("fullresolution.vp", "c1c1c1c1c0");
}
#[test]
fn test_ql() {
	run_model("ql.vp", "c0");
}
#[test]
fn test_escore_old() {
	run_model("escore_old.vp", "c1c1");
}
#[test]
fn test_test1() {
	run_model("test1.vp", "c1c1c1a1a1a1");
}
#[test]
fn test_test2() {
	run_model("test2.vp", "c0c0c0a0a1a1");
}
#[test]
fn test_test3() {
	run_model("test3.vp", "c1c1c1a1a1a1");
}
#[test]
fn test_test4() {
	run_model("test4.vp", "c0c0c0a0a1a1e0");
}
#[test]
fn test_test5() {
	run_model("test5.vp", "c1c1c1a1a1a1");
}
#[test]
fn test_ffgg() {
	run_model("ffgg.vp", "c1");
}
#[test]
fn test_exa() {
	run_model("exa.vp", "c1");
}
#[test]
fn test_exa2() {
	run_model("exa2.vp", "c1");
}
#[test]
fn test_fakeauth() {
	run_model("fakeauth.vp", "a0");
}
#[test]
fn test_replay_simple() {
	run_model("replay-simple.vp", "a0f0");
}
#[test]
fn test_mwe() {
	run_model("mwe.vp", "c0");
}
#[test]
fn test_password() {
	run_model("password.vp", "c1c1c1c1");
}
#[test]
fn test_dh_equiv() {
	run_model("dh_equiv.vp", "c1c1c1e0");
}
#[test]
fn test_melanie_bugs() {
	run_model("melanie_bugs.vp", "c1c1c1c1c1a1");
}
#[test]
fn test_simple_equiv() {
	run_model("simple_equiv.vp", "e0");
}
#[test]
fn test_equivalence_halt_scope() {
	run_model("equivalence_halt_scope.vp", "e0");
}
#[test]
fn test_ordering_a() {
	run_model("ordering_a.vp", "c1a1");
}
#[test]
fn test_ordering_b() {
	run_model("ordering_b.vp", "c1a1");
}
#[test]
fn test_aead_leak() {
	run_model("aead_leak.vp", "c0");
}
#[test]
fn test_deep_nesting() {
	run_model("deep_nesting.vp", "c0c0c0e1a1");
}
#[test]
fn test_triple_dh() {
	run_model("triple_dh.vp", "c0c0a0e0");
}
#[test]
fn test_key_ratchet() {
	run_model("key_ratchet.vp", "c0c0c0a0a0a0");
}
#[test]
fn test_four_party() {
	run_model("four_party.vp", "c1a0a0a0");
}
#[test]
fn test_phase_forward_secrecy() {
	run_model("phase_forward_secrecy.vp", "c0a0e0");
}

#[test]
fn test_phase_tamper_then_compromise() {
	run_model("phase_tamper_then_compromise.vp", "c1c1c1c1");
}

#[test]
fn test_phase_tamper_without_compromise() {
	run_model("phase_tamper_without_compromise.vp", "c0c0");
}

#[test]
fn test_phase_tamper_compromise_three_phases() {
	run_model("phase_tamper_compromise_three_phases.vp", "c1");
}

#[test]
fn test_phase_retroactive_forgery() {
	run_model("phase_retroactive_forgery.vp", "c0a0");
}

#[test]
fn test_phase_retroactive_aead_bypass() {
	run_model("phase_retroactive_aead_bypass.vp", "c1a0");
}

#[test]
fn test_phase_signed_prekey() {
	run_model("phase_signed_prekey.vp", "c0");
}

#[test]
fn test_phase_unsigned_prekey() {
	run_model("phase_unsigned_prekey.vp", "c1");
}
#[test]
fn test_shamir_reconstruction() {
	run_model("shamir_reconstruction.vp", "c1c1e1");
}
#[test]
fn test_blind_signature() {
	run_model("blind_signature.vp", "c0c0a1");
}
#[test]
fn test_relay_not_forgery() {
	run_model("relay_not_forgery.vp", "a0");
}
#[test]
fn test_concat_bomb() {
	run_model("concat_bomb.vp", "c0c0c0c0c0a0");
}
#[test]
fn test_concat_bomb_leak() {
	run_model("concat_bomb_leak.vp", "c1c1c1c1c1a1");
}
#[test]
fn test_concat_bomb_unguarded() {
	run_model("concat_bomb_unguarded.vp", "c0c0c0c0c0a1");
}
#[test]
fn test_concat_bomb_equiv() {
	// Pinned at one session explicitly: the default is two, where this model
	// legitimately fails (test_session_concat_bomb_cross_feed).
	run_model_sessions("concat_bomb_equiv.vp", 1, "e0e0e0e0e0f0");
}
#[test]
fn test_passive_dh_chain() {
	run_model("passive_dh_chain.vp", "c0c0c0e0");
}
#[test]
fn test_double_ratchet() {
	run_model("double_ratchet.vp", "c0c0a0a0e0e0");
}
#[test]
fn test_many_principals() {
	run_model("many_principals.vp", "c1a0a0a0a0a0f0");
}
#[test]
fn test_psk_with_dh() {
	run_model("psk_with_dh.vp", "c0c0a1a1");
}
#[test]
fn test_concat_password() {
	run_model("concat_password.vp", "c0c0c0");
}
#[test]
fn test_password_aead() {
	run_model("password_aead.vp", "c0");
}
#[test]
fn test_password_underspec() {
	run_model("password_underspec.vp", "c0c1c0c0c0c1c0c1c0c0c1c0");
}
#[test]
fn test_password_dh_unknown_base() {
	run_model("password_dh_unknown_base.vp", "c0");
}
#[test]
fn test_password_dh_known_base() {
	run_model("password_dh_known_base.vp", "c1");
}
#[test]
fn test_piknik_signature_not_forgeable() {
	run_model_at(
		"examples/transport-layer/piknik.vp",
		"piknik.vp",
		"c0a0a0a0f0",
	);
}
#[test]
fn test_kem_roundtrip() {
	run_model("kem_roundtrip.vp", "c0a1");
}
#[test]
fn test_kem_signed_ct() {
	run_model("kem_signed_ct.vp", "c0a0");
}
#[test]
fn test_kem_unguarded_ek() {
	run_model("kem_unguarded_ek.vp", "c1a1");
}
#[test]
fn test_kem_static_key_no_forward_secrecy() {
	run_model("kem_static_key_no_forward_secrecy.vp", "c1c1");
}
#[test]
fn test_kem_ephemeral_forward_secrecy() {
	run_model("kem_ephemeral_forward_secrecy.vp", "c0");
}
#[test]
fn test_kem_encapsulation_randomness_leak() {
	run_model("kem_encapsulation_randomness_leak.vp", "c1c1");
}
#[test]
fn test_kem_hybrid_classical_broken() {
	run_model("kem_hybrid_classical_broken.vp", "c0");
}
#[test]
fn test_kem_hybrid_pq_broken() {
	run_model("kem_hybrid_pq_broken.vp", "c0");
}
#[test]
fn test_kem_hybrid_both_broken() {
	run_model("kem_hybrid_both_broken.vp", "c1");
}
#[test]
fn test_kem_reused_randomness() {
	run_model("kem_reused_randomness.vp", "e0e1");
}
#[test]
fn test_kem_secret_not_forgeable() {
	run_model("kem_secret_not_forgeable.vp", "c0c0");
}
#[test]
fn test_kem_checked_decap() {
	run_model("kem_checked_decap.vp", "c0a0");
}
#[test]
fn test_kem_freshness() {
	run_model("kem_freshness.vp", "f0f1");
}
#[test]
fn test_minimal_witness() {
	run_model("minimal_witness.vp", "c1");
}
#[test]
fn test_bypass_witness_narration() {
	run_model("bypass_witness_narration.vp", "c0a1");
}
#[test]
fn a_witness_narrates_only_actions_the_attacker_can_take() {
	let (results, _) =
		crate::verify::verify("examples/test/bypass_witness_narration.vp").expect("verify");
	let auth = results
		.iter()
		.find(|r| r.resolved)
		.expect("the authentication query fails");
	assert!(
		!auth.summary.contains("replaces decrypted_file_alice_a"),
		"decrypted_file_alice_a is Bob's own computation: no wire crosses it, so a \
		 trace claiming the attacker replaces it describes an action no attacker can \
		 take. Narrated: {}",
		auth.summary
	);
	assert!(
		auth.summary.contains("replaces g_file_alice_a_key"),
		"the forgery is only accepted because the ephemeral public key was \
		 substituted; a trace without that step hides the attack's load-bearing \
		 move. Narrated: {}",
		auth.summary
	);
	assert!(
		auth.summary.contains("is successfully used in AEAD_DEC"),
		"the value is used in Bob's decryption; naming the slot whose injected \
		 key happens to share a term reports a usage that never happened. \
		 Narrated: {}",
		auth.summary
	);
}
