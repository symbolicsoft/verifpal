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

// ---------------------------------------------------------------------------
// Models added in the 2026-08 coverage pass. Every expected verdict below is
// argued in the corresponding model's own header comment in examples/test/,
// which is where the reasoning belongs; this file only pins the codes.
// ---------------------------------------------------------------------------
#[test]
fn test_anonymous_constants_many() {
	run_model("anonymous_constants_many.vp", "c0c0a0");
}
#[test]
fn test_assert_nested_deep() {
	run_model("assert_nested_deep.vp", "a0a1");
}
#[test]
fn test_blind_double_blinded() {
	run_model("blind_double_blinded.vp", "c1c0");
}
#[test]
fn test_blind_factor_leaked() {
	run_model("blind_factor_leaked.vp", "c1c0c0");
}
#[test]
fn test_blind_message_substituted() {
	run_model("blind_message_substituted.vp", "a1c0");
}
#[test]
fn test_blind_signing_oracle() {
	run_model("blind_signing_oracle.vp", "a1a0");
}
#[test]
fn test_blind_unblind_wrong_factor() {
	run_model("blind_unblind_wrong_factor.vp", "c0e1");
}
#[test]
fn test_broadcast_one_malicious_member() {
	run_model("broadcast_one_malicious_member.vp", "c1c0c0");
}
#[test]
fn test_cap_aead_weak_forgeable_matrix() {
	run_model("cap_aead_weak_forgeable_matrix.vp", "c1c0c1a0a1a1");
}
#[test]
fn test_cap_err_hkdf_weak() {
	run_model_err(
		"cap_err_hkdf_weak.vp",
		"HKDF does not support the `weak` parameter",
	);
}
#[test]
fn test_cap_err_mac_malleable() {
	run_model_err("cap_err_mac_malleable.vp", "did you mean `MAC[forgeable]`");
}
#[test]
fn test_cap_forgeable_cert_chain() {
	run_model("cap_forgeable_cert_chain.vp", "c1c0a1a0");
}
#[test]
fn test_cap_forgeable_mac() {
	run_model("cap_forgeable_mac.vp", "a1a0");
}
#[test]
fn test_cap_malleable_from_phase() {
	run_model("cap_malleable_from_phase.vp", "a0a1");
}
#[test]
fn test_cap_malleable_key_scoped() {
	run_model("cap_malleable_key_scoped.vp", "a1a0");
}
#[test]
fn test_cap_weak_enc() {
	run_model("cap_weak_enc.vp", "c1c0c0");
}
#[test]
fn test_cap_weak_hash_chain() {
	run_model("cap_weak_hash_chain.vp", "c1c0c1c1");
}
#[test]
fn test_cap_weak_layered_onsets() {
	run_model("cap_weak_layered_onsets.vp", "c1c1c0c0");
}
#[test]
fn test_cap_weak_pke_enc() {
	run_model("cap_weak_pke_enc.vp", "c1c0c0");
}
#[test]
fn test_cap_weak_pubkey_pke() {
	run_model("cap_weak_pubkey_pke.vp", "c1c0c1c0");
}
#[test]
fn test_checked_order_halt() {
	run_model("checked_order_halt.vp", "a1a0");
}
#[test]
fn test_concat_arity_roundtrip() {
	run_model("concat_arity_roundtrip.vp", "e0e0e0e1");
}
#[test]
fn test_concat_five_split_five() {
	run_model("concat_five_split_five.vp", "c0e0e1");
}
#[test]
fn test_concat_nested_projection() {
	run_model("concat_nested_projection.vp", "e0e1c0");
}
#[test]
fn test_cross_protocol_message_confusion() {
	run_model("cross_protocol_message_confusion.vp", "a1a0");
}
#[test]
fn test_dec_bypass_leaked_key() {
	run_model("dec_bypass_leaked_key.vp", "a1a0");
}
#[test]
fn test_dh_exponent_reuse() {
	run_model("dh_exponent_reuse.vp", "c1c0c0");
}
#[test]
fn test_dh_key_confirmation() {
	run_model("dh_key_confirmation.vp", "c0a0e0");
}
#[test]
fn test_dh_mitm_half_guarded() {
	run_model("dh_mitm_half_guarded.vp", "c0c1");
}
#[test]
fn test_dh_psk_hybrid() {
	run_model("dh_psk_hybrid.vp", "c0c1");
}
#[test]
fn test_dh_pubkey_leak_not_exponent() {
	run_model("dh_pubkey_leak_not_exponent.vp", "c0c0c1");
}
#[test]
fn test_dh_signed_ephemeral() {
	run_model("dh_signed_ephemeral.vp", "a0a1c0c1");
}
#[test]
fn test_dh_three_party_hub() {
	run_model("dh_three_party_hub.vp", "c1c1c0");
}
#[test]
fn test_dh_x3dh_signed_prekey() {
	run_model("dh_x3dh_signed_prekey.vp", "c0a1e1");
}
#[test]
fn test_downgrade_algorithm_choice() {
	run_model("downgrade_algorithm_choice.vp", "c1a1c0a0");
}
#[test]
fn test_eap_tunnel_channel_binding() {
	run_model("eap_tunnel_channel_binding.vp", "e0e1c0");
}
#[test]
fn test_equiv_aead_ad_mismatch() {
	run_model("equiv_aead_ad_mismatch.vp", "e0e1c0");
}
#[test]
fn test_equiv_dh_cross_principal() {
	run_model("equiv_dh_cross_principal.vp", "e0e1");
}
#[test]
fn test_equiv_kem_roundtrip() {
	run_model("equiv_kem_roundtrip.vp", "e0e1c0");
}
#[test]
fn test_equiv_pke_halt_scope() {
	run_model("equiv_pke_halt_scope.vp", "e0c0");
}
#[test]
fn test_equiv_ratchet_desync() {
	run_model("equiv_ratchet_desync.vp", "e0e1");
}
#[test]
fn test_equiv_shamir_all_pairs() {
	run_model("equiv_shamir_all_pairs.vp", "e0e0e1");
}
#[test]
fn test_equiv_three_constants() {
	run_model("equiv_three_constants.vp", "e0e1e0");
}
#[test]
fn test_equiv_unblind_roundtrip() {
	run_model("equiv_unblind_roundtrip.vp", "e0e1");
}
#[test]
fn test_flawed_anonymous_chat() {
	run_model("flawed_anonymous_chat.vp", "c1c1a1a1");
}
#[test]
fn test_flawed_blind_factor_public() {
	run_model("flawed_blind_factor_public.vp", "c1c1u0");
}
#[test]
fn test_flawed_debug_logging() {
	run_model("flawed_debug_logging.vp", "c1c1c1c1");
}
#[test]
fn test_flawed_downgrade_to_plaintext() {
	run_model("flawed_downgrade_to_plaintext.vp", "c1a1a1");
}
#[test]
fn test_flawed_encrypt_only_no_integrity() {
	run_model("flawed_encrypt_only_no_integrity.vp", "a1a1");
}
#[test]
fn test_flawed_escrow_master_key() {
	run_model("flawed_escrow_master_key.vp", "c1c1c1c1");
}
#[test]
fn test_flawed_hash_only_authentication() {
	run_model("flawed_hash_only_authentication.vp", "a1a1a1");
}
#[test]
fn test_flawed_iv_reuse_stream() {
	run_model("flawed_iv_reuse_stream.vp", "c1c1c1");
}
#[test]
fn test_flawed_kem_no_binding() {
	run_model("flawed_kem_no_binding.vp", "c1c1a1");
}
#[test]
fn test_flawed_key_from_public_data() {
	run_model("flawed_key_from_public_data.vp", "c1c1c1");
}
#[test]
fn test_flawed_nested_weak_layers() {
	run_model("flawed_nested_weak_layers.vp", "c1c1c1c1");
}
#[test]
fn test_flawed_password_login() {
	run_model("flawed_password_login.vp", "c1c1a1");
}
#[test]
fn test_flawed_pseudonym_reuse() {
	run_model("flawed_pseudonym_reuse.vp", "u1u1u1");
}
#[test]
fn test_flawed_psk_from_serial() {
	run_model("flawed_psk_from_serial.vp", "c1c1a1");
}
#[test]
fn test_flawed_pubkey_directory() {
	run_model("flawed_pubkey_directory.vp", "c1c1a1");
}
#[test]
fn test_flawed_ratchet_no_deletion() {
	run_model("flawed_ratchet_no_deletion.vp", "c1c1c1");
}
#[test]
fn test_flawed_resumption_ticket() {
	run_model("flawed_resumption_ticket.vp", "c1c1a1");
}
#[test]
fn test_flawed_shamir_broadcast() {
	run_model("flawed_shamir_broadcast.vp", "c1c1c1");
}
#[test]
fn test_flawed_shared_secret_broadcast() {
	run_model("flawed_shared_secret_broadcast.vp", "c1c1a1");
}
#[test]
fn test_flawed_signed_public_only() {
	run_model("flawed_signed_public_only.vp", "a1a1");
}
#[test]
fn test_flawed_static_timestamps() {
	run_model("flawed_static_timestamps.vp", "f1f1f1");
}
#[test]
fn test_flawed_trust_on_first_use() {
	run_model("flawed_trust_on_first_use.vp", "c1c1a1");
}
#[test]
fn test_forwarding_without_reencryption() {
	run_model("forwarding_without_reencryption.vp", "c1c0");
}
#[test]
fn test_freshness_concat_fields() {
	run_model("freshness_concat_fields.vp", "f0f1f0");
}
#[test]
fn test_freshness_deep_chain() {
	run_model("freshness_deep_chain.vp", "f1f0");
}
#[test]
fn test_freshness_dh_static() {
	run_model("freshness_dh_static.vp", "f1f0");
}
#[test]
fn test_freshness_hkdf_salt() {
	run_model("freshness_hkdf_salt.vp", "f0f1");
}
#[test]
fn test_freshness_kem_secret() {
	run_model("freshness_kem_secret.vp", "f0f1");
}
#[test]
fn test_freshness_shamir_share() {
	run_model("freshness_shamir_share.vp", "f1f0");
}
#[test]
fn test_freshness_unguarded_wire() {
	run_model("freshness_unguarded_wire.vp", "f0f1");
}
#[test]
fn test_guard_bypass_signverif() {
	run_model("guard_bypass_signverif.vp", "a0a1");
}
#[test]
fn test_hash_arity_distinguishes() {
	run_model("hash_arity_distinguishes.vp", "e1e1c0");
}
#[test]
fn test_hash_five_weak() {
	run_model("hash_five_weak.vp", "c1c1c0c0");
}
#[test]
fn test_hkdf_five_outputs() {
	run_model("hkdf_five_outputs.vp", "c0c1e1");
}
#[test]
fn test_hkdf_salt_swap() {
	run_model("hkdf_salt_swap.vp", "c0a0e1");
}
#[test]
fn test_identity_misbinding_uks() {
	run_model("identity_misbinding_uks.vp", "a1a1");
}
#[test]
fn test_kem_direction_reflection() {
	run_model("kem_direction_reflection.vp", "a1a0");
}
#[test]
fn test_kem_pke_hybrid() {
	run_model("kem_pke_hybrid.vp", "c0c0c1c1");
}
#[test]
fn test_kerberos_kdc_compromise() {
	run_model("kerberos_kdc_compromise.vp", "c1c1c0a1");
}
#[test]
fn test_key_reuse_sign_and_dh() {
	run_model("key_reuse_sign_and_dh.vp", "c1c0");
}
#[test]
fn test_leak_of_derived_not_root() {
	run_model("leak_of_derived_not_root.vp", "c0c1c1c0");
}
#[test]
fn test_mac_then_encrypt_order() {
	run_model("mac_then_encrypt_order.vp", "a1a0");
}
#[test]
fn test_mutual_auth_both_directions() {
	run_model("mutual_auth_both_directions.vp", "a0a1");
}
#[test]
fn test_nil_as_key() {
	run_model("nil_as_key.vp", "c1c0c1");
}
#[test]
fn test_noise_nk_anonymous_initiator() {
	run_model("noise_nk_anonymous_initiator.vp", "c0a1");
}
#[test]
fn test_noise_xx_mutual() {
	run_model("noise_xx_mutual.vp", "c1a1a1");
}
#[test]
fn test_nonce_echo_reflection() {
	run_model("nonce_echo_reflection.vp", "e0e1");
}
#[test]
fn test_oauth_code_interception() {
	run_model("oauth_code_interception.vp", "c1a0a0");
}
#[test]
fn test_otp_counter_freshness() {
	run_model("otp_counter_freshness.vp", "f1f0c0");
}
#[test]
fn test_password_deep_siblings() {
	run_model("password_deep_siblings.vp", "c1c0");
}
#[test]
fn test_password_kem_transcript() {
	run_model("password_kem_transcript.vp", "c1c0a1a0");
}
#[test]
fn test_password_mac_chain() {
	run_model("password_mac_chain.vp", "c0c1a0a1");
}
#[test]
fn test_password_pake_transcript() {
	run_model("password_pake_transcript.vp", "c1c0a1a0");
}
#[test]
fn test_password_sibling_leaked_later() {
	run_model("password_sibling_leaked_later.vp", "c0c1");
}
#[test]
fn test_phase_ad_reuse() {
	run_model("phase_ad_reuse.vp", "a1a0");
}
#[test]
fn test_phase_delayed_use() {
	run_model("phase_delayed_use.vp", "c1c0");
}
#[test]
fn test_phase_equiv_rotation() {
	run_model("phase_equiv_rotation.vp", "e0e1");
}
#[test]
fn test_phase_four_deep() {
	run_model("phase_four_deep.vp", "c0c1c1c1");
}
#[test]
fn test_phase_guard_dropped_later() {
	run_model("phase_guard_dropped_later.vp", "c0c1");
}
#[test]
fn test_phase_kem_harvest_later() {
	run_model("phase_kem_harvest_later.vp", "c1c0");
}
#[test]
fn test_phase_key_rotation() {
	run_model("phase_key_rotation.vp", "c0c1c1");
}
#[test]
fn test_phase_shamir_release() {
	run_model("phase_shamir_release.vp", "c1c0");
}
#[test]
fn test_phase_signing_key_leak() {
	run_model("phase_signing_key_leak.vp", "a0a1");
}
#[test]
fn test_phase_unlink_window() {
	run_model("phase_unlink_window.vp", "u1u0");
}
#[test]
fn test_pke_no_sender_authentication() {
	run_model("pke_no_sender_authentication.vp", "a1a0");
}
#[test]
fn test_pke_onion_two_layers() {
	run_model("pke_onion_two_layers.vp", "c0c1");
}
#[test]
fn test_pke_replay_wrong_recipient() {
	run_model("pke_replay_wrong_recipient.vp", "e0e1c0");
}
#[test]
fn test_pubkey_of_pubkey_rejected() {
	run_model_err(
		"pubkey_of_pubkey_rejected.vp",
		"PUBKEY cannot take PUBKEY as argument",
	);
}
#[test]
fn test_pw_hash_five_args() {
	run_model("pw_hash_five_args.vp", "c0c1");
}
#[test]
fn test_pw_hash_public_salt() {
	run_model("pw_hash_public_salt.vp", "c0c1c0c1");
}
#[test]
fn test_pw_hash_weak_cap() {
	run_model("pw_hash_weak_cap.vp", "c1c0c1c0");
}
#[test]
fn test_pw_hash_weak_from_phase() {
	run_model("pw_hash_weak_from_phase.vp", "c0c1");
}
#[test]
fn test_receipt_chain_broken_link() {
	run_model("receipt_chain_broken_link.vp", "a1a0");
}
#[test]
fn test_relay_four_hops() {
	run_model("relay_four_hops.vp", "c0a1a0");
}
#[test]
fn test_ringsign_forgeable_cap() {
	run_model("ringsign_forgeable_cap.vp", "a1a0");
}
#[test]
fn test_ringsign_ring_order() {
	run_model("ringsign_ring_order.vp", "e0e1a0");
}
#[test]
fn test_ringsign_ring_substituted() {
	run_model("ringsign_ring_substituted.vp", "a1");
}
#[test]
fn test_session_ad_binding_one_session() {
	run_model_sessions("session_ad_binding.vp", 1, "e0e0");
}
#[test]
fn test_session_ad_binding_two_sessions() {
	run_model_sessions("session_ad_binding.vp", 2, "e1e0");
}
#[test]
fn test_session_blind_stable_one_session() {
	run_model_sessions("session_blind_stable.vp", 1, "c0a0");
}
#[test]
fn test_session_blind_stable_two_sessions() {
	run_model_sessions("session_blind_stable.vp", 2, "c0a0");
}
#[test]
fn test_session_dh_static_cross_one_session() {
	run_model_sessions("session_dh_static_cross.vp", 1, "c0e0");
}
#[test]
fn test_session_dh_static_cross_two_sessions() {
	run_model_sessions("session_dh_static_cross.vp", 2, "c0e1");
}
#[test]
fn test_session_equiv_stable_one_session() {
	run_model_sessions("session_equiv_stable.vp", 1, "e0");
}
#[test]
fn test_session_equiv_stable_two_sessions() {
	run_model_sessions("session_equiv_stable.vp", 2, "e0");
}
#[test]
fn test_session_guard_stable_one_session() {
	run_model_sessions("session_guard_stable.vp", 1, "c0c1");
}
#[test]
fn test_session_guard_stable_two_sessions() {
	run_model_sessions("session_guard_stable.vp", 2, "c0c1");
}
#[test]
fn test_session_hkdf_cross_feed_one_session() {
	run_model_sessions("session_hkdf_cross_feed.vp", 1, "c0e0");
}
#[test]
fn test_session_hkdf_cross_feed_two_sessions() {
	run_model_sessions("session_hkdf_cross_feed.vp", 2, "c0e1");
}
#[test]
fn test_session_mac_key_rotation_one_session() {
	run_model_sessions("session_mac_key_rotation.vp", 1, "e0e0");
}
#[test]
fn test_session_mac_key_rotation_two_sessions() {
	run_model_sessions("session_mac_key_rotation.vp", 2, "e1e0");
}
#[test]
fn test_session_pke_cross_feed_one_session() {
	run_model_sessions("session_pke_cross_feed.vp", 1, "c0e0");
}
#[test]
fn test_session_pke_cross_feed_two_sessions() {
	run_model_sessions("session_pke_cross_feed.vp", 2, "c0e1");
}
#[test]
fn test_session_ringsign_stable_one_session() {
	run_model_sessions("session_ringsign_stable.vp", 1, "a0");
}
#[test]
fn test_session_ringsign_stable_two_sessions() {
	run_model_sessions("session_ringsign_stable.vp", 2, "a0");
}
#[test]
fn test_session_shamir_dealer_cross_one_session() {
	run_model_sessions("session_shamir_dealer_cross.vp", 1, "c0");
}
#[test]
fn test_session_shamir_dealer_cross_two_sessions() {
	run_model_sessions("session_shamir_dealer_cross.vp", 2, "c0");
}
#[test]
fn test_session_sign_oracle_cross_one_session() {
	run_model_sessions("session_sign_oracle_cross.vp", 1, "a0");
}
#[test]
fn test_session_sign_oracle_cross_two_sessions() {
	run_model_sessions("session_sign_oracle_cross.vp", 2, "a1");
}
#[test]
fn test_session_three_party_relay_one_session() {
	run_model_sessions("session_three_party_relay.vp", 1, "c0a0");
}
#[test]
fn test_session_three_party_relay_two_sessions() {
	run_model_sessions("session_three_party_relay.vp", 2, "c0a0");
}
#[test]
fn test_shamir_cross_dealer_join() {
	run_model("shamir_cross_dealer_join.vp", "c0c0e1");
}
#[test]
fn test_shamir_escrow_dh() {
	run_model("shamir_escrow_dh.vp", "c1c1");
}
#[test]
fn test_shamir_join_same_share() {
	run_model("shamir_join_same_share.vp", "c0c1");
}
#[test]
fn test_shamir_outer_shares() {
	run_model("shamir_outer_shares.vp", "c1c0");
}
#[test]
fn test_sigma_i() {
	run_model("sigma_i.vp", "c0a0a0e1");
}
#[test]
fn test_signverif_unchecked() {
	run_model("signverif_unchecked.vp", "a0a1");
}
#[test]
fn test_split_narrower_than_concat() {
	run_model("split_narrower_than_concat.vp", "e0e0e1c0");
}
#[test]
fn test_split_stuck_halts() {
	run_model("split_stuck_halts.vp", "a0a1");
}
#[test]
fn test_srp_naive_verifier() {
	run_model("srp_naive_verifier.vp", "c1c1a1a0");
}
#[test]
fn test_station_to_station() {
	run_model("station_to_station.vp", "c0c0a0a0e1");
}
#[test]
fn test_station_to_station_unsigned() {
	run_model("station_to_station_unsigned.vp", "c1c1a1a1");
}
#[test]
fn test_two_phase_commit_forged_ack() {
	run_model("two_phase_commit_forged_ack.vp", "a1a0");
}
#[test]
fn test_unlink_blind_active() {
	run_model("unlink_blind_active.vp", "u1u0");
}
#[test]
fn test_unlink_kem_decap_identifying() {
	run_model("unlink_kem_decap_identifying.vp", "u1u0");
}
#[test]
fn test_unlink_pke_recipient() {
	run_model("unlink_pke_recipient.vp", "u1u0");
}
#[test]
fn test_unlink_pw_hash_records() {
	run_model("unlink_pw_hash_records.vp", "u1u0");
}
#[test]
fn test_unlink_shamir_origin() {
	run_model("unlink_shamir_origin.vp", "u1u0");
}
#[test]
fn test_webauthn_origin_binding() {
	run_model("webauthn_origin_binding.vp", "e0e1");
}
#[test]
fn test_wireguard_static_fetched() {
	run_model("wireguard_static_fetched.vp", "c1a1");
}
