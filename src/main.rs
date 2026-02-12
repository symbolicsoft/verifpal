/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

mod attackerstate;
mod construct;
mod info;
mod inject;
mod mutationmap;
mod narrative;
mod parser;
mod possible;
mod pretty;
mod primitive;
mod principal;
mod query;
mod sanity;
mod types;
mod util;
mod value;
mod verify;
mod verifyactive;
mod verifyanalysis;
mod verifyresults;
mod tui;
mod verifhub;

use clap::{Parser, Subcommand};

const VERSION: &str = "0.31.2";

#[derive(Parser)]
#[command(name = "verifpal", version = VERSION, about = format!("Verifpal {} - https://verifpal.com", VERSION))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a Verifpal model
    #[command(arg_required_else_help = true)]
    Verify {
        /// Path to the Verifpal model file
        model: String,
        /// Submit to VerifHub upon analysis completion
        #[arg(long, default_value_t = false)]
        verifhub: bool,
        /// Output only the result code (for testing)
        #[arg(long, default_value_t = false)]
        result_code: bool,
        /// Attacker character voice (jevil, spamton)
        #[arg(long)]
        character: Option<String>,
    },
    /// Pretty-print a Verifpal model
    #[command(arg_required_else_help = true)]
    Pretty {
        /// Path to the Verifpal model file
        model: String,
    },
    /// About information for the Verifpal software
    About,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Verify { model, verifhub: hub, result_code, character } => {
            if let Some(ref ch) = character {
                if let Err(e) = narrative::set_character(ch) {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
            if !result_code {
                tui::set_tui_mode(true);
                info::info_banner(VERSION);
                info::info_message("Verifpal is Beta software.", "warning", false);
            }
            verifhub::VERIFHUB_SCHEDULED.store(hub, std::sync::atomic::Ordering::Relaxed);
            match verify::verify(&model) {
                Ok((_, code)) => {
                    if result_code {
                        println!("{}", code);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Pretty { model } => {
            match pretty::pretty_print(&model) {
                Ok(output) => print!("{}", output),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::About => {
            info::info_banner(VERSION);
            println!("Verifpal is authored by Nadim Kobeissi.");
            println!("The following individuals have contributed");
            println!("meaningful suggestions, bug reports, ideas");
            println!("or discussion to the Verifpal project:");
            println!();
            println!("  - Angèle Bossuat");
            println!("  - Bruno Blanchet (Prof. Dr.)");
            println!("  - Fabian Drinck");
            println!("  - Friedrich Wiemer");
            println!("  - Georgio Nicolas");
            println!("  - Jean-Philippe Aumasson (Dr.)");
            println!("  - Laurent Grémy");
            println!("  - Loup Vaillant David");
            println!("  - Michiel Leenars");
            println!("  - \"Mike\" (pseudonym)");
            println!("  - Mukesh Tiwari (Dr.)");
            println!("  - Oleksandra \"Sasha\" Lapiha");
            println!("  - Oskar Goldhahn");
            println!("  - Renaud Lifchitz");
            println!("  - Sebastian R. Verschoor");
            println!("  - Tom Roeder");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{LazyLock, Mutex};

    // Global lock: the verification engine uses process-wide mutable state
    // (attacker state, verify results, etc.), so tests must run sequentially.
    static TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn run_model(model: &str, expected: &str) {
        let _guard = TEST_LOCK.lock().unwrap();
        let file_name = format!("examples/test/{}", model);
        let (_, results_code) = crate::verify::verify(&file_name)
            .unwrap_or_else(|e| panic!("ERROR • {} ({})", model, e));
        assert_eq!(
            results_code, expected,
            "FAIL • {} (expected {}, got {})",
            model, expected, results_code
        );
    }

    #[test] fn test_challengeresponse() { run_model("challengeresponse.vp", "a0a1"); }
    #[test] fn test_checked_aead() { run_model("checked_aead.vp", "c0a0a0"); }
    #[test] fn test_ephemerals_sign() { run_model("ephemerals_sign.vp", "c1a1"); }
    #[test] fn test_hmac_ok() { run_model("hmac_ok.vp", "c0a0"); }
    #[test] fn test_hmac_unchecked_assert() { run_model("hmac_unchecked_assert.vp", "c0a1"); }
    #[test] fn test_hmac_unguarded_alice() { run_model("hmac_unguarded_alice.vp", "c0a1"); }
    #[test] fn test_hmac_unguarded_bob() { run_model("hmac_unguarded_bob.vp", "c1a0"); }
    #[test] fn test_ok() { run_model("ok.vp", "c0a0a0"); }
    #[test] fn test_pke() { run_model("pke.vp", "c0a0"); }
    #[test] fn test_pke_unguarded_alice() { run_model("pke_unguarded_alice.vp", "c0a1"); }
    #[test] fn test_pke_unguarded_bob() { run_model("pke_unguarded_bob.vp", "c1a0"); }
    #[test] fn test_pke_unchecked_assert() { run_model("pke_unchecked_assert.vp", "c0a1"); }
    #[test] fn test_pw_hash() { run_model("pw_hash.vp", "c1c0c0c0c1c1"); }
    #[test] fn test_pw_hash2() { run_model("pw_hash2.vp", "c0"); }
    #[test] fn test_shamir() { run_model("shamir.vp", "c1"); }
    #[test] fn test_subkey() { run_model("subkey.vp", "c1"); }
    #[test] fn test_subkey_hash() { run_model("subkey_hash.vp", "c1"); }
    #[test] fn test_subkey_hkdf() { run_model("subkey_hkdf.vp", "c1"); }
    #[test] fn test_trivial() { run_model("trivial.vp", "c1a1"); }
    #[test] fn test_unchecked_aead() { run_model("unchecked_aead.vp", "c0a1a1"); }
    #[test] fn test_unguarded_alice() { run_model("unguarded_alice.vp", "c0a1a1"); }
    #[test] fn test_unguarded_bob() { run_model("unguarded_bob.vp", "c1a0a0e1"); }
    #[test] fn test_signal_small_nophase() { run_model("signal_small_nophase.vp", "c1a1"); }
    #[test] fn test_signal_small_unguarded() { run_model("signal_small_unguarded.vp", "c1a1"); }
    #[test] fn test_auth_with_signing() { run_model("auth_with_signing.vp", "c1a1a1"); }
    #[test] fn test_auth_with_signing_false_attack() { run_model("auth_with_signing_false-attack.vp", "c0a1a0"); }
    #[test] fn test_hmac_verif() { run_model("hmac_verif.vp", "a1a1"); }
    #[test] fn test_sign_ciphertext() { run_model("sign_ciphertext.vp", "c0a0"); }
    #[test] fn test_signature() { run_model("signature.vp", "c0a0a0"); }
    #[test] fn test_precondition() { run_model("precondition.vp", "a1"); }
    #[test] fn test_e_collection_key() { run_model("e_collection_key.vp", "c0a1"); }
    #[test] fn test_ringsign() { run_model("ringsign.vp", "a0"); }
    #[test] fn test_ringsign_substitute() { run_model("ringsign_substitute.vp", "a1a0a1a1"); }
    #[test] fn test_ringsign_unguarded() { run_model("ringsign_unguarded.vp", "a1"); }
    #[test] fn test_saltchannel() { run_model("saltchannel.vp", "c1"); }
    #[test] fn test_concat1() { run_model("concat1.vp", "c1"); }
    #[test] fn test_concat2() { run_model("concat2.vp", "c0"); }
    #[test] fn test_freshness() { run_model("freshness.vp", "f1f0"); }
    #[test] fn test_unlinkability() { run_model("unlinkability.vp", "u1u1u0"); }
    #[test] fn test_needham_schroeder_pk() { run_model("needham-schroeder-pk.vp", "a1a1c1c1"); }
    #[test] fn test_needham_schroeder_pk_withfix() { run_model("needham-schroeder-pk-withfix.vp", "a1a1c1c0"); }
    #[test] fn test_fullresolution() { run_model("fullresolution.vp", "c1c1c1c1c0"); }
    #[test] fn test_ql() { run_model("ql.vp", "c0"); }
    #[test] fn test_escore_old() { run_model("escore_old.vp", "c1c1"); }
    #[test] fn test_test1() { run_model("test1.vp", "c1c1c1a1a1a1"); }
    #[test] fn test_test2() { run_model("test2.vp", "c0c0c0a0a1a1"); }
    #[test] fn test_test3() { run_model("test3.vp", "c1c1c1a1a1a1"); }
    #[test] fn test_test4() { run_model("test4.vp", "c0c0c0a0a1a1e0"); }
    #[test] fn test_test5() { run_model("test5.vp", "c1c1c1a1a1a1"); }
    #[test] fn test_ffgg() { run_model("ffgg.vp", "c1"); }
    #[test] fn test_exa() { run_model("exa.vp", "c1"); }
    #[test] fn test_exa2() { run_model("exa2.vp", "c1"); }
    #[test] fn test_fakeauth() { run_model("fakeauth.vp", "a0"); }
    #[test] fn test_replay_simple() { run_model("replay-simple.vp", "a0f0"); }
    #[test] fn test_mwe() { run_model("mwe.vp", "c0"); }
    #[test] fn test_password() { run_model("password.vp", "c1c1c1c1"); }
    #[test] fn test_dh_equiv() { run_model("dh_equiv.vp", "c1c1c1e0"); }
    #[test] fn test_melanie_bugs() { run_model("melanie_bugs.vp", "c1c1c1c1c1a1"); }
    #[test] fn test_simple_equiv() { run_model("simple_equiv.vp", "e0"); }
    #[test] fn test_ordering_a() { run_model("ordering_a.vp", "c1a1"); }
    #[test] fn test_ordering_b() { run_model("ordering_b.vp", "c1a1"); }
    #[test] fn test_aead_leak() { run_model("aead_leak.vp", "c1"); }
    #[test] fn test_deep_nesting() { run_model("deep_nesting.vp", "c0c0c0e1a1"); }
    #[test] fn test_triple_dh() { run_model("triple_dh.vp", "c0c0a0e1"); }
    #[test] fn test_key_ratchet() { run_model("key_ratchet.vp", "c0c0c0a1a1a0"); }
    #[test] fn test_four_party() { run_model("four_party.vp", "c1a0a1a1"); }
    #[test] fn test_phase_forward_secrecy() { run_model("phase_forward_secrecy.vp", "c0a0e1"); }
    #[test] fn test_shamir_reconstruction() { run_model("shamir_reconstruction.vp", "c1c1e1"); }
    #[test] fn test_blind_signature() { run_model("blind_signature.vp", "c0c0a1"); }
    #[test] fn test_concat_bomb() { run_model("concat_bomb.vp", "c0c0c0c0c0a0"); }
    #[test] fn test_concat_bomb_leak() { run_model("concat_bomb_leak.vp", "c1c1c1c1c1a1"); }
    #[test] fn test_concat_bomb_unguarded() { run_model("concat_bomb_unguarded.vp", "c0c0c0c0c0a1"); }
    #[test] fn test_concat_bomb_equiv() { run_model("concat_bomb_equiv.vp", "e1e1e1e1e1f0"); }
    #[test] fn test_passive_dh_chain() { run_model("passive_dh_chain.vp", "c0c0c0e0"); }
    #[test] fn test_double_ratchet() { run_model("double_ratchet.vp", "c0c0a0a0e1e1"); }
    #[test] fn test_many_principals() { run_model("many_principals.vp", "c1a0a0a0a0a0f0"); }
    #[test] fn test_psk_with_dh() { run_model("psk_with_dh.vp", "c0c0a1a1"); }
}
