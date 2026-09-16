# CLAUDE.md

Repository guidance for Claude Code.

## What this is

Verifpal checks `.vp` cryptographic-protocol models for confidentiality, authentication, freshness, unlinkability and equivalence under passive/active attackers. Default: **two concurrent sessions per principal** (`--sessions k`); a hold means no attack found within that bound. One Rust crate (`verifpal` 1.4.2, edition 2024, Rust 1.98, GPL-3.0-only) builds the CLI and separate WASM library for website/VS Code. [User Manual](https://verifpal.com/docs/): language reference; `README.md`: overview; [*From Toy to Instrument: Seven Years of Verifpal*](https://eprint.iacr.org/2026/1654): authoritative where this guide disagrees.

**Sound but incomplete:** `src/solve/` only proposes substitutions; `validate.rs` concretely re-executes them before recording results. Solver bugs may miss attacks but cannot invent them (Theorem 4; `query.rs::tcb_tests`).

## The one rule about primitives

**Declare primitives only in `src/primitive/spec.rs`.** `PrimitiveSpec` / `PrimitiveCoreSpec` own names, arities, outputs, argument names/restrictions/errors, decomposition/recomposition/rewrite/rebuild/reuse, bypass keys, commutativity, key/identifying roles, capabilities/reveals, tuple/projection/equality/divergence roles, help and editor docs. The engine interprets fields.

`PRIM_*` exports are test-only; `the_engine_names_no_primitive_outside_its_spec` rejects ids and quoted primitive names in non-test engine code. Parser reservations and editor docs come from the registry. If behavior seems to require `p.id == …` or a name check, **add a spec field and generic interpreter**. `ReuseRule` is the example. Core roles work identically: `CONCAT.reveals_args`, `SPLIT.projection_of`, `ASSERT.equality`; ask the registry which primitive supplies each.

False attacks and missed attacks are the worst possible regressions. These models pin past **false** attacks:

| model | code | what it pins |
| --- | --- | --- |
| `auth_with_signing_false-attack.vp` | `c0a1a0`@1 | `signature` holds while `ciphertext` legitimately fails; a second session makes the signature replayable (`c0a1a1`) |
| `concat_split_replay.vp` | `a0` | a `SPLIT(CONCAT(…))` reducing to the honest value is a replay |
| `wire_projection_replay.vp` | `a0` | projecting a wire value back onto itself is a replay |
| `aead_replay_not_forgery.vp` | `a0c0`@1, `a1c0`@2 | a fully attacker-known ciphertext under an unreachable key is not forgeable |
| `equivalence_halt_scope.vp` | `e0` | halting is not a divergence: a state truncated at a failed check cannot answer over slots it no longer holds |
| `foreign_halt_no_oracle.vp` | `a0`@1, `a1`@2 | only the re-executed principal's *own* failed check truncates; values behind a foreign halt are suppressed. Counterweight `exa.vp` (`c1`), a genuine decryption oracle |
| `equivalence_halt_at_slot.vp` | `e0`@1, `e1`@2 | the *failing* slot is kept, still holding a decryption that did not decrypt; comparing it is the same false attack |
| `examples/transport-layer/piknik.vp` | `c0a0a1a1f0` | a substitution the attacker cannot build is not an attack; the two `a1`s are **replays**, and a trace saying *replaces* is the regression. Reached through `run_model_at` |
| `session_replay_breaks_injectivity.vp` | `a1`@2, `a0`@1 | replaying another session's honestly-signed pair forges nothing, but one send is accepted twice |
| `session_peer_run_matches.vp`, `session_nonce_cross.vp`, `session_sign_oracle_cross.vp` | `a0` at every count | a matching run of the same agent is not an attack. ASSERT, SIGNVERIF, authenticated first flight |
| `kem_secret_does_not_reveal_randomness.vp` | `c0` | `KEM_ENCAP`'s decompose runs on the ciphertext, not at either projection. Counterweight `kem_decap_reveals_randomness.vp` (`c1c1`) |
| `kem_secret_is_not_a_ciphertext.vp` | `c0` | `KEM_DECAP`'s rewrite undoes only the ciphertext projection. Counterweight `kem_real_ciphertext_still_breaks.vp` (`c1`) |
| `incompatible_histories.vp` | `a0` | knowledge derived under one execution of a principal may not be spent against another. `incompatible_histories_mitm.vp` (`c1a1`) unguards `ga` so the halves land on different principals |
| `concat_bomb_equiv.vp` | `e0…f0`@1, `e1…f0`@2 | halting Bob is not a divergence; another session's bundle under the same long-term key is one |
| `precondition_halt_before_send.vp` | `a1a0`@2, `a0a0`@1 | a violation outside a query's precondition is not an attack on that query. `precondition_accepted_key.vp` (`c1c0c0`) is the confidentiality shape |
| `matching_run_routing.vp`, `matching_run_two_inputs.vp`, `matching_run_nested_term.vp` | `a0`@1 | a value the declared sender's own run emits under the attacker's flight is not a forgery. The four `matching_run_*` models at `a1` (forged not emitted, forged unguarded, constructed not emitted, halts before send) are the counterweights |
| `history_closure_incompatible.vp` | `c0c1c1a0a1f0f1e1e1` | the closure-route version of the same rule (`junglegym_hybrid_pq.vp` without its phase-3 `weak`) |
| `history_incompatible_knowledge.vp` | `a0` | the same rule when the revealing message went to a third principal. Counterweight `history_compatible_oracle.vp` (`a1`) |
| `nonce_echo_reflection.vp`, `webauthn_origin_binding.vp` | `e0e1` | a forwarded state answers only queries over values it legitimately holds |
| `halted_use_is_not_acceptance.vp` | `a0` | a recipient that halts is not credited with a use it made on the way to failing |
| `conf_attacker_supplied_value.vp` | `c1c0` | the verdict stands but carries `Subtype::AttackerSuppliedValue`. `conf_forced_key_is_a_real_disclosure.vp` (`c1`, no subtype) is a forced key still carrying Bob's own exponent |
| `closure_halted_send.vp` | `c0c1c1` | a truncated run still holds a slot computed before its checks, so the gate asks whether the *emission* was reached |
| `closure_cyclic_union.vp` | `c1c1c0` | two installs whose union defines each slot in terms of the other: a replay that cannot execute is refused, not admitted because no state came back |
| `aead_nonce_reuse_other_nonce_holds.vp` | `c1c1c0` | a reused nonce gives up the messages under that nonce and nothing else |
| `aead_nonce_reuse_same_message_twice.vp` | `c0` | one message sealed twice under one key, nonce and AD is one term under two names |
| `aead_nonce_needed_to_decrypt.vp` | `c0` | the nonce is a decryption input. Counterweight `aead_nonce_leaked_decrypts.vp` (`c1`) |
| `threshold_sign_leaked_share_holds.vp`, `threshold_sign_three_of_five.vp` | `c0c0a0` | a share is not the key; a leaked share plus partials over the coordinator's own message is short of the threshold. `threshold_sign_three_of_five_two_oracles_hold.vp` is two oracles and no share |
| `causal_late_leak.vp` | `a0`@1, `a1`@2 | a key disclosed only downstream of the check it would forge is not held in time — neither the install nor the guard bypass may spend it. `signal_small_leaks.vp` is `c0a1`@1 for the same reason |
| `unlink_forced_equality.vp`, `unlink_forced_origin.vp` | `u0` | a link the attacker manufactured is not a link. Counterweight `unlink_active_links.vp` (`u1`), a substitution that *reveals* a link the honest tokens carry |
| `scenario_corrupt_by_wire.vp`, `scenario_corrupt_by_derivation.vp` | `c0` | a peer whose private key travels bare, or is computable from public constants, is as corrupt as one whose key is leaked |
| `aead_failed_decryption_hides_ciphertext.vp` | `c0` | a decryption yields the plaintext or nothing, so `AEAD_DEC` and `PKE_DEC` declare no `decompose`; `DEC` keeps its own, a symmetric permutation inverting under any key |
| `gate_taint_by_provenance.vp` | `a1` | trace-only: a check is narrated as attacker-controlled only when a slot in its own dependency cone was installed |
| `history_own_later_emission.vp` | `a0` at every count | a value one execution of a run hands the attacker may not be spent against another execution of the same run. Counterweight `history_own_early_emission.vp` (`a1`); `scuttlebutt.vp`'s `secretBox1Bob` was the same shape |
| `bypass_needs_the_signed_message_public.vp` | `a0` | a defeated check that passes with its honest input restored accepts nothing the sender did not already send. Counterweight `bypass_needs_the_signed_message_wire.vp` (`a1`) |
| `phase_second_delivery_later_leak.vp` | `a0a0`@1 | a delivery is judged against its own phase, so a key leaked after both deliveries forges neither |
| `phase_relay_guarded_delivery.vp` | `a1a0`@2 | a guarded relay is judged by the open leg it stands for |
| `relay_guarded_replay_is_not_a_duplicate.vp` | `a0a0` | a relay handed another session's flight forwards it itself, once. Counterweight `relay_guarded_replay_open_hop.vp` (`a1a0`@2) |
| `equivalence_starved_by_foreign_halt.vp` | `e0`@1 | a value built from what a halted sender never handed on was never computed |
| `unlink_forced_origin_derived.vp` | `u0` | a common origin one derivation below the wire is still manufactured |
| `unlink_public_identifier.vp` | `u0u0` | a check succeeding under a key every principal holds identifies nobody |
| `unlink_sealed_carrier_not_observed.vp` | `u0` | a value sealed under a key nobody gave up was carried past the attacker, not shown to it. `unlink_sealed_carrier_opened.vp` (`u1`) leaks the wrapping key |
| `cap_forgeable_is_not_a_reuse_pair.vp` | `c0a1` | a ciphertext minted under `forgeable` repeats no keystream, so it is not the second member of a reuse pair. `cap_forgeable_guard_never_adds_an_attack.vp` (`c0`) is the same claim read off a guard |
| `history_phase_archive.vp`, `history_phase_archive_third_party.vp` | `a0` at every count | `incompatible_histories.vp` and `history_incompatible_knowledge.vp` with a phase boundary: a slot delivered in an earlier phase is proven derivable against that phase's archive, and the archive goes through the same history-coherence restriction as current knowledge |
| `scenario_corrupt_by_leaked_derived_key.vp`, `scenario_corrupt_by_derived_key_on_wire.vp` | `c0` | a private key that is an assignment output (`HASH(mk)` under `PUBKEY`) is a compromise seed when leaked or sent bare, exactly as a declared secret is |
| `unlink_shares_recomposed_secret.vp` | `c1u0` | a secret assembled out of the two queried values is not their common origin; a witness must stay derivable with either value and everything derived through it withheld. `junglegym_threshold_ring.vp`'s share pair stays `u1` because a third share is held |

And these pin **missed** attacks, the other worst regression:

| model | code | what it pins |
| --- | --- | --- |
| `forward_transitive_relay.vp` | `f1` | a guard says the attacker did not alter a message in transit, not that the sender held an honest value. `forward_relay_all_guarded.vp` (`f0`) guards the first leg too |
| `forward_computed_under_guard.vp` | `f1` | only the sender's own re-executed run emitting a tag over an attacker-supplied input reaches it. Counterweights `forward_computed_guarded_input.vp`, `forward_halted_sender_emits_nothing.vp` (`f0`), `forward_emission_is_not_a_forgery.vp` (`a0f1`) |
| `pitoy_depth.vp` | `c1`@2, `c0`@1 | Arapinis and Duflot's Pi_Toy: a message nested two layers deeper than the protocol builds. Needs the per-slot term bound and `aligned_held_free` |
| `injective_recipient_nonce_unchecked.vp`, `injective_routed_emission_twice.vp` | `a0`@1, `a1`@2 | duplicates the recipient could have told apart, reported with `Subtype::DuplicateAcceptance` |
| `closure_two_recipients.vp` | `c1` | one constant delivered to two recipients with different values in one execution |
| `matching_run_leaked_generated_key.vp` | `a1` | a leaked *generated* key is the attacker's own forging capability |
| `blind_signature_forgeable_with_factor.vp` | `c1` | unblinding is public: `UNBLIND` is the one rewrite whose reduct is neither an argument nor `decompose`-reachable. `blind_signature_safe_without_factor.vp` (`c0`) withholds the factor |
| `aead_nonce_reuse_forgery.vp` | `a1` | two ciphertexts under one key and nonce make the pair forgeable, and the agreement exemption cannot excuse it. Counterweight `aead_nonce_distinct_forgery_holds.vp` (`a0`@1) |
| `threshold_sign_leaked_share_and_oracle.vp`, `threshold_sign_three_of_five_two_oracles.vp` | `c0c0a1` | a leaked share plus signing oracles reaching the threshold is a forgery. `threshold_sign_rogue_coordinator.vp` is the unauthenticated-channel case with no share |
| `threshold_group_key_from_shares.vp` | `c1c0` | the group key interpolates from enough verification shares |
| `threshold_sign_nonce_reuse.vp` | `c0c1` | a nonce reused under one share gives the share up |
| `threshold_sign_leaked_nonce.vp` | `c0c1a0` | a disclosed nonce and one partial reveal the signing share; `threshold_sign.vp` keeps the nonce secret |
| `threshold_sign_forgeable_is_not_a_reuse.vp` | `c1c0` | its public nonce reveals the share from the honest partial, independently of reuse or the forgeable assumption |
| `aead_nonce_reuse_partner_unreached.vp` | `c1c1` | a reuse pair one of whose reads sits in a run the replay never executes is compared against that reader's `execution_base`, not refused |
| `blind_signature_attacker_unblinds.vp` | `c1` | the attacker can assemble `UNBLIND` around a held blind signature from values it holds |
| `equivalence_unused_received.vp` | `e1` | an `equivalence?` compares slots as held, so a constant it names is controllable even where the recipient never uses it in a primitive |
| `relay_guard_transitive.vp` | `a1a1f1` | a guard on a relayed value is upstream of the substitution at every later hop |
| `phase_second_delivery.vp` | `a0a1`@1 | the second delivery of one constant is substitutable in its own phase |
| `unlink_recognized_nested_message.vp` | `u1` | the recognized-secret witness follows a pinned argument into its own leaves, so wrapping a shared secret no longer hides it |
| `forged_bundle_from_held_terms.vp` | `c1` | a bundle the attacker assembles from two held values, where the split over it is the controlled slot itself |
| `scenario_binding_is_not_a_forgery.vp` | `a0` | a scenario binding separates two clones only for the values that depend on it |
| `scenario_corrupt_needs_every_ingredient.vp` | `c1` | a key derived from two secrets is not compromised when one half leaks, so the peer holding it stays honest |
| `scenario_corrupt_by_certified_key.vp` | `c0` | a certificate the attacker cannot build still names a peer it controls, so that run is corrupt and its failing check is not a model error |
| `unlink_hash_chain_direct.vp` | `u1` | a queried value that appears among the other queried value's origins is a witness in its own right; `unlink_chain_forward.vp` (`u0`) is the counterweight where neither token recomputes from the other |
| `unlink_signature_in_tuple.vp` | `u1u1` | the identifying-check and recognized-secret witnesses are also tried over every pair of components a tuple exposes |
| `closure_route_withheld_by_halt.vp` | `c1` | a derivation is refused only when no execution produces it. Swapping the KEM key halts Alice at a tag check after she has sent, so her ephemeral is withheld and the route recorded through it dies; Bob reaches his leak and the same Diffie-Hellman leg reopens through his key. Needs the `combination_coheres` fallback, and `gbx` guarded so that key is the only way through |
| `cap_forgeable_still_binds_its_key.vp` | `a1` | a capability exemption widens the solver's option set and never replaces it: the exempt position is solved *and* allowed through unsolved, or annotating a relay's AEAD loses the MitM the unannotated model reports. Found by `weakening_a_primitive_never_loses_an_attack` over `examples/messaging/simplex_xftp.vp` |

`cap_forgeable_other_message.vp` (`c1` at both counts) licenses other messages under the annotated key; `cap_forgeable_other_key_holds.vp` (`c0`) preserves the key boundary. Same-key consequences: `cap_forgeable_cert_chain.vp` = `c1c1a1a1`, `ringsign_forgeable_cap.vp` = `a1a1` ([Definition 20](https://eprint.iacr.org/2026/1654.pdf)).

`solver_constructible_reduct.vp` (`c1` at both counts): encrypting nil twice to Bob makes his decryptions reduce to nil and his wrapping key public. Require the **reduct** derivable, not the unreduced decryption's private key. `solver_constructible_reduct_guarded.vp` (`c0`) guards input 1. This also finds `junglegym_threshold_ring.vp`'s receipt forgery: `c1c0c0a1a1a1u0u1u1f0f1e1e1` at both counts.

Emit replayable-first-flight notices **only in `emit_query_result`**, after acceptance/preconditions, never while classifying siblings. `duplicate_notices_belong_only_to_recorded_acceptances` covers refusal (`threshold_sign.vp`), real replay and repeated reporting. No `origin_only` set is needed: the result-write gate emits once.

`solver_rewrite_matching.vp` / `solver_weak_oracle.vp` are `c1` at both counts: respectively, retain the second key alignment satisfying the nonce; steer a hash oracle to the exact weak term to recover its MAC argument. `solver_rewrite_matching_guarded.vp` / `solver_weak_oracle_strong.vp` hold.

**Known does not imply forgeable** (`aead_replay_not_forgery.vp`, `piknik.vp`). `run_model` prefixes `examples/test/`.

## Commands

```sh
cargo build --release                  # build (also: make build)
cargo clippy --all-targets -- -D warnings   # exactly what CI runs
make lint                              # the above, plus cargo fmt --check and the wasm clippy
cargo test --release                   # 1181 tests (unit + model), ~4m once built (also: make test)
cargo test --release -- --ignored      # the exhaustive metamorphic sweeps (also: make test-exhaustive)
make test-tex                          # compile every generated LaTeX report with tectonic
cargo test --release test_ok           # a single end-to-end model test
cargo test --release model_tests::     # only the end-to-end model tests
cargo fmt                              # rustfmt: hard tabs, Unix newlines (rustfmt.toml)
cargo check --lib --no-default-features --features wasm   # fast check that the wasm build isn't broken
make wasm                              # wasm-pack build + copy into ../verifpal-website/res/wasm/
make dist-assets                       # completions + man pages into target/dist-assets (goreleaser before hook)
make release-dry                       # rehearse a release without touching git or the network
```

CI runs clippy, `cargo test --release` and the exhaustive sweeps on Ubuntu and macOS plus a wasm clippy job; one warning fails the build. **CI only runs when the commit title contains `[ci]`** (or on manual dispatch). Formatting is not gated in CI, so keep the tree formatted with `make lint`.

```sh
cargo run --release -- verify examples/simple.vp             # full analysis
cargo run --release -- verify path/to/model.vp --result-code # appends the compact result code
cargo run --release -- verify path/to/model.vp --format html > report.html  # self-contained report
cargo run --release -- verify path/to/model.vp --format tex > report.tex    # LaTeX; tectonic report.tex
cargo run --release -- verify path/to/model.vp --sessions 1  # single-session; default is 2 per principal
cargo run --release -- verify path/to/model.vp --saturate    # raise k until the verdicts stop moving
cargo run --release -- verify path/to/model.vp --auto-queries # replace the queries block with a generated one
cargo run --release -- pretty path/to/model.vp               # canonical formatter, to stdout
VERIFPAL_SOLVE_DEBUG=1 cargo run --release -- verify m.vp    # log every solver proposal and pass to stderr
VERIFPAL_CHECK_PROPOSALS=1 cargo run --release -- verify m.vp # recompute every recalled proposal list and assert equality
```

`verify` takes several models at once. `--result-code` only suppresses the banner; the code is the **last** line (`… | tail -1`), and is refused beside `--format json|html|tex`. `--fail-on-attack` makes a found attack a nonzero exit; `-q`/`-v` and `--color` are the remaining flags. Other subcommands: `about`, `diagram <model>` (mermaid), `lsp`, `completion <shell>`, `man` (hidden). `internal-json` is **gone**, replaced by `verify --format json`. The json, html, tex and LSP outputs all come from `src/report.rs`; `verifpal-vscode` and `verifpal-nvim` are thin clients of it.

Errors carry a `Span` into the model source and render as a Rust-style diagnostic; `or_span` keeps the narrower span, and `.located(file_name, &model.source)` makes plain `Display` show the position. `VERIFPAL_SOLVE_DEBUG` is the first thing to reach for when an active-attacker result is wrong: it prints each proposal as `[solve] <Principal> ran=<bool> [slot=value …]`, including the ones `validate` rejected.

## Crate layout and features

- Lib `verifpal` (`cdylib`, `rlib`), bin `src/main.rs` (default `cli` feature). CLI stdout uses `out!`/`outp!`, ignoring closed pipes.
- **Engine modules are `pub(crate)`**; only `lib.rs` re-exports are public. Keep `#![warn(unreachable_pub)]` / `#![forbid(unsafe_code)]`.
- No `tests/` directory: integration targets collide with the `cdylib` artifact; use `src/model_tests.rs`.
- Features: default `cli` (clap, colored, ureq, `lsp`), `lsp`, `wasm` (`wasm_verify`/`wasm_pretty` return JSON; `info::wasm_messages_*` buffers output).
- `parallel.rs` is the sole rayon seam, with a sequential WASM twin: **change both and run the WASM check**. `map_ordered` preserves order; `VERIFPAL_THREADS=n` sets pool size, `1` is sequential (`an_analysis_is_identical_under_one_thread_and_many`). **Workers only evaluate**: no `learn`, `attacker_put_with`, `attacker_note_reuse`, `emit_query_result`, `defer_replays`, `note_depth_cut`, `note_replication_rejection`, `analysis_count_increment`, `ctx.replayed` or `info` calls. Caller-thread learning preserves primary routes/traces. `VerifyContext` is interior-mutable and `Sync` (`everything_a_worker_borrows_is_sync`).
- `REWRITE_CACHE` / `CONES` use `context::Generational`, clearing on first access in a different generation to prevent cross-model id contamination. **Internal parallelism only with one live analysis**: `live_generations() > 1` makes `map_ordered` sequential. `NEEDS` / `ANY_TAINT` retain their source `Arc`; `DeductionMemo::scoped` installs/restores `MEMO`.
- **Always use `--release`**: opt-level 3, fat LTO, one codegen unit, abort panics, stripped symbols.

## The Verifpal language (enough to write test models)

```verifpal
attacker[active]                    // or passive

principal Alice[
    knows public c0                 // also: private
    generates a                     // fresh value
    ga = PUBKEY(a)                  // public key from a private value
    k  = DH_KEX(gb, a)              // DH_KEX(PUBKEY(b), a) == DH_KEX(PUBKEY(a), b)
    generates n                     // an AEAD nonce: reusing one under a key is what the engine watches for
    e = AEAD_ENC(k, n, m, ad)
    x, y = SPLIT(CONCAT(m, n))      // multi-output primitives bind several constants
    s1, s2, s3 = THRESHOLD_SPLIT[2](k)  // t-of-n sharing; the bracket is t, the outputs are n
    p = THRESHOLD_SIGN(s1, n, cl, m)    // a FROST partial; THRESHOLD_JOIN(p, q) is SIGN(k, m)
    _ = HASH(m)                     // `_` is an anonymous constant (becomes unnamed_N)
    leaks something                 // hands value to attacker
]

Alice -> Bob: [ga], n, e            // [x] = guarded: attacker cannot replace it
                                    // `→` (U+2192) is accepted in place of `->`

phase[1]                            // phases must increment by exactly 1

principal Bob[
    d = AEAD_DEC(k, n, e, ad)?      // '?' = checked: failure halts this principal
]

scenarios[                          // optional, and it must come before `queries`
    Alice[gpeer = gb]               // run 1: Alice's peer is Bob
    Alice[gpeer = gm]               // run 2: Alice's peer is Mallory
]

queries[
    confidentiality? m
    authentication? Alice -> Bob: e
    freshness? x
    unlinkability? a, b             // ≥2 distinct constants
    equivalence? k1, k2             // ≥2 distinct constants
    // queries take an optional option block, e.g.:
    // confidentiality? k[ precondition[ Client -> Server: req ] ]
    // which restricts the query to executions in which that message is sent
]
```

Parser / `sanity.rs` constraints:

- Required `queries` is last; at most one `scenarios[…]`, immediately before it.
- `MAX_PRINCIPALS = 128`; case-insensitive names (principals title-cased, other identifiers lower-cased). Model filenames: `.vp`, ≤64 characters.
- Registry `argument_restrictions` enforce: no public key inside `PUBKEY` or as DH second argument; no nested DH; no DH/KEM/public values where KEM expects a key. Registry also determines arity, outputs and checkability.
- Constants cannot shadow `parser.rs::RESERVED`, primitive names, or `attacker*` / `unnamed*`. `queries` / `scenarios` are keywords.
- No repeated assignment/generation, conflicting `knows`, sending unknown values or receiving already-known ones. Leakers must know values; `_` is assignment-output-only. `nil` may appear in equivalence, not as confidentiality/freshness subject.
- Authentication requires sender knowledge and recipient receipt/use inside a primitive. Preconditions must name a sent message. `sanity_capabilities` rejects unsupported assumptions or nonexistent onset phases.

All 25 primitives (arity → outputs): ASSERT(2), CONCAT(2–5), SPLIT(1→1–5), HASH(1–5), HKDF(3→1–5), AEAD_ENC/AEAD_DEC(4), ENC/DEC(2), MAC(2), PUBKEY(1), DH_KEX(2), SIGN(2), SIGNVERIF(3), PKE_ENC/PKE_DEC(2), THRESHOLD_SPLIT(1→2–16), THRESHOLD_JOIN(2–16), THRESHOLD_SIGN(4), RINGSIGN(4), RINGSIGNVERIF(5), BLIND(2), UNBLIND(3), KEM_ENCAP(2→2), KEM_DECAP(2). `RENAMED` diagnoses obsolete `SHAMIR_SPLIT`/`SHAMIR_JOIN` names. Only `definition_check` primitives accept `?`: ASSERT, SPLIT, AEAD_DEC, SIGNVERIF, RINGSIGNVERIF, KEM_DECAP. Core ASSERT/CONCAT/SPLIT live in `CORE_SPECS`, reduce in Rust and trigger theory bailouts via `primitive_is_core`; others are data.

**Capabilities:** `PUBKEY[weak](a)`, `SIGN[forgeable](sk, m)`, `AEAD_ENC[weak, forgeable from phase 2](k, n, m, ad)`. Onset binds to the preceding capability, persists from N onward, defaults to phase 0.

- `weak` loses confidentiality (`weak_reveals` / `weak_reveals_output`): HASH reveals all arguments; AEAD_ENC/ENC/PKE_ENC plaintext; KEM_ENCAP shared secret; PUBKEY private key (`can_reconstruct_primitive` supplies the DH cascade; `cap_weak_pubkey_dh.vp`).
- `forgeable` loses authenticity (`forgeable_secret`): SIGN, MAC, RINGSIGN, AEAD_ENC. Distinct from weak (`cap_forgeable_aead.vp`).
- `malleable` reshapes ciphertext under an unlearned key: only ENC, `malleable_vary` position 1. Requires **both** `solve_by_malleability` and derivability's `malleable_positions`. Pins: `cap_malleable_enc.vp` / `cap_malleable_absent.vp` (`a1` / `a0`), `cap_err_aead_malleable.vp`, `cap_err_malleable_unsupported.vp`.

`weak`, `forgeable`, `malleable`, `from` are **contextual**, absent from `RESERVED`, usable as constant names.

**Threshold:** required only where spec declares `threshold`, e.g. `THRESHOLD_SPLIT[3](k)` or `[3, weak]`. Errors: `err_threshold_missing.vp`, `err_threshold_on_hash.vp`, `err_threshold_twice.vp`, `err_threshold_one.vp`, `err_threshold_above_shares.vp`. `Primitive.threshold` participates in `primitive_hash`, `equivalent_primitives`, `structurally_identical_primitive`; shares at different thresholds never combine (`threshold_thresholds_are_distinct.vp`). Output count n belongs to the assignment, not term; `MAX_SHARES = 16`.

AST comments (`//`, `/* */`) round-trip through `pretty`; bracket/argument comments lead the enclosing statement. `MAX_NESTING = 64`; deeper primitives produce parse errors.

## Architecture

### Pipeline

```
parse_file (parser.rs)              hand-written recursive-descent, comment-preserving AST
  → expand_scenarios (scenario.rs)  one model copy per declared peer scenario
  → expand_sessions (sessions.rs)   k copies of that, one per concurrent session
  → sanity (sanity.rs)              model validation; drives construct.rs
      → construct_protocol_trace    "km": ProtocolTrace — global immutable protocol description
      → construct_principal_states  one PrincipalState per principal
  → VerifyContext::new (context.rs) shared mutable state for the whole run
  → verify_passive (verify.rs) | verify_active (solve/mod.rs)      per phase
  → verify_end                      prints results, returns the results code
```

`verify::analyze(&Model)` is the **one** place that sequence exists; it is `analyze_sessions(m, DEFAULT_SESSIONS)`, and the wasm entry points and the LSP call it too — **do not give one entry point its own default.** Throughout, `km` is the `ProtocolTrace` and `ps` a `PrincipalState`.

### Parallel sessions (sessions.rs)

`expand_sessions` clones principal and message blocks `k` times **before** `sanity`: the result is a model the user could write, inheriting engine soundness. Fresh and assigned constants become `c#s` across the scenario/session grid (`MAX_COPIES = 30`, `s*k <= 31`); `knows` constants stay shared. Original queries cover session 1; per-session `variants` share their `query_index`.

- **Authentication is injective.** Accepting a sibling session's honest wire value twice is an attack without a forgery. `session_sibling_replay` narrates it as "replays". `copy_siblings` spans both expansion axes; `copy_sibling_replay` labels cross-scenario replays **after** `emitted_by_matching_run` declines, so labels cannot move verdicts (`scenario_replay_is_a_replay.vp`). `sibling_flight_substitutions` remains session-only.
- **Clones are runs, not agents.** `install` stamps `ATTACKER_ID` for any deviation from the pristine expectation. `agreement.rs::emitted_by_matching_run` distinguishes rerouting from authoring: find the same base constant emitted by an interchangeable sender run to this recipient's agent, then re-execute that run with the recipient's flight. It uses `attacker_can_derive`, `TermBound` and `Controllable`; the pristine-sibling replay is tried first. `Emission::emits` compares full installs and target on memo hits: a wrong `false` causes a false attack.
- `interchangeable_for` checks **per slot** whether the resolved value depends on `scenario_bound`. Comparing whole binding sets loses `scenario_binding_is_not_a_forgery.vp`; canonicalising by base name excuses Lowe's attack. Match recipients by agent.
- `forgeable_without_sender` transitively removes reads of **assignment outputs** from sender runs; a still-`derivable` value is a forgery (`matching_run_forged_unguarded.vp`). Keep generated keys (`matching_run_leaked_generated_key.vp`). Then try three sender re-executions: **mirror** (`delivered_to` this recipient), **record** (tainted diffs where `Obtained` at the sender's own slot), **routing** (sibling flight).
- Never suppress duplicates. Use `Subtype::DuplicateAcceptance` if `recipient_contributed`, otherwise `Subtype::ReplayableFirstFlight`. Suppressing the latter loses the 0-RTT replay in `tls13-0rtt.vp` (RFC 9846 §2.3).
- `query_authentication_get_pass_indices` tests `original ≡ value` before siblings, excluding values without session freshness. `k = 1` skips expansion and cannot report cross-session replay; pin non-forgery claims there (`a_false_attack_pin_survives_at_one_session`).
- At `k > 1`, `prefer_replication` / `replication_only` / `replication_rejected` order two passes: initially refuse `replays_own_freshness` (self-produced terms carrying own freshness), then lift it if anything was refused and queries remain. This only orders proposals. Re-measure both corpora before changing the default; 55 analysing models differed at one and two sessions when measured.

### Causal availability (reexec.rs)

`attacker_phase_update` publishes reached wire values before principals run, allowing concurrent routing independent of block order. That knowledge still must be available **before the attacked receive/check** (`atemporal_forward_value.vp`). `available_before_receive` finds the earliest delivery; `held_at` restricts knowledge there; `influenced_from` computes blocked trace slots as a fixed point over sends. Receives and guard checks share this filter.

- Block by **disclosure**, not declaration (`causal_late_leak.vp`); except `nil` and public constants.
- Judge bypasses at the check's own `declared_at`, not installed-slot order: message 3 may spend a message-2 disclosure (`noise_xx_mutual.vp`). Memoized bypass decisions retain position and are rechecked **in both directions**.
- `restrict_known` follows primary derivations through `reachable_knowledge`, retaining unblocked reads and ingredient-free constructions, never comparing pristine trace values (`later_value_fed_back.vp`). `validate.rs` independently re-proves `derivable` against the restriction.
- **Each delivery is substitutable in its own phase.** `SlotMeta::delivery_phases` records the recipient's phase; guarded relays use the upstream open leg's phase (`phase_relay_guarded_delivery.vp`). `install` stamps it; `mutation_reaches` hides mutations from earlier recipients. Keep `compute_visibility`, `state_mentions` and `symbolic::reaches` aligned (`phase_second_delivery.vp`, `phase_second_delivery_later_leak.vp`).
- Cache by position and `KnowledgeKey`, never knowledge size alone. Clones have no cross-copy message edges. `probe_with` applies the same ordering to each install. Pins include `scuttlebutt.vp`'s `secretBox1Bob` and the one-session confidentiality results in `signal_small_leaks.vp`, `signal_small_leaks_bob.vp`, `signal_small_nophase.vp`.

### History coherence (reexec.rs::Coherence)

Global monotone knowledge must not spend one execution's disclosures against another execution of the same principal. `Coherence::of(km, ps)` records each received slot's honest creator value; `compatible` filters primary `Obtained`/`Leaked` derivations that disagree. `VerifyContext::coherence` caches per principal and knowledge `Saturation`, making pointer-keyed memos exact.

- `validate.rs` uses restricted knowledge for **both derivability and re-execution**, including `try_guard_bypass`. `attacker_can_derive` also restricts earlier-phase archives through `Coherence::compatible` (`history_phase_archive.vp`, `history_phase_archive_third_party.vp`).
- Follow **derivations**, never ambient `MutationRecord` diffs, even tainted-only: treating snapshots as prerequisites loses `kem_direction_reflection.vp` and `forged_statement_rebuilt.vp`.
- `execution_agrees` handles disclosures sent to third principals: replay each supplier under diffs observed in its own state (`history_incompatible_knowledge.vp`, `history_compatible_oracle.vp`).
- Restrict only slots **received from another principal**, read in the **creator's** run or another execution of **this principal**. Skip where the proposal installs an **attacker-authored** value, but not an honest reinstall (`incompatible_histories.vp`, `incompatible_histories_mitm.vp`).
- Separately, `validate.rs::spends_another_execution` refuses installs whose cone-filtered `deduction::needs_of` require a different value at this principal's **receive** slot. Recurse into unheld terms' arguments; do not reject own output reads needed for cross-session routing (`history_own_later_emission.vp` against `history_own_early_emission.vp`).

### Execution coherence in the closure (deduction.rs::combination_coheres)

`learn` also checks combinations completed entirely within global knowledge. Collect ingredients' primary `Obtained`/`Leaked` reads and tainted substitutions; refuse conflicting values at one principal/slot. Empty or uniform unions pass directly. Otherwise `replay_diffs` replays the union and requires differently recorded reads to be **reached**: slot held, no foreign halt, emission not `withheld_by_own_halt`. Refuse unexecutable unions (`closure_cyclic_union.vp`).

**An unreached read refuses the recorded route, not the value.** Knowledge is deduped by equivalence and each value keeps one derivation, so the route the closure happened to record may read something only a halted run discloses while the same value is reachable another way: a Diffie--Hellman secret recorded through a leaked ephemeral is the same term as one computable from the peer's leaked long-term key. Refusing there loses real attacks (`closure_route_withheld_by_halt.vp`, and the PQXDH handshake with its KEM signature unchecked). So when some read is not reached, `combination_coheres` restricts knowledge to what the replay does reach (`reachable_knowledge` under the same predicate, then `retaining`) and asks whether the derivation still goes through against that: `can_decompose` for a `Decomposed`, every ingredient `obtainable` otherwise. The fallback is strictly narrower than the knowledge the rule ran against, so it admits nothing the replayed execution cannot derive.

- **Primary routes are order-dependent.** `closure_cyclic_union.vp` is `c1c1c0` at two sessions, `c1c1c1` with `z` first. Alternate-route retries reintroduced `history_closure_incompatible.vp` even with replay equality; do not revive them. Metamorphic `rotate` runs at one session, where orders agree.
- `SlotDiff` retains the observed **state**; needs are `(principal, slot, value)`, allowing one execution to deliver different values at one slot to Bob and Carol (`closure_two_recipients.vp`). Key read prerequisites to the slot's **creator**. Union cone-filtered needs with the current state's ambient, never whole records of all visited terms.
- `collect_reads` follows in-place `obtainable` reconstruction via `ReconstructResult::from` / `DecomposeResult::used`. `read_preconditions` follows installed values in a read's cone into their reads: provenance stops at installs. Wire/leak cones extend to `emitted_at`, not declaration (`closure_halted_send.vp`).
- Different per-recipient values need `witness.rs::Addressed`, the fourth `LADDER` rung, offered only after all three shared-install rungs fail.

### Forward execution (reexec.rs::execute_forward)

`execute_forward` runs a principal, delivers its changed (`attacker_authored`) emissions as produced, then runs recipients to a fixed point bounded by principal count. This lets the minimizer start at the origin of a downstream attack.

- Forwarding is justified by the send, not attacker derivability. `forwarded_installs` checks the declared leg, phase and reached send (`a_forwarded_value_is_only_ever_what_its_sender_sent`).
- `install_forwarded` sets **only** `attacker_tainted`; `sender`, `creator`, `original` remain honest (`forward_emission_is_not_a_forgery.vp`). Taint makes downstream learning depend on the input; omitting it caused false attacks in `piknik.vp`, `ringsign.vp`, `mutual_auth_both_directions.vp`. Pure forwarders are controllable.
- `PrincipalState::forwarded` gates `query_start` through `answers_for`: forwarded states answer only over legitimately held constants (`precondition_foreign_halt.vp`). Applying a `known` gate to every state loses `concat_bomb_equiv.vp`.

### Peer scenarios (scenario.rs)

`scenarios[…]` expands **before sessions**, expressing counterparty confusion (Lowe/Denning-Sacco). With `p` principals, `s` entries and `k` sessions there are `p*s*k` principals: entries are whole-model configurations, **not a cross product**. Each entry rebinds one principal, drops its bound `knows` declaration, substitutes throughout that principal, then freshens (`gm@2`). `sanity_scenarios` rejects undeclared principals/values, targets not `knows`n, duplicate targets and wire targets. Identity bindings are no-ops; `peer_binding_key` and `scenario_corrupt_from` skip them (`scenario_identity_binding_keeps_the_error.vp`).

**Inferred corruption asks two different questions:**

- `compromised_constants`: what is computable? Seed secrets leaked or sent bare at the disclosure phase: `generates`, `knows private`, and arguments of key-derivation primitives, including assigned private keys (`scenario_corrupt_by_leaked_derived_key.vp`). Close through `computable_from` only when **every** ingredient is `nil`, public or compromised; date an assignment at its latest ingredient (`scenario_corrupt_needs_every_ingredient.vp`).
- `scenario_corrupt_from`: does a binding identify a controlled peer? The bound value may be compromised **or mention** a compromised value in its assignment. A CA-signed certificate can identify a corrupt peer without being forgeable (`scenario_corrupt_by_certified_key.vp`); confusing these questions makes `tls13.vp`'s intended Mallory hostname failure a model error.

`is_honest` governs honest-run checks: `generate_trace` partitions failed checks by slot **creator**, raising `sanity_fail_on_failed_checked_primitive_rewrite` only for honest creators; others still halt through `halt_at_failed_checks`. `claims_apply_to` governs queries: `query_start` skips corrupt runs. Both verifiers rerun `verify_standard_run` at each phase end when relativisation applies and queries remain, so knowledge found in a corrupt run can break an honest run's confidentiality. For `Some(empty)`, only the honest-run check stays relaxed; without scenarios, `honest = None` and both predicates return true.

- `honest_run_halts` finds each creator's earliest failed check; `attacker_phase_update` withholds wire/leaked slots at or beyond it. **Also** let `attacker_absorb_disclosed` republish exactly what a successful replay reaches (`spore_ns_pk.vp`'s `m3@2`). Pins: `scenario_post_halt_no_oracle.vp`, `scenario_post_halt_leak_no_oracle.vp` (`c0`) against `scenario_pre_halt_oracle.vp` (`c1`).
- Query `variants` cover honest scenarios only, then sessions. Normalize scenarios **honest-first** (`scenario_order_is_not_a_verdict.vp`, `…_swapped.vp`); compromise is phase-indexed (`scenario_peer_compromised_later.vp`, `…_throughout.vp`).
- Feature acceptance: `spore_ns_pk.vp` (`c1a1a0`, discovered Lowe attack) versus `spore_nsl_pk.vp` (`c0a1a0`). **Do not add scenario-free variants to `examples/`.**

### Verdict envelope

`VerifyResult` carries `Envelope { sessions, truncations }`, printed after PASS (`[search exhausted at 2 sessions]` / `[search truncated: term depth]`) and serialized as `QueryReport.envelope`. Attacks are unqualified by envelopes; FAIL may carry `Subtype::{AttackerSuppliedValue, DuplicateAcceptance, ReplayableFirstFlight}`. `VerifyResult.notes` supplies `Note:` lines; spanless auto-queries set `QueryReport.generated`. Empty notes/generated fields are omitted from JSON. The only truncation, `Truncation::TermDepth`, attaches to queries **unresolved when encountered**; `finalize_envelopes` preserves that scope.

**"Exhausted" means this engine's search space at these parameters, never absence of attacks.** Do not describe results as "proof", "verified", "correct" or "complete".

### `--auto-queries` and `--saturate`

`autoquery.rs::auto_queries` **replaces** queries after `sanity` validates the original model. Generate confidentiality for each fresh/private trace constant, authentication for each delivery used in a recipient primitive, freshness for every sent-and-used constant; skip unlinkability/equivalence (`generated_queries_all_pass_sanity`).

`saturation_sessions` tries `DEFAULT_SESSIONS` through `SATURATE_MAX` (4), stopping at the first repeated result code and returning that count's **analysis**. Starting at one would stop before three-run attacks (`saturation_never_stops_before_it_has_looked_above_the_default`). `attack_disappeared` warns about attacks vanishing at higher counts: an engine bug.

### Core data model (types.rs)

- `Value = Constant | Primitive(Arc)`. Constants are model-interned (`nil` id 1), compared by id. DH is ordinary `PUBKEY`/`DH_KEX`; `PrimitiveSpec::commutativity` drives `equivalence.rs`, `hashing.rs`, `solve/matching.rs`.
- **`a.equivalent(b)` implies equal `hash_value()`**: attacker knowledge first selects a hash bucket. DH exponent hashing is commutative; tests pin this invariant.
- **Terms are DAGs; tree walks can be exponential.** Memoize `vars::apply`, `ground_free_as`, `resolve_trace_value` by input `Arc`, and equivalence/structural comparison by equal pointer pairs (`memoised_pair`). `Primitive::HashCell` caches hashes and solver-variable presence; changing a multi-output `output` clears the hash, retaining the flag. Grounding must preserve unchanged ground subgraphs' `Arc`s across proposals (`grounding_reuses_ground_subgraphs_between_proposals`).
- `value::subterms` visits each primitive pointer once in encounter order. It serves hashing, variable/constraint collection, unlinkability, narration, `admissible`, `collect_slot_references`, `contains_failed_check` and `carries_own_fresh`. `Value::constant_leaves` serves freshness, recipient contribution, scenarios, cones and secrecy; follow aliases with a cycle guard. Public `collect_constants` preserves occurrences. **Never prune by repeated term hash**: equivalent DH terms expose different public-key subterms, and hashes collide. Preserve dependency order and find failed checks behind shared prefixes. Forty-layer tests, `shared_transcript_metadata.vp` (`c0f0`) and `shared_transcript_search.vp` (`c0`) pin this. Rendering can still expand exponentially (`NameTable` produced 215 MB from fourteen layers).
- **`Primitive.capabilities` does not affect term identity** (`primitive_hash`, `equivalent_primitives`, `structurally_identical_primitive`; `cap_noop_annotated.vp` / `hmac_ok.vp`). Read them from the state's `CapabilityIndex`, never a deduped held term. `construct.rs` visits each declared annotated subterm, inserts written/resolved forms; `CapabilityIndex::insert` reduces **arguments**, retaining the call's annotations. Whole-term reduction can erase the call; the annotation-blind rewrite cache cannot collect assumptions. `can_break_weak` / `can_decompose` also reduce reveals. Pins: `cap_weak_on_reduced_argument.vp`, `cap_forgeable_on_reduced_key.vp`, `cap_*_nested_reduction.vp`, `cap_weak_cached_reduction.vp`.
- **Three `SlotValues` must remain distinct:** `original` = honest computation/principal belief; `pre_rewrite` = mutated, unreduced; `value` = mutated, reduced. `should_use_original` / `effective_value` and `compute_visibility` choose perception. `bypassed` stores the defeated guard's accepted key.
- `Provenance`: `creator`, `sender` (`ATTACKER_ID = 0` for injection), `attacker_tainted`, `bypass_injected`. Keep the last two separate: bypass must be reportable without changing taint-based perception.
- Immutable `SlotMeta`: `constant`, `guard`, `known`, `wire`, `mutatable_to` (unguarded recipients), `known_by`, `declared_at`, `sent_at`, `phase`, delivery phases. `halted_at` is the earliest failed checked slot's `declared_at`; re-execution truncates there.
- `AttackerState`: append-only `known`, hash index, parallel `mutation_records` / `derivations`, state-reading `Route` `alternates`, `routes_epoch` (replacement invalidation without growth), and process-unique `chain` for independently built states. **Length-keyed memos also need chain identity**, including `pair_vetted`, `origin_leaves`, `forgeable_without_sender`, `Emission::key`, `ctx.replayed`, `held_at`: minimization creates another chain on the same thread. Retain alternate state reads, not derived routes; filters follow **primary routes only**, because accepting alternates reintroduces three false attacks.
- `MutationRecord` stores necessary slot diffs, principal and phase; `DerivationRecord` explains `Initial`, `Leaked`, `Obtained`, `Decomposed`, `Reconstructed`, `Recomposed`, `Fragment`, `Rewritten`, `Broken`, `Reused`, `ReusedForge`, `Combined`. **Every learned value needs an honest derivation**, or its trace is inexplicable.
- `RewriteCache` uses weak input keys, an unchanged-result case owning no `Arc`, and 1024 recent inputs. Eviction changes recomputation only.
- `NameTable` uses term-hash buckets, insertion order and full equivalence, preserving collisions, aliases, exclusions and preferred names (`name_table_disambiguates_collisions_and_preserves_alias_order`).

DAG-aware secrecy/usage walks, ground-subgraph reuse and indexed naming remove severe shared-transcript or large-name-table costs. Measurements were targeted; ordinary protocol timings showed no broad speedup, and the naming index trades storage for lookup time.

### Provenance travels along derivation edges (context.rs)

`derivation_provenance`: state reads inherit ambient diffs; combinations inherit ingredients' records and the influential ingredient's session; `Initial` gets an empty record. `attacker_state_absorb` upgrades unexplained records when a useful explanation arrives, without changing knowledge.

`VerifyContext` provides shared interior mutability: `attacker_put_with` dedupes, `results_put` resolves once, `principal_states()` returns pristine starts, `scratch_for_query(i)` answers only `i` and cannot write back.

**Cancellation converts to an error once.** Loops check `Arc<AtomicBool>` beside `all_resolved()` and merely stop. Only the foot of `analyze_sessions_traced_cancellable` returns `Err(ErrorKind::Cancelled)`, preventing unreached queries from being reported as holds.

### Standard run (verify.rs)

Both attacker kinds use `verify_standard_run`: per principal, `generate_trace` (resolve, rewrite, sanity), knowledge closure, then queries. Honest checked failures are model errors; corrupt-peer creators halt. **Closure never evaluates queries.** Each phase resets knowledge and seeds resolved/rewritten `principal_states[0]`: every public constant and reached-phase wire/leaked value (`public_constant_is_never_confidential.vp`).

### Knowledge closure (deduction.rs)

Monotone fixed point (Knaster–Tarski), using a fresh snapshot per pass and this order:

1. Held values: `decompose`, `break_weak`, `rewrite_build`.
2. Assigned values: `reconstruct`, `recompose`, `rule_rewrite_forward`.
3. Held values: `equivalize`, `concat_extract`.
4. `rule_reuse`: a new vetted pair is progress even if its reveals were public, because forgery becomes possible (`aead_reuse_public_payloads.vp`: `c1c0c0`; distinct-nonce companion: `c0c0c0`).

Every rule calls `learn`; its message is a closure, avoiding output during minimization. `rule_equivalize` rejects leaks declared after the principal's halt.

- `try_deduction_step` spells out order; no rule dispatch table or `RuleDomain`/`Reads` metadata. `knowledge_rules_saturated` skips the five capability-index-only rules when phase, knowledge length, pair count and `routes_epoch` match; four slot-reading rules always run. A skip must be a true no-op: held derived values do not acquire routes unless `reads_from_state`. Preserve learn order.
- `rule_rewrite_forward` reads assigned `pre_rewrite`: when reducible with every argument `obtainable`, learn the reduct. All rewrites except `UNBLIND` already learn it elsewhere; dedup handles them.
- `rule_rewrite_build` constructs a rewrite around held values, learning changed reducts as `Rewritten { built: true }`, a **combined** derivation (`blind_signature_attacker_unblinds.vp`). Skip checks with an already-held fixed `RewriteTo` and no rebuild/combine rule: enumerating pinned inputs can only rediscover that result or fail.
- State rewriting uses only `theory::can_rewrite`; `REDUCE_CACHE` and the second reducer are gone. Report failed outer checks, preserve partial argument reductions, and update `original` iff the root or a descendant successfully rewrote (`failed_checks_preserve_originals_unless_a_subterm_rewrites`, cold/warm cache). Keep generation/eviction tests. Shared-term rewrite microbenchmarks improved, without a measured full-analysis speedup.

### Query evaluation (query.rs)

`query_start` skips corrupt-peer states via `claims_apply_to`; `goals_for_query` mirrors each evaluator:

- **Confidentiality:** attacker knows resolved `value`. If changed from honest and `carries_a_secret` finds no generated/private leaf through state aliases, label `Subtype::AttackerSuppliedValue`.
- **Authentication:** injective agreement, evaluated at the recipient. Fail when `provenance.sender` differs, the constant has a successful primitive use, and no interchangeable sender run emits the delivered value. `query_find_constant_usage_indices` accepts no-rewrite, successful-rewrite or unchecked uses. Acceptance is **positional**: all slots mentioning the constant must be reached, with at least one successful/unchecked use; an unrelated later failure need not cancel it. Thus a check *after* consuming the message may leave `a1`; see the completeness inventory before changing this rule.
  `state_mentions` follows definitions, visiting primitive/**owner** pairs once; only occurrences visible to that owner count. Otherwise opaque blobs create false uses (`piknik.vp`); dropping owner from the visited key hides later visible uses (`shared_transcript_usage.vp`, `a0`). `sanity_queries_check_known` and auto-queries share `principal_uses_constant`. Forgery and replay both yield `a1`; sibling classification narrates `Step::Replay`. **Replays require a touchable leg**: if `delivery_is_guarded` for every sender/recipient delivery, the run itself forwarded the value (`relay_guarded_replay_is_not_a_duplicate.vp`, `relay_guarded_replay_open_hop.vp`).
- **Freshness:** a used value transitively contains no `fresh` constant. No solver proposals originate from freshness.
- **Equivalence:** queried mutated values differ. Require every slot held, no failed-check placeholder and no `slot_starved` dependency on a withheld foreign emission (`concat_bomb_equiv.vp`, `triple_dh.vp`, `equivalence_starved_by_foreign_halt.vp`). Forwarded states also use `answers_for`. Starvation closes over cross-principal definitions but is consulted **only here**; applying it to `slot_unreached` loses Lowe's attack in `spore_ns_pk.vp`.
- **Preconditions:** after finding a violation, every evaluator calls `preconditions_reached` before `attack_trace`; P must reach the send in `precondition[P -> T: d]`. Unreached sends produce no verdict or output; probes use the same evaluator. Render the conjunct, not an annotation. `restrict` may only remove violations. `precondition_*.vp` covers all kinds, foreign halts, split recipients, multiple options, later phases and scenarios; seven `err_precondition_*.vp` pin rejection.
- **Unlinkability:** `unlink.rs::find_link_witness` seeks a pair of observable, non-attacker-authored queried values. In order: observed equality; identifying check under one participant's secret-dependent identifier (`depends_on_secret`); common secret origin (`origin_leaves`); recognized secret that can be tested but not recomputed (`recognized_secrets`, following pinned arguments' origins). The manual's two-world definition remains the specification; this attack-sound procedure is incomplete.

Unlinkability gates:

- `witness_shared_secret` requires a common leaf to remain held, obtainable or recomposable after **either** queried value and all its consequences are withheld (`held_independently`, `without_consequences`). Joining the queried shares is not an origin; a third held share can make it one (`unlink_shares_recomposed_secret.vp`, `junglegym_threshold_ring.vp`). A queried value in the other's origins is itself a witness (`unlink_hash_chain_direct.vp`). Try check witnesses across exposed tuple-component pairs too (`unlink_signature_in_tuple.vp`).
- Honest **unreduced** values must already `share_secret_subterm` before seeking a witness (`unlink_forced_origin_derived.vp`). Revealing a preexisting shared secret is valid (`unlink_active_links.vp`), including a blinding factor erased by reduction (`unlink_blind_active.vp`). Equality also requires honest values equal after reduction; drop `attacker_supplied` witness values (`unlink_forced_equality.vp`, `unlink_forced_origin.vp`).
- `carried_observably` requires **both** attacker knowledge and extractability from a wire/leak (`unlink_carried_in_ciphertext.vp`, `unlink_never_sent.vp`). `opened_subterm` follows tuples and actual `can_decompose` / `can_break_weak` reveals, not arbitrary arguments (`unlink_sealed_carrier_not_observed.vp`, `unlink_sealed_carrier_opened.vp`, `unlink_keys_not_carried.vp`). Revealed projections need not be syntactic subterms (`unlink_kem_carried_output.vp`, `unlink_kem_sealed_output.vp`).
- `observed_value` closes under **tuple assembly only** (`primitive_core_reveals_args`; `unlink_reassembled_chunks.vp`, `unlink_reassembled_by_recipient.vp`). Capabilities and vetted reuse pairs count, the latter only while both members remain held; expose declared reveals, never unrevealed keys (`unlink_weak_carrier.vp` / `unlink_strong_carrier.vp`, `unlink_reused_carrier.vp` / `unlink_distinct_nonce_carrier.vp`).
- Check witnesses must actually run: `check_is_runnable` supplies all matching inputs from knowledge, assigns distinct inner positions and confirms with `can_rewrite`. Pins: `unlink_public_identifier.vp`, `unlink_recognized_nested_message.vp`, `unlink_kem_secret_projection.vp`, `unlink_aead_missing_inputs.vp` / `unlink_aead_complete_inputs.vp`, `unlink_signature_missing_messages.vp`, `unlink_ring_missing_members.vp` / `unlink_ring_complete_members.vp`, `unlink_kem_needs_the_private_key.vp` / `unlink_kem_leaked_private_key.vp`.
- Recognized candidates must not be `bypass_key` constructor applications: ring members would otherwise link every signature (`unlink_ringsign.vp`, `unlink_signature_links.vp`, `unlink_signature_recognized.vp`). `is_key_derivation` is structural: a `PUBKEY`-headed value names a participant, not a session.

`attack_trace` minimizes then narrates. Confidentiality seeds mutations from the disclosed **value**, possibly another principal's execution. Authentication seeds nothing explicitly; `seeded_mutations` uses the answering state's tainted slots and their histories. Seeding from a use-site decryption result selected unrelated histories and left `scuttlebutt.vp`'s fifth/sixth witnesses unminimized.

### Equational theory (theory.rs + primitive/spec.rs)

`PrimitiveSpec` declares decompose, recompose, rewrite, rebuild, combine and bypass-key rules; `theory.rs` interprets them. `obtainable` is the common argument-recovery cascade. Decompose returns a **set** of `Reveal::Argument(i)` / `Reveal::Output(i)`, covering everything the legitimate key holder learns: `KEM_ENCAP` reveals secret **and randomness** (ML-KEM re-encryption re-derives coins). Consumers name projections via `rewrite.from_output` / `decompose.output`. Recompose/rebuild count distinct projections of one split against its threshold (`shares_of_one_split`).

- Rewrite `matching` is a **bijection** onto distinct inner positions; overlapping `RINGSIGNVERIF` `inner_idxs` must not collapse a ring (`ringsign_ring_collapse.vp`).
- `can_reconstruct_primitive` refuses irreducible core applications: `ASSERT` is a check; reducing `SPLIT` still reconstructs.
- `obtainable` opens a `DeductionMemo` scope when absent for its principal/snapshot, shares subproofs within direct calls and restores enclosing scopes (`shared_transcript_bypass.vp`, `c0`; unavailable-leaf/scope-restoration tests). This fixes shared-key bypass costs, not general protocol latency.
- **No recursion cap.** `to` rules return subterms or reassemble strict subterms: depth descent is well-founded. Memoize by term hash alone; adding depth made the suite drastically slower.
- `can_rewrite` is the sole reducer: argument reduction, `can_rebuild`, `can_combine`, then rewrite. `reduce_term` wraps it for states; divergent reducers once made minimization prefer an honest reinstall over forgery.
- **Add primitives only in `src/primitive/spec.rs`**, using `build_primitive_specs`; core entries use `build_core_specs` plus `core_rule_*`. Then add model tests. `every_spec_index_is_within_the_primitive_it_is_declared_on` checks direct indices (`rewrite.from`, `recompose.reveal`, `rebuild.reveal`, `bypass_key`) against narrowest arity, checked indices against widest.

### Nonces (AEAD)

`AEAD_ENC` declares `ReuseRule { fixed: [0, 1], reveals: [Argument(2)], forgeable: [0, 1] }`: two non-equivalent held ciphertexts with equal key/nonce form a pair. Different AD counts; identical key/nonce/message/AD does not. Effects are confined to the reused nonce.

- **Recovery:** `rule_reuse` unconditionally learns both plaintexts. This deliberately over-approximates real XOR leakage when neither is known. Skip buckets whose fixed positions are obtainable and members the attacker could mint (`attacker_mints`), regardless of their recorded derivation: an installed mint can be read back. Otherwise `forgeable` becomes `weak` (`cap_forgeable_is_not_a_reuse_pair.vp`, `cap_forgeable_guard_never_adds_an_attack.vp`). `protocol_produced` follows honest subterms too, retaining nested honest ciphertexts that later become mintable. The threshold counterpart `threshold_sign_forgeable_is_not_a_reuse.vp` reveals its share through public-nonce disclosure, not reuse.
- **Pairs must coexist.** `combination_coheres` merely checks reached reads, insufficient for reuse (`spore_otway_rees.vp`, `spore_yahalom.vp`, `injective_recipient_nonce_unchecked.vp`, `injective_routed_emission_twice.vp`). `pair_vetted` combines shape (`reused_pair`), `theory::one_execution` (also rechecked by both `tracecheck` arms), and `pair_coheres` (**equality** under replay). Unexecutable replay rejects; an unexecuted reader uses its `execution_base` (`aead_nonce_reuse_partner_unreached.vp`). Store vetted pairs in `AttackerState::reused`; `theory::reused` requires both members still held in the snapshot. Pins: `aead_nonce_two_executions_not_a_reuse.vp` (`c0` at both counts).
- **Forgery:** held replacement message/AD suffice with `forgeable` positions exempt in `can_reconstruct_primitive_directly` (`Forged::Reuse` names the pair), `validate::derivable`, `deduce.rs::solve_by_reuse`. Agreement inherits `derivable` (`aead_nonce_reuse_forgery.vp`).
- Decryption requires key **and nonce** (`given: [0, 1]`), so expose the nonce when attacker decryption is intended. `knows` nonces are session-shared; `generates` nonces are fresh (`aead_nonce_reuse_sessions.vp`: `c0`@1, `c1`@2). Static-ciphertext models such as `otp_counter_freshness.vp` declare their nonce; fresh plaintexts normally use generated nonces.

### Threshold primitives (FROST)

`THRESHOLD_SPLIT[t](k)` models dealer Shamir sharing; `THRESHOLD_SIGN(share, nonce, commitments, message)` models RFC 9591 round-2 signing; `THRESHOLD_JOIN` interpolates shares, partials or verification shares. A `CombineRule` requires each `partial` to use a projection of `split` at `share`, agree at `agree` positions and yield `whole(secret, carry…)`; other positions (nonce) vary. Rules join signing partials agreeing on commitments/message into ordinary `SIGN(k, message)`, and `PUBKEY(share)` into `PUBKEY(k)`. `SIGNVERIF` stays unchanged (`threshold_join_agreement.vp`: `e0e0e1e1`). Commitment binding in partials prevents mixing signing sessions.

- Forward: `can_combine` shares the reducer with `can_rebuild`. Reverse: `can_reconstruct_primitive_directly` tries `combinable`, grouping held partials by split/agreement (`partial_groups`), adding constructible partials from held shares and checking threshold. This reconstructs even attacker-chosen signatures assigned nowhere.
- `solve_by_combination` takes `held_splits`, binds the secret, creates shared variables for agreed-but-not-carried positions and per-partial variables for free positions, then walks outputs with a take/skip frontier to threshold. Constructed single-slot proposals supply signing oracles; this goal spends them (`threshold_sign_leaked_share_and_oracle.vp`).
- **Retain distinct substitutions and counts, not subsets.** `remove_local_bindings` substitutes local variables into surviving bindings before dropping entries, preserving wire-dependent nonce constraints. `dedupe_counts` keeps first-encounter representatives per substitution/count; different counts can need different later oracle bindings. `threshold_subset_search.vp` (`a0` at both counts) and the 8-of-16 unit test collapse 12,870 subsets to one solution without pooling disagreeing commitments.
- Seed **all** key alignments: only a later exponent ordering may satisfy message constraints (`solver_threshold_key_alignment.vp`: `c1` at both counts; guarded companion: `c0`).
- Record `Combined { from }`, checked by `tracecheck::combination_holds`; partial ingredients are not arguments. `Recomposed` must not list the unheld split term as an ingredient (`threshold_three_of_five.vp`).
- `THRESHOLD_SIGN` declares `forgeable_secret: Some(0)` and `ReuseRule { fixed: [0, 1], reveals: [Argument(0)], forgeable: [] }`. Two partials sharing share/nonce reveal the share (`threshold_sign_nonce_reuse.vp`, `threshold_sign_fresh_nonces.vp`, `threshold_sign_nonce_reuse_sessions.vp`). This is plain-Schnorr abstraction: one nonce represents FROST's hiding/binding pair; it fires at two uses although exact FROST algebra needs a third. RFC 9591 §7.3 forbids reuse.
- Separately, one partial reveals its share when `decompose` obtains `[1, 2, 3]` (complete nonce pair, commitments, message). A nonce commitment alone is insufficient (`threshold_sign_leaked_nonce.vp`, `threshold_sign.vp`, `threshold_sign_nonce_disclosure_needs_the_signing_context`).
- Models transport shares under pre-shared keys, representing the dealer's confidential authenticated channels (RFC Appendix C); guards stop substitution, not disclosure. AEAD group-key AD binding is a model choice preventing cross-session key-generation replay. A dealer generates shares; model a DKG as a principal splitting a generated key and never using it.
- Metamorphic `lower` may lose no attack; `raise` may add none. Skip equivalence/unlinkability queries because threshold affects term identity.

### Active attacker search (src/solve/)

Goal-directed backward deduction; termination uses memoization, cycle cutting and a finite basis, never effort caps. `reexec::TermBound` limits shape **per slot** to protocol depth plus recipient `peel_depth`; excess above the flat cap must come from protocol subterms (`depth_over_protocol`), not arbitrary held terms that an oracle could ratchet. `TermBound::protocol` collects all trace-resolved constants' subterms **and reduced forms**. `VerifyContext::term_bound` shares one immutable basis/bound across search, agreement and minimization.

Per phase: passive baseline, then knowledge-fixpoint rounds, each running `Pass::Targeted` for **all** principals before `Pass::Constructed` for all. Interleaving fails 13 models. Before building symbolic state, `solve_principal` checks phase-specific `Controllable`; guarded relays with controllable upstream inputs remain eligible.

**Proposal recall tracks reads.** `propose` depends on principal, pass, honest slots, phase, unresolved queries, deferred replays and logged knowledge reads (`reads.rs`): hash-keyed `knows` misses, head-index patterns rematched on new terms, primitive-filtered scans, protocol-basis scans and basis misses. `pass_repeats` recalls only if new knowledge cannot change those reads and reuse pairs / route epoch match. `dispose` always runs; only symbolic work is skipped. `VERIFPAL_CHECK_PROPOSALS=1` recomputes recalled lists and asserts equality (corpus at both counts); `VERIFPAL_SOLVE_DEBUG` emits `[pass]` lines.

Search rules that must retain alternatives:

- `matching::commutative_equations` can shape a receive variable into the declared public-key constructor; unification shapes either side, one-way matching keeps targets rigid (`solver_dh_unshaped_causal_alternative.vp`: `c1` at both counts; guarded/no-wrapping-key companions: `c0`).
- Keep **all** decomposition `match_values` alignments before solving opening requirements: later alignments may be causal (`solver_dh_wrapped_causal_alternative.vp`, guarded/secret-key companions). Respect `decompose.output` / `rewrite.from_output`. Wire rewrites use `build_rewrite_shapes_with` and `unifiers` to solve pinned positions together, retaining source arguments elsewhere; oracles need not reveal their own secret.
- `solve_decomposition_from` traverses nested decomposition and tuple `reveals_args`, retaining every outer opening requirement (`solver_dh_nested_causal_alternative.vp`, `solver_dh_bundled_causal_alternative.vp`). It follows vetted reuse reveals (`solver_dh_nested_reuse_opens_key.vp`, `solver_dh_nested_reuse_opens_nonce.vp`) and active `weak_reveals` / `weak_reveals_output` without opening inputs. Weak routes must match the **whole carrier** to the annotation; payload-only matching over-applies assumptions and exhausts variables on SMP envelopes. Both delivery variants are regular tests. Never recurse into a revealed output equal to the source projection.
- Filtering must expand unheld ingredients using `theory::KnowledgeInputs` and `construction_inputs`, not treat them as free (`causal_derived_unblind.vp`: `a0`@1, `a1`@2; `_early` fails at both). Causality, `Coherence`, `collect_reads`, `forgeable_without_sender` share `reachable_knowledge`, rooted only in permitted reads and ingredient-free constructions. Failed recipes reject combinations.
- Witness/history installs must be jointly causal: `available_before_pending` starts influence at **all pending receives**, removes ready installs in recipient order and rejects a stall. `replay_diffs` groups actual receivers and calls shared `causally_grounded` before execution. Per-run checks admitted circular oracle leaks (`causal_oracle_cycle.vp`: `c1c1c0`@1, `c1c1c1`@2; `causal_oracle_cycle_early.vp` admits both). `harvested_late` also checks receiver. `scratch_for_witness` keeps only the concrete query, excluding sibling variants sharing its result index, so minimization cannot substitute another session's disclosure.

Modules:

- `symbolic.rs`: replace controllable wires with variables and reduce as the real state does. `attacker_controllable` / `Controllable` rejects guarded-unless-`mutatable_to`, self-created, wrong-phase, unused and `nil` slots. Equivalence-named slots waive unused (`equivalence_unused_received.vp`); `construct_wire_index` propagates mutability through every relay (`relay_guard_transitive.vp`, `relay_forward_before_check.vp`). DH shares become `PUBKEY($x)`.
  **Refinement** uses `build_assuming_honest` to reason through selected honest inputs hidden by `build`'s variables (`relay_rewrap_oracle.vp`, `relay_rewrap_no_oracle.vp`). Run only after `search_fixpoint`, with queries outstanding, in Targeted, **after** the unrefined pass; earlier ordering worsens `identity_misbinding_uks.vp` / `ringsign_ring_substituted.vp`. `slots_blocking_reduction` holds honest both the slot blocking a rewrite and bare slot variables in its pinned `matching` positions.
- `vars.rs`: reserved interned constants: slots at `ATTACKER_VAR_BASE = 0x8000_0000`, free choices at `FREE_VAR_BASE = 0xC000_0000`. Free positions survive until materialization; `ground_free` uses shared `nil`, hence divergence fillers.
- `matching.rs`: one-sided `match_value` / `match_values`, two-sided `unifiers`, and `merge`, modulo commutativity. Keep both exponent orders until **all pending equations** succeed (`solver_dh_backtracking.vp`); lazy held/wire matching retains later constructible/causal alternatives (`solver_dh_causal_alternative.vp`). Checked inversion does too (`solver_dh_checked_alternative.vp`: `c1` at both; `solver_dh_checked_ordered.vp` holds). Reuse/malleability retain every fixed-position match through remaining requirements. `merge` queues all binding constraints together and yields all unifiers (`combining_constraint_groups_keeps_alignments_needed_by_later_groups`). All reject `vars::occurs`, including overwritten bindings.
- `deduce.rs`: discharge goals through held values, bare variables (`nil`), replay, wire unification, finite-basis oracles, rewrite matching, arguments, decomposition, `invert`, and `satisfy_check`. `tuple_shapes` uses the smallest legal arity accommodating projection output and honest bundle; enumerating every arity multiplies nested projection searches (`examples/attestation/aws_nitro_attestation.vp`). Collect projection constraints whenever arguments carry variables, including bare slots (`forged_bundle_from_held_terms.vp`).
  `require_constructible` obligates a slot's **wire term under its binding**, not the raw binding: `PUBKEY($x)` can stay honest without learning `$x` (`scuttlebutt.vp`). All-sibling goals are deferred until after Constructed families. Reduce goals under the incoming substitution **before deduction/memoization**, avoiding repeated shape search and variable exhaustion (`simplex_pqdr.vp`'s unguarded `ekb` variant). Memoize by reduced goal **and entire substitution**, even for ground goals with symbolic oracles (`solver_memo_oracle_bindings.vp`); do not cache results computed after cycle cutting.
  **Rewrite inversion solves equations.** `rewrite_shapes_yielding` fills unpinned positions with fresh variables and unifies `to(shape)` with target; filling them with target recursively nests it. Carry every unifier, including existing-variable bindings, into remaining obligations. Apply and project out shape-only existential bindings before constructibility: losing bindings misses `solver_unblind_bindings.vp` (`c1` at both; `solver_unblind_bindings_guarded.vp`: `c0`), but obligating hidden existential plaintexts loses one-session `mac_then_encrypt_order.vp`. The single-result `unify` wrapper is removed.
- `diverge.rs`: `solve_divergent` grounds one-sided variables to `nil`; `distinguish` gives shared installed-tuple projections distinct `fillers()` (`nil`, then `HASH` at every arity), all derivable from nothing. Pins: `equiv_forged_bundle_projections.vp` (`e1`), `equiv_forged_bundle_far_fields.vp`, `equiv_sealed_bundle_holds.vp`, `equiv_guarded_bundle_holds.vp`, `unlink_forged_bundle_not_a_link.vp`.
- `validate.rs`: **the only search-to-query path**. Search materializes one concrete `(slot, value)` signature for dedup/validation. Validator receives no `SymbolicState` or `Substitution`; it rejects out-of-range/residual-variable/duplicate slots and independently proves installs. Required order: **controllability → derivability/causal availability → queue install → execute**; any failure abandons the whole proposal. Its independent `derivable` repeats capability exemptions (`forgeable_secret_position`, `malleable_positions`). Memoize derivability per pointer/call with scoped `DeductionMemo`; history checks stop at held terms and examine needs without tree-sized lists. Keep these predicates separate from `obtainable`: malleability differs. Forty-layer tests cover constructibility, unavailable secrets and changing capabilities.
  `remember_execution` / `recall_execution` store diffs against `execution_base` plus every `bypass_is_constructible` decision. Knowledge is **not monotone** after restriction: invalidate when any decision changes **either way**. Compare states/signatures by `structurally_identical`, not equivalence: commuted terms narrate differently. Re-run guards on every recall; keep the single `execute_forward(` after `installs.push(`. `note_execution_closed` skips closure/queries only for current `Saturation`.

**Proposal families, in order:** unresolved-query goals; `constraint_goals`; blanket substitution; single-slot substitutions; then Constructed-only sibling flights and held-protocol/required-rewrite candidates, alone and with blanket. Explicit honest-other-slot variants are redundant after `leave_honest_slots`. `fill_aligned_with` adds `keyed_free`, `preserved_free` and, only for outstanding equivalence, `distinguish`. Shared `aligned_free_positions` walks proposed/honest pairs iteratively, skips ground branches and visits repeated pairs once (`shared_transcript_replay.vp`).

- `keyed_free`: attacker public keys only where aligned honest terms have keys. Unrestricted filling costs 1.84x (`forged_key_swap_bundled.vp`: `c1c0`; hand witness `witness_key_swap_bundled.vp`: `e0`).
- `preserved_free`: retain held honest fields outside the attack (`forged_statement_rebuilt.vp`: `c1c1`; `forged_statement_on_wire.vp`; hand witness `witness_statement_rebuilt.vp`: `e0`).
- `aligned_held_free`: fill ciphertext positions with every held **protocol** ciphertext under the same key (`pitoy_depth.vp`). Arbitrary held terms inflate the basis severely.
- `sibling_flight_substitutions`: one complete honest flight per sibling, keeping session key shares/ciphertexts together (`tls13-0rtt.vp`). Constructed-only ordering preserves `bypass_witness_narration.vp`.
- `constraint_goals` solves authenticated flights. `constraint_sets` follows declaration dependencies from sends, leaks, queries and each principal's last check, stops at controllable receives and retains earlier prefixes (oracles can emit before later failure). Seed both empty substitution **and independent solutions of every non-projection check**; refine the conjunction in source order, dropping ground contradictions unless bypass keys are obtainable (`piknik.vp`, `forged_flight_mitm.vp`).
  `canonical_slots` dedupes applied receive bindings, renaming existentials in first-occurrence order while preserving sharing/equality constraints; never ground them. The flight's private `Deducer` replay index excludes non-protocol reconstructed terms and injected receives to stop feedback. **Do not apply that restriction to query/per-slot deduction** (`scenario_three_peers_multibind.vp`).

Stronger inversion exposes `ringsign_ring_permutation.vp` (unguarded member permutation; collapse companion guards the other member) and `userbase.vp` (public login-token salt becomes wrapping salt/key). The ring fixture separates signer-input/verifier-receive names: sharing a mutable slot couples symbolic bindings, a remaining limitation. `hkdf_salt_substitution.vp` isolates Userbase; `hkdf_salt_domain_separation.vp` fixes its info argument.

`propose` evaluates pure work with `parallel::map_ordered`; caller-thread writes preserve sequential order. `Deducer::lane_factory` shares immutable `Arc` basis/wire/shaped-slot/held-term indexes; each lane owns `RefCell` memos/cycle state. Flight filtering uses private `Arc::make_mut`. Lane 0 gets the lower free-variable half; lane k gets a top `FREE_LANE_STRIDE` block. `lanes` caps ranges at `FREE_LANES`; create deducers inside callbacks, not per pending item. `fresh_var` asserts no exhaustion: shared variable ids across tasks corrupt fillers. Sharing removes setup/allocations, not a demonstrated broad latency improvement. Parallel closure evaluation was removed because light-rule handoff costs exceeded gains.

**Never irreversibly replace `{honest value} ∪ {derivable values}` with one representative.** Defer and enumerate; when attacks are missed, compare families available to minimization but absent from search. Dedup proposals by reduced concrete `install_signature`, never substitution identity or across rounds. `leave_honest_slots` drops honest bindings unused by others; unbound receive variables stay free and validation skips them. **Do not revive `skeleton.rs` or give the attacker shapes it did not derive.**

### Re-execution (reexec.rs)

`reexecute`: install → reject cyclic slot graph → resolve → rewrite → bypass constructible guards or truncate at the failing check and set `halted_at`. `try_guard_bypass` uses the **pre-resolution** state and registry `bypass_key`; no cap is needed because each round flips a fresh `bypass_injected` flag. Replacing an identity key with `PUBKEY(nil)` explains why a failed signature check may be bypassable.

- `bypass_is_constructible` requires the key **and every other pinned matching input** obtainable: KEM needs the key, AEAD also nonce/AD, signatures message, ring signatures ring/message (`bypass_needs_the_whole_check.vp`, `bypass_needs_the_signed_message.vp`, `…_ad_leaked.vp`, `…_wire.vp`). Only checkable primitives declare bypass keys.
- `honest_input_accepted` refuses a bypass if restoring honest `rule.from` makes the check pass: other inputs already accept the sender's value; alternatives can be installed directly (`bypass_needs_the_signed_message_public.vp`).
- `Guards` borrows `Controllable::of` tokens, `TermBound`, `Coherence`; causal availability runs after derivability, before queueing. Only `reexec.rs` may mint `Controllable` (private fields); `admits` rechecks principal/phase.
- `slot_graph_is_cyclic` lets resolution remain uncapped. Only installs write out of declaration order; primitive references and bare aliases both create edges. Validator and minimizer must use **exactly the same** cycle check.

### Attack traces (witness.rs + narrate.rs)

`witness.rs::minimize_witness` tries candidates in each principal's pristine session: canonical DH MitM, recorded mutations, then those with keys replaced by `PUBKEY(nil)`; retain a resolving candidate and drop installs individually. Probes use a scratch context reseeded from the **passive baseline**, not final knowledge. If none reproduces, `unminimized` sets `reproduced: false` and claims no attacker actions.

- Prefer witnesses without `needs_guard_bypass`; `drop_one` must not reintroduce one. `forged_from` asks failed checks for bypass-free shapes at controlled non-key slots. `payload_shapes` tries held honest fields and attacker public keys before `nil`; every candidate is probed. `examples/silly/cloudbackup.vp` must explain the unguarded Alice → Server → Bob substitution of `g_file_alice_a_key` with both long-term keys guarded, not regress to `nil`.
- A signature bypass under a substituted identity can be the attack, but `TRACE_USES_A_GUARD_BYPASS` is currently empty. `forged_flight` collects **all** shapes accepted by the strict climb and continues from best `(halts, bypasses, stuck)`. Keep strict acceptance unchanged: relaxed variants regressed other paths. A **second** climb accepts only strict improvement, permitting first-check forgery that exposes downstream bypasses. `flight_shapes` also substitutes wanted shapes at every position in the current forged term (`scuttlebutt.vp` equivalence).
- `probe_with` grounds installs greedily: earlier pending receives constrain only the **same recipient's run**; every chosen install must be `attacker_can_derive`-able from preceding knowledge. Clones run concurrently. Joint pending-receive causality is described above. `choose` prefers grounded, nonhalting witnesses among bypass-free ones; `drop_one` preserves groundedness (`the_lowe_witness_replays_through_bob_before_it_learns_the_nonce`, `spore_otway_rees.vp`).
- `seeded_mutations` breadth-first closes tainted diffs over their values' histories, skipping `costs_nothing`. Bound slots by `km.slots.len()`, not possibly truncated `ps.values.len()` (`spore_ns_pk.vp`).
- Shared `(slot, value)` installs reach all controllers; addressed `(principal, slot, value)` installs reach one. Only `split_recipients` mints addressed installs; otherwise keep `others` empty (`forged_key_swap_bare.vp`).
- `narrate.rs::out_of_order_note` / `out_of_order_harvest` is a backstop: no model should earn it; an entry means causal availability missed an impossible trace.

`narrate_attack` emits causal `Mutations`, `Gate`, `Derive` steps per wire message in install order (`mutation_groups`), deriving each installed value immediately before its install.

- Every renderer excludes `shadowed_names` (installed slots and dependents) **at every depth**, including gates, carried-value `via`, and `Narration.shadowed` summaries; otherwise forged values acquire displaced honest names.
- `Leaked` / `Obtained` prefer their recorded slot if still valid and unexcluded (`compress_outer_preferring`), not an arbitrary equivalent name. `Gate` requires an installed slot in `own_cone`. Never call an install an observation at that same slot. `forged_recipient_context` selects `DuplicateAcceptance` when witness installs carry recipient-generated values.
- `attacker_orientation`, `deep_resolve` and unheld `Narrator::walk` preserve DAG sharing with per-call pointer memos and unchanged `Arc`s.
- `NameTable` renders multi-output projections as `|n` (`equivalence_names_the_projection.vp`); `Display for Primitive` omits them. `Broken` displaces assumption-free derivations; `walk` must retain the declared weakening (`cap_forgeable_names_its_assumption.vp`). `Initial` says "it is public" only at the root.
- **Words require evidence:** only `session_prefix`, reading `MutationRecord.principal_id`, names a derivation's run; never call another run "earlier". Only `copy_sibling_replay` justifies "from another session" in `Step::Replay`; otherwise say "unaltered". `Step::Bypass` requires `try_guard_bypass`'s held-key proof, not merely a substituted guarded slot. `Obtained` is "on the wire" only with `sent_by`.

### The soundness tests (query.rs::tcb_tests)

Theorem 4 of the paper is that a solver bug cannot produce a false attack, *whatever the solver does*, reduced to facts pinned by reading the source:

| fact | what it says | pinned by |
| --- | --- | --- |
| (i) | one write path: `results_put`, whose token constructor is private to `query.rs`, called once from `emit_query_result` | the `QueryVerdict` type + `a_query_result_has_exactly_one_write_path` |
| (ii) | reached only from query evaluation: five `emit_query_result` callers, one per query kind | `results_are_recorded_only_by_query_evaluation` |
| (iii) | the verdict comes from a state: an evaluator is handed a `PrincipalState` and an `AttackerState` and nothing that could carry a verdict | `a_query_evaluator_is_handed_states_and_nothing_else` |
| (iv) | every state it is handed was executed: three `verify_resolve_queries` call sites, nothing under `src/solve/` reaches evaluation directly | `query_evaluation_is_entered_only_over_an_executed_state`, `the_solver_cannot_reach_query_evaluation_except_through_the_validator`, `the_solver_holds_no_shared_cell_over_analysis_state` |
| (v) | every term the attacker installs was derivable *and causally available*, against knowledge restricted to compatible executions; `validate.rs` proves this before `execute_forward` runs and abandons the *whole* substitution on failure | `an_install_is_proven_controllable_then_derivable_before_it_is_executed` |
| (vi) | every slot installed into was controlled, tested *first*, against a `Controllable` only `reexec.rs` can mint | the same test, plus `controllability_is_minted_only_by_reexec_and_bound_to_one_session` |
| (vii) | a value entering a state by forwarding is exactly what its sender sent: over a declared leg, in a reached phase, from a run that reached the send, with sender and creator left honest and taint set | `a_forwarded_value_is_only_ever_what_its_sender_sent` |

Two are about *order*: testing derivability after queueing an install, or letting a failed test `continue` to the next slot, executes a state the replay system does not permit. Keep `Controllable`'s fields private and `admits` checking both principal and phase. Adding a query kind touches (ii) and (iii): a sixth `emit_query_result` caller and a sixth arm in `query_start`, both counted.

### Supporting modules

- `parser.rs`: byte-level recursive descent; comments round-trip through `pretty`. Skip a leading BOM **by position**, preserving editor-relative spans. `pretty.rs`: golden-tested, idempotent, pure/infallible AST walk, **not sanity-gated**; owns `Display` for `Value`, `Constant`, `Primitive`, `Query`, `Expression`.
- `resolution.rs`: inlining, visibility and uses. `resolve_ps_values` follows installed bare aliases with a cycle guard (`matching_run_two_inputs.vp`). `rewrite.rs` reports failures as `(Primitive, slot)`. `primitive::normalise_arguments` unwraps forbidden key-derivation nesting per registry restrictions, bounding term space. `construct.rs` owns trace/states and `clone_for_depth(purify)`.
- `info.rs`: output, WASM buffering, `InfoQuiet` for probes, `InfoCapture` for saturation. `update.rs` (`cli`): the only outbound call, GitHub tags GET on a thread read via `try_recv`, **only when stdout is a terminal**; starting it under pipes delayed process exit on DNS.
- `lsp/`: stdio, `recv_timeout` debounce, explicit `shutdown`/`exit`, worker-thread analysis, URI-keyed documents, no filesystem access. **Both threads set `info::set_verbosity(Verbosity::Silent)`**: thread-local `VERBOSITY` otherwise corrupts the protocol on stdout. `docs.rs` (`CC-BY-SA-4.0`) owns keyword/query prose; primitive docs come from specs, capability docs are generated.
- `report.rs`: shared serializable analysis for JSON/HTML/TeX/LSP. Ranges are byte offsets plus 1-based line/column, never LSP positions. `describe` includes leak-only principals (`leaks_without_a_message_is_visible.vp`). Parse once in `Run::of`; renderers never call `crate::parser`.
- `html/`, `tex/`: **no markup in Rust** (`no_markup_is_written_in_rust`, `no_latex_is_written_in_rust`). `include_str!` embeds `tpl/*`, `report.css`, `report.js`, `preamble.tex`. Shared `src/template.rs` uses `Dialect` delimiters (`{{…}}` / `<<…>>`); `Val::Text` escapes, `Val::Raw` does not. Under tests, both missing placeholders and unused supplied values panic. `every_model_in_the_corpus_renders_a_sound_page` checks filled placeholders, unique ids, valid fragment links and balanced tags.
- LaTeX figures use paired `%% --- BEGIN verifpal … ---` / `END` markers and only `\vp…` macros for extraction. `listing_safe` withholds source lines containing `\end{lstlisting}` to prevent embedded `\input`. `the_document_never_claims_a_proof` rejects proof/completeness claims and requires the disclaimer. Bless with `VERIFPAL_BLESS_HTML=1` / `VERIFPAL_BLESS_TEX=1`; enable `the_golden_document_compiles_under_tectonic` via `VERIFPAL_TECTONIC=1`.
- `msc.rs`: shared sequence-diagram rows; `tokens.rs`: index even on parse failure. **Do not add `Span` to `Constant`.** Parser-owned `ValueNames` / `PrincipalNames` and unnamed counter, thread-local analysis counter: no process-global mutable state. Interners error before ids enter attacker, copy or solver bands. Removed modules: `inject.rs`, `mutationmap.rs`, `verifyactive.rs`, `skeleton.rs`.

## Design simplification audit (2026-09-07)

Simplify duplicate representation, **not gates**. The audit consolidated concrete proposals, causal restriction, knowledge filtering and protocol basis/bound. Removed: `RuleDomain`, `RuleGroup`, `RuleFn`, `Reads`, dispatch table, `CausalOrder`, three-field `Delivery`. Full-output comparisons at one/two sessions plus three-session/multi-worker checks preserved behavior.

Keep distinct: causality / other-run compatibility / own receive history; closure reachability / reuse coexistence; knowledge / constructibility / observability; concrete interpretation / symbolic deduction; `original` / `pre_rewrite` / `value`; own halt / foreign halt / starvation; solver / minimizer; scenarios / sessions; term caches / execution caches. Primary-route selection and proposal order remain incompleteness sources. Replacing global knowledge with explicit histories would be a different engine requiring its own migration and compatibility target.

## Weakening audit (2026-09-08)

`malleable_source` selects the earliest held annotated ciphertext matching fixed positions. Reconstruction records `Forged::Assumption`; **both** `construction_inputs` and `DerivationRecord::ingredients` retain the source. `forgeable` needs no source application; `weak`/`malleable` do. Omitting the source admits time-travel forgery (`cap_malleable_causal_source.vp`: `a0a1`@1, `a1a1`@2; `cap_malleable_early_source.vp`: `a1a1` at both).

Passive/nested reshapes use ordinary reconstruction → `learn` → coherence; `note_malleable_reshapes` is removed. `cap_malleable_deduction.vp` is `c1c1c0`; absent-assumption/unheld-source companions are `c0c0c0`. Validator shares source eligibility, keeping independent recursive constructibility for opaque core applications.

Symbolic and ground forgery use the secret index: repeated same-key annotations yield one option at earliest onset, preserving primitive/onset boundaries (128-annotation test). Malleability skips empty indexes and scans by primitive head. Metamorphic weakening also moves delayed assumptions to phase zero. Full release/lint/WASM/exhaustive checks preserved existing verdicts; trace changes added missing source observations. Synthetic indexing gains were small, not a broad performance claim.

## Weakening normalization audit (2026-09-08)

Collect each annotated call independently and reduce its arguments while retaining annotations (see `CapabilityIndex` above). Whole-assignment reduction or cached unannotated twins can erase assumptions. Resolve **only annotated calls**, never expand every assignment to discover an empty index (`capability_collection_leaves_unannotated_transcripts_unexpanded`, 1,000-step DAG).

At both counts: `cap_weak_nested_reduction.vp`, `cap_weak_cached_reduction.vp` are `c1c0`; `cap_forgeable_nested_reduction.vp`, `cap_malleable_nested_reduction.vp` are `c1c0c0`. Active/passive assumption-free twins keep all queries confidential. Registry-wide tests cover every capability/output, delayed onset, cache twins and another message under a normalized key. Release tests, exhaustive weakening, native/WASM lint and full-output corpus comparisons passed; only these regression verdicts changed. Transcript-collection speedups were targeted, not general search gains.

## Testing conventions

- Unit tests: module-local `#[cfg(test)] mod tests`; shared builders in `src/testutil.rs`. End-to-end tests: `src/model_tests.rs`, `run_model("foo.vp", "c0a1")` at shipped default two sessions; `run_model_sessions("foo.vp", 1, "a0")` for explicit counts; `run_model_err("foo.vp", "error substring")` for rejection. Pin session-sensitive verdicts at both counts.
- Codes follow query order: `c/a/f/u/e`, `0` holds, `1` attack. Add each regression under `examples/test/`, obtain `--result-code | tail -1`, **read the trace to justify every bit**, add its test and `// Expected:` argument. Every test model must be wired. Pretty goldens: byte comparisons in `examples/test/golden_pretty/`.
- Shared `testutil::test_value_id` interner requires unique per-test constant names. After parsing, obtain handcrafted constants with `testutil::trace_constant`.
- Engine changes need before/after binaries and **full-output** diffs over `examples/` at one and two sessions, not just codes. **Always exclude `examples/transport-layer/tls13.vp` and `signal_twelve.vp`** (prohibitive cost; neither in model tests).

### Checking *why* a verdict happened, not just that it did

Sweep `examples/test/` plus `SWEPT_MODELS_OUTSIDE_EXAMPLES_TEST` (HPKE, messaging except `signal_twelve.vp`, simple/contact-tracing models, and `cloudbackup.vp`). Re-measure corpus counts when it changes.

- **Replay:** every test analysis runs `witness::assert_reported_attacks_replay`, executing the reporting principal's pristine session with exactly minimized installs; queries must still fail and printed traces may name no fewer slots than required.
- **Narration:** `attack_traces_keep_their_shape_and_name_only_wires_that_exist` pins five **empty** sets: `TRACE_USES_A_GUARD_BYPASS`, `TRACE_IS_NOT_A_MINIMIZED_WITNESS`, `TRACE_IS_NOT_CAUSALLY_ORDERED`, `TRACE_FEEDS_BACK_A_LATER_VALUE`, `ATTACK_IS_REPORTED_WITHOUT_A_TRACE`. New entries regress explanations; removed entries require updated pins. Detect bypass via "does not halt", including unnamed `_` checks.
- **Step proofs (`tracecheck.rs`):** test-only structured `Step` operands are re-derived before return. Ingredients must come from earlier steps/installs, `Initial`, `obtainable`, or justified construction; use stepwise `Grown` knowledge, never final knowledge. Recheck decomposition; `Obtained`'s travelled/leaked/public/held slot; reached `Leaked`; `Broken` with `in_force` at the trace phase; successful tainted `Gate`; obtainable `Bypass` key.
- `Resolves`, `Static`, `Received` and confidentiality targets must describe **the minimized state**: `attack_trace_with` takes closures evaluated against `witness.ps`, not the original answering state.
- **Holds:** `assert_holds_were_searched` requires `goals_for_query` attempted each active-model hold if any slot is controllable (zero goals allowed; freshness exempt). `assert_holds_survive_final_knowledge` reevaluates holds against fresh principal traces and final knowledge.
- Run both one/default sessions; narration sets measure default only. Reject replacements on nonexistent messages or universally guarded copies without bypass. Require `// Expected:` codes to agree; the undocumented-model ceiling (`undocumented <= 126`) is a ratchet.

### The metamorphic harness (`src/metamorphic.rs`)

Detect missed attacks by language-preserving or monotone transforms: parse → transform → `pretty_model` → **re-parse** → `analyze_sessions`. Baselines use one session. `settle` enforces comparison floors; counts live in the harness and must be re-measured.

| property | transformation | allowed change |
| --- | --- | --- |
| `unguard` | remove a guard | gain attacks only |
| `guard` | add a guard | lose attacks only |
| `leaks` | add `leaks c` | gain only |
| `weaken` | add a capability or activate it earlier | gain only |
| `sessions` | 1 → 2 sessions | gain only |
| `dephase` | delete last phase boundary (no renumbering) | gain only |
| `promote` / `demote` | passive → active / reverse | gain / lose only |
| `rotate` | reorder queries | same code, accounting for order |
| `rename` / `pad` | alpha-rename / add unused private constant | invariant |
| `scenario` | identity binding `P[c = c]` | invariant |
| `scenarios` | duplicate identity scenario | gain only |
| `restrict` | add last-message preconditions | lose only |

`guard` found the forgeable/reuse confusion (`cap_forgeable_aead.vp`, `cap_aead_weak_forgeable_matrix.vp`). `rename`/`pad` probe interners/id bands. Threshold `lower`/`raise` are described above.

- `KNOWN_MISSED_ATTACKS` and `KNOWN_BAD_TRACES` are **empty ratchets**, failing for both new violations and exercised entries that stop violating. Judge staleness only on exercised models.
- `asks_the_same_question` skips transformations changing any original scenario's corrupt-from phase.
- **Do not add `name_intermediate`.** Naming a subterm can turn a use inside a failing check into a separate successful use; it is not invariant (`auth_with_signing_false-attack.vp`). Check claimed metamorphic false attacks against pinned semantics before altering gates.
- Analyses run to completion: **no timeouts or deferrals**; skip parse/sanity failures. `spread` / `worker_cap()` cap workers (default 4, `VERIFPAL_METAMORPHIC_WORKERS`); stronger-attacker transforms skip attack-free baselines. `Sweep::Fast` uses `witness::MinimizingGuard` to skip narration/minimization. Regular `unguard`, `leaks`, `weaken` use Fast and omit eleven `COSTLY_MODELS`; ignored `_exhaustively` twins run in CI.

### The completeness inventory

The inventory classifies collapses, memos, gates, bounds and ordering by loosening them and running tests. Changed verdicts identify semantic effects; unchanged results mean dead, redundant or untested behavior; exploding runtime identifies a bound. **Measurements are dated, not code properties** (five rows had drifted by 2026-09-05). Re-measure before citing; "no change" never licenses deleting a gate.

| site | kind | loosened | reading |
| --- | --- | --- | --- |
| `symbolic::build` slot → variable | collapse | — | was a **leak** (`exa.vp`); closed by the refinement search |
| `vars::ground_free` | collapse | — | **leak**; `diverge::distinguish`, `keyed_free` and `preserved_free` cover it |
| projection-constraint collection | gate | **1 missed attack** in the former collector | a split over a bare slot variable is stuck too (`forged_bundle_from_held_terms.vp`); now collected by declaration dependency |
| `keyed_free` aligned-position walk | gate | 1.84x, `concat_split_replay.vp` 2.4s → >120s | cost guard |
| `slot_candidates` protocol-term basis | collapse | **stack overflow** | a second finiteness guard beside `normalise_arguments` |
| `validate` authored-slot gate | gate | no change | **the protection moved** to `reexec::install` and the `original ≡ value` guard. Keep it as a performance guard |
| `deduce` goal-memo bucket | memo | no change | the `equivalent` disambiguation is **untested** |
| `deduce` goal-memo incoming substitution | memo | **1 missed attack** | **fixed**: oracle availability depends on the bindings even when the goal is ground (`solver_memo_oracle_bindings.vp` at one session) |
| `rule_equivalize` halt guard | gate | 2 fail | soundness guard, `halted_principal_false-attack.vp` |
| `unlink` attacker-authored refusal | gate | 6 fail | soundness guard |
| `bind_from_shape` unbound refusal | gate | 4 fail, 3 metamorphic before the attestation-search change | retained for oracle shapes; checked-message shapes defer existential fields but refuse receive variables |
| `validate::replays_own_freshness` | gate | 1 fail | narration-shaping; the two-pass search reorders around it |
| `Pass::Targeted` before `Constructed` | order | 13 fail | load-bearing |
| `unlink::is_observable` knowledge half | gate | **1 false attack** | soundness guard, `unlink_carried_in_ciphertext.vp` |
| `unlink::is_observable` carried-by-a-wire-slot half | gate | **1 model** | soundness guard: loosening turns `unlink_never_sent.vp` from `u0` to `u1` |
| `carried_observably` subterm direction | collapse | **3 models** | **fixed**: a value **assembled from** disclosed chunks never qualified; `observed_value` closes observability under **tuple assembly only** (`unlink_reassembled_chunks.vp`) |
| `unlink::attacker_authored_slot` refusal | gate | 5 models | soundness guard (`unlinkability.vp`, `unlink_injected_equality.vp`, `session_unlink_stable.vp`, `precondition_unlink_halt.vp`, `junglegym_threshold_ring.vp`) |
| `restrict_known` primary derivation route | collapse | **3 false attacks** | following any retained alternate route returns `incompatible_histories.vp`, `history_incompatible_knowledge.vp` and `atemporal_forward_value.vp` as attacks |
| `Coherence::forwards` creator-or-self condition | gate | **1 false attack** | soundness guard, `incompatible_histories.vp` against `…_mitm.vp`. The third-principal exclusion is **untested** |
| `Coherence` reading derivations rather than `MutationRecord.diffs` | collapse | 2 models | the diff-based reading loses `kem_direction_reflection.vp` and `forged_statement_rebuilt.vp` (`c1`) |
| `agreement::emitted_by_matching_run` routes | collapse | measured | three routes (mirror, recorded, routing), each a re-execution |
| `query_authentication_get_pass_indices` `original ≡ value` | gate | no change | **redundant today**, the mirror of `validate`'s authored-slot gate; keep both |
| `query_find_constant_usage_indices` failed-check rule | gate | **42 models** | the most load-bearing gate measured: counting a use in a *failed* check means a halted recipient "accepted" it |
| `query_find_constant_usage_indices` truncated-slot abort | gate | **4 false attacks** | `halted_use_is_not_acceptance.vp`. The `slot_unreached` abort beside it changes nothing either way and is kept for coherence. **Specified**, not open: the manual (chapter 3, "Both conditions depend on successful use") defines acceptance as use-based — every slot mentioning the constant reached, and one of them a successful or unchecked use — and says an unrelated later failure need not cancel an earlier use, so put the checks before the operation that consumes the message. A guarded MAC checked *after* a hash of the message is therefore `a1` by specification. The rule is positional — a use before a failing check counts unless the constant is mentioned again after the halt, so `needham-schroeder.vp`'s `e_n_b_minus_one` and `junglegym_threshold_ring.vp`'s `escrow_sealed` are `a1` on a recipient that rejects the message, and adding a later use flips each to `a0`; `auth_with_signing_false-attack.vp` pins the same shape as a genuine `a1`. Deciding it is a semantics choice between per-use and per-completion acceptance, not a bookkeeping fix |
| `query_equivalence` `value_check_failed` | gate | **11 models** | soundness guard — comparing a decryption that did not decrypt (`equivalence_halt_at_slot.vp`, `double_ratchet.vp`, the `session_*_cross*` family) |
| `resolution.rs` constant-chain resolution | collapse | 1 false attack | **fixed**: the chain is followed with a cycle guard (`matching_run_two_inputs.vp`) |
| `deduce::forgeable_shapes` core exclusion | gate | not loosenable | `satisfy_check` covers projections and equalities during flight solving |

One invariant is still re-run by hand: a two-session run's attacks must be a subset of a three-session run's, clean when last measured.

## Style and licensing

- Every source file starts with an SPDX header (`GPL-3.0-only` for code, `CC-BY-SA-4.0` for prose), including `.vp` test models.
- rustfmt with **hard tabs** and Unix newlines; clippy is a hard gate (`-D warnings`).
- **Do not write comments.** Reasoning belongs in the commit message and in this file, where it cannot drift silently against the source. `sessions.rs` keeps a module-level doc from before that rule, and `deduction.rs`, `reexec.rs`, `agreement.rs`, `context.rs` and `solve/mod.rs` carry item-level docs on the gates whose reasoning does not fit a name. Those are the register to match *if* asked for one; otherwise add none, including to code touched in passing. `.vp` test models are the exception — a new one must carry a `// Expected:` header arguing its code, since the `undocumented` ratchet cannot go up.
