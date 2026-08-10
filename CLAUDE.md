# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Verifpal is a symbolic formal verification tool for cryptographic protocols. Users write protocol models in the Verifpal language (`.vp` files), and the engine checks security queries (confidentiality, authentication, freshness, unlinkability, equivalence) against a passive or active attacker, with each principal running two concurrent sessions by default (`--sessions k` to change it). Sessions are bounded, not unbounded: a passing query means no attack was found within that many sessions. It is a single Rust crate (`verifpal` 0.53.0, edition 2024, `rust-version 1.88`, GPL-3.0-only) that builds as a CLI binary and, separately, as a WASM library used by the Verifpal website and the VS Code extension. The [Verifpal User Manual](https://static.verifpal.com/manual.pdf) is the language reference; `README.md` is the user-facing pitch.

The engine is **sound but incomplete**: any reported attack must be genuine, but the search may still miss attacks. Soundness is structural rather than argued — the solver in `src/solve/` only ever *proposes* substitutions, and `validate.rs` re-executes each one concretely before any result can be recorded, so a solver bug costs a missed attack and never a false one. A false attack (unsoundness) remains the worst possible regression; four test models exist purely to pin past ones:

| model | code | what it pins |
| --- | --- | --- |
| `auth_with_signing_false-attack.vp` | `c0a1a0` | the `signature` authentication query must hold, while the `ciphertext` one legitimately fails |
| `concat_split_replay.vp` | `a0` | a `SPLIT(CONCAT(…))` that reduces to the honest value is a replay |
| `wire_projection_replay.vp` | `a0` | projecting a wire value back onto itself is a replay |
| `aead_replay_not_forgery.vp` | `a0c0` | a fully attacker-known ciphertext under an unreachable key is not forgeable |
| `equivalence_halt_scope.vp` | `e0` | halting a principal is not a divergence: a state truncated at a failed check cannot answer an `equivalence?` query over slots it no longer holds |
| `examples/transport-layer/piknik.vp` | `c0a0a0a0f0` | a substitution the attacker cannot build is not an attack: every value under Client1's signature stays authenticated, because forging it would need `signprivkey` (never leaked) and the confidential plaintext `m` |
| `session_replay_not_attack.vp` | `a0` (both `--sessions 1` and `2`) | replaying another session's honestly-signed pair is non-injective agreement, not a forgery — the session-sibling replay carve-out in `query.rs`. Reporting `a1` here is a false attack |
| `session_nonce_cross.vp` | `a0` at `--sessions 1`, `a1` at `--sessions 2` | pins that session replication finds a genuine cross-session oracle attack: session 2's responder, fed session 1's nonce, forges a MAC session 1 accepts |
| `concat_bomb_equiv.vp` | `e0…f0` at `--sessions 1`, `e1…f0` at `--sessions 2` | the two halves of the same distinction: halting Bob is not a divergence, but feeding him another session's bundle under the same long-term key is one |

"Known to the attacker" is not "forgeable by the attacker" — that distinction is what the last two models exist to hold down. `piknik.vp` is reached through `run_model_at`, which takes a full path; `run_model` still prefixes `examples/test/`.

## Commands

```sh
cargo build --release                  # build (also: make build)
cargo clippy --all-targets -- -D warnings   # exactly what CI runs (also: make lint)
cargo test --release                   # 412 tests (unit + model), ~8s once built (also: make test)
cargo test --release test_ok           # a single end-to-end model test
cargo test --release model_tests::     # only the end-to-end model tests
cargo fmt                              # rustfmt: hard tabs, Unix newlines (rustfmt.toml)
cargo check --lib --no-default-features --features wasm   # fast check that the wasm build isn't broken
make wasm                              # wasm-pack build + copy into ../verifpal-website/res/wasm/
```

CI (`.github/workflows/main.yml`) runs `cargo clippy --all-targets -- -D warnings` and `cargo test --release` on Ubuntu and macOS, plus a separate job that clippies the wasm library for `wasm32-unknown-unknown`. A single warning fails the build. Formatting is **not** gated in CI; `make lint` still runs `cargo fmt --check` locally, so keep the tree formatted.

Running the tool:

```sh
cargo run --release -- verify examples/simple.vp             # full analysis
cargo run --release -- verify path/to/model.vp --result-code # appends the compact result code
cargo run --release -- verify path/to/model.vp --sessions 1  # single-session analysis; the default is 2 per principal
cargo run --release -- pretty path/to/model.vp               # canonical formatter, to stdout
VERIFPAL_SOLVE_DEBUG=1 cargo run --release -- verify m.vp    # log every solver proposal to stderr
```

`--result-code` only suppresses the banner and the beta-software warning; the whole analysis still prints and the code is the **last** line (`… | tail -1`). Other subcommands: `about`; `internal-json <knowledgeMap|verify|prettyPrint|prettyDiagram>` reads a model from stdin (to EOF or `0x04`) and emits JSON — this is the VS Code extension interface.

Errors carry a `Span` into the model source and print as `file:line:col: kind: message` with the offending line and a caret. Parser errors get the position the parser stopped at automatically; `sanity.rs`/`construct.rs` attach the span of the query or declaration at fault via `VerifpalError::or_span`, which keeps whichever span is narrower. Call `.located(file_name, &model.source)` at an entry point so plain `Display` shows the position — `Model` carries its own source for exactly this.

`VERIFPAL_SOLVE_DEBUG` is the first thing to reach for when an active-attacker result is wrong: it prints each proposal as `[solve] <Principal> ran=<bool> [slot=value …]`, including the ones `validate` rejected as indistinguishable replays, which is otherwise very tedious to reconstruct.

## Crate layout and features

- One crate: lib `verifpal` (`src/lib.rs`, `crate-type = ["cdylib", "rlib"]`) + bin (`src/main.rs`, requires the default `cli` feature). `src/main.rs` is the CLI only and holds no tests.
- **Every engine module is `pub(crate)`**; the public API is what `lib.rs` re-exports — `verify`, `pretty_print`, `handle_internal_json`, `info_banner`/`info_message`, the `types` module, and the wasm entry points. `#![warn(unreachable_pub)]` is on, so a stray `pub` on an internal item fails CI; write `pub(crate)`.
- There is no `tests/` directory: an integration-test target collides with this crate's `cdylib` output on one artifact name, and wasm-pack needs the `cdylib`. End-to-end model tests live in `src/model_tests.rs` instead.
- Features: `cli` (default: clap, colored) and `wasm` (wasm-bindgen; entry points `wasm_verify`/`wasm_pretty` in `lib.rs`, which return JSON strings and buffer all output through `info::wasm_messages_*`).
- The engine is single-threaded; rayon was dropped with the mutation search that used it. If you add a parallel code path it must be `cli`-only, with a sequential `#[cfg(not(feature = "cli"))]` twin for WASM — **when you change one, change the other**, and run the wasm feature check above. `VerifyContext` is already interior-mutable, so it is safe to share.
- Release profile: `opt-level = 3`, fat LTO, 1 codegen unit, `panic = "abort"`, `strip = "symbols"`. Use `--release` for anything that actually runs analysis; the engine is compute-heavy and the debug build is about 11× slower (`tls13.vp`: 1.4s release, 15s debug).

## The Verifpal language (enough to write test models)

```verifpal
attacker[active]                    // or passive

principal Alice[
    knows public c0                 // also: private, password
    generates a                     // fresh value
    ga = PUBKEY(a)                  // public key from a private value
    k  = DH_KEX(gb, a)              // DH shared secret; DH_KEX(PUBKEY(b), a) == DH_KEX(PUBKEY(a), b)
    e = AEAD_ENC(k, m, ad)
    x, y = SPLIT(CONCAT(m, n))      // multi-output primitives bind several constants
    _ = HASH(m)                     // `_` is an anonymous constant (becomes unnamed_N)
    leaks something                 // hands value to attacker
]

Alice -> Bob: [ga], e               // [x] = guarded: attacker cannot replace it
                                    // `→` (U+2192) is accepted in place of `->`

phase[1]                            // phases must increment by exactly 1

principal Bob[
    d = AEAD_DEC(k, e, ad)?         // '?' = checked: failure halts this principal
]

queries[
    confidentiality? m
    authentication? Alice -> Bob: e
    freshness? x
    unlinkability? a, b             // ≥2 distinct constants
    equivalence? k1, k2             // ≥2 distinct constants
    // queries take an optional option block, e.g.:
    // confidentiality? m[ precondition[ Bob -> Alice: ack ] ]
]
```

Constraints enforced by the parser and `sanity.rs`:

- Nothing may follow the `queries` block (hard error — it used to be silently ignored and could hide leaks). The `queries` block itself must exist and come last.
- ≤128 principals. Principal names are title-cased (`alice` → `Alice`); every other identifier is lower-cased, so the language is case-insensitive throughout.
- `PUBKEY`/`DH_KEX` argument restrictions are declared in `spec.rs` and enforced by `sanity.rs`: `DH_KEX`'s second argument may not be a public key (this is what makes CDH structural), `DH_KEX` may not nest inside `DH_KEX`, and `PUBKEY` may not take a public key.
- Primitive names are resolved case-insensitively against the spec registry. Arity, output count, and "may this be checked" all come from the spec.
- A model file's *name* must end in `.vp` and be ≤64 characters (`parser.rs::parse_file`).
- Constants cannot shadow reserved words: everything in `parser.rs::RESERVED`, plus any name starting with `attacker` or `unnamed`. **Adding a primitive means adding its lowercase name to `RESERVED` too.**
- A constant cannot be assigned twice, generated twice, `knows`n two different ways, sent by someone who does not know it, or received by someone who already knows it. `leaks` requires the leaker to know the value.
- Authentication and `precondition` queries are validated at load time: the sender must know the constant, the recipient must receive it, and the recipient must actually *use* it inside a primitive — otherwise the query is a sanity error, not a failing query.
- Capability parameters (below) are validated against the spec at load time by `sanity_capabilities`. A capability the primitive does not declare, or one whose `from phase N` names a phase the model never reaches, is a hard error with a message naming the right alternative — an assumption that silently does nothing reads as a check that was performed.

Primitives (arity → outputs): ASSERT(2), CONCAT(2–5), SPLIT(1→1–5), HASH(1–5), PW_HASH(1–5), HKDF(3→1–5), AEAD_ENC/AEAD_DEC(3), ENC/DEC(2), MAC(2), SIGN(2), SIGNVERIF(3), PKE_ENC/PKE_DEC(2), SHAMIR_SPLIT(1→3), SHAMIR_JOIN(2), RINGSIGN(4), RINGSIGNVERIF(5), BLIND(2), UNBLIND(3), KEM_ENCAP(2→2), KEM_DECAP(2). Only primitives with `definition_check` — ASSERT, SPLIT, AEAD_DEC, SIGNVERIF, RINGSIGNVERIF, KEM_DECAP — may take the `?` suffix. ASSERT, CONCAT and SPLIT are *core* primitives: they live in a separate registry (`CORE_SPECS`) whose reduction is a hand-written Rust function rather than a declarative rewrite rule, and several theory functions bail out on them explicitly (`primitive_is_core`). Everything else is data.

**Capability parameters.** A primitive call site may carry a bracketed list of declared weakening assumptions between the name and the arguments: `PUBKEY[weak](a)`, `SIGN[forgeable](sk, m)`, `AEAD_ENC[weak, forgeable from phase 2](k, m, ad)`. `from phase N` means *from phase N onward*, and binds to the preceding capability; absent it, the capability is in force from phase 0.

- `weak` — confidentiality is lost, so holding the term yields what it protects. Declared by `weak_reveals` / `weak_reveals_output` on `PrimitiveSpec`: `HASH`, `PW_HASH` (preimage, revealing every argument), `AEAD_ENC`, `ENC`, `PKE_ENC` (plaintext), `KEM_ENCAP` (shared secret), `PUBKEY` (the private key). `PUBKEY[weak]` is discrete log, and the DH cascade falls out of the *existing* `can_reconstruct_primitive` with no DH-specific rule — `cap_weak_pubkey_dh.vp` pins that.
- `forgeable` — authenticity is lost, so the term is constructible without its secret. Declared by `forgeable_secret`: `SIGN`, `MAC`, `RINGSIGN`, `AEAD_ENC`. Splitting this from `weak` is what makes `AEAD_ENC[forgeable]` — forgeable but still unreadable — expressible; `cap_forgeable_aead.vp` exists to keep the two from collapsing into one.
- `malleable` — in the vocabulary and parsed, but **no primitive declares it**, so any use is a hard error. See the note in `capability.rs::unsupported_message` and the commit that added it: the attack it enables needs two coordinated wire substitutions, which the solver only forms through its goal-directed path, and that path cannot derive the required ciphertext goal.

`weak`, `forgeable`, `malleable` and `from` are **contextual keywords**, deliberately absent from `RESERVED`: they are recognised only inside the parameter brackets, where no constant can appear, so reserving them would gratuitously break models using `weak` or `from` as a constant name.

Comments (`//` and `/* */`) are captured into AST nodes so `pretty` round-trips them, **except** in positions where they are deliberately dropped: inside primitive argument lists, inside the `attacker[…]`/`phase[…]` brackets, and inside a query option's inner brackets.

## Architecture

### Pipeline

```
parse_file (parser.rs)              hand-written recursive-descent, comment-preserving AST
  → sanity (sanity.rs)              model validation; drives construct.rs
      → construct_protocol_trace    "km": ProtocolTrace — global immutable protocol description
      → construct_principal_states  one PrincipalState per principal
  → VerifyContext::new (context.rs) shared mutable state for the whole run
  → verify_passive (verify.rs) | verify_active (solve/mod.rs)      per phase
  → verify_end                      prints results, returns the results code
```

`verify::analyze(&Model)` is the **one** place that sequence exists: it runs sanity, builds the context, dispatches on the attacker kind and returns the `VerifyContext` holding the results. `analyze` is `analyze_sessions(m, DEFAULT_SESSIONS)`; `verify::verify(path)` is `verify_with_sessions(path, DEFAULT_SESSIONS)`. `json.rs` and the wasm entry points call `analyze`, so the CLI, the IDE interface and the website cannot disagree about what a model means — **that shared default is the point; do not give one entry point its own.** Throughout the code, `km` is the `ProtocolTrace` (historical name "knowledge map") and `ps` a `PrincipalState`.

**Parallel sessions (sessions.rs).** Every principal runs `DEFAULT_SESSIONS` (2) concurrent sessions unless `--sessions k` says otherwise. This is a *front-end* to the same engine: `sessions::expand_sessions` rewrites the parsed `Model` into one where every principal and message block is cloned `k` times **before** `sanity` runs, so everything downstream is unchanged and the feature inherits the engine's attack-soundness — an expanded model is a legal model the user could have typed by hand (the `Alice2`/`na2` workaround, automated), and `sanity` re-validates all of it. The freshening rule falls out of existing syntax: `generates` constants and assignment outputs get per-session copies (`c#s`, rebanded into the session-copy id range — see `value.rs::SESSION_STRIDE`, bands 0..=14 for sessions, band 15 for the minimizer), while `knows` constants stay shared. Clones are emitted in place; the lockstep layout loses nothing because within-phase attacker knowledge is atemporal. Each written query is kept verbatim (session 1) and also given per-session **variants** (`VerifyResult.variants`), all resolving the original `query_index`, so the result code keeps one entry per query and an attack in any session resolves it; `verify_resolve_queries` and `goals_for_query` iterate original + variants. The one new semantic obligation is the **session-sibling replay carve-out** in `query.rs`: a received value equal (after the same resolve-and-reduce recipe as `reexec::attacker_authored`) to a session sibling's honest wire value is a cross-session replay of something the sender honestly sent, hence non-injective agreement, not an authentication attack — this only ever *suppresses* a report, so it cannot cause a false attack. `attacker_authored` itself stays session-strict so such states remain explorable as oracle stepping stones. `k = 1` skips expansion entirely and is bit-for-bit the pre-sessions behavior, which is what makes it the escape hatch for a model too large to afford the roughly 4x that replication costs.

Raising the default from 1 to 2 changed no verdict on any of the 16 shipped protocol models, and exactly two in `examples/test/` — both genuinely: `session_nonce_cross.vp` and `concat_bomb_equiv.vp`. Re-measure both corpora before touching the default again.

### Core data model (types.rs)

- `Value` = `Constant` | `Primitive(Arc)`. Constants are interned per model: name → `ValueId` (`value.rs`; `nil` is id 1); equivalence compares ids. Diffie-Hellman is expressed with the ordinary primitives `PUBKEY(sk)` and `DH_KEX(pk, sk)`; their commutativity (`DH_KEX(PUBKEY(a), b) == DH_KEX(PUBKEY(b), a)`) is declared by the `commutativity` field on `PrimitiveSpec` and consumed generically by `equivalence.rs`, `hashing.rs` and `solve/matching.rs`.
- `Primitive` carries a `HashCell`: a term's hash is computed once and cached, which makes `hash_value` O(1) and lets `Value::equivalent` reject non-equal terms on hash inequality before any deep comparison. Terms are immutable once built; the single in-place mutation (`construct.rs`, setting a multi-output `output` index) clears the cell.
- **Invariant: `a.equivalent(b)` ⟹ `a.hash_value() == b.hash_value()`** (`hashing.rs` uses a commutative hash for DH exponents). `AttackerState::knows()` looks up by hash bucket first, so breaking this silently breaks attacker knowledge. Unit tests pin it.
- `Primitive.capabilities` carries the parsed weakening annotations, and is deliberately **not** consulted by `primitive_hash`, `equivalent_primitives`, or `theory.rs::structurally_identical_primitive`: an annotated term and its unannotated twin are the same cryptographic object, which is what keeps every existing invariant untouched and makes an unparametrized model behave bit-for-bit as before (`cap_noop_annotated.vp` pins this against `hmac_ok.vp`). The engine reads capabilities from the `CapabilityIndex` on `PrincipalState`, **never** off the copy of a term it happens to hold — `AttackerState` dedupes by equivalence, so if an unannotated copy reached the attacker first the annotated one would be discarded and the rule would silently never fire, making results depend on which principal the engine walked first. The one place that cannot use the index directly is `solve/deduce.rs`, whose goals are patterns containing free variables: it unifies against the index's annotated terms instead.
- `SlotValues` holds **three values per slot** — the single most important invariant in the engine:
  - `original`: what the protocol honestly computed (what the principal *believes*),
  - `pre_rewrite`: after attacker mutation, before cryptographic rewriting (for forensics/narration),
  - `value`: after mutation and rewriting (what analysis uses).

  `PrincipalState::should_use_original`/`effective_value` and `resolution.rs::compute_visibility` decide which one a principal sees. Getting this wrong causes false authentication attacks (principals "seeing" the attacker's tampering in their own computations).
- `Provenance` rides alongside: `creator`, `sender` (`ATTACKER_ID` = 0 when injected), `attacker_tainted`, and `bypass_injected`. The last two are **deliberately separate**: taint decides which value a principal perceives, and a guard bypass must not change that (the principal genuinely computed with what it was handed), but the substitution still has to be *reportable*, or the most important step of a MitM trace becomes invisible to the narrator.
- `SlotMeta` is the immutable half of a slot: `guard`, `known`, `wire` (recipients this value travelled to), `mutatable_to` (recipients it reached *unguarded*), `known_by` as `(recipient, sender)` pairs, `declared_at`, and the phases it appears in. `mutatable_to` is what `symbolic.rs::reaches` and `compute_visibility` consult to decide whether an attacker choice can influence a given computation.
- `PrincipalState::halted_at` records the `declared_at` of the earliest checked-primitive failure after mutation. `reexec.rs` sets it and truncates the state there; `deduction.rs::rule_equivalize` uses it to suppress `leaks` the principal never reached.
- `AttackerState`: append-only `known` set + `known_map` hash index + `skeleton_hashes` (so `attacker_learn_skeletons` can skip a shape it already holds) + `mutation_records` and `derivations`, both parallel to `known`.
  - A `MutationRecord` is the set of slot diffs (against the trace's initial values) that had to be in force for the attacker to hold that value, plus the principal and phase whose session that was.
  - A `DerivationRecord` says *how* the value was obtained: `Initial`, `Leaked`, `Obtained`, `Decomposed`, `Reconstructed`, `Recomposed`, `PasswordExtracted`, `ConcatFragment`, `Injected`. Attack narration walks this DAG, so **a rule that adds knowledge without recording an honest derivation produces an unexplainable trace.**

### Provenance travels along derivation edges (context.rs)

This is subtle and was the subject of several recent fixes. `context.rs::derivation_provenance` decides which `MutationRecord` attaches to a newly learned value:

- A value **read out of a principal's state** (`Leaked`/`Obtained`/`Reconstructed`, or one whose ingredients a rule rebuilt on the spot) picks up that state's ambient diffs.
- A value **combined out of values the attacker already held** inherits *their* records instead, and adopts the session of whichever ingredient actually carried the leverage.
- `Initial` and `Injected` cost the attacker nothing, so they get an empty record.

Snapshotting the ambient state at absorption time instead would describe one attack's actions beside another attack's consequences: the attacker learns a ciphertext in the run where it substituted a public key, then decrypts it in a later run whose substitutions are about something else entirely.

`attacker_state_absorb` also *upgrades* an existing record: if the stored one explains nothing (no tainted diffs) and the arriving one does, the record and derivation are replaced. Knowledge is unchanged either way — only the explanation is. Without this, a trace can end up describing an attack with nothing in it, because the first path to reach a term was one that had already purified the state.

`VerifyContext` is the interior-mutability container (RwLock/atomics) shared by `&VerifyContext` rather than threaded as `&mut`. `attacker_put`/`attacker_put_with` dedupe new knowledge; `results_put` resolves each query at most once; `all_resolved()` short-circuits every search loop; `principal_states()` hands back every principal's pristine starting state (used by the minimizer to replay an attack in the session it belongs to); `scratch_for_query(i)` builds a disposable context that can only answer query `i` and cannot write back. `ANALYSIS_COUNT` is a process-global counter used only to label output, and is deliberately not incremented while output is quiet.

### Standard run (verify.rs)

`verify_standard_run` is shared by both attacker kinds — the active search uses it as its passive baseline. For each principal, three phases:

1. **Trace generation** (`generate_trace`) — `resolve_all_values` (inline constants per visibility rules), `compute_slot_diffs`, skeleton injection, `perform_all_rewrites` (rewrite.rs), then sanity checks (a failed *checked* primitive here is a model error, not an attack).
2. **Knowledge closure** — `deduction.rs::compute_knowledge_closure`.
3. **Query evaluation** — `query.rs::query_start` for each unresolved query.

Closure never checks queries — that separation is what makes the fixed-point argument clean. Each phase begins by resetting attacker knowledge (`attacker_init`) and re-seeding it from `principal_states[0]` resolved purely (`attacker_phase_update`): public constants that some principal actually uses, plus every wire or leaked value whose earliest phase has been reached.

### Knowledge closure (deduction.rs)

A monotone fixed point over three rule groups, restarting from the first group on any progress:

1. over attacker-known values: `decompose`
2. over principal-assigned values: `reconstruct`, `recompose`
3. over attacker-known values: `equivalize`, `password_extract`, `concat_extract`

Termination is Knaster–Tarski: knowledge grows monotonically, the derivable set is finite, each iteration either adds a value or stops. Every rule ends by calling `learn`, which records the value together with its `DerivationRecord` and emits the matching `Deduction ›` line — routing them all through one function is what keeps "knowledge and the derivation that explains it are recorded together" true by construction. Its message argument is a closure because minimization re-runs the closure many times with output suppressed.

`rule_equivalize` carries the one non-obvious guard: if the principal halted on a failed checked primitive, a `leaks` this same principal declared *after* that point never fired, so re-resolving through it would let the attacker harvest values from a branch the principal never reached.

### Query evaluation (query.rs)

Each kind resolves differently, and the solver's goal analysis in `solve/mod.rs::goals_for_query` mirrors these exactly:

- **confidentiality** — the attacker knows the slot's resolved `value`.
- **authentication** — evaluated only while walking the recipient. Fails when the slot's `provenance.sender` is not the declared sender *and* the constant is successfully used inside a primitive the recipient computed (`query_find_constant_usage_indices`: the primitive has no rewrite rule, or its rewrite passes, or it is unchecked).
- **freshness** — the value transitively contains no `fresh` constant, yet is used in a primitive. No attacker choice affects this, so the solver never proposes anything for it.
- **unlinkability** — the attacker exhibits a *link witness* for some pair of the queried constants (`unlink.rs::find_link_witness`). Both must be observable (they travelled on the wire or were leaked) and neither slot may be attacker-authored, since an attacker that overwrites two slots with one value manufactures the equality it would then be reporting. Three witness kinds, cheapest first: **observed equality** (the attacker holds both and they are the same secret-dependent value), **identifying check** (a `definition_check` primitive with a declared identifying position succeeds over both under one participant's key), and **common secret origin** (both values' reconstructions bottom out on one secret the attacker holds, found by `origin_leaves`, which withholds each value from the attacker first — receiving a value explains nothing about whose it is, only recomputing it does). The manual's two-world definition is the specification; this is the decision procedure, sound for attacks and incomplete. `identifying_positions` on `PrimitiveSpec` is empty for `RINGSIGNVERIF` on purpose — a ring names a set and never a member, and that emptiness is the only thing keeping `unlinkability?` from reporting a false attack on the one primitive whose whole purpose is unlinkability (`unlink_ringsign.vp` versus `unlink_signature_links.vp`, structurally identical models with opposite verdicts).
- **equivalence** — the queried constants do not all resolve to equivalent values, using the *mutated* value rather than `original`. Solved as a divergence rather than a deduction. It first requires that this state actually *hold* every queried value: `reexec::drop_after_index` truncates a halted principal's slots, and `resolve_constant` answers for a slot that is gone with the bare constant, so comparing that placeholder against the other side's real value reports a divergence nobody computed. Making a principal abort is not making two principals disagree — an aborted principal has no value to disagree with. This is why `concat_bomb_equiv.vp` and `triple_dh.vp` hold: in both, the attacker can only halt the recipient, and in `triple_dh.vp` unguarding `gb_ident` makes the real MitM available and the query fails again, which is what keeps that `e0` honest.
- The `precondition[A -> B: c]` option annotates a failing query with "A sends c to B despite the query failing".

When a query resolves, `attack_trace` minimizes the state that resolved it (`witness.rs`) and narrates it (`narrate.rs`), seeding the minimizer with the mutations recorded against the *value* rather than whatever state happened to answer the query.

### Equational theory (theory.rs + primitive/spec.rs)

All cryptographic behavior is **declarative data**: `PrimitiveSpec` entries define decompose ("knows key → learns plaintext"; `reveal_output` makes the rule yield one of the primitive's *outputs* instead of an argument, which is how an attacker holding a decapsulation key opens a `KEM_ENCAP` ciphertext no principal ever decapsulated), recompose (threshold shares), rewrite ("DEC undoes ENC", with matching constraints and filters), rebuild (SHAMIR_JOIN), password protection, and guard-bypass key extraction. `theory.rs` interprets the specs (`can_decompose`, `can_reconstruct_primitive`, `can_rewrite`, `can_rebuild`, `find_obtainable_passwords`). `obtainable` is the shared "can the attacker get this argument at all" cascade that decomposition and reconstruction both run over each of their arguments.

None of it carries a recursion cap, and reintroducing one is a regression. The descent is well-founded on term depth: every `to` rule in `spec.rs` returns a subterm of its input or reassembles strict subterms of it, and every `decompose` filter returns an argument or something inside one, so each step hands the next a strictly shallower term. The memo is keyed on the term hash **alone** — it once carried the recursion depth beside it, which was purely an artifact of the cap, and putting depth back splits every answer across as many entries as there are levels: the suite goes from two seconds to six minutes and finds exactly the same attacks.

Password extraction is worth knowing: a `password` constant is recoverable when, at *every* primitive level enclosing it, the position is not in `password_hashing` (only `PW_HASH` sets that) **and** the attacker knows every sibling argument — i.e. it can verify a guess offline.

**To add a primitive, edit only `src/primitive/spec.rs`** — it has extensive field-by-field docs and a worked STREAM_ENC/STREAM_DEC example at the spec table. Also add the lowercase name to `RESERVED` in `parser.rs`. Then add model tests.

### Active attacker search (src/solve/)

Goal-directed. The engine asks "what would the attacker need in order to learn this, and can it arrange that", and solves backwards from each query — it does **not** enumerate substitutions forwards. There is no depth cap, no per-principal budget, and no `SearchConfig`; an attack needing four simultaneous wire substitutions is the union of four bindings each forced independently, not a four-element subset someone had to afford. Termination comes from memoisation, cycle cutting, and a finite basis, never from a cap on how hard to look.

Per phase: passive baseline, then rounds to a knowledge fixed point (validation grows attacker knowledge, which can unlock goals). Each round runs `Pass::Targeted` for every principal, then `Pass::Constructed` for every principal — never interleaved per principal, because one principal offering a large pile of constructible values would otherwise delay ever looking at the principal that matters.

- `symbolic.rs` — the principal's computation with every attacker-controllable wire slot replaced by a variable, then reduced the way `perform_all_rewrites` would reduce it. `is_mutable_slot` decides controllability (guarded-unless-`mutatable_to`, self-created, wrong-phase, unused-by-this-principal, and `nil` is excluded). A DH public key becomes `PUBKEY($x)`, not a bare `$x`, so the MitM shape falls out of the representation. Terms are memoised per slot; without that, nested ciphertexts expand exponentially. `reaches` mirrors `compute_visibility`, so a choice that can only be made *after* a principal acted does not appear inside what that principal computed.
- `vars.rs` — attacker variables are interned `Constant`s in reserved id ranges (`ATTACKER_VAR_BASE = 0x8000_0000` for slots, `FREE_VAR_BASE = 0xC000_0000` for free choices), so there is no fourth `Value` variant and nothing else in the engine needs to know they exist. Free positions stay variables until materialisation — committing them to `nil` early makes two partial solutions for the same forged message unmergeable.
- `matching.rs` — one-sided `match_value`, two-sided `unify`, and `merge` (which unifies rather than rejecting conflicting bindings), all modulo DH commutativity (a closed two-case analysis, not AC unification). All three refuse a binding whose variable occurs in what it is bound to (`vars::occurs`): without that check the unifier answers with rational terms — `$x = ENC(k, HASH(DEC(k, $x)))` is a solution only if a term may contain itself — and `vars::apply`, which chases a bound variable into its own binding, never returns. `merge` has to repeat the check when it *overwrites* a binding, since that path does not go through `bind`.
- `deduce.rs` — the solver proper. Goals are discharged by: already-known, bare-variable (`nil`), **replay** (a held value that is an instance of the pattern), wire unification, oracle (restricted to the finite basis), rewrite-match, primitive-by-arguments, decomposition, `invert` (backwards through rewrite rules and `SPLIT`/`CONCAT`), and `satisfy_check` for checked primitives. Bindings produced by unification are then put under obligation by `require_constructible`, which is what forces the DH substitution in a real MitM. Goals are memoised by `goal_key`, which **must** include a kind tag, or a primitive and a constant sharing a hash collide silently. Results computed while a cycle was cut are not cached.
- `diverge.rs` — equivalence queries, solved by grounding the variables that reach only one side.
- `validate.rs` — **propose and dispose**. Nothing in `solve/` can record a query result; every proposal is materialised into a concrete `PrincipalState`, re-executed via `reexec.rs`, and re-checked against real attacker knowledge. It owns `is_worthwhile` — a term that reduces back to the honest value is a replay, not an attack (false-attack issue #18), and dropping this check is how you manufacture false authentication results. Errors from analysing a hypothetical state are swallowed: a speculative branch that cannot be analysed answers nothing, and must not abort the whole run.

Proposal families, in the order they are offered: goals derived from each unresolved query; `constraint_goals` (make every checked primitive in the model succeed, since a check the attacker can satisfy is a check that does not halt the principal); the **blanket** substitution (every controlled slot replaced by the attacker's own value — one substitution, one validation, and the shape most protocol attacks take); one single-slot substitution per controlled slot (for when the blanket would trip some *other* check); and finally, only in `Pass::Constructed`, per-slot candidates drawn from protocol terms the attacker holds and from shapes the recipient's own rewrite rules demand — each offered alone, combined with the blanket, and combined with a **relay** substitution that forwards every other slot unchanged.

Variables the solver never bound are deliberately left free, and `validate` skips those slots: the attacker has no reason to touch that wire value, and grounding it would fail an unrelated check and halt the principal before the attack could land.

**Skeletons** (`skeleton.rs`) are no longer part of the search: they are a primitive's shape with secrets erased (constants→`nil`, public keys→`PUBKEY(nil)`), added to attacker knowledge during trace generation. Since `nil` and `PUBKEY(nil)` are values the attacker already holds, a skeleton is by construction something it can build, so this asserts nothing new.

### Re-execution (reexec.rs)

`reexecute` installs attacker-chosen values into a principal and runs it forward: install → check the slot graph is still acyclic → resolve → rewrite → then either bypass guards the attacker can defeat (`try_guard_bypass`, keyed on the spec's `bypass_key`; the bypass loop is uncapped — each round must flip a fresh `bypass_injected` flag, so it terminates structurally) or truncate at the checked primitive that halts the principal and set `halted_at`. Guard bypass has to work from the *pre-resolution* state, because injecting into an already-inlined state does not propagate to the slots that referenced the guard's output.

The bypass exists because substituting `PUBKEY(nil)` for an identity key fails a signature check — but the attacker knows the private key for `PUBKEY(nil)`, so treating that as a halt would discard the whole man-in-the-middle.

`slot_graph_is_cyclic` is what lets `resolution.rs` carry no depth cap. `install` is the only thing that rewrites a slot's value out of declaration order, and the search will happily offer a slot a wire value that names that same slot — `piknik.vp` reaches for exactly this, proposing `ekid = ENC(DH_KEX(PUBKEY(keygen), ekid), CONCAT(n, m))`. No execution reaches such a state, so `reexecute` returns `Err` and `validate` drops the proposal, which is the ordinary propose-and-dispose path. Only slots holding a *primitive* have outgoing edges: resolution stops at a constant-valued slot rather than inlining through it, so a leaf slot is not a cycle of length one.

This lives in one place because **two callers must agree exactly**: `solve/validate.rs` validating a proposal, and `witness.rs` deciding whether a mutation is load-bearing. A minimizer that re-executed even slightly differently could drop a mutation the engine actually needs and report a trace that does not reproduce.

### Attack traces (witness.rs + narrate.rs)

A query result carries a narrated trace, produced in two steps after the query resolves:

- `witness.rs::minimize_witness` — the solver installs the union of the bindings for *every* goal it was pursuing, so a raw witness routinely contains substitutions only some other query needed. The minimizer first picks a **candidate**: for each principal's pristine session (the query's own principal first), it tries the canonical MitM (attacker's key wherever a DH public value arrived over the wire), then the recorded mutations, then those with public keys replaced by `PUBKEY(nil)` — taking the first that still resolves the query. It then drops mutations one at a time for as long as the query keeps resolving. If nothing replays anywhere, it falls back to `derivation_only`: report the derivation and claim no attacker actions, rather than name substitutions that may not be the ones that mattered.
  - Probes run against a **scratch `VerifyContext`** whose results are discarded, so this too cannot record a result — a bug here yields a larger witness, never an attack that does not exist.
  - Each probe re-seeds from the **passive baseline**, not end-of-search knowledge. Attacker knowledge is monotone, so probing against the snapshot would answer every confidentiality query "yes" immediately and make every mutation look droppable.
  - Sessions come from `ctx.principal_states()`, never from the state in hand: a guard bypass writes its injected key into `original`, which is the field purification restores from, so a bypassed state cannot be cleaned by purifying it.
  - `in_minimization()` gates re-entry and `info.rs::InfoQuiet` gates output, so the many hypothetical re-runs neither recurse nor print.
- `narrate.rs::narrate_attack` — renders the minimized witness as numbered causal steps: `Mutations` (grouped per wire message), `Gate` (a checked primitive that passed with attacker-controlled inputs — the step readers are most likely to disbelieve), and `Derive` (one line per `DerivationRecord`, ingredients before target). A derivation the attacker performed in another principal's session is prefixed with that session per line, never as a mode switch. `NameTable` compresses terms back to slot names, excluding the slots a step itself touches so a line never reads "replaces `gb` with `gb`"; the returned `Narration` carries that table so the summary line quotes the same vocabulary as the steps.

### Supporting modules

`parser.rs` — byte-level recursive descent; comments are captured into AST nodes so `pretty` round-trips them (round-trip idempotence is unit-tested). `pretty.rs` — canonical formatter, golden-tested; it also owns the `Display` impls for `Value`/`Constant`/`Primitive`/`Query`/`Expression`, so *every* engine message and attack trace is rendered by this file. `resolution.rs` — inlining and `compute_visibility`; unbounded, because it descends only through slots holding a primitive and the slot graph is acyclic (`construct.rs` builds in an order `sanity.rs` has already made topological, and `reexec::slot_graph_is_cyclic` refuses any install that would close a loop). `rewrite.rs` — applies the rewrite rules over a whole state and reports failures as `(Primitive, slot)`. `equivalence.rs`/`hashing.rs` — the equivalence/hash invariant above and `collect_subterm_hashes`. `primitive::normalise_arguments` is the one place that keeps the term space finite: where `argument_restrictions` forbids a key-derivation application in a position, it unwraps it, so the solver cannot build `PUBKEY(PUBKEY(x))` and recurse forever. Removing it makes attacker knowledge fail to saturate on models with an unguarded public key. `construct.rs` — builds the trace and principal states under `sanity.rs`, and owns `clone_for_depth(purify)`. `info.rs` — all user-facing output, buffered into JSON messages under wasm; also `InfoQuiet`, the thread-local guard that silences hypothetical re-runs. `json.rs` — the `internal-json` IDE interface and the sequence-diagram renderer. `unlink.rs` — the link-witness decision procedure behind `unlinkability?`, described under Query evaluation above. `capability.rs` — `Capability`/`Capabilities` (the parsed annotation), the spec-support queries and their diagnostics, and `CapabilityIndex`, the model-level lookup the engine consults; see the capability-parameter notes under the language section and the core data model. `util.rs` — three small helpers.

There is no process-global mutable state. `ValueNames` (`value.rs`) and `PrincipalNames` (`principal.rs`) are interners **owned by the `Parser`**, so ids are per-model and two analyses in one process cannot interfere; the unnamed-constant counter is a parser field, and the analysis counter is thread-local. `PrincipalNames::intern` errors past `PrincipalId::MAX` rather than truncating a 256th principal onto `ATTACKER_ID = 0`, and `ValueNames::intern` refuses to reach the id range `solve::vars` reserves. Principal *names* travel on `Message`/`Principal` and via `ProtocolTrace::principal_name`, because `Display for Query` cannot take a lookup table.

All output is plain text: there is no alternate-screen progress UI and no attacker-voice easter egg, so don't go looking for `tui.rs`, `narrative.rs`, or a `--character` flag that older docs may still mention. Likewise `inject.rs`, `mutationmap.rs` and `verifyactive.rs` were the forward mutation search and are gone.

## Testing conventions

- Unit tests live in a `#[cfg(test)] mod tests` at the foot of the module they exercise, so they can reach private items directly. `src/testutil.rs` holds the shared value/state builders. `src/model_tests.rs` holds the end-to-end model tests (`run_model("foo.vp", "c0a1")` runs `examples/test/foo.vp` and asserts the result code). `run_model` goes through `verify`, so it exercises the **shipped default** of two sessions. `run_model_sessions("foo.vp", 1, "a0")` pins an explicit count; a model whose verdict depends on session count should be pinned at both `1` and `2`, so single-session behavior stays a regression guard rather than becoming untested.
- **Result code format**: one letter+digit per query, in model order — `c`/`a`/`f`/`u`/`e` for the query kind, `0` = holds, `1` = attack found. So `"c1a0"` means the confidentiality query failed and the authentication query passed.
- Adding an engine regression test: write a model in `examples/test/`, get the code via `cargo run --release -- verify examples/test/foo.vp --result-code | tail -1`, **verify by reading the attack trace that each 0/1 is actually correct** (the tool's own output is only ground truth for regressions, not correctness), then add a `run_model` test. Explaining *why* the expected code is right in a comment at the top of the model is the house style — see `aead_replay_not_forgery.vp`.
- Golden pretty-printer files live in `examples/test/golden_pretty/` (6 of them) and are compared byte-for-byte via `include_str!`. Update them deliberately when changing the formatter.
- The engine interns names per model, but the test builders share one table (`testutil::test_value_id`), so **unit tests must still use unique constant names** (existing tests prefix names per-test, e.g. `cre3_a`, `hash_dh_b`, `mw_m`). A test that both parses a model *and* builds a value by hand must take the constant from the parsed trace via `testutil::trace_constant` — ids from the shared test table will not match the model's own.
- Every model in `examples/test/` is wired to a `run_model` test; keep it that way when you add one.

### Performance expectations

Every model in `examples/test/` runs in milliseconds, with one exception: the five `junglegym_*.vp` stress models are deliberately convoluted, and `junglegym_deep_ratchet.vp` takes roughly 1.5s on its own — it is most of the test suite's wall clock. They exist to lean on resolution, the theory descent, `normalise_arguments`, guard bypass and the unlinkability witness search all at once; each carries its expected result code and the reasoning for it in a header comment. Of the shipped real-world models, `examples/transport-layer/tls13.vp` is the slowest that completes (~1.4s); `signal.vp`, `scuttlebutt.vp`, `firefox-sync.vp`, `piknik.vp`, `cen.vp`, `lc-dp-3t.vp`, `protonmail.vp` and `userbase.vp` are all well under a second. `examples/transport-layer/needham-schroeder.vp` used to run for many minutes without resolving a query; the self-feeding replay cut in `solve/validate.rs` brings it to 0.016s. The slowest model in the tree is now `examples/messaging/signal_twelve.vp` at roughly a minute, which is 24 queries over twelve ratchet steps and is expected to be slow.

## Style and licensing

- Every source file starts with an SPDX header (`GPL-3.0-only` for code, `CC-BY-SA-4.0` for prose). Keep it on new files, including `.vp` test models.
- rustfmt with **hard tabs** and Unix newlines; clippy is a hard gate (`-D warnings`).
- The codebase leans hard on module-level `//!` docs to carry the *reasoning* — why a design choice was made, and what breaks if it is undone. `solve/mod.rs`, `solve/deduce.rs`, `witness.rs` and `primitive/spec.rs` are the best examples. Match that register when you touch them: a comment here is expected to explain the failure mode, not restate the code.
- Commit messages are short imperative summaries, usually scope-prefixed (`parser: …`, `witness: …`, `narrate: …`).

## Packaging (usually not your concern, but don't break it)

- Releases are cut with goreleaser (`.goreleaser.yml`, cargo-zigbuild, 6 targets). The repo doubles as its own Homebrew tap (`HomebrewFormula/verifpal.rb`) and Scoop bucket (`verifpal.json`) — release automation rewrites these; don't hand-edit them with code changes.
- `pkg/` is wasm-pack output (the npm package) and is untracked — wasm-pack writes a `.gitignore` with `*` into it; regenerate via `make wasm`, which also copies artifacts into the sibling checkout `../verifpal-website`. `../verifpal-manual` holds the manual source.
- `assets/releasenotes.txt` is the human-written release-notes text; `assets/email.txt` is the announcement template (`0VERSION0` is substituted at release time) and `assets/pgp.txt` the project signing key.
- `default.nix` exists for Nix users; `scripts` is a symlink to a private directory outside the repo (gitignored) — it may be broken on other machines, and nothing in the build depends on it.
