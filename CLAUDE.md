# CLAUDE.md

Repository guidance for Claude Code.

## What this is

Verifpal checks `.vp` cryptographic-protocol models for confidentiality, authentication, freshness, unlinkability and equivalence under passive/active attackers. Default: **two concurrent sessions per principal** (`--sessions k`); a hold means no attack found within that bound. One Rust crate (`verifpal` 1.6.3, edition 2024, Rust 1.98, GPL-3.0-only) builds the CLI and a WASM library for the website and VS Code. [User Manual](https://verifpal.com/docs/): language reference; `README.md`: overview; [*From Toy to Instrument: Seven Years of Verifpal*](https://eprint.iacr.org/2026/1654): language and query semantics.

**An attack is one execution.** `src/engine/` runs every session and scenario copy of every principal together as one execution under a map of attacker installs, with one attacker knowledge set belonging to that execution. A query fails only when the evaluator finds its violation in such an execution. The search (`engine/search/`, drawing candidates from `src/solve/`) only proposes install maps; it cannot record a result. Nothing reconstructs a joint history after the fact, so no gate has to decide whether one exists.

## Non-negotiable rules

**Declare primitives only in `src/primitive/spec.rs`.** `PrimitiveSpec` / `PrimitiveCoreSpec` own names, arities, outputs, restrictions, decomposition/recomposition/rewrite/rebuild/reuse, checking keys, commutativity, capabilities, core roles and documentation; the engine interprets fields. `PRIM_*` exports are test-only, and `the_engine_names_no_primitive_outside_its_spec` rejects primitive ids and quoted names in non-test engine code. If behavior seems to need an id/name check, **add a spec field and a generic interpreter**. Ask the registry for tuple, projection and equality roles too.

**Keep the design lean; do not pile fixes on top of each other.** Make the simple fix when one exists. Otherwise do not wrap a flawed component in another layer, special case or side table: when a bug shows that a component represents something wrongly or twice, redesign it so the correct behavior follows from a simpler structure, even if that means rewriting it. Prefer deleting a representation to adding one.

**The session count and `TermBound` are the only bounds on an analysis.** Never add a budget, timeout, pass cap or per-lane ceiling. Candidate generation may be narrowed only by a principled, non-numeric rule, and every such narrowing is an incompleteness source listed under Search below.

False attacks and missed attacks are equally serious. Preserve these distinctions:

- Known versus forgeable; replay versus forgery; computed versus emitted; knowledge versus constructibility versus observability.
- **An install is delivered only when the execution's own knowledge derives it at that receive** (`engine/exec.rs`, `Event::Recv`). Never admit one from another execution's knowledge, the search's union or final knowledge.
- **A forwarded value is exactly what the sender's executed send recorded** (`ex.sent[d]`). A guarded slot never takes an install; it takes the sender's value or nothing.
- Own halt, foreign halt and starvation differ. A halted run stops; a run whose next receive has neither a sent value nor an install is blocked. A run the attacker never starts does nothing: sessions are up to k, not exactly k. The attacker can also drop any value of any message its sender sent, guarded or not: the recipient keeps what arrived and continues until the first assignment, send or leak that needs a value it does not hold, and stops there (`search_selective_drop.vp`). A value never sent cannot be dropped: the recipient still waits for it (`a_value_its_sender_never_sent_cannot_be_dropped`). A failed decryption is not a value for equivalence.
- Search output is untrusted. Only `engine::judge` over an executed `Execution` reports, and only `Judge::evaluate` mints the `Verdict` that `results_put` requires.
- Simplify duplicate representations, not correctness gates. An unchanged corpus never licenses removing a gate.

The regression inventory is `src/testing/model_tests.rs` and `examples/test/`. Representative pairs (`@1`/`@2`: session count):

| invariant | regression / counterweight |
| --- | --- |
| Known is not forgeable | `aead_replay_not_forgery.vp`: `a0c0`@1, `a1c0`@2, through replays, never replacements |
| Cross-session replay breaks injectivity | `session_replay_breaks_injectivity.vp`: `a0`@1, `a1`@2; `session_peer_run_matches.vp`: `a0` |
| Histories must coexist | `incompatible_histories.vp`: `a0`; `incompatible_histories_mitm.vp`: `c1a1` |
| Reflection within one execution is an attack | `history_own_later_emission.vp`: `a1` at both counts (Bob's own box reflected back to him); `history_own_later_emission_directional.vp`: `a0` |
| Disclosure must precede every affected receive | `causal_late_leak.vp`, `causal_foreign_receive.vp`: `a0`@1, `a1`@2; `causal_foreign_receive_early.vp`: `a1` |
| Halts withhold sends and downstream computations | `halted_peer_relay_holds.vp`: `c0`; `halted_peer_relay.vp`: `c1` |
| Installs name values, not slots | `closure_cyclic_union.vp`: `c1c1c1` at both counts |
| Acceptance needs a matching emission, whatever the value | `auth_mac_reflection.vp`: `a0`@1, `a1`@2; `woolam_pi_pristine_pin.vp`: `a1a1`; `woolam_pif_pristine_pin.vp`: `a0a0`@1, `a1a0`@2 |
| Duplicate acceptance counts emissions, not honest values | `auth_static_tag_replay.vp`: `a0`@1, `a1`@2; `auth_static_tag_challenge_bound.vp`: `a0` |
| Acceptance counts runs of one agent | `four_party.vp`: `c1a0a0a0`@1, `c1a1a1a0`@2 |
| Forwarding a genuine replay is not forging | `relay_origin_authenticated.vp`: `a0`; `relay_origin_other_sender.vp`: `a1` |
| Freshness fails when two runs of an agent accept one value | `freshness_replayed_across_sessions.vp`: `f0a0`@1, `f1a1`@2; `freshness_bound_to_challenge.vp`: `f0a0` |
| A phase is judged as it stood at its barrier | `phase_claims_after_compromise.vp`: `f0e0`; `phase_claims_before_compromise.vp`: `f1e1` |
| A phase claim leaves out later steps the run reaches, not steps it never reaches | `phase_claim_ignores_later_use.vp`: `f1`; `phase_claim_never_reached_use.vp`: `a0` |
| A copy corrupt from phase N answers for its state at the end of phase N−1 | `scenario_forward_secrecy_with_honest_peer.vp`: `c1`; `_without_leak`: `c0` |
| Guards preserve upstream control | `forward_transitive_relay.vp`: `f1`; `forward_relay_all_guarded.vp`: `f0` |
| Addressed installs affect one recipient | `split_delivery_equivalence.vp`: `e1`; `split_delivery_through_relay.vp`: `e0` |
| Declaration order is not a verdict | `order_relay_declared_first.vp`, `order_relay_declared_later.vp`: `a1` at both counts |
| A forged term reveals nothing it was forged over, until its genuine copy leaks | `threshold_sign_forged_partial_keeps_share.vp`: `c0c1`; `closure_forged_then_leaked.vp`: `a1`; `closure_forged_never_leaked.vp`: `a0` |
| Weakening preserves key boundaries | `cap_forgeable_other_message.vp`: `c1`; `cap_forgeable_other_key_holds.vp`: `c0` |
| Search retains deeper terms and oracle chains | `pitoy_depth.vp`: `c0`@1, `c1`@2; `solver_oracle_chained_inputs.vp`: `a1` |
| A key the attacker can reshape is a key it can replace | `solver_wrapped_key_decomposition.vp`: `c1`; `_guarded`: `c0` |
| A key-shaped slot also takes a non-key value | `solver_key_slot_type_flaw.vp`: `a1`; `_bound`: `a0` |
| An oracle answers through the channel it seals | `solver_oracle_sealed_relay.vp`: `c1`; `_guarded`: `c0` |
| A broadcast may be replaced at some recipients only | `search_broadcast_subset.vp`: `c1`; `_guarded`: `c0` |
| Silencing a run may mean silencing its upstream | `search_idle_upstream_relay.vp`: `a1` at both counts; `search_idle_upstream_guarded.vp`: `a0` |
| The attacker drops any single value, guarded or not | `search_selective_drop.vp`: `a0`@1, `a1`@2; `_bound`: `a0`; `spore_splice_as.vp`: `c0a1`; `spore_splice_as_hwang_chen.vp`: `c0a0`; `threshold_sign.vp`: `c0c0a1`; `threshold_sign_sealed_partials.vp`: `c0c0a0` |
| A source for a disrupted honest value may fill the same input differently | `search_supplier_same_input.vp`: `a1`; `_guarded`: `a0` |
| A receive waiting only on withheld slots is starved, not stuck | `search_starved_not_stuck.vp`: `a1`; `_guarded`: `a0` |
| Disclosing a bound signature brings back a nonce-reuse forgery | `remote_aa_bound_leaked_signature.vp`: `a0`@1, `a1`@2; `epassport/remote_aa_bound_private_nfc.vp`: `a0` |
| A query-source merge may need a costlier source | `search_source_alternative.vp`: `c1`; `_guarded`: `c0`@1, `c1`@2 |
| The attacker must reveal an existing link | `unlink_forced_equality.vp`: `u0`; `unlink_active_links.vp`: `u1`; `unlink_carrier_field_not_shared.vp`: `u0` |
| A split tuple is as open as its fields | `ffgg_tuple.vp`: `c0`@1, `c1`@2; `ffgg_tuple_guarded.vp`: `c0` |
| Lowe's attack needs scenarios | `spore_ns_pk.vp`: `c1a1a0`; `spore_nsl_pk.vp`: `c0a1a0` |
| A starved oracle run is repaired | `spore_x509_three_way.vp`: `a0a0`@1, `a1a0`@2; `_named`: `a0a0` |

Pin new regressions beside a counterweight, read their traces, and test session-sensitive claims at both counts.

## Commands

**Use release mode for builds, model runs and tests.** Debug analyses are prohibitively slow.

```sh
cargo build --release
cargo test --release                         # unit + model tests
cargo test --release model_tests::           # end-to-end models only
cargo test --release test_ok                 # one test
cargo test --release -- --ignored            # exhaustive metamorphic sweeps
cargo clippy --all-targets -- -D warnings     # native CI lint
make lint                                   # native/WASM (host and wasm32) clippy + fmt check
cargo fmt                                   # hard tabs, Unix newlines
cargo check --lib --no-default-features --features wasm
cargo test --release --no-default-features --features wasm --lib wasm::
make test-tex                               # compile generated LaTeX with tectonic
make wasm                                   # build/copy website WASM
make dist-assets                            # completions + man pages
make release-dry                            # no git/network changes

cargo run --release -- verify examples/simple.vp
cargo run --release -- verify path/to/model.vp --result-code
cargo run --release -- verify path/to/model.vp --sessions 1
cargo run --release -- pretty path/to/model.vp
VERIFPAL_SOLVE_DEBUG=1 cargo run --release -- verify m.vp
```

CI runs clippy, release tests and exhaustive sweeps on Ubuntu/macOS, plus WASM clippy, **only when the commit title contains `[ci]`** or on manual dispatch. Formatting is not gated there; use `make lint`.

`verify` accepts several models. `--result-code` suppresses only the banner; read the **last line** (`| tail -1`); it cannot accompany `--format json|html|tex`. `--fail-on-attack` returns nonzero for attacks; `--auto-queries` replaces queries. Other commands: `about`, `diagram` (Mermaid), `lsp`, `completion`, hidden `man`.

For wrong active-attacker results, start with `VERIFPAL_SOLVE_DEBUG=1`: it logs each proposal round, every install map tried with its candidate family, check repairs, union growth and per-family counts to stderr, prefixed `[search]`. Errors carry source `Span`s; `.located(file_name, &model.source)` makes `Display` positional.

## Crate layout and features

```
src/lib.rs     crate root: module tree and public re-exports    main.rs  CLI    wasm.rs  WASM exports
  util/        IdMap/IdSet, text helpers, generations, lock helpers, the rayon seam (parallel.rs)
  console/     verbosity, messages, status line; colors (terminal.rs), update check (update.rs)
  syntax/      AST (ast.rs), Span/VerifpalError (error.rs), name interning (names.rs), tokens, parser/, pretty
  term/        Value/Constant/Primitive and copy ids (mod.rs), hash-consing (hashing.rs), equivalence
  primitive/   registry types and accessors (mod.rs), declarations (spec.rs), capabilities
  theory/      AttackerState (attacker.rs), reduction (rewrite.rs), decomposition, reuse, obtainability, memos
  protocol/    ProtocolTrace and resolution (trace.rs), sanity, construct, sessions, scenario, autoquery
  engine/      program, exec, knowledge, judgment, unlink, narrate, search/
  solve/       propose, goals, free positions, deduce/, symbolic, matching, vars, control, diverge
  verify/      the pipeline (mod.rs), VerifyContext, results, the verdict-recording boundary (record.rs)
  report/      structured report (mod.rs), msc, template, html/, tex/
  lsp/         language server and editor services     testing/  builders (mod.rs), model_tests, metamorphic
```

Indices are typed: `RunIdx`, `StepIdx`, `DeliveryIdx` (`engine/program.rs`), `SlotIdx` (`protocol/trace.rs`), `NodeIdx` and `AttemptIdx` (search), declared with `util::index::index_type!` and stored in `IndexVec<I, T>`; do not fall back to bare `usize` for them. Call registry and console functions module-qualified (`primitive::spec(id)`, `primitive::name(id)`, `console::message(..)`) rather than re-prefixing names with their module.

Each component's `mod.rs` declares its files and re-exports the types other components name (`crate::syntax::Model`, `crate::term::Value`). Files other components reach into are `pub(crate)` modules (`crate::syntax::parser::parse_string`); a component split for size keeps its files private, re-exports what others use (`crate::theory::obtainable`, `crate::solve::propose`) and widens to `pub(super)` only what a sibling calls. Imports within a component are relative (`super::`, a child's name), across components absolute (`crate::`). A module that is a directory keeps its unit tests in `tests.rs`; the source scans treat every `tests.rs` and `testing/` as test-only.

- Lib `verifpal` (`cdylib`, `rlib`), bin `src/main.rs` (default `cli` feature). CLI stdout uses `out!`/`outp!`, ignoring closed pipes. Engine modules are `pub(crate)`; only `lib.rs` re-exports are public. Keep `#![warn(unreachable_pub)]` / `#![forbid(unsafe_code)]`. No `tests/` directory: integration targets collide with the `cdylib`.
- Features: default `cli` (clap, colored, ureq, rayon, `lsp`); `language` (lsp-types only); `lsp` (`language`, crossbeam, lsp-server); `wasm` (`language`, wasm-bindgen, js-sys). Language items the WASM build does not use carry `cfg_attr(not(feature = "lsp"), allow(dead_code))`.
- `src/wasm.rs` holds every export; each takes and returns JSON strings and never panics on bad input. **Do not change the `wasm_verify`/`wasm_pretty` shapes.** `wasm_analyze` runs the CLI's `verify_parsed` path; `wasm_check`, `wasm_language` (LSP JSON, UTF-16 positions) and `wasm_suggest_queries` serve editors under `InfoQuiet`. On wasm32, buffered messages and a throttled status line also go to `globalThis.verifpalProgress(kind, text)` through a `catch` import. Imported JS panics natively: gate those calls on `target_arch = "wasm32"`, since the `wasm` unit tests run natively.
- `util/parallel.rs` is the sole rayon seam, with a sequential WASM twin: **change both and run the WASM check**. `map_ordered` preserves order; `VERIFPAL_THREADS=1` is sequential and must give identical results. Only the solver's pure proposal work runs on workers; execution, closure, judgment, reporting and `VerifyContext` writes stay on the caller thread.
- Analysis-scoped thread-local caches are `util::generation::AnalysisLocal`, reachable only through `with_current`, which clears the cache on first access in a new generation so ids never leak between models. Internal parallelism runs only with one live analysis (`live_generations() > 1` makes `map_ordered` sequential).

## Language essentials

See the manual for the full language and `src/primitive/spec.rs` for arities, outputs, argument restrictions and checkability. Minimal model:

```verifpal
attacker[active]
principal Alice[
    knows private k
    knows public ad
    generates m, n
    e = AEAD_ENC(k, n, m, ad)
]
Alice -> Bob: n, e
principal Bob[
    knows private k
    knows public ad
    d = AEAD_DEC(k, n, e, ad)?
]
queries[
    confidentiality? m
    authentication? Alice -> Bob: e
]
```

- `[e]` on a message guards it against replacement; `?` checks an operation and halts its principal on failure. `leaks x` discloses a known value. `_` is an anonymous output. `phase[N]` increments by exactly one.
- `queries` is required and last; an optional `scenarios[Alice[gpeer = gb] Alice[gpeer = gm]]` immediately precedes it. Queries also include `freshness? x`, `unlinkability? a, b`, `equivalence? x, y`. `[precondition[Alice -> Bob: e]]` restricts a query to executions reaching that send.
- Names are case-insensitive; principals title-case, constants lowercase. Constants cannot shadow reserved words, primitives, `attacker*` or `unnamed*`. No repeated assignment or generation, conflicting `knows`, unknown sends or already-known receives. Comments round-trip through `pretty`.
- Capabilities: `PUBKEY[weak](a)`, `SIGN[forgeable](sk, m)`, `AEAD_ENC[weak, forgeable from phase 2](k, n, m, ad)`. An onset belongs to the preceding capability and persists. `weak` exposes declared reveals; `forgeable` permits authenticity-breaking construction under its annotated secret; `malleable` reshapes a held ciphertext under an unknown key (ENC only). These words and `from` are contextual.
- `THRESHOLD_SPLIT[3](k)` binds 3-of-n shares, n being the number of outputs (2–16). Each assignment's sharing is distinct (`Primitive.instance`, shared by its session/scenario copies).

## Architecture

### Pipeline

```
parse_file (syntax/parser/)         hand-written recursive-descent, comment-preserving AST
  → expand_scenarios (protocol/)    one model copy per declared peer scenario
  → expand_sessions (protocol/)     k copies of that, one per concurrent session
  → sanity (protocol/sanity.rs)     model validation; drives protocol/construct.rs
      → construct_protocol_trace    "km": ProtocolTrace — slots with their delivery facts,
                                    and the CapabilityIndex
  → VerifyContext::new (verify/)    results, envelopes, claims, term bound
  → engine::verify (engine/mod.rs)
      → Program::of                 every copy as a straight-line run
      → execute(&[])                the honest execution; judged at once
      → check_honest_run            honest failed checks and argument restrictions are model errors
      → Search::run                 active attacker only, while queries remain
  → verify_end                      prints results, returns the results code
```

`verify::analyze` is the **one** place that sequence exists (`verify::expand` is its expansion, shared with the LSP's live check); `wasm_verify` and the LSP call it, the CLI and `wasm_analyze` reach it through `verify_parsed`. **Do not give one entry point its own default session count.** Throughout, `km` is the `ProtocolTrace`, `cx` the engine `Context` and `ex` an `Execution`.

### Program and execution (engine/program.rs, engine/exec.rs)

`Program::of` flattens the expanded model into one `Run` per principal copy: steps `Event::{Hold, Assign, Leak, Send(d), Recv(d)}` with their phases, in declaration order. A `Delivery { sender, recipient, slots: [(slot, guarded)] }` is a `Send` in its sender's run and a `Recv` in its recipient's.

`execute(cx, installs)`, with `Installs = Vec<Install>` (`Install::Value { run, slot, value }`, `Install::Idle { run }` or `Install::Drop { run, slot }`), produces one `Execution`: per-run environments of `Held { value, pre, sender, installed, authored }`, program counters, halts, recorded sends `sent[d]`, the step order, one `Knowledge`, and the configuration archived at each phase barrier (`ex.at(p)`).

- Within phase N every run advances while it can; a receive waits for its sender's send. Only when no run can move is one waiting receive whose installs are all derivable delivered, the lowest delivery first, and the loop resumes, so an upstream sender sends before a downstream receive is taken early (`an_install_its_sender_then_sends_is_not_authored`). Enabling is monotone, so this is the unique maximal execution for the install map, independent of run order: an install equal to what its sender is about to send never counts as attacker-authored.
- `Assign` reduces with `theory::can_rewrite`; a failed checked primitive halts the run. `Send` and `Leak` teach the attacker (`Origin::Wire`, `Origin::Leak`).
- `Recv`: an install enters as its reduct, since a message on the wire is its normal form; every held value is therefore reduced and the judge compares values without rewriting them (`an_install_is_delivered_as_its_reduct`: an unreduced copy of a sent ciphertext once paired with itself as a nonce reuse). An unguarded install equal to the forwarded value is not an install; any other must be `deliverable` (admissible, no failed checked rewrite inside) **and derivable from this execution's knowledge at this moment**, or the run blocks. A received value is `authored` when installed or relayed from an authored copy. An installed `Held` records the components the attacker could build it from at that receive.
- `Install::Idle` leaves its run `idle`: it never starts. `Install::Drop { run, slot }` withholds one received value from that run, guarded or not: once the sender has sent, its receive takes the other values, and the run stops at the first step that references a received slot it does not hold (`lacks`), neither halted nor waiting on anything; `freeze` classifies none of its receives.
- At a phase end, a frozen run is `stuck` at every unguarded slot of its remaining receives in that phase whose install it cannot deliver, not only at the receive it waits on, so how a flight is cut into messages cannot hide an awaited value from the search (`history_own_later_emission_split.vp`, `search_starved_not_stuck_split.vp`); the unguarded slots of an unsent delivery a run waits on are `withheld`; runs that could not finish are `frozen` for good. A receive waiting only on withheld slots is starved, not stuck, even when it also takes installs, so the search fills it rather than dropping it (`search_starved_not_stuck.vp`). Knowledge closes at each barrier.

### Knowledge (engine/knowledge.rs)

`Knowledge` wraps one `AttackerState`, an `Origin` per value (`Initial`, `Wire`, `Leak`, `Derived(DerivationRecord)`) and the protocol terms the execution saw. `close(capabilities)` is a monotone fixed point over:

1. held values: decomposition, weak reveals, `rewrite_build` and core-reveal fragments;
2. reconstruction of protocol subterms (and combine wholes for walked partials), recorded as `Reconstructed`, `Combined`, `Broken` or `ReusedForge`; the walk is per pointer and only the candidates are deduplicated by equivalence, so an equivalent DH orientation still contributes its own subterms;
3. threshold recomposition;
4. forward rewrites of protocol terms whose arguments are obtainable;
5. reuse pairs and their declared reveals.

A held value is *settled* for a rule once everything the rule could reveal from it is held, and `rewrite_build` skips a pool whose size has not changed; both are exact because knowledge only grows. A term held only by forgery, or one the attacker could mint that no principal built, is never decomposed: the forged-over secret stays hidden. A later wire or leak disclosure of a value first derived replaces its record and reopens the closure (`closure_forged_then_leaked.vp`), and so does a genuine derivation whose provenance avoids the forged value itself (`closure_forged_then_opened_later.vp`; a container built from the forgery is no genuine copy: `closure_forged_container_unsent.vp`); a container whose contents are held only as forgeries is not settled. `origins` keeps how a value was first acquired, which is what narration reads, except that a forged first record is narrated by its genuine replacement once that replacement's ingredients are in the step's knowledge prefix. Any change to what the closure reads clears `closed`. A `DerivationRecord` lists its inputs in two orders, `ingredients()` (held source first) and `recipe()` (supplied values first); search and narration each depend on theirs, so do not merge them.

**Nonce reuse pairs coexist by construction**: both members are in one execution's knowledge. A member the attacker could mint counts only if a principal built it, and `Knowledge::built` holds only the constructors an assignment applied, never a received argument (`aead_nonce_two_executions_not_a_reuse.vp`, `cap_forgeable_is_not_a_reuse_pair.vp`).

### Judgment (engine/judgment.rs, engine/unlink.rs)

`Judge { cx, ex, whole, claims }` evaluates one query against the configuration at the end of one phase (`ex.at(p)`, knowledge K_p): a claim at `p` concerns what honest runs had done by then. `claims` (`VerifyContext::claims_at`) gives the phase each run answers for: a copy honest at `p` answers for `p`; a copy corrupt from phase N ≤ `p` for the end of phase N−1, judged against K_p (forward secrecy); a copy corrupt from phase 0 for nothing, unless every copy is. `Judge::claimed(r, slot)` is the run's own `Held`, else its creator's when that creator is claimed. A precondition requires its named send to have executed in `whole`, in any phase.

- **Confidentiality:** a claimed run holds the slot and K_p holds its value. `AttackerSuppliedValue` labels a value that differs from the honest reduct and carries no fresh or private leaf.
- **Authentication:** injective agreement at the recipient run. The slot must be held with a sender and used: every slot that mentions it reached, one use succeeding or unchecked, a use failing exactly when its run halted there. A use reached only in a later phase is left out; one never reached cancels. Uses are the run's own assignments or, only when it has none, other principals' computations as sanity finds them (widening this loses Lowe's attack). An unauthored value straight from the named sender agrees. Otherwise count emissions of an equivalent value by runs interchangeable with the sender (`km.interchangeable_for`) on deliveries reaching the recipient's agent (`km.same_actor`) directly or through relays, counted only when some sender's copy is not authored. With no emission the verdict is `Substituted` for an unauthored value from another principal, else `Forged`, whatever the value. With more acceptances across the agent's runs than emissions it is `Replayed` (`DuplicateAcceptance` if the recipient contributed a fresh value, else `ReplayableFirstFlight`).
- **Freshness:** a claimed run uses a value with no fresh leaf, or a replayed value that another run of its agent also holds and uses: `Stale`. A value is replayed when it is authored or the run computed it from an authored received slot (`freshness_projected_replay.vp`, `spore_wmf.vp`).
- **Equivalence** compares the claimed values of every queried slot per claimed run; every slot must be claimed in this configuration and not a failed check.
- **Unlinkability** asks one `unlink::Linker` per query about each claimed pair; it computes what the configuration disclosed and what the attacker supplied once.

`link` rejects authored values and requires both values observable: known, and extracted from what this configuration disclosed by projection, decomposition, weakening or a held reuse pair, or a tuple of such values, or public. It collects each value's **ties**, the secret-dependent terms the attacker can connect to it: the value itself, the ingredients it can rebuild it from (a value it can only open is tied to its contents, not to the opening key: `unlink_opened_fresh_content.vp`), and the key and confirmed arguments of a runnable check. Witnesses the attacker could build from public values and what it installed anywhere (with the components it could build each install from at that receive) are rejected: a key it forced Bob to derive from its own input links nothing (`unlink_forced_key_carries_no_secret.vp`). A shared pair of ties in `strongest`'s table is a link. These predicates are not two-world equivalence. Preserve every gate:

- honest **unreduced** values must already share a secret subterm, read through projections only (`unlink_carrier_field_not_shared.vp`); equality also needs equal honest reducts;
- a non-equality witness carries a secret leaf both values honestly share, still derivable after withholding **either** queried value;
- observability needs knowledge **and** extraction, following actual reveals, never arbitrary arguments; reuse counts only while both members are held;
- checks must be runnable with every input, distinct matching positions and a successful `can_rewrite`; public identifiers identify nobody;
- every candidate passes every gate before it is ranked.

### Reporting (engine/mod.rs, engine/narrate.rs)

`judge` evaluates every unresolved query and its variants at every phase. `minimal` shrinks a violating install map, dropping one install or two on the same message while the same query still fails at the same phase with nothing stuck. The minimized configuration at that phase is narrated and recorded, so a trace never cites later-phase steps.

`Narrator` walks the step order. Before each receive that took installs it explains each installed value from the knowledge prefix that step recorded: a wire observation, a leak, a derivation step, or, when not yet recorded, a construction from available arguments or the forgery, reshaping or combination that builds it. A disclosure after that point never explains the step (`narrate_derived_before_leak.vp`). An install equal to a preceding sibling emission is a **replay** ("from another session|scenario|run"); any other is a replacement. A checked assignment that passes on authored input gets a `gate` step. Every line is also a structured `TraceStep` for JSON/HTML/TeX/LSP.

Terms use the model's vocabulary: `Names` maps values held at non-authored slots to slot names, preferring unchanged and session-1 names; a *shaped* name, whose slot holds a non-honest value, is spelled one level out when it is the subject of a construction. Words require evidence: "from another session" only for an actual sibling emission in this execution, "on the wire" only for a recorded send; never call a concurrent run "earlier".

### Search (engine/search/)

`mod.rs` holds `Search`, its records and the pass order; `rounds.rs` the proposal rounds and `idle`, `placement.rs` installs and probes, `worklist.rs` the attempt store, execution, settling and fills, `union.rs` absorption, `merge.rs` query-source merges and sibling transfers, `stuck.rs` stuck retries and fresh-emission sources, `reroute.rs` the rerouted pass.

`Search` keeps the honest execution and compact facts from each accepted candidate (a *node*): its install map, received values and queried subjects, sends, and the attacker state at each phase without derivation records. The **union** knowledge records which nodes supplied each value, and its closure feeds proposals. It also keeps the union as it stood at each earlier phase barrier, absorbed from every judged execution's archived knowledge, because a run's proposals read the union only as of the latest phase in which an install can reach it (`TraceSlot::substitution_phases`): knowledge first disclosed later can never be delivered to it. Proposing phase-0 installs from phase-1 leaks made `pqxdh.vp` run for minutes at one session and indefinitely at two. Nothing is ever delivered from the union, and node facts never stand in for an execution at the judge.

Its state is grouped: `facts` (fixed per analysis), `union`, `attempts` (the attempt store, worklist and merges done), `retries` (stuck candidates and their sources), `memo` (caches over nodes) and `log`. One depth-first worklist over a content-indexed attempt store processes candidates: execute, record halted checks, judge, absorb, queue continuations. Repeated maps reuse their outcome. Installs and node facts are hash-consed, so comparing them is a pointer check.

- **Rounds.** `fixpoint`: for every run, Targeted then Constructed proposals from `solve::propose` against a symbolic state with the union at that run's last install phase as knowledge (**all Targeted before any Constructed**; interleaving changes verdicts); then close the union, merge query sources and retry stuck candidates; stop when a round leaves the union unchanged at every phase. `run`: the fixpoint, honest-input refinement (`slots_blocking_reduction`) and, if that grew the union, the fixpoint again; then `idle`; then, when the model has a key-shaped slot, the **unshaped** pass, which repeats the fixpoint with key-shaped slot variables replaced by plain ones for every run (`solver_key_slot_type_flaw.vp`), while `shaped_var` stays because every Diffie-Hellman man-in-the-middle needs it; last, the **rerouted** pass. Split deliveries get an addressed pass.
- **Rerouted pass.** A send equal to the honest one still counts as fresh when its sender took a genuine install earlier in its run: the value no longer waits for the honest route, so it can reach a receive that the honest route reaches only after that receive (`history_own_later_emission.vp` and `scuttlebutt.vp` at one session: Bob's own box reflected back to him lets him answer before Alice has). Executions not kept that emit such sends are noted during the search with the deliveries their installs replaced. At the end, a stuck candidate waits for each stuck value, and each proper subterm of it, that the honest execution sends only at or after the stuck receive (`search_reroute_built_value.vp`); a rerouted send of that value is a source for it when one of the deliveries it bypassed is sent causally after that receive, following the delivery graph from the stuck receive (`search_reroute_third_run.vp`), and its installs are compatible with the candidate and add to it. Such sends of existing nodes are registered, noted executions with one not yet registered are re-executed and kept, and each waiting candidate is retried once with its sources. It runs last because counting rerouted sends from the start reorders this order-sensitive search: `remote_aa_bound.vp` lost its two-session attack. Appended, it can only add attacks. After it, a refill of a halted run's input that its execution cannot obtain is retried once with every execution that freshly emits that value (`supply_wants`, `search_fill_from_sources.vp`).
- **Placement.** A proposal installs at the proposing run when it receives the slot directly, else at the unguarded receivers upstream through guarded relays, within `TermBound::admits_at` (a cut notes `Truncation::TermDepth`). `bases` adds, for each needed value the union derives, the installs of the cheapest node that knows its ingredients and derives it by the phase of the receive it is installed at (`search_phase_blind_bases.vp`); a value the honest execution derives by then is taken on trust, and a flight that is then stuck is placed again with sources for it too, since the honest disclosure may come after the receive (`search_bases_after_own_leak.vp`). A value not yet derivable is allowed only when the union plus what the proposal makes principals emit derives it: an oracle chain. Unless addressed, a `shared` probe also installs the value at every other unguarded receiver of the slot, then retries without those it halted, or, only when none halted, those it froze (`search_broadcast_subset.vp`, `search_broadcast_subset_swapped.vp`); probes are judged but never absorbed.
- **Families.** `base`; `repair` (`Deducer::repair_check` rebuilds a halted check's inputs, and a proposer starved on slots the honest execution also withholds is repaired at the first check they feed: `search_starved_oracle_repair.vp`); `fill` (judged against the knowledge at the end of each receive's phase, `search_fill_phase_blind.vp`: a starved receive's withheld slots take the honest value if derivable, else nil, a session sibling's value, or the honest message rebuilt from what is derivable; at a newly halted run, diverted inputs take their derivable honest values); `drop` (single-install removals); `merge` (sibling-copy transfers and query-source merges); `stuck` (a stuck candidate retried with a node that freshly emits the stuck value, plus that node's installs in the emission's causal cone, or, for a value the honest execution derives, with the next node that installs at every input the candidate's other installs fill, derives it by the stuck receive's phase and gives a merge not yet tried, the candidate's values winning the merge: the candidate's own installs may be what stops the honest derivation, and the executions that still derive it may replace the same input differently, `search_supplier_same_input.vp`; one node per stuck install per round, so a node whose merge was already tried must not take that turn, `remote_aa_bound_leaked_signature.vp`); `cleared` (that merge without the candidate's installs in the source's cone that disagree with it: `woolam_pi_pristine_pin.vp`); `admitted` (a stuck candidate's other installs); `idle` (a node with one more run that feeds an unresolved authentication or freshness query, for every such query's slots, left unstarted (`search_idle_senders.vp`, `search_idle_freshness.vp`), or given one dropped value: of the values it receives that a step up to its relied-on send needs, the one needed last, so that it does as much as it can before it stops; the drop is skipped when the run would send or leak nothing before stopping and leaving it unstarted is also tried: `search_idle_upstream_relay.vp`, `spore_splice_as.vp`, `search_selective_drop.vp`).
- **Settle.** Every unstuck execution is judged. Its knowledge at each earlier barrier is absorbed into the union at that phase whether or not it is kept. It is kept when it teaches the union something: a value it cannot obtain, a principal emission within the term depth, a reuse pair, a fresh emission or an alternative non-honest route. **No caps on kept alternatives** (`matching_run_recipient_halt.vp`).
- **Projection.** Install maps keep only the receives that can affect pending queries: every send's and leak's input history, queried holders' prefixes (whole runs for authentication and freshness, since later unreached uses cancel), and creators' prefixes for unlinkability (`removing_inputs_after_relevant_actions_preserves_query_violations`).
- **Query-source merges** target a value the union derives but no node knows (for unlinkability, the queried values' secret-bearing arguments). The holder with the fewest installs is the context; the plan is the first compatible choice of one source per derivation leaf, cheapest first, backtracking over conflicts (`search_source_alternative.vp`).

**Narrowings.** Each is principled, non-numeric and an incompleteness source; revisit them before widening anything else. A run's proposals see only the union as of its last install phase, so a value first learned in a later phase is never proposed to it, not even as a stuck candidate awaiting a source; constructed held replacements are protocol terms with the honest value's constructor; `repair` follows only Targeted proposals; a blocked `fill`, `stuck`, `cleared` or `admitted` candidate is dropped, so stuck retries never cascade; a query-source merge uses one context per target, once, with the first compatible plan; rounds end when the union stops growing; the rerouted pass runs once; a halted run's refill from another execution's emission is tried once, after it; Targeted goals exist only for the queries asked, so what the union learns, and therefore whether another query's attack is found, can depend on the query set; an opened tuple has one width, the narrowest covering the projections visible in that equation system, so a projection of a wider index met in a later, separate unification cannot widen it; `idle` drops one value per relied-on sender, the one needed last before its relied-on send, so a silencing that needs two drops, or an earlier stop, is not tried (every drop candidate of every received value made `inspect_ca.vp` seven times slower through the fills of the runs it starves). Each was introduced because its wider form ran for hours on models in the suite.

### Solver (src/solve/)

The solver generates candidates. It never sees an execution and only ever outputs install maps.

- `control.rs`: `Controllable` (the slots the attacker can replace in a phase; only this module mints it), `TermBound` (protocol depth plus recipient peel depth; partial deductions check a conservative lower bound) and `attacker_authored`.
- `symbolic.rs` replaces controllable wires with variables and reduces like the executor, rejecting self-created, wrong-phase, unused and nil slots (equivalence-named slots waive unused). `build_addressed` handles a direct delivery also sent to another recipient by a different sender.
- `vars.rs`: `VariableId`s live outside the constant namespace; free variables come from per-lane namespaces whose counters grow without ceiling. An ungrounded variable is not an admissible message. `matching.rs`: one-way matching, two-way unification and merge modulo commutativity; **retain every alignment until all equations succeed**; reject occurs cycles.
- `constraint_goals` propagates check equations across a whole constraint group before solving wire values (`solver_mac_then_tuple.vp`). Besides each principal's last check, each send, leak and query declaration, every check of a non-creator that mentions an authentication or freshness subject ends a group, since positional acceptance counts a value that passes the uses before a later failing check (`auth_accept_then_halt.vp`, `freshness_accept_then_halt.vp`).
- `deduce/` (`mod.rs`: the goal loop and its memo; `rules.rs`, `shapes.rs`, `decomposition.rs`, `combination.rs`, `inversion.rs`, `checks.rs`) tries held values, variables, replay, two-way wire unification (`solver_reflected_request.vp`), oracles, rewrite matching, argument construction, decomposition and check inversion. **A position that must have a registry shape is solved for that shape rather than refused**: commuted, blocked-decomposition and check-input shapes (`solver_wrapped_key_decomposition.vp`, `solver_sealed_share_substitution.vp`). A constructed goal solves first the arguments in which a variable sits under a primitive that constrains its shape (a rewrite, a projection, an equality or a commutative constructor), then those that merely carry variables, where `nil` serves (`solver_kem_shape_before_carrier.vp`). An equation that fails at a projection of an unbound variable opens that variable into a tuple of fresh fields as wide as its widest projection, and substitution projects tuples, so two fields of one split tuple unify like two slots (`solver_threshold_key_alignment_tuple.vp`, `ffgg_tuple.vp`, `solver_unblind_bindings_tuple.vp`). Goal memos are keyed by the goal and every binding it can read; never cache cycle-cut results. A ground goal the attacker already obtains is answered directly, and decomposition skips wire terms whose reveals can never have the goal's head. `tuple_shapes` offers the narrowest, the honest and every held tuple arity (`solver_split_prefix_replay.vp`). An oracle input is unified with its required shape before that shape is proven constructible; oracle and projection inversion accept goals outside the protocol basis.
- Free positions (`free.rs`) take protocol terms only (`keyed_free`, `preserved_free` preferring a held honest value before the attacker's key, `rekeyed_free` taking the attacker's key at key positions and held honest values elsewhere (`forged_statement_rebuilt_secret_only.vp`), `aligned_held_free`, `swapped_free` at reuse-pinned positions); arbitrary held terms inflate the basis.
- `propose` (`propose.rs`, goals in `goals.rs`): query goals, constraint goals, oracle input goals (another principal's check shapes unified with this principal's emissions, or with what decomposing them reveals: `solver_oracle_sealed_relay.vp`; their free positions stay open for the free-position policy and for repair: `eac_bac_unbound_tuple.vp`), blanket and single-slot substitutions, then Constructed sibling flights (every slot from one sibling session, and each message on its own when a run's variable slots come from several: `search_message_replay.vp`), held replacements and rewrite candidates. Proposals are deduplicated by canonical slot bindings before free positions are expanded, so different repair possibilities survive even when grounding gives the same install map; an executed map keeps its own halt positions, since a filled execution cannot stand in for the original proposal's halt. Do not give the attacker shapes it did not derive.

### Sessions and scenarios (protocol/sessions.rs, protocol/scenario.rs)

`expand_scenarios` then `expand_sessions` clone principal and message blocks before sanity, sharing `sessions::ModelCopy`. Fresh and assigned constants become `c#s` (session) or `c@k` (scenario); `knows` constants stay shared; `s*k <= 31`. Original queries cover session 1; variants share `query_index`. `km.session_siblings`/`copy_siblings` group a constant's copies and `km.interchangeable`/`actors` group principal copies. Copies are runs, not agents: match recipients by agent and senders per slot.

A scenario entry rebinds one principal's `knows` values throughout that principal, as a whole-model configuration; entries are not a cross product. Reject undeclared and wire targets. Repeated entries are legal.

- `corruption` dates each scenario from the engine's own knowledge: it expands the scenarios in declared order at one session, runs `sanity` and the honest `execute`, and finds the first phase barrier whose knowledge obtains any of the binding's key material: the bound value as the bound principal holds it when the target is `knows private` (unless it is a public key: `a_public_key_bound_to_a_private_target_is_not_key_material`), and every argument at a registry secret position, whole, never leaf by leaf (`scenario_corrupt_inline_key_half_leaked.vp`). There is no second model of disclosure: a bound key the attacker reads on the wire, a public constant or recomposed shares all count (`scenario_corrupt_by_bound_key_on_wire.vp`, `scenario_corrupt_by_public_constant.vp`, `scenario_corrupt_by_recomposed_shares.vp`). Query variants cover scenarios honest at phase 0, or every scenario when none is.
- `check_honest_run` reports an honest creator's failed check as a model error; a corrupt creator just halts (`scenario_corrupt_at_late_check.vp`). Reading only the honest execution's least halt suffices because a run blocks solely behind an earlier halt in its own copy and corruption covers a whole copy from one phase on: keep both true or check unreached slots too.

**Do not add scenario-free variants to `examples/`.**

### Verdicts and auto-queries

`VerifyResult` carries `Envelope { sessions, truncations }`, printed after PASS (`[search exhausted at 2 sessions]`, `[search truncated: term depth]`) and serialized as `QueryReport.envelope`; `Truncation::TermDepth` attaches to queries unresolved when first met. FAIL may carry `Subtype::{AttackerSuppliedValue, DuplicateAcceptance, ReplayableFirstFlight}`. Declared weakening assumptions come from the source model (`capability::declared_assumptions`), one row per capability at its earliest onset; never render the `CapabilityIndex`.

**"Exhausted" means this engine's search space at these parameters, never absence of attacks.** Do not call results "proof", "verified", "correct" or "complete". Agreement between adjacent session counts says nothing about higher ones (a 4-of-4 threshold secret needs four concurrent runs); there is no saturation mode.

`--auto-queries` **replaces** queries after sanity: confidentiality for each fresh or private constant, authentication for each delivery used in a recipient primitive, freshness for each sent-and-used constant.

### Core data model (term/, syntax/ast.rs, theory/attacker.rs)

- `Value = Constant | Primitive(Arc) | Variable(VariableId)`; constants are model-interned ids (nil = 1). **Equivalent values must have equal hashes.** Registry commutativity drives equivalence, hashing and matching.
- **Terms are DAGs.** Memoize transformations by `Arc` pointer and comparisons by pointer pair; never walk a term as a tree. Never prune by hash: equivalent DH terms hide distinct subterms.
- A `Primitive` is an immutable `Application` (id, arguments, output, threshold, instance, check, capabilities) behind `Deref`, plus a `HashCell` caching its hash, variable presence and `can_rewrite` result. Fields cannot be assigned: `with`, `with_arguments` and `with_output` build a changed copy with an empty cache, while a plain clone keeps the hash.
- `term::hashing::hashcons` is the one analysis-scoped hash-consing table; its identity is structural, capabilities and every constant field included. Trace resolution, the executor, the search and the theory canonicalize the terms they build, so memos and equality checks hit across executions.
- **Capabilities do not affect term identity**: read `km.capabilities`, never a deduped held term.
- There is no per-principal state: sanity and the solver read `km` plus a `PrincipalId`; runtime state lives only in executions.
- `AttackerState = { current_phase, known, known_map, derivations, reused, chain }`. **Length-keyed memos need chain identity**: every learn and phase change mints a new `chain`.

### Equational theory (theory/)

`theory/` interprets the registry. `can_rewrite` (`rewrite.rs`) is the sole reducer (arguments, rebuild, combine, then rewrite) and reports a failed outer check with its arguments reduced. `obtainable` (`obtain.rs`) is the common argument-recovery cascade, memoised within a `DeductionMemo` scope; a search node keeps a `SavedMemo` for its knowledge at each phase. Decomposition returns a **set** of reveals covering everything the legitimate holder learns (`KEM_ENCAP` reveals the secret **and** the randomness).

- Rewrite matching is a **bijection** onto distinct inner positions (`ringsign_ring_collapse.vp`).
- `can_reconstruct_primitive` refuses irreducible core applications. A failing unchecked application is an ordinary value; a failing checked one is not, since its run halts.
- **No recursion cap**: rewrite results are subterms or rebuilt strict subterms.
- Weakening: `weak` covers the term an annotated call computes in the execution, not only its honest term: each `Knowledge` indexes the annotated terms its assignments computed (`cap_weak_executed_term.vp`). `forgeable` needs no source application; `weak` and `malleable` do (`malleable_source` picks an eligible held ciphertext, or time-travel forgery appears). A capability exemption **adds** an option and keeps the solved alternatives. Constructibility concerns the **reduct** (`solver_constructible_reduct.vp`).
- **AEAD nonces:** `ReuseRule { fixed: [0, 1], reveals: [Argument(2)], forgeable: [0, 1] }`. Two non-equivalent held ciphertexts with equal key and nonce form a pair: both plaintexts are learned (a deliberate over-approximation) and forgery under the pair is allowed. Decryption needs key **and** nonce. `knows` nonces are session-shared, `generates` nonces fresh (`aead_nonce_reuse_sessions.vp`: `c0`@1, `c1`@2).
- **Threshold (FROST):** `THRESHOLD_SPLIT[t](k)` deals shares; `THRESHOLD_SIGN(share, nonce, commitments, message)` makes a partial; `THRESHOLD_JOIN` combines distinct projections of one sharing, with agreed fields and committed nonces, into a SIGN or PUBKEY. Reusing a share and nonce across two partials, or disclosing a partial's nonce, commitments and message, reveals the share. A share of an assignment's sharing is obtainable only by interpolation, from `t` other shares or from the secret and `t`−1 other shares: the secret alone fixes no share (`threshold_secret_reveals_no_share.vp`). Model dealer channels as confidential and authenticated, and DKG as a principal splitting a fresh key it never otherwise uses. Lowering a threshold cannot lose attacks.

Add a primitive with `build_primitive_specs` (core entries: `build_core_specs`, `core_rule_*`), then add model tests.

### Result-writing boundaries (verify/record.rs::tcb_tests)

Source-level tests pin these boundaries; they do **not** prove evaluator correctness. `results_put` requires a `Verdict` token that only `Judge::evaluate` constructs and only `engine::report` records. The evaluator is handed one `Execution`, never `VerifyContext`, and executions come only from `execute`, called by the root run, the minimizer, the search and scenario corruption dating (which only reads knowledge). The receive arm gates installs on derivability, and a receive without an install takes the sender's recorded send. Adding a query kind must update `Judge::evaluate`, `Violation`, `report` and `goals_for_query`.

### Supporting modules

- `syntax/parser/` preserves comments and indexes tokens even for failed parses. `syntax/pretty.rs` is pure, idempotent, golden-tested and **not sanity-gated**; it owns AST `Display`.
- `console/update.rs` makes the sole outbound request (GitHub tags), only when stdout is a terminal.
- `lsp/`: stdio server, debounced worker analysis, documents keyed by URI, no filesystem access. **Both threads set Silent verbosity**, or thread-local output corrupts stdout. Keyword prose lives in `lsp/docs.rs`; primitive docs come from specs.
- `report/mod.rs` builds JSON/HTML/TeX/LSP from one `Run::of` parse; renderers never parse and share its derived facts and `msc::Chart`. **No HTML/LaTeX markup in Rust**: embed templates; `Val::Text` escapes, `Val::Raw` does not. The LaTeX preamble lays out and paginates charts itself. Preserve the no-proof disclaimer. Bless goldens with `VERIFPAL_BLESS_HTML`/`VERIFPAL_BLESS_TEX`; `VERIFPAL_TECTONIC=1` compiles them.
- **Do not add `Span` to `Constant` or process-global mutable state.**

## Testing conventions

- Unit tests are module-local; shared builders live in `src/testing/mod.rs` (unique constant names per test; `trace_constant` after parsing). End-to-end: `run_model("foo.vp", "c0a1")` at two sessions, `run_model_sessions(path, 1, code)`, `run_model_err(path, substring)`, and `run_model_at` outside `examples/test/`.
- Codes follow query order (`c/a/f/u/e`; `0` holds, `1` attack). For each regression obtain `--result-code | tail -1`, **read the trace to justify every bit**, wire its test and write its `// Expected:` header. Pretty goldens live in `examples/test/golden_pretty/`.
- Engine changes need before/after **full-output** diffs over `examples/` at one and two sessions, not just codes. **Always exclude `tls13.vp`, `pqxdh.vp` and `signal_twelve.vp`** from sweeps and benchmarks.
- `attack_traces_keep_their_shape_and_name_only_wires_that_exist` sweeps `examples/test/` and selected other models at both counts: `// Expected:` headers must match, the count of undocumented models is a ratchet, every attack carries a trace, and every replaced or replayed slot must be one an unguarded message carries to that recipient.

### Metamorphic harness (src/testing/metamorphic.rs)

Missed attacks show up under language-preserving or monotone transforms: parse → transform → `pretty_model` → **re-parse** → `analyze_sessions`, from one-session baselines.

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

- `KNOWN_MISSED_ATTACKS` and `KNOWN_BAD_TRACES` are **empty ratchets**, failing for new violations and for exercised entries that stop violating.
- **Do not add `name_intermediate`**: naming a subterm can legitimately change a verdict (`auth_with_signing_false-attack.vp`). Check a claimed metamorphic false attack against the pinned semantics before changing the engine.
- Analyses run to completion: **no timeouts or deferrals**. `VERIFPAL_METAMORPHIC_WORKERS` caps workers (default 4) and `VERIFPAL_METAMORPHIC_PROGRESS=1` logs progress. Fast sweeps omit `COSTLY_MODELS`; the ignored `_exhaustively` twins cover them in CI.

### Completeness audits

Changing candidate generation, union absorption, memos or ordering changes what the search finds; re-measure rather than cite old numbers. Sensitive sites: key-shaped slot variables and the unshaped pass, Targeted-before-Constructed order, tuple arities, free-position filling, goal memo keys, which executions are kept, and the narrowings above. Authentication's positional acceptance is specified semantics, not a bookkeeping bug: changing it needs a semantics decision. Increasing sessions must never lose an attack; compare two- against three-session attacks.

## Style and licensing

- Every source file starts with an SPDX header (`GPL-3.0-only` for code, `CC-BY-SA-4.0` for prose), including `.vp` test models.
- rustfmt with **hard tabs** and Unix newlines; clippy is a hard gate (`-D warnings`).
- **Do not write comments.** Reasoning belongs in the commit message and in this file, where it cannot drift silently against the source. `protocol/sessions.rs` keeps a module-level doc and `solve/free.rs` and `solve/deduce/rules.rs` a few item-level docs from before that rule; add none, including to code touched in passing. `.vp` test models are the exception: a new one must carry a `// Expected:` header arguing its code.
