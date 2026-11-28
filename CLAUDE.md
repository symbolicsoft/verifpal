# CLAUDE.md

Repository guidance for Claude Code.

## What this is

Verifpal checks `.vp` cryptographic-protocol models for confidentiality, authentication, freshness, unlinkability and equivalence under passive/active attackers. Default: **two concurrent sessions per principal** (`--sessions k`); a hold means no attack found within that bound. One Rust crate (`verifpal`, edition 2024, Rust 1.98, GPL-3.0-only) builds the CLI and a WASM library for the website and VS Code. [User Manual](https://verifpal.com/docs/): language reference; `README.md`: overview; [*From Toy to Instrument: Seven Years of Verifpal*](https://eprint.iacr.org/2026/1654): language and query semantics.

**An attack is one execution.** `src/engine/` runs every session and scenario copy of every principal together as one execution under a map of attacker installs, with one attacker knowledge set belonging to that execution. A query fails only when the evaluator finds its violation in such an execution. The search (`engine/search/`, drawing candidates from `src/solve/`) only proposes install maps; it cannot record a result. Nothing reconstructs a joint history after the fact, so no gate has to decide whether one exists.

## Non-negotiable rules

**Declare primitives only in `src/primitive/spec.rs`.** `PrimitiveSpec` / `PrimitiveCoreSpec` own names, arities, outputs, restrictions, decomposition/recomposition/rewrite/rebuild/reuse, checking keys, commutativity, capabilities, core roles and documentation; the engine interprets fields. `PRIM_*` exports are test-only, and `the_engine_names_no_primitive_outside_its_spec` rejects primitive ids and any registry name written as a whole word in non-test engine code; `PRIMITIVE_NAMED_OUTSIDE_ITS_SPEC` counts the help-text examples that remain and fails when one is added or goes stale. If behavior seems to need an id/name check, **add a spec field and a generic interpreter**. Ask the registry for tuple, projection and equality roles too. A lookup by another primitive's id (`rewriting`, `combines_from`, `combines_into`, `is_tuple`) reads a table inverted once (`INVERSE`), never a scan of every spec: these sit under the closure's innermost loop, and scanning the 256 slots on each call cost up to a quarter of the runtime of `pace.vp` and `inspect_ta.vp` at two sessions.

**Keep the design lean; do not pile fixes on top of each other.** Make the simple fix when one exists. Otherwise do not wrap a flawed component in another layer, special case or side table: when a bug shows that a component represents something wrongly or twice, redesign it so the correct behavior follows from a simpler structure, even if that means rewriting it. Prefer deleting a representation to adding one.

**The session count and `TermBound` are the only parameters that bound an analysis.** Never add a budget, timeout, pass cap, per-lane ceiling or any other tunable limit: no work is cut off because a count or a clock ran out, and a result is a function of the model and those two parameters alone, never of the machine, the thread count or the time taken. Candidate generation may still be narrowed, and a narrowing is a bound in effect: several fix a small arity by design (one freed slot per extension, one context per merge target, two routes joined, a pass that runs once). Admit one only when it is a rule about the structure of the candidates a family builds, its wider form was measured on a named model, and both that cost and what it no longer tries are recorded under Narrowings in Search. Every narrowing is an incompleteness source.

**False attacks and missed attacks are equally serious.** Preserve these distinctions:

- Known versus forgeable; replay versus forgery; computed versus emitted; knowledge versus constructibility versus observability.
- **An install is delivered only when the execution's own knowledge derives it at that receive** (`engine/exec.rs`, `Event::Recv`). Never admit one from another execution's knowledge, the search's union or final knowledge.
- **A forwarded value is exactly what the sender's executed send recorded** (`ex.sent[d]`). A guarded slot never takes an install; it takes the sender's value or nothing.
- Own halt, foreign halt and starvation differ. A halted run stops; a run whose next receive has neither a sent value nor an install is blocked.
- A run the attacker never starts does nothing: sessions are up to k, not exactly k.
- The attacker can drop any value of any message its sender sent, guarded or not: the recipient keeps what arrived and continues until the first assignment, send or leak that needs a value it does not hold, and stops there. A value never sent cannot be dropped: the recipient still waits for it (`a_value_its_sender_never_sent_cannot_be_dropped`).
- A failed checked operation is not a value for equivalence; an unchecked one that fails is an ordinary value (`equiv_aead_ad_mismatch.vp`).
- Search output is untrusted. Only `engine::judge` over an executed `Execution` reports, and only `Judge::evaluate` mints the `Verdict` that `results_put` requires.
- Simplify duplicate representations, not correctness gates. An unchanged corpus never licenses removing a gate.

**Each invariant is stated once, beside its mechanism, with the models that pin it.** The regression inventory is `src/testing/model_tests.rs` and `examples/test/`; result codes live there and in each model's `// Expected:` header, where tests check them, so this file quotes none. In a citation, the models before a slash show the invariant and those after it are their counterweights; a semicolon starts another pair; `_x` names the full model name before it with `_x` appended. Pin new regressions beside a counterweight, read their traces, and test session-sensitive claims at both counts.

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

- Lib `verifpal` (`cdylib`, `rlib`), bin `src/main.rs` (default `cli` feature). CLI output goes through `out!`/`outp!` (stdout) and `err!` (stderr), which ignore closed pipes. A usage error exits 1: status 2 means an attack under `--fail-on-attack`. Engine modules are `pub(crate)`; only `lib.rs` re-exports are public. Keep `#![warn(unreachable_pub)]` / `#![forbid(unsafe_code)]`. No `tests/` directory: integration targets collide with the `cdylib`.
- Features: default `cli` (clap, colored, ureq, rayon, `lsp`); `language` (lsp-types only); `lsp` (`language`, crossbeam, lsp-server); `wasm` (`language`, wasm-bindgen, js-sys). Language items the WASM build does not use carry `cfg_attr(not(feature = "lsp"), allow(dead_code))`.
- `src/wasm.rs` holds every export; each takes and returns JSON strings and never panics on bad input. **Do not change the `wasm_verify`/`wasm_pretty` shapes.** `wasm_analyze` runs the CLI's `verify_parsed` path; `wasm_check`, `wasm_language` (LSP JSON, UTF-16 positions) and `wasm_suggest_queries` serve editors under `InfoQuiet`. On wasm32, buffered messages and a throttled status line also go to `globalThis.verifpalProgress(kind, text)` through a `catch` import. Imported JS panics natively: gate those calls on `target_arch = "wasm32"`, since the `wasm` unit tests run natively.
- `util/parallel.rs` is the sole rayon seam, with a sequential WASM twin: **change both and run the WASM check**. `map_ordered` preserves order; `VERIFPAL_THREADS=1` is sequential and must give identical results, and a pool that cannot be built is the same as one thread. Only the solver's pure proposal work runs on workers; execution, closure, judgment, reporting and `VerifyContext` writes stay on the caller thread.
- Analysis-scoped thread-local caches are `util::generation::AnalysisLocal`, reachable only through `with_current`, which clears the cache on first access in a new generation so ids never leak between models. Internal parallelism runs only with one live analysis (`live_generations() > 1` makes `map_ordered` sequential); every live check of the language server and every editor export is a generation of its own, so the term table never outlives a document's text (`a_live_check_starts_from_an_empty_term_table`).

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

`verify::analyze` is the **one** place that sequence exists; `wasm_verify` and the LSP call it, the CLI and `wasm_analyze` reach it through `verify_parsed`. `verify::check` is the same sequence stopped after `check_honest_run` (`engine::check`), and it is what the LSP's live check and `wasm_check` run, so an editor rejects exactly what `verify` rejects before searching. **Do not give one entry point its own default session count.** Throughout, `km` is the `ProtocolTrace`, `cx` the engine `Context` and `ex` an `Execution`.

### Program and execution (engine/program.rs, engine/exec.rs)

`Program::of` flattens the expanded model into one `Run` per principal copy: steps `Event::{Hold, Assign, Leak, Send(d), Recv(d)}` with their phases, in declaration order. A `Delivery { sender, recipient, slots: [(slot, guarded)] }` is a `Send` in its sender's run and a `Recv` in its recipient's.

`Program` is the model of who receives what that execution, the solver and the search read. It also keeps:

- `order`, the order in which the model declares its steps, a schedule in which every receive follows its send;
- per slot, the runs that receive it unguarded (`receivers`) and those it is forwarded to from there (`carriers`);
- `points`, `receipt` and `install_phase`, from which the solver's view, its control facts and the phase a run's proposals read all come.

`ProtocolTrace` keeps declaration facts (`sent_by`, `known_by`, `declared_at`, and `mutatable_to` for the judge's cross-principal uses) for sanity, auto-queries and the language server.

`execute(cx, installs)`, with `Installs = Vec<Install>` (`Install::Value { run, slot, value }`, `Install::Idle { run }` or `Install::Drop { run, slot }`), produces one `Execution`: per-run environments of `Held { value, pre, sender, installed, authored, fed }`, program counters, halts, recorded sends `sent[d]`, the step order, one `Knowledge`, and the configuration archived at each phase barrier (`ex.at(p)`).

- **Scheduling.** Within phase N every run advances while it can; a receive waits for its sender's send. Only when no run can move is one waiting receive whose installs are all derivable delivered, the lowest delivery first, and the loop resumes, so an upstream sender sends before a downstream receive is taken early (`an_install_its_sender_then_sends_is_not_authored`). Enabling is monotone, so this is the unique maximal execution for the install map, independent of run order: an install equal to what its sender is about to send never counts as attacker-authored.
- **`Assign`** reduces with `theory::can_rewrite`; a failed checked primitive halts the run. A checked assignment is one check although each output is its own step: its first output also evaluates the later ones, and when any fails the run halts there. Its `Halt` keeps the failing application apart from the environment, for the honest-run error, so no output of a failed checked assignment is held, used or read by any query, even when an unchecked copy of the same failing application is disclosed (`split_checked_partial_output.vp` / `_full`; `failed_check_output_not_disclosed.vp` / `failed_check_output_disclosed.vp`; `unlink_failed_check_output.vp` / `_unchecked`).
- **`Send` and `Leak`** teach the attacker (`Origin::Wire`, `Origin::Leak`), except an authored value: the attacker built it, so relaying it discloses nothing, and a minted copy a principal relays is no disclosure of the principal's term (`an_authored_relay_discloses_nothing`). Every disclosure is recorded with its phase, the installs it was computed from (`Held.fed`, as `Need`s) and the install receives causally before it (`RunState.past`, carried along forwarded messages): the execution's own knowledge takes it as it is, and every world built from the disclosures asks whether it could exist there (Knowledge, below).
- **`Recv`.**
  - An install enters as its reduct, since a message on the wire is its normal form; every held value is therefore reduced and the judge compares values without rewriting them (`an_install_is_delivered_as_its_reduct`: an unreduced copy of a sent ciphertext once paired with itself as a nonce reuse).
  - An unguarded install equal to the forwarded value is not an install. Any other must be `deliverable` (admissible, no failed checked rewrite inside) **and derivable from this execution's knowledge at this moment**, or the run blocks.
  - A received value is `authored` when installed or relayed from an authored copy. `fed` names the receives whose installs a value was computed from: the receive itself when installed, the sender's when forwarded, and for an assignment those of every slot it reads.
  - An installed `Held` records the components the attacker could build it from at that receive, and with them the components of every install a component rests on, when the attacker holds that component only as a principal's output over an earlier install.
- **`Install::Idle`** leaves its run `idle`: it never starts.
- **`Install::Drop { run, slot }`** withholds one received value from that run, guarded or not: once the sender has sent, its receive takes the other values, and the run stops at the first step that references a received slot it does not hold (`lacks`), neither halted nor waiting on anything; `freeze` classifies none of its receives (`search_selective_drop.vp` / `_bound`; `spore_splice_as.vp` / `spore_splice_as_hwang_chen.vp`; `threshold_sign.vp` / `threshold_sign_sealed_partials.vp`).
- **Phase end.**
  - A frozen run is `stuck` at every unguarded slot of its remaining receives in that phase whose install it cannot deliver, not only at the receive it waits on, so how a flight is cut into messages cannot hide an awaited value from the search (`history_own_later_emission_split.vp`, `search_starved_not_stuck_split.vp`).
  - The unguarded slots without an install of every unsent delivery a waiting run receives before its next send or leak are `withheld`, so a fill covers a reply however it is cut (`search_fill_split_reply.vp` / `_tagged`).
  - A receive waiting only on withheld slots is starved, not stuck, even when it also takes installs, so the search fills it rather than dropping it (`search_starved_not_stuck.vp` / `_guarded`).
  - Runs that could not finish are `frozen` for good, and knowledge closes at each barrier.

### Knowledge (engine/knowledge.rs)

`Knowledge` wraps one `AttackerState`, an `Origin` per value (`Initial`, `Wire`, `Leak`, `Derived(DerivationRecord)`) and the protocol terms the execution saw. `close()` is a monotone fixed point, under the execution's own capability index, over:

1. held values: decomposition, weak reveals, `rewrite_build` and core-reveal fragments;
2. reconstruction of protocol subterms (and combine wholes for walked partials), recorded as `Reconstructed`, `Combined`, `Broken` or `ReusedForge`; the walk is per pointer and only the candidates are deduplicated by equivalence, so an equivalent DH orientation still contributes its own subterms;
3. threshold recomposition;
4. forward rewrites of protocol terms whose arguments are obtainable;
5. reuse pairs and their declared reveals, a masked reveal field by field, each field only while the aligned field of another member's masked argument is obtainable.

A held value is *settled* for a rule once everything the rule could reveal from it is held, and `rewrite_build` skips a pool whose size has not changed; both are exact because knowledge only grows. Any change to what the closure reads clears `closed`.

**Genuineness.**

- A term the attacker could mint that no principal built is never decomposed.
- One a principal built and the attacker could also mint is decomposed only when it was disclosed directly or is *genuine*: the closure of the direct disclosures derives it with that one term unforgeable (`CapabilityIndex::without_forging`), every route at once. The forged-over secret therefore stays hidden whenever every route to the term passes through its own forgery (`closure_forged_then_opened_later.vp`, `threshold_sign_forged_partial_keeps_share.vp`), and a container built from the forgery is no genuine copy (`closure_forged_container_unsent.vp`).
- The check runs when the closure reaches its fixed point with such a term still unopened, and a proof reopens the closure.
- A proof closes a world of its own, and inside that world another such term needs a proof of its own, with both terms unforgeable. A world depends only on the direct disclosures, the protocol terms, the built terms, the annotations, its scope and the set of terms held unforgeable, so `Knowledge` keeps the worlds it has closed, keyed by that set and scope (`Proofs`), and drops them whenever one of the others changes (`reopen`).
- **A world admits a disclosure computed from installs only where each install could be supplied at its own receive** (`Knowledge::admit`, `supplies`): the installed value must be obtainable in the same world scoped to the disclosures of that receive's phase or earlier that are not causally after it (`Scope`), a fixed point from below. This is the executor's delivery rule asked of the world, without the executor's order: a genuine copy sent in the same phase by a run that did not need the receive counts, whichever was declared first (`closure_forged_echo_same_phase_container.vp`), one sent in a later phase or only because the receive happened does not (`closure_forged_echo_late_container.vp`; `closure_forged_echo_causal_container.vp`, which holds at one session only). So a principal's echo of the attacker's own forgery is no genuine copy (`closure_forged_echo_container.vp` / `_leaked`; `closure_forged_echo_identity.vp` / `_leaked`), and a principal's computation over an input the attacker could supply is (`closure_forged_oracle_output.vp` / `_guarded`; `closure_forged_oracle_nested_proof.vp`). A disclosure counts as direct, for opening without a proof, only when it rests on no install.
- Nested proofs reach one set in every order, and every closure of an execution asks again about the terms it could not prove: closing a world per request ran `relay_rewrap_oracle.vp` for 19 s at two sessions instead of 0.2 s.
- **Never decide genuineness from recorded routes.** One record per value depends on rule and disclosure order, misses later genuine routes, cycles, and is never checked on a first derivation or a reuse reveal (`closure_forged_genuine_route_late.vp`, `closure_forged_genuine_route_early.vp`, `closure_forged_key_leaked.vp`, `closure_forged_container_rebuilt.vp`, `closure_forged_cyclic_records.vp` / `closure_forged_genuine_route_absent.vp`, `closure_forged_key_opens_itself.vp`, `closure_forged_reuse_bypass.vp`).
- A later wire or leak disclosure of a value first derived replaces its record and reopens the closure (`closure_forged_then_leaked.vp` / `closure_forged_never_leaked.vp`); no other record is ever replaced.

**Records and narration.**

- `origins` keeps how a value was first acquired, which is what narration reads.
- A genuine term is narrated inside the closure that proves it, rebuilt from the disclosures in the step's knowledge prefix, only where a step opens it (a held input of its record: what is decomposed, broken, split or paired); as a supplied argument its own record serves, normally its forgery (`narrate_cycle_through_genuine_partial.vp`).
- A record that cycles back to a value still being explained is narrated by construction, and a construction that reaches the same value again stops.
- A `DerivationRecord` lists its inputs in two orders, `ingredients()` (held source first) and `recipe()` (supplied values first); search and narration each depend on theirs, so do not merge them.

**Nonce reuse pairs coexist by construction**: both members are in one execution's knowledge. A member the attacker could mint counts only if the attacker holds a principal's copy, by the same test decomposition applies: built, and disclosed directly or genuine (`cap_forgeable_unsent_reuse_member.vp`, `threshold_sign_forged_unsent_reuse_member.vp`, `cap_forgeable_echoed_reuse_member.vp`, `_late` / `cap_forgeable_sent_reuse_member.vp`, `threshold_sign_forged_sent_reuse_member.vp`). `Knowledge::built` holds only the constructors an assignment applied, never a received argument (`aead_nonce_two_executions_not_a_reuse.vp`, `cap_forgeable_is_not_a_reuse_pair.vp`).

### Judgment (engine/judgment.rs, engine/unlink.rs)

`Judge { cx, ex, whole, claims }` evaluates one query against the configuration at the end of one phase (`ex.at(p)`, knowledge K_p): a claim at `p` concerns what honest runs had done by then (`phase_claims_after_compromise.vp` / `phase_claims_before_compromise.vp`).

- `claims` (`VerifyContext::claims_at`) gives the phase each run answers for: a copy honest at `p` answers for `p`; a copy corrupt from phase N ≤ `p` for the end of phase N−1, judged against K_p (forward secrecy: `scenario_forward_secrecy_with_honest_peer.vp` / `scenario_forward_secrecy_without_leak.vp`); a copy corrupt from phase 0 for nothing, unless every copy is.
- `Judge::claimed(r, slot)` is the run's own `Held`, else its creator's when that creator is claimed.
- A precondition requires its named send to have executed in `whole`, in any phase.
- A phase claim leaves out later steps the run reaches, not steps it never reaches: a use reached only in a later phase is left out, and one never reached cancels (`phase_claim_ignores_later_use.vp` / `phase_claim_never_reached_use.vp`).

**Confidentiality:** a claimed run holds the slot and K_p holds its value. `AttackerSuppliedValue` labels a value that differs from the honest reduct and carries no fresh or private leaf.

**Authentication:** injective agreement at the recipient run.

- *Accepted.* The slot must be held with a sender and used: every slot that mentions it reached (subject to the phase rule above), one use succeeding or unchecked, a use failing exactly when its run halted there, every output of the halted assignment being that one failed use (`auth_accept_then_split_halt.vp` / `_later_use`). Uses are the run's own assignments or, only when it has none, other principals' computations as sanity finds them (widening this loses Lowe's attack).
- *Agreeing.* An unauthored value straight from the named sender agrees. Otherwise count emissions of an equivalent value by runs interchangeable with the sender (`km.interchangeable_for`) on deliveries reaching the recipient's agent (`km.same_actor`) directly or through relays, counted only when some sender's copy is not authored.
- *Interchangeable.* A copy with another scenario binding is interchangeable for a slot on a delivery only when neither the slot nor a checked assignment the copy makes before that send depends on a target its scenario rebinds, computed on the original model (`ProtocolTrace::scenario_dependent`). Resolving a slot's value cannot decide this, since resolution erases an assigned bound value.
  - A run that signs what passed a check under its own peer's key spoke to that peer (`spore_x509_three_way.vp` / `_named`; `scenario_peer_checked_emission.vp` / `_named`).
  - An earlier send of the same slot to someone else does not make a later one interchangeable (`scenario_peer_checked_later_send.vp`).
  - A check the copy makes only after the send does not count (`scenario_peer_checked_after_send.vp`).
- *Verdict.* With no emission it is `Substituted` for an unauthored value from another principal, else `Forged`, whatever the value. With more acceptances across the agent's runs than emissions it is `Replayed`; a run of another binding whose checks on the slot depend on that binding accepted it from its own peer and is not counted (`DuplicateAcceptance` if the recipient contributed a fresh value, else `ReplayableFirstFlight`).

**Freshness:** a claimed run uses a value with no fresh leaf, or a replayed value that another run of its agent also holds and uses: `Stale` (`freshness_replayed_across_sessions.vp` / `freshness_bound_to_challenge.vp`). A value is replayed when it is authored, when it was received from a sender whose copy is replayed, or when the run computed it from a replayed received slot, so which run computes or projects a replayed input never launders it (`freshness_replay_through_relay.vp`, `_bundle`, `freshness_projected_replay.vp`, `spore_wmf.vp` / `freshness_replay_through_relay_bound.vp`).

**Equivalence** compares the claimed values of every queried slot per claimed run; every slot must be claimed in this configuration and not a failed check.

**Unlinkability** asks one `unlink::Linker` per query about each claimed pair. The `Linker` owns what it computes about the configuration, each once: what was disclosed (`observed`), what is below each term (`below`) and the knowledge left when one value is withheld (`sealed`).

**The attacker links two values when it reaches, from both, one term that carries a secret their honest values share.** The terms it holds are the nodes of a graph, and from a term it takes these steps, composed freely:

- **made**: to each held term it rebuilds the term from, through any argument it can only construct (`ingredients`). The step exists when it can rebuild the term without the term's own disclosure, or when opening the term, layer by layer through the keys it holds, reveals something it holds without that disclosure;
- **opened**: otherwise to what opening the term reveals, whether or not the attacker can rebuild it: a tuple's fields, with no key, and what decomposition under keys it holds, a weak break or a held reuse pair reveals (`opening`, the step `observed` follows). A term it can rebuild also reveals what its decomposition would under any key, since the attacker holds its arguments;
- **checked**: to the key under which the registry check that undoes the term runs, and to each argument that check confirms (`check`). The check must be runnable with every input, distinct matching positions and a successful `can_rewrite` (`runnable`), and an argument is confirmed only at a position the check matches against one target, so a certified key is tied to its certificate and a ring member is not (`unlink_cert_key_confirms.vp`).

`ties` is the one walk: every term reachable from a queried value by those steps, each with the step that reached it, under an ordinary visited set. It only descends, and it never enters a term the attacker supplied (the last gate below).

Without a term's own disclosure means `Knowledge::withholding`: the execution's disclosures closed again without the term, never the one route the closure recorded, which depends on disclosure order (`unlink_opened_content_leaked_after.vp`, `unlink_opened_content_leaked_before.vp` / `unlink_opened_fresh_content.vp`). A send computed from an install that only opening the withheld term could supply is withheld with it (`unlink_opened_fresh_content_echoed.vp`, `_late` / `unlink_opened_fresh_content_echoed_sent.vp`). What follows from the steps, each pinned:

- A value the attacker can only open is tied to its contents, not to the opening key, unless what opening reveals is something it holds independently. Content is recognized by what opening reveals, never by how it was built, nested or not: a ciphertext inside a hash reaches no key that opens it to fresh content (`unlink_nested_key_not_content.vp` / `_recognized`; `unlink_supplied_wrapper_late_key.vp` / `_tagged`).
- A value it can rebuild only through its own disclosure, such as a share interpolated from a secret recomposed out of that share, is tied only to what opening it reveals, never to what it was rebuilt from (`unlink_shares_recomposed_secret.vp`, `unlink_origin_late_absent.vp`, `unlink_tuple_shares_recomposed.vp`).
- A weak hash still ties to its arguments (the `weaken` metamorphic sweep over `unlink_authored_cross_copies.vp`).
- A held value met inside a rebuild or a signed message contributes what is below it, never its rebuild's ingredients directly, so a share inside a signed message reaches no sibling through the secret recomposed from itself (`unlink_signed_nested_sibling_share.vp` / `_leaked`).
- Opening a tuple reveals its fields, and a field two tuples carry in the clear links them as content two ciphertexts open to does (`unlink_tuple_shared_field.vp`, `unlink_tuple_key_field.vp` / `unlink_tuple_shared_field_public.vp`, `unlink_tuple_shared_field_supplied.vp`, `unlink_tuple_key_field_fresh.vp`, `unlink_tuple_ciphertexts_one_public_key.vp`).
- What opening reveals is below a value whether or not the attacker can rebuild it: a ciphertext it opens without being able to rebuild it is still tied to its plaintext (`unlink_aead_opened_without_data.vp` / `_unsent_nonce`; `unlink_weak_ciphertext_content.vp` / `_strong`; `unlink_reuse_opened_content.vp` / `_fresh_nonce`).
- Every term below a value takes its own step, however it was reached: a MAC inside an opened ciphertext is still made of its key (`unlink_opened_mac_key.vp` / `_unleaked`), and a signature inside a tuple inside a hash is still checked (`unlink_check_inside_hashed_tuple.vp` / `_unsent_key`).
- What a check confirms is checked in turn, never through a term the attacker supplied (`unlink_check_chain.vp` / `_unverifiable`, `_replayed`).

A link is a term both walks reach that passes the gates. `Tie::joins` only names it for narration: the two values themselves (equality), the key of the same check on both, a term below both, one value below the other, or a term a check on either path keys or confirms. `LinkKind::preference` chooses the link to narrate, in that order, and a link whose last check ran on a term below a queried value comes after every other; preference decides no verdict, since every candidate passes every gate before it is ranked.

The gates are conditions on the queried values and on the common term (`witness` in `link`). These predicates are not two-world equivalence. Preserve every gate:

- **Both values are observable**: known, and extracted from what this configuration disclosed by projection, decomposition, weakening or a held reuse pair, or a tuple of such values, or public. Observability needs knowledge **and** extraction, following actual reveals, never arbitrary arguments.
  - Opening a disclosed value does not enter what the attacker supplied into it, the components of the installs that feed it: neither an install a principal relays, nor one it wraps, nor one a second principal unwraps is observed (`unlink_relay_echo_not_observed.vp` / `unlink_relay_echo_sent.vp`; `unlink_container_echo_not_observed.vp` / `unlink_container_echo_sent.vp`; `unlink_container_echo_laundered.vp` / `_sent`).
  - Weak reveals come from `can_break_weak` under the execution's capability index, so they cover executed terms as the closure does (`unlink_weak_executed_term.vp`).
  - Reuse counts only while both members are held and, for a masked rule, reveals only the fields whose aligned field in another member is obtainable.
  - Each claimed run contributes its own copy of a queried value only when that copy is not authored, else the creator's (`unlink_authored_cross_copies.vp` / `_guarded`).
- **The honest values already share a secret.** Honest **unreduced** values must share a secret subterm, read through projections only (`unlink_carrier_field_not_shared.vp`), and the common term must carry a secret leaf both share, so a public field identifies nobody (`unlink_tuple_shared_field_public.vp`). Only an equality between values whose honest reducts are the same value is exempt, so an equality the attacker forces links only values one secret made (`unlink_forced_equality.vp`, the RFID tracking attack `unlink_rfid_mac_tag.vp`, `unlink_active_links.vp` / `unlink_forced_equality_two_keys.vp`, `unlink_rfid_mac_tag_nonce.vp`).
- **Independence.** A term below both values, reached through no check, must still be derivable with one of the two values withheld (`Linker::independent`).
- **Nothing the attacker supplied is a witness.** The walk does not enter a term the attacker could build, under no weakening assumption, from public values and what it installed into the queried values (with the components it could build each install from at that receive), so neither such a term nor anything found only inside one is a witness.
  - A value it could only forge under an honest secret still carries that secret (`unlink_forced_equality_forgeable.vp`).
  - A key it forced Bob to derive from its own input links nothing (`unlink_forced_key_carries_no_secret.vp`), nor does a field it replayed into both tuples (`unlink_tuple_shared_field_supplied.vp`), the message of a signature it replayed into a signed value (`unlink_check_chain_replayed.vp`) or its own key under two ciphertexts (`unlink_tuple_ciphertexts_one_public_key.vp`).
  - Only installs the two values read count, through relays and the computations of other runs; an install feeding an unrelated oracle supplies nothing (`unlink_supplied_unrelated_oracle.vp` / `_guarded`).

Invariants of execution and judgment that no sentence above carries:

| invariant | pinned by |
| --- | --- |
| Known is not forgeable | `aead_replay_not_forgery.vp`, through replays, never replacements |
| Cross-session replay breaks injectivity | `session_replay_breaks_injectivity.vp` / `session_peer_run_matches.vp` |
| Histories must coexist | `incompatible_histories.vp` / `_mitm` |
| Reflection within one execution is an attack | `history_own_later_emission.vp` (Bob's own box reflected back to him) / `_directional` |
| Disclosure must precede every affected receive | `causal_late_leak.vp`, `causal_foreign_receive.vp` / `causal_foreign_receive_early.vp` |
| Halts withhold sends and downstream computations | `halted_peer_relay_holds.vp` / `halted_peer_relay.vp` |
| Installs name values, not slots | `closure_cyclic_union.vp` |
| Acceptance needs a matching emission, whatever the value | `auth_mac_reflection.vp`; `woolam_pi_pristine_pin.vp` / `woolam_pif_pristine_pin.vp` |
| Duplicate acceptance counts emissions, not honest values | `auth_static_tag_replay.vp` / `auth_static_tag_challenge_bound.vp` |
| Acceptance counts runs of one agent | `four_party.vp` |
| Forwarding a genuine replay is not forging | `relay_origin_authenticated.vp` / `relay_origin_other_sender.vp` |
| Lowe's attack needs scenarios | `spore_ns_pk.vp` / `spore_nsl_pk.vp` |
| Guards preserve upstream control | `forward_transitive_relay.vp` / `forward_relay_all_guarded.vp` |
| Addressed installs affect one recipient | `split_delivery_equivalence.vp` / `split_delivery_through_relay.vp` |
| Declaration order is not a verdict | `order_relay_declared_first.vp`, `order_relay_declared_later.vp` |

### Reporting (engine/mod.rs, engine/narrate.rs)

`judge` evaluates every unresolved query and its variants at every phase. `minimal` shrinks a violating install map, dropping one install or two on the same message while the same query still fails at the same phase with nothing stuck. The minimized configuration at that phase is narrated and recorded.

Steps after that phase are narrated only when the attacker acts in them (`Narrator::continued`): an install or drop that survives minimization there is one the verdict needs, for a precondition's send or for a use that must be reached, and the trace then continues through it and the checks it passes, each explained from the knowledge at its own receive (`precondition_later_phase_action.vp`, `_unconditional` / `_guarded`). Otherwise a trace cites no later-phase step.

`Narrator` walks the step order.

- Before each receive that took installs it explains each installed value from the knowledge prefix that step recorded: a wire observation, a leak, a derivation step, or, when not yet recorded, a construction from available arguments or the forgery, reshaping or combination that builds it. A disclosure after that point never explains the step (`narrate_derived_before_leak.vp`), and neither does a capability that starts in a later phase: the explanation, and the world that proves a term in it genuine, are closed at the phase the receive ran in (`Narrator::phase`; `narrate_install_before_capability_onset.vp`, `_genuine` / `narrate_install_after_capability_onset.vp`).
- An install equal to a preceding sibling emission is a **replay** ("from another session|scenario|run"); any other is a replacement.
- A checked assignment that passes on authored input gets a `gate` step.
- A link is narrated with what it rests on, per queried value: how the attacker holds the value, then each step from the value to the linking term (`Link::legs`), and last how it holds the linking term (`search_unlink_nested_requirements_message_query.vp`, `unlink_check_chain.vp`). A leg is the opening or the rebuild that shows it the next term inside the last (a rebuild omitted when it built that term itself) or the check it runs, whose application the leg carries from `runnable`.
- Every line is also a structured `TraceStep` for JSON/HTML/TeX/LSP, whose `kind` is a `StepKind`: the renderers match on it exhaustively and read what a step acts on from its fields (a leak's principal and values, a drop's route), never from its prose.

Terms use the model's vocabulary: `Names` maps values held at non-authored slots to slot names, preferring unchanged and session-1 names; a *shaped* name, whose slot holds a non-honest value, is spelled one level out when it is the subject of a construction. Words require evidence: "from another session" only for an actual sibling emission in this execution, "on the wire" only for a recorded send; never call a concurrent run "earlier".

### Search (engine/search/)

`mod.rs` holds `Search`, its records and the pass order; `rounds.rs` the proposal rounds and `idle`, `placement.rs` installs and their bases, `worklist.rs` the attempt store, execution, settling and fills, `union.rs` absorption, `merge.rs` query-source merges, `stuck.rs` stuck retries and fresh-emission sources, `reroute.rs` the rerouted pass.

**Records.**

- `Search` keeps the honest execution and compact facts from each accepted candidate (a *node*): its install map, received values and queried subjects, sends, and the attacker state at each phase without derivation records.
- Nodes whose attacker states at a phase are the same sequence of values, with the same reuse pairs and capability index, share one state and its deduction memo (`States`); most are, by a factor of two to eight on the slow models. A state is compared as a sequence, not a set: `extended` hands a node's last state to the deducer, whose solutions come in the order of the held values.
- The **union** knowledge records which nodes supplied each value; proposals read it as it is, and its closure plans query-source merges.
- The union is also kept as it stood at each earlier phase barrier, absorbed from every judged execution's archived knowledge, because a run's proposals read the union only as of the latest phase in which an install can reach it (`Program::install_phase`): knowledge first disclosed later can never be delivered to it. Proposing phase-0 installs from phase-1 leaks made `pqxdh.vp` run for minutes at one session and indefinitely at two.
- Nothing is ever delivered from the union, and node facts never stand in for an execution at the judge.
- State is grouped: `facts` (fixed per analysis), `union`, `attempts` (the attempt store, worklist and merges done), `retries` (stuck candidates and their sources), `memo` (caches over nodes) and `log`.
- One depth-first worklist over a content-indexed attempt store processes candidates: execute, record halted checks, judge, absorb, queue continuations. Repeated maps reuse their outcome, except that a stuck map a derived family dropped is run again when a base family proposes it, so which family reaches a map first never decides its retries. Installs and node facts are hash-consed, so comparing them is a pointer check.

**Pass order** (`run`).

1. `fixpoint`: for every run, Targeted then Constructed proposals from `solve::propose` against a symbolic state with the union at that run's last install phase as knowledge; then close the union, merge query sources and retry stuck candidates; stop when a round leaves the union unchanged at every phase. **All Targeted before any Constructed**: interleaving changes verdicts.
2. Honest-input refinement (`slots_blocking_reduction`) and, if that grew the union, the fixpoint again.
3. `idle`.
4. When the model has a key-shaped slot, the **unshaped** pass, which repeats the fixpoint with key-shaped slot variables replaced by plain ones for every run (`solver_key_slot_type_flaw.vp` / `_bound`). The shaped variable (`symbolic::shaped`) stays because every Diffie-Hellman man-in-the-middle needs it.
5. The **rerouted** pass.
6. A refill of a halted run's input that its execution cannot obtain is retried once with every execution that freshly emits that value (`supply_wants`, `search_fill_from_sources.vp`).

**Order-sensitivity is a defect to remove, not a property to keep.** A verdict belongs to one execution and does not depend on when that execution ran, so order can only decide which install maps are executed at all. All Targeted before any Constructed is kept because interleaving changes verdicts, a measured loss and not a principle, and every narrowing below that takes the first or the cheapest choice, or tries something once, is a place where order can choose. Prefer a change that makes the set of candidates independent of order to one that adds an ordering constraint, and add an ordering constraint only with the model that needs it pinned and the constraint stated here.

**Rerouted pass.**

- A send equal to the honest one still counts as fresh when its sender took a genuine install earlier in its run: the value no longer waits for the honest route, so it can reach a receive that the honest route reaches only after that receive (`history_own_later_emission.vp` and `scuttlebutt.vp` at one session: Bob's own box reflected back to him lets him answer before Alice has).
- Executions not kept that emit such sends are noted during the search with the deliveries their installs replaced.
- At the end, a stuck candidate waits for each stuck value, and each proper subterm of it, that the honest execution sends only at or after the stuck receive (`search_reroute_built_value.vp`).
- A rerouted send of that value is a source for it when one of the deliveries it bypassed is sent causally after that receive, following the delivery graph from the stuck receive (`search_reroute_third_run.vp`), and its installs are compatible with the candidate and add to it.
- Such sends of existing nodes are registered, noted executions with one not yet registered are re-executed and kept, and each waiting candidate is retried once with its sources.
- It runs last: counting rerouted sends from the start reorders the search, and appended it can only add attacks.

**Placement.**

- A proposal installs each variable exactly where its view placed it (`SymbolicState::installed_at`, see the solver), within `TermBound::admits_at` (a cut notes `Truncation::TermDepth`): the search translates nothing.
- `bases` adds, for each needed value the union derives, the installs of the cheapest node that knows its ingredients and derives it by the phase of the receive it is installed at (`search_phase_blind_bases.vp`).
- A value the honest execution derives by then is taken on trust, and a flight that is then stuck is placed again with sources for it too, since the honest disclosure may come after the receive (`search_bases_after_own_leak.vp` / `_guarded`).
- There, a value the honest disclosures before that receive (`Knowledge::disclosing`) do not derive takes as its source, ahead of the others, the cheapest node that derives it from them plus what the node obtains beyond the honest execution, under its own annotations. Every node derives such a value by the end of the phase through the same late disclosure, so end-of-phase derivability cannot tell a source from the cheapest node (`cap_forgeable_executed_secret_leaked.vp` / `_guarded`).
- A node a late query-source merge built (below) also adds what it was built to supply before that receive (`search_combined_secret_forgery_late_leak.vp`).
- A value not yet derivable is allowed only when the union plus what the proposal makes principals emit derives it: an oracle chain.
- **Unblocking.** A Targeted flight that leaves its proposer waiting on a message whose sender halted in this execution but not in the honest one is placed again with the installs of the cheapest node in which that sender sends that message and whose merge settles with the proposer past it; a stuck merge leaves the sender stuck, not unblocked (`search_unblock_settled_source.vp` / `_guarded`). It takes only that node's installs in the causal cone of what the sender receives before that send, the flight's own values winning, and that outcome feeds repair (`search_unblock_halted_sender.vp` / `_guarded`). Forging a reply makes its sender halt upstream, and a guarded value only that sender emits then blocks the proposer before any check of its own can halt.
- Any flight left waiting so also has its `bases` chosen again among the nodes in which every message it has waited on is sent, while each choice gets it past the last one (`search_bases_other_source.vp` / `_guarded`).

**Families.**

- `base`.
- `repair`: `Deducer::repair_check` rebuilds a halted check's inputs, and a proposer starved on slots whose message the honest execution never sends is repaired at the first check they feed, wherever the honest run waits (`search_starved_oracle_repair.vp`, `_split` / `_tagged`).
- `fill`, judged against the knowledge at the end of each receive's phase (`search_fill_phase_blind.vp`): a starved receive's withheld slots take the honest value if derivable, else nil, a session sibling's value, or the honest message rebuilt from what is derivable; at a newly halted run, diverted inputs take their derivable honest values.
- `drop`: single-install removals.
- `merge`: query-source merges (below).
- `stuck`: a stuck candidate retried with a source.
  - The source is a node that freshly emits the stuck value or a subterm of it the honest execution does not derive, plus that node's installs in the emission's causal cone (`search_stuck_subterm_source.vp` / `_guarded`).
  - When no such node agrees with every install of the candidate, one that differs only at stuck installs in its emission's cone takes their place, since a placement may have taken a source that teaches the value only after the receive (`search_stuck_subterm_source_malleable.vp` / `_guarded`).
  - For a value the honest execution derives, the source is the next node that installs at every input the candidate's other installs fill, derives it by the stuck receive's phase and gives a merge not yet tried, the candidate's values winning the merge: the candidate's own installs may be what stops the honest derivation, and the executions that still derive it may replace the same input differently (`search_supplier_same_input.vp` / `_guarded`).
  - One node per stuck install per round, so a node whose merge was already tried must not take that turn (`remote_aa_bound_leaked_signature.vp`).
- `admitted`: a stuck candidate's other installs.
- `idle`: a node with one more run that feeds an unresolved authentication or freshness query, for every such query's slots, either left unstarted (`search_idle_senders.vp`, `search_idle_freshness.vp`) or given one dropped value: of the values it receives that a step up to its relied-on send needs, the one needed last, so that it does as much as it can before it stops. The drop is skipped when the run would send or leak nothing before stopping and leaving it unstarted is also tried. Silencing a run may mean silencing its upstream (`search_idle_upstream_relay.vp` / `search_idle_upstream_guarded.vp`; `spore_splice_as.vp`, `search_selective_drop.vp`).
- `extended`, in a model with a later phase.
  - Each round, the honest node and every node a constructing family (base, repair, merge, unshaped, rerouted) kept are extended at each run whose installs precede the last phase.
  - Every open confidentiality and unlinkability goal is solved against that node's own final-phase knowledge, with the node's installs at that run fixed, every other slot honest but one key-shaped slot left free, and no variable at another receiver of a fixed slot. The results are tried as Targeted flights, so a halted check is repaired from the install-phase union.
  - A substitution can pay off only once a later phase discloses a secret, and only one execution's knowledge says which inputs still need replacing: the union at the install phase knows none of the later secrets, and the union at the last phase mixes in executions whose runs disclosed what this one withholds (`kem_key_confusion_later_leak.vp`, the PQXDH key confusion with the tags dropped / `_tagged`).
  - It is derived, so a stuck extension is dropped.

**Settle.** Every unstuck execution is judged. Its knowledge at each earlier barrier is absorbed into the union at that phase whether or not it is kept. It is kept when it teaches the union something, at the last phase or at an earlier barrier (`search_earlier_phase_source.vp` / `_guarded`, `_late`):

- a value the union cannot obtain;
- a principal emission within the term depth (a value whose record is a wire or leak disclosure, however it was first acquired);
- a reuse pair;
- a fresh emission: a send, or a leak whose value differs from the honest leak at that step (`search_fresh_leak_source.vp` / `_guarded`, `_late`);
- an alternative non-honest route;
- a queried value a run holds that no node holds yet and this execution does not obtain (`search_holder_unsourced.vp` / `_guarded`, `_bobguarded`).

**No caps on kept alternatives** (`matching_run_recipient_halt.vp`).

**Projection.** Install maps keep only the receives that can affect pending queries (`removing_inputs_after_relevant_actions_preserves_query_violations`):

- every send's and leak's input history;
- queried holders' prefixes: whole runs for the holders of an authentication or freshness subject that use it, since later unreached uses cancel; a holder that never uses the subject cannot accept it, so only its sends and leaks count (`search_inert_recipient.vp` / `_private_nfc`);
- creators' prefixes for unlinkability.

**Query-source merges.**

*Targets.*

- A value the union derives that its holder does not, including one some node knows directly (`search_holder_unsourced.vp`).
- For unlinkability, what one route by which `link` ties a queried value needs, for the value and for each of its subterms, which covers every term the walk reaches by splitting or rebuilding. Each base model here has a `_guarded` twin that holds.
  - A route needs every such secret-bearing argument, which a rebuild needs (`search_unlink_joint_arguments.vp` / `_guarded`), or every such input of the check that undoes it, as `unlink::check_inputs` derives it for `runnable`, a signature's public key rather than its signing key (`search_unlink_check_route.vp`, `_unsent_keys`, `_message_query`; `search_unlink_check_key_oracle.vp`, `_public_keys`, `_witness`, `_message_query`; `search_unlink_check_ring_member.vp`, `_unsent_keys`, `_witness`; `search_unlink_check_inside_tuple.vp`, `_message_query`; `search_unlink_check_inside_hash.vp`, `_message_query`).
  - A route into a subterm also carries what rebuilding every term above it needs, a tuple aside, whose fields need nothing: the evaluator reaches a part only through its whole, so a signature inside a salted hash is checked only in an execution that also discloses the salt (`Search::routes`; `search_unlink_nested_requirements.vp`, `_public_salts`, `_message_query`).
  - A route into an argument that the check on the term above it confirms (`unlink::check_confirms`) carries that check's inputs instead, as the evaluator's chain of checks does, so two public keys sealed behind two oracles are disclosed in one execution (`search_unlink_check_chain.vp`).
  - Each route is a target alone and joined with each route of every other queried value the context holds, since a link needs ties on both sides in one execution (`search_unlink_pair_check_keys.vp`, `search_unlink_pair_rebuild.vp`).
- Every value a run that answers an authentication or freshness query holds honestly and only the union's closure derives, with the honest execution as context, so a secret that several executions disclose only together enters the union (`search_combined_secret_forgery.vp` / `_same_oracle`).
- At each receive of such a subject, every value the receiving run holds without receiving it and uses with the subject, not computed from it, that the honest disclosures before that receive do not derive but those plus every value some execution freshly emitted do. The plan follows that closure's records, a leaf those disclosures derive supplied by the honest execution and any other by the nodes that freshly emit it, and the node it builds is recorded as that value's source at that receive, so a late honest disclosure, which every node holds by the end of the phase, stands in for no source (`search_combined_secret_forgery_late_leak.vp` / `search_combined_secret_forgery_same_oracle_late_leak.vp`).

*Context.* The holder of each held value with the fewest installs is its context, and two targets are one only when they want the same values in the same context: a cheaper holder of another query's subject lacks the installs that make this one's subject hold its value (`search_merge_target_context.vp`, `_reversed`, `_alone` / `_guarded_key`, `_guarded_ciphertext`).

*Plan.*

- The plan is the first compatible choice of one source per derivation leaf, cheapest first, backtracking over conflicts (`search_source_alternative.vp` / `_guarded`).
- A source is compared by every value it supplied: its installs and each value one of its runs received authored through a relay at an unguarded slot, so a source installing upstream of a relay conflicts with one installing a different value downstream of it (`search_merge_relayed_source.vp` / `_one_tagger`).
- Leaves follow the closure's records; when no choice is compatible, each leaf of a minimal conflicting set is withheld in turn as a disclosure (it may still be derived) and the union's disclosures closed again (`Knowledge::disclosing`), following the new records, so every route is reached (`search_merge_other_route.vp` / `_same_oracle`).
- A plan whose execution leaves a run waiting on a message whose sender halted is chosen again over the same leaves from only the sources that send every such message (`search_merge_unblocked_source.vp` / `_guarded`).

**Also pinned.** The search retains deeper terms and oracle chains (`pitoy_depth.vp`, `solver_oracle_chained_inputs.vp`). Disclosing a bound signature brings back a nonce-reuse forgery once the challenge is known (`remote_aa_bound_leaked_signature.vp` / `remote_aa_bound_private_nfc_known_challenge.vp`, `epassport/remote_aa_bound.vp`).

**Narrowings.** Each is a rule about the structure of the candidates a family builds and an incompleteness source, and each was introduced because its wider form ran for hours on models in the suite; revisit them before widening anything else. Where one fixes a small arity (one, once, two), that arity is a bound in effect, fixed by design and recorded here with its cost, never a tunable.

- A run's proposals see only the union as of its last install phase, so a value first learned in a later phase is never proposed to it, not even as a stuck candidate awaiting a source; only `extended` reasons from a later phase, and only within one execution.
- `extended` frees one key-shaped slot at a time, whose candidates are public keys and so deliverable at the install, and extends only the honest node and nodes a constructing family kept. Freeing any slot against a later phase's knowledge proposes values the attacker can build only once later secrets leak (it made `simplex_pqdr.vp` five times slower at one session), and solving the goal against the last-phase union instead enumerated every leaked private key at every key slot (9,000 goals at one session, and no end at two, on PQXDH).
- Proposals read the union of the executions' knowledge, never its closure (the closure made `simplex_proxy.vp` and `simplex_smp.vp` run for over eight minutes at one session), so a value only several executions derive together is proposed only once a query-source merge has executed them together.
- Constructed held replacements are protocol terms with the honest value's constructor.
- `repair` follows only Targeted proposals, and so does unblocking, which takes the first source in cost order that lets the proposer past the awaited message.
- A blocked `fill`, `stuck` or `admitted` candidate is dropped, so stuck retries never cascade.
- A stuck candidate's stuck installs give way to a source only when no source agrees with all of them (letting every source replace them made `spore_otway_rees.vp` half again slower at two sessions).
- A query-source merge uses one context per target, once, with the first compatible plan, chosen again only over the same route and only while its execution leaves a run waiting on a halted sender (withholding sources that do not send and closing the union again made `search_chain_through_server_labelled.vp` run for minutes at two sessions).
- An unlinkability merge target is what one route of a queried value or of one of its subterms needs, alone or joined with one route of another queried value as the merge's context holds it: never a subset of a route's needs, never three routes joined, and never a partner value held only in another execution. A route reaches a subterm by rebuilding the terms above it, so it asks for all their secret-bearing arguments the union derives, even where a key alone, or a weak break, would open one of them.
- Merges target only confidentiality and unlinkability subjects and the values that runs answering authentication or freshness queries hold. A late merge target is a value its run holds without receiving it and uses with the subject, so a value it receives, or computes from the subject, never is one (every late value of every holder made `simplex_smp.vp` nearly six times slower at two sessions).
- `bases` follows one recipe per value from the cheapest node, chosen again only when the flight waits on a halted sender. A late value's source is sought only once the union's own additions over the honest execution derive it, so an addition the union did not absorb, because it could build it from values the honest execution discloses late, is not seen, and a node that obtains early a value the honest execution discloses late adds nothing unless a late query-source merge built it for that value.
- Rounds end when the union stops growing; the rerouted pass runs once; a halted run's refill from another execution's emission is tried once, after it.
- Targeted goals exist only for the queries asked, so what the union learns, and therefore whether another query's attack is found, can depend on the query set.
- An opened tuple has one width, the narrowest covering the projections visible in that equation system, so a projection of a wider index met in a later, separate unification cannot widen it.
- While the deducer solves a revealed oracle's key, it tries only the revealed oracles whose own keys the attacker already holds under the goal's bindings, so a key the attacker reaches only through a second sealed oracle, behind an install the goal has not yet bound, waits for a later round in which the union holds that oracle's key. Solving those keys with every revealed oracle made each key lead back through the others and defeated the goal memo (the WalletConnect model `solver_revealed_oracle_sealed.vp` reduces ran for over fourteen minutes at two sessions without finishing, the reduced model for four), and never solving them, trying an oracle only once its key was already held, lost `solver_revealed_oracle_keyed_tuple_leaked.vp`.
- An oracle input is completed from held terms only when nil leaves it unconstructible or fills it with a value its receiver alone discloses later in declaration order, so a value another run discloses after the receive still counts as constructible there (dropping that gate made `pace.vp` five times and `inspect_ca.vp` eighteen times slower at two sessions).
- Foreign slots an oracle input reads past a non-equality check take their honest values together, in one variant, never each held value that passes the check (one variant per pin took `spore_yahalom.vp` from 0.4 s to 9 s at one session).
- A join inversion fills its open pieces from the pool in order, as combinations, never permutations.
- `idle` drops one value per relied-on sender, the one needed last before its relied-on send, so a silencing that needs two drops, or an earlier stop, is not tried (every drop candidate of every received value made `inspect_ca.vp` seven times slower through the fills of the runs it starves).
- Field rewrites under a reused nonce are proposed only over ciphertexts some execution noted as a reuse pair, one base ciphertext at a time, so a splice of fields the goal leaves open, which no check distinguishes, and a rewrite over ciphertexts that only the union holds together are not proposed; the closure and the executor still accept every splice and rewrite. Rewriting every field from every member of the union's same-key-and-nonce groups made `simplex_proxy.vp` run for over two minutes at one session instead of under one second, the groups reaching thirty-eight ciphertexts.

### Solver (src/solve/)

The solver generates candidates. It never sees an execution and only ever outputs install maps. Do not give the attacker shapes it did not derive.

- `control.rs`: `Controllable` (the slots a run's proposals may replace in a phase, read off `Program`: not its own, not nil, carried to it by an unguarded delivery or a relay of one if it receives them at all, first installable by that phase, and used or sent by it or named by an equivalence query), `TermBound` (protocol depth plus recipient peel depth; partial deductions check a conservative lower bound) and `attacker_authored`.
- `vars.rs`: `VariableId`s live outside the constant namespace; free variables come from per-lane namespaces whose counters grow without ceiling. An ungrounded variable is not an admissible message.
- `matching.rs`: one-way matching, two-way unification and merge modulo commutativity; **retain every alignment until all equations succeed**; reject occurs cycles.
- `diverge.rs`: an equivalence goal varies each replaceable value of the queried terms to the first filler of the ladder (`nil`, `HASH(nil)`, ...) that is not its honest value; `nil` alone proposes nothing where `nil` is honest (`equivalence_nil_payload.vp` / `_guarded`).
- `constraint_goals` propagates check equations across a whole constraint group before solving wire values (`solver_mac_then_tuple.vp`). Besides each principal's last check, each send, leak and query declaration, every check of a non-creator that mentions an authentication or freshness subject ends a group, since positional acceptance counts a value that passes the uses before a later failing check (`auth_accept_then_halt.vp`, `freshness_accept_then_halt.vp`).
- Free positions (`free.rs`) take protocol terms only (`keyed_free`, `preserved_free` preferring a held honest value before the attacker's key, `rekeyed_free` taking the attacker's key at key positions and held honest values elsewhere (`forged_statement_rebuilt_secret_only.vp`), `aligned_held_free`, `swapped_free` at reuse-pinned positions); arbitrary held terms inflate the basis.

**Symbolic execution (`symbolic.rs`).**

- `executed` runs `Program` symbolically: in the declared order every run holds, assigns and receives as the executor would, taking at an unguarded receive the variable its view places there and otherwise what its sender holds. The solver's terms are therefore the executor's with variables for installs, and there is no second model of delivery to keep in step.
- A `View` gives each replaceable slot one variable, installed at `Program::points` for the proposing run (that run if it receives the slot unguarded, else the unguarded receivers upstream through guarded relays, else every unguarded receiver), and a variable of its own (`Receiver`, `VariableId::Receiver(run, slot)`) to every other unguarded receiver that uses the slot or relays it guarded.
- A variable a proposal leaves unbound is no install: its receive takes what its sender holds (`forwarded`), the honest value from the original sender or whatever an upstream install made a relay carry, and `emissions_under` and `leave_honest_slots` read a proposal that way (`SymbolicState::forwarding`).
- A receiver's variable is bound only through `vars::bind`, whose occurs check refuses a variable its own value mentions: a proposal may bind one receiver's variable to another's, and inserting that binding raw once made a variable its own value, which `apply` follows forever (`solver_receiver_alias_echo.vp`, `solver_receiver_alias_key_confirmation.vp` / `solver_receiver_alias_sealed_echo.vp`).
- A proposal binds the receivers its goals and constraints need, and every flight is also tried with its value installed at every other receiver the proposal left alone that would otherwise take another value (`solve::everywhere`), so a broadcast replaced at one recipient, consistently at two, or at all but one that checks it is found without a second pass (`broadcast_consistent_replacement.vp`, `search_broadcast_subset.vp`, `_swapped` / `_guarded`).
- A view built `within` another names each receive as that view does, so the checks of one principal and the emissions of another speak of one variable per receive: the oracle input goals build every other principal's view inside the proposer's and install an oracle's output at the receive that checks it.

**Deduction (`deduce/`).** `mod.rs` holds the goal loop and its memo; the rules are in `rules.rs`, `shapes.rs`, `decomposition.rs`, `combination.rs`, `inversion.rs` and `checks.rs`. The deducer tries held values, variables, replay, two-way wire unification (`solver_reflected_request.vp`), oracles, rewrite matching, argument construction, decomposition and check inversion.

- **Oracles.**
  - A value that a decomposition route of a wire term reveals and that still reduces over variables is an oracle like a wire term, tried for each solution of the keys that route needs (`solver_nested_oracle.vp` / `_guarded`; `solver_revealed_oracle_keyed_tuple_leaked.vp`). While it solves such a key, the deducer tries only the revealed oracles whose own keys the attacker already holds (see Narrowings), and memoizes the goals it solves there apart from the others.
  - A wire rewrite whose opened argument is another reducible application over variables is inverted through it (`solver_onion_oracle.vp` / `_guarded`).
  - A rewrite of attacker input under a constructor is abstracted to a variable, the term unified with the goal and the variable's value produced through that rewrite (`solver_nested_hashed_oracle.vp` / `_guarded`).
  - An oracle input is unified with its required shape before that shape is proven constructible; oracle and projection inversion accept goals outside the protocol basis.
  - An oracle behind a key the attacker must first make derivable is still found (`solver_revealed_oracle_keyed_decryption.vp`, `solver_revealed_oracle_keyed_signature.vp`, `solver_revealed_oracle_keyed_tuple.vp`, `solver_revealed_oracle_keyed_tuple_leaked.vp`, `solver_revealed_oracle_keyed_request.vp`, `solver_revealed_oracle_chain_encryption.vp`, `solver_revealed_oracle_chain_decryption.vp`, `solver_revealed_oracle_sealed_leaked.vp` / `solver_revealed_oracle_sealed.vp` and the guarded twins of the others).
- **Joins.**
  - A join is inverted against the whole its combine rule yields, whatever key the check names, its pieces taking distinct shares of a held sharing: either the attacker's own partials under its nonce and commitment (`solver_threshold_join_inversion.vp`, `_unguarded_key` / `_one_share`, `_unguarded_key_one_share`), or, around an anchor, partials that share the anchor's agreed fields.
  - An anchor is a held partial or a partial piece, and the attacker's partials around it take each nonce the anchor's list commits. A partial piece may stand for itself, and its honest share reserves that share. A held partial anchors only a join that has an open piece and whose list commits a value the attacker holds or that is still free.
  - Every result uses at least one attacker-made partial: a join of held or emitted partials alone is a replay or the honest join.
  - A principal's emitted partial is inverted toward the whole as one piece of a join the attacker completes, so a signing oracle is asked for a partial under a list that commits the attacker's nonce (`solver_threshold_join_honest_partial.vp` / `_guarded`).
- **Shapes.**
  - **A position that must have a registry shape is solved for that shape rather than refused**: commuted, blocked-decomposition and check-input shapes (`solver_wrapped_key_decomposition.vp` / `solver_wrapped_key_guarded.vp`; `solver_sealed_share_substitution.vp`).
  - A blocked decomposition is shaped even when a weak or reuse route is also offered for it: those routes are options, and a `weak` annotation on one term of a primitive must not hide the attacker key another term of it needs (`solver_weak_route_keeps_shaped_key.vp` / `_guarded`; `unlink_authored_cross_copies_weak.vp` / `_guarded`; `search_unlink_joint_arguments_weak.vp` / `_guarded`).
  - A constructed goal solves first the arguments in which a variable sits under a primitive that constrains its shape (a rewrite, a projection, an equality or a commutative constructor), then those that merely carry variables, where `nil` serves (`solver_kem_shape_before_carrier.vp`).
- **Tuples.**
  - An equation that fails at a projection of an unbound variable opens that variable into a tuple of fresh fields as wide as its widest projection, and substitution projects tuples, so two fields of one split tuple unify like two slots (`solver_threshold_key_alignment_tuple.vp`, `solver_unblind_bindings_tuple.vp`, `ffgg_tuple.vp` / `_guarded`).
  - `tuple_shapes` offers the narrowest, the honest and every held tuple arity (`solver_split_prefix_replay.vp`).
- **Memos.**
  - Goal memos are keyed by the goal and every binding it can read; never cache cycle-cut results.
  - A ground goal the attacker already obtains is answered directly, and decomposition skips wire terms whose reveals can never have the goal's head.

**Proposals (`propose.rs`, goals in `goals.rs`).** `propose` yields query goals, constraint goals, oracle input goals, blanket and single-slot substitutions, then Constructed sibling flights (every slot from one sibling session, and each message on its own when a run's variable slots come from several: `search_message_replay.vp`), held replacements and rewrite candidates.

- **Oracle input goals** are the shapes of another principal's checks and of its unchecked rewrites over received slots, so that one oracle feeds another (`solver_oracle_chain_unguarded_link.vp` / `_guarded`), unified with this principal's emissions, inverted through them, or with what decomposing them reveals (`solver_oracle_sealed_relay.vp` / `_guarded`).
  - Their free positions stay open for the free-position policy and for repair (`eac_bac_unbound_tuple.vp`).
  - That principal's slots take nil or the attacker's key, and also each value its own equality checks pin (`solver_oracle_input_honest_field.vp` / `_guarded`).
  - One more variant gives each non-key slot that the plain fillers fail at one of that principal's other checks its honest value, if held (`solver_oracle_input_signed_field.vp` / `_guarded`; `solver_oracle_input_decrypted_field.vp` / `_guarded`).
  - An input that nil leaves unconstructible, or that nil fills with a value only the receiving principal discloses, in a step declared after that receive, is also completed from each held term it matches, or built from held terms, constructor by constructor (`solver_oracle_input_held_completion.vp`, `_leaked_key` / `_guarded`).
  - So is an input whose open positions one variable ties together, such as the two fields of an opened tuple when one keys the other (`solver_oracle_input_held_tuple.vp` / `_guarded`).
- Proposals are deduplicated by canonical slot bindings before free positions are expanded, so different repair possibilities survive even when grounding gives the same install map.
- An executed map keeps its own halt positions, since a filled execution cannot stand in for the original proposal's halt.

### Sessions and scenarios (protocol/sessions.rs, protocol/scenario.rs)

`expand_scenarios` then `expand_sessions` clone principal and message blocks before sanity, sharing `sessions::ModelCopy`. Fresh and assigned constants become `c#s` (session) or `c@k` (scenario); `knows` constants stay shared; `s*k <= 31`. Original queries cover session 1; variants share `query_index`. `km.session_siblings`/`copy_siblings` group a constant's copies and `km.interchangeable`/`actors` group principal copies. Copies are runs, not agents: match recipients by agent and senders per slot.

A scenario entry rebinds one principal's `knows` values throughout that principal, as a whole-model configuration; entries are not a cross product. Its bindings apply at once, so a target another binding of the same entry takes as its value stays declared (`scenario_binding_swap.vp`, `scenario_binding_chain.vp`). Reject undeclared and wire targets. Repeated entries are legal.

A written query names the first copy, and its scenario and session variants live on the expanded model (`Model::variants`). It is sane when it or one of its variants is, so neither the order of the entries nor which entry makes a principal use a value decides whether a model is accepted (`scenario_query_each_entry.vp`, `_reversed` / `scenario_query_no_entry.vp`, rejected).

`corruption` dates each scenario from the engine's own knowledge: it expands the scenarios in declared order at one session, runs `sanity` without the queries and the honest `execute`, and finds the first phase barrier whose knowledge obtains any of the binding's key material.

- A value bound to a `knows private` target is a credential, and it is its own key material, as the bound principal holds it and whole: a secret inside it is not the credential (`scenario_private_binding_nested_key.vp`, `_nil` / `_unopened`; `scenario_private_binding_whole_key_leaked.vp`).
- Any other bound value identifies the peer, as does a public key bound to a private target (`a_public_key_bound_to_a_private_target_is_not_key_material`), and its key material is every argument at a registry secret position reached through the other positions, whole, never leaf by leaf (`scenario_corrupt_inline_key_half_leaked.vp`), each term node walked once (`scenario_binding_shared_chain.vp`).
- There is no second model of disclosure: a bound key the attacker reads on the wire, a public constant or recomposed shares all count (`scenario_corrupt_by_bound_key_on_wire.vp`, `scenario_corrupt_by_public_constant.vp`, `scenario_corrupt_by_recomposed_shares.vp`).
- Query variants cover scenarios honest at phase 0, or every scenario when none is.

`check_honest_run` reports an honest creator's failed check as a model error; a corrupt creator just halts (`scenario_corrupt_at_late_check.vp`).

- The diagnostic spells the operation as the model writes it, each named argument one level out (`sanity::spelled_out`), never the resolved term, whose text doubles with every shared argument (`err_honest_check_shared_chain.vp`, `err_split_shared_chain.vp`).
- Reading only the honest execution's least halt suffices because a run blocks solely behind an earlier halt in its own copy and corruption covers a whole copy from one phase on: keep both true or check unreached slots too.

**Do not add scenario-free variants to `examples/`.**

### Verdicts and auto-queries

`VerifyResult` carries `Envelope { sessions, truncations }`, printed after PASS (`[search exhausted at 2 sessions]`, `[search truncated: term depth]`) and serialized as `QueryReport.envelope`; `Truncation::TermDepth` attaches to queries unresolved when first met. FAIL may carry `Subtype::{AttackerSuppliedValue, DuplicateAcceptance, ReplayableFirstFlight}`. Declared weakening assumptions come from the source model (`capability::declared_assumptions`), one row per capability at its earliest onset; never render the `CapabilityIndex`.

**"Exhausted" means this engine's search space at these parameters, never absence of attacks.** Do not call results "proof", "verified", "correct" or "complete". Agreement between adjacent session counts says nothing about higher ones (a 4-of-4 threshold secret needs four concurrent runs); there is no saturation mode.

`--auto-queries` **replaces** queries after sanity: confidentiality for each fresh or private constant, authentication for each delivery used in a recipient primitive, freshness for each sent-and-used constant. They are read off the one-session scenario expansion, in the model's own names and declaration order, so a value is asked about where some copy that answers queries uses it, bound values included. A scenario target every copy of its declaring principal rebinds has no slot there and is left out: an identity binding rebinds nothing, and a binding in one principal leaves another holder's secret in place (`auto_queries_identity_scenario.vp`, `auto_queries_shared_rebound.vp`).

### Core data model (term/, syntax/ast.rs, theory/attacker.rs)

- `Value = Constant | Primitive(Arc) | Variable(VariableId)`; constants are model-interned ids (nil = 1). **Equivalent values must have equal hashes.** Registry commutativity drives equivalence, hashing and matching.
- **Terms are DAGs.** Memoize transformations by `Arc` pointer and comparisons by pointer pair; never walk a term as a tree (`unlink_shared_dag.vp` / `_equal`; `unlink_observable_shared_dag.vp`, `_roots` / `_shared`). Never prune by hash: equivalent DH terms hide distinct subterms. An equivalence comparison keeps every nested answer, unequal ones too, until it returns, since two unequal terms can share an index hash at every level (`equivalence_colliding_hashes.vp`); a pointer-keyed answer outlives its comparison only behind `Weak` references. Provenance across runs is a DAG as well: decide it once per run state and slot (`freshness_converging_dependencies.vp` / `_replayed`).
- A `Primitive` is an immutable `Application` (id, arguments, output, threshold, instance, instance_check, capabilities) behind `Deref`, plus a `HashCell` caching its hash, variable presence, whether any subterm carries a capability annotation (`term::annotated`) and its `can_rewrite` result. Fields cannot be assigned: `with`, `with_arguments` and `with_output` build a changed copy with an empty cache, while a plain clone keeps the hash.
- `term::hashing::hashcons` is the one analysis-scoped hash-consing table; its identity is structural, capabilities and every constant field included. Trace resolution, the executor, the search and the theory canonicalize the terms they build, so memos and equality checks hit across executions.
- **Capabilities do not affect term identity**: read a capability index (`km.capabilities` for the declarations, `Knowledge::capabilities()` within an execution), never a deduped held term.
- There is no per-principal state: sanity and the solver read `km` plus a `PrincipalId`; runtime state lives only in executions.
- `km.dependencies` holds the two static relations asked about a slot's expression: `km.reads(slot)`, the slots it names, in order, and `km.mentions(slot, target)`, whether it reaches `target` through its creator's own primitive assignments. The judge's uses, replay provenance, the unlinkability witness, the executor's `lacks` and the search's cones all read them; do not walk `initial_value` again for either. Walking it on every judgment was a third of the runtime of `signal_twelve.vp`.
- `AttackerState = { current_phase, known, known_map, derivations, reused, chain }`. **Length-keyed memos need chain identity**: every learn and phase change mints a new `chain`.

### Equational theory (theory/)

`theory/` interprets the registry. `can_rewrite` (`rewrite.rs`) is the sole reducer (arguments, rebuild, combine, then rewrite) and reports a failed outer check with its arguments reduced. `obtainable` (`obtain.rs`) is the common argument-recovery cascade, memoised within a `DeductionMemo` scope; a search state keeps a `SavedMemo`, the only memo of what that state derives. The memo answers a hash-consed term by its pointer alone and keeps the structural table for terms built on the fly: storing every term in both, with a bucket allocated per term, was more than half of the heap the search retained on `tls13.vp`. Decomposition returns a **set** of reveals covering everything the legitimate holder learns (`KEM_ENCAP` reveals the secret **and** the randomness).

- Rewrite matching is a **bijection** onto distinct inner positions (`ringsign_ring_collapse.vp`).
- A core application is built like any other: an unchecked SPLIT that does not match and an ASSERT, which stores itself, are values their principal holds, so the attacker applies SPLIT and ASSERT to what it holds (`core_split_unchecked_junk.vp`, `core_assert_value_public.vp`, `core_split_unchecked_junk_auth.vp` / `core_split_checked_junk.vp`, `core_assert_value_private.vp`, `core_split_checked_junk_auth.vp`).
- **No recursion cap**: rewrite results are subterms or rebuilt strict subterms.

**Weakening.**

- An annotation is on the call, so every capability covers the terms an annotated call computes in the execution, not only its honest term: each `Knowledge` carries one `CapabilityIndex`, the declared annotations plus the annotated terms its assignments computed, and every theory call against that knowledge reads it (`cap_weak_executed_term.vp` / `_strong`; `cap_malleable_executed_term.vp` / `_strong`). `forgeable` thus covers every secret an annotated call keyed itself with (`cap_forgeable_executed_secret.vp` / `_strong`).
- The union absorbs the annotated terms of the executions it absorbs, and the solver reads the union's index.
- `forgeable` needs no source application; `weak` and `malleable` do (`malleable_source` picks an eligible held ciphertext, or time-travel forgery appears).
- A capability exemption **adds** an option and keeps the solved alternatives: a forgeable or reused position is exempt only when its argument is not obtainable, or the recipe drops a key the attacker holds (`cap_forgeable_known_key_links.vp`).
- Weakening preserves key boundaries (`cap_forgeable_other_message.vp` / `cap_forgeable_other_key_holds.vp`).
- Constructibility concerns the **reduct** (`solver_constructible_reduct.vp`).

**AEAD nonces** (`theory/reuse.rs`). `ReuseRule { fixed: [0, 1], reveals: [Argument(2)], forgeable: [0, 1], masked: Some(2) }`, read as AES-GCM and ChaCha20-Poly1305 behave: the key and nonce fix a keystream that masks the plaintext.

- **Alignment.** A plaintext built with the registry's tuple role is masked field by field, field *i* of every member lying over the same stretch. Tuples align on their common prefix of fields, recursively, which assumes fixed-width encodings. Two plaintexts are walked together once per pair of nodes, and `spans` and `covers` answer once per pair, so a field shared by many positions costs one visit (`aead_nonce_reuse_shared_dag.vp`, `_known`, `_known_fresh_nonce`).
- **Pairs.** Two non-equivalent held ciphertexts with equal key and nonce form a pair, which gives up the tag key but only the XOR of the plaintexts.
- **Re-tagging.** A pair lets the attacker re-tag a member under any obtainable `ad` (`Retagged`: `aead_nonce_reuse_forgery.vp`, `aead_nonce_reuse_same_plaintext_retag.vp`).
- **Reveals.** A member's field is revealed only when the aligned field of another member is obtainable, the whole plaintext being the outermost field.
- **Reach.** A known value reaches over whatever is aligned with it, except that a known tuple reaches over an aligned tuple only as far as its own fields go, recursively: a narrower known plaintext opens only the common prefix of a wider one and gives no keystream past its last field, for reading or for forging (`spans`; `aead_nonce_reuse_shorter_known.vp` / `_equal`; `aead_nonce_reuse_shorter_known_forgery.vp` / `_equal`). An atomic value has no width, so it still covers a whole aligned tuple (`Reused`: `aead_nonce_reuse_counter_known.vp`, `aead_nonce_reuse_known_field_reveals.vp`). Two unknown plaintexts stay hidden (`aead_nonce_reuse_counter.vp`, `aead_nonce_reuse_known_field_reveals_hidden.vp`), and equal ones reveal nothing (`aead_nonce_reuse_same_plaintext_different_ad.vp`).
- **Construction.** A ciphertext under that key and nonce is constructible exactly when every field of its plaintext is either a member's field at that position, copied however unknown, or constructible over a position where some member's field is known. So the attacker splices and overwrites fields (`Retagged` with a changed plaintext: `aead_nonce_reuse_rewrite_known_field.vp` / `_fresh_nonce`; `aead_nonce_reuse_splice_fields.vp` / `_bound`) and forges any plaintext once a whole one that reaches over it is known (`ReusedForge`: `aead_nonce_reuse_chosen_plaintext.vp` / `_unknown`), never one of the pair's own members.
- **Solver: re-tags.** The solver offers a re-tag of every held ciphertext that shares its key and nonce with another held one, beside any keyed forgery and whether or not the union noted the pair: proposals read knowledge at the end of the phase, where a later disclosure of the key may already open both, so the closure no longer pairs them and a known plaintext offers only chosen ones (`aead_nonce_reuse_retag_late_key.vp`).
- **Solver: field rewrites.** After the re-tags it rewrites the goal's plaintext field by field against each group of ciphertexts that share key and nonce and that some execution noted as reuse pairs, unless the attacker obtains that key and nonce (`rewrite_masked`): each member in turn is the base, a field that matches the base keeps it, and a field that conflicts with it is copied from another member or, when the goal pins it and some member's field there is known, solved as a constructed value.
- **Not modelled:** a known part of an atomic plaintext, a shift of an unknown field by a known difference (its result is a value no term names), and misalignment from variable-length fields.
- Decryption needs key **and** nonce. `knows` nonces are session-shared, `generates` nonces fresh (`aead_nonce_reuse_sessions_retag.vp` / `aead_nonce_fresh_sessions_retag.vp`).

**Threshold (FROST).** `THRESHOLD_SPLIT[t](k)` deals shares; `THRESHOLD_SIGN(share, nonce, commitments, message)` makes a partial; `THRESHOLD_JOIN` combines distinct projections of one sharing, with agreed fields and committed nonces, into a SIGN or PUBKEY.

- Partials the attacker produces itself, from held or forgeable shares, join under its own nonce and commitment list, not only around a partial it holds (`threshold_combine_own_partials.vp`).
- Reusing a share and nonce across two partials, or disclosing a partial's nonce, commitments and message, reveals the share.
- A share of an assignment's sharing is obtainable only by interpolation, from `t` other shares or from the secret and `t`−1 other shares: the secret alone fixes no share (`threshold_secret_reveals_no_share.vp`).
- Both derivations are `Recomposed` records that list every point they use, so query-source merges bring in every execution that supplied one and narration explains each (`threshold_interpolation_two_oracles.vp` / `_guarded`).
- Model dealer channels as confidential and authenticated, and DKG as a principal splitting a fresh key it never otherwise uses.
- Lowering a threshold cannot lose attacks.

Add a primitive with `build_primitive_specs` (core entries: `build_core_specs`, `core_rule_*`), then add model tests.

### Result-writing boundaries (verify/record.rs::tcb_tests)

Source-level tests pin these boundaries; they do **not** prove evaluator correctness. `results_put` requires a `Verdict` token that only `Judge::evaluate` constructs and only `engine::report` records. The evaluator is handed one `Execution`, never `VerifyContext`, and executions come only from `execute`, called by the root run, the minimizer, the search and scenario corruption dating (which only reads knowledge). The receive arm gates installs on derivability, and a receive without an install takes the sender's recorded send. Adding a query kind must update `Judge::evaluate`, `Violation`, `report` and `goals_for_query`.

### Supporting modules

- `syntax/parser/` preserves comments and indexes tokens even for failed parses. `syntax/pretty.rs` is pure, idempotent, golden-tested and **not sanity-gated**; it owns AST `Display`.
- `console/update.rs` makes the sole outbound request (GitHub tags), only when stdout is a terminal.
- **Cancellation is an outcome.** `execute` returns `Err(Cancelled)` once the analysis's flag is set (`Context::cancellable`): it asks between steps and inside the closure, where `Knowledge::close_unless` asks before each held value of a pass and reports whether it reached the fixed point, and it asks once more before returning, so an execution whose closure was interrupted is never returned, whole or partial. The root run, scenario dating, the minimizer and the search propagate it, and `analyze_sessions_cancellable` returns `ErrorKind::Cancelled`. Closures outside `execute` (the union's, withholding, proving) run to completion: their callers assume a fixed point, and the next execution or `Search::done` ends the analysis. Cancellation is not a bound: it yields no verdict.
- `lsp/`: stdio server, debounced worker analysis, documents keyed by URI, no filesystem access. `transport.rs` owns the read loop: a frame of known length that does not parse is answered with an error (`-32700` or `-32600`) and the session goes on, and only a frame whose length cannot be read ends it. The dispatch thread is the one publisher of diagnostics: a worker stores its verdicts and hands its report over a channel. `Runner` keeps each worker's handle; a new analysis joins the cancelled workers on its own thread before it starts, so a cancelled analysis never runs beside its replacement (which would also force the replacement sequential, `live_generations() > 1`) and the dispatch thread never waits. **Both threads set Silent verbosity**, or thread-local output corrupts stdout. Keyword prose lives in `lsp/docs.rs`; primitive docs come from specs.
- `report/mod.rs` builds JSON/HTML/TeX/LSP from one `Run::of` parse; renderers never parse and share its derived facts and `msc::Chart`. **No HTML/LaTeX markup in Rust**: embed templates; `Val::Text` escapes, `Val::Raw` does not. TeX has two dialects, prose and verbatim: model source and diagnostics are set as `\vpline` lines from the token chunks the HTML pane uses, with control characters spelled in caret notation, so no model text is ever read by TeX under changed catcodes. The LaTeX preamble lays out and paginates charts itself. Preserve the no-proof disclaimer. Bless goldens with `VERIFPAL_BLESS_HTML`/`VERIFPAL_BLESS_TEX`; `VERIFPAL_TECTONIC=1` compiles them.
- **Do not add `Span` to `Constant` or process-global mutable state.**

## Testing conventions

- Unit tests are module-local; shared builders live in `src/testing/mod.rs` (unique constant names per test; `trace_constant` after parsing). End-to-end: `run_model("foo.vp", "c0a1")` at two sessions, `run_model_sessions(path, 1, code)`, `run_model_err(path, substring)`, and `run_model_at` outside `examples/test/`.
- Codes follow query order (`c/a/f/u/e`; `0` holds, `1` attack). For each regression obtain `--result-code | tail -1`, **read the trace to justify every bit**, wire its test and write its `// Expected:` header. Pretty goldens live in `examples/test/golden_pretty/`.
- Engine changes need before/after **full-output** diffs over `examples/` at one and two sessions, not just codes. **Always exclude `tls13.vp`, `pqxdh.vp`, `signal_twelve.vp` and `aws_nitro_attestation.vp`** from sweeps and benchmarks; the last needs tens of gigabytes at two sessions.
- `attack_traces_keep_their_shape_and_name_only_wires_that_exist` sweeps `examples/test/` and selected other models at both counts: `// Expected:` headers must match and state the one-session result (`HEADER_OMITS_THE_ONE_SESSION_RESULT` is an empty ratchet), the number of models without a stated result is pinned exactly (`MODELS_WITHOUT_A_STATED_RESULT`), every attack carries a trace at one session and at two, and every replaced or replayed slot must be one an unguarded message carries to that recipient. `inspect_ta.vp` is swept by a test of its own, because three of its one-session metamorphic variants do not finish.

### Metamorphic harness (src/testing/metamorphic.rs)

Missed attacks show up under language-preserving or monotone transforms: parse → transform → `pretty_model` → **re-parse** → `analyze_sessions`, from one-session baselines. A variant that does not re-parse fails its property, as does a baseline or a variant that panics, in every sweep. A variant sanity rejects is counted and printed, and for an invariant property a rejected or differently-dated variant is a violation. Each property has a floor on the pairs it compares, set just below the measured count, so a transformation that stops applying fails.

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
| `restrict` | add last-message preconditions to queries that have none | lose only |
| `permute` | reverse `knows`/`generates`/`leaks` lists, message values, unlinkability/equivalence arguments | invariant |
| `swap` | swap adjacent blocks of different principals | invariant |
| `split_passive` / `split_active` | one message or `leaks` per value | invariant / gain only (a sender lacking one value still sends the others) |
| `delay_passive` / `delay_active` | move every `leaks` to the end of its phase | invariant / lose only |
| `hoist_passive` / `hoist_active` | move every `leaks` to the earliest point in its phase its principal knows the value | invariant / gain only |
| `uncheck` / `check` | remove / add one `?` | gain / lose only, confidentiality and freshness (a halt can withhold the emission an authentication attack needs) |
| `ungenerate` | turn one `generates` into `knows private` | gain only, confidentiality and freshness (equal long-term values add emissions to replay counts) |
| `publicize` | turn one `knows private` constant into `knows public` everywhere, in models without scenarios | gain only, except unlinkability and equivalence |

- `KNOWN_MISSED_ATTACKS` and `KNOWN_BAD_TRACES` are **empty ratchets**, failing for new violations and for exercised entries that stop violating.
- **Do not add `name_intermediate`**: naming a subterm can legitimately change a verdict (`auth_with_signing_false-attack.vp`). Check a claimed metamorphic false attack against the pinned semantics before changing the engine.
- Analyses run to completion: **no timeouts or deferrals**. `VERIFPAL_METAMORPHIC_WORKERS` caps workers (default 4), `VERIFPAL_METAMORPHIC_PROGRESS=1` logs progress and why a variant was rejected, and `VERIFPAL_METAMORPHIC_CORPUS=dir` runs the properties over the `.vp` files of `dir` instead of the swept models, without floors (for fuzzed models). Fast sweeps omit `COSTLY_MODELS`; the ignored `_exhaustively` twins cover them in CI, and every fast sweep has one (`every_fast_sweep_has_an_exhaustive_twin`).

### Completeness audits

Changing candidate generation, union absorption, memos or ordering changes what the search finds; re-measure rather than cite old numbers. Sensitive sites: key-shaped slot variables and the unshaped pass, Targeted-before-Constructed order, tuple arities, free-position filling, goal memo keys, which executions are kept, and the narrowings above. Authentication's positional acceptance is specified semantics, not a bookkeeping bug: changing it needs a semantics decision. Increasing sessions must never lose an attack; compare two- against three-session attacks.

## Style and licensing

- Every source file starts with an SPDX header (`GPL-3.0-only` for code, `CC-BY-SA-4.0` for prose), including `.vp` test models.
- rustfmt with **hard tabs** and Unix newlines; clippy is a hard gate (`-D warnings`).
- **Do not write comments.** Reasoning belongs in the commit message and in this file. `protocol/sessions.rs` keeps a module-level doc and `solve/free.rs` a few item-level docs from before that rule; add none, including to code touched in passing. `.vp` test models are the exception: a new one must carry a `// Expected:` header arguing its code.
- **Keep this file true and lean.** Nothing checks it against the source, so a change that renames, moves or removes what it describes updates it in the same commit. Record a fix by correcting the sentence that states the rule it changed: one claim, the model that pins it and, for a narrowing, the measured cost. Do not append a clause per fix: a paragraph that has grown a list of exceptions usually describes a component that has too, which is the lean-design rule's business.
