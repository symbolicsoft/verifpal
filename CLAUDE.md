# CLAUDE.md

Repository guidance for Claude Code.

## What this is

Verifpal checks `.vp` cryptographic-protocol models for confidentiality, authentication, freshness, unlinkability and equivalence under passive/active attackers. Default: **two concurrent sessions per principal** (`--sessions k`); a hold means no attack found within that bound. One Rust crate (`verifpal` 1.5.2, edition 2024, Rust 1.98, GPL-3.0-only) builds the CLI and separate WASM library for website/VS Code. [User Manual](https://verifpal.com/docs/): language reference; `README.md`: overview; [*From Toy to Instrument: Seven Years of Verifpal*](https://eprint.iacr.org/2026/1654): the language and query semantics.

**An attack is one execution.** `src/engine/` runs every session and scenario copy of every principal together as one execution under a map of attacker installs, with one attacker knowledge set belonging to that execution. A query fails only when the evaluator finds its violation in such an execution. The search (`src/engine/search.rs`, drawing candidates from `src/solve/`) only proposes install maps; it cannot record a result. Nothing reconstructs a joint history after the fact, so no gate has to decide whether one exists.

## Non-negotiable rules

**Declare primitives only in `src/primitive/spec.rs`.** `PrimitiveSpec` / `PrimitiveCoreSpec` own names, arities, outputs, restrictions, decomposition/recomposition/rewrite/rebuild/reuse, checking keys, commutativity, capabilities, core roles and documentation. The engine interprets fields. `PRIM_*` exports are test-only; `the_engine_names_no_primitive_outside_its_spec` rejects ids and quoted primitive names in non-test engine code. If behavior seems to require an id/name check, **add a spec field and generic interpreter**. Ask the registry for tuple, projection and equality roles too.

False attacks and missed attacks are equally serious. Preserve these distinctions:

- Known versus forgeable; replay versus forgery; computed versus emitted; knowledge versus constructibility versus observability.
- **An install is delivered only when the execution's own knowledge derives it at that receive** (`exec.rs::step_run`, `Event::Recv`). Never admit an install from another execution's knowledge, the search's union knowledge or final knowledge.
- **A forwarded value is exactly what the sender's executed send recorded** (`ex.sent[d]`). A guarded slot never takes an install; it takes the sender's value or nothing.
- Own halt, foreign halt and starvation differ. A halted run stops; a run whose next receive has no sent value and no install is blocked, and stays blocked at the end of its phase. A failed decryption is not a value suitable for equivalence comparison.
- Search output is untrusted. Only `engine::judge` over an executed `Execution` reports, and only `Judge::evaluate` mints the `Verdict` that `results_put` requires.
- Simplify duplicate representations, not correctness gates. Unchanged corpus verdicts do not justify removing a gate. Candidate generation and its ordering remain incompleteness sources.

The executable regression inventory is `src/model_tests.rs` and `examples/test/`. Representative paired cases to consult when touching the executor, knowledge or judgment (`@1`/`@2` means session count):

| invariant | regression / counterweight |
| --- | --- |
| Known is not forgeable | `aead_replay_not_forgery.vp`: `a0c0`@1, `a1c0`@2; `examples/transport-layer/piknik.vp`: `c0a0a1a1f0`, with **replays**, never replacements |
| Cross-session replay breaks injectivity | `session_replay_breaks_injectivity.vp`: `a0`@1, `a1`@2; `session_peer_run_matches.vp`: `a0` |
| Histories must coexist | `incompatible_histories.vp`: `a0`; `incompatible_histories_mitm.vp`: `c1a1`; `history_kem_reply_under_secret.vp`: `c0`; `history_dh_reply_under_secret.vp`: `c1c0` |
| Reflection within one execution is an attack | `history_own_later_emission.vp`: `a0`@1, `a1`@2; `history_own_early_emission.vp` |
| Disclosure must precede every affected receive | `causal_late_leak.vp`, `causal_foreign_receive.vp`: `a0`@1, `a1`@2; `causal_foreign_receive_early.vp`: `a1` |
| Halts withhold sends and downstream computations | `halted_peer_relay_holds.vp`, `halted_peer_downstream_reencrypt_holds.vp`: `c0`; companions without `_holds`: `c1` |
| An unavailable route does not make the value unavailable | `closure_route_withheld_by_halt.vp`, `closure_route_collision.vp`: `c1` |
| Installs name values, not slots | `closure_cyclic_union.vp`: `c1c1c1` at both counts |
| An install equal to the honest value is real when the sender now sends something else | `woolam_pi_pristine_pin.vp`: `a1a0`; repaired `woolam_pif_pristine_pin.vp`: `a0a0`@1, `a1a0`@2 |
| Query scope and held slots matter | `equivalence_halt_scope.vp`: `e0`; `precondition_halt_before_send.vp`: `a0a0`@1, `a1a0`@2 |
| Guards preserve upstream control | `forward_transitive_relay.vp`: `f1`; `forward_relay_all_guarded.vp`: `f0` |
| Addressed installs affect one recipient | `split_delivery_equivalence.vp`: `e1`; `split_delivery_through_relay.vp`: `e0` |
| Search must retain deeper terms and oracle chains | `pitoy_depth.vp`: `c0`@1, `c1`@2; `solver_oracle_chained_inputs.vp`: `a1`; separated companion: `a0` |
| The attacker must reveal an existing link | `unlink_forced_equality.vp`, `unlink_forced_origin.vp`: `u0`; `unlink_active_links.vp`: `u1` |
| Weakening preserves key boundaries | `cap_forgeable_other_message.vp`: `c1`; `cap_forgeable_other_key_holds.vp`: `c0`; `cap_forgeable_still_binds_its_key.vp`: `a1` |
| Acceptance counts runs of one agent | `four_party.vp`: `c1a0a0a0`@1, `c1a1a1a0`@2 |

Pin new regressions beside a counterweight, read their traces, and test session-sensitive claims at both counts. `run_model` prefixes `examples/test/`; use `run_model_at` for other paths.

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

CI runs clippy, release tests and exhaustive sweeps on Ubuntu/macOS, plus WASM clippy. **CI runs only when the commit title contains `[ci]`**, or on manual dispatch. Formatting is not gated there; use `make lint`.

`verify` accepts several models. `--result-code` suppresses only the banner; read the **last line** (`| tail -1`). It cannot accompany `--format json|html|tex`. HTML is self-contained; TeX compiles with tectonic. `--fail-on-attack` returns nonzero for attacks. `--auto-queries` replaces queries; `--saturate` raises the session bound. Other commands include `about`, `diagram` (Mermaid), `lsp`, `completion` and hidden `man`. JSON/HTML/TeX/LSP share `src/report.rs`; editor plugins are thin clients.

For wrong active-attacker results, start with `VERIFPAL_SOLVE_DEBUG=1`. It logs to stderr, prefixed `[search]`: each proposal round (`<Principal> <targeted?> known=… proposals=…`), every install map tried (`try [Run.slot=value …] stuck=… known=…`) or derived from another candidate (`derived <family> […] stuck=… halted=[…]`), check repairs, each round's union growth, and per-family tried/accepted counts at the end. Errors carry source `Span`s; `or_span` preserves the narrower span, and `.located(file_name, &model.source)` makes plain `Display` positional.

## Crate layout and features

- Lib `verifpal` (`cdylib`, `rlib`), bin `src/main.rs` (default `cli` feature). CLI stdout uses `out!`/`outp!`, ignoring closed pipes.
- **Engine modules are `pub(crate)`**; only `lib.rs` re-exports are public. Keep `#![warn(unreachable_pub)]` / `#![forbid(unsafe_code)]`.
- No `tests/` directory: integration targets collide with the `cdylib` artifact; use `src/model_tests.rs`.
- Features: default `cli` (clap, colored, ureq, rayon, `lsp`); `language` (lsp-types only); `lsp` (`language`, crossbeam, lsp-server); `wasm` (`language`, wasm-bindgen, js-sys). Language items the WASM build does not use carry `cfg_attr(not(feature = "lsp"), allow(dead_code))`.
- `src/wasm.rs` holds every export. Each takes and returns JSON strings and never panics on bad input. `wasm_verify`/`wasm_pretty` shapes are depended on; do not change them. `wasm_analyze(input, options)` runs the CLI's `--sessions`/`--auto-queries`/`--saturate` through `verify_parsed`/`saturate` and adds `Run::of`'s model report and, on request, `html_report`. `wasm_check` is the LSP's live diagnostics; `wasm_language` answers hover, completion, signature help, definition, references, highlights, rename, symbols and inlay hints in LSP JSON with UTF-16 positions; `wasm_suggest_queries` returns `auto_queries` as canonical query lines; it alone parses with `parse_string_queries_optional`, which accepts a missing or empty `queries` block and keeps every other check. The language exports run under `InfoQuiet`, since wasm32 messages ignore verbosity.
- `info::wasm_messages_*` buffers output for `messages`. On wasm32 each buffered line (`"message"`) and the search status line, throttled to 100 ms (`"status"`), also go to `globalThis.verifpalProgress(kind, text)` through a `catch` import, so an absent or throwing handler is ignored. On wasm32 `info_status_elapsed` reads `js_sys::Date`, so reports carry real elapsed time, while the forwarded status line omits it. Imported JS panics natively: gate those calls on `target_arch = "wasm32"`; the `wasm` unit tests run natively.
- `parallel.rs` is the sole rayon seam, with a sequential WASM twin: **change both and run the WASM check**. `map_ordered` preserves order; `VERIFPAL_THREADS=n` sets pool size, `1` is sequential (`an_analysis_is_identical_under_one_thread_and_many`). Only the solver's pure proposal work runs on workers (`solve::propose`); execution, knowledge closure, judgment, reporting and every `VerifyContext` write stay on the caller thread. `VerifyContext` is interior-mutable and `Sync` (`everything_a_worker_borrows_is_sync`).
- Thread-local caches use `context::Generational`, clearing on first access in a different generation to prevent cross-model id contamination. **Internal parallelism only with one live analysis**: `live_generations() > 1` makes `map_ordered` sequential. `DeductionMemo::scoped` installs/restores the theory's deduction memo.
- **Always use `--release`**: opt-level 3, fat LTO, one codegen unit, abort panics, stripped symbols.

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

- `[e]` on a message guards it against replacement; `?` checks an operation and halts its principal on failure. `leaks x` discloses a known value. `_` is an anonymous assignment output. `phase[N]` must increment by exactly one.
- `queries` is required and last. Optional `scenarios[Alice[gpeer = gb] Alice[gpeer = gm]]` immediately precedes it. Queries also include `freshness? x`, `unlinkability? a, b`, `equivalence? x, y`; the last two require distinct constants. An option such as `[precondition[Alice -> Bob: e]]` restricts a query to executions reaching that send.
- Names are case-insensitive; principals title-case, constants lowercase. Maximum 128 principals; `.vp` filenames at most 64 characters. Constants cannot shadow reserved words, primitives, `attacker*` or `unnamed*`. Nesting limit is 64.
- No repeated assignment/generation, conflicting `knows`, unknown sends or already-known receives. Authentication needs sender knowledge and recipient receipt/use in a primitive. `nil` is allowed in equivalence, not as a confidentiality/freshness subject. Comments round-trip through `pretty`.
- Capabilities: `PUBKEY[weak](a)`, `SIGN[forgeable](sk, m)`, `AEAD_ENC[weak, forgeable from phase 2](k, n, m, ad)`. Onset belongs to the preceding capability and persists from N, default 0. `weak` exposes declared reveals; `forgeable` permits authenticity-breaking construction under its annotated secret; `malleable` reshapes an eligible held ciphertext under an unknown key (ENC only). These words and `from` are contextual, usable as constant names.
- `THRESHOLD_SPLIT[3](k)` binds 3-of-n shares, with n determined by assignment outputs (2–16). Threshold participates in identity. `distinct_per_assignment` stamps `Primitive.instance` from the first output's base constant id, shared by session/scenario copies: separate sharings never mix. `THRESHOLD_JOIN` combines shares/partials; `THRESHOLD_SIGN(share, nonce, commitments, message)` creates a partial.

## Architecture

### Pipeline

```
parse_file (parser.rs)              hand-written recursive-descent, comment-preserving AST
  → expand_scenarios (scenario.rs)  one model copy per declared peer scenario
  → expand_sessions (sessions.rs)   k copies of that, one per concurrent session
  → sanity (sanity.rs)              model validation; drives construct.rs
      → construct_protocol_trace    "km": ProtocolTrace — global immutable protocol description
      → construct_principal_states  one PrincipalState per principal copy
  → VerifyContext::new (context.rs) results, envelopes, claims, term bound
  → engine::verify (engine/mod.rs)
      → Program::of                 every copy as a straight-line run
      → execute(&[])                the honest execution; judged at once
      → check_honest_run            honest checked failures are model errors; argument
                                    restrictions checked at every slot the honest execution reaches
      → Search::run                 active attacker only, while queries remain
  → verify_end                      prints results, returns the results code
```

`verify::analyze(&Model)` is the **one** place that sequence exists; it is `analyze_sessions(m, DEFAULT_SESSIONS)`, and `wasm_verify` and the LSP call it too, while `wasm_analyze` takes the CLI's `verify_parsed` path at `DEFAULT_SESSIONS` unless asked otherwise — **do not give one entry point its own default.** Throughout, `km` is the `ProtocolTrace`, `ps` a `PrincipalState`, `cx` the engine `Context` (program, `km`, carrier state, initial knowledge) and `ex` an `Execution`.

### Program (engine/program.rs)

`Program::of(model, km)` flattens the expanded model into one `Run` per principal copy: a list of `Step { event, phase }` with `Event::{Hold, Assign, Leak, Send(d), Recv(d)}` in declaration order. `Delivery { sender, recipient, slots: [(slot, guarded)] }` indexes messages; a message becomes a `Send` in its sender's run and a `Recv` in its recipient's. `step_of_slot` maps a slot to the step that first gives it a value in that run. Copies have no message edges between them except those the expanded model declares.

### Execution (engine/exec.rs)

`execute(cx, installs)` with `Installs = Vec<(run, slot, value)>` produces one `Execution`: per-run environments of `Held { value, pre, sender, installed, authored }`, program counters, halts, recorded sends (`sent[d]`), the order in which steps ran, one `Knowledge`, and per-phase knowledge snapshots when the model has phases.

- Phases are barriers. Within phase N every run advances while its next step belongs to a phase ≤ N; the loop repeats until no run moves. Enabling is monotone within a phase (knowledge only grows, recorded sends are never retracted), so this greedy fixpoint is the unique maximal execution for the install map, independent of run order.
- `Hold` binds the declared value. `Assign` resolves the expression against the run's environment and reduces it with `theory::can_rewrite`; a failed checked primitive halts the run at that slot. `Send` records the held values and teaches them to the attacker (`Origin::Wire`). `Leak` teaches the held value (`Origin::Leak`).
- `Recv`: per slot, an unguarded install equal to the forwarded value is not an install; any other install must be `deliverable` (registry-admissible, no failed checked rewrite inside) **and derivable from this execution's knowledge at this moment**, or the run blocks. Without an install the slot takes `sent[d]`; if the sender has not sent, the run blocks. A received value is `authored` when installed or when the sender's own copy was authored (relay authorship).
- At a phase end, a run blocked at a receive that carries an install is `stuck` (the install never became derivable); unguarded slots of an unsent delivery that carries some installs are `partial`. Runs that could not finish the phase are `frozen` and never resume. Knowledge closes at each phase end and at the end.
- Causal availability, history coherence and cross-execution consistency are not checked anywhere: an install can only be spent in the execution whose disclosures derive it, at the receive where it is delivered.

### Knowledge (engine/knowledge.rs)

`Knowledge` wraps one `AttackerState` with an `Origin` per value (`Initial`, `Wire { run, slot }`, `Leak { slot }`, `Derived(DerivationRecord)`) and the `protocol` terms (value, unreduced form, produced-by-a-principal flag) seen in the execution. `close(ps)` is a monotone fixed point over fresh snapshots:

1. Held values: `can_decompose`, `can_break_weak`, `rewrite_build`, and core-reveal fragments.
2. Reconstruction candidates (every subterm of protocol terms): `can_reconstruct_primitive`, recording `Reconstructed`, `Combined`, `Broken` (capability) or `ReusedForge`.
3. Threshold splits: `can_recompose`, skipped once the secret is held.
4. Forward rewrites of protocol terms whose arguments are all `obtainable`.
5. Reuse pairs (`reuse_pairs`) and their declared reveals.

`derivable(v, ps)` closes, then asks `theory::obtainable`. Every learned value keeps its `DerivationRecord`; narration depends on it.

- `rewrite_build` constructs a rewrite around a held value, learning changed reducts as `Rewritten { built: true }` (`blind_signature_attacker_unblinds.vp`). Skip checks with an already-held fixed `RewriteTo` and no rebuild/combine rule.
- **Nonce reuse pairs coexist by construction**: both members are in one execution's knowledge. `reuse_pairs` buckets held ciphertexts by the rule's `fixed` positions, skips buckets whose fixed positions are obtainable, and skips members the attacker could mint unless a principal built that term. `Knowledge::built` holds only the constructors an assignment applied: nodes of its declared expression and nodes its reduct reassembled. A received argument is not built by the principal that hashes it. Pins: `aead_nonce_two_executions_not_a_reuse.vp` (`c0` at both counts), `cap_forgeable_is_not_a_reuse_pair.vp`, `cap_forgeable_hashed_is_not_a_reuse_pair.vp` against `cap_forgeable_inline_reuse_pair.vp`, `aead_reuse_public_payloads.vp` (`c1c0c0`).

### Judgment (engine/query.rs, engine/view.rs)

`Judge { cx, ex, knowledge, honest, states, claims, views }` evaluates one query against one execution at one phase. `honest` is the install-free execution. `claims` is `VerifyContext::claims_apply_at` (scenario corruption). `evaluate` first requires every precondition's named send to have executed, then returns a `Violation` and a `Verdict` token.

- **Confidentiality:** some claimed run holds the queried slot and the phase knowledge holds its value. The report labels `AttackerSuppliedValue` when the value differs from the honest reduct and carries no fresh or private leaf.
- **Authentication:** injective agreement at the recipient run `b`. The slot must be held with a sender and used positionally (`uses`: every slot that mentions it reached, one use succeeding or unchecked). A slot mentions it through the run's own assignments. Only when the run has no such slot are its uses found as sanity finds them, through other principals' computations (`state_mentions`): `auth_use_through_guarded_relay.vp` (`a1`), `auth_use_through_checked_relay.vp` (`a0`). Widening this for runs that do use the value directly adds later unreached uses and loses Lowe's attack (`spore_ns_pk.vp` at one session). Unauthored from a different principal: `Substituted`. Authored and different from the honest reduct: count emissions of an equivalent value by interchangeable senders (`km.interchangeable_for`, per slot) at sibling slots, delivered to runs of the recipient's agent (`km.same_actor`), excluding authored copies. None: `Forged`. Otherwise count acceptances of that value across the agent's runs; more acceptances than emissions, over an install or an open leg: `Replayed`, reported as `DuplicateAcceptance` when the recipient contributed a fresh value to it and `ReplayableFirstFlight` otherwise.
- **Freshness:** a claimed run holds and uses a value with no fresh leaf: `Stale`. Freshness generates no solver proposals.
- **Equivalence and unlinkability** reuse the `PrincipalState` evaluators: `view::project` turns run `r` of the execution into a state (values, `pre_rewrite`, `original` from the honest run where authored, provenance, `foreign_halts`, `starved`, `halted_at` truncation). Equivalence requires every slot held in this execution (never the honest fallback of an assignment that did not run: `equivalence_unexecuted_assignment.vp`), reached, not starved and not a failed check. Unlinkability calls `unlink::find_link_witness` over the projected state and the phase knowledge.

`unlink.rs::find_link_witness` tries observable equality, an identifying check, a common secret origin, then a recognized secret that can be tested but not recomputed. These predicates are not two-world behavioral equivalence. Preserve all gates:

- Queried values must be observable and not attacker-authored; honest **unreduced** values must already share a secret subterm. Equality also requires honest reducts equal. Reject attacker-supplied witnesses.
- Non-equality witnesses must carry a secret leaf honestly shared by both values. The secret must remain derivable after **either** queried value and its consequences are withheld; joining queried shares is not their origin.
- Observability needs knowledge **and** extraction from a wire/leak. Follow exposed tuples and actual decomposition/weakening/reuse reveals, never arbitrary arguments or unrevealed keys. Close observed values under tuple assembly only. Reuse counts only while both members remain held.
- Try exposed tuple components and reconstruction ingredients. Checks must be runnable with every required input, distinct matching positions and successful `can_rewrite`. Public identifiers identify nobody; exclude `check_key` constructor applications from recognized candidates.

### Reporting (engine/mod.rs, engine/narrate.rs)

`judge(ctx, cx, ex, installs, honest, states)` evaluates every unresolved query and its session/scenario variants at every phase. On a violation, `minimal` shrinks the install map: drop one install, or two installs on the same received message, re-execute, and keep the drop when the **same query** still fails at the same phase with nothing stuck; repeat until nothing drops. The minimized execution is narrated and recorded through `query::record_verdict`.

`Narrator` walks the execution's step order. Before each receive that took installs it explains each installed value from the knowledge prefix available at that receive (after its closure): origins become "observes … on the wire", "is handed … by a leaks declaration in <run>", or the derivation record's step. A value not yet recorded is narrated as a construction from its arguments, recursively, when those are available at that point (DH terms may be read in their swapped orientation); otherwise through `KnowledgeInputs`. An installed value equal to a sibling slot's emission in this execution is a **replay** ("Attacker replays x (A to B) from another session|scenario, where it is v"); any other install is a replacement ("Attacker replaces x, y (sent by A to B) with …", noting the honest values, or, for an install equal to the honest value, what the sender sent in this execution). Each checked assignment that passes on an attacker-influenced input (an authored slot in its own cone) gets a `gate` step where the run performed it. Context steps: a public value, a principal-substituted receive, the leaves of a stale value, and resolved values for equivalence/unlinkability. Conclusions name the use site by its declared expression. Every line is also a structured `TraceStep` (`derive`, `mutations`, `replay`, `gate`, `received`, `static`, `resolves`) for JSON/HTML/TeX/LSP.

Terms are written in the model's vocabulary. `Names` maps every value held at a named, non-authored slot of the execution (value and unreduced forms, never bare constants or `PUBKEY(nil)`) to its slot name, preferring unchanged names and then session-1 names. A name is *shaped* when its slot holds something other than its honest value; a shaped name is still used inside terms, but as the subject of a construction it is spelled one level out ("constructs gab, where it is DH_KEX(gb, nil)"). Replacements name a delivered value only by an unshaped name; replays, gates and parenthesized conclusion values spell their terms, excluding the step's own base name. Displaced honest values are named from the honest execution. DH terms are shown in the orientation whose arguments the attacker holds at that step.

Words require evidence: "from another session" only for a sibling's actual emission in this execution; "on the wire" only for a recorded send. Never call another concurrent run "earlier".

### Search (engine/search.rs)

`Search` keeps accepted `Node { installs, ex }`, a **union** knowledge over them with per-value provenance (which nodes supplied it), and the union closed. The union is only where candidates come from; nothing is ever delivered from it.

- `fixpoint` rounds: for every run, Targeted then Constructed proposals from `solve::propose` against a symbolic state (`solve::symbolic`) with the union as attacker knowledge; then close the union, merge sources for unresolved confidentiality targets, and retry stuck candidates; stop when the union stops growing. **Run Targeted for all runs before Constructed for all**; interleaving changes verdicts. `run` then repeats with honest-input refinement (`slots_blocking_reduction`) and, if that grew the union, once more unrefined. Split deliveries also get an addressed pass (`build_addressed`).
- A proposal becomes installs at every unguarded receiver of the slot (one receiver when addressed), bounded by `TermBound::admits_at` (a cut notes `Truncation::TermDepth`). `bases` adds the installs of accepted nodes whose executions derive values the proposal needs; a value not yet derivable is allowed only when this principal emits it under the other installs (`emissions_under`: an oracle chain, delivered because the victim's own run discloses it first).
- Candidate families: `base`; `fill` (unguarded slots of a partially installed unsent message take the honest value if derivable, else nil); `repair` (`Deducer::repair_check` rebuilds a halted check's inputs, retried while the halt moves later); `drop` (every single-install removal of a multi-install single-run flight); `merge` (sibling-copy transfer of accepted installs; merges of the nodes supplying a confidentiality target's derivation leaves); `stuck` (a stuck candidate retried with each accepted node that freshly emits the stuck value, never cascading; sources are kept per value, emitting run and set of runs the source installs at, since sources touching different runs are different ways to produce the value); `cleared` (when that merge stays stuck, the same merge without the candidate's installs inside the causal cone of the source's emission that disagree with what the source's execution received there: solver fillers such as `nil` otherwise undo the source, `woolam_pi_pristine_pin.vp`); `admitted` (a stuck candidate's non-stuck installs).
- `settle`: every unstuck execution is judged. It is kept when it teaches the union a value the union cannot obtain, a principal-produced emission within the term depth, a new reuse pair, a fresh emission, or an alternative non-honest route to a value. **No caps on kept alternatives**: `matching_run_recipient_halt.vp` stays monotone under `unguard` only because every execution supplying a non-honest term is kept. Tried install maps are deduplicated by content.
- Deducer exhaustion marks `Truncation::SolverVariables`. Cancellation and `all_resolved` stop every loop.

### Solver (src/solve/)

The solver is the candidate generator. It never sees an execution and its output is only ever an install map.

- `control.rs`: `Controllable` (which slots the attacker can replace in a phase; only this module mints it), `TermBound` (per-slot shape bound: protocol depth plus recipient peel depth, excess only from protocol subterms), `attacker_authored` (compared with the honest trace reduct, cached per slot and constant).
- `symbolic.rs` replaces controllable wires with variables and reduces like concrete execution. Reject self-created, wrong-phase, unused and nil slots; equivalence-named slots waive unused. `build_addressed` adds a pass for a direct unguarded delivery also sent to another recipient by a **different sender**; refuse when the other delivery passes through that owner.
- `vars.rs` separates slot variables (`0x8000_0000`) from free choices (`0xC000_0000`). `matching.rs` provides one-way matching, two-way unifiers and merge modulo commutativity: **retain every alignment until all pending equations succeed**; reject occurs cycles.
- `deduce.rs` tries held values, variables, replay, wire unification, finite-basis oracles, rewrite matching, argument construction, decomposition and check inversion. Memo keys include the **whole substitution**; never cache cycle-cut results. Rewrite inversion carries every unifier; nested decomposition retains every outer opening requirement. `repair_check` serves the search's repair family.
- `diverge.rs` distinguishes installed tuple projections using derivable fillers; `keyed_free`, `preserved_free`, `aligned_held_free` restrict fillers to protocol terms. Arbitrary held terms inflate the basis.
- `mod.rs::propose`: query goals, constraint goals, blanket substitutions, single-slot substitutions, then Constructed sibling flights and protocol/rewrite candidates. Proposal lanes run on `map_ordered` with disjoint free-variable bands. `leave_honest_slots` removes honest bindings unused elsewhere; `install_signature` dedups by reduced concrete installs. Do not revive `skeleton.rs` or give the attacker shapes it did not derive.

### Parallel sessions (sessions.rs)

`expand_sessions` clones principal/message blocks before sanity. Fresh/assigned constants become `c#s`; `knows` constants stay shared. Scenario/session expansion requires `s*k <= 31` (`MAX_COPIES = 30`). Original queries cover session 1; variants share `query_index`. Keep scenarios and sessions distinct. `km.session_siblings` and `km.copy_siblings` group a constant's copies; `km.interchangeable` and `km.actors` group principal copies for sender matching and recipient agents. Clones are runs, not agents: match recipients by agent, compare scenario interchangeability per slot (`interchangeable_for`); base-name canonicalization excuses Lowe's attack.

### Peer scenarios (scenario.rs)

Scenarios expand **before sessions**. Each entry is a whole-model configuration rebinding one principal, dropping its bound `knows`, substituting throughout that principal and freshening outputs. Entries are not a cross product: p principals, s entries and k sessions yield p×s×k runs. Reject undeclared values/principals, non-`knows` targets, duplicate targets and wire targets. Identity bindings are no-ops. Normalize honest-first; query variants cover honest scenarios, then sessions.

- `compromised_constants` asks what is computable. Seed secrets leaked/sent bare at disclosure time, including assigned private keys and tuple-exposed secrets. Generated constants qualify only at registry `secret_positions`; public identifiers/salts do not. Follow aliases/nested tuples only through `reveals_args`. Derivations need **every** ingredient public, nil or compromised; date them at the latest ingredient.
- `scenario_corrupt_from` asks whether a binding identifies a controlled peer: a bound value may be compromised **or mention** one.
- `VerifyContext::is_honest_at` governs honest-run checking by slot creator (honest failed checks are model errors; corrupt creators just halt); `claims_apply_at` governs query eligibility.

Acceptance pair: `spore_ns_pk.vp` (`c1a1a0`, Lowe attack), `spore_nsl_pk.vp` (`c0a1a0`). **Do not add scenario-free variants to `examples/`.**

### Verdict envelope

`VerifyResult` carries `Envelope { sessions, truncations }`, printed after PASS (`[search exhausted at 2 sessions]` / `[search truncated: term depth]`) and serialized as `QueryReport.envelope`. Attacks are unqualified by envelopes; FAIL may carry `Subtype::{AttackerSuppliedValue, DuplicateAcceptance, ReplayableFirstFlight}`. `VerifyResult.notes` supplies `Note:` lines; spanless auto-queries set `QueryReport.generated`. Empty notes/generated fields are omitted from JSON. `Truncation::TermDepth` and `Truncation::SolverVariables` attach to queries **unresolved when encountered**; `finalize_envelopes` preserves that scope.

**"Exhausted" means this engine's search space at these parameters, never absence of attacks.** Do not describe results as "proof", "verified", "correct" or "complete".

### `--auto-queries` and `--saturate`

`autoquery.rs::auto_queries` **replaces** queries after `sanity` validates the original model. Generate confidentiality for each fresh/private trace constant, authentication for each delivery used in a recipient primitive, freshness for every sent-and-used constant; skip unlinkability/equivalence (`generated_queries_all_pass_sanity`).

`verify::saturate`, behind `saturation_sessions` and `wasm_analyze`, tries `DEFAULT_SESSIONS` through `SATURATE_MAX` (4), stopping at the first repeated result code and returning that count's **analysis**. Each round's output is captured (on wasm32 too) and only the reported round's is replayed. Starting at one would stop before three-run attacks (`saturation_never_stops_before_it_has_looked_above_the_default`). `attack_disappeared` warns about attacks vanishing at higher counts: an engine bug.

### Core data model (types.rs)

- `Value = Constant | Primitive(Arc)`; constants are model-interned ids (nil = 1). **Equivalent values must have equal hashes**: knowledge first selects a hash bucket. Registry commutativity drives equivalence, hashing and matching; structural identity also retains checked-instance distinctions.
- **Terms are DAGs.** Memoize transformations by input `Arc`, comparisons by pointer pair. `subterms` visits primitive pointers once in encounter order; `constant_leaves` follows aliases with a cycle guard. Never prune by term hash: collisions/equivalent DH terms hide distinct subterms. Rendering can still expand exponentially.
- Changing a multi-output `output` clears its cached hash. Pointer caches retain references preventing address reuse; eviction changes only recomputation. `NameTable` uses hash buckets plus full equivalence.
- **Capabilities do not affect term identity.** Read the state's `CapabilityIndex`, never a deduped held term. Collect annotated calls independently; reduce arguments while retaining annotations.
- `PrincipalState` remains the input shape for sanity, the solver, unlinkability and equivalence: `original` = honest computation/belief; `pre_rewrite` = mutated/unreduced; `value` = mutated/reduced. The engine's own `Held` keeps `value` and `pre`; `view::project` fills the rest.
- `AttackerState = { current_phase, known, known_map, derivations, reused, chain }`. **Length-keyed memos need chain identity**: every learn and phase change mints a new `chain`.

### Equational theory (theory.rs + primitive/spec.rs)

`PrimitiveSpec` declares decompose, recompose, rewrite, rebuild, combine and checking-key metadata; `theory.rs` interprets them. `obtainable` is the common argument-recovery cascade. Decompose returns a **set** of `Reveal::Argument(i)` / `Reveal::Output(i)`, covering everything the legitimate key holder learns: `KEM_ENCAP` reveals secret **and randomness** (ML-KEM re-encryption re-derives coins). Consumers name projections via `rewrite.from_output` / `decompose.output`. Recompose/rebuild count distinct projections of one split against its threshold (`shares_of_one_split`).

- Rewrite `matching` is a **bijection** onto distinct inner positions; overlapping `RINGSIGNVERIF` `inner_idxs` must not collapse a ring (`ringsign_ring_collapse.vp`).
- `can_reconstruct_primitive` refuses irreducible core applications: `ASSERT` is a check; reducing `SPLIT` still reconstructs.
- `obtainable` opens a `DeductionMemo` scope when absent for its principal/snapshot, shares subproofs within direct calls and restores enclosing scopes (`shared_transcript_bypass.vp`, `c0`).
- **No recursion cap.** `to` rules return subterms or reassemble strict subterms: depth descent is well-founded.
- `can_rewrite` is the sole reducer: argument reduction, `can_rebuild`, `can_combine`, then rewrite. Report failed outer checks, preserve partial argument reductions (`failed_checks_preserve_originals_unless_a_subterm_rewrites`).
- **Add primitives only in `src/primitive/spec.rs`**, using `build_primitive_specs`; core entries use `build_core_specs` plus `core_rule_*`. Then add model tests. `every_spec_index_is_within_the_primitive_it_is_declared_on` checks direct indices against narrowest arity, checked indices against widest.

Weakening: `forgeable` needs no source application; `weak` and `malleable` do. `malleable_source` chooses an eligible held annotated ciphertext matching fixed positions, and derivation ingredients retain it; omitting it admits time-travel forgery. A capability exemption **adds** an unsolved option while retaining solved alternatives; replacing them loses attacks. Constructibility concerns the **reduct**, not an unreduced operation's hidden key (`solver_constructible_reduct.vp`).

### Nonces (AEAD)

`AEAD_ENC` declares `ReuseRule { fixed: [0, 1], reveals: [Argument(2)], forgeable: [0, 1] }`: two non-equivalent held ciphertexts with equal key/nonce form a pair. Different AD counts; identical key/nonce/message/AD does not. Effects are confined to the reused nonce.

- **Recovery** unconditionally learns both plaintexts. This deliberately over-approximates real XOR leakage when neither is known. The mint/`built` rule keeps `forgeable` from becoming `weak` (`cap_forgeable_is_not_a_reuse_pair.vp`, `cap_forgeable_guard_never_adds_an_attack.vp`); `threshold_sign_forgeable_is_not_a_reuse.vp` reveals its share through public-nonce disclosure, not reuse.
- **Forgery:** held replacement message/AD suffice with `forgeable` positions exempt in `can_reconstruct_primitive_directly` (`Forged::Reuse` names the pair) and `deduce.rs::solve_by_reuse` (`aead_nonce_reuse_forgery.vp`).
- Decryption requires key **and nonce** (`given: [0, 1]`), so expose the nonce when attacker decryption is intended. `knows` nonces are session-shared; `generates` nonces are fresh (`aead_nonce_reuse_sessions.vp`: `c0`@1, `c1`@2).

### Threshold primitives (FROST)

`THRESHOLD_SPLIT[t](k)` models dealer sharing; `THRESHOLD_SIGN(share, nonce, commitments, message)` creates a signing partial. `THRESHOLD_JOIN` interpolates shares, partials or verification shares. Registry `CombineRule`/`CombineBinding` require distinct projections of one sharing, agreed fields and each nonce's public commitment in the agreed tuple. Signing joins become ordinary SIGN; verification-share joins become PUBKEY. Commitment binding prevents mixing sessions.

- `can_combine` shares the reducer with rebuild; `solve_by_combination` retains a take/skip frontier to threshold, with shared agreed variables and per-partial free variables. Retain **distinct substitutions and counts**, not every subset. Record `Combined { from }` with actual ingredients.
- Reusing share/nonce across two partials reveals the share. This deliberately abstracts FROST's two nonces into one Schnorr nonce and fires at two uses. A single partial also reveals its share if the complete nonce, commitments and message are disclosed; a public commitment alone does not.
- Model dealer channels with confidential authenticated transport; guards prevent replacement, not disclosure. Represent DKG by a principal splitting a fresh key it never otherwise uses.
- Metamorphic threshold lowering cannot lose attacks; raising cannot add them. Skip equivalence/unlinkability because threshold affects term identity.

### Result-writing boundaries (query.rs::tcb_tests)

Source-level tests pin these boundaries; they do **not** prove evaluator correctness:

- `results_put` requires a `Verdict` token; only `Judge::evaluate` constructs one (`a_verdict_is_minted_only_by_the_evaluator`), and only `engine::report` records one (`results_are_recorded_only_by_the_execution_judge`).
- The evaluator is handed one `Execution` and never `VerifyContext` (`the_evaluator_judges_nothing_but_an_execution`); executions come only from `execute`, called by the root run, the minimizer and the search.
- The receive arm gates installs on derivability (`an_install_is_delivered_only_once_it_is_derivable`); a receive without an install takes the sender's recorded send (`a_forwarded_value_is_only_ever_what_its_sender_sent`).

Adding a query kind must update `Judge::evaluate`, `Violation`, `report` and `goals_for_query`.

### Supporting modules

- `parser.rs` preserves comments and skips a leading BOM by position. `pretty.rs` is pure, idempotent, golden-tested and **not sanity-gated**; it owns AST `Display`. `resolution.rs` follows bare aliases with cycle guards; registry argument normalization bounds forbidden nesting.
- `info.rs` handles output, silent probes and saturation capture. `update.rs` makes the sole outbound request (GitHub tags), **only when stdout is a terminal**; network work under pipes delayed exit.
- `lsp/server.rs` uses stdio, debouncing, worker analysis (`analysis.rs`) and URI-keyed documents (`state.rs`) without filesystem access. Only the server, `analysis.rs` and `proto.rs` need `lsp`; the rest also serves the WASM language exports. **Both threads set Silent verbosity** or thread-local output corrupts stdout. Keyword/query prose lives in `docs.rs`; primitive/capability docs come from specs.
- `report.rs` supplies JSON/HTML/TeX/LSP. Ranges use byte offsets and 1-based line/column, not LSP positions. Parse once in `Run::of`; renderers never parse. Include leak-only principals. Session/scenario suffix notes appear only when a structured trace step names a `#`/`@` value.
- **No HTML/LaTeX markup in Rust.** Embed templates/assets; `Val::Text` escapes, `Val::Raw` does not. Tests reject missing/unused placeholders. LaTeX figures retain paired extraction markers and `\vp…` macros; `listing_safe` excludes embedded `\end{lstlisting}`. The preamble lays out and paginates charts itself, so Rust estimates no heights: every row and every box line is a strip measured where it is drawn, spanning the chart's fixed width so all strips scale alike; the column is set whole when it fits (or moves whole when under a page and less than half a page remains), otherwise `\vsplit` at each page end under repeated plates, and always whole inside a float or minipage (`\ifinner`). Verdict and summary tables are `longtable`s with fixed column widths. Keep `\color` out of titlesec's vertical-mode format argument: its whatsit lets a page break separate consecutive headings. Preserve the no-proof disclaimer. Bless goldens with `VERIFPAL_BLESS_HTML`/`VERIFPAL_BLESS_TEX`; `VERIFPAL_TECTONIC=1` enables compilation.
- `msc.rs` shares diagram rows; `tokens.rs` indexes even failed parses. **Do not add `Span` to `Constant` or process-global mutable state.** Interners are parser-owned and error before ids enter attacker/copy/solver bands.

## Testing conventions

- Unit tests: module-local `#[cfg(test)] mod tests`; shared builders in `src/testutil.rs`. End-to-end tests: `src/model_tests.rs`, `run_model("foo.vp", "c0a1")` at shipped default two sessions; `run_model_sessions("foo.vp", 1, "a0")` for explicit counts; `run_model_err("foo.vp", "error substring")` for rejection. Pin session-sensitive verdicts at both counts.
- Codes follow query order: `c/a/f/u/e`, `0` holds, `1` attack. Add each regression under `examples/test/`, obtain `--result-code | tail -1`, **read the trace to justify every bit**, add its test and `// Expected:` argument. Every test model must be wired. Pretty goldens: byte comparisons in `examples/test/golden_pretty/`.
- Shared `testutil::test_value_id` interner requires unique per-test constant names. After parsing, obtain handcrafted constants with `testutil::trace_constant`.
- Engine changes need before/after binaries and **full-output** diffs over `examples/` at one and two sessions, not just codes. **Always exclude `examples/transport-layer/tls13.vp`, `examples/messaging/pqxdh.vp` and `signal_twelve.vp`** (prohibitive cost; none in model tests). Keep PQXDH out of test sweeps.

### Checking *why* a verdict happened, not just that it did

`attack_traces_keep_their_shape_and_name_only_wires_that_exist` sweeps `examples/test/` plus `SWEPT_MODELS_OUTSIDE_EXAMPLES_TEST` (HPKE, messaging except `signal_twelve.vp`, simple/contact-tracing models, and `cloudbackup.vp`) at one and two sessions:

- `// Expected:` headers must agree with the codes produced; the undocumented-model ceiling (`undocumented <= 126`) is a ratchet.
- Every attack carries an `Attack trace:` (`ATTACK_IS_REPORTED_WITHOUT_A_TRACE` is an empty pin).
- Every "replaces"/"replays" step must name a slot some message in the model carries to that recipient, and a slot every message guards may not be named at all.

Replay and holds need no separate harness: every reported attack is the judgment of an execution, and its narration is of the minimized execution that was judged.

### The metamorphic harness (`src/metamorphic.rs`)

Detect missed attacks by language-preserving or monotone transforms: parse → transform → `pretty_model` → **re-parse** → `analyze_sessions`. Baselines use one session. `settle` enforces comparison floors; counts live in the harness and must be re-measured.

Set `VERIFPAL_METAMORPHIC_PROGRESS=1` to log each worker's current model, session count and scenario count during long sweeps.

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
- **Do not add `name_intermediate`.** Naming a subterm can turn a use inside a failing check into a separate successful use; it is not invariant (`auth_with_signing_false-attack.vp`). Check claimed metamorphic false attacks against pinned semantics before altering the engine.
- Analyses run to completion: **no timeouts or deferrals**; skip parse/sanity failures. `spread` / `worker_cap()` cap workers (default 4, `VERIFPAL_METAMORPHIC_WORKERS`); stronger-attacker transforms skip attack-free baselines. Regular `unguard`, `leaks`, `weaken` sweeps (`Sweep::Fast`) omit ten `COSTLY_MODELS`; ignored `_exhaustively` twins run in CI and also check `KNOWN_BAD_TRACES`.

### Completeness audits

Loosening candidate generation, union absorption, memos, bounds and ordering can expose semantic effects or runtime bounds. Measurements are dated, not code properties: re-measure before citing them. An unchanged corpus never licenses deleting a gate; it may be redundant today or untested.

Known sensitive sites include Targeted-before-Constructed order, finite protocol-term candidates, aligned-position filling, substitution-sensitive goal memos, which executions the search keeps, failed-check/truncated-use acceptance and failed-decryption equivalence. Authentication's positional acceptance is specified, not a bookkeeping bug: a successful use before an unrelated failed check may count; a later unreached use of that constant cancels it. Changing this requires a semantics decision.

Also compare two-session attacks against three-session attacks; increasing sessions must never lose an attack.

## Style and licensing

- Every source file starts with an SPDX header (`GPL-3.0-only` for code, `CC-BY-SA-4.0` for prose), including `.vp` test models.
- rustfmt with **hard tabs** and Unix newlines; clippy is a hard gate (`-D warnings`).
- **Do not write comments.** Reasoning belongs in the commit message and in this file, where it cannot drift silently against the source. `sessions.rs` keeps a module-level doc from before that rule, and `solve/mod.rs` carries a few item-level docs. Those are the register to match *if* asked for one; otherwise add none, including to code touched in passing. `.vp` test models are the exception — a new one must carry a `// Expected:` header arguing its code, since the `undocumented` ratchet cannot go up.
