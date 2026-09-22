# CLAUDE.md

Repository guidance for Claude Code.

## What this is

Verifpal checks `.vp` cryptographic-protocol models for confidentiality, authentication, freshness, unlinkability and equivalence under passive/active attackers. Default: **two concurrent sessions per principal** (`--sessions k`); a hold means no attack found within that bound. One Rust crate (`verifpal` 1.5.0, edition 2024, Rust 1.98, GPL-3.0-only) builds the CLI and separate WASM library for website/VS Code. [User Manual](https://verifpal.com/docs/): language reference; `README.md`: overview; [*From Toy to Instrument: Seven Years of Verifpal*](https://eprint.iacr.org/2026/1654): authoritative where this guide disagrees.

**Validated, incomplete search:** `src/solve/` only proposes substitutions; `validate.rs` checks control, derivability, causal availability and execution compatibility before re-execution. Query evaluation records an attack only after a fresh witness replay reproduces and grounds it. The paper distinguishes these implementation checks from a proof of single-history reachability; `query.rs::tcb_tests` pins the write path, not a complete correctness proof.

## Non-negotiable rules

**Declare primitives only in `src/primitive/spec.rs`.** `PrimitiveSpec` / `PrimitiveCoreSpec` own names, arities, outputs, restrictions, decomposition/recomposition/rewrite/rebuild/reuse, checking keys, commutativity, capabilities, core roles and documentation. The engine interprets fields. `PRIM_*` exports are test-only; `the_engine_names_no_primitive_outside_its_spec` rejects ids and quoted primitive names in non-test engine code. If behavior seems to require an id/name check, **add a spec field and generic interpreter**. Ask the registry for tuple, projection and equality roles too.

False attacks and missed attacks are equally serious. Preserve these distinctions:

- Known versus forgeable; replay versus forgery; computed versus emitted; knowledge versus constructibility versus observability.
- Causal availability, compatibility with other executions and the recipient's own receive history are separate checks. Global monotone knowledge cannot combine incompatible executions.
- Own halt, foreign halt and starvation differ. A held slot does not establish that its send was reached; a failed decryption is not a value suitable for equivalence comparison.
- A guard prevents replacement on that leg, not an upstream attacker-controlled computation. Forwarding must use the sender's actual reached emission.
- Solver proposals are untrusted. Independent validation and fresh witness replay gate every recorded attack.
- Simplify duplicate representations, not correctness gates. Unchanged corpus verdicts do not justify removing a gate. Primary-route selection and proposal order remain incompleteness sources.

The executable regression inventory is `src/model_tests.rs` and `examples/test/`. Representative paired cases to consult when touching a gate (`@1`/`@2` means session count):

| invariant | regression / counterweight |
| --- | --- |
| Known is not forgeable | `aead_replay_not_forgery.vp`: `a0c0`@1, `a1c0`@2; `examples/transport-layer/piknik.vp`: `c0a0a1a1f0`, with **replays**, never replacements |
| Cross-session replay breaks injectivity | `session_replay_breaks_injectivity.vp`: `a0`@1, `a1`@2; `session_peer_run_matches.vp`: `a0` |
| Histories must coexist | `incompatible_histories.vp`: `a0`; `incompatible_histories_mitm.vp`: `c1a1`; `history_kem_reply_under_secret.vp`: `c0`; `history_dh_reply_under_secret.vp`: `c1c0` |
| Disclosure must precede every affected receive | `causal_late_leak.vp`, `causal_foreign_receive.vp`: `a0`@1, `a1`@2; `causal_foreign_receive_early.vp`: `a1` |
| Halts withhold sends and downstream computations | `halted_peer_relay_holds.vp`, `halted_peer_downstream_reencrypt_holds.vp`: `c0`; companions without `_holds`: `c1` |
| An unavailable recorded route does not make the value unavailable | `closure_route_withheld_by_halt.vp`, `closure_route_collision.vp`: `c1` |
| Query scope and held slots matter | `equivalence_halt_scope.vp`: `e0`; `precondition_halt_before_send.vp`: `a0a0`@1, `a1a0`@2 |
| Guards preserve upstream control | `forward_transitive_relay.vp`: `f1`; `forward_relay_all_guarded.vp`: `f0` |
| Addressed installs affect one recipient | `split_delivery_equivalence.vp`: `e1`; `split_delivery_through_relay.vp`: `e0` |
| Search must retain deeper terms and oracle chains | `pitoy_depth.vp`: `c0`@1, `c1`@2; `solver_oracle_chained_inputs.vp`: `a1`; separated companion: `a0` |
| The attacker must reveal an existing link | `unlink_forced_equality.vp`, `unlink_forced_origin.vp`: `u0`; `unlink_active_links.vp`: `u1` |
| Weakening preserves key boundaries | `cap_forgeable_other_message.vp`: `c1`; `cap_forgeable_other_key_holds.vp`: `c0`; `cap_forgeable_still_binds_its_key.vp`: `a1` |

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
make lint                                   # native/WASM clippy + fmt check
cargo fmt                                   # hard tabs, Unix newlines
cargo check --lib --no-default-features --features wasm
make test-tex                               # compile generated LaTeX with tectonic
make wasm                                   # build/copy website WASM
make dist-assets                            # completions + man pages
make release-dry                            # no git/network changes

cargo run --release -- verify examples/simple.vp
cargo run --release -- verify path/to/model.vp --result-code
cargo run --release -- verify path/to/model.vp --sessions 1
cargo run --release -- pretty path/to/model.vp
VERIFPAL_SOLVE_DEBUG=1 cargo run --release -- verify m.vp
VERIFPAL_SOLVE_DEBUG=passes cargo run --release -- verify m.vp
VERIFPAL_CHECK_PROPOSALS=1 cargo run --release -- verify m.vp
```

CI runs clippy, release tests and exhaustive sweeps on Ubuntu/macOS, plus WASM clippy. **CI runs only when the commit title contains `[ci]`**, or on manual dispatch. Formatting is not gated there; use `make lint`.

`verify` accepts several models. `--result-code` suppresses only the banner; read the **last line** (`| tail -1`). It cannot accompany `--format json|html|tex`. HTML is self-contained; TeX compiles with tectonic. `--fail-on-attack` returns nonzero for attacks. `--auto-queries` replaces queries; `--saturate` raises the session bound. Other commands include `about`, `diagram` (Mermaid), `lsp`, `completion` and hidden `man`. JSON/HTML/TeX/LSP share `src/report.rs`; editor plugins are thin clients.

Use `VERIFPAL_SOLVE_DEBUG=passes` to report search rounds, knowledge counts and proposal counts without rendering terms. For wrong active-attacker results, start with `VERIFPAL_SOLVE_DEBUG`: `[solve] <Principal> ran=<bool> [slot=value …]` includes rejected proposals. `VERIFPAL_CHECK_PROPOSALS` recomputes recalled proposal lists and asserts equality. Errors carry source `Span`s; `or_span` preserves the narrower span, and `.located(file_name, &model.source)` makes plain `Display` positional.

## Crate layout and features

- Lib `verifpal` (`cdylib`, `rlib`), bin `src/main.rs` (default `cli` feature). CLI stdout uses `out!`/`outp!`, ignoring closed pipes.
- **Engine modules are `pub(crate)`**; only `lib.rs` re-exports are public. Keep `#![warn(unreachable_pub)]` / `#![forbid(unsafe_code)]`.
- No `tests/` directory: integration targets collide with the `cdylib` artifact; use `src/model_tests.rs`.
- Features: default `cli` (clap, colored, ureq, `lsp`), `lsp`, `wasm` (`wasm_verify`/`wasm_pretty` return JSON; `info::wasm_messages_*` buffers output).
- `parallel.rs` is the sole rayon seam, with a sequential WASM twin: **change both and run the WASM check**. `map_ordered` preserves order; `VERIFPAL_THREADS=n` sets pool size, `1` is sequential (`an_analysis_is_identical_under_one_thread_and_many`). **Workers only evaluate**: no `learn`, `attacker_put_with`, `attacker_note_reuse`, `emit_query_result`, `defer_replays`, `note_depth_cut`, `note_replication_rejection`, `analysis_count_increment`, `ctx.replayed` or `info` calls. Caller-thread learning preserves primary routes/traces. `VerifyContext` is interior-mutable and `Sync` (`everything_a_worker_borrows_is_sync`).
- `REWRITE_CACHE` / `CONES` use `context::Generational`, clearing on first access in a different generation to prevent cross-model id contamination. **Internal parallelism only with one live analysis**: `live_generations() > 1` makes `map_ordered` sequential. `NEEDS` / `ANY_TAINT` retain their source `Arc`; `DeductionMemo::scoped` installs/restores `MEMO`.
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
      → construct_principal_states  one PrincipalState per principal
  → VerifyContext::new (context.rs) shared mutable state for the whole run
  → verify_passive (verify.rs) | verify_active (solve/mod.rs)      per phase
  → verify_end                      prints results, returns the results code
```

`verify::analyze(&Model)` is the **one** place that sequence exists; it is `analyze_sessions(m, DEFAULT_SESSIONS)`, and the wasm entry points and the LSP call it too — **do not give one entry point its own default.** Throughout, `km` is the `ProtocolTrace` and `ps` a `PrincipalState`.

### Parallel sessions (sessions.rs)

`expand_sessions` clones principal/message blocks before sanity. Fresh/assigned constants become `c#s`; `knows` constants stay shared. Scenario/session expansion requires `s*k <= 31` (`MAX_COPIES = 30`). Original queries cover session 1; variants share `query_index`. Keep scenarios and sessions distinct.

- Authentication reports sibling replay only after **joint re-execution** establishes two successful uses of the same sibling value, compatible worlds and a reached source send. Copies span both expansion axes. Check duplicates before matching-run exemptions; never suppress them. Use `DuplicateAcceptance` if the recipient contributed, otherwise `ReplayableFirstFlight`.
- Clones are runs, not agents. `install` stamps attacker authorship for deviations from pristine expectations. `agreement::emitted_by_matching_run` re-executes an interchangeable sender with the recipient's flight, requiring derivability, term bound and control. Try pristine-sibling replay first, then mirror, recorded and routing paths. Memo hits confirm full installs and target.
- `interchangeable_for` checks scenario dependence **per slot**. Whole-binding comparisons lose valid matches; base-name canonicalization excuses Lowe's attack. Match recipients by agent.
- `forgeable_without_sender` removes run-dependent assignment reads, not generated keys or derived/public values emitted in every execution. A value still derivable is an independent forgery.
- Test `original ≡ value` before sibling classification. One session cannot report cross-session replay; pin non-forgery claims there. At higher counts, defer own-freshness replays initially and retry if unresolved queries remain. This orders proposals only. Re-measure both corpora before changing defaults.

### Causal availability (reexec.rs)

Phase seeding publishes reached wire values before principals run, permitting concurrent routing. Nevertheless ingredients must exist **before the replaced receive/check**. `available_before_receive` finds the earliest delivery to **every affected principal**, not only the re-executed one; addressed installs affect only their recipient. `held_before` restricts knowledge at this set; `close_influences` closes blocked slots over sends. Guard checks share this filter.

- Block by **disclosure**, not declaration, except nil/public constants. Admit concrete forgeries at the delivery they replace.
- `restrict_known` follows primary derivations through `reachable_knowledge`, keeping permitted reads and ingredient-free constructions. Do not compare pristine values. Consult an alternate only when the primary route is unreachable, at an unblocked observable slot whose recorded installs are all public constructions from `Initial` knowledge. Broader alternates resurrect temporal/history false attacks. `Coherence::compatible` also refuses alternates installing at this principal's received slots. Prune only consulted alternates; scanning all routes needlessly re-executes the snapshot. Validation independently re-proves derivability.
- **Each delivery is substitutable in its own phase.** Record recipient delivery phases; guarded relays inherit the upstream open leg's phase. `install` stamps it; `mutation_reaches` hides later mutations from earlier recipients. Keep visibility, `state_mentions` and symbolic reach aligned (`phase_second_delivery.vp`).
- Cache by position/set and `KnowledgeKey`, never size alone. Clones have no cross-copy message edges. Witness probes obey the same ordering, including joint pending-receive causality.

### History coherence (reexec.rs::Coherence)

Global monotone knowledge must not spend one execution's disclosures against another execution of the same principal. `Coherence::of(km, ps)` records each received slot's honest creator value; `compatible` filters primary `Obtained`/`Leaked` derivations that disagree. `VerifyContext::coherence` caches per principal and knowledge `Saturation`, making pointer-keyed memos exact.

- `validate.rs` uses restricted knowledge for **both derivability and re-execution**. `attacker_can_derive` also restricts earlier-phase archives through `Coherence::compatible` (`history_phase_archive.vp`, `history_phase_archive_third_party.vp`).
- Follow **derivations**, never ambient `MutationRecord` diffs, even tainted-only: treating snapshots as prerequisites loses `kem_direction_reflection.vp` and `forged_statement_rebuilt.vp`.
- `execution_agrees` handles disclosures sent to third principals: replay each supplier under diffs observed in its own state (`history_incompatible_knowledge.vp`, `history_compatible_oracle.vp`).
- Restrict only slots **received from another principal**, read in the **creator's** run or another execution of **this principal**. Skip where the proposal installs an **attacker-authored** value, but not an honest reinstall (`incompatible_histories.vp`, `incompatible_histories_mitm.vp`).
- `execution_agrees` reads nothing from knowledge: it replays the record's tainted diffs at their origins and compares the forwarded slots. Its memo is keyed by those diffs and the authored set, never by the record pointer or the knowledge chain; records are displaced as routes improve, so a pointer key missed on nearly every call and re-ran tens of thousands of re-executions per model.
- Separately, `validate.rs::spends_another_execution` checks installs whose cone-filtered `deduction::needs_of` require a different value at this principal's **receive** slot. Before refusing a primary-route conflict, it checks the joint world constraints of all installs against the recipient's chosen inputs, allowing a compatible alternate derivation. Recurse into unheld terms' arguments; do not reject own output reads needed for cross-session routing (`history_own_later_emission.vp` against `history_own_early_emission.vp`).

### Worlds: which executions produce a value (world.rs)

Every learned value carries a **world set**: a disjunction of constraints, each a conjunction of `(principal, slot, value)` pins naming a producing execution. `learn` refuses combinations whose ingredient worlds have no consistent merge. This catches incompatibility deeper than two reads assigning different values to one slot.

- `state_world`: installed slots pin themselves and inherit the value's nonempty recorded worlds; received slots pin themselves and recurse into the creator's computation. Own `knows`, public constants and nil pin nothing. Collect dependency pins before intersecting input sets; cache hits confirm state values and input worlds.
- `derived_worlds` merges ingredient worlds and adds an unconstrained world if the value is obtainable from knowledge held in every execution. Otherwise an arbitrary recorded route decides the verdict (`closure_route_withheld_by_halt.vp`). `rule_equivalize` widens worlds only through slots that travel or leak; an unobserved private alias cannot make a value unconstrained.
- `world/formula.rs` stores **exact** factored positive Boolean formulas over execution pins. Union/intersection retain all constraints without distributing products. SAT encodes each junction by equivalence and allows at most one non-equivalent value per principal/slot; assigning no named value represents an unspecified value. Inclusion is the unsatisfiability of `left AND NOT right`; equivalence checks both directions. A consistent conjunction can be checked by evaluating the positive formula at its least assignment. Shared subformulas required by the left can establish the right by positive structural evaluation; an inconclusive check falls back to SAT. Witness selection preserves the diagram order, trying unspecified values before named edges. Hashes select buckets; full value equivalence confirms atoms. Consistent candidate assignments can establish nonemptiness or refute inclusion only after evaluating the formulas; a failed candidate always falls back to SAT. Bounded caches and rebuilding SAT contexts change recomputation only: a query exceeding a reuse-cache capacity is still encoded in full. Never cap alternatives. `world/diagram.rs` remains the test-only reference, checked against complete small truth tables, chosen witnesses and the factored implementation.
- Proved implication facts used by the Boolean reasoner stay separate from `includes`, which also serves route-selection shortcuts. Reusing a proved superset can accelerate evaluation of a larger formula without broadening those shortcuts. The decision entry retains weak references that prevent pointer reuse; evicting it removes its dependent implication fact.
- Canonical witness selection uses a fresh SAT context. Pins required by the outer conjunction condition that context before encoding, and are restored in the selected history; contradictory required pins reject it. Constant propagation removes only branches made irrelevant by those requirements. Exponential search followed by binary search skips a prefix of unspecified receives only when SAT confirms the whole prefix; the first required receive still tries values in diagram order. Neither optimization alters the stored worlds or the witness replay gates. Inclusion checks retain shared unconditioned SAT contexts: conditioning their caches by the left formula's required pins lost useful reuse in both SimpleX and Yahalom measurements.
- Install validation and final joint witness grounding require nonempty world intersections. Intersect receive pins before ingredient worlds, then check the complete intersection once; checking every prefix repeats SAT work without changing whether the joint history exists. `worlds` parallels `known`; `worlds_epoch` invalidates memos, and unchanged unions preserve allocation/epoch. Unconditional-knowledge keys include phase, vetted-pair count, knowledge chain/length and world epoch.

### Execution coherence in the closure (deduction.rs::combination_coheres)

For every learn, collect ingredients' primary `Obtained`/`Leaked` reads and tainted substitutions. Refuse conflicting values at one principal/slot. Empty or uniform unions pass; otherwise replay the union and require differently recorded reads to be **reached**: slot held, no foreign halt, emission not withheld by own halt. Refuse unexecutable unions (`closure_cyclic_union.vp`).

**An unreached read refuses the route, not the value.** Restrict knowledge to what the replay reaches, then re-prove the derivation: `can_decompose` for `Decomposed`, all ingredients obtainable otherwise. This admits a compatible alternate computation without spending unreachable knowledge (`closure_route_withheld_by_halt.vp`).

- Consult alternate reads only when primary routes **collide**, never to retry a union refused by replay. Skip unobserved slots. Wider retry resurrects `history_closure_incompatible.vp`; legitimate collisions are pinned by `closure_route_collision.vp`.
- Needs are `(principal, slot, value)`, allowing different recipient values. `SlotDiff` retains the observed state. Key read prerequisites to the creator; combine cone-filtered needs with current ambient, never whole snapshots of every visited record.
- `collect_reads` follows reconstruction/decomposition inputs; `read_preconditions` follows installed values in the read's cone. Wire/leak cones extend to **emission**, not declaration. Provenance stops at installs.
- Scope deduction/restriction memos to the principal and fixed pass snapshot, retaining referenced `Arc`s. Execution depends on seeds, phase and honest halts; knowledge-sensitive grounding still reruns on group misses.
- Different recipient values use `witness.rs::Addressed`, the fourth `LADDER` rung, after shared-install rungs fail.

### Forward execution (reexec.rs::execute_forward)

`execute_forward` runs a principal, delivers its changed (`attacker_authored`) emissions as produced, then runs recipients, including the initiating principal, to a fixed point. The stopping condition includes forwarded installs, halt information and starvation; a repeated nonstable configuration or rejected update rejects the replay. Explicit attacker installs remain in force. This lets the minimizer start at the origin of a downstream attack and handles arbitrarily many written message exchanges between the same principals.

- Forwarding is justified by the send, not attacker derivability. `forwarded_installs` checks the declared leg, phase and reached send (`a_forwarded_value_is_only_ever_what_its_sender_sent`); it forwards changed emissions and, unchanged, emissions the honest run never delivered (`honest_run_delivered`). The recipient then `adopt_foreign_halts` from the executed sources, since its own view cannot see the installs that let a source past its check.
- `install_forwarded` sets `attacker_tainted` and preserves `creator` and `original`. A direct relay retains an upstream attacker `sender`; a locally computed reply keeps its producer's identity (`relay_halt_before_forward_leaked.vp`, `forward_emission_is_not_a_forgery.vp`). Taint makes downstream learning depend on the input; omitting it caused false attacks in `piknik.vp`, `ringsign.vp`, `mutual_auth_both_directions.vp`. Pure forwarders are controllable.
- `PrincipalState::forwarded` gates `query_start` through `answers_for`: forwarded states answer only over legitimately held constants (`precondition_foreign_halt.vp`). Applying a `known` gate to every state loses `concat_bomb_equiv.vp`.

### Peer scenarios (scenario.rs)

Scenarios expand **before sessions**. Each entry is a whole-model configuration rebinding one principal, dropping its bound `knows`, substituting throughout that principal and freshening outputs. Entries are not a cross product: p principals, s entries and k sessions yield p×s×k runs. Reject undeclared values/principals, non-`knows` targets, duplicate targets and wire targets. Identity bindings are no-ops. Normalize honest-first; query variants cover honest scenarios, then sessions.

Corruption has two distinct questions:

- `compromised_constants` asks what is computable. Seed secrets leaked/sent bare at disclosure time, including assigned private keys and tuple-exposed secrets. Generated constants qualify only at registry `secret_positions`; public identifiers/salts do not. Follow aliases/nested tuples only through `reveals_args`, not opaque hashes/keys/ciphertexts. Derivations need **every** ingredient public, nil or compromised; date them at the latest ingredient.
- `scenario_corrupt_from` asks whether a binding identifies a controlled peer. A bound value may be compromised **or mention** one: an unforgeable certificate can identify a corrupt peer.

`is_honest` governs honest-run checks by slot creator; honest failed checks are model errors, corrupt creators still halt. `claims_apply_to` governs query eligibility. Without scenarios both return true; `Some(empty)` relaxes only honest-run checking. Both verifiers rerun the standard run at phase end when relativisation applies and queries remain.

`honest_run_halts`, `honest_run_unreached` and `slot_held` close over deliveries: computation requires reached inputs; disclosure requires a reached send/leak. `attacker_absorb_disclosed` republishes values an executed run reaches but the honest run withheld. Starvation respects third-party deliveries and counts attacker installs as delivered. Own `knows` precedes checks of another declarer's halt; private computations do not. `rule_equivalize` cannot resolve names through unreached/starved slots.

Acceptance pair: `spore_ns_pk.vp` (`c1a1a0`, Lowe attack), `spore_nsl_pk.vp` (`c0a1a0`). **Do not add scenario-free variants to `examples/`.**

### Verdict envelope

`VerifyResult` carries `Envelope { sessions, truncations }`, printed after PASS (`[search exhausted at 2 sessions]` / `[search truncated: term depth]`) and serialized as `QueryReport.envelope`. Attacks are unqualified by envelopes; FAIL may carry `Subtype::{AttackerSuppliedValue, DuplicateAcceptance, ReplayableFirstFlight}`. `VerifyResult.notes` supplies `Note:` lines; spanless auto-queries set `QueryReport.generated`. Empty notes/generated fields are omitted from JSON. `Truncation::TermDepth` and `Truncation::SolverVariables` attach to queries **unresolved when encountered**; `Truncation::WitnessValidation` identifies a candidate that could not be confirmed for its query. `finalize_envelopes` preserves that scope. A candidate that fails witness validation is not recorded as FAIL.

**"Exhausted" means this engine's search space at these parameters, never absence of attacks.** Do not describe results as "proof", "verified", "correct" or "complete".

### `--auto-queries` and `--saturate`

`autoquery.rs::auto_queries` **replaces** queries after `sanity` validates the original model. Generate confidentiality for each fresh/private trace constant, authentication for each delivery used in a recipient primitive, freshness for every sent-and-used constant; skip unlinkability/equivalence (`generated_queries_all_pass_sanity`).

`saturation_sessions` tries `DEFAULT_SESSIONS` through `SATURATE_MAX` (4), stopping at the first repeated result code and returning that count's **analysis**. Starting at one would stop before three-run attacks (`saturation_never_stops_before_it_has_looked_above_the_default`). `attack_disappeared` warns about attacks vanishing at higher counts: an engine bug.

### Core data model (types.rs)

- `Value = Constant | Primitive(Arc)`; constants are model-interned ids (nil = 1). **Equivalent values must have equal hashes**: knowledge first selects a hash bucket. Registry commutativity drives equivalence, hashing and matching; structural identity also retains checked-instance distinctions.
- **Terms are DAGs.** Memoize transformations by input `Arc`, comparisons by pointer pair. Preserve unchanged ground subgraphs across proposals. Resolution interns mapped calls only after comparing every primitive field, constant metadata and child identity, including capability annotations and checked instances; equivalent cryptographic terms alone are not sufficient for this cache. `subterms` visits primitive pointers once in encounter order; `constant_leaves` follows aliases with a cycle guard. Public `collect_constants` preserves occurrences. Never prune by term hash: collisions/equivalent DH terms hide distinct subterms. Preserve dependency order and failed checks behind shared prefixes. Rendering can still expand exponentially.
- Changing a multi-output `output` clears its cached hash. Pointer caches retain references preventing address reuse; eviction changes only recomputation. `NameTable` uses hash buckets plus full equivalence, preserving order, aliases, exclusions and preferred names.
- **Capabilities do not affect term identity.** Read the state's `CapabilityIndex`, never a deduped held term. Collect annotated calls independently; reduce arguments while retaining annotations. Whole-call reduction and annotation-blind cache twins erase assumptions. Resolve only annotated calls, avoiding expansion of unannotated transcripts.
- **Keep slot values distinct:** `original` = honest computation/belief; `pre_rewrite` = mutated/unreduced; `value` = mutated/reduced. `effective_value`, `should_use_original` and visibility select perception; computation follows actual rewritten inputs.
- Provenance carries creator, sender (`ATTACKER_ID = 0` for injection) and taint. Immutable slot metadata records declarations, knowledge, guards, recipients and delivery phases. `halted_at` is the earliest failed checked slot's declaration position.
- `AttackerState` has append-only knowledge, derivations/records, alternate **state reads**, `routes_epoch` and a unique `chain`. **Length-keyed memos need chain identity**: minimization creates independent knowledge on the same thread. Route replacement invalidates without growth; worlds have their own epoch. Filters use primary routes except specified causal/collision fallbacks.
- Every learned value needs an honest `DerivationRecord` and prerequisite `MutationRecord`. Missing provenance makes traces unjustifiable.

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

`query_start` applies `claims_apply_to`; `goals_for_query` mirrors evaluators. Only `emit_query_result` records results, after preconditions and witness validation. Emit replayable-first-flight notices **there only**, never while classifying siblings (`duplicate_notices_belong_only_to_recorded_acceptances`).

- **Confidentiality:** attacker knows resolved `value`. Label `AttackerSuppliedValue` only when it differs from honest and carries no generated/private secret through aliases.
- **Authentication:** injective agreement at the recipient. A changed sender, successful primitive use and no interchangeable sender emitting the value establish forgery; duplicate acceptance is checked before the matching-run exemption. Acceptance is **positional**: every slot mentioning the constant must be reached, and one use must succeed or be unchecked. An unrelated later failure need not cancel an earlier use. A check after consuming a message may leave `a1`; changing this is a semantics decision.
- Sender matching requires a declared, reached send to the recipient's **agent** in the current phase; computing the value is insufficient. Include recipient in emission memo keys. Compare scenario interchangeability per value, not whole binding sets. `state_mentions` visits primitive/**owner** pairs and counts only visible occurrences; sanity and auto-queries share `principal_uses_constant`.
- Both recipient copies must successfully use a duplicated value. Replays need a touchable leg: where every sender/recipient delivery is guarded, forwarding is the run's own send. Forgery and replay both yield `a1`; narration distinguishes them.
- **Freshness:** a used value transitively contains no fresh constant. Freshness generates no solver proposals.
- **Equivalence:** mutated values differ, every slot is held, none is a failed-check placeholder or starved by withheld foreign emission. Forwarded states also require `answers_for`. Keep the equivalence starvation gate separate from general `slot_unreached`, or Lowe's attack disappears.
- **Preconditions:** every evaluator calls `preconditions_reached` before `attack_trace`. Require the named send and its input deliveries/computations. Resolve message constants against `km`, not a possibly truncated answering state. Confidentiality evaluates the gate in the disclosing execution, using the value's recorded substitutions and the sender's replayed state. Unreached sends produce no verdict/output; probes use the same evaluator.

`unlink.rs::find_link_witness` tries observable equality, an identifying check, a common secret origin, then a recognized secret that can be tested but not recomputed. These predicates are not two-world behavioral equivalence. Preserve all gates:

- Queried values must be observable and not attacker-authored; honest **unreduced** values must already share a secret subterm. Equality also requires honest reducts equal. Reject attacker-supplied witnesses.
- Non-equality witnesses must carry a secret leaf honestly shared by both values. The secret must remain derivable after **either** queried value and its consequences are withheld; joining queried shares is not their origin.
- Observability needs knowledge **and** extraction from a wire/leak. Follow exposed tuples and actual decomposition/weakening/reuse reveals, never arbitrary arguments or unrevealed keys. Close observed values under tuple assembly only. Reuse counts only while both members remain held.
- Try exposed tuple components and reconstruction ingredients. Checks must be runnable with every required input, distinct matching positions and successful `can_rewrite`. Public identifiers identify nobody; exclude `check_key` constructor applications from recognized candidates.

`attack_trace` minimizes then narrates. Confidentiality seeds from the disclosed **value**, possibly another execution. Authentication seeds from answering-state taint/history, never a use-site decryption's unrelated record.

### Equational theory (theory.rs + primitive/spec.rs)

`PrimitiveSpec` declares decompose, recompose, rewrite, rebuild, combine and checking-key metadata; `theory.rs` interprets them. `obtainable` is the common argument-recovery cascade. Decompose returns a **set** of `Reveal::Argument(i)` / `Reveal::Output(i)`, covering everything the legitimate key holder learns: `KEM_ENCAP` reveals secret **and randomness** (ML-KEM re-encryption re-derives coins). Consumers name projections via `rewrite.from_output` / `decompose.output`. Recompose/rebuild count distinct projections of one split against its threshold (`shares_of_one_split`).

- Rewrite `matching` is a **bijection** onto distinct inner positions; overlapping `RINGSIGNVERIF` `inner_idxs` must not collapse a ring (`ringsign_ring_collapse.vp`).
- `can_reconstruct_primitive` refuses irreducible core applications: `ASSERT` is a check; reducing `SPLIT` still reconstructs.
- `obtainable` opens a `DeductionMemo` scope when absent for its principal/snapshot, shares subproofs within direct calls and restores enclosing scopes (`shared_transcript_bypass.vp`, `c0`; unavailable-leaf/scope-restoration tests). This fixes shared-key constructibility costs, not general protocol latency.
- **No recursion cap.** `to` rules return subterms or reassemble strict subterms: depth descent is well-founded. Memoization is independent of recursion depth; including depth repeats reduction of identical terms.
- `can_rewrite` is the sole reducer: argument reduction, `can_rebuild`, `can_combine`, then rewrite. `reduce_term` wraps it for states; divergent reducers once made minimization prefer an honest reinstall over forgery.
- The rewrite memo first checks an exact input pointer, then its original hash bucket with full structural comparison. Its bounded 8,192-entry pointer index includes structurally matched aliases. Each entry retains a weak input reference, preventing address reuse; unchanged outputs do not keep their own inputs alive. Eviction and generation changes only require recomputation. Checked-instance distinctions and hash-collision checks still apply to structural matches.
- **Add primitives only in `src/primitive/spec.rs`**, using `build_primitive_specs`; core entries use `build_core_specs` plus `core_rule_*`. Then add model tests. `every_spec_index_is_within_the_primitive_it_is_declared_on` checks direct indices (`rewrite.from`, `recompose.reveal`, `rebuild.reveal`, `check_key`) against narrowest arity, checked indices against widest.

Weakening must preserve provenance and alternatives. `forgeable` needs no source application; `weak` and `malleable` do. `malleable_source` chooses an eligible held annotated ciphertext matching fixed positions, and both `construction_inputs` and derivation ingredients retain it; omitting it admits time-travel forgery. Passive/nested reshapes use ordinary reconstruction, learning and coherence. A capability exemption **adds** an unsolved option while retaining solved alternatives; replacing them loses attacks. Constructibility concerns the **reduct**, not an unreduced operation's hidden key (`solver_constructible_reduct.vp`).

### Nonces (AEAD)

`AEAD_ENC` declares `ReuseRule { fixed: [0, 1], reveals: [Argument(2)], forgeable: [0, 1] }`: two non-equivalent held ciphertexts with equal key/nonce form a pair. Different AD counts; identical key/nonce/message/AD does not. Effects are confined to the reused nonce.

- **Recovery:** `rule_reuse` unconditionally learns both plaintexts. This deliberately over-approximates real XOR leakage when neither is known. Skip buckets whose fixed positions are obtainable and members the attacker could mint (`attacker_mints`), regardless of their recorded derivation: an installed mint can be read back. Otherwise `forgeable` becomes `weak` (`cap_forgeable_is_not_a_reuse_pair.vp`, `cap_forgeable_guard_never_adds_an_attack.vp`). `protocol_produced` follows honest subterms too, retaining nested honest ciphertexts that later become mintable. The threshold counterpart `threshold_sign_forgeable_is_not_a_reuse.vp` reveals its share through public-nonce disclosure, not reuse.
- **Pairs must coexist.** `combination_coheres` merely checks reached reads, insufficient for reuse (`spore_otway_rees.vp`, `spore_yahalom.vp`, `injective_recipient_nonce_unchecked.vp`, `injective_routed_emission_twice.vp`). `pair_vetted` combines shape (`reused_pair`), `theory::one_execution` (also rechecked by both `tracecheck` arms), and `pair_coheres` (**equality** under replay). Unexecutable replay rejects; an unexecuted reader uses its `execution_base` (`aead_nonce_reuse_partner_unreached.vp`). Store vetted pairs in `AttackerState::reused`; `theory::reused` requires both members still held in the snapshot. Pins: `aead_nonce_two_executions_not_a_reuse.vp` (`c0` at both counts).
- **Forgery:** held replacement message/AD suffice with `forgeable` positions exempt in `can_reconstruct_primitive_directly` (`Forged::Reuse` names the pair), `validate::derivable`, `deduce.rs::solve_by_reuse`. Agreement inherits `derivable` (`aead_nonce_reuse_forgery.vp`).
- Decryption requires key **and nonce** (`given: [0, 1]`), so expose the nonce when attacker decryption is intended. `knows` nonces are session-shared; `generates` nonces are fresh (`aead_nonce_reuse_sessions.vp`: `c0`@1, `c1`@2). Static-ciphertext models such as `otp_counter_freshness.vp` declare their nonce; fresh plaintexts normally use generated nonces.

### Threshold primitives (FROST)

`THRESHOLD_SPLIT[t](k)` models dealer sharing; `THRESHOLD_SIGN(share, nonce, commitments, message)` creates a signing partial. `THRESHOLD_JOIN` interpolates shares, partials or verification shares. Registry `CombineRule`/`CombineBinding` require distinct projections of one sharing, agreed fields and each nonce's public commitment in the agreed tuple. Signing joins become ordinary SIGN; verification-share joins become PUBKEY. Commitment binding prevents mixing sessions.

- `can_combine` shares the reducer with rebuild; reverse construction groups held partials by split/agreement and adds constructible partials. `solve_by_combination` retains a take/skip frontier to threshold, with shared agreed variables and per-partial free variables.
- Retain **distinct substitutions and counts**, not every subset. Apply local bindings to surviving bindings before dropping them; different counts may need different later oracle inputs. Seed every key alignment. Record `Combined { from }` with actual ingredients; `Recomposed` cannot list an unheld split term.
- Reusing share/nonce across two partials reveals the share. This deliberately abstracts FROST's two nonces into one Schnorr nonce and fires at two uses; exact FROST algebra needs a third. A single partial also reveals its share if the complete nonce, commitments and message are disclosed; a public commitment alone does not.
- Model dealer channels with confidential authenticated transport; guards prevent replacement, not disclosure. Represent DKG by a principal splitting a fresh key it never otherwise uses.
- Metamorphic threshold lowering cannot lose attacks; raising cannot add them. Skip equivalence/unlinkability because threshold affects term identity.

### Active attacker search (src/solve/)

Goal-directed backward deduction terminates through memoization, cycle cutting and a finite basis, never effort caps. `TermBound` limits shape **per slot** to protocol depth plus recipient peel depth; excess above the flat cap must come from protocol subterms, not arbitrary oracle-grown held terms. Include trace-resolved constants' subterms and reducts. Search, agreement and minimization share one immutable bound/basis.

Per phase: passive baseline, then knowledge-fixpoint rounds. Run **Targeted for all principals before Constructed for all**; interleaving changes verdicts. Check phase-specific controllability before building symbolic state. Refinement through selected honest inputs runs only after the unrefined Targeted fixpoint with outstanding queries.

Proposal recall tracks actual reads: principal/pass, honest slots, phase, unresolved queries, deferred replays, knowledge misses/scans, reuse pairs and route epoch. `dispose` always runs; recall skips only symbolic work. Concrete-flight caches additionally confirm full installs, worlds and knowledge branch. Every recalled flight returns through validation. Use `VERIFPAL_CHECK_PROPOSALS=1` when changing recall.

- `symbolic.rs` replaces controllable wires with variables and reduces like concrete execution. Reject self-created, wrong-phase, unused and nil slots; equivalence-named slots waive unused. Mutability propagates through relays. `build_addressed` adds a Targeted pass for a direct unguarded delivery also sent to another recipient by a **different sender**. Only the addressed owner sees its mutation. Refuse when the other delivery passes through that owner; do not refuse merely because the owner forwards somewhere. Keep other principals' computations honest. Minimized probes preserve addressed flags.
- `vars.rs` separates slot variables (`0x8000_0000`) from free choices (`0xC000_0000`). Free choices survive until materialization; shared nil grounding needs divergence fillers. Preserve DAG sharing.
- `matching.rs` provides one-way matching, two-way unifiers and merge modulo commutativity. **Retain every alignment until all pending equations succeed**, including decomposition, checked inversion, reuse/malleability and key alignments. Merge all binding constraints together. Reject occurs cycles even for overwritten bindings.
- `deduce.rs` tries held values, variables, replay, wire unification, finite-basis oracles, rewrite matching, argument construction, decomposition and check inversion. Collect projection constraints for bare slot variables too; tuple shapes use the smallest sufficient legal arity. Constructibility obligates the bound **wire term**, not a hidden raw variable binding. Reduce under the incoming substitution before deduction/memoization; memo keys include the **whole substitution**, even for ground goals. Never cache cycle-cut results.
- Rewrite inversion fills unpinned fields with fresh variables and solves `to(shape) = target`. Carry every unifier; apply/project shape-only bindings before constructibility. Losing them misses attacks; requiring hidden existential plaintexts also misses attacks. Nested decomposition retains every outer opening requirement and follows actual tuple, weak and vetted reuse reveals. Weak routes match the whole annotated carrier; never recurse into a reveal equal to its source.
- `diverge.rs` distinguishes installed tuple projections using derivable fillers (nil, then HASH at each arity). `keyed_free` changes only aligned key positions; `preserved_free` retains held honest fields; `aligned_held_free` uses held **protocol** ciphertexts under matching keys. Arbitrary held terms inflate the basis.
- **`validate.rs` is the only search-to-query path.** It receives concrete installs, no symbolic state/substitution. Reject residual variables, duplicates and invalid slots. Order: **controllability → derivability/causal availability → queue install → execute**. Any failed gate abandons the whole proposal. Keep independent `derivable`, including capability exemptions, separate from `obtainable`. Recheck guards on recalls; compare cached signatures structurally, not by term equivalence. Only current `Saturation` permits skipping closure/queries.

Proposal order: query goals, constraint goals, blanket substitutions, single-slot substitutions, then Constructed sibling flights and protocol/rewrite candidates. Dedup by reduced concrete install signature, never substitution identity or across rounds. Keep honest alternatives; do not replace `{honest} ∪ {derivable}` with a representative. `leave_honest_slots` removes honest bindings unused elsewhere; unbound receives remain free and are skipped by validation.

A refused proposal may retry its `admitted_prefix` only for an `oracle_chain`: each dropped install is emitted by this principal under the retained installs. This stages an oracle across rounds without unrestricted prefix explosion. `oracle_input_goals` matches emissions against every principal's checked shapes, including nested demanded shapes filtered by emission head/arity. Preserve occurs checks and honest alignment of other principals' variables (`solver_oracle_chained_inputs.vp`).

`constraint_sets` follows declaration dependencies from sends, leaks, queries and last checks, stopping at controlled receives and retaining earlier prefixes. Seed empty and independent non-projection-check solutions, then refine in source order. Canonicalize existential bindings without grounding or losing equality/sharing. The flight-private replay index excludes non-protocol constructions and injected receives; **do not apply that restriction to query/per-slot deduction**.

Unheld ingredients must be expanded through `KnowledgeInputs`/`construction_inputs`, never treated as free. History installs are jointly causal: `available_before_pending` starts influence at **all pending receives**, removes ready installs in recipient order and rejects stalls. `replay_diffs` groups actual receivers and calls shared `causally_grounded`; per-run checks alone admit circular oracle leaks. Scratch witnesses isolate the concrete query, not sibling variants with the same result index.

`propose` parallelizes pure work with `map_ordered`; caller writes preserve order. Lanes share immutable indexes but own memos/cycle state and disjoint free-variable bands. Never spill ids across lanes; exhaustion stops proposing and marks unresolved queries `SolverVariables`. Do not revive `skeleton.rs` or give the attacker shapes it did not derive. Compare minimizer-only proposal families when investigating missed attacks.

### Re-execution (reexec.rs)

`reexecute`: install → reject cyclic slot graph → resolve → rewrite → truncate at a failed checked primitive and set `halted_at`. `solve::dispose` can refine a flight with concrete constructors for failed checks, sharing the witness reducer's strict improvement search. Every resulting flight returns through the independent validator.

- `Guards` borrows `Controllable::of` tokens, `TermBound`, `Coherence`; causal availability runs after derivability, before queueing. Only `reexec.rs` may mint `Controllable` (private fields); `admits` rechecks principal/phase.
- `slot_graph_is_cyclic_from` lets resolution remain uncapped. Only installs write out of declaration order; primitive references and bare aliases both create edges. A purified base is acyclic, so every new cycle passes through an installed or forwarded slot and the search starts only there, computing edges on demand. Validator and minimizer must use **exactly the same** cycle check.
- `attacker_authored` compares against the honest trace reduct of the slot, cached per `(slot, constant)`: resolving and reducing it afresh was a tenth of every re-execution.

### Attack traces (witness.rs + narrate.rs)

`minimize_witness` tries pristine-session candidates: canonical DH MitM, target world support, recorded mutations, then mutations with attacker keys. Scratch contexts start from the **passive baseline**, never final knowledge. Replay every candidate, including empty installs. Failure to reproduce or ground leaves the query unresolved with `WitnessValidation` truncation; never record it as an attack.

- `forged_from` builds concrete constructor shapes for failed checks at controlled non-key slots, trying honest held fields and attacker keys before nil. `forged_flight` scores `(halts, stuck)`; solver refinement requires strict improvement. Every result still passes independent control, derivability, causality, depth and world checks.
- Reuse the complete failure list, including checks beyond the eventual halt, until installs change. Repeated installs at one slot need separate check collection because authorship is sequential. Knowledge-independent `staged_costs`/`staged_checks` memoize by principal/installs across the analysis. Score one slot's trials **sequentially** to retain thread-local caches. Exact pruning skips uncontrollable slots and, in strict mode, slots unable to reach any currently failing wanted check. Include constants mentioned in installed values in that dependency cone. One `DeductionMemo` scope spans a search.
- Preserve the actual sender execution of forwarded values even when a weakening assumption makes them constructible. `probe_with` evaluates and narrates the **same state**. Earlier pending receives constrain only the same recipient's run; every chosen install must derive from preceding knowledge. Prefer grounded, nonhalting witnesses. `drop_one` repeats until no install drops: removing one can make another removable.
- Close tainted diffs through value histories. If grounding fails, retry read records restricted to the creator's `reach_cone`, including checks before emission. Derived values follow ingredients, not ambient record diffs. Tuple assembly/opening adds only its inputs' prerequisites. Bound slots by `km.slots.len()`, not truncated state length.
- Shared installs reach all controllers; addressed installs reach one. Only `split_recipients` mints addressed installs; otherwise `others` stays empty.

Narration derives each installed value immediately before its wire mutation. Exclude displaced honest `shadowed_names` at **every depth**. Prefer valid recorded read slots, and show a tainted `Gate` only when an installed slot lies in its own cone. Never narrate an install as an observation at that slot. Preserve DAG sharing, multi-output projection names and declared weakening sources.

Words require evidence: only recorded principal ids justify a derivation's run; only sibling replay proves “from another session”; `Obtained` is “on the wire” only with `sent_by`. Never call another concurrent run “earlier”. `out_of_order_note`/`out_of_order_harvest` are regression backstops: no model should earn them.

### Result-writing boundaries (query.rs::tcb_tests)

Source-level tests pin these boundaries; they do **not** prove evaluator correctness or single-history reachability:

- `results_put` requires a `QueryVerdict` token private to `query.rs`; only `emit_query_result` writes results, with one caller per query kind.
- Evaluators receive principal/attacker states, never precomputed verdicts. Evaluation is entered only over executed states; search reaches it only through validation and holds no shared mutable analysis cell.
- Every install passes control, independent derivability, causal availability and compatibility **before queueing**. A failure abandons the whole proposal, never continues with its remainder.
- Only `reexec.rs` mints `Controllable`; keep fields private and `admits` checking principal/phase. Forwarding preserves the exact reached send, declared leg, phase, creator, upstream origin and taint.

Adding a query kind must update counted evaluator and `emit_query_result` arms.

### Supporting modules

- `parser.rs` preserves comments and skips a leading BOM by position. `pretty.rs` is pure, idempotent, golden-tested and **not sanity-gated**; it owns AST `Display`. `resolution.rs` follows bare aliases with cycle guards; registry argument normalization bounds forbidden nesting.
- `info.rs` handles output, silent probes and saturation capture. `update.rs` makes the sole outbound request (GitHub tags), **only when stdout is a terminal**; network work under pipes delayed exit.
- `lsp/` uses stdio, debouncing, worker analysis and URI-keyed documents without filesystem access. **Both threads set Silent verbosity** or thread-local output corrupts stdout. Keyword/query prose lives in `docs.rs`; primitive/capability docs come from specs.
- `report.rs` supplies JSON/HTML/TeX/LSP. Ranges use byte offsets and 1-based line/column, not LSP positions. Parse once in `Run::of`; renderers never parse. Include leak-only principals.
- **No HTML/LaTeX markup in Rust.** Embed templates/assets; `Val::Text` escapes, `Val::Raw` does not. Tests reject missing/unused placeholders. LaTeX figures retain paired extraction markers and `\vp…` macros; `listing_safe` excludes embedded `\end{lstlisting}`. Preserve the no-proof disclaimer. Bless goldens with `VERIFPAL_BLESS_HTML`/`VERIFPAL_BLESS_TEX`; `VERIFPAL_TECTONIC=1` enables compilation.
- `msc.rs` shares diagram rows; `tokens.rs` indexes even failed parses. **Do not add `Span` to `Constant` or process-global mutable state.** Interners are parser-owned and error before ids enter attacker/copy/solver bands.

## Testing conventions

- Unit tests: module-local `#[cfg(test)] mod tests`; shared builders in `src/testutil.rs`. End-to-end tests: `src/model_tests.rs`, `run_model("foo.vp", "c0a1")` at shipped default two sessions; `run_model_sessions("foo.vp", 1, "a0")` for explicit counts; `run_model_err("foo.vp", "error substring")` for rejection. Pin session-sensitive verdicts at both counts.
- Codes follow query order: `c/a/f/u/e`, `0` holds, `1` attack. Add each regression under `examples/test/`, obtain `--result-code | tail -1`, **read the trace to justify every bit**, add its test and `// Expected:` argument. Every test model must be wired. Pretty goldens: byte comparisons in `examples/test/golden_pretty/`.
- Shared `testutil::test_value_id` interner requires unique per-test constant names. After parsing, obtain handcrafted constants with `testutil::trace_constant`.
- Engine changes need before/after binaries and **full-output** diffs over `examples/` at one and two sessions, not just codes. **Always exclude `examples/transport-layer/tls13.vp`, `examples/messaging/pqxdh.vp` and `signal_twelve.vp`** (prohibitive cost; none in model tests). Keep PQXDH out of test sweeps.

### Checking *why* a verdict happened, not just that it did

Sweep `examples/test/` plus `SWEPT_MODELS_OUTSIDE_EXAMPLES_TEST` (HPKE, messaging except `signal_twelve.vp`, simple/contact-tracing models, and `cloudbackup.vp`). Re-measure corpus counts when it changes.

- **Replay:** every test analysis runs `witness::assert_reported_attacks_replay`, executing the replay driver's pristine session with exactly minimized installs; queries must still fail and printed traces may name no fewer slots than required. The driver can differ from the reporting state when forwarding delivers the violation downstream.
- **Narration:** `attack_traces_keep_their_shape_and_name_only_wires_that_exist` pins five **empty** sets: `TRACE_USES_A_GUARD_BYPASS`, `TRACE_IS_NOT_A_MINIMIZED_WITNESS`, `TRACE_IS_NOT_CAUSALLY_ORDERED`, `TRACE_FEEDS_BACK_A_LATER_VALUE`, `ATTACK_IS_REPORTED_WITHOUT_A_TRACE`. New entries regress explanations; removed entries require updated pins. Detect bypass via "does not halt", including unnamed `_` checks.
- **Step proofs (`tracecheck.rs`):** test-only structured `Step` operands are re-derived before return. Ingredients must come from earlier steps/installs, `Initial`, `obtainable`, or justified construction; use stepwise `Grown` knowledge, never final knowledge. Recheck decomposition; `Obtained`'s travelled/leaked/public/held slot; reached `Leaked`; `Broken` with `in_force` at the trace phase; successful tainted `Gate`.
- `Resolves`, `Static`, `Received` and confidentiality targets must describe **the minimized state**: `attack_trace_with` takes closures evaluated against `witness.ps`, not the original answering state.
- **Holds:** `assert_holds_were_searched` requires `goals_for_query` attempted each active-model hold if any slot is controllable (zero goals allowed; freshness exempt). `assert_holds_survive_final_knowledge` reevaluates holds against fresh principal traces and final knowledge.
- Run both one/default sessions; narration sets measure default only. Reject replacements on nonexistent messages or universally guarded copies. Require `// Expected:` codes to agree; the undocumented-model ceiling (`undocumented <= 126`) is a ratchet.

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
- **Do not add `name_intermediate`.** Naming a subterm can turn a use inside a failing check into a separate successful use; it is not invariant (`auth_with_signing_false-attack.vp`). Check claimed metamorphic false attacks against pinned semantics before altering gates.
- Analyses run to completion: **no timeouts or deferrals**; skip parse/sanity failures. `spread` / `worker_cap()` cap workers (default 4, `VERIFPAL_METAMORPHIC_WORKERS`); stronger-attacker transforms skip attack-free baselines. `Sweep::Fast` uses `witness::MinimizingGuard` to skip narration/minimization. Regular `unguard`, `leaks`, `weaken` use Fast and omit ten `COSTLY_MODELS`; ignored `_exhaustively` twins run in CI.

### Completeness and gate audits

Loosening collapses, memos, gates, bounds and ordering can expose semantic effects or runtime bounds. Measurements are dated, not code properties: re-measure before citing them. An unchanged corpus never licenses deleting a gate; it may be redundant today or untested.

Known sensitive sites include Targeted-before-Constructed order, finite protocol-term candidates, aligned-position filling, substitution-sensitive goal memos, primary-route filtering, failed-check/truncated-use acceptance and failed-decryption equivalence. Keep authored-slot and `original ≡ value` guards even where another layer currently duplicates their protection. Authentication's positional acceptance is specified, not a bookkeeping bug: a successful use before an unrelated failed check may count; a later unreached use of that constant cancels it. Changing this requires a semantics decision.

Also compare two-session attacks against three-session attacks; increasing sessions must never lose an attack.

## Style and licensing

- Every source file starts with an SPDX header (`GPL-3.0-only` for code, `CC-BY-SA-4.0` for prose), including `.vp` test models.
- rustfmt with **hard tabs** and Unix newlines; clippy is a hard gate (`-D warnings`).
- **Do not write comments.** Reasoning belongs in the commit message and in this file, where it cannot drift silently against the source. `sessions.rs` keeps a module-level doc from before that rule, and `deduction.rs`, `reexec.rs`, `agreement.rs`, `context.rs` and `solve/mod.rs` carry item-level docs on the gates whose reasoning does not fit a name. Those are the register to match *if* asked for one; otherwise add none, including to code touched in passing. `.vp` test models are the exception — a new one must carry a `// Expected:` header arguing its code, since the `undocumented` ratchet cannot go up.
