<!---
# SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Parametrized primitives

> **Implementation outcome (2026-08-06).** `weak` and `forgeable` shipped as
> specified. `malleable` did **not**: it parses and stays in the vocabulary, but
> no primitive declares it and any use is a hard error. The attack it enables
> needs two coordinated wire substitutions, which the solver only forms through
> its goal-directed path, and that path cannot derive the required ciphertext
> goal — it would have to invert a nested *unchecked* rewrite, and the natural
> check to hang it on is `ASSERT`, a core primitive the theory functions bail
> out of. Deducing retargeted ciphertexts forward instead works, but feeds them
> back as retarget targets and inflates the term space without bound, which is
> the finiteness property `normalise_arguments` exists to protect. Two further
> corrections to this document appear inline below, marked the same way.

## Summary

Verifpal models today assert that every primitive is perfectly secure. There is no way
to ask "my protocol is fine, but what if this signature turns out to be forgeable?" or
"is traffic I send today safe from someone who records it and breaks it in 2035?"

This feature adds a per-call-site parameter list to primitives:

```verifpal
ga = PUBKEY[weak](a)
e  = AEAD_ENC[weak from phase 2](k, m, ad)
s  = SIGN[forgeable](sk, m)
c  = ENC[malleable, weak from phase 3](k, m)
```

A parameter is a **declared weakening assumption**. It grants the attacker a specific,
named capability over that term, and does nothing else.

## Semantics

A parameter does **not** change what a term is. `SIGN[forgeable](sk, m)` and
`SIGN(sk, m)` remain equivalent under `Value::equivalent`, hash identically under
`primitive_hash`, and rewrite identically. The annotation gates extra attacker rules
and nothing more.

Three consequences follow, and they are the reason this design is cheap and safe:

1. **An unparametrized model behaves bit-for-bit as it does today.** Every existing
   test, golden pretty-printer file and result code is unchanged. Verifying this is a
   test obligation, not an assumption (see [Testing](#testing)).

2. **Parameters are monotone.** They only ever add attacker power. No parameter
   suppresses an attack. A knob that hides attacks in a verification tool is a footgun
   regardless of how it is documented, so there is no `randomized`, no
   `not_malleable`, and no way to spell "assume this is stronger than the engine
   thinks".

3. **Equivalent terms share the annotation.** If Alice writes `HASH[weak](m)` and Bob
   writes `HASH(m)`, both are breakable — they denote the same cryptographic object,
   so a break of one is a break of the other. This is what makes per-term annotation
   degrade gracefully rather than confusingly.

Point 2 does not make results *unconditionally* sound in the usual sense: an attack
found under `SIGN[forgeable]` is genuine only under the stated assumption. That is why
[Reporting](#reporting) is part of this design rather than a follow-up.

### Soundness posture

The engine's existing stance — sound but incomplete, where a false attack is the worst
possible regression — is preserved structurally. Parameters are consumed only inside
`theory.rs`, which *proposes*; `solve/validate.rs` still re-executes every proposal
concretely before any result is recorded. A bug in a capability rule therefore costs a
missed attack or an attack correctly attributed to the user's own stated assumption; it
cannot manufacture an attack in an unparametrized model, because in an unparametrized
model no capability rule is ever reachable.

## Capabilities

The organizing principle: a cryptographic primitive provides **confidentiality** or
**authenticity**, so a break is the loss of one of them. Each `PrimitiveSpec` declares
what losing it means for that primitive. A capability a primitive does not declare is a
**sanity error with guidance**, never a silent no-op.

| capability | guarantee lost | engine rule | declared for |
| --- | --- | --- | --- |
| `weak` | confidentiality | `decompose` with an **empty** `given` set | `HASH`, `PW_HASH` → preimage; `AEAD_ENC`, `ENC`, `PKE_ENC` → plaintext; `KEM_ENCAP` → shared secret; `PUBKEY` → the private key |
| `forgeable` | authenticity | relax `can_reconstruct_primitive`: build the term knowing every argument *except* the declared secret | `SIGN`, `MAC`, `RINGSIGN`, `AEAD_ENC` |
| `malleable` | authenticity, weakly | given a held instance and both plaintexts, substitute the varying argument without knowing the key | `ENC`, `PKE_ENC` |

### Why these three

`weak` and `forgeable` are the two halves of what a primitive can lose, and keeping
them separate is what makes `AEAD_ENC[forgeable]` — forgeable but still unreadable —
expressible. Collapsing them into a single `weak` whose meaning varies per primitive
would lose exactly that case, which is the interesting one.

`malleable` is strictly weaker than `forgeable`: the attacker cannot build the term
from scratch, only transform one it already holds. It models CBC/CTR bit-flipping and
textbook-RSA malleability, which are real, frequently exploited, and inexpressible in
Verifpal today. It is deliberately **not** declared for `AEAD_ENC`, because
malleability of an authenticated cipher just *is* an authenticity break, and that is
already spelled `forgeable`.

`weak` on `PUBKEY` deserves special note: it is the entire post-quantum story in one
annotation. The attacker takes `ga = PUBKEY(a)` off the wire, recovers `a`, and then
`DH_KEX(PUBKEY(b), a)` reconstructs through the **existing** `can_reconstruct_primitive`
with no new rule at all. Discrete log is a property of the key, not of the exchange.

### Sanity errors with guidance

These are hard errors at load time, in the house style of turning ambiguity into a
diagnostic rather than a surprise:

| written | error |
| --- | --- |
| `SIGN[weak]`, `MAC[weak]` | "SIGN provides authenticity, not confidentiality; did you mean `SIGN[forgeable]`?" |
| `DH_KEX[weak]` | "discrete log is a property of the key; did you mean `PUBKEY[weak]`?" |
| `HASH[forgeable]`, `PUBKEY[forgeable]` | "HASH has no secret argument; anyone can compute it." |
| `AEAD_ENC[malleable]` | "malleability of an authenticated cipher is an authenticity break; did you mean `AEAD_ENC[forgeable]`?" |
| any parameter on `CONCAT`, `SPLIT`, `ASSERT` | "core primitives provide no cryptographic guarantee to weaken." |
| `[weak from phase 5]` in a model with 2 phases | "phase 5 is never reached; this assumption has no effect." |
| an unrecognized parameter name | "unknown primitive parameter `foo`." |

The last two matter for the same reason: a weakening assumption that silently does
nothing reads as a check that was performed when it was not.

## Syntax

```
primitive     := IDENT [ "[" paramlist "]" ] "(" arglist ")" [ "?" ]
paramlist     := param { "," param }
param         := capability [ "from" "phase" INT ]
capability    := "weak" | "forgeable" | "malleable"
```

- The parameter list is optional; omitting it is exactly today's behaviour.
- `from phase N` binds to the **immediately preceding** capability, so
  `AEAD_ENC[forgeable, weak from phase 2]` means forgeable from the start, readable
  from phase 2 onward.
- Absent a phase clause, a capability is in force from phase 0.
- The semantics are **from phase N onward**, never "in phase N only". Cryptanalysis
  does not un-happen. The `from` keyword carries this and is required.
- Duplicate capabilities in one list are a sanity error.
- Consistent with `attacker[…]` and `phase[…]`, comments inside the parameter brackets
  are **dropped**, not captured into the AST.

`NAME[...](args)` is unambiguous for the parser: `parse_primitive` (`src/parser.rs:767`)
reads an identifier and then expects `(`, and no other construct puts a bracket between
an identifier and an open parenthesis. There is no conflict with guarded values `[ga]`
in messages or with query option blocks.

`weak`, `forgeable`, `malleable` and `from` are **contextual keywords** and are
deliberately **not** added to `RESERVED` in `src/parser.rs`. They are recognized only
inside a primitive's parameter brackets, a position where no constant can ever appear,
so there is no ambiguity to resolve. Reserving them would be a gratuitous
backwards-compatibility break: any existing model using `weak` or `from` as a constant
name would stop parsing.

This is a deliberate departure from the rule that adding a primitive means adding its
lowercase name to `RESERVED`. That rule exists because primitive names appear in value
position, where they *would* collide with constants. Capability names never do.

## Engine integration

### Where the annotation lives

The parsed capabilities live on `Primitive` (`src/types.rs:368`), beside
`instance_check`, which is the existing precedent for a per-call-site annotation:

```rust
pub struct Primitive {
    pub id: PrimitiveId,
    pub arguments: Vec<Value>,
    pub output: usize,
    pub instance_check: bool,
    pub capabilities: Capabilities,   // new; Default = empty
    pub hash: HashCell,
}
```

`Capabilities` is a small `Copy` bitset plus per-capability onset phases. It is what
the parser produces and what `pretty.rs` round-trips. It is **not** consulted by
`primitive_hash`, and **not** consulted by `equivalent_primitives` — per
[Semantics](#semantics), annotated and unannotated terms are the same term.

`theory.rs::structurally_identical_primitive` is likewise **left unchanged** — it does
not compare capabilities. It backs the `obtainable` memo's cache-validity check, and
since capability lookup is driven by the index rather than by the held term, two terms
differing only in their annotation are genuinely interchangeable for that cache.

### The dedup hazard, and the fix

The engine must **never** read capabilities off the attacker's copy of a term.
`AttackerState` dedupes new knowledge by equivalence, and equivalence ignores
capabilities — so if an unannotated copy of a term reaches the attacker first, the
annotated one is discarded and the break rule silently never fires. That is a missed
attack rather than a false one, so it is sound, but it would make results depend on
which principal the engine happened to walk first.

The fix is to look capabilities up in a model-level index rather than on the held term:

- `construct.rs` builds a `CapabilityIndex` once, while walking the trace: a
  hash-bucket map from annotated term to `Capabilities`, using the same
  bucket-then-equivalence pattern as `AttackerState::knows`. Because equivalent terms
  hash identically, this is precisely the "equivalent terms share the annotation"
  semantics from §Semantics, made operational.
- The index rides on `PrincipalState` as an `Arc<CapabilityIndex>`, so it is free to
  clone and is already in scope at every call site that matters.

Result: deterministic regardless of walk order, no change to `attacker_state_absorb`,
no change to `primitive_hash`, no new `Value` variant.

### Rule sites

Both entry points already receive everything they need — `&PrincipalState` for the
index and `&AttackerState` for `current_phase` — so no new arguments thread through the
engine:

- `theory.rs::can_decompose` gains the `weak` branch: if the index reports `weak` in
  force at `attacker.current_phase`, reveal the spec's declared argument without
  requiring the `given` set.
- `theory.rs::can_reconstruct_primitive` gains the `forgeable` and `malleable`
  branches: `forgeable` drops the declared secret argument from the "must know all
  arguments" requirement; `malleable` additionally requires the attacker to hold an
  instance of the primitive agreeing on every non-varying argument, and to know both
  the old and the new value of the varying one.

Placing the rules at these two functions means every downstream consumer picks them up
for free: `deduction.rs`'s closure, `solve/deduce.rs`, `unlink.rs`, and — importantly —
`solve/deduce.rs::satisfy_check`, which is what makes a forged signature actually pass
`SIGNVERIF` rather than halting the principal before the attack can land.

> **Correction.** This last claim is wrong. `solve/deduce.rs::require_constructible`
> routes through the solver's *own* rule set, not `theory::can_reconstruct_primitive`,
> so `forgeable` needed a second branch in `solve_primitive_arguments`. And because
> solver goals are patterns containing free variables, the capability lookup there
> unifies against the index's annotated terms rather than comparing for equivalence —
> `AEAD_ENC(k, $free, ad)` is not equivalent to the annotated `AEAD_ENC(k, m, ad)`.

`solve/validate.rs::is_worthwhile` needs no change: a `malleable` substitution that
reproduces the honest plaintext reduces back to the honest value and is already
correctly rejected as a replay.

### Spec fields

Three new `PrimitiveSpec` fields, all defaulting to empty, so unmodified specs are
unaffected:

```rust
pub weak_reveals:    Vec<usize>,          // argument positions revealed under `weak`
pub weak_reveals_output: Option<usize>,   // for KEM_ENCAP, mirroring decompose.reveal_output
pub forgeable_secret: Option<usize>,      // argument position not needed under `forgeable`
pub malleable_vary:  Vec<usize>,          // argument positions substitutable under `malleable`
```

A capability is *declared* for a primitive exactly when its corresponding field is
populated — for `weak`, that means `weak_reveals` is non-empty **or**
`weak_reveals_output` is set, since `KEM_ENCAP` declares only the latter. This is what
the sanity errors above test against, so the error table and the spec table cannot
drift apart.

## Reporting

An attack that exists only because of a weakening assumption must say so, or traces
will be pasted without the caveat that makes them meaningful.

- Every attack trace names the assumptions in force, with their source spans.
- The run summary states them even when no query fails, e.g. "verified under 2
  weakening assumptions", so a clean result is not mistaken for an unconditional one.
- `internal-json` carries them, so the VS Code extension can surface them. Note that
  `../verifpal-vscode` must be updated by hand; nothing checks it.

> **Correction.** The `internal-json` verify payload is a top-level *array*, not an
> object, so there is nowhere to hang a sibling `assumptions` key without changing its
> shape — which would break the extension for the same reason the result code format is
> frozen. Assumptions ship as an `"Assumptions"` key on each result object instead,
> which consumers that ignore unknown keys tolerate.
- **The result code format does not change.** It is per-query letter-plus-digit and
  every existing test, plus the extension, depends on it.

## Testing

New models in `examples/test/`, each with a comment at the top explaining why its
expected result code is right, per house style:

- one per capability: `weak`, `forgeable`, `malleable`
- `PUBKEY[weak]` collapsing a DH protocol, confirming the cascade through
  `DH_KEX` needs no new rule
- `AEAD_ENC[forgeable]` where confidentiality still holds and authentication fails —
  the case that justifies splitting the two capabilities
- a phase-delayed model where confidentiality holds in phase 0 and fails from phase 2
  (harvest-now-decrypt-later)
- one model per row of the sanity error table

Plus the regression that matters most: **an existing passing model, annotated, whose
result code is asserted identical.** This pins the bit-for-bit claim in §Semantics.

Unit tests: `Capabilities` parsing and round-trip through `pretty.rs`; the
`CapabilityIndex` returning the same answer for two equivalent-but-differently-written
terms; the phase gate.

Golden pretty-printer files gain one new entry covering the parameter list, including
the `from phase N` form and multiple capabilities.

## Non-goals

Each of these was considered and cut:

- **Algorithm agility and downgrade attacks** (`HASH[sha1]` as a term distinct from
  `HASH[sha256]`). This requires parameters to be part of term identity, which would
  touch equivalence, hashing, every rewrite rule, `solve/matching.rs` and `unlink.rs`.
  It is a much larger feature and is not what this one is for.
- **A `collision` capability.** Finding `m' ≠ m` with the same digest needs an
  attacker-only collision term that the engine treats as equivalent to the honest hash,
  which is the one construct that pokes directly at the
  `equivalent ⟹ same hash` invariant.
- **A global switch** — `attacker[active, quantum]`, or assumption-based
  `attacker[active, breaks[discrete_log] from phase 2]`. Convenient for auditing a
  large model, but it means one line changes the meaning of a primitive at arbitrary
  distance, and a reader scanning the model cannot tell that a plain `DH_KEX` is
  broken. Explicit per-call-site annotation is the deliberate trade.
- **Randomness and nonce-reuse modeling.** Verifpal's terms are deterministic by
  construction, so `deterministic` would be a no-op and `randomized` would *remove*
  attacker power, violating monotonicity. Doing it properly means making `AEAD_ENC`
  randomized by default, which is a semantic change to the entire tool.
