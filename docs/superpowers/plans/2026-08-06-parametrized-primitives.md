<!---
# SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
# SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Parametrized Primitives Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a Verifpal model annotate a primitive call site with a declared weakening assumption — `SIGN[forgeable](sk, m)`, `PUBKEY[weak](a)`, `AEAD_ENC[weak from phase 2](k, m, ad)` — that grants the attacker a specific named capability over that term and nothing else.

**Architecture:** A parameter never changes what a term *is*: annotated and unannotated terms stay equivalent, hash identically, and rewrite identically. The parsed annotation rides on `Primitive` for round-tripping, but the engine reads capabilities from a model-level `CapabilityIndex` built once by `construct.rs` and carried on `PrincipalState`. Reading capabilities off the attacker's held copy of a term would be order-dependent, because `AttackerState` dedupes by equivalence and equivalence ignores the annotation.

**Tech Stack:** Rust 2024, single crate `verifpal`, no new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-06-parametrized-primitives-design.md`

## Global Constraints

- Every new source file starts with the SPDX header: `GPL-3.0-only` for `.rs` and `.vp`, `CC-BY-SA-4.0` for prose. Copy the exact two-line form from any existing file.
- rustfmt with **hard tabs** and Unix newlines. Run `cargo fmt` before every commit.
- `cargo clippy --all-targets -- -D warnings` must pass. A single warning fails CI.
- Every engine item is `pub(crate)`, never `pub`. `#![warn(unreachable_pub)]` is on. The three exceptions in this plan are `Capability`, `Capabilities` and `CapabilityIndex`, which must be `pub` because they appear in `pub` fields of `pub` structs in the public `types` module — see Task 1 Step 3 for the exact mechanism.
- Use `--release` for anything that runs analysis. The debug build is ~11× slower.
- Unit tests live in `#[cfg(test)] mod tests` at the foot of the module they exercise. Test builders share one interner table, so **every unit test must use unique constant names** — prefix them per-test (`cap1_a`, `weak_k`, …).
- Every model added to `examples/test/` must be wired to a `run_model` test in `src/model_tests.rs`, and must carry a comment at the top explaining why its expected result code is right.
- The result code format never changes: one letter+digit per query in model order, `c`/`a`/`f`/`u`/`e`, `0` = holds, `1` = attack found.

## Deviations from the spec

Three, all discovered by reading the actual signatures. They are refinements, not scope changes.

1. **`weak` gets its own theory function, not a branch in `can_decompose`.** `HASH` and `PW_HASH` are variadic and a preimage reveals *every* argument, but `DecomposeResult` carries a single `revealed: Value`. Widening it would touch every decomposition call site. Task 4 adds `theory::can_break_weak` returning `Vec<Value>` and a matching closure rule instead.
2. **`malleable` lives in the solver, not the knowledge closure.** Forward enumeration is quadratic — every held ciphertext crossed with every known plaintext — and malleability only pays off when the attacker injects, which is goal-directed territory. Task 6 puts it in `solve/deduce.rs`. Consequence: a **passive** attacker never uses malleability. That is correct (a passive attacker injects nothing) and is an incompleteness, never an unsoundness.
3. **A new `DerivationRecord` variant is mandatory.** `deduction.rs` routes all knowledge through `learn`, which records the value together with the derivation that explains it. A capability rule that reused `Reconstructed` would produce a trace that cannot explain itself, and would make the spec's Reporting section unimplementable. Task 4 adds `DerivationRecord::Broken`.

---

### Task 1: `Capabilities` data type, parser, and pretty round-trip

Parsing and printing only. No semantics — an annotated model parses, round-trips, and behaves exactly as it does today.

**Files:**
- Create: `src/capability.rs`
- Modify: `src/lib.rs` (declare the module), `src/types.rs:368-395` (`Primitive` struct + `with_arguments`/`with_output`, and the re-export), `src/parser.rs:767-799` (`parse_primitive`), `src/pretty.rs:28-43` (`Display for Primitive`)
- Modify (mechanical): every `Primitive { … }` struct literal. There are **40** sites across `equivalence.rs`, `parser.rs`, `testutil.rs`, `narrate.rs`, `theory.rs`, `skeleton.rs`, `primitive/mod.rs`, `primitive/spec.rs`, `types.rs`, `solve/deduce.rs`, `unlink.rs`, `solve/vars.rs`. The compiler lists every one.
- Test: `src/capability.rs` (unit), `src/parser.rs` (unit), `src/pretty.rs` (unit)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `Capability` — `enum { Weak, Forgeable, Malleable }`, `Copy`. Methods: `fn name(self) -> &'static str`, `fn from_name(s: &str) -> Option<Capability>`, `const ALL: [Capability; 3]`, `fn index(self) -> usize`.
  - `Capabilities` — `Copy`, `PartialEq`, `Eq`, `Debug`. Methods: `fn is_empty(&self) -> bool`, `fn set(&mut self, cap: Capability, from_phase: i32)`, `fn has(&self, cap: Capability) -> bool`, `fn onset(&self, cap: Capability) -> Option<i32>`, `fn in_force(&self, cap: Capability, phase: i32) -> bool`, `fn iter(&self) -> impl Iterator<Item = (Capability, i32)> + '_`, `fn merge(&mut self, other: &Capabilities)`.
  - `Primitive.capabilities: Capabilities` — new public field.

- [ ] **Step 1: Write the failing unit tests for `Capabilities`**

Create `src/capability.rs` containing only the SPDX header and this test module:

```rust
/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn default_capabilities_are_empty() {
		let c = Capabilities::default();
		assert!(c.is_empty());
		for cap in Capability::ALL {
			assert!(!c.has(cap));
			assert_eq!(c.onset(cap), None);
			assert!(!c.in_force(cap, 0));
			assert!(!c.in_force(cap, 99));
		}
	}

	#[test]
	fn phase_zero_capability_is_in_force_everywhere() {
		let mut c = Capabilities::default();
		c.set(Capability::Weak, 0);
		assert!(c.in_force(Capability::Weak, 0));
		assert!(c.in_force(Capability::Weak, 3));
		assert!(!c.in_force(Capability::Forgeable, 0));
	}

	#[test]
	fn delayed_capability_is_in_force_from_onset_onward() {
		let mut c = Capabilities::default();
		c.set(Capability::Weak, 2);
		assert!(!c.in_force(Capability::Weak, 0));
		assert!(!c.in_force(Capability::Weak, 1));
		assert!(c.in_force(Capability::Weak, 2));
		assert!(c.in_force(Capability::Weak, 7));
	}

	#[test]
	fn merge_takes_the_earlier_onset() {
		let mut a = Capabilities::default();
		a.set(Capability::Weak, 5);
		let mut b = Capabilities::default();
		b.set(Capability::Weak, 2);
		b.set(Capability::Forgeable, 1);
		a.merge(&b);
		assert_eq!(a.onset(Capability::Weak), Some(2));
		assert_eq!(a.onset(Capability::Forgeable), Some(1));
	}

	#[test]
	fn iter_yields_only_declared_capabilities_in_order() {
		let mut c = Capabilities::default();
		c.set(Capability::Malleable, 3);
		c.set(Capability::Weak, 0);
		let got: Vec<_> = c.iter().collect();
		assert_eq!(got, vec![(Capability::Weak, 0), (Capability::Malleable, 3)]);
	}

	#[test]
	fn from_name_is_case_insensitive_and_rejects_unknown() {
		assert_eq!(Capability::from_name("weak"), Some(Capability::Weak));
		assert_eq!(Capability::from_name("FORGEABLE"), Some(Capability::Forgeable));
		assert_eq!(Capability::from_name("nonsense"), None);
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --release capability::`
Expected: FAIL to compile — `cannot find type Capabilities in this scope`.

- [ ] **Step 3: Implement `Capability` and `Capabilities`**

Insert above the test module in `src/capability.rs`:

```rust
/// A declared weakening assumption over a primitive call site.
///
/// A capability never changes what a term *is* — annotated and unannotated
/// terms remain equivalent and hash identically. It only ever grants the
/// attacker power it would not otherwise have, which is what makes an
/// unparametrized model behave bit-for-bit as it did before this feature.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Capability {
	/// Confidentiality is lost: the protected argument is recoverable.
	Weak,
	/// Authenticity is lost: the term is constructible without its secret.
	Forgeable,
	/// Authenticity is weakly lost: a held instance can be retargeted.
	Malleable,
}

impl Capability {
	pub const ALL: [Capability; 3] = [
		Capability::Weak,
		Capability::Forgeable,
		Capability::Malleable,
	];

	pub fn index(self) -> usize {
		match self {
			Capability::Weak => 0,
			Capability::Forgeable => 1,
			Capability::Malleable => 2,
		}
	}

	pub fn name(self) -> &'static str {
		match self {
			Capability::Weak => "weak",
			Capability::Forgeable => "forgeable",
			Capability::Malleable => "malleable",
		}
	}

	pub fn from_name(s: &str) -> Option<Capability> {
		Capability::ALL
			.into_iter()
			.find(|c| c.name().eq_ignore_ascii_case(s))
	}
}

/// The set of capabilities declared at one primitive call site, each with the
/// phase it comes into force from.
///
/// `ABSENT` is `-1` rather than `0` because phase 0 is a perfectly good onset:
/// deriving `Default` over the raw array would silently declare every
/// capability in force from the start of every model.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Capabilities {
	onset: [i32; 3],
}

const ABSENT: i32 = -1;

impl Default for Capabilities {
	fn default() -> Self {
		Capabilities {
			onset: [ABSENT; 3],
		}
	}
}

impl Capabilities {
	pub fn is_empty(&self) -> bool {
		self.onset.iter().all(|&o| o == ABSENT)
	}

	pub fn set(&mut self, cap: Capability, from_phase: i32) {
		self.onset[cap.index()] = from_phase.max(0);
	}

	pub fn has(&self, cap: Capability) -> bool {
		self.onset[cap.index()] != ABSENT
	}

	pub fn onset(&self, cap: Capability) -> Option<i32> {
		match self.onset[cap.index()] {
			ABSENT => None,
			o => Some(o),
		}
	}

	pub fn in_force(&self, cap: Capability, phase: i32) -> bool {
		match self.onset(cap) {
			Some(o) => phase >= o,
			None => false,
		}
	}

	pub fn iter(&self) -> impl Iterator<Item = (Capability, i32)> + '_ {
		Capability::ALL
			.into_iter()
			.filter_map(|c| self.onset(c).map(|o| (c, o)))
	}

	pub fn merge(&mut self, other: &Capabilities) {
		for (cap, onset) in other.iter() {
			match self.onset(cap) {
				Some(existing) if existing <= onset => {}
				_ => self.set(cap, onset),
			}
		}
	}
}
```

Declare the module in `src/lib.rs`, next to the other `pub(crate) mod` lines:

```rust
pub(crate) mod capability;
```

Then re-export from `src/types.rs` so the types reach public effective visibility (`Primitive` is a `pub` struct in the public `types` module, so a `pub` field's type must be publicly reachable or the `private_interfaces` lint fires under `-D warnings`). Add near the top of `src/types.rs`, beside the existing `use` lines:

```rust
pub use crate::capability::{Capabilities, Capability};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --release capability::`
Expected: PASS, 6 tests.

- [ ] **Step 5: Add the field to `Primitive` and fix the 40 struct literals**

In `src/types.rs:368`:

```rust
pub struct Primitive {
	pub id: PrimitiveId,
	pub arguments: Vec<Value>,
	pub output: usize,
	pub instance_check: bool,
	pub capabilities: Capabilities,
	pub hash: HashCell,
}
```

In `with_arguments` (`src/types.rs:377`) and `with_output` (`src/types.rs:387`), carry it through — both already carry `instance_check`, so add `capabilities: self.capabilities,` beside it in each.

Then run `cargo build --release` and add `capabilities: Capabilities::default(),` to every literal the compiler flags. **All 40 take the default.** The only sites that will later set a non-default value are the parser (Step 7) and `CapabilityIndex` construction (Task 3); everything else — solver-synthesised terms, skeletons, test builders, equivalence probes — is engine-internal and correctly carries no annotation.

Do **not** touch `hashing.rs::primitive_hash_uncached`, `equivalence.rs::equivalent_primitives`, or `theory.rs::structurally_identical_primitive`. Leaving all three blind to capabilities is the design, not an oversight: annotated and unannotated terms are the same term.

- [ ] **Step 6: Write the failing parser and pretty-printer tests**

Add to the existing `#[cfg(test)] mod tests` at the foot of `src/parser.rs`:

```rust
#[test]
fn parses_primitive_capabilities() {
	let src = "attacker[active]\nprincipal Alice[\n\tknows private cap1_sk\n\tknows private cap1_m\n\tcap1_s = SIGN[forgeable](cap1_sk, cap1_m)\n]\nqueries[\n\tconfidentiality? cap1_m\n]\n";
	let m = parse_string("cap1.vp", src).expect("parses");
	let p = first_primitive(&m).expect("a primitive");
	assert!(p.capabilities.has(Capability::Forgeable));
	assert_eq!(p.capabilities.onset(Capability::Forgeable), Some(0));
	assert!(!p.capabilities.has(Capability::Weak));
}

#[test]
fn parses_capability_with_phase_onset() {
	let src = "attacker[active]\nprincipal Alice[\n\tknows private cap2_k\n\tknows private cap2_m\n\tknows private cap2_ad\n\tcap2_e = AEAD_ENC[forgeable, weak from phase 2](cap2_k, cap2_m, cap2_ad)\n]\nqueries[\n\tconfidentiality? cap2_m\n]\n";
	let m = parse_string("cap2.vp", src).expect("parses");
	let p = first_primitive(&m).expect("a primitive");
	assert_eq!(p.capabilities.onset(Capability::Forgeable), Some(0));
	assert_eq!(p.capabilities.onset(Capability::Weak), Some(2));
}

#[test]
fn rejects_unknown_capability() {
	let src = "attacker[active]\nprincipal Alice[\n\tknows private cap3_m\n\tcap3_h = HASH[bogus](cap3_m)\n]\nqueries[\n\tconfidentiality? cap3_m\n]\n";
	let err = parse_string("cap3.vp", src).expect_err("should reject");
	assert!(
		format!("{}", err).contains("unknown primitive parameter"),
		"got: {}",
		err
	);
}

#[test]
fn rejects_duplicate_capability() {
	let src = "attacker[active]\nprincipal Alice[\n\tknows private cap4_m\n\tcap4_h = HASH[weak, weak](cap4_m)\n]\nqueries[\n\tconfidentiality? cap4_m\n]\n";
	let err = parse_string("cap4.vp", src).expect_err("should reject");
	assert!(
		format!("{}", err).contains("duplicate primitive parameter"),
		"got: {}",
		err
	);
}
```

`parse_string(name, src)` is the existing helper these tests use — see `parser::tests::pubkey_parses_to_a_primitive` at `src/parser.rs:1073`. Add `first_primitive` beside the existing `first_assigned` helper at `src/parser.rs:1059`:

```rust
	fn first_primitive(m: &Model) -> Option<Primitive> {
		let Block::Principal(p) = &m.blocks[0] else {
			return None;
		};
		p.expressions.iter().find_map(|e| match e.assigned.as_ref() {
			Some(Value::Primitive(p)) => Some((**p).clone()),
			_ => None,
		})
	}
```

Add to the existing `#[cfg(test)] mod tests` at the foot of `src/pretty.rs`:

```rust
#[test]
fn displays_primitive_capabilities() {
	let a = make_constant("prcap_a");
	let b = make_constant("prcap_b");
	let mut caps = Capabilities::default();
	caps.set(Capability::Weak, 0);
	let Value::Primitive(p) = make_primitive(PRIM_SIGN, vec![a, b], 0) else {
		panic!("expected a primitive");
	};
	let mut p = (*p).clone();
	p.capabilities = caps;
	assert_eq!(format!("{}", p), "SIGN[weak](prcap_a, prcap_b)");
	p.capabilities.set(Capability::Forgeable, 2);
	assert_eq!(
		format!("{}", p),
		"SIGN[weak, forgeable from phase 2](prcap_a, prcap_b)"
	);
}
```

- [ ] **Step 7: Run the tests to verify they fail**

Run: `cargo test --release parser::tests::parses_primitive_capabilities pretty::tests::displays_primitive_capabilities`
Expected: FAIL — the parser ignores the bracket and errors on the unexpected `[`; the printer omits the parameter list.

- [ ] **Step 8: Implement parsing**

In `src/parser.rs`, change the head of `parse_primitive` (line 767) to read the optional parameter list between the identifier and the open parenthesis:

```rust
	fn parse_primitive(&mut self) -> VResult<Value> {
		let name = self.parse_identifier()?;
		let prim_name = name.to_uppercase();
		self.skip_whitespace();
		let capabilities = if self.peek() == Some(b'[') {
			self.parse_capabilities()?
		} else {
			Capabilities::default()
		};
		self.skip_whitespace();
		self.expect("(")?;
```

and add `capabilities,` to the `Primitive { … }` literal it returns (line 795).

Add the new method beside it:

```rust
	fn parse_capabilities(&mut self) -> VResult<Capabilities> {
		let start = self.pos;
		self.expect("[")?;
		let mut caps = Capabilities::default();
		loop {
			self.consume_trivia_nocapture();
			let word = self.parse_identifier()?;
			let cap = Capability::from_name(&word).ok_or_else(|| {
				VerifpalError::parse(
					format!("unknown primitive parameter `{}`", word).into(),
				)
				.at(Span::at(start))
			})?;
			if caps.has(cap) {
				return Err(VerifpalError::parse(
					format!("duplicate primitive parameter `{}`", cap.name()).into(),
				)
				.at(Span::at(start)));
			}
			self.consume_trivia_nocapture();
			let onset = self.parse_capability_onset()?;
			caps.set(cap, onset);
			self.consume_trivia_nocapture();
			if self.peek() == Some(b',') {
				self.advance();
				continue;
			}
			break;
		}
		self.consume_trivia_nocapture();
		self.expect("]")?;
		Ok(caps)
	}

	/// Parses an optional `from phase N` clause. Returns 0 when absent, which
	/// is "in force from the start". `from` and `phase` are contextual
	/// keywords: they are recognised only here, where no constant can appear,
	/// so they are deliberately absent from RESERVED and a model using `from`
	/// as a constant name keeps parsing.
	fn parse_capability_onset(&mut self) -> VResult<i32> {
		let saved = self.snapshot();
		let Ok(word) = self.parse_identifier() else {
			self.restore(saved);
			return Ok(0);
		};
		if !word.eq_ignore_ascii_case("from") {
			self.restore(saved);
			return Ok(0);
		}
		self.consume_trivia_nocapture();
		let kw = self.parse_identifier()?;
		if !kw.eq_ignore_ascii_case("phase") {
			return Err(VerifpalError::parse(
				"expected `phase` after `from` in primitive parameter".into(),
			)
			.at(Span::at(self.pos)));
		}
		self.consume_trivia_nocapture();
		let start = self.pos;
		while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
			self.pos += 1;
		}
		if start == self.pos {
			return Err(VerifpalError::parse(
				"expected a phase number in primitive parameter".into(),
			)
			.at(Span::at(self.pos)));
		}
		let num = std::str::from_utf8(&self.input[start..self.pos])
			.ok()
			.and_then(|s| s.parse::<i32>().ok())
			.ok_or_else(|| {
				VerifpalError::parse("invalid phase number in primitive parameter".into())
					.at(Span::at(start))
			})?;
		Ok(num)
	}
```

`consume_trivia_nocapture` is deliberate throughout: comments inside the parameter brackets are dropped, matching how `attacker[…]` and `phase[…]` already treat them.

- [ ] **Step 9: Implement pretty-printing**

In `src/pretty.rs`, in `impl fmt::Display for Primitive` (line 28), between the name and the open parenthesis:

```rust
		let name = primitive_name(self.id);
		write!(f, "{}", name)?;
		if !self.capabilities.is_empty() {
			write!(f, "[")?;
			for (i, (cap, onset)) in self.capabilities.iter().enumerate() {
				if i > 0 {
					write!(f, ", ")?;
				}
				write!(f, "{}", cap.name())?;
				if onset > 0 {
					write!(f, " from phase {}", onset)?;
				}
			}
			write!(f, "]")?;
		}
		write!(f, "(")?;
```

- [ ] **Step 10: Run the full suite**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test --release`
Expected: PASS. All 322 pre-existing tests still pass — nothing has semantics yet, so no result code may change. If any model test's code moved, stop: something is reading capabilities that shouldn't be.

- [ ] **Step 11: Commit**

```bash
git add src/capability.rs src/lib.rs src/types.rs src/parser.rs src/pretty.rs src/
git commit -m "parser: parse and round-trip primitive capability parameters"
```

---

### Task 2: Spec declarations and sanity validation

Declares which primitive supports which capability, and rejects the rest with a diagnostic that names the right alternative.

**Files:**
- Modify: `src/primitive/mod.rs:82-98` (`PrimitiveSpec` fields), `src/primitive/spec.rs` (populate 10 specs), `src/capability.rs` (spec query helpers), `src/sanity.rs` (new validation pass), `src/model_tests.rs` (add `run_model_err`)
- Create: `examples/test/cap_err_sign_weak.vp`, `examples/test/cap_err_dh_kex_weak.vp`, `examples/test/cap_err_hash_forgeable.vp`, `examples/test/cap_err_aead_malleable.vp`, `examples/test/cap_err_core_primitive.vp`, `examples/test/cap_err_phase_unreached.vp`

**Interfaces:**
- Consumes: `Capability`, `Capabilities` from Task 1.
- Produces:
  - `PrimitiveSpec.weak_reveals: Vec<usize>`, `.weak_reveals_output: Option<usize>`, `.forgeable_secret: Option<usize>`, `.malleable_vary: Vec<usize>`
  - `capability::supports(id: PrimitiveId, cap: Capability) -> bool`
  - `capability::unsupported_message(id: PrimitiveId, cap: Capability) -> String`
  - `sanity::sanity_capabilities(m: &Model, km: &ProtocolTrace) -> VResult<()>`
  - `model_tests::run_model_err(model: &str, expected_substring: &str)`

- [ ] **Step 1: Write the failing model tests**

Create the six models. Each needs the SPDX header and a comment explaining the expectation. `cap_err_sign_weak.vp`:

```verifpal
// SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
// SPDX-License-Identifier: GPL-3.0-only
//
// SIGN provides authenticity, not confidentiality: a signature does not hide
// its message, so `weak` has nothing to reveal. This must be a sanity error
// pointing at `forgeable`, not a silent no-op — an annotation that quietly
// does nothing reads as a check that was performed when it was not.
attacker[active]

principal Alice[
	knows private sk
	knows private m
	s = SIGN[weak](sk, m)
]

Alice -> Bob: s

principal Bob[
	knows private m
	_ = HASH(s)
]

queries[
	confidentiality? m
]
```

The other five follow the same shape, differing only in the annotated line and the comment:

| file | annotated line | comment says |
| --- | --- | --- |
| `cap_err_dh_kex_weak.vp` | `k = DH_KEX[weak](gb, a)` | discrete log is a property of the key; `PUBKEY[weak]` is the way to say it |
| `cap_err_hash_forgeable.vp` | `h = HASH[forgeable](m)` | HASH has no secret argument, so there is nothing to forge without |
| `cap_err_aead_malleable.vp` | `e = AEAD_ENC[malleable](k, m, ad)` | malleability of an authenticated cipher *is* an authenticity break, spelled `forgeable` |
| `cap_err_core_primitive.vp` | `x = CONCAT[weak](m, n)` | core primitives carry no cryptographic guarantee to weaken |
| `cap_err_phase_unreached.vp` | `e = AEAD_ENC[weak from phase 5](k, m, ad)` in a model with no `phase` block | phase 5 is never reached, so the assumption has no effect |

Add the harness and the tests to `src/model_tests.rs`, beside `run_model_at`:

```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --release model_tests::test_cap_err`
Expected: FAIL — every model verifies successfully and returns a result code, because nothing validates capabilities yet.

- [ ] **Step 3: Add the spec fields**

In `src/primitive/mod.rs:82`, append to `PrimitiveSpec`:

```rust
	/// Argument positions revealed when `weak` is in force. Positions past a
	/// given call's arity are skipped, which is how the variadic HASH and
	/// PW_HASH declare "a preimage reveals every argument".
	pub weak_reveals: Vec<usize>,
	/// Output index revealed when `weak` is in force, for primitives whose
	/// protected value is an output rather than an argument. Mirrors
	/// `decompose.reveal_output`.
	pub weak_reveals_output: Option<usize>,
	/// The argument position the attacker need *not* know to build this term
	/// when `forgeable` is in force — the signing key, the MAC key.
	pub forgeable_secret: Option<usize>,
	/// Argument positions substitutable when `malleable` is in force, given a
	/// held instance agreeing on every other argument.
	pub malleable_vary: Vec<usize>,
```

`PrimitiveSpec` derives `Default` and every spec literal ends in `..PrimitiveSpec::default()`, so no existing literal needs touching.

- [ ] **Step 4: Populate the ten specs**

In `src/primitive/spec.rs`, add exactly these fields to the named entries and nothing else. Argument indices verified against the existing `decompose` and `rewrite` rules in that file:

| primitive | fields to add |
| --- | --- |
| `PW_HASH` | `weak_reveals: vec![0, 1, 2, 3, 4],` |
| `HASH` | `weak_reveals: vec![0, 1, 2, 3, 4],` |
| `AEAD_ENC` | `weak_reveals: vec![1], forgeable_secret: Some(0),` |
| `ENC` | `weak_reveals: vec![1], malleable_vary: vec![1],` |
| `MAC` | `forgeable_secret: Some(0),` |
| `PUBKEY` | `weak_reveals: vec![0],` |
| `SIGN` | `forgeable_secret: Some(0),` |
| `PKE_ENC` | `weak_reveals: vec![1], malleable_vary: vec![1],` |
| `RINGSIGN` | `forgeable_secret: Some(0),` |
| `KEM_ENCAP` | `weak_reveals_output: Some(0),` |

`RINGSIGN`'s argument 0 is the signer's private key: `RINGSIGNVERIF`'s rewrite matches its arguments 0–2 against `RINGSIGN`'s 0–2 through `filter_ringsignverif_rewrite`, which unwraps a `PUBKEY` at position 0. `KEM_ENCAP`'s protected value is output 0, matching its own `decompose.reveal_output`.

`PKE_ENC`'s `malleable_vary` is declared for completeness but is largely redundant in this model — the public key is public, so the attacker can usually build `PKE_ENC(pk, m')` outright. Task 6's test model therefore uses `ENC`, where malleability genuinely adds power.

- [ ] **Step 5: Add the spec query helpers**

Append to `src/capability.rs`, above the test module:

```rust
use crate::primitive::{primitive_get, primitive_is_core, primitive_name};
use crate::types::PrimitiveId;

/// Whether this primitive declares a meaning for this capability.
pub(crate) fn supports(id: PrimitiveId, cap: Capability) -> bool {
	if primitive_is_core(id) {
		return false;
	}
	let Ok(spec) = primitive_get(id) else {
		return false;
	};
	match cap {
		Capability::Weak => !spec.weak_reveals.is_empty() || spec.weak_reveals_output.is_some(),
		Capability::Forgeable => spec.forgeable_secret.is_some(),
		Capability::Malleable => !spec.malleable_vary.is_empty(),
	}
}

/// The diagnostic for a capability a primitive does not declare. Each arm
/// names the alternative the user most likely wanted, because a bare
/// "unsupported" tells them nothing about which of the three to reach for.
pub(crate) fn unsupported_message(id: PrimitiveId, cap: Capability) -> String {
	let name = primitive_name(id);
	if primitive_is_core(id) {
		return format!(
			"{} is a core primitive and carries no cryptographic guarantee to weaken",
			name
		);
	}
	match cap {
		Capability::Weak if supports(id, Capability::Forgeable) => format!(
			"{} provides authenticity, not confidentiality; did you mean `{}[forgeable]`?",
			name, name
		),
		Capability::Weak if name == "DH_KEX" => {
			"discrete log is a property of the key, not the exchange; \
			 did you mean `PUBKEY[weak]`?"
				.to_string()
		}
		Capability::Forgeable => format!(
			"{} has no secret argument; anyone who knows its inputs can compute it",
			name
		),
		Capability::Malleable if supports(id, Capability::Forgeable) => format!(
			"malleability of an authenticated primitive is an authenticity break; \
			 did you mean `{}[forgeable]`?",
			name
		),
		_ => format!("{} does not support the `{}` parameter", name, cap.name()),
	}
}
```

Note the arm order: `AEAD_ENC[malleable]` must reach the "did you mean forgeable" arm, and `AEAD_ENC` does declare `forgeable_secret`, so the guard holds. `HASH[forgeable]` reaches the "no secret argument" arm.

- [ ] **Step 6: Add the sanity pass**

In `src/sanity.rs`, add a function that walks every primitive in the model — including nested arguments — and validate both the capability and its onset phase. Call it from the main sanity entry point *after* the protocol trace is built, since it needs `km.max_phase`:

```rust
pub(crate) fn sanity_capabilities(m: &Model, km: &ProtocolTrace) -> VResult<()> {
	for block in &m.blocks {
		for value in block_values(block) {
			sanity_capabilities_value(&value, km)?;
		}
	}
	Ok(())
}

fn sanity_capabilities_value(v: &Value, km: &ProtocolTrace) -> VResult<()> {
	let Value::Primitive(p) = v else {
		return Ok(());
	};
	for (cap, onset) in p.capabilities.iter() {
		if !crate::capability::supports(p.id, cap) {
			return Err(VerifpalError::sanity(
				crate::capability::unsupported_message(p.id, cap).into(),
			));
		}
		if onset > km.max_phase {
			return Err(VerifpalError::sanity(
				format!(
					"`{}` on {} comes into force at phase {}, which is never reached; \
					 this assumption has no effect",
					cap.name(),
					crate::primitive::primitive_name(p.id),
					onset
				)
				.into(),
			));
		}
	}
	for arg in &p.arguments {
		sanity_capabilities_value(arg, km)?;
	}
	Ok(())
}
```

`block_values` is a helper you must write in `src/sanity.rs`: given a `Block`, yield every `Value` appearing in it — the right-hand sides of expressions inside a `Principal` block, and the values in a `Message` block. Follow whatever traversal the neighbouring sanity functions already use over `m.blocks`; do not invent a second traversal style. Attach the offending declaration's span with `VerifpalError::or_span` the same way the surrounding code does, so the error prints with a caret at the annotation.

Find where `sanity.rs` currently drives `construct_protocol_trace` and add the call immediately after the trace exists.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test --release model_tests::test_cap_err`
Expected: PASS, 6 tests.

- [ ] **Step 8: Run the full suite**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test --release`
Expected: PASS. Still no result code may change on any pre-existing model.

- [ ] **Step 9: Commit**

```bash
git add src/primitive/ src/capability.rs src/sanity.rs src/model_tests.rs examples/test/cap_err_*.vp
git commit -m "sanity: validate primitive capability parameters against the spec"
```

---

### Task 3: `CapabilityIndex` and wiring into `PrincipalState`

The lookup the engine actually consults. Still no attacker rules — this task only makes "is this term weak at this phase?" answerable.

**Files:**
- Modify: `src/capability.rs` (the index), `src/types.rs:688-697` (`PrincipalState` field), `src/construct.rs:376-433` (build and attach), `src/reexec.rs` / `src/witness.rs` / `src/solve/validate.rs` (any site that builds a `PrincipalState` literal — the compiler lists them)
- Test: `src/capability.rs` (unit)

**Interfaces:**
- Consumes: `Capability`, `Capabilities` from Task 1.
- Produces:
  - `CapabilityIndex` — `Default`, `Debug`. Methods: `fn insert(&mut self, v: &Value)` (walks subterms, recording every annotated primitive), `fn lookup(&self, p: &Primitive) -> Capabilities`, `fn in_force(&self, p: &Primitive, cap: Capability, phase: i32) -> bool`, `fn is_empty(&self) -> bool`, `fn assumptions(&self) -> Vec<(Value, Capability, i32)>`.
  - `PrincipalState.capabilities: Arc<CapabilityIndex>` — new public field.

- [ ] **Step 1: Write the failing unit tests**

Add to the test module in `src/capability.rs`:

```rust
#[test]
fn index_answers_for_an_equivalent_but_unannotated_term() {
	use crate::testutil::*;
	let k = make_constant("cidx_k");
	let m = make_constant("cidx_m");
	let ad = make_constant("cidx_ad");
	let annotated = {
		let Value::Primitive(p) =
			make_primitive(PRIM_AEAD_ENC, vec![k.clone(), m.clone(), ad.clone()], 0)
		else {
			panic!("expected a primitive");
		};
		let mut p = (*p).clone();
		p.capabilities.set(Capability::Weak, 0);
		Value::Primitive(std::sync::Arc::new(p))
	};
	let plain = make_primitive(PRIM_AEAD_ENC, vec![k, m, ad], 0);

	let mut index = CapabilityIndex::default();
	index.insert(&annotated);

	let Value::Primitive(plain_p) = &plain else {
		panic!("expected a primitive");
	};
	assert!(
		index.in_force(plain_p, Capability::Weak, 0),
		"equivalent terms must share the annotation"
	);
}

#[test]
fn index_records_nested_annotations() {
	use crate::testutil::*;
	let a = make_constant("cnest_a");
	let inner = {
		let Value::Primitive(p) = make_primitive(PRIM_PUBKEY, vec![a], 0) else {
			panic!("expected a primitive");
		};
		let mut p = (*p).clone();
		p.capabilities.set(Capability::Weak, 3);
		Value::Primitive(std::sync::Arc::new(p))
	};
	let b = make_constant("cnest_b");
	let outer = make_primitive(PRIM_DH_KEX, vec![inner.clone(), b], 0);

	let mut index = CapabilityIndex::default();
	index.insert(&outer);

	let Value::Primitive(inner_p) = &inner else {
		panic!("expected a primitive");
	};
	assert!(!index.in_force(inner_p, Capability::Weak, 2));
	assert!(index.in_force(inner_p, Capability::Weak, 3));
}

#[test]
fn empty_index_grants_nothing() {
	use crate::testutil::*;
	let a = make_constant("cempty_a");
	let p = make_primitive(PRIM_HASH, vec![a], 0);
	let Value::Primitive(p) = &p else {
		panic!("expected a primitive");
	};
	let index = CapabilityIndex::default();
	assert!(index.is_empty());
	for cap in Capability::ALL {
		assert!(!index.in_force(p, cap, 0));
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --release capability::`
Expected: FAIL to compile — `cannot find type CapabilityIndex in this scope`.

- [ ] **Step 3: Implement `CapabilityIndex`**

Append to `src/capability.rs`, above the test module:

```rust
use std::collections::HashMap;

use crate::types::{Primitive, Value};

/// Model-level record of which terms carry which weakening assumptions.
///
/// The engine consults this rather than the `capabilities` field on whatever
/// copy of a term it happens to be holding. `AttackerState` dedupes knowledge
/// by equivalence and equivalence ignores capabilities, so if an unannotated
/// copy of a term reached the attacker first the annotated one would be
/// discarded and the rule would silently never fire — a missed attack whose
/// presence depended on which principal the engine walked first.
///
/// Keying by hash bucket and confirming with `equivalent` is the same pattern
/// `AttackerState::knows` uses, and it is what makes "equivalent terms share
/// the annotation" true by construction rather than by convention.
#[derive(Clone, Debug, Default)]
pub struct CapabilityIndex {
	buckets: HashMap<u64, Vec<(Value, Capabilities)>>,
}

impl CapabilityIndex {
	pub fn is_empty(&self) -> bool {
		self.buckets.is_empty()
	}

	/// Records every annotated primitive in `v`, including nested ones.
	pub fn insert(&mut self, v: &Value) {
		let Value::Primitive(p) = v else {
			return;
		};
		for arg in &p.arguments {
			self.insert(arg);
		}
		if p.capabilities.is_empty() {
			return;
		}
		let hash = v.hash_value();
		let bucket = self.buckets.entry(hash).or_default();
		for (existing, caps) in bucket.iter_mut() {
			if existing.equivalent(v, true) {
				caps.merge(&p.capabilities);
				return;
			}
		}
		bucket.push((v.clone(), p.capabilities));
	}

	pub fn lookup(&self, p: &Primitive) -> Capabilities {
		let probe = Value::Primitive(std::sync::Arc::new(p.clone()));
		let hash = probe.hash_value();
		let Some(bucket) = self.buckets.get(&hash) else {
			return Capabilities::default();
		};
		for (existing, caps) in bucket {
			if existing.equivalent(&probe, true) {
				return *caps;
			}
		}
		Capabilities::default()
	}

	pub fn in_force(&self, p: &Primitive, cap: Capability, phase: i32) -> bool {
		if self.buckets.is_empty() {
			return false;
		}
		self.lookup(p).in_force(cap, phase)
	}

	/// Every assumption the model declares, for reporting.
	pub fn assumptions(&self) -> Vec<(Value, Capability, i32)> {
		let mut out = Vec::new();
		for bucket in self.buckets.values() {
			for (v, caps) in bucket {
				for (cap, onset) in caps.iter() {
					out.push((v.clone(), cap, onset));
				}
			}
		}
		out.sort_by_key(|(v, cap, onset)| (v.hash_value(), cap.index(), *onset));
		out
	}
}
```

The `buckets.is_empty()` early return in `in_force` matters: it is the fast path every unparametrized model takes, and it keeps this feature off the hot path entirely for models that don't use it.

Re-export it from `src/types.rs` alongside the others:

```rust
pub use crate::capability::{CapabilityIndex, Capabilities, Capability};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --release capability::`
Expected: PASS, 9 tests.

- [ ] **Step 5: Attach the index to `PrincipalState`**

In `src/types.rs:688`, add the field:

```rust
pub struct PrincipalState {
	pub name: String,
	pub id: PrincipalId,
	pub max_declared_at: i32,
	pub meta: Arc<Vec<SlotMeta>>,
	pub values: Vec<SlotValues>,
	pub index: Arc<HashMap<ValueId, usize>>,
	pub leaks: Arc<Vec<LeakEvent>>,
	pub halted_at: Option<i32>,
	pub capabilities: Arc<CapabilityIndex>,
}
```

In `src/construct.rs::construct_principal_states` (line 376), build the index **once before the per-principal loop** and share the `Arc`:

```rust
	let mut capability_index = CapabilityIndex::default();
	for slot in &trace.slots {
		capability_index.insert(&slot.initial_value);
	}
	let capabilities = Arc::new(capability_index);
```

and add `capabilities: capabilities.clone(),` to the `PrincipalState { … }` literal at line 421.

`src/testutil.rs::make_principal_state` (line 81) is also a `PrincipalState` literal; give it `capabilities: Arc::new(CapabilityIndex::default())` so unit-test states grant nothing by default.

Build and fix every other `PrincipalState { … }` literal the compiler flags — those in `reexec.rs`, `witness.rs` and `solve/validate.rs` are clones or rebuilds of an existing state, so each must carry the **same** `Arc` forward (`capabilities: ps.capabilities.clone()`). A rebuilt state that dropped the index would silently disable every capability during re-execution, which is exactly the validation path that decides whether an attack is real. If a site uses struct-update syntax (`..ps.clone()`), it needs no change.

Check `construct.rs::clone_for_depth(purify)` specifically: purification restores values from `original`, and the index must survive it untouched.

- [ ] **Step 6: Run the full suite**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test --release`
Expected: PASS, no result code changes. Nothing reads `in_force` yet.

- [ ] **Step 7: Commit**

```bash
git add src/capability.rs src/types.rs src/construct.rs src/reexec.rs src/witness.rs src/solve/
git commit -m "construct: build a model-level capability index onto principal states"
```

---

### Task 4: `weak`

The first capability with teeth, plus the derivation record all three need and the phase gate.

**Files:**
- Modify: `src/types.rs:731-771` (`DerivationRecord`), `src/theory.rs` (new `can_break_weak`), `src/deduction.rs:44-102` (new closure rule), `src/narrate.rs` (render the new variant)
- Create: `examples/test/cap_weak_hash.vp`, `examples/test/cap_weak_pubkey_dh.vp`, `examples/test/cap_weak_phase_delayed.vp`
- Test: `src/theory.rs` (unit), `src/model_tests.rs`

**Interfaces:**
- Consumes: `CapabilityIndex` on `PrincipalState` (Task 3), spec fields (Task 2).
- Produces:
  - `DerivationRecord::Broken { of: Value, capability: Capability, using: Vec<Value> }`
  - `theory::can_break_weak(p: &Primitive, ps: &PrincipalState, attacker: &AttackerState) -> Option<Vec<Value>>`

- [ ] **Step 1: Write the failing model tests**

`examples/test/cap_weak_hash.vp` — a preimage recovers every argument of a variadic hash:

```verifpal
// SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
// SPDX-License-Identifier: GPL-3.0-only
//
// Expected: c1c1
//
// Alice sends a hash of two secrets. Under `weak` the attacker inverts it and
// recovers BOTH arguments, because a preimage of HASH(a, b) is the whole input
// — this is why `weak` cannot reuse the single-valued DecomposeRule::reveal.
attacker[passive]

principal Alice[
	knows private m
	knows private n
	h = HASH[weak](m, n)
]

Alice -> Bob: h

principal Bob[
	_ = HASH(h)
]

queries[
	confidentiality? m
	confidentiality? n
]
```

`examples/test/cap_weak_pubkey_dh.vp` — the discrete-log cascade, which must need **no** new rule:

```verifpal
// SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
// SPDX-License-Identifier: GPL-3.0-only
//
// Expected: c1
//
// PUBKEY[weak] is discrete log. The attacker takes ga off the wire, recovers
// a, and then reconstructs DH_KEX(gb, a) through the EXISTING
// can_reconstruct_primitive — no DH-specific rule is involved. This model is
// the regression that pins that cascade.
attacker[passive]

principal Alice[
	generates a
	ga = PUBKEY[weak](a)
]

principal Bob[
	generates b
	gb = PUBKEY(b)
]

Alice -> Bob: ga
Bob -> Alice: gb

principal Alice[
	knows private m
	k = DH_KEX(gb, a)
	e = AEAD_ENC(k, m, nil)
]

Alice -> Bob: e

principal Bob[
	k_b = DH_KEX(ga, b)
	m_b = AEAD_DEC(k_b, e, nil)
]

queries[
	confidentiality? m
]
```

`examples/test/cap_weak_phase_delayed.vp` — harvest now, decrypt later:

```verifpal
// SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
// SPDX-License-Identifier: GPL-3.0-only
//
// Expected: c0c1
//
// The same ciphertext, queried before and after the break comes into force.
// `m_now` is confidential in phase 0 and stays so; `m_later` is recorded by
// the attacker in phase 0 and opened in phase 2. This is harvest-now-
// decrypt-later, and it is the reason `from phase N` exists: no amount of
// `leaks` can express "the attacker gains the ability to invert this".
attacker[passive]

principal Alice[
	knows private k
	knows private m_now
	knows private m_later
	e_now = AEAD_ENC(k, m_now, nil)
	e_later = AEAD_ENC[weak from phase 2](k, m_later, nil)
]

Alice -> Bob: e_now, e_later

principal Bob[
	d_now = AEAD_DEC(k, e_now, nil)
	d_later = AEAD_DEC(k, e_later, nil)
]

phase[1]

phase[2]

queries[
	confidentiality? m_now
	confidentiality? m_later
]
```

Add the tests to `src/model_tests.rs`:

```rust
#[test]
fn test_cap_weak_hash() {
	run_model("cap_weak_hash.vp", "c1c1");
}
#[test]
fn test_cap_weak_pubkey_dh() {
	run_model("cap_weak_pubkey_dh.vp", "c1");
}
#[test]
fn test_cap_weak_phase_delayed() {
	run_model("cap_weak_phase_delayed.vp", "c0c1");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --release model_tests::test_cap_weak`
Expected: FAIL — each reports the confidentiality queries holding (`c0c0`, `c0`, `c0c0`), because nothing consumes `weak` yet.

- [ ] **Step 3: Add the `Broken` derivation record**

In `src/types.rs:732`, add the variant:

```rust
	/// The attacker broke a primitive the model declared weak, forgeable or
	/// malleable. Carrying the capability is not decoration: narration must be
	/// able to say which declared assumption a step rests on, or an attack
	/// found only under an assumption reads as an unconditional one.
	Broken {
		of: Value,
		capability: Capability,
		using: Vec<Value>,
	},
```

Extend both match arms in the `impl DerivationRecord` block (line 744). In `ingredients`, group it with `Decomposed`/`Recomposed` — it has the same `of` + `using` shape:

```rust
			DerivationRecord::Decomposed { of, using }
			| DerivationRecord::Recomposed { of, using }
			| DerivationRecord::Broken { of, using, .. } => {
				let mut v = vec![of];
				v.extend(using.iter());
				v
			}
```

In `reads_from_state`, leave `Broken` out — it derives from values the attacker already holds, not from a principal's slot. The compiler will flag every other non-exhaustive match on `DerivationRecord`; `narrate.rs` is handled in Step 6, and any other site should follow whatever it does for `Decomposed`.

- [ ] **Step 4: Write the failing unit test for `can_break_weak`**

Add to the test module at the foot of `src/theory.rs`:

```rust
#[test]
fn can_break_weak_reveals_every_in_range_argument() {
	let m = make_constant("cbw_m");
	let n = make_constant("cbw_n");
	let h = make_primitive(PRIM_HASH, vec![m.clone(), n.clone()], 0);
	let Value::Primitive(hp) = &h else {
		panic!("expected a primitive");
	};
	let mut annotated = (**hp).clone();
	annotated.capabilities.set(Capability::Weak, 0);

	let mut index = CapabilityIndex::default();
	index.insert(&Value::Primitive(Arc::new(annotated)));

	let mut ps = make_principal_state("Alice", 1, vec![], vec![]);
	ps.capabilities = Arc::new(index);
	let attacker = make_attacker_state(vec![h.clone()]);

	let revealed = can_break_weak(hp, &ps, &attacker).expect("weak is in force");
	assert_eq!(revealed.len(), 2);
	assert!(revealed.iter().any(|v| v.equivalent(&m, true)));
	assert!(revealed.iter().any(|v| v.equivalent(&n, true)));
}

#[test]
fn can_break_weak_is_none_before_its_onset_phase() {
	let m = make_constant("cbwp_m");
	let h = make_primitive(PRIM_HASH, vec![m], 0);
	let Value::Primitive(hp) = &h else {
		panic!("expected a primitive");
	};
	let mut annotated = (**hp).clone();
	annotated.capabilities.set(Capability::Weak, 2);

	let mut index = CapabilityIndex::default();
	index.insert(&Value::Primitive(Arc::new(annotated)));

	let mut ps = make_principal_state("Alice", 1, vec![], vec![]);
	ps.capabilities = Arc::new(index);
	let mut attacker = make_attacker_state(vec![h.clone()]);

	attacker.current_phase = 1;
	assert!(can_break_weak(hp, &ps, &attacker).is_none());
	attacker.current_phase = 2;
	assert!(can_break_weak(hp, &ps, &attacker).is_some());
}
```

`make_principal_state(name, id, meta, values)` and `make_attacker_state(known)` are the real helpers in `src/testutil.rs` at lines 81 and 66. `make_attacker_state` builds `known_map` for you, so `attacker.knows` works without further setup.

- [ ] **Step 5: Implement `can_break_weak`**

Add to `src/theory.rs`, beside `can_decompose`:

```rust
/// The `weak` capability: the primitive's confidentiality is gone, so holding
/// the term is enough to recover what it protects.
///
/// This is deliberately not a branch inside `can_decompose`. A preimage of a
/// variadic `HASH(a, b, c)` recovers every argument, and `DecomposeResult`
/// carries a single `revealed` value; widening that would disturb every
/// decomposition call site to serve one capability.
pub(crate) fn can_break_weak(
	p: &Primitive,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Option<Vec<Value>> {
	if primitive_is_core(p.id) {
		return None;
	}
	if !ps
		.capabilities
		.in_force(p, Capability::Weak, attacker.current_phase)
	{
		return None;
	}
	let spec = primitive_get(p.id).ok()?;
	let mut revealed = Vec::new();
	for &idx in &spec.weak_reveals {
		if let Some(a) = p.arguments.get(idx) {
			revealed.push(a.clone());
		}
	}
	if let Some(output) = spec.weak_reveals_output {
		revealed.push(Value::Primitive(Arc::new(p.with_output(output))));
	}
	if revealed.is_empty() {
		return None;
	}
	Some(revealed)
}
```

Indices past a call's arity are skipped by `arguments.get`, which is how `HASH`'s `weak_reveals: vec![0,1,2,3,4]` works for every arity from 1 to 5.

- [ ] **Step 6: Add the closure rule**

In `src/deduction.rs`, add a rule with the same signature as `rule_decompose` (line 104) and register it in **rule group 1**, the group that iterates attacker-known values, immediately after `rule_decompose`:

```rust
fn rule_break_weak(
	ctx: &VerifyContext,
	value: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	let Value::Primitive(p) = value else {
		return false;
	};
	let Some(revealed) = crate::theory::can_break_weak(p, ps, attacker) else {
		return false;
	};
	let mut progress = false;
	for r in revealed {
		progress |= learn(
			ctx,
			&r,
			record,
			DerivationRecord::Broken {
				of: value.clone(),
				capability: Capability::Weak,
				using: vec![],
			},
			|| {
				format!(
					"{} recovered from {} under the declared `weak` assumption.",
					info_output_text(&r),
					value,
				)
			},
		);
	}
	progress
}
```

`learn`'s signature is `(ctx, value, record, derivation, message)` — note `record` comes **before** `derivation` (`src/deduction.rs:90`). `info_output_text` is what `rule_decompose` uses to render the learned value; follow it. The message is a closure because minimization re-runs the closure many times with output suppressed.

`using` is empty because the attacker needs nothing beyond the term itself: that is precisely what `weak` means.

Render the new variant in `src/narrate.rs` wherever `DerivationRecord` is matched for the `Derive` step, following the `Decomposed` arm's shape and naming the capability:

```
	Derive › m from HASH(m, n) — declared `weak`
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test --release model_tests::test_cap_weak && cargo test --release theory::tests::can_break_weak`
Expected: PASS, 5 tests.

- [ ] **Step 8: Read the attack traces and confirm each 0/1 is right**

This step is not optional. The tool's own output is ground truth for regressions, never for correctness.

```bash
cargo run --release -- verify examples/test/cap_weak_hash.vp
cargo run --release -- verify examples/test/cap_weak_pubkey_dh.vp
cargo run --release -- verify examples/test/cap_weak_phase_delayed.vp
```

Confirm specifically: in `cap_weak_pubkey_dh.vp` the trace recovers `a` from `ga` and then *reconstructs* `DH_KEX(gb, a)` — if it reports learning `k` some other way, the cascade claim is wrong and the model is not testing what its comment says. In `cap_weak_phase_delayed.vp` confirm `m_now` is reported as holding and that `m_later`'s break is attributed to phase 2, not phase 0.

- [ ] **Step 9: Run the full suite**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test --release`
Expected: PASS. **No pre-existing model's result code may change.** If one did, `in_force` is returning true for an unannotated term — check the `buckets.is_empty()` fast path.

- [ ] **Step 10: Commit**

```bash
git add src/types.rs src/theory.rs src/deduction.rs src/narrate.rs src/model_tests.rs examples/test/cap_weak_*.vp
git commit -m "theory: implement the weak capability with phase-delayed onset"
```

---

### Task 5: `forgeable`

**Files:**
- Modify: `src/theory.rs:318-357` (`can_reconstruct_primitive` and `_directly`), plus its 4 non-test callers: `src/deduction.rs:156`, `src/reexec.rs:132`, `src/unlink.rs:229`, `src/theory.rs:264`
- Create: `examples/test/cap_forgeable_sign.vp`, `examples/test/cap_forgeable_aead.vp`
- Test: `src/model_tests.rs`

**Interfaces:**
- Consumes: `CapabilityIndex` (Task 3), `forgeable_secret` (Task 2), `DerivationRecord::Broken` (Task 4).
- Produces: `theory::ReconstructResult { from: Vec<Value>, forged: Option<Capability> }`, and `can_reconstruct_primitive` now returns `Option<ReconstructResult>`.

- [ ] **Step 1: Write the failing model tests**

`examples/test/cap_forgeable_sign.vp`:

```verifpal
// SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
// SPDX-License-Identifier: GPL-3.0-only
//
// Expected: a1
//
// Under `forgeable` the attacker builds SIGN(sk, m') without sk, so Bob's
// SIGNVERIF check passes on a message Alice never signed. The check passing is
// the whole point: a forgery that halted Bob at the checked primitive would
// never reach the authentication query.
attacker[active]

principal Alice[
	generates sk
	pk = PUBKEY(sk)
	knows public m
	s = SIGN[forgeable](sk, m)
]

Alice -> Bob: [pk], m, s

principal Bob[
	_ = SIGNVERIF(pk, m, s)?
]

queries[
	authentication? Alice -> Bob: s
]
```

`examples/test/cap_forgeable_aead.vp` — the case that justifies splitting `weak` from `forgeable`:

```verifpal
// SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
// SPDX-License-Identifier: GPL-3.0-only
//
// Expected: c0a1
//
// AEAD_ENC[forgeable] loses authenticity but keeps confidentiality: the
// attacker can manufacture a ciphertext Bob accepts, yet still cannot read
// Alice's. If `c` ever flips to 1 the two capabilities have been collapsed
// into one and the split has stopped paying for itself.
attacker[active]

principal Alice[
	knows private k
	knows private m
	knows public ad
	e = AEAD_ENC[forgeable](k, m, ad)
]

Alice -> Bob: e

principal Bob[
	knows private k
	knows public ad
	d = AEAD_DEC(k, e, ad)?
	_ = HASH(d)
]

queries[
	confidentiality? m
	authentication? Alice -> Bob: e
]
```

Add to `src/model_tests.rs`:

```rust
#[test]
fn test_cap_forgeable_sign() {
	run_model("cap_forgeable_sign.vp", "a1");
}
#[test]
fn test_cap_forgeable_aead() {
	run_model("cap_forgeable_aead.vp", "c0a1");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --release model_tests::test_cap_forgeable`
Expected: FAIL — `a0` and `c0a0`.

- [ ] **Step 3: Introduce `ReconstructResult`**

Add to `src/types.rs`, immediately after `DecomposeResult` (line 802):

```rust
pub struct ReconstructResult {
	/// The ingredients the attacker actually held. A forged argument is
	/// deliberately absent: listing a value the attacker never knew would put
	/// a lie in the attack trace's ingredient list.
	pub from: Vec<Value>,
	/// Set when the reconstruction was only possible under a declared
	/// assumption, so narration can say so.
	pub forged: Option<Capability>,
}
```

- [ ] **Step 4: Implement the `forgeable` branch**

Rewrite the tail of `can_reconstruct_primitive_directly` (`src/theory.rs:330`):

```rust
fn can_reconstruct_primitive_directly(
	p: &Primitive,
	ps: &PrincipalState,
	attacker: &AttackerState,
	depth: usize,
) -> Option<ReconstructResult> {
	if depth > MAX_DEPTH {
		return None;
	}
	let (rewritten, rewrite_value) = can_rewrite(p, ps, 0);
	if !rewritten {
		return None;
	}
	let Value::Primitive(rewritten_prim) = &rewrite_value else {
		return None;
	};
	let forgeable_secret = ps
		.capabilities
		.in_force(rewritten_prim, Capability::Forgeable, attacker.current_phase)
		.then(|| primitive_get(rewritten_prim.id).ok()?.forgeable_secret)
		.flatten();
	let mut has = Vec::new();
	let mut skipped = 0usize;
	for (i, a) in rewritten_prim.arguments.iter().enumerate() {
		if Some(i) == forgeable_secret {
			skipped += 1;
			continue;
		}
		if obtainable(a, ps, attacker, depth) {
			has.push(a.clone());
		}
	}
	if has.len() + skipped < rewritten_prim.arguments.len() {
		return None;
	}
	Some(ReconstructResult {
		from: has,
		forged: (skipped > 0).then_some(Capability::Forgeable),
	})
}
```

Note `skipped` is counted rather than pushed into `has`: the skipped argument is exactly the value the attacker does *not* know, and `has` becomes the ingredient list of a `Reconstructed` derivation.

Update `can_reconstruct_primitive` (line 318) to return `Option<ReconstructResult>` — its body is unchanged apart from the type.

- [ ] **Step 5: Update the four callers**

- `src/reexec.rs:132` — `.is_some()`, no change needed beyond the type inferring.
- `src/theory.rs:264` — `.is_some()`, likewise.
- `src/unlink.rs:229` — currently `can_reconstruct_primitive(p, ps, attacker, 0).map(...)`; change to read `.from` off the result.
- `src/deduction.rs:156` — this one matters. Use `forged` to pick the derivation:

```rust
			let result = can_reconstruct_primitive(p, ps, attacker, 0);
			if let Some(r) = result {
				let derivation = match r.forged {
					Some(capability) => DerivationRecord::Broken {
						of: value.clone(),
						capability,
						using: r.from.clone(),
					},
					None => DerivationRecord::Reconstructed { from: r.from.clone() },
				};
				// … then learn(…) with `derivation`, matching the existing call shape
			}
```

Because `satisfy_check` in `src/solve/deduce.rs` reaches reconstruction through this same path, a forged signature now genuinely passes `SIGNVERIF` rather than halting the principal — which is what makes `cap_forgeable_sign.vp` reach its authentication query at all.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --release model_tests::test_cap_forgeable`
Expected: PASS, 2 tests.

- [ ] **Step 7: Read the attack traces and confirm**

```bash
cargo run --release -- verify examples/test/cap_forgeable_sign.vp
cargo run --release -- verify examples/test/cap_forgeable_aead.vp
```

Confirm in `cap_forgeable_aead.vp` that the confidentiality query genuinely holds and that the authentication failure names the forged ciphertext. If the trace shows the attacker *reading* `m`, `forgeable` has been implemented as `weak` and the split is broken.

- [ ] **Step 8: Run the full suite**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test --release`
Expected: PASS, no pre-existing result code changes. Pay attention to `auth_with_signing_false-attack.vp` (`c0a1a0`) and `aead_replay_not_forgery.vp` (`a0c0`) — those two pin the known-vs-forgeable line this task edits, and they are the most likely to break.

- [ ] **Step 9: Commit**

```bash
git add src/types.rs src/theory.rs src/deduction.rs src/unlink.rs src/reexec.rs src/model_tests.rs examples/test/cap_forgeable_*.vp
git commit -m "theory: implement the forgeable capability"
```

---

### Task 6: `malleable`

Goal-directed, in the solver. See Deviation 2 above for why it is not in the closure.

**Files:**
- Modify: `src/solve/deduce.rs` (new goal-discharge branch)
- Create: `examples/test/cap_malleable_enc.vp`
- Test: `src/model_tests.rs`

**Interfaces:**
- Consumes: `CapabilityIndex` (Task 3), `malleable_vary` (Task 2), `DerivationRecord::Broken` (Task 4).
- Produces: nothing other tasks consume.

- [ ] **Step 1: Write the failing model test**

`examples/test/cap_malleable_enc.vp`:

```verifpal
// SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
// SPDX-License-Identifier: GPL-3.0-only
//
// Expected: c0a1
//
// Malleability only buys the attacker anything when a CHECK constrains what it
// may substitute. If Bob simply used the decryption in an unchecked primitive,
// the ordinary blanket substitution would already break authentication and
// this model would prove nothing — so Bob verifies a signature over the
// decrypted value.
//
// Honest run: Bob decrypts c to m1 and SIGNVERIF(pk, m1, sig1) passes.
// Attack: the attacker swaps sig1 for sig2 and malleates c from ENC(k, m1)
// into ENC(k, m2) — it knows both plaintexts, both public — so Bob decrypts to
// m2 and the signature check passes on a message Alice never sent in this
// slot. Without `malleable` there is no attack: the attacker cannot produce
// ENC(k, m2) without k, so the check halts Bob.
//
// `confidentiality? k` must hold. That is what separates `malleable` from
// `forgeable`: the attacker redirects a ciphertext it already holds, and never
// learns the key or builds one from nothing.
attacker[active]

principal Alice[
	generates sk
	pk = PUBKEY(sk)
	knows private k
	knows public m1
	knows public m2
	c = ENC[malleable](k, m1)
	sig1 = SIGN(sk, m1)
	sig2 = SIGN(sk, m2)
]

Alice -> Bob: [pk], c, sig1, sig2

principal Bob[
	knows private k
	d = DEC(k, c)
	_ = SIGNVERIF(pk, d, sig1)?
]

queries[
	confidentiality? k
	authentication? Alice -> Bob: c
]
```

Add to `src/model_tests.rs`:

```rust
#[test]
fn test_cap_malleable_enc() {
	run_model("cap_malleable_enc.vp", "c0a1");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --release model_tests::test_cap_malleable_enc`
Expected: FAIL, reporting **`c0a0`**.

This is a gate, not a formality. If it reports `c0a1` the model does **not** discriminate — the attack is landing without malleability, and the test would pass in Step 4 while proving nothing. Fix the model before writing any implementation: tighten Bob's check until the honest run passes and the attacker has no substitution that survives it.

- [ ] **Step 3: Implement the goal-discharge branch**

First, give `Deducer` access to the index. It currently takes `ps: &PrincipalState` in `new` (`src/solve/deduce.rs:37`) but keeps only wire terms from it, so add a field to the struct at line 26:

```rust
pub(crate) struct Deducer<'a> {
	attacker: &'a AttackerState,
	capabilities: Arc<CapabilityIndex>,
	wire_terms: Vec<Value>,
	memo: RefCell<HashMap<u64, Vec<Substitution>>>,
	active: RefCell<Vec<u64>>,
	cycles_cut: Cell<usize>,
	basis: HashSet<u64>,
	fresh: Cell<u32>,
}
```

and `capabilities: ps.capabilities.clone(),` to the `Deducer { … }` literal at the foot of `new`.

Then add the strategy. Strategies are methods on `Deducer` that push into `out`, dispatched from `solve_rules` (`src/solve/deduce.rs:144`); follow `solve_by_wire`'s shape. Register the call in `solve_rules` **after** the primitive-by-arguments and decomposition strategies, so the cheap ordinary routes are tried first:

```rust
	/// The `malleable` capability: retarget a ciphertext the attacker already
	/// holds rather than building one from scratch.
	///
	/// This lives in the solver rather than the knowledge closure because
	/// forward enumeration is quadratic — every held instance crossed with
	/// every known plaintext — and malleability only pays off when the attacker
	/// injects, which is goal-directed by nature. The consequence is that a
	/// passive attacker never malleates. That is correct, not a gap: a passive
	/// attacker injects nothing.
	fn solve_by_malleation(&self, g: &Value, s: &Substitution, out: &mut Vec<Substitution>) {
		let Value::Primitive(goal_p) = g else {
			return;
		};
		if !self.capabilities.in_force(
			goal_p,
			Capability::Malleable,
			self.attacker.current_phase,
		) {
			return;
		}
		let Ok(spec) = primitive_get(goal_p.id) else {
			return;
		};
		if spec.malleable_vary.is_empty() {
			return;
		}
		for held in self.attacker.known.iter() {
			let Value::Primitive(held_p) = held else {
				continue;
			};
			if held_p.id != goal_p.id || held_p.arguments.len() != goal_p.arguments.len() {
				continue;
			}
			// Must agree on every argument the attacker cannot vary — the key.
			let agrees_elsewhere = goal_p.arguments.iter().enumerate().all(|(i, a)| {
				spec.malleable_vary.contains(&i)
					|| a.equivalent(&held_p.arguments[i], true)
			});
			if !agrees_elsewhere {
				continue;
			}
			// Must know both what it is replacing and what it substitutes in.
			let knows_both = spec.malleable_vary.iter().all(|&i| {
				self.attacker.knows(&held_p.arguments[i]).is_some()
					&& self.attacker.knows(&goal_p.arguments[i]).is_some()
			});
			if !knows_both {
				continue;
			}
			out.push(s.clone());
			return;
		}
	}
```

`out.push(s.clone())` is the same "goal discharged, no new bindings" move `solve_rules` makes at line 145 for an already-known goal — the malleated term needs no variable bound, because every argument is either shared with the held instance or already known.

Memoisation needs no change: `solve_into` memoises on `goal_key(&g)`, which already tags primitive-vs-constant, and this strategy is reached through the same path. Do not touch `goal_key` — it **must** keep its kind tag, or a primitive and a constant sharing a hash collide silently.

Note there are already methods named `solve_forgeable` (line 380) and `forgeable_shapes` (line 384) in this file. They predate this feature and are about attacker-constructible shapes generally — they are unrelated to `Capability::Forgeable` and must not be conflated with it.

`solve/validate.rs::is_worthwhile` needs no change: a malleation that reproduces the honest plaintext reduces back to the honest value and is already rejected as a replay.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --release model_tests::test_cap_malleable_enc`
Expected: PASS.

- [ ] **Step 5: Read the attack trace and confirm**

```bash
cargo run --release -- verify examples/test/cap_malleable_enc.vp
VERIFPAL_SOLVE_DEBUG=1 cargo run --release -- verify examples/test/cap_malleable_enc.vp 2>&1 | head -40
```

Confirm the trace shows the attacker retargeting `c` and that `confidentiality? k` still holds. If `k` leaks, malleable has been implemented as `weak`.

- [ ] **Step 6: Run the full suite and check performance**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test --release`
Expected: PASS, no pre-existing result code changes.

Then confirm the solver hasn't slowed down on the models that stress it:

```bash
time cargo run --release -- verify examples/transport-layer/tls13.vp --result-code | tail -1
```

Expected: still ~1.4s. The `buckets.is_empty()` fast path should make this exactly a no-op for unannotated models. Do **not** run `examples/transport-layer/needham-schroeder.vp` — it does not complete, and that is a pre-existing property of the model.

- [ ] **Step 7: Commit**

```bash
git add src/solve/deduce.rs src/model_tests.rs examples/test/cap_malleable_enc.vp
git commit -m "solve: implement the malleable capability as a goal-discharge strategy"
```

---

### Task 7: Reporting

An attack that exists only under a declared assumption must say so, or the trace reads as unconditional.

**Files:**
- Modify: `src/info.rs` (summary line), `src/narrate.rs` (assumptions in the trace), `src/json.rs` (`internal-json` payload), `src/verify.rs:118` area (thread the index to `verify_end`)
- Test: `src/model_tests.rs` is unchanged; verification is by reading output plus one JSON unit test

**Interfaces:**
- Consumes: `CapabilityIndex::assumptions()` (Task 3).
- Produces: nothing other tasks consume.

- [ ] **Step 1: Write the failing JSON test**

Add to the test module at the foot of `src/json.rs`:

```rust
#[test]
fn internal_json_reports_declared_assumptions() {
	let out = handle_verify(
		"attacker[passive]\nprincipal Alice[\n\tknows private jcap_m\n\tjcap_h = HASH[weak](jcap_m)\n]\nAlice -> Bob: jcap_h\nprincipal Bob[\n\t_ = HASH(jcap_h)\n]\nqueries[\n\tconfidentiality? jcap_m\n]\n",
	)
	.expect("verifies");
	assert!(
		out.contains("\"assumptions\""),
		"payload must carry declared assumptions: {}",
		out
	);
	assert!(out.contains("weak"), "payload must name the capability: {}", out);
}
```

`handle_verify(input: &str) -> VResult<String>` is the private function `handle_internal_json` dispatches `"verify"` to (`src/json.rs:181`); the test module is inside `json.rs` and uses `super::*`, so it is directly reachable. The existing test `json::tests::phase_notes_name_a_participant` (line 203) is the pattern to follow.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --release json::tests::internal_json_reports_declared_assumptions`
Expected: FAIL — no `assumptions` key.

- [ ] **Step 3: Add the summary line**

In `src/info.rs`, add a message emitted by `verify_end` when the index is non-empty, before the per-query results:

```
Verifpal • Analysis performed under 2 declared weakening assumptions:
        HASH(m, n) — weak
        AEAD_ENC(k, m_later, nil) — weak from phase 2
```

It must print even when every query holds. A clean result under a stated assumption is not a clean result, and this line is the only thing preventing that confusion. Route it through `info.rs` like every other user-facing message so it is buffered correctly under wasm, and make sure it respects `InfoQuiet` so the minimizer's hypothetical re-runs stay silent.

- [ ] **Step 4: Add assumptions to the attack trace**

In `src/narrate.rs`, have `narrate_attack` list the assumptions the narrated steps actually rest on, gathered from **two** sources:

1. the capability in every `DerivationRecord::Broken` entry the trace walks — this covers `weak` and `forgeable`, which add attacker *knowledge*;
2. any annotated term in the `CapabilityIndex` that appears in the witness's mutations — this covers `malleable`, which produces a substitution rather than a derivation and would otherwise go unmentioned. Task 6's `solve_by_malleation` discharges its goal with no new bindings, so there is no `Broken` record to find.

Render them through `NameTable` so the terms use the same slot vocabulary as the surrounding steps.

Fall back to naming nothing rather than naming everything: the model-wide list already prints in the summary line from Step 3, and repeating it here would tell the reader an assumption was load-bearing when it was not.

- [ ] **Step 5: Add assumptions to the JSON payload**

In `src/json.rs`, add an `assumptions` array to the `verify` payload, one object per `(term, capability, onset)` from `CapabilityIndex::assumptions()`:

```json
"assumptions": [
  { "term": "HASH(m, n)", "capability": "weak", "fromPhase": 0 }
]
```

The result code string is untouched.

- [ ] **Step 6: Run the test to verify it passes**

Run: `cargo test --release json::tests::internal_json_reports_declared_assumptions`
Expected: PASS.

- [ ] **Step 7: Read the output of every capability model**

```bash
for f in examples/test/cap_weak_hash.vp examples/test/cap_weak_pubkey_dh.vp examples/test/cap_weak_phase_delayed.vp examples/test/cap_forgeable_sign.vp examples/test/cap_forgeable_aead.vp examples/test/cap_malleable_enc.vp; do
	echo "=== $f"
	cargo run --release -- verify "$f"
done
```

Confirm every one names its assumptions, and that `cap_weak_phase_delayed.vp` — where one query holds and one fails — still prints the summary line.

- [ ] **Step 8: Run the full suite**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test --release`
Expected: PASS. Confirm no unparametrized model gained a summary line.

- [ ] **Step 9: Commit**

```bash
git add src/info.rs src/narrate.rs src/json.rs src/verify.rs
git commit -m "info: report declared weakening assumptions in results and traces"
```

---

### Task 8: Bit-for-bit regression, golden file, and documentation

The task that pins the central claim: an annotation that grants nothing must change nothing.

**Files:**
- Create: `examples/test/cap_noop_annotated.vp`, `examples/test/golden_pretty/cap_parameters.vp` (+ its expected output file, following the existing golden pair convention)
- Modify: `src/model_tests.rs`, `src/pretty.rs` (golden test registration), `CLAUDE.md`
- Check: `../verifpal-vscode`

**Interfaces:**
- Consumes: everything.
- Produces: nothing.

- [ ] **Step 1: Create the no-op regression model**

Take an existing passing model — `examples/test/hmac_ok.vp` (`c0a0`) — and copy it to `examples/test/cap_noop_annotated.vp`, adding a capability whose onset phase the model never reaches, so it parses and validates but grants nothing:

```verifpal
// SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
// SPDX-License-Identifier: GPL-3.0-only
//
// Expected: c0a0 — identical to hmac_ok.vp.
//
// This model exists to pin the central claim of the capability feature: an
// annotation the engine never puts in force changes nothing. The MAC is
// declared forgeable from phase 1, and phase 1 exists but carries no traffic,
// so every query resolves exactly as it does in hmac_ok.vp. If this code ever
// diverges from that model's, capabilities have leaked into term identity,
// hashing, or equivalence.
```

with the body of `hmac_ok.vp`, one `MAC(...)` changed to `MAC[forgeable from phase 1](...)`, and a `phase[1]` block added after all traffic. Verify by hand that no query can be affected by a phase-1 capability.

- [ ] **Step 2: Add the regression test**

```rust
#[test]
fn test_cap_noop_annotated() {
	run_model("cap_noop_annotated.vp", "c0a0");
}
```

- [ ] **Step 3: Run it**

Run: `cargo test --release model_tests::test_cap_noop_annotated`
Expected: PASS. If it fails, do not adjust the expected code — find out what the annotation changed.

- [ ] **Step 4: Add the golden pretty-printer file**

Create `examples/test/golden_pretty/cap_parameters.vp` exercising every form: a bare capability, a phase-delayed one, two capabilities in one list, and a nested annotated primitive. Follow the existing golden pair convention in that directory exactly — look at the five existing ones first and match how input and expected output are stored and compared via `include_str!`.

Generate the expected output with `cargo run --release -- pretty examples/test/golden_pretty/cap_parameters.vp` and **read it** before saving: the golden file is only as good as the eyes on it. Confirm capability lists print with `, ` separators and that `from phase 0` is elided.

- [ ] **Step 5: Register and run the golden test**

Run: `cargo test --release pretty::`
Expected: PASS.

- [ ] **Step 6: Update `CLAUDE.md`**

Three edits:

1. In "The Verifpal language", add the parameter syntax to the sample model and a line to the constraints list: capability parameters are validated against the spec at load time, and `weak`/`forgeable`/`malleable`/`from` are contextual keywords deliberately absent from `RESERVED`.
2. In "Architecture", add `src/capability.rs` to the supporting-modules paragraph, and note under the core data model that `Primitive.capabilities` is **not** consulted by `primitive_hash`, `equivalent_primitives`, or `structurally_identical_primitive`, and that the engine reads capabilities from the `CapabilityIndex` on `PrincipalState` instead — with the reason (attacker dedup would otherwise make the annotation order-dependent).
3. Update the test count in "Commands" from 322 to the new total.

- [ ] **Step 7: Note the VS Code extension**

The `internal-json` payload gained an `assumptions` array in Task 7. `../verifpal-vscode` must be updated by hand; nothing checks it. Record this in the commit message so it is not lost. Do not edit that repository as part of this plan.

- [ ] **Step 8: Full verification**

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --release
cargo check --lib --no-default-features --features wasm
```

Expected: all PASS. The wasm check matters — `info.rs` gained a message path in Task 7 and must still build for `wasm32-unknown-unknown`.

- [ ] **Step 9: Commit**

```bash
git add examples/test/cap_noop_annotated.vp examples/test/golden_pretty/ src/model_tests.rs src/pretty.rs CLAUDE.md
git commit -m "tests: pin capability no-op regression and document the feature

The internal-json payload gained an \"assumptions\" array; ../verifpal-vscode
needs a matching update by hand."
```

---

## Verification checklist

Run before considering the feature complete:

- [ ] `cargo fmt --check` clean
- [ ] `cargo clippy --all-targets -- -D warnings` clean
- [ ] `cargo test --release` — all pass, count is 322 + the new tests
- [ ] `cargo check --lib --no-default-features --features wasm` clean
- [ ] Every pre-existing model's result code is unchanged (`git diff` on `src/model_tests.rs` shows only additions)
- [ ] `examples/transport-layer/tls13.vp` still completes in ~1.4s
- [ ] The four false-attack regression models still hold: `auth_with_signing_false-attack.vp` `c0a1a0`, `concat_split_replay.vp` `a0`, `wire_projection_replay.vp` `a0`, `aead_replay_not_forgery.vp` `a0c0`, and `examples/transport-layer/piknik.vp` `c0a0a0a0f0`
- [ ] Every attack trace produced by a capability model has been read, and each 0/1 confirmed by reasoning rather than by trusting the tool
