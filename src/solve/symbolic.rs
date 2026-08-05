/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # The symbolic view of a principal
//!
//! Before the solver can ask "what would the attacker have to send here", it
//! needs the principal's computation expressed in terms of the attacker's
//! choices rather than the honest values.  This module produces that view: for
//! each slot, the term the principal computes, with every attacker-controllable
//! wire slot replaced by a variable.
//!
//! ## Why this does not reuse `resolve_all_values`
//!
//! [`crate::resolution`] errors out on any constant missing from the principal's
//! index (`VerifpalError::resolution("invalid index")`), so attacker variables
//! cannot simply be dropped into slots and resolved.  Rather than bend the
//! state representation to accommodate them, the inlining is mirrored here over
//! the same slot data.
//!
//! That leaves a deliberate approximation.  This resolver does not reproduce
//! `compute_visibility`, the rule deciding whether a nested constant is seen as
//! `original` or as the possibly-tampered `value`.  It always inlines the
//! principal's own computation, which is what determines the *shape* of the
//! term and therefore what the attacker must supply.
//!
//! The approximation is safe because of where it sits.  Nothing here decides a
//! verdict; it only proposes substitutions, and `validate.rs` re-executes each
//! proposal through the real pipeline before any attack is reported.  An
//! imprecise symbolic view costs a wasted validation, never a wrong answer.
//!
//! ## Variable shapes
//!
//! A wire slot does not get an opaque variable if its honest value is a DH
//! public key.  `gbs = G^bs` becomes `G^$gbs` — the attacker's own public key
//! with an unknown exponent — rather than a bare `$gbs`.  This matters for two
//! reasons.  Equations must keep `G` in base position (`sanity.rs` enforces it,
//! and `can_reconstruct_equation` indexes exponents positionally), and it
//! encodes the fact that the only useful thing to send in a DH public position
//! *is* a group element the attacker knows the exponent of.  The MitM shape
//! falls out of the representation instead of being searched for.

use std::sync::Arc;

use crate::equivalence::splice_equation;
use crate::theory::can_rewrite;
use crate::types::*;
use crate::value::value_g;

use super::vars::attacker_var;

/// A principal's computation expressed over attacker variables.
pub(crate) struct SymbolicState {
	/// Symbolic term per slot, parallel to `ps.values`.
	pub terms: Vec<Value>,
	/// Slots the attacker controls in the current phase.
	pub var_slots: Vec<usize>,
	/// Per slot, the variable term substituted for it (`None` if not controlled).
	pub var_terms: Vec<Option<Value>>,
}

impl SymbolicState {
	pub(crate) fn is_var_slot(&self, slot: usize) -> bool {
		self.var_terms.get(slot).is_some_and(|t| t.is_some())
	}
}

/// Whether the attacker may replace slot `idx` in this principal's state.
///
/// The phase clause is what preserves phase semantics: a slot carrying a
/// message from an earlier phase is not controllable now, so the attacker
/// cannot retroactively tamper with it.
pub(crate) fn is_mutable_slot(
	idx: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> bool {
	let meta = &ps.meta[idx];
	// `g` and `nil` are the term algebra's fixed points, not messages.
	// Substituting either would rewrite the meaning of every equation in the
	// model rather than model an attacker action.
	if meta.constant.is_g_or_nil() {
		return false;
	}
	if meta.guard {
		if !meta
			.mutatable_to
			.contains(&ps.values[idx].provenance.sender)
		{
			return false;
		}
	} else if ps.values[idx].provenance.creator == ps.id || meta.wire.is_empty() {
		// Creating the value is not the only way to hold it off the network:
		// `knows private k` declared by two principals is one trace slot with one
		// creator, so the *other* principal's copy has a foreign creator while
		// still never having been transmitted.  The attacker cannot reach what
		// never crossed a wire, so the test is whether the value travelled at
		// all, not who made it.
		//
		// It is deliberately not "did *this* principal receive it": a value can
		// be substituted on a wire it travels earlier and still reach a later
		// principal that never received it directly, which is exactly the
		// oracle in `exa.vp`.
		//
		// Getting this wrong hides real attacks as well as inventing ones. A
		// recipient's own key admitted as controllable enters the symbolic term
		// as `$k`, so the shape its rewrite rule demands becomes `ENC($k, ...)`
		// instead of `ENC(k, ...)`, and the forgery that key would unlock is
		// never proposed.
		return false;
	}
	if !meta.phase.contains(&attacker.current_phase) {
		return false;
	}
	if !km.constant_used_by(ps.id, &meta.constant) {
		return false;
	}
	true
}

fn shaped_var(slot: usize, honest: &Value, name: &str) -> Value {
	match honest {
		Value::Equation(_) => Value::Equation(Arc::new(Equation {
			values: vec![value_g(), attacker_var(slot, name)],
		})),
		_ => attacker_var(slot, name),
	}
}

pub(crate) fn build(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> SymbolicState {
	let n = ps.values.len();
	let mut var_terms: Vec<Option<Value>> = vec![None; n];
	let mut var_slots = Vec::new();

	for (idx, slot) in var_terms.iter_mut().enumerate() {
		if !is_mutable_slot(idx, km, ps, attacker) {
			continue;
		}
		let name = &ps.meta[idx].constant.name;
		*slot = Some(shaped_var(idx, &ps.values[idx].value, name));
		var_slots.push(idx);
	}

	// Terms are memoised per slot.  Without this, a slot referenced from several
	// places is expanded afresh each time, and a chain of such references is
	// expanded exponentially — which on a model whose messages nest ciphertexts
	// a few levels deep is the difference between microseconds and minutes.
	let mut memo: Vec<Option<Value>> = vec![None; n];
	let mut building: Vec<bool> = vec![false; n];
	let mut terms: Vec<Value> = Vec::with_capacity(n);
	for idx in 0..n {
		terms.push(slot_term(idx, ps, &var_terms, &mut memo, &mut building));
	}

	SymbolicState {
		terms,
		var_slots,
		var_terms,
	}
}

/// Reduce a term the way `perform_all_rewrites` would.
///
/// Inlining alone leaves `AEAD_DEC(k, AEAD_ENC(k, x, ad), ad)` standing, but the
/// principal computes `x`, and so does every comparison the attacker's knowledge
/// is tested against.  Without this step symbolic terms are shaped differently
/// from the real ones and match nothing.
///
/// `can_rewrite` reads no slots — it threads the state only for recursion — so
/// it is safe to apply to a term containing attacker variables.
fn reduce(v: &Value, ps: &PrincipalState) -> Value {
	match v {
		Value::Primitive(p) => {
			let (_, reduced) = can_rewrite(p, ps, 0);
			reduced
		}
		_ => v.clone(),
	}
}

/// The symbolic term for one slot, computed once and reused.
///
/// `building` guards a slot whose definition reaches itself; such a slot is its
/// own base case (a `knows` or `generates` declaration) and expanding it again
/// would not terminate.
fn slot_term(
	idx: usize,
	ps: &PrincipalState,
	var_terms: &[Option<Value>],
	memo: &mut Vec<Option<Value>>,
	building: &mut Vec<bool>,
) -> Value {
	if let Some(cached) = &memo[idx] {
		return cached.clone();
	}
	if let Some(var) = &var_terms[idx] {
		let v = var.clone();
		memo[idx] = Some(v.clone());
		return v;
	}
	if building[idx] {
		return ps.values[idx].value.clone();
	}

	// Whose computation this is.  A value another principal produced was
	// produced from what *that* principal held at the time.
	let owner = ps.values[idx].provenance.creator;
	building[idx] = true;
	let inlined = inline(&ps.values[idx].value, ps, var_terms, owner, memo, building);
	building[idx] = false;

	let reduced = reduce(&inlined, ps);
	memo[idx] = Some(reduced.clone());
	reduced
}

/// Whether the attacker's choice for slot `idx` reaches a computation performed
/// by `owner`.
///
/// This is `resolution.rs::compute_visibility`'s rule. A value the attacker can
/// replace *en route to* `owner` does influence what `owner` computes; one it
/// can only replace later does not. Ignoring the distinction would let a
/// signature made by one principal appear to cover whatever the attacker hands
/// to another, and the solver would then "obtain" forgeries by binding that
/// variable — while collapsing it the other way loses every attack that works
/// by tampering before an intermediate principal acts.
fn reaches(ps: &PrincipalState, idx: usize, owner: PrincipalId) -> bool {
	owner == ps.id || ps.meta[idx].mutatable_to.contains(&owner)
}

/// Inline constant references, substituting variables for controlled slots.
fn inline(
	v: &Value,
	ps: &PrincipalState,
	var_terms: &[Option<Value>],
	owner: PrincipalId,
	memo: &mut Vec<Option<Value>>,
	building: &mut Vec<bool>,
) -> Value {
	match v {
		Value::Constant(c) => match ps.index_of(c) {
			Some(idx) => {
				if var_terms[idx].is_some() && !reaches(ps, idx, owner) {
					// Controlled, but not on a path into this computation:
					// resolve it honestly instead.
					if building[idx] {
						return v.clone();
					}
					building[idx] = true;
					let honest =
						inline(&ps.values[idx].value, ps, var_terms, owner, memo, building);
					building[idx] = false;
					return reduce(&honest, ps);
				}
				slot_term(idx, ps, var_terms, memo, building)
			}
			None => v.clone(),
		},
		Value::Primitive(p) => {
			let args: Vec<Value> = p
				.arguments
				.iter()
				.map(|a| inline(a, ps, var_terms, owner, memo, building))
				.collect();
			Value::Primitive(Arc::new(p.with_arguments(args)))
		}
		Value::Equation(e) => Value::Equation(Arc::new(splice_equation(
			e.values
				.iter()
				.map(|item| inline(item, ps, var_terms, owner, memo, building)),
		))),
	}
}
