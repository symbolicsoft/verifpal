/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Unified Equational Theory
//!
//! This module centralizes Verifpal's equational theory — the complete set of
//! rules governing what the attacker can derive and how symbolic values reduce.
//! All derivation, reduction, and reconstruction operations are defined here,
//! driven by the declarative [`PrimitiveSpec`] system in `primitive/spec.rs`.
//!
//! ## Complete rule set
//!
//! ```text
//! DEC(k, ENC(k, m)) → m                                    [given: k]
//! AEAD_DEC(k, AEAD_ENC(k, m, ad), ad) → m                  [given: k, ad]
//! AEAD_ENC(k, m, ad) → ad                                   [passive]
//! ENC(k, m) → m                                             [given: k]
//! BLIND(factor, m) → m                                      [given: factor]
//! PKE_DEC(sk, PKE_ENC(G^sk, m)) → m                         [given: sk]
//! PKE_ENC(G^sk, m) → m                                      [given: sk (via G^sk)]
//! SIGNVERIF(G^sk, msg, SIGN(sk, msg)) → nil                 [rewrite: def check]
//! RINGSIGNVERIF(G^sk, ..., RINGSIGN(sk, ...)) → nil         [rewrite: def check]
//! UNBLIND(factor, SIGN(sk, BLIND(factor, m)), m) → SIGN(sk, m) [rewrite]
//! SHAMIR_SPLIT(s)[i] + SHAMIR_SPLIT(s)[j] → s               [recompose: 2-of-3]
//! SHAMIR_JOIN(SHAMIR_SPLIT(s)[i], SHAMIR_SPLIT(s)[j]) → s   [rebuild]
//! CONCAT(a, b, ...) → a, b, ...                             [passive: reveals args]
//! G^a^b = G^b^a                                              [DH commutativity]
//! ```
//!
//! ## Derivation kinds
//!
//! The attacker can derive new values through six operations:
//!
//! - **Decompose** — open a primitive given knowledge of its key arguments
//! - **Passive reveal** — extract always-visible arguments (e.g., AEAD associated data)
//! - **Recompose** — combine threshold shares to recover a secret
//! - **Reconstruct** — build a value from individually known components
//! - **Symbolic rewrite** — reduce paired primitives (encrypt/decrypt)
//! - **Rebuild** — eagerly join matching sub-values
//!
//! ## Adding a new primitive
//!
//! To extend the equational theory, add a [`PrimitiveSpec`] entry in
//! `primitive/spec.rs`. The rule engine picks it up automatically — no other
//! files need changes.

use std::sync::Arc;

use crate::equivalence::equivalent_primitives;
use crate::primitive::*;
use crate::types::*;

/// Maximum recursion depth for derivation operations.
const MAX_DEPTH: usize = 16;

// ---------------------------------------------------------------------------
// Decomposition: "attacker knows the key → learns the plaintext"
// ---------------------------------------------------------------------------

/// Passively decompose a primitive: extract arguments that are always visible
/// to the attacker without any key knowledge (e.g., associated data in AEAD_ENC).
pub fn passively_decompose(p: &Primitive) -> Vec<Value> {
	if primitive_is_core(p.id) {
		return vec![];
	}
	let Ok(prim) = primitive_get(p.id) else {
		return vec![];
	};
	if !prim.decompose.has_rule {
		return vec![];
	}
	prim.decompose
		.passive_reveal
		.iter()
		.filter_map(|&i| p.arguments.get(i).cloned())
		.collect()
}

/// Actively decompose a primitive: if the attacker knows the required "given"
/// arguments (e.g., the encryption key), reveal the hidden argument (e.g., the
/// plaintext).
///
/// The attacker may obtain the given arguments directly (already in their
/// knowledge set) or indirectly (by reconstructing or decomposing nested values).
pub fn can_decompose(
	p: &Primitive,
	ps: &PrincipalState,
	attacker: &AttackerState,
	depth: usize,
) -> Option<DecomposeResult> {
	if depth > MAX_DEPTH || primitive_is_core(p.id) {
		return None;
	}
	let Ok(prim) = primitive_get(p.id) else {
		return None;
	};
	if !prim.decompose.has_rule {
		return None;
	}
	let filter_fn = prim.decompose.filter?;
	let mut has = Vec::new();
	for (filter_i, &idx) in prim.decompose.given.iter().enumerate() {
		if idx >= p.arguments.len() {
			continue;
		}
		let a = &p.arguments[idx];
		let (filtered, valid) = filter_fn(p, a, filter_i);
		if !valid {
			continue;
		}
		if attacker.knows(&filtered).is_some() {
			has.push(filtered);
			continue;
		}
		match &filtered {
			Value::Primitive(inner_p) => {
				if can_reconstruct_primitive(inner_p, ps, attacker, depth + 1).is_some() {
					has.push(filtered.clone());
					continue;
				}
				if can_decompose(inner_p, ps, attacker, depth + 1).is_some() {
					has.push(filtered.clone());
				}
			}
			Value::Equation(inner_e) => {
				if can_reconstruct_equation(inner_e, attacker).is_some() {
					has.push(filtered.clone());
				}
			}
			_ => {}
		}
	}
	if has.len() >= prim.decompose.given.len() {
		Some(DecomposeResult {
			revealed: p.arguments[prim.decompose.reveal].clone(),
			used: has,
		})
	} else {
		None
	}
}

// ---------------------------------------------------------------------------
// Recomposition: "attacker has enough threshold shares → recovers secret"
// ---------------------------------------------------------------------------

/// Check if the attacker can recompose a secret from threshold shares.
///
/// For primitives like SHAMIR_SPLIT that produce multiple outputs, the attacker
/// can recover the original input if they possess enough shares (as specified
/// by the recompose rule's `given` sets).
pub fn can_recompose(p: &Primitive, attacker: &AttackerState) -> Option<RecomposeResult> {
	if primitive_is_core(p.id) {
		return None;
	}
	let Ok(prim) = primitive_get(p.id) else {
		return None;
	};
	if !prim.recompose.has_rule {
		return None;
	}
	for given_set in &prim.recompose.given {
		let mut candidates = Vec::new();
		for &output_idx in given_set {
			for known in attacker.known.iter() {
				if let Value::Primitive(known_prim) = known {
					let pm = equivalent_primitives(known_prim, p, false);
					if !pm.equivalent || pm.output_left != output_idx {
						continue;
					}
					candidates.push(known.clone());
					if candidates.len() < given_set.len() {
						continue;
					}
					return Some(RecomposeResult {
						revealed: p.arguments[prim.recompose.reveal].clone(),
						used: candidates,
					});
				}
			}
		}
	}
	None
}

// ---------------------------------------------------------------------------
// Reconstruction: "attacker knows all components → can build the value"
// ---------------------------------------------------------------------------

/// Check if the attacker can reconstruct a primitive from individually known
/// components. First rewrites the primitive symbolically, then checks if every
/// argument of the rewritten form is attacker-obtainable.
pub fn can_reconstruct_primitive(
	p: &Primitive,
	ps: &PrincipalState,
	attacker: &AttackerState,
	depth: usize,
) -> Option<Vec<Value>> {
	if depth > MAX_DEPTH {
		return None;
	}
	let (rewritten, rewrite_values) = can_rewrite(p, ps, 0);
	if !rewritten {
		return None;
	}
	let Value::Primitive(rewritten_prim) = &rewrite_values[0] else {
		return None;
	};
	let mut has = Vec::new();
	for a in &rewritten_prim.arguments {
		if attacker.knows(a).is_some() {
			has.push(a.clone());
			continue;
		}
		match a {
			Value::Primitive(inner_p) => {
				if can_decompose(inner_p, ps, attacker, depth + 1).is_some() {
					has.push(a.clone());
					continue;
				}
				if can_reconstruct_primitive(inner_p, ps, attacker, depth + 1).is_some() {
					has.push(a.clone());
					continue;
				}
			}
			Value::Equation(inner_e) => {
				if can_reconstruct_equation(inner_e, attacker).is_some() {
					has.push(a.clone());
					continue;
				}
			}
			_ => {}
		}
	}
	if has.len() < rewritten_prim.arguments.len() {
		return None;
	}
	Some(has)
}

/// Check if the attacker can reconstruct a DH equation from known components.
///
/// Equations model Diffie-Hellman exponentiation chains: `G^a^b` is `[G, a, b]`.
/// The DH commutativity rule `G^a^b = G^b^a` means that knowing `a` and `G^b`
/// (or `b` and `G^a`) suffices to construct `G^a^b`.
///
/// For a 2-element equation `G^a`, the attacker needs to know `a`.
/// For a 3-element equation `G^a^b`, the attacker needs either:
///   - Both exponents `a` and `b`, or
///   - One exponent and the partial equation (e.g., `a` and `G^b`)
pub fn can_reconstruct_equation(e: &Equation, attacker: &AttackerState) -> Option<Vec<Value>> {
	if e.values.len() < 2 {
		return None;
	}
	if e.values.len() == 2 {
		if attacker.knows(&e.values[1]).is_some() {
			return Some(vec![e.values[1].clone()]);
		}
		return None;
	}
	let s0 = &e.values[1];
	let s1 = &e.values[2];
	let hs0 = attacker.knows(s0).is_some();
	let hs1 = attacker.knows(s1).is_some();
	if hs0 && hs1 {
		return Some(vec![s0.clone(), s1.clone()]);
	}
	let p0 = Value::Equation(Arc::new(Equation {
		values: vec![e.values[0].clone(), e.values[1].clone()],
	}));
	let p1 = Value::Equation(Arc::new(Equation {
		values: vec![e.values[0].clone(), e.values[2].clone()],
	}));
	let hp1 = attacker.knows(&p1).is_some();
	if hs0 && hp1 {
		return Some(vec![s0.clone(), p1]);
	}
	let hp0 = attacker.knows(&p0).is_some();
	if hp0 && hs1 {
		return Some(vec![p0, s1.clone()]);
	}
	None
}

// ---------------------------------------------------------------------------
// Symbolic rewrite: "DEC(k, ENC(k, m)) → m"
// ---------------------------------------------------------------------------

/// Symbolically rewrite a primitive by checking if its arguments match the
/// rewrite rule's pattern. Recursively rewrites child primitives first.
///
/// Returns `(success, result_values)` where `success` is false if a checked
/// primitive's rewrite rule failed (indicating a protocol error).
pub fn can_rewrite(p: &Primitive, ps: &PrincipalState, depth: usize) -> (bool, Vec<Value>) {
	if depth > MAX_DEPTH {
		return (false, vec![Value::Primitive(Arc::new(p.clone()))]);
	}
	// COW: only clone arguments if a child rewrite actually changed something
	let mut new_args: Option<Vec<Value>> = None;
	for (i, a) in p.arguments.iter().enumerate() {
		if let Value::Primitive(inner_p) = a {
			let (_, pp) = can_rewrite(inner_p, ps, depth + 1);
			if !pp[0].equivalent(a, true) {
				let args = new_args.get_or_insert_with(|| p.arguments.clone());
				args[i] = pp[0].clone();
			}
		}
	}
	// pc_ref points to either the original or the modified primitive
	let pc_owned: Primitive;
	let pc_ref: &Primitive;
	if let Some(args) = new_args {
		pc_owned = p.with_arguments(args);
		pc_ref = &pc_owned;
	} else {
		pc_ref = p;
	}
	let wrap = |pr: &Primitive| vec![Value::Primitive(Arc::new(pr.clone()))];
	if primitive_is_core(pc_ref.id) {
		let prim = match primitive_core_get(pc_ref.id) {
			Ok(s) => s,
			Err(_) => return (false, wrap(pc_ref)),
		};
		if prim.has_rule {
			if let Some(rule) = prim.core_rule {
				return rule(pc_ref);
			}
		}
		return (!prim.definition_check, wrap(pc_ref));
	}
	let prim = match primitive_get(pc_ref.id) {
		Ok(s) => s,
		Err(_) => return (false, wrap(pc_ref)),
	};
	if !prim.rewrite.has_rule {
		return (true, wrap(pc_ref));
	}
	let from = &pc_ref.arguments[prim.rewrite.from];
	if let Value::Primitive(from_p) = from {
		if from_p.id != prim.rewrite.id {
			return (!prim.definition_check, wrap(pc_ref));
		}
		if !can_rewrite_primitive(pc_ref, ps, depth) {
			return (!prim.definition_check, wrap(pc_ref));
		}
		if let Some(to_fn) = prim.rewrite.to {
			let rewrite = to_fn(from_p);
			return (true, vec![rewrite]);
		}
	}
	(!prim.definition_check, wrap(pc_ref))
}

/// Internal: check if a primitive's rewrite rule's matching constraints are
/// satisfied. Each constraint requires that an argument of the outer primitive
/// matches (after filtering) an argument of the inner primitive.
fn can_rewrite_primitive(p: &Primitive, ps: &PrincipalState, depth: usize) -> bool {
	let Ok(prim) = primitive_get(p.id) else {
		return false;
	};
	let from = &p.arguments[prim.rewrite.from];
	let Value::Primitive(from_p) = from else {
		return false;
	};
	let Some(filter_fn) = prim.rewrite.filter else {
		return false;
	};
	for &(a_idx, ref m_vec) in &prim.rewrite.matching {
		let mut valid = false;
		for &mm in m_vec {
			if a_idx >= p.arguments.len() || mm >= from_p.arguments.len() {
				continue;
			}
			let mut ax = [p.arguments[a_idx].clone(), from_p.arguments[mm].clone()];
			let (filtered, fvalid) = filter_fn(p, &ax[0], mm);
			if !fvalid {
				continue;
			}
			ax[0] = filtered;
			// Rewrite primitives in ax
			for item in &mut ax {
				let replacement = match &*item {
					Value::Primitive(inner_p) => {
						let (r, v) = can_rewrite(inner_p, ps, depth + 1);
						if r {
							v.into_iter().next()
						} else {
							None
						}
					}
					Value::Equation(inner_e) => {
						let mut new_values: Option<Vec<Value>> = None;
						for (ii, ev) in inner_e.values.iter().enumerate() {
							if let Value::Primitive(ep) = ev {
								let (r, v) = can_rewrite(ep, ps, depth + 1);
								if r {
									let vals =
										new_values.get_or_insert_with(|| inner_e.values.clone());
									vals[ii] = v[0].clone();
								}
							}
						}
						new_values.map(|vals| Value::Equation(Arc::new(Equation { values: vals })))
					}
					_ => None,
				};
				if let Some(new_val) = replacement {
					*item = new_val;
				}
			}
			valid = ax[0].equivalent(&ax[1], true);
			if valid {
				break;
			}
		}
		if !valid {
			return false;
		}
	}
	true
}

// ---------------------------------------------------------------------------
// Rebuild: "SHAMIR_JOIN(split[0], split[1]) → secret"
// ---------------------------------------------------------------------------

/// Check if a primitive can be eagerly rebuilt from matching sub-values.
///
/// Used during symbolic rewriting (not attacker deduction): when two arguments
/// of a join primitive (e.g., SHAMIR_JOIN) are shares from the same split
/// (e.g., SHAMIR_SPLIT), the join is immediately resolved.
pub fn can_rebuild(p: &Primitive) -> Option<Value> {
	if primitive_is_core(p.id) {
		return None;
	}
	let prim = primitive_get(p.id).ok()?;
	if !prim.rebuild.has_rule {
		return None;
	}
	for given_set in &prim.rebuild.given {
		let mut has = Vec::new();
		for &arg_idx in given_set {
			if arg_idx >= p.arguments.len() {
				continue;
			}
			if let Value::Primitive(arg_p) = &p.arguments[arg_idx] {
				if arg_p.id == prim.rebuild.id {
					has.push(&p.arguments[arg_idx]);
				}
			}
		}
		if has.len() < given_set.len() {
			continue;
		}
		// Check that all has entries are equivalent but with different outputs
		let all_ok = has[1..].iter().all(|has_p| {
			if let (Value::Primitive(h0), Value::Primitive(hp)) = (has[0], has_p) {
				let pm = equivalent_primitives(h0, hp, false);
				pm.equivalent && pm.output_left != pm.output_right
			} else {
				false
			}
		});
		if !all_ok {
			continue;
		}
		if let Value::Primitive(h0) = has[0] {
			return Some(h0.arguments[prim.rebuild.reveal].clone());
		}
	}
	None
}

// ---------------------------------------------------------------------------
// Password extraction
// ---------------------------------------------------------------------------

/// Find password-qualified values that appear in unhashed positions within
/// a value tree. These are passwords the attacker can attempt offline
/// guessing against.
///
/// The `password_hashing` field in [`PrimitiveSpec`] lists argument indices
/// where passwords are cryptographically protected. Passwords at other
/// indices are considered exposed.
pub fn find_obtainable_passwords(
	a: &Value,
	a_parent: &Value,
	a_index: Option<usize>,
	ps: &PrincipalState,
	out: &mut Vec<Value>,
) {
	match a {
		Value::Constant(c) => {
			let (resolved, _) = ps.resolve_constant(c, true);
			let is_password = matches!(&resolved, Value::Constant(rc) if rc.qualifier == Some(Qualifier::Password));
			if is_password {
				let is_hashed = a_index.is_some_and(|idx| {
					matches!(a_parent, Value::Primitive(pp) if !primitive_is_core(pp.id)
						&& primitive_get(pp.id).is_ok_and(|prim| prim.password_hashing.contains(&idx)))
				});
				if !is_hashed {
					out.push(resolved);
				}
			}
		}
		Value::Primitive(p) => {
			let is_hashing = !primitive_is_core(p.id)
				&& a_index.is_some_and(|idx| {
					primitive_get(p.id).is_ok_and(|prim| prim.password_hashing.contains(&idx))
				});
			let parent_owned;
			let parent = if is_hashing {
				parent_owned = a.clone();
				&parent_owned
			} else {
				a_parent
			};
			for (i, arg) in p.arguments.iter().enumerate() {
				find_obtainable_passwords(arg, parent, Some(i), ps, out);
			}
		}
		Value::Equation(e) => {
			for v in &e.values {
				find_obtainable_passwords(v, a, None, ps, out);
			}
		}
	}
}
