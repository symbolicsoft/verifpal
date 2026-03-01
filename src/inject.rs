/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::context::VerifyContext;
use crate::equivalence::equivalent_primitives;
use crate::info::info_message;
use crate::mutationmap::mutation_product;
use crate::types::*;
use crate::value::*;

/// Maximum number of injected value combinations per primitive.  The Cartesian
/// product of per-argument injectants can grow very fast (e.g. 3 args with
/// 50 candidates each = 125k).  500 is enough to cover the useful injection
/// space for real protocols while keeping the inner loop fast.
const MAX_INJECTIONS_PER_PRIMITIVE: usize = 500;


/// Generate all attacker-constructible values that could replace a given
/// primitive in a principal's state.
///
/// Rather than enumerating *all* possible combinations of attacker-known
/// values (which would be astronomically expensive), injection works by
/// filtering candidates per-argument based on structural compatibility:
///
/// - Constants can only replace constant arguments.
/// - Primitives can only replace primitive arguments with the same
///   **skeleton** (see below).
/// - Equations can only replace equations of the same length.
///
/// The results are combined via Cartesian product (capped at
/// `MAX_INJECTIONS_PER_PRIMITIVE`) to produce concrete replacement values.
///
/// ## Skeletons
///
/// A skeleton is the "shape" of a primitive with all secrets erased:
/// constants become `nil`, equations become `G` or `G^nil` depending on
/// length.  Two primitives with the same skeleton have the same structure
/// and could plausibly be interchanged.  This avoids injecting, say, an
/// `ENC(k, m)` where an `AEAD_ENC(k, m, ad)` is expected.
///
/// Skeleton comparison uses a three-step filter for speed:
/// 1. **Depth check** — O(1), no allocation.
/// 2. **Hash check** — O(n) FNV-style hash, no allocation.
/// 3. **Full equivalence** — only if depth and hash match.
pub fn inject(
	ctx: &VerifyContext,
	p: &Primitive,
	inject_depth: usize,
	ps: &PrincipalState,
	attacker: &AttackerState,
	depth: usize,
) -> Vec<Value> {
	if ctx.all_resolved() {
		return vec![];
	}
	inject_primitive(ctx, p, ps, attacker, inject_depth, depth)
}

fn inject_value_rules(value: &Value, arg: usize, p: &Primitive) -> bool {
	match value {
		Value::Constant(c) => inject_constant_rules(c, arg, p),
		Value::Primitive(prim) => inject_primitive_rules(prim, arg, p),
		Value::Equation(e) => inject_equation_rules(e, arg, p),
	}
}

fn inject_constant_rules(c: &Constant, arg: usize, p: &Primitive) -> bool {
	matches!(&p.arguments[arg], Value::Constant(_)) && c.id != 0
}

fn inject_primitive_rules(candidate: &Primitive, arg: usize, p: &Primitive) -> bool {
	let Value::Primitive(ref_p) = &p.arguments[arg] else {
		return false;
	};
	inject_skeleton_equivalent(candidate, ref_p)
}

fn inject_equation_rules(e: &Equation, arg: usize, p: &Primitive) -> bool {
	match &p.arguments[arg] {
		Value::Equation(pe) => e.values.len() == pe.values.len(),
		_ => false,
	}
}

/// Compute the skeleton of a primitive: a normalized form where all secret
/// values are replaced by canonical attacker-known surrogates.
///
/// - Constants → `nil` (the attacker's canonical known constant).
/// - Nested primitives → recursively skeletonized.
/// - Equations with 1 element → `G` (bare generator).
/// - Equations with 2+ elements → `G^nil` (attacker's canonical DH public key).
///
/// Returns the skeleton and the maximum nesting depth encountered.
fn inject_primitive_skeleton(p: &Primitive, depth: usize) -> (Primitive, usize) {
	let mut skeleton = Primitive {
		id: p.id,
		arguments: Vec::with_capacity(p.arguments.len()),
		output: p.output,
		instance_check: false,
	};
	let mut d = depth;
	for a in &p.arguments {
		match a {
			Value::Constant(_) => skeleton.arguments.push(value_nil()),
			Value::Primitive(pp) => {
				let (child, new_d) = inject_primitive_skeleton(pp, d + 1);
				d = new_d;
				skeleton.arguments.push(Value::Primitive(Arc::new(child)));
			}
			Value::Equation(e) => {
				if e.values.len() <= 1 {
					skeleton.arguments.push(value_g());
				} else {
					skeleton.arguments.push(value_g_nil());
				}
			}
		}
	}
	(skeleton, d + 1)
}

/// Compute the nesting depth of a primitive's skeleton without materializing it.
/// Used as a cheap pre-filter: a candidate injectant can only replace a
/// reference primitive if its skeleton depth is ≤ the reference's depth
/// (injecting a deeper structure would change the protocol's computation shape).
pub fn primitive_skeleton_depth(p: &Primitive, depth: usize) -> usize {
	let max_child = p
		.arguments
		.iter()
		.filter_map(|a| match a {
			Value::Primitive(pp) => Some(primitive_skeleton_depth(pp, depth + 1)),
			_ => None,
		})
		.max()
		.unwrap_or(depth);
	max_child + 1
}

/// FNV-style hash of a primitive's structure (primitive IDs, argument types,
/// equation lengths).  Used as a fast second filter after depth comparison:
/// if two skeletons have different hashes, they cannot be equivalent, avoiding
/// the cost of a full recursive comparison.
pub fn primitive_skeleton_hash(p: &Primitive) -> u64 {
	let mut h = (p.id as u64).wrapping_mul(2654435761);
	for a in &p.arguments {
		match a {
			Value::Constant(_) => h = h.wrapping_mul(31).wrapping_add(1),
			Value::Primitive(pp) => {
				h = h.wrapping_mul(31).wrapping_add(primitive_skeleton_hash(pp))
			}
			Value::Equation(e) => {
				h = h
					.wrapping_mul(31)
					.wrapping_add((e.values.len() as u64).wrapping_mul(97))
			}
		}
	}
	h
}

/// Compute the skeleton hash of a primitive (hash of its skeleton form).
/// This normalizes equations the same way inject_primitive_skeleton does.
pub fn primitive_skeleton_hash_of(p: &Primitive) -> u64 {
	let (skel, _) = inject_primitive_skeleton(p, 0);
	primitive_skeleton_hash(&skel)
}

/// Check if candidate primitive `p` has the same skeleton as `reference`.
/// Uses the three-step filter (same ID → depth ≤ → hash match → full check)
/// to avoid expensive recursive comparisons in the common non-matching case.
fn inject_skeleton_equivalent(p: &Primitive, reference: &Primitive) -> bool {
	if p.id != reference.id {
		return false;
	}
	let pd = primitive_skeleton_depth(p, 0);
	let sd = primitive_skeleton_depth(reference, 0);
	if sd > pd {
		return false;
	}
	if primitive_skeleton_hash(p) != primitive_skeleton_hash(reference) {
		return false;
	}
	let (p1, _) = inject_primitive_skeleton(p, 0);
	let (p2, _) = inject_primitive_skeleton(reference, 0);
	equivalent_primitives(&p1, &p2, false).equivalent
}

pub fn inject_missing_skeletons(
	ctx: &VerifyContext,
	p: &Primitive,
	record: &Arc<MutationRecord>,
	attacker: &AttackerState,
) {
	let (skeleton, _) = inject_primitive_skeleton(p, 0);
	let sh = primitive_skeleton_hash(&skeleton);
	if !attacker.skeleton_hashes.contains(&sh) {
		let known = Value::Primitive(Arc::new(skeleton.clone()));
		if ctx.attacker_put(&known, record) {
			info_message(
				&format!("Constructed skeleton {} based on {}.", skeleton, p),
				InfoLevel::Analysis,
				true,
			);
		}
	}
	for a in &p.arguments {
		if let Value::Primitive(pp) = a {
			inject_missing_skeletons(ctx, pp, record, attacker);
		}
	}
}

/// Returns true if `p` has the same primitive ID as `reference` and its
/// skeleton depth is no greater than `reference`'s skeleton depth.
pub fn skeleton_not_deeper(p: &Primitive, reference: &Primitive) -> bool {
	if p.id != reference.id {
		return false;
	}
	primitive_skeleton_depth(p, 0) <= primitive_skeleton_depth(reference, 0)
}

fn inject_primitive(
	ctx: &VerifyContext,
	p: &Primitive,
	ps: &PrincipalState,
	attacker: &AttackerState,
	inject_depth: usize,
	depth: usize,
) -> Vec<Value> {
	let n = p.arguments.len();
	let mut kinjectants: Vec<Vec<Value>> = vec![vec![]; n];
	let mut uinjectants: Vec<Vec<Value>> = vec![vec![]; n];
	for (arg, (kinj, uinj)) in kinjectants
		.iter_mut()
		.zip(uinjectants.iter_mut())
		.enumerate()
	{
		if ctx.all_resolved() {
			return vec![];
		}
		for known in attacker.known.iter() {
			let resolved = match known {
				Value::Constant(c) => {
					let (v, _) = ps.resolve_constant(c, true);
					v
				}
				_ => known.clone(),
			};
			if !inject_value_rules(&resolved, arg, p) {
				continue;
			}
			let is_new = push_unique_value(uinj, resolved.clone());
			if let Value::Primitive(known_prim) = &resolved {
				// Recursive injection: bounded by depth − 1
				if depth > 0 && inject_depth < depth.saturating_sub(1) {
					let recursive_injectants =
						inject(ctx, known_prim, inject_depth + 1, ps, attacker, depth);
					for injected in recursive_injectants {
						if push_unique_value(uinj, injected.clone()) {
							kinj.push(injected);
						}
					}
				}
			}
			if is_new {
				kinj.push(resolved);
			}
		}
	}
	inject_loop_n(ctx, p, &kinjectants)
}

fn inject_loop_n(ctx: &VerifyContext, p: &Primitive, kinjectants: &[Vec<Value>]) -> Vec<Value> {
	if ctx.all_resolved() {
		return vec![];
	}
	let n = kinjectants.len();
	if n == 0 {
		return vec![];
	}
	for candidates in kinjectants {
		if candidates.is_empty() {
			return vec![];
		}
	}
	let total_size = mutation_product(
		kinjectants.iter().map(|candidates| candidates.len()),
		MAX_INJECTIONS_PER_PRIMITIVE,
	)
	.unwrap_or(MAX_INJECTIONS_PER_PRIMITIVE);
	let mut injectants = Vec::with_capacity(total_size);
	let mut indices = vec![0usize; n];
	loop {
		if ctx.all_resolved() {
			return injectants;
		}
		let args: Vec<Value> = indices
			.iter()
			.zip(kinjectants.iter())
			.map(|(&idx, candidates)| candidates[idx].clone())
			.collect();
		injectants.push(Value::Primitive(Arc::new(p.with_arguments(args))));
		if injectants.len() >= MAX_INJECTIONS_PER_PRIMITIVE {
			break;
		}
		let mut carry = true;
		for j in (0..n).rev() {
			if !carry {
				break;
			}
			indices[j] += 1;
			if indices[j] < kinjectants[j].len() {
				carry = false;
			} else {
				indices[j] = 0;
			}
		}
		if carry {
			break;
		}
	}
	injectants
}
