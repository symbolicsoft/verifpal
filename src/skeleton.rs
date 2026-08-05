/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Skeletons
//!
//! A skeleton is the shape of a primitive with every secret erased: constants
//! become `nil`, equations become `G` or `G^nil` by length, and nested
//! primitives are skeletonized in turn.  `AEAD_ENC(k, m, ad)` has skeleton
//! `AEAD_ENC(nil, nil, nil)`.
//!
//! Because `nil` and `G^nil` are values the attacker holds outright, a skeleton
//! is by construction something the attacker can actually build.  Adding it to
//! attacker knowledge therefore asserts nothing new about the attacker's power;
//! it only makes an already-available term explicit, so that the knowledge
//! closure and the query evaluator can see a well-formed term of the right
//! shape where the protocol expects one.
//!
//! Skeleton *hashes* serve a second purpose in [`crate::context`], which indexes
//! attacker knowledge by them so that "is there anything of this shape" is a
//! lookup rather than a scan.

use std::sync::Arc;

use crate::context::VerifyContext;
use crate::info::info_message;
use crate::types::*;
use crate::value::{value_g, value_g_nil, value_nil};

fn primitive_skeleton(p: &Primitive) -> Primitive {
	let arguments = p
		.arguments
		.iter()
		.map(|a| match a {
			Value::Constant(_) => value_nil(),
			Value::Primitive(pp) => Value::Primitive(Arc::new(primitive_skeleton(pp))),
			Value::Equation(e) if e.values.len() <= 1 => value_g(),
			Value::Equation(_) => value_g_nil(),
		})
		.collect();
	Primitive {
		id: p.id,
		arguments,
		output: p.output,
		instance_check: false,
	}
}

/// FNV-style hash of a primitive's structure (primitive IDs, argument types,
/// equation lengths).  Two primitives with different hashes cannot share a
/// skeleton, so this rules out a match without a recursive comparison.
pub(crate) fn primitive_skeleton_hash(p: &Primitive) -> u64 {
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

/// The hash of a primitive's skeleton, rather than of the primitive itself.
pub(crate) fn primitive_skeleton_hash_of(p: &Primitive) -> u64 {
	primitive_skeleton_hash(&primitive_skeleton(p))
}

/// Give the attacker the skeleton of `p`, and of every primitive nested inside
/// it, unless it already holds something of that shape.
pub(crate) fn attacker_learn_skeletons(
	ctx: &VerifyContext,
	p: &Primitive,
	record: &Arc<MutationRecord>,
	attacker: &AttackerState,
) {
	let skeleton = primitive_skeleton(p);
	let sh = primitive_skeleton_hash(&skeleton);
	if !attacker.skeleton_hashes.contains(&sh) {
		let known = Value::Primitive(Arc::new(skeleton.clone()));
		if ctx.attacker_put_with(&known, record, DerivationRecord::Injected) {
			info_message(
				&format!("Constructed skeleton {} based on {}.", skeleton, p),
				InfoLevel::Analysis,
				true,
			);
		}
	}
	for a in &p.arguments {
		if let Value::Primitive(pp) = a {
			attacker_learn_skeletons(ctx, pp, record, attacker);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::*;
	use crate::testutil::*;

	#[test]
	fn skeleton_hash_same_structure() {
		let a = make_constant("sh_a");
		let b = make_constant("sh_b");
		let p1 = Primitive {
			id: PRIM_ENC,
			arguments: vec![a.clone(), b.clone()],
			output: 0,
			instance_check: false,
		};
		let p2 = Primitive {
			id: PRIM_ENC,
			arguments: vec![b, a],
			output: 0,
			instance_check: false,
		};
		// Same structure (constants are normalized to nil in skeleton)
		assert_eq!(primitive_skeleton_hash(&p1), primitive_skeleton_hash(&p2));
	}
}
