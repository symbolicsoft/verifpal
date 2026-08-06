/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::context::VerifyContext;
use crate::info::info_message;
use crate::types::*;
use crate::value::value_nil;

fn primitive_skeleton(p: &Primitive) -> Primitive {
	let arguments = p
		.arguments
		.iter()
		.map(|a| match a {
			Value::Constant(_) => value_nil(),
			Value::Primitive(pp) if crate::primitive::primitive_is_key_derivation(pp.id) => {
				crate::primitive::nil_key_derivation().unwrap_or_else(value_nil)
			}
			Value::Primitive(pp) => Value::Primitive(Arc::new(primitive_skeleton(pp))),
		})
		.collect();
	Primitive {
		id: p.id,
		arguments,
		output: p.output,
		instance_check: false,
		capabilities: Capabilities::default(),
		hash: HashCell::default(),
	}
}

pub(crate) fn primitive_skeleton_hash(p: &Primitive) -> u64 {
	let mut h = (p.id as u64).wrapping_mul(2654435761);
	for a in &p.arguments {
		match a {
			Value::Constant(_) => h = h.wrapping_mul(31).wrapping_add(1),
			Value::Primitive(pp) => {
				h = h.wrapping_mul(31).wrapping_add(primitive_skeleton_hash(pp))
			}
		}
	}
	h
}

pub(crate) fn primitive_skeleton_hash_of(p: &Primitive) -> u64 {
	primitive_skeleton_hash(&primitive_skeleton(p))
}

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
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		};
		let p2 = Primitive {
			id: PRIM_ENC,
			arguments: vec![b, a],
			output: 0,
			instance_check: false,
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		};
		assert_eq!(primitive_skeleton_hash(&p1), primitive_skeleton_hash(&p2));
	}
}
