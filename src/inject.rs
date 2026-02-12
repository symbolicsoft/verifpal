/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::context::VerifyContext;
use crate::info::info_message;
use crate::mutationmap::mutation_product;
use crate::primitive::primitive_is_explosive;
use crate::types::*;
use crate::value::*;

const MAX_INJECTIONS_PER_PRIMITIVE: usize = 500;
const STAGE_RECURSIVE_INJECTION: i32 = 5;

pub fn inject(
	ctx: &VerifyContext,
	p: &Primitive,
	inject_depth: usize,
	ps: &PrincipalState,
	as_: &AttackerState,
	stage: i32,
) -> Vec<Value> {
	if ctx.all_resolved() {
		return vec![];
	}
	inject_primitive(ctx, p, ps, as_, inject_depth, stage)
}

fn inject_value_rules(k: &Value, arg: usize, p: &Primitive, stage: i32) -> bool {
	match k {
		Value::Constant(c) => inject_constant_rules(c, arg, p),
		Value::Primitive(kp) => inject_primitive_rules(kp, arg, p, stage),
		Value::Equation(e) => inject_equation_rules(e, arg, p),
	}
}

fn inject_constant_rules(c: &Constant, arg: usize, p: &Primitive) -> bool {
	if !matches!(&p.arguments[arg], Value::Constant(_)) {
		return false;
	}
	if c.equivalent(value_g().as_constant().expect("g is Constant")) {
		return false;
	}
	true
}

fn inject_primitive_rules(k: &Primitive, arg: usize, p: &Primitive, stage: i32) -> bool {
	let ref_p = match &p.arguments[arg] {
		Value::Primitive(p) => p,
		_ => return false,
	};
	if inject_primitive_stage_restricted(k, stage) {
		return false;
	}
	inject_skeleton_equivalent(k, ref_p)
}

fn inject_equation_rules(e: &Equation, arg: usize, p: &Primitive) -> bool {
	match &p.arguments[arg] {
		Value::Equation(pe) => e.values.len() == pe.values.len(),
		_ => false,
	}
}

fn inject_primitive_stage_restricted(p: &Primitive, stage: i32) -> bool {
	match stage {
		0 | 1 => true,
		2 => primitive_is_explosive(p.id),
		_ => false,
	}
}

fn inject_primitive_skeleton(p: &Primitive, depth: usize) -> (Primitive, usize) {
	let mut skeleton = Primitive {
		id: p.id,
		arguments: Vec::with_capacity(p.arguments.len()),
		output: p.output,
		check: false,
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
	let (e, _, _) = value_equivalent_primitives(&p1, &p2, false);
	e
}

pub fn inject_missing_skeletons(
	ctx: &VerifyContext,
	p: &Primitive,
	record: &MutationRecord,
	as_: &AttackerState,
) {
	let (skeleton, _) = inject_primitive_skeleton(p, 0);
	let sh = primitive_skeleton_hash(&skeleton);
	if !as_.skeleton_hashes.contains(&sh) {
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
			inject_missing_skeletons(ctx, pp, record, as_);
		}
	}
}

fn inject_primitive(
	ctx: &VerifyContext,
	p: &Primitive,
	ps: &PrincipalState,
	as_: &AttackerState,
	inject_depth: usize,
	stage: i32,
) -> Vec<Value> {
	if inject_primitive_stage_restricted(p, stage) {
		return vec![];
	}
	let n = p.arguments.len();
	let mut kinjectants: Vec<Vec<Value>> = vec![vec![]; n];
	let mut uinjectants: Vec<Vec<Value>> = vec![vec![]; n];
	for arg in 0..n {
		if ctx.all_resolved() {
			return vec![];
		}
		for k in as_.known.iter() {
			let resolved = match k {
				Value::Constant(c) => {
					let (v, _) = ps.resolve_constant(c, true);
					v
				}
				_ => k.clone(),
			};
			if !inject_value_rules(&resolved, arg, p, stage) {
				continue;
			}
			let is_new = push_unique_value(&mut uinjectants[arg], resolved.clone());
			if let Value::Primitive(kp) = &resolved {
				if stage >= STAGE_RECURSIVE_INJECTION
					&& inject_depth as i32 <= stage - STAGE_RECURSIVE_INJECTION
				{
					let kp_inj = inject(ctx, kp, inject_depth + 1, ps, as_, stage);
					for kkp in kp_inj {
						if push_unique_value(&mut uinjectants[arg], kkp.clone()) {
							kinjectants[arg].push(kkp);
						}
					}
				}
			}
			if is_new {
				kinjectants[arg].push(resolved);
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
	for k in kinjectants {
		if k.is_empty() {
			return vec![];
		}
	}
	let total_size = mutation_product(
		kinjectants.iter().map(|k| k.len()),
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
			.map(|(&idx, k)| k[idx].clone())
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
