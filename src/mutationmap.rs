/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::info::info_message;
use crate::inject::*;
use crate::types::*;
use crate::util::*;
use crate::value::*;

pub fn mutation_map_init(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	as_: &AttackerState,
	stage: i32,
) -> VResult<MutationMap> {
	let mut mm = MutationMap {
		out_of_mutations: false,
		constants: vec![],
		mutations: vec![],
		combination: vec![],
		depth_index: vec![],
	};
	info_message(
		&format!(
			"Initializing Stage {} mutation map for {}...",
			stage, ps.name
		),
		InfoLevel::Analysis,
		false,
	);
	for v in as_.known.iter() {
		let c = match v {
			Value::Constant(c) => c,
			_ => continue,
		};
		let (a, i) = ps.resolve_constant(c, true);
		let idx = match i {
			Some(i) => i,
			None => continue,
		};
		if mutation_map_skip_value(v, idx, km, ps, as_) {
			continue;
		}
		let r = mutation_map_replace_value(ctx, &a, idx, stage, ps, as_)?;
		if r.is_empty() {
			continue;
		}
		mm.constants.push(c.clone());
		mm.mutations.push(r);
	}
	mm.combination = vec![value_nil(); mm.constants.len()];
	mm.depth_index = vec![0; mm.constants.len()];
	if !mm.constants.is_empty() {
		let mut_sizes: Vec<usize> = mm.mutations.iter().map(|m| m.len()).collect();
		info_message(
			&format!(
				"Mutation map for {} at stage {}: {} constants, mutations: {:?}",
				ps.name,
				stage,
				mm.constants.len(),
				mut_sizes
			),
			InfoLevel::Analysis,
			false,
		);
	}
	Ok(mm)
}

fn mutation_map_skip_value(
	v: &Value,
	idx: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	as_: &AttackerState,
) -> bool {
	if ps.meta[idx].guard {
		if !ps.meta[idx].mutatable_to.contains(&ps.values[idx].sender) {
			return true;
		}
	} else if ps.values[idx].creator == ps.id {
		return true;
	}
	if !ps.meta[idx].phase.contains(&as_.current_phase) {
		return true;
	}
	if let Value::Constant(c) = v {
		if !km.constant_used_by(ps.id, c) {
			return true;
		}
	}
	false
}

fn mutation_map_replace_value(
	ctx: &VerifyContext,
	a: &Value,
	root_index: usize,
	stage: i32,
	ps: &PrincipalState,
	as_: &AttackerState,
) -> VResult<Vec<Value>> {
	let a =
		value_resolve_value_internal_values_from_principal_state(a, a, root_index, ps, as_, false)?;
	match &a {
		Value::Constant(_) => Ok(mutation_map_replace_constant(&a, stage, ps, as_)),
		Value::Primitive(_) => Ok(mutation_map_replace_primitive(ctx, &a, stage, ps, as_)),
		Value::Equation(_) => Ok(mutation_map_replace_equation(&a, stage, as_)),
	}
}

fn mutation_map_replace_constant(
	a: &Value,
	stage: i32,
	ps: &PrincipalState,
	as_: &AttackerState,
) -> Vec<Value> {
	let mut mutations = vec![];
	if let Value::Constant(c) = a {
		if c.is_g_or_nil() {
			return mutations;
		}
	}
	mutations.push(value_nil());
	if stage <= 3 {
		return mutations;
	} // stageMutationExpansion = 3
	for v in as_.known.iter() {
		if let Value::Constant(vc) = v {
			if vc.is_g_or_nil() {
				continue;
			}
			let (c, _) = ps.resolve_constant(vc, true);
			if let Value::Constant(_) = &c {
				push_unique_value(&mut mutations, c);
			}
		}
	}
	mutations
}

fn mutation_map_replace_primitive(
	ctx: &VerifyContext,
	a: &Value,
	stage: i32,
	ps: &PrincipalState,
	as_: &AttackerState,
) -> Vec<Value> {
	let mut mutations = vec![];
	let a_prim = match a {
		Value::Primitive(p) => p,
		_ => return mutations,
	};
	for v in as_.known.iter() {
		match v {
			Value::Constant(vc) => {
				if vc.is_g_or_nil() {
					continue;
				}
				let (c, _) = ps.resolve_constant(vc, true);
				if let Value::Constant(_) = &c {
					push_unique_value(&mut mutations, c);
				}
			}
			Value::Primitive(vp) => {
				if !inject_skeleton_not_deeper_pub(vp, a_prim) {
					continue;
				}
				push_unique_value(&mut mutations, v.clone());
			}
			_ => {}
		}
	}
	let injectants = inject(ctx, a_prim, 0, ps, as_, stage);
	for inj in injectants {
		push_unique_value(&mut mutations, inj);
	}
	mutations
}

fn mutation_map_replace_equation(a: &Value, stage: i32, as_: &AttackerState) -> Vec<Value> {
	let mut mutations = vec![];
	if let Value::Equation(e) = a {
		match e.values.len() {
			1 => mutations.push(value_g()),
			2 => mutations.push(value_g_nil()),
			3 => mutations.push(value_g_nil_nil()),
			_ => {}
		}
		if stage <= 3 {
			return mutations;
		}
		for v in as_.known.iter() {
			if let Value::Equation(ve) = v {
				if ve.values.len() == e.values.len()
					&& find_equivalent(v, &mutations).is_none()
				{
					mutations.push(v.clone());
				}
			}
		}
	}
	mutations
}

pub fn mutation_map_subset(full_map: &MutationMap, indices: &[usize]) -> MutationMap {
	MutationMap {
		out_of_mutations: false,
		constants: indices
			.iter()
			.map(|&i| full_map.constants[i].clone())
			.collect(),
		mutations: indices
			.iter()
			.map(|&i| full_map.mutations[i].clone())
			.collect(),
		combination: vec![value_nil(); indices.len()],
		depth_index: vec![0; indices.len()],
	}
}

/// Compute the product of mutation sizes, returning None if it exceeds `cap`.
pub fn mutation_product(sizes: impl Iterator<Item = usize>, cap: usize) -> Option<usize> {
	let mut product: usize = 1;
	for m in sizes {
		if m > 0 && product > cap / m {
			return None;
		}
		product *= m;
	}
	if product <= cap {
		Some(product)
	} else {
		None
	}
}

pub fn mutation_map_subset_capped(
	full_map: &MutationMap,
	indices: &[usize],
	max_product: usize,
) -> MutationMap {
	let mut sub = full_map.subset(indices);
	let n = indices.len();
	if n == 0 {
		return sub;
	}
	if mutation_product(sub.mutations.iter().map(|m| m.len()), max_product).is_some() {
		return sub;
	}
	let capped_product = max_product.min(i32::MAX as usize) as i32;
	let capped_n = n.min(i32::MAX as usize) as i32;
	let per_dim = int_nth_root(capped_product, capped_n).max(1) as usize;
	for i in 0..n {
		if sub.mutations[i].len() > per_dim {
			sub.mutations[i].truncate(per_dim);
		}
	}
	sub
}

pub fn mutation_map_next(mut mm: MutationMap) -> MutationMap {
	if mm.combination.is_empty() {
		mm.out_of_mutations = true;
		return mm;
	}
	let n = mm.combination.len();
	for i in 0..n {
		mm.combination[i] = mm.mutations[i][mm.depth_index[i]].clone();
	}
	// Increment last dimension and carry
	mm.depth_index[n - 1] += 1;
	let mut j = n - 1;
	while mm.depth_index[j] == mm.mutations[j].len() {
		if j == 0 {
			mm.out_of_mutations = true;
			break;
		}
		mm.depth_index[j] = 0;
		j -= 1;
		mm.depth_index[j] += 1;
	}
	mm
}

impl MutationMap {
	pub fn new(
		ctx: &VerifyContext,
		km: &ProtocolTrace,
		ps: &PrincipalState,
		as_: &AttackerState,
		stage: i32,
	) -> VResult<MutationMap> {
		mutation_map_init(ctx, km, ps, as_, stage)
	}
	pub fn next(self) -> MutationMap {
		mutation_map_next(self)
	}
	pub fn subset(&self, indices: &[usize]) -> MutationMap {
		mutation_map_subset(self, indices)
	}
}

pub fn inject_skeleton_not_deeper_pub(p: &Primitive, reference: &Primitive) -> bool {
	if p.id != reference.id {
		return false;
	}
	primitive_skeleton_depth(p, 0) <= primitive_skeleton_depth(reference, 0)
}
