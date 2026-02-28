/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::info::info_message;
use crate::inject::*;
use crate::types::*;
use crate::util::*;
use crate::value::*;


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

impl MutationMap {
	pub fn new(
		ctx: &VerifyContext,
		km: &ProtocolTrace,
		ps: &PrincipalState,
		attacker: &AttackerState,
		depth: usize,
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
				"Initializing depth {} mutation map for {}...",
				depth, ps.name
			),
			InfoLevel::Analysis,
			false,
		);
		for v in attacker.known.iter() {
			let c = match v {
				Value::Constant(c) => c,
				_ => continue,
			};
			let (a, i) = ps.resolve_constant(c, true);
			let idx = match i {
				Some(i) => i,
				None => continue,
			};
			if skip_value(v, idx, km, ps, attacker) {
				continue;
			}
			let r = replace_value(ctx, &a, idx, depth, ps, attacker)?;
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
					"Mutation map for {} at depth {}: {} constants, mutations: {:?}",
					ps.name,
					depth,
					mm.constants.len(),
					mut_sizes
				),
				InfoLevel::Analysis,
				false,
			);
		}
		Ok(mm)
	}

	pub fn next(mut self) -> MutationMap {
		if self.combination.is_empty() {
			self.out_of_mutations = true;
			return self;
		}
		let n = self.combination.len();
		for i in 0..n {
			self.combination[i] = self.mutations[i][self.depth_index[i]].clone();
		}
		// Increment last dimension and carry
		self.depth_index[n - 1] += 1;
		let mut j = n - 1;
		while self.depth_index[j] == self.mutations[j].len() {
			if j == 0 {
				self.out_of_mutations = true;
				break;
			}
			self.depth_index[j] = 0;
			j -= 1;
			self.depth_index[j] += 1;
		}
		self
	}

	pub fn subset(&self, indices: &[usize]) -> MutationMap {
		MutationMap {
			out_of_mutations: false,
			constants: indices.iter().map(|&i| self.constants[i].clone()).collect(),
			mutations: indices.iter().map(|&i| self.mutations[i].clone()).collect(),
			combination: vec![value_nil(); indices.len()],
			depth_index: vec![0; indices.len()],
		}
	}

	pub fn subset_capped(&self, indices: &[usize], max_product: usize) -> MutationMap {
		let mut sub = self.subset(indices);
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
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn skip_value(
	v: &Value,
	idx: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> bool {
	if ps.meta[idx].guard {
		if !ps.meta[idx].mutatable_to.contains(&ps.values[idx].provenance.sender) {
			return true;
		}
	} else if ps.values[idx].provenance.creator == ps.id {
		return true;
	}
	if !ps.meta[idx].phase.contains(&attacker.current_phase) {
		return true;
	}
	if let Value::Constant(c) = v {
		if !km.constant_used_by(ps.id, c) {
			return true;
		}
	}
	false
}

fn replace_value(
	ctx: &VerifyContext,
	a: &Value,
	root_index: usize,
	depth: usize,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> VResult<Vec<Value>> {
	let a = resolve_ps_values(a, a, root_index, ps, attacker, false)?;
	match &a {
		Value::Constant(_) => Ok(replace_constant(&a, depth, ps, attacker)),
		Value::Primitive(_) => Ok(replace_primitive(ctx, &a, depth, ps, attacker)),
		Value::Equation(_) => Ok(replace_equation(&a, depth, attacker)),
	}
}

fn replace_constant(
	a: &Value,
	_depth: usize,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Vec<Value> {
	let mut mutations = vec![];
	if let Value::Constant(c) = a {
		if c.is_g_or_nil() {
			return mutations;
		}
	}
	mutations.push(value_nil());
	for v in attacker.known.iter() {
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

fn replace_primitive(
	ctx: &VerifyContext,
	a: &Value,
	depth: usize,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Vec<Value> {
	let mut mutations = vec![];
	let a_prim = match a {
		Value::Primitive(p) => p,
		_ => return mutations,
	};
	for v in attacker.known.iter() {
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
				if !skeleton_not_deeper(vp, a_prim) {
					continue;
				}
				push_unique_value(&mut mutations, v.clone());
			}
			_ => {}
		}
	}
	let injectants = inject(ctx, a_prim, 0, ps, attacker, depth);
	for inj in injectants {
		push_unique_value(&mut mutations, inj);
	}
	mutations
}

fn replace_equation(value: &Value, _depth: usize, attacker: &AttackerState) -> Vec<Value> {
	let mut mutations = vec![];
	if let Value::Equation(e) = value {
		match e.values.len() {
			1 => mutations.push(value_g()),
			2 => mutations.push(value_g_nil()),
			3 => mutations.push(value_g_nil_nil()),
			_ => {}
		}
		if false {
			return mutations;
		}
		for v in attacker.known.iter() {
			if let Value::Equation(ve) = v {
				if ve.values.len() == e.values.len() && find_equivalent(v, &mutations).is_none() {
					mutations.push(v.clone());
				}
			}
		}
	}
	mutations
}
