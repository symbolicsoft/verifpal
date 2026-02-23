/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::possible::{can_rebuild, can_rewrite};
use crate::primitive::{primitive_has_rewrite_rule, primitive_is_core};
use crate::types::*;
use crate::value::value_nil;

// ---------------------------------------------------------------------------
// Rewrite: primitives
// ---------------------------------------------------------------------------

pub(crate) fn perform_primitive_rewrite(
	p: &Primitive,
	slot_index: Option<usize>,
	ps: &mut PrincipalState,
) -> RewriteResult {
	let mut r = perform_primitive_arguments_rewrite(p, ps);
	let rewrite_p = match r.value.as_primitive() {
		Some(p) => p,
		None => return r,
	};
	if let Some(rebuild) = can_rebuild(rewrite_p) {
		if let Some(idx) = slot_index {
			ps.values[idx].set_assigned(rebuild.clone());
		}
		r.value = rebuild;
		match r.value {
			Value::Constant(_) | Value::Equation(_) => return r,
			_ => {}
		}
	}
	let rewrite_p2 = match r.value.as_primitive() {
		Some(p) => p,
		None => return r,
	};
	let (rewritten_root, rewritten_values) = can_rewrite(rewrite_p2, ps, 0);
	if !rewritten_root {
		if let Some(p) = rewritten_values[0].as_primitive() {
			r.failed_rewrites.push(p.clone());
		}
	}
	let r_index = if rewritten_root && primitive_is_core(p.id) {
		p.output
	} else {
		0
	};
	if r_index >= rewritten_values.len() {
		if let Some(idx) = slot_index {
			ps.values[idx].set_assigned(value_nil());
		}
		r.rewritten = r.rewritten || rewritten_root;
		r.value = value_nil();
		return r;
	}
	if let Some(idx) = slot_index {
		if r.rewritten || rewritten_root {
			ps.values[idx].rewritten = true;
			ps.values[idx].set_assigned(rewritten_values[r_index].clone());
		}
	}
	r.rewritten = r.rewritten || rewritten_root;
	r.value = rewritten_values[r_index].clone();
	r
}

// ---------------------------------------------------------------------------
// Rewrite: primitive arguments
// ---------------------------------------------------------------------------

fn perform_primitive_arguments_rewrite(p: &Primitive, ps: &mut PrincipalState) -> RewriteResult {
	let mut failed_rewrites: Vec<Primitive> = Vec::new();
	let mut rewritten = false;
	// COW: only allocate new arguments vec if something actually changes
	let mut new_args: Option<Vec<Value>> = None;
	for (i, a) in p.arguments.iter().enumerate() {
		match a {
			Value::Constant(_) => {}
			Value::Primitive(inner_p) => {
				let r = perform_primitive_rewrite(inner_p, None, ps);
				if r.rewritten {
					rewritten = true;
					let args = new_args.get_or_insert_with(|| p.arguments.clone());
					args[i] = r.value;
				} else {
					failed_rewrites.extend(r.failed_rewrites);
				}
			}
			Value::Equation(inner_e) => {
				let r = perform_equation_rewrite(inner_e, None, ps);
				if r.rewritten {
					rewritten = true;
					let args = new_args.get_or_insert_with(|| p.arguments.clone());
					args[i] = r.value;
				} else {
					failed_rewrites.extend(r.failed_rewrites);
				}
			}
		}
	}
	let value = if let Some(args) = new_args {
		Value::Primitive(Arc::new(p.with_arguments(args)))
	} else {
		Value::Primitive(Arc::new(p.clone()))
	};
	RewriteResult {
		failed_rewrites,
		rewritten,
		value,
	}
}

// ---------------------------------------------------------------------------
// Rewrite: equations
// ---------------------------------------------------------------------------

pub(crate) fn perform_equation_rewrite(
	e: &Equation,
	slot_index: Option<usize>,
	ps: &mut PrincipalState,
) -> RewriteResult {
	let mut rewritten = false;
	let mut failed_rewrites: Vec<Primitive> = Vec::new();
	let mut rewrite_eq = Equation { values: Vec::new() };
	for (i, a) in e.values.iter().enumerate() {
		match a {
			Value::Constant(_) => {
				rewrite_eq.values.push(a.clone());
			}
			Value::Primitive(inner_p) => {
				if !primitive_has_rewrite_rule(inner_p.id) {
					continue;
				}
				let r = perform_primitive_rewrite(inner_p, None, ps);
				if !r.rewritten {
					rewrite_eq.values.push(e.values[i].clone());
					failed_rewrites.extend(r.failed_rewrites);
					continue;
				}
				rewritten = true;
				match &r.value {
					Value::Constant(_) | Value::Primitive(_) => {
						rewrite_eq.values.push(r.value);
					}
					Value::Equation(inner_e) => {
						rewrite_eq.values.extend(inner_e.values.iter().cloned());
					}
				}
			}
			Value::Equation(inner_e) => {
				let r = perform_equation_rewrite(inner_e, None, ps);
				if !r.rewritten {
					rewrite_eq.values.push(e.values[i].clone());
					failed_rewrites.extend(r.failed_rewrites);
					continue;
				}
				rewritten = true;
				rewrite_eq.values.push(r.value);
			}
		}
	}
	let value = Value::Equation(Arc::new(rewrite_eq));
	if let Some(idx) = slot_index {
		if rewritten {
			ps.values[idx].rewritten = true;
			ps.values[idx].set_assigned(value.clone());
		}
	}
	RewriteResult {
		failed_rewrites,
		rewritten,
		value,
	}
}
