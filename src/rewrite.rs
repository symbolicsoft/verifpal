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
) -> (Vec<Primitive>, bool, Value) {
	let (mut rewrite, mut failed_rewrites, rewritten) =
		perform_primitive_arguments_rewrite(p, ps);
	let rewrite_p = match rewrite.as_primitive() {
		Some(p) => p,
		None => return (failed_rewrites, rewritten, rewrite),
	};
	let (rebuilt, rebuild) = can_rebuild(rewrite_p);
	if rebuilt {
		if let Some(idx) = slot_index {
			ps.values[idx].set_assigned(rebuild.clone());
		}
		rewrite = rebuild;
		match rewrite {
			Value::Constant(_) | Value::Equation(_) => {
				return (failed_rewrites, rewritten, rewrite);
			}
			_ => {}
		}
	}
	let rewrite_p2 = match rewrite.as_primitive() {
		Some(p) => p,
		None => return (failed_rewrites, rewritten, rewrite),
	};
	let (rewritten_root, rewritten_values) = can_rewrite(rewrite_p2, ps, 0);
	if !rewritten_root {
		if let Some(p) = rewritten_values[0].as_primitive() {
			failed_rewrites.push(p.clone());
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
		return (failed_rewrites, rewritten || rewritten_root, value_nil());
	}
	if let Some(idx) = slot_index {
		if rewritten || rewritten_root {
			ps.values[idx].rewritten = true;
			ps.values[idx].set_assigned(rewritten_values[r_index].clone());
		}
	}
	(
		failed_rewrites,
		rewritten || rewritten_root,
		rewritten_values[r_index].clone(),
	)
}

// ---------------------------------------------------------------------------
// Rewrite: primitive arguments
// ---------------------------------------------------------------------------

fn perform_primitive_arguments_rewrite(
	p: &Primitive,
	ps: &mut PrincipalState,
) -> (Value, Vec<Primitive>, bool) {
	let mut failed_rewrites: Vec<Primitive> = Vec::new();
	let mut rewritten = false;
	// COW: only allocate new arguments vec if something actually changes
	let mut new_args: Option<Vec<Value>> = None;
	for (i, a) in p.arguments.iter().enumerate() {
		match a {
			Value::Constant(_) => {}
			Value::Primitive(inner_p) => {
				let (p_failed, p_rewritten, p_rewrite) =
					perform_primitive_rewrite(inner_p, None, ps);
				if p_rewritten {
					rewritten = true;
					let args = new_args.get_or_insert_with(|| p.arguments.clone());
					args[i] = p_rewrite;
				} else {
					failed_rewrites.extend(p_failed);
				}
			}
			Value::Equation(inner_e) => {
				let (e_failed, e_rewritten, e_rewrite) =
					perform_equation_rewrite(inner_e, None, ps);
				if e_rewritten {
					rewritten = true;
					let args = new_args.get_or_insert_with(|| p.arguments.clone());
					args[i] = e_rewrite;
				} else {
					failed_rewrites.extend(e_failed);
				}
			}
		}
	}
	let result = if let Some(args) = new_args {
		Value::Primitive(Arc::new(p.with_arguments(args)))
	} else {
		Value::Primitive(Arc::new(p.clone()))
	};
	(result, failed_rewrites, rewritten)
}

// ---------------------------------------------------------------------------
// Rewrite: equations
// ---------------------------------------------------------------------------

pub(crate) fn perform_equation_rewrite(
	e: &Equation,
	slot_index: Option<usize>,
	ps: &mut PrincipalState,
) -> (Vec<Primitive>, bool, Value) {
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
				let (p_failed, p_rewritten, p_rewrite) =
					perform_primitive_rewrite(inner_p, None, ps);
				if !p_rewritten {
					rewrite_eq.values.push(e.values[i].clone());
					failed_rewrites.extend(p_failed);
					continue;
				}
				rewritten = true;
				match &p_rewrite {
					Value::Constant(_) | Value::Primitive(_) => {
						rewrite_eq.values.push(p_rewrite);
					}
					Value::Equation(inner_e) => {
						rewrite_eq.values.extend(inner_e.values.iter().cloned());
					}
				}
			}
			Value::Equation(inner_e) => {
				let (e_failed, e_rewritten, e_rewrite) =
					perform_equation_rewrite(inner_e, None, ps);
				if !e_rewritten {
					rewrite_eq.values.push(e.values[i].clone());
					failed_rewrites.extend(e_failed);
					continue;
				}
				rewritten = true;
				rewrite_eq.values.push(e_rewrite);
			}
		}
	}
	let rewrite = Value::Equation(Arc::new(rewrite_eq));
	if let Some(idx) = slot_index {
		if rewritten {
			ps.values[idx].rewritten = true;
			ps.values[idx].set_assigned(rewrite.clone());
		}
	}
	(failed_rewrites, rewritten, rewrite)
}
