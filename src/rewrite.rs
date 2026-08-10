/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::theory::{can_rebuild, can_rewrite};
use crate::types::*;

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
			ps.values[idx].set_value(rebuild.clone());
		}
		r.value = rebuild;
	}
	let rewrite_p2 = match r.value.as_primitive() {
		Some(p) => p,
		None => return r,
	};
	let (rewritten_root, rewritten_value) = can_rewrite(rewrite_p2, ps);
	if !rewritten_root && let Some(p) = rewritten_value.as_primitive() {
		r.failed_rewrites.push(p.clone());
	}
	if let Some(idx) = slot_index
		&& (r.rewritten || rewritten_root)
	{
		ps.values[idx].rewritten = true;
		ps.values[idx].set_value(rewritten_value.clone());
	}
	r.rewritten = r.rewritten || rewritten_root;
	r.value = rewritten_value;
	r
}

fn perform_primitive_arguments_rewrite(p: &Primitive, ps: &mut PrincipalState) -> RewriteResult {
	let mut failed_rewrites: Vec<Primitive> = Vec::new();
	let mut rewritten = false;
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
