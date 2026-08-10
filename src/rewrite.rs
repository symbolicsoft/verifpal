/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::RefCell;
use std::sync::Arc;

use crate::theory::{can_rebuild, can_rewrite, structurally_identical_primitive};
use crate::types::*;

#[derive(Clone)]
struct Reduced {
	failed: Vec<Primitive>,
	rewritten: bool,
	value: Value,
	rebuilt: Option<Value>,
}

type ReduceCache = IdMap<u64, Vec<(Arc<Primitive>, Reduced)>>;

thread_local! {
	static REDUCE_CACHE: RefCell<ReduceCache> = RefCell::new(IdMap::default());
}

pub(crate) fn reduce_cache_reset() {
	REDUCE_CACHE.with(|c| c.borrow_mut().clear());
}

pub(crate) fn perform_primitive_rewrite(
	p: &Arc<Primitive>,
	slot_index: Option<usize>,
	ps: &mut PrincipalState,
) -> RewriteResult {
	let reduced = reduce_term(p);
	if let Some(idx) = slot_index {
		if let Some(rebuilt) = reduced.rebuilt {
			ps.values[idx].set_value(rebuilt);
		}
		if reduced.rewritten {
			ps.values[idx].set_value(reduced.value.clone());
		}
	}
	RewriteResult {
		failed_rewrites: reduced.failed,
		rewritten: reduced.rewritten,
		value: reduced.value,
	}
}

fn reduce_term(p: &Arc<Primitive>) -> Reduced {
	let key = crate::hashing::primitive_hash(p);
	if let Some(hit) = reduce_cache_get(key, p) {
		return hit;
	}
	let computed = reduce_term_uncached(p);
	REDUCE_CACHE.with(|c| {
		c.borrow_mut()
			.entry(key)
			.or_default()
			.push((Arc::clone(p), computed.clone()));
	});
	computed
}

fn reduce_cache_get(key: u64, p: &Arc<Primitive>) -> Option<Reduced> {
	REDUCE_CACHE.with(|c| {
		c.borrow()
			.get(&key)?
			.iter()
			.find(|(candidate, _)| {
				Arc::ptr_eq(candidate, p) || structurally_identical_primitive(candidate, p)
			})
			.map(|(_, hit)| hit.clone())
	})
}

fn reduce_term_uncached(p: &Arc<Primitive>) -> Reduced {
	let (failed, rewritten, value) = reduce_arguments(p);
	let mut reduced = Reduced {
		failed,
		rewritten,
		value,
		rebuilt: None,
	};
	let Some(rewrite_p) = reduced.value.as_primitive() else {
		return reduced;
	};
	if let Some(rebuild) = can_rebuild(rewrite_p) {
		reduced.rebuilt = Some(rebuild.clone());
		reduced.value = rebuild;
	}
	let Value::Primitive(root) = &reduced.value else {
		return reduced;
	};
	let (rewritten_root, rewritten_value) = can_rewrite(&Arc::clone(root));
	if !rewritten_root && let Some(p) = rewritten_value.as_primitive() {
		reduced.failed.push(p.clone());
	}
	reduced.rewritten = reduced.rewritten || rewritten_root;
	reduced.value = rewritten_value;
	reduced
}

fn reduce_arguments(p: &Arc<Primitive>) -> (Vec<Primitive>, bool, Value) {
	let mut failed: Vec<Primitive> = Vec::new();
	let mut rewritten = false;
	let mut new_args: Option<Vec<Value>> = None;
	for (i, a) in p.arguments.iter().enumerate() {
		let Value::Primitive(inner_p) = a else {
			continue;
		};
		let r = reduce_term(inner_p);
		if r.rewritten {
			rewritten = true;
			new_args.get_or_insert_with(|| p.arguments.clone())[i] = r.value;
		} else {
			failed.extend(r.failed);
		}
	}
	let value = match new_args {
		Some(args) => Value::Primitive(Arc::new(p.with_arguments(args))),
		None => Value::Primitive(Arc::clone(p)),
	};
	(failed, rewritten, value)
}
