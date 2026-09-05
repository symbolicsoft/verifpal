/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::RefCell;
use std::sync::Arc;

use crate::theory::{can_rewrite, structurally_identical_primitive};
use crate::types::*;

#[derive(Clone)]
struct Reduced {
	failed: Option<Primitive>,
	rewritten: bool,
	value: Value,
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
	slot_index: usize,
	ps: &mut PrincipalState,
) -> Option<Primitive> {
	let reduced = reduce_term(p);
	if reduced.rewritten {
		ps.values[slot_index].set_value(reduced.value);
	}
	reduced.failed
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
	let (rewritten, value) = reduce_arguments(p);
	let mut reduced = Reduced {
		failed: None,
		rewritten,
		value,
	};
	let Value::Primitive(root) = &reduced.value else {
		return reduced;
	};
	let (rewritten_root, rewritten_value) = can_rewrite(&Arc::clone(root));
	if !rewritten_root && let Some(p) = rewritten_value.as_primitive() {
		reduced.failed = Some(p.clone());
	}
	reduced.rewritten = reduced.rewritten || rewritten_root;
	reduced.value = rewritten_value;
	reduced
}

fn reduce_arguments(p: &Arc<Primitive>) -> (bool, Value) {
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
		}
	}
	let value = match new_args {
		Some(args) => Value::Primitive(Arc::new(p.with_arguments(args))),
		None => Value::Primitive(Arc::clone(p)),
	};
	(rewritten, value)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::*;
	use crate::testutil::*;

	fn one_slot(value: &Value) -> PrincipalState {
		let name = make_constant("rw_slot");
		let c = name.as_constant().expect("constant").clone();
		make_principal_state(
			"Alice",
			0,
			vec![make_slot_meta(&c, true)],
			vec![make_slot_values(value, 0)],
		)
	}

	fn rewrite(value: &Value) -> (PrincipalState, Option<Primitive>) {
		reduce_cache_reset();
		let mut ps = one_slot(value);
		let Value::Primitive(p) = value else {
			panic!("expected a primitive");
		};
		let failed = perform_primitive_rewrite(&Arc::clone(p), 0, &mut ps);
		(ps, failed)
	}

	#[test]
	fn a_decryption_that_undoes_its_encryption_replaces_the_slot() {
		let k = make_constant("rw_k");
		let m = make_constant("rw_m");
		let enc = make_primitive(PRIM_ENC, vec![k.clone(), m.clone()], 0);
		let (ps, failed) = rewrite(&make_primitive(PRIM_DEC, vec![k, enc], 0));
		assert!(failed.is_none());
		assert!(ps.values[0].value.equivalent(&m, true));
	}

	#[test]
	fn a_checked_decryption_under_the_wrong_key_is_reported_as_a_failure() {
		let k = make_constant("rwf_k");
		let other = make_constant("rwf_other");
		let m = make_constant("rwf_m");
		let ad = make_constant("rwf_ad");
		let n = make_constant("rwf_n");
		let sealed = make_primitive(PRIM_AEAD_ENC, vec![k, n.clone(), m, ad.clone()], 0);
		let dec = Value::Primitive(Arc::new(Primitive {
			id: PRIM_AEAD_DEC,
			arguments: vec![other, n, sealed, ad],
			output: 0,
			instance_check: true,
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		}));
		let (ps, failed) = rewrite(&dec);
		let failed = failed.expect("the check fails");
		assert_eq!(failed.id, PRIM_AEAD_DEC);
		assert!(
			ps.values[0].value.equivalent(&dec, true),
			"a failed check leaves the slot holding the term that did not reduce"
		);
	}

	#[test]
	fn an_inner_rewrite_is_applied_before_the_outer_one_is_tried() {
		let k = make_constant("rwi_k");
		let m = make_constant("rwi_m");
		let inner = make_primitive(
			PRIM_DEC,
			vec![k.clone(), make_primitive(PRIM_ENC, vec![k, m.clone()], 0)],
			0,
		);
		let (ps, failed) = rewrite(&make_primitive(PRIM_HASH, vec![inner], 0));
		assert!(failed.is_none());
		assert!(
			ps.values[0]
				.value
				.equivalent(&make_primitive(PRIM_HASH, vec![m], 0), true)
		);
	}

	#[test]
	fn shamir_join_rebuilds_the_secret_from_two_distinct_shares() {
		let secret = make_constant("rws_secret");
		let share = |output: usize| make_primitive(PRIM_SHAMIR_SPLIT, vec![secret.clone()], output);
		let (ps, failed) = rewrite(&make_primitive(
			PRIM_SHAMIR_JOIN,
			vec![share(0), share(1)],
			0,
		));
		assert!(failed.is_none());
		assert!(ps.values[0].value.equivalent(&secret, true));
	}

	#[test]
	fn two_shares_of_the_same_output_do_not_rebuild_anything() {
		let secret = make_constant("rwd_secret");
		let share = make_primitive(PRIM_SHAMIR_SPLIT, vec![secret.clone()], 0);
		let join = make_primitive(PRIM_SHAMIR_JOIN, vec![share.clone(), share], 0);
		let (ps, _) = rewrite(&join);
		assert!(
			ps.values[0].value.equivalent(&join, true),
			"a threshold scheme needs distinct shares, so the join stays unreduced"
		);
	}

	#[test]
	fn the_reduce_cache_answers_for_a_structurally_identical_term() {
		let k = make_constant("rwc_k");
		let m = make_constant("rwc_m");
		let build = || {
			make_primitive(
				PRIM_DEC,
				vec![
					k.clone(),
					make_primitive(PRIM_ENC, vec![k.clone(), m.clone()], 0),
				],
				0,
			)
		};
		reduce_cache_reset();
		let mut first = one_slot(&build());
		let Value::Primitive(p) = build() else {
			unreachable!()
		};
		perform_primitive_rewrite(&p, 0, &mut first);
		let mut second = one_slot(&build());
		let Value::Primitive(q) = build() else {
			unreachable!()
		};
		assert!(!Arc::ptr_eq(&p, &q), "two separately built terms");
		perform_primitive_rewrite(&q, 0, &mut second);
		assert!(second.values[0].value.equivalent(&m, true));
	}
}
