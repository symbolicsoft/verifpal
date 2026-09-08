/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::theory::can_rewrite;
use crate::types::*;

pub(crate) fn perform_primitive_rewrite(
	p: &Arc<Primitive>,
	slot_index: usize,
	ps: &mut PrincipalState,
) -> Option<Primitive> {
	let (rewritten, value) = can_rewrite(p);
	let failed = if rewritten {
		None
	} else {
		value.as_primitive().cloned()
	};
	if rewritten
		|| crate::value::subterms(&Value::Primitive(Arc::clone(p)))
			.skip(1)
			.any(|term| matches!(term, Value::Primitive(inner) if can_rewrite(inner).0))
	{
		ps.values[slot_index].set_value(value);
	}
	failed
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
		crate::context::enter_generation(crate::context::next_generation());
		let mut ps = one_slot(value);
		let Value::Primitive(p) = value else {
			panic!("expected a primitive");
		};
		let failed = perform_primitive_rewrite(&Arc::clone(p), 0, &mut ps);
		(ps, failed)
	}

	#[test]
	fn failed_checks_preserve_originals_unless_a_subterm_rewrites() {
		let left = make_constant("rw_failure_left");
		let right = make_constant("rw_failure_right");
		let marker = make_constant("rw_failure_original");
		let check = |a, b| make_primitive(PRIM_ASSERT, vec![a, b], 0);
		let failed = check(left.clone(), right.clone());
		let unchanged = make_primitive(PRIM_HASH, vec![left.clone()], 0);
		let reduced = make_primitive(
			PRIM_DEC,
			vec![
				left.clone(),
				make_primitive(PRIM_ENC, vec![left.clone(), right.clone()], 0),
			],
			0,
		);
		for (term, updates_original) in [
			(failed.clone(), false),
			(check(failed, right.clone()), false),
			(check(unchanged, right.clone()), true),
			(check(reduced, left), true),
		] {
			let Value::Primitive(p) = &term else {
				unreachable!();
			};
			for _ in 0..2 {
				let mut ps = one_slot(&term);
				ps.values[0].original = marker.clone();
				let failure = perform_primitive_rewrite(p, 0, &mut ps);
				assert!(failure.is_some());
				assert_eq!(
					ps.values[0].original.equivalent(&marker, true),
					!updates_original
				);
				assert!(
					ps.values[0]
						.value
						.equivalent(&crate::theory::reduce_once(&term), true)
				);
			}
		}
	}

	#[test]
	fn unchanged_shared_terms_keep_their_nodes_during_state_rewriting() {
		let mut term = make_constant("rw_shared_unchanged");
		for _ in 0..40 {
			term = make_primitive(PRIM_HASH, vec![term.clone(), term.clone(), term], 0);
		}
		let (ps, failed) = rewrite(&term);
		assert!(failed.is_none());
		assert!(ps.values[0].value.same_term(&term));
		assert!(ps.values[0].original.same_term(&term));
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
			threshold: 0,
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
	fn threshold_join_rebuilds_the_secret_from_two_distinct_shares() {
		let secret = make_constant("rws_secret");
		let share = |output: usize| {
			let mut p = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], output);
			p.threshold = 2;
			Value::Primitive(Arc::new(p))
		};
		let (ps, failed) = rewrite(&make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![share(0), share(1)],
			0,
		));
		assert!(failed.is_none());
		assert!(ps.values[0].value.equivalent(&secret, true));
	}

	#[test]
	fn a_three_of_five_join_needs_three_distinct_shares() {
		let secret = make_constant("rw35_secret");
		let share = |output: usize| {
			let mut p = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], output);
			p.threshold = 3;
			Value::Primitive(Arc::new(p))
		};
		let join = |shares: Vec<Value>| make_primitive(PRIM_THRESHOLD_JOIN, shares, 0);
		let (ps, _) = rewrite(&join(vec![share(0), share(2), share(4)]));
		assert!(ps.values[0].value.equivalent(&secret, true));
		let two = join(vec![share(0), share(4)]);
		let (ps, _) = rewrite(&two);
		assert!(ps.values[0].value.equivalent(&two, true));
		let repeated = join(vec![share(0), share(0), share(2)]);
		let (ps, _) = rewrite(&repeated);
		assert!(ps.values[0].value.equivalent(&repeated, true));
	}

	#[test]
	fn a_two_of_n_join_accepts_any_two_shares() {
		let secret = make_constant("rw2n_secret");
		let share = |output: usize| {
			let mut p = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], output);
			p.threshold = 2;
			Value::Primitive(Arc::new(p))
		};
		let (ps, _) = rewrite(&make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![share(4), share(3)],
			0,
		));
		assert!(ps.values[0].value.equivalent(&secret, true));
		let (ps, _) = rewrite(&make_primitive(
			PRIM_THRESHOLD_JOIN,
			vec![share(1), share(3), share(0)],
			0,
		));
		assert!(ps.values[0].value.equivalent(&secret, true));
	}

	#[test]
	fn two_shares_of_the_same_output_do_not_rebuild_anything() {
		let secret = make_constant("rwd_secret");
		let mut split = Primitive::new(PRIM_THRESHOLD_SPLIT, vec![secret.clone()], 0);
		split.threshold = 2;
		let share = Value::Primitive(Arc::new(split));
		let join = make_primitive(PRIM_THRESHOLD_JOIN, vec![share.clone(), share], 0);
		let (ps, _) = rewrite(&join);
		assert!(
			ps.values[0].value.equivalent(&join, true),
			"a threshold scheme needs distinct shares, so the join stays unreduced"
		);
	}

	#[test]
	fn state_rewriting_accepts_a_structurally_identical_cached_term() {
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
		crate::context::enter_generation(crate::context::next_generation());
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
