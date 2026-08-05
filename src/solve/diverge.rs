/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Divergence goals
//!
//! Equivalence queries are the one kind that is not a deducibility question:
//! they fail when the queried constants do not all resolve alike, and never
//! consult the attacker at all.  So the goal is "make these two terms differ",
//! and candidates come from the *asymmetry* in which attacker variables reach
//! which side.
//!
//! Divergence at an inner position does not always survive to the top — an
//! enclosing destructor can collapse the differing argument, and modelling that
//! would mean running the rewrite theory in reverse.  So this proposes and lets
//! `validate.rs` decide.  Over-proposing costs one wasted validation;
//! over-claiming would be a false attack.

use crate::types::*;

use super::vars::{Substitution, collect_vars, dedupe};
use crate::value::value_nil;

/// Substitutions that plausibly make `a` and `b` differ.
pub(crate) fn solve_divergent(a: &Value, b: &Value, s: &Substitution) -> Vec<Substitution> {
	let mut a_vars = Vec::new();
	let mut b_vars = Vec::new();
	collect_vars(a, &mut a_vars);
	collect_vars(b, &mut b_vars);

	if a_vars.is_empty() && b_vars.is_empty() {
		// Nothing the attacker controls reaches either term, so if they agree
		// honestly they will keep agreeing.  The passive baseline has already
		// settled this query.
		return Vec::new();
	}

	let mut out = Vec::new();

	// Variables reaching exactly one side are the ones that create asymmetry.
	// Each gets its own proposal, so a query that can be broken in several
	// independent ways yields several candidates rather than one conflated one.
	for id in a_vars.iter().chain(b_vars.iter()) {
		let in_a = a_vars.contains(id);
		let in_b = b_vars.contains(id);
		if in_a == in_b {
			continue;
		}
		let mut extended = s.clone();
		extended.entry(*id).or_insert_with(value_nil);
		out.push(extended);
	}

	// Both sides may depend on the same variables but at different positions
	// (say one hashes it and the other does not), so also offer the substitution
	// that grounds everything the attacker controls here.
	let mut all = s.clone();
	for id in a_vars.iter().chain(b_vars.iter()) {
		all.entry(*id).or_insert_with(value_nil);
	}
	out.push(all);

	dedupe(out)
}
