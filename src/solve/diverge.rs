/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Divergence goals
//!
//! Equivalence queries are the one kind that is not a deducibility question.
//! They fail when the queried constants, resolved within a single principal's
//! state, are not all pairwise equivalent, and they never consult the attacker
//! at all (`query.rs`).  So the goal form is not "make this derivable" but
//! "make these two terms differ".
//!
//! ## Method
//!
//! Two terms diverge under a substitution when they depend on the attacker's
//! choices differently.  If `a` mentions `$gbe` and `b` does not, then binding
//! `$gbe` to anything other than the honest value makes the position where it
//! occurs differ.  So the candidate substitutions are generated from the
//! *asymmetry* in variable occurrence between the two terms, and each is bound
//! to `nil` — inside the `G^X` shape, the attacker's own key.
//!
//! ## Why this may propose too much, and why that is fine
//!
//! Divergence at an inner position does not always survive to the top.  It
//! propagates through constructor contexts such as `HASH` and `CONCAT`, but an
//! enclosing destructor with a rewrite rule can discard or collapse the
//! differing argument.  Modelling that faithfully would mean reimplementing the
//! rewrite theory in reverse.
//!
//! Instead this module treats propagation as a proposal heuristic and lets
//! `validate.rs` decide, exactly as it decides for every other goal kind.  A
//! proposal whose difference gets collapsed costs one wasted validation and
//! reports nothing.  The asymmetry is deliberate: over-proposing is cheap,
//! over-claiming would be a false attack.

use crate::types::*;

use super::vars::{Substitution, collect_vars, dedupe};
use crate::value::value_nil;

/// Substitutions that plausibly make `a` and `b` differ.
///
/// The returned substitutions are proposals only; whether the two terms really
/// end up inequivalent is settled by concrete re-execution.
pub fn solve_divergent(a: &Value, b: &Value, s: &Substitution) -> Vec<Substitution> {
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
