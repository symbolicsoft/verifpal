/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Deduction Rule Engine
//!
//! Implements the attacker's knowledge expansion as a monotone fixed-point
//! computation over a finite set of deduction rules.
//!
//! ## Fixed-point property
//!
//! The attacker's knowledge set K is monotonically increasing: each rule
//! application either adds a new value to K or leaves it unchanged. Since
//! the set of derivable values is finite (bounded by the protocol model),
//! the iteration terminates when K is closed under all rules — i.e., when
//! no rule can derive a value not already in K. This is the least fixed
//! point of F(K) = K ∪ { v : v derivable from K under some rule }.
//!
//! ## Rule groups and priority
//!
//! Rules are organized into groups, each iterating over a specific domain
//! (attacker-known values or principal-assigned values). Within each group,
//! rules are tried in order with short-circuit on first success. On any
//! success, the outer loop restarts from the first group.
//!
//! The ordering reflects priority: cheaper derivations (decomposition) are
//! tried before more expensive ones (reconstruction, equivalization).

use std::sync::Arc;

use crate::context::VerifyContext;
use crate::info::{info_analysis, info_message, info_output_text};
use crate::possible::{
	can_decompose, can_recompose, can_reconstruct_equation, can_reconstruct_primitive,
	find_obtainable_passwords, passively_decompose,
};
use crate::pretty::pretty_values;
use crate::primitive::primitive_core_reveals_args;
use crate::types::*;
use crate::value::compute_slot_diffs;

// ---------------------------------------------------------------------------
// Rule abstraction
// ---------------------------------------------------------------------------

/// The domain a rule group iterates over.
pub enum RuleDomain {
	/// Iterate over values in the attacker's current knowledge set.
	AttackerKnown,
	/// Iterate over assigned values in the principal's state.
	PrincipalAssigned,
}

/// A deduction rule function.
///
/// Takes a source value (from the rule's domain), the principal state,
/// the current attacker knowledge, and the mutation record. Returns true
/// if new knowledge was gained (i.e., at least one new value was added
/// to the attacker's knowledge set).
type RuleFn =
	fn(&VerifyContext, &Value, &PrincipalState, &AttackerState, &Arc<MutationRecord>) -> bool;

/// A group of deduction rules that share an iteration domain.
///
/// Within a group, for each source value, rules are tried in order.
/// On first success (any rule returns true), iteration stops and the
/// outer fixed-point loop restarts from the first group.
pub struct RuleGroup {
	pub domain: RuleDomain,
	pub rules: &'static [RuleFn],
}

/// The complete set of deduction rules, organized into priority groups.
///
/// - Group 1 (AttackerKnown): decompose, passive_decompose
/// - Group 2 (PrincipalAssigned): reconstruct, recompose
/// - Group 3 (AttackerKnown): equivalize, password_extract, concat_extract
static DEDUCTION_RULES: &[RuleGroup] = &[
	RuleGroup {
		domain: RuleDomain::AttackerKnown,
		rules: &[rule_decompose, rule_passive_decompose],
	},
	RuleGroup {
		domain: RuleDomain::PrincipalAssigned,
		rules: &[rule_reconstruct, rule_recompose],
	},
	RuleGroup {
		domain: RuleDomain::AttackerKnown,
		rules: &[rule_equivalize, rule_password_extract, rule_concat_extract],
	},
];

// ---------------------------------------------------------------------------
// Fixed-point computation
// ---------------------------------------------------------------------------

/// Compute the least fixed point of the attacker's knowledge under the
/// deduction rules.
///
/// Each iteration applies all rule groups in priority order, breaking on
/// first progress (new knowledge gained). The loop terminates when no
/// rule can derive new knowledge — i.e., the knowledge set is closed
/// under all rules.
///
/// This function is a pure fixed-point computation: it does not check
/// queries or exit early when all queries are resolved. Query evaluation
/// happens in a separate phase after the closure completes. This makes
/// the correctness argument trivial by Knaster-Tarski: the iteration
/// converges to the least fixed point, and every value in the result is
/// genuinely derivable.
///
/// Convergence is guaranteed because:
/// - The attacker's knowledge set is monotonically increasing
/// - The set of derivable values is finite (bounded by the protocol model)
/// - Each iteration either adds a new value or terminates
pub fn compute_knowledge_closure(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	depth: i32,
) -> VResult<()> {
	let record = compute_slot_diffs(ps, km);

	loop {
		let attacker = ctx.attacker_snapshot();

		if !try_deduction_step(ctx, &attacker, ps, &record) {
			ctx.analysis_count_increment();
			info_analysis(depth);
			return Ok(());
		}
	}
}

/// Apply all deduction rule groups in priority order.
///
/// Returns true if any rule derived new knowledge (triggering a restart
/// of the outer fixed-point loop).
fn try_deduction_step(
	ctx: &VerifyContext,
	attacker: &AttackerState,
	ps: &PrincipalState,
	record: &Arc<MutationRecord>,
) -> bool {
	for group in DEDUCTION_RULES {
		match group.domain {
			RuleDomain::AttackerKnown => {
				for known in attacker.known.iter() {
					for rule in group.rules {
						if rule(ctx, known, ps, attacker, record) {
							return true;
						}
					}
				}
			}
			RuleDomain::PrincipalAssigned => {
				for sv in &ps.values {
					for rule in group.rules {
						if rule(ctx, &sv.value, ps, attacker, record) {
							return true;
						}
					}
				}
			}
		}
	}
	false
}

// ---------------------------------------------------------------------------
// Rule implementations
// ---------------------------------------------------------------------------
//
// Each rule function follows the same pattern:
//   1. Check if the source value is the right type
//   2. Try the deduction operation
//   3. If successful, add the result to attacker knowledge
//   4. Log what was derived
//   5. Return whether progress was made

fn rule_decompose(
	ctx: &VerifyContext,
	value: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	let Value::Primitive(prim) = value else {
		return false;
	};
	let Some(result) = can_decompose(prim, ps, attacker, 0) else {
		return false;
	};
	if ctx.attacker_put(&result.revealed, record) {
		info_message(
			&format!(
				"{} obtained by decomposing {} with {}.",
				info_output_text(&result.revealed),
				value,
				pretty_values(&result.used),
			),
			InfoLevel::Deduction,
			true,
		);
		true
	} else {
		false
	}
}

fn rule_passive_decompose(
	ctx: &VerifyContext,
	value: &Value,
	_ps: &PrincipalState,
	_attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	let Value::Primitive(prim) = value else {
		return false;
	};
	let mut found = false;
	for revealed in &passively_decompose(prim) {
		if ctx.attacker_put(revealed, record) {
			info_message(
				&format!(
					"{} obtained as associated data from {}.",
					info_output_text(revealed),
					value,
				),
				InfoLevel::Deduction,
				true,
			);
			found = true;
		}
	}
	found
}

fn rule_reconstruct(
	ctx: &VerifyContext,
	value: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	reconstruct_recursive(ctx, value, ps, attacker, record)
}

fn reconstruct_recursive(
	ctx: &VerifyContext,
	value: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	let mut found = false;
	let result = match value {
		Value::Primitive(p) => {
			let result = can_reconstruct_primitive(p, ps, attacker, 0);
			for arg in &p.arguments {
				found |= reconstruct_recursive(ctx, arg, ps, attacker, record);
			}
			result
		}
		Value::Equation(e) => can_reconstruct_equation(e, attacker),
		_ => return found,
	};
	if let Some(used) = result {
		if ctx.attacker_put(value, record) {
			info_message(
				&format!(
					"{} obtained by reconstructing with {}.",
					info_output_text(value),
					pretty_values(&used),
				),
				InfoLevel::Deduction,
				true,
			);
			found = true;
		}
	}
	found
}

fn rule_recompose(
	ctx: &VerifyContext,
	value: &Value,
	_ps: &PrincipalState,
	attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	let Value::Primitive(prim) = value else {
		return false;
	};
	let Some(result) = can_recompose(prim, attacker) else {
		return false;
	};
	if ctx.attacker_put(&result.revealed, record) {
		info_message(
			&format!(
				"{} obtained by recomposing {} with {}.",
				info_output_text(&result.revealed),
				value,
				pretty_values(&result.used),
			),
			InfoLevel::Deduction,
			true,
		);
		true
	} else {
		false
	}
}

fn rule_equivalize(
	ctx: &VerifyContext,
	value: &Value,
	ps: &PrincipalState,
	_attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	let resolved = if let Value::Constant(c) = value {
		let (r, _) = ps.resolve_constant(c, true);
		r
	} else {
		value.clone()
	};
	let mut found = false;
	for sv in &ps.values {
		if resolved.equivalent(&sv.value, true) && ctx.attacker_put(&sv.value, record) {
			info_message(
				&format!(
					"{} obtained by equivalizing with the current resolution of {}.",
					info_output_text(&sv.value),
					value,
				),
				InfoLevel::Deduction,
				true,
			);
			found = true;
		}
	}
	found
}

fn rule_password_extract(
	ctx: &VerifyContext,
	value: &Value,
	ps: &PrincipalState,
	_attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	let mut passwords = Vec::new();
	find_obtainable_passwords(value, value, None, ps, &mut passwords);
	let mut found = false;
	for password in &passwords {
		if ctx.attacker_put(password, record) {
			info_message(
				&format!(
					"{} obtained as a password unsafely used within {}.",
					info_output_text(password),
					value,
				),
				InfoLevel::Deduction,
				true,
			);
			found = true;
		}
	}
	found
}

fn rule_concat_extract(
	ctx: &VerifyContext,
	value: &Value,
	_ps: &PrincipalState,
	_attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	let Value::Primitive(prim) = value else {
		return false;
	};
	if !primitive_core_reveals_args(prim.id) {
		return false;
	}
	let mut found = false;
	for arg in &prim.arguments {
		if ctx.attacker_put(arg, record) {
			info_message(
				&format!(
					"{} obtained as a concatenated fragment of {}.",
					info_output_text(arg),
					value,
				),
				InfoLevel::Deduction,
				true,
			);
			found = true;
		}
	}
	found
}
