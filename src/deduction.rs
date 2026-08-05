/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Deduction rule engine
//!
//! The attacker's knowledge expansion, as a monotone fixed point over a finite
//! set of rules: knowledge only grows, the derivable set is bounded by the
//! model, so iterating to closure terminates at the least fixed point of
//! F(K) = K ∪ { v : v derivable from K under some rule }.
//!
//! Rules are grouped by the domain they iterate over. Within a group they are
//! tried in order and short-circuit on first success; any success restarts the
//! outer loop from the first group. Cheap derivations come before expensive
//! ones.

use std::sync::Arc;

use crate::context::VerifyContext;
use crate::info::{info_is_quiet, info_message, info_output_text};
use crate::pretty::pretty_values;
use crate::primitive::primitive_core_reveals_args;
use crate::theory::{
	can_decompose, can_recompose, can_reconstruct_equation, can_reconstruct_primitive,
	find_obtainable_passwords, passively_decompose,
};
use crate::types::*;
use crate::value::compute_slot_diffs;

pub(crate) enum RuleDomain {
	AttackerKnown,
	PrincipalAssigned,
}

/// Returns true if the rule gained the attacker new knowledge.
type RuleFn =
	fn(&VerifyContext, &Value, &PrincipalState, &AttackerState, &Arc<MutationRecord>) -> bool;

pub(crate) struct RuleGroup {
	pub domain: RuleDomain,
	pub rules: &'static [RuleFn],
}

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

/// Grow attacker knowledge to its least fixed point.
///
/// Deliberately checks no queries and takes no early exit when they are all
/// resolved: keeping evaluation in a separate phase is what makes the
/// Knaster-Tarski argument trivial.
pub(crate) fn compute_knowledge_closure(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> VResult<()> {
	let record = compute_slot_diffs(ps, km, ctx.attacker_snapshot().current_phase);

	loop {
		let attacker = ctx.attacker_snapshot();

		if !try_deduction_step(ctx, &attacker, ps, &record) {
			ctx.analysis_count_increment();
			return Ok(());
		}
	}
}

/// Returns true if any rule derived new knowledge, restarting the outer loop.
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

/// Record a value the attacker derived, and say how — unless output is quiet.
///
/// Every rule ends this way.  Routing them all through one function is what
/// keeps "knowledge and the derivation that explains it are recorded together"
/// true by construction.  The message is a closure because minimization re-runs
/// this whole closure many times with output suppressed, and every `format!`
/// built for a suppressed line is thrown away.
fn learn(
	ctx: &VerifyContext,
	value: &Value,
	record: &Arc<MutationRecord>,
	derivation: DerivationRecord,
	message: impl FnOnce() -> String,
) -> bool {
	if !ctx.attacker_put_with(value, record, derivation) {
		return false;
	}
	if !info_is_quiet() {
		info_message(&message(), InfoLevel::Deduction, true);
	}
	true
}

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
	learn(
		ctx,
		&result.revealed,
		record,
		DerivationRecord::Decomposed {
			of: value.clone(),
			using: result.used.clone(),
		},
		|| {
			format!(
				"{} obtained by decomposing {} with {}.",
				info_output_text(&result.revealed),
				value,
				pretty_values(&result.used),
			)
		},
	)
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
		found |= learn(
			ctx,
			revealed,
			record,
			DerivationRecord::Decomposed {
				of: value.clone(),
				using: vec![],
			},
			|| {
				format!(
					"{} obtained as associated data from {}.",
					info_output_text(revealed),
					value,
				)
			},
		);
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
		found |= learn(
			ctx,
			value,
			record,
			DerivationRecord::Reconstructed { from: used.clone() },
			|| {
				format!(
					"{} obtained by reconstructing with {}.",
					info_output_text(value),
					pretty_values(&used),
				)
			},
		);
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
	learn(
		ctx,
		&result.revealed,
		record,
		DerivationRecord::Recomposed {
			of: value.clone(),
			using: result.used.clone(),
		},
		|| {
			format!(
				"{} obtained by recomposing {} with {}.",
				info_output_text(&result.revealed),
				value,
				pretty_values(&result.used),
			)
		},
	)
}

fn rule_equivalize(
	ctx: &VerifyContext,
	value: &Value,
	ps: &PrincipalState,
	_attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	// When the principal halted on a failed checked primitive (ASSERT?,
	// AEAD_DEC?, SIGNVERIF?, …), any `leaks` this same principal declared
	// after that point never fires.  Using the attacker's token for such
	// a leaked constant to re-resolve in the current mutated state would
	// let them harvest values from a branch the principal never reached.
	if let Value::Constant(c) = value
		&& let Some(halted_at) = ps.halted_at
	{
		let suppressed = ps.leaks.iter().any(|leak| {
			leak.constant_id == c.id && leak.principal_id == ps.id && leak.declared_at > halted_at
		});
		if suppressed {
			return false;
		}
	}
	let resolved = if let Value::Constant(c) = value {
		let (r, _) = ps.resolve_constant(c, true);
		r
	} else {
		value.clone()
	};
	let mut found = false;
	for (slot, sv) in ps.values.iter().enumerate() {
		if !resolved.equivalent(&sv.value, true) {
			continue;
		}
		found |= learn(
			ctx,
			&sv.value,
			record,
			DerivationRecord::Obtained {
				slot: SlotIdx(slot),
			},
			|| {
				format!(
					"{} obtained by equivalizing with the current resolution of {}.",
					info_output_text(&sv.value),
					value,
				)
			},
		);
	}
	found
}

fn rule_password_extract(
	ctx: &VerifyContext,
	value: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	let mut passwords = Vec::new();
	find_obtainable_passwords(value, false, true, attacker, ps, &mut passwords);
	let mut found = false;
	for password in &passwords {
		found |= learn(
			ctx,
			password,
			record,
			DerivationRecord::PasswordExtracted {
				from: value.clone(),
			},
			|| {
				format!(
					"{} obtained as a password unsafely used within {}.",
					info_output_text(password),
					value,
				)
			},
		);
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
		found |= learn(
			ctx,
			arg,
			record,
			DerivationRecord::ConcatFragment { of: value.clone() },
			|| {
				format!(
					"{} obtained as a concatenated fragment of {}.",
					info_output_text(arg),
					value,
				)
			},
		);
	}
	found
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::parser::parse_string;

	#[test]
	fn deduction_records_real_derivations() {
		use crate::context::VerifyContext;
		// Alice leaks the key, so the attacker decomposes the ciphertext.
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private ddr_m\n\
			knows private ddr_k\n\
			ddr_e = ENC(ddr_k, ddr_m)\n\
			leaks ddr_k\n\
			]\n\
			principal Bob[\n\
			knows private ddr_b\n\
			]\n\
			Alice -> Bob: ddr_e\n\
			queries[\n\
			confidentiality? ddr_m\n\
			]\n";
		let m = parse_string("ddr.vp", src).expect("parse");
		let (km, states) = crate::sanity::sanity(&m).expect("sanity");
		let ctx = VerifyContext::new(&m, &states);
		let mut pure = states[0].clone_for_depth(true);
		pure.resolve_all_values(&ctx.attacker_snapshot())
			.expect("resolve");
		ctx.attacker_phase_update(&km, &pure, 0).expect("phase");
		crate::verify::verify_standard_run(&ctx, &km, &states).expect("run");

		let attacker = ctx.attacker_snapshot();
		assert_eq!(attacker.known.len(), attacker.derivations.len());
		// Something must have been decomposed: that is how ddr_m is learned.
		assert!(
			attacker
				.derivations
				.iter()
				.any(|d| matches!(d, DerivationRecord::Decomposed { .. })),
			"expected at least one Decomposed derivation, got {:?}",
			attacker.derivations
		);
		// The leaked key must be recorded as leaked, not as generic knowledge.
		assert!(
			attacker
				.derivations
				.iter()
				.any(|d| matches!(d, DerivationRecord::Leaked { .. })),
			"expected the leaks declaration to be recorded, got {:?}",
			attacker.derivations
		);
	}
}
