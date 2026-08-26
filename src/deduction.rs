/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::context::VerifyContext;
use crate::info::{info_deduction, info_output_text};
use crate::pretty::pretty_values;
use crate::primitive::primitive_core_reveals_args;
use crate::theory::{
	can_decompose, can_recompose, can_reconstruct_primitive, find_obtainable_passwords,
};
use crate::types::*;
use crate::value::compute_slot_diffs;

pub(crate) enum RuleDomain {
	AttackerKnown,
	PrincipalAssigned,
}

type RuleFn =
	fn(&VerifyContext, &Value, &PrincipalState, &AttackerState, &Arc<MutationRecord>) -> bool;

pub(crate) struct RuleGroup {
	pub domain: RuleDomain,
	pub rules: &'static [RuleFn],
}

static DEDUCTION_RULES: &[RuleGroup] = &[
	RuleGroup {
		domain: RuleDomain::AttackerKnown,
		rules: &[rule_decompose, rule_break_weak],
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

pub(crate) fn compute_knowledge_closure(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> VResult<()> {
	let record = compute_slot_diffs(ps, km, ctx.attacker_snapshot().current_phase);
	let index = crate::theory::StateIndex::of(ps);

	loop {
		if ctx.cancelled() {
			return Ok(());
		}
		let attacker = ctx.attacker_snapshot();

		if !try_deduction_step(ctx, &attacker, ps, &record, &index) {
			ctx.analysis_count_increment();
			return Ok(());
		}
	}
}

fn try_deduction_step(
	ctx: &VerifyContext,
	attacker: &AttackerState,
	ps: &PrincipalState,
	record: &Arc<MutationRecord>,
	index: &Arc<crate::theory::StateIndex>,
) -> bool {
	let _memo = crate::theory::DeductionMemo::scoped(ps, attacker, index);
	let mut progress = false;
	for group in DEDUCTION_RULES {
		match group.domain {
			RuleDomain::AttackerKnown => {
				for known in attacker.known.iter() {
					for rule in group.rules {
						progress |= rule(ctx, known, ps, attacker, record);
					}
				}
			}
			RuleDomain::PrincipalAssigned => {
				for (slot, sv) in ps.values.iter().enumerate() {
					if ps.slot_unreached(slot) {
						continue;
					}
					for rule in group.rules {
						progress |= rule(ctx, &sv.value, ps, attacker, record);
					}
				}
			}
		}
	}
	progress
}

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
	info_deduction(message);
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
	let Some(result) = can_decompose(prim, ps, attacker) else {
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

fn rule_break_weak(
	ctx: &VerifyContext,
	value: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	let Value::Primitive(p) = value else {
		return false;
	};
	let Some(revealed) = crate::theory::can_break_weak(p, ps, attacker) else {
		return false;
	};
	let mut progress = false;
	for r in revealed {
		progress |= learn(
			ctx,
			&r,
			record,
			DerivationRecord::Broken {
				of: value.clone(),
				capability: Capability::Weak,
				using: vec![],
			},
			|| {
				format!(
					"{} recovered from {} under the declared `weak` assumption.",
					info_output_text(&r),
					value,
				)
			},
		);
	}
	progress
}

fn rule_reconstruct(
	ctx: &VerifyContext,
	value: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	let mut found = false;
	let result = match value {
		Value::Primitive(p) => {
			let result = can_reconstruct_primitive(p, ps, attacker);
			for arg in &p.arguments {
				found |= rule_reconstruct(ctx, arg, ps, attacker, record);
			}
			result
		}
		_ => return found,
	};
	if let Some(reconstructed) = result {
		let used = reconstructed.from;
		let derivation = match reconstructed.forged {
			Some(capability) => DerivationRecord::Broken {
				of: value.clone(),
				capability,
				using: used.clone(),
			},
			None => DerivationRecord::Reconstructed { from: used.clone() },
		};
		let forged = reconstructed.forged;
		found |= learn(ctx, value, record, derivation, || match forged {
			Some(capability) => format!(
				"{} forged from {} under the declared `{}` assumption.",
				info_output_text(value),
				pretty_values(&used),
				capability.name(),
			),
			None => format!(
				"{} obtained by reconstructing with {}.",
				info_output_text(value),
				pretty_values(&used),
			),
		});
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

fn unsent_after_halt(ps: &PrincipalState, c: &Constant, halted_at: i32) -> bool {
	ps.index
		.get(&c.id)
		.and_then(|&slot| ps.meta.get(slot))
		.and_then(|sm| sm.sent_at)
		.is_some_and(|sent_at| sent_at > halted_at)
}

fn rule_equivalize(
	ctx: &VerifyContext,
	value: &Value,
	ps: &PrincipalState,
	_attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	if let Value::Constant(c) = value
		&& let Some(halted_at) = ps.halted_at
	{
		let suppressed = ps.leaks.iter().any(|leak| {
			leak.constant_id == c.id && leak.principal_id == ps.id && leak.declared_at > halted_at
		});
		if suppressed || unsent_after_halt(ps, c, halted_at) {
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
	for slot in crate::theory::slots_equivalent_to(ps, &resolved) {
		if ps.slot_unreached(slot) {
			continue;
		}
		let sv = &ps.values[slot];
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
	if !crate::theory::state_declares_passwords(ps) {
		return false;
	}
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
		let ctx = VerifyContext::new(&m, &states, Vec::new(), 2, crate::types::IdSet::default());
		let mut pure = states[0].clone_for_depth(true);
		pure.resolve_all_values().expect("resolve");
		ctx.attacker_phase_update(&km, &pure, 0).expect("phase");
		crate::verify::verify_standard_run(&ctx, &km, &states).expect("run");

		let attacker = ctx.attacker_snapshot();
		assert_eq!(attacker.known.len(), attacker.derivations.len());
		assert!(
			attacker
				.derivations
				.iter()
				.any(|d| matches!(d, DerivationRecord::Decomposed { .. })),
			"expected at least one Decomposed derivation, got {:?}",
			attacker.derivations
		);
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
