/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::info::{info_analysis, info_message, info_output_text};
use crate::possible::{
	can_decompose, can_recompose, can_reconstruct_equation, can_reconstruct_primitive,
	find_obtainable_passwords, passively_decompose,
};
use crate::pretty::pretty_values;
use crate::primitive::PRIM_CONCAT;
use crate::types::*;
use crate::value::compute_slot_diffs;
use crate::verify::verify_resolve_queries;

// ---------------------------------------------------------------------------
// Main analysis entry point
// ---------------------------------------------------------------------------

pub(crate) fn verify_analysis(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	stage: i32,
) -> VResult<()> {
	let mut current_attacker = ctx.attacker_snapshot();
	let record = compute_slot_diffs(ps, km);
	loop {
		if ctx.all_resolved() {
			return Ok(());
		}
		verify_resolve_queries(ctx, km, ps)?;

		let mut progress = false;

		// Phase 1: decompose and passive decompose from attacker known values
		for known in current_attacker.known.iter() {
			if verify_analysis_decompose(ctx, known, ps, &current_attacker, &record)
				|| verify_analysis_passive_decompose(ctx, known, &record)
			{
				progress = true;
				break;
			}
		}

		// Phase 2: reconstruct and recompose from principal assigned values
		if !progress {
			for sv in &ps.values {
				if verify_analysis_reconstruct(ctx, &sv.assigned, ps, &current_attacker, &record)
					|| verify_analysis_recompose(ctx, &sv.assigned, &current_attacker, &record)
				{
					progress = true;
					break;
				}
			}
		}

		// Phase 3: equivalize, passwords, and concat from attacker known values
		if !progress {
			for known in current_attacker.known.iter() {
				if verify_analysis_equivalize(ctx, known, ps, &record)
					|| verify_analysis_passwords(ctx, known, ps, &record)
					|| verify_analysis_concat(ctx, known, &record)
				{
					progress = true;
					break;
				}
			}
		}

		if progress {
			current_attacker = ctx.attacker_snapshot();
			continue;
		}
		ctx.analysis_count_increment();
		info_analysis(stage);
		return Ok(());
	}
}

// ---------------------------------------------------------------------------
// Decompose
// ---------------------------------------------------------------------------

fn verify_analysis_decompose(
	ctx: &VerifyContext,
	value: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	record: &MutationRecord,
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

// ---------------------------------------------------------------------------
// Passive decompose
// ---------------------------------------------------------------------------

fn verify_analysis_passive_decompose(
	ctx: &VerifyContext,
	value: &Value,
	record: &MutationRecord,
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

// ---------------------------------------------------------------------------
// Recompose
// ---------------------------------------------------------------------------

fn verify_analysis_recompose(
	ctx: &VerifyContext,
	value: &Value,
	attacker: &AttackerState,
	record: &MutationRecord,
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

// ---------------------------------------------------------------------------
// Reconstruct (recursive)
// ---------------------------------------------------------------------------

fn verify_analysis_reconstruct(
	ctx: &VerifyContext,
	value: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	record: &MutationRecord,
) -> bool {
	let mut found = false;
	let result = match value {
		Value::Primitive(p) => {
			let result = can_reconstruct_primitive(p, ps, attacker, 0);
			for arg in &p.arguments {
				found |= verify_analysis_reconstruct(ctx, arg, ps, attacker, record);
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

// ---------------------------------------------------------------------------
// Equivalize
// ---------------------------------------------------------------------------

fn verify_analysis_equivalize(
	ctx: &VerifyContext,
	value: &Value,
	ps: &PrincipalState,
	record: &MutationRecord,
) -> bool {
	let resolved = if let Value::Constant(c) = value {
		let (r, _) = ps.resolve_constant(c, true);
		r
	} else {
		value.clone()
	};
	let mut found = false;
	for sv in &ps.values {
		if resolved.equivalent(&sv.assigned, true) && ctx.attacker_put(&sv.assigned, record) {
			info_message(
				&format!(
					"{} obtained by equivalizing with the current resolution of {}.",
					info_output_text(&sv.assigned),
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

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

fn verify_analysis_passwords(
	ctx: &VerifyContext,
	value: &Value,
	ps: &PrincipalState,
	record: &MutationRecord,
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

// ---------------------------------------------------------------------------
// Concat
// ---------------------------------------------------------------------------

fn verify_analysis_concat(ctx: &VerifyContext, value: &Value, record: &MutationRecord) -> bool {
	let Value::Primitive(prim) = value else {
		return false;
	};
	if prim.id != PRIM_CONCAT {
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
