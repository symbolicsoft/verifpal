/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::info::{info_analysis, info_message, info_output_text};
use crate::possible::{
	can_decompose, find_obtainable_passwords,
	passively_decompose, can_recompose,
	can_reconstruct_equation, can_reconstruct_primitive,
};
use crate::pretty::pretty_values;
use crate::primitive::PRIM_CONCAT;
use crate::types::*;
use crate::value::compute_slot_diffs;
use crate::verify::verify_resolve_queries;

// ---------------------------------------------------------------------------
// Main analysis entry point
// ---------------------------------------------------------------------------

pub fn verify_analysis(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	stage: i32,
) -> VResult<()> {
	let mut current_as = ctx.attacker_snapshot();
	let record = compute_slot_diffs(ps, km);
	loop {
		if ctx.all_resolved() {
			return Ok(());
		}
		verify_resolve_queries(ctx, km, ps)?;

		let mut progress = false;

		// Phase 1: decompose and passive decompose from attacker known values
		for k in current_as.known.iter() {
			if verify_analysis_decompose(ctx, k, ps, &current_as, &record) > 0
				|| verify_analysis_passive_decompose(ctx, k, &record) > 0
			{
				progress = true;
				break;
			}
		}

		// Phase 2: reconstruct and recompose from principal assigned values
		if !progress {
			for sv in &ps.values {
				if verify_analysis_reconstruct(ctx, &sv.assigned, ps, &current_as, 0, &record) > 0
					|| verify_analysis_recompose(ctx, &sv.assigned, &current_as, &record) > 0
				{
					progress = true;
					break;
				}
			}
		}

		// Phase 3: equivalize, passwords, and concat from attacker known values
		if !progress {
			for k in current_as.known.iter() {
				if verify_analysis_equivalize(ctx, k, ps, &record) > 0
					|| verify_analysis_passwords(ctx, k, ps, &record) > 0
					|| verify_analysis_concat(ctx, k, &record) > 0
				{
					progress = true;
					break;
				}
			}
		}

		if progress {
			current_as = ctx.attacker_snapshot();
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
	a: &Value,
	ps: &PrincipalState,
	as_: &AttackerState,
	record: &MutationRecord,
) -> usize {
	let p = match a {
		Value::Primitive(p) => p,
		_ => return 0,
	};
	let (r, revealed, ar) = can_decompose(p, ps, as_, 0);
	if r && ctx.attacker_put(&revealed, record) {
		info_message(
			&format!(
				"{} obtained by decomposing {} with {}.",
				info_output_text(&revealed),
				a,
				pretty_values(&ar),
			),
			InfoLevel::Deduction,
			true,
		);
		1
	} else {
		0
	}
}

// ---------------------------------------------------------------------------
// Passive decompose
// ---------------------------------------------------------------------------

fn verify_analysis_passive_decompose(
	ctx: &VerifyContext,
	a: &Value,
	record: &MutationRecord,
) -> usize {
	let p = match a {
		Value::Primitive(p) => p,
		_ => return 0,
	};
	let mut o: usize = 0;
	for revealed in &passively_decompose(p) {
		if ctx.attacker_put(revealed, record) {
			info_message(
				&format!(
					"{} obtained as associated data from {}.",
					info_output_text(revealed),
					a,
				),
				InfoLevel::Deduction,
				true,
			);
			o += 1;
		}
	}
	o
}

// ---------------------------------------------------------------------------
// Recompose
// ---------------------------------------------------------------------------

fn verify_analysis_recompose(
	ctx: &VerifyContext,
	a: &Value,
	as_: &AttackerState,
	record: &MutationRecord,
) -> usize {
	let p = match a {
		Value::Primitive(p) => p,
		_ => return 0,
	};
	let (r, revealed, ar) = can_recompose(p, as_);
	if r && ctx.attacker_put(&revealed, record) {
		info_message(
			&format!(
				"{} obtained by recomposing {} with {}.",
				info_output_text(&revealed),
				a,
				pretty_values(&ar),
			),
			InfoLevel::Deduction,
			true,
		);
		1
	} else {
		0
	}
}

// ---------------------------------------------------------------------------
// Reconstruct (recursive)
// ---------------------------------------------------------------------------

fn verify_analysis_reconstruct(
	ctx: &VerifyContext,
	a: &Value,
	ps: &PrincipalState,
	as_: &AttackerState,
	mut o: usize,
	record: &MutationRecord,
) -> usize {
	let (r, ar) = match a {
		Value::Primitive(p) => {
			let (r, ar) = can_reconstruct_primitive(p, ps, as_, 0);
			for aa in &p.arguments {
				o += verify_analysis_reconstruct(ctx, aa, ps, as_, o, record);
			}
			(r, ar)
		}
		Value::Equation(e) => can_reconstruct_equation(e, as_),
		_ => return o,
	};
	if r && ctx.attacker_put(a, record) {
		info_message(
			&format!(
				"{} obtained by reconstructing with {}.",
				info_output_text(a),
				pretty_values(&ar),
			),
			InfoLevel::Deduction,
			true,
		);
		o += 1;
	}
	o
}

// ---------------------------------------------------------------------------
// Equivalize
// ---------------------------------------------------------------------------

fn verify_analysis_equivalize(
	ctx: &VerifyContext,
	a: &Value,
	ps: &PrincipalState,
	record: &MutationRecord,
) -> usize {
	let ar = if let Value::Constant(c) = a {
		let (resolved, _) = ps.resolve_constant(c, true);
		resolved
	} else {
		a.clone()
	};
	let mut o: usize = 0;
	for sv in &ps.values {
		if ar.equivalent(&sv.assigned, true)
			&& ctx.attacker_put(&sv.assigned, record)
		{
			info_message(
				&format!(
					"{} obtained by equivalizing with the current resolution of {}.",
					info_output_text(&sv.assigned),
					a,
				),
				InfoLevel::Deduction,
				true,
			);
			o += 1;
		}
	}
	o
}

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

fn verify_analysis_passwords(
	ctx: &VerifyContext,
	a: &Value,
	ps: &PrincipalState,
	record: &MutationRecord,
) -> usize {
	let mut o: usize = 0;
	let mut passwords = Vec::new();
	find_obtainable_passwords(a, a, None, ps, &mut passwords);
	for password in &passwords {
		if ctx.attacker_put(password, record) {
			info_message(
				&format!(
					"{} obtained as a password unsafely used within {}.",
					info_output_text(password),
					a,
				),
				InfoLevel::Deduction,
				true,
			);
			o += 1;
		}
	}
	o
}

// ---------------------------------------------------------------------------
// Concat
// ---------------------------------------------------------------------------

fn verify_analysis_concat(ctx: &VerifyContext, a: &Value, record: &MutationRecord) -> usize {
	let p = match a {
		Value::Primitive(p) if p.id == PRIM_CONCAT => p,
		_ => return 0,
	};
	let mut o: usize = 0;
	for arg in &p.arguments {
		if ctx.attacker_put(arg, record) {
			info_message(
				&format!(
					"{} obtained as a concatenated fragment of {}.",
					info_output_text(arg),
					a,
				),
				InfoLevel::Deduction,
				true,
			);
			o += 1;
		}
	}
	o
}
