/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::info::{info_analysis, info_message, info_output_text};
use crate::possible::{
	possible_to_decompose_primitive, possible_to_obtain_passwords,
	possible_to_passively_decompose_primitive, possible_to_recompose_primitive,
	possible_to_reconstruct_equation, possible_to_reconstruct_primitive,
};
use crate::pretty::{pretty_value, pretty_values};
use crate::primitive::PRIM_CONCAT;
use crate::types::*;
use crate::value::{value_equivalent_values, value_nil, value_resolve_constant};
use crate::verify::verify_resolve_queries;

// ---------------------------------------------------------------------------
// Main analysis entry point
// ---------------------------------------------------------------------------

pub fn verify_analysis(
	ctx: &VerifyContext,
	km: &KnowledgeMap,
	ps: &PrincipalState,
	stage: i32,
) -> Result<(), String> {
	let mut current_as = ctx.attacker_snapshot();
	loop {
		if ctx.all_resolved() {
			return Ok(());
		}
		verify_resolve_queries(ctx, km, ps)?;

		let mut o: usize = 0;

		// Phase 1: decompose and passive decompose from attacker known values
		for i in 0..current_as.known.len() {
			o += verify_analysis_decompose(ctx, &current_as.known[i], ps, &current_as);
			if o > 0 {
				break;
			}
			o += verify_analysis_passive_decompose(ctx, &current_as.known[i], ps);
			if o > 0 {
				break;
			}
		}

		// Phase 2: reconstruct and recompose from principal assigned values
		if o == 0 {
			for i in 0..ps.assigned.len() {
				o += verify_analysis_reconstruct(ctx, &ps.assigned[i], ps, &current_as, 0);
				if o > 0 {
					break;
				}
				o += verify_analysis_recompose(ctx, &ps.assigned[i], ps, &current_as);
				if o > 0 {
					break;
				}
			}
		}

		// Phase 3: equivalize, passwords, and concat from attacker known values
		if o == 0 {
			for i in 0..current_as.known.len() {
				o += verify_analysis_equivalize(ctx, &current_as.known[i], ps);
				if o > 0 {
					break;
				}
				o += verify_analysis_passwords(ctx, &current_as.known[i], ps);
				if o > 0 {
					break;
				}
				o += verify_analysis_concat(ctx, &current_as.known[i], ps);
				if o > 0 {
					break;
				}
			}
		}

		if o > 0 {
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
) -> usize {
	let mut o: usize = 0;
	let mut r = false;
	let mut revealed = value_nil();
	let mut ar: Vec<Value> = Vec::new();
	if let Value::Primitive(p) = a {
		let result = possible_to_decompose_primitive(p, ps, as_, 0);
		r = result.0;
		revealed = result.1;
		ar = result.2;
	}
	if r && ctx.attacker_put(&revealed, ps) {
		info_message(
			&format!(
				"{} obtained by decomposing {} with {}.",
				info_output_text(&revealed),
				pretty_value(a),
				pretty_values(&ar),
			),
			"deduction",
			true,
		);
		o += 1;
	}
	o
}

// ---------------------------------------------------------------------------
// Passive decompose
// ---------------------------------------------------------------------------

fn verify_analysis_passive_decompose(ctx: &VerifyContext, a: &Value, ps: &PrincipalState) -> usize {
	let mut o: usize = 0;
	if let Value::Primitive(p) = a {
		let passive_revealed = possible_to_passively_decompose_primitive(p);
		for revealed in &passive_revealed {
			if ctx.attacker_put(revealed, ps) {
				info_message(
					&format!(
						"{} obtained as associated data from {}.",
						info_output_text(revealed),
						pretty_value(a),
					),
					"deduction",
					true,
				);
				o += 1;
			}
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
	ps: &PrincipalState,
	as_: &AttackerState,
) -> usize {
	let mut o: usize = 0;
	let mut r = false;
	let mut revealed = value_nil();
	let mut ar: Vec<Value> = Vec::new();
	if let Value::Primitive(p) = a {
		let result = possible_to_recompose_primitive(p, as_);
		r = result.0;
		revealed = result.1;
		ar = result.2;
	}
	if r && ctx.attacker_put(&revealed, ps) {
		info_message(
			&format!(
				"{} obtained by recomposing {} with {}.",
				info_output_text(&revealed),
				pretty_value(a),
				pretty_values(&ar),
			),
			"deduction",
			true,
		);
		o += 1;
	}
	o
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
) -> usize {
	let mut r = false;
	let mut ar: Vec<Value> = Vec::new();
	match a {
		Value::Primitive(p) => {
			let result = possible_to_reconstruct_primitive(p, ps, as_, 0);
			r = result.0;
			ar = result.1;
			for aa in &p.arguments {
				o += verify_analysis_reconstruct(ctx, aa, ps, as_, o);
			}
		}
		Value::Equation(e) => {
			let result = possible_to_reconstruct_equation(e, as_);
			r = result.0;
			ar = result.1;
		}
		_ => {}
	}
	if r && ctx.attacker_put(a, ps) {
		info_message(
			&format!(
				"{} obtained by reconstructing with {}.",
				info_output_text(a),
				pretty_values(&ar),
			),
			"deduction",
			true,
		);
		o += 1;
	}
	o
}

// ---------------------------------------------------------------------------
// Equivalize
// ---------------------------------------------------------------------------

fn verify_analysis_equivalize(ctx: &VerifyContext, a: &Value, ps: &PrincipalState) -> usize {
	let mut o: usize = 0;
	let ar = match a {
		Value::Constant(c) => {
			let (resolved, _) = value_resolve_constant(c, ps, true);
			resolved
		}
		_ => a.clone(),
	};
	for i in 0..ps.assigned.len() {
		if value_equivalent_values(&ar, &ps.assigned[i], true)
			&& ctx.attacker_put(&ps.assigned[i], ps)
		{
			info_message(
				&format!(
					"{} obtained by equivalizing with the current resolution of {}.",
					info_output_text(&ps.assigned[i]),
					pretty_value(a),
				),
				"deduction",
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

fn verify_analysis_passwords(ctx: &VerifyContext, a: &Value, ps: &PrincipalState) -> usize {
	let mut o: usize = 0;
	let passwords = possible_to_obtain_passwords(a, a, -1, ps);
	for password in &passwords {
		if ctx.attacker_put(password, ps) {
			info_message(
				&format!(
					"{} obtained as a password unsafely used within {}.",
					info_output_text(password),
					pretty_value(a),
				),
				"deduction",
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

fn verify_analysis_concat(ctx: &VerifyContext, a: &Value, ps: &PrincipalState) -> usize {
	let mut o: usize = 0;
	if let Value::Primitive(p) = a {
		if p.id == PRIM_CONCAT {
			for arg in &p.arguments {
				if ctx.attacker_put(arg, ps) {
					info_message(
						&format!(
							"{} obtained as a concatenated fragment of {}.",
							info_output_text(arg),
							pretty_value(a),
						),
						"deduction",
						true,
					);
					o += 1;
				}
			}
		}
	}
	o
}
