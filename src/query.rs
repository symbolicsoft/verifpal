/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::info::*;
use crate::possible::*;
use crate::primitive::*;
use crate::principal::*;
use crate::types::*;
use crate::value::*;

pub fn query_start(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> VResult<()> {
	let attacker = ctx.attacker_snapshot();
	match query.kind {
		QueryKind::Confidentiality => {
			query_confidentiality(ctx, query, query_index, km, ps, &attacker);
		}
		QueryKind::Authentication => {
			query_authentication(ctx, query, query_index, km, ps, &attacker);
		}
		QueryKind::Freshness => {
			query_freshness(ctx, query, query_index, km, ps, &attacker)?;
		}
		QueryKind::Unlinkability => {
			query_unlinkability(ctx, query, query_index, km, ps, &attacker)?;
		}
		QueryKind::Equivalence => {
			query_equivalence(ctx, query, query_index, km, ps, &attacker);
		}
	}
	Ok(())
}

/// Write a resolved query result and log it. Returns true if newly written.
fn emit_query_result(ctx: &VerifyContext, result: &VerifyResult) {
	if ctx.results_put(result) {
		info_message(
			&format!("{}{}", &result.query, result.summary),
			InfoLevel::Result,
			true,
		);
	}
}

fn query_confidentiality(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> VerifyResult {
	let mut result = VerifyResult::new(query, query_index);
	let slot_idx = match ps.index_of(&query.constants[0]) {
		Some(idx) => idx,
		None => return result,
	};
	let resolved_value = &ps.values[slot_idx].value;
	let attacker_idx = match attacker.knows(resolved_value) {
		Some(idx) => idx,
		None => return result,
	};
	let mutated_info = info_query_mutated_values(
		km,
		&attacker.mutation_records[attacker_idx].diffs,
		attacker,
		resolved_value,
		0,
	);
	result.resolved = true;
	result.summary = info_verify_result_summary(
		&mutated_info,
		&format!(
			"{} ({}) is obtained by Attacker.",
			query.constants[0], attacker.known[attacker_idx],
		),
		&result.options,
	);
	result = query_precondition(result, ps);
	emit_query_result(ctx, &result);
	result
}

fn query_authentication(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> VerifyResult {
	let mut result = VerifyResult::new(query, query_index);
	if query.message.recipient != ps.id {
		return result;
	}
	let (indices, sender, c) = query_authentication_get_pass_indices(query, km, ps);
	for &index in &indices {
		if query.message.sender == sender {
			continue;
		}
		result.resolved = true;
		let assigned = &ps.values[index].value;
		let before = &ps.values[index].pre_rewrite;
		let diffs = compute_slot_diffs(ps, km);
		let mutated_info = info_query_mutated_values(km, &diffs.diffs, attacker, assigned, 0);
		result = query_precondition(result, ps);
		return query_authentication_handle_pass(
			ctx,
			result,
			&c,
			before,
			&mutated_info,
			sender,
			ps,
		);
	}
	result
}

/// Find indices of PrincipalState slots where constant `c` is used inside a
/// primitive by this principal, and the primitive either has no rewrite rule,
/// or its rewrite succeeds, or it's unchecked. Returns `None` if a constant
/// resolution fails (caller should bail).
fn query_find_constant_usage_indices(
	c: &Constant,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> Option<Vec<usize>> {
	let mut indices = Vec::new();
	for slot in &km.slots {
		if slot.creator != ps.id {
			continue;
		}
		if !matches!(&slot.initial_value, Value::Primitive(_)) {
			continue;
		}
		if !find_constant_in_trace_primitive(c, &slot.initial_value, km) {
			continue;
		}
		let (_, slot_idx) = ps.resolve_constant(&slot.constant, true);
		let slot_idx = slot_idx?;
		let before = &ps.values[slot_idx].pre_rewrite;
		let before_prim = match before {
			Value::Primitive(p) => p,
			_ => continue,
		};
		if !primitive_has_rewrite_rule(before_prim.id) {
			indices.push(slot_idx);
			continue;
		}
		let (pass, _) = can_rewrite(before_prim, ps, 0);
		if pass || !before_prim.instance_check {
			indices.push(slot_idx);
		}
	}
	Some(indices)
}

fn query_authentication_get_pass_indices(
	query: &Query,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> (Vec<usize>, PrincipalId, Constant) {
	let empty_c = Constant::default();
	let (_, idx) = ps.resolve_constant(&query.message.constants[0], true);
	let idx = match idx {
		Some(i) => i,
		None => return (vec![], 0, empty_c),
	};
	let c = km.slots[idx].constant.clone();
	let sender = ps.values[idx].provenance.sender;
	if sender == ATTACKER_ID {
		let v = &ps.values[idx].original;
		if v.equivalent(&ps.values[idx].value, true) {
			return (vec![], sender, c);
		}
	}
	let indices = query_find_constant_usage_indices(&c, km, ps).unwrap_or_default();
	(indices, sender, c)
}

fn query_authentication_handle_pass(
	ctx: &VerifyContext,
	mut result: VerifyResult,
	c: &Constant,
	b: &Value,
	mutated_info: &str,
	sender: PrincipalId,
	ps: &PrincipalState,
) -> VerifyResult {
	let (resolved, _) = ps.resolve_constant(c, true);
	result.summary = info_verify_result_summary(
		mutated_info,
		&format!(
			"{} ({}), sent by {} and not by {}, is successfully used in {} within {}'s state.",
			c,
			resolved,
			principal_get_name_from_id(sender),
			principal_get_name_from_id(result.query.message.sender),
			b,
			principal_get_name_from_id(result.query.message.recipient),
		),
		&result.options,
	);
	emit_query_result(ctx, &result);
	result
}

fn query_freshness(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> VResult<VerifyResult> {
	let mut result = VerifyResult::new(query, query_index);
	let freshness_found = value_constant_contains_fresh_values(&query.constants[0], ps)?;
	if freshness_found {
		return Ok(result);
	}
	let indices = match query_find_constant_usage_indices(&query.constants[0], km, ps) {
		Some(v) => v,
		None => return Ok(result),
	};
	if indices.is_empty() {
		return Ok(result);
	}
	let (resolved, _) = ps.resolve_constant(&query.constants[0], true);
	let diffs = compute_slot_diffs(ps, km);
	let mutated_info = info_query_mutated_values(km, &diffs.diffs, attacker, &resolved, 0);
	result.resolved = true;
	result.summary = info_verify_result_summary(
		&mutated_info,
		&format!(
			"{} ({}) is used by {} in {} despite not being a fresh value.",
			query.constants[0], resolved, ps.name, ps.values[indices[0]].pre_rewrite,
		),
		&result.options,
	);
	result = query_precondition(result, ps);
	emit_query_result(ctx, &result);
	Ok(result)
}

fn query_unlinkability(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> VResult<VerifyResult> {
	let mut result = VerifyResult::new(query, query_index);
	let mut no_freshness = Vec::new();
	for c in &query.constants {
		let found = value_constant_contains_fresh_values(c, ps)?;
		if !found {
			no_freshness.push(c.clone());
		}
	}
	if !no_freshness.is_empty() {
		let (resolved, _) = ps.resolve_constant(&no_freshness[0], true);
		let diffs = compute_slot_diffs(ps, km);
		let mutated_info = info_query_mutated_values(km, &diffs.diffs, attacker, &resolved, 0);
		result.resolved = true;
		result.summary = info_verify_result_summary(&mutated_info, &format!(
            "{} ({}) cannot be a suitable unlinkability candidate since it does not satisfy freshness.",
            no_freshness[0], resolved,
        ), &result.options);
		result = query_precondition(result, ps);
		emit_query_result(ctx, &result);
		return Ok(result);
	}
	let resolved_values: Vec<Value> = query
		.constants
		.iter()
		.map(|c| ps.resolve_constant(c, true).0)
		.collect();
	for (i, val_a) in resolved_values.iter().enumerate() {
		for (j, val_b) in resolved_values.iter().enumerate() {
			if i == j {
				continue;
			}
			if !val_a.equivalent(val_b, false) {
				continue;
			}
			let obtainable = match val_a {
				Value::Primitive(p) => {
					can_reconstruct_primitive(p, ps, attacker, 0).is_some()
						|| can_recompose(p, attacker).is_some()
				}
				_ => false,
			};
			if !obtainable {
				continue;
			}
			let empty = Value::Constant(Constant::default());
			let diffs = compute_slot_diffs(ps, km);
			let mutated_info = info_query_mutated_values(km, &diffs.diffs, attacker, &empty, 0);
			result.resolved = true;
			result.summary = info_verify_result_summary(&mutated_info, &format!(
                "{} and {} are not unlinkable since they are the output of the same primitive ({}), which can be obtained by Attacker",
                query.constants[i], query.constants[j],
                resolved_values[i],
            ), &result.options);
			result = query_precondition(result, ps);
			emit_query_result(ctx, &result);
			return Ok(result);
		}
	}
	Ok(result)
}

fn query_equivalence(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> VerifyResult {
	let mut result = VerifyResult::new(query, query_index);
	let values: Vec<Value> = query
		.constants
		.iter()
		.map(|c| ps.resolve_constant(c, false).0)
		.collect();
	let all_equivalent = values.windows(2).all(|w| w[0].equivalent(&w[1], true));
	if all_equivalent {
		return result;
	}
	let empty = Value::Constant(Constant::default());
	let diffs = compute_slot_diffs(ps, km);
	let mutated_info = info_query_mutated_values(km, &diffs.diffs, attacker, &empty, 0);
	result.resolved = true;
	result.summary = info_verify_result_summary(
		&mutated_info,
		&format!(
			"{} are not equivalent.",
			values
				.iter()
				.map(|v| v.to_string())
				.collect::<Vec<_>>()
				.join(", "),
		),
		&result.options,
	);
	result = query_precondition(result, ps);
	emit_query_result(ctx, &result);
	result
}

fn query_precondition(mut result: VerifyResult, ps: &PrincipalState) -> VerifyResult {
	if !result.resolved {
		return result;
	}
	for option in &result.query.options {
		let mut option_result = QueryOptionResult {
			resolved: false,
			summary: String::new(),
		};
		let (_, slot_idx) = ps.resolve_constant(&option.message.constants[0], true);
		let idx = match slot_idx {
			Some(idx) => idx,
			None => {
				result.options.push(option_result);
				continue;
			}
		};
		let sender = ps.meta[idx]
			.known_by
			.iter()
			.find_map(|m| m.get(&option.message.recipient).copied());
		if sender == Some(option.message.sender) {
			option_result.resolved = true;
			option_result.summary = format!(
				"{} sends {} to {} despite the query failing.",
				principal_get_name_from_id(option.message.sender),
				option.message.constants[0],
				principal_get_name_from_id(option.message.recipient),
			);
		}
		result.options.push(option_result);
	}
	result
}
