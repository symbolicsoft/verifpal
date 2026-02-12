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
	let as_ = ctx.attacker_snapshot();
	match query.kind {
		QueryKind::Confidentiality => {
			query_confidentiality(ctx, query, query_index, km, ps, &as_);
		}
		QueryKind::Authentication => {
			query_authentication(ctx, query, query_index, km, ps, &as_);
		}
		QueryKind::Freshness => {
			query_freshness(ctx, query, query_index, km, ps, &as_)?;
		}
		QueryKind::Unlinkability => {
			query_unlinkability(ctx, query, query_index, km, ps, &as_)?;
		}
		QueryKind::Equivalence => {
			query_equivalence(ctx, query, query_index, km, ps, &as_);
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
	as_: &AttackerState,
) -> VerifyResult {
	let mut result = VerifyResult::new(query, query_index);
	let i = match ps.index_of(&query.constants[0]) {
		Some(idx) => idx,
		None => return result,
	};
	let resolved_value = &ps.values[i].assigned;
	let ii = match as_.knows(resolved_value) {
		Some(idx) => idx,
		None => return result,
	};
	let mutated_info =
		info_query_mutated_values(km, &as_.mutation_records[ii].diffs, as_, resolved_value, 0);
	result.resolved = true;
	result.summary = info_verify_result_summary(
		&mutated_info,
		&format!(
			"{} ({}) is obtained by Attacker.",
			query.constants[0],
			as_.known[ii],
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
	as_: &AttackerState,
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
		let a = &ps.values[index].assigned;
		let b = &ps.values[index].before_rewrite;
		let diffs = compute_slot_diffs(ps, km);
		let mutated_info = info_query_mutated_values(km, &diffs.diffs, as_, a, 0);
		result = query_precondition(result, ps);
		return query_authentication_handle_pass(ctx, result, &c, b, &mutated_info, sender, ps);
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
		if !value_find_constant_in_primitive_from_protocol_trace(c, &slot.initial_value, km) {
			continue;
		}
		let (_, ii) = ps.resolve_constant(&slot.constant, true);
		let ii_idx = ii?;
		let b = &ps.values[ii_idx].before_rewrite;
		let b_prim = match b {
			Value::Primitive(p) => p,
			_ => continue,
		};
		if !primitive_has_rewrite_rule(b_prim.id) {
			indices.push(ii_idx);
			continue;
		}
		let (pass, _) = can_rewrite(b_prim, ps, 0);
		if pass || !b_prim.check {
			indices.push(ii_idx);
		}
	}
	Some(indices)
}

fn query_authentication_get_pass_indices(
	query: &Query,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> (Vec<usize>, PrincipalId, Constant) {
	let empty_c = Constant::empty();
	let (_, idx) = ps.resolve_constant(&query.message.constants[0], true);
	let idx = match idx {
		Some(i) => i,
		None => return (vec![], 0, empty_c),
	};
	let c = km.slots[idx].constant.clone();
	let sender = ps.values[idx].sender;
	if sender == principal_get_attacker_id() {
		let v = &ps.values[idx].before_mutate;
		if v.equivalent(&ps.values[idx].assigned, true) {
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
	let (cc, _) = ps.resolve_constant(c, true);
	result.summary = info_verify_result_summary(
		mutated_info,
		&format!(
			"{} ({}), sent by {} and not by {}, is successfully used in {} within {}'s state.",
			c,
			cc,
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
	as_: &AttackerState,
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
	let mutated_info = info_query_mutated_values(km, &diffs.diffs, as_, &resolved, 0);
	result.resolved = true;
	result.summary = info_verify_result_summary(
		&mutated_info,
		&format!(
			"{} ({}) is used by {} in {} despite not being a fresh value.",
			query.constants[0],
			resolved,
			ps.name,
			ps.values[indices[0]].before_rewrite,
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
	as_: &AttackerState,
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
		let mutated_info = info_query_mutated_values(km, &diffs.diffs, as_, &resolved, 0);
		result.resolved = true;
		result.summary = info_verify_result_summary(&mutated_info, &format!(
            "{} ({}) cannot be a suitable unlinkability candidate since it does not satisfy freshness.",
            no_freshness[0], resolved,
        ), &result.options);
		result = query_precondition(result, ps);
		emit_query_result(ctx, &result);
		return Ok(result);
	}
	let assigneds: Vec<Value> = query
		.constants
		.iter()
		.map(|c| ps.resolve_constant(c, true).0)
		.collect();
	for (i, ai) in assigneds.iter().enumerate() {
		for (ii, aii) in assigneds.iter().enumerate() {
			if i == ii {
				continue;
			}
			if !ai.equivalent(aii, false) {
				continue;
			}
			let obtainable = match ai {
				Value::Primitive(p) => {
					let (ok0, _) = can_reconstruct_primitive(p, ps, as_, 0);
					let (ok1, _, _) = can_recompose(p, as_);
					ok0 || ok1
				}
				_ => false,
			};
			if !obtainable {
				continue;
			}
			let empty = Value::Constant(Constant::empty());
			let diffs = compute_slot_diffs(ps, km);
			let mutated_info = info_query_mutated_values(km, &diffs.diffs, as_, &empty, 0);
			result.resolved = true;
			result.summary = info_verify_result_summary(&mutated_info, &format!(
                "{} and {} are not unlinkable since they are the output of the same primitive ({}), which can be obtained by Attacker",
                query.constants[i], query.constants[ii],
                assigneds[i],
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
	as_: &AttackerState,
) -> VerifyResult {
	let mut result = VerifyResult::new(query, query_index);
	let values: Vec<Value> = query
		.constants
		.iter()
		.map(|c| ps.resolve_constant(c, false).0)
		.collect();
	let all_equivalent = values
		.windows(2)
		.all(|w| w[0].equivalent(&w[1], true));
	if all_equivalent {
		return result;
	}
	let empty = Value::Constant(Constant::empty());
	let diffs = compute_slot_diffs(ps, km);
	let mutated_info = info_query_mutated_values(km, &diffs.diffs, as_, &empty, 0);
	result.resolved = true;
	result.summary = info_verify_result_summary(
		&mutated_info,
		&format!("{} are not equivalent.", values.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", "),),
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
		let mut o_result = QueryOptionResult {
			resolved: false,
			summary: String::new(),
		};
		let (_, i) = ps.resolve_constant(&option.message.constants[0], true);
		let idx = match i {
			Some(i) => i,
			None => {
				result.options.push(o_result);
				continue;
			}
		};
		let sender = ps.meta[idx]
			.known_by
			.iter()
			.find_map(|m| m.get(&option.message.recipient).copied());
		if sender == Some(option.message.sender) {
			o_result.resolved = true;
			o_result.summary = format!(
				"{} sends {} to {} despite the query failing.",
				principal_get_name_from_id(option.message.sender),
				option.message.constants[0],
				principal_get_name_from_id(option.message.recipient),
			);
		}
		result.options.push(o_result);
	}
	result
}
