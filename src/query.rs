/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::info::*;
use crate::narrate::{Narration, narrate_attack};
use crate::primitive::*;
use crate::principal::*;
use crate::theory::*;
use crate::types::*;
use crate::value::*;
use crate::witness::{in_minimization, minimize_witness};

fn attack_trace(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	query_index: usize,
	target: &Value,
	seed: &[(SlotIdx, Value)],
) -> Narration {
	if in_minimization() {
		return Narration::none();
	}
	let witness = minimize_witness(ctx, km, ps, query_index, seed);
	narrate_attack(km, &witness, target)
}

fn recorded_mutations(attacker: &AttackerState, attacker_idx: KnownIdx) -> Vec<(SlotIdx, Value)> {
	attacker
		.mutation_records
		.get(attacker_idx.get())
		.map(|record| {
			record
				.diffs
				.iter()
				.filter(|d| d.tainted)
				.map(|d| (d.index, d.value.clone()))
				.collect()
		})
		.unwrap_or_default()
}

pub(crate) fn query_start(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> VResult<()> {
	let attacker = ctx.attacker_snapshot();
	match query.kind {
		QueryKind::Confidentiality => {
			query_confidentiality(ctx, query, query_index, km, ps, &attacker)?;
		}
		QueryKind::Authentication => {
			query_authentication(ctx, query, query_index, km, ps, &attacker)?;
		}
		QueryKind::Freshness => {
			query_freshness(ctx, query, query_index, km, ps, &attacker)?;
		}
		QueryKind::Unlinkability => {
			query_unlinkability(ctx, query, query_index, km, ps, &attacker)?;
		}
		QueryKind::Equivalence => {
			query_equivalence(ctx, query, query_index, km, ps, &attacker)?;
		}
	}
	Ok(())
}

fn emit_query_result(ctx: &VerifyContext, result: &VerifyResult) {
	if ctx.results_put(result) {
		info_message(
			&format!("{}{}", result.query, result.summary),
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
) -> VResult<VerifyResult> {
	let mut result = VerifyResult::new(query, query_index);
	let subject = query.subject()?;
	let slot_idx = match ps.index_of(subject) {
		Some(idx) => idx,
		None => return Ok(result),
	};
	let resolved_value = &ps.values[slot_idx].value;
	let attacker_idx = match attacker.knows(resolved_value) {
		Some(idx) => idx,
		None => return Ok(result),
	};
	let seed = recorded_mutations(attacker, attacker_idx);
	let mutated_info = attack_trace(ctx, km, ps, query_index, resolved_value, &seed);
	result.resolved = true;
	result.summary = info_verify_result_summary(
		&mutated_info.trace,
		&format!(
			"{} ({}) is obtained by Attacker.",
			subject,
			mutated_info.term(&attacker.known[attacker_idx.get()]),
		),
		&result.options,
	);
	result = query_precondition(result, ps);
	emit_query_result(ctx, &result);
	Ok(result)
}

fn query_authentication(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> VResult<VerifyResult> {
	let mut result = VerifyResult::new(query, query_index);
	if query.message.recipient != ps.id {
		return Ok(result);
	}
	let (indices, sender, c) = query_authentication_get_pass_indices(query, km, ps)?;
	for &index in &indices {
		if query.message.sender == sender {
			continue;
		}
		result.resolved = true;
		let assigned = &ps.values[index].value;
		let before = &ps.values[index].pre_rewrite;
		let seed = attacker
			.knows(assigned)
			.map(|i| recorded_mutations(attacker, i))
			.unwrap_or_default();
		let mutated_info = attack_trace(ctx, km, ps, query_index, assigned, &seed);
		result = query_precondition(result, ps);
		return Ok(query_authentication_handle_pass(
			ctx,
			result,
			&c,
			before,
			&mutated_info,
			km.principal_name(sender),
			ps,
		));
	}
	Ok(result)
}

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
) -> VResult<(Vec<usize>, PrincipalId, Constant)> {
	let empty_c = Constant::default();
	let (_, idx) = ps.resolve_constant(query.message.constant()?, true);
	let idx = match idx {
		Some(i) => i,
		None => return Ok((vec![], 0, empty_c)),
	};
	let c = km.slots[idx].constant.clone();
	let sender = ps.values[idx].provenance.sender;
	if sender == ATTACKER_ID {
		let v = &ps.values[idx].original;
		if v.equivalent(&ps.values[idx].value, true) {
			return Ok((vec![], sender, c));
		}
	}
	let indices = query_find_constant_usage_indices(&c, km, ps).unwrap_or_default();
	Ok((indices, sender, c))
}

fn query_authentication_handle_pass(
	ctx: &VerifyContext,
	mut result: VerifyResult,
	c: &Constant,
	b: &Value,
	mutated_info: &Narration,
	sender_name: &str,
	ps: &PrincipalState,
) -> VerifyResult {
	let (resolved, _) = ps.resolve_constant(c, true);
	result.summary = info_verify_result_summary(
		&mutated_info.trace,
		&format!(
			"{} ({}), sent by {} and not by {}, is successfully used in {} within {}'s state.",
			c,
			mutated_info.term(&resolved),
			sender_name,
			result.query.message.sender_name,
			mutated_info.term(b),
			result.query.message.recipient_name,
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
	_attacker: &AttackerState,
) -> VResult<VerifyResult> {
	let mut result = VerifyResult::new(query, query_index);
	let subject = query.subject()?;
	let freshness_found = value_constant_contains_fresh_values(subject, ps)?;
	if freshness_found {
		return Ok(result);
	}
	let indices = match query_find_constant_usage_indices(subject, km, ps) {
		Some(v) => v,
		None => return Ok(result),
	};
	if indices.is_empty() {
		return Ok(result);
	}
	let (resolved, _) = ps.resolve_constant(subject, true);
	let mutated_info = attack_trace(ctx, km, ps, query_index, &resolved, &[]);
	result.resolved = true;
	result.summary = info_verify_result_summary(
		&mutated_info.trace,
		&format!(
			"{} ({}) is used by {} in {} despite not being a fresh value.",
			subject,
			mutated_info.term(&resolved),
			ps.name,
			mutated_info.term(&ps.values[indices[0]].pre_rewrite),
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
		let mutated_info = attack_trace(ctx, km, ps, query_index, &resolved, &[]);
		result.resolved = true;
		result.summary = info_verify_result_summary(
			&mutated_info.trace,
			&format!(
				"{} ({}) cannot be a suitable unlinkability candidate since it does not satisfy freshness.",
				no_freshness[0],
				mutated_info.term(&resolved),
			),
			&result.options,
		);
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
			let mutated_info = attack_trace(ctx, km, ps, query_index, &empty, &[]);
			result.resolved = true;
			result.summary = info_verify_result_summary(
				&mutated_info.trace,
				&format!(
					"{} and {} are not unlinkable since they are the output of the same primitive ({}), which can be obtained by Attacker",
					query.constants[i],
					query.constants[j],
					mutated_info.term(&resolved_values[i]),
				),
				&result.options,
			);
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
	_attacker: &AttackerState,
) -> VResult<VerifyResult> {
	let mut result = VerifyResult::new(query, query_index);
	let values: Vec<Value> = query
		.constants
		.iter()
		.map(|c| ps.resolve_constant(c, false).0)
		.collect();
	let all_equivalent = values.windows(2).all(|w| w[0].equivalent(&w[1], true));
	if all_equivalent {
		return Ok(result);
	}
	let empty = Value::Constant(Constant::default());
	let mutated_info = attack_trace(ctx, km, ps, query_index, &empty, &[]);
	result.resolved = true;
	result.summary = info_verify_result_summary(
		&mutated_info.trace,
		&format!(
			"{} are not equivalent.",
			values
				.iter()
				.map(|v| mutated_info.term(v))
				.collect::<Vec<_>>()
				.join(", "),
		),
		&result.options,
	);
	result = query_precondition(result, ps);
	emit_query_result(ctx, &result);
	Ok(result)
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
		let Ok(option_constant) = option.message.constant() else {
			result.options.push(option_result);
			continue;
		};
		let (_, slot_idx) = ps.resolve_constant(option_constant, true);
		let idx = match slot_idx {
			Some(idx) => idx,
			None => {
				result.options.push(option_result);
				continue;
			}
		};
		let sender = ps.meta[idx].known_by.iter().find_map(|&(recipient, from)| {
			if recipient == option.message.recipient {
				Some(from)
			} else {
				None
			}
		});
		if sender == Some(option.message.sender) {
			option_result.resolved = true;
			option_result.summary = format!(
				"{} sends {} to {} despite the query failing.",
				option.message.sender_name, option_constant, option.message.recipient_name,
			);
		}
		result.options.push(option_result);
	}
	result
}
