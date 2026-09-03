/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
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
	target: impl Fn(&PrincipalState) -> Value,
	seed: &[(SlotIdx, Value)],
) -> Narration {
	attack_trace_with(ctx, km, ps, query_index, target, seed, |_| Vec::new())
}

#[allow(clippy::too_many_arguments)]
fn attack_trace_with(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	query_index: usize,
	target: impl Fn(&PrincipalState) -> Value,
	seed: &[(SlotIdx, Value)],
	prelude: impl Fn(&PrincipalState) -> Vec<crate::narrate::Step>,
) -> Narration {
	if in_minimization() {
		return Narration::none(target(ps));
	}
	let ambient = ctx.attacker_snapshot();
	let witness = minimize_witness(ctx, km, ps, query_index, seed);
	#[cfg(test)]
	ctx.witness_put(
		query_index,
		ResultWitness {
			installs: witness.installs.clone(),
			wide: witness.wide,
			narrated: crate::narrate::narrated_installs(&witness.ps),
			principal: witness.ps.id,
			phase: ambient.current_phase,
			reproduced: witness.reproduced,
			out_of_order: witness.out_of_order.clone(),
		},
	);
	let target = target(&witness.ps);
	let narration = narrate_attack(km, &witness, &target, &ambient, prelude(&witness.ps));
	#[cfg(test)]
	crate::tracecheck::assert_trace_is_well_founded(&crate::tracecheck::TraceUnderTest {
		file_name: ctx.results_file_name(),
		query: &ctx.results_get()[query_index].query,
		query_index,
		steps: &narration.steps,
		km,
		ps: &witness.ps,
		attacker: &witness.attacker,
		target: &target,
		phase: ambient.current_phase,
	});
	narration
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
	if !ctx.claims_apply_to(ps.id) {
		return Ok(());
	}
	if !ps.answers_for(&query.constants) || !ps.answers_for(&query.message.constants) {
		return Ok(());
	}
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

pub(crate) struct QueryVerdict(());

#[cfg(test)]
impl QueryVerdict {
	pub(crate) fn for_test() -> QueryVerdict {
		QueryVerdict(())
	}
}

fn emit_query_result(ctx: &VerifyContext, result: &VerifyResult) {
	if ctx.results_put(result, &QueryVerdict(())) {
		let headline = crate::pretty::query_line(&result.query);
		let qualifier = result.subtype.map(Subtype::qualifier).unwrap_or_default();
		crate::info::info_analysis_result(&headline, || {
			format!("{}{}{}", headline, qualifier, result.summary)
		});
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
	if ps.slot_unreached(slot_idx) {
		return Ok(result);
	}
	let resolved_value = &ps.values[slot_idx].value;
	let attacker_idx = match attacker.knows(resolved_value) {
		Some(idx) => idx,
		None => return Ok(result),
	};
	let Some(options) = preconditions_reached(query, km, ps, attacker.current_phase) else {
		return Ok(result);
	};
	let seed = recorded_mutations(attacker, attacker_idx);
	let mutated_info = attack_trace(
		ctx,
		km,
		ps,
		query_index,
		|state| {
			state
				.index_of(subject)
				.filter(|&i| !state.slot_unreached(i))
				.map(|i| state.values[i].value.clone())
				.unwrap_or_else(|| resolved_value.clone())
		},
		&seed,
	);
	result.resolved = true;
	result.options = options;
	result.subtype = attacker_supplied(&mutated_info.target, km, ps, slot_idx);
	let conclusion = match result.subtype {
		Some(_) => format!(
			"{} ({}) is obtained by Attacker, but that is the value the attacker put \
			 there: it carries nothing {} generated or holds privately, so the honest \
			 {} is not shown to be disclosed.",
			subject,
			mutated_info.term_excluding(&mutated_info.target, &[&subject.name]),
			ps.name,
			subject,
		),
		None => format!(
			"{} ({}) is obtained by Attacker.",
			subject,
			mutated_info.term_excluding(&mutated_info.target, &[&subject.name]),
		),
	};
	result.set_summary(&mutated_info.trace, mutated_info.kinded(), &conclusion);
	emit_query_result(ctx, &result);
	Ok(result)
}

fn attacker_supplied(
	target: &Value,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	slot: usize,
) -> Option<Subtype> {
	let honest = km
		.slots
		.get(slot)
		.map(|s| reduce_once(&resolve_trace_constant(&s.constant, km)))?;
	if reduce_once(target).equivalent(&honest, true) {
		return None;
	}
	let mut seen = Vec::new();
	(!carries_a_secret(target, ps, &mut seen)).then_some(Subtype::AttackerSuppliedValue)
}

fn carries_a_secret(v: &Value, ps: &PrincipalState, seen: &mut Vec<ValueId>) -> bool {
	match v {
		Value::Constant(c) => {
			let declared = ps.index_of(c).map(|i| &ps.meta[i].constant).unwrap_or(c);
			if declared.fresh || declared.qualifier == Some(Qualifier::Private) {
				return true;
			}
			if seen.contains(&c.id) {
				return false;
			}
			seen.push(c.id);
			match ps.index_of(c) {
				Some(i) => match &ps.values[i].value {
					Value::Constant(inner) if inner.id == c.id => false,
					inner => carries_a_secret(&inner.clone(), ps, seen),
				},
				None => false,
			}
		}
		Value::Primitive(p) => p.arguments.iter().any(|a| carries_a_secret(a, ps, seen)),
	}
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
	let (indices, sender, c, sibling_replay) =
		query_authentication_get_pass_indices(ctx, query, query_index, km, ps, attacker)?;
	if query.message.sender == sender {
		return Ok(result);
	}
	let Some(&index) = indices.first() else {
		return Ok(result);
	};
	let Some(options) = preconditions_reached(query, km, ps, attacker.current_phase) else {
		return Ok(result);
	};
	result.resolved = true;
	result.options = options;
	let assigned = &ps.values[index].value;
	let before = match (&ps.values[index].bypassed, km.slots.get(index)) {
		(Some(_), Some(slot)) => &slot.initial_value,
		_ => &ps.values[index].pre_rewrite,
	};
	let seed = attacker
		.knows(assigned)
		.map(|i| recorded_mutations(attacker, i))
		.unwrap_or_default();
	let prelude = |state: &PrincipalState| {
		if sender == ATTACKER_ID {
			return Vec::new();
		}
		let Some(_idx) = state.index_of(&c) else {
			return Vec::new();
		};
		vec![crate::narrate::Step::Received {
			name: std::sync::Arc::clone(&c.name),
			sender: std::sync::Arc::from(km.principal_name(sender)),
			recipient: std::sync::Arc::from(state.name.as_str()),
			#[cfg(test)]
			slot: SlotIdx(_idx),
		}]
	};
	let mutated_info = attack_trace_with(
		ctx,
		km,
		ps,
		query_index,
		|_| assigned.clone(),
		&seed,
		prelude,
	);
	let witnessed = mutated_info.state().and_then(|w| {
		let used = query_find_constant_usage_indices(&c, km, w)?;
		let &i = used.first()?;
		Some(km.slots.get(i)?.initial_value.clone())
	});
	result.subtype = sibling_replay.then(|| {
		if recipient_contributed(&c, km, ps) {
			Subtype::DuplicateAcceptance
		} else {
			Subtype::ReplayableFirstFlight
		}
	});
	Ok(query_authentication_handle_pass(
		ctx,
		result,
		&c,
		witnessed.as_ref().unwrap_or(before),
		&mutated_info,
		if sibling_replay {
			AuthFailure::Replayed
		} else {
			AuthFailure::Substituted(km.principal_name(sender))
		},
		ps,
	))
}

enum AuthFailure<'a> {
	Substituted(&'a str),
	Replayed,
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
		if !crate::resolution::state_mentions(&slot.initial_value, km, ps, ps.id, c.id) {
			continue;
		}
		let (_, slot_idx) = ps.resolve_constant(&slot.constant, true);
		let slot_idx = slot_idx?;
		if ps.slot_unreached(slot_idx) {
			return None;
		}
		let before = &ps.values[slot_idx].pre_rewrite;
		let before_prim = match before {
			Value::Primitive(p) => p,
			_ => continue,
		};
		if !primitive_has_rewrite_rule(before_prim.id) {
			indices.push(slot_idx);
			continue;
		}
		let (pass, _) = can_rewrite(before_prim);
		if pass || !before_prim.instance_check {
			indices.push(slot_idx);
		}
	}
	Some(indices)
}

fn query_authentication_get_pass_indices(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> VResult<(Vec<usize>, PrincipalId, Constant, bool)> {
	let empty_c = Constant::default();
	let (_, idx) = ps.resolve_constant(query.message.constant()?, true);
	let idx = match idx {
		Some(i) => i,
		None => return Ok((vec![], 0, empty_c, false)),
	};
	let c = km.slots[idx].constant.clone();
	let sender = ps.values[idx].provenance.sender;
	let mut sibling_replay = false;
	if sender == ATTACKER_ID {
		let v = &ps.values[idx].original;
		if v.equivalent(&ps.values[idx].value, true) {
			return Ok((vec![], sender, c, false));
		}
		sibling_replay = session_sibling_replay(&c, &ps.values[idx].value, km);
		if sibling_replay && !recipient_contributed(&c, km, ps) {
			note_origin_only(ctx, query, query_index);
		}
		if !sibling_replay
			&& crate::agreement::emitted_by_matching_run(
				ctx,
				km,
				ps,
				idx,
				query.message.sender,
				attacker,
			) {
			return Ok((vec![], query.message.sender, c, false));
		}
	}
	let indices = query_find_constant_usage_indices(&c, km, ps).unwrap_or_default();
	Ok((indices, sender, c, sibling_replay))
}

fn recipient_contributed(c: &Constant, km: &ProtocolTrace, ps: &PrincipalState) -> bool {
	let resolved = crate::value::resolve_trace_constant(c, km);
	let mut constants = Vec::new();
	resolved.collect_constants(&mut constants);
	constants.iter().any(|inner| {
		km.index_of(inner).is_some_and(|i| {
			let slot = &km.slots[i];
			slot.constant.fresh && km.same_actor(slot.creator, ps.id)
		})
	})
}

fn note_origin_only(ctx: &VerifyContext, query: &Query, query_index: usize) {
	if !ctx.note_origin_only(query_index) {
		return;
	}
	crate::info::info_message(
		&format!(
			"{} reports a duplicate that {} cannot rule out on its own: it contributes \
			 nothing to {} before accepting it, so any run of it takes the same message \
			 twice. Read it as a replay-protection question about this flight rather \
			 than as a forgery.",
			crate::pretty::query_display(query),
			query.message.recipient_name,
			query
				.message
				.constants
				.first()
				.map(|c| c.name.to_string())
				.unwrap_or_default(),
		),
		InfoLevel::Info,
		false,
	);
}

pub(crate) fn session_sibling_values(c: &Constant, km: &ProtocolTrace) -> Vec<Value> {
	let Some(group) = km.session_siblings.get(&c.id) else {
		return Vec::new();
	};
	group
		.iter()
		.filter(|&&sid| sid != c.id)
		.filter_map(|&sid| {
			let &slot = km.index.get(&sid)?;
			Some(resolve_trace_constant(&km.slots[slot].constant, km))
		})
		.collect()
}

pub(crate) fn session_sibling_replay(c: &Constant, used: &Value, km: &ProtocolTrace) -> bool {
	let used_reduct = reduce_once(used);
	session_sibling_values(c, km)
		.iter()
		.any(|v| reduce_once(v).equivalent(&used_reduct, true))
}

fn query_authentication_handle_pass(
	ctx: &VerifyContext,
	mut result: VerifyResult,
	c: &Constant,
	b: &Value,
	mutated_info: &Narration,
	failure: AuthFailure<'_>,
	ps: &PrincipalState,
) -> VerifyResult {
	let resolved = mutated_info
		.installed(c)
		.unwrap_or_else(|| ps.resolve_constant(c, true).0);
	let summary = match failure {
		AuthFailure::Replayed => format!(
			"{} ({}), which {} sent in another session and not in this one, is successfully \
			 used in {} within {}'s state: {} sent it once, {} accepts it twice, so agreement \
			 is not injective.",
			c,
			mutated_info.term_excluding(&resolved, &[&c.name]),
			result.query.message.sender_name,
			mutated_info.term_excluding(b, &[]),
			result.query.message.recipient_name,
			result.query.message.sender_name,
			result.query.message.recipient_name,
		),
		AuthFailure::Substituted(sender_name) => format!(
			"{} ({}), sent by {} and not by {}, is successfully used in {} within {}'s state.",
			c,
			mutated_info.term_excluding(&resolved, &[&c.name]),
			sender_name,
			result.query.message.sender_name,
			mutated_info.term_excluding(b, &[]),
			result.query.message.recipient_name,
		),
	};
	result.set_summary(&mutated_info.trace, mutated_info.kinded(), &summary);
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
	let subject = query.subject()?;
	let Some(subject_idx) = ps.index_of(subject) else {
		return Ok(result);
	};
	if ps.slot_unreached(subject_idx) {
		return Ok(result);
	}
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
	let Some(options) = preconditions_reached(query, km, ps, attacker.current_phase) else {
		return Ok(result);
	};
	let (resolved, _) = ps.resolve_constant(subject, true);
	let prelude = |state: &PrincipalState| {
		let (shown, _) = state.resolve_constant(subject, true);
		let leaves = crate::narrate::constant_leaves(&shown);
		if leaves.is_empty() {
			return Vec::new();
		}
		vec![crate::narrate::Step::Static {
			name: std::sync::Arc::clone(&subject.name),
			leaves: leaves
				.iter()
				.map(|c| c.name.to_string())
				.collect::<Vec<_>>()
				.join(", "),
			#[cfg(test)]
			terms: leaves.iter().map(|c| Value::Constant(c.clone())).collect(),
		}]
	};
	let mutated_info =
		attack_trace_with(ctx, km, ps, query_index, |_| resolved.clone(), &[], prelude);
	result.resolved = true;
	result.options = options;
	result.set_summary(
		&mutated_info.trace,
		mutated_info.kinded(),
		&format!(
			"{} ({}) is used by {} in {} despite not being a fresh value.",
			subject,
			mutated_info.term_excluding(&resolved, &[&subject.name]),
			ps.name,
			mutated_info.term(&ps.values[indices[0]].pre_rewrite),
		),
	);
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
	let Some(options) = preconditions_reached(query, km, ps, attacker.current_phase) else {
		return Ok(result);
	};
	for (i, a) in query.constants.iter().enumerate() {
		for b in query.constants.iter().skip(i + 1) {
			let Some(witness) = crate::unlink::find_link_witness(a, b, km, ps, attacker) else {
				continue;
			};
			let mutated_info =
				attack_trace(ctx, km, ps, query_index, |_| witness.value.clone(), &[]);
			let clause = witness.describe(&mutated_info.term(&witness.value));
			result.resolved = true;
			result.options = options;
			result.set_summary(
				&mutated_info.trace,
				mutated_info.kinded(),
				&format!("Attacker links {a} and {b} {clause}."),
			);
			emit_query_result(ctx, &result);
			return Ok(result);
		}
	}
	Ok(result)
}

fn value_check_failed(v: &Value) -> bool {
	match v {
		Value::Primitive(p) => p.instance_check && !can_rewrite(p).0,
		Value::Constant(_) => false,
	}
}

fn query_equivalence(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> VResult<VerifyResult> {
	let mut result = VerifyResult::new(query, query_index);
	let mut values: Vec<Value> = Vec::with_capacity(query.constants.len());
	for c in &query.constants {
		let (value, slot) = ps.resolve_constant(c, false);
		let Some(slot) = slot else {
			return Ok(result);
		};
		if ps.slot_unreached(slot) || value_check_failed(&value) {
			return Ok(result);
		}
		values.push(value);
	}
	let all_equivalent = values.windows(2).all(|w| w[0].equivalent(&w[1], true));
	if all_equivalent {
		return Ok(result);
	}
	let Some(options) = preconditions_reached(query, km, ps, attacker.current_phase) else {
		return Ok(result);
	};
	let empty = Value::Constant(Constant::default());
	let prelude = |state: &PrincipalState| {
		let table = crate::narrate::NameTable::from_state(state);
		let shadowed = crate::narrate::shadowed_names(km, state);
		let mut hidden: Vec<&str> = shadowed.iter().map(|s| &**s).collect();
		query
			.constants
			.iter()
			.filter_map(|c| {
				let (shown, slot) = state.resolve_constant(c, false);
				let _slot = slot?;
				hidden.push(&c.name);
				let rendered = table.compress_excluding(&shown, &hidden);
				hidden.pop();
				Some(crate::narrate::Step::Resolves {
					name: std::sync::Arc::clone(&c.name),
					value: rendered,
					#[cfg(test)]
					slot: SlotIdx(_slot),
					#[cfg(test)]
					term: shown,
				})
			})
			.collect()
	};
	let mutated_info = attack_trace_with(ctx, km, ps, query_index, |_| empty.clone(), &[], prelude);
	result.resolved = true;
	result.options = options;
	result.set_summary(
		&mutated_info.trace,
		mutated_info.kinded(),
		&format!(
			"{} are not equivalent.",
			query
				.constants
				.iter()
				.map(|c| c.name.to_string())
				.collect::<Vec<_>>()
				.join(", "),
		),
	);
	emit_query_result(ctx, &result);
	Ok(result)
}

fn preconditions_reached(
	query: &Query,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	phase: i32,
) -> Option<Vec<QueryOptionResult>> {
	let mut options = Vec::with_capacity(query.options.len());
	for option in &query.options {
		let constant = option.message.constant().ok()?;
		let (_, slot_idx) = ps.resolve_constant(constant, true);
		let slot = km.slots.get(slot_idx?)?;
		let reached = slot.sent_by.iter().any(|event| {
			event.phase <= phase
				&& event.sender == option.message.sender
				&& event.recipient == option.message.recipient
				&& ps.event_reached(km, event.sender, event.declared_at)
		});
		if !reached {
			return None;
		}
		options.push(QueryOptionResult {
			summary: format!(
				"{} still sends {} to {}, so the failure counts.",
				option.message.sender_name, constant, option.message.recipient_name,
			),
		});
	}
	Some(options)
}

#[cfg(test)]
mod behavior_tests {
	use super::*;

	#[test]
	fn a_confidentiality_summary_includes_its_satisfied_precondition() {
		let source = "attacker[passive]\nprincipal Alice[\nknows private qp_secret\ngenerates qp_ack\nleaks qp_secret\n]\nAlice -> Bob: qp_ack\nprincipal Bob[\n_ = HASH(qp_ack)\n]\nqueries[\nconfidentiality? qp_secret[\nprecondition[Alice -> Bob: qp_ack]\n]\n]\n";
		let model = crate::parser::parse_string("precondition.vp", source).expect("parses");
		let result = crate::verify::analyze(&model)
			.expect("analyzes")
			.results_get()
			.remove(0);
		assert!(result.resolved);
		assert_eq!(result.options.len(), 1);
		assert!(result.summary.contains("Alice still sends qp_ack to Bob"));
	}

	#[test]
	fn a_violation_outside_the_precondition_resolves_nothing() {
		let source = "attacker[active]\nprincipal Bob[\nknows private qg_sk\nqg_pk = PUBKEY(qg_sk)\n]\nBob -> Alice: [qg_pk]\nprincipal Alice[\ngenerates qg_a\nqg_ga = PUBKEY(qg_a)\n]\nAlice -> Bob: [qg_ga]\nprincipal Bob[\ngenerates qg_b\nqg_gb = PUBKEY(qg_b)\nqg_sig = SIGN(qg_sk, qg_gb)\nqg_kb = DH_KEX(qg_ga, qg_b)\n]\nBob -> Alice: qg_gb, qg_sig\nprincipal Alice[\nqg_ka = DH_KEX(qg_gb, qg_a)\n_ = SIGNVERIF(qg_pk, qg_gb, qg_sig)?\nqg_done = HASH(qg_ka)\n]\nAlice -> Bob: qg_done\nprincipal Bob[\n_ = ASSERT(qg_done, HASH(qg_kb))?\n]\nqueries[\nconfidentiality? qg_ka\nconfidentiality? qg_ka[\nprecondition[Alice -> Bob: qg_done]\n]\n]\n";
		let model = crate::parser::parse_string("gated.vp", source).expect("parses");
		let results = crate::verify::analyze_sessions(&model, 1)
			.expect("analyzes")
			.results_get();
		assert!(results[0].resolved);
		assert!(!results[1].resolved);
	}

	#[test]
	fn a_future_send_does_not_satisfy_an_earlier_precondition() {
		let source = "attacker[passive]\nprincipal Alice[\nknows private qt_secret\ngenerates qt_ack\nleaks qt_secret\n]\nphase[1]\nAlice -> Bob: qt_ack\nprincipal Bob[\n_ = HASH(qt_ack)\n]\nqueries[\nconfidentiality? qt_secret[\nprecondition[Alice -> Bob: qt_ack]\n]\n]\n";
		let model = crate::parser::parse_string("future-precondition.vp", source).expect("parses");
		let (trace, states) = crate::sanity::sanity(&model).expect("passes sanity");
		let state = states
			.iter()
			.find(|state| state.name == "Alice")
			.expect("Alice exists");
		assert!(preconditions_reached(&model.queries[0], &trace, state, 0).is_none());
		assert!(preconditions_reached(&model.queries[0], &trace, state, 1).is_some());
	}

	#[test]
	fn a_foreign_sender_halt_does_not_hide_an_accepted_substitution() {
		let source = "attacker[active]\nprincipal Alice[\ngenerates qh_m\n]\nAlice -> Bob: qh_m\nprincipal Bob[\nqh_use = HASH(qh_m)\n]\nqueries[\nauthentication? Alice -> Bob: qh_m\n]\n";
		let model = crate::parser::parse_string("foreign-auth-halt.vp", source).expect("parses");
		let (trace, mut states) = crate::sanity::sanity(&model).expect("passes sanity");
		let state = states
			.iter_mut()
			.find(|state| state.name == "Bob")
			.expect("Bob exists");
		let subject = model.queries[0].message.constant().expect("subject exists");
		let slot = state.index_of(subject).expect("subject slot exists");
		state.values[slot].value = value_nil();
		state.values[slot].provenance.sender = ATTACKER_ID;
		state.foreign_halts = vec![(model.queries[0].message.sender, slot)];
		assert!(state.slot_unreached(slot));
		let ctx = crate::context::VerifyContext::new(&model, &[], Vec::new(), 1, None, Vec::new());
		let attacker = crate::testutil::make_attacker_state(vec![]);
		let (indices, sender, _, _) = query_authentication_get_pass_indices(
			&ctx,
			&model.queries[0],
			0,
			&trace,
			state,
			&attacker,
		)
		.expect("evaluates");
		assert!(!indices.is_empty());
		assert_eq!(sender, ATTACKER_ID);
	}

	#[test]
	fn a_sender_halting_before_the_send_puts_the_execution_outside_the_precondition() {
		let source = "attacker[active]\nprincipal Alice[\ngenerates qh_secret, qh_ack\n]\nAlice -> Bob: qh_ack\nprincipal Bob[\n_ = HASH(qh_ack)\n]\nqueries[\nconfidentiality? qh_secret[\nprecondition[Alice -> Bob: qh_ack]\n]\n]\n";
		let model = crate::parser::parse_string("halt.vp", source).expect("parses");
		let (trace, mut states) = crate::sanity::sanity(&model).expect("passes sanity");
		let state = states
			.iter_mut()
			.find(|state| state.name == "Alice")
			.expect("Alice exists");
		let ack = state
			.meta
			.iter()
			.position(|meta| meta.constant.name.as_ref() == "qh_ack")
			.expect("ack exists");
		let sent_at = state.meta[ack].sent_at.expect("ack is sent");
		state.halted_at = Some(sent_at - 1);
		assert!(preconditions_reached(&model.queries[0], &trace, state, 0).is_none());
	}

	#[test]
	fn an_earlier_send_does_not_satisfy_a_later_withheld_precondition() {
		let source = "attacker[active]\nprincipal Alice[\ngenerates qm_secret, qm_ack\n]\nAlice -> Bob: qm_ack\nprincipal Bob[\n_ = HASH(qm_ack)\n]\nAlice -> Charlie: qm_ack\nprincipal Charlie[\n_ = HASH(qm_ack)\n]\nqueries[\nconfidentiality? qm_secret[\nprecondition[Alice -> Charlie: qm_ack]\n]\n]\n";
		let model = crate::parser::parse_string("multi-send-halt.vp", source).expect("parses");
		let (trace, mut states) = crate::sanity::sanity(&model).expect("passes sanity");
		let state = states
			.iter_mut()
			.find(|state| state.name == "Alice")
			.expect("Alice exists");
		let ack = state
			.meta
			.iter()
			.position(|meta| meta.constant.name.as_ref() == "qm_ack")
			.expect("ack exists");
		let second_send = trace.slots[ack]
			.sent_by
			.iter()
			.find(|event| event.recipient == model.queries[0].options[0].message.recipient)
			.map(|event| event.declared_at)
			.expect("second send exists");
		state.halted_at = Some(second_send - 1);
		assert!(preconditions_reached(&model.queries[0], &trace, state, 0).is_none());
	}

	#[test]
	fn a_foreign_halt_does_not_create_equivalence_or_freshness_violations() {
		let source = "attacker[active]\nprincipal Alice[\nknows private qf_k\ngenerates qf_m\nqf_tag = MAC(qf_k, qf_m)\nqf_ax = HASH(qf_m)\n]\nAlice -> Bob: qf_m, qf_tag\nprincipal Bob[\nknows private qf_k\n_ = ASSERT(qf_tag, MAC(qf_k, qf_m))?\nqf_bx = HASH(qf_m)\n]\nBob -> Charlie: [qf_bx]\nprincipal Charlie[\n_ = HASH(qf_bx)\n]\nqueries[\nequivalence? qf_ax, qf_bx\nfreshness? qf_bx\n]\n";
		let model = crate::parser::parse_string("foreign-halt.vp", source).expect("parses");
		let results = crate::verify::analyze_sessions(&model, 1)
			.expect("analyzes")
			.results_get();
		assert_eq!(results.len(), 2);
		assert!(results.iter().all(|result| !result.resolved));
	}
}

#[cfg(test)]
mod tcb_tests {
	use std::fs;
	use std::path::{Path, PathBuf};

	/// Whole files declared `#[cfg(test)] mod ...` in lib.rs: no shipping code.
	const TEST_ONLY: [&str; 2] = ["model_tests.rs", "testutil.rs"];

	fn engine_sources() -> Vec<PathBuf> {
		fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
			for entry in fs::read_dir(dir).expect("read src/").flatten() {
				let path = entry.path();
				if path.is_dir() {
					walk(&path, out);
				} else if path.extension().is_some_and(|e| e == "rs") {
					let name = path.file_name().unwrap_or_default().to_string_lossy();
					if !TEST_ONLY.contains(&name.as_ref()) {
						out.push(path);
					}
				}
			}
		}
		let mut out = Vec::new();
		walk(
			Path::new(env!("CARGO_MANIFEST_DIR")).join("src").as_path(),
			&mut out,
		);
		out.sort();
		out
	}

	/// The lines of `path` that ship, with `#[cfg(test)]` modules removed.
	fn shipping_lines(path: &Path) -> Vec<(usize, String)> {
		let text = fs::read_to_string(path).expect("read source");
		let lines: Vec<&str> = text.lines().collect();
		let mut out = Vec::new();
		let mut i = 0;
		while i < lines.len() {
			let is_test_attr = lines[i].trim() == "#[cfg(test)]";
			let opens_mod = lines
				.get(i + 1)
				.is_some_and(|l| l.trim_start().starts_with("mod ") && l.trim_end().ends_with('{'));
			if is_test_attr && opens_mod {
				let mut depth = 0i32;
				i += 1;
				while i < lines.len() {
					depth += lines[i].matches('{').count() as i32;
					depth -= lines[i].matches('}').count() as i32;
					i += 1;
					if depth <= 0 {
						break;
					}
				}
				continue;
			}
			out.push((i + 1, lines[i].to_string()));
			i += 1;
		}
		out
	}

	fn relative(path: &Path) -> String {
		path.strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
			.unwrap_or(path)
			.to_string_lossy()
			.into_owned()
	}

	fn engine_source(relative_path: &str) -> PathBuf {
		Path::new(env!("CARGO_MANIFEST_DIR"))
			.join("src")
			.join(relative_path)
	}

	fn block_lines(path: &Path, is_header: impl Fn(&str) -> bool) -> Vec<(usize, String)> {
		let lines = shipping_lines(path);
		let Some(start) = lines
			.iter()
			.position(|(_, line)| is_header(line.trim_start()))
		else {
			return Vec::new();
		};
		let mut depth = 0i32;
		let mut opened = false;
		let mut out = Vec::new();
		for entry in &lines[start..] {
			depth += entry.1.matches('{').count() as i32;
			depth -= entry.1.matches('}').count() as i32;
			out.push(entry.clone());
			opened |= depth > 0;
			if opened && depth <= 0 {
				break;
			}
		}
		out
	}

	fn fn_body(path: &Path, name: &str) -> Vec<(usize, String)> {
		let bare = format!("fn {name}(");
		let exported = format!("pub(crate) fn {name}(");
		block_lines(path, |header| {
			header.starts_with(&bare) || header.starts_with(&exported)
		})
	}

	fn fn_parameter_types(path: &Path, name: &str) -> Vec<String> {
		let body = fn_body(path, name);
		let mut out = Vec::new();
		for (_, line) in body.iter().skip(1) {
			let trimmed = line.trim();
			if trimmed.starts_with(')') {
				break;
			}
			if let Some((_, ty)) = trimmed.split_once(": ") {
				out.push(ty.trim_end_matches(',').trim().to_string());
			}
		}
		out
	}

	fn body_hits(body: &[(usize, String)], needle: &str) -> Vec<usize> {
		body.iter()
			.enumerate()
			.filter(|(_, (_, line))| line.contains(needle))
			.map(|(i, _)| i)
			.collect()
	}

	/// The files containing shipping call sites of `name`, with a count each.
	fn call_site_files(name: &str) -> Vec<(String, usize)> {
		let mut counts: Vec<(String, usize)> = Vec::new();
		for site in call_sites(name) {
			let file = site
				.rsplit_once(':')
				.map(|(f, _)| f.to_string())
				.unwrap_or(site);
			match counts.iter_mut().find(|(f, _)| *f == file) {
				Some((_, n)) => *n += 1,
				None => counts.push((file, 1)),
			}
		}
		counts.sort();
		counts
	}

	/// Every shipping call site of `name`, excluding its definition and `use`.
	fn call_sites(name: &str) -> Vec<String> {
		let needle = format!("{name}(");
		let mut sites = Vec::new();
		for path in engine_sources() {
			let rel = relative(&path);
			for (number, line) in shipping_lines(&path) {
				if !line.contains(&needle) {
					continue;
				}
				let trimmed = line.trim_start();
				if trimmed.starts_with("use ") || trimmed.contains(&format!("fn {name}")) {
					continue;
				}
				sites.push(format!("{rel}:{number}"));
			}
		}
		sites
	}

	#[test]
	fn a_query_result_has_exactly_one_write_path() {
		assert_eq!(
			call_site_files("results_put"),
			vec![("query.rs".to_string(), 1)],
			"`results_put` is the only way to record a query result, and it must \
			 keep exactly one caller. Adding a second write path invalidates fact \
			 (i) of the soundness theorem."
		);
	}

	#[test]
	fn results_are_recorded_only_by_query_evaluation() {
		assert_eq!(
			call_site_files("emit_query_result"),
			vec![("query.rs".to_string(), 5)],
			"fact (ii) of the soundness theorem: one call per query kind, every \
			 one of them inside query.rs."
		);
	}

	#[test]
	fn query_evaluation_is_entered_only_over_an_executed_state() {
		assert_eq!(
			call_site_files("verify_resolve_queries"),
			vec![
				("solve/validate.rs".to_string(), 1),
				("verify.rs".to_string(), 1),
				("witness.rs".to_string(), 1),
			],
			"fact (iv) of the soundness theorem: query evaluation runs over the \
			 honest run (verify.rs), over a re-executed state (validate.rs), or \
			 over a minimizer probe against a scratch context (witness.rs), and \
			 nowhere else. A new call site must be shown to hand it a state that \
			 was concretely executed."
		);
	}

	#[test]
	fn a_query_evaluator_is_handed_states_and_nothing_else() {
		const ALLOWED: [&str; 6] = [
			"&VerifyContext",
			"&Query",
			"usize",
			"&ProtocolTrace",
			"&PrincipalState",
			"&AttackerState",
		];
		let query_rs = engine_source("query.rs");

		let mut evaluators: Vec<String> = fn_body(&query_rs, "query_start")
			.iter()
			.filter_map(|(_, line)| {
				let trimmed = line.trim();
				if !trimmed.starts_with("query_") {
					return None;
				}
				trimmed.split_once('(').map(|(name, _)| name.to_string())
			})
			.collect();
		evaluators.sort();
		evaluators.dedup();

		assert_eq!(
			evaluators.len(),
			5,
			"fact (ii) again, from the dispatch side: `query_start` calls exactly one \
			 evaluator per query kind. Found {evaluators:?}"
		);

		for name in &evaluators {
			let types = fn_parameter_types(&query_rs, name);
			assert!(
				types.iter().any(|t| t == "&PrincipalState")
					&& types.iter().any(|t| t == "&AttackerState"),
				"fact (iii) of the soundness theorem: {name} must compute its violation \
				 predicate from a PrincipalState and an AttackerState, so it has to be \
				 handed both. Its parameters are {types:?}"
			);
			for ty in &types {
				assert!(
					ALLOWED.contains(&ty.as_str()),
					"fact (iii) of the soundness theorem: an evaluator takes no verdict, \
					 score or justification from a caller — all a caller decides is which \
					 state it is handed. {name} takes a {ty}, which is outside that set. A \
					 parameter carrying a decision made elsewhere would put that decision \
					 inside the one write path."
				);
			}
		}
	}

	#[test]
	fn an_install_is_proven_controllable_then_derivable_before_it_is_executed() {
		let validate_rs = engine_source("solve/validate.rs");
		let body = fn_body(&validate_rs, "validate");
		assert!(
			!body.is_empty(),
			"solve/validate.rs must define `fn validate`: it is the only route from the \
			 search into query evaluation"
		);

		let once = |needle: &str| -> usize {
			let hits = body_hits(&body, needle);
			assert_eq!(
				hits.len(),
				1,
				"`{needle}` must appear exactly once in `fn validate`; a second one is a \
				 second policy for the same decision. Found {hits:?}"
			);
			hits[0]
		};

		let controllable = once("controllable.admits(");
		let derivable = once("attacker_can_derive(");
		let install = once("installs.push(");
		let execute = once("execute_forward(");

		assert!(
			controllable < derivable && controllable < install,
			"fact (vi) of the soundness theorem: controllability is tested in the same \
			 loop and *first*. A slot the attacker does not control is not a Dolev-Yao \
			 transition, whatever the term put into it"
		);
		assert!(
			derivable < install,
			"fact (v) of the soundness theorem: a term is proven derivable against closed \
			 attacker knowledge before it is queued for installation"
		);
		assert!(
			install < execute,
			"facts (v) and (vi) of the soundness theorem: every install is queued only \
			 after both tests pass, and `reexec` runs over the queue afterwards. Executing \
			 before the tests would make the state unreachable in the replay system"
		);

		for (fact, guard, at) in [
			("(vi)", "controllable.admits", controllable),
			("(v)", "attacker_can_derive", derivable),
		] {
			let abandons = body
				.iter()
				.skip(at + 1)
				.take(2)
				.any(|(_, line)| line.trim() == "return Ok(false);");
			assert!(
				abandons,
				"fact {fact} of the soundness theorem: a failing `{guard}` test abandons \
				 the whole substitution. Skipping the slot with `continue` instead would \
				 execute the rest of a substitution whose remainder was never justified"
			);
		}
	}

	#[test]
	fn a_forwarded_value_is_only_ever_what_its_sender_sent() {
		let reexec_rs = engine_source("reexec.rs");

		let chooses = fn_body(&reexec_rs, "forwarded_installs");
		assert!(
			!chooses.is_empty(),
			"reexec.rs must define `forwarded_installs`: carrying a run forward is the \
			 second way a value enters a state, and it needs its own gate"
		);
		for needle in [
			"event.sender == source.id",
			"event.recipient == target.id",
			"event.phase <= attacker.current_phase",
			"source.event_reached(",
			"source.slot_unreached(at)",
		] {
			assert!(
				!body_hits(&chooses, needle).is_empty(),
				"a forwarded value is justified by the sender having sent it, not by the \
				 attacker being able to build it, so every part of that claim has to be \
				 checked: `{needle}` is missing from `forwarded_installs`. Without it the \
				 forwarding rule becomes a way to place a value on a leg the model does \
				 not have, or one the sender never reached"
			);
		}

		let installs = fn_body(&reexec_rs, "install_forwarded");
		assert!(
			!installs.is_empty(),
			"reexec.rs must define `install_forwarded`"
		);
		for forbidden in ["provenance.sender", "provenance.creator"] {
			assert!(
				body_hits(&installs, forbidden).is_empty(),
				"an honest principal really did send this value, so `install_forwarded` \
				 must leave `{forbidden}` alone. Attributing a forwarded emission to the \
				 attacker would turn every carried consequence into an authentication \
				 failure against a sender that did exactly what the protocol says"
			);
		}
		assert!(
			!body_hits(&installs, "attacker_tainted = true").is_empty(),
			"a forwarded slot is still a precondition of whatever is learned downstream \
			 of it: it took the attacker's substitution upstream to put that value there. \
			 A record that did not say so would let the knowledge be spent in an \
			 execution where that substitution never happened"
		);
		assert!(
			body_hits(&installs, "sv.original").is_empty(),
			"`original` keeps what the protocol honestly computed, which is what makes \
			 purification total; overwriting it would leave a forwarded state impossible \
			 to return to its honest form"
		);
	}

	#[test]
	fn controllability_is_minted_only_by_reexec_and_bound_to_one_session() {
		let mut minted_elsewhere: Vec<String> = Vec::new();
		for path in engine_sources() {
			let rel = relative(&path);
			if rel == "reexec.rs" {
				continue;
			}
			for (number, line) in shipping_lines(&path) {
				let trimmed = line.trim_start();
				if trimmed.contains("Controllable {") && !trimmed.contains("struct Controllable") {
					minted_elsewhere.push(format!("{rel}:{number}: {trimmed}"));
				}
			}
		}
		assert!(
			minted_elsewhere.is_empty(),
			"fact (vi) of the soundness theorem: controllability is decided once per \
			 solving pass because deciding it is expensive, and a cached answer is exactly \
			 what an untrusted search would forge. Only reexec.rs may build one: \
			 {minted_elsewhere:?}"
		);

		let reexec_rs = engine_source("reexec.rs");
		let fields = block_lines(&reexec_rs, |header| {
			header.starts_with("pub(crate) struct Controllable {")
		});
		assert!(!fields.is_empty(), "reexec.rs must declare `Controllable`");
		let exposed: Vec<&str> = fields
			.iter()
			.skip(1)
			.map(|(_, line)| line.trim())
			.filter(|line| line.starts_with("pub"))
			.collect();
		assert!(
			exposed.is_empty(),
			"fact (vi) of the soundness theorem: `Controllable`'s fields stay private, or \
			 another module can assemble one field by field and the private constructor \
			 buys nothing: {exposed:?}"
		);

		let checks_session = shipping_lines(&reexec_rs);
		for needle in [
			"self.principal == ps.id",
			"self.phase == attacker.current_phase",
		] {
			assert!(
				checks_session.iter().any(|(_, line)| line.contains(needle)),
				"fact (vi) of the soundness theorem: the validator must check that the \
				 controllability value it was handed was built for the principal and phase \
				 it is currently validating; `{needle}` is missing from reexec.rs"
			);
		}
	}

	#[test]
	fn the_solver_holds_no_shared_cell_over_analysis_state() {
		const ALLOWED: [&str; 4] = ["memo:", "active:", "cycles_cut:", "fresh:"];
		let mut offenders: Vec<String> = Vec::new();
		for path in engine_sources() {
			if !path.to_string_lossy().contains("/solve/") {
				continue;
			}
			let rel = relative(&path);
			for (number, line) in shipping_lines(&path) {
				let trimmed = line.trim_start();
				let shared = ["RefCell<", "Cell<", "Mutex<", "RwLock<", "static mut"]
					.iter()
					.any(|needle| trimmed.contains(needle));
				if !shared || trimmed.starts_with("use ") {
					continue;
				}
				if ALLOWED.iter().any(|field| trimmed.starts_with(field)) {
					continue;
				}
				offenders.push(format!("{rel}:{number}: {trimmed}"));
			}
		}
		assert!(
			offenders.is_empty(),
			"the solver's interior mutability is confined to its own memo tables; 			 a cell over analysis state would let a search bug reach past the 			 validator: {offenders:?}"
		);
	}

	#[test]
	fn the_solver_cannot_reach_query_evaluation_except_through_the_validator() {
		let offenders: Vec<String> = engine_sources()
			.into_iter()
			.filter(|p| p.to_string_lossy().contains("/solve/"))
			.filter(|p| !p.ends_with("validate.rs"))
			.filter(|p| {
				shipping_lines(p).iter().any(|(_, line)| {
					line.contains("verify_resolve_queries")
						|| line.contains("results_put")
						|| line.contains("emit_query_result")
				})
			})
			.map(|p| p.to_string_lossy().into_owned())
			.collect();
		assert!(
			offenders.is_empty(),
			"the search is outside the trusted base only for as long as it cannot \
			 record anything: {offenders:?}"
		);
	}
}
