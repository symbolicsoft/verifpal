/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub(crate) mod deduce;
pub(crate) mod diverge;
pub(crate) mod matching;
pub(crate) mod symbolic;
pub(crate) mod validate;
pub(crate) mod vars;

use std::collections::HashSet;

use crate::context::VerifyContext;
use crate::hashing::collect_subterm_hashes;
use crate::info::info_message;
use crate::types::*;
use crate::value::{push_unique_value, resolve_trace_values};
use crate::verify::verify_standard_run;

use deduce::Deducer;
use symbolic::SymbolicState;
use vars::{Substitution, dedupe};

pub(crate) fn verify_active(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	principal_states: &[PrincipalState],
) -> VResult<()> {
	info_message("Attacker is configured as active.", InfoLevel::Info, false);

	for phase in 0..=km.max_phase {
		info_message(
			&format!("Running at phase {phase}."),
			InfoLevel::Info,
			false,
		);
		ctx.attacker_init();
		let mut ps_pure_resolved = principal_states[0].clone_for_depth(true);
		ps_pure_resolved.resolve_all_values(&ctx.attacker_snapshot())?;
		ctx.attacker_phase_update(km, &ps_pure_resolved, phase)?;

		verify_standard_run(ctx, km, principal_states)?;

		loop {
			if ctx.all_resolved() {
				break;
			}
			let before = ctx.attacker_known_count();

			for ps in principal_states {
				solve_principal(ctx, km, ps, Pass::Targeted)?;
				if ctx.all_resolved() {
					break;
				}
			}
			if !ctx.all_resolved() {
				for ps in principal_states {
					solve_principal(ctx, km, ps, Pass::Constructed)?;
					if ctx.all_resolved() {
						break;
					}
				}
			}

			if ctx.attacker_known_count() == before {
				break;
			}
		}

		ctx.attacker_phase_archive(phase);
	}
	Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
	Targeted,
	Constructed,
}

fn solve_principal(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	pass: Pass,
) -> VResult<()> {
	let attacker = ctx.attacker_snapshot();
	let sym = symbolic::build(km, ps, &attacker);
	if sym.var_slots.is_empty() {
		return Ok(());
	}

	let deducer = Deducer::new(ps, &attacker, &sym);
	let empty = Substitution::new();
	let mut proposals: Vec<Substitution> = Vec::new();

	for result in ctx.results_get() {
		if result.resolved || pass != Pass::Targeted {
			continue;
		}
		proposals.extend(goals_for_query(
			&result.query,
			km,
			ps,
			&sym,
			&deducer,
			&empty,
		));
	}

	if pass == Pass::Targeted {
		proposals.extend(deducer.constraint_goals(&sym, &empty));
	}

	let blanket = blanket_substitution(&sym);
	if pass == Pass::Targeted && !blanket.is_empty() {
		proposals.push(blanket.clone());

		for &slot in &sym.var_slots {
			if let Some(term) = &sym.var_terms[slot] {
				let mut single = Substitution::new();
				vars::ground_remaining(term, &mut single);
				if !single.is_empty() {
					proposals.push(single);
				}
			}
		}
	}

	let relayed = relay_substitution(km, ps, &sym);

	let protocol = if pass == Pass::Constructed {
		protocol_terms(km, ps)
	} else {
		HashSet::new()
	};
	for &slot in &sym.var_slots {
		if pass != Pass::Constructed {
			break;
		}
		let Some(meta) = ps.meta.get(slot) else {
			continue;
		};
		let (honest, _) = resolve_trace_values(&Value::Constant(meta.constant.clone()), km);
		for candidate in slot_candidates(
			&attacker, &sym, &deducer, &protocol, &honest, &blanket, slot,
		) {
			let var_id = vars::attacker_var_id(slot);
			let mut alone = Substitution::new();
			alone.insert(var_id, candidate.clone());
			proposals.push(alone);
			if !blanket.is_empty() {
				let mut combined = blanket.clone();
				combined.insert(var_id, candidate.clone());
				proposals.push(combined);
			}
			let mut with_relay = relayed.clone();
			with_relay.insert(var_id, candidate);
			proposals.push(with_relay);
		}
	}

	for proposal in dedupe(proposals) {
		if ctx.all_resolved() {
			break;
		}
		let ran = validate::validate(ctx, km, ps, &sym, &attacker, &proposal)?;
		trace_proposal(ps, &sym, &proposal, ran);
	}
	Ok(())
}

fn goals_for_query(
	query: &Query,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
	deducer: &Deducer,
	base: &Substitution,
) -> Vec<Substitution> {
	match query.kind {
		QueryKind::Confidentiality => match slot_term(query.constants.first(), ps, sym) {
			Some(term) => deducer.solve(&term, base),
			None => Vec::new(),
		},
		QueryKind::Authentication => authentication_goals(query, km, ps, sym, deducer, base),
		QueryKind::Unlinkability => {
			let mut out = Vec::new();
			for c in &query.constants {
				if let Some(term) = slot_term(Some(c), ps, sym) {
					out.extend(deducer.solve(&term, base));
				}
			}
			out
		}
		QueryKind::Equivalence => {
			let mut out = Vec::new();
			let terms: Vec<Value> = query
				.constants
				.iter()
				.filter_map(|c| slot_term(Some(c), ps, sym))
				.collect();
			for pair in terms.windows(2) {
				out.extend(diverge::solve_divergent(&pair[0], &pair[1], base));
			}
			out
		}
		QueryKind::Freshness => Vec::new(),
	}
}

fn authentication_goals(
	query: &Query,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
	deducer: &Deducer,
	base: &Substitution,
) -> Vec<Substitution> {
	if query.message.recipient != ps.id {
		return Vec::new();
	}
	let Some(c) = query.message.constants.first() else {
		return Vec::new();
	};
	let Some(slot) = ps.index_of(c) else {
		return Vec::new();
	};
	if !sym.is_var_slot(slot) {
		return Vec::new();
	}
	let Some(var_term) = &sym.var_terms[slot] else {
		return Vec::new();
	};
	let mut out = Vec::new();

	for shape in deducer.forgeable_shapes(sym, vars::attacker_var_id(slot)) {
		for candidate in deducer.solve(&shape, base) {
			let forged = vars::apply(&shape, &candidate);
			if vars::contains_var(&forged) {
				continue;
			}
			if let Some(bound) = matching::match_value(var_term, &forged, &candidate) {
				out.push(bound);
			}
		}
	}

	let (honest, _) = resolve_trace_values(&Value::Constant(c.clone()), km);
	for candidate in deducer.solve_forgeable(&honest, base) {
		if let Some(bound) = matching::match_value(var_term, &honest, &candidate) {
			out.push(bound);
		}
	}
	out
}

fn blanket_substitution(sym: &SymbolicState) -> Substitution {
	let mut out = Substitution::new();
	for &slot in &sym.var_slots {
		if let Some(term) = &sym.var_terms[slot] {
			vars::ground_remaining(term, &mut out);
		}
	}
	out
}

fn trace_proposal(ps: &PrincipalState, sym: &SymbolicState, proposal: &Substitution, ran: bool) {
	let debug = std::env::var_os("VERIFPAL_SOLVE_DEBUG").is_some();
	if !debug && !ran {
		return;
	}
	let bindings = binding_summary(ps, sym, proposal);
	if debug {
		eprintln!("[solve] {} ran={ran} [{}]", ps.name, bindings.join(" "));
	}
}

fn binding_summary(
	ps: &PrincipalState,
	sym: &SymbolicState,
	proposal: &Substitution,
) -> Vec<String> {
	sym.var_slots
		.iter()
		.filter_map(|&slot| {
			let term = sym.var_terms[slot].as_ref()?;
			let ground = vars::ground_free(&vars::apply(term, proposal));
			if vars::contains_var(&ground) {
				None
			} else {
				Some(format!("{}={}", ps.meta[slot].constant.name, ground))
			}
		})
		.collect()
}

fn relay_substitution(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
) -> Substitution {
	let mut out = Substitution::new();
	for &slot in &sym.var_slots {
		let Some(meta) = ps.meta.get(slot) else {
			continue;
		};
		let (honest, _) = resolve_trace_values(&Value::Constant(meta.constant.clone()), km);
		out.insert(vars::attacker_var_id(slot), honest);
	}
	out
}

fn protocol_terms(km: &ProtocolTrace, ps: &PrincipalState) -> HashSet<u64> {
	let mut out = HashSet::new();
	for meta in ps.meta.iter() {
		let (v, _) = resolve_trace_values(&Value::Constant(meta.constant.clone()), km);
		collect_subterm_hashes(&v, &mut out);
	}
	out
}

fn slot_candidates(
	attacker: &AttackerState,
	sym: &SymbolicState,
	deducer: &Deducer,
	protocol: &HashSet<u64>,
	honest: &Value,
	blanket: &Substitution,
	slot: usize,
) -> Vec<Value> {
	let mut out = Vec::new();

	for candidate in attacker.known.iter() {
		if !protocol.contains(&candidate.hash_value()) || candidate.equivalent(honest, true) {
			continue;
		}
		let compatible = match (honest, candidate) {
			(Value::Primitive(h), Value::Primitive(k)) => k.id == h.id,
			(Value::Constant(_), Value::Constant(k)) => !k.is_nil(),
			_ => false,
		};
		if compatible {
			push_unique_value(&mut out, candidate.clone());
		}
	}

	let mut contexts = vec![Substitution::new()];
	if !blanket.is_empty() {
		contexts.push(blanket.clone());
	}
	for shape in deducer.forgeable_shapes(sym, vars::attacker_var_id(slot)) {
		for context in &contexts {
			for solution in deducer.solve(&shape, context) {
				let applied = vars::apply(&shape, &solution);
				let attacker_key =
					crate::primitive::nil_key_derivation().unwrap_or_else(crate::value::value_nil);
				for filler in [crate::value::value_nil(), attacker_key] {
					let built = vars::ground_free_as(&applied, &filler);
					if !vars::contains_var(&built) {
						push_unique_value(&mut out, built);
					}
				}
			}
		}
	}
	out
}

fn slot_term(c: Option<&Constant>, ps: &PrincipalState, sym: &SymbolicState) -> Option<Value> {
	let c = c?;
	let slot = ps.index_of(c)?;
	sym.terms.get(slot).cloned()
}
