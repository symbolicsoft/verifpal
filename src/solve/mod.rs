/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub(crate) mod deduce;
pub(crate) mod diverge;
pub(crate) mod matching;
pub(crate) mod symbolic;
pub(crate) mod validate;
pub(crate) mod vars;

use crate::context::VerifyContext;
use crate::hashing::collect_subterm_hashes;
use crate::info::info_message;
use crate::types::*;
use crate::value::{push_unique_value, resolve_trace_constant};
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
	let bound = &crate::reexec::TermBound::of(km);
	let Some(seed) = principal_states.first() else {
		return Ok(());
	};

	for phase in 0..=km.max_phase {
		info_message(
			&format!("Running at phase {phase}."),
			InfoLevel::Info,
			false,
		);
		crate::verify::attacker_seed_phase(ctx, km, seed, phase)?;
		verify_standard_run(ctx, km, principal_states)?;
		if ctx.prefers_replication() {
			ctx.set_replication_only(true);
			search_rounds(ctx, km, principal_states, bound)?;
			ctx.set_replication_only(false);
			if ctx.replication_rejected() && !ctx.all_resolved() {
				search_rounds(ctx, km, principal_states, bound)?;
			}
		} else {
			search_rounds(ctx, km, principal_states, bound)?;
		}
		if ctx.relativises() && !ctx.all_resolved() && !ctx.cancelled() {
			verify_standard_run(ctx, km, principal_states)?;
		}
		ctx.attacker_phase_archive(phase);
	}
	Ok(())
}

fn search_rounds(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	principal_states: &[PrincipalState],
	bound: &crate::reexec::TermBound,
) -> VResult<()> {
	search_fixpoint(ctx, km, principal_states, bound, Search::Direct)?;
	if ctx.all_resolved() || ctx.cancelled() {
		return Ok(());
	}
	let before = ctx.attacker_known_count();
	search_fixpoint(ctx, km, principal_states, bound, Search::Refined)?;
	if ctx.attacker_known_count() != before && !ctx.all_resolved() {
		search_fixpoint(ctx, km, principal_states, bound, Search::Direct)?;
	}
	Ok(())
}

fn search_fixpoint(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	principal_states: &[PrincipalState],
	bound: &crate::reexec::TermBound,
	search: Search,
) -> VResult<()> {
	loop {
		if ctx.all_resolved() || ctx.cancelled() {
			break;
		}
		let before = ctx.attacker_known_count();

		for ps in principal_states {
			solve_principal(ctx, km, ps, Pass::Targeted, bound, search)?;
			if ctx.all_resolved() {
				break;
			}
		}
		if !ctx.all_resolved() {
			for ps in principal_states {
				solve_principal(ctx, km, ps, Pass::Constructed, bound, search)?;
				if ctx.all_resolved() {
					break;
				}
			}
		}
		if ctx.attacker_known_count() == before {
			break;
		}
	}
	Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Search {
	Direct,
	Refined,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
	Targeted,
	Constructed,
}

impl Pass {
	fn name(self) -> &'static str {
		match self {
			Pass::Targeted => "targeted search",
			Pass::Constructed => "constructed search",
		}
	}
}

fn solve_principal(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	pass: Pass,
	bound: &crate::reexec::TermBound,
	search: Search,
) -> VResult<()> {
	let attacker = ctx.attacker_snapshot();
	let controllable = crate::reexec::Controllable::of(km, ps, &attacker);
	let sym = symbolic::build(&controllable, ps, &attacker);
	if sym.var_slots.is_empty() {
		return Ok(());
	}
	if search == Search::Direct || pass != Pass::Targeted {
		return solve_with(ctx, km, ps, pass, bound, &attacker, &controllable, &sym);
	}
	for honest in slots_blocking_reduction(&sym) {
		if ctx.all_resolved() || ctx.cancelled() {
			return Ok(());
		}
		let refined = symbolic::build_assuming_honest(&controllable, ps, &attacker, Some(honest));
		if !refined.var_slots.is_empty() {
			solve_with(ctx, km, ps, pass, bound, &attacker, &controllable, &refined)?;
		}
	}
	Ok(())
}

fn slots_blocking_reduction(sym: &SymbolicState) -> Vec<usize> {
	let mut out: Vec<usize> = Vec::new();
	for term in &sym.terms {
		collect_blocking_slots(term, &mut out);
	}
	out.sort();
	out.dedup();
	out
}

fn collect_blocking_slots(v: &Value, out: &mut Vec<usize>) {
	let Value::Primitive(p) = v else {
		return;
	};
	if let Some(rule) = crate::primitive::primitive_get(p.id)
		.ok()
		.and_then(|s| s.rewrite.as_ref())
		&& !crate::theory::can_rewrite(p).0
		&& let Some(Value::Constant(c)) = p.arguments.get(rule.from)
		&& vars::is_slot_var_id(c.id)
	{
		out.push(vars::slot_of_var_id(c.id));
	}
	for a in &p.arguments {
		collect_blocking_slots(a, out);
	}
}

#[allow(clippy::too_many_arguments)]
fn solve_with(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	pass: Pass,
	bound: &crate::reexec::TermBound,
	attacker: &AttackerState,
	controllable: &crate::reexec::Controllable,
	sym: &SymbolicState,
) -> VResult<()> {
	#[cfg(test)]
	ctx.note_search_reached_a_controllable_slot();

	let deducer = Deducer::new(ps, attacker, sym);
	let proposals = propose(ctx, km, ps, pass, attacker, sym, &deducer);
	dispose(
		ctx,
		km,
		ps,
		pass,
		bound,
		attacker,
		controllable,
		sym,
		proposals,
	)
}

#[allow(clippy::too_many_arguments)]
fn propose(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	pass: Pass,
	attacker: &AttackerState,
	sym: &SymbolicState,
	deducer: &Deducer,
) -> Vec<Substitution> {
	let empty = Substitution::default();
	let mut proposals: Vec<Substitution> = Vec::new();

	let results = ctx.results_get();
	for result in &results {
		if result.resolved || pass != Pass::Targeted {
			continue;
		}
		for query in std::iter::once(&result.query).chain(result.variants.iter()) {
			#[cfg(test)]
			ctx.goals_noted(result.query_index, 1);
			proposals.extend(goals_for_query(query, km, ps, sym, deducer, &empty));
		}
	}

	if pass == Pass::Targeted {
		proposals.extend(deducer.constraint_goals(sym, &empty));
	}

	let blanket = blanket_substitution(sym);
	if pass == Pass::Targeted && !blanket.is_empty() {
		proposals.push(blanket.clone());

		for &slot in &sym.var_slots {
			let single = slot_substitution(sym, slot);
			if !single.is_empty() {
				proposals.push(single);
			}
		}
	}

	if pass == Pass::Constructed {
		proposals.extend(sibling_flight_substitutions(km, ps, sym));
		let relayed = relay_substitution(km, ps, sym);
		let protocol = protocol_terms(km, ps);
		for &slot in &sym.var_slots {
			let Some(meta) = ps.meta.get(slot) else {
				continue;
			};
			let honest = resolve_trace_constant(&meta.constant, km);
			for candidate in
				slot_candidates(attacker, sym, deducer, &protocol, &honest, &blanket, slot)
			{
				let var_id = vars::attacker_var_id(slot);
				let mut alone = Substitution::default();
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
	}

	if results
		.iter()
		.any(|r| !r.resolved && r.query.kind == QueryKind::Equivalence)
	{
		let distinguished: Vec<Substitution> = proposals
			.iter()
			.filter_map(|proposal| diverge::distinguish(sym, proposal))
			.collect();
		proposals.extend(distinguished);
	}

	proposals
}

#[allow(clippy::too_many_arguments)]
fn dispose(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	pass: Pass,
	bound: &crate::reexec::TermBound,
	attacker: &AttackerState,
	controllable: &crate::reexec::Controllable,
	sym: &SymbolicState,
	proposals: Vec<Substitution>,
) -> VResult<()> {
	let mut seen: Vec<Vec<(usize, u64)>> = Vec::new();
	let mut buckets: IdMap<u64, Vec<usize>> = IdMap::default();
	let mut checked = 0usize;
	for proposal in dedupe(proposals) {
		if ctx.all_resolved() || ctx.cancelled() {
			break;
		}
		let signature = install_signature(sym, &proposal);
		let key = signature_hash(&signature);
		let bucket = buckets.entry(key).or_default();
		if bucket.iter().any(|&i| seen[i] == signature) {
			continue;
		}
		bucket.push(seen.len());
		seen.push(signature);
		let guards = crate::reexec::Guards {
			controllable,
			bound,
		};
		checked += 1;
		crate::info::info_status_update(|| {
			crate::verify::status_line(
				ctx,
				attacker.current_phase,
				&ps.name,
				&format!(
					"{}, {} state{} checked",
					pass.name(),
					checked,
					if checked == 1 { "" } else { "s" }
				),
			)
		});
		let ran = validate::validate(ctx, km, ps, sym, &guards, attacker, &proposal)?;
		trace_proposal(ps, sym, &proposal, ran);
	}
	Ok(())
}

fn install_signature(sym: &SymbolicState, proposal: &Substitution) -> Vec<(usize, u64)> {
	let mut out = Vec::new();
	for &slot in &sym.var_slots {
		let Some(term) = &sym.var_terms[slot] else {
			continue;
		};
		if !proposal.contains_key(&vars::attacker_var_id(slot)) {
			continue;
		}
		let ground = vars::ground_free(&vars::apply(term, proposal));
		if vars::contains_var(&ground) {
			continue;
		}
		out.push((slot, ground.hash_value()));
	}
	out
}

fn signature_hash(signature: &[(usize, u64)]) -> u64 {
	let mut acc: u64 = 0x9E37_79B9_7F4A_7C15;
	for (slot, hash) in signature {
		acc = acc
			.rotate_left(13)
			.wrapping_add((*slot as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F))
			^ hash;
	}
	acc
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
				let Some(term) = slot_term(Some(c), ps, sym) else {
					continue;
				};
				let Value::Primitive(p) = &term else {
					continue;
				};
				for arg in &p.arguments {
					if !crate::unlink::depends_on_secret(arg, ps) {
						continue;
					}
					out.extend(deducer.solve(arg, base));
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

	let honest = resolve_trace_constant(c, km);
	for candidate in deducer.solve(&honest, base) {
		if let Some(bound) = matching::match_value(var_term, &honest, &candidate) {
			out.push(bound);
		}
	}
	out
}

fn slot_substitution(sym: &SymbolicState, slot: usize) -> Substitution {
	let mut out = Substitution::default();
	if let Some(term) = &sym.var_terms[slot] {
		vars::ground_remaining(term, &mut out);
	}
	out
}

fn blanket_substitution(sym: &SymbolicState) -> Substitution {
	let mut out = Substitution::default();
	for &slot in &sym.var_slots {
		out.extend(slot_substitution(sym, slot));
	}
	out
}

fn solve_debug() -> bool {
	static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
	*ENABLED.get_or_init(|| std::env::var_os("VERIFPAL_SOLVE_DEBUG").is_some())
}

fn trace_proposal(ps: &PrincipalState, sym: &SymbolicState, proposal: &Substitution, ran: bool) {
	if !solve_debug() {
		return;
	}
	let bindings = binding_summary(ps, sym, proposal);
	eprintln!("[solve] {} ran={ran} [{}]", ps.name, bindings.join(" "));
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

fn sibling_flight_substitutions(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
) -> Vec<Substitution> {
	let mut widest = 0;
	for &slot in &sym.var_slots {
		if let Some(meta) = ps.meta.get(slot) {
			widest = widest.max(crate::query::session_sibling_values(&meta.constant, km).len());
		}
	}
	let mut out = Vec::new();
	for i in 0..widest {
		let mut flight = Substitution::default();
		for &slot in &sym.var_slots {
			let Some(meta) = ps.meta.get(slot) else {
				continue;
			};
			let siblings = crate::query::session_sibling_values(&meta.constant, km);
			if let Some(v) = siblings.get(i) {
				flight.insert(vars::attacker_var_id(slot), v.clone());
			}
		}
		if !flight.is_empty() {
			out.push(flight);
		}
	}
	out
}

fn relay_substitution(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
) -> Substitution {
	let mut out = Substitution::default();
	for &slot in &sym.var_slots {
		let Some(meta) = ps.meta.get(slot) else {
			continue;
		};
		out.insert(
			vars::attacker_var_id(slot),
			resolve_trace_constant(&meta.constant, km),
		);
	}
	out
}

fn protocol_terms(km: &ProtocolTrace, ps: &PrincipalState) -> IdSet<u64> {
	let mut out = IdSet::default();
	for meta in ps.meta.iter() {
		collect_subterm_hashes(&resolve_trace_constant(&meta.constant, km), &mut out);
	}
	out
}

fn slot_candidates(
	attacker: &AttackerState,
	sym: &SymbolicState,
	deducer: &Deducer,
	protocol: &IdSet<u64>,
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

	let mut contexts = vec![Substitution::default()];
	if !blanket.is_empty() {
		contexts.push(blanket.clone());
	}
	for shape in deducer.forgeable_shapes(sym, vars::attacker_var_id(slot)) {
		for context in &contexts {
			for solution in deducer.solve(&shape, context) {
				let applied = vars::apply(&shape, &solution);
				for filler in [
					crate::value::value_nil(),
					crate::primitive::attacker_public_key(),
				] {
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
