/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::context::VerifyContext;
use crate::info::{info_deduction, info_output_text};
use crate::pretty::pretty_values;
use crate::primitive::{Reveal, primitive_core_reveals_args, reuse_fixed_names, reuse_rule};
use crate::theory::{
	can_decompose, can_recompose, can_reconstruct_primitive, can_rewrite, obtainable,
	one_execution, reduce_once, reused_pair,
};
use crate::types::*;
use crate::value::compute_slot_diffs;

pub(crate) enum RuleDomain {
	AttackerKnown,
	PrincipalAssigned,
}

type RuleFn = fn(
	&VerifyContext,
	&ProtocolTrace,
	&Value,
	&PrincipalState,
	&AttackerState,
	&Arc<MutationRecord>,
) -> bool;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reads {
	Knowledge,
	State,
}

pub(crate) struct RuleGroup {
	pub domain: RuleDomain,
	rules: &'static [(RuleFn, Reads)],
}

static DEDUCTION_RULES: &[RuleGroup] = &[
	RuleGroup {
		domain: RuleDomain::AttackerKnown,
		rules: &[
			(rule_decompose, Reads::Knowledge),
			(rule_break_weak, Reads::Knowledge),
			(rule_rewrite_build, Reads::Knowledge),
		],
	},
	RuleGroup {
		domain: RuleDomain::PrincipalAssigned,
		rules: &[
			(rule_reconstruct, Reads::State),
			(rule_recompose, Reads::State),
		],
	},
	RuleGroup {
		domain: RuleDomain::AttackerKnown,
		rules: &[
			(rule_equivalize, Reads::State),
			(rule_concat_extract, Reads::Knowledge),
		],
	},
];

pub(crate) fn compute_knowledge_closure(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> VResult<()> {
	let phase = ctx.attacker_snapshot().current_phase;
	let record = compute_slot_diffs(ps, km, phase);
	ctx.attacker_absorb_disclosed(km, ps, &record, phase);
	let index = crate::theory::StateIndex::of(ps);

	loop {
		if ctx.cancelled() {
			return Ok(());
		}
		let attacker = ctx.attacker_snapshot();

		if !try_deduction_step(ctx, km, &attacker, ps, &record, &index) {
			ctx.analysis_count_increment();
			return Ok(());
		}
	}
}

fn try_deduction_step(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	attacker: &AttackerState,
	ps: &PrincipalState,
	record: &Arc<MutationRecord>,
	index: &Arc<crate::theory::StateIndex>,
) -> bool {
	let _memo = crate::theory::DeductionMemo::scoped(ps, attacker, index);
	let saturated = ctx.knowledge_rules_saturated(ps.id, attacker);
	let mut progress = false;
	for group in DEDUCTION_RULES {
		match group.domain {
			RuleDomain::AttackerKnown => {
				for known in attacker.known.iter() {
					for (rule, reads) in group.rules {
						if saturated && *reads == Reads::Knowledge {
							continue;
						}
						progress |= rule(ctx, km, known, ps, attacker, record);
					}
				}
			}
			RuleDomain::PrincipalAssigned => {
				for (slot, sv) in ps.values.iter().enumerate() {
					if ps.slot_unreached(slot) {
						continue;
					}
					for (rule, _) in group.rules {
						progress |= rule(ctx, km, &sv.value, ps, attacker, record);
					}
					progress |=
						rule_rewrite_forward(ctx, km, &sv.pre_rewrite, ps, attacker, record);
				}
			}
		}
	}
	if !saturated {
		progress |= rule_reuse(ctx, km, ps, attacker, record);
		ctx.note_knowledge_rules_saturated(ps.id, attacker);
	}
	progress
}

#[allow(clippy::too_many_arguments)]
fn learn(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	value: &Value,
	record: &Arc<MutationRecord>,
	derivation: DerivationRecord,
	message: impl FnOnce() -> String,
) -> bool {
	if attacker.knows(value).is_none()
		&& !ctx.attacker_knows(value)
		&& !combination_coheres(ctx, km, ps, attacker, record, &derivation)
	{
		return false;
	}
	if !ctx.attacker_put_with(value, record, derivation) {
		return false;
	}
	info_deduction(message);
	true
}

/// Whether the reads a derivation rests on can all have happened in one
/// execution.
///
/// Knowledge is global and monotone, so a rule may combine a value read out of
/// one execution of a principal with one that exists only in another: a seed
/// learned because Bob was handed the attacker's key, and a ciphertext Alice
/// only computes once she has verified Bob's signature over the honest one.
/// No install separates the two, so the validator's filters never see it, and
/// the result is a term no execution produces.
///
/// So the combination is checked where it is made. The reads the ingredients
/// bottom out in are collected, each with the substitution *it depends on*:
/// not the whole record of the state it was read from, which lists every
/// install there, but the installs in the dependency cone of its slot within
/// the reader's own computation, followed into the values installed there.
/// Two reads that need different values at one slot are refused outright.
/// Otherwise the union is replayed as the one execution it describes
/// (`reexec::replay_diffs`, carried forward through every principal it
/// reaches, cached per substitution and phase), and every read recorded under
/// a different substitution must still be *reached* there.
///
/// Reached, not equal. A run that halts before a slot never produced it, and
/// that is a fact about the execution. A slot that is reached but holds
/// something else is not: the union is assembled from ambient records, which
/// list every install in the state a value came from rather than the ones it
/// needed, so a mismatch there is as likely to be an artifact of the union as
/// a real disagreement. Refusing on mismatch was measured and cost real
/// attacks in `test1.vp`, `test3.vp`, `test5.vp` and `noise_xx_mutual.vp`,
/// which the `leaks` and `weaken` sweeps caught as lost attacks.
fn combination_coheres(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	ambient: &Arc<MutationRecord>,
	derivation: &DerivationRecord,
) -> bool {
	let ingredients = derivation.ingredients();
	if ingredients.is_empty() || !any_taint(attacker) {
		return true;
	}
	let seed: Vec<Need> = if derivation.reads_from_state() {
		let mut seed = Vec::new();
		merge_into(&tainted(ambient), &mut seed);
		seed
	} else {
		Vec::new()
	};
	let Some((reads, mut union)) = gather_reads(km, ps, attacker, &ingredients, &seed) else {
		return false;
	};
	if union.is_empty() {
		return true;
	}
	union.sort_by_key(|(state, slot, _)| (*state, *slot));
	let signature = needs_signature(&union);
	let differs = |read: &Read| read.signature != signature || !same_needs(&read.needs, &union);
	if !reads.iter().any(differs) {
		return true;
	}
	let Some(replayed) = ctx.replayed(km, &seeds_of(&union), attacker) else {
		return false;
	};
	reads.iter().filter(|read| differs(read)).all(|read| {
		let Some(state) = replayed.iter().find(|state| state.id == read.reader) else {
			return true;
		};
		read.slot < state.values.len()
			&& !state.slot_unreached(read.slot)
			&& !state.withheld_by_own_halt(read.slot)
	})
}

fn pair_coheres(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	a: &Value,
	b: &Value,
) -> bool {
	let Some((reads, mut union)) = gather_reads(km, ps, attacker, &[a, b], &[]) else {
		return false;
	};
	if union.is_empty() {
		return true;
	}
	union.sort_by_key(|(state, slot, _)| (*state, *slot));
	let Some(replayed) = ctx.replayed(km, &seeds_of(&union), attacker) else {
		return false;
	};
	reads.iter().all(|read| {
		let holds = |state: &PrincipalState| {
			read.slot < state.values.len()
				&& !state.slot_unreached(read.slot)
				&& state.values[read.slot].value.equivalent(&read.value, true)
		};
		match replayed.iter().find(|state| state.id == read.reader) {
			Some(state) => holds(state),
			None => ctx
				.execution_base(read.reader)
				.is_some_and(|base| holds(&base)),
		}
	})
}

type Need = (PrincipalId, SlotIdx, Value);

fn needs_signature(needs: &[Need]) -> u64 {
	let mut hash = 0xcbf2_9ce4_8422_2325u64;
	let mut mix = |word: u64| {
		hash ^= word;
		hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
	};
	for (state, slot, value) in needs {
		mix(u64::from(*state));
		mix(slot.get() as u64);
		mix(value.hash_value());
	}
	hash
}

fn same_needs(a: &[Need], b: &[Need]) -> bool {
	a.len() == b.len()
		&& a.iter()
			.zip(b.iter())
			.all(|((sa, ia, va), (sb, ib, vb))| sa == sb && ia == ib && va.equivalent(vb, true))
}

fn seeds_of(union: &[Need]) -> crate::reexec::Seeds {
	let mut seeds: crate::reexec::Seeds = Vec::new();
	for (state, slot, value) in union {
		match seeds.iter_mut().find(|(principal, _)| principal == state) {
			Some((_, mine)) => mine.push((*slot, value.clone())),
			None => seeds.push((*state, vec![(*slot, value.clone())])),
		}
	}
	seeds
}

type ConeCache = IdMap<(PrincipalId, usize), Arc<Vec<usize>>>;
type TaintFlag = (Arc<Vec<Arc<MutationRecord>>>, bool);

type NeedsMemo = (Arc<Vec<Arc<MutationRecord>>>, IdMap<usize, Vec<Need>>);

thread_local! {
	static ANY_TAINT: std::cell::RefCell<Option<TaintFlag>> = const { std::cell::RefCell::new(None) };
	static CONES: std::cell::RefCell<crate::context::Generational<ConeCache>> =
		std::cell::RefCell::new(crate::context::Generational::default());
	static NEEDS: std::cell::RefCell<Option<NeedsMemo>> = const { std::cell::RefCell::new(None) };
}

fn take_needs_memo(attacker: &AttackerState) -> IdMap<usize, Vec<Need>> {
	NEEDS.with(|cell| match cell.borrow_mut().take() {
		Some((seen, memo)) if Arc::ptr_eq(&seen, &attacker.mutation_records) => memo,
		_ => IdMap::default(),
	})
}

fn keep_needs_memo(attacker: &AttackerState, memo: IdMap<usize, Vec<Need>>) {
	NEEDS.with(|cell| {
		*cell.borrow_mut() = Some((Arc::clone(&attacker.mutation_records), memo));
	});
}

/// Whether any value the attacker holds was recorded under a substitution. If
/// none was, every combination is trivially of one execution, and the gate can
/// answer without walking anything.
///
/// Memoised per snapshot, since the check is linear in what the attacker knows
/// and the gate runs inside the closure's fixed point. The cell keeps the `Arc`
/// it was computed from rather than its address: `AttackerState` is
/// copy-on-write, so a records vector that dies frees its block, the allocator
/// hands the same block to the next vector of that size, and a cached `false`
/// would then answer for a *tainted* snapshot and switch the whole gate off.
fn any_taint(attacker: &AttackerState) -> bool {
	ANY_TAINT.with(|cell| {
		let mut cell = cell.borrow_mut();
		if let Some((seen, hit)) = cell.as_ref()
			&& Arc::ptr_eq(seen, &attacker.mutation_records)
		{
			return *hit;
		}
		let hit = attacker
			.mutation_records
			.iter()
			.any(|record| record.diffs.iter().any(|diff| diff.tainted));
		*cell = Some((Arc::clone(&attacker.mutation_records), hit));
		hit
	})
}

fn tainted(record: &MutationRecord) -> Vec<Need> {
	record
		.tainted()
		.map(|diff| (diff.state, diff.index, diff.value.clone()))
		.collect()
}

/// One read a derivation rests on: what was read, where, by whom, and the
/// substitution that read depends on.
struct Read {
	slot: usize,
	reader: PrincipalId,
	value: Value,
	needs: Vec<Need>,
	signature: u64,
}

fn merge_absorb(needs: &[Need], union: &mut Vec<Need>) {
	for (state, slot, value) in needs {
		if !union
			.iter()
			.any(|(held_state, held, _)| held_state == state && held == slot)
		{
			union.push((*state, *slot, value.clone()));
		}
	}
}

/// Merge a substitution into the union, reporting a contradiction: two reads
/// that need different values at one slot of one principal cannot both have
/// happened, whatever a replay would show.
fn merge_into(needs: &[Need], union: &mut Vec<Need>) -> bool {
	let mut coherent = true;
	for (state, slot, value) in needs {
		match union
			.iter()
			.find(|(held_state, held, _)| held_state == state && held == slot)
		{
			Some((_, _, held)) => coherent &= held.equivalent(value, true),
			None => union.push((*state, *slot, value.clone())),
		}
	}
	coherent
}

/// The accumulators the read walk fills: which known terms it has already
/// visited, the per-term precondition memo, the reads it found, and the union
/// of every record it passed through.
struct Walk {
	seen: IdSet<usize>,
	memo: IdMap<usize, Vec<Need>>,
	reads: Vec<Read>,
	union: Vec<Need>,
}

fn gather_reads(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	terms: &[&Value],
	seed: &[Need],
) -> Option<(Vec<Read>, Vec<Need>)> {
	let mut walk = Walk {
		seen: IdSet::default(),
		memo: take_needs_memo(attacker),
		reads: Vec::new(),
		union: seed.to_vec(),
	};
	for term in terms {
		collect_reads(km, ps, attacker, term, &mut walk);
	}
	let Walk {
		reads,
		mut union,
		memo,
		..
	} = walk;
	keep_needs_memo(attacker, memo);
	for read in &reads {
		if !merge_into(&read.needs, &mut union) {
			return None;
		}
	}
	Some((reads, union))
}

/// The reads an ingredient rests on, whether or not the attacker holds it as
/// a term.
///
/// A rule may use an ingredient it never learned: `obtainable` rebuilds a key
/// in place out of the walked state, rewriting it and reconstructing the
/// result from arguments the attacker holds, or projecting it from a sibling
/// output it can open. The seed learned under a substitution can then sit two
/// levels inside a key nothing in attacker knowledge names. So the walk asks
/// the cascade itself which arguments it rebuilt from, and follows those; it
/// does not guess at routes, since a route the cascade did not take would
/// refuse combinations that are sound.
fn collect_reads(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	term: &Value,
	walk: &mut Walk,
) {
	if let Some(idx) = attacker.knows(term) {
		collect_leaves(km, attacker, idx, walk);
		return;
	}
	let Value::Primitive(p) = term else {
		return;
	};
	if let Some(rebuilt) = can_reconstruct_primitive(p, ps, attacker) {
		for argument in &rebuilt.from {
			collect_reads(km, ps, attacker, argument, walk);
		}
		return;
	}
	let Ok(spec) = crate::primitive::primitive_get(p.id) else {
		return;
	};
	let Some(&outputs) = spec.output.iter().max() else {
		return;
	};
	for j in (0..outputs.max(0) as usize).filter(|&j| j != p.output) {
		let sibling = Arc::new(p.with_output(j));
		let projected = Value::Primitive(Arc::clone(&sibling));
		if attacker.knows(&projected).is_none() {
			continue;
		}
		let Some(opened) = can_decompose(&sibling, ps, attacker) else {
			continue;
		};
		collect_reads(km, ps, attacker, &projected, walk);
		for key in &opened.used {
			collect_reads(km, ps, attacker, key, walk);
		}
		return;
	}
}

/// The reads a known term bottoms out in.
fn collect_leaves(km: &ProtocolTrace, attacker: &AttackerState, idx: KnownIdx, walk: &mut Walk) {
	if !walk.seen.insert(idx.get()) {
		return;
	}
	let Some(derivation) = attacker.derivation(idx) else {
		return;
	};
	match derivation {
		DerivationRecord::Obtained { slot } | DerivationRecord::Leaked { slot } => {
			let reader = km
				.slots
				.get(slot.get())
				.map(|s| s.creator)
				.unwrap_or(crate::principal::ATTACKER_ID);
			let needs = read_preconditions(
				km,
				attacker,
				idx,
				&mut walk.memo,
				&mut Vec::new(),
				&mut false,
			);
			walk.reads.push(Read {
				slot: slot.get(),
				reader,
				value: attacker.known[idx.get()].clone(),
				signature: needs_signature(&needs),
				needs,
			});
		}
		DerivationRecord::Initial => {}
		other => {
			for ingredient in other.ingredients() {
				if let Some(inner) = attacker.knows(ingredient) {
					collect_leaves(km, attacker, inner, walk);
				}
			}
		}
	}
}

/// The substitution a read depends on: the installs in the dependency cone of
/// its slot within the reader's own computation, followed into the values
/// installed there. A record lists every install in the state a value was
/// read from; most of them the value never touched, and treating them as
/// preconditions makes two unrelated reads of one principal contradict each
/// other.
pub(crate) fn needs_of(
	km: &ProtocolTrace,
	attacker: &AttackerState,
	value: &Value,
) -> Vec<(PrincipalId, SlotIdx, Value)> {
	let Some(idx) = attacker.knows(value) else {
		return Vec::new();
	};
	let mut memo: IdMap<usize, Vec<Need>> = IdMap::default();
	let mut active: Vec<usize> = Vec::new();
	let mut cut = false;
	read_preconditions(km, attacker, idx, &mut memo, &mut active, &mut cut)
}

fn read_preconditions(
	km: &ProtocolTrace,
	attacker: &AttackerState,
	idx: KnownIdx,
	memo: &mut IdMap<usize, Vec<Need>>,
	active: &mut Vec<usize>,
	cut: &mut bool,
) -> Vec<Need> {
	if let Some(hit) = memo.get(&idx.get()) {
		return hit.clone();
	}
	if active.contains(&idx.get()) {
		*cut = true;
		return Vec::new();
	}
	active.push(idx.get());
	let mut out: Vec<Need> = Vec::new();
	let (slot, record) = match (attacker.derivation(idx), attacker.record(idx)) {
		(
			Some(DerivationRecord::Obtained { slot } | DerivationRecord::Leaked { slot }),
			Some(record),
		) => (slot.get(), Arc::clone(record)),
		(Some(other), _) => {
			for ingredient in other.ingredients() {
				if let Some(inner) = attacker.knows(ingredient) {
					let mut inner_cut = false;
					for need in
						read_preconditions(km, attacker, inner, memo, active, &mut inner_cut)
					{
						merge_absorb(&[need], &mut out);
					}
					*cut |= inner_cut;
				}
			}
			out.sort_by_key(|(state, slot, _)| (*state, *slot));
			active.pop();
			if !*cut {
				memo.insert(idx.get(), out.clone());
			}
			return out;
		}
		_ => {
			active.pop();
			return out;
		}
	};
	let reader = km.slots.get(slot).map(|s| s.creator).unwrap_or(0);
	for &at in reach_cone(km, reader, slot).iter() {
		let Some(diff) = record
			.diffs
			.iter()
			.find(|diff| diff.tainted && diff.index.get() == at)
		else {
			continue;
		};
		merge_absorb(&[(reader, diff.index, diff.value.clone())], &mut out);
		if let Some(inner) = attacker.knows(&diff.value) {
			let mut inner_cut = false;
			for need in read_preconditions(km, attacker, inner, memo, active, &mut inner_cut) {
				merge_absorb(&[need], &mut out);
			}
			*cut |= inner_cut;
		}
	}
	out.sort_by_key(|(state, slot, _)| (*state, *slot));
	active.pop();
	if !*cut {
		memo.insert(idx.get(), out.clone());
	}
	out
}

/// Everything a read of `slot` by `principal` depends on: the slots its value
/// is built from, and the slots every check the principal had to pass on the
/// way to it is built from. A value the principal computes after a signature
/// check exists only in executions where that check passed, so an install that
/// made it pass is a precondition of the read even though the value's own
/// definition never mentions it. Dropping those let a signature harvested from
/// one execution of a run stand beside a seed harvested from another.
fn reach_cone(km: &ProtocolTrace, principal: PrincipalId, slot: usize) -> Arc<Vec<usize>> {
	if let Some(hit) =
		CONES.with(|cones| cones.borrow_mut().fresh().get(&(principal, slot)).cloned())
	{
		return hit;
	}
	let built = Arc::new(reach_cone_uncached(km, principal, slot));
	CONES.with(|cones| {
		cones
			.borrow_mut()
			.fresh()
			.insert((principal, slot), Arc::clone(&built))
	});
	built
}

fn reach_cone_uncached(km: &ProtocolTrace, principal: PrincipalId, slot: usize) -> Vec<usize> {
	let mut out = own_cone(km, principal, slot);
	let Some(emitted_at) = km.slots.get(slot).map(|s| emitted_at(km, s, principal)) else {
		return out;
	};
	for (at, trace_slot) in km.slots.iter().enumerate() {
		if trace_slot.creator != principal || trace_slot.declared_at >= emitted_at {
			continue;
		}
		let checked = matches!(&trace_slot.initial_value, Value::Primitive(p) if p.instance_check);
		if !checked {
			continue;
		}
		for reached in own_cone(km, principal, at) {
			if !out.contains(&reached) {
				out.push(reached);
			}
		}
	}
	out
}

fn emitted_at(km: &ProtocolTrace, slot: &TraceSlot, principal: PrincipalId) -> i32 {
	let sent = slot
		.sent_by
		.iter()
		.filter(|event| event.sender == principal)
		.map(|event| event.declared_at)
		.min();
	let leaked = km
		.leaks
		.iter()
		.filter(|leak| leak.principal_id == principal && leak.constant_id == slot.constant.id)
		.map(|leak| leak.declared_at)
		.min();
	match (sent, leaked) {
		(Some(a), Some(b)) => a.min(b),
		(Some(a), None) | (None, Some(a)) => a,
		(None, None) => slot.declared_at,
	}
}

/// The slots a slot's value is built from within one principal's own
/// computation: the slot itself, and every slot its definition mentions,
/// following definitions only through slots that principal created. A slot it
/// received is a leaf, whatever its sender computed it from.
pub(crate) fn own_cone(km: &ProtocolTrace, principal: PrincipalId, slot: usize) -> Vec<usize> {
	let mut out: Vec<usize> = vec![slot];
	let mut frontier: Vec<usize> = vec![slot];
	while let Some(at) = frontier.pop() {
		let Some(trace_slot) = km.slots.get(at) else {
			continue;
		};
		if trace_slot.creator != principal && at != slot {
			continue;
		}
		let mut mentioned: Vec<Constant> = Vec::new();
		trace_slot.initial_value.collect_constants(&mut mentioned);
		for c in mentioned {
			let Some(&next) = km.index.get(&c.id) else {
				continue;
			};
			if !out.contains(&next) {
				out.push(next);
				frontier.push(next);
			}
		}
	}
	out
}

fn rule_decompose(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
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
	let mut learned = false;
	for revealed in &result.revealed {
		learned |= learn(
			ctx,
			km,
			ps,
			attacker,
			revealed,
			record,
			DerivationRecord::Decomposed {
				of: value.clone(),
				using: result.used.clone(),
			},
			|| {
				format!(
					"{} obtained by decomposing {} with {}.",
					info_output_text(revealed),
					value,
					pretty_values(&result.used),
				)
			},
		);
	}
	learned
}

fn rule_break_weak(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
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
			km,
			ps,
			attacker,
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
	km: &ProtocolTrace,
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
				found |= rule_reconstruct(ctx, km, arg, ps, attacker, record);
			}
			result
		}
		_ => return found,
	};
	if let Some(reconstructed) = result {
		let used = reconstructed.from;
		let forged = reconstructed.forged;
		let combined = reconstructed.combined;
		let derivation = match &forged {
			Some(Forged::Assumption(capability)) => DerivationRecord::Broken {
				of: value.clone(),
				capability: *capability,
				using: used.clone(),
			},
			Some(Forged::Reuse(with)) => DerivationRecord::ReusedForge {
				with: with.clone(),
				using: used.clone(),
			},
			None if combined => DerivationRecord::Combined { from: used.clone() },
			None => DerivationRecord::Reconstructed { from: used.clone() },
		};
		found |= learn(
			ctx,
			km,
			ps,
			attacker,
			value,
			record,
			derivation,
			|| match &forged {
				Some(Forged::Assumption(capability)) => format!(
					"{} forged from {} under the declared `{}` assumption.",
					info_output_text(value),
					pretty_values(&used),
					capability.name(),
				),
				Some(Forged::Reuse(with)) => format!(
					"{} forged from {} under the {} shared by {} and {}.",
					info_output_text(value),
					pretty_values(&used),
					reuse_fixed_names(&with[0]),
					with[0],
					with[1],
				),
				None if combined => format!(
					"{} obtained by combining {}.",
					info_output_text(value),
					pretty_values(&used),
				),
				None => format!(
					"{} obtained by reconstructing with {}.",
					info_output_text(value),
					pretty_values(&used),
				),
			},
		);
	}
	found
}

fn rule_reuse(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	let mut buckets: IdMap<u64, Vec<usize>> = IdMap::default();
	for (i, known) in attacker.known.iter().enumerate() {
		let Value::Primitive(p) = known else {
			continue;
		};
		let Some(rule) = reuse_rule(p.id) else {
			continue;
		};
		if attacker_mints(p, ps, attacker) && !protocol_produced(ctx, known) {
			continue;
		}
		if rule.fixed.iter().all(|&at| {
			p.arguments
				.get(at)
				.is_some_and(|a| obtainable(a, ps, attacker))
		}) {
			continue;
		}
		let mut key = u64::from(p.id);
		for &at in &rule.fixed {
			let Some(argument) = p.arguments.get(at) else {
				continue;
			};
			key = key.rotate_left(17).wrapping_add(argument.hash_value());
		}
		buckets.entry(key).or_default().push(i);
	}
	let mut progress = false;
	for members in buckets.values() {
		if members.len() < 2 {
			continue;
		}
		for &i in members {
			let of = &attacker.known[i];
			let Some(&j) = members
				.iter()
				.find(|&&j| pair_vetted(ctx, km, ps, attacker, of, &attacker.known[j]))
			else {
				continue;
			};
			let with = &attacker.known[j];
			let Value::Primitive(p) = of else {
				continue;
			};
			let Some(rule) = reuse_rule(p.id) else {
				continue;
			};
			ctx.attacker_note_reuse([of.clone(), with.clone()]);
			for reveal in &rule.reveals {
				let revealed = match *reveal {
					Reveal::Argument(index) => match p.arguments.get(index) {
						Some(argument) => reduce_once(argument),
						None => continue,
					},
					Reveal::Output(output) => Value::Primitive(Arc::new(p.with_output(output))),
				};
				progress |= learn(
					ctx,
					km,
					ps,
					attacker,
					&revealed,
					record,
					DerivationRecord::Reused {
						of: of.clone(),
						with: with.clone(),
					},
					|| {
						format!(
							"{} recovered from {}: {} shares its {}.",
							info_output_text(&revealed),
							of,
							with,
							reuse_fixed_names(of),
						)
					},
				);
			}
		}
	}
	progress
}

fn attacker_mints(p: &Arc<Primitive>, ps: &PrincipalState, attacker: &AttackerState) -> bool {
	can_reconstruct_primitive(p, ps, attacker).is_some_and(|built| built.forged.is_some())
}

fn protocol_produced(ctx: &VerifyContext, value: &Value) -> bool {
	let hash = value.hash_value();
	ctx.principal_states().iter().any(|state| {
		ctx.execution_base(state.id).is_some_and(|base| {
			base.values.iter().enumerate().any(|(i, sv)| {
				base.meta
					.get(i)
					.is_some_and(|meta| meta.creator == state.id)
					&& sv.value.hash_value() == hash
					&& sv.value.equivalent(value, true)
			})
		})
	})
}

type PairKey = (PrincipalId, u64, u64, i32, usize, usize, u64, u64);
type Pairs = crate::context::Generational<IdMap<PairKey, Vec<(Value, Value, bool)>>>;

thread_local! {
	static PAIRS: std::cell::RefCell<Pairs> =
		std::cell::RefCell::new(crate::context::Generational::default());
}

fn pair_vetted(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	of: &Value,
	with: &Value,
) -> bool {
	let key = (
		ps.id,
		of.hash_value(),
		with.hash_value(),
		attacker.current_phase,
		attacker.known.len(),
		attacker.reused.len(),
		attacker.routes_epoch,
		attacker.chain,
	);
	let remembered = PAIRS.with(|memo| {
		memo.borrow_mut().fresh().get(&key).and_then(|bucket| {
			bucket
				.iter()
				.find(|(a, b, _)| a.equivalent(of, true) && b.equivalent(with, true))
				.map(|(_, _, vetted)| *vetted)
		})
	});
	if let Some(vetted) = remembered {
		return vetted;
	}
	let vetted = reused_pair(of, with)
		&& one_execution(attacker, of, with)
		&& pair_coheres(ctx, km, ps, attacker, of, with);
	PAIRS.with(|memo| {
		memo.borrow_mut()
			.fresh()
			.entry(key)
			.or_default()
			.push((of.clone(), with.clone(), vetted));
	});
	vetted
}

fn rule_rewrite_forward(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	pre_rewrite: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	let Value::Primitive(p) = pre_rewrite else {
		return false;
	};
	let (reduces, reduced) = can_rewrite(p);
	if !reduces || reduced.equivalent(pre_rewrite, true) {
		return false;
	}
	if !p.arguments.iter().all(|arg| obtainable(arg, ps, attacker)) {
		return false;
	}
	let using = p.arguments.clone();
	learn(
		ctx,
		km,
		ps,
		attacker,
		&reduced,
		record,
		DerivationRecord::Rewritten {
			of: pre_rewrite.clone(),
			using: using.clone(),
			built: false,
		},
		|| {
			format!(
				"{} obtained by applying {} to {}.",
				info_output_text(&reduced),
				crate::primitive::primitive_name(p.id),
				pretty_values(&using),
			)
		},
	)
}

fn rule_rewrite_build(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	value: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	let Value::Primitive(inner) = value else {
		return false;
	};
	if can_decompose(inner, ps, attacker).is_some() {
		return false;
	}
	let mut progress = false;
	for spec in crate::primitive::primitives_rewriting(inner.id) {
		let Some(rule) = spec.rewrite.as_ref() else {
			continue;
		};
		if rule
			.from_output
			.is_some_and(|output| output != inner.output)
		{
			continue;
		}
		let mut pool: Vec<Value> = Vec::new();
		for (_, positions) in &rule.matching {
			for &at in positions {
				let Some(pinned) = inner.arguments.get(at) else {
					continue;
				};
				let mut candidates = vec![pinned.clone()];
				if let Value::Primitive(p) = pinned {
					candidates.extend(p.arguments.iter().cloned());
				}
				for candidate in candidates {
					if obtainable(&candidate, ps, attacker)
						&& !pool.iter().any(|held| held.equivalent(&candidate, true))
					{
						pool.push(candidate);
					}
				}
			}
		}
		if pool.is_empty() {
			continue;
		}
		for &arity in &spec.arity {
			let arity = arity as usize;
			if rule.from >= arity {
				continue;
			}
			let open: Vec<usize> = (0..arity).filter(|&at| at != rule.from).collect();
			let mut choice = vec![0usize; open.len()];
			loop {
				let mut args = vec![value.clone(); arity];
				for (&at, &pick) in open.iter().zip(choice.iter()) {
					args[at] = pool[pick].clone();
				}
				let built = Value::primitive(spec.id, args, 0);
				if let Value::Primitive(p) = &built {
					let (reduces, reduced) = can_rewrite(p);
					if reduces
						&& !reduced.equivalent(&built, true)
						&& attacker.knows(&reduced).is_none()
					{
						let using = p.arguments.clone();
						progress |= learn(
							ctx,
							km,
							ps,
							attacker,
							&reduced,
							record,
							DerivationRecord::Rewritten {
								of: built.clone(),
								using: using.clone(),
								built: true,
							},
							|| {
								format!(
									"{} obtained by applying {} to {}.",
									info_output_text(&reduced),
									crate::primitive::primitive_name(spec.id),
									pretty_values(&using),
								)
							},
						);
					}
				}
				let mut digit = 0;
				loop {
					if digit == choice.len() {
						break;
					}
					choice[digit] += 1;
					if choice[digit] < pool.len() {
						break;
					}
					choice[digit] = 0;
					digit += 1;
				}
				if digit == choice.len() {
					break;
				}
			}
		}
	}
	progress
}

fn rule_recompose(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	value: &Value,
	ps: &PrincipalState,
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
		km,
		ps,
		attacker,
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

fn rule_equivalize(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	value: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
	record: &Arc<MutationRecord>,
) -> bool {
	if let Value::Constant(c) = value
		&& ps
			.index_of(c)
			.is_some_and(|slot| ps.withheld_by_own_halt(slot))
	{
		return false;
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
			km,
			ps,
			attacker,
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

fn rule_concat_extract(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	value: &Value,
	ps: &PrincipalState,
	attacker: &AttackerState,
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
			km,
			ps,
			attacker,
			arg,
			record,
			DerivationRecord::Fragment { of: value.clone() },
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
		let ctx = VerifyContext::new(&m, &states, Vec::new(), 2, None, Vec::new());
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
