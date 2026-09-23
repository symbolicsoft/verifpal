/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub(crate) mod exec;
pub(crate) mod knowledge;
pub(crate) mod narrate;
pub(crate) mod program;
pub(crate) mod query;
pub(crate) mod search;
pub(crate) mod view;

use crate::context::VerifyContext;
use crate::info::info_message;
use crate::types::*;

use exec::{Context, Execution, Installs, execute};
use program::Program;
use query::{Judge, Violation};

pub(crate) fn verify(
	ctx: &VerifyContext,
	m: &Model,
	km: &ProtocolTrace,
	states: &[PrincipalState],
) -> VResult<()> {
	let Some(carrier) = states.first() else {
		return Ok(());
	};
	let program = Program::of(m, km);
	let cx = Context::new(&program, km, carrier);
	let root = execute(&cx, &Vec::new());
	for ps in states {
		let run = program.run_index(ps.id);
		crate::verify::check_honest_run(ctx, km, ps, |slot| {
			run.is_some_and(|r| root.runs[r].held(slot).is_some())
		})?;
	}
	info_message(
		&format!("Attacker is configured as {}.", m.attacker),
		InfoLevel::Info,
		false,
	);
	ctx.analysis_count_increment();
	for (i, v) in root.knowledge.state.known.iter().enumerate() {
		if matches!(root.knowledge.origin(i), knowledge::Origin::Initial) {
			continue;
		}
		crate::info::info_deduction(|| {
			format!(
				"{} is obtained by the attacker.",
				crate::info::info_output_text(v)
			)
		});
	}
	judge(ctx, &cx, &root, &Vec::new(), &root, states);
	if m.attacker == AttackerKind::Active && !ctx.all_resolved() {
		let mut search = search::Search::new(ctx, &cx, states, root);
		search.run();
		search.report_stats();
	}
	Ok(())
}

fn violation_at(
	ctx: &VerifyContext,
	cx: &Context,
	ex: &Execution,
	honest: &Execution,
	states: &[PrincipalState],
	phase: i32,
	q: &Query,
) -> Option<(Violation, query::Verdict)> {
	let knowledge = if cx.program.max_phase == 0 {
		&ex.knowledge
	} else {
		&ex.phases[phase as usize]
	};
	let claims = |p: PrincipalId| ctx.claims_apply_at(p, phase);
	Judge {
		cx,
		ex,
		knowledge,
		honest,
		states,
		claims: &claims,
		views: std::cell::RefCell::new(Vec::new()),
	}
	.evaluate(q)
}

type Found = (Execution, (Violation, query::Verdict));

fn minimal(
	ctx: &VerifyContext,
	cx: &Context,
	installs: &Installs,
	honest: &Execution,
	states: &[PrincipalState],
	phase: i32,
	q: &Query,
) -> Option<Found> {
	let mut kept = installs.clone();
	let mut best = None;
	let attempt = |kept: &Installs, drop: &[usize], best: &mut Option<Found>| -> Option<Installs> {
		let trial: Installs = kept
			.iter()
			.enumerate()
			.filter(|(i, _)| !drop.contains(i))
			.map(|(_, install)| install.clone())
			.collect();
		let ex = execute(cx, &trial);
		if !ex.stuck.is_empty() {
			return None;
		}
		let found = violation_at(ctx, cx, &ex, honest, states, phase, q)?;
		*best = Some((ex, found));
		Some(trial)
	};
	let message = |(run, slot, _): &(usize, usize, Value)| {
		(*run, cx.program.runs[*run].step_of_slot.get(slot).copied())
	};
	'shrink: loop {
		for width in 1..=2 {
			for i in 0..kept.len() {
				for j in i..kept.len() {
					if (width == 1) != (i == j) || message(&kept[i]) != message(&kept[j]) {
						continue;
					}
					if let Some(trial) = attempt(&kept, &[i, j], &mut best) {
						kept = trial;
						continue 'shrink;
					}
				}
			}
		}
		return best;
	}
}

pub(crate) fn judge(
	ctx: &VerifyContext,
	cx: &Context,
	ex: &Execution,
	installs: &Installs,
	honest: &Execution,
	states: &[PrincipalState],
) -> bool {
	let mut found = false;
	for phase in 0..=cx.program.max_phase {
		for result in ctx.results_get() {
			if result.resolved {
				continue;
			}
			for q in std::iter::once(&result.query).chain(result.variants.iter()) {
				let Some(first) = violation_at(ctx, cx, ex, honest, states, phase, q) else {
					continue;
				};
				match minimal(ctx, cx, installs, honest, states, phase, q) {
					Some((smaller, found)) => report(ctx, cx, &smaller, honest, &result, q, &found),
					None => report(ctx, cx, ex, honest, &result, q, &first),
				}
				found = true;
				break;
			}
		}
	}
	found
}

fn carries_a_secret(v: &Value, km: &ProtocolTrace) -> bool {
	v.constant_leaves().any(|c| {
		km.index_of(c).is_some_and(|i| {
			let declared = &km.slots[i].constant;
			declared.fresh || declared.qualifier == Some(Qualifier::Private)
		})
	})
}

fn recipient_contributed(c: &Constant, km: &ProtocolTrace, recipient: PrincipalId) -> bool {
	crate::value::resolve_trace_constant(c, km)
		.constant_leaves()
		.any(|inner| {
			km.index_of(inner).is_some_and(|i| {
				let slot = &km.slots[i];
				slot.constant.fresh && km.same_actor(slot.creator, recipient)
			})
		})
}

fn report(
	ctx: &VerifyContext,
	cx: &Context,
	ex: &Execution,
	honest: &Execution,
	result: &VerifyResult,
	q: &Query,
	(v, verdict): &(Violation, query::Verdict),
) {
	let km = cx.km;
	let program = cx.program;
	let mut out = VerifyResult::new(&result.query, result.query_index);
	out.resolved = true;
	out.options = q
		.options
		.iter()
		.filter_map(|option| {
			let c = option.message.constant().ok()?;
			Some(QueryOptionResult {
				summary: format!(
					"{} still sends {} to {}, so the failure counts.",
					option.message.sender_name, c, option.message.recipient_name,
				),
			})
		})
		.collect();
	let name = |run: usize| program.runs[run].name.clone();
	let mut narrator = narrate::Narrator::new(cx, ex, honest);
	narrator.installs();
	let shown = |narrator: &narrate::Narrator, slot: usize, value: &Value| {
		let own = km.slots[slot].constant.to_string();
		narrator.spelled(value, &[&own])
	};
	let conclusion = match v {
		Violation::Disclosed { run, slot, value } => {
			narrator.public(value);
			narrator.explain(value, ex.knowledge.len());
			let constant = &km.slots[*slot].constant;
			let value_shown = shown(&narrator, *slot, value);
			let honest_value =
				crate::theory::reduce_once(&crate::value::resolve_trace_constant(constant, km));
			if !crate::theory::reduce_once(value).equivalent(&honest_value, true)
				&& !carries_a_secret(value, km)
			{
				out.subtype = Some(Subtype::AttackerSuppliedValue);
				format!(
					"{constant} ({value_shown}) is obtained by Attacker, but that is the value the \
					 attacker put there: it carries nothing {} generated or holds privately, so the \
					 honest {constant} is not shown to be disclosed.",
					name(*run)
				)
			} else {
				format!("{constant} ({value_shown}) is obtained by Attacker.")
			}
		}
		Violation::Forged {
			run,
			slot,
			value,
			used,
		} => {
			narrator.gate(*run, *used);
			format!(
				"{} ({}), sent by Attacker and not by {}, is successfully used in {} within {}'s state.",
				km.slots[*slot].constant,
				shown(&narrator, *slot, value),
				q.message.sender_name,
				narrator.declared(*used),
				name(*run)
			)
		}
		Violation::Replayed {
			run,
			slot,
			value,
			used,
		} => {
			narrator.gate(*run, *used);
			let constant = &km.slots[*slot].constant;
			out.subtype = Some(
				if recipient_contributed(constant, km, q.message.recipient) {
					Subtype::DuplicateAcceptance
				} else {
					Subtype::ReplayableFirstFlight
				},
			);
			let axis = narrator.replayed_from(*run, *slot, value).unwrap_or("run");
			format!(
				"{constant} ({}), which {s} sent in another {axis} and not in this one, is \
				 successfully used in {} within {r}'s state: {s} sent it once, {r} accepts it \
				 twice, so agreement is not injective.",
				shown(&narrator, *slot, value),
				narrator.declared(*used),
				s = q.message.sender_name,
				r = q.message.recipient_name,
			)
		}
		Violation::Substituted {
			run,
			slot,
			sender,
			used,
		} => {
			narrator.received(*run, *slot, *sender);
			format!(
				"{}, sent by {} and not by {}, is successfully used in {} within {}'s state.",
				km.slots[*slot].constant,
				name(*sender),
				q.message.sender_name,
				narrator.declared(*used),
				name(*run)
			)
		}
		Violation::Stale {
			run,
			slot,
			value,
			used,
		} => {
			narrator.built_from(*slot, value);
			format!(
				"{} ({}) is used by {} in {} despite not being a fresh value.",
				km.slots[*slot].constant,
				shown(&narrator, *slot, value),
				name(*run),
				narrator.declared(*used)
			)
		}
		Violation::Linked { clause, resolved } => {
			narrator.resolves(resolved);
			clause.clone()
		}
		Violation::Differ { resolved } => {
			narrator.resolves(resolved);
			format!(
				"{} are not equivalent.",
				q.constants
					.iter()
					.map(|c| c.name.to_string())
					.collect::<Vec<_>>()
					.join(", ")
			)
		}
	};
	out.set_summary(
		&narrator.trace(),
		std::mem::take(&mut narrator.steps),
		&conclusion,
	);
	crate::query::record_verdict(ctx, &out, verdict);
}
