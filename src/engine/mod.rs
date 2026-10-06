/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub(crate) mod exec;
pub(crate) mod judgment;
pub(crate) mod knowledge;
pub(crate) mod narrate;
pub(crate) mod program;
pub(crate) mod search;
pub(crate) mod unlink;

use crate::console::{InfoLevel, info_message};
use crate::protocol::ProtocolTrace;
use crate::syntax::{AttackerKind, Model, PrincipalId, Query, VResult, VerifpalError};
use crate::term::{Constant, Value};
use crate::verify::context::VerifyContext;
use crate::verify::{QueryOptionResult, Subtype, VerifyResult};
use exec::{Context, Execution, Installs, execute};
use judgment::{Judge, Violation};
use program::Program;

pub(crate) fn verify(ctx: &VerifyContext, m: &Model, km: &ProtocolTrace) -> VResult<()> {
	let program = Program::of(m, km);
	let cx = Context::new(&program, km);
	let root = execute(&cx, &Vec::new());
	check_honest_run(ctx, km, &program, &root)?;
	info_message(
		&format!("Attacker is configured as {}.", m.attacker),
		InfoLevel::Info,
	);
	ctx.analysis_count_increment();
	for (i, v) in root.knowledge.state.known.iter().enumerate() {
		if matches!(root.knowledge.origin(i), knowledge::Origin::Initial) {
			continue;
		}
		crate::console::info_deduction(|| {
			format!(
				"{} is obtained by the attacker.",
				crate::console::info_output_text(v)
			)
		});
	}
	judge(ctx, &cx, &root, &Vec::new(), &root);
	if m.attacker == AttackerKind::Active && !ctx.all_resolved() {
		let mut search = search::Search::new(ctx, &cx, root);
		search.run();
		search.report_stats();
	}
	Ok(())
}

fn check_honest_run(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	program: &Program,
	root: &Execution,
) -> VResult<()> {
	let located = |e: VerifpalError, slot: usize| e.or_span(km.slots[slot].declared_span);
	let failed = root
		.runs
		.iter()
		.filter_map(|run| run.halted.map(|slot| (slot, run)))
		.filter(|&(slot, _)| {
			let creator = km.slots[slot].creator;
			ctx.is_honest_at(creator, program.phase_of(creator, slot))
		})
		.min_by_key(|&(slot, _)| slot);
	if let Some((slot, run)) = failed
		&& let Some(Value::Primitive(p)) = run.held(slot).map(|held| &held.value)
	{
		return Err(located(
			crate::protocol::sanity::honest_check_failure(p),
			slot,
		));
	}
	for run in &root.runs {
		for (slot, held) in run.env.iter().enumerate() {
			if let Some(held) = held {
				crate::protocol::sanity::sanity_check_argument_restrictions(&held.value)
					.map_err(|e| located(e, slot))?;
			}
		}
	}
	Ok(())
}

type Found = (Violation, judgment::Verdict);

fn minimal(
	cx: &Context,
	installs: &Installs,
	violation: impl Fn(&Execution) -> Option<Found>,
) -> Option<(Execution, Found)> {
	let message = |(run, slot, _): &(usize, usize, Value)| {
		(*run, cx.program.runs[*run].step_of_slot.get(slot).copied())
	};
	let mut kept = installs.clone();
	let mut best = None;
	loop {
		let n = kept.len();
		let singles = (0..n).map(|i| (i, i));
		let pairs = (0..n)
			.flat_map(|i| (i + 1..n).map(move |j| (i, j)))
			.filter(|&(i, j)| message(&kept[i]) == message(&kept[j]));
		let Some((trial, found)) = singles.chain(pairs).find_map(|(i, j)| {
			let trial: Installs = kept
				.iter()
				.enumerate()
				.filter(|&(k, _)| k != i && k != j)
				.map(|(_, install)| install.clone())
				.collect();
			let ex = execute(cx, &trial);
			if !ex.stuck.is_empty() {
				return None;
			}
			let found = violation(&ex)?;
			Some((trial, (ex, found)))
		}) else {
			return best;
		};
		kept = trial;
		best = Some(found);
	}
}

pub(crate) fn judge(
	ctx: &VerifyContext,
	cx: &Context,
	ex: &Execution,
	installs: &Installs,
	honest: &Execution,
) {
	for phase in 0..=cx.km.max_phase {
		let claims = |p: PrincipalId| ctx.claims_at(p, phase);
		let violation = |ex: &Execution, q: &Query| Judge::at(cx, ex, phase, &claims).evaluate(q);
		for (index, queries) in ctx.unresolved() {
			for q in &queries {
				let Some(first) = violation(ex, q) else {
					continue;
				};
				let smaller = minimal(cx, installs, |ex| violation(ex, q));
				let (ex, found) = match &smaller {
					Some((smaller, found)) => (smaller, found),
					None => (ex, &first),
				};
				let out = VerifyResult::new(&queries[0], index);
				report(ctx, cx, ex.at(phase), honest, out, q, found);
				break;
			}
		}
	}
}

fn carries_a_secret(v: &Value, km: &ProtocolTrace) -> bool {
	v.constant_leaves().any(|c| unlink::declared_secret(c, km))
}

fn recipient_contributed(c: &Constant, km: &ProtocolTrace, recipient: PrincipalId) -> bool {
	crate::protocol::trace::resolve_trace_constant(c, km)
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
	mut out: VerifyResult,
	q: &Query,
	(v, verdict): &Found,
) {
	let km = cx.km;
	let program = cx.program;
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
	let name = |run: usize| program.runs[run].name.as_str();
	let mut narrator = narrate::Narrator::new(cx, ex, honest);
	narrator.installs();
	let shown = |narrator: &narrate::Narrator, slot: usize, value: &Value| {
		let own = km.slots[slot].constant.to_string();
		narrator.spelled(value, &[&own])
	};
	let conclusion = match v {
		Violation::Disclosed { run, slot, value } => {
			narrator.public(value);
			narrator.explain(value, ex.order.len());
			let constant = &km.slots[*slot].constant;
			let value_shown = shown(&narrator, *slot, value);
			if !crate::theory::reduce_once(value)
				.equivalent(&unlink::honest_reduct(km, *slot), true)
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
			emissions,
			acceptances,
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
			let times = |n: usize| match n {
				1 => "once".to_string(),
				2 => "twice".to_string(),
				n => format!("{n} times"),
			};
			format!(
				"{constant} ({}), which {s} sent in another {axis} and not in this one, is \
				 successfully used in {} within {}'s state: {s} sent it {}, {r} accepts it \
				 {}, so agreement is not injective.",
				shown(&narrator, *slot, value),
				narrator.declared(*used),
				name(*run),
				times(*emissions),
				times(*acceptances),
				s = crate::syntax::names::copy_base_name(&q.message.sender_name),
				r = crate::syntax::names::copy_base_name(&q.message.recipient_name),
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
			repeated: None,
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
		Violation::Stale {
			run,
			slot,
			value,
			used,
			repeated: Some(other),
		} => {
			narrator.gate(*run, *used);
			format!(
				"{} ({}) is used by {} in {}, and {} accepts the same value: the attacker keeps \
				 it the same across sessions, so it is not fresh.",
				km.slots[*slot].constant,
				shown(&narrator, *slot, value),
				name(*run),
				narrator.declared(*used),
				name(*other)
			)
		}
		Violation::Linked { link, resolved } => {
			narrator.resolves(resolved);
			let [a, b] = [&resolved[0].0, &resolved[1].0].map(ToString::to_string);
			format!(
				"Attacker links {a} and {b} {}.",
				link.describe(|v| narrator.term(v, &[&a, &b]))
			)
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
	crate::verify::record::record_verdict(ctx, &out, verdict);
}
