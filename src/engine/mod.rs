/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub(crate) mod exec;
pub(crate) mod judgment;
pub(crate) mod knowledge;
pub(crate) mod narrate;
pub(crate) mod program;
pub(crate) mod search;
pub(crate) mod unlink;

use crate::console::InfoLevel;
use crate::protocol::ProtocolTrace;
use crate::protocol::SlotIdx;
use crate::syntax::{AttackerKind, Model, PrincipalId, Query, VResult, VerifpalError};
use crate::term::Value;
use crate::verify::context::VerifyContext;
use crate::verify::{QueryOptionResult, VerifyResult};
use exec::{Context, Execution, Install, Installs, execute};
use judgment::{Judge, Violation};
use program::Program;

pub(crate) fn verify(ctx: &VerifyContext, m: &Model, km: &ProtocolTrace) -> VResult<()> {
	let program = Program::of(m, km);
	let cx = Context::new(&program, km);
	let root = execute(&cx, &Vec::new());
	check_honest_run(ctx, km, &program, &root)?;
	crate::console::message(
		&format!("Attacker is configured as {}.", m.attacker),
		InfoLevel::Info,
	);
	ctx.analysis_count_increment();
	for (i, v) in root.knowledge.state.known.iter().enumerate() {
		if matches!(root.knowledge.origin(i), knowledge::Origin::Initial) {
			continue;
		}
		crate::console::deduction(|| {
			format!(
				"{} is obtained by the attacker.",
				crate::console::output_text(v)
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
	let located = |e: VerifpalError, slot: SlotIdx| e.or_span(km.slots[slot].declared_span);
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
		for (slot, held) in run.env.iter_enumerated() {
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
	let message = |install: &Install| {
		let run = install.run();
		let step = install
			.slot()
			.and_then(|slot| cx.program.runs[run].step_of_slot.get(&slot).copied());
		(run, step)
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

fn report(
	ctx: &VerifyContext,
	cx: &Context,
	ex: &Execution,
	honest: &Execution,
	mut out: VerifyResult,
	q: &Query,
	(v, verdict): &Found,
) {
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
	let mut narrator = narrate::Narrator::new(cx, ex, honest);
	narrator.installs();
	let (conclusion, subtype) = narrator.conclude(q, v);
	out.subtype = subtype;
	out.set_summary(
		&narrator.trace(),
		std::mem::take(&mut narrator.steps),
		&conclusion,
	);
	crate::verify::record::record_verdict(ctx, &out, verdict);
}
