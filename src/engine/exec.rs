/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::knowledge::{Knowledge, Origin};
use super::program::{DeliveryIdx, Event, Program, RunIdx, StepIdx};
use crate::primitive::CapabilityIndex;
use crate::protocol::ProtocolTrace;
use crate::protocol::SlotIdx;
use crate::syntax::{Declaration, Qualifier};
use crate::term::Value;
use crate::theory::can_rewrite;
use crate::util::IdMap;
use crate::util::index::{Idx, IndexVec};

#[derive(Clone, Debug)]
pub(crate) enum Install {
	Value {
		run: RunIdx,
		slot: SlotIdx,
		value: Value,
	},
	Idle {
		run: RunIdx,
	},
	Drop {
		run: RunIdx,
		slot: SlotIdx,
	},
}

impl Install {
	pub(crate) fn run(&self) -> RunIdx {
		match self {
			Install::Value { run, .. } | Install::Idle { run } | Install::Drop { run, .. } => *run,
		}
	}

	pub(crate) fn slot(&self) -> Option<SlotIdx> {
		match self {
			Install::Value { slot, .. } | Install::Drop { slot, .. } => Some(*slot),
			Install::Idle { .. } => None,
		}
	}

	pub(crate) fn value(&self) -> Option<&Value> {
		match self {
			Install::Value { value, .. } => Some(value),
			Install::Idle { .. } | Install::Drop { .. } => None,
		}
	}

	pub(crate) fn same(&self, other: &Install) -> bool {
		match (self, other) {
			(
				Install::Value { run, slot, value },
				Install::Value {
					run: r,
					slot: s,
					value: v,
				},
			) => run == r && slot == s && value.equivalent(v, true),
			(Install::Idle { run }, Install::Idle { run: r }) => run == r,
			(Install::Drop { run, slot }, Install::Drop { run: r, slot: s }) => {
				run == r && slot == s
			}
			_ => false,
		}
	}

	pub(crate) fn same_input(&self, other: &Install) -> bool {
		self.run() == other.run() && self.slot() == other.slot()
	}

	pub(crate) fn order(&self) -> (RunIdx, bool, Option<SlotIdx>) {
		(self.run(), self.slot().is_none(), self.slot())
	}
}

pub(crate) type Installs = Vec<Install>;

#[derive(Clone, Debug)]
pub(crate) struct Held {
	pub(crate) value: Value,
	pub(crate) pre: Value,
	pub(crate) sender: Option<RunIdx>,
	pub(crate) installed: Option<Arc<[Value]>>,
	pub(crate) authored: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct RunState {
	pub(crate) env: IndexVec<SlotIdx, Option<Held>>,
	pub(crate) pc: StepIdx,
	pub(crate) halted: Option<SlotIdx>,
	pub(crate) frozen: bool,
	pub(crate) idle: bool,
}

impl RunState {
	pub(crate) fn held(&self, slot: SlotIdx) -> Option<&Held> {
		self.env.get(slot).and_then(Option::as_ref)
	}

	pub(crate) fn reached(&self, step: StepIdx) -> bool {
		step < self.pc
	}
}

#[derive(Clone)]
pub(crate) struct Execution {
	pub(crate) runs: IndexVec<RunIdx, RunState>,
	pub(crate) knowledge: Knowledge,
	pub(crate) sent: IndexVec<DeliveryIdx, Option<Vec<Value>>>,
	pub(crate) order: Vec<Taken>,
	pub(crate) stuck: Vec<(RunIdx, SlotIdx)>,
	pub(crate) withheld: Vec<(RunIdx, SlotIdx)>,
	pub(crate) barriers: Vec<Execution>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Taken {
	pub(crate) run: RunIdx,
	pub(crate) step: StepIdx,
	pub(crate) known: usize,
}

impl Execution {
	pub(crate) fn at(&self, phase: i32) -> &Execution {
		usize::try_from(phase)
			.ok()
			.and_then(|phase| self.barriers.get(phase))
			.unwrap_or(self)
	}
}

pub(crate) struct Context<'a> {
	pub(crate) program: &'a Program,
	pub(crate) km: &'a ProtocolTrace,
	pub(crate) initial: Knowledge,
}

impl<'a> Context<'a> {
	pub(crate) fn new(program: &'a Program, km: &'a ProtocolTrace) -> Context<'a> {
		let mut initial = Knowledge::new(0);
		initial.learn(&crate::term::value_nil(), Origin::Initial);
		for slot in &km.slots {
			let c = &slot.constant;
			if c.declaration == Some(Declaration::Knows) && c.qualifier == Some(Qualifier::Public) {
				initial.learn(&Value::Constant(c.clone()), Origin::Initial);
			}
		}
		Context {
			program,
			km,
			initial,
		}
	}
}

fn resolve(
	v: &Value,
	env: &IndexVec<SlotIdx, Option<Held>>,
	km: &ProtocolTrace,
	memo: &mut IdMap<usize, Value>,
) -> Value {
	match v {
		Value::Variable(_) => v.clone(),
		Value::Constant(c) => match km.index_of(c).and_then(|i| env.get(i)?.as_ref()) {
			Some(h) => h.value.clone(),
			None => v.clone(),
		},
		Value::Primitive(p) => {
			let key = Arc::as_ptr(p) as usize;
			if let Some(hit) = memo.get(&key) {
				return hit.clone();
			}
			let out = match p.map_arguments(|a| {
				let r = resolve(a, env, km, memo);
				(!r.same_term(a)).then_some(r)
			}) {
				Some(mapped) => Value::Primitive(Arc::new(mapped)),
				None => v.clone(),
			};
			memo.insert(key, out.clone());
			out
		}
	}
}

fn deliverable(v: &Value) -> bool {
	crate::primitive::admissible(v)
		&& !crate::term::subterms(v).any(|term| {
			matches!(term, Value::Primitive(p) if p.instance_check
				&& crate::primitive::rewrite_rule(p.id).is_some()
				&& !can_rewrite(p).0)
		})
}

fn installed_components(
	value: &Value,
	knowledge: &Knowledge,
	capabilities: &CapabilityIndex,
) -> Arc<[Value]> {
	let _memo = crate::theory::DeductionMemo::scoped(capabilities, &knowledge.state);
	let mut seen = crate::term::hashing::TermSet::default();
	let mut pending = vec![value.clone()];
	let mut out = Vec::new();
	while let Some(value) = pending.pop() {
		if !seen.insert(value.clone()) {
			continue;
		}
		if let Value::Primitive(p) = &value
			&& let Some(recipe) =
				crate::theory::can_reconstruct_primitive(p, capabilities, &knowledge.state)
		{
			pending.extend(recipe.supplied().iter().cloned());
		}
		out.push(value);
	}
	out.into()
}

fn delivered(installs: &Installs, run: RunIdx, slot: SlotIdx) -> Option<Value> {
	install_at(installs, run, slot)
		.map(|value| crate::term::hashing::hashcons(&crate::theory::reduce_once(value)))
}

pub(crate) fn install_at(installs: &Installs, run: RunIdx, slot: SlotIdx) -> Option<&Value> {
	installs.iter().find_map(|install| match install {
		Install::Value {
			run: r,
			slot: s,
			value,
		} if *r == run && *s == slot => Some(value),
		_ => None,
	})
}

fn idle(installs: &Installs, run: RunIdx) -> bool {
	installs
		.iter()
		.any(|install| matches!(install, Install::Idle { run: r } if *r == run))
}

pub(crate) fn dropped(installs: &Installs, run: RunIdx, slot: SlotIdx) -> bool {
	installs.iter().any(
		|install| matches!(install, Install::Drop { run: r, slot: s } if *r == run && *s == slot),
	)
}

fn lacks(cx: &Context, r: RunIdx, state: &RunState, event: Event) -> bool {
	let km = cx.km;
	let run = &cx.program.runs[r];
	let missing = |slot: SlotIdx| {
		state.held(slot).is_none()
			&& run
				.step_of_slot
				.get(&slot)
				.is_some_and(|&at| matches!(run.steps[at].event, Event::Recv(_)))
	};
	match event {
		Event::Assign(slot) => km.slots[slot]
			.initial_value
			.constant_leaves()
			.filter_map(|c| km.index_of(c))
			.any(missing),
		Event::Send(d) => cx.program.deliveries[d]
			.slots
			.iter()
			.any(|&(slot, _)| missing(slot)),
		Event::Leak(slot) => missing(slot),
		Event::Hold(_) | Event::Recv(_) => false,
	}
}

pub(crate) fn execute(cx: &Context, installs: &Installs) -> Execution {
	let program = cx.program;
	let km = cx.km;
	let n = km.slots.len();
	let mut ex = Execution {
		runs: program
			.runs
			.indices()
			.map(|r| {
				let idle = idle(installs, r);
				RunState {
					env: IndexVec::from_elem(None, n),
					pc: StepIdx::new(0),
					halted: None,
					frozen: idle,
					idle,
				}
			})
			.collect(),
		knowledge: cx.initial.clone(),
		sent: IndexVec::from_elem(None, program.deliveries.len()),
		order: Vec::new(),
		stuck: Vec::new(),
		withheld: Vec::new(),
		barriers: Vec::new(),
	};
	let mut barriers = Vec::new();
	for phase in 0..=km.max_phase {
		ex.knowledge.set_phase(phase);
		let mut early = false;
		loop {
			let progress = if early {
				let mut waiting: Vec<(DeliveryIdx, RunIdx)> = program
					.runs
					.indices()
					.filter_map(|r| match program.runs[r].steps.get(ex.runs[r].pc)?.event {
						Event::Recv(d) => Some((d, r)),
						_ => None,
					})
					.collect();
				waiting.sort_unstable();
				waiting
					.into_iter()
					.any(|(_, r)| advance(cx, &mut ex, r, installs, phase, true))
			} else {
				let mut progress = false;
				for r in program.runs.indices() {
					progress |= advance(cx, &mut ex, r, installs, phase, false);
				}
				progress
			};
			if progress {
				early = false;
			} else if early {
				break;
			} else {
				early = true;
			}
		}
		freeze(cx, &mut ex, installs, phase);
		if phase < km.max_phase {
			ex.knowledge.close(&cx.km.capabilities);
			barriers.push(ex.clone());
		}
	}
	ex.knowledge.close(&cx.km.capabilities);
	ex.barriers = barriers;
	ex
}

fn advance(
	cx: &Context,
	ex: &mut Execution,
	r: RunIdx,
	installs: &Installs,
	phase: i32,
	early: bool,
) -> bool {
	let mut progress = false;
	loop {
		let state = &ex.runs[r];
		if state.halted.is_some() || state.frozen {
			break;
		}
		let Some(step) = cx.program.runs[r].steps.get(state.pc).copied() else {
			break;
		};
		if lacks(cx, r, state, step.event) {
			break;
		}
		if step.phase > phase {
			break;
		}
		let pc = state.pc;
		let before = ex.knowledge.len();
		if !step_run(cx, ex, r, step.event, installs, early) {
			break;
		}
		let known = match step.event {
			Event::Recv(_) => ex.knowledge.len(),
			_ => before,
		};
		ex.order.push(Taken {
			run: r,
			step: pc,
			known,
		});
		ex.runs[r].pc = pc.next();
		progress = true;
		if early {
			break;
		}
	}
	progress
}

fn freeze(cx: &Context, ex: &mut Execution, installs: &Installs, phase: i32) {
	let program = cx.program;
	for r in program.runs.indices() {
		let state = &ex.runs[r];
		if state.halted.is_some() || state.frozen {
			continue;
		}
		let Some(step) = program.runs[r].steps.get(state.pc) else {
			continue;
		};
		if step.phase > phase {
			continue;
		}
		let pc = state.pc;
		let lacking = lacks(cx, r, state, step.event);
		ex.runs[r].frozen = true;
		if lacking {
			continue;
		}
		if let Event::Recv(d) = step.event {
			for &(slot, guarded) in &program.deliveries[d].slots {
				if !guarded
					&& install_at(installs, r, slot).is_none()
					&& !dropped(installs, r, slot)
					&& ex.sent[d].is_none()
				{
					ex.withheld.push((r, slot));
				}
			}
		}
		for later in program.runs[r].steps.indices_from(pc) {
			let step = program.runs[r].steps[later];
			if step.phase > phase {
				break;
			}
			let Event::Recv(d) = step.event else {
				continue;
			};
			for &(slot, guarded) in &program.deliveries[d].slots {
				if guarded {
					continue;
				}
				if let Some(t) = delivered(installs, r, slot)
					&& !ex.stuck.contains(&(r, slot))
					&& !(deliverable(&t) && ex.knowledge.derivable(&t, &cx.km.capabilities))
				{
					ex.stuck.push((r, slot))
				}
			}
		}
	}
}

fn assign(cx: &Context, ex: &mut Execution, r: RunIdx, slot: SlotIdx) {
	let km = cx.km;
	let mut memo = IdMap::default();
	let pre = resolve(
		&km.slots[slot].initial_value,
		&ex.runs[r].env,
		km,
		&mut memo,
	);
	let pre = crate::term::hashing::hashcons(&pre);
	let (value, failed) = match &pre {
		Value::Primitive(p) => {
			let (ok, reduced) = can_rewrite(p);
			(
				crate::term::hashing::hashcons(&reduced),
				!ok && p.instance_check,
			)
		}
		Value::Constant(_) => (pre.clone(), false),
		Value::Variable(_) => (pre.clone(), true),
	};
	ex.knowledge.note_protocol(&value, &pre, true);
	ex.knowledge
		.note_computed(&km.slots[slot].initial_value, &pre, &value);
	ex.runs[r].env[slot] = Some(Held {
		value,
		pre,
		sender: None,
		installed: None,
		authored: false,
	});
	if failed {
		ex.runs[r].halted = Some(slot);
	}
}

fn step_run(
	cx: &Context,
	ex: &mut Execution,
	r: RunIdx,
	event: Event,
	installs: &Installs,
	early: bool,
) -> bool {
	let km = cx.km;
	match event {
		Event::Hold(slot) => {
			let value = crate::term::hashing::hashcons(&km.slots[slot].initial_value);
			ex.runs[r].env[slot] = Some(Held {
				pre: value.clone(),
				value,
				sender: None,
				installed: None,
				authored: false,
			});
		}
		Event::Assign(slot) => assign(cx, ex, r, slot),
		Event::Leak(slot) => {
			if let Some(h) = ex.runs[r].held(slot) {
				let v = h.value.clone();
				ex.knowledge.learn(&v, Origin::Leak { run: r, slot });
			}
		}
		Event::Send(d) => {
			let delivery = &cx.program.deliveries[d];
			let mut values = Vec::with_capacity(delivery.slots.len());
			for &(slot, _) in &delivery.slots {
				let v = ex.runs[r]
					.held(slot)
					.map_or_else(|| km.slots[slot].initial_value.clone(), |h| h.value.clone());
				ex.knowledge.learn(&v, Origin::Wire { run: r, slot });
				values.push(v);
			}
			ex.sent[d] = Some(values);
		}
		Event::Recv(d) => {
			let delivery = &cx.program.deliveries[d];
			let sent = ex.sent[d].clone();
			let kept = |&(_, &(slot, _)): &(usize, &(SlotIdx, bool))| !dropped(installs, r, slot);
			if sent.is_none() != early
				|| (sent.is_none() && delivery.slots.iter().enumerate().any(|slot| !kept(&slot)))
			{
				return false;
			}
			let mut received: Vec<(SlotIdx, Value, bool)> =
				Vec::with_capacity(delivery.slots.len());
			for (k, &(slot, guarded)) in delivery.slots.iter().enumerate().filter(kept) {
				let forwarded = sent.as_ref().map(|values| values[k].clone());
				let install = (!guarded).then(|| delivered(installs, r, slot)).flatten();
				match (install, forwarded) {
					(Some(t), forwarded) => {
						if forwarded.as_ref().is_some_and(|f| f.equivalent(&t, true)) {
							received.push((slot, t, false));
							continue;
						}
						if !deliverable(&t) || !ex.knowledge.derivable(&t, &cx.km.capabilities) {
							return false;
						}
						received.push((slot, t, true));
					}
					(None, Some(f)) => received.push((slot, f, false)),
					(None, None) => return false,
				}
			}
			for (slot, value, installed) in received {
				let components = installed
					.then(|| installed_components(&value, &ex.knowledge, &cx.km.capabilities));
				ex.knowledge.note_protocol(&value, &value, false);
				let relayed = !installed
					&& ex.runs[delivery.sender]
						.held(slot)
						.is_some_and(|h| h.authored);
				ex.runs[r].env[slot] = Some(Held {
					pre: value.clone(),
					value,
					sender: Some(delivery.sender),
					installed: components,
					authored: installed || relayed,
				});
			}
		}
	}
	true
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn an_install_its_sender_then_sends_is_not_authored() {
		let _generation = crate::util::generation::GenerationGuard::enter();
		let source = "attacker[active]\n\
			principal Ech_a[\n\
			generates ech_x\n\
			]\n\
			Ech_a -> Ech_b: ech_x\n\
			principal Ech_b[\n\
			ech_y = HASH(ech_x)\n\
			]\n\
			Ech_b -> Ech_c: ech_y\n\
			principal Ech_c[\n\
			ech_z = HASH(ech_y)\n\
			]\n\
			queries[\n\
			confidentiality? ech_x\n\
			]\n";
		let m = crate::syntax::parser::parse_string("ech.vp", source).expect("parses");
		let km = crate::protocol::sanity::sanity(&m).expect("sane");
		let program = Program::of(&m, &km);
		let cx = Context::new(&program, &km);
		let run = |name: &str| program.runs.position(|r| r.name == name).expect("run");
		let slot = |name: &str| {
			km.slots
				.position(|s| s.constant.name.as_ref() == name)
				.expect("declared")
		};
		let nil = crate::term::value_nil();
		let installs: Installs = vec![
			Install::Idle { run: run("Ech_a") },
			Install::Value {
				run: run("Ech_b"),
				slot: slot("ech_x"),
				value: nil.clone(),
			},
			Install::Value {
				run: run("Ech_c"),
				slot: slot("ech_y"),
				value: Value::primitive(crate::primitive::PRIM_HASH, vec![nil], 0),
			},
		];
		let ex = execute(&cx, &installs);
		assert!(ex.stuck.is_empty());
		let held = ex.runs[run("Ech_c")].held(slot("ech_y")).expect("received");
		assert!(
			held.installed.is_none() && !held.authored,
			"Ech_b sends HASH(nil) itself once it receives nil"
		);
	}

	#[test]
	fn a_value_its_sender_never_sent_cannot_be_dropped() {
		let _generation = crate::util::generation::GenerationGuard::enter();
		let m = crate::syntax::parser::parse_string(
			"unsent.vp",
			include_str!("../../examples/test/equivalence_unexecuted_assignment.vp"),
		)
		.expect("parses");
		let km = crate::protocol::sanity::sanity(&m).expect("sane");
		let program = Program::of(&m, &km);
		let cx = Context::new(&program, &km);
		let charlie = program.runs.position(|r| r.name == "Charlie").expect("run");
		let slot = |name: &str| {
			km.slots
				.position(|s| s.constant.name.as_ref() == name)
				.expect("declared")
		};
		let replaced = Install::Value {
			run: charlie,
			slot: slot("x"),
			value: crate::term::value_nil(),
		};
		let drop = Install::Drop {
			run: charlie,
			slot: slot("ack"),
		};
		let ex = execute(&cx, &vec![replaced.clone(), drop.clone()]);
		assert!(
			ex.runs[charlie].held(slot("right")).is_none(),
			"Bob halts and never sends ack, so Charlie still waits for it"
		);
		let ex = execute(&cx, &vec![drop]);
		assert!(
			ex.runs[charlie].held(slot("ack")).is_none()
				&& ex.runs[charlie].held(slot("right")).is_some(),
			"once Bob sends ack, dropping it lets Charlie go on without it"
		);
	}
}
