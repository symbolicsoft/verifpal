/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::knowledge::{Knowledge, Origin};
use super::program::{Event, Program};
use crate::theory::can_rewrite;
use crate::types::*;

pub(crate) type Installs = Vec<(usize, usize, Value)>;

#[derive(Clone, Debug)]
pub(crate) struct Held {
	pub(crate) value: Value,
	pub(crate) pre: Value,
	pub(crate) sender: Option<usize>,
	pub(crate) installed: bool,
	pub(crate) authored: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct RunState {
	pub(crate) env: Vec<Option<Held>>,
	pub(crate) pc: usize,
	pub(crate) halted: Option<usize>,
	pub(crate) frozen: bool,
}

impl RunState {
	pub(crate) fn held(&self, slot: usize) -> Option<&Held> {
		self.env.get(slot).and_then(Option::as_ref)
	}

	pub(crate) fn reached(&self, step: usize) -> bool {
		step < self.pc
	}
}

#[derive(Clone)]
pub(crate) struct Execution {
	pub(crate) runs: Vec<RunState>,
	pub(crate) knowledge: Knowledge,
	pub(crate) sent: Vec<Option<Vec<Value>>>,
	pub(crate) order: Vec<(usize, usize, usize)>,
	pub(crate) stuck: Vec<(usize, usize)>,
	pub(crate) partial: Vec<(usize, usize)>,
	pub(crate) phases: Vec<Knowledge>,
}

pub(crate) struct Context<'a> {
	pub(crate) program: &'a Program,
	pub(crate) km: &'a ProtocolTrace,
	pub(crate) carrier: &'a PrincipalState,
	pub(crate) initial: Knowledge,
}

impl<'a> Context<'a> {
	pub(crate) fn new(
		program: &'a Program,
		km: &'a ProtocolTrace,
		carrier: &'a PrincipalState,
	) -> Context<'a> {
		let mut initial = Knowledge::new(0);
		initial.learn(&crate::value::value_nil(), Origin::Initial);
		for slot in &km.slots {
			let c = &slot.constant;
			if c.declaration == Some(Declaration::Knows) && c.qualifier == Some(Qualifier::Public) {
				initial.learn(&Value::Constant(c.clone()), Origin::Initial);
			}
		}
		Context {
			program,
			km,
			carrier,
			initial,
		}
	}
}

fn resolve(
	v: &Value,
	env: &[Option<Held>],
	km: &ProtocolTrace,
	memo: &mut IdMap<usize, Value>,
) -> Value {
	match v {
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
		&& !crate::value::subterms(v).any(|term| {
			matches!(term, Value::Primitive(p) if p.instance_check
				&& crate::primitive::primitive_get(p.id).is_ok_and(|spec| spec.rewrite.is_some())
				&& !can_rewrite(p).0)
		})
}

pub(crate) fn evaluate(pre: &Value) -> (Value, bool) {
	match pre {
		Value::Primitive(p) => {
			let (ok, reduced) = can_rewrite(p);
			let failed = !ok && p.instance_check;
			(reduced, failed)
		}
		Value::Constant(_) => (pre.clone(), false),
	}
}

enum Outcome {
	Done,
	Blocked,
	Halted,
}

pub(crate) fn execute(cx: &Context, installs: &Installs) -> Execution {
	let program = cx.program;
	let km = cx.km;
	let n = km.slots.len();
	let mut ex = Execution {
		runs: program
			.runs
			.iter()
			.map(|_| RunState {
				env: vec![None; n],
				pc: 0,
				halted: None,
				frozen: false,
			})
			.collect(),
		knowledge: cx.initial.clone(),
		sent: vec![None; program.deliveries.len()],
		order: Vec::new(),
		stuck: Vec::new(),
		partial: Vec::new(),
		phases: Vec::new(),
	};
	let install_of = |run: usize, slot: usize| -> Option<&Value> {
		installs
			.iter()
			.find(|(r, s, _)| *r == run && *s == slot)
			.map(|(_, _, v)| v)
	};
	for phase in 0..=program.max_phase {
		ex.knowledge.set_phase(phase);
		loop {
			let mut progress = false;
			for r in 0..program.runs.len() {
				loop {
					let state = &ex.runs[r];
					if state.halted.is_some() || state.frozen {
						break;
					}
					let Some(step) = program.runs[r].steps.get(state.pc).copied() else {
						break;
					};
					if step.phase > phase {
						break;
					}
					let pc = state.pc;
					let before = ex.knowledge.len();
					let outcome = step_run(cx, &mut ex, r, step.event, &install_of);
					let known = match step.event {
						Event::Recv(_) => ex.knowledge.len(),
						_ => before,
					};
					match outcome {
						Outcome::Done => {
							ex.order.push((r, pc, known));
							ex.runs[r].pc += 1;
							progress = true;
						}
						Outcome::Halted => {
							ex.order.push((r, pc, known));
							ex.runs[r].pc += 1;
							progress = true;
							break;
						}
						Outcome::Blocked => break,
					}
				}
			}
			if !progress {
				break;
			}
		}
		for r in 0..program.runs.len() {
			let state = &ex.runs[r];
			if state.halted.is_some() || state.frozen {
				continue;
			}
			if let Some(step) = program.runs[r].steps.get(state.pc)
				&& step.phase <= phase
				&& let Event::Recv(d) = step.event
			{
				let delivery = &program.deliveries[d];
				let partly = delivery
					.slots
					.iter()
					.any(|&(slot, guarded)| !guarded && install_of(r, slot).is_some());
				if partly && ex.sent[d].is_none() {
					for &(slot, guarded) in &delivery.slots {
						if !guarded && install_of(r, slot).is_none() {
							ex.partial.push((r, slot));
						}
					}
				}
				for &(slot, guarded) in &program.deliveries[d].slots {
					if !guarded && install_of(r, slot).is_some() && !ex.stuck.contains(&(r, slot)) {
						ex.stuck.push((r, slot));
					}
				}
			}
		}
		for r in 0..program.runs.len() {
			let state = &ex.runs[r];
			if state.halted.is_some() || state.frozen {
				continue;
			}
			if program.runs[r]
				.steps
				.get(state.pc)
				.is_some_and(|step| step.phase <= phase)
			{
				ex.runs[r].frozen = true;
			}
		}
		if program.max_phase > 0 {
			ex.knowledge.close(cx.carrier);
			ex.phases.push(ex.knowledge.clone());
		}
	}
	ex.knowledge.close(cx.carrier);
	ex
}

fn step_run<'i>(
	cx: &Context,
	ex: &mut Execution,
	r: usize,
	event: Event,
	install_of: &impl Fn(usize, usize) -> Option<&'i Value>,
) -> Outcome {
	let km = cx.km;
	match event {
		Event::Hold(slot) => {
			let value = km.slots[slot].initial_value.clone();
			ex.runs[r].env[slot] = Some(Held {
				pre: value.clone(),
				value,
				sender: None,
				installed: false,
				authored: false,
			});
			Outcome::Done
		}
		Event::Assign(slot) => {
			let mut memo = IdMap::default();
			let pre = resolve(
				&km.slots[slot].initial_value,
				&ex.runs[r].env,
				km,
				&mut memo,
			);
			let (value, failed) = evaluate(&pre);
			ex.knowledge.note_protocol(&value, &pre, true);
			ex.knowledge
				.note_computed(&km.slots[slot].initial_value, &pre, &value);
			ex.runs[r].env[slot] = Some(Held {
				value,
				pre,
				sender: None,
				installed: false,
				authored: false,
			});
			if failed {
				ex.runs[r].halted = Some(slot);
				return Outcome::Halted;
			}
			Outcome::Done
		}
		Event::Leak(slot) => {
			if let Some(h) = ex.runs[r].held(slot) {
				let v = h.value.clone();
				ex.knowledge.learn(&v, Origin::Leak { run: r, slot });
			}
			Outcome::Done
		}
		Event::Send(d) => {
			let delivery = &cx.program.deliveries[d];
			let mut values = Vec::with_capacity(delivery.slots.len());
			for &(slot, _) in &delivery.slots {
				let v = ex.runs[r]
					.held(slot)
					.map(|h| h.value.clone())
					.unwrap_or_else(|| km.slots[slot].initial_value.clone());
				values.push(v);
			}
			for (&(slot, _), v) in delivery.slots.iter().zip(values.iter()) {
				ex.knowledge.learn(v, Origin::Wire { run: r, slot });
			}
			ex.sent[d] = Some(values);
			Outcome::Done
		}
		Event::Recv(d) => {
			let delivery = &cx.program.deliveries[d];
			let sent = ex.sent[d].clone();
			let mut received: Vec<(usize, Value, bool)> = Vec::with_capacity(delivery.slots.len());
			for (k, &(slot, guarded)) in delivery.slots.iter().enumerate() {
				let forwarded = sent.as_ref().map(|values| values[k].clone());
				let install = (!guarded).then(|| install_of(r, slot)).flatten();
				match (install, forwarded) {
					(Some(t), forwarded) => {
						if forwarded.as_ref().is_some_and(|f| f.equivalent(t, true)) {
							received.push((slot, t.clone(), false));
							continue;
						}
						if !deliverable(t) || !ex.knowledge.derivable(t, cx.carrier) {
							return Outcome::Blocked;
						}
						received.push((slot, t.clone(), true));
					}
					(None, Some(f)) => received.push((slot, f, false)),
					(None, None) => return Outcome::Blocked,
				}
			}
			for (slot, value, installed) in received {
				ex.knowledge.note_protocol(&value, &value, false);
				let relayed = !installed
					&& ex.runs[delivery.sender]
						.held(slot)
						.is_some_and(|h| h.authored);
				ex.runs[r].env[slot] = Some(Held {
					pre: value.clone(),
					value,
					sender: Some(delivery.sender),
					installed,
					authored: installed || relayed,
				});
			}
			Outcome::Done
		}
	}
}
