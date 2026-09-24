/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::exec::{Context, Execution};
use super::program::Event;
use crate::primitive::primitive_has_rewrite_rule;
use crate::theory::{can_rewrite, obtainable, reduce_once};
use crate::types::*;

#[derive(Clone, Debug)]
pub(crate) enum Violation {
	Disclosed {
		run: usize,
		slot: usize,
		value: Value,
	},
	Forged {
		run: usize,
		slot: usize,
		value: Value,
		used: usize,
	},
	Replayed {
		run: usize,
		slot: usize,
		value: Value,
		used: usize,
	},
	Substituted {
		run: usize,
		slot: usize,
		sender: usize,
		used: usize,
	},
	Stale {
		run: usize,
		slot: usize,
		value: Value,
		used: usize,
	},
	Linked {
		clause: String,
		resolved: Vec<(Constant, Value)>,
	},
	Differ {
		resolved: Vec<(Constant, Value)>,
	},
}

pub(crate) struct Verdict(());

#[cfg(test)]
impl Verdict {
	pub(crate) fn for_test() -> Verdict {
		Verdict(())
	}
}

pub(crate) struct Judge<'a, 'b> {
	pub(crate) cx: &'a Context<'b>,
	pub(crate) ex: &'a Execution,
	pub(crate) honest: &'a Execution,
	pub(crate) states: &'a [PrincipalState],
	pub(crate) claims: &'a dyn Fn(PrincipalId) -> bool,
	pub(crate) views: std::cell::RefCell<Vec<Option<std::rc::Rc<PrincipalState>>>>,
}

impl Judge<'_, '_> {
	pub(crate) fn view(&self, r: usize) -> std::rc::Rc<PrincipalState> {
		let mut views = self.views.borrow_mut();
		if views.len() <= r {
			views.resize(self.ex.runs.len(), None);
		}
		views[r]
			.get_or_insert_with(|| {
				std::rc::Rc::new(super::view::project(
					self.cx,
					self.ex,
					self.honest,
					&self.states[r],
					r,
				))
			})
			.clone()
	}

	fn km(&self) -> &ProtocolTrace {
		self.cx.km
	}

	pub(crate) fn evaluate(&self, q: &Query) -> Option<(Violation, Verdict)> {
		if !self.preconditions(q) {
			return None;
		}
		let violation = match q.kind {
			QueryKind::Confidentiality => self.confidentiality(q),
			QueryKind::Authentication => self.authentication(q),
			QueryKind::Freshness => self.freshness(q),
			QueryKind::Unlinkability => self.unlinkability(q),
			QueryKind::Equivalence => self.equivalence(q),
		}?;
		Some((violation, Verdict(())))
	}

	fn preconditions(&self, q: &Query) -> bool {
		let program = self.cx.program;
		q.options.iter().all(|option| {
			let Ok(c) = option.message.constant() else {
				return false;
			};
			let Some(slot) = self.km().index_of(c) else {
				return false;
			};
			program.deliveries.iter().enumerate().any(|(d, delivery)| {
				program.runs[delivery.sender].id == option.message.sender
					&& program.runs[delivery.recipient].id == option.message.recipient
					&& delivery.slots.iter().any(|&(s, _)| s == slot)
					&& self.ex.sent[d].is_some()
			})
		})
	}

	fn confidentiality(&self, q: &Query) -> Option<Violation> {
		let c = q.subject().ok()?;
		let slot = self.km().index_of(c)?;
		let knowledge = &self.ex.knowledge;
		for (r, run) in self.ex.runs.iter().enumerate() {
			if !(self.claims)(self.cx.program.runs[r].id) {
				continue;
			}
			let Some(h) = run.held(slot) else {
				continue;
			};
			if knowledge.knows(&h.value).is_some()
				|| obtainable(&h.value, self.cx.carrier, &knowledge.state)
			{
				return Some(Violation::Disclosed {
					run: r,
					slot,
					value: h.value.clone(),
				});
			}
		}
		None
	}

	pub(crate) fn uses(&self, run: usize, target: ValueId) -> Option<Vec<usize>> {
		let km = self.km();
		let program = &self.cx.program.runs[run];
		let state = &self.ex.runs[run];
		let sites = |mentioned: &dyn Fn(&Value) -> bool| -> Vec<(usize, usize)> {
			program
				.steps
				.iter()
				.enumerate()
				.filter_map(|(i, step)| match step.event {
					Event::Assign(slot)
						if matches!(km.slots[slot].initial_value, Value::Primitive(_))
							&& mentioned(&km.slots[slot].initial_value) =>
					{
						Some((i, slot))
					}
					_ => None,
				})
				.collect()
		};
		let mut mentioning = sites(&|v| mentions(km, v, target, program.id, &mut Vec::new()));
		if mentioning.is_empty() {
			let ps = &self.states[run];
			mentioning =
				sites(&|v| crate::resolution::state_mentions(v, km, ps, program.id, target));
		}
		let mut uses = Vec::new();
		for (i, slot) in mentioning {
			if !state.reached(i) {
				return None;
			}
			let h = state.held(slot)?;
			let Value::Primitive(pre) = &h.pre else {
				continue;
			};
			if !primitive_has_rewrite_rule(pre.id) || can_rewrite(pre).0 || !pre.instance_check {
				uses.push(slot);
			}
		}
		Some(uses)
	}

	fn accepted(&self, run: usize, slot: usize) -> bool {
		let id = self.km().slots[slot].constant.id;
		self.uses(run, id).is_some_and(|uses| !uses.is_empty())
	}

	fn siblings(&self, slot: usize) -> Vec<usize> {
		let km = self.km();
		let id = km.slots[slot].constant.id;
		let mut out = vec![slot];
		for groups in [&km.session_siblings, &km.copy_siblings] {
			if let Some(group) = groups.get(&id) {
				for sid in group.iter() {
					if let Some(&at) = km.index.get(sid)
						&& !out.contains(&at)
					{
						out.push(at);
					}
				}
			}
		}
		out
	}

	fn authentication(&self, q: &Query) -> Option<Violation> {
		let km = self.km();
		let program = self.cx.program;
		let c = q.message.constant().ok()?;
		let slot = km.index_of(c)?;
		let b = program.run_index(q.message.recipient)?;
		if !(self.claims)(q.message.recipient) {
			return None;
		}
		let h = self.ex.runs[b].held(slot)?;
		let sender = h.sender?;
		let use_slot = *self.uses(b, km.slots[slot].constant.id)?.first()?;
		if !h.authored {
			if program.runs[sender].id == q.message.sender {
				return None;
			}
			return Some(Violation::Substituted {
				run: b,
				slot,
				sender,
				used: use_slot,
			});
		}
		let used = reduce_once(&h.value);
		let siblings = self.siblings(slot);
		let mut emissions = 0usize;
		for (d, delivery) in program.deliveries.iter().enumerate() {
			let Some(sent) = &self.ex.sent[d] else {
				continue;
			};
			if !km.same_actor(program.runs[delivery.recipient].id, q.message.recipient) {
				continue;
			}
			for (k, &(s, _)) in delivery.slots.iter().enumerate() {
				if siblings.contains(&s)
					&& !self.ex.runs[delivery.sender]
						.held(s)
						.is_some_and(|h| h.authored)
					&& km.interchangeable_for(program.runs[delivery.sender].id, q.message.sender, s)
					&& reduce_once(&sent[k]).equivalent(&used, true)
				{
					emissions += 1;
				}
			}
		}
		if emissions == 0 {
			if self.honest.runs[b]
				.held(slot)
				.is_some_and(|honest| reduce_once(&honest.value).equivalent(&used, true))
			{
				return None;
			}
			return Some(Violation::Forged {
				run: b,
				slot,
				value: h.value.clone(),
				used: use_slot,
			});
		}
		let mut acceptances = 0usize;
		for (r, run) in self.ex.runs.iter().enumerate() {
			if !km.same_actor(program.runs[r].id, q.message.recipient) {
				continue;
			}
			for &s in &siblings {
				if let Some(held) = run.held(s)
					&& held.sender.is_some()
					&& reduce_once(&held.value).equivalent(&used, true)
					&& self.accepted(r, s)
				{
					acceptances += 1;
				}
			}
		}
		let open_leg = program.deliveries.iter().any(|delivery| {
			delivery.recipient == b
				&& delivery
					.slots
					.iter()
					.any(|&(s, guarded)| s == slot && !guarded)
		});
		if (h.installed || open_leg) && acceptances > emissions {
			return Some(Violation::Replayed {
				run: b,
				slot,
				value: h.value.clone(),
				used: use_slot,
			});
		}
		None
	}

	fn freshness(&self, q: &Query) -> Option<Violation> {
		let c = q.subject().ok()?;
		let slot = self.km().index_of(c)?;
		for (r, run) in self.ex.runs.iter().enumerate() {
			if !(self.claims)(self.cx.program.runs[r].id) {
				continue;
			}
			let Some(h) = run.held(slot) else {
				continue;
			};
			let km = self.km();
			if h.value.constant_leaves().any(|leaf| {
				km.index_of(leaf)
					.is_some_and(|i| km.slots[i].constant.fresh)
			}) {
				continue;
			}
			if let Some(&used) = self.uses(r, c.id).as_ref().and_then(|uses| uses.first()) {
				return Some(Violation::Stale {
					run: r,
					slot,
					value: h.value.clone(),
					used,
				});
			}
		}
		None
	}
}

impl Judge<'_, '_> {
	fn equivalence(&self, q: &Query) -> Option<Violation> {
		'runs: for r in 0..self.ex.runs.len() {
			if !(self.claims)(self.cx.program.runs[r].id) {
				continue;
			}
			let ps = self.view(r);
			let mut resolved: Vec<(Constant, Value)> = Vec::with_capacity(q.constants.len());
			for c in &q.constants {
				let (value, slot) = ps.resolve_constant(c, false);
				let Some(slot) = slot else {
					continue 'runs;
				};
				if !super::view::claimable(self.cx, self.ex, r, slot, self.claims)
					|| ps.slot_unreached(slot)
					|| ps.slot_starved(slot)
					|| check_failed(&value)
				{
					continue 'runs;
				}
				resolved.push((c.clone(), value));
			}
			if !resolved
				.windows(2)
				.all(|w| w[0].1.equivalent(&w[1].1, true))
			{
				return Some(Violation::Differ { resolved });
			}
		}
		None
	}

	fn unlinkability(&self, q: &Query) -> Option<Violation> {
		for r in 0..self.ex.runs.len() {
			if !(self.claims)(self.cx.program.runs[r].id) {
				continue;
			}
			let ps = self.view(r);
			let claimable = |c: &Constant| {
				ps.index_of(c).is_some_and(|slot| {
					super::view::claimable(self.cx, self.ex, r, slot, self.claims)
				})
			};
			for (i, a) in q.constants.iter().enumerate() {
				if !claimable(a) {
					continue;
				}
				for b in q.constants.iter().skip(i + 1) {
					if !claimable(b) {
						continue;
					}
					let Some(witness) = crate::unlink::find_link_witness(
						a,
						b,
						self.km(),
						&ps,
						&self.ex.knowledge.state,
					) else {
						continue;
					};
					let clause = witness.describe(|v| v.to_string());
					let resolved = [a, b]
						.into_iter()
						.map(|c| (c.clone(), ps.resolve_constant(c, false).0))
						.collect();
					return Some(Violation::Linked {
						clause: format!("Attacker links {a} and {b} {clause}."),
						resolved,
					});
				}
			}
		}
		None
	}
}

fn check_failed(v: &Value) -> bool {
	match v {
		Value::Primitive(p) => p.instance_check && !can_rewrite(p).0,
		Value::Constant(_) => false,
	}
}

fn mentions(
	km: &ProtocolTrace,
	v: &Value,
	target: ValueId,
	owner: PrincipalId,
	seen: &mut Vec<ValueId>,
) -> bool {
	for c in v.constant_leaves() {
		if c.id == target {
			return true;
		}
		if seen.contains(&c.id) {
			continue;
		}
		seen.push(c.id);
		let Some(i) = km.index_of(c) else {
			continue;
		};
		let slot = &km.slots[i];
		if slot.creator != owner || !matches!(slot.initial_value, Value::Primitive(_)) {
			continue;
		}
		if mentions(km, &slot.initial_value, target, owner, seen) {
			return true;
		}
	}
	false
}
