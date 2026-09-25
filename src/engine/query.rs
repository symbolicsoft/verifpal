/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::exec::{Context, Execution, Held, RunState};
use super::program::Event;
use super::unlink::{Link, link};
use crate::resolution::mentions_across_principals;
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
		emissions: usize,
		acceptances: usize,
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
		repeated: Option<usize>,
	},
	Linked {
		a: Constant,
		b: Constant,
		link: Link,
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
	pub(crate) whole: &'a Execution,
	pub(crate) claims: &'a dyn Fn(PrincipalId) -> Option<i32>,
}

impl Judge<'_, '_> {
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
			program
				.deliveries
				.iter()
				.zip(&self.whole.sent)
				.any(|(delivery, sent)| {
					program.runs[delivery.sender].id == option.message.sender
						&& program.runs[delivery.recipient].id == option.message.recipient
						&& delivery.slots.iter().any(|&(s, _)| s == slot)
						&& sent.is_some()
				})
		})
	}

	fn claimed_runs(&self) -> impl Iterator<Item = usize> + '_ {
		(0..self.ex.runs.len()).filter(|&r| self.state(r).is_some())
	}

	fn state(&self, r: usize) -> Option<&RunState> {
		let phase = (self.claims)(self.cx.program.runs[r].id)?;
		Some(&self.whole.at(phase).runs[r])
	}

	fn creator_run(&self, slot: usize) -> Option<usize> {
		self.cx.program.run_index(self.km().slots[slot].creator)
	}

	fn claimed(&self, r: usize, slot: usize) -> Option<&Held> {
		self.state(r)?
			.held(slot)
			.or_else(|| self.state(self.creator_run(slot)?)?.held(slot))
	}

	fn confidentiality(&self, q: &Query) -> Option<Violation> {
		let c = q.subject().ok()?;
		let slot = self.km().index_of(c)?;
		let attacker = &self.ex.knowledge.state;
		self.claimed_runs().find_map(|r| {
			let h = self.state(r)?.held(slot)?;
			obtainable(&h.value, &self.cx.km.capabilities, attacker).then(|| Violation::Disclosed {
				run: r,
				slot,
				value: h.value.clone(),
			})
		})
	}

	fn uses(&self, now: &RunState, run: usize, target: ValueId) -> Option<Vec<usize>> {
		let km = self.km();
		let program = &self.cx.program.runs[run];
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
			mentioning = sites(&|v| mentions_across_principals(v, km, program.id, target));
		}
		let eventually = &self.whole.runs[run];
		let mut uses = Vec::new();
		for (i, slot) in mentioning {
			if !now.reached(i) {
				if eventually.reached(i) {
					continue;
				}
				return None;
			}
			if now.halted != Some(slot) {
				uses.push(slot);
			}
		}
		Some(uses)
	}

	fn authentication(&self, q: &Query) -> Option<Violation> {
		let km = self.km();
		let program = self.cx.program;
		let c = q.message.constant().ok()?;
		let slot = km.index_of(c)?;
		let b = program.run_index(q.message.recipient)?;
		let state = self.state(b)?;
		let h = state.held(slot)?;
		let sender = h.sender?;
		let used = *self.uses(state, b, c.id)?.first()?;
		if !h.authored && program.runs[sender].id == q.message.sender {
			return None;
		}
		let reduct = reduce_once(&h.value);
		let siblings = self.km().sibling_slots(slot);
		let emissions = self.emissions(q, &siblings, &reduct);
		if !h.authored {
			return (emissions == 0).then_some(Violation::Substituted {
				run: b,
				slot,
				sender,
				used,
			});
		}
		if emissions == 0 {
			return Some(Violation::Forged {
				run: b,
				slot,
				value: h.value.clone(),
				used,
			});
		}
		let acceptances = self
			.accepting(q.message.recipient, &siblings, &reduct)
			.count();
		(acceptances > emissions).then(|| Violation::Replayed {
			run: b,
			slot,
			value: h.value.clone(),
			used,
			emissions,
			acceptances,
		})
	}

	fn emissions(&self, q: &Query, siblings: &[usize], reduct: &Value) -> usize {
		let km = self.km();
		let program = self.cx.program;
		let sends = program
			.deliveries
			.iter()
			.zip(&self.ex.sent)
			.enumerate()
			.filter_map(|(d, (delivery, sent))| Some((d, delivery, sent.as_ref()?)))
			.flat_map(|(d, delivery, sent)| {
				delivery
					.slots
					.iter()
					.zip(sent)
					.map(move |(&(s, _), v)| (d, delivery.sender, s, v))
			})
			.filter(|&(_, _, s, v)| {
				siblings.contains(&s) && reduce_once(v).equivalent(reduct, true)
			});
		let genuine = sends
			.clone()
			.any(|(_, from, s, _)| !self.ex.runs[from].held(s).is_some_and(|h| h.authored));
		if !genuine {
			return 0;
		}
		sends
			.filter(|&(d, from, s, _)| {
				km.interchangeable_for(program.runs[from].id, q.message.sender, s)
					&& self.reaches(d, s, q.message.recipient, &mut Vec::new())
			})
			.count()
	}

	fn reaches(
		&self,
		d: usize,
		slot: usize,
		recipient: PrincipalId,
		seen: &mut Vec<usize>,
	) -> bool {
		let program = self.cx.program;
		let to = program.deliveries[d].recipient;
		if self.km().same_actor(program.runs[to].id, recipient) {
			return true;
		}
		if seen.contains(&d) {
			return false;
		}
		seen.push(d);
		program
			.deliveries
			.iter()
			.enumerate()
			.any(|(next, delivery)| {
				delivery.sender == to
					&& delivery.slots.iter().any(|&(s, _)| s == slot)
					&& self.reaches(next, slot, recipient, seen)
			})
	}

	fn accepting<'s>(
		&'s self,
		actor: PrincipalId,
		siblings: &'s [usize],
		reduct: &'s Value,
	) -> impl Iterator<Item = usize> + 's {
		let km = self.km();
		(0..self.ex.runs.len())
			.filter(move |&r| km.same_actor(self.cx.program.runs[r].id, actor))
			.flat_map(move |r| siblings.iter().map(move |&s| (r, s)))
			.filter(move |&(r, s)| {
				self.ex.runs[r].held(s).is_some_and(|held| {
					held.sender.is_some() && reduce_once(&held.value).equivalent(reduct, true)
				}) && self
					.uses(&self.ex.runs[r], r, km.slots[s].constant.id)
					.is_some_and(|uses| !uses.is_empty())
			})
			.map(|(r, _)| r)
	}

	fn freshness(&self, q: &Query) -> Option<Violation> {
		let km = self.km();
		let c = q.subject().ok()?;
		let slot = km.index_of(c)?;
		let siblings = self.km().sibling_slots(slot);
		self.claimed_runs().find_map(|r| {
			let state = self.state(r)?;
			let h = state.held(slot)?;
			let fresh = h.value.constant_leaves().any(|leaf| {
				km.index_of(leaf)
					.is_some_and(|i| km.slots[i].constant.fresh)
			});
			let reduct = reduce_once(&h.value);
			let repeated = match fresh {
				false => None,
				true if !h.authored => return None,
				true => Some(
					self.accepting(self.cx.program.runs[r].id, &siblings, &reduct)
						.find(|&other| other != r)?,
				),
			};
			let used = *self.uses(state, r, c.id)?.first()?;
			Some(Violation::Stale {
				run: r,
				slot,
				value: h.value.clone(),
				used,
				repeated,
			})
		})
	}

	fn equivalence(&self, q: &Query) -> Option<Violation> {
		let km = self.km();
		'runs: for r in self.claimed_runs() {
			let mut resolved: Vec<(Constant, Value)> = Vec::with_capacity(q.constants.len());
			for c in &q.constants {
				let Some(slot) = km.index_of(c) else {
					continue 'runs;
				};
				let value = match self.claimed(r, slot) {
					Some(held) => &held.value,
					None if self.creator_run(slot).is_none() => &km.slots[slot].initial_value,
					None => continue 'runs,
				};
				if check_failed(value) {
					continue 'runs;
				}
				resolved.push((c.clone(), value.clone()));
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
		let km = self.km();
		for r in self.claimed_runs() {
			let claimed: Vec<(&Constant, usize, &Held)> = q
				.constants
				.iter()
				.filter_map(|c| {
					let slot = km.index_of(c)?;
					Some((c, slot, self.claimed(r, slot)?))
				})
				.collect();
			for (i, &(a, sa, ha)) in claimed.iter().enumerate() {
				for &(b, sb, hb) in &claimed[i + 1..] {
					if let Some(link) = link(self.cx, self.ex, [(sa, ha), (sb, hb)]) {
						return Some(Violation::Linked {
							a: a.clone(),
							b: b.clone(),
							link,
							resolved: vec![
								(a.clone(), ha.value.clone()),
								(b.clone(), hb.value.clone()),
							],
						});
					}
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
