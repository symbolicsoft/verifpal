/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::exec::{Context, Execution, Held};
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
	pub(crate) honest: &'a Execution,
	pub(crate) claims: &'a dyn Fn(PrincipalId) -> bool,
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
		(0..self.ex.runs.len()).filter(|&r| (self.claims)(self.cx.program.runs[r].id))
	}

	fn creator_run(&self, slot: usize) -> Option<usize> {
		self.cx.program.run_index(self.km().slots[slot].creator)
	}

	fn claimed(&self, r: usize, slot: usize) -> Option<&Held> {
		self.ex.runs[r].held(slot).or_else(|| {
			let creator = self.creator_run(slot)?;
			(self.claims)(self.cx.program.runs[creator].id)
				.then(|| self.ex.runs[creator].held(slot))
				.flatten()
		})
	}

	fn confidentiality(&self, q: &Query) -> Option<Violation> {
		let c = q.subject().ok()?;
		let slot = self.km().index_of(c)?;
		let attacker = &self.ex.knowledge.state;
		self.claimed_runs().find_map(|r| {
			let h = self.ex.runs[r].held(slot)?;
			obtainable(&h.value, &self.cx.km.capabilities, attacker).then(|| Violation::Disclosed {
				run: r,
				slot,
				value: h.value.clone(),
			})
		})
	}

	fn uses(&self, run: usize, target: ValueId) -> Option<Vec<usize>> {
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
		let (now, eventually) = (&self.ex.runs[run], &self.whole.runs[run]);
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

	fn siblings(&self, slot: usize) -> Vec<usize> {
		let km = self.km();
		let id = km.slots[slot].constant.id;
		let mut out = vec![slot];
		for group in [&km.session_siblings, &km.copy_siblings]
			.into_iter()
			.filter_map(|groups| groups.get(&id))
		{
			for &at in group.iter().filter_map(|sid| km.index.get(sid)) {
				if !out.contains(&at) {
					out.push(at);
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
		let used = *self.uses(b, c.id)?.first()?;
		if !h.authored {
			return (program.runs[sender].id != q.message.sender).then_some(
				Violation::Substituted {
					run: b,
					slot,
					sender,
					used,
				},
			);
		}
		let reduct = reduce_once(&h.value);
		let siblings = self.siblings(slot);
		let emissions = self.emissions(q, &siblings, &reduct);
		if emissions == 0 {
			let honest = self.honest.runs[b]
				.held(slot)
				.is_some_and(|honest| reduce_once(&honest.value).equivalent(&reduct, true));
			return (!honest).then(|| Violation::Forged {
				run: b,
				slot,
				value: h.value.clone(),
				used,
			});
		}
		let open_leg = program
			.deliveries
			.iter()
			.any(|delivery| delivery.recipient == b && delivery.slots.contains(&(slot, false)));
		if !h.installed && !open_leg {
			return None;
		}
		let acceptances = self.acceptances(q, &siblings, &reduct);
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
		let mut emissions = 0;
		for (delivery, sent) in program.deliveries.iter().zip(&self.ex.sent) {
			let Some(sent) = sent else {
				continue;
			};
			if !km.same_actor(program.runs[delivery.recipient].id, q.message.recipient) {
				continue;
			}
			let from = delivery.sender;
			emissions += delivery
				.slots
				.iter()
				.zip(sent)
				.filter(|&(&(s, _), v)| {
					siblings.contains(&s)
						&& !self.ex.runs[from].held(s).is_some_and(|h| h.authored)
						&& km.interchangeable_for(program.runs[from].id, q.message.sender, s)
						&& reduce_once(v).equivalent(reduct, true)
				})
				.count();
		}
		emissions
	}

	fn acceptances(&self, q: &Query, siblings: &[usize], reduct: &Value) -> usize {
		let km = self.km();
		(0..self.ex.runs.len())
			.filter(|&r| km.same_actor(self.cx.program.runs[r].id, q.message.recipient))
			.flat_map(|r| siblings.iter().map(move |&s| (r, s)))
			.filter(|&(r, s)| {
				self.ex.runs[r].held(s).is_some_and(|held| {
					held.sender.is_some() && reduce_once(&held.value).equivalent(reduct, true)
				}) && self
					.uses(r, km.slots[s].constant.id)
					.is_some_and(|uses| !uses.is_empty())
			})
			.count()
	}

	fn freshness(&self, q: &Query) -> Option<Violation> {
		let km = self.km();
		let c = q.subject().ok()?;
		let slot = km.index_of(c)?;
		self.claimed_runs().find_map(|r| {
			let h = self.ex.runs[r].held(slot)?;
			if h.value.constant_leaves().any(|leaf| {
				km.index_of(leaf)
					.is_some_and(|i| km.slots[i].constant.fresh)
			}) {
				return None;
			}
			let used = *self.uses(r, c.id)?.first()?;
			Some(Violation::Stale {
				run: r,
				slot,
				value: h.value.clone(),
				used,
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
