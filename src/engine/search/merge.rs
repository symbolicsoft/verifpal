/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::{
	Family, HONEST_NODE, NodeIdx, Search, Tried, compatible_with, normalize, runs_of, same_installs,
};
use crate::engine::exec::{Execution, Install, Installs};
use crate::engine::knowledge::{Knowledge, Origin};
use crate::engine::program::{DeliveryIdx, Event, RunIdx};
use crate::protocol::ProtocolTrace;
use crate::protocol::SlotIdx;
use crate::syntax::QueryKind;
use crate::term::Value;
use crate::theory::obtainable;

fn secret_arguments<'v>(held: &'v Value, km: &ProtocolTrace) -> impl Iterator<Item = &'v Value> {
	let arguments = match held {
		Value::Primitive(p) => &p.arguments[..],
		_ => &[],
	};
	arguments
		.iter()
		.filter(|a| crate::engine::unlink::depends_on_secret(a, km))
}

type Leaf = (Value, Vec<NodeIdx>);

impl<'a, 'b> Search<'a, 'b> {
	fn first_compatible(&self, context: &Installs, leaves: &[Vec<NodeIdx>]) -> Option<Installs> {
		if !leaves.iter().all(|sources| {
			sources
				.iter()
				.any(|&n| compatible_with(context, &self.supplied(n)))
		}) {
			return None;
		}
		let mut failed: Vec<Tried> = leaves.iter().map(|_| Tried::default()).collect();
		self.choose(context, leaves, &mut failed)
	}

	fn choose(
		&self,
		plan: &Installs,
		leaves: &[Vec<NodeIdx>],
		failed: &mut [Tried],
	) -> Option<Installs> {
		let Some((sources, rest)) = leaves.split_first() else {
			return Some(plan.clone());
		};
		if failed[rest.len()].position(plan).is_some() {
			return None;
		}
		for &n in sources {
			let source = &self.supplied(n);
			if !compatible_with(plan, source) {
				continue;
			}
			let mut next = plan.clone();
			next.extend(
				source
					.iter()
					.filter(|install| !plan.iter().any(|held| held.same_input(install)))
					.cloned(),
			);
			if let Some(done) = self.choose(&normalize(next), rest, failed) {
				return Some(done);
			}
		}
		failed[rest.len()].insert(plan);
		None
	}

	fn conflict(&self, context: &Installs, leaves: &[Vec<NodeIdx>]) -> Vec<usize> {
		let mut core: Vec<usize> = (0..leaves.len()).collect();
		for at in (0..leaves.len()).rev() {
			let rest: Vec<Vec<NodeIdx>> = core
				.iter()
				.filter(|&&i| i != at)
				.map(|&i| leaves[i].clone())
				.collect();
			if self.first_compatible(context, &rest).is_none() {
				core.retain(|&i| i != at);
			}
		}
		core
	}

	fn leaves(
		&self,
		knowledge: &Knowledge,
		idx: usize,
		supply: &dyn Fn(&Value) -> Option<Vec<NodeIdx>>,
		out: &mut Vec<Leaf>,
		seen: &mut Vec<usize>,
	) {
		if seen.contains(&idx) {
			return;
		}
		seen.push(idx);
		let value = &knowledge.state.known[idx];
		if matches!(
			knowledge.origin(idx),
			Origin::Initial | Origin::Wire { .. } | Origin::Leak { .. }
		) && let Some(sources) = supply(value)
		{
			out.push((value.clone(), sources));
			return;
		}
		let Some(record) = knowledge.state.derivations.get(idx) else {
			return;
		};
		for ingredient in record.ingredients() {
			if let Some(i) = knowledge.knows(ingredient) {
				self.leaves(knowledge, i, supply, out, seen);
			}
		}
	}

	fn known_by(&self, v: &Value) -> Option<Vec<NodeIdx>> {
		let (known, nodes) = self.union.closed_at;
		let at = self.union.knowledge.knows(v).filter(|&at| at < known)?;
		Some(
			self.union.by_cost[at]
				.iter()
				.flatten()
				.copied()
				.filter(|&n| n < nodes)
				.collect(),
		)
	}

	fn emitted_by(&self, v: &Value, before: &Knowledge) -> Option<Vec<NodeIdx>> {
		if obtainable(v, before.capabilities(), &before.state) {
			return Some(vec![HONEST_NODE]);
		}
		let mut sources: Vec<NodeIdx> = self
			.fresh_sources(v)
			.into_iter()
			.map(|source| source.node)
			.collect();
		sources.sort_by_key(|&n| (self.nodes[n].installs.len(), n));
		sources.dedup();
		Some(sources)
	}

	fn route(
		&self,
		wanted: &[Value],
		context: &Installs,
		base: &Knowledge,
		supply: &dyn Fn(&Value) -> Option<Vec<NodeIdx>>,
		restrict: &dyn Fn(&[Value]) -> Knowledge,
	) -> Option<(Installs, Vec<Vec<NodeIdx>>)> {
		let mut pending: Vec<Vec<Value>> = vec![Vec::new()];
		let mut visited: Vec<Vec<Value>> = vec![Vec::new()];
		while let Some(withheld) = pending.pop() {
			let restricted;
			let knowledge = if withheld.is_empty() {
				base
			} else {
				restricted = restrict(&withheld);
				&restricted
			};
			let mut leaves = Vec::new();
			let mut seen = Vec::new();
			let mut derived = true;
			for v in wanted {
				let Some(idx) = knowledge.knows(v) else {
					derived = false;
					break;
				};
				self.leaves(knowledge, idx, supply, &mut leaves, &mut seen);
			}
			if !derived {
				continue;
			}
			let sources: Vec<Vec<NodeIdx>> = leaves.iter().map(|(_, s)| s.clone()).collect();
			if self.log.debug {
				eprintln!(
					"[search] route withholding {}: sources {:?}",
					withheld.len(),
					sources.iter().map(Vec::len).collect::<Vec<_>>()
				);
			}
			if let Some(plan) = self.first_compatible(context, &sources) {
				return Some((plan, sources));
			}
			for at in self.conflict(context, &sources).into_iter().rev() {
				let mut next = withheld.clone();
				next.push(leaves[at].0.clone());
				if !visited.iter().any(|seen| {
					seen.len() == next.len()
						&& next
							.iter()
							.all(|v| seen.iter().any(|w| w.equivalent(v, true)))
				}) {
					visited.push(next.clone());
					pending.push(next);
				}
			}
		}
		None
	}

	fn accepting_runs(&self) -> Vec<(RunIdx, SlotIdx)> {
		let km = self.cx.km;
		let program = self.cx.program;
		let mut runs: Vec<(RunIdx, SlotIdx)> = Vec::new();
		for q in self.ctx.open_queries() {
			let subject = match q.kind {
				QueryKind::Authentication => q.message.constant().ok(),
				QueryKind::Freshness => q.subject().ok(),
				_ => continue,
			};
			let Some(slot) = subject.and_then(|c| km.index_of(c)) else {
				continue;
			};
			let siblings = km.sibling_slots(slot);
			for (r, run) in self.honest.runs.iter_enumerated() {
				if runs.iter().any(|&(held, _)| held == r)
					|| (q.kind == QueryKind::Authentication
						&& program.runs[r].id != q.message.recipient)
				{
					continue;
				}
				if let Some(&s) = siblings.iter().find(|&&s| run.held(s).is_some()) {
					runs.push((r, s));
				}
			}
		}
		runs
	}

	fn used_with(&self, r: RunIdx, subject: SlotIdx) -> Vec<SlotIdx> {
		let km = self.cx.km;
		let program = &self.cx.program.runs[r];
		let target = km.slots[subject].constant.id;
		let mut out: Vec<SlotIdx> = Vec::new();
		let downstream = |slot: SlotIdx| {
			crate::engine::judgment::mentions(
				km,
				&km.slots[slot].initial_value,
				target,
				program.id,
				&mut Vec::new(),
			)
		};
		let mut pending: Vec<SlotIdx> = program
			.steps
			.iter()
			.filter_map(|step| match step.event {
				Event::Assign(slot) => Some(slot),
				_ => None,
			})
			.filter(|&slot| downstream(slot))
			.collect();
		while let Some(slot) = pending.pop() {
			for c in km.slots[slot].initial_value.constant_leaves() {
				let Some(at) = km.index_of(c) else {
					continue;
				};
				let Some(&step) = program.step_of_slot.get(&at) else {
					continue;
				};
				if out.contains(&at) {
					continue;
				}
				match program.steps[step].event {
					Event::Recv(_) => {}
					Event::Assign(_) if downstream(at) => {}
					Event::Assign(_) => {
						out.push(at);
						pending.push(at);
					}
					_ => out.push(at),
				}
			}
		}
		out.sort_unstable();
		out
	}

	fn late_targets(&self) -> Vec<(Value, RunIdx, SlotIdx, i32)> {
		let mut late: Vec<(Value, RunIdx, SlotIdx, i32)> = Vec::new();
		for (r, slot) in self.accepting_runs() {
			let program = &self.cx.program.runs[r];
			let Some(&step) = program.step_of_slot.get(&slot) else {
				continue;
			};
			if !matches!(program.steps[step].event, Event::Recv(_)) {
				continue;
			}
			let phase = program.steps[step].phase;
			let Some(mut receive) = self.receiving(r, slot, phase) else {
				continue;
			};
			let receive = &mut *receive;
			let before = &receive.before;
			let fresh: Vec<Value> = self
				.used_with(r, slot)
				.into_iter()
				.filter_map(|c| self.honest.runs[r].held(c))
				.map(|held| held.value.clone())
				.filter(|v| {
					!obtainable(v, before.capabilities(), &before.state)
						&& !receive
							.supplied
							.iter()
							.any(|(held, _)| held.equivalent(v, true))
				})
				.collect();
			if fresh.is_empty() {
				continue;
			}
			let within = self.within(receive, phase);
			for v in fresh {
				if within.knows(&v).is_some()
					&& !late
						.iter()
						.any(|(held, run, ..)| *run == r && held.equivalent(&v, true))
				{
					late.push((v, r, slot, phase));
				}
			}
		}
		late
	}

	fn merge_late(&mut self) {
		for (value, r, slot, phase) in self.late_targets() {
			if self.done() {
				return;
			}
			let routed = {
				let Some(mut receive) = self.receiving(r, slot, phase) else {
					continue;
				};
				receive.supplied.push((value.clone(), None));
				let within = self.within(&mut receive, phase).clone();
				let before = receive.before.clone();
				drop(receive);
				let additions = self.emitted(phase);
				self.route(
					std::slice::from_ref(&value),
					&Installs::new(),
					&within,
					&|v| self.emitted_by(v, &before),
					&|withheld| {
						let mut restricted = before.clone();
						for v in &additions {
							if !withheld.iter().any(|w| w.equivalent(v, true)) {
								restricted.learn(v, Origin::Initial);
							}
						}
						restricted.close();
						restricted
					},
				)
			};
			if self.log.debug {
				eprintln!(
					"[search] late merge target {value}: plan {}",
					routed
						.as_ref()
						.map_or("none".to_string(), |(plan, _)| self.shown(plan))
				);
			}
			let Some((plan, _)) = routed else {
				continue;
			};
			let at = self.as_family(Family::Merge, |search| search.consider(plan));
			let installs = &self.attempts.tried.entries[at].0;
			let Some(n) = self
				.nodes
				.indices()
				.rev()
				.find(|&n| same_installs(&self.nodes[n].installs, installs))
			else {
				continue;
			};
			if let Some(mut receive) = self.receiving(r, slot, phase)
				&& let Some(entry) = receive
					.supplied
					.iter_mut()
					.find(|(held, _)| held.equivalent(&value, true))
			{
				entry.1 = Some(n);
			}
		}
	}

	pub(super) fn merge_for_queries(&mut self) {
		self.merge_late();
		let km = self.cx.km;
		let mut targets: Vec<(Value, Vec<usize>, NodeIdx)> = Vec::new();
		for (r, _) in self.accepting_runs() {
			for held in self.honest.runs[r].env.iter().flatten() {
				let Some(idx) = self.union.closed.knows(&held.value) else {
					continue;
				};
				if idx >= self.union.closed_at.0
					&& !targets.iter().any(|(_, other, _)| *other == [idx])
				{
					targets.push((held.value.clone(), vec![idx], HONEST_NODE));
				}
			}
		}
		for q in self.ctx.open_queries() {
			if !matches!(
				q.kind,
				QueryKind::Confidentiality | QueryKind::Unlinkability
			) {
				continue;
			}
			for c in &q.constants {
				let Some(slot) = km.index_of(c) else {
					continue;
				};
				self.index_holders(slot);
				for (held, holder) in &self.memo.holders[&slot].values {
					let wanted: Vec<&Value> = match q.kind {
						QueryKind::Unlinkability => secret_arguments(held, km).collect(),
						_ => vec![held],
					};
					let missing: Vec<usize> = wanted
						.into_iter()
						.filter_map(|v| {
							let idx = self.union.closed.knows(v)?;
							(idx >= self.union.closed_at.0
								|| !self.derivable_in(*holder, v, km.max_phase))
							.then_some(idx)
						})
						.collect();
					if missing.is_empty() {
						continue;
					}
					match targets.iter_mut().find(|(_, other, _)| *other == missing) {
						Some(target) => {
							if self.nodes[target.2].installs.len()
								> self.nodes[*holder].installs.len()
							{
								target.2 = *holder;
							}
						}
						None => targets.push((held.clone(), missing, *holder)),
					}
				}
			}
		}
		let mut plans = Vec::new();
		for (value, missing, context) in targets {
			if self.done() {
				break;
			}
			let wanted: Vec<Value> = missing
				.iter()
				.map(|&idx| self.union.closed.state.known[idx].clone())
				.collect();
			let tried = self
				.attempts
				.merged
				.entry((value.hash_value(), context))
				.or_default();
			if tried.iter().any(|held| {
				held.len() == wanted.len()
					&& held.iter().zip(&wanted).all(|(h, w)| h.equivalent(w, true))
			}) {
				continue;
			}
			tried.push(wanted.clone());
			let routed = self.route(
				&wanted,
				&self.supplied(context),
				&self.union.closed,
				&|v| self.known_by(v),
				&|withheld| {
					self.union
						.closed
						.disclosing(|_, v| !withheld.iter().any(|w| w.equivalent(v, true)))
				},
			);
			if self.log.debug {
				eprintln!(
					"[search] merge target {value}: context {context}, plan {}",
					routed
						.as_ref()
						.map_or("none".to_string(), |(plan, _)| self.shown(plan))
				);
			}
			if let Some((plan, sources)) = routed {
				plans.push((context, plan, sources));
			}
		}
		for (context, mut plan, sources) in plans {
			let mut awaited: Vec<DeliveryIdx> = Vec::new();
			while !self.done() {
				let at = self.as_family(Family::Merge, |search| search.consider(plan));
				let Some(outcome) = self.outcome(at) else {
					break;
				};
				let before = awaited.len();
				for &(_, d) in &outcome.blocked {
					if !awaited.contains(&d) {
						awaited.push(d);
					}
				}
				if awaited.len() == before {
					break;
				}
				let sending: Vec<Vec<NodeIdx>> = sources
					.iter()
					.map(|leaf| {
						leaf.iter()
							.copied()
							.filter(|&n| self.sends(n, &awaited))
							.collect()
					})
					.collect();
				let Some(next) = self.first_compatible(&self.supplied(context), &sending) else {
					break;
				};
				plan = next;
			}
		}
	}

	pub(super) fn holds_unsourced(&mut self, ex: &Execution) -> bool {
		let km = self.cx.km;
		let mut subjects: Vec<(SlotIdx, QueryKind)> = Vec::new();
		for q in self.ctx.open_queries() {
			if !matches!(
				q.kind,
				QueryKind::Confidentiality | QueryKind::Unlinkability
			) {
				continue;
			}
			for c in &q.constants {
				if let Some(slot) = km.index_of(c)
					&& !subjects.contains(&(slot, q.kind))
				{
					subjects.push((slot, q.kind));
				}
			}
		}
		let obtained = |v: &Value| obtainable(v, ex.knowledge.capabilities(), &ex.knowledge.state);
		for (slot, kind) in subjects {
			self.index_holders(slot);
			let holders = &self.memo.holders[&slot];
			for run in ex.runs.iter() {
				let Some(h) = run.held(slot) else {
					continue;
				};
				let held = holders
					.index
					.get(&h.value.hash_value())
					.is_some_and(|bucket| {
						bucket
							.iter()
							.any(|&at| holders.values[at].0.equivalent(&h.value, true))
					});
				if held {
					continue;
				}
				let unsourced = match kind {
					QueryKind::Unlinkability => {
						secret_arguments(&h.value, km).any(|a| !obtained(a))
					}
					_ => !obtained(&h.value),
				};
				if unsourced {
					return true;
				}
			}
		}
		false
	}

	fn index_holders(&mut self, slot: SlotIdx) {
		let holders = self.memo.holders.entry(slot).or_default();
		for n in self.nodes.indices_from(holders.scanned) {
			let node = &self.nodes[n];
			for run in node.held.indices() {
				let Some(h) = node.held(run, slot) else {
					continue;
				};
				let wanted = &h.value;
				let bucket = holders.index.entry(wanted.hash_value()).or_default();
				match bucket
					.iter()
					.copied()
					.find(|&at| holders.values[at].0.equivalent(wanted, true))
				{
					Some(at) => {
						let held = &mut holders.values[at].1;
						if self.nodes[*held].installs.len() > node.installs.len() {
							*held = n;
						}
					}
					None => {
						bucket.push(holders.values.len());
						holders.values.push((wanted.clone(), n));
					}
				}
			}
		}
		holders.scanned = self.nodes.next_index();
	}

	fn sibling_slot(&self, slot: SlotIdx, r: RunIdx) -> Option<SlotIdx> {
		let km = self.cx.km;
		let id = km.slots[slot].constant.id;
		let group = km.copy_siblings.get(&id)?;
		group.iter().find_map(|sid| {
			let at = *km.index.get(sid)?;
			self.cx.program.runs[r]
				.step_of_slot
				.contains_key(&at)
				.then_some(at)
		})
	}

	pub(super) fn transfer(&mut self, node: NodeIdx) {
		let km = self.cx.km;
		let program = self.cx.program;
		let installs = self.nodes[node].installs.clone();
		let runs = runs_of(&installs);
		let mut plans: Vec<Installs> = Vec::new();
		for &q in &runs {
			for r in program.runs.indices() {
				if r == q
					|| runs.contains(&r)
					|| !km.same_actor(program.runs[r].id, program.runs[q].id)
				{
					continue;
				}
				let mut plan: Installs = installs
					.iter()
					.filter(|install| install.run() != q)
					.cloned()
					.collect();
				let mut complete = true;
				for install in installs.iter().filter(|install| install.run() == q) {
					let moved = match install {
						Install::Value { slot, value, .. } => {
							self.sibling_slot(*slot, r).map(|slot| Install::Value {
								run: r,
								slot,
								value: value.clone(),
							})
						}
						Install::Idle { .. } => Some(Install::Idle { run: r }),
						Install::Drop { slot, .. } => self
							.sibling_slot(*slot, r)
							.map(|slot| Install::Drop { run: r, slot }),
					};
					match moved {
						Some(moved) => plan.push(moved),
						None => {
							complete = false;
							break;
						}
					}
				}
				if complete {
					plans.push(normalize(plan));
				}
			}
		}
		for plan in plans.into_iter().rev() {
			if self.done() {
				break;
			}
			self.as_family(Family::Merge, |search| search.enqueue(plan));
		}
	}
}
