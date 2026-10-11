/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::{
	Adders, AttemptIdx, Cheapest, Family, HONEST_NODE, Late, NodeIdx, Search, normalize, runs_of,
	same_installs,
};
use crate::engine::exec::{Install, Installs, install_at};
use crate::engine::knowledge::{Knowledge, Origin};
use crate::engine::program::{DeliveryIdx, Event, RunIdx};
use crate::protocol::SlotIdx;
use crate::term::Value;
use crate::theory::obtainable;
use crate::util::index::Idx;
use crate::verify::Truncation;

impl<'a, 'b> Search<'a, 'b> {
	pub(super) fn merged(&self, extra: &[NodeIdx], mut installs: Installs) -> Installs {
		let touched = runs_of(&installs);
		for &base in extra {
			for install in &self.nodes[base].installs {
				if touched.contains(&install.run())
					|| installs.iter().any(|held| held.same_input(install))
				{
					continue;
				}
				installs.push(install.clone());
			}
		}
		normalize(installs)
	}

	fn bases(
		&self,
		signature: &[(SlotIdx, Value, Vec<RunIdx>)],
		chained: &[Value],
		trusted: bool,
		sending: &[DeliveryIdx],
	) -> Option<Vec<NodeIdx>> {
		let capabilities = self.union.knowledge.capabilities();
		let mut inputs =
			crate::theory::KnowledgeInputs::new(capabilities, &self.union.knowledge.state);
		let mut chosen: Vec<NodeIdx> = Vec::new();
		let mut emitted: Option<Knowledge> = None;
		for (slot, value, targets) in signature {
			let phase = targets
				.iter()
				.filter_map(|&run| {
					let program = &self.cx.program.runs[run];
					let step = *program.step_of_slot.get(slot)?;
					Some(program.steps[step].phase)
				})
				.min()
				.unwrap_or(self.cx.km.max_phase);
			if !trusted
				&& self.derivable_in(HONEST_NODE, value, phase)
				&& let Some(&run) = targets.first()
				&& let Some(late) = self.late_source(run, *slot, value, phase, &chosen)
			{
				if !chosen.contains(&late) {
					chosen.insert(0, late);
				}
				continue;
			}
			if chosen.iter().any(|&n| self.derivable_in(n, value, phase)) {
				continue;
			}
			if trusted && self.derivable_in(HONEST_NODE, value, phase) {
				continue;
			}
			let Some(used) = inputs.of_value(value) else {
				if chained.is_empty() {
					return None;
				}
				let with = emitted.get_or_insert_with(|| {
					let mut with = self.union.closed.clone();
					for v in chained {
						with.learn(v, Origin::Initial);
					}
					with
				});
				if obtainable(value, with.capabilities(), &with.state) || with.derivable(value) {
					continue;
				}
				return None;
			};
			let used: Vec<usize> = used.iter().map(|idx| idx.get()).collect();
			match self.cheapest_source(value, &used, phase, sending) {
				Some(best) => chosen.push(best),
				None => {
					for &idx in &used {
						let Some(buckets) = self.union.by_cost.get(idx) else {
							continue;
						};
						let Some(&best) =
							buckets.iter().flatten().find(|&&n| self.sends(n, sending))
						else {
							continue;
						};
						if best != HONEST_NODE && !chosen.contains(&best) {
							chosen.push(best);
						}
					}
				}
			}
		}
		Some(chosen)
	}

	pub(super) fn receiving(
		&self,
		run: RunIdx,
		slot: SlotIdx,
		phase: i32,
	) -> Option<std::cell::RefMut<'_, Late>> {
		let step = *self.cx.program.runs[run].step_of_slot.get(&slot)?;
		Some(std::cell::RefMut::map(
			self.memo.late.borrow_mut(),
			|memo| {
				memo.entry((run, step)).or_insert_with(|| {
					let honest = self.honest.at(phase);
					let len = self
						.facts
						.honest_at
						.get(&(run, step))
						.map_or(honest.knowledge.len(), |&at| self.honest.order[at].known);
					let before = honest.knowledge.disclosing(|at, _| at < len);
					Late {
						within: (usize::MAX, before.clone()),
						before,
						supplied: Vec::new(),
						values: Vec::new(),
					}
				})
			},
		))
	}

	fn phase_union(&self, phase: i32) -> &Knowledge {
		usize::try_from(phase)
			.ok()
			.and_then(|phase| self.union.earlier.get(phase))
			.unwrap_or(&self.union.knowledge)
	}

	pub(super) fn emitted(&self, phase: i32) -> Vec<Value> {
		let union = self.phase_union(phase);
		let mut out: Vec<Value> = Vec::new();
		for (v, _, _) in self.retries.fresh.values().flatten() {
			if union.knows(v).is_some() && !out.iter().any(|held| held.equivalent(v, true)) {
				out.push(v.clone());
			}
		}
		out
	}

	pub(super) fn within<'l>(&self, receive: &'l mut Late, phase: i32) -> &'l Knowledge {
		let registered = self.retries.fresh.values().map(Vec::len).sum::<usize>();
		if receive.within.0 != registered {
			let mut within = receive.before.clone();
			for v in self.emitted(phase) {
				within.learn(&v, Origin::Initial);
			}
			within.close();
			receive.within = (registered, within);
		}
		&receive.within.1
	}

	fn late_source(
		&self,
		run: RunIdx,
		slot: SlotIdx,
		value: &Value,
		phase: i32,
		chosen: &[NodeIdx],
	) -> Option<NodeIdx> {
		let mut receive = self.receiving(run, slot, phase)?;
		let receive = &mut *receive;
		let before = &receive.before;
		let at = match receive
			.values
			.iter()
			.position(|held| held.value.equivalent(value, true))
		{
			Some(at) => at,
			None => {
				receive.values.push(Adders {
					value: value.clone(),
					late: !obtainable(value, before.capabilities(), &before.state),
					reachable: (0, false),
					scanned: HONEST_NODE.next(),
					best: None,
				});
				receive.values.len() - 1
			}
		};
		let adders = &mut receive.values[at];
		if !adders.late {
			return None;
		}
		let rank = |n: NodeIdx| (self.nodes[n].installs.len(), n);
		let supplied = receive
			.supplied
			.iter()
			.filter_map(|(target, n)| Some((target, (*n)?)))
			.filter(|&(target, n)| {
				let mut with = before.clone();
				with.learn(target, Origin::Initial);
				self.adds(n, value, phase, &with)
			})
			.map(|(_, n)| n)
			.min_by_key(|&n| rank(n));
		let union = self.phase_union(phase);
		if adders.reachable.0 != self.union.size() {
			let honest = &self.nodes[HONEST_NODE].at(phase).0;
			let mut within = before.clone();
			for v in union.state.known.iter() {
				if honest.knows(v).is_none() {
					within.learn(v, Origin::Initial);
				}
			}
			adders.reachable = (
				self.union.size(),
				obtainable(value, union.capabilities(), &within.state),
			);
		}
		if !adders.reachable.1 {
			return supplied;
		}
		if let Some(&n) = chosen.iter().find(|&&n| self.adds(n, value, phase, before)) {
			return Some(n);
		}
		for n in (adders.scanned.index()..self.nodes.len()).map(NodeIdx::new) {
			if adders.best.is_some_and(|best| rank(best) <= rank(n))
				|| !self.adds(n, value, phase, before)
			{
				continue;
			}
			adders.best = Some(n);
		}
		adders.scanned = self.nodes.next_index();
		adders.best.or(supplied)
	}

	fn adds(&self, n: NodeIdx, value: &Value, phase: i32, before: &Knowledge) -> bool {
		let capabilities = &self.nodes[n].at(phase).1;
		let additions = self.additions(n, phase);
		if additions.is_empty() {
			return obtainable(value, capabilities, &before.state);
		}
		let mut within = before.clone();
		for v in additions.iter() {
			within.learn(v, Origin::Initial);
		}
		obtainable(value, capabilities, &within.state)
	}

	fn additions(&self, n: NodeIdx, phase: i32) -> Arc<[Value]> {
		if let Some(known) = self.memo.additions.borrow().get(&(n, phase)) {
			return Arc::clone(known);
		}
		let honest = &self.nodes[HONEST_NODE].at(phase).0;
		let known: Arc<[Value]> = self.nodes[n]
			.at(phase)
			.0
			.known
			.iter()
			.filter(|v| honest.knows(v).is_none())
			.cloned()
			.collect();
		self.memo
			.additions
			.borrow_mut()
			.insert((n, phase), Arc::clone(&known));
		known
	}

	pub(super) fn sends(&self, n: NodeIdx, sending: &[DeliveryIdx]) -> bool {
		sending.iter().all(|&d| self.nodes[n].sent[d].is_some())
	}

	fn cheapest_source(
		&self,
		value: &Value,
		used: &[usize],
		phase: i32,
		sending: &[DeliveryIdx],
	) -> Option<NodeIdx> {
		let key = match value {
			Value::Primitive(p) if sending.is_empty() && crate::term::hashing::hashconsed(p) => {
				Some((Arc::as_ptr(p) as usize, phase))
			}
			_ => None,
		};
		let (from, mut best) = key
			.and_then(|key| {
				self.memo
					.cheapest
					.borrow()
					.get(&key)
					.filter(|cheapest| cheapest.used == used)
					.map(|cheapest| (cheapest.scanned, cheapest.best))
			})
			.unwrap_or((HONEST_NODE, None));
		let rank = |n: NodeIdx| (self.nodes[n].installs.len(), n);
		let bound = best.map(rank);
		let narrowest = used
			.iter()
			.copied()
			.min_by_key(|&idx| self.union.by_cost[idx].iter().map(Vec::len).sum::<usize>());
		if let Some(narrowest) = narrowest
			&& let Some(buckets) = self.union.by_cost.get(narrowest)
		{
			'scan: for (cost, bucket) in buckets.iter().enumerate() {
				if bound.is_some_and(|(limit, _)| cost > limit) {
					break;
				}
				let start = bucket.partition_point(|&n| n < from);
				for &n in &bucket[start..] {
					if n == HONEST_NODE
						|| !self.sends(n, sending)
						|| !used.iter().all(|&idx| self.supplies(idx, n))
						|| !self.derivable_in(n, value, phase)
					{
						continue;
					}
					if bound.is_none_or(|limit| (cost, n) < limit) {
						best = Some(n);
					}
					break 'scan;
				}
			}
		}
		if let Some(key) = key {
			self.memo.cheapest.borrow_mut().insert(
				key,
				Cheapest {
					used: used.to_vec(),
					scanned: self.nodes.next_index(),
					best,
				},
			);
		}
		best
	}

	fn targets(&self, r: RunIdx, slot: SlotIdx, addressed: bool) -> Vec<RunIdx> {
		let receivers = &self.facts.receivers[slot];
		if receivers.contains(&r) || addressed {
			return vec![r];
		}
		let program = self.cx.program;
		let mut reach = vec![r];
		let mut upstream = Vec::new();
		let mut at = 0;
		while at < reach.len() {
			let run = reach[at];
			at += 1;
			for delivery in &program.deliveries {
				if delivery.recipient != run {
					continue;
				}
				for &(s, guarded) in &delivery.slots {
					if s != slot {
						continue;
					}
					if !guarded {
						if !upstream.contains(&run) {
							upstream.push(run);
						}
					} else if !reach.contains(&delivery.sender) {
						reach.push(delivery.sender);
					}
				}
			}
		}
		if upstream.is_empty() {
			return receivers.clone();
		}
		upstream
	}

	pub(super) fn try_flight(
		&mut self,
		r: RunIdx,
		signature: Vec<(SlotIdx, Value)>,
		addressed: bool,
		chained: &[Value],
		targeted: bool,
	) -> Option<SlotIdx> {
		let signature: Vec<(SlotIdx, Value, Vec<RunIdx>)> = signature
			.into_iter()
			.filter_map(|(slot, value)| {
				let targets = self.targets(r, slot, addressed);
				targets
					.iter()
					.any(|&run| self.relevant_input(run, slot))
					.then(|| (slot, crate::term::hashing::hashcons(&value), targets))
			})
			.collect();
		let bases = self.bases(&signature, chained, true, &[])?;
		let km = self.cx.km;
		let bound = self.ctx.term_bound(km);
		let mut installs: Installs = Vec::new();
		let mut shared: Installs = Vec::new();
		for (slot, value, targets) in signature.iter().cloned() {
			for run in targets {
				let id = self.cx.program.runs[run].id;
				if !bound.admits_at(id, slot, &value) {
					self.ctx.note_truncation(Truncation::TermDepth);
					return None;
				}
				installs.push(Install::Value {
					run,
					slot,
					value: value.clone(),
				});
			}
			if addressed {
				continue;
			}
			for &run in &self.facts.receivers[slot] {
				if install_at(&installs, run, slot).is_some() {
					continue;
				}
				let id = self.cx.program.runs[run].id;
				let consumed = km.constant_used_by(id, &km.slots[slot].constant)
					|| km.slots[slot]
						.sent_by
						.iter()
						.any(|event| event.sender == id && event.guarded);
				if consumed && bound.admits_at(id, slot, &value) {
					shared.push(Install::Value {
						run,
						slot,
						value: value.clone(),
					});
				}
			}
		}
		let extra = runs_of(&shared);
		let everywhere = (!shared.is_empty()).then(|| {
			let mut everywhere = installs.clone();
			everywhere.extend(shared);
			everywhere
		});
		let merged = self.merged(&bases, installs.clone());
		let mut at = self.consider(merged);
		if self.outcome(at).is_some_and(|outcome| !outcome.settled)
			&& !self.done()
			&& let Some(sourced) = self
				.bases(&signature, chained, false, &[])
				.filter(|sourced| *sourced != bases)
		{
			let merged = self.merged(&sourced, installs.clone());
			self.consider(merged);
		}
		let first = at;
		let mut awaited: Vec<DeliveryIdx> = Vec::new();
		while let Some(d) = self.awaited(r, at).filter(|d| !awaited.contains(d))
			&& !self.done()
		{
			awaited.push(d);
			let Some(sending) = self
				.bases(&signature, chained, true, &awaited)
				.filter(|sending| *sending != bases)
			else {
				break;
			};
			let merged = self.merged(&sending, installs.clone());
			let again = self.consider(merged);
			if self.awaited(r, again) == Some(d) {
				break;
			}
			at = again;
		}
		if targeted
			&& !self.done()
			&& let Some(unblocked) = self.unblocking(r, first)
		{
			at = unblocked;
		}
		if let Some(everywhere) = everywhere
			&& !self.done()
		{
			let merged = self.merged(&bases, everywhere);
			self.probe(merged, &extra);
		}
		let outcome = self.outcome(at)?;
		outcome
			.halts
			.iter()
			.chain(&outcome.waits)
			.find(|(run, _)| *run == r)
			.map(|(_, slot)| *slot)
	}

	fn awaited(&self, r: RunIdx, at: AttemptIdx) -> Option<DeliveryIdx> {
		self.outcome(at)?
			.blocked
			.iter()
			.find(|(run, _)| *run == r)
			.map(|&(_, d)| d)
	}

	fn unblocking(&mut self, r: RunIdx, at: AttemptIdx) -> Option<AttemptIdx> {
		let d = self.awaited(r, at)?;
		let plan = self.attempts.tried.entries[at].0.clone();
		let sender = self.cx.program.deliveries[d].sender;
		let mut cone = Vec::new();
		for step in self.cx.program.runs[sender].steps.iter() {
			match step.event {
				Event::Send(sent) if sent == d => break,
				Event::Recv(received) => {
					for &(slot, _) in &self.cx.program.deliveries[received].slots {
						self.cone(sender, slot, &mut cone);
					}
				}
				_ => {}
			}
		}
		let mut sources: Vec<NodeIdx> = self
			.nodes
			.indices()
			.filter(|&n| n != HONEST_NODE && self.nodes[n].sent[d].is_some())
			.collect();
		sources.sort_by_key(|&n| self.nodes[n].installs.len());
		let mut merges: Vec<Installs> = Vec::new();
		for n in sources {
			if self.done() {
				break;
			}
			let mut merged = plan.clone();
			for install in &self.nodes[n].installs {
				if let Some(slot) = install.slot()
					&& cone.contains(&(install.run(), slot))
					&& !merged.iter().any(|held| held.same_input(install))
				{
					merged.push(install.clone());
				}
			}
			let merged = self.project(normalize(merged));
			if same_installs(&merged, &plan) || merges.iter().any(|m| same_installs(m, &merged)) {
				continue;
			}
			merges.push(merged.clone());
			let at = self.as_family(Family::Unblocked, |search| search.consider(merged));
			if self
				.outcome(at)
				.is_some_and(|outcome| outcome.settled && !outcome.blocked.contains(&(r, d)))
			{
				return Some(at);
			}
		}
		None
	}

	fn probe(&mut self, installs: Installs, droppable: &[RunIdx]) {
		let installs = self.project(installs);
		if !self.attempts.probed.insert(&installs) {
			return;
		}
		let ex = self.execute_counted(&installs);
		self.tally(Family::Shared, false);
		if self.log.debug {
			eprintln!(
				"[search]   probe [{}] stuck={}",
				self.shown(&installs),
				ex.stuck.len()
			);
		}
		if ex.stuck.is_empty() {
			crate::engine::judge(self.ctx, self.cx, &ex, &installs, &self.honest);
		}
		if self.done() {
			return;
		}
		let halted: Vec<RunIdx> = droppable
			.iter()
			.copied()
			.filter(|&r| ex.runs[r].halted.is_some())
			.collect();
		let blocked: Vec<RunIdx> = if halted.is_empty() {
			droppable
				.iter()
				.copied()
				.filter(|&r| ex.runs[r].frozen)
				.collect()
		} else {
			halted
		};
		if blocked.is_empty() {
			return;
		}
		let fewer: Installs = installs
			.iter()
			.filter(|install| !blocked.contains(&install.run()))
			.cloned()
			.collect();
		if fewer.is_empty() || fewer.len() == installs.len() {
			return;
		}
		let rest: Vec<RunIdx> = droppable
			.iter()
			.copied()
			.filter(|r| !blocked.contains(r))
			.collect();
		self.probe(fewer, &rest);
	}
}
