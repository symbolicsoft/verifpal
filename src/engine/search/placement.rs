/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::{Cheapest, Family, HONEST_NODE, NodeIdx, Search, normalize, runs_of};
use crate::engine::exec::{Install, Installs, install_at};
use crate::engine::knowledge::{Knowledge, Origin};
use crate::engine::program::RunIdx;
use crate::protocol::SlotIdx;
use crate::term::Value;
use crate::theory::obtainable;
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
	) -> Option<Vec<NodeIdx>> {
		let capabilities = &self.cx.km.capabilities;
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
				if obtainable(value, capabilities, &with.state)
					|| with.derivable(value, capabilities)
				{
					continue;
				}
				return None;
			};
			let used: Vec<usize> = used.iter().map(|idx| idx.get()).collect();
			match self.cheapest_source(value, &used, phase) {
				Some(best) => chosen.push(best),
				None => {
					for &idx in &used {
						let Some(buckets) = self.union.by_cost.get(idx) else {
							continue;
						};
						let Some(&best) = buckets.iter().find_map(|bucket| bucket.first()) else {
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

	fn cheapest_source(&self, value: &Value, used: &[usize], phase: i32) -> Option<NodeIdx> {
		let key = match value {
			Value::Primitive(p) if crate::term::hashing::hashconsed(p) => {
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
		let bases = self.bases(&signature, chained, true)?;
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
		let at = self.consider(merged);
		if self.outcome(at).is_some_and(|outcome| !outcome.settled)
			&& !self.done()
			&& let Some(sourced) = self
				.bases(&signature, chained, false)
				.filter(|sourced| *sourced != bases)
		{
			let merged = self.merged(&sourced, installs);
			self.consider(merged);
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
