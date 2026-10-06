/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::{Cheapest, Family, Search, normalize, runs_of};
use crate::engine::exec::{Installs, install_at};
use crate::engine::knowledge::{Knowledge, Origin};
use crate::term::Value;
use crate::theory::{AttackerState, obtainable};
use crate::verify::Truncation;

impl<'a, 'b> Search<'a, 'b> {
	pub(super) fn merged(&self, extra: &[usize], mut installs: Installs) -> Installs {
		let touched = runs_of(&installs);
		for &base in extra {
			for (run, slot, value) in &self.nodes[base].installs {
				if touched.contains(run) || install_at(&installs, *run, *slot).is_some() {
					continue;
				}
				installs.push((*run, *slot, value.clone()));
			}
		}
		normalize(installs)
	}

	fn bases(
		&self,
		attacker: &AttackerState,
		signature: &[(usize, Value, Vec<usize>)],
		chained: &[Value],
	) -> Option<Vec<usize>> {
		let capabilities = &self.cx.km.capabilities;
		let mut inputs = crate::theory::KnowledgeInputs::new(capabilities, attacker);
		let mut chosen: Vec<usize> = Vec::new();
		let mut emitted: Option<Knowledge> = None;
		for (_, value, _) in signature {
			if self.derivable_in(0, value) || chosen.iter().any(|&n| self.derivable_in(n, value)) {
				continue;
			}
			let Some(used) = inputs.of_value(value) else {
				if chained.is_empty() {
					return None;
				}
				let with = emitted.get_or_insert_with(|| {
					let mut with = self.closed.clone();
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
			match self.cheapest_source(value, &used) {
				Some(best) => chosen.push(best),
				None => {
					for &idx in &used {
						let Some(buckets) = self.by_cost.get(idx) else {
							continue;
						};
						let Some(&best) = buckets.iter().find_map(|bucket| bucket.first()) else {
							continue;
						};
						if best != 0 && !chosen.contains(&best) {
							chosen.push(best);
						}
					}
				}
			}
		}
		Some(chosen)
	}

	fn cheapest_source(&self, value: &Value, used: &[usize]) -> Option<usize> {
		let key = match value {
			Value::Primitive(p) if crate::term::hashing::hashconsed(p) => {
				Some(Arc::as_ptr(p) as usize)
			}
			_ => None,
		};
		let (from, mut best) = key
			.and_then(|key| {
				self.cheapest
					.borrow()
					.get(&key)
					.filter(|cheapest| cheapest.used == used)
					.map(|cheapest| (cheapest.scanned, cheapest.best))
			})
			.unwrap_or((0, None));
		let rank = |n: usize| (self.nodes[n].installs.len(), n);
		let bound = best.map(rank);
		let narrowest = used
			.iter()
			.copied()
			.min_by_key(|&idx| self.by_cost[idx].iter().map(Vec::len).sum::<usize>());
		if let Some(narrowest) = narrowest
			&& let Some(buckets) = self.by_cost.get(narrowest)
		{
			'scan: for (cost, bucket) in buckets.iter().enumerate() {
				if bound.is_some_and(|(limit, _)| cost > limit) {
					break;
				}
				let start = bucket.partition_point(|&n| n < from);
				for &n in &bucket[start..] {
					if n == 0
						|| !used.iter().all(|&idx| self.supplies(idx, n))
						|| !self.derivable_in(n, value)
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
			self.cheapest.borrow_mut().insert(
				key,
				Cheapest {
					used: used.to_vec(),
					scanned: self.nodes.len(),
					best,
				},
			);
		}
		best
	}

	fn targets(&self, r: usize, slot: usize, addressed: bool) -> Vec<usize> {
		let receivers = &self.receivers[slot];
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
		r: usize,
		attacker: &AttackerState,
		signature: Vec<(usize, Value)>,
		addressed: bool,
		chained: &[Value],
	) -> Option<usize> {
		let signature: Vec<(usize, Value, Vec<usize>)> = signature
			.into_iter()
			.filter_map(|(slot, value)| {
				let targets = self.targets(r, slot, addressed);
				targets
					.iter()
					.any(|&run| self.relevant_input(run, slot))
					.then(|| (slot, crate::term::hashing::hashcons(&value), targets))
			})
			.collect();
		let bases = self.bases(attacker, &signature, chained)?;
		let km = self.cx.km;
		let bound = self.ctx.term_bound(km);
		let mut installs: Installs = Vec::new();
		let mut shared: Installs = Vec::new();
		for (slot, value, targets) in signature {
			for run in targets {
				let id = self.cx.program.runs[run].id;
				if !bound.admits_at(id, slot, &value) {
					self.ctx.note_truncation(Truncation::TermDepth);
					return None;
				}
				installs.push((run, slot, value.clone()));
			}
			if addressed {
				continue;
			}
			for &run in &self.receivers[slot] {
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
					shared.push((run, slot, value.clone()));
				}
			}
		}
		let extra = runs_of(&shared);
		let everywhere = (!shared.is_empty()).then(|| {
			let mut everywhere = installs.clone();
			everywhere.extend(shared);
			everywhere
		});
		let merged = self.merged(&bases, installs);
		let at = self.consider(merged);
		if let Some(everywhere) = everywhere
			&& !self.done()
		{
			let merged = self.merged(&bases, everywhere);
			self.probe(merged, &extra);
		}
		self.outcome(at)?
			.halts
			.iter()
			.find(|(run, _)| *run == r)
			.map(|(_, slot)| *slot)
	}

	fn probe(&mut self, installs: Installs, droppable: &[usize]) {
		let installs = self.project(installs);
		if !self.probed.insert(&installs) {
			return;
		}
		let ex = self.execute_counted(&installs);
		self.tally(Family::Shared, false);
		if self.debug {
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
		let blocked: Vec<usize> = droppable
			.iter()
			.copied()
			.filter(|&r| ex.runs[r].halted.is_some() || ex.runs[r].frozen)
			.collect();
		if blocked.is_empty() {
			return;
		}
		let fewer: Installs = installs
			.iter()
			.filter(|(r, _, _)| !blocked.contains(r))
			.cloned()
			.collect();
		if fewer.is_empty() || fewer.len() == installs.len() {
			return;
		}
		let rest: Vec<usize> = droppable
			.iter()
			.copied()
			.filter(|r| !blocked.contains(r))
			.collect();
		self.probe(fewer, &rest);
	}
}
