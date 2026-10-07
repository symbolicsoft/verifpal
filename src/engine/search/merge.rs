/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::{Family, NodeIdx, Search, Tried, compatible_with, normalize, runs_of};
use crate::engine::exec::{Install, Installs};
use crate::engine::program::RunIdx;
use crate::protocol::ProtocolTrace;
use crate::protocol::SlotIdx;
use crate::syntax::QueryKind;
use crate::term::Value;
use crate::util::IdMap;

fn first_compatible(context: &Installs, leaves: &[Vec<Installs>]) -> Option<Installs> {
	if !leaves.iter().all(|sources| {
		sources
			.iter()
			.any(|source| compatible_with(context, source))
	}) {
		return None;
	}
	let mut failed: Vec<Tried> = leaves.iter().map(|_| Tried::default()).collect();
	choose(context, leaves, &mut failed)
}

fn choose(plan: &Installs, leaves: &[Vec<Installs>], failed: &mut [Tried]) -> Option<Installs> {
	let Some((sources, rest)) = leaves.split_first() else {
		return Some(plan.clone());
	};
	if failed[rest.len()].position(plan).is_some() {
		return None;
	}
	for source in sources {
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
		if let Some(done) = choose(&normalize(next), rest, failed) {
			return Some(done);
		}
	}
	failed[rest.len()].insert(plan);
	None
}

fn wanted_values(held: &Value, kind: QueryKind, km: &ProtocolTrace) -> Vec<Value> {
	if kind != QueryKind::Unlinkability {
		return vec![held.clone()];
	}
	let Value::Primitive(p) = held else {
		return Vec::new();
	};
	p.arguments
		.iter()
		.filter(|a| crate::engine::unlink::depends_on_secret(a, km))
		.cloned()
		.collect()
}

impl<'a, 'b> Search<'a, 'b> {
	fn leaves(&self, idx: usize, out: &mut Vec<Vec<Installs>>, seen: &mut Vec<usize>) {
		if seen.contains(&idx) {
			return;
		}
		seen.push(idx);
		let (known, nodes) = self.union.closed_at;
		if idx < known {
			let sources: Vec<Installs> = self.union.by_cost[idx]
				.iter()
				.flatten()
				.filter(|&&n| n < nodes)
				.map(|&n| self.nodes[n].installs.clone())
				.collect();
			if !sources.is_empty() {
				out.push(sources);
				return;
			}
		}
		let Some(record) = self.union.closed.state.derivations.get(idx) else {
			return;
		};
		for ingredient in record.ingredients() {
			if let Some(i) = self.union.closed.knows(ingredient) {
				self.leaves(i, out, seen);
			}
		}
	}

	pub(super) fn merge_for_queries(&mut self) {
		let km = self.cx.km;
		let mut targets: Vec<(usize, NodeIdx)> = Vec::new();
		let mut index: IdMap<usize, usize> = IdMap::default();
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
				self.index_holders(slot, q.kind);
				for (wanted, holder) in &self.memo.holders[&(slot, q.kind)].values {
					let Some(idx) = self.union.closed.knows(wanted) else {
						continue;
					};
					if idx < self.union.closed_at.0 {
						continue;
					}
					match index.get(&idx) {
						Some(&at) => {
							if self.nodes[targets[at].1].installs.len()
								> self.nodes[*holder].installs.len()
							{
								targets[at].1 = *holder;
							}
						}
						None => {
							index.insert(idx, targets.len());
							targets.push((idx, *holder));
						}
					}
				}
			}
		}
		let mut plans = Vec::new();
		for (idx, context) in targets {
			if self.done() {
				break;
			}
			let value = &self.union.closed.state.known[idx];
			let key = (value.hash_value(), context);
			if self
				.attempts
				.merged
				.get(&key)
				.is_some_and(|seen| seen.iter().any(|held: &Value| held.equivalent(value, true)))
			{
				continue;
			}
			self.attempts
				.merged
				.entry(key)
				.or_default()
				.push(value.clone());
			let mut leaves = Vec::new();
			self.leaves(idx, &mut leaves, &mut Vec::new());
			if leaves.is_empty() {
				continue;
			}
			if self.log.debug {
				eprintln!(
					"[search] merge target {}: context {}, sources {:?}",
					self.union.closed.state.known[idx],
					context,
					leaves.iter().map(Vec::len).collect::<Vec<_>>()
				);
			}
			if let Some(plan) = first_compatible(&self.nodes[context].installs, &leaves) {
				plans.push(plan);
			}
		}
		for plan in plans {
			if self.done() {
				break;
			}
			self.as_family(Family::Merge, |search| search.consider(plan));
		}
	}

	fn index_holders(&mut self, slot: SlotIdx, kind: QueryKind) {
		let km = self.cx.km;
		let holders = self.memo.holders.entry((slot, kind)).or_default();
		for n in self.nodes.indices_from(holders.scanned) {
			let node = &self.nodes[n];
			for run in node.held.indices() {
				let Some(h) = node.held(run, slot) else {
					continue;
				};
				for wanted in wanted_values(&h.value, kind, km) {
					let bucket = holders.index.entry(wanted.hash_value()).or_default();
					match bucket
						.iter()
						.copied()
						.find(|&at| holders.values[at].0.equivalent(&wanted, true))
					{
						Some(at) => {
							let held = &mut holders.values[at].1;
							if self.nodes[*held].installs.len() > node.installs.len() {
								*held = n;
							}
						}
						None => {
							bucket.push(holders.values.len());
							holders.values.push((wanted, n));
						}
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
