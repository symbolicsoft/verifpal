/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::Search;
use crate::engine::exec::Execution;
use crate::engine::knowledge::{Knowledge, Origin};
use crate::term::Value;
use crate::theory::obtainable;
use crate::util::IdMap;

impl<'a, 'b> Search<'a, 'b> {
	pub(super) fn novel_terms(&self, ex: &Execution) -> Vec<Value> {
		let capabilities = &self.cx.km.capabilities;
		let union = &self.union.state;
		let _memo = crate::theory::DeductionMemo::scoped(capabilities, union);
		let depth = self.ctx.term_bound(self.cx.km).depth();
		let mut own: IdMap<u64, Vec<&Value>> = IdMap::default();
		for (value, _, produced) in ex.knowledge.protocol.iter() {
			if *produced {
				own.entry(value.hash_value()).or_default().push(value);
			}
		}
		let produced = |v: &Value| {
			own.get(&v.hash_value())
				.is_some_and(|bucket| bucket.iter().any(|held| held.equivalent(v, true)))
		};
		let knowledge = &ex.knowledge;
		knowledge
			.state
			.known
			.iter()
			.enumerate()
			.filter(|(i, v)| {
				let emitted = matches!(
					knowledge.origin(*i),
					Origin::Wire { .. } | Origin::Leak { .. }
				);
				union.knows(v).is_none()
					&& ((emitted && produced(v) && crate::solve::control::term_depth(v) <= depth)
						|| !obtainable(v, capabilities, union))
			})
			.map(|(_, v)| v.clone())
			.collect()
	}

	fn note_source(&mut self, i: usize, node: usize) {
		let cost = self.nodes[node].installs.len();
		let buckets = &mut self.by_cost[i];
		if buckets.len() <= cost {
			buckets.resize_with(cost + 1, Vec::new);
		}
		buckets[cost].push(node);
	}

	pub(super) fn supplies(&self, idx: usize, node: usize) -> bool {
		self.by_cost[idx]
			.get(self.nodes[node].installs.len())
			.is_some_and(|bucket| bucket.binary_search(&node).is_ok())
	}

	pub(super) fn absorb(&mut self, node: usize, novel: Vec<Value>, knowledge: &Knowledge) {
		for v in knowledge.state.known.iter() {
			if let Some(i) = self.union.knows(v) {
				self.note_source(i, node);
			}
		}
		for v in novel {
			if self.union.learn(&v, Origin::Initial) {
				self.by_cost.push(Vec::new());
				self.note_source(self.by_cost.len() - 1, node);
				crate::console::info_deduction(|| {
					format!(
						"{} is obtained in an execution where {}.",
						crate::console::info_output_text(&v),
						self.describe(node)
					)
				});
			}
		}
		self.absorb_terms(knowledge);
	}

	pub(super) fn absorb_terms(&mut self, knowledge: &Knowledge) {
		let protocol = Arc::clone(&knowledge.protocol);
		let built = Arc::clone(&knowledge.built);
		let reused = Arc::clone(&knowledge.state.reused);
		for (value, pre, own) in protocol.iter() {
			let key = value.hash_value() ^ pre.hash_value().rotate_left(7);
			let bucket = self.protocol_seen.entry(key).or_default();
			if bucket
				.iter()
				.any(|(v, p)| v.equivalent(value, true) && p.equivalent(pre, true))
			{
				continue;
			}
			bucket.push((value.clone(), pre.clone()));
			self.union.note_protocol(value, pre, *own);
		}
		for term in built.iter() {
			self.union.note_built(term);
		}
		for pair in reused.iter() {
			self.union.note_reused(pair);
		}
	}

	pub(super) fn close_union(&mut self) {
		self.closed = self.union.clone();
		self.closed_at = (self.union.len(), self.nodes.len());
		self.closed.close(&self.cx.km.capabilities);
	}

	pub(super) fn derivable_in(&self, node: usize, v: &Value) -> bool {
		let derive = || {
			let capabilities = &self.cx.km.capabilities;
			let node = &self.nodes[node];
			node.memo
				.borrow_mut()
				.within(capabilities, node.state(), || {
					obtainable(v, capabilities, node.state())
				})
		};
		let Value::Primitive(p) = v else {
			return derive();
		};
		if !crate::term::hashing::hashconsed(p) {
			return derive();
		}
		let key = (node, Arc::as_ptr(p) as usize);
		if let Some(&known) = self.derivable.borrow().get(&key) {
			return known;
		}
		let found = derive();
		self.derivable.borrow_mut().insert(key, found);
		found
	}
}
