/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::{Attempt, Bypassed, Family, Node, Outcome, Search, Stuck, normalize, runs_of};
use crate::engine::exec::{Execution, Installs, execute};
use crate::engine::program::Event;
use crate::term::Value;
use crate::theory::obtainable;
use crate::util::IdSet;

fn varied(
	fills: &Installs,
	alternative: impl Fn(usize, usize, &Value) -> Option<Value>,
) -> Option<Installs> {
	let mut changed = false;
	let out = fills
		.iter()
		.map(|(run, slot, value)| match alternative(*run, *slot, value) {
			Some(v) => {
				changed = true;
				(*run, *slot, v)
			}
			None => (*run, *slot, value.clone()),
		})
		.collect();
	changed.then_some(out)
}

fn rebuilt(honest: &Value, obtains: &impl Fn(&Value) -> bool) -> Value {
	if obtains(honest) {
		return honest.clone();
	}
	match honest {
		Value::Primitive(p) => {
			let arguments: Vec<Value> = p.arguments.iter().map(|a| rebuilt(a, obtains)).collect();
			Value::Primitive(Arc::new(p.with_arguments(arguments)))
		}
		Value::Constant(_) | Value::Variable(_) => crate::term::value_nil(),
	}
}

fn halts_of(ex: &Execution) -> Vec<(usize, usize)> {
	ex.runs
		.iter()
		.enumerate()
		.filter_map(|(run, state)| state.halted.map(|slot| (run, slot)))
		.collect()
}

impl<'a, 'b> Search<'a, 'b> {
	pub(super) fn drain(&mut self) {
		while !self.done() {
			if let Some(at) = self.pending.pop() {
				self.advance(at);
				continue;
			}
			let Some(installs) = self.drops.pop() else {
				break;
			};
			for skip in 0..installs.len() {
				if self.done() {
					return;
				}
				let fewer: Installs = installs
					.iter()
					.enumerate()
					.filter(|(i, _)| *i != skip)
					.map(|(_, install)| install.clone())
					.collect();
				self.as_family(Family::Drop, |search| search.enqueue(fewer));
			}
		}
	}

	pub(super) fn push_node(&mut self, node: Node) {
		let at = self.nodes.len();
		for (run, slot, value) in &node.installs {
			self.by_install
				.entry((*run, *slot, value.hash_value()))
				.or_default()
				.push(at);
		}
		self.nodes.push(node);
	}

	pub(super) fn as_family<T>(&mut self, family: Family, f: impl FnOnce(&mut Self) -> T) -> T {
		let outer = std::mem::replace(&mut self.family, family);
		let out = f(self);
		self.family = outer;
		out
	}

	pub(super) fn execute_counted(&mut self, installs: &Installs) -> Execution {
		self.executed += 1;
		self.ctx.analysis_count_increment();
		let executed = self.executed;
		let ctx = self.ctx;
		crate::console::info_status_update(|| {
			crate::verify::status_line(
				ctx,
				self.cx.km.max_phase,
				&self.cx.program.runs[self.current].name,
				&format!(
					"{executed} execution{} checked",
					if executed == 1 { "" } else { "s" }
				),
			)
		});
		execute(self.cx, installs)
	}

	pub(super) fn consider(&mut self, installs: Installs) -> usize {
		let (at, _) = self.enqueue(installs);
		self.advance(at);
		self.drain();
		at
	}

	pub(super) fn settles(&mut self, installs: Installs) -> bool {
		let (at, new) = self.enqueue(installs);
		if !new {
			return false;
		}
		self.advance(at);
		self.drain();
		self.outcome(at).is_some_and(|outcome| outcome.settled)
	}

	pub(super) fn outcome(&self, at: usize) -> Option<&Outcome> {
		self.tried.entries[at].1.outcome.as_ref()
	}

	pub(super) fn enqueue(&mut self, installs: Installs) -> (usize, bool) {
		let installs = self.project(installs);
		if let Some(at) = self.tried.position(&installs) {
			return (at, false);
		}
		let at = self.tried.len();
		self.tried.remember(
			&installs,
			Attempt {
				outcome: None,
				family: self.family,
			},
		);
		self.pending.push(at);
		(at, true)
	}

	fn advance(&mut self, at: usize) {
		if self.tried.entries[at].1.outcome.is_some() {
			return;
		}
		let installs = self.tried.entries[at].0.clone();
		let family = self.tried.entries[at].1.family;
		self.as_family(family, |search| {
			let ex = search.execute_counted(&installs);
			let stuck = !ex.stuck.is_empty();
			search.tried.entries[at].1.outcome = Some(Outcome {
				halts: halts_of(&ex),
				settled: !stuck,
			});
			if stuck && family.derived() {
				return;
			}
			let fills = search.fills(&ex);
			let accepted = search.accept(installs.clone(), ex);
			search.tally(family, accepted);
			for fill in fills {
				if search.done() {
					break;
				}
				let mut filled = installs.clone();
				filled.extend(fill);
				search.as_family(Family::Fill, |search| search.enqueue(normalize(filled)));
			}
		});
	}

	fn fills(&self, ex: &Execution) -> Vec<Installs> {
		let km = self.cx.km;
		let honest = &self.honest;
		let state = &ex.knowledge.state;
		let _memo = crate::theory::DeductionMemo::scoped(&km.capabilities, state);
		let obtains = |v: &Value| obtainable(v, &km.capabilities, state);
		let honest_value = |run: usize, slot: usize| honest.runs[run].held(slot).map(|h| &h.value);
		let mut fills: Installs = ex
			.withheld
			.iter()
			.map(|&(run, slot)| {
				let value = honest_value(run, slot)
					.filter(|v| obtains(v))
					.cloned()
					.unwrap_or_else(crate::term::value_nil);
				(run, slot, value)
			})
			.collect();
		for (b, run) in ex.runs.iter().enumerate() {
			if run.halted.is_none() || honest.runs[b].halted.is_some() {
				continue;
			}
			for step in &self.cx.program.runs[b].steps[..run.pc] {
				let Event::Recv(d) = step.event else {
					continue;
				};
				for &(slot, guarded) in &self.cx.program.deliveries[d].slots {
					let Some(held) = run.held(slot) else {
						continue;
					};
					if guarded || held.installed.is_some() {
						continue;
					}
					let Some(value) = honest_value(b, slot) else {
						continue;
					};
					if value.equivalent(&held.value, true) || !obtains(value) {
						continue;
					}
					fills.push((b, slot, value.clone()));
				}
			}
		}
		if fills.is_empty() {
			return Vec::new();
		}
		let replayed = varied(&fills, |run, slot, value| {
			if honest_value(run, slot).is_some_and(obtains) {
				return None;
			}
			km.session_sibling_values(&km.slots[slot].constant)
				.into_iter()
				.find(|v| !v.equivalent(value, true) && obtains(v))
		});
		let built = varied(&fills, |run, slot, value| {
			honest_value(run, slot)
				.filter(|h| !obtains(h))
				.map(|h| rebuilt(h, &obtains))
				.filter(|v| !v.equivalent(value, true) && obtains(v))
		});
		[built, replayed]
			.into_iter()
			.flatten()
			.chain(std::iter::once(fills))
			.collect()
	}

	pub(super) fn accept(&mut self, installs: Installs, ex: Execution) -> bool {
		if self.debug {
			eprintln!(
				"[search]   try {:?} [{}] stuck={} known={}",
				self.family,
				self.shown(&installs),
				ex.stuck.len(),
				ex.knowledge.len()
			);
		}
		if !ex.stuck.is_empty() {
			let admitted: Installs = installs
				.iter()
				.filter(|(run, slot, _)| !ex.stuck.contains(&(*run, *slot)))
				.cloned()
				.collect();
			let supply = installs
				.iter()
				.enumerate()
				.filter(|(_, (run, slot, value))| {
					!admitted.is_empty()
						&& ex.stuck.contains(&(*run, *slot))
						&& self.derivable_in(0, value)
				})
				.map(|(install, _)| (install, 1))
				.collect();
			self.stuck.push(Stuck {
				installs,
				slots: ex.stuck,
				tried_with: IdSet::default(),
				supply,
			});
			self.retry_stuck(self.stuck.len() - 1);
			if !admitted.is_empty() {
				self.as_family(Family::Admitted, |search| search.enqueue(admitted));
			}
			return false;
		}
		crate::engine::judge(self.ctx, self.cx, &ex, &installs, &self.honest);
		let novel = self.novel_terms(&ex);
		let kept = !novel.is_empty()
			|| ex
				.knowledge
				.state
				.reused
				.iter()
				.any(|pair| !self.union.has_reused(pair));
		let alternative = !kept
			&& ex
				.knowledge
				.state
				.known
				.iter()
				.any(|v| self.union.knows(v).is_some_and(|i| i >= self.honest_known));
		if kept
			&& self.family != Family::Drop
			&& runs_of(&installs).len() == 1
			&& installs.len() > 1
		{
			self.drops.push(installs.clone());
		}
		let node = Node::of(installs, &ex, &self.queried);
		let at = self.nodes.len();
		let fresh = self.note_fresh(at, &node);
		if !(kept || fresh || alternative) {
			if !self.rerouting {
				let sends: Vec<(Value, usize, Bypassed)> = self
					.rerouted_sends(at, &node)
					.into_iter()
					.map(|(v, source, bypassed)| (v, source.run, bypassed))
					.collect();
				if !sends.is_empty() {
					self.routes.push((node.installs, sends));
				}
			}
			return false;
		}
		self.push_node(node);
		self.absorb(at, novel, &ex.knowledge);
		if kept {
			self.transfer(at);
		}
		kept
	}
}
