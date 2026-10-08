/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::{Family, Mode, NodeIdx, Search, normalize};
use crate::engine::exec::Install;
use crate::engine::program::RunIdx;
use crate::protocol::{ProtocolTrace, SlotIdx};
use crate::solve::deduce::Deducer;
use crate::solve::symbolic::{self, SymbolicState};
use crate::solve::vars::{self, Substitution};
use crate::solve::{Pass, propose};
use crate::syntax::QueryKind;
use crate::term::Value;
use crate::theory::AttackerState;
use crate::util::index::IndexVec;
use crate::verify::Truncation;

impl<'a, 'b> Search<'a, 'b> {
	pub(super) fn idle(&mut self) {
		let km = self.cx.km;
		let program = self.cx.program;
		let mut senders: Vec<(RunIdx, Vec<SlotIdx>)> = Vec::new();
		for q in self.ctx.open_queries() {
			if q.kind != QueryKind::Authentication {
				continue;
			}
			let Some(slot) = q.message.constant().ok().and_then(|c| km.index_of(c)) else {
				continue;
			};
			let siblings = km.sibling_slots(slot);
			for (r, run) in program.runs.iter_enumerated() {
				if !km.interchangeable_for(run.id, q.message.sender, slot) {
					continue;
				}
				let mut upstream = Vec::new();
				for &s in &siblings {
					self.cone(r, s, &mut upstream);
				}
				for candidate in std::iter::once(r).chain(upstream.into_iter().map(|(u, _)| u)) {
					if !senders.iter().any(|(s, _)| *s == candidate) {
						senders.push((candidate, siblings.clone()));
					}
				}
			}
		}
		for node in self.nodes.indices() {
			for (r, siblings) in &senders {
				if self.done() {
					return;
				}
				if self.nodes[node]
					.installs
					.iter()
					.any(|install| install.run() == *r)
					|| !self.relied_on(node, *r, siblings)
				{
					continue;
				}
				let mut installs = self.nodes[node].installs.clone();
				installs.push(Install::Idle { run: *r });
				self.as_family(Family::Idle, |search| search.consider(normalize(installs)));
			}
		}
	}

	fn relied_on(&self, node: NodeIdx, r: RunIdx, siblings: &[SlotIdx]) -> bool {
		let node = &self.nodes[node];
		let program = self.cx.program;
		program
			.sends(&node.sent)
			.filter(|(_, delivery, slot, _)| delivery.sender == r && siblings.contains(slot))
			.any(|(_, _, _, v)| {
				node.held.indices().any(|b| {
					b != r
						&& siblings.iter().any(|&s| {
							node.held(b, s)
								.is_some_and(|h| h.received && h.value.equivalent(v, true))
						})
				})
			})
	}

	pub(super) fn fixpoint(&mut self, mode: Mode) {
		let runs = self.cx.program.runs.len();
		let mut deferred: IndexVec<RunIdx, Vec<Substitution>> =
			IndexVec::from_elem(Vec::new(), runs);
		loop {
			let known = self.union.size();
			for pass in [Pass::Targeted, Pass::Constructed] {
				for (r, pending) in deferred.iter_enumerated_mut() {
					if self.done() {
						return;
					}
					let taken = match pass {
						Pass::Targeted => Vec::new(),
						Pass::Constructed => std::mem::take(pending),
					};
					let replays = self.solve_run(r, pass, mode, taken);
					if pass == Pass::Targeted {
						*pending = replays;
					}
				}
			}
			self.close_union();
			self.merge_for_queries();
			self.retry_all_stuck();
			self.drain();
			if self.log.debug {
				eprintln!(
					"[search] round: union {} -> {}, nodes {}, tried {}, fresh {}",
					known,
					self.union.knowledge.len(),
					self.nodes.len(),
					self.attempts.tried.len(),
					self.retries.fresh.values().map(Vec::len).sum::<usize>()
				);
			}
			if self.union.size() == known {
				break;
			}
		}
	}

	fn solve_run(
		&mut self,
		r: RunIdx,
		pass: Pass,
		mode: Mode,
		taken: Vec<Substitution>,
	) -> Vec<Substitution> {
		self.log.proposer = r;
		let km = self.cx.km;
		let principal = self.cx.program.runs[r].id;
		let Some(attacker) = self.union.at_last_receive(km, principal) else {
			return Vec::new();
		};
		let controllable = crate::solve::control::Controllable::of(km, principal, &attacker);
		let sym = match mode {
			Mode::Unshaped => symbolic::build_unshaped(&controllable, km, principal, &attacker),
			Mode::Plain | Mode::Refined => symbolic::build(&controllable, km, principal, &attacker),
		};
		if !sym.has_variables() {
			return Vec::new();
		}
		let mut replays = Vec::new();
		if mode != Mode::Refined || pass != Pass::Targeted {
			replays = self.propose_and_try(r, pass, &attacker, &sym, taken, false);
		} else {
			for honest in crate::solve::slots_blocking_reduction(&sym) {
				if self.done() {
					return replays;
				}
				let refined = symbolic::build_assuming_honest(
					&controllable,
					km,
					principal,
					&attacker,
					&honest,
				);
				if refined.has_variables() {
					replays.extend(self.propose_and_try(
						r,
						pass,
						&attacker,
						&refined,
						Vec::new(),
						false,
					));
				}
			}
		}
		if pass != Pass::Targeted || self.done() {
			return replays;
		}
		if !sym
			.var_slots()
			.any(|slot| crate::solve::split_delivered(km, principal, slot))
		{
			return replays;
		}
		let shared: Vec<SlotIdx> = sym
			.var_slots()
			.filter(|&slot| !crate::solve::directly_unguarded(km, principal, slot))
			.collect();
		let addressed = symbolic::build_addressed(&controllable, km, principal, &attacker, &shared);
		if addressed.has_variables() {
			self.propose_and_try(r, pass, &attacker, &addressed, Vec::new(), true);
		}
		replays
	}

	fn propose_and_try(
		&mut self,
		r: RunIdx,
		pass: Pass,
		attacker: &AttackerState,
		sym: &SymbolicState,
		taken: Vec<Substitution>,
		addressed: bool,
	) -> Vec<Substitution> {
		let km = self.cx.km;
		let run = &self.cx.program.runs[r];
		let deducer = self.deducer(attacker, sym);
		let (mut proposals, replays) = propose(self.ctx, km, run.id, pass, attacker, sym, deducer);
		proposals.extend(taken);
		let flights = flights(km, sym, proposals);
		if self.log.debug {
			eprintln!(
				"[search] {} {:?} known={} proposals={}",
				run.name,
				pass == Pass::Targeted,
				attacker.known.len(),
				flights.len()
			);
		}
		let mut repairer: Option<Deducer> = None;
		for (signature, chained, variant) in flights {
			if self.done() {
				break;
			}
			let halted = self.try_flight(r, signature, addressed, &chained);
			if let Some(check) = halted.filter(|_| pass == Pass::Targeted) {
				self.repair(r, attacker, sym, addressed, (check, variant), &mut repairer);
			}
		}
		replays
	}

	fn repair<'x>(
		&mut self,
		r: RunIdx,
		attacker: &'x AttackerState,
		sym: &'x SymbolicState,
		addressed: bool,
		halted: (SlotIdx, Substitution),
		repairer: &mut Option<Deducer<'x>>,
	) where
		'b: 'x,
	{
		let km = self.cx.km;
		let run = &self.cx.program.runs[r];
		let mut pending = vec![halted];
		let mut seen = vars::Distinct::default();
		while let Some((check, binding)) = pending.pop() {
			if self.done() {
				break;
			}
			if !seen.insert(vars::canonical_slots(&binding), check) {
				continue;
			}
			if !self.relevant_input(r, check) {
				continue;
			}
			let Some(Value::Primitive(p)) = sym.terms.get(check) else {
				continue;
			};
			if !vars::contains_var(&Value::Primitive(p.clone())) {
				continue;
			}
			let deducer = repairer.get_or_insert_with(|| {
				self.deducer(attacker, sym)
					.in_scope(std::sync::Arc::from("repair"))
			});
			let started = self.log.debug.then(std::time::Instant::now);
			let solutions = deducer.repair_check(p, &binding);
			if deducer.declined_bound() {
				self.ctx.note_truncation(Truncation::TermDepth);
			}
			if let Some(started) = started {
				eprintln!(
					"[search] repair {} at {} -> {} solutions in {:?}",
					run.name,
					km.slots[check].constant,
					solutions.len(),
					started.elapsed()
				);
			}
			let mut next = Vec::new();
			for solution in vars::dedupe(solutions) {
				if self.done() {
					break;
				}
				let signature = crate::solve::install_signature(sym, &solution);
				if signature.is_empty() {
					continue;
				}
				let emitted = crate::solve::emissions_under(km, sym, &solution);
				let halt = self.as_family(Family::Repair, |search| {
					search.try_flight(r, signature, addressed, &emitted)
				});
				if let Some(later) = halt
					&& later > check
				{
					next.push((later, solution));
				}
			}
			pending.extend(next.into_iter().rev());
		}
	}

	fn deducer<'x>(&self, attacker: &'x AttackerState, sym: &'x SymbolicState) -> Deducer<'x>
	where
		'b: 'x,
	{
		let km = self.cx.km;
		let honest: Substitution = sym
			.var_slots()
			.zip(crate::solve::honest_slot_terms(km, sym))
			.map(|(slot, honest)| (vars::attacker_var_id(slot), honest))
			.collect();
		let inputs = sym
			.variables()
			.filter(|&(slot, _)| {
				self.cx
					.program
					.runs
					.indices()
					.any(|r| self.relevant_input(r, slot))
			})
			.map(|(slot, term)| {
				(
					term.clone(),
					self.ctx.term_bound(km).maximum_depth(km, slot),
				)
			})
			.collect();
		Deducer::with_basis(km, attacker, sym, &self.ctx.known_arities(attacker), honest)
			.with_bound(inputs)
	}
}

type Flight = (Vec<(SlotIdx, Value)>, Vec<Value>, Substitution);

fn flights(km: &ProtocolTrace, sym: &SymbolicState, proposals: Vec<Substitution>) -> Vec<Flight> {
	let mut flights = Vec::new();
	let mut variants_seen = vars::Distinct::default();
	for proposal in vars::dedupe(proposals) {
		let unpinned = crate::solve::leave_honest_slots(km, sym, proposal.clone());
		let variants = if unpinned.len() == proposal.len() {
			vec![proposal]
		} else {
			vec![unpinned, proposal]
		};
		for variant in variants {
			if variant.is_empty() {
				continue;
			}
			let signature = crate::solve::install_signature(sym, &variant);
			if signature.is_empty() {
				continue;
			}
			if !variants_seen.insert(vars::canonical_slots(&variant), ()) {
				continue;
			}
			let chained = crate::solve::emissions_under(km, sym, &variant);
			flights.push((signature, chained, variant));
		}
	}
	flights
}
