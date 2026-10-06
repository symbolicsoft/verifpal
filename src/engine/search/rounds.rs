/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::{Family, Mode, Search, normalize};
use crate::engine::exec::UNSTARTED;
use crate::solve::deduce::Deducer;
use crate::solve::symbolic::{self, SymbolicState};
use crate::solve::vars::{self, Substitution};
use crate::solve::{Pass, propose};
use crate::syntax::QueryKind;
use crate::term::Value;
use crate::theory::AttackerState;
use crate::verify::Truncation;

impl<'a, 'b> Search<'a, 'b> {
	pub(super) fn idle(&mut self) {
		let km = self.cx.km;
		let program = self.cx.program;
		let mut senders: Vec<(usize, Vec<usize>)> = Vec::new();
		for q in self.ctx.open_queries() {
			if q.kind != QueryKind::Authentication {
				continue;
			}
			let Some(slot) = q.message.constant().ok().and_then(|c| km.index_of(c)) else {
				continue;
			};
			let siblings = km.sibling_slots(slot);
			for (r, run) in program.runs.iter().enumerate() {
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
		for node in 0..self.nodes.len() {
			for (r, siblings) in &senders {
				if self.done() {
					return;
				}
				if self.nodes[node].installs.iter().any(|(run, _, _)| run == r)
					|| !self.relied_on(node, *r, siblings)
				{
					continue;
				}
				let mut installs = self.nodes[node].installs.clone();
				installs.push((*r, UNSTARTED, crate::term::value_nil()));
				self.as_family(Family::Idle, |search| search.consider(normalize(installs)));
			}
		}
	}

	fn relied_on(&self, node: usize, r: usize, siblings: &[usize]) -> bool {
		let node = &self.nodes[node];
		let program = self.cx.program;
		program
			.sends(&node.sent)
			.filter(|(_, delivery, slot, _)| delivery.sender == r && siblings.contains(slot))
			.any(|(_, _, _, v)| {
				(0..node.held.len()).any(|b| {
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
		let mut deferred: Vec<Vec<Substitution>> = vec![Vec::new(); runs];
		loop {
			let known = self.union.len();
			for pass in [Pass::Targeted, Pass::Constructed] {
				for (r, pending) in deferred.iter_mut().enumerate() {
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
			if self.debug {
				eprintln!(
					"[search] round: union {} -> {}, nodes {}, tried {}, fresh {}",
					known,
					self.union.len(),
					self.nodes.len(),
					self.tried.len(),
					self.fresh.values().map(Vec::len).sum::<usize>()
				);
			}
			if self.union.len() == known {
				break;
			}
		}
	}

	fn solve_run(
		&mut self,
		r: usize,
		pass: Pass,
		mode: Mode,
		taken: Vec<Substitution>,
	) -> Vec<Substitution> {
		self.current = r;
		let km = self.cx.km;
		let principal = self.cx.program.runs[r].id;
		let attacker: AttackerState = (*self.union.state).clone();
		let controllable = crate::solve::control::Controllable::of(km, principal, &attacker);
		if !(0..km.slots.len()).any(|slot| controllable.admits(principal, &attacker, slot)) {
			return Vec::new();
		}
		let sym = match mode {
			Mode::Unshaped => symbolic::build_unshaped(&controllable, km, principal, &attacker),
			Mode::Plain | Mode::Refined => symbolic::build(&controllable, km, principal, &attacker),
		};
		if sym.var_slots.is_empty() {
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
				if !refined.var_slots.is_empty() {
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
			.var_slots
			.iter()
			.any(|&slot| crate::solve::split_delivered(km, principal, slot))
		{
			return replays;
		}
		let shared: Vec<usize> = sym
			.var_slots
			.iter()
			.copied()
			.filter(|&slot| !crate::solve::directly_unguarded(km, principal, slot))
			.collect();
		let addressed = symbolic::build_addressed(&controllable, km, principal, &attacker, &shared);
		if !addressed.var_slots.is_empty() {
			self.propose_and_try(r, pass, &attacker, &addressed, Vec::new(), true);
		}
		replays
	}

	fn propose_and_try(
		&mut self,
		r: usize,
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
		let mut signatures = Vec::new();
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
				signatures.push((signature, chained, variant));
			}
		}
		if self.debug {
			eprintln!(
				"[search] {} {:?} known={} proposals={}",
				run.name,
				pass == Pass::Targeted,
				attacker.known.len(),
				signatures.len()
			);
		}
		let mut repairer: Option<Deducer> = None;
		for (signature, chained, variant) in signatures {
			if self.done() {
				break;
			}
			let halted = self.try_flight(r, attacker, signature, addressed, &chained);
			let mut pending = halted
				.filter(|_| pass == Pass::Targeted)
				.map(|check| vec![(check, variant)])
				.unwrap_or_default();
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
				let started = self.debug.then(std::time::Instant::now);
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
						search.try_flight(r, attacker, signature, addressed, &emitted)
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
		replays
	}

	fn deducer<'x>(&self, attacker: &'x AttackerState, sym: &'x SymbolicState) -> Deducer<'x>
	where
		'b: 'x,
	{
		let km = self.cx.km;
		let honest: Substitution = sym
			.var_slots
			.iter()
			.zip(crate::solve::honest_slot_terms(km, sym))
			.map(|(&slot, honest)| (vars::attacker_var_id(slot), honest))
			.collect();
		let inputs = sym
			.var_slots
			.iter()
			.filter(|&&slot| (0..self.cx.program.runs.len()).any(|r| self.relevant_input(r, slot)))
			.filter_map(|&slot| {
				Some((
					sym.var_terms.get(slot)?.as_ref()?.clone(),
					self.ctx.term_bound(km).maximum_depth(km, slot),
				))
			})
			.collect();
		Deducer::with_basis(km, attacker, sym, &self.ctx.known_arities(attacker), honest)
			.with_bound(inputs)
	}
}
