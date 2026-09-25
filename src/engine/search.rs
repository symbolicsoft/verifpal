/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::exec::{Context, Execution, Installs, execute, install_at};
use super::knowledge::{Knowledge, Origin};
use super::program::Event;
use crate::context::VerifyContext;
use crate::solve::deduce::Deducer;
use crate::solve::symbolic::{self, SymbolicState};
use crate::solve::vars::{self, Substitution};
use crate::solve::{Pass, propose};
use crate::theory::obtainable;
use crate::types::*;

struct Node {
	installs: Installs,
	ex: Execution,
}

pub(crate) struct Search<'a, 'b> {
	ctx: &'a VerifyContext,
	cx: &'a Context<'b>,
	nodes: Vec<Node>,
	union: Knowledge,
	provenance: Vec<Vec<u32>>,
	closed: Knowledge,
	closed_provenance: Vec<Vec<u32>>,
	tried: Tried,
	probed: Tried,
	protocol_seen: IdMap<u64, Vec<(Value, Value)>>,
	stuck: Vec<Stuck>,
	fresh: IdMap<u64, Vec<(Value, Source)>>,
	merged_targets: Vec<u64>,
	drops: Vec<Installs>,
	executed: usize,
	current: usize,
	debug: bool,
	family: &'static str,
	stats: Vec<(&'static str, usize, usize)>,
}

#[derive(Clone)]
struct Stuck {
	installs: Installs,
	slots: Vec<(usize, usize)>,
	tried_with: Vec<usize>,
}

#[derive(Clone, Copy)]
struct Source {
	node: usize,
	run: usize,
	slot: usize,
}

struct Settled {
	accepted: bool,
	halts: Vec<Option<usize>>,
}

#[derive(Default)]
struct Tried(IdMap<u64, Vec<Installs>>);

impl Tried {
	fn insert(&mut self, installs: &Installs) -> bool {
		let bucket = self.0.entry(installs_hash(installs)).or_default();
		if bucket.iter().any(|seen| same_installs(seen, installs)) {
			return false;
		}
		bucket.push(installs.clone());
		true
	}

	fn len(&self) -> usize {
		self.0.values().map(Vec::len).sum()
	}
}

type Candidate = (Vec<(usize, Value)>, Vec<Value>, Substitution);

fn installs_hash(installs: &Installs) -> u64 {
	let mut acc: u64 = 0x9E37_79B9_7F4A_7C15;
	for (run, slot, value) in installs {
		acc = acc
			.rotate_left(13)
			.wrapping_add(((*run as u64) << 32 | *slot as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F))
			^ value.hash_value();
	}
	acc
}

fn same_installs(a: &Installs, b: &Installs) -> bool {
	a.len() == b.len()
		&& a.iter()
			.zip(b)
			.all(|((r1, s1, v1), (r2, s2, v2))| r1 == r2 && s1 == s2 && v1.equivalent(v2, true))
}

fn runs_of(installs: &Installs) -> Vec<usize> {
	let mut runs: Vec<usize> = installs.iter().map(|(run, _, _)| *run).collect();
	runs.sort_unstable();
	runs.dedup();
	runs
}

fn normalize(mut installs: Installs) -> Installs {
	installs.sort_by_key(|(run, slot, _)| (*run, *slot));
	installs.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
	installs
}

impl<'a, 'b> Search<'a, 'b> {
	pub(crate) fn new(ctx: &'a VerifyContext, cx: &'a Context<'b>, root: Execution) -> Self {
		let mut union = Knowledge::new(cx.km.max_phase);
		let mut provenance = Vec::new();
		for v in root.knowledge.state.known.iter() {
			if union.learn(v, Origin::Initial) {
				provenance.push(vec![0]);
			}
		}
		let mut search = Search {
			ctx,
			cx,
			nodes: vec![Node {
				installs: Vec::new(),
				ex: root,
			}],
			closed: union.clone(),
			closed_provenance: provenance.clone(),
			union,
			provenance,
			tried: Tried::default(),
			probed: Tried::default(),
			protocol_seen: IdMap::default(),
			stuck: Vec::new(),
			fresh: IdMap::default(),
			merged_targets: Vec::new(),
			drops: Vec::new(),
			executed: 0,
			current: 0,
			debug: std::env::var("VERIFPAL_SOLVE_DEBUG").is_ok(),
			family: "base",
			stats: Vec::new(),
		};
		search.absorb_terms(0);
		search.close_union();
		search
	}

	fn done(&self) -> bool {
		self.ctx.all_resolved() || self.ctx.cancelled()
	}

	fn novel_terms(&self, ex: &Execution) -> Vec<Value> {
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

	fn absorb(&mut self, node: usize, novel: Vec<Value>) {
		let known = Arc::clone(&self.nodes[node].ex.knowledge.state.known);
		for v in known.iter() {
			if let Some(i) = self.union.knows(v)
				&& !self.provenance[i].contains(&(node as u32))
			{
				self.provenance[i].push(node as u32);
			}
		}
		for v in novel {
			if self.union.learn(&v, Origin::Initial) {
				self.provenance.push(vec![node as u32]);
				crate::info::info_deduction(|| {
					format!(
						"{} is obtained in an execution where {}.",
						crate::info::info_output_text(&v),
						self.describe(node)
					)
				});
			}
		}
		self.absorb_terms(node);
	}

	fn absorb_terms(&mut self, node: usize) {
		let knowledge = &self.nodes[node].ex.knowledge;
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

	fn describe(&self, node: usize) -> String {
		let shown: Vec<String> = self.nodes[node]
			.installs
			.iter()
			.map(|(run, slot, value)| {
				format!(
					"{}'s {} is {}",
					self.cx.program.runs[*run].name, self.cx.km.slots[*slot].constant, value
				)
			})
			.collect();
		if shown.is_empty() {
			"the protocol runs honestly".to_string()
		} else {
			shown.join(", ")
		}
	}

	fn close_union(&mut self) {
		self.closed = self.union.clone();
		self.closed_provenance = self.provenance.clone();
		self.closed.close(&self.cx.km.capabilities);
		while self.closed_provenance.len() < self.closed.len() {
			self.closed_provenance.push(Vec::new());
		}
	}

	fn compatible(&self, plan: &Installs, node: usize) -> bool {
		self.nodes[node].installs.iter().all(|(run, slot, value)| {
			plan.iter()
				.all(|(r2, s2, v2)| r2 != run || s2 != slot || v2.equivalent(value, true))
		})
	}

	fn leaves(&self, idx: usize, plan: &mut Installs, out: &mut Vec<usize>, seen: &mut Vec<usize>) {
		if seen.contains(&idx) {
			return;
		}
		seen.push(idx);
		let from = &self.closed_provenance[idx];
		if !from.is_empty() {
			if from.contains(&0) || from.iter().any(|&n| out.contains(&(n as usize))) {
				return;
			}
			let mut candidates: Vec<usize> = from.iter().map(|&n| n as usize).collect();
			candidates.sort_by_key(|&n| self.nodes[n].installs.len());
			let best = candidates
				.iter()
				.copied()
				.find(|&n| self.compatible(plan, n))
				.unwrap_or(candidates[0]);
			for install in &self.nodes[best].installs {
				if install_at(plan, install.0, install.1).is_none() {
					plan.push(install.clone());
				}
			}
			out.push(best);
			return;
		}
		let Some(record) = self.closed.state.derivations.get(idx) else {
			return;
		};
		for ingredient in record.ingredients() {
			if let Some(i) = self.closed.knows(ingredient) {
				self.leaves(i, plan, out, seen);
			}
		}
	}

	fn merged(&self, extra: &[usize], mut installs: Installs) -> Installs {
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

	fn merge_for_queries(&mut self) {
		let km = self.cx.km;
		let mut targets: Vec<(Value, usize)> = Vec::new();
		for result in self.ctx.results_get() {
			if result.resolved || result.query.kind != QueryKind::Confidentiality {
				continue;
			}
			for q in std::iter::once(&result.query).chain(result.variants.iter()) {
				let Ok(c) = q.subject() else {
					continue;
				};
				let Some(slot) = km.index_of(c) else {
					continue;
				};
				for (n, node) in self.nodes.iter().enumerate() {
					for run in &node.ex.runs {
						let Some(h) = run.held(slot) else {
							continue;
						};
						if self.closed.knows(&h.value).is_none() {
							continue;
						}
						match targets
							.iter()
							.position(|(v, _)| v.equivalent(&h.value, true))
						{
							Some(at) => {
								if self.nodes[targets[at].1].installs.len() > node.installs.len() {
									targets[at].1 = n;
								}
							}
							None => targets.push((h.value.clone(), n)),
						}
					}
				}
			}
		}
		let mut plans: Vec<Installs> = Vec::new();
		for (value, n) in targets {
			if self
				.nodes
				.iter()
				.any(|node| node.ex.knowledge.knows(&value).is_some())
			{
				continue;
			}
			let Some(idx) = self.closed.knows(&value) else {
				continue;
			};
			let key = value.hash_value() ^ (n as u64).rotate_left(29);
			if self.merged_targets.contains(&key) {
				continue;
			}
			self.merged_targets.push(key);
			let mut extra = Vec::new();
			let mut plan = self.nodes[n].installs.clone();
			self.leaves(idx, &mut plan, &mut extra, &mut Vec::new());
			extra.retain(|&e| e != n);
			if extra.is_empty() {
				continue;
			}
			let plan = normalize(plan);
			if !plans.iter().any(|p| same_installs(p, &plan)) {
				plans.push(plan);
			}
		}
		self.consider_all("merge", plans);
	}

	pub(crate) fn run(&mut self) {
		self.fixpoint(false);
		if self.done() {
			return;
		}
		let before = self.union.len();
		self.fixpoint(true);
		if self.union.len() != before && !self.done() {
			self.fixpoint(false);
		}
	}

	fn fixpoint(&mut self, refined: bool) {
		let runs = self.cx.program.runs.len();
		let mut deferred: Vec<Vec<Vec<(ValueId, Value)>>> = vec![Vec::new(); runs];
		loop {
			let before = self.union.len();
			for pass in [Pass::Targeted, Pass::Constructed] {
				for (r, pending) in deferred.iter_mut().enumerate() {
					if self.done() {
						return;
					}
					let taken = match pass {
						Pass::Targeted => Vec::new(),
						Pass::Constructed => std::mem::take(pending),
					};
					let replays = self.solve_run(r, pass, refined, taken);
					if pass == Pass::Targeted {
						*pending = replays;
					}
				}
			}
			self.close_union();
			self.merge_for_queries();
			self.retry_all_stuck();
			if self.debug {
				eprintln!(
					"[search] round: union {} -> {}, nodes {}, tried {}, stuck {}, fresh {}",
					before,
					self.union.len(),
					self.nodes.len(),
					self.tried.len(),
					self.stuck.len(),
					self.fresh.values().map(Vec::len).sum::<usize>()
				);
			}
			if self.union.len() == before {
				break;
			}
		}
	}

	fn solve_run(
		&mut self,
		r: usize,
		pass: Pass,
		refined: bool,
		taken: Vec<Vec<(ValueId, Value)>>,
	) -> Vec<Vec<(ValueId, Value)>> {
		self.current = r;
		let km = self.cx.km;
		let principal = self.cx.program.runs[r].id;
		let attacker: AttackerState = (*self.union.state).clone();
		let controllable = crate::solve::control::Controllable::of(km, principal, &attacker);
		if !(0..km.slots.len()).any(|slot| controllable.admits(principal, &attacker, slot)) {
			return Vec::new();
		}
		let sym = symbolic::build(&controllable, km, principal, &attacker);
		if sym.var_slots.is_empty() {
			return Vec::new();
		}
		let mut replays = Vec::new();
		if !refined || pass != Pass::Targeted {
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
		taken: Vec<Vec<(ValueId, Value)>>,
		addressed: bool,
	) -> Vec<Vec<(ValueId, Value)>> {
		let km = self.cx.km;
		let run = &self.cx.program.runs[r];
		let deducer = self.deducer(attacker, sym);
		let truncated = deducer.truncation_flag();
		let (proposals, replays) =
			propose(self.ctx, km, run.id, pass, attacker, sym, deducer, taken);
		if truncated.load(std::sync::atomic::Ordering::Relaxed) {
			self.ctx.note_truncation(Truncation::SolverVariables);
		}
		let mut signatures: Vec<Candidate> = Vec::new();
		let mut buckets: IdMap<u64, Vec<usize>> = IdMap::default();
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
				let chained = crate::solve::emissions_under(km, sym, &variant);
				let bucket = buckets
					.entry(crate::solve::signature_hash(&signature))
					.or_default();
				if bucket
					.iter()
					.any(|&i| crate::solve::same_install_signature(&signatures[i].0, &signature))
				{
					continue;
				}
				bucket.push(signatures.len());
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
			let mut halted = self.try_flight(r, attacker, signature, addressed, &chained);
			let mut binding = variant;
			while let Some(check) = halted {
				let Some(Value::Primitive(p)) = sym.terms.get(check) else {
					break;
				};
				if !vars::contains_var(&Value::Primitive(p.clone())) {
					break;
				}
				let deducer = repairer.get_or_insert_with(|| self.deducer(attacker, sym));
				let started = self.debug.then(std::time::Instant::now);
				let solutions = deducer.repair_check(p, &binding);
				if let Some(started) = started {
					eprintln!(
						"[search] repair {} at {} -> {} solutions in {:?}",
						run.name,
						km.slots[check].constant,
						solutions.len(),
						started.elapsed()
					);
				}
				let mut next: Option<(usize, Substitution)> = None;
				for solution in vars::dedupe(solutions) {
					if self.done() {
						break;
					}
					let signature = crate::solve::install_signature(sym, &solution);
					if signature.is_empty() {
						continue;
					}
					let emitted = crate::solve::emissions_under(km, sym, &solution);
					let halt = self.as_family("repair", |search| {
						search.try_flight(r, attacker, signature, addressed, &emitted)
					});
					match halt {
						Some(later) if later > check && next.is_none() => {
							next = Some((later, solution));
						}
						_ => {}
					}
				}
				match next {
					Some((later, solution)) => {
						halted = Some(later);
						binding = solution;
					}
					None => break,
				}
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
		Deducer::with_basis(km, attacker, sym, self.ctx.known_subterms(attacker), honest)
	}

	fn derivable_in(&self, node: usize, v: &Value) -> bool {
		obtainable(
			v,
			&self.cx.km.capabilities,
			&self.nodes[node].ex.knowledge.state,
		)
	}

	fn bases(
		&self,
		attacker: &AttackerState,
		signature: &[(usize, Value)],
		chained: &[Value],
	) -> Option<Vec<usize>> {
		let capabilities = &self.cx.km.capabilities;
		let mut inputs = crate::theory::KnowledgeInputs::new(capabilities, attacker);
		let mut chosen: Vec<usize> = Vec::new();
		let mut emitted: Option<Knowledge> = None;
		for (_, value) in signature {
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
			let mut candidates: Vec<usize> = Vec::new();
			for idx in &used {
				for &n in self.provenance.get(idx.get()).into_iter().flatten() {
					if n != 0 && !candidates.contains(&(n as usize)) {
						candidates.push(n as usize);
					}
				}
			}
			candidates.sort_by_key(|&n| self.nodes[n].installs.len());
			match candidates
				.iter()
				.copied()
				.find(|&n| self.derivable_in(n, value))
			{
				Some(best) => chosen.push(best),
				None => {
					for idx in &used {
						let Some(from) = self.provenance.get(idx.get()) else {
							continue;
						};
						if from.contains(&0) {
							continue;
						}
						if let Some(best) = from
							.iter()
							.copied()
							.min_by_key(|&n| self.nodes[n as usize].installs.len())
							.map(|n| n as usize) && !chosen.contains(&best)
						{
							chosen.push(best);
						}
					}
				}
			}
		}
		Some(chosen)
	}

	fn receivers(&self, slot: usize) -> Vec<usize> {
		let program = self.cx.program;
		let mut out = Vec::new();
		for delivery in &program.deliveries {
			if delivery
				.slots
				.iter()
				.any(|&(s, guarded)| s == slot && !guarded)
				&& !out.contains(&delivery.recipient)
			{
				out.push(delivery.recipient);
			}
		}
		out
	}

	fn targets(&self, r: usize, slot: usize, addressed: bool) -> Vec<usize> {
		let receivers = self.receivers(slot);
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
			return receivers;
		}
		upstream
	}

	fn try_flight(
		&mut self,
		r: usize,
		attacker: &AttackerState,
		signature: Vec<(usize, Value)>,
		addressed: bool,
		chained: &[Value],
	) -> Option<usize> {
		let bases = self.bases(attacker, &signature, chained)?;
		let km = self.cx.km;
		let bound = self.ctx.term_bound(km);
		let mut installs: Installs = Vec::new();
		let mut shared: Installs = Vec::new();
		for (slot, value) in signature {
			for run in self.targets(r, slot, addressed) {
				let id = self.cx.program.runs[run].id;
				if !bound.admits_at(km, id, slot, &value) {
					self.ctx.note_truncation(Truncation::TermDepth);
					return None;
				}
				installs.push((run, slot, value.clone()));
			}
			if addressed {
				continue;
			}
			for run in self.receivers(slot) {
				if install_at(&installs, run, slot).is_some() {
					continue;
				}
				let id = self.cx.program.runs[run].id;
				let consumed = km.constant_used_by(id, &km.slots[slot].constant)
					|| km.slots[slot]
						.sent_by
						.iter()
						.any(|event| event.sender == id && event.guarded);
				if consumed && bound.admits_at(km, id, slot, &value) {
					shared.push((run, slot, value.clone()));
				}
			}
		}
		let everywhere = (!shared.is_empty()).then(|| {
			let mut everywhere = installs.clone();
			everywhere.extend(shared);
			everywhere
		});
		let merged = self.merged(&bases, installs);
		let halts = self.consider(merged);
		self.drain_drops();
		if let Some(everywhere) = everywhere
			&& !self.done()
		{
			let merged = self.merged(&bases, everywhere);
			self.probe(merged);
		}
		halts.and_then(|halts| halts[r])
	}

	fn drain_drops(&mut self) {
		while let Some(installs) = self.drops.pop() {
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
				self.as_family("drop", |search| search.consider_derived(fewer));
			}
		}
	}

	fn sibling_slot(&self, slot: usize, r: usize) -> Option<usize> {
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

	fn transfer(&mut self, node: usize) {
		let km = self.cx.km;
		let program = self.cx.program;
		let installs = self.nodes[node].installs.clone();
		let runs = runs_of(&installs);
		let mut plans: Vec<Installs> = Vec::new();
		for &q in &runs {
			for r in 0..program.runs.len() {
				if r == q
					|| runs.contains(&r)
					|| !km.same_actor(program.runs[r].id, program.runs[q].id)
				{
					continue;
				}
				let mut plan: Installs = installs
					.iter()
					.filter(|(run, _, _)| *run != q)
					.cloned()
					.collect();
				let mut complete = true;
				for (run, slot, value) in &installs {
					if *run != q {
						continue;
					}
					match self.sibling_slot(*slot, r) {
						Some(mapped) => plan.push((r, mapped, value.clone())),
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
		self.consider_all("merge", plans);
	}

	fn fresh_emissions(&self, node: usize) -> Vec<(Value, Source)> {
		let root = &self.nodes[0].ex;
		let ex = &self.nodes[node].ex;
		let mut out: Vec<(Value, Source)> = Vec::new();
		for (d, delivery) in self.cx.program.deliveries.iter().enumerate() {
			let Some(sent) = &ex.sent[d] else {
				continue;
			};
			for (k, v) in sent.iter().enumerate() {
				let honest = root.sent[d].as_ref().map(|values| &values[k]);
				if honest.is_some_and(|h| h.equivalent(v, true)) {
					continue;
				}
				if !out
					.iter()
					.any(|(w, source)| source.run == delivery.sender && w.equivalent(v, true))
				{
					let source = Source {
						node,
						run: delivery.sender,
						slot: delivery.slots[k].0,
					};
					out.push((v.clone(), source));
				}
			}
		}
		out
	}

	fn note_fresh(&mut self, node: usize) -> bool {
		let touched = runs_of(&self.nodes[node].installs);
		let mut added = false;
		for (v, source) in self.fresh_emissions(node) {
			let bucket = self.fresh.entry(v.hash_value()).or_default();
			if bucket.iter().any(|(w, held)| {
				held.run == source.run
					&& w.equivalent(&v, true)
					&& runs_of(&self.nodes[held.node].installs) == touched
			}) {
				continue;
			}
			bucket.push((v, source));
			added = true;
		}
		added
	}

	fn fresh_sources(&self, v: &Value) -> Vec<Source> {
		self.fresh
			.get(&v.hash_value())
			.into_iter()
			.flatten()
			.filter(|(w, _)| w.equivalent(v, true))
			.map(|(_, source)| *source)
			.collect()
	}

	fn cone(&self, run: usize, slot: usize, out: &mut Vec<(usize, usize)>) {
		if out.contains(&(run, slot)) {
			return;
		}
		out.push((run, slot));
		let program = self.cx.program;
		let km = self.cx.km;
		let Some(&step) = program.runs[run].step_of_slot.get(&slot) else {
			return;
		};
		match program.runs[run].steps[step].event {
			Event::Recv(d) => self.cone(program.deliveries[d].sender, slot, out),
			Event::Assign(_) => {
				for leaf in km.slots[slot].initial_value.constant_leaves() {
					if let Some(at) = km.index_of(leaf) {
						self.cone(run, at, out);
					}
				}
			}
			_ => {}
		}
	}

	fn cleared(
		&self,
		plan: &Installs,
		stuck: &[(usize, usize)],
		source: Source,
	) -> Option<Installs> {
		let mut cone = Vec::new();
		self.cone(source.run, source.slot, &mut cone);
		let source = &self.nodes[source.node];
		let kept: Installs = plan
			.iter()
			.filter(|(r, s, v)| {
				stuck.contains(&(*r, *s))
					|| !cone.contains(&(*r, *s))
					|| install_at(&source.installs, *r, *s).is_some()
					|| source.ex.runs[*r]
						.held(*s)
						.is_none_or(|h| h.value.equivalent(v, true))
			})
			.cloned()
			.collect();
		(kept.len() < plan.len()).then_some(kept)
	}

	fn retry_stuck(&mut self, at: usize) {
		let Stuck {
			installs,
			slots,
			tried_with,
		} = self.stuck[at].clone();
		let mut sources: Vec<Source> = Vec::new();
		for (run, slot, value) in &installs {
			if !slots.contains(&(*run, *slot)) {
				continue;
			}
			for source in self.fresh_sources(value) {
				let n = source.node;
				if n != 0
					&& !sources.iter().any(|s| s.node == n)
					&& !tried_with.contains(&n)
					&& self.compatible(&installs, n)
				{
					sources.push(source);
				}
			}
		}
		self.stuck[at]
			.tried_with
			.extend(sources.iter().map(|s| s.node));
		for source in sources {
			if self.done() {
				return;
			}
			let plan = self.merged(&[source.node], installs.clone());
			let cleared = self.cleared(&plan, &slots, source);
			let settled = !same_installs(&plan, &installs)
				&& self
					.as_family("stuck", |search| search.consider_derived(plan))
					.is_some();
			if !settled && let Some(cleared) = cleared {
				self.as_family("cleared", |search| search.consider_derived(cleared));
			}
		}
	}

	fn retry_all_stuck(&mut self) {
		let mut at = 0;
		while at < self.stuck.len() {
			self.retry_stuck(at);
			at += 1;
		}
	}

	fn as_family<T>(&mut self, family: &'static str, f: impl FnOnce(&mut Self) -> T) -> T {
		let outer = std::mem::replace(&mut self.family, family);
		let out = f(self);
		self.family = outer;
		out
	}

	fn consider_all(&mut self, family: &'static str, plans: Vec<Installs>) {
		for plan in plans {
			if self.done() {
				break;
			}
			self.as_family(family, |search| search.consider(plan));
		}
	}

	fn execute_counted(&mut self, installs: &Installs) -> Execution {
		self.executed += 1;
		self.ctx.analysis_count_increment();
		let executed = self.executed;
		let ctx = self.ctx;
		crate::info::info_status_update(|| {
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

	fn consider(&mut self, installs: Installs) -> Option<Vec<Option<usize>>> {
		if !self.tried.insert(&installs) {
			return None;
		}
		let ex = self.execute_counted(&installs);
		let halts = halts_of(&ex);
		let fills = self.fills(&ex);
		self.settle(installs.clone(), ex);
		if !fills.is_empty() && !self.done() {
			let mut filled = installs;
			filled.extend(fills);
			let filled = normalize(filled);
			if let Some(settled) = self.as_family("fill", |search| search.consider_derived(filled))
			{
				return Some(settled.halts);
			}
		}
		Some(halts)
	}

	fn consider_derived(&mut self, installs: Installs) -> Option<Settled> {
		if !self.tried.insert(&installs) {
			return None;
		}
		let ex = self.execute_counted(&installs);
		if self.debug {
			let halted: Vec<String> = ex
				.runs
				.iter()
				.enumerate()
				.filter_map(|(r, run)| {
					run.halted.map(|slot| {
						format!(
							"{}@{}",
							self.cx.program.runs[r].name,
							self.cx
								.km
								.slots
								.get(slot)
								.map(|s| s.constant.to_string())
								.unwrap_or_default()
						)
					})
				})
				.collect();
			eprintln!(
				"[search]   derived {} [{}] stuck={} halted=[{}]",
				self.family,
				self.shown(&installs),
				ex.stuck.len(),
				halted.join(" ")
			);
		}
		if !ex.stuck.is_empty() {
			return None;
		}
		let halts = halts_of(&ex);
		let accepted = self.settle(installs, ex);
		Some(Settled { accepted, halts })
	}

	fn fills(&self, ex: &Execution) -> Installs {
		let honest = &self.nodes[0].ex;
		let obtains = |v: &Value| obtainable(v, &self.cx.km.capabilities, &ex.knowledge.state);
		let mut fills: Installs = ex
			.withheld
			.iter()
			.map(|&(run, slot)| {
				let value = honest.runs[run]
					.held(slot)
					.map(|h| h.value.clone())
					.filter(|v| obtains(v))
					.unwrap_or_else(crate::value::value_nil);
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
					if guarded || held.installed {
						continue;
					}
					let Some(value) = honest.runs[b].held(slot).map(|h| &h.value) else {
						continue;
					};
					if value.equivalent(&held.value, true) || !obtains(value) {
						continue;
					}
					fills.push((b, slot, value.clone()));
				}
			}
		}
		fills
	}

	fn probe(&mut self, installs: Installs) {
		let installs = normalize(installs);
		if !self.probed.insert(&installs) {
			return;
		}
		let ex = self.execute_counted(&installs);
		self.tally("shared", false);
		if self.debug {
			eprintln!(
				"[search]   probe [{}] stuck={}",
				self.shown(&installs),
				ex.stuck.len()
			);
		}
		if ex.stuck.is_empty() {
			super::judge(self.ctx, self.cx, &ex, &installs, &self.nodes[0].ex);
		}
	}

	fn shown(&self, installs: &Installs) -> String {
		installs
			.iter()
			.map(|(run, slot, v)| {
				format!(
					"{}.{}={}",
					self.cx.program.runs[*run].name, self.cx.km.slots[*slot].constant, v
				)
			})
			.collect::<Vec<String>>()
			.join(" ")
	}

	fn tally(&mut self, family: &'static str, accepted: bool) {
		let at = match self.stats.iter().position(|(seen, _, _)| *seen == family) {
			Some(at) => at,
			None => {
				self.stats.push((family, 0, 0));
				self.stats.len() - 1
			}
		};
		self.stats[at].1 += 1;
		self.stats[at].2 += usize::from(accepted);
	}

	pub(crate) fn report_stats(&self) {
		if !self.debug {
			return;
		}
		for (family, tried, accepted) in &self.stats {
			eprintln!("[search] family {family}: tried {tried}, accepted {accepted}");
		}
	}

	fn settle(&mut self, installs: Installs, ex: Execution) -> bool {
		let accepted = self.accept(installs, ex);
		self.tally(self.family, accepted);
		accepted
	}

	fn accept(&mut self, installs: Installs, ex: Execution) -> bool {
		if self.debug {
			eprintln!(
				"[search]   try [{}] stuck={} known={}",
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
			let unchanged = admitted.len() == installs.len();
			self.stuck.push(Stuck {
				installs,
				slots: ex.stuck,
				tried_with: Vec::new(),
			});
			self.retry_stuck(self.stuck.len() - 1);
			if admitted.is_empty() || unchanged {
				return false;
			}
			return self
				.as_family("admitted", |search| search.consider_derived(admitted))
				.is_some_and(|settled| settled.accepted);
		}
		let honest = &self.nodes[0].ex;
		super::judge(self.ctx, self.cx, &ex, &installs, honest);
		let novel = self.novel_terms(&ex);
		let reuse = ex
			.knowledge
			.state
			.reused
			.iter()
			.any(|pair| !self.union.has_reused(pair));
		if novel.is_empty() && !reuse {
			let alternative = ex.knowledge.state.known.iter().any(|v| {
				self.union
					.knows(v)
					.is_some_and(|i| !self.provenance[i].contains(&0))
			});
			self.nodes.push(Node { installs, ex });
			let at = self.nodes.len() - 1;
			if self.note_fresh(at) || alternative {
				self.absorb(at, Vec::new());
			} else {
				self.nodes.pop();
			}
			return false;
		}
		if self.family != "drop" && runs_of(&installs).len() == 1 && installs.len() > 1 {
			self.drops.push(installs.clone());
		}
		self.nodes.push(Node { installs, ex });
		let at = self.nodes.len() - 1;
		self.note_fresh(at);
		self.absorb(at, novel);
		self.transfer(at);
		true
	}
}

fn halts_of(ex: &Execution) -> Vec<Option<usize>> {
	ex.runs.iter().map(|run| run.halted).collect()
}
