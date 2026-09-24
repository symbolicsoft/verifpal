/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::exec::{Context, Execution, Installs, execute};
use super::knowledge::{Knowledge, Origin};
use crate::context::VerifyContext;
use crate::solve::deduce::Deducer;
use crate::solve::symbolic;
use crate::solve::vars::{self, Substitution};
use crate::solve::{Pass, propose};
use crate::types::*;

pub(crate) struct Node {
	pub(crate) installs: Installs,
	pub(crate) ex: Execution,
}

pub(crate) struct Search<'a, 'b> {
	pub(crate) ctx: &'a VerifyContext,
	pub(crate) cx: &'a Context<'b>,
	pub(crate) states: &'a [PrincipalState],
	pub(crate) nodes: Vec<Node>,
	pub(crate) union: Knowledge,
	provenance: Vec<Vec<u32>>,
	closed: Knowledge,
	closed_provenance: Vec<Vec<u32>>,
	tried: IdMap<u64, Vec<Installs>>,
	protocol_seen: IdMap<u64, Vec<(Value, Value)>>,
	stuck: Vec<Stuck>,
	fresh: IdMap<u64, Vec<(Value, usize, usize, usize)>>,
	merged_targets: Vec<u64>,
	drops: Vec<Installs>,
	executed: usize,
	current: usize,
	pub(crate) debug: bool,
	family: &'static str,
	stats: IdMap<u64, (&'static str, usize, usize)>,
}

type Stuck = (Installs, Vec<(usize, usize)>, Vec<usize>);

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
	pub(crate) fn new(
		ctx: &'a VerifyContext,
		cx: &'a Context<'b>,
		states: &'a [PrincipalState],
		root: Execution,
	) -> Self {
		let mut union = Knowledge::new(cx.program.max_phase);
		let mut provenance = Vec::new();
		for v in root.knowledge.state.known.iter() {
			if union.learn(v, Origin::Initial) {
				provenance.push(vec![0]);
			}
		}
		let mut search = Search {
			ctx,
			cx,
			states,
			nodes: vec![Node {
				installs: Vec::new(),
				ex: root,
			}],
			closed: union.clone(),
			closed_provenance: provenance.clone(),
			union,
			provenance,
			tried: IdMap::default(),
			protocol_seen: IdMap::default(),
			stuck: Vec::new(),
			fresh: IdMap::default(),
			merged_targets: Vec::new(),
			drops: Vec::new(),
			executed: 0,
			current: 0,
			debug: std::env::var("VERIFPAL_SOLVE_DEBUG").is_ok(),
			family: "base",
			stats: IdMap::default(),
		};
		search.absorb_reuse(0);
		let protocol: Vec<(Value, Value, bool)> = search.nodes[0].ex.knowledge.protocol.to_vec();
		for (value, pre, own) in protocol {
			search.note_union_protocol(value, pre, own);
		}
		let built = Arc::clone(&search.nodes[0].ex.knowledge.built);
		for term in built.values().flatten() {
			search.union.note_built(term);
		}
		search.close_union();
		search
	}

	fn done(&self) -> bool {
		self.ctx.all_resolved() || self.ctx.cancelled()
	}

	fn absorb_reuse(&mut self, node: usize) {
		let pairs: Vec<[Value; 2]> = self.nodes[node].ex.knowledge.state.reused.to_vec();
		for pair in pairs {
			if !self.union.state.reused.iter().any(|held| {
				held[0].equivalent(&pair[0], true) && held[1].equivalent(&pair[1], true)
			}) {
				let state = Arc::make_mut(&mut self.union.state);
				Arc::make_mut(&mut state.reused).push(pair);
				state.chain = next_chain();
			}
		}
	}

	fn novel_terms(&self, ex: &Execution) -> Vec<Value> {
		let carrier = self.cx.carrier;
		let union = &self.union.state;
		let _memo = crate::theory::DeductionMemo::scoped(carrier, union);
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
					super::knowledge::Origin::Wire { .. } | super::knowledge::Origin::Leak { .. }
				);
				union.knows(v).is_none()
					&& ((emitted && produced(v) && crate::solve::control::term_depth(v) <= depth)
						|| !crate::theory::obtainable(v, carrier, union))
			})
			.map(|(_, v)| v.clone())
			.collect()
	}

	fn absorb(&mut self, node: usize, novel: Vec<Value>) {
		let known: Vec<Value> = self.nodes[node].ex.knowledge.state.known.to_vec();
		for v in known {
			if let Some(i) = self.union.knows(&v)
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
		let protocol: Vec<(Value, Value, bool)> = self.nodes[node].ex.knowledge.protocol.to_vec();
		for (value, pre, own) in protocol {
			self.note_union_protocol(value, pre, own);
		}
		let built = Arc::clone(&self.nodes[node].ex.knowledge.built);
		for term in built.values().flatten() {
			self.union.note_built(term);
		}
		self.absorb_reuse(node);
	}

	fn note_union_protocol(&mut self, value: Value, pre: Value, own: bool) {
		let key = value.hash_value() ^ pre.hash_value().rotate_left(7);
		let bucket = self.protocol_seen.entry(key).or_default();
		if bucket
			.iter()
			.any(|(v, p)| v.equivalent(&value, true) && p.equivalent(&pre, true))
		{
			return;
		}
		bucket.push((value.clone(), pre.clone()));
		self.union.note_protocol(&value, &pre, own);
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
		self.closed.close(self.cx.carrier);
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
				if !plan
					.iter()
					.any(|(r, s, _)| *r == install.0 && *s == install.1)
				{
					plan.push(install.clone());
				}
			}
			out.push(best);
			return;
		}
		let Some(record) = self.closed.state.derivations.get(idx) else {
			return;
		};
		let mut next: Vec<usize> = Vec::new();
		for ingredient in record.ingredients() {
			if let Some(i) = self.closed.knows(ingredient) {
				next.push(i);
			}
		}
		if let DerivationRecord::Decomposed { using, .. }
		| DerivationRecord::Recomposed { using, .. }
		| DerivationRecord::Rewritten { using, .. } = record
		{
			for u in using {
				if let Some(i) = self.closed.knows(u) {
					next.push(i);
				}
			}
		}
		for i in next {
			self.leaves(i, plan, out, seen);
		}
	}

	fn merged(&self, extra: &[usize], installs: Installs) -> Installs {
		let mut installs = installs;
		let touched: Vec<usize> = installs.iter().map(|(run, _, _)| *run).collect();
		for &base in extra {
			for (run, slot, value) in &self.nodes[base].installs {
				if touched.contains(run)
					|| installs.iter().any(|(r2, s2, _)| r2 == run && s2 == slot)
				{
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
		for plan in plans {
			if self.done() {
				break;
			}
			let family = std::mem::replace(&mut self.family, "merge");
			self.consider(plan);
			self.family = family;
		}
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
					self.tried.values().map(Vec::len).sum::<usize>(),
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
		let ps = &self.states[r];
		let attacker: AttackerState = (*self.union.state).clone();
		let controllable = crate::solve::control::Controllable::of(km, ps, &attacker);
		if !(0..ps.values.len()).any(|slot| controllable.admits(ps, &attacker, slot)) {
			return Vec::new();
		}
		let sym = symbolic::build(&controllable, ps, &attacker);
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
				let refined =
					symbolic::build_assuming_honest(&controllable, ps, &attacker, &honest);
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
		let shared: Vec<usize> = sym
			.var_slots
			.iter()
			.copied()
			.filter(|&slot| !crate::solve::directly_unguarded(km, ps, slot))
			.collect();
		if !sym
			.var_slots
			.iter()
			.any(|&slot| crate::solve::split_delivered(km, ps, slot))
		{
			return replays;
		}
		let addressed = symbolic::build_addressed(&controllable, ps, &attacker, &shared);
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
		sym: &symbolic::SymbolicState,
		taken: Vec<Vec<(ValueId, Value)>>,
		addressed: bool,
	) -> Vec<Vec<(ValueId, Value)>> {
		let km = self.cx.km;
		let ps = &self.states[r];
		let honest_terms: Substitution = sym
			.var_slots
			.iter()
			.zip(crate::solve::honest_slot_terms(km, ps, sym))
			.map(|(&slot, honest)| (vars::attacker_var_id(slot), honest))
			.collect();
		let deducer = Deducer::with_basis(
			ps,
			attacker,
			sym,
			self.ctx.known_subterms(attacker),
			honest_terms,
		);
		let truncated = deducer.truncation_flag();
		let (proposals, replays) = propose(self.ctx, km, ps, pass, attacker, sym, deducer, taken);
		if truncated.load(std::sync::atomic::Ordering::Relaxed) {
			self.ctx.note_truncation(Truncation::SolverVariables);
		}
		let mut signatures: Vec<Candidate> = Vec::new();
		let mut buckets: IdMap<u64, Vec<usize>> = IdMap::default();
		for proposal in vars::dedupe(proposals) {
			let unpinned = crate::solve::leave_honest_slots(km, ps, sym, proposal.clone());
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
				let chained = if crate::solve::emits_an_install(ps, sym, &variant, &signature) {
					crate::solve::emissions_under(ps, sym, &variant)
				} else {
					Vec::new()
				};
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
				ps.name,
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
			let halts = self.try_flight(r, attacker, signature, addressed, &chained);
			let mut halted = halts.get(r).copied().flatten();
			let mut binding = variant;
			while let Some(check) = halted {
				let Some(Value::Primitive(p)) = sym.terms.get(check) else {
					break;
				};
				if !vars::contains_var(&Value::Primitive(p.clone())) {
					break;
				}
				let deducer = repairer.get_or_insert_with(|| {
					let honest_terms: Substitution = sym
						.var_slots
						.iter()
						.zip(crate::solve::honest_slot_terms(km, ps, sym))
						.map(|(&slot, honest)| (vars::attacker_var_id(slot), honest))
						.collect();
					Deducer::with_basis(
						ps,
						attacker,
						sym,
						self.ctx.known_subterms(attacker),
						honest_terms,
					)
				});
				let started = self.debug.then(std::time::Instant::now);
				let solutions = deducer.repair_check(p, &binding);
				if let Some(started) = started {
					eprintln!(
						"[search] repair {} at {} -> {} solutions in {:?}",
						ps.name,
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
					let family = std::mem::replace(&mut self.family, "repair");
					let emitted = crate::solve::emissions_under(ps, sym, &solution);
					let halts = self.try_flight(r, attacker, signature, addressed, &emitted);
					self.family = family;
					match halts.get(r).copied().flatten() {
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

	fn derivable_in(&self, node: usize, v: &Value) -> bool {
		let state = &self.nodes[node].ex.knowledge.state;
		state.knows(v).is_some() || crate::theory::obtainable(v, self.cx.carrier, state)
	}

	fn bases(
		&self,
		attacker: &AttackerState,
		signature: &[(usize, Value)],
		chained: &[Value],
	) -> Option<Vec<usize>> {
		let carrier = self.cx.carrier;
		let mut inputs = crate::theory::KnowledgeInputs::new(carrier, attacker);
		let mut chosen: Vec<usize> = Vec::new();
		for (_, value) in signature {
			if self.derivable_in(0, value) || chosen.iter().any(|&n| self.derivable_in(n, value)) {
				continue;
			}
			let Some(used) = inputs.of_value(value) else {
				let reduced = crate::theory::reduce_once(value);
				if chained
					.iter()
					.any(|emitted| emitted.equivalent(&reduced, true))
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
		receivers
	}

	fn try_flight(
		&mut self,
		r: usize,
		attacker: &AttackerState,
		signature: Vec<(usize, Value)>,
		addressed: bool,
		chained: &[Value],
	) -> Vec<Option<usize>> {
		let Some(bases) = self.bases(attacker, &signature, chained) else {
			return Vec::new();
		};
		let km = self.cx.km;
		let bound = self.ctx.term_bound(km);
		let mut installs: Installs = Vec::new();
		for (slot, value) in signature {
			for run in self.targets(r, slot, addressed) {
				let id = self.cx.program.runs[run].id;
				if !bound.admits_at(km, id, slot, &value) {
					self.ctx.note_depth_cut(id, slot);
					return Vec::new();
				}
				installs.push((run, slot, value.clone()));
			}
		}
		let merged = self.merged(&bases, installs);
		let halts = self.consider_halts(merged).1;
		self.drain_drops();
		halts
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
				let family = std::mem::replace(&mut self.family, "drop");
				self.consider_derived(fewer);
				self.family = family;
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
		let mut runs: Vec<usize> = installs.iter().map(|(run, _, _)| *run).collect();
		runs.dedup();
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
		for plan in plans {
			if self.done() {
				break;
			}
			let family = std::mem::replace(&mut self.family, "merge");
			self.consider(plan);
			self.family = family;
		}
	}

	fn fresh_emissions(&self, ex: &Execution) -> Vec<(Value, usize, usize)> {
		let root = &self.nodes[0].ex;
		let mut out: Vec<(Value, usize, usize)> = Vec::new();
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
					.any(|(w, run, _)| *run == delivery.sender && w.equivalent(v, true))
				{
					out.push((v.clone(), delivery.sender, delivery.slots[k].0));
				}
			}
		}
		out
	}

	fn note_fresh(&mut self, node: usize) -> bool {
		let emissions = self.fresh_emissions(&self.nodes[node].ex);
		let touched = runs_of(&self.nodes[node].installs);
		let mut added = false;
		for (v, run, slot) in emissions {
			let bucket = self.fresh.entry(v.hash_value()).or_default();
			if bucket.iter().any(|(w, r, _, n)| {
				*r == run && w.equivalent(&v, true) && runs_of(&self.nodes[*n].installs) == touched
			}) {
				continue;
			}
			bucket.push((v, run, slot, node));
			added = true;
		}
		added
	}

	fn fresh_sources(&self, v: &Value) -> Vec<(usize, usize, usize)> {
		self.fresh
			.get(&v.hash_value())
			.map(|bucket| {
				bucket
					.iter()
					.filter(|(w, _, _, _)| w.equivalent(v, true))
					.map(|(_, run, slot, node)| (*node, *run, *slot))
					.collect()
			})
			.unwrap_or_default()
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
			super::program::Event::Recv(d) => self.cone(program.deliveries[d].sender, slot, out),
			super::program::Event::Assign(_) => {
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
		(node, run, slot): (usize, usize, usize),
	) -> Option<Installs> {
		let mut cone = Vec::new();
		self.cone(run, slot, &mut cone);
		let source = &self.nodes[node];
		let kept: Installs = plan
			.iter()
			.filter(|(r, s, v)| {
				stuck.contains(&(*r, *s))
					|| !cone.contains(&(*r, *s))
					|| source.installs.iter().any(|(r2, s2, _)| r2 == r && s2 == s)
					|| source.ex.runs[*r]
						.held(*s)
						.is_none_or(|h| h.value.equivalent(v, true))
			})
			.cloned()
			.collect();
		(kept.len() < plan.len()).then_some(kept)
	}

	fn retry_stuck(&mut self, at: usize) {
		let (installs, stuck, tried) = self.stuck[at].clone();
		let mut sources: Vec<(usize, usize, usize)> = Vec::new();
		for (run, slot, value) in &installs {
			if !stuck.contains(&(*run, *slot)) {
				continue;
			}
			for source in self.fresh_sources(value) {
				let n = source.0;
				if n != 0
					&& !sources.iter().any(|s| s.0 == n)
					&& !tried.contains(&n)
					&& self.compatible(&installs, n)
				{
					sources.push(source);
				}
			}
		}
		self.stuck[at].2.extend(sources.iter().map(|s| s.0));
		for source in sources {
			if self.done() {
				return;
			}
			let plan = self.merged(&[source.0], installs.clone());
			let cleared = self.cleared(&plan, &stuck, source);
			let family = std::mem::replace(&mut self.family, "stuck");
			let settled =
				!same_installs(&plan, &installs) && !self.consider_derived_halts(plan).1.is_empty();
			if !settled && let Some(cleared) = cleared {
				self.family = "cleared";
				self.consider_derived(cleared);
			}
			self.family = family;
		}
	}

	fn retry_all_stuck(&mut self) {
		let mut at = 0;
		while at < self.stuck.len() {
			self.retry_stuck(at);
			at += 1;
		}
	}

	pub(crate) fn consider(&mut self, installs: Installs) -> Option<usize> {
		self.consider_halts(installs).0
	}

	fn consider_derived(&mut self, installs: Installs) -> Option<usize> {
		self.consider_derived_halts(installs).0
	}

	fn execute_counted(&mut self, installs: &Installs) -> Execution {
		self.executed += 1;
		self.ctx.analysis_count_increment();
		let executed = self.executed;
		let ctx = self.ctx;
		crate::info::info_status_update(|| {
			crate::verify::status_line(
				ctx,
				self.cx.program.max_phase,
				&self.cx.program.runs[self.current].name,
				&format!(
					"{executed} execution{} checked",
					if executed == 1 { "" } else { "s" }
				),
			)
		});
		execute(self.cx, installs)
	}

	fn consider_derived_halts(
		&mut self,
		installs: Installs,
	) -> (Option<usize>, Vec<Option<usize>>) {
		let key = installs_hash(&installs);
		let bucket = self.tried.entry(key).or_default();
		if bucket.iter().any(|seen| same_installs(seen, &installs)) {
			return (None, Vec::new());
		}
		bucket.push(installs.clone());
		let ex = self.execute_counted(&installs);
		if self.debug {
			let shown: Vec<String> = installs
				.iter()
				.map(|(run, slot, v)| {
					format!(
						"{}.{}={}",
						self.cx.program.runs[*run].name, self.cx.km.slots[*slot].constant, v
					)
				})
				.collect();
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
				shown.join(" "),
				ex.stuck.len(),
				halted.join(" ")
			);
		}
		if !ex.stuck.is_empty() {
			return (None, Vec::new());
		}
		let halts: Vec<Option<usize>> = ex.runs.iter().map(|run| run.halted).collect();
		(self.settle(installs, ex), halts)
	}

	fn consider_halts(&mut self, installs: Installs) -> (Option<usize>, Vec<Option<usize>>) {
		let key = installs_hash(&installs);
		let bucket = self.tried.entry(key).or_default();
		if bucket.iter().any(|seen| same_installs(seen, &installs)) {
			return (None, Vec::new());
		}
		bucket.push(installs.clone());
		let ex = self.execute_counted(&installs);
		let halts: Vec<Option<usize>> = ex.runs.iter().map(|run| run.halted).collect();
		let mut fills: Installs = Vec::new();
		for &(run, slot) in &ex.withheld {
			let honest = self.nodes[0].ex.runs[run]
				.held(slot)
				.map(|h| h.value.clone());
			let value = honest
				.filter(|v| {
					ex.knowledge.knows(v).is_some()
						|| crate::theory::obtainable(v, self.cx.carrier, &ex.knowledge.state)
				})
				.unwrap_or_else(crate::value::value_nil);
			fills.push((run, slot, value));
		}
		let accepted = self.settle(installs.clone(), ex);
		if !fills.is_empty() && !self.done() {
			let mut filled = installs;
			filled.extend(fills);
			let filled = normalize(filled);
			let family = std::mem::replace(&mut self.family, "fill");
			let (filled_accepted, filled_halts) = self.consider_derived_halts(filled);
			self.family = family;
			if !filled_halts.is_empty() {
				return (accepted.or(filled_accepted), filled_halts);
			}
		}
		(accepted, halts)
	}

	fn tally(&mut self, accepted: bool) {
		let key = self.family.as_ptr() as u64;
		let entry = self.stats.entry(key).or_insert((self.family, 0, 0));
		entry.1 += 1;
		if accepted {
			entry.2 += 1;
		}
	}

	pub(crate) fn report_stats(&self) {
		if !self.debug {
			return;
		}
		for (family, tried, accepted) in self.stats.values() {
			eprintln!("[search] family {family}: tried {tried}, accepted {accepted}");
		}
	}

	fn settle(&mut self, installs: Installs, ex: Execution) -> Option<usize> {
		let accepted = self.settle_inner(installs, ex);
		self.tally(accepted.is_some());
		accepted
	}

	fn settle_inner(&mut self, installs: Installs, ex: Execution) -> Option<usize> {
		if self.debug {
			let shown: Vec<String> = installs
				.iter()
				.map(|(run, slot, v)| {
					format!(
						"{}.{}={}",
						self.cx.program.runs[*run].name, self.cx.km.slots[*slot].constant.name, v
					)
				})
				.collect();
			eprintln!(
				"[search]   try [{}] stuck={} known={}",
				shown.join(" "),
				ex.stuck.len(),
				ex.knowledge.len()
			);
		}
		if !ex.stuck.is_empty() {
			self.stuck
				.push((installs.clone(), ex.stuck.clone(), Vec::new()));
			let at = self.stuck.len() - 1;
			self.retry_stuck(at);
			let admitted: Installs = installs
				.iter()
				.filter(|(run, slot, _)| !ex.stuck.contains(&(*run, *slot)))
				.cloned()
				.collect();
			if admitted.is_empty() || admitted.len() == installs.len() {
				return None;
			}
			let family = std::mem::replace(&mut self.family, "admitted");
			let out = self.consider_derived(admitted);
			self.family = family;
			return out;
		}
		let honest = &self.nodes[0].ex;
		super::judge(self.ctx, self.cx, &ex, &installs, honest, self.states);
		let novel = self.novel_terms(&ex);
		let reuse = ex.knowledge.state.reused.iter().any(|pair| {
			!self.union.state.reused.iter().any(|held| {
				held[0].equivalent(&pair[0], true) && held[1].equivalent(&pair[1], true)
			})
		});
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
			return None;
		}
		let mut runs: Vec<usize> = installs.iter().map(|(run, _, _)| *run).collect();
		runs.dedup();
		if self.family != "drop" && runs.len() == 1 && installs.len() > 1 {
			self.drops.push(installs.clone());
		}
		self.nodes.push(Node { installs, ex });
		let at = self.nodes.len() - 1;
		self.note_fresh(at);
		self.absorb(at, novel);
		self.transfer(at);
		Some(at)
	}
}
