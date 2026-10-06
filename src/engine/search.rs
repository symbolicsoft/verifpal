/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::exec::{Context, Execution, Installs, UNSTARTED, execute, install_at};
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
	held: Vec<Vec<HeldValue>>,
	sent: Vec<Option<Vec<Value>>>,
	knowledge: Vec<Arc<AttackerState>>,
	memo: std::cell::RefCell<crate::theory::SavedMemo>,
}

struct HeldValue {
	slot: usize,
	value: Value,
	received: bool,
}

impl Node {
	fn of(installs: Installs, ex: &Execution, queried: &IdSet<usize>) -> Self {
		Self {
			installs,
			held: ex
				.runs
				.iter()
				.map(|run| {
					run.env
						.iter()
						.enumerate()
						.filter_map(|(slot, held)| {
							let held = held.as_ref()?;
							(held.sender.is_some() || queried.contains(&slot)).then(|| HeldValue {
								slot,
								value: crate::hashing::hashcons(&held.value),
								received: held.sender.is_some(),
							})
						})
						.collect()
				})
				.collect(),
			sent: ex
				.sent
				.iter()
				.map(|sent| {
					sent.as_ref()
						.map(|values| values.iter().map(crate::hashing::hashcons).collect())
				})
				.collect(),
			knowledge: ex
				.barriers
				.iter()
				.chain(std::iter::once(ex))
				.map(|phase| {
					let state = &phase.knowledge.state;
					Arc::new(AttackerState {
						current_phase: state.current_phase,
						known: Arc::clone(&state.known),
						known_map: Arc::clone(&state.known_map),
						derivations: Arc::default(),
						reused: Arc::clone(&state.reused),
						chain: next_chain(),
					})
				})
				.collect(),
			memo: std::cell::RefCell::default(),
		}
	}

	fn held(&self, run: usize, slot: usize) -> Option<&HeldValue> {
		let values = &self.held[run];
		values
			.binary_search_by_key(&slot, |held| held.slot)
			.ok()
			.map(|at| &values[at])
	}

	fn state(&self) -> &AttackerState {
		self.knowledge.last().unwrap()
	}

	fn at(&self, phase: i32) -> &AttackerState {
		usize::try_from(phase)
			.ok()
			.and_then(|phase| self.knowledge.get(phase))
			.map_or_else(|| self.state(), AsRef::as_ref)
	}
}

pub(crate) struct Search<'a, 'b> {
	ctx: &'a VerifyContext,
	cx: &'a Context<'b>,
	relevant: Vec<usize>,
	queried: IdSet<usize>,
	honest: Execution,
	nodes: Vec<Node>,
	union: Knowledge,
	honest_known: usize,
	by_cost: Vec<Vec<Vec<usize>>>,
	closed: Knowledge,
	closed_at: (usize, usize),
	tried: Tried<Attempt>,
	pending: Vec<usize>,
	probed: Tried,
	protocol_seen: IdMap<u64, Vec<(Value, Value)>>,
	fresh: IdMap<u64, Vec<(Value, Source, Vec<usize>)>>,
	stuck: Vec<Stuck>,
	by_install: IdMap<(usize, usize, u64), Vec<usize>>,
	drops: Vec<Installs>,
	executed: usize,
	current: usize,
	debug: bool,
	family: Family,
	stats: Vec<(Family, usize, usize)>,
	receivers: Vec<Vec<usize>>,
	derivable: std::cell::RefCell<IdMap<(usize, usize), bool>>,
	cheapest: std::cell::RefCell<IdMap<usize, Cheapest>>,
	holders: IdMap<(usize, QueryKind), Holders>,
	merged_targets: IdMap<(u64, usize), Vec<Value>>,
}

struct Cheapest {
	used: Vec<usize>,
	scanned: usize,
	best: Option<usize>,
}

#[derive(Default)]
struct Holders {
	scanned: usize,
	values: Vec<(Value, usize)>,
	index: IdMap<u64, Vec<usize>>,
}

#[derive(Clone)]
struct Outcome {
	halts: Vec<(usize, usize)>,
	settled: bool,
}

struct Attempt {
	outcome: Option<Outcome>,
	family: Family,
}

#[derive(Clone, Copy)]
struct Source {
	node: usize,
	run: usize,
	slot: usize,
}

struct Stuck {
	installs: Installs,
	slots: Vec<(usize, usize)>,
	tried_with: IdSet<usize>,
	supply: Vec<(usize, usize)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
	Base,
	Repair,
	Fill,
	Drop,
	Merge,
	Stuck,
	Cleared,
	Admitted,
	Idle,
	Unshaped,
	Shared,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
	Plain,
	Refined,
	Unshaped,
}

impl Family {
	fn derived(self) -> bool {
		matches!(
			self,
			Family::Fill | Family::Stuck | Family::Cleared | Family::Admitted
		)
	}
}

struct Tried<T = ()> {
	entries: Vec<(Installs, T)>,
	index: IdMap<u64, Vec<usize>>,
}

impl<T> Default for Tried<T> {
	fn default() -> Self {
		Self {
			entries: Vec::new(),
			index: IdMap::default(),
		}
	}
}

impl<T> Tried<T> {
	#[cfg(test)]
	fn get(&self, installs: &Installs) -> Option<&T> {
		self.position(installs).map(|at| &self.entries[at].1)
	}

	fn position(&self, installs: &Installs) -> Option<usize> {
		self.index
			.get(&installs_hash(installs))?
			.iter()
			.copied()
			.find(|&at| same_installs(&self.entries[at].0, installs))
	}

	fn remember(&mut self, installs: &Installs, value: T) -> bool {
		if self.position(installs).is_some() {
			return false;
		}
		self.index
			.entry(installs_hash(installs))
			.or_default()
			.push(self.entries.len());
		self.entries.push((installs.clone(), value));
		true
	}

	fn len(&self) -> usize {
		self.entries.len()
	}
}

impl Tried {
	fn insert(&mut self, installs: &Installs) -> bool {
		self.remember(installs, ())
	}
}

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
		let queried: IdSet<_> = ctx
			.open_queries()
			.into_iter()
			.filter(|query| {
				matches!(
					query.kind,
					QueryKind::Confidentiality | QueryKind::Unlinkability
				)
			})
			.flat_map(|query| query.constants)
			.filter_map(|constant| cx.km.index_of(&constant))
			.collect();
		let mut union = Knowledge::new(cx.km.max_phase);
		let mut by_cost = Vec::new();
		for v in root.knowledge.state.known.iter() {
			if union.learn(v, Origin::Initial) {
				by_cost.push(vec![vec![0]]);
			}
		}
		let mut search = Search {
			ctx,
			cx,
			relevant: relevant_prefixes(ctx, cx),
			nodes: Vec::new(),
			queried,
			honest: root,
			closed: Knowledge::new(cx.km.max_phase),
			closed_at: (0, 0),
			honest_known: union.len(),
			union,
			by_cost,
			tried: Tried::default(),
			pending: Vec::new(),
			probed: Tried::default(),
			protocol_seen: IdMap::default(),
			fresh: IdMap::default(),
			stuck: Vec::new(),
			by_install: IdMap::default(),
			drops: Vec::new(),
			executed: 0,
			current: 0,
			debug: std::env::var("VERIFPAL_SOLVE_DEBUG").is_ok(),
			family: Family::Base,
			stats: Vec::new(),
			receivers: (0..cx.km.slots.len())
				.map(|slot| {
					let mut out = Vec::new();
					for delivery in &cx.program.deliveries {
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
				})
				.collect(),
			derivable: std::cell::RefCell::default(),
			cheapest: std::cell::RefCell::default(),
			holders: IdMap::default(),
			merged_targets: IdMap::default(),
		};
		let root = Node::of(Vec::new(), &search.honest, &search.queried);
		search.push_node(root);
		search.absorb_terms(&search.honest.knowledge.clone());
		search.close_union();
		search
	}

	fn done(&self) -> bool {
		self.ctx.all_resolved() || self.ctx.cancelled()
	}

	fn relevant_input(&self, run: usize, slot: usize) -> bool {
		if slot == UNSTARTED {
			return self.relevant[run] > 0;
		}
		self.cx.program.runs[run]
			.step_of_slot
			.get(&slot)
			.is_some_and(|&step| step < self.relevant[run])
	}

	fn project(&mut self, mut installs: Installs) -> Installs {
		installs.retain(|(run, slot, _)| self.relevant_input(*run, *slot));
		for (_, _, value) in &mut installs {
			*value = crate::hashing::hashcons(value);
		}
		normalize(installs)
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

	fn note_source(&mut self, i: usize, node: usize) {
		let cost = self.nodes[node].installs.len();
		let buckets = &mut self.by_cost[i];
		if buckets.len() <= cost {
			buckets.resize_with(cost + 1, Vec::new);
		}
		buckets[cost].push(node);
	}

	fn supplies(&self, idx: usize, node: usize) -> bool {
		self.by_cost[idx]
			.get(self.nodes[node].installs.len())
			.is_some_and(|bucket| bucket.binary_search(&node).is_ok())
	}

	fn absorb(&mut self, node: usize, novel: Vec<Value>, knowledge: &Knowledge) {
		for v in knowledge.state.known.iter() {
			if let Some(i) = self.union.knows(v) {
				self.note_source(i, node);
			}
		}
		for v in novel {
			if self.union.learn(&v, Origin::Initial) {
				self.by_cost.push(Vec::new());
				self.note_source(self.by_cost.len() - 1, node);
				crate::info::info_deduction(|| {
					format!(
						"{} is obtained in an execution where {}.",
						crate::info::info_output_text(&v),
						self.describe(node)
					)
				});
			}
		}
		self.absorb_terms(knowledge);
	}

	fn absorb_terms(&mut self, knowledge: &Knowledge) {
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
					self.cx.program.runs[*run].name,
					self.slot_name(*slot),
					value
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
		self.closed_at = (self.union.len(), self.nodes.len());
		self.closed.close(&self.cx.km.capabilities);
	}

	fn leaves(&self, idx: usize, out: &mut Vec<Vec<Installs>>, seen: &mut Vec<usize>) {
		if seen.contains(&idx) {
			return;
		}
		seen.push(idx);
		let (known, nodes) = self.closed_at;
		if idx < known {
			let sources: Vec<Installs> = self.by_cost[idx]
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
		let Some(record) = self.closed.state.derivations.get(idx) else {
			return;
		};
		for ingredient in record.ingredients() {
			if let Some(i) = self.closed.knows(ingredient) {
				self.leaves(i, out, seen);
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
		let mut targets: Vec<(usize, usize)> = Vec::new();
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
				for (wanted, holder) in &self.holders[&(slot, q.kind)].values {
					let Some(idx) = self.closed.knows(wanted) else {
						continue;
					};
					if idx < self.closed_at.0 {
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
			let value = &self.closed.state.known[idx];
			let key = (value.hash_value(), context);
			if self
				.merged_targets
				.get(&key)
				.is_some_and(|seen| seen.iter().any(|held: &Value| held.equivalent(value, true)))
			{
				continue;
			}
			self.merged_targets
				.entry(key)
				.or_default()
				.push(value.clone());
			let mut leaves = Vec::new();
			self.leaves(idx, &mut leaves, &mut Vec::new());
			if leaves.is_empty() {
				continue;
			}
			if self.debug {
				eprintln!(
					"[search] merge target {}: context {}, sources {:?}",
					self.closed.state.known[idx],
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

	fn index_holders(&mut self, slot: usize, kind: QueryKind) {
		let km = self.cx.km;
		let holders = self.holders.entry((slot, kind)).or_default();
		for n in holders.scanned..self.nodes.len() {
			let node = &self.nodes[n];
			for run in 0..node.held.len() {
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
		holders.scanned = self.nodes.len();
	}

	pub(crate) fn run(&mut self) {
		self.fixpoint(Mode::Plain);
		if self.done() {
			return;
		}
		let before = self.union.len();
		self.fixpoint(Mode::Refined);
		if self.union.len() != before && !self.done() {
			self.fixpoint(Mode::Plain);
		}
		self.idle();
		if !self.done() && symbolic::has_key_shaped_slot(self.cx.km) {
			self.as_family(Family::Unshaped, |search| search.fixpoint(Mode::Unshaped));
		}
	}

	fn idle(&mut self) {
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
				installs.push((*r, UNSTARTED, crate::value::value_nil()));
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

	fn fixpoint(&mut self, mode: Mode) {
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

	fn derivable_in(&self, node: usize, v: &Value) -> bool {
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
		if !crate::hashing::hashconsed(p) {
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
			Value::Primitive(p) if crate::hashing::hashconsed(p) => Some(Arc::as_ptr(p) as usize),
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

	fn try_flight(
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
					.then(|| (slot, crate::hashing::hashcons(&value), targets))
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

	fn drain(&mut self) {
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

	fn sibling_slot(&self, slot: usize, r: usize) -> Option<usize> {
		if slot == UNSTARTED {
			return Some(UNSTARTED);
		}
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
		for plan in plans.into_iter().rev() {
			if self.done() {
				break;
			}
			self.as_family(Family::Merge, |search| search.enqueue(plan));
		}
	}

	fn note_fresh(&mut self, at: usize, node: &Node) -> bool {
		let touched = runs_of(&node.installs);
		let mut added = false;
		for (d, delivery) in self.cx.program.deliveries.iter().enumerate() {
			let Some(sent) = &node.sent[d] else {
				continue;
			};
			for (k, v) in sent.iter().enumerate() {
				let honest = self.nodes[0].sent[d].as_ref().map(|values| &values[k]);
				if honest.is_some_and(|h| h.equivalent(v, true)) {
					continue;
				}
				let source = Source {
					node: at,
					run: delivery.sender,
					slot: delivery.slots[k].0,
				};
				let bucket = self.fresh.entry(v.hash_value()).or_default();
				if bucket.iter().any(|(w, held, runs)| {
					held.run == source.run && w.equivalent(v, true) && *runs == touched
				}) {
					continue;
				}
				bucket.push((v.clone(), source, touched.clone()));
				added = true;
			}
		}
		added
	}

	fn push_node(&mut self, node: Node) {
		let at = self.nodes.len();
		for (run, slot, value) in &node.installs {
			self.by_install
				.entry((*run, *slot, value.hash_value()))
				.or_default()
				.push(at);
		}
		self.nodes.push(node);
	}

	fn fresh_sources(&self, v: &Value) -> Vec<Source> {
		self.fresh
			.get(&v.hash_value())
			.into_iter()
			.flatten()
			.filter(|(w, _, _)| w.equivalent(v, true))
			.map(|(_, source, _)| *source)
			.collect()
	}

	fn cleared(
		&self,
		plan: &Installs,
		stuck: &[(usize, usize)],
		source: Source,
		cone: &[(usize, usize)],
	) -> Option<Installs> {
		let source = &self.nodes[source.node];
		let kept: Installs = plan
			.iter()
			.filter(|(r, s, v)| {
				stuck.contains(&(*r, *s))
					|| !cone.contains(&(*r, *s))
					|| install_at(&source.installs, *r, *s).is_some()
					|| source
						.held(*r, *s)
						.is_none_or(|h| h.value.equivalent(v, true))
			})
			.cloned()
			.collect();
		(kept.len() < plan.len()).then_some(kept)
	}

	fn retry_stuck(&mut self, at: usize) {
		let installs = self.stuck[at].installs.clone();
		let slots = self.stuck[at].slots.clone();
		let mut supply = std::mem::take(&mut self.stuck[at].supply);
		let tried_with = &self.stuck[at].tried_with;
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
					&& compatible_with(&installs, &self.nodes[n].installs)
				{
					sources.push(source);
				}
			}
		}
		let mut suppliers: Vec<usize> = Vec::new();
		let context: Vec<&(usize, usize, Value)> = installs
			.iter()
			.filter(|(run, slot, _)| !slots.contains(&(*run, *slot)))
			.collect();
		let rarest = context
			.iter()
			.map(|(run, slot, value)| {
				self.by_install
					.get(&(*run, *slot, value.hash_value()))
					.map_or(&[][..], Vec::as_slice)
			})
			.min_by_key(|posting| posting.len())
			.unwrap_or(&[]);
		for (install, next) in supply.iter_mut() {
			let (run, slot, value) = &installs[*install];
			let program = &self.cx.program.runs[*run];
			let phase = program
				.step_of_slot
				.get(slot)
				.map_or(0, |&step| program.steps[step].phase);
			let start = rarest.partition_point(|&n| n < *next);
			let mut found = false;
			for &n in &rarest[start..] {
				*next = n + 1;
				if sources.iter().any(|s| s.node == n)
					|| suppliers.contains(&n)
					|| tried_with.contains(&n)
				{
					continue;
				}
				let within = context.iter().all(|(run, slot, held)| {
					install_at(&self.nodes[n].installs, *run, *slot)
						.is_some_and(|v| v.equivalent(held, true))
				});
				if within
					&& compatible_with(&installs, &self.nodes[n].installs)
					&& obtainable(value, &self.cx.km.capabilities, self.nodes[n].at(phase))
				{
					suppliers.push(n);
					found = true;
					break;
				}
			}
			if !found {
				*next = self.nodes.len();
			}
		}
		self.stuck[at].supply = supply;
		self.stuck[at].tried_with.extend(
			sources
				.iter()
				.map(|s| s.node)
				.chain(suppliers.iter().copied()),
		);
		for n in suppliers {
			if self.done() {
				return;
			}
			let plan = self.merged(&[n], installs.clone());
			if !same_installs(&plan, &installs) {
				self.as_family(Family::Stuck, |search| search.consider(plan));
			}
		}
		for source in sources {
			if self.done() {
				return;
			}
			let mut plan = self.merged(&[source.node], installs.clone());
			let mut cone = Vec::new();
			self.cone(source.run, source.slot, &mut cone);
			for (r, s, v) in &self.nodes[source.node].installs {
				if cone.contains(&(*r, *s)) && install_at(&plan, *r, *s).is_none() {
					plan.push((*r, *s, v.clone()));
				}
			}
			let plan = normalize(plan);
			let cleared = self.cleared(&plan, &slots, source, &cone);
			let settled = !same_installs(&plan, &installs)
				&& self.as_family(Family::Stuck, |search| search.settles(plan));
			if !settled && let Some(cleared) = cleared {
				self.as_family(Family::Cleared, |search| search.consider(cleared));
			}
		}
	}

	fn retry_all_stuck(&mut self) {
		let mut at = 0;
		while at < self.stuck.len() {
			if self.done() {
				return;
			}
			self.retry_stuck(at);
			at += 1;
		}
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

	fn as_family<T>(&mut self, family: Family, f: impl FnOnce(&mut Self) -> T) -> T {
		let outer = std::mem::replace(&mut self.family, family);
		let out = f(self);
		self.family = outer;
		out
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

	fn consider(&mut self, installs: Installs) -> usize {
		let (at, _) = self.enqueue(installs);
		self.advance(at);
		self.drain();
		at
	}

	fn settles(&mut self, installs: Installs) -> bool {
		let (at, new) = self.enqueue(installs);
		if !new {
			return false;
		}
		self.advance(at);
		self.drain();
		self.outcome(at).is_some_and(|outcome| outcome.settled)
	}

	fn outcome(&self, at: usize) -> Option<&Outcome> {
		self.tried.entries[at].1.outcome.as_ref()
	}

	fn enqueue(&mut self, installs: Installs) -> (usize, bool) {
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
			super::judge(self.ctx, self.cx, &ex, &installs, &self.honest);
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

	fn shown(&self, installs: &Installs) -> String {
		installs
			.iter()
			.map(|(run, slot, v)| {
				format!(
					"{}.{}={}",
					self.cx.program.runs[*run].name,
					self.slot_name(*slot),
					v
				)
			})
			.collect::<Vec<String>>()
			.join(" ")
	}

	fn slot_name(&self, slot: usize) -> String {
		match slot {
			UNSTARTED => "unstarted".to_string(),
			slot => self.cx.km.slots[slot].constant.to_string(),
		}
	}

	fn tally(&mut self, family: Family, accepted: bool) {
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
			eprintln!("[search] family {family:?}: tried {tried}, accepted {accepted}");
		}
	}

	fn accept(&mut self, installs: Installs, ex: Execution) -> bool {
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
		super::judge(self.ctx, self.cx, &ex, &installs, &self.honest);
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

fn compatible_with(plan: &Installs, source: &Installs) -> bool {
	source.iter().all(|(run, slot, value)| {
		install_at(plan, *run, *slot).is_none_or(|held| held.equivalent(value, true))
	})
}

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
				.filter(|(run, slot, _)| install_at(plan, *run, *slot).is_none())
				.cloned(),
		);
		if let Some(done) = choose(&normalize(next), rest, failed) {
			return Some(done);
		}
	}
	failed[rest.len()].insert(plan);
	None
}

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
		Value::Constant(_) | Value::Variable(_) => crate::value::value_nil(),
	}
}

fn halts_of(ex: &Execution) -> Vec<(usize, usize)> {
	ex.runs
		.iter()
		.enumerate()
		.filter_map(|(run, state)| state.halted.map(|slot| (run, slot)))
		.collect()
}

fn relevant_prefixes(ctx: &VerifyContext, cx: &Context) -> Vec<usize> {
	let mut ends: Vec<_> = cx
		.program
		.runs
		.iter()
		.map(|run| {
			run.steps
				.iter()
				.rposition(|step| matches!(step.event, Event::Send(_) | Event::Leak(_)))
				.map_or(0, |step| step + 1)
		})
		.collect();
	for query in ctx.open_queries() {
		for constant in query.constants.iter().chain(&query.message.constants) {
			let Some(slot) = cx.km.index_of(constant) else {
				continue;
			};
			for (r, run) in cx.program.runs.iter().enumerate() {
				if query.kind == QueryKind::Unlinkability && run.id != cx.km.slots[slot].creator {
					continue;
				}
				let Some(&step) = run.step_of_slot.get(&slot) else {
					continue;
				};
				let end = match query.kind {
					QueryKind::Authentication | QueryKind::Freshness => run.steps.len(),
					_ => step + 1,
				};
				ends[r] = ends[r].max(end);
			}
		}
	}
	ends
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn removing_inputs_after_relevant_actions_preserves_query_violations() {
		let fixtures = [
			(
				"precondition_unlink_halt.vp",
				include_str!("../../examples/test/precondition_unlink_halt.vp"),
			),
			(
				"auth_use_through_checked_relay.vp",
				include_str!("../../examples/test/auth_use_through_checked_relay.vp"),
			),
			(
				"phase_claim_never_reached_use.vp",
				include_str!("../../examples/test/phase_claim_never_reached_use.vp"),
			),
			(
				"equivalence_borrowed_while_starved.vp",
				include_str!("../../examples/test/equivalence_borrowed_while_starved.vp"),
			),
			(
				"freshness_replayed_across_sessions.vp",
				include_str!("../../examples/test/freshness_replayed_across_sessions.vp"),
			),
			(
				"search_source_alternative.vp",
				include_str!("../../examples/test/search_source_alternative.vp"),
			),
		];
		let mut removed = 0;
		for (name, source) in fixtures {
			let _generation = crate::context::GenerationGuard::enter();
			let model = crate::parser::parse_string(name, source).unwrap();
			let km = crate::sanity::sanity(&model).unwrap();
			let program = crate::engine::program::Program::of(&model, &km);
			let cx = Context::new(&program, &km);
			let ctx = VerifyContext::new(&model, Vec::new(), 1, None, Vec::new(), Vec::new());
			let root = execute(&cx, &Vec::new());
			let mut search = Search::new(&ctx, &cx, root);
			let mut choices: Installs = program
				.deliveries
				.iter()
				.flat_map(|delivery| {
					delivery
						.slots
						.iter()
						.filter(|(_, guarded)| !guarded)
						.flat_map(|(slot, _)| {
							[
								crate::value::value_nil(),
								crate::primitive::attacker_public_key(),
							]
							.into_iter()
							.map(|value| (delivery.recipient, *slot, value))
						})
				})
				.collect();
			choices.extend(
				(0..program.runs.len()).map(|run| (run, UNSTARTED, crate::value::value_nil())),
			);
			for first in &choices {
				for second in &choices {
					let plan = normalize(vec![first.clone(), second.clone()]);
					let projected = search.project(plan.clone());
					if same_installs(&plan, &projected) {
						continue;
					}
					removed += 1;
					let original = execute(&cx, &plan);
					if !original.stuck.is_empty() {
						continue;
					}
					let after = execute(&cx, &projected);
					assert!(after.stuck.is_empty(), "{name}");
					for phase in 0..=km.max_phase {
						let claims = |principal| ctx.claims_at(principal, phase);
						let violates = |ex: &Execution, query: &Query| {
							super::super::query::Judge {
								cx: &cx,
								ex: ex.at(phase),
								whole: ex,
								claims: &claims,
							}
							.evaluate(query)
							.is_some()
						};
						for query in &model.queries {
							assert!(
								!violates(&original, query) || violates(&after, query),
								"{name}: {plan:?}"
							);
						}
					}
				}
			}
		}
		assert!(removed > 0);
	}

	#[test]
	fn colliding_install_maps_keep_their_own_continuations() {
		let constant = |name: &str, id| {
			Value::Constant(Constant {
				name: Arc::from(name),
				id,
				..Default::default()
			})
		};
		let left = Value::primitive(
			crate::primitive::PRIM_HASH,
			vec![constant("sig_a", 10), constant("sig_b", 100)],
			0,
		);
		let right = Value::primitive(
			crate::primitive::PRIM_HASH,
			vec![constant("sig_c", 11), constant("sig_d", 69)],
			0,
		);
		let left = vec![(1, 7, left)];
		let right = vec![(1, 7, right)];
		assert_eq!(installs_hash(&left), installs_hash(&right));
		let mut tried = Tried::default();
		assert!(tried.remember(&left, vec![None, Some(8)]));
		assert!(tried.remember(&right, vec![None, Some(10)]));
		assert_eq!(tried.get(&left), Some(&vec![None, Some(8)]));
		assert_eq!(tried.get(&right), Some(&vec![None, Some(10)]));
	}

	#[test]
	fn a_repeated_execution_keeps_its_repair_continuation() {
		let _generation = crate::context::GenerationGuard::enter();
		let model = crate::parser::parse_string(
			"solver_mac_then_tuple.vp",
			include_str!("../../examples/test/solver_mac_then_tuple.vp"),
		)
		.unwrap();
		let km = crate::sanity::sanity(&model).unwrap();
		let program = crate::engine::program::Program::of(&model, &km);
		let cx = Context::new(&program, &km);
		let ctx = VerifyContext::new(&model, Vec::new(), 1, None, Vec::new(), Vec::new());
		let root = execute(&cx, &Vec::new());
		let mut search = Search::new(&ctx, &cx, root);
		let bob = program
			.runs
			.iter()
			.position(|run| run.name == "Bob")
			.unwrap();
		let slot = km
			.slots
			.iter()
			.position(|slot| &*slot.constant.name == "ciphertext")
			.unwrap();
		let plan = vec![(bob, slot, crate::value::value_nil())];
		let first = search.consider(plan.clone());
		assert!(
			search
				.outcome(first)
				.is_some_and(|outcome| outcome.halts.iter().any(|&(run, _)| run == bob))
		);
		let executed = search.executed;
		assert_eq!(search.consider(plan), first);
		assert_eq!(search.executed, executed);
	}
}
