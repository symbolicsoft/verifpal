/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

mod merge;
mod placement;
mod reroute;
mod rounds;
mod stuck;
#[cfg(test)]
mod tests;
mod union;
mod worklist;

use std::sync::Arc;

use super::exec::{Context, Execution, Install, Installs, install_at};
use super::knowledge::{Knowledge, Origin};
use super::program::{DeliveryIdx, Event, RunIdx, StepIdx};
use crate::protocol::SlotIdx;
use crate::solve::symbolic;
use crate::syntax::QueryKind;
use crate::term::Value;
use crate::theory::AttackerState;
use crate::theory::attacker::next_chain;
use crate::util::index::{Idx, IndexVec, index_type};
use crate::util::{IdMap, IdSet};
use crate::verify::context::VerifyContext;

index_type!(
	struct NodeIdx;
);
index_type!(
	struct AttemptIdx;
);

const HONEST_NODE: NodeIdx = NodeIdx(0);

struct Node {
	installs: Installs,
	held: IndexVec<RunIdx, Vec<HeldValue>>,
	sent: IndexVec<DeliveryIdx, Option<Vec<Value>>>,
	knowledge: Vec<Arc<AttackerState>>,
	memo: std::cell::RefCell<crate::theory::SavedMemo>,
}

struct HeldValue {
	slot: SlotIdx,
	value: Value,
	received: bool,
	installed: bool,
}

impl Node {
	fn of(installs: Installs, ex: &Execution, queried: &IdSet<SlotIdx>) -> Self {
		Self {
			installs,
			held: ex
				.runs
				.iter()
				.map(|run| {
					run.env
						.iter_enumerated()
						.filter_map(|(slot, held)| {
							let held = held.as_ref()?;
							(held.sender.is_some() || queried.contains(&slot)).then(|| HeldValue {
								slot,
								value: crate::term::hashing::hashcons(&held.value),
								received: held.sender.is_some(),
								installed: held.installed.is_some(),
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
						.map(|values| values.iter().map(crate::term::hashing::hashcons).collect())
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

	fn held(&self, run: RunIdx, slot: SlotIdx) -> Option<&HeldValue> {
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
	honest: Execution,
	facts: Facts,
	nodes: IndexVec<NodeIdx, Node>,
	union: Union,
	attempts: Attempts,
	retries: Retries,
	memo: Memo,
	log: Log,
}

struct Facts {
	relevant: IndexVec<RunIdx, StepIdx>,
	queried: IdSet<SlotIdx>,
	receivers: IndexVec<SlotIdx, Vec<RunIdx>>,
	honest_at: IdMap<(RunIdx, StepIdx), usize>,
}

struct Union {
	knowledge: Knowledge,
	honest_known: usize,
	by_cost: Vec<Vec<Vec<NodeIdx>>>,
	closed: Knowledge,
	closed_at: (usize, NodeIdx),
	protocol_seen: IdMap<u64, Vec<(Value, Value)>>,
}

struct Attempts {
	tried: Tried<Attempt>,
	pending: Vec<AttemptIdx>,
	probed: Tried,
	drops: Vec<Installs>,
	merged: IdMap<(u64, NodeIdx), Vec<Value>>,
	family: Family,
	executed: usize,
}

#[derive(Default)]
struct Retries {
	stuck: Vec<Stuck>,
	fresh: IdMap<u64, Vec<(Value, Source, Vec<RunIdx>)>>,
	by_install: IdMap<(RunIdx, Option<SlotIdx>, u64), Vec<NodeIdx>>,
	routes: Vec<Route>,
	rerouting: bool,
}

#[derive(Default)]
struct Memo {
	derivable: std::cell::RefCell<IdMap<(NodeIdx, usize), bool>>,
	cheapest: std::cell::RefCell<IdMap<usize, Cheapest>>,
	holders: IdMap<(SlotIdx, QueryKind), Holders>,
}

struct Log {
	debug: bool,
	proposer: RunIdx,
	stats: Vec<(Family, usize, usize)>,
}

struct Cheapest {
	used: Vec<usize>,
	scanned: NodeIdx,
	best: Option<NodeIdx>,
}

struct Holders {
	scanned: NodeIdx,
	values: Vec<(Value, NodeIdx)>,
	index: IdMap<u64, Vec<usize>>,
}

impl Default for Holders {
	fn default() -> Self {
		Holders {
			scanned: NodeIdx::new(0),
			values: Vec::new(),
			index: IdMap::default(),
		}
	}
}

#[derive(Clone)]
struct Outcome {
	halts: Vec<(RunIdx, SlotIdx)>,
	settled: bool,
}

struct Attempt {
	outcome: Option<Outcome>,
	family: Family,
}

#[derive(Clone, Copy)]
struct Source {
	node: NodeIdx,
	run: RunIdx,
	slot: SlotIdx,
}

struct Stuck {
	installs: Installs,
	slots: Vec<(RunIdx, SlotIdx)>,
	tried_with: IdSet<NodeIdx>,
	supply: Vec<(usize, NodeIdx)>,
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
	Rerouted,
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
	entries: IndexVec<AttemptIdx, (Installs, T)>,
	index: IdMap<u64, Vec<AttemptIdx>>,
}

impl<T> Default for Tried<T> {
	fn default() -> Self {
		Self {
			entries: IndexVec::new(),
			index: IdMap::default(),
		}
	}
}

impl<T> Tried<T> {
	#[cfg(test)]
	fn get(&self, installs: &Installs) -> Option<&T> {
		self.position(installs).map(|at| &self.entries[at].1)
	}

	fn position(&self, installs: &Installs) -> Option<AttemptIdx> {
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
			.push(self.entries.next_index());
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
	for install in installs {
		let run = (install.run().index() as u64) << 32;
		let (input, value) = match install {
			Install::Value { slot, value, .. } => (run | slot.index() as u64, value.hash_value()),
			Install::Idle { .. } => (run | u64::from(u32::MAX), 0),
		};
		acc = acc
			.rotate_left(13)
			.wrapping_add(input.wrapping_mul(0xC2B2_AE3D_27D4_EB4F))
			^ value;
	}
	acc
}

fn same_installs(a: &Installs, b: &Installs) -> bool {
	a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.same(y))
}

fn install_key(install: &Install) -> (RunIdx, Option<SlotIdx>, u64) {
	(
		install.run(),
		install.slot(),
		install.value().map_or(0, Value::hash_value),
	)
}

fn runs_of(installs: &Installs) -> Vec<RunIdx> {
	let mut runs: Vec<RunIdx> = installs.iter().map(Install::run).collect();
	runs.sort_unstable();
	runs.dedup();
	runs
}

fn normalize(mut installs: Installs) -> Installs {
	installs.sort_by_key(Install::order);
	installs.dedup_by(|a, b| a.same_input(b));
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
		let mut knowledge = Knowledge::new(cx.km.max_phase);
		let mut by_cost = Vec::new();
		for v in root.knowledge.state.known.iter() {
			if knowledge.learn(v, Origin::Initial) {
				by_cost.push(vec![vec![HONEST_NODE]]);
			}
		}
		let honest_at = root
			.order
			.iter()
			.enumerate()
			.map(|(i, taken)| ((taken.run, taken.step), i))
			.collect();
		let receivers = cx
			.km
			.slots
			.indices()
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
			.collect();
		let mut search = Search {
			ctx,
			cx,
			honest: root,
			facts: Facts {
				relevant: relevant_prefixes(ctx, cx),
				queried,
				receivers,
				honest_at,
			},
			nodes: IndexVec::new(),
			union: Union {
				honest_known: knowledge.len(),
				knowledge,
				by_cost,
				closed: Knowledge::new(cx.km.max_phase),
				closed_at: (0, NodeIdx::new(0)),
				protocol_seen: IdMap::default(),
			},
			attempts: Attempts {
				tried: Tried::default(),
				pending: Vec::new(),
				probed: Tried::default(),
				drops: Vec::new(),
				merged: IdMap::default(),
				family: Family::Base,
				executed: 0,
			},
			retries: Retries::default(),
			memo: Memo::default(),
			log: Log {
				debug: std::env::var("VERIFPAL_SOLVE_DEBUG").is_ok(),
				proposer: RunIdx::new(0),
				stats: Vec::new(),
			},
		};
		let root = Node::of(Vec::new(), &search.honest, &search.facts.queried);
		search.push_node(root);
		search.absorb_terms(&search.honest.knowledge.clone());
		search.close_union();
		search
	}

	fn done(&self) -> bool {
		self.ctx.all_resolved() || self.ctx.cancelled()
	}

	fn relevant_input(&self, run: RunIdx, slot: SlotIdx) -> bool {
		self.cx.program.runs[run]
			.step_of_slot
			.get(&slot)
			.is_some_and(|&step| step < self.facts.relevant[run])
	}

	fn relevant(&self, install: &Install) -> bool {
		match install {
			Install::Value { run, slot, .. } => self.relevant_input(*run, *slot),
			Install::Idle { run } => self.facts.relevant[*run] > StepIdx::new(0),
		}
	}

	fn project(&mut self, mut installs: Installs) -> Installs {
		installs.retain(|install| self.relevant(install));
		for install in &mut installs {
			if let Install::Value { value, .. } = install {
				*value = crate::term::hashing::hashcons(value);
			}
		}
		normalize(installs)
	}

	fn describe(&self, node: NodeIdx) -> String {
		let shown: Vec<String> = self.nodes[node]
			.installs
			.iter()
			.map(|install| self.spoken(install))
			.collect();
		if shown.is_empty() {
			"the protocol runs honestly".to_string()
		} else {
			shown.join(", ")
		}
	}

	pub(crate) fn run(&mut self) {
		self.fixpoint(Mode::Plain);
		if self.done() {
			return;
		}
		let before = self.union.knowledge.len();
		self.fixpoint(Mode::Refined);
		if self.union.knowledge.len() != before && !self.done() {
			self.fixpoint(Mode::Plain);
		}
		self.idle();
		if !self.done() && symbolic::has_key_shaped_slot(self.cx.km) {
			self.as_family(Family::Unshaped, |search| search.fixpoint(Mode::Unshaped));
		}
		self.reroute();
	}

	fn spoken(&self, install: &Install) -> String {
		let name = &self.cx.program.runs[install.run()].name;
		match install {
			Install::Value { slot, value, .. } => {
				format!("{name}'s {} is {value}", self.cx.km.slots[*slot].constant)
			}
			Install::Idle { .. } => format!("{name} never starts"),
		}
	}

	fn shown(&self, installs: &Installs) -> String {
		installs
			.iter()
			.map(|install| {
				let name = &self.cx.program.runs[install.run()].name;
				match install {
					Install::Value { slot, value, .. } => {
						format!("{name}.{}={value}", self.cx.km.slots[*slot].constant)
					}
					Install::Idle { .. } => format!("{name}.unstarted"),
				}
			})
			.collect::<Vec<String>>()
			.join(" ")
	}

	fn tally(&mut self, family: Family, accepted: bool) {
		let at = match self
			.log
			.stats
			.iter()
			.position(|(seen, _, _)| *seen == family)
		{
			Some(at) => at,
			None => {
				self.log.stats.push((family, 0, 0));
				self.log.stats.len() - 1
			}
		};
		self.log.stats[at].1 += 1;
		self.log.stats[at].2 += usize::from(accepted);
	}

	pub(crate) fn report_stats(&self) {
		if !self.log.debug {
			return;
		}
		for (family, tried, accepted) in &self.log.stats {
			eprintln!("[search] family {family:?}: tried {tried}, accepted {accepted}");
		}
	}
}

type Bypassed = Vec<(RunIdx, usize)>;

type Route = (Installs, Vec<(Value, RunIdx, Bypassed)>);

fn compatible_with(plan: &Installs, source: &Installs) -> bool {
	source.iter().all(|install| match install {
		Install::Value { run, slot, value } => {
			install_at(plan, *run, *slot).is_none_or(|held| held.equivalent(value, true))
		}
		Install::Idle { .. } => true,
	})
}

fn relevant_prefixes(ctx: &VerifyContext, cx: &Context) -> IndexVec<RunIdx, StepIdx> {
	let mut ends: IndexVec<RunIdx, StepIdx> = cx
		.program
		.runs
		.iter()
		.map(|run| {
			run.steps
				.iter_enumerated()
				.rev()
				.find(|(_, step)| matches!(step.event, Event::Send(_) | Event::Leak(_)))
				.map_or(StepIdx::new(0), |(step, _)| step.next())
		})
		.collect();
	for query in ctx.open_queries() {
		for constant in query.constants.iter().chain(&query.message.constants) {
			let Some(slot) = cx.km.index_of(constant) else {
				continue;
			};
			for (r, run) in cx.program.runs.iter_enumerated() {
				if query.kind == QueryKind::Unlinkability && run.id != cx.km.slots[slot].creator {
					continue;
				}
				let Some(&step) = run.step_of_slot.get(&slot) else {
					continue;
				};
				let end = match query.kind {
					QueryKind::Authentication | QueryKind::Freshness => run.steps.next_index(),
					_ => step.next(),
				};
				ends[r] = ends[r].max(end);
			}
		}
	}
	ends
}
