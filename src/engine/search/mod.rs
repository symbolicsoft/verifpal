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

use super::exec::{Context, Execution, Installs, UNSTARTED, install_at};
use super::knowledge::{Knowledge, Origin};
use super::program::Event;
use crate::solve::symbolic;
use crate::syntax::QueryKind;
use crate::term::Value;
use crate::theory::AttackerState;
use crate::theory::attacker::next_chain;
use crate::util::{IdMap, IdSet};
use crate::verify::context::VerifyContext;

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
	installed: bool,
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
	routes: Vec<Route>,
	rerouting: bool,
	honest_at: IdMap<(usize, usize), usize>,
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
		let honest_at = root
			.order
			.iter()
			.enumerate()
			.map(|(i, &(run, step, _))| ((run, step), i))
			.collect();
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
			routes: Vec::new(),
			rerouting: false,
			honest_at,
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
			*value = crate::term::hashing::hashcons(value);
		}
		normalize(installs)
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
		self.reroute();
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
}

type Bypassed = Vec<(usize, usize)>;

type Route = (Installs, Vec<(Value, usize, Bypassed)>);

fn compatible_with(plan: &Installs, source: &Installs) -> bool {
	source.iter().all(|(run, slot, value)| {
		install_at(plan, *run, *slot).is_none_or(|held| held.equivalent(value, true))
	})
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
