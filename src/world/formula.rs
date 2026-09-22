/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::Generational;
use crate::types::{Constraint, IdMap, IdSet, PrincipalId, SlotIdx, Value, ValueId};
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, OnceLock, Weak};
use varisat::{ExtendFormula, Lit, Solver};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Key(usize, PrincipalId, ValueId);

impl Ord for Key {
	fn cmp(&self, other: &Self) -> std::cmp::Ordering {
		other
			.2
			.cmp(&self.2)
			.then(self.0.cmp(&other.0))
			.then(self.1.cmp(&other.1))
	}
}

impl PartialOrd for Key {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		Some(self.cmp(other))
	}
}

#[derive(Clone, Debug, Default)]
pub struct Worlds(Root);

#[derive(Clone, Debug, Default)]
enum Root {
	#[default]
	Empty,
	Any,
	Node(Arc<Node>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Operation {
	And,
	Or,
}

#[derive(Debug)]
enum Expression {
	Pin(Key, Value),
	Junction(Operation, Worlds, Worlds),
}

#[derive(Debug)]
struct Node {
	expression: Expression,
	height: usize,
	empty: OnceLock<bool>,
	choice: OnceLock<Option<Constraint>>,
	conjunction: OnceLock<Conjunction>,
	example: OnceLock<Option<Arc<IdMap<Key, Value>>>>,
}

#[derive(Debug)]
enum Conjunction {
	General,
	Impossible,
	Pins(IdMap<Key, Value>),
}

#[derive(Default)]
struct Interner {
	pins: IdMap<(Key, u64), Vec<Weak<Node>>>,
	junctions: IdMap<(Operation, usize, usize), Weak<Node>>,
	insertions: usize,
}

struct Included {
	_root: Weak<Node>,
	members: IdMap<usize, Weak<Node>>,
	order: VecDeque<usize>,
}

#[derive(Default)]
struct Inclusions {
	entries: IdMap<usize, Included>,
	order: VecDeque<usize>,
}

impl Inclusions {
	fn remember(&mut self, parent: &Arc<Node>, child: &Arc<Node>) {
		let parent_id = Arc::as_ptr(parent) as usize;
		let child_id = Arc::as_ptr(child) as usize;
		if parent_id == child_id {
			return;
		}
		let mut inherited = self
			.entries
			.get(&child_id)
			.map(|entry| {
				entry
					.order
					.iter()
					.filter_map(|id| entry.members.get(id).map(|node| (*id, node.clone())))
					.collect::<Vec<_>>()
			})
			.unwrap_or_default();
		inherited.push((child_id, Arc::downgrade(child)));
		if !self.entries.contains_key(&parent_id) {
			if self.entries.len() >= 8192
				&& let Some(oldest) = self.order.pop_front()
			{
				self.entries.remove(&oldest);
			}
			self.entries.insert(
				parent_id,
				Included {
					_root: Arc::downgrade(parent),
					members: IdMap::default(),
					order: VecDeque::new(),
				},
			);
			self.order.push_back(parent_id);
		}
		let entry = self.entries.get_mut(&parent_id).unwrap();
		for (id, node) in inherited {
			if id == parent_id || entry.members.contains_key(&id) {
				continue;
			}
			if entry.members.len() >= 1024
				&& let Some(oldest) = entry.order.pop_front()
			{
				entry.members.remove(&oldest);
			}
			entry.members.insert(id, node);
			entry.order.push_back(id);
		}
	}
}

struct Encoded {
	_source: Weak<Node>,
	literal: Lit,
}

#[derive(Default)]
struct Domain {
	values: IdMap<u64, Vec<(Value, Lit)>>,
	any: Option<Lit>,
}

struct Decision {
	_inputs: Vec<Weak<Node>>,
	result: bool,
}

#[derive(Default)]
struct Decisions {
	decisions: IdMap<(usize, usize), Decision>,
	supersets: IdMap<usize, Vec<usize>>,
	order: VecDeque<(usize, usize)>,
	queries: VecDeque<(Worlds, Reasoner)>,
}

struct Reasoner {
	solver: Solver<'static>,
	truth: Lit,
	fixed: IdMap<Key, Value>,
	nodes: IdMap<usize, Encoded>,
	domains: IdMap<Key, Domain>,
	models: VecDeque<IdMap<Key, Value>>,
	base_size: usize,
}

impl Default for Reasoner {
	fn default() -> Self {
		let mut solver = Solver::new();
		let truth = solver.new_lit();
		solver.add_clause(&[truth]);
		Self {
			solver,
			truth,
			fixed: IdMap::default(),
			nodes: IdMap::default(),
			domains: IdMap::default(),
			models: VecDeque::new(),
			base_size: 0,
		}
	}
}

impl Decisions {
	fn remember_superset(&mut self, key: (usize, usize)) {
		let entry = self.supersets.entry(key.0).or_default();
		entry.retain(|right| *right != key.1);
		entry.push(key.1);
		if entry.len() > 8 {
			entry.remove(0);
		}
	}

	fn subset(&mut self, left: &Worlds, right: &Worlds) -> bool {
		let key = (left.identity(), right.identity());
		if let Some(hit) = self.decisions.get(&key).map(|entry| entry.result) {
			if hit {
				self.remember_superset(key);
			}
			return hit;
		}
		let result = match left.conjunction() {
			Some(Conjunction::Pins(pins)) => right.accepts(pins, &mut IdMap::default()),
			Some(Conjunction::Impossible) => true,
			_ if left
				.example()
				.is_some_and(|pins| !right.accepts(&pins, &mut IdMap::default())) =>
			{
				false
			}
			_ if left.structurally_implies(right, &self.supersets) => true,
			_ => {
				let mut query = self
					.queries
					.iter()
					.position(|(target, _)| target.identity() == right.identity())
					.or_else(|| {
						self.queries.iter().rposition(|(_, query)| {
							query.nodes.contains_key(&right.identity())
								|| query.nodes.contains_key(&left.identity())
						})
					})
					.and_then(|index| self.queries.remove(index))
					.map(|(_, query)| query)
					.unwrap_or_default();
				let result = if query.models.iter().any(|pins| {
					let mut memo = IdMap::default();
					left.accepts(pins, &mut memo) && !right.accepts(pins, &mut memo)
				}) {
					false
				} else {
					if query.nodes.len() > 1024.max(query.base_size.saturating_mul(4)) {
						query = Reasoner::default();
					}
					let a = query.encode(left);
					let b = query.encode(right);
					if query.base_size == 0 {
						query.base_size = query.nodes.len();
					}
					let included = !query.satisfiable(&[a, !b]);
					if !included {
						query.remember_model();
					}
					included
				};
				self.queries.push_back((right.clone(), query));
				if self.queries.len() > 8 {
					self.queries.pop_front();
				}
				result
			}
		};
		let inputs = [left, right]
			.into_iter()
			.filter_map(|worlds| match &worlds.0 {
				Root::Node(node) => Some(Arc::downgrade(node)),
				_ => None,
			})
			.collect();
		self.decisions.insert(
			key,
			Decision {
				_inputs: inputs,
				result,
			},
		);
		if result {
			self.remember_superset(key);
		}
		self.order.push_back(key);
		if self.order.len() > 65_536
			&& let Some(oldest) = self.order.pop_front()
		{
			self.decisions.remove(&oldest);
			if let Some(entry) = self.supersets.get_mut(&oldest.0) {
				entry.retain(|right| *right != oldest.1);
				if entry.is_empty() {
					self.supersets.remove(&oldest.0);
				}
			}
		}
		result
	}
}

impl Reasoner {
	fn remember_model(&mut self) {
		let assignment: IdSet<Lit> = self
			.solver
			.model()
			.expect("satisfiable worlds have a model")
			.into_iter()
			.filter(|literal| literal.is_positive())
			.collect();
		let mut pins = IdMap::default();
		for (key, domain) in &self.domains {
			for bucket in domain.values.values() {
				for (value, literal) in bucket {
					if assignment.contains(literal) {
						pins.insert(*key, value.clone());
					}
				}
			}
		}
		self.models.push_front(pins);
		if self.models.len() > 8 {
			self.models.pop_back();
		}
	}

	fn encode(&mut self, worlds: &Worlds) -> Lit {
		match &worlds.0 {
			Root::Empty => !self.truth,
			Root::Any => self.truth,
			Root::Node(node) => {
				let identity = worlds.identity();
				if let Some(encoded) = self.nodes.get(&identity) {
					return encoded.literal;
				}
				let literal = match &node.expression {
					Expression::Pin(key, value) if self.fixed.contains_key(key) => {
						if self.fixed[key].equivalent(value, true) {
							self.truth
						} else {
							!self.truth
						}
					}
					Expression::Pin(key, value) => {
						let domain = self.domains.entry(*key).or_default();
						let bucket = domain.values.entry(value.hash_value()).or_default();
						if let Some((_, literal)) =
							bucket.iter().find(|(seen, _)| seen.equivalent(value, true))
						{
							*literal
						} else {
							let literal = self.solver.new_lit();
							if let Some(previous) = domain.any {
								self.solver.add_clause(&[!previous, !literal]);
								let any = self.solver.new_lit();
								self.solver.add_clause(&[!previous, any]);
								self.solver.add_clause(&[!literal, any]);
								self.solver.add_clause(&[previous, literal, !any]);
								domain.any = Some(any);
							} else {
								domain.any = Some(literal);
							}
							bucket.push((value.clone(), literal));
							literal
						}
					}
					Expression::Junction(operation, left, right) => {
						let left = self.encode(left);
						let absorbing = match operation {
							Operation::And => !self.truth,
							Operation::Or => self.truth,
						};
						if left == absorbing {
							left
						} else {
							let right = self.encode(right);
							if right == absorbing || left == !absorbing {
								right
							} else if right == !absorbing || left == right {
								left
							} else {
								let output = self.solver.new_lit();
								match operation {
									Operation::And => {
										self.solver.add_clause(&[!output, left]);
										self.solver.add_clause(&[!output, right]);
										self.solver.add_clause(&[output, !left, !right]);
									}
									Operation::Or => {
										self.solver.add_clause(&[output, !left]);
										self.solver.add_clause(&[output, !right]);
										self.solver.add_clause(&[!output, left, right]);
									}
								}
								output
							}
						}
					}
				};
				self.nodes.insert(
					identity,
					Encoded {
						_source: Arc::downgrade(node),
						literal,
					},
				);
				literal
			}
		}
	}

	fn satisfiable(&mut self, assumptions: &[Lit]) -> bool {
		self.solver.assume(assumptions);
		self.solver
			.solve()
			.expect("uninterrupted world satisfiability without proof I/O")
	}

	fn choose(&mut self, worlds: &Worlds) -> Option<Constraint> {
		let mut seen = IdSet::default();
		let mut pending = vec![worlds];
		while let Some(next) = pending.pop() {
			if !seen.insert(next.identity()) {
				continue;
			}
			match &next.0 {
				Root::Empty => return None,
				Root::Any => (),
				Root::Node(node) => match &node.expression {
					Expression::Pin(key, value) => {
						if let Some(previous) = self.fixed.insert(*key, value.clone())
							&& !previous.equivalent(value, true)
						{
							return None;
						}
					}
					Expression::Junction(Operation::And, left, right) => {
						pending.extend([left, right]);
					}
					Expression::Junction(Operation::Or, ..) => (),
				},
			}
		}
		let root = self.encode(worlds);
		let mut assumptions = vec![root];
		if !self.satisfiable(&assumptions) {
			return None;
		}
		let mut domains: BTreeMap<Key, Vec<(Value, Lit)>> = BTreeMap::new();
		let mut seen = IdSet::default();
		let mut pending = vec![worlds];
		while let Some(next) = pending.pop() {
			if !seen.insert(next.identity()) {
				continue;
			}
			if let Root::Node(node) = &next.0 {
				match &node.expression {
					Expression::Pin(key, value) => {
						if let Some(encoded) = self.nodes.get(&next.identity())
							&& encoded.literal != !self.truth
						{
							domains
								.entry(*key)
								.or_default()
								.push((value.clone(), encoded.literal));
						}
					}
					Expression::Junction(_, left, right) => {
						pending.push(right);
						pending.push(left);
					}
				}
			}
		}
		for (key, value) in &self.fixed {
			domains.insert(*key, vec![(value.clone(), self.truth)]);
		}
		let mut domains = domains.into_iter().collect::<Vec<_>>();
		let mut negative = Vec::new();
		let mut offsets = vec![0];
		for (_, values) in &mut domains {
			values.sort_by_key(|(value, _)| value.hash_value());
			negative.extend(values.iter().map(|(_, literal)| !*literal));
			offsets.push(negative.len());
		}
		let mut out = Vec::new();
		let mut start = 0;
		while start < domains.len() {
			let before = assumptions.len();
			let mut low = start;
			let mut high = start + 1;
			loop {
				assumptions.truncate(before);
				assumptions.extend_from_slice(&negative[offsets[start]..offsets[high]]);
				if !self.satisfiable(&assumptions) {
					break;
				}
				low = high;
				if low == domains.len() {
					break;
				}
				high = (start + (high - start).saturating_mul(2)).min(domains.len());
			}
			if low == domains.len() {
				break;
			}
			while high > low + 1 {
				let middle = low + (high - low) / 2;
				assumptions.truncate(before);
				assumptions.extend_from_slice(&negative[offsets[start]..offsets[middle]]);
				if self.satisfiable(&assumptions) {
					low = middle;
				} else {
					high = middle;
				}
			}
			assumptions.truncate(before);
			assumptions.extend_from_slice(&negative[offsets[start]..offsets[low]]);
			let (key, values) = &domains[low];
			let (value, literal) = values
				.iter()
				.find(|(_, literal)| {
					assumptions.push(*literal);
					let possible = self.satisfiable(&assumptions);
					assumptions.pop();
					possible
				})
				.expect("a satisfiable world has a satisfiable branch");
			assumptions.push(*literal);
			out.push((key.1, SlotIdx(key.0), value.clone()));
			start = low + 1;
		}
		out.reverse();
		Some(out)
	}
}

thread_local! {
	static NODES: RefCell<Generational<Interner>> = RefCell::new(Generational::default());
	static INCLUSIONS: RefCell<Generational<Inclusions>> = RefCell::new(Generational::default());
	static DECISIONS: RefCell<Generational<Decisions>> = RefCell::new(Generational::default());
}

impl Worlds {
	pub(crate) fn any() -> Self {
		Self(Root::Any)
	}

	fn identity(&self) -> usize {
		match &self.0 {
			Root::Empty => 0,
			Root::Any => 1,
			Root::Node(node) => Arc::as_ptr(node) as usize,
		}
	}

	pub(crate) fn is_unconditional(&self) -> bool {
		matches!(self.0, Root::Any)
	}

	pub(crate) fn is_empty(&self) -> bool {
		match &self.0 {
			Root::Empty => true,
			Root::Any => false,
			Root::Node(node) => *node.empty.get_or_init(|| match &node.expression {
				Expression::Pin(..) => false,
				Expression::Junction(Operation::Or, left, right) => {
					left.is_empty() && right.is_empty()
				}
				Expression::Junction(Operation::And, ..) => match self.conjunction() {
					Some(Conjunction::Pins(_)) => false,
					Some(Conjunction::Impossible) => true,
					_ if self.example().is_some() => false,
					_ => DECISIONS
						.with(|cell| cell.borrow_mut().fresh().subset(self, &Self::default())),
				},
			}),
		}
	}

	fn example(&self) -> Option<Arc<IdMap<Key, Value>>> {
		match &self.0 {
			Root::Empty => None,
			Root::Any => Some(Arc::default()),
			Root::Node(node) => node
				.example
				.get_or_init(|| match &node.expression {
					Expression::Pin(key, value) => {
						Some(Arc::new(IdMap::from_iter([(*key, value.clone())])))
					}
					Expression::Junction(Operation::Or, left, right) => {
						left.example().or_else(|| right.example())
					}
					Expression::Junction(Operation::And, left, right) => {
						let mut left = left.example()?;
						let right = right.example()?;
						if left.iter().any(|(key, value)| {
							right
								.get(key)
								.is_some_and(|other| !value.equivalent(other, true))
						}) {
							return None;
						}
						if right.keys().all(|key| left.contains_key(key)) {
							return Some(left);
						}
						if left.keys().all(|key| right.contains_key(key)) {
							return Some(right);
						}
						Arc::make_mut(&mut left)
							.extend(right.iter().map(|(key, value)| (*key, value.clone())));
						Some(left)
					}
				})
				.clone(),
		}
	}

	pub(crate) fn choose(&self) -> Option<Constraint> {
		match &self.0 {
			Root::Empty => None,
			Root::Any => Some(Vec::new()),
			Root::Node(node) => node
				.choice
				.get_or_init(|| match self.conjunction() {
					Some(Conjunction::Pins(pins)) => {
						let mut pins = pins.iter().collect::<Vec<_>>();
						pins.sort_by_key(|(key, _)| std::cmp::Reverse(**key));
						Some(
							pins.into_iter()
								.map(|(key, value)| (key.1, SlotIdx(key.0), value.clone()))
								.collect(),
						)
					}
					Some(Conjunction::Impossible) => None,
					_ => Reasoner::default().choose(self),
				})
				.clone(),
		}
	}

	fn conjunction(&self) -> Option<&Conjunction> {
		let Root::Node(node) = &self.0 else {
			return None;
		};
		Some(node.conjunction.get_or_init(|| {
			let mut pins: IdMap<Key, Value> = IdMap::default();
			let mut seen = IdSet::default();
			let mut pending = vec![self];
			while let Some(next) = pending.pop() {
				if !seen.insert(next.identity()) {
					continue;
				}
				match &next.0 {
					Root::Empty => return Conjunction::Impossible,
					Root::Any => (),
					Root::Node(node) => match &node.expression {
						Expression::Pin(key, value) => {
							if let Some(previous) = pins.get(key)
								&& !previous.equivalent(value, true)
							{
								return Conjunction::Impossible;
							}
							pins.insert(*key, value.clone());
						}
						Expression::Junction(Operation::And, left, right) => {
							pending.extend([left, right])
						}
						Expression::Junction(Operation::Or, ..) => return Conjunction::General,
					},
				}
			}
			Conjunction::Pins(pins)
		}))
	}

	fn accepts(&self, pins: &IdMap<Key, Value>, memo: &mut IdMap<usize, bool>) -> bool {
		if let Some(hit) = memo.get(&self.identity()) {
			return *hit;
		}
		let result = match &self.0 {
			Root::Empty => false,
			Root::Any => true,
			Root::Node(node) => match &node.expression {
				Expression::Pin(key, value) => {
					pins.get(key).is_some_and(|pin| pin.equivalent(value, true))
				}
				Expression::Junction(Operation::And, left, right) => {
					left.accepts(pins, memo) && right.accepts(pins, memo)
				}
				Expression::Junction(Operation::Or, left, right) => {
					left.accepts(pins, memo) || right.accepts(pins, memo)
				}
			},
		};
		memo.insert(self.identity(), result);
		result
	}

	fn structurally_implies(&self, other: &Self, supersets: &IdMap<usize, Vec<usize>>) -> bool {
		let mut certain = IdSet::default();
		let mut pending = vec![self];
		while let Some(next) = pending.pop() {
			if !certain.insert(next.identity()) {
				continue;
			}
			if let Root::Node(node) = &next.0
				&& let Expression::Junction(Operation::And, left, right) = &node.expression
			{
				pending.extend([left, right]);
			}
		}
		let proven = certain
			.iter()
			.filter_map(|id| supersets.get(id))
			.flatten()
			.copied()
			.collect::<Vec<_>>();
		certain.extend(proven);
		other.follows_from(&certain, &mut IdMap::default())
	}

	fn follows_from(&self, certain: &IdSet<usize>, memo: &mut IdMap<usize, bool>) -> bool {
		if certain.contains(&self.identity()) || self.is_unconditional() {
			return true;
		}
		if let Some(hit) = memo.get(&self.identity()) {
			return *hit;
		}
		let covered = INCLUSIONS.with(|cell| {
			cell.borrow_mut()
				.fresh()
				.entries
				.get(&self.identity())
				.is_some_and(|entry| certain.iter().any(|id| entry.members.contains_key(id)))
		});
		let result = covered
			|| match &self.0 {
				Root::Node(node) => match &node.expression {
					Expression::Pin(..) => false,
					Expression::Junction(Operation::And, left, right) => {
						left.follows_from(certain, memo) && right.follows_from(certain, memo)
					}
					Expression::Junction(Operation::Or, left, right) => {
						left.follows_from(certain, memo) || right.follows_from(certain, memo)
					}
				},
				_ => false,
			};
		memo.insert(self.identity(), result);
		result
	}

	pub(crate) fn includes(&self, other: &Self) -> bool {
		if self.identity() == other.identity()
			|| self.is_unconditional()
			|| other.known_empty() == Some(true)
		{
			return true;
		}
		INCLUSIONS.with(|cell| {
			cell.borrow_mut()
				.fresh()
				.entries
				.get(&self.identity())
				.is_some_and(|entry| entry.members.contains_key(&other.identity()))
		})
	}

	fn known_empty(&self) -> Option<bool> {
		match &self.0 {
			Root::Empty => Some(true),
			Root::Any => Some(false),
			Root::Node(node) => node.empty.get().copied(),
		}
	}

	fn remember_included(&self, other: &Self) {
		if let (Root::Node(parent), Root::Node(child)) = (&self.0, &other.0) {
			INCLUSIONS.with(|cell| cell.borrow_mut().fresh().remember(parent, child));
		}
	}

	pub(crate) fn subset_of(&self, other: &Self) -> bool {
		if other.includes(self) {
			return true;
		}
		if self.is_unconditional() {
			return false;
		}
		DECISIONS.with(|cell| cell.borrow_mut().fresh().subset(self, other))
	}

	pub(crate) fn equivalent(&self, other: &Self) -> bool {
		self.identity() == other.identity() || (self.subset_of(other) && other.subset_of(self))
	}

	fn pin(key: Key, value: Value) -> Self {
		NODES.with(|cell| {
			let mut cache = cell.borrow_mut();
			let cache = cache.fresh();
			let bucket = cache.pins.entry((key, value.hash_value())).or_default();
			bucket.retain(|node| node.strong_count() != 0);
			for node in bucket.iter().filter_map(Weak::upgrade) {
				if let Expression::Pin(_, seen) = &node.expression
					&& seen.equivalent(&value, true)
				{
					return Self(Root::Node(node));
				}
			}
			let node = Arc::new(Node {
				expression: Expression::Pin(key, value),
				height: 0,
				empty: OnceLock::from(false),
				choice: OnceLock::new(),
				conjunction: OnceLock::new(),
				example: OnceLock::new(),
			});
			bucket.push(Arc::downgrade(&node));
			Self(Root::Node(node))
		})
	}

	fn height(&self, operation: Operation) -> usize {
		if let Root::Node(node) = &self.0
			&& let Expression::Junction(kind, ..) = node.expression
			&& kind == operation
		{
			node.height
		} else {
			0
		}
	}

	fn children(&self) -> (&Self, &Self) {
		if let Root::Node(node) = &self.0
			&& let Expression::Junction(_, left, right) = &node.expression
		{
			(left, right)
		} else {
			unreachable!()
		}
	}

	fn junction(operation: Operation, left: &Self, right: &Self) -> Self {
		if left.identity() == right.identity() {
			return left.clone();
		}
		let mut key = (operation, left.identity(), right.identity());
		if key.1 > key.2 {
			(key.1, key.2) = (key.2, key.1);
		}
		NODES.with(|cell| {
			let mut cache = cell.borrow_mut();
			let cache = cache.fresh();
			if let Some(node) = cache.junctions.get(&key).and_then(Weak::upgrade) {
				return Self(Root::Node(node));
			}
			cache.insertions += 1;
			if cache.insertions.is_multiple_of(65_536) {
				cache.junctions.retain(|_, node| node.strong_count() != 0);
				cache.pins.retain(|_, bucket| {
					bucket.retain(|node| node.strong_count() != 0);
					!bucket.is_empty()
				});
			}
			let empty = match (operation, left.known_empty(), right.known_empty()) {
				(Operation::Or, Some(false), _) | (Operation::Or, _, Some(false)) => {
					OnceLock::from(false)
				}
				(Operation::Or, Some(true), Some(true))
				| (Operation::And, Some(true), _)
				| (Operation::And, _, Some(true)) => OnceLock::from(true),
				_ => OnceLock::new(),
			};
			let node = Arc::new(Node {
				expression: Expression::Junction(operation, left.clone(), right.clone()),
				height: 1 + left.height(operation).max(right.height(operation)),
				empty,
				choice: OnceLock::new(),
				conjunction: OnceLock::new(),
				example: OnceLock::new(),
			});
			cache.junctions.insert(key, Arc::downgrade(&node));
			Self(Root::Node(node))
		})
	}

	fn balance(operation: Operation, left: &Self, right: &Self) -> Self {
		let lh = left.height(operation);
		let rh = right.height(operation);
		if lh > rh + 1 {
			let (a, b) = left.children();
			if a.height(operation) >= b.height(operation) {
				Self::junction(operation, a, &Self::junction(operation, b, right))
			} else {
				let (ba, bb) = b.children();
				Self::junction(
					operation,
					&Self::junction(operation, a, ba),
					&Self::junction(operation, bb, right),
				)
			}
		} else if rh > lh + 1 {
			let (a, b) = right.children();
			if b.height(operation) >= a.height(operation) {
				Self::junction(operation, &Self::junction(operation, left, a), b)
			} else {
				let (aa, ab) = a.children();
				Self::junction(
					operation,
					&Self::junction(operation, left, aa),
					&Self::junction(operation, ab, b),
				)
			}
		} else {
			Self::junction(operation, left, right)
		}
	}

	fn join(operation: Operation, left: &Self, right: &Self) -> Self {
		if left.height(operation) > right.height(operation) + 1 {
			let (a, b) = left.children();
			Self::balance(operation, a, &Self::join(operation, b, right))
		} else if right.height(operation) > left.height(operation) + 1 {
			let (a, b) = right.children();
			Self::balance(operation, &Self::join(operation, left, a), b)
		} else {
			Self::junction(operation, left, right)
		}
	}

	#[cfg(test)]
	pub(crate) fn from_constraint(needs: Constraint) -> Self {
		Self::ordered(needs, |slot| slot.get() as ValueId)
	}

	pub(crate) fn ordered(mut needs: Constraint, rank: impl Fn(SlotIdx) -> ValueId) -> Self {
		needs.sort_by_key(|need| Key(need.1.get(), need.0, rank(need.1)));
		let mut out = Self::any();
		let mut previous: Option<(Key, Value)> = None;
		for (principal, slot, value) in needs.into_iter().rev() {
			let key = Key(slot.get(), principal, rank(slot));
			if let Some((last, seen)) = &previous
				&& *last == key
			{
				if seen.equivalent(&value, true) {
					continue;
				}
				return Self::default();
			}
			previous = Some((key, value.clone()));
			let pin = Self::pin(key, value);
			out = if out.is_unconditional() {
				pin
			} else {
				Self::join(Operation::And, &out, &pin)
			};
			if let Root::Node(node) = &out.0 {
				let _ = node.empty.set(false);
			}
		}
		out
	}

	pub(crate) fn union(&self, other: &Self) -> Self {
		self.combine(other, Operation::Or)
	}
	pub(crate) fn intersect(&self, other: &Self) -> Self {
		self.combine(other, Operation::And)
	}

	fn combine(&self, other: &Self, operation: Operation) -> Self {
		if self.includes(other) {
			return if operation == Operation::And {
				other
			} else {
				self
			}
			.clone();
		}
		if other.includes(self) {
			return if operation == Operation::And {
				self
			} else {
				other
			}
			.clone();
		}
		let out = Self::join(operation, self, other);
		if operation == Operation::And {
			self.remember_included(&out);
			other.remember_included(&out);
		} else {
			out.remember_included(self);
			out.remember_included(other);
		}
		out
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testutil::make_constant;
	use crate::world::diagram::Worlds as Diagram;

	fn accepts(worlds: &Worlds, assignment: &[Value]) -> bool {
		match &worlds.0 {
			Root::Empty => false,
			Root::Any => true,
			Root::Node(node) => match &node.expression {
				Expression::Pin(key, value) => value.equivalent(&assignment[key.0], true),
				Expression::Junction(Operation::And, a, b) => {
					accepts(a, assignment) && accepts(b, assignment)
				}
				Expression::Junction(Operation::Or, a, b) => {
					accepts(a, assignment) || accepts(b, assignment)
				}
			},
		}
	}

	fn same_choice(a: Option<Constraint>, b: Option<Constraint>) -> bool {
		match (a, b) {
			(Some(a), Some(b)) => {
				a.len() == b.len()
					&& a.iter()
						.zip(b)
						.all(|(a, b)| a.0 == b.0 && a.1 == b.1 && a.2.equivalent(&b.2, true))
			}
			(None, None) => true,
			_ => false,
		}
	}

	#[test]
	fn factored_operations_match_diagrams_and_complete_truth_tables() {
		let values = (0..3)
			.map(|i| make_constant(&format!("factored_truth_{i}")))
			.collect::<Vec<_>>();
		let mut formulas = vec![
			(Worlds::default(), Diagram::default()),
			(Worlds::any(), Diagram::any()),
		];
		for slot in 0..3 {
			for value in &values[..2] {
				let pin = vec![(1, SlotIdx(slot), value.clone())];
				formulas.push((
					Worlds::from_constraint(pin.clone()),
					Diagram::from_constraint(pin),
				));
			}
		}
		let atoms = formulas.clone();
		for (a, ar) in &atoms {
			for (b, br) in &atoms {
				formulas.push((a.union(b), ar.union(br)));
				formulas.push((a.intersect(b), ar.intersect(br)));
			}
		}
		for (a, ar) in &formulas {
			assert_eq!(a.is_empty(), ar.is_empty());
			assert_eq!(a.is_unconditional(), ar.is_unconditional());
			assert!(same_choice(a.choose(), ar.choose()));
			for (b, br) in &formulas {
				let union = a.union(b);
				let intersection = a.intersect(b);
				let mut subset = true;
				assert!(union.equivalent(&b.union(a)));
				assert!(intersection.equivalent(&b.intersect(a)));
				assert!(same_choice(union.choose(), ar.union(br).choose()));
				assert!(same_choice(
					intersection.choose(),
					ar.intersect(br).choose()
				));
				for x in &values {
					for y in &values {
						for z in &values {
							let assignment = [x.clone(), y.clone(), z.clone()];
							let (a, b) = (accepts(a, &assignment), accepts(b, &assignment));
							subset &= !a || b;
							assert_eq!(accepts(&union, &assignment), a || b);
							assert_eq!(accepts(&intersection, &assignment), a && b);
						}
					}
				}
				assert_eq!(a.subset_of(b), subset);
			}
		}
	}

	#[test]
	fn incompatible_equalities_survive_hash_collisions_and_cache_rebuilds() {
		let a = Value::primitive(
			crate::primitive::PRIM_HASH,
			vec![make_constant("formula_collision_a")],
			0,
		);
		let b = Value::primitive(
			crate::primitive::PRIM_HASH,
			vec![make_constant("formula_collision_b")],
			0,
		);
		b.as_primitive().unwrap().hash.set(a.hash_value());
		let make = |value: Value| Worlds::from_constraint(vec![(1, SlotIdx(0), value)]);
		let first = make(a.clone());
		let second = make(b.clone());
		assert!(!first.equivalent(&second));
		assert!(first.intersect(&second).is_empty());
		let both = first.union(&second);
		assert!(!both.is_unconditional());
		NODES.with(|cell| *cell.borrow_mut().fresh() = Interner::default());
		DECISIONS.with(|cell| *cell.borrow_mut().fresh() = Decisions::default());
		let repeated = make(a).union(&make(b));
		assert_ne!(both.identity(), repeated.identity());
		assert!(both.equivalent(&repeated));
		assert!(!both.subset_of(&first));
	}

	#[test]
	fn canonical_choices_preserve_sparse_and_forced_receive_histories() {
		let a = make_constant("formula_sparse_choice_a");
		let b = make_constant("formula_sparse_choice_b");
		let mut factored = Worlds::default();
		let mut reference = Diagram::default();
		for slot in 0..128 {
			let constraint = vec![(1, SlotIdx(slot), a.clone())];
			factored = factored.union(&Worlds::ordered(constraint.clone(), |_| 0));
			reference = reference.union(&Diagram::ordered(constraint, |_| 0));
		}
		assert!(same_choice(factored.choose(), reference.choose()));
		assert!(same_choice(
			factored.choose(),
			Some(vec![(1, SlotIdx(127), a.clone())])
		));
		let forced = vec![(1, SlotIdx(64), b.clone())];
		factored = factored.intersect(&Worlds::ordered(forced.clone(), |_| 0));
		reference = reference.intersect(&Diagram::ordered(forced, |_| 0));
		assert!(same_choice(factored.choose(), reference.choose()));
		assert!(same_choice(
			factored.choose(),
			Some(vec![(1, SlotIdx(127), a), (1, SlotIdx(64), b)])
		));
	}

	#[test]
	fn factored_products_keep_every_independent_alternative() {
		let a = make_constant("formula_independent_a");
		let b = make_constant("formula_independent_b");
		let mut out = Worlds::any();
		for slot in 0..128 {
			let first = Worlds::from_constraint(vec![(1, SlotIdx(slot), a.clone())]);
			let second = Worlds::from_constraint(vec![(1, SlotIdx(slot), b.clone())]);
			out = out.intersect(&first.union(&second));
		}
		assert!(!out.is_empty());
		assert!(!out.is_unconditional());
		assert!(accepts(&out, &vec![a; 128]));
		assert!(accepts(&out, &vec![b; 128]));
		assert!(out.height(Operation::And) <= 8);
		let chosen = Worlds::from_constraint(out.choose().unwrap());
		assert!(chosen.subset_of(&out));
		let other = Worlds::from_constraint(vec![(
			1,
			SlotIdx(71),
			make_constant("formula_independent_other"),
		)]);
		assert!(out.intersect(&other).is_empty());
	}

	#[test]
	fn redundant_products_do_not_grow_or_lose_alternatives() {
		let make = |slot| {
			Worlds::from_constraint(vec![(
				1,
				SlotIdx(slot),
				make_constant("formula_absorption"),
			)])
		};
		let a = make(0);
		let b = make(1);
		let c = make(2);
		let product = a.union(&b).intersect(&a.union(&c));
		assert!(product.equivalent(&a.union(&b.intersect(&c))));
		assert!(product.subset_of(&product.union(&make(3))));
		assert!(!product.union(&make(3)).subset_of(&product));
	}

	#[test]
	fn joint_histories_reject_a_conflict_that_every_pair_allows() {
		let first = make_constant("formula_joint_first");
		let second = make_constant("formula_joint_second");
		let pin = |principal, slot, value: &Value| {
			Worlds::from_constraint(vec![(principal, SlotIdx(slot), value.clone())])
		};
		let a = pin(1, 0, &first).union(&pin(1, 1, &first));
		let b = pin(1, 0, &second).union(&pin(1, 1, &first));
		let c = pin(1, 1, &second);
		assert!(!a.intersect(&b).is_empty());
		assert!(!a.intersect(&c).is_empty());
		assert!(!b.intersect(&c).is_empty());
		let impossible = a.intersect(&b).intersect(&c);
		assert!(impossible.is_empty());
		assert!(impossible.choose().is_none());
		assert!(!a.intersect(&b).intersect(&pin(2, 1, &second)).is_empty());
		DECISIONS.with(|cell| *cell.borrow_mut().fresh() = Decisions::default());
		assert!(a.intersect(&b).subset_of(&pin(1, 1, &first)));
		assert!(!a.subset_of(&pin(1, 1, &first)));
	}

	#[test]
	fn proved_implications_help_larger_formulas_without_changing_route_facts() {
		let pin = |slot| {
			Worlds::from_constraint(vec![(
				1,
				SlotIdx(slot),
				make_constant("formula_proved_implication"),
			)])
		};
		let a = pin(0);
		let b = pin(1);
		let c = pin(2);
		let d = pin(3);
		let left = a.union(&b).intersect(&a.union(&c));
		let right = a.union(&b.intersect(&c));
		let mut decisions = Decisions::default();
		assert!(!right.includes(&left));
		assert!(decisions.subset(&left, &right));
		assert!(!right.includes(&left));
		let larger = right.union(&d);
		assert!(left.structurally_implies(&larger, &decisions.supersets));
		assert!(decisions.subset(&left, &larger));
		assert!(!decisions.subset(&left, &right.intersect(&d)));
		assert!(!decisions.subset(&left, &d));
	}

	#[test]
	fn evicted_decisions_remove_the_implications_backed_by_their_pointers() {
		let a = make_constant("formula_fact_eviction_a");
		let b = make_constant("formula_fact_eviction_b");
		let make = |value: &Value| Worlds::from_constraint(vec![(1, SlotIdx(0), value.clone())]);
		let left = make(&a);
		let mut decisions = Decisions::default();
		for (value, expected) in [(&a, true), (&b, false)] {
			for _ in 0..=65_536 {
				NODES.with(|cell| *cell.borrow_mut().fresh() = Interner::default());
				assert_eq!(decisions.subset(&left, &make(value)), expected);
			}
			assert_eq!(decisions.decisions.len(), 65_536);
			assert_eq!(decisions.supersets.len(), usize::from(expected));
			for (&from, targets) in &decisions.supersets {
				for &to in targets {
					assert!(decisions.decisions[&(from, to)].result);
				}
			}
		}
	}

	#[test]
	fn union_inclusions_survive_balancing_without_broadening_route_facts() {
		let pin = |slot| {
			Worlds::from_constraint(vec![(
				1,
				SlotIdx(slot),
				make_constant("formula_balanced_inclusion"),
			)])
		};
		let base = pin(0).union(&pin(1)).union(&pin(2)).union(&pin(3));
		let wider = base.union(&pin(4));
		let extra = pin(7);
		let narrower = base.intersect(&extra);
		assert!(!wider.includes(&narrower));
		assert!(narrower.structurally_implies(&wider, &IdMap::default()));
		assert!(narrower.subset_of(&wider));
		assert!(!wider.includes(&narrower));
		assert!(!extra.subset_of(&wider));
	}

	#[test]
	fn crossed_choices_remain_factored_without_discarding_a_world() {
		let a = make_constant("formula_crossed_a");
		let b = make_constant("formula_crossed_b");
		let pin =
			|slot, value: &Value| Worlds::from_constraint(vec![(1, SlotIdx(slot), value.clone())]);
		let mut out = Worlds::any();
		for slot in 0..64 {
			out = out.intersect(&pin(slot, &a).union(&pin(slot + 64, &a)));
		}
		let mut seen = IdSet::default();
		let mut pending = vec![&out];
		while let Some(next) = pending.pop() {
			if !seen.insert(next.identity()) {
				continue;
			}
			if let Root::Node(node) = &next.0
				&& let Expression::Junction(_, left, right) = &node.expression
			{
				pending.extend([left, right]);
			}
		}
		assert_eq!(seen.len(), 255);
		assert!(!out.is_empty());
		for slot in 0..64 {
			assert!(!out.intersect(&pin(slot, &b)).is_empty());
			assert!(
				out.intersect(&pin(slot, &b))
					.intersect(&pin(slot + 64, &b))
					.is_empty()
			);
		}
		assert!(Worlds::from_constraint(out.choose().unwrap()).subset_of(&out));
	}
}
