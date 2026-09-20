/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::Generational;
use crate::types::{Constraint, IdMap, IdSet, PrincipalId, SlotIdx, Value, ValueId};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::{Arc, Weak};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
	Branch(Arc<Node>),
}

#[derive(Debug)]
struct Node {
	key: Key,
	edges: Vec<(Value, Worlds)>,
	fallback: Worlds,
	hash: u64,
}

impl Node {
	fn matching(&self, value: &Value) -> Option<&Worlds> {
		let hash = value.hash_value();
		let at = self
			.edges
			.partition_point(|(value, _)| value.hash_value() < hash);
		self.edges[at..]
			.iter()
			.take_while(|(value, _)| value.hash_value() == hash)
			.find(|(candidate, _)| candidate.equivalent(value, true))
			.map(|(_, child)| child)
	}
}

#[derive(Default)]
struct Interner {
	nodes: IdMap<u64, Vec<Weak<Node>>>,
	insertions: usize,
}

struct Applied {
	_inputs: [Weak<Node>; 2],
	result: Cached,
	_retained: Option<Worlds>,
}

enum Cached {
	Empty,
	Any,
	Branch(Weak<Node>),
}

impl Applied {
	fn new(left: &Worlds, right: &Worlds, result: &Worlds) -> Self {
		let (Root::Branch(left), Root::Branch(right)) = (&left.0, &right.0) else {
			unreachable!();
		};
		Self {
			_inputs: [Arc::downgrade(left), Arc::downgrade(right)],
			_retained: None,
			result: match &result.0 {
				Root::Empty => Cached::Empty,
				Root::Any => Cached::Any,
				Root::Branch(node) => Cached::Branch(Arc::downgrade(node)),
			},
		}
	}

	fn result(&self) -> Option<Worlds> {
		Some(Worlds(match &self.result {
			Cached::Empty => Root::Empty,
			Cached::Any => Root::Any,
			Cached::Branch(node) => Root::Branch(node.upgrade()?),
		}))
	}
}

type ApplicationKey = (usize, usize, u8);

#[derive(Default)]
struct Applications {
	entries: IdMap<ApplicationKey, Applied>,
	order: VecDeque<ApplicationKey>,
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

impl Applications {
	fn insert(&mut self, key: ApplicationKey, entry: Applied, capacity: usize) {
		if self.entries.len() >= capacity
			&& let Some(oldest) = self.order.pop_front()
		{
			self.entries.remove(&oldest);
		}
		if self.entries.insert(key, entry).is_none() {
			self.order.push_back(key);
		}
	}
}

thread_local! {
	static NODES: RefCell<Generational<Interner>> = RefCell::new(Generational::default());
	static APPLICATIONS: RefCell<Generational<Applications>> = RefCell::new(Generational::default());
	static COMPLETED: RefCell<Generational<Applications>> = RefCell::new(Generational::default());
	static INCLUSIONS: RefCell<Generational<Inclusions>> = RefCell::new(Generational::default());
}

impl Worlds {
	pub(crate) fn any() -> Self {
		Self(Root::Any)
	}

	pub(crate) fn is_empty(&self) -> bool {
		matches!(self.0, Root::Empty)
	}

	pub(crate) fn is_unconditional(&self) -> bool {
		matches!(self.0, Root::Any)
	}

	pub(crate) fn choose(&self) -> Option<Constraint> {
		match &self.0 {
			Root::Empty => None,
			Root::Any => Some(Vec::new()),
			Root::Branch(node) => {
				if let Some(needs) = node.fallback.choose() {
					return Some(needs);
				}
				node.edges.iter().find_map(|(value, next)| {
					let mut needs = next.choose()?;
					needs.push((node.key.1, SlotIdx(node.key.0), value.clone()));
					Some(needs)
				})
			}
		}
	}

	#[cfg(test)]
	fn subset_of(&self, other: &Self) -> bool {
		fn visit(a: &Worlds, b: &Worlds, memo: &mut IdMap<(usize, usize), bool>) -> bool {
			if a.identity() == b.identity() || a.is_empty() || b.is_unconditional() {
				return true;
			}
			if a.is_unconditional() || b.is_empty() {
				return false;
			}
			let key = (a.identity(), b.identity());
			if let Some(hit) = memo.get(&key) {
				return *hit;
			}
			let cached_key = (key.0, key.1, 2);
			if let Some(hit) = APPLICATIONS.with(|cell| {
				cell.borrow_mut()
					.fresh()
					.entries
					.get(&cached_key)
					.and_then(Applied::result)
					.map(|result| result.is_unconditional())
			}) {
				return hit;
			}
			let (Root::Branch(left), Root::Branch(right)) = (&a.0, &b.0) else {
				unreachable!();
			};
			let result = if left.key == right.key {
				visit(&left.fallback, &right.fallback, memo)
					&& left.edges.iter().all(|(value, child)| {
						visit(
							child,
							right.matching(value).unwrap_or(&right.fallback),
							memo,
						)
					}) && right.edges.iter().all(|(value, child)| {
					left.matching(value).is_some() || visit(&left.fallback, child, memo)
				})
			} else if left.key < right.key {
				visit(&left.fallback, b, memo)
					&& left.edges.iter().all(|(_, child)| visit(child, b, memo))
			} else {
				visit(a, &right.fallback, memo)
					&& right.edges.iter().all(|(_, child)| visit(a, child, memo))
			};
			memo.insert(key, result);
			APPLICATIONS.with(|cell| {
				cell.borrow_mut().fresh().insert(
					cached_key,
					Applied::new(
						a,
						b,
						&if result {
							Worlds::any()
						} else {
							Worlds::default()
						},
					),
					262_144,
				);
			});
			result
		}
		self.completed(other, 2, || {
			if visit(self, other, &mut IdMap::default()) {
				Self::any()
			} else {
				Self::default()
			}
		})
		.is_unconditional()
	}

	fn identity(&self) -> usize {
		match &self.0 {
			Root::Empty => 0,
			Root::Any => 1,
			Root::Branch(node) => Arc::as_ptr(node) as usize,
		}
	}

	fn hash(&self) -> u64 {
		match &self.0 {
			Root::Empty => 0,
			Root::Any => 1,
			Root::Branch(node) => node.hash,
		}
	}

	pub(crate) fn equivalent(&self, other: &Self) -> bool {
		fn visit(a: &Worlds, b: &Worlds, seen: &mut IdSet<(usize, usize)>) -> bool {
			if a.identity() == b.identity() {
				return true;
			}
			let (Root::Branch(a_node), Root::Branch(b_node)) = (&a.0, &b.0) else {
				return false;
			};
			if a_node.hash != b_node.hash
				|| a_node.key != b_node.key
				|| a_node.edges.len() != b_node.edges.len()
			{
				return false;
			}
			if !seen.insert((a.identity(), b.identity())) {
				return true;
			}
			visit(&a_node.fallback, &b_node.fallback, seen)
				&& a_node.edges.iter().all(|(value, next)| {
					b_node
						.matching(value)
						.is_some_and(|tail| visit(next, tail, seen))
				})
		}
		visit(self, other, &mut IdSet::default())
	}

	fn branch(key: Key, mut edges: Vec<(Value, Worlds)>, fallback: Worlds) -> Self {
		edges.retain(|(_, next)| !next.equivalent(&fallback));
		if edges.is_empty() {
			return fallback;
		}
		edges.sort_by_key(|(value, _)| value.hash_value());
		let mut hash = (key.0 as u64).wrapping_mul(0x9E37_79B1)
			^ (key.1 as u64).wrapping_mul(0x85EB_CA77)
			^ fallback.hash().rotate_left(17);
		for (value, next) in &edges {
			let edge = value
				.hash_value()
				.wrapping_mul(0xC2B2_AE3D)
				.wrapping_add(next.hash().rotate_left(29));
			hash ^= (edge ^ (edge >> 31)).wrapping_mul(0x9E37_79B1_85EB_CA87);
		}
		let candidate = Self(Root::Branch(Arc::new(Node {
			key,
			edges,
			fallback,
			hash,
		})));
		NODES.with(|cell| {
			let mut cache = cell.borrow_mut();
			let cache = cache.fresh();
			cache.insertions += 1;
			let nodes = &mut cache.nodes;
			if cache.insertions.is_multiple_of(65_536) {
				nodes.retain(|_, bucket| {
					bucket.retain(|node| node.strong_count() != 0);
					!bucket.is_empty()
				});
			}
			let bucket = nodes.entry(hash).or_default();
			bucket.retain(|node| node.strong_count() != 0);
			for existing in bucket.iter().filter_map(Weak::upgrade) {
				let existing = Self(Root::Branch(existing));
				if candidate.equivalent(&existing) {
					return existing;
				}
			}
			if let Root::Branch(node) = &candidate.0 {
				bucket.push(Arc::downgrade(node));
			}
			candidate
		})
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
			out = Self::branch(key, vec![(value, out)], Self::default());
		}
		out
	}

	pub(crate) fn union(&self, other: &Self) -> Self {
		self.combine(other, false)
	}

	pub(crate) fn intersect(&self, other: &Self) -> Self {
		self.combine(other, true)
	}

	pub(crate) fn includes(&self, other: &Self) -> bool {
		if self.identity() == other.identity() || self.is_unconditional() || other.is_empty() {
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

	fn remember_included(&self, other: &Self) {
		if let (Root::Branch(parent), Root::Branch(child)) = (&self.0, &other.0) {
			INCLUSIONS.with(|cell| cell.borrow_mut().fresh().remember(parent, child));
		}
	}

	fn combine(&self, other: &Self, intersect: bool) -> Self {
		if self.includes(other) {
			return if intersect { other } else { self }.clone();
		}
		if other.includes(self) {
			return if intersect { self } else { other }.clone();
		}
		let out = self.completed(other, u8::from(intersect), || {
			self.apply(other, intersect, &mut IdMap::default())
		});
		if intersect {
			self.remember_included(&out);
			other.remember_included(&out);
		} else {
			out.remember_included(self);
			out.remember_included(other);
		}
		out
	}

	fn completed(&self, other: &Self, operation: u8, compute: impl FnOnce() -> Self) -> Self {
		if self.identity() == other.identity()
			|| !matches!((&self.0, &other.0), (Root::Branch(_), Root::Branch(_)))
		{
			return compute();
		}
		let mut key = (self.identity(), other.identity(), operation);
		if operation != 2 && key.0 > key.1 {
			(key.0, key.1) = (key.1, key.0);
		}
		if let Some(hit) = COMPLETED.with(|cell| {
			cell.borrow_mut()
				.fresh()
				.entries
				.get(&key)
				.and_then(Applied::result)
		}) {
			return hit;
		}
		let result = compute();
		COMPLETED.with(|cell| {
			let mut entry = Applied::new(self, other, &result);
			entry._retained = Some(result.clone());
			cell.borrow_mut().fresh().insert(key, entry, 512);
		});
		result
	}

	fn apply(&self, other: &Self, intersect: bool, memo: &mut IdMap<(usize, usize), Self>) -> Self {
		if self.identity() == other.identity() {
			return self.clone();
		}
		match (&self.0, &other.0, intersect) {
			(Root::Empty, _, true) | (_, Root::Empty, true) => return Self::default(),
			(Root::Any, _, false) | (_, Root::Any, false) => return Self::any(),
			(Root::Empty, _, false) | (Root::Any, _, true) => return other.clone(),
			(_, Root::Empty, false) | (_, Root::Any, true) => return self.clone(),
			_ => {}
		}
		let mut memo_key = (self.identity(), other.identity());
		if memo_key.0 > memo_key.1 {
			memo_key = (memo_key.1, memo_key.0);
		}
		if let Some(hit) = memo.get(&memo_key) {
			return hit.clone();
		}
		let cached_key = (memo_key.0, memo_key.1, u8::from(intersect));
		if let Some(hit) = APPLICATIONS.with(|cell| {
			cell.borrow_mut()
				.fresh()
				.entries
				.get(&cached_key)
				.and_then(Applied::result)
		}) {
			return hit;
		}
		let (Root::Branch(left), Root::Branch(right)) = (&self.0, &other.0) else {
			unreachable!();
		};
		let out = if left.key == right.key {
			let fallback = left.fallback.apply(&right.fallback, intersect, memo);
			let mut unchanged = fallback.identity() == left.fallback.identity();
			let mut edges = Vec::with_capacity(left.edges.len() + right.edges.len());
			for (value, child) in &left.edges {
				let other_child = right.matching(value).unwrap_or(&right.fallback);
				let result = child.apply(other_child, intersect, memo);
				unchanged &= result.identity() == child.identity();
				edges.push((value.clone(), result));
			}
			for (value, child) in &right.edges {
				if left.matching(value).is_none() {
					let result = left.fallback.apply(child, intersect, memo);
					if result.identity() != fallback.identity() {
						unchanged = false;
						edges.push((value.clone(), result));
					}
				}
			}
			if unchanged {
				self.clone()
			} else {
				Self::branch(left.key, edges, fallback)
			}
		} else {
			let (original, first, second) = if left.key < right.key {
				(self, left, other)
			} else {
				(other, right, self)
			};
			let fallback = first.fallback.apply(second, intersect, memo);
			let mut unchanged = fallback.identity() == first.fallback.identity();
			let edges = first
				.edges
				.iter()
				.map(|(value, child)| {
					let result = child.apply(second, intersect, memo);
					unchanged &= result.identity() == child.identity();
					(value.clone(), result)
				})
				.collect();
			if unchanged {
				original.clone()
			} else {
				Self::branch(first.key, edges, fallback)
			}
		};
		memo.insert(memo_key, out.clone());
		APPLICATIONS.with(|cell| {
			let mut cache = cell.borrow_mut();
			let cache = cache.fresh();
			cache.insert(cached_key, Applied::new(self, other, &out), 262_144);
		});
		out
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testutil::make_constant;
	use crate::types::SlotIdx;

	#[test]
	fn colliding_term_hashes_still_name_different_worlds() {
		let left = Value::primitive(
			crate::primitive::PRIM_HASH,
			vec![make_constant("diagram_collision_left")],
			0,
		);
		let right = Value::primitive(
			crate::primitive::PRIM_HASH,
			vec![make_constant("diagram_collision_right")],
			0,
		);
		right.as_primitive().unwrap().hash.set(left.hash_value());
		let a = Worlds::from_constraint(vec![(1, SlotIdx(0), left.clone())]);
		let b = Worlds::from_constraint(vec![(1, SlotIdx(0), right.clone())]);
		assert_eq!(a.hash(), b.hash());
		assert!(!a.equivalent(&b));
		assert!(a.intersect(&b).is_empty());
		let either = a.union(&b);
		assert!(accepts(&either, &[left]));
		assert!(accepts(&either, &[right]));
		assert!(!either.is_unconditional());
	}

	#[test]
	fn operation_caches_release_evicted_worlds() {
		let left = Worlds::from_constraint(vec![(1, SlotIdx(0), make_constant("cache_left"))]);
		let right = Worlds::from_constraint(vec![(1, SlotIdx(1), make_constant("cache_right"))]);
		let Root::Branch(node) = &left.0 else {
			panic!("expected a constrained world");
		};
		let observed = Arc::downgrade(node);
		let both = left.intersect(&right);
		let either = left.union(&right);
		assert!(!both.is_empty());
		assert!(!either.is_unconditional());
		drop((left, right, both, either));
		COMPLETED.with(|cell| *cell.borrow_mut().fresh() = Applications::default());
		assert!(observed.upgrade().is_none());
	}

	#[test]
	fn worlds_remain_equal_across_interner_eviction() {
		let pin = vec![(1, SlotIdx(0), make_constant("diagram_eviction"))];
		let before = Worlds::from_constraint(pin.clone());
		NODES.with(|cell| cell.borrow_mut().fresh().nodes.clear());
		let after = Worlds::from_constraint(pin);
		assert_ne!(before.identity(), after.identity());
		assert!(before.equivalent(&after));
		assert!(before.union(&after).equivalent(&before));
		assert!(before.intersect(&after).equivalent(&before));
	}

	fn accepts(worlds: &Worlds, assignment: &[Value]) -> bool {
		match &worlds.0 {
			Root::Empty => false,
			Root::Any => true,
			Root::Branch(node) => accepts(
				node.edges
					.iter()
					.find(|(value, _)| value.equivalent(&assignment[node.key.0], true))
					.map_or(&node.fallback, |(_, next)| next),
				assignment,
			),
		}
	}

	#[test]
	fn decision_operations_preserve_the_complete_truth_table() {
		let values = (0..3)
			.map(|i| make_constant(&format!("diagram_truth_{i}")))
			.collect::<Vec<_>>();
		let mut formulas = vec![Worlds::default(), Worlds::any()];
		for slot in 0..3 {
			for value in &values[..2] {
				formulas.push(Worlds::from_constraint(vec![(
					1,
					SlotIdx(slot),
					value.clone(),
				)]));
			}
		}
		let atoms = formulas.clone();
		for a in &atoms {
			for b in &atoms {
				formulas.push(a.union(b));
				formulas.push(a.intersect(b));
			}
		}
		for a in &formulas {
			match a.choose() {
				Some(needs) => assert!(Worlds::from_constraint(needs).subset_of(a)),
				None => assert!(a.is_empty()),
			}
			for b in &atoms {
				let union = a.union(b);
				let intersection = a.intersect(b);
				let mut subset = true;
				assert!(union.equivalent(&b.union(a)));
				assert!(intersection.equivalent(&b.intersect(a)));
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
	fn independent_choices_share_their_tails() {
		let a = make_constant("diagram_independent_a");
		let b = make_constant("diagram_independent_b");
		let mut out = Worlds::any();
		for slot in 0..40 {
			let first = Worlds::from_constraint(vec![(1, SlotIdx(slot), a.clone())]);
			let second = Worlds::from_constraint(vec![(1, SlotIdx(slot), b.clone())]);
			out = out.intersect(&first.union(&second));
		}
		let mut nodes = IdSet::default();
		let mut pending = vec![&out];
		while let Some(worlds) = pending.pop() {
			if let Root::Branch(node) = &worlds.0
				&& nodes.insert(worlds.identity())
			{
				pending.extend(node.edges.iter().map(|(_, child)| child));
				pending.push(&node.fallback);
			}
		}
		assert_eq!(nodes.len(), 40);
		assert!(accepts(&out, &vec![a; 40]));
		assert!(accepts(&out, &vec![b; 40]));
	}
}
