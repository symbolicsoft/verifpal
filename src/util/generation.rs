/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::Cell;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use super::IdMap;
use super::sync::write_lock;

thread_local! {
	static CURRENT_GENERATION: Cell<u64> = const { Cell::new(0) };
}

static ANALYSIS_GENERATION: AtomicU64 = AtomicU64::new(0);

static LIVE_GENERATIONS: RwLock<Vec<u64>> = RwLock::new(Vec::new());

#[cfg(feature = "cli")]
pub(crate) fn live_generations() -> usize {
	super::sync::read_lock(&LIVE_GENERATIONS).len()
}

pub(crate) fn next_generation() -> u64 {
	ANALYSIS_GENERATION.fetch_add(1, Ordering::Relaxed) + 1
}

pub(crate) fn enter_generation(generation: u64) {
	CURRENT_GENERATION.with(|g| g.set(generation));
}

pub(crate) fn current_generation() -> u64 {
	CURRENT_GENERATION.with(|g| g.get())
}

pub(crate) struct GenerationGuard(u64);

impl GenerationGuard {
	pub(crate) fn enter() -> GenerationGuard {
		let generation = next_generation();
		write_lock(&LIVE_GENERATIONS).push(generation);
		enter_generation(generation);
		GenerationGuard(generation)
	}
}

impl Drop for GenerationGuard {
	fn drop(&mut self) {
		write_lock(&LIVE_GENERATIONS).retain(|&live| live != self.0);
	}
}

pub(crate) struct Generational<T> {
	generation: u64,
	inner: T,
}

impl<T: Default> Default for Generational<T> {
	fn default() -> Self {
		Generational {
			generation: 0,
			inner: T::default(),
		}
	}
}

impl<T: Default> Generational<T> {
	pub(crate) fn fresh(&mut self) -> &mut T {
		let now = current_generation();
		if self.generation != now {
			self.generation = now;
			self.inner = T::default();
		}
		&mut self.inner
	}
}

const RECENT_GROUPS: usize = 8;

pub(crate) struct Recent<G, K, V> {
	groups: Vec<(G, IdMap<K, V>)>,
}

impl<G, K, V> Default for Recent<G, K, V> {
	fn default() -> Self {
		Recent { groups: Vec::new() }
	}
}

impl<G: PartialEq, K: std::hash::Hash + Eq, V> Recent<G, K, V> {
	pub(crate) fn group(&mut self, group: G) -> &mut IdMap<K, V> {
		match self.groups.iter().position(|(seen, _)| *seen == group) {
			Some(0) => {}
			Some(at) => {
				let found = self.groups.remove(at);
				self.groups.insert(0, found);
			}
			None => {
				self.groups.truncate(RECENT_GROUPS - 1);
				self.groups.insert(0, (group, IdMap::default()));
			}
		}
		&mut self.groups[0].1
	}
}
