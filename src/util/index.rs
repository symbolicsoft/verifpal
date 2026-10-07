/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::fmt;
use std::marker::PhantomData;
use std::ops::{Index, IndexMut};

pub(crate) trait Idx: Copy + Eq + Ord + std::hash::Hash + fmt::Debug {
	fn new(index: usize) -> Self;
	fn index(self) -> usize;

	fn next(self) -> Self {
		Self::new(self.index() + 1)
	}
}

macro_rules! index_type {
	($vis:vis struct $name:ident;) => {
		#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
		$vis struct $name(usize);

		impl std::fmt::Display for $name {
			fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				self.0.fmt(f)
			}
		}

		impl $crate::util::index::Idx for $name {
			fn new(index: usize) -> Self {
				$name(index)
			}

			fn index(self) -> usize {
				self.0
			}
		}
	};
}

pub(crate) use index_type;

pub(crate) struct IndexVec<I, T> {
	raw: Vec<T>,
	index: PhantomData<fn(&I)>,
}

impl<I: Idx, T> IndexVec<I, T> {
	pub(crate) fn new() -> Self {
		IndexVec {
			raw: Vec::new(),
			index: PhantomData,
		}
	}

	pub(crate) fn from_elem(elem: T, len: usize) -> Self
	where
		T: Clone,
	{
		IndexVec::from(vec![elem; len])
	}

	pub(crate) fn len(&self) -> usize {
		self.raw.len()
	}

	pub(crate) fn next_index(&self) -> I {
		I::new(self.raw.len())
	}

	pub(crate) fn push(&mut self, value: T) -> I {
		let at = self.next_index();
		self.raw.push(value);
		at
	}

	pub(crate) fn get(&self, at: I) -> Option<&T> {
		self.raw.get(at.index())
	}

	pub(crate) fn position(&self, predicate: impl FnMut(&T) -> bool) -> Option<I> {
		self.raw.iter().position(predicate).map(I::new)
	}

	pub(crate) fn iter(&self) -> std::slice::Iter<'_, T> {
		self.raw.iter()
	}

	pub(crate) fn indices(&self) -> impl DoubleEndedIterator<Item = I> + Clone + use<I, T> {
		(0..self.raw.len()).map(I::new)
	}

	pub(crate) fn indices_from(&self, start: I) -> impl Iterator<Item = I> + use<I, T> {
		(start.index()..self.raw.len()).map(I::new)
	}

	pub(crate) fn iter_enumerated(&self) -> impl DoubleEndedIterator<Item = (I, &T)> + Clone {
		self.raw.iter().enumerate().map(|(i, v)| (I::new(i), v))
	}

	pub(crate) fn iter_enumerated_mut(&mut self) -> impl DoubleEndedIterator<Item = (I, &mut T)> {
		self.raw.iter_mut().enumerate().map(|(i, v)| (I::new(i), v))
	}

	pub(crate) fn before(&self, end: I) -> &[T] {
		&self.raw[..end.index()]
	}
}

impl<I, T: Clone> Clone for IndexVec<I, T> {
	fn clone(&self) -> Self {
		IndexVec {
			raw: self.raw.clone(),
			index: PhantomData,
		}
	}
}

impl<I, T: fmt::Debug> fmt::Debug for IndexVec<I, T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.raw.fmt(f)
	}
}

impl<I, T> Default for IndexVec<I, T> {
	fn default() -> Self {
		IndexVec {
			raw: Vec::new(),
			index: PhantomData,
		}
	}
}

impl<I, T> From<Vec<T>> for IndexVec<I, T> {
	fn from(raw: Vec<T>) -> Self {
		IndexVec {
			raw,
			index: PhantomData,
		}
	}
}

impl<I, T> FromIterator<T> for IndexVec<I, T> {
	fn from_iter<It: IntoIterator<Item = T>>(iter: It) -> Self {
		IndexVec::from(iter.into_iter().collect::<Vec<T>>())
	}
}

impl<'a, I, T> IntoIterator for &'a IndexVec<I, T> {
	type Item = &'a T;
	type IntoIter = std::slice::Iter<'a, T>;

	fn into_iter(self) -> Self::IntoIter {
		self.raw.iter()
	}
}

impl<'a, I, T> IntoIterator for &'a mut IndexVec<I, T> {
	type Item = &'a mut T;
	type IntoIter = std::slice::IterMut<'a, T>;

	fn into_iter(self) -> Self::IntoIter {
		self.raw.iter_mut()
	}
}

impl<I: Idx, T> Index<I> for IndexVec<I, T> {
	type Output = T;

	fn index(&self, at: I) -> &T {
		&self.raw[at.index()]
	}
}

impl<I: Idx, T> IndexMut<I> for IndexVec<I, T> {
	fn index_mut(&mut self, at: I) -> &mut T {
		&mut self.raw[at.index()]
	}
}
