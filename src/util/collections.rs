/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::hash::{BuildHasherDefault, Hasher};

#[derive(Default)]
pub(crate) struct IdHasher(u64);

impl Hasher for IdHasher {
	fn finish(&self) -> u64 {
		self.0
	}
	fn write(&mut self, bytes: &[u8]) {
		for &b in bytes {
			self.write_u64(b as u64);
		}
	}
	fn write_u8(&mut self, i: u8) {
		self.write_u64(i as u64);
	}
	fn write_u32(&mut self, i: u32) {
		self.write_u64(i as u64);
	}
	fn write_usize(&mut self, i: usize) {
		self.write_u64(i as u64);
	}
	fn write_u64(&mut self, i: u64) {
		let mut x = self.0.rotate_left(11) ^ i;
		x ^= x >> 33;
		x = x.wrapping_mul(0xff51afd7ed558ccd);
		x ^= x >> 33;
		x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
		self.0 = x ^ (x >> 33);
	}
}

pub(crate) type IdMap<K, V> = std::collections::HashMap<K, V, BuildHasherDefault<IdHasher>>;

pub(crate) type IdSet<K> = std::collections::HashSet<K, BuildHasherDefault<IdHasher>>;

pub(crate) fn append_unique<T: PartialEq>(vec: &mut Vec<T>, value: T) {
	if !vec.contains(&value) {
		vec.push(value);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn append_unique_keeps_the_first_of_each() {
		let mut v = vec![1, 2];
		append_unique(&mut v, 3);
		append_unique(&mut v, 2);
		assert_eq!(v, vec![1, 2, 3]);
	}
}
