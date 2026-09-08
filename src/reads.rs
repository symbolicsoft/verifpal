/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::RefCell;

use crate::types::*;

#[derive(Clone, Default)]
pub(crate) struct Reads {
	misses: IdSet<u64>,
	patterns: IdMap<u64, Value>,
	heads: IdSet<(PrimitiveId, usize)>,
	ids: IdSet<PrimitiveId>,
	basis: IdSet<u64>,
	protocol: bool,
}

thread_local! {
	static LOG: RefCell<Option<Reads>> = const { RefCell::new(None) };
}

pub(crate) fn observe<R>(f: impl FnOnce() -> R) -> (R, Reads) {
	let outer = LOG.with(|log| log.replace(Some(Reads::default())));
	let out = f();
	let reads = LOG.with(|log| log.replace(outer)).unwrap_or_default();
	(out, reads)
}

fn note(f: impl FnOnce(&mut Reads)) {
	LOG.with(|log| {
		if let Some(reads) = log.borrow_mut().as_mut() {
			f(reads);
		}
	});
}

pub(crate) fn miss(hash: u64) {
	note(|reads| {
		reads.misses.insert(hash);
	});
}

pub(crate) fn head(id: PrimitiveId, arity: usize) {
	note(|reads| {
		reads.heads.insert((id, arity));
	});
}

pub(crate) fn pattern(pattern: &Value) {
	note(|reads| {
		reads
			.patterns
			.entry(pattern.hash_value())
			.or_insert_with(|| pattern.clone());
	});
}

pub(crate) fn id(id: PrimitiveId) {
	note(|reads| {
		reads.ids.insert(id);
	});
}

pub(crate) fn basis_miss(hash: u64) {
	note(|reads| {
		reads.basis.insert(hash);
	});
}

pub(crate) fn protocol() {
	note(|reads| reads.protocol = true);
}

pub(crate) fn absorb(other: Reads) {
	note(|reads| reads.merge(other));
}

impl Reads {
	pub(crate) fn merge(&mut self, other: Reads) {
		self.misses.extend(other.misses);
		self.patterns.extend(other.patterns);
		self.heads.extend(other.heads);
		self.ids.extend(other.ids);
		self.basis.extend(other.basis);
		self.protocol |= other.protocol;
	}

	pub(crate) fn admits(
		&self,
		attacker: &AttackerState,
		since: usize,
		protocol: &IdSet<u64>,
	) -> bool {
		attacker.known.get(since..).is_some_and(|learned| {
			learned.iter().all(|v| {
				let hash = v.hash_value();
				if self.misses.contains(&hash) || (self.protocol && protocol.contains(&hash)) {
					return false;
				}
				if let Value::Primitive(p) = v
					&& (self.heads.contains(&(p.id, p.arguments.len())) || self.ids.contains(&p.id))
				{
					return false;
				}
				if self.patterns.values().any(|pattern| {
					crate::solve::matching::match_values(pattern, v, &Default::default())
						.next()
						.is_some()
				}) {
					return false;
				}
				self.basis.is_empty()
					|| !crate::value::subterms(v).any(|t| self.basis.contains(&t.hash_value()))
			})
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testutil::*;

	#[test]
	fn a_read_log_admits_only_knowledge_that_answers_no_recorded_read() {
		let a = make_constant("reads_a");
		let b = make_constant("reads_b");
		let hashed = make_primitive(crate::primitive::PRIM_HASH, vec![a.clone()], 0);
		let mac = make_primitive(crate::primitive::PRIM_MAC, vec![a.clone(), b.clone()], 0);
		let basis_terms: IdSet<u64> = [mac.hash_value()].into_iter().collect();
		let (_, reads) = observe(|| {
			miss(b.hash_value());
			head(crate::primitive::PRIM_HASH, 1);
			basis_miss(a.hash_value());
		});
		let grown = |extra: Vec<Value>| {
			let mut known = vec![crate::value::value_nil()];
			known.extend(extra);
			make_attacker_state(known)
		};
		assert!(reads.admits(&grown(vec![]), 1, &basis_terms));
		assert!(!reads.admits(&grown(vec![b.clone()]), 1, &basis_terms));
		assert!(!reads.admits(&grown(vec![hashed.clone()]), 1, &basis_terms));
		assert!(!reads.admits(&grown(vec![mac.clone()]), 1, &basis_terms));
		let (_, none) = observe(|| {});
		assert!(none.admits(&grown(vec![b, hashed, mac.clone()]), 1, &basis_terms));
		let (_, scans) = observe(protocol);
		assert!(!scans.admits(&grown(vec![mac]), 1, &basis_terms));
		let variable = crate::solve::vars::attacker_var(0, "reads_pattern_var");
		let (_, patterns) = observe(|| {
			pattern(&make_primitive(
				crate::primitive::PRIM_MAC,
				vec![variable, crate::value::value_nil()],
				0,
			))
		});
		let over_nil = make_primitive(
			crate::primitive::PRIM_MAC,
			vec![crate::value::value_nil(), crate::value::value_nil()],
			0,
		);
		let over_a = make_primitive(crate::primitive::PRIM_MAC, vec![a.clone(), a], 0);
		assert!(!patterns.admits(&grown(vec![over_nil.clone()]), 1, &basis_terms));
		assert!(patterns.admits(&grown(vec![over_a]), 1, &basis_terms));
		let (_, ids) = observe(|| id(crate::primitive::PRIM_MAC));
		assert!(!ids.admits(&grown(vec![over_nil]), 1, &basis_terms));
	}
}
