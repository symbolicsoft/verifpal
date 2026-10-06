/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::primitive::Capability;
use crate::term::Value;
use crate::util::IdMap;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotIdx(pub usize);

impl SlotIdx {
	pub fn get(self) -> usize {
		self.0
	}
}

impl fmt::Display for SlotIdx {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KnownIdx(pub usize);

impl KnownIdx {
	pub fn get(self) -> usize {
		self.0
	}
}

#[derive(Clone, Debug)]
pub enum DerivationRecord {
	Initial,
	Leaked {
		slot: SlotIdx,
	},
	Obtained {
		slot: SlotIdx,
	},
	Decomposed {
		of: Value,
		using: Vec<Value>,
	},
	Reconstructed {
		from: Vec<Value>,
	},
	Combined {
		from: Vec<Value>,
	},
	Recomposed {
		of: Value,
		using: Vec<Value>,
	},
	Fragment {
		of: Value,
	},
	Rewritten {
		of: Value,
		using: Vec<Value>,
		built: bool,
	},
	Broken {
		of: Value,
		capability: Capability,
		using: Vec<Value>,
	},
	Reused {
		of: Value,
		with: Value,
	},
	ReusedForge {
		with: [Value; 2],
		using: Vec<Value>,
	},
}

impl DerivationRecord {
	pub fn ingredients(&self) -> Vec<&Value> {
		match self {
			DerivationRecord::Decomposed { of, using } => {
				let mut v = vec![of];
				v.extend(using.iter());
				v
			}
			DerivationRecord::Recomposed { using, .. }
			| DerivationRecord::Rewritten { using, .. } => using.iter().collect(),
			DerivationRecord::Broken {
				of,
				using,
				capability,
			} => {
				let mut v = Vec::new();
				if matches!(capability, Capability::Weak | Capability::Malleable) {
					v.push(of);
				}
				v.extend(using.iter());
				v
			}
			DerivationRecord::Reused { of, with } => vec![of, with],
			DerivationRecord::ReusedForge { with, using } => {
				let mut v: Vec<&Value> = with.iter().collect();
				v.extend(using.iter());
				v
			}
			DerivationRecord::Reconstructed { from } | DerivationRecord::Combined { from } => {
				from.iter().collect()
			}
			DerivationRecord::Fragment { of } => vec![of],
			DerivationRecord::Initial
			| DerivationRecord::Leaked { .. }
			| DerivationRecord::Obtained { .. } => vec![],
		}
	}
}

#[derive(Clone, Debug)]
pub struct AttackerState {
	pub current_phase: i32,
	pub known: Arc<Vec<Value>>,
	pub known_map: Arc<IdMap<u64, Vec<usize>>>,
	pub derivations: Arc<Vec<DerivationRecord>>,
	pub reused: Arc<Vec<[Value; 2]>>,
	pub chain: u64,
}

static CHAINS: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_chain() -> u64 {
	CHAINS.fetch_add(1, Ordering::Relaxed)
}

impl Default for AttackerState {
	fn default() -> Self {
		AttackerState {
			current_phase: 0,
			known: Arc::new(vec![]),
			known_map: Arc::new(IdMap::default()),
			derivations: Arc::new(vec![]),
			reused: Arc::new(vec![]),
			chain: next_chain(),
		}
	}
}

pub struct DecomposeResult {
	pub revealed: Vec<Value>,
	pub used: Vec<Value>,
}

pub enum Forged {
	Assumption { capability: Capability, of: Value },
	Reuse([Value; 2]),
}

pub struct ReconstructResult {
	pub from: Vec<Value>,
	pub forged: Option<Forged>,
	pub combined: bool,
}

pub struct RecomposeResult {
	pub revealed: Value,
	pub used: Vec<Value>,
}

impl AttackerState {
	pub(crate) fn retaining(&self, keep: &[bool]) -> std::borrow::Cow<'_, AttackerState> {
		assert_eq!(keep.len(), self.known.len());
		if keep.iter().all(|&keep| keep) {
			return std::borrow::Cow::Borrowed(self);
		}
		let known: Vec<Value> = self
			.known
			.iter()
			.zip(keep.iter())
			.filter(|&(_, &keep)| keep)
			.map(|(v, _)| v.clone())
			.collect();
		let mut known_map: IdMap<u64, Vec<usize>> = IdMap::default();
		for (i, v) in known.iter().enumerate() {
			known_map.entry(v.hash_value()).or_default().push(i);
		}
		let derivations = self
			.derivations
			.iter()
			.zip(keep.iter())
			.filter(|&(_, &keep)| keep)
			.map(|(d, _)| d.clone())
			.collect();
		std::borrow::Cow::Owned(AttackerState {
			current_phase: self.current_phase,
			derivations: Arc::new(derivations),
			reused: Arc::clone(&self.reused),
			known: Arc::new(known),
			known_map: Arc::new(known_map),
			chain: crate::theory::attacker::next_chain(),
		})
	}

	pub fn derivation(&self, idx: KnownIdx) -> Option<&DerivationRecord> {
		self.derivations.get(idx.get())
	}

	pub fn knows(&self, v: &Value) -> Option<KnownIdx> {
		self.knows_hashed(v, v.hash_value())
	}

	pub fn knows_hashed(&self, v: &Value, h: u64) -> Option<KnownIdx> {
		self.known_map
			.get(&h)?
			.iter()
			.find(|&&i| v.equivalent(&self.known[i], true))
			.map(|&i| KnownIdx(i))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::*;
	use crate::testing::*;

	#[test]
	fn nonce_reuse_records_list_both_ciphertexts_as_ingredients() {
		let k = make_constant("nrr_k");
		let n = make_constant("nrr_n");
		let ad = make_constant("nrr_ad");
		let e1 = make_primitive(
			PRIM_AEAD_ENC,
			vec![k.clone(), n.clone(), make_constant("nrr_m1"), ad.clone()],
			0,
		);
		let e2 = make_primitive(
			PRIM_AEAD_ENC,
			vec![k, n, make_constant("nrr_m2"), ad.clone()],
			0,
		);
		let reuse = DerivationRecord::Reused {
			of: e1.clone(),
			with: e2.clone(),
		};
		assert_eq!(reuse.ingredients().len(), 2);
		let forged = DerivationRecord::ReusedForge {
			with: [e1, e2],
			using: vec![ad],
		};
		assert_eq!(forged.ingredients().len(), 3);
	}

	#[test]
	fn attacker_knows_value() {
		let a = make_constant("ak_a");
		let b = make_constant("ak_b");
		let c = make_constant("ak_c");
		let attacker = make_attacker_state(vec![a.clone(), b.clone()]);
		assert!(attacker.knows(&a).is_some());
		assert!(attacker.knows(&b).is_some());
		assert!(attacker.knows(&c).is_none());
	}
}
