/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::RefCell;
use std::sync::Arc;

use super::attacker::{AttackerState, KnownIdx};
use crate::primitive::CapabilityIndex;
use crate::term::{Primitive, Value};
use crate::util::IdMap;

pub(super) struct ObtainableMemo {
	owner: (usize, usize),
	pub(super) entries: IdMap<u64, Vec<(Value, bool)>>,
	pub(super) pointers: IdMap<usize, (Arc<Primitive>, bool)>,
	pub(super) inputs: IdMap<usize, (Arc<Primitive>, Option<Vec<KnownIdx>>)>,
}

impl ObtainableMemo {
	fn new(capabilities: &CapabilityIndex, attacker: &AttackerState) -> Self {
		ObtainableMemo {
			owner: (
				capabilities as *const CapabilityIndex as usize,
				attacker as *const AttackerState as usize,
			),
			entries: IdMap::default(),
			pointers: IdMap::default(),
			inputs: IdMap::default(),
		}
	}

	fn is_for(&self, capabilities: &CapabilityIndex, attacker: &AttackerState) -> bool {
		self.owner
			== (
				capabilities as *const CapabilityIndex as usize,
				attacker as *const AttackerState as usize,
			)
	}
}

#[derive(Default)]
pub(crate) struct SavedMemo(Option<ObtainableMemo>);

impl SavedMemo {
	pub(crate) fn within<R>(
		&mut self,
		capabilities: &CapabilityIndex,
		attacker: &AttackerState,
		f: impl FnOnce() -> R,
	) -> R {
		let memo = self
			.0
			.take()
			.filter(|memo| memo.is_for(capabilities, attacker))
			.unwrap_or_else(|| ObtainableMemo::new(capabilities, attacker));
		let previous = MEMO.with(|m| m.borrow_mut().replace(memo));
		let out = f();
		self.0 = MEMO.with(|m| std::mem::replace(&mut *m.borrow_mut(), previous));
		out
	}
}

pub(super) fn with_memo<R>(
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
	f: impl FnOnce(&mut ObtainableMemo) -> R,
) -> Option<R> {
	MEMO.with(|m| {
		m.borrow_mut()
			.as_mut()
			.filter(|memo| memo.is_for(capabilities, attacker))
			.map(f)
	})
}

thread_local! {
	static MEMO: RefCell<Option<ObtainableMemo>> = const { RefCell::new(None) };
}

pub(crate) struct DeductionMemo<'a> {
	previous: Option<Option<ObtainableMemo>>,
	borrowed: std::marker::PhantomData<(&'a CapabilityIndex, &'a AttackerState)>,
}

impl<'a> DeductionMemo<'a> {
	pub(crate) fn ensure(
		capabilities: &'a CapabilityIndex,
		attacker: &'a AttackerState,
	) -> DeductionMemo<'a> {
		if with_memo(capabilities, attacker, |_| ()).is_some() {
			return DeductionMemo {
				previous: None,
				borrowed: std::marker::PhantomData,
			};
		}
		Self::scoped(capabilities, attacker)
	}

	pub(crate) fn scoped(
		capabilities: &'a CapabilityIndex,
		attacker: &'a AttackerState,
	) -> DeductionMemo<'a> {
		let installed = ObtainableMemo::new(capabilities, attacker);
		let previous = MEMO.with(|m| m.borrow_mut().replace(installed));
		DeductionMemo {
			previous: Some(previous),
			borrowed: std::marker::PhantomData,
		}
	}
}

impl Drop for DeductionMemo<'_> {
	fn drop(&mut self) {
		if let Some(previous) = self.previous.take() {
			MEMO.with(|m| *m.borrow_mut() = previous);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::PRIM_HASH;
	use crate::testing::*;
	use crate::theory::obtainable;

	#[test]
	fn an_unscoped_deduction_walks_a_shared_term_once() {
		let leaf = make_constant("unscoped_deduction_leaf");
		let capabilities = CapabilityIndex::default();
		let known = make_attacker_state(vec![leaf.clone()]);
		let unknown = make_attacker_state(vec![]);
		let mut term = leaf;
		for _ in 0..40 {
			term = make_primitive(PRIM_HASH, vec![term.clone(), term.clone(), term], 0);
		}
		assert!(MEMO.with(|memo| memo.borrow().is_none()));
		assert!(obtainable(&term, &capabilities, &known));
		assert!(!obtainable(&term, &capabilities, &unknown));
		assert!(MEMO.with(|memo| memo.borrow().is_none()));
		let _scope = DeductionMemo::scoped(&capabilities, &unknown);
		assert!(!obtainable(&term, &capabilities, &unknown));
		assert!(obtainable(&term, &capabilities, &known));
		assert!(!obtainable(&term, &capabilities, &unknown));
		assert!(MEMO.with(|memo| {
			memo.borrow()
				.as_ref()
				.unwrap()
				.is_for(&capabilities, &unknown)
		}));
	}
}
