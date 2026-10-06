/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::Arc;

use super::{PrincipalId, VResult, VerifpalError};
use crate::term::{COPY_STRIDE, ValueId};

pub(crate) const ATTACKER_ID: PrincipalId = 0;
pub(crate) const ATTACKER_NAME: &str = "Attacker";

pub(crate) struct PrincipalNames {
	map: HashMap<Arc<str>, PrincipalId>,
	names: Vec<Arc<str>>,
}

impl Default for PrincipalNames {
	fn default() -> Self {
		Self::new()
	}
}

impl PrincipalNames {
	pub(crate) fn new() -> Self {
		let mut map = HashMap::new();
		map.insert(Arc::from(ATTACKER_NAME), ATTACKER_ID);
		PrincipalNames {
			map,
			names: vec![Arc::from(ATTACKER_NAME)],
		}
	}

	pub(crate) fn intern(&mut self, name: &str) -> VResult<PrincipalId> {
		if let Some(&id) = self.map.get(name) {
			return Ok(id);
		}
		let next = self.names.len();
		if next > PrincipalId::MAX as usize {
			return Err(VerifpalError::sanity(
				format!(
					"more than {} distinct principal names",
					PrincipalId::MAX as usize
				)
				.into(),
			));
		}
		let id = next as PrincipalId;
		let arc_name: Arc<str> = Arc::from(name);
		self.map.insert(Arc::clone(&arc_name), id);
		self.names.push(arc_name);
		Ok(id)
	}

	pub(crate) fn name_of(&self, id: PrincipalId) -> Arc<str> {
		self.names
			.get(id as usize)
			.cloned()
			.unwrap_or_else(|| Arc::from(""))
	}
}

pub(crate) struct ValueNames {
	map: HashMap<Arc<str>, ValueId>,
	counter: ValueId,
}

impl Default for ValueNames {
	fn default() -> Self {
		Self::new()
	}
}

impl ValueNames {
	pub(crate) fn new() -> Self {
		let mut map = HashMap::new();
		map.insert(Arc::from("nil"), 1);
		ValueNames { map, counter: 2 }
	}

	pub(crate) fn intern(&mut self, name: &str) -> VResult<ValueId> {
		if let Some(&id) = self.map.get(name) {
			return Ok(id);
		}
		if self.counter >= COPY_STRIDE {
			return Err(VerifpalError::sanity(
				"model declares too many distinct constants".into(),
			));
		}
		let id = self.counter;
		self.map.insert(Arc::from(name), id);
		self.counter += 1;
		Ok(id)
	}
}

pub(crate) fn base_name(name: &str) -> &str {
	name.split('#').next().unwrap_or(name)
}

pub(crate) fn copy_base_name(name: &str) -> &str {
	let end = name.find(['#', '@']).unwrap_or(name.len());
	&name[..end]
}

pub(crate) const ANONYMOUS_PREFIX: &str = "unnamed";

pub(crate) fn is_anonymous_name(name: &str) -> bool {
	copy_base_name(name).starts_with(ANONYMOUS_PREFIX)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn interning_is_idempotent_and_starts_after_the_attacker() {
		let mut names = PrincipalNames::new();
		let a = names.intern("Alice").expect("intern");
		let b = names.intern("Bob").expect("intern");
		assert_eq!(a, names.intern("Alice").expect("intern"));
		assert_ne!(a, b);
		assert_ne!(a, ATTACKER_ID);
		assert_ne!(b, ATTACKER_ID);
		assert_eq!(&*names.name_of(ATTACKER_ID), ATTACKER_NAME);
	}

	#[test]
	fn exhausting_the_id_space_errors_instead_of_wrapping_onto_the_attacker() {
		let mut names = PrincipalNames::new();
		for i in 0..PrincipalId::MAX {
			let id = names
				.intern(&format!("P{i}"))
				.unwrap_or_else(|e| panic!("id {i} should fit: {e}"));
			assert_ne!(id, ATTACKER_ID, "no principal may alias the attacker");
		}
		assert!(names.intern("OneTooMany").is_err());
	}

	#[test]
	fn a_copy_suffix_is_stripped_by_the_name_helpers() {
		assert_eq!(base_name("alice#2"), "alice");
		assert_eq!(base_name("alice"), "alice");
		assert_eq!(
			base_name("alice@3"),
			"alice@3",
			"base_name strips only the session suffix"
		);
		assert_eq!(copy_base_name("alice#2"), "alice");
		assert_eq!(copy_base_name("alice@3"), "alice");
		assert_eq!(copy_base_name("alice"), "alice");
	}

	#[test]
	fn an_anonymous_name_is_recognised_through_its_copy_suffix() {
		assert!(is_anonymous_name("unnamed_0"));
		assert!(is_anonymous_name("unnamed_0#2"));
		assert!(is_anonymous_name("unnamed_0@3"));
		assert!(
			is_anonymous_name("unnamedish"),
			"the prefix is what `check_reserved` refuses, so anything carrying it counts"
		);
		assert!(!is_anonymous_name("named_0"));
		assert!(!is_anonymous_name(""));
	}
}
