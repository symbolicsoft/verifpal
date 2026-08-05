/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::Arc;

use crate::types::{PrincipalId, VResult, VerifpalError};

pub(crate) const ATTACKER_ID: PrincipalId = 0;
pub(crate) const ATTACKER_NAME: &str = "Attacker";

/// Per-model principal name to id table.
///
/// Owned by the parser rather than the process. A global table would keep
/// allocating ids across every model analysed in one process, and since
/// `PrincipalId` is a `u8` the 256th distinct name would wrap onto
/// `ATTACKER_ID` — aliasing a principal with the attacker rather than failing.
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
		// A `PrincipalId` is a `u8`. Allocating past it used to truncate, and
		// the first name to wrap landed on `ATTACKER_ID` — aliasing a principal
		// with the attacker rather than failing.
		let mut names = PrincipalNames::new();
		for i in 0..PrincipalId::MAX {
			let id = names
				.intern(&format!("P{i}"))
				.unwrap_or_else(|e| panic!("id {i} should fit: {e}"));
			assert_ne!(id, ATTACKER_ID, "no principal may alias the attacker");
		}
		assert!(names.intern("OneTooMany").is_err());
	}
}
