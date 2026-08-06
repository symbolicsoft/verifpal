/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Capability {
	Weak,
	Forgeable,
	Malleable,
}

impl Capability {
	pub const ALL: [Capability; 3] = [
		Capability::Weak,
		Capability::Forgeable,
		Capability::Malleable,
	];

	pub fn index(self) -> usize {
		match self {
			Capability::Weak => 0,
			Capability::Forgeable => 1,
			Capability::Malleable => 2,
		}
	}

	pub fn name(self) -> &'static str {
		match self {
			Capability::Weak => "weak",
			Capability::Forgeable => "forgeable",
			Capability::Malleable => "malleable",
		}
	}

	pub fn from_name(s: &str) -> Option<Capability> {
		Capability::ALL
			.into_iter()
			.find(|c| c.name().eq_ignore_ascii_case(s))
	}
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Capabilities {
	onset: [i32; 3],
}

const ABSENT: i32 = -1;

impl Default for Capabilities {
	fn default() -> Self {
		Capabilities { onset: [ABSENT; 3] }
	}
}

impl Capabilities {
	pub fn is_empty(&self) -> bool {
		self.onset.iter().all(|&o| o == ABSENT)
	}

	pub fn set(&mut self, cap: Capability, from_phase: i32) {
		self.onset[cap.index()] = from_phase.max(0);
	}

	pub fn has(&self, cap: Capability) -> bool {
		self.onset[cap.index()] != ABSENT
	}

	pub fn onset(&self, cap: Capability) -> Option<i32> {
		match self.onset[cap.index()] {
			ABSENT => None,
			o => Some(o),
		}
	}

	pub fn in_force(&self, cap: Capability, phase: i32) -> bool {
		match self.onset(cap) {
			Some(o) => phase >= o,
			None => false,
		}
	}

	pub fn iter(&self) -> impl Iterator<Item = (Capability, i32)> + '_ {
		Capability::ALL
			.into_iter()
			.filter_map(|c| self.onset(c).map(|o| (c, o)))
	}

	pub fn merge(&mut self, other: &Capabilities) {
		for (cap, onset) in other.iter() {
			match self.onset(cap) {
				Some(existing) if existing <= onset => {}
				_ => self.set(cap, onset),
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn default_capabilities_are_empty() {
		let c = Capabilities::default();
		assert!(c.is_empty());
		for cap in Capability::ALL {
			assert!(!c.has(cap));
			assert_eq!(c.onset(cap), None);
			assert!(!c.in_force(cap, 0));
			assert!(!c.in_force(cap, 99));
		}
	}

	#[test]
	fn phase_zero_capability_is_in_force_everywhere() {
		let mut c = Capabilities::default();
		c.set(Capability::Weak, 0);
		assert!(c.in_force(Capability::Weak, 0));
		assert!(c.in_force(Capability::Weak, 3));
		assert!(!c.in_force(Capability::Forgeable, 0));
	}

	#[test]
	fn delayed_capability_is_in_force_from_onset_onward() {
		let mut c = Capabilities::default();
		c.set(Capability::Weak, 2);
		assert!(!c.in_force(Capability::Weak, 0));
		assert!(!c.in_force(Capability::Weak, 1));
		assert!(c.in_force(Capability::Weak, 2));
		assert!(c.in_force(Capability::Weak, 7));
	}

	#[test]
	fn merge_takes_the_earlier_onset() {
		let mut a = Capabilities::default();
		a.set(Capability::Weak, 5);
		let mut b = Capabilities::default();
		b.set(Capability::Weak, 2);
		b.set(Capability::Forgeable, 1);
		a.merge(&b);
		assert_eq!(a.onset(Capability::Weak), Some(2));
		assert_eq!(a.onset(Capability::Forgeable), Some(1));
	}

	#[test]
	fn iter_yields_only_declared_capabilities_in_order() {
		let mut c = Capabilities::default();
		c.set(Capability::Malleable, 3);
		c.set(Capability::Weak, 0);
		let got: Vec<_> = c.iter().collect();
		assert_eq!(got, vec![(Capability::Weak, 0), (Capability::Malleable, 3)]);
	}

	#[test]
	fn from_name_is_case_insensitive_and_rejects_unknown() {
		assert_eq!(Capability::from_name("weak"), Some(Capability::Weak));
		assert_eq!(
			Capability::from_name("FORGEABLE"),
			Some(Capability::Forgeable)
		);
		assert_eq!(Capability::from_name("nonsense"), None);
	}
}
