/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::equivalence::{equation_is_flat, flatten_equation};
use crate::types::*;

// ---------------------------------------------------------------------------
// Hashing helpers
// ---------------------------------------------------------------------------

pub fn primitive_hash(p: &Primitive) -> u64 {
	let mut h = (p.id as u64).wrapping_mul(2654435761) ^ (p.output as u64).wrapping_mul(97);
	for a in &p.arguments {
		h = h.wrapping_mul(31).wrapping_add(a.hash_value());
	}
	h
}

pub fn equation_hash(e: &Equation) -> u64 {
	if equation_is_flat(e) {
		return equation_hash_inner(e);
	}
	let ef = flatten_equation(e);
	equation_hash_inner(&ef)
}

fn equation_hash_inner(e: &Equation) -> u64 {
	match e.values.len() {
		0 => 0,
		1 => e.values[0].hash_value(),
		2 => e.values[0]
			.hash_value()
			.wrapping_mul(31)
			.wrapping_add(e.values[1].hash_value()),
		3 => {
			let mut h1 = e.values[1].hash_value();
			let mut h2 = e.values[2].hash_value();
			// Commutative hash for 3-element DH equations
			if h1 > h2 {
				std::mem::swap(&mut h1, &mut h2);
			}
			e.values[0]
				.hash_value()
				.wrapping_mul(31)
				.wrapping_add(h1.wrapping_mul(17))
				.wrapping_add(h2)
		}
		_ => {
			// >3 elements: commutative hash for exponents (same as DH equivalence)
			let base_h = e.values[0].hash_value();
			let mut exp_hashes: Vec<u64> = e.values[1..].iter().map(|v| v.hash_value()).collect();
			exp_hashes.sort_unstable();
			let mut h = base_h;
			for eh in exp_hashes {
				h = h.wrapping_mul(31).wrapping_add(eh);
			}
			h
		}
	}
}
