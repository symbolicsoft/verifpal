/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::*;

// ---------------------------------------------------------------------------
// Equivalence helpers
// ---------------------------------------------------------------------------

/// Result of comparing two primitives for structural equivalence.
pub struct PrimitiveMatch {
	pub equivalent: bool,
	/// Output index of the first primitive (meaningful only when `equivalent` is true).
	pub output_left: usize,
	/// Output index of the second primitive (meaningful only when `equivalent` is true).
	pub output_right: usize,
}

impl PrimitiveMatch {
	fn no_match() -> Self {
		PrimitiveMatch {
			equivalent: false,
			output_left: 0,
			output_right: 0,
		}
	}
}

pub fn equivalent_primitives(
	p1: &Primitive,
	p2: &Primitive,
	consider_output: bool,
) -> PrimitiveMatch {
	if p1.id != p2.id {
		return PrimitiveMatch::no_match();
	}
	if consider_output && (p1.output != p2.output) {
		return PrimitiveMatch::no_match();
	}
	if p1.arguments.len() != p2.arguments.len() {
		return PrimitiveMatch::no_match();
	}
	for (a1, a2) in p1.arguments.iter().zip(p2.arguments.iter()) {
		if !a1.equivalent(a2, true) {
			return PrimitiveMatch::no_match();
		}
	}
	PrimitiveMatch {
		equivalent: true,
		output_left: p1.output,
		output_right: p2.output,
	}
}

/// Check structural equivalence of two equations (DH exponentiation chains).
///
/// Equations model repeated Diffie-Hellman exponentiation: `G^a^b^c` is
/// represented as `[G, a, b, c]`.  The equivalence rules reflect the
/// algebraic properties of DH groups:
///
/// - **Length 1-2**: exact element-wise match (no commutativity for the base).
/// - **Length 3** (`G^a^b`): exponents are commutative due to the DH property
///   `G^a^b = G^b^a`.  We check both orderings: `(a==c && b==d)` or
///   `(a==d && b==c)`.  The base `G` is NOT checked because in a 3-element
///   equation it is always the generator.
/// - **Length >3**: the base (index 0) must match exactly; the remaining
///   exponents are treated as a commutative multiset (checked via
///   permutation matching with a marker array to enforce bijectivity).
pub fn equivalent_equations(e1: &Equation, e2: &Equation) -> bool {
	if e1.values.is_empty() || e2.values.is_empty() {
		return false;
	}
	let (e1f, e2f): (Equation, Equation);
	let (e1_ref, e2_ref): (&Equation, &Equation);
	if equation_is_flat(e1) && equation_is_flat(e2) {
		e1_ref = e1;
		e2_ref = e2;
	} else {
		e1f = flatten_equation(e1);
		e2f = flatten_equation(e2);
		e1_ref = &e1f;
		e2_ref = &e2f;
	}
	if e1_ref.values.len() != e2_ref.values.len() {
		return false;
	}
	match e1_ref.values.len() {
		1 => e1_ref.values[0].equivalent(&e2_ref.values[0], true),
		2 => {
			e1_ref.values[0].equivalent(&e2_ref.values[0], true)
				&& e1_ref.values[1].equivalent(&e2_ref.values[1], true)
		}
		3 => {
			equivalent_equations_rule(
				&e1_ref.values[1],
				&e2_ref.values[1],
				&e1_ref.values[2],
				&e2_ref.values[2],
			) || equivalent_equations_rule(
				&e1_ref.values[1],
				&e2_ref.values[2],
				&e1_ref.values[2],
				&e2_ref.values[1],
			)
		}
		_ => {
			// >3 elements: base must match, exponents are commutative
			if !e1_ref.values[0].equivalent(&e2_ref.values[0], true) {
				return false;
			}
			// Check that exponents [1..] are a permutation of each other
			let n = e1_ref.values.len();
			let mut matched = vec![false; n];
			for i in 1..n {
				let mut found = false;
				for (j, m) in matched.iter_mut().enumerate().skip(1) {
					if !*m && e1_ref.values[i].equivalent(&e2_ref.values[j], true) {
						*m = true;
						found = true;
						break;
					}
				}
				if !found {
					return false;
				}
			}
			true
		}
	}
}

/// Cross-match rule for 3-element DH equations: checks if two (exponent, exponent)
/// pairs match under commutativity.  For `G^a^b == G^c^d`, we need either
/// `(a==c && b==d)` or `(a==d && b==c)`.  This function checks one ordering;
/// the caller invokes it twice with swapped arguments to cover both.
fn equivalent_equations_rule(base1: &Value, base2: &Value, exp1: &Value, exp2: &Value) -> bool {
	base1.equivalent(exp2, true) && exp1.equivalent(base2, true)
}

// ---------------------------------------------------------------------------
// Equation flattening
// ---------------------------------------------------------------------------

/// An equation is "flat" if none of its elements are themselves equations.
/// Flattening normalizes nested DH chains like `(G^a)^b` into `[G, a, b]`
/// so that equivalence comparison works on a canonical form regardless of
/// how the expression was originally constructed.
pub fn equation_is_flat(e: &Equation) -> bool {
	e.values.iter().all(|v| !matches!(v, Value::Equation(_)))
}

pub fn flatten_equation(e: &Equation) -> Equation {
	let mut ef = Equation {
		values: Vec::with_capacity(e.values.len()),
	};
	for v in &e.values {
		if let Value::Equation(inner) = v {
			let eff = flatten_equation(inner);
			ef.values.extend(eff.values);
		} else {
			ef.values.push(v.clone());
		}
	}
	ef
}

// ---------------------------------------------------------------------------
// Find constant in primitive from protocol trace
// ---------------------------------------------------------------------------

pub fn find_constant_in_trace_primitive(
	c: &Constant,
	value: &Value,
	trace: &ProtocolTrace,
) -> bool {
	let target = Value::Constant(c.clone());
	let (_, resolved_values) = crate::resolution::resolve_trace_values(value, trace);
	crate::value::find_equivalent(&target, &resolved_values).is_some()
}
