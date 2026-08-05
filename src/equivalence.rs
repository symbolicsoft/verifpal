/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::*;

pub(crate) struct PrimitiveMatch {
	pub equivalent: bool,
	pub output_left: usize,
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

pub(crate) fn equivalent_primitives(
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

pub(crate) fn equivalent_equations(e1: &Equation, e2: &Equation) -> bool {
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
			e1_ref.values[0].equivalent(&e2_ref.values[0], true)
				&& (equivalent_equations_rule(
					&e1_ref.values[1],
					&e2_ref.values[1],
					&e1_ref.values[2],
					&e2_ref.values[2],
				) || equivalent_equations_rule(
					&e1_ref.values[1],
					&e2_ref.values[2],
					&e1_ref.values[2],
					&e2_ref.values[1],
				))
		}
		_ => {
			if !e1_ref.values[0].equivalent(&e2_ref.values[0], true) {
				return false;
			}
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

fn equivalent_equations_rule(a1: &Value, b1: &Value, a2: &Value, b2: &Value) -> bool {
	a1.equivalent(b2, true) && a2.equivalent(b1, true)
}

pub(crate) fn equation_is_flat(e: &Equation) -> bool {
	e.values.iter().all(|v| !matches!(v, Value::Equation(_)))
}

pub(crate) fn splice_equation(elements: impl IntoIterator<Item = Value>) -> Equation {
	let elements = elements.into_iter();
	let mut values: Vec<Value> = Vec::with_capacity(elements.size_hint().0);
	for (i, resolved) in elements.enumerate() {
		match &resolved {
			Value::Equation(inner) => {
				if i == 0 {
					values = inner.values.clone();
				} else if inner.values.len() > 1 {
					values.extend(inner.values[1..].iter().cloned());
				}
			}
			_ => values.push(resolved),
		}
	}
	Equation { values }
}

pub(crate) fn flatten_equation(e: &Equation) -> Equation {
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

pub(crate) fn find_constant_in_trace_primitive(
	c: &Constant,
	value: &Value,
	trace: &ProtocolTrace,
) -> bool {
	let target = Value::Constant(c.clone());
	let (_, resolved_values) = crate::resolution::resolve_trace_values(value, trace);
	crate::value::find_equivalent(&target, &resolved_values).is_some()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::*;
	use crate::testutil::*;
	use crate::value::*;
	use std::sync::Arc;

	#[test]
	fn constant_equivalence_same_id() {
		let a = make_constant("test_const_a");
		let b = make_constant("test_const_a");
		assert!(a.equivalent(&b, true));
	}

	#[test]
	fn constant_equivalence_different_id() {
		let a = make_constant("eq_const_x");
		let b = make_constant("eq_const_y");
		assert!(!a.equivalent(&b, true));
	}

	#[test]
	fn equation_equivalence_2_element() {
		let a = make_constant("eq2_a");
		let b = make_constant("eq2_b");
		let e1 = make_equation(vec![value_g(), a.clone()]);
		let e2 = make_equation(vec![value_g(), a.clone()]);
		assert!(e1.equivalent(&e2, true));
		let e3 = make_equation(vec![value_g(), b]);
		assert!(!e1.equivalent(&e3, true));
	}

	#[test]
	fn equation_equivalence_3_element_commutative() {
		let a = make_constant("dh_a");
		let b = make_constant("dh_b");
		let e1 = make_equation(vec![value_g(), a.clone(), b.clone()]);
		let e2 = make_equation(vec![value_g(), b, a]);
		assert!(e1.equivalent(&e2, true));
	}

	#[test]
	fn equation_equivalence_3_element_requires_same_base() {
		let a = make_constant("dh_base_a");
		let b = make_constant("dh_base_b");
		let e1 = make_equation(vec![value_g(), a.clone(), b.clone()]);
		let e2 = make_equation(vec![value_nil(), a, b]);
		assert!(!e1.equivalent(&e2, true));
		assert_ne!(e1.hash_value(), e2.hash_value());
	}

	#[test]
	fn equation_equivalence_3_element_not_equal() {
		let a = make_constant("dh_ne_a");
		let b = make_constant("dh_ne_b");
		let c = make_constant("dh_ne_c");
		let e1 = make_equation(vec![value_g(), a.clone(), b]);
		let e2 = make_equation(vec![value_g(), a, c]);
		assert!(!e1.equivalent(&e2, true));
	}

	#[test]
	fn equation_equivalence_empty() {
		let e1 = make_equation(vec![]);
		let e2 = make_equation(vec![]);
		assert!(!e1.equivalent(&e2, true));
	}

	#[test]
	fn equation_flatten_nested() {
		let a = make_constant("flat_a");
		let b = make_constant("flat_b");
		let inner = Equation {
			values: vec![value_g(), a.clone()],
		};
		let outer = Equation {
			values: vec![Value::Equation(Arc::new(inner)), b.clone()],
		};
		assert!(!equation_is_flat(&outer));
		let flat = flatten_equation(&outer);
		assert!(equation_is_flat(&flat));
		assert_eq!(flat.values.len(), 3);
	}

	#[test]
	fn equation_already_flat() {
		let a = make_constant("aflat_a");
		let eq = Equation {
			values: vec![value_g(), a],
		};
		assert!(equation_is_flat(&eq));
	}

	#[test]
	fn primitive_equivalence_same() {
		let a = make_constant("peq_a");
		let b = make_constant("peq_b");
		let p1 = Primitive {
			id: PRIM_ENC,
			arguments: vec![a.clone(), b.clone()],
			output: 0,
			instance_check: false,
		};
		let p2 = Primitive {
			id: PRIM_ENC,
			arguments: vec![a, b],
			output: 0,
			instance_check: false,
		};
		assert!(equivalent_primitives(&p1, &p2, true).equivalent);
	}

	#[test]
	fn primitive_equivalence_different_id() {
		let a = make_constant("pdiff_a");
		let b = make_constant("pdiff_b");
		let p1 = Primitive {
			id: PRIM_ENC,
			arguments: vec![a.clone(), b.clone()],
			output: 0,
			instance_check: false,
		};
		let p2 = Primitive {
			id: PRIM_DEC,
			arguments: vec![a, b],
			output: 0,
			instance_check: false,
		};
		assert!(!equivalent_primitives(&p1, &p2, true).equivalent);
	}

	#[test]
	fn primitive_equivalence_different_output() {
		let a = make_constant("pout_a");
		let p1 = Primitive {
			id: PRIM_HKDF,
			arguments: vec![a.clone(), a.clone(), a.clone()],
			output: 0,
			instance_check: false,
		};
		let p2 = Primitive {
			id: PRIM_HKDF,
			arguments: vec![a.clone(), a.clone(), a],
			output: 1,
			instance_check: false,
		};
		assert!(!equivalent_primitives(&p1, &p2, true).equivalent);
		let pm = equivalent_primitives(&p1, &p2, false);
		assert!(pm.equivalent);
		assert_eq!(pm.output_left, 0);
		assert_eq!(pm.output_right, 1);
	}

	#[test]
	fn canonical_g_nil_equivalence() {
		let g = value_g();
		let nil = value_nil();
		assert!(g.equivalent(&value_g(), true));
		assert!(nil.equivalent(&value_nil(), true));
		assert!(!g.equivalent(&nil, true));
	}

	#[test]
	fn canonical_g_nil_equation() {
		let gn = value_g_nil();
		let expected = make_equation(vec![value_g(), value_nil()]);
		assert!(gn.equivalent(&expected, true));
	}
}
