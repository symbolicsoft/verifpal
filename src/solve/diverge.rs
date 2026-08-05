/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::*;

use super::vars::{Substitution, collect_vars, dedupe};
use crate::value::value_nil;

pub(crate) fn solve_divergent(a: &Value, b: &Value, s: &Substitution) -> Vec<Substitution> {
	let mut a_vars = Vec::new();
	let mut b_vars = Vec::new();
	collect_vars(a, &mut a_vars);
	collect_vars(b, &mut b_vars);

	if a_vars.is_empty() && b_vars.is_empty() {
		return Vec::new();
	}

	let mut out = Vec::new();

	for id in a_vars.iter().chain(b_vars.iter()) {
		let in_a = a_vars.contains(id);
		let in_b = b_vars.contains(id);
		if in_a == in_b {
			continue;
		}
		let mut extended = s.clone();
		extended.entry(*id).or_insert_with(value_nil);
		out.push(extended);
	}

	let mut all = s.clone();
	for id in a_vars.iter().chain(b_vars.iter()) {
		all.entry(*id).or_insert_with(value_nil);
	}
	out.push(all);

	dedupe(out)
}
