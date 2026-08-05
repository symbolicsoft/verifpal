/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::deduction::compute_knowledge_closure;
use crate::primitive::primitive_get;
use crate::reexec::attacker_authored;
use crate::theory::can_rewrite;
use crate::types::*;
use crate::util::min_int_in_slice;
use crate::verify::verify_resolve_queries;

use super::symbolic::SymbolicState;
use super::vars::{Substitution, apply};

pub(crate) fn validate(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps_base: &PrincipalState,
	sym: &SymbolicState,
	attacker: &AttackerState,
	subst: &Substitution,
) -> VResult<bool> {
	let ps = ps_base.clone_for_depth(true);
	let mut installs: Vec<(SlotIdx, Value)> = Vec::new();
	let mut worthwhile = false;

	for &slot in &sym.var_slots {
		let Some(var_term) = &sym.var_terms[slot] else {
			continue;
		};
		if !subst.contains_key(&super::vars::attacker_var_id(slot)) {
			continue;
		}
		let ground = super::vars::ground_free(&apply(var_term, subst));
		if super::vars::contains_var(&ground) {
			continue;
		}
		if slot >= ps.values.len() {
			continue;
		}
		if contains_failed_check(&ground, &ps) {
			return Ok(false);
		}
		if !phase_permits(ctx, slot, &ground, &ps, attacker.current_phase) {
			return Ok(false);
		}
		if attacker_authored(&ground, slot, km, &ps) {
			worthwhile = true;
		}
		installs.push((SlotIdx(slot), ground));
	}

	if !worthwhile {
		return Ok(false);
	}

	let governing = crate::reexec::governing_attacker(ctx, &installs, &ps, attacker);
	let Ok(ps) = crate::reexec::reexecute(&ps, &installs, &governing, km) else {
		return Ok(false);
	};

	let _ = compute_knowledge_closure(ctx, km, &ps);
	let _ = verify_resolve_queries(ctx, km, &ps);
	Ok(true)
}

fn phase_permits(
	ctx: &VerifyContext,
	slot: usize,
	ground: &Value,
	ps: &PrincipalState,
	current_phase: i32,
) -> bool {
	let Some(meta) = ps.meta.get(slot) else {
		return true;
	};
	let Ok(earliest) = min_int_in_slice(&meta.phase) else {
		return true;
	};
	if earliest >= current_phase {
		return true;
	}
	match ctx.attacker_knowledge_at(earliest) {
		Some(snapshot) => available_at(ground, &snapshot),
		None => false,
	}
}

fn available_at(v: &Value, snapshot: &AttackerState) -> bool {
	if snapshot.knows(v).is_some() {
		return true;
	}
	match v {
		Value::Constant(c) => c.is_g_or_nil(),
		Value::Primitive(p) => p.arguments.iter().all(|a| available_at(a, snapshot)),
		Value::Equation(e) => e.values.iter().all(|a| available_at(a, snapshot)),
	}
}

fn contains_failed_check(v: &Value, ps: &PrincipalState) -> bool {
	match v {
		Value::Primitive(p) => {
			if p.instance_check
				&& primitive_get(p.id).is_ok_and(|spec| spec.rewrite.has_rule)
				&& !can_rewrite(p, ps, 0).0
			{
				return true;
			}
			p.arguments.iter().any(|a| contains_failed_check(a, ps))
		}
		Value::Equation(e) => e.values.iter().any(|a| contains_failed_check(a, ps)),
		Value::Constant(_) => false,
	}
}
