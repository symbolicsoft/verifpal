/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::context::VerifyContext;
use crate::primitive::primitive_extract_bypass_key;
use crate::principal::ATTACKER_ID;
use crate::theory::{can_reconstruct_equation, can_reconstruct_primitive, can_rewrite};
use crate::types::*;
use crate::util::min_int_in_slice;
use crate::value::{resolve_trace_values, value_g_nil};

pub(crate) fn governing_attacker(
	ctx: &VerifyContext,
	installs: &[(SlotIdx, Value)],
	ps: &PrincipalState,
	ambient: &AttackerState,
) -> AttackerState {
	let earliest = installs
		.iter()
		.filter_map(|(slot, _)| ps.meta.get(slot.get()))
		.filter_map(|meta| min_int_in_slice(&meta.phase).ok())
		.min();
	match earliest {
		Some(phase) if phase < ambient.current_phase => {
			ctx.attacker_knowledge_at(phase).unwrap_or_default()
		}
		_ => ambient.clone(),
	}
}

pub(crate) fn reexecute(
	ps_base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	attacker: &AttackerState,
	km: &ProtocolTrace,
) -> VResult<PrincipalState> {
	let mut ps = ps_base.clone();
	let authored: Vec<bool> = installs
		.iter()
		.map(|(slot, ground)| {
			slot.get() < ps.values.len() && attacker_authored(ground, slot.get(), km, &ps)
		})
		.collect();
	for ((slot, ground), authored) in installs.iter().zip(authored) {
		if slot.get() < ps.values.len() {
			install(&mut ps, slot.get(), ground.clone(), authored);
		}
	}

	let ps_pre = ps.clone();
	ps.resolve_all_values(attacker)?;
	let failures = ps.perform_all_rewrites();

	if let Some(bypassed) = try_guard_bypass(&ps_pre, &ps, &failures, attacker)? {
		ps = bypassed;
	} else if let Some((truncate_at, halted_at)) = truncation_point(&ps, &failures) {
		ps = drop_after_index(ps, truncate_at);
		ps.halted_at = Some(halted_at);
	}
	Ok(ps)
}

const MAX_BYPASS_ROUNDS: usize = 5;

fn try_guard_bypass(
	ps_pre: &PrincipalState,
	ps_resolved: &PrincipalState,
	failures: &[(Primitive, usize)],
	attacker: &AttackerState,
) -> VResult<Option<PrincipalState>> {
	let bypassable: Vec<usize> = failures
		.iter()
		.filter(|(prim, idx)| {
			prim.instance_check
				&& ps_resolved.values[*idx].provenance.creator == ps_resolved.id
				&& primitive_extract_bypass_key(prim)
					.is_some_and(|key| can_obtain(&key, ps_resolved, attacker))
		})
		.map(|(_, idx)| *idx)
		.collect();

	if bypassable.is_empty() {
		return Ok(None);
	}

	let mut ps = ps_pre.clone();
	for idx in bypassable {
		if idx < ps.values.len() {
			ps.values[idx].override_all_bypassed(value_g_nil());
		}
	}

	for _ in 0..MAX_BYPASS_ROUNDS {
		ps.resolve_all_values(attacker)?;
		let round = ps.perform_all_rewrites();
		let mut injected = false;
		for (prim, idx) in &round {
			if !prim.instance_check || ps.values[*idx].provenance.creator != ps.id {
				continue;
			}
			if primitive_extract_bypass_key(prim).is_some_and(|key| can_obtain(&key, &ps, attacker))
			{
				ps.values[*idx].override_all_bypassed(value_g_nil());
				injected = true;
			}
		}
		if !injected {
			break;
		}
	}

	ps.resolve_all_values(attacker)?;
	let remaining = ps.perform_all_rewrites();
	if let Some((truncate_at, halted_at)) = truncation_point(&ps, &remaining) {
		ps = drop_after_index(ps, truncate_at);
		ps.halted_at = Some(halted_at);
	}
	Ok(Some(ps))
}

fn can_obtain(v: &Value, ps: &PrincipalState, attacker: &AttackerState) -> bool {
	if attacker.knows(v).is_some() {
		return true;
	}
	match v {
		Value::Primitive(p) => can_reconstruct_primitive(p, ps, attacker, 0).is_some(),
		Value::Equation(e) => can_reconstruct_equation(e, attacker).is_some(),
		_ => false,
	}
}

pub(crate) fn attacker_authored(
	ground: &Value,
	slot: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> bool {
	let honest = &ps.values[slot].value;
	let (trace_resolved, _) = resolve_trace_values(honest, km);
	let trace_reduct = reduce(&trace_resolved, ps).unwrap_or(trace_resolved);
	let ground_reduct = reduce(ground, ps).unwrap_or_else(|| ground.clone());
	!ground_reduct.equivalent(&trace_reduct, true)
}

fn reduce(v: &Value, ps: &PrincipalState) -> Option<Value> {
	let p = v.as_primitive()?;
	let (_, rewritten) = can_rewrite(p, ps, 0);
	if rewritten.equivalent(v, true) {
		None
	} else {
		Some(rewritten)
	}
}

pub(crate) fn install(ps: &mut PrincipalState, slot: usize, ground: Value, authored: bool) {
	let previous = ps.values[slot].value.clone();
	let sv = &mut ps.values[slot];
	sv.original = previous;
	sv.provenance.creator = ATTACKER_ID;
	sv.provenance.attacker_tainted = true;
	if authored {
		sv.provenance.sender = ATTACKER_ID;
	}
	sv.pre_rewrite = ground.clone();
	sv.value = ground;
}

fn truncation_point(ps: &PrincipalState, failures: &[(Primitive, usize)]) -> Option<(usize, i32)> {
	for (prim, idx) in failures {
		if !prim.instance_check || ps.values[*idx].provenance.creator != ps.id {
			continue;
		}
		let declared_at = ps.meta[*idx].declared_at;
		let truncate_at = if declared_at == ps.max_declared_at {
			idx + 1
		} else {
			match ps.meta.iter().position(|m| m.declared_at == declared_at) {
				Some(pos) => pos + 1,
				None => idx + 1,
			}
		};
		return Some((truncate_at, declared_at));
	}
	None
}

fn drop_after_index(mut ps: PrincipalState, at: usize) -> PrincipalState {
	Arc::make_mut(&mut ps.meta).truncate(at);
	ps.values.truncate(at);
	ps
}

#[cfg(test)]
mod tests {
	use crate::testutil::*;
	use crate::types::SlotIdx;

	#[test]
	fn reexecute_installs_with_attacker_provenance() {
		use crate::reexec::reexecute;
		let a = make_constant("rex_a");
		let b = make_constant("rex_b");
		let ca = a.as_constant().expect("constant").clone();
		let cb = b.as_constant().expect("constant").clone();
		let meta = vec![make_slot_meta(&ca, true), make_slot_meta(&cb, false)];
		let values = vec![make_slot_values(&a, 0), make_slot_values(&b, 1)];
		let ps = make_principal_state("Alice", 0, meta, values);
		let attacker = make_attacker_state(vec![]);

		let km = make_trace();
		let out = reexecute(&ps, &[(SlotIdx(1), a.clone())], &attacker, &km).expect("reexecute");

		assert!(out.values[1].value.equivalent(&a, true));
		assert!(out.values[1].provenance.attacker_tainted);
		assert_eq!(
			out.values[1].provenance.sender,
			crate::principal::ATTACKER_ID
		);
		assert!(out.values[1].original.equivalent(&b, true));
		assert!(!out.values[0].provenance.attacker_tainted);
	}

	#[test]
	fn reexecute_does_not_attribute_a_relayed_value_to_the_attacker() {
		use crate::reexec::reexecute;
		let a = make_constant("relay_a");
		let b = make_constant("relay_b");
		let ca = a.as_constant().expect("constant").clone();
		let cb = b.as_constant().expect("constant").clone();
		let meta = vec![make_slot_meta(&ca, true), make_slot_meta(&cb, false)];
		let values = vec![make_slot_values(&a, 0), make_slot_values(&b, 1)];
		let ps = make_principal_state("Alice", 0, meta, values);
		let attacker = make_attacker_state(vec![]);
		let km = make_trace();

		let out = reexecute(&ps, &[(SlotIdx(1), b.clone())], &attacker, &km).expect("reexecute");

		assert!(out.values[1].value.equivalent(&b, true));
		assert!(out.values[1].provenance.attacker_tainted);
		assert_ne!(
			out.values[1].provenance.sender,
			crate::principal::ATTACKER_ID,
			"a forwarded value must not be attributed to the attacker"
		);
	}
}
