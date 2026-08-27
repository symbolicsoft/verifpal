/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::context::VerifyContext;
use crate::primitive::{attacker_public_key, primitive_extract_bypass_key};
use crate::principal::ATTACKER_ID;
use crate::theory::{obtainable, reduce_once};
use crate::types::*;
use crate::util::min_int_in_slice;
use crate::value::{resolve_trace_constant, resolve_trace_term};

pub(crate) struct Controllable {
	principal: PrincipalId,
	phase: i32,
	slots: Vec<bool>,
}

impl Controllable {
	pub(crate) fn of(
		km: &ProtocolTrace,
		ps: &PrincipalState,
		attacker: &AttackerState,
	) -> Controllable {
		Controllable {
			principal: ps.id,
			phase: attacker.current_phase,
			slots: (0..ps.values.len())
				.map(|i| attacker_controllable(i, km, ps, attacker))
				.collect(),
		}
	}

	pub(crate) fn admits(
		&self,
		ps: &PrincipalState,
		attacker: &AttackerState,
		slot: usize,
	) -> bool {
		self.principal == ps.id
			&& self.phase == attacker.current_phase
			&& self.slots.get(slot).copied().unwrap_or(false)
	}
}

pub(crate) struct TermBound {
	max_depth: usize,
}

impl TermBound {
	pub(crate) fn of(km: &ProtocolTrace) -> TermBound {
		let max_depth = km
			.slots
			.iter()
			.map(|slot| term_depth(&resolve_trace_constant(&slot.constant, km)))
			.max()
			.unwrap_or(0);
		TermBound { max_depth }
	}

	pub(crate) fn admits(&self, v: &Value) -> bool {
		term_depth(v) <= self.max_depth
	}

	pub(crate) fn depth(&self) -> usize {
		self.max_depth
	}
}

pub(crate) struct Guards<'a> {
	pub(crate) controllable: &'a Controllable,
	pub(crate) bound: &'a TermBound,
}

fn term_depth(v: &Value) -> usize {
	match v {
		Value::Constant(_) => 0,
		Value::Primitive(p) => 1 + p.arguments.iter().map(term_depth).max().unwrap_or(0),
	}
}

pub(crate) fn attacker_controllable(
	idx: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> bool {
	let Some(meta) = ps.meta.get(idx) else {
		return false;
	};
	if idx >= ps.values.len() {
		return false;
	}
	if meta.constant.is_nil() {
		return false;
	}
	if meta.guard {
		if !meta
			.mutatable_to
			.contains(&ps.values[idx].provenance.sender)
		{
			return false;
		}
	} else if ps.values[idx].provenance.creator == ps.id || meta.wire.is_empty() {
		return false;
	}
	if !meta.phase.iter().any(|&p| p <= attacker.current_phase) {
		return false;
	}
	if !km.constant_used_by(ps.id, &meta.constant) {
		return false;
	}
	true
}

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

	if slot_graph_is_cyclic(&ps) {
		return Err(VerifpalError::resolution(
			"attacker-chosen values would define a slot in terms of itself".into(),
		));
	}

	let ps_pre = ps.clone();
	ps.resolve_all_values()?;
	let failures = ps.perform_all_rewrites();

	let foreign = foreign_halts(&ps, &failures);

	if let Some(bypassed) = try_guard_bypass(&ps_pre, &ps, &failures, attacker)? {
		ps = bypassed;
	} else if let Some((truncate_at, halted_at)) = truncation_point(&ps, &failures) {
		ps = drop_after_index(ps, truncate_at);
		ps.halted_at = Some(halted_at);
	}
	ps.foreign_halts = foreign;
	Ok(ps)
}

pub(crate) fn halt_at_failed_checks(
	mut ps: PrincipalState,
	failures: &[(Primitive, usize)],
) -> PrincipalState {
	let foreign = foreign_halts(&ps, failures);
	if let Some((truncate_at, halted_at)) = truncation_point(&ps, failures) {
		ps = drop_after_index(ps, truncate_at);
		ps.halted_at = Some(halted_at);
	}
	ps.foreign_halts = foreign;
	ps
}

pub(crate) fn creator_halts(
	ps: &PrincipalState,
	failures: &[(Primitive, usize)],
) -> Vec<(PrincipalId, usize)> {
	let mut out: Vec<(PrincipalId, usize)> = Vec::new();
	for (prim, idx) in failures {
		if !prim.instance_check {
			continue;
		}
		let Some(sv) = ps.values.get(*idx) else {
			continue;
		};
		let creator = sv.provenance.creator;
		if creator == ATTACKER_ID {
			continue;
		}
		match out.iter_mut().find(|(principal, _)| *principal == creator) {
			Some((_, at)) => *at = (*at).min(*idx),
			None => out.push((creator, *idx)),
		}
	}
	out
}

fn foreign_halts(
	ps: &PrincipalState,
	failures: &[(Primitive, usize)],
) -> Vec<(PrincipalId, usize)> {
	creator_halts(ps, failures)
		.into_iter()
		.filter(|&(principal, _)| principal != ps.id)
		.collect()
}

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
					.is_some_and(|key| obtainable(&key, ps_resolved, attacker))
		})
		.map(|(_, idx)| *idx)
		.collect();

	if bypassable.is_empty() {
		return Ok(None);
	}

	let mut ps = ps_pre.clone();
	for idx in bypassable {
		if idx < ps.values.len() {
			ps.values[idx].override_all_bypassed(attacker_public_key());
		}
	}

	loop {
		ps.resolve_all_values()?;
		let round = ps.perform_all_rewrites();
		let mut injected = false;
		for (prim, idx) in &round {
			if !prim.instance_check
				|| ps.values[*idx].provenance.creator != ps.id
				|| ps.values[*idx].provenance.bypass_injected
			{
				continue;
			}
			if primitive_extract_bypass_key(prim).is_some_and(|key| obtainable(&key, &ps, attacker))
			{
				ps.values[*idx].override_all_bypassed(attacker_public_key());
				injected = true;
			}
		}
		if !injected {
			break;
		}
	}

	ps.resolve_all_values()?;
	let remaining = ps.perform_all_rewrites();
	if let Some((truncate_at, halted_at)) = truncation_point(&ps, &remaining) {
		ps = drop_after_index(ps, truncate_at);
		ps.halted_at = Some(halted_at);
	}
	Ok(Some(ps))
}

pub(crate) fn attacker_authored(
	ground: &Value,
	slot: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> bool {
	let honest = &ps.values[slot].value;
	let trace_reduct = reduce_once(&resolve_trace_term(honest, km));
	let ground_reduct = reduce_once(ground);
	!ground_reduct.equivalent(&trace_reduct, true)
}

pub(crate) fn slot_graph_is_cyclic(ps: &PrincipalState) -> bool {
	let n = ps.values.len();
	let mut edges: Vec<usize> = Vec::new();
	let mut bounds: Vec<usize> = Vec::with_capacity(n + 1);
	bounds.push(0);
	for sv in &ps.values {
		let from = edges.len();
		for v in [&sv.value, sv.perceived()] {
			if matches!(v, Value::Primitive(_)) {
				collect_slot_references(v, ps, &mut edges, from);
			}
		}
		bounds.push(edges.len());
	}

	// Iterative depth-first search: 0 unvisited, 1 on the current path, 2 done.
	let mut mark = vec![0u8; n];
	let mut stack: Vec<(usize, usize)> = Vec::new();
	for start in 0..n {
		if mark[start] != 0 {
			continue;
		}
		mark[start] = 1;
		stack.push((start, bounds[start]));
		while let Some((slot, edge)) = stack.pop() {
			if edge >= bounds[slot + 1] {
				mark[slot] = 2;
				continue;
			}
			let next = edges[edge];
			stack.push((slot, edge + 1));
			match mark[next] {
				1 => return true,
				0 => {
					mark[next] = 1;
					stack.push((next, bounds[next]));
				}
				_ => {}
			}
		}
	}
	false
}

fn collect_slot_references(v: &Value, ps: &PrincipalState, out: &mut Vec<usize>, from: usize) {
	match v {
		Value::Constant(c) => {
			if let Some(i) = ps.index_of(c)
				&& !out[from..].contains(&i)
			{
				out.push(i);
			}
		}
		Value::Primitive(p) => {
			for a in &p.arguments {
				collect_slot_references(a, ps, out, from);
			}
		}
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
		return Some((idx + 1, declared_at));
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
	use crate::types::{PrincipalState, SlotIdx};
	#[test]
	fn a_generated_key_is_not_attacker_controllable() {
		use crate::parser::parse_string;
		let src = "attacker[active]\n\
			principal Bob[\n\
			knows private ctl_secret\n\
			generates ctl_kk\n\
			ctl_c = AEAD_ENC(ctl_kk, ctl_secret, nil)\n\
			]\n\
			Bob -> Alice: ctl_c\n\
			principal Alice[\n\
			knows private ctl_kk2\n\
			ctl_m = AEAD_DEC(ctl_kk2, ctl_c, nil)\n\
			]\n\
			queries[\n\
			confidentiality? ctl_secret\n\
			]\n";
		let m = parse_string("ctl.vp", src).expect("parse");
		let (km, states) = crate::sanity::sanity(&m).expect("sanity");
		let attacker = make_attacker_state(vec![]);

		let slot_named = |ps: &PrincipalState, name: &str| -> usize {
			ps.meta
				.iter()
				.position(|m| m.constant.name.as_ref() == name)
				.unwrap_or_else(|| panic!("{name} is a slot"))
		};

		let bob = states.iter().find(|s| s.name == "Bob").expect("Bob");
		let kk = slot_named(bob, "ctl_kk");
		assert!(
			!super::attacker_controllable(kk, &km, bob, &attacker),
			"a value its own principal generated is not on any wire, so no \
			 substitution over it describes a Dolev-Yao transition"
		);
		let alice = states.iter().find(|s| s.name == "Alice").expect("Alice");
		let c = slot_named(alice, "ctl_c");
		assert!(super::attacker_controllable(c, &km, alice, &attacker));
	}

	#[test]
	fn an_install_that_names_its_own_slot_is_refused() {
		use crate::parser::parse_string;
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private cyc_m\n\
			generates cyc_k\n\
			cyc_e = ENC(cyc_k, cyc_m)\n\
			]\n\
			Alice -> Bob: cyc_e\n\
			principal Bob[\n\
			knows private cyc_k2\n\
			cyc_d = DEC(cyc_k2, cyc_e)\n\
			]\n\
			queries[\n\
			confidentiality? cyc_m\n\
			]\n";
		let m = parse_string("cyc.vp", src).expect("parse");
		let (km, states) = crate::sanity::sanity(&m).expect("sanity");
		let bob = states.iter().find(|s| s.name == "Bob").expect("Bob");
		let slot = bob
			.meta
			.iter()
			.position(|m| m.constant.name.as_ref() == "cyc_e")
			.expect("cyc_e is a slot");
		let attacker = make_attacker_state(vec![]);

		// A term naming the very slot it is installed into. Honest states never
		// contain one, and a state that does denotes only its own unfolding.
		let self_naming = crate::testutil::make_primitive(
			crate::primitive::PRIM_HASH,
			vec![crate::types::Value::Constant(
				bob.meta[slot].constant.clone(),
			)],
			0,
		);
		assert!(
			super::reexecute(bob, &[(SlotIdx(slot), self_naming)], &attacker, &km,).is_err(),
			"a cyclic install must be refused, not analysed"
		);

		// The same install with a closed term goes through.
		let closed = crate::testutil::make_primitive(
			crate::primitive::PRIM_HASH,
			vec![crate::value::value_nil()],
			0,
		);
		assert!(super::reexecute(bob, &[(SlotIdx(slot), closed)], &attacker, &km).is_ok());
	}

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
