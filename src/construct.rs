/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::pretty::*;
use crate::principal::*;
use crate::sanity::{sanity_assignment_constants, sanity_primitive};
use crate::types::*;
use crate::util::*;
use crate::value::*;
use std::collections::HashMap;
use std::sync::Arc;

pub fn construct_knowledge_map(
	m: &Model,
	principals: &[String],
	principal_ids: &[PrincipalId],
) -> Result<KnowledgeMap, String> {
	let mut km = KnowledgeMap {
		principals: principals.to_vec(),
		principal_ids: principal_ids.to_vec(),
		constants: vec![],
		assigned: vec![],
		creator: vec![],
		known_by: vec![],
		declared_at: vec![],
		max_declared_at: 0,
		phase: vec![],
		max_phase: 0,
		constant_index: HashMap::new(),
		used_by: HashMap::new(),
	};
	let mut declared_at = 0i32;
	let mut current_phase = 0i32;

	// Add g
	let g = value_g();
	let g_const = g.as_constant().expect("g is Constant").clone();
	km.constants.push(g_const.clone());
	km.constant_index.insert(g_const.id, km.constants.len() - 1);
	km.assigned.push(g);
	km.creator.push(principal_get_attacker_id());
	let mut g_known_by = Vec::new();
	for &pid in principal_ids {
		let mut m = HashMap::new();
		m.insert(pid, pid);
		g_known_by.push(m);
	}
	km.known_by.push(g_known_by);
	km.declared_at.push(declared_at);
	km.phase.push(vec![current_phase]);

	// Add nil
	let nil = value_nil();
	let nil_const = nil.as_constant().expect("nil is Constant").clone();
	km.constants.push(nil_const.clone());
	km.constant_index
		.insert(nil_const.id, km.constants.len() - 1);
	km.assigned.push(nil);
	km.creator.push(principal_get_attacker_id());
	let mut nil_known_by = Vec::new();
	for &pid in principal_ids {
		let mut m = HashMap::new();
		m.insert(pid, pid);
		nil_known_by.push(m);
	}
	km.known_by.push(nil_known_by);
	km.declared_at.push(declared_at);
	km.phase.push(vec![current_phase]);

	for blck in &m.blocks {
		match blck.kind {
			BlockKind::Principal => {
				let (new_km, new_da) =
					construct_knowledge_map_render_principal(km, blck, declared_at, current_phase)?;
				km = new_km;
				declared_at = new_da;
			}
			BlockKind::Message => {
				declared_at += 1;
				km.max_declared_at = declared_at;
				km = construct_knowledge_map_render_message(km, blck, current_phase)?;
			}
			BlockKind::Phase => {
				current_phase = blck.phase.number;
			}
		}
	}
	km.max_phase = current_phase;
	km.used_by = construct_knowledge_map_used_by(&km);
	Ok(km)
}

fn construct_knowledge_map_used_by(
	km: &KnowledgeMap,
) -> HashMap<ValueId, HashMap<PrincipalId, bool>> {
	let mut used_by: HashMap<ValueId, HashMap<PrincipalId, bool>> = HashMap::new();
	for (ii, a) in km.assigned.iter().enumerate() {
		match a {
			Value::Primitive(_) | Value::Equation(_) => {
				let (_, v) = value_resolve_value_internal_values_from_knowledge_map(a, km);
				let creator_id = km.creator[ii];
				for vv in &v {
					if let Value::Constant(c) = vv {
						used_by.entry(c.id).or_default().insert(creator_id, true);
					}
				}
				if let Value::Constant(c) = &km.assigned[ii] {
					used_by.entry(c.id).or_default().insert(creator_id, true);
				}
			}
			_ => {}
		}
	}
	used_by
}

fn construct_knowledge_map_render_principal(
	mut km: KnowledgeMap,
	blck: &Block,
	mut declared_at: i32,
	current_phase: i32,
) -> Result<(KnowledgeMap, i32), String> {
	for expr in &blck.principal.expressions {
		match expr.kind {
			Declaration::Knows => {
				km = construct_knowledge_map_render_knows(km, blck, declared_at, expr)?;
			}
			Declaration::Generates => {
				km = construct_knowledge_map_render_generates(km, blck, declared_at, expr)?;
			}
			Declaration::Assignment => {
				km = construct_knowledge_map_render_assignment(km, blck, declared_at, expr)?;
			}
			Declaration::Leaks => {
				declared_at += 1;
				km = construct_knowledge_map_render_leaks(km, blck, expr, current_phase)?;
			}
		}
	}
	Ok((km, declared_at))
}

fn construct_knowledge_map_render_knows(
	mut km: KnowledgeMap,
	blck: &Block,
	declared_at: i32,
	expr: &Expression,
) -> Result<KnowledgeMap, String> {
	for c in &expr.constants {
		let i = value_get_knowledge_map_index_from_constant(&km, c);
		if let Some(idx) = i {
			let d1 = km.constants[idx].declaration;
			let q1 = km.constants[idx].qualifier;
			let q2 = expr.qualifier;
			let fresh = km.constants[idx].fresh;
			if d1 != Some(Declaration::Knows) || q1 != q2 || fresh {
				return Err(format!(
					"constant is known more than once and in different ways ({})",
					pretty_constant(c)
				));
			}
			let mut m = HashMap::new();
			m.insert(blck.principal.id, blck.principal.id);
			km.known_by[idx].push(m);
			continue;
		}
		let new_c = Constant {
			name: c.name.clone(),
			id: c.id,
			guard: c.guard,
			fresh: false,
			leaked: false,
			declaration: Some(Declaration::Knows),
			qualifier: expr.qualifier,
		};
		km.constants.push(new_c.clone());
		km.constant_index.insert(new_c.id, km.constants.len() - 1);
		km.assigned.push(Value::Constant(new_c));
		km.creator.push(blck.principal.id);
		km.known_by.push(vec![]);
		km.declared_at.push(declared_at);
		km.phase.push(vec![]);
		let l = km.constants.len() - 1;
		if expr.qualifier != Some(Qualifier::Public) {
			continue;
		}
		for &pid in &km.principal_ids {
			if pid != blck.principal.id {
				let mut m = HashMap::new();
				m.insert(pid, pid);
				km.known_by[l].push(m);
			}
		}
	}
	Ok(km)
}

fn construct_knowledge_map_render_generates(
	mut km: KnowledgeMap,
	blck: &Block,
	declared_at: i32,
	expr: &Expression,
) -> Result<KnowledgeMap, String> {
	for c in &expr.constants {
		let i = value_get_knowledge_map_index_from_constant(&km, c);
		if i.is_some() {
			return Err(format!(
				"generated constant already exists ({})",
				pretty_constant(c)
			));
		}
		let new_c = Constant {
			name: c.name.clone(),
			id: c.id,
			guard: c.guard,
			fresh: true,
			leaked: false,
			declaration: Some(Declaration::Generates),
			qualifier: Some(Qualifier::Private),
		};
		km.constants.push(new_c.clone());
		km.constant_index.insert(new_c.id, km.constants.len() - 1);
		km.assigned.push(Value::Constant(new_c));
		km.creator.push(blck.principal.id);
		km.known_by.push(vec![HashMap::new()]);
		km.declared_at.push(declared_at);
		km.phase.push(vec![]);
	}
	Ok(km)
}

fn construct_knowledge_map_render_assignment(
	mut km: KnowledgeMap,
	blck: &Block,
	declared_at: i32,
	expr: &Expression,
) -> Result<KnowledgeMap, String> {
	let assigned = expr.assigned.as_ref().ok_or("missing assignment value")?;
	let constants = sanity_assignment_constants(assigned, &[], &km)?;
	if let Value::Primitive(p) = assigned {
		sanity_primitive(p, &expr.constants)?;
	}
	for c in &constants {
		let idx = match value_get_knowledge_map_index_from_constant(&km, c) {
			Some(idx) => idx,
			None => return Err(format!("constant does not exist ({})", pretty_constant(c))),
		};
		let mut knows = km.creator[idx] == blck.principal.id;
		for m in &km.known_by[idx] {
			if m.contains_key(&blck.principal.id) {
				knows = true;
				break;
			}
		}
		if !knows {
			return Err(format!(
				"{} is using constant ({}) despite not knowing it",
				blck.principal.name,
				pretty_constant(c)
			));
		}
	}
	for (i, c) in expr.constants.iter().enumerate() {
		let ii = value_get_knowledge_map_index_from_constant(&km, c);
		if ii.is_some() {
			return Err(format!("constant assigned twice ({})", pretty_constant(c)));
		}
		let new_c = Constant {
			name: c.name.clone(),
			id: c.id,
			guard: c.guard,
			fresh: false,
			leaked: false,
			declaration: Some(Declaration::Assignment),
			qualifier: Some(Qualifier::Private),
		};
		let mut a = assigned.clone();
		if let Value::Primitive(ref mut p) = a {
			Arc::make_mut(p).output = i;
		}
		km.constants.push(new_c.clone());
		km.constant_index.insert(new_c.id, km.constants.len() - 1);
		km.assigned.push(a);
		km.creator.push(blck.principal.id);
		km.known_by.push(vec![HashMap::new()]);
		km.declared_at.push(declared_at);
		km.phase.push(vec![]);
	}
	Ok(km)
}

fn construct_knowledge_map_render_leaks(
	mut km: KnowledgeMap,
	blck: &Block,
	expr: &Expression,
	current_phase: i32,
) -> Result<KnowledgeMap, String> {
	for c in &expr.constants {
		let idx = match value_get_knowledge_map_index_from_constant(&km, c) {
			Some(idx) => idx,
			None => {
				return Err(format!(
					"leaked constant does not exist ({})",
					pretty_constant(c)
				))
			}
		};
		let mut known = km.creator[idx] == blck.principal.id;
		for m in &km.known_by[idx] {
			if m.contains_key(&blck.principal.id) {
				known = true;
				break;
			}
		}
		if !known {
			return Err(format!(
				"{} leaks a constant that they do not know ({})",
				blck.principal.name,
				pretty_constant(c)
			));
		}
		km.constants[idx].leaked = true;
		append_unique_int(&mut km.phase[idx], current_phase);
	}
	Ok(km)
}

fn construct_knowledge_map_render_message(
	mut km: KnowledgeMap,
	blck: &Block,
	current_phase: i32,
) -> Result<KnowledgeMap, String> {
	for c in &blck.message.constants {
		let idx = match value_get_knowledge_map_index_from_constant(&km, c) {
			Some(idx) => idx,
			None => {
				return Err(format!(
					"{} sends unknown constant to {} ({})",
					principal_get_name_from_id(blck.message.sender),
					principal_get_name_from_id(blck.message.recipient),
					pretty_constant(c)
				))
			}
		};
		let mut sender_knows = km.creator[idx] == blck.message.sender;
		let mut recipient_knows = km.creator[idx] == blck.message.recipient;
		for m in &km.known_by[idx] {
			if m.contains_key(&blck.message.sender) {
				sender_knows = true;
			}
			if m.contains_key(&blck.message.recipient) {
				recipient_knows = true;
			}
		}
		if !sender_knows {
			return Err(format!(
				"{} is sending constant ({}) despite not knowing it",
				principal_get_name_from_id(blck.message.sender),
				pretty_constant(c)
			));
		}
		if recipient_knows {
			return Err(format!(
				"{} is receiving constant ({}) despite already knowing it",
				principal_get_name_from_id(blck.message.recipient),
				pretty_constant(c)
			));
		}
		let mut m = HashMap::new();
		m.insert(blck.message.recipient, blck.message.sender);
		km.known_by[idx].push(m);
		append_unique_int(&mut km.phase[idx], current_phase);
	}
	Ok(km)
}

pub fn construct_principal_states(m: &Model, km: &KnowledgeMap) -> Vec<PrincipalState> {
	let mut states = Vec::new();
	for p in 0..km.principals.len() {
		let n = km.constants.len();
		let mut constants = Vec::with_capacity(n);
		let mut assigned = Vec::with_capacity(n);
		let mut guard_vec = Vec::with_capacity(n);
		let mut known_vec = Vec::with_capacity(n);
		let mut wire_vec = Vec::with_capacity(n);
		let mut known_by_vec = Vec::with_capacity(n);
		let mut declared_at_vec = Vec::with_capacity(n);
		let mut creator_vec = Vec::with_capacity(n);
		let mut sender_vec = Vec::with_capacity(n);
		let mut before_rewrite = Vec::with_capacity(n);
		let mut mutatable_to_vec = Vec::with_capacity(n);
		let mut before_mutate = Vec::with_capacity(n);
		let mut phase_vec = Vec::with_capacity(n);
		let mut constant_index = HashMap::with_capacity(n);

		for (i, c) in km.constants.iter().enumerate() {
			let mut wire = vec![];
			let mut guard = false;
			let mut mutatable_to = vec![];
			let mut knows = km.creator[i] == km.principal_ids[p];
			let mut sender = km.creator[i];
			for m_map in &km.known_by[i] {
				if let Some(&preceding_sender) = m_map.get(&km.principal_ids[p]) {
					sender = preceding_sender;
					knows = true;
					break;
				}
			}
			for blck in &m.blocks {
				if blck.kind == BlockKind::Message {
					let (w, g, mt) = construct_principal_states_get_value_mutatability(
						c,
						blck,
						km.principal_ids[p],
						km.creator[i],
						wire,
						guard,
						mutatable_to,
					);
					wire = w;
					guard = g;
					mutatable_to = mt;
				}
			}
			constants.push(c.clone());
			constant_index.insert(c.id, constants.len() - 1);
			assigned.push(km.assigned[i].clone());
			guard_vec.push(guard);
			known_vec.push(knows);
			wire_vec.push(wire);
			known_by_vec.push(km.known_by[i].clone());
			declared_at_vec.push(km.declared_at[i]);
			creator_vec.push(km.creator[i]);
			sender_vec.push(sender);
			before_rewrite.push(km.assigned[i].clone());
			mutatable_to_vec.push(mutatable_to);
			before_mutate.push(km.assigned[i].clone());
			phase_vec.push(km.phase[i].clone());
		}
		states.push(PrincipalState {
			name: km.principals[p].clone(),
			id: km.principal_ids[p],
			constants: Arc::new(constants),
			guard: Arc::new(guard_vec),
			known: Arc::new(known_vec),
			wire: Arc::new(wire_vec),
			known_by: Arc::new(known_by_vec),
			declared_at: Arc::new(declared_at_vec),
			max_declared_at: km.max_declared_at,
			mutatable_to: Arc::new(mutatable_to_vec),
			phase: Arc::new(phase_vec),
			constant_index: Arc::new(constant_index),
			assigned,
			creator: creator_vec,
			sender: sender_vec,
			rewritten: vec![false; n],
			before_rewrite,
			mutated: vec![false; n],
			before_mutate,
		});
	}
	states
}

fn construct_principal_states_get_value_mutatability(
	c: &Constant,
	blck: &Block,
	principal_id: PrincipalId,
	creator: PrincipalId,
	mut wire: Vec<PrincipalId>,
	mut guard: bool,
	mut mutatable_to: Vec<PrincipalId>,
) -> (Vec<PrincipalId>, bool, Vec<PrincipalId>) {
	if blck.kind != BlockKind::Message {
		return (wire, guard, mutatable_to);
	}
	let ir = blck.message.recipient == principal_id;
	let ic = creator == principal_id;
	for cc in &blck.message.constants {
		if c.id != cc.id {
			continue;
		}
		append_unique_principal_enum(&mut wire, blck.message.recipient);
		if !guard {
			guard = cc.guard && (ir || ic);
		}
		if !cc.guard {
			append_unique_principal_enum(&mut mutatable_to, blck.message.recipient);
		}
	}
	(wire, guard, mutatable_to)
}

pub fn construct_principal_state_clone(ps: &PrincipalState, purify: bool) -> PrincipalState {
	let n = ps.assigned.len();
	let mut clone = PrincipalState {
		name: ps.name.clone(),
		id: ps.id,
		constants: ps.constants.clone(),
		assigned: Vec::with_capacity(n),
		guard: ps.guard.clone(),
		known: ps.known.clone(),
		wire: ps.wire.clone(),
		known_by: ps.known_by.clone(),
		declared_at: ps.declared_at.clone(),
		max_declared_at: ps.max_declared_at,
		creator: ps.creator.clone(),
		sender: ps.sender.clone(),
		rewritten: vec![false; n],
		before_rewrite: Vec::with_capacity(n),
		mutated: ps.mutated.clone(),
		mutatable_to: ps.mutatable_to.clone(),
		before_mutate: ps.before_mutate.clone(),
		phase: ps.phase.clone(),
		constant_index: ps.constant_index.clone(),
	};
	if purify {
		clone.assigned = ps.before_mutate.clone();
		clone.before_rewrite = ps.before_mutate.clone();
	} else {
		clone.assigned = ps.assigned.clone();
		clone.before_rewrite = ps.before_rewrite.clone();
	}
	clone
}
