/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::principal::*;
use crate::sanity::{sanity_assignment_constants, sanity_primitive};
use crate::types::*;
use crate::util::*;
use crate::value::*;
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) fn construct_protocol_trace(
	m: &Model,
	principals: &[String],
	principal_ids: &[PrincipalId],
) -> VResult<ProtocolTrace> {
	let mut trace = ProtocolTrace {
		principals: principals.to_vec(),
		principal_ids: principal_ids.to_vec(),
		slots: vec![],
		index: HashMap::new(),
		max_declared_at: 0,
		max_phase: 0,
		used_by: HashMap::new(),
	};
	let mut declared_at = 0i32;
	let mut current_phase = 0i32;

	// Add builtins (g, nil)
	for builtin in &[value_g(), value_nil()] {
		let c = match builtin.as_constant() {
			Some(c) => c.clone(),
			None => continue,
		};
		let known_by: Vec<_> = principal_ids
			.iter()
			.map(|&pid| HashMap::from([(pid, pid)]))
			.collect();
		let const_id = c.id;
		trace.slots.push(TraceSlot {
			constant: c,
			initial_value: builtin.clone(),
			creator: principal_get_attacker_id(),
			known_by,
			declared_at,
			phases: vec![current_phase],
		});
		trace.index.insert(const_id, trace.slots.len() - 1);
	}

	for block in &m.blocks {
		match block {
			Block::Principal(principal) => {
				declared_at = construct_trace_render_principal(
					&mut trace,
					principal,
					declared_at,
					current_phase,
				)?;
			}
			Block::Message(message) => {
				declared_at += 1;
				trace.max_declared_at = declared_at;
				construct_trace_render_message(&mut trace, message, current_phase)?;
			}
			Block::Phase(phase) => {
				current_phase = phase.number;
			}
		}
	}
	trace.max_phase = current_phase;
	trace.used_by = construct_trace_used_by(&trace);
	Ok(trace)
}

fn construct_trace_used_by(trace: &ProtocolTrace) -> HashMap<ValueId, HashMap<PrincipalId, bool>> {
	let mut used_by: HashMap<ValueId, HashMap<PrincipalId, bool>> = HashMap::new();
	for slot in &trace.slots {
		match &slot.initial_value {
			Value::Primitive(_) | Value::Equation(_) => {
				let (_, resolved_values) = resolve_trace_values(&slot.initial_value, trace);
				for resolved in &resolved_values {
					if let Value::Constant(c) = resolved {
						used_by.entry(c.id).or_default().insert(slot.creator, true);
					}
				}
			}
			Value::Constant(c) => {
				if c.id != slot.constant.id {
					used_by.entry(c.id).or_default().insert(slot.creator, true);
				}
			}
		}
	}
	used_by
}

fn construct_trace_render_principal(
	trace: &mut ProtocolTrace,
	principal: &Principal,
	mut declared_at: i32,
	current_phase: i32,
) -> VResult<i32> {
	for expr in &principal.expressions {
		match expr.kind {
			Declaration::Knows => {
				construct_trace_render_knows(trace, principal, declared_at, expr)?;
			}
			Declaration::Generates => {
				construct_trace_render_generates(trace, principal, declared_at, expr)?;
			}
			Declaration::Assignment => {
				construct_trace_render_assignment(trace, principal, declared_at, expr)?;
			}
			Declaration::Leaks => {
				declared_at += 1;
				construct_trace_render_leaks(trace, principal, expr, current_phase)?;
			}
		}
	}
	Ok(declared_at)
}

fn construct_trace_render_knows(
	trace: &mut ProtocolTrace,
	principal: &Principal,
	declared_at: i32,
	expr: &Expression,
) -> VResult<()> {
	for c in &expr.constants {
		if let Some(idx) = trace.index_of(c) {
			let existing = &trace.slots[idx].constant;
			if existing.declaration != Some(Declaration::Knows)
				|| existing.qualifier != expr.qualifier
				|| existing.fresh
			{
				return Err(VerifpalError::Sanity(format!(
					"constant is known more than once and in different ways ({})",
					c
				)));
			}
			trace.slots[idx]
				.known_by
				.push(HashMap::from([(principal.id, principal.id)]));
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
		let const_id = new_c.id;
		trace.slots.push(TraceSlot {
			constant: new_c.clone(),
			initial_value: Value::Constant(new_c),
			creator: principal.id,
			known_by: vec![],
			declared_at,
			phases: vec![],
		});
		let slot_idx = trace.slots.len() - 1;
		trace.index.insert(const_id, slot_idx);
		if expr.qualifier != Some(Qualifier::Public) {
			continue;
		}
		for &pid in &trace.principal_ids {
			if pid != principal.id {
				trace.slots[slot_idx].known_by.push(HashMap::from([(pid, pid)]));
			}
		}
	}
	Ok(())
}

fn construct_trace_render_generates(
	trace: &mut ProtocolTrace,
	principal: &Principal,
	declared_at: i32,
	expr: &Expression,
) -> VResult<()> {
	for c in &expr.constants {
		if trace.index_of(c).is_some() {
			return Err(VerifpalError::Sanity(format!(
				"generated constant already exists ({})",
				c
			)));
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
		let const_id = new_c.id;
		trace.slots.push(TraceSlot {
			constant: new_c.clone(),
			initial_value: Value::Constant(new_c),
			creator: principal.id,
			known_by: vec![HashMap::new()],
			declared_at,
			phases: vec![],
		});
		trace.index.insert(const_id, trace.slots.len() - 1);
	}
	Ok(())
}

fn construct_trace_render_assignment(
	trace: &mut ProtocolTrace,
	principal: &Principal,
	declared_at: i32,
	expr: &Expression,
) -> VResult<()> {
	let assigned = expr.assigned.as_ref().ok_or_else(|| VerifpalError::Sanity("missing assignment value".to_string()))?;
	let constants = sanity_assignment_constants(assigned, &[], trace)?;
	if let Value::Primitive(p) = assigned {
		sanity_primitive(p, &expr.constants)?;
	}
	for c in &constants {
		let idx = match trace.index_of(c) {
			Some(idx) => idx,
			None => return Err(VerifpalError::Sanity(format!("constant does not exist ({})", c))),
		};
		let knows = trace.slots[idx].known_by_principal(principal.id);
		if !knows {
			return Err(VerifpalError::Sanity(format!(
				"{} is using constant ({}) despite not knowing it",
				principal.name,
				c
			)));
		}
	}
	for (output_idx, c) in expr.constants.iter().enumerate() {
		if trace.index_of(c).is_some() {
			return Err(VerifpalError::Sanity(format!("constant assigned twice ({})", c)));
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
		let mut initial_value = assigned.clone();
		if let Value::Primitive(ref mut p) = initial_value {
			Arc::make_mut(p).output = output_idx;
		}
		let const_id = new_c.id;
		trace.slots.push(TraceSlot {
			constant: new_c,
			initial_value,
			creator: principal.id,
			known_by: vec![HashMap::new()],
			declared_at,
			phases: vec![],
		});
		trace.index.insert(const_id, trace.slots.len() - 1);
	}
	Ok(())
}

fn construct_trace_render_leaks(
	trace: &mut ProtocolTrace,
	principal: &Principal,
	expr: &Expression,
	current_phase: i32,
) -> VResult<()> {
	for c in &expr.constants {
		let idx = match trace.index_of(c) {
			Some(idx) => idx,
			None => {
				return Err(VerifpalError::Sanity(format!(
					"leaked constant does not exist ({})",
					c
				)))
			}
		};
		let known = trace.slots[idx].known_by_principal(principal.id);
		if !known {
			return Err(VerifpalError::Sanity(format!(
				"{} leaks a constant that they do not know ({})",
				principal.name,
				c
			)));
		}
		trace.slots[idx].constant.leaked = true;
		append_unique_int(&mut trace.slots[idx].phases, current_phase);
	}
	Ok(())
}

fn construct_trace_render_message(
	trace: &mut ProtocolTrace,
	message: &Message,
	current_phase: i32,
) -> VResult<()> {
	for c in &message.constants {
		let idx = match trace.index_of(c) {
			Some(idx) => idx,
			None => {
				return Err(VerifpalError::Sanity(format!(
					"{} sends unknown constant to {} ({})",
					principal_get_name_from_id(message.sender),
					principal_get_name_from_id(message.recipient),
					c
				)))
			}
		};
		let sender_knows = trace.slots[idx].known_by_principal(message.sender);
		let recipient_knows = trace.slots[idx].known_by_principal(message.recipient);
		if !sender_knows {
			return Err(VerifpalError::Sanity(format!(
				"{} is sending constant ({}) despite not knowing it",
				principal_get_name_from_id(message.sender),
				c
			)));
		}
		if recipient_knows {
			return Err(VerifpalError::Sanity(format!(
				"{} is receiving constant ({}) despite already knowing it",
				principal_get_name_from_id(message.recipient),
				c
			)));
		}
		trace.slots[idx]
			.known_by
			.push(HashMap::from([(message.recipient, message.sender)]));
		append_unique_int(&mut trace.slots[idx].phases, current_phase);
	}
	Ok(())
}

pub(crate) fn construct_principal_states(m: &Model, trace: &ProtocolTrace) -> Vec<PrincipalState> {
	let mut states = Vec::new();
	for (principal_name, &principal_id) in trace.principals.iter().zip(trace.principal_ids.iter()) {
		let n = trace.slots.len();
		let mut meta_vec = Vec::with_capacity(n);
		let mut values_vec = Vec::with_capacity(n);
		let mut index_map = HashMap::with_capacity(n);

		for slot in &trace.slots {
			let c = &slot.constant;
			let mut wire = vec![];
			let mut guard = false;
			let mut mutatable_to = vec![];
			let mut knows = slot.creator == principal_id;
			let mut sender = slot.creator;
			for m_map in &slot.known_by {
				if let Some(&preceding_sender) = m_map.get(&principal_id) {
					sender = preceding_sender;
					knows = true;
					break;
				}
			}
			for blck in &m.blocks {
				if let Block::Message(message) = blck {
					construct_principal_states_get_value_mutatability(
						c,
						message,
						principal_id,
						slot.creator,
						&mut wire,
						&mut guard,
						&mut mutatable_to,
					);
				}
			}
			index_map.insert(c.id, meta_vec.len());
			meta_vec.push(SlotMeta {
				constant: c.clone(),
				guard,
				known: knows,
				wire,
				known_by: slot.known_by.clone(),
				declared_at: slot.declared_at,
				mutatable_to,
				phase: slot.phases.clone(),
			});
			values_vec.push(SlotValues {
				assigned: slot.initial_value.clone(),
				before_rewrite: slot.initial_value.clone(),
				before_mutate: slot.initial_value.clone(),
				mutated: false,
				rewritten: false,
				creator: slot.creator,
				sender,
			});
		}
		states.push(PrincipalState {
			name: principal_name.clone(),
			id: principal_id,
			max_declared_at: trace.max_declared_at,
			meta: Arc::new(meta_vec),
			values: values_vec,
			index: Arc::new(index_map),
		});
	}
	states
}

fn construct_principal_states_get_value_mutatability(
	c: &Constant,
	message: &Message,
	principal_id: PrincipalId,
	creator: PrincipalId,
	wire: &mut Vec<PrincipalId>,
	guard: &mut bool,
	mutatable_to: &mut Vec<PrincipalId>,
) {
	let is_recipient = message.recipient == principal_id;
	let is_creator = creator == principal_id;
	for msg_const in &message.constants {
		if c.id != msg_const.id {
			continue;
		}
		append_unique_principal_enum(wire, message.recipient);
		if !*guard {
			*guard = msg_const.guard && (is_recipient || is_creator);
		}
		if !msg_const.guard {
			append_unique_principal_enum(mutatable_to, message.recipient);
		}
	}
}

pub(crate) fn construct_principal_state_clone(ps: &PrincipalState, purify: bool) -> PrincipalState {
	let values = ps
		.values
		.iter()
		.map(|sv| {
			let (assigned, before_rewrite) = if purify {
				(&sv.before_mutate, &sv.before_mutate)
			} else {
				(&sv.assigned, &sv.before_rewrite)
			};
			SlotValues {
				assigned: assigned.clone(),
				before_rewrite: before_rewrite.clone(),
				before_mutate: sv.before_mutate.clone(),
				mutated: if purify { false } else { sv.mutated },
				rewritten: false,
				creator: sv.creator,
				sender: sv.sender,
			}
		})
		.collect();
	PrincipalState {
		name: ps.name.clone(),
		id: ps.id,
		max_declared_at: ps.max_declared_at,
		meta: ps.meta.clone(),
		values,
		index: ps.index.clone(),
	}
}
