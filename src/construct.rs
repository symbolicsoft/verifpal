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
		leaks: Arc::new(Vec::new()),
	};
	let mut leaks: Vec<LeakEvent> = Vec::new();
	let mut declared_at = 0i32;
	let mut current_phase = 0i32;

	for builtin in &[value_g(), value_nil()] {
		let c = match builtin.as_constant() {
			Some(c) => c.clone(),
			None => continue,
		};
		let known_by: Vec<_> = principal_ids.iter().map(|&pid| (pid, pid)).collect();
		let const_id = c.id;
		trace.slots.push(TraceSlot {
			constant: c,
			initial_value: builtin.clone(),
			creator: ATTACKER_ID,
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
					&mut leaks,
					principal,
					declared_at,
					current_phase,
				)?;
			}
			Block::Message(message) => {
				declared_at += 1;
				trace.max_declared_at = declared_at;
				construct_trace_render_message(&mut trace, message, current_phase)
					.map_err(|e| e.or_span(message.span))?;
			}
			Block::Phase(phase) => {
				current_phase = phase.number;
			}
		}
	}
	trace.max_phase = current_phase;
	trace.used_by = construct_trace_used_by(&trace);
	trace.leaks = Arc::new(leaks);
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
	leaks: &mut Vec<LeakEvent>,
	principal: &Principal,
	mut declared_at: i32,
	current_phase: i32,
) -> VResult<i32> {
	for expr in &principal.expressions {
		let located = |e: VerifpalError| e.or_span(expr.span);
		match expr.kind {
			Declaration::Knows => {
				construct_trace_render_knows(trace, principal, declared_at, expr)
					.map_err(located)?;
			}
			Declaration::Generates => {
				construct_trace_render_generates(trace, principal, declared_at, expr)
					.map_err(located)?;
			}
			Declaration::Assignment => {
				construct_trace_render_assignment(trace, principal, declared_at, expr)
					.map_err(located)?;
			}
			Declaration::Leaks => {
				declared_at += 1;
				construct_trace_render_leaks(
					trace,
					leaks,
					principal,
					expr,
					current_phase,
					declared_at,
				)
				.map_err(located)?;
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
				return Err(VerifpalError::sanity(
					format!(
						"constant is known more than once and in different ways ({})",
						c
					)
					.into(),
				));
			}
			trace.slots[idx].known_by.push((principal.id, principal.id));
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
			initial_value: Value::Constant(new_c.clone()),
			constant: new_c,
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
				trace.slots[slot_idx].known_by.push((pid, pid));
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
			return Err(VerifpalError::sanity(
				format!("generated constant already exists ({})", c).into(),
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
		let const_id = new_c.id;
		trace.slots.push(TraceSlot {
			initial_value: Value::Constant(new_c.clone()),
			constant: new_c,
			creator: principal.id,
			known_by: vec![],
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
	let assigned = expr
		.assigned
		.as_ref()
		.ok_or_else(|| VerifpalError::sanity("missing assignment value".into()))?;
	let constants = sanity_assignment_constants(assigned, &[], trace)?;
	if let Value::Primitive(p) = assigned {
		sanity_primitive(p, &expr.constants)?;
	}
	for c in &constants {
		let idx = match trace.index_of(c) {
			Some(idx) => idx,
			None => {
				return Err(VerifpalError::sanity(
					format!("constant does not exist ({})", c).into(),
				));
			}
		};
		let knows = trace.slots[idx].known_by_principal(principal.id);
		if !knows {
			return Err(VerifpalError::sanity(
				format!(
					"{} is using constant ({}) despite not knowing it",
					principal.name, c
				)
				.into(),
			));
		}
	}
	for (output_idx, c) in expr.constants.iter().enumerate() {
		if trace.index_of(c).is_some() {
			return Err(VerifpalError::sanity(
				format!("constant assigned twice ({})", c).into(),
			));
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
			known_by: vec![],
			declared_at,
			phases: vec![],
		});
		trace.index.insert(const_id, trace.slots.len() - 1);
	}
	Ok(())
}

fn construct_trace_render_leaks(
	trace: &mut ProtocolTrace,
	leaks: &mut Vec<LeakEvent>,
	principal: &Principal,
	expr: &Expression,
	current_phase: i32,
	declared_at: i32,
) -> VResult<()> {
	for c in &expr.constants {
		let idx = match trace.index_of(c) {
			Some(idx) => idx,
			None => {
				return Err(VerifpalError::sanity(
					format!("leaked constant does not exist ({})", c).into(),
				));
			}
		};
		let known = trace.slots[idx].known_by_principal(principal.id);
		if !known {
			return Err(VerifpalError::sanity(
				format!(
					"{} leaks a constant that they do not know ({})",
					principal.name, c
				)
				.into(),
			));
		}
		trace.slots[idx].constant.leaked = true;
		append_unique(&mut trace.slots[idx].phases, current_phase);
		leaks.push(LeakEvent {
			constant_id: c.id,
			principal_id: principal.id,
			declared_at,
			phase: current_phase,
		});
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
				return Err(VerifpalError::sanity(
					format!(
						"{} sends unknown constant to {} ({})",
						message.sender_name, message.recipient_name, c
					)
					.into(),
				));
			}
		};
		let sender_knows = trace.slots[idx].known_by_principal(message.sender);
		let recipient_knows = trace.slots[idx].known_by_principal(message.recipient);
		if !sender_knows {
			return Err(VerifpalError::sanity(
				format!(
					"{} is sending constant ({}) despite not knowing it",
					message.sender_name, c
				)
				.into(),
			));
		}
		if recipient_knows {
			return Err(VerifpalError::sanity(
				format!(
					"{} is receiving constant ({}) despite already knowing it",
					message.recipient_name, c
				)
				.into(),
			));
		}
		trace.slots[idx]
			.known_by
			.push((message.recipient, message.sender));
		append_unique(&mut trace.slots[idx].phases, current_phase);
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

		let wire_index = construct_wire_index(m, trace, principal_id);

		for slot in &trace.slots {
			let c = &slot.constant;
			let mut knows = slot.creator == principal_id;
			let mut sender = slot.creator;
			for &(recipient, from) in &slot.known_by {
				if recipient == principal_id {
					sender = from;
					knows = true;
					break;
				}
			}
			let travel = wire_index.get(&c.id);
			index_map.insert(c.id, meta_vec.len());
			meta_vec.push(SlotMeta {
				constant: c.clone(),
				guard: travel.is_some_and(|t| t.guard),
				known: knows,
				wire: travel.map(|t| t.wire.clone()).unwrap_or_default(),
				known_by: slot.known_by.clone(),
				declared_at: slot.declared_at,
				mutatable_to: travel.map(|t| t.mutatable_to.clone()).unwrap_or_default(),
				phase: slot.phases.clone(),
			});
			values_vec.push(SlotValues {
				value: slot.initial_value.clone(),
				pre_rewrite: slot.initial_value.clone(),
				original: slot.initial_value.clone(),
				rewritten: false,
				provenance: Provenance {
					creator: slot.creator,
					sender,
					attacker_tainted: false,
					bypass_injected: false,
				},
			});
		}
		states.push(PrincipalState {
			name: principal_name.clone(),
			id: principal_id,
			max_declared_at: trace.max_declared_at,
			meta: Arc::new(meta_vec),
			values: values_vec,
			index: Arc::new(index_map),
			leaks: trace.leaks.clone(),
			halted_at: None,
		});
	}
	states
}

/// How a value travelled on the wire, from one principal's point of view.
#[derive(Default)]
struct WireTravel {
	wire: Vec<PrincipalId>,
	guard: bool,
	mutatable_to: Vec<PrincipalId>,
}

/// Index every message once per principal.
///
/// The alternative is rescanning the whole model for each slot, which makes
/// state construction grow with principals × slots × messages rather than with
/// the size of the model.
fn construct_wire_index(
	m: &Model,
	trace: &ProtocolTrace,
	principal_id: PrincipalId,
) -> HashMap<ValueId, WireTravel> {
	let mut index: HashMap<ValueId, WireTravel> = HashMap::new();
	for block in &m.blocks {
		let Block::Message(message) = block else {
			continue;
		};
		for msg_const in &message.constants {
			let Some(slot_idx) = trace.index_of(msg_const) else {
				continue;
			};
			let is_recipient = message.recipient == principal_id;
			let is_creator = trace.slots[slot_idx].creator == principal_id;
			let travel = index.entry(msg_const.id).or_default();
			append_unique(&mut travel.wire, message.recipient);
			if !travel.guard {
				travel.guard = msg_const.guard && (is_recipient || is_creator);
			}
			if !msg_const.guard {
				append_unique(&mut travel.mutatable_to, message.recipient);
			}
		}
	}
	index
}

impl PrincipalState {
	/// Deep-clone this state; `purify` resets every value to its pre-mutation
	/// form, discarding attacker taint and any halt.
	pub fn clone_for_depth(&self, purify: bool) -> PrincipalState {
		let values = self
			.values
			.iter()
			.map(|sv| {
				let (value, pre_rewrite) = if purify {
					(&sv.original, &sv.original)
				} else {
					(&sv.value, &sv.pre_rewrite)
				};
				SlotValues {
					value: value.clone(),
					pre_rewrite: pre_rewrite.clone(),
					original: sv.original.clone(),
					rewritten: false,
					provenance: Provenance {
						creator: sv.provenance.creator,
						sender: sv.provenance.sender,
						attacker_tainted: if purify {
							false
						} else {
							sv.provenance.attacker_tainted
						},
						bypass_injected: if purify {
							false
						} else {
							sv.provenance.bypass_injected
						},
					},
				}
			})
			.collect();
		PrincipalState {
			name: self.name.clone(),
			id: self.id,
			max_declared_at: self.max_declared_at,
			meta: self.meta.clone(),
			values,
			index: self.index.clone(),
			leaks: self.leaks.clone(),
			halted_at: if purify { None } else { self.halted_at },
		}
	}
}
