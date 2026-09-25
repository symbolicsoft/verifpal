/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::{Arc, LazyLock, Mutex};

use crate::types::*;
use crate::value::*;

static TEST_NAMES: LazyLock<Mutex<ValueNames>> = LazyLock::new(|| Mutex::new(ValueNames::new()));

pub(crate) fn test_value_id(name: &str) -> ValueId {
	TEST_NAMES
		.lock()
		.unwrap_or_else(|e| e.into_inner())
		.intern(name)
		.expect("test interner exhausted")
}

pub(crate) fn make_trace(slots: Vec<TraceSlot>) -> ProtocolTrace {
	let index = slots
		.iter()
		.enumerate()
		.map(|(i, slot)| (slot.constant.id, i))
		.collect();
	ProtocolTrace {
		slots,
		index,
		..ProtocolTrace::default()
	}
}

pub(crate) fn make_trace_slot(c: &Value, value: &Value, creator: PrincipalId) -> TraceSlot {
	TraceSlot {
		declared_span: Span::default(),
		constant: c.as_constant().expect("a constant names the slot").clone(),
		initial_value: value.clone(),
		creator,
		known_by: vec![],
		sent_by: vec![],
		declared_at: 0,
		phases: vec![],
		mutatable_to: vec![],
		delivery_phase: None,
	}
}

pub(crate) fn make_wire_slot(c: &Value, value: &Value, creator: PrincipalId) -> TraceSlot {
	TraceSlot {
		sent_by: vec![SendEvent {
			sender: creator,
			recipient: 0,
			declared_at: 0,
			phase: 0,
			guarded: false,
		}],
		..make_trace_slot(c, value, creator)
	}
}

pub(crate) fn trace_constant(km: &ProtocolTrace, name: &str) -> Value {
	km.slots
		.iter()
		.find(|s| &*s.constant.name == name)
		.map(|s| Value::Constant(s.constant.clone()))
		.unwrap_or_else(|| panic!("no constant named {name} in trace"))
}

pub(crate) fn make_constant(name: &str) -> Value {
	Value::Constant(Constant {
		name: Arc::from(name),
		id: test_value_id(name),
		guard: false,
		fresh: false,
		leaked: false,
		declaration: Some(Declaration::Knows),
		qualifier: Some(Qualifier::Public),
	})
}

pub(crate) fn make_private(name: &str) -> Value {
	Value::Constant(Constant {
		name: Arc::from(name),
		id: test_value_id(name),
		guard: false,
		fresh: false,
		leaked: false,
		declaration: Some(Declaration::Knows),
		qualifier: Some(Qualifier::Private),
	})
}

pub(crate) fn make_primitive(id: PrimitiveId, args: Vec<Value>, output: usize) -> Value {
	Value::primitive(id, args, output)
}

pub(crate) fn make_attacker_state(known: Vec<Value>) -> AttackerState {
	let mut known_map: IdMap<u64, Vec<usize>> = IdMap::default();
	for (i, v) in known.iter().enumerate() {
		known_map.entry(v.hash_value()).or_default().push(i);
	}
	AttackerState {
		current_phase: 0,
		reused: Arc::new(vec![]),
		derivations: Arc::new(known.iter().map(|_| DerivationRecord::Initial).collect()),
		known: Arc::new(known),
		known_map: Arc::new(known_map),
		chain: crate::types::next_chain(),
	}
}
