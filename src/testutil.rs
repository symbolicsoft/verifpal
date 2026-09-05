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

pub(crate) fn make_trace() -> ProtocolTrace {
	ProtocolTrace::default()
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
	let free = Arc::new(MutationRecord {
		diffs: vec![],
		principal_id: crate::principal::ATTACKER_ID,
		phase: 0,
	});
	AttackerState {
		current_phase: 0,
		mutation_records: Arc::new(known.iter().map(|_| Arc::clone(&free)).collect()),
		alternates: Arc::new(vec![Vec::new(); known.len()]),
		reused: Arc::new(vec![]),
		derivations: Arc::new(known.iter().map(|_| DerivationRecord::Initial).collect()),
		known: Arc::new(known),
		known_map: Arc::new(known_map),
	}
}

pub(crate) fn make_principal_state(
	name: &str,
	id: PrincipalId,
	mut meta: Vec<SlotMeta>,
	values: Vec<SlotValues>,
) -> PrincipalState {
	let mut index = IdMap::default();
	for (m, v) in meta.iter_mut().zip(values.iter()) {
		m.creator = v.provenance.creator;
	}
	for (i, m) in meta.iter().enumerate() {
		index.insert(m.constant.id, i);
	}
	PrincipalState {
		name: name.to_string(),
		id,
		meta: Arc::new(meta),
		values,
		index: Arc::new(index),
		leaks: Arc::new(Vec::new()),
		halted_at: None,
		forwarded: false,
		foreign_halts: Vec::new(),
		capabilities: Arc::new(CapabilityIndex::default()),
	}
}

pub(crate) fn make_slot_meta(c: &Constant, creator_is_self: bool) -> SlotMeta {
	SlotMeta {
		constant: c.clone(),
		creator: 0,
		guard: false,
		known: true,
		wire: if creator_is_self { vec![] } else { vec![0] },
		known_by: vec![],
		sent_at: None,
		declared_at: 0,
		mutatable_to: vec![],
		phase: vec![0],
	}
}

pub(crate) fn make_slot_values(v: &Value, creator: PrincipalId) -> SlotValues {
	SlotValues {
		bypassed: None,
		value: v.clone(),
		pre_rewrite: v.clone(),
		original: v.clone(),
		provenance: Provenance {
			creator,
			sender: creator,
			attacker_tainted: false,
			bypass_injected: false,
		},
	}
}
