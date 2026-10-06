/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::primitive::CapabilityIndex;
use crate::syntax::names::{ATTACKER_ID, ATTACKER_NAME};
use crate::syntax::{PrincipalId, Span};
use crate::term::{Constant, Value, ValueId, copy_index_of, hashing};
use crate::util::{IdMap, IdSet};

#[derive(Clone, Debug)]
pub struct TraceSlot {
	pub declared_span: Span,
	pub constant: Constant,
	pub initial_value: Value,
	pub creator: PrincipalId,
	pub known_by: Vec<(PrincipalId, PrincipalId)>,
	pub sent_by: Vec<SendEvent>,
	pub declared_at: i32,
	pub phases: Vec<i32>,
	pub mutatable_to: Vec<PrincipalId>,
	pub delivery_phase: Option<i32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendEvent {
	pub sender: PrincipalId,
	pub recipient: PrincipalId,
	pub declared_at: i32,
	pub phase: i32,
	pub guarded: bool,
}

impl TraceSlot {
	pub fn known_by_principal(&self, pid: PrincipalId) -> bool {
		self.creator == pid || self.known_by.iter().any(|&(recipient, _)| recipient == pid)
	}

	pub(crate) fn sender_to(&self, pid: PrincipalId) -> PrincipalId {
		self.known_by
			.iter()
			.find(|&&(recipient, _)| recipient == pid)
			.map_or(self.creator, |&(_, from)| from)
	}

	pub(crate) fn guarded_for(&self, pid: PrincipalId) -> bool {
		self.sent_by
			.iter()
			.any(|event| event.guarded && (event.recipient == pid || self.creator == pid))
	}

	pub(crate) fn sent_from(&self, pid: PrincipalId) -> bool {
		self.sent_by.iter().any(|event| event.sender == pid)
	}

	pub(crate) fn disclosed(&self) -> bool {
		!self.sent_by.is_empty() || self.constant.leaked
	}

	pub(crate) fn mutation_reaches(&self, pid: PrincipalId) -> bool {
		self.mutatable_to.contains(&pid)
	}

	pub(crate) fn substitution_phase(&self, recipient: PrincipalId) -> Option<i32> {
		self.substitution_phase_from(recipient, &mut Vec::new())
	}

	fn substitution_phase_from(
		&self,
		recipient: PrincipalId,
		visiting: &mut Vec<PrincipalId>,
	) -> Option<i32> {
		if visiting.contains(&recipient) {
			return None;
		}
		visiting.push(recipient);
		let earliest = self
			.sent_by
			.iter()
			.filter(|event| event.recipient == recipient)
			.filter_map(|event| {
				if event.guarded {
					self.substitution_phase_from(event.sender, visiting)
				} else {
					Some(event.phase)
				}
			})
			.min();
		visiting.pop();
		earliest
	}
}

#[derive(Clone, Debug, Default)]
pub struct ProtocolTrace {
	pub principals: Vec<String>,
	pub principal_ids: Vec<PrincipalId>,
	pub slots: Vec<TraceSlot>,
	pub index: IdMap<ValueId, usize>,
	pub max_phase: i32,
	pub used_by: IdMap<ValueId, IdSet<PrincipalId>>,
	pub leaks: Vec<LeakEvent>,
	pub session_siblings: IdMap<ValueId, Arc<Vec<ValueId>>>,
	pub copy_siblings: IdMap<ValueId, Arc<Vec<ValueId>>>,
	pub interchangeable: IdMap<PrincipalId, PrincipalId>,
	pub actors: IdMap<PrincipalId, PrincipalId>,
	pub scenario_bound: IdSet<ValueId>,
	pub equivalence_queried: IdSet<ValueId>,
	pub capabilities: CapabilityIndex,
}

impl ProtocolTrace {
	pub fn index_of(&self, c: &Constant) -> Option<usize> {
		self.index.get(&c.id).copied()
	}

	pub fn principal_name(&self, id: PrincipalId) -> &str {
		if id == ATTACKER_ID {
			return ATTACKER_NAME;
		}
		self.principal_ids
			.iter()
			.position(|&p| p == id)
			.and_then(|i| self.principals.get(i))
			.map(String::as_str)
			.unwrap_or("")
	}

	pub fn constant_used_by(&self, principal_id: PrincipalId, c: &Constant) -> bool {
		self.used_by
			.get(&c.id)
			.is_some_and(|principals| principals.contains(&principal_id))
	}

	pub(crate) fn same_actor(&self, a: PrincipalId, b: PrincipalId) -> bool {
		Self::grouped(&self.actors, a, b)
	}

	pub(crate) fn sibling_slots(&self, slot: usize) -> Vec<usize> {
		let id = self.slots[slot].constant.id;
		let mut out = vec![slot];
		for group in [&self.session_siblings, &self.copy_siblings]
			.into_iter()
			.filter_map(|groups| groups.get(&id))
		{
			for &at in group.iter().filter_map(|sid| self.index.get(sid)) {
				if !out.contains(&at) {
					out.push(at);
				}
			}
		}
		out
	}

	pub(crate) fn interchangeable_for(&self, a: PrincipalId, b: PrincipalId, slot: usize) -> bool {
		if Self::grouped(&self.interchangeable, a, b) {
			return true;
		}
		if !self.same_actor(a, b) || self.scenario_bound.is_empty() {
			return false;
		}
		let Some(trace_slot) = self.slots.get(slot) else {
			return false;
		};
		!resolve_trace_constant(&trace_slot.constant, self)
			.constant_leaves()
			.any(|c| self.scenario_bound.contains(&copy_index_of(c.id).1))
	}

	fn grouped(map: &IdMap<PrincipalId, PrincipalId>, a: PrincipalId, b: PrincipalId) -> bool {
		a == b || map.get(&a).copied().unwrap_or(a) == map.get(&b).copied().unwrap_or(b)
	}

	pub(crate) fn session_sibling_values(&self, c: &Constant) -> Vec<Value> {
		let Some(group) = self.session_siblings.get(&c.id) else {
			return Vec::new();
		};
		group
			.iter()
			.filter(|&&sid| sid != c.id)
			.filter_map(|&sid| {
				let &slot = self.index.get(&sid)?;
				Some(resolve_trace_constant(&self.slots[slot].constant, self))
			})
			.collect()
	}
}

#[derive(Clone, Debug)]
pub struct LeakEvent {
	pub constant_id: ValueId,
	pub principal_id: PrincipalId,
	pub declared_at: i32,
}

type TraceMemo = IdMap<usize, Option<Value>>;

pub(crate) fn resolve_trace_constant(c: &Constant, trace: &ProtocolTrace) -> Value {
	let value = Value::Constant(c.clone());
	resolve_trace_value(&value, trace, &mut TraceMemo::default()).unwrap_or(value)
}

pub(crate) fn resolve_trace_term(value: &Value, trace: &ProtocolTrace) -> Value {
	resolve_trace_value(value, trace, &mut TraceMemo::default()).unwrap_or_else(|| value.clone())
}

fn resolve_trace_value(
	value: &Value,
	trace: &ProtocolTrace,
	memo: &mut TraceMemo,
) -> Option<Value> {
	let Value::Constant(c) = value else {
		return resolve_trace_primitive(value, trace, memo);
	};
	let idx = trace.index_of(c)?;
	if let Some(hit) = memo.get(&idx) {
		return hit.clone();
	}
	let resolved = &trace.slots[idx].initial_value;
	let out = match resolved {
		Value::Variable(_) => Some(resolved.clone()),
		Value::Constant(rc) => (rc.id != c.id).then(|| resolved.clone()),
		Value::Primitive(_) => {
			Some(resolve_trace_primitive(resolved, trace, memo).unwrap_or_else(|| resolved.clone()))
		}
	};
	memo.insert(idx, out.clone());
	out
}

fn resolve_trace_primitive(
	value: &Value,
	trace: &ProtocolTrace,
	memo: &mut TraceMemo,
) -> Option<Value> {
	let Value::Primitive(prim) = value else {
		return None;
	};
	prim.map_arguments(|arg| resolve_trace_value(arg, trace, memo))
		.map(|mapped| hashing::hashcons(&Value::Primitive(Arc::new(mapped))))
}

pub(crate) fn mentions_across_principals(
	value: &Value,
	trace: &ProtocolTrace,
	principal: PrincipalId,
	target: ValueId,
) -> bool {
	let mut pending = vec![(value, principal)];
	let mut seen = IdSet::default();
	while let Some((value, owner)) = pending.pop() {
		match value {
			Value::Variable(_) => {}
			Value::Constant(c) => {
				if c.id == target {
					if trace.index_of(c).is_some_and(|idx| {
						owner == principal || trace.slots[idx].mutation_reaches(owner)
					}) {
						return true;
					}
					continue;
				}
				let Some(slot) = trace.index_of(c).map(|idx| &trace.slots[idx]) else {
					continue;
				};
				if matches!(slot.initial_value, Value::Primitive(_)) {
					pending.push((&slot.initial_value, slot.creator));
				}
			}
			Value::Primitive(p) => {
				if seen.insert((Arc::as_ptr(p) as usize, owner)) {
					pending.extend(p.arguments.iter().rev().map(|arg| (arg, owner)));
				}
			}
		}
	}
	false
}

pub(crate) fn principal_uses_constant(
	trace: &ProtocolTrace,
	principal: PrincipalId,
	c: &Constant,
) -> bool {
	trace.slots.iter().any(|slot| {
		slot.creator == principal
			&& matches!(&slot.initial_value, Value::Primitive(_))
			&& mentions_across_principals(&slot.initial_value, trace, principal, c.id)
	})
}

pub(crate) fn constant_used_by_any_principal(trace: &ProtocolTrace, c: &Constant) -> bool {
	trace
		.principal_ids
		.iter()
		.any(|&principal| principal_uses_constant(trace, principal, c))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::Capability;
	use crate::term::{Primitive, value_nil};
	use crate::testing::*;

	#[test]
	fn repeated_resolution_shares_ground_terms_and_tracks_changed_inputs() {
		let model = crate::syntax::parser::parse_string("resolved.vp", "attacker[active]\nprincipal Sender[generates a, b]\nSender -> Reader: a, b\nprincipal Reader[x = HASH(a)\ny = HASH(x)\nz = HASH(b)]\nqueries[confidentiality? y]\n").unwrap();
		let trace = crate::protocol::sanity::sanity(&model).unwrap();
		let y = trace_constant(&trace, "y");
		let first = resolve_trace_term(&y, &trace);
		let second = resolve_trace_term(&y, &trace);
		assert!(first.same_term(&second));
		let changed = resolve_trace_term(
			&Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![trace_constant(&trace, "z")],
				0,
			),
			&trace,
		);
		assert!(!first.equivalent(&changed, true));
	}

	fn resolved_primitive(mapped: Primitive) -> Value {
		hashing::hashcons(&Value::Primitive(Arc::new(mapped)))
	}

	#[test]
	fn resolved_terms_preserve_annotations_checks_and_constant_metadata() {
		let input = make_constant("resolution_metadata_input");
		let source = Arc::new(Primitive::new(
			crate::primitive::PRIM_ENC,
			vec![input.clone(), input.clone()],
			0,
		));
		let output = make_constant("resolution_metadata_output");
		let plain = resolved_primitive(source.with_arguments(vec![input.clone(), output.clone()]));
		let mut annotated = source.as_ref().clone();
		annotated.capabilities.set(Capability::Weak, 2);
		annotated.instance_check = true;
		let annotated = Arc::new(annotated);
		let checked =
			resolved_primitive(annotated.with_arguments(vec![input.clone(), output.clone()]));
		assert!(checked.as_primitive().unwrap().instance_check);
		assert_eq!(
			checked.as_primitive().unwrap().capabilities,
			annotated.capabilities
		);
		assert!(!plain.as_primitive().unwrap().instance_check);
		let parent = Arc::new(Primitive::new(
			crate::primitive::PRIM_HASH,
			vec![input.clone()],
			0,
		));
		let plain_parent = resolved_primitive(parent.with_arguments(vec![plain.clone()]));
		let checked_parent = resolved_primitive(parent.with_arguments(vec![checked]));
		assert!(
			!plain_parent.as_primitive().unwrap().arguments[0]
				.as_primitive()
				.unwrap()
				.instance_check
		);
		assert!(
			checked_parent.as_primitive().unwrap().arguments[0]
				.as_primitive()
				.unwrap()
				.instance_check
		);
		let mut fresh = output.as_constant().unwrap().clone();
		fresh.fresh = true;
		let changed =
			resolved_primitive(source.with_arguments(vec![input, Value::Constant(fresh)]));
		assert!(
			changed.as_primitive().unwrap().arguments[1]
				.as_constant()
				.unwrap()
				.fresh
		);
		assert!(
			!plain.as_primitive().unwrap().arguments[1]
				.as_constant()
				.unwrap()
				.fresh
		);
	}

	#[test]
	fn use_checks_visit_shared_terms_without_expanding_their_occurrences() {
		let target = make_constant("mentions_dag_target");
		let seed = make_constant("mentions_dag_seed");
		let trace = make_trace(vec![make_trace_slot(&target, &target, 1)]);
		let mut term = seed;
		for _ in 0..40 {
			term = Value::primitive(
				crate::primitive::PRIM_HASH,
				vec![term.clone(), term.clone(), term],
				0,
			);
		}
		let id = target.as_constant().unwrap().id;
		assert!(!mentions_across_principals(&term, &trace, 1, id));
		let used = Value::primitive(crate::primitive::PRIM_HASH, vec![term, target], 0);
		assert!(mentions_across_principals(&used, &trace, 1, id));
	}

	#[test]
	fn use_checks_keep_distinct_owners_of_a_shared_term() {
		let model = crate::syntax::parser::parse_string(
			"mentions_owner.vp",
			"attacker[passive]\n\
			principal Alice[generates target\n sealed = HASH(target)]\n\
			Alice -> Bob: target, sealed\n\
			principal Bob[local = HASH(target)]\n\
			queries[confidentiality? target]\n",
		)
		.unwrap();
		let trace = crate::protocol::sanity::sanity(&model).unwrap();
		let bob = trace.principal_ids[trace.principals.iter().position(|p| p == "Bob").unwrap()];
		let target = trace_constant(&trace, "target");
		let sealed = trace_constant(&trace, "sealed");
		let slot = trace.index_of(sealed.as_constant().unwrap()).unwrap();
		let shared = trace.slots[slot].initial_value.clone();
		let id = target.as_constant().unwrap().id;
		assert!(!mentions_across_principals(&sealed, &trace, bob, id));
		let both = Value::primitive(crate::primitive::PRIM_HASH, vec![sealed, shared], 0);
		assert!(mentions_across_principals(&both, &trace, bob, id));
	}

	#[test]
	fn trace_slot_known_by_creator() {
		let c = Constant {
			name: Arc::from("ts_a"),
			id: test_value_id("ts_a"),
			..Constant::default()
		};
		let slot = make_trace_slot(&Value::Constant(c), &value_nil(), 0);
		assert!(slot.known_by_principal(0));
		assert!(!slot.known_by_principal(1));
	}

	#[test]
	fn trace_slot_known_by_receiver() {
		let c = Constant {
			name: Arc::from("ts2_a"),
			id: test_value_id("ts2_a"),
			..Constant::default()
		};
		let slot = TraceSlot {
			known_by: vec![(1, 0)],
			sent_by: vec![SendEvent {
				sender: 0,
				recipient: 1,
				declared_at: 1,
				phase: 0,
				guarded: false,
			}],
			..make_trace_slot(&Value::Constant(c), &value_nil(), 0)
		};
		assert!(slot.known_by_principal(1));
	}

	#[test]
	fn trace_index_of() {
		let a = make_constant("ps_idx_a");
		let km = make_trace(vec![make_trace_slot(&a, &a, 0)]);
		assert_eq!(km.index_of(a.as_constant().unwrap()), Some(0));
		let other = make_constant("ps_idx_b");
		assert_eq!(km.index_of(other.as_constant().unwrap()), None);
	}
}
