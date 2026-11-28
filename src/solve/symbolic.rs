/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::control::Controllable;
use super::vars::{Substitution, attacker_var_id, receiver_var_id};
use crate::engine::program::{Event, Program, RunIdx};
use crate::protocol::ProtocolTrace;
use crate::protocol::SlotIdx;
use crate::syntax::PrincipalId;
use crate::term::{Value, VariableId};
use crate::theory::reduce_once;
use crate::util::IdMap;
use crate::util::index::IndexVec;

#[derive(Default)]
pub(crate) struct SymbolicState {
	pub terms: IndexVec<SlotIdx, Value>,
	pub var_terms: IndexVec<SlotIdx, Option<Value>>,
	pub(crate) named: IndexVec<SlotIdx, Option<VariableId>>,
	pub(crate) points: IndexVec<SlotIdx, Vec<RunIdx>>,
	pub(crate) forwards: IndexVec<SlotIdx, Option<Value>>,
	pub(crate) others: Vec<Receiver>,
}

pub(crate) struct Receiver {
	pub(crate) id: VariableId,
	pub(crate) run: RunIdx,
	pub(crate) slot: SlotIdx,
	pub(crate) term: Value,
	pub(crate) forwarded: Value,
}

impl SymbolicState {
	pub(crate) fn is_var_slot(&self, slot: SlotIdx) -> bool {
		self.var_terms.get(slot).is_some_and(|t| t.is_some())
	}

	pub(crate) fn variables(&self) -> impl Iterator<Item = (SlotIdx, &Value)> + Clone {
		self.var_terms
			.iter_enumerated()
			.filter_map(|(slot, term)| Some((slot, term.as_ref()?)))
	}

	pub(crate) fn var_slots(&self) -> impl Iterator<Item = SlotIdx> + Clone {
		self.variables().map(|(slot, _)| slot)
	}

	pub(crate) fn has_variables(&self) -> bool {
		self.var_terms.iter().any(Option::is_some)
	}

	pub(crate) fn primary(&self, slot: SlotIdx) -> VariableId {
		self.named
			.get(slot)
			.cloned()
			.flatten()
			.unwrap_or_else(|| attacker_var_id(slot))
	}

	pub(crate) fn inputs(&self) -> impl Iterator<Item = (VariableId, SlotIdx, &Value)> + Clone {
		self.variables()
			.map(|(slot, term)| (self.primary(slot), slot, term))
			.chain(
				self.others
					.iter()
					.map(|other| (other.id.clone(), other.slot, &other.term)),
			)
	}

	pub(crate) fn term_of(&self, id: &VariableId) -> Option<&Value> {
		self.inputs()
			.find(|(held, _, _)| held == id)
			.map(|(_, _, term)| term)
	}

	pub(crate) fn installed_at(&self, id: &VariableId) -> &[RunIdx] {
		match self.others.iter().find(|other| other.id == *id) {
			Some(other) => std::slice::from_ref(&other.run),
			None => self
				.points
				.get(super::vars::slot_of_var_id(id))
				.map_or(&[], Vec::as_slice),
		}
	}

	pub(crate) fn variable_at(&self, run: RunIdx, slot: SlotIdx) -> VariableId {
		match self.points.get(slot).is_some_and(|at| at.contains(&run)) {
			true => self.primary(slot),
			false => receiver_var_id(slot, run),
		}
	}

	pub(crate) fn forwarded(&self, id: &VariableId) -> Option<&Value> {
		match self.others.iter().find(|other| other.id == *id) {
			Some(other) => Some(&other.forwarded),
			None => self
				.forwards
				.get(super::vars::slot_of_var_id(id))
				.and_then(Option::as_ref),
		}
	}

	pub(crate) fn forwarding(&self, proposal: &Substitution) -> Substitution {
		let mut out = proposal.clone();
		for other in &self.others {
			if !out.contains_key(&other.id) {
				super::vars::bind(&mut out, other.id.clone(), other.forwarded.clone());
			}
		}
		out
	}
}

fn shaped(var: Value, honest: &Value) -> Value {
	match honest {
		Value::Primitive(_) if crate::primitive::value_is_key_derivation(honest) => {
			crate::primitive::key_derivation_of(var.clone()).unwrap_or(var)
		}
		_ => var,
	}
}

pub(crate) struct View<'a> {
	controllable: Controllable,
	program: &'a Program,
	km: &'a ProtocolTrace,
	principal: PrincipalId,
	within: Option<&'a SymbolicState>,
}

impl<'a> View<'a> {
	pub(crate) fn of(
		program: &'a Program,
		km: &'a ProtocolTrace,
		principal: PrincipalId,
		phase: i32,
	) -> Self {
		View {
			controllable: Controllable::of(program, km, principal, phase),
			program,
			km,
			principal,
			within: None,
		}
	}

	pub(crate) fn within(self, outer: &'a SymbolicState) -> Self {
		View {
			within: Some(outer),
			..self
		}
	}

	pub(crate) fn build(&self) -> SymbolicState {
		self.build_with(&[], &[], true)
	}

	pub(crate) fn build_unshaped(&self) -> SymbolicState {
		self.build_with(&[], &[], false)
	}

	pub(crate) fn build_assuming_honest(&self, honest: &[SlotIdx]) -> SymbolicState {
		self.build_with(honest, &[], true)
	}

	pub(crate) fn build_narrowed(&self, honest: &[SlotIdx], alone: &[SlotIdx]) -> SymbolicState {
		self.build_with(honest, alone, true)
	}

	fn build_with(&self, honest: &[SlotIdx], alone: &[SlotIdx], shape: bool) -> SymbolicState {
		let (km, program) = (self.km, self.program);
		let variable = |id: &VariableId, slot: SlotIdx| match shape {
			true => shaped(Value::Variable(id.clone()), &km.slots[slot].initial_value),
			false => Value::Variable(id.clone()),
		};
		let slots = km.slots.len();
		let mut var_terms: IndexVec<SlotIdx, Option<Value>> = IndexVec::from_elem(None, slots);
		let mut named: IndexVec<SlotIdx, Option<VariableId>> = IndexVec::from_elem(None, slots);
		let mut points: IndexVec<SlotIdx, Vec<RunIdx>> = IndexVec::from_elem(Vec::new(), slots);
		let mut receivers: Vec<(VariableId, RunIdx, SlotIdx)> = Vec::new();
		for slot in km.slots.indices() {
			let Some(proposer) = program.run_index(self.principal) else {
				break;
			};
			if !self.controllable.admits(slot) || honest.contains(&slot) {
				continue;
			}
			let outer = |run: RunIdx| self.within.map(|outer| outer.variable_at(run, slot));
			let mut at = program.points(proposer, slot);
			let id = at
				.first()
				.and_then(|&run| outer(run))
				.unwrap_or_else(|| attacker_var_id(slot));
			for &run in program.receivers(slot) {
				let uses = km.constant_used_by(program.runs[run].id, &km.slots[slot].constant)
					|| program.emits(run, slot, Some(true));
				if !uses || at.contains(&run) || alone.contains(&slot) {
					continue;
				}
				let other = outer(run).unwrap_or_else(|| receiver_var_id(slot, run));
				match other == id {
					true => at.push(run),
					false => receivers.push((other, run, slot)),
				}
			}
			var_terms[slot] = Some(variable(&id, slot));
			named[slot] = Some(id);
			points[slot] = at;
		}
		let held = executed(program, km, &|run, slot| {
			if points[slot].contains(&run) {
				return var_terms[slot].clone();
			}
			receivers
				.iter()
				.find(|(_, at, of)| *at == run && *of == slot)
				.map(|(id, _, _)| variable(id, slot))
		});
		let forwarded = |run: RunIdx, slot: SlotIdx| {
			program
				.receipt(run, slot)
				.and_then(|(delivery, _, _)| held[delivery.sender].get(&slot))
				.unwrap_or(&km.slots[slot].initial_value)
				.clone()
		};
		let forwards = points
			.iter_enumerated()
			.map(|(slot, at)| at.first().map(|&run| forwarded(run, slot)))
			.collect();
		let others = receivers
			.iter()
			.map(|(id, run, slot)| Receiver {
				term: variable(id, *slot),
				id: id.clone(),
				run: *run,
				slot: *slot,
				forwarded: forwarded(*run, *slot),
			})
			.collect();
		let terms = km
			.slots
			.iter_enumerated()
			.map(|(idx, slot)| match &var_terms[idx] {
				Some(var) => var.clone(),
				None => program
					.run_index(slot.creator)
					.and_then(|creator| held[creator].get(&idx))
					.unwrap_or(&slot.initial_value)
					.clone(),
			})
			.collect();
		SymbolicState {
			terms,
			var_terms,
			named,
			points,
			forwards,
			others,
		}
	}
}

pub(crate) fn has_key_shaped_slot(km: &ProtocolTrace) -> bool {
	km.slots
		.iter()
		.any(|slot| crate::primitive::value_is_key_derivation(&slot.initial_value))
}

fn resolved(v: &Value, held: &IdMap<SlotIdx, Value>, km: &ProtocolTrace) -> Value {
	match v {
		Value::Variable(_) => v.clone(),
		Value::Constant(c) => km
			.index_of(c)
			.and_then(|slot| held.get(&slot))
			.unwrap_or(v)
			.clone(),
		Value::Primitive(p) => {
			let arguments = p.arguments.iter().map(|a| resolved(a, held, km)).collect();
			Value::Primitive(Arc::new(p.with_arguments(arguments)))
		}
	}
}

pub(crate) fn executed(
	program: &Program,
	km: &ProtocolTrace,
	taken: &dyn Fn(RunIdx, SlotIdx) -> Option<Value>,
) -> IndexVec<RunIdx, IdMap<SlotIdx, Value>> {
	let mut held: IndexVec<RunIdx, IdMap<SlotIdx, Value>> =
		IndexVec::from_elem(IdMap::default(), program.runs.len());
	for &(run, step) in &program.order {
		match program.runs[run].steps[step].event {
			Event::Hold(slot) => {
				held[run].insert(slot, km.slots[slot].initial_value.clone());
			}
			Event::Assign(slot) => {
				let value = reduce_once(&resolved(&km.slots[slot].initial_value, &held[run], km));
				held[run].insert(slot, value);
			}
			Event::Recv(d) => {
				let delivery = &program.deliveries[d];
				for &(slot, guarded) in &delivery.slots {
					let value = (!guarded)
						.then(|| taken(run, slot))
						.flatten()
						.or_else(|| held[delivery.sender].get(&slot).cloned())
						.unwrap_or_else(|| km.slots[slot].initial_value.clone());
					held[run].insert(slot, value);
				}
			}
			Event::Send(_) | Event::Leak(_) => {}
		}
	}
	held
}

#[cfg(test)]
mod tests {
	use super::*;

	const SRC: &str = "attacker[active]\n\
		principal Alice[\n\
		generates sym_a\n\
		sym_ga = PUBKEY(sym_a)\n\
		]\n\
		Alice -> Bob: sym_ga\n\
		principal Bob[\n\
		knows private sym_b\n\
		sym_k = DH_KEX(sym_ga, sym_b)\n\
		sym_t = HASH(sym_k)\n\
		]\n\
		queries[\n\
		confidentiality? sym_a\n\
		]\n";

	fn bob() -> (ProtocolTrace, Program, PrincipalId) {
		let m = crate::syntax::parser::parse_string("sym.vp", SRC).expect("parses");
		let km = crate::protocol::sanity::sanity(&m).expect("passes sanity");
		let program = Program::of(&m, &km);
		let bob = km.principal_ids[km
			.principals
			.iter()
			.position(|p| p == "Bob")
			.expect("Bob exists")];
		(km, program, bob)
	}

	fn slot(km: &ProtocolTrace, name: &str) -> SlotIdx {
		km.slots
			.position(|s| &*s.constant.name == name)
			.unwrap_or_else(|| panic!("no slot named {name}"))
	}

	#[test]
	fn a_controllable_wire_slot_becomes_a_variable_shaped_like_what_it_replaced() {
		let (km, program, bob) = bob();
		let sym = View::of(&program, &km, bob, 0).build();
		let ga = slot(&km, "sym_ga");
		assert!(
			sym.is_var_slot(ga),
			"an unguarded wire value is controllable"
		);
		assert!(
			crate::solve::vars::contains_var(&sym.terms[slot(&km, "sym_k")]),
			"the key Bob computes is a function of the slot the attacker controls, so \
			 the symbolic term has to carry the variable: got {}",
			sym.terms[slot(&km, "sym_k")]
		);
		assert!(
			crate::solve::vars::contains_var(&sym.terms[slot(&km, "sym_t")]),
			"and so does everything downstream of it"
		);
	}

	#[test]
	fn holding_one_slot_honest_removes_it_from_the_variables_and_from_every_term() {
		let (km, program, bob) = bob();
		let ga = slot(&km, "sym_ga");
		let refined = View::of(&program, &km, bob, 0).build_assuming_honest(&[ga]);
		assert!(!refined.is_var_slot(ga), "the held slot is not a variable");
		assert!(!refined.has_variables());
		for name in ["sym_ga", "sym_k", "sym_t"] {
			assert!(
				!crate::solve::vars::contains_var(&refined.terms[slot(&km, name)]),
				"{name} still mentions a variable after the only controllable slot \
				 was held honest"
			);
		}
	}

	#[test]
	fn a_slot_this_principal_created_is_never_a_variable() {
		let (km, program, bob) = bob();
		let sym = View::of(&program, &km, bob, 0).build();
		for name in ["sym_b", "sym_k", "sym_t"] {
			assert!(
				!sym.is_var_slot(slot(&km, name)),
				"{name} is Bob's own, so the attacker cannot replace it"
			);
		}
	}

	#[test]
	fn a_guarded_receive_takes_what_its_sender_holds() {
		let source = "attacker[active]\n\
			principal Alice[\n\
			generates fwd_x\n\
			]\n\
			Alice -> Bob: fwd_x\n\
			principal Bob[\n\
			fwd_b = HASH(fwd_x)\n\
			]\n\
			Bob -> Carol: [fwd_x]\n\
			principal Carol[\n\
			fwd_c = HASH(fwd_x)\n\
			]\n\
			queries[\n\
			confidentiality? fwd_x\n\
			]\n";
		let m = crate::syntax::parser::parse_string("fwd.vp", source).expect("parses");
		let km = crate::protocol::sanity::sanity(&m).expect("passes sanity");
		let program = Program::of(&m, &km);
		let run = |name: &str| program.runs.position(|r| r.name == name).expect("run");
		let x = slot(&km, "fwd_x");
		let var = crate::solve::vars::attacker_var(x);
		let held = executed(&program, &km, &|run, at| {
			(program.runs[run].name == "Bob" && at == x).then(|| var.clone())
		});
		assert!(crate::solve::vars::contains_var(
			&held[run("Carol")][&slot(&km, "fwd_c")]
		));
		assert!(!crate::solve::vars::contains_var(&held[run("Alice")][&x]));
		let held = executed(&program, &km, &|run, at| {
			(program.runs[run].name == "Carol" && at == x).then(|| var.clone())
		});
		assert!(
			!crate::solve::vars::contains_var(&held[run("Carol")][&slot(&km, "fwd_c")]),
			"a guarded receive takes no install"
		);
	}
}
