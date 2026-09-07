/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::RefCell;

use crate::context::{Generational, KnowledgeKey, Recent, VerifyContext};
use crate::primitive::admissible;
use crate::principal::ATTACKER_ID;
use crate::reexec::{Controllable, TermBound, governing_attacker, reexecute_at, same_installs};
use crate::solve::validate::attacker_can_derive;
use crate::theory::reduce_once;
use crate::types::*;
use crate::value::{copy_index_of, copy_value_id, resolve_trace_constant};

pub(crate) fn emitted_by_matching_run(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	slot: usize,
	sender: PrincipalId,
	attacker: &AttackerState,
) -> bool {
	if sender == ATTACKER_ID {
		return false;
	}
	let (Some(delivered), Some(claimed)) = (ps.values.get(slot), km.slots.get(slot)) else {
		return false;
	};
	let (run, base) = copy_index_of(claimed.constant.id);
	let target = reduce_once(&delivered.value);
	let candidates: Vec<usize> = (0..km.slots.len())
		.filter(|&j| corresponds(km, j, base, sender, ps.id))
		.filter(|&j| !pristine_is(km, j, &target))
		.collect();
	if candidates.is_empty() || forgeable_without_sender(km, ps, sender, &target, attacker) {
		return false;
	}
	let bound = ctx.term_bound(km);
	let driving = driving_installs(attacker, &target);
	let mut controllables: Vec<(PrincipalId, Controllable)> = Vec::new();
	candidates.into_iter().any(|j| {
		let Some(origin) = origin_of(ctx, km, j) else {
			return false;
		};
		if !controllables.iter().any(|(id, _)| *id == origin.id) {
			controllables.push((origin.id, Controllable::of(km, origin, attacker)));
		}
		let controllable = controllables
			.iter()
			.find(|(id, _)| *id == origin.id)
			.map(|(_, controllable)| controllable)
			.expect("just inserted");
		if controllable.admits(origin, attacker, j) {
			return false;
		}
		let guards = Emission {
			ctx,
			km,
			origin,
			controllable,
			attacker,
			bound,
			j,
		};
		guards.emits(&target, |at| delivered_to(ps, at))
			|| driving.as_ref().is_some_and(|(read_at, diffs)| {
				*read_at == j
					&& guards.emits(&target, |at| {
						diffs
							.iter()
							.find(|(slot, _)| *slot == at)
							.map(|(_, value)| value.clone())
					})
			}) || (j != slot
			&& guards.emits(&target, |at| run_copy(km, &origin.meta[at].constant, run)))
	})
}

struct Emission<'a> {
	ctx: &'a VerifyContext,
	km: &'a ProtocolTrace,
	origin: &'a PrincipalState,
	controllable: &'a Controllable,
	attacker: &'a AttackerState,
	bound: &'a TermBound,
	j: usize,
}

impl Emission<'_> {
	fn emits(&self, target: &Value, choose: impl Fn(usize) -> Option<Value>) -> bool {
		let origin = self.origin;
		let mut installs: Vec<(SlotIdx, Value)> = Vec::new();
		for at in 0..origin.values.len() {
			if !self.controllable.admits(origin, self.attacker, at)
				|| origin.meta[at].declared_at >= origin.meta[self.j].declared_at
			{
				continue;
			}
			let Some(value) = choose(at) else {
				continue;
			};
			if value.equivalent(&origin.values[at].value, true) {
				continue;
			}
			installs.push((SlotIdx(at), value));
		}
		if installs.is_empty() {
			return false;
		}
		let group = KnowledgeKey::of(self.attacker);
		let key = self.key(&installs, target);
		let remembered = EMISSIONS.with(|memo| {
			memo.borrow_mut()
				.fresh()
				.group(group)
				.get(&key)
				.and_then(|bucket| {
					bucket
						.iter()
						.find(|seen| {
							same_installs(&seen.installs, &installs)
								&& seen.target.equivalent(target, true)
						})
						.map(|seen| seen.emits)
				})
		});
		if let Some(emits) = remembered {
			return emits;
		}
		let emits = self.runs_to(&installs, target);
		EMISSIONS.with(|memo| {
			memo.borrow_mut()
				.fresh()
				.group(group)
				.entry(key)
				.or_default()
				.push(Emitted {
					installs,
					target: target.clone(),
					emits,
				});
		});
		emits
	}

	fn runs_to(&self, installs: &[(SlotIdx, Value)], target: &Value) -> bool {
		let origin = self.origin;
		let mut phases: Vec<i32> = Vec::with_capacity(installs.len());
		for (at, value) in installs {
			if !admissible(value) || !self.bound.admits_at(self.km, origin.id, at.get(), value) {
				return false;
			}
			let Some(phase) = attacker_can_derive(self.ctx, at.get(), value, origin, self.attacker)
			else {
				return false;
			};
			phases.push(phase);
		}
		let governing = governing_attacker(self.ctx, &phases, self.attacker);
		let Ok(out) = reexecute_at(
			&origin.clone_for_depth(true),
			installs,
			&phases,
			&governing,
			self.km,
		) else {
			return false;
		};
		if self.j >= out.values.len() || out.slot_unreached(self.j) {
			return false;
		}
		reduce_once(&out.values[self.j].value).equivalent(target, true)
	}

	fn key(&self, installs: &[(SlotIdx, Value)], target: &Value) -> EmissionKey {
		let mut mixed = target.hash_value();
		for (at, value) in installs {
			mixed = mixed
				.rotate_left(13)
				.wrapping_add(at.get() as u64)
				.rotate_left(17)
				.wrapping_add(value.hash_value());
		}
		(self.origin.id, self.j, mixed)
	}
}

type EmissionKey = (PrincipalId, usize, u64);

struct Emitted {
	installs: Vec<(SlotIdx, Value)>,
	target: Value,
	emits: bool,
}

type ForgeableKey = (PrincipalId, PrincipalId, u64);

type Emissions = Generational<Recent<KnowledgeKey, EmissionKey, Vec<Emitted>>>;

type Forgeable = Generational<Recent<KnowledgeKey, ForgeableKey, Vec<(Value, bool)>>>;

thread_local! {
	static EMISSIONS: RefCell<Emissions> = RefCell::new(Generational::default());
	static FORGEABLE: RefCell<Forgeable> = RefCell::new(Generational::default());
}

fn driving_installs(
	attacker: &AttackerState,
	target: &Value,
) -> Option<(usize, Vec<(usize, Value)>)> {
	let idx = attacker.knows(target)?;
	let DerivationRecord::Obtained { slot } = attacker.derivation(idx)? else {
		return None;
	};
	let record = attacker.record(idx)?;
	let diffs: Vec<(usize, Value)> = record
		.tainted()
		.map(|diff| (diff.index.get(), diff.value.clone()))
		.collect();
	(!diffs.is_empty()).then_some((slot.get(), diffs))
}

fn delivered_to(ps: &PrincipalState, at: usize) -> Option<Value> {
	let sv = ps.values.get(at)?;
	let handed = sv.provenance.attacker_tainted
		&& ps
			.meta
			.get(at)
			.is_some_and(|meta| meta.wire.contains(&ps.id));
	handed.then(|| sv.value.clone())
}

/// Whether the attacker could have produced the delivered value on its own.
///
/// A matching run excuses an acceptance only where the run is the sole source
/// of what was accepted. Where the attacker can build the value from what it
/// holds with every read off the sender's runs taken away, a run that would
/// also have emitted it changes nothing: the forgery stands whether or not the
/// sender was driven, and reporting it as excused would make removing a guard
/// lose an attack, which the `unguard` property forbids. The reads are taken
/// away transitively, so a term the attacker assembled out of something it
/// learned from the sender goes with them. A `knows` constant is static data
/// rather than anything a run produced, and its slot's creator is only its
/// first declarer, so a read of one is never a read off the sender.
fn forgeable_without_sender(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sender: PrincipalId,
	target: &Value,
	attacker: &AttackerState,
) -> bool {
	let group = KnowledgeKey::of(attacker);
	let key = (ps.id, sender, target.hash_value());
	let remembered = FORGEABLE.with(|memo| {
		memo.borrow_mut()
			.fresh()
			.group(group)
			.get(&key)
			.and_then(|bucket| {
				bucket
					.iter()
					.find(|(seen, _)| seen.equivalent(target, true))
					.map(|(_, forgeable)| *forgeable)
			})
	});
	if let Some(forgeable) = remembered {
		return forgeable;
	}
	let forgeable = forgeable_without_sender_uncached(km, ps, sender, target, attacker);
	FORGEABLE.with(|memo| {
		memo.borrow_mut()
			.fresh()
			.group(group)
			.entry(key)
			.or_default()
			.push((target.clone(), forgeable));
	});
	forgeable
}

fn forgeable_without_sender_uncached(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sender: PrincipalId,
	target: &Value,
	attacker: &AttackerState,
) -> bool {
	let mut keep = crate::reexec::reachable_knowledge(ps, attacker, |_, slot| {
		!km.slots.get(slot.get()).is_some_and(|read| {
			read.constant.declaration == Some(Declaration::Assignment)
				&& km.interchangeable_with(read.creator, sender)
		})
	});
	if let Some(held) = attacker.knows(target) {
		keep[held.get()] = false;
	}
	let without_sender = attacker.retaining(&keep);
	let view = without_sender.as_deref().unwrap_or(attacker);
	crate::solve::validate::derivable(target, ps, view)
}

fn corresponds(
	km: &ProtocolTrace,
	j: usize,
	base: ValueId,
	sender: PrincipalId,
	recipient: PrincipalId,
) -> bool {
	let Some(slot) = km.slots.get(j) else {
		return false;
	};
	if copy_index_of(slot.constant.id).1 != base {
		return false;
	}
	if slot.creator == ATTACKER_ID || !km.interchangeable_for(slot.creator, sender, j) {
		return false;
	}
	slot.sent_by.iter().any(|event| {
		km.interchangeable_for(event.sender, sender, j) && km.same_actor(event.recipient, recipient)
	})
}

fn pristine_is(km: &ProtocolTrace, j: usize, target: &Value) -> bool {
	km.slots.get(j).is_some_and(|slot| {
		reduce_once(&resolve_trace_constant(&slot.constant, km)).equivalent(target, true)
	})
}

fn origin_of<'a>(
	ctx: &'a VerifyContext,
	km: &ProtocolTrace,
	j: usize,
) -> Option<&'a PrincipalState> {
	let creator = km.slots.get(j)?.creator;
	let base = ctx
		.principal_states()
		.iter()
		.find(|state| state.id == creator)?;
	(j < base.values.len()).then_some(base)
}

fn run_copy(km: &ProtocolTrace, constant: &Constant, run: u32) -> Option<Value> {
	let (own, base) = copy_index_of(constant.id);
	if own == run {
		return Some(resolve_trace_constant(constant, km));
	}
	let id = if run == 0 {
		base
	} else {
		copy_value_id(base, run)
	};
	let &slot = km.index.get(&id)?;
	Some(resolve_trace_constant(&km.slots[slot].constant, km))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::primitive::{PRIM_HASH, PRIM_MAC};
	use crate::testutil::{make_attacker_state, trace_constant};
	use std::sync::Arc;

	#[test]
	fn sender_filter_follows_in_place_and_later_ingredients() {
		let model = crate::parser::parse_string(
			"sender_ingredients.vp",
			"attacker[passive]\nprincipal Alice[\nknows private key\ntoken = HASH(key)\n]\nAlice -> Bob: token\nprincipal Bob[\nseen = HASH(token)\n]\nqueries[\nconfidentiality? key\n]\n",
		)
		.unwrap();
		let (km, states) = crate::sanity::sanity(&model).unwrap();
		let alice = states.iter().find(|state| state.name == "Alice").unwrap();
		let bob = states.iter().find(|state| state.name == "Bob").unwrap();
		let nil = crate::value::value_nil();
		for (name, forgeable) in [("token", false), ("key", true)] {
			let source = trace_constant(&km, name);
			let slot = SlotIdx(km.index_of(source.as_constant().unwrap()).unwrap());
			let source = resolve_trace_constant(source.as_constant().unwrap(), &km);
			for (in_place, reverse) in [(false, false), (true, false), (false, true)] {
				let ingredient = if in_place {
					Value::primitive(PRIM_HASH, vec![source.clone()], 0)
				} else {
					source.clone()
				};
				let derived = Value::primitive(PRIM_MAC, vec![ingredient.clone(), nil.clone()], 0);
				let target = Value::primitive(PRIM_HASH, vec![derived.clone()], 0);
				let mut known = vec![source.clone(), derived, nil.clone()];
				let mut derivations = vec![
					DerivationRecord::Obtained { slot },
					DerivationRecord::Reconstructed {
						from: vec![ingredient, nil.clone()],
					},
					DerivationRecord::Initial,
				];
				if reverse {
					known.swap(0, 1);
					derivations.swap(0, 1);
				}
				let mut attacker = make_attacker_state(known);
				attacker.derivations = Arc::new(derivations);
				assert_eq!(
					forgeable_without_sender_uncached(&km, bob, alice.id, &target, &attacker),
					forgeable,
					"source={name}, in_place={in_place}, reverse={reverse}"
				);
			}
		}
	}
}
