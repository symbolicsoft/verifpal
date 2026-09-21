/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::Generational;
use crate::types::*;
use std::cell::RefCell;
use std::sync::Arc;

mod diagram;

pub use diagram::Worlds;

pub(crate) fn constraints(ps: &PrincipalState, needs: Constraint) -> Worlds {
	Worlds::ordered(needs, |slot| {
		crate::value::copy_index_of(ps.meta[slot.get()].constant.id).1
	})
}

#[cfg(test)]
fn add(set: &mut Worlds, new: Constraint) -> bool {
	let widened = set.union(&Worlds::from_constraint(new));
	if set.equivalent(&widened) {
		return false;
	}
	*set = widened;
	true
}

pub(crate) fn merge_all(sets: &[Worlds]) -> Worlds {
	let mut out = Worlds::any();
	for choices in sets {
		out = out.intersect(choices);
		if out.is_empty() {
			break;
		}
	}
	out
}

pub(crate) fn scheduled_world(
	states: &[PrincipalState],
	attacker: &AttackerState,
	scheduled: &[Need],
) -> Worlds {
	let Some(state) = states.first() else {
		return if scheduled.is_empty() {
			Worlds::any()
		} else {
			Worlds::default()
		};
	};
	let mut world = constraints(state, scheduled.to_vec());
	for (who, _, value) in scheduled {
		let Some(state) = states.iter().find(|state| state.id == *who) else {
			return Worlds::default();
		};
		let mut inputs = crate::theory::KnowledgeInputs::new(state, attacker);
		let Some(known) = inputs.of_value(value) else {
			return Worlds::default();
		};
		for at in known {
			let Some(available) = attacker.worlds.get(at.get()) else {
				return Worlds::default();
			};
			world = world.intersect(available);
			if world.is_empty() {
				return world;
			}
		}
	}
	world
}

pub(crate) fn install_world(
	ps: &PrincipalState,
	attacker: &AttackerState,
	installs: &[(usize, Value)],
	addressed: bool,
) -> Worlds {
	let mut inputs = crate::theory::KnowledgeInputs::new(ps, attacker);
	let mut pins = Vec::new();
	let mut required = Vec::new();
	for (slot, value) in installs {
		let Some(meta) = ps.meta.get(*slot) else {
			return Worlds::default();
		};
		for &recipient in &meta.wire {
			if meta.creator != recipient && (!addressed || recipient == ps.id) {
				pins.push((recipient, SlotIdx(*slot), value.clone()));
			}
		}
		let Some(known) = inputs.of_value(value) else {
			return Worlds::default();
		};
		required.extend(known);
	}
	let mut world = constraints(ps, pins);
	for at in required {
		let Some(available) = attacker.worlds.get(at.get()) else {
			return Worlds::default();
		};
		world = world.intersect(available);
		if world.is_empty() {
			return world;
		}
	}
	world
}

pub(crate) fn state_world(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	slot: usize,
) -> Worlds {
	let key = (
		ps.id,
		attacker.chain,
		attacker.known.len(),
		attacker.reused.len(),
		attacker.current_phase,
	);
	if let Some(hit) = WORLDS.with(|cell| {
		let mut cache = cell.borrow_mut();
		cache
			.fresh()
			.as_ref()
			.filter(|cached| cached.key == key && cached.matches(ps))
			.and_then(|cached| cached.slots.get(&slot))
			.filter(|cached| {
				cached.inputs.iter().all(|(at, expected)| {
					attacker
						.worlds
						.get(at.get())
						.is_some_and(|actual| actual.equivalent(expected))
				})
			})
			.map(|cached| cached.worlds.clone())
	}) {
		return hit;
	}
	let owner = match (ps.values.get(slot), km.slots.get(slot)) {
		(Some(sv), _) if sv.provenance.attacker_tainted => ps.id,
		(_, Some(trace_slot)) => trace_slot.creator,
		_ => return Worlds::any(),
	};
	let mut visit = WorldVisit::default();
	walk(km, ps, attacker, slot, owner, &mut visit);
	let mut out = constraints(ps, visit.pins);
	for worlds in visit.inputs.values().filter(|worlds| !worlds.is_empty()) {
		out = out.intersect(worlds);
		if out.is_empty() {
			break;
		}
	}
	let result = CachedWorld {
		worlds: out.clone(),
		inputs: visit.inputs,
	};
	WORLDS.with(|cell| {
		let mut cache = cell.borrow_mut();
		let cache = cache.fresh();
		match cache.as_mut() {
			Some(cached) if cached.key == key && cached.matches(ps) => {
				cached.slots.insert(slot, result);
			}
			_ => {
				*cache = Some(WorldCache {
					key,
					values: ps
						.values
						.iter()
						.map(|sv| {
							(
								sv.value.clone(),
								sv.provenance.attacker_tainted,
								sv.provenance.creator,
							)
						})
						.collect(),
					slots: IdMap::from_iter([(slot, result)]),
				});
			}
		}
	});
	out
}

#[derive(Default)]
struct WorldVisit {
	seen: IdSet<(PrincipalId, usize)>,
	pins: Constraint,
	inputs: IdMap<KnownIdx, Worlds>,
}

fn walk(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	slot: usize,
	owner: PrincipalId,
	visit: &mut WorldVisit,
) {
	if !visit.seen.insert((owner, slot)) {
		return;
	}
	let (Some(sv), Some(trace_slot)) = (ps.values.get(slot), km.slots.get(slot)) else {
		return;
	};
	if pinless(trace_slot, owner) {
		return;
	}
	if owner == ps.id && sv.provenance.attacker_tainted {
		visit.pins.push((ps.id, SlotIdx(slot), sv.value.clone()));
		if let Some(idx) = attacker.knows(&sv.value)
			&& let Some(worlds) = attacker.worlds.get(idx.get())
		{
			visit.inputs.insert(idx, worlds.clone());
		}
	} else if owner == trace_slot.creator {
		for &at in crate::deduction::reach_cone(km, owner, slot).iter() {
			let Some(leaf) = km.slots.get(at) else {
				continue;
			};
			if at == slot || leaf.creator == owner || pinless(leaf, owner) {
				continue;
			}
			walk(km, ps, attacker, at, owner, visit);
		}
	} else {
		visit.pins.push((owner, SlotIdx(slot), sv.value.clone()));
		let creator = trace_slot.creator;
		walk(km, ps, attacker, slot, creator, visit);
	}
}

fn pinless(trace_slot: &TraceSlot, owner: PrincipalId) -> bool {
	trace_slot.constant.is_nil()
		|| trace_slot.constant.qualifier == Some(Qualifier::Public)
		|| trace_slot
			.known_by
			.iter()
			.any(|&(holder, sender)| holder == owner && sender == owner)
}

pub(crate) fn observable(trace_slot: &TraceSlot) -> bool {
	!trace_slot.sent_by.is_empty() || trace_slot.constant.leaked
}

pub(crate) fn derived_worlds(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	target: &Value,
	derivation: &DerivationRecord,
) -> Worlds {
	let existing = attacker.knows(target).and_then(|known| {
		attacker
			.worlds
			.get(known.get())
			.map(|worlds| (known, worlds))
	});
	if matches!(derivation, DerivationRecord::Initial)
		|| existing.is_some_and(|(_, worlds)| worlds.is_unconditional())
		|| unconditional(ps, attacker, target)
	{
		return Worlds::any();
	}
	recorded_worlds(km, ps, attacker, derivation, existing)
}

type Everywhere = ((u64, usize, u64, i32, usize), Option<Arc<AttackerState>>);

struct CachedWorld {
	worlds: Worlds,
	inputs: IdMap<KnownIdx, Worlds>,
}

struct WorldCache {
	key: (PrincipalId, u64, usize, usize, i32),
	values: Vec<(Value, bool, PrincipalId)>,
	slots: IdMap<usize, CachedWorld>,
}

impl WorldCache {
	fn matches(&self, ps: &PrincipalState) -> bool {
		self.values.len() == ps.values.len()
			&& self
				.values
				.iter()
				.zip(&ps.values)
				.all(|((value, tainted, creator), sv)| {
					*tainted == sv.provenance.attacker_tainted
						&& *creator == sv.provenance.creator
						&& value.equivalent(&sv.value, true)
				})
	}
}

thread_local! {
	static EVERYWHERE: RefCell<Option<Everywhere>> = const { RefCell::new(None) };
	static WORLDS: RefCell<Generational<Option<WorldCache>>> = RefCell::new(Generational::default());
	static DERIVED: RefCell<Generational<crate::context::Recent<u64, KnownIdx, Vec<CachedWorld>>>> = RefCell::new(Generational::default());
}

fn everywhere_state(attacker: &AttackerState) -> Option<Arc<AttackerState>> {
	let key = (
		attacker.chain,
		attacker.known.len(),
		attacker.worlds_epoch,
		attacker.current_phase,
		attacker.reused.len(),
	);
	if let Some(hit) = EVERYWHERE.with(|cell| {
		cell.borrow()
			.as_ref()
			.filter(|(seen, _)| *seen == key)
			.map(|(_, state)| state.clone())
	}) {
		return hit;
	}
	let keep: Vec<bool> = (0..attacker.known.len())
		.map(|i| {
			attacker
				.worlds
				.get(i)
				.is_some_and(|worlds| worlds.is_unconditional())
		})
		.collect();
	let built = if keep.iter().any(|&kept| kept) {
		Some(
			attacker
				.retaining(&keep)
				.unwrap_or_else(|| Arc::new(attacker.clone())),
		)
	} else {
		None
	};
	EVERYWHERE.with(|cell| *cell.borrow_mut() = Some((key, built.clone())));
	built
}

fn unconditional(ps: &PrincipalState, attacker: &AttackerState, target: &Value) -> bool {
	let Some(everywhere) = everywhere_state(attacker) else {
		return false;
	};
	crate::theory::obtainable(target, ps, &everywhere)
}

fn recorded_worlds(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	derivation: &DerivationRecord,
	existing: Option<(KnownIdx, &Worlds)>,
) -> Worlds {
	match derivation {
		DerivationRecord::Initial => Worlds::any(),
		DerivationRecord::Obtained { slot } | DerivationRecord::Leaked { slot } => {
			state_world(km, ps, attacker, slot.get())
		}
		_ => {
			let mut inputs = crate::theory::KnowledgeInputs::new(ps, attacker);
			let mut sets: IdMap<KnownIdx, Worlds> = IdMap::default();
			for ingredient in derivation.ingredients() {
				let Some(found) = inputs.of_value(ingredient) else {
					continue;
				};
				for idx in found {
					if let Some(worlds) = attacker.worlds.get(idx.get())
						&& !worlds.is_empty()
					{
						if let Some((_, existing)) = existing
							&& existing.includes(worlds)
						{
							return existing.clone();
						}
						sets.insert(idx, worlds.clone());
					}
				}
			}
			if let Some((target, _)) = existing
				&& let Some(hit) = DERIVED.with(|cell| {
					cell.borrow_mut()
						.fresh()
						.group(attacker.chain)
						.get(&target)
						.and_then(|choices| {
							choices.iter().find(|cached| {
								cached.inputs.len() == sets.len()
									&& sets.iter().all(|(at, worlds)| {
										cached
											.inputs
											.get(at)
											.is_some_and(|seen| seen.equivalent(worlds))
									})
							})
						})
						.map(|cached| cached.worlds.clone())
				}) {
				return hit;
			}
			let out = merge_all(&sets.values().cloned().collect::<Vec<_>>());
			if let Some((target, _)) = existing {
				DERIVED.with(|cell| {
					let mut cache = cell.borrow_mut();
					let choices = cache
						.fresh()
						.group(attacker.chain)
						.entry(target)
						.or_default();
					choices.retain(|cached| {
						cached.inputs.len() != sets.len()
							|| cached.inputs.keys().any(|at| !sets.contains_key(at))
					});
					if choices.len() >= 8 {
						choices.remove(0);
					}
					choices.push(CachedWorld {
						worlds: out.clone(),
						inputs: sets,
					});
				});
			}
			out
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testutil::make_constant;

	#[test]
	fn unconditional_deductions_revisit_new_reuse_capabilities() {
		let key = make_constant("everywhere_reuse_key");
		let nonce = make_constant("everywhere_reuse_nonce");
		let first = make_constant("everywhere_reuse_first");
		let second = make_constant("everywhere_reuse_second");
		let message = make_constant("everywhere_reuse_message");
		let ad = make_constant("everywhere_reuse_ad");
		let sealed = |message: Value| {
			Value::primitive(
				crate::primitive::PRIM_AEAD_ENC,
				vec![key.clone(), nonce.clone(), message, ad.clone()],
				0,
			)
		};
		let pair = [sealed(first), sealed(second)];
		let target = sealed(message.clone());
		let mut attacker = crate::testutil::make_attacker_state(vec![
			pair[0].clone(),
			pair[1].clone(),
			message,
			ad,
		]);
		let ps =
			crate::testutil::make_principal_state("EverywhereReuse", 1, Vec::new(), Vec::new());
		assert!(!unconditional(&ps, &attacker, &target));
		attacker.reused = Arc::new(vec![pair]);
		assert!(unconditional(&ps, &attacker, &target));
		attacker.reused = Arc::new(Vec::new());
		assert!(!unconditional(&ps, &attacker, &target));
	}

	#[test]
	fn unconditional_deductions_follow_phase_and_principal_capabilities() {
		let key = make_constant("everywhere_forgery_key");
		let message = make_constant("everywhere_forgery_message");
		let target = Value::primitive(crate::primitive::PRIM_SIGN, vec![key, message.clone()], 0);
		let mut attacker = crate::testutil::make_attacker_state(vec![message]);
		let mut ps =
			crate::testutil::make_principal_state("EverywhereForgery", 1, Vec::new(), Vec::new());
		assert!(!unconditional(&ps, &attacker, &target));
		let mut annotated = target.as_primitive().unwrap().clone();
		annotated.capabilities.set(Capability::Forgeable, 1);
		Arc::make_mut(&mut ps.capabilities).insert(&Value::Primitive(Arc::new(annotated)));
		assert!(!unconditional(&ps, &attacker, &target));
		attacker.current_phase = 1;
		assert!(unconditional(&ps, &attacker, &target));
		ps.capabilities = Arc::new(CapabilityIndex::default());
		assert!(!unconditional(&ps, &attacker, &target));
	}

	#[test]
	fn derived_world_cache_follows_changed_ingredients_and_worlds() {
		let first = make_constant("derive_cache_first");
		let second = make_constant("derive_cache_second");
		let target = make_constant("derive_cache_target");
		let a = Worlds::from_constraint(vec![(1, SlotIdx(0), first.clone())]);
		let b = Worlds::from_constraint(vec![(1, SlotIdx(0), second.clone())]);
		let mut attacker =
			crate::testutil::make_attacker_state(vec![first.clone(), second.clone(), target]);
		let ps = crate::testutil::make_principal_state("DeriveCache", 1, Vec::new(), Vec::new());
		let km = ProtocolTrace::default();
		let empty = Worlds::default();
		for (mut worlds, from, expected) in [
			(
				vec![a.clone(), a.clone()],
				vec![first.clone(), second.clone()],
				a.clone(),
			),
			(
				vec![a.clone(), a.clone()],
				vec![first.clone(), second.clone()],
				a.clone(),
			),
			(
				vec![b.clone(), a.clone()],
				vec![first.clone(), second.clone()],
				empty.clone(),
			),
			(
				vec![b.clone(), b.clone()],
				vec![first.clone(), second.clone()],
				b.clone(),
			),
			(vec![a.clone(), b.clone()], vec![first.clone()], a.clone()),
			(vec![a, b.clone()], vec![second], b),
		] {
			worlds.push(empty.clone());
			attacker.worlds = Arc::new(worlds);
			let actual = recorded_worlds(
				&km,
				&ps,
				&attacker,
				&DerivationRecord::Reconstructed { from },
				Some((KnownIdx(2), &empty)),
			);
			assert!(actual.equivalent(&expected));
		}
	}

	#[test]
	fn cached_state_worlds_follow_their_installed_value_dependencies() {
		use crate::testutil::{
			make_attacker_state, make_principal_state, make_private, make_slot_meta,
			make_slot_values,
		};
		let received = make_private("world_cache_received");
		let first = make_constant("world_cache_first");
		let second = make_constant("world_cache_second");
		let declared = make_private("world_cache_declared");
		let constant = declared.as_constant().unwrap().clone();
		let mut slot = make_slot_values(&received, 2);
		slot.provenance.attacker_tainted = true;
		let ps = make_principal_state(
			"WorldCache",
			1,
			vec![make_slot_meta(&constant, false)],
			vec![slot],
		);
		let mut km = ProtocolTrace::default();
		km.slots.push(TraceSlot {
			declared_span: Span::default(),
			constant,
			initial_value: declared,
			creator: 2,
			known_by: vec![(2, 2), (1, 2)],
			sent_by: Vec::new(),
			declared_at: 0,
			phases: vec![0],
		});
		let a = constraints(&ps, vec![(3, SlotIdx(0), first)]);
		let b = constraints(&ps, vec![(3, SlotIdx(0), second)]);
		let mut attacker = make_attacker_state(vec![received]);
		attacker.worlds = Arc::new(vec![a.clone()]);
		let before = state_world(&km, &ps, &attacker, 0);
		assert!(before.intersect(&b).is_empty());
		attacker.worlds = Arc::new(vec![a.union(&b)]);
		attacker.worlds_epoch += 1;
		let after = state_world(&km, &ps, &attacker, 0);
		assert!(!after.intersect(&b).is_empty());
	}

	#[test]
	fn alternatives_never_erase_their_constraints() {
		let mut worlds = Worlds::default();
		for i in 0..32 {
			assert!(add(
				&mut worlds,
				vec![(1, SlotIdx(0), make_constant(&format!("world_{i}")))]
			));
		}
		assert!(!worlds.is_empty());
		assert!(!worlds.is_unconditional());
		let incompatible =
			Worlds::from_constraint(vec![(1, SlotIdx(0), make_constant("world_other"))]);
		assert!(merge_all(&[worlds, incompatible]).is_empty());
	}

	#[test]
	fn repeated_alternatives_do_not_exhaust_a_merge_budget() {
		let pin = vec![(1, SlotIdx(0), make_constant("world_pin"))];
		let mut choices = Worlds::default();
		for _ in 0..5000 {
			add(&mut choices, pin.clone());
		}
		let expected = Worlds::from_constraint(pin);
		let result = merge_all(&[choices, expected.clone()]);
		assert!(result.equivalent(&expected));
	}

	#[test]
	fn contradictory_constraints_are_not_worlds() {
		let mut worlds = Worlds::default();
		assert!(!add(
			&mut worlds,
			vec![
				(1, SlotIdx(0), make_constant("world_first")),
				(1, SlotIdx(0), make_constant("world_second")),
			]
		));
		assert!(worlds.is_empty());
	}
}
