/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::context::VerifyContext;
use crate::primitive::{
	BypassKeyKind, attacker_public_key, primitive_extract_bypass_key, primitive_get,
};
use crate::principal::ATTACKER_ID;
use crate::theory::{obtainable, reduce_once};
use crate::types::*;
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
	deep: std::cell::OnceCell<Deep>,
}

struct Deep {
	protocol: IdSet<u64>,
	ids: Vec<ValueId>,
	creators: Vec<PrincipalId>,
	consumes: Vec<Option<ValueId>>,
	peel: std::cell::RefCell<IdMap<(PrincipalId, usize), usize>>,
}

impl TermBound {
	pub(crate) fn of(km: &ProtocolTrace) -> TermBound {
		let max_depth = km
			.slots
			.iter()
			.map(|slot| term_depth(&resolve_trace_constant(&slot.constant, km)))
			.max()
			.unwrap_or(0);
		TermBound {
			max_depth,
			deep: std::cell::OnceCell::new(),
		}
	}

	fn deep(&self, km: &ProtocolTrace) -> &Deep {
		self.deep.get_or_init(|| {
			let mut protocol: IdSet<u64> = IdSet::default();
			for slot in &km.slots {
				crate::hashing::collect_subterm_hashes(
					&resolve_trace_constant(&slot.constant, km),
					&mut protocol,
				);
			}
			Deep {
				protocol,
				ids: km.slots.iter().map(|slot| slot.constant.id).collect(),
				creators: km.slots.iter().map(|slot| slot.creator).collect(),
				consumes: km
					.slots
					.iter()
					.map(|slot| unwrapped_by(&slot.initial_value))
					.collect(),
				peel: std::cell::RefCell::new(IdMap::default()),
			}
		})
	}

	pub(crate) fn admits_at(
		&self,
		km: &ProtocolTrace,
		principal: PrincipalId,
		slot: usize,
		v: &Value,
	) -> bool {
		let depth = term_depth(v);
		if depth <= self.max_depth {
			return true;
		}
		let deep = self.deep(km);
		depth <= self.max_depth + deep.peel_depth(principal, slot)
			&& deep.depth_over_protocol(v) <= self.max_depth
	}

	pub(crate) fn depth(&self) -> usize {
		self.max_depth
	}
}

impl Deep {
	fn depth_over_protocol(&self, v: &Value) -> usize {
		match v {
			Value::Constant(_) => 0,
			Value::Primitive(p) => {
				if self.protocol.contains(&v.hash_value()) {
					return 0;
				}
				1 + p
					.arguments
					.iter()
					.map(|a| self.depth_over_protocol(a))
					.max()
					.unwrap_or(0)
			}
		}
	}

	fn peel_depth(&self, principal: PrincipalId, slot: usize) -> usize {
		if let Some(&hit) = self.peel.borrow().get(&(principal, slot)) {
			return hit;
		}
		let mut visiting: Vec<usize> = Vec::new();
		let depth = self.peel_from(principal, slot, &mut visiting);
		self.peel.borrow_mut().insert((principal, slot), depth);
		depth
	}

	fn peel_from(&self, principal: PrincipalId, slot: usize, visiting: &mut Vec<usize>) -> usize {
		let Some(&id) = self.ids.get(slot) else {
			return 0;
		};
		if visiting.contains(&slot) {
			return 0;
		}
		visiting.push(slot);
		let deepest = (0..self.ids.len())
			.filter(|&t| self.creators[t] == principal && self.consumes[t] == Some(id))
			.map(|t| 1 + self.peel_from(principal, t, visiting))
			.max()
			.unwrap_or(0);
		visiting.pop();
		deepest
	}
}

fn unwrapped_by(v: &Value) -> Option<ValueId> {
	let Value::Primitive(p) = v else {
		return None;
	};
	let at = match primitive_get(p.id)
		.ok()
		.and_then(|spec| spec.rewrite.as_ref())
	{
		Some(rule) => rule.from,
		None if p.id == crate::primitive::PRIM_SPLIT => 0,
		None => return None,
	};
	match p.arguments.get(at) {
		Some(Value::Constant(c)) => Some(c.id),
		_ => None,
	}
}

type Restriction = (
	*const Vec<bool>,
	Arc<Vec<Value>>,
	Option<Arc<AttackerState>>,
);

pub(crate) struct CausalOrder {
	principal: PrincipalId,
	blocked: Vec<Option<Arc<Vec<bool>>>>,
	restricted: std::cell::RefCell<Vec<Restriction>>,
}

impl CausalOrder {
	pub(crate) fn of(km: &ProtocolTrace, principal: PrincipalId) -> CausalOrder {
		let mut cache: Vec<(i32, Arc<Vec<bool>>)> = Vec::new();
		let mut blocked = vec![None; km.slots.len()];
		for (slot, entry) in blocked.iter_mut().enumerate() {
			let Some(at) = km.slots[slot]
				.sent_by
				.iter()
				.filter(|event| event.recipient == principal)
				.map(|event| event.declared_at)
				.min()
			else {
				continue;
			};
			let set = match cache.iter().find(|&&(when, _)| when == at) {
				Some((_, set)) => Arc::clone(set),
				None => {
					let set = Arc::new(unreachable_before(km, principal, at));
					cache.push((at, Arc::clone(&set)));
					set
				}
			};
			if set.iter().any(|&blocked| blocked) {
				*entry = Some(set);
			}
		}
		CausalOrder {
			principal,
			blocked,
			restricted: std::cell::RefCell::new(Vec::new()),
		}
	}

	pub(crate) fn available(
		&self,
		ps: &PrincipalState,
		slot: usize,
		attacker: &AttackerState,
	) -> Option<Arc<AttackerState>> {
		if self.principal != ps.id {
			return None;
		}
		let blocked = self.blocked.get(slot)?.as_ref()?;
		let key = Arc::as_ptr(blocked);
		if let Some((_, _, hit)) = self
			.restricted
			.borrow()
			.iter()
			.find(|(seen, known, _)| *seen == key && Arc::ptr_eq(known, &attacker.known))
		{
			return hit.clone();
		}
		let built = self.restrict(blocked, attacker);
		self.restricted
			.borrow_mut()
			.push((key, Arc::clone(&attacker.known), built.clone()));
		built
	}

	fn restrict(&self, blocked: &[bool], attacker: &AttackerState) -> Option<Arc<AttackerState>> {
		let n = attacker.known.len();
		let mut reachable = vec![false; n];
		for i in 0..n {
			reachable[i] = match attacker.derivation(KnownIdx(i)) {
				None | Some(DerivationRecord::Initial) => true,
				Some(DerivationRecord::Leaked { slot } | DerivationRecord::Obtained { slot }) => {
					!blocked.get(slot.0).copied().unwrap_or(false)
				}
				Some(other) => other.ingredients().iter().all(|v| {
					attacker
						.knows(v)
						.map(|found| found.0 >= i || reachable[found.0])
						.unwrap_or(true)
				}),
			};
		}
		retain_known(attacker, &reachable)
	}
}

pub(crate) fn retain_known(attacker: &AttackerState, keep: &[bool]) -> Option<Arc<AttackerState>> {
	if keep.iter().all(|&keep| keep) {
		return None;
	}
	let known: Vec<Value> = attacker
		.known
		.iter()
		.zip(keep.iter())
		.filter(|&(_, &keep)| keep)
		.map(|(v, _)| v.clone())
		.collect();
	let mut known_map: IdMap<u64, Vec<usize>> = IdMap::default();
	for (i, v) in known.iter().enumerate() {
		known_map.entry(v.hash_value()).or_default().push(i);
	}
	let mutation_records = attacker
		.mutation_records
		.iter()
		.zip(keep.iter())
		.filter(|&(_, &keep)| keep)
		.map(|(r, _)| Arc::clone(r))
		.collect();
	let derivations = attacker
		.derivations
		.iter()
		.zip(keep.iter())
		.filter(|&(_, &keep)| keep)
		.map(|(d, _)| d.clone())
		.collect();
	let alternates = attacker
		.alternates
		.iter()
		.zip(keep.iter())
		.filter(|&(_, &keep)| keep)
		.map(|(d, _)| d.clone())
		.collect();
	Some(Arc::new(AttackerState {
		current_phase: attacker.current_phase,
		mutation_records: Arc::new(mutation_records),
		derivations: Arc::new(derivations),
		alternates: Arc::new(alternates),
		known: Arc::new(known),
		known_map: Arc::new(known_map),
	}))
}

fn influenced_from(km: &ProtocolTrace, principal: PrincipalId, at: i32) -> IdMap<PrincipalId, i32> {
	let mut after: IdMap<PrincipalId, i32> = IdMap::default();
	after.insert(principal, at);
	loop {
		let mut changed = false;
		for slot in &km.slots {
			for event in &slot.sent_by {
				let Some(&reached) = after.get(&event.sender) else {
					continue;
				};
				if event.declared_at < reached {
					continue;
				}
				match after.get(&event.recipient) {
					Some(&known) if known <= event.declared_at => {}
					_ => {
						after.insert(event.recipient, event.declared_at);
						changed = true;
					}
				}
			}
		}
		if !changed {
			return after;
		}
	}
}

fn unreachable_before(km: &ProtocolTrace, principal: PrincipalId, at: i32) -> Vec<bool> {
	let after = influenced_from(km, principal, at);
	km.slots
		.iter()
		.map(|slot| {
			after
				.get(&slot.creator)
				.is_some_and(|&reached| slot.declared_at >= reached)
				&& !slot.constant.is_nil()
				&& slot.constant.qualifier != Some(Qualifier::Public)
		})
		.collect()
}

type Delivery = (usize, Value, bool);
type Agreement = (Vec<usize>, Arc<Vec<Value>>, Option<Arc<AttackerState>>);

type Agreed = (Arc<MutationRecord>, Vec<usize>, bool);

pub(crate) struct Coherence {
	principal: PrincipalId,
	forwarded: Vec<Option<Value>>,
	agreed: std::cell::RefCell<IdMap<u64, Vec<Agreement>>>,
	histories: std::cell::RefCell<Vec<Agreed>>,
}

impl Coherence {
	pub(crate) fn of(km: &ProtocolTrace, ps: &PrincipalState) -> Coherence {
		let forwarded = km
			.slots
			.iter()
			.map(|slot| {
				(slot.creator != ps.id && slot.sent_by.iter().any(|event| event.recipient == ps.id))
					.then(|| reduce_once(&resolve_trace_constant(&slot.constant, km)))
			})
			.collect();
		Coherence {
			principal: ps.id,
			forwarded,
			agreed: std::cell::RefCell::new(IdMap::default()),
			histories: std::cell::RefCell::new(Vec::new()),
		}
	}

	pub(crate) fn compatible(
		&self,
		ctx: &VerifyContext,
		km: &ProtocolTrace,
		ps: &PrincipalState,
		delivered: &[Delivery],
		attacker: &AttackerState,
	) -> Option<Arc<AttackerState>> {
		if self.principal != ps.id {
			return None;
		}
		let authored: Vec<usize> = delivered
			.iter()
			.filter(|(_, _, authored)| *authored)
			.map(|(slot, _, _)| *slot)
			.collect();
		let size = attacker.known.len();
		let key = authored_hash(&authored, Arc::as_ptr(&attacker.known), size);
		if let Some(bucket) = self.agreed.borrow().get(&key)
			&& let Some((_, _, hit)) = bucket
				.iter()
				.find(|(seen, known, _)| Arc::ptr_eq(known, &attacker.known) && *seen == authored)
		{
			return hit.clone();
		}
		let mut keep = vec![true; size];
		for i in 0..size {
			keep[i] = match attacker.derivation(KnownIdx(i)) {
				None | Some(DerivationRecord::Initial) => true,
				Some(DerivationRecord::Leaked { slot } | DerivationRecord::Obtained { slot }) => {
					self.forwards(km, attacker, i, slot.get(), &authored)
						&& attacker.record(KnownIdx(i)).is_some_and(|record| {
							self.execution_agrees(ctx, km, attacker, record, &authored)
						})
				}
				Some(other) => other.ingredients().iter().all(|v| {
					attacker
						.knows(v)
						.map(|found| found.0 >= i || keep[found.0])
						.unwrap_or(true)
				}),
			};
		}
		let built = retain_known(attacker, &keep);
		self.agreed.borrow_mut().entry(key).or_default().push((
			authored,
			Arc::clone(&attacker.known),
			built.clone(),
		));
		built
	}

	fn execution_agrees(
		&self,
		ctx: &VerifyContext,
		km: &ProtocolTrace,
		attacker: &AttackerState,
		record: &Arc<MutationRecord>,
		authored: &[usize],
	) -> bool {
		let diffs: Vec<(PrincipalId, SlotIdx, Value)> = record
			.diffs
			.iter()
			.filter(|diff| diff.tainted)
			.map(|diff| (diff.state, diff.index, diff.value.clone()))
			.collect();
		if diffs.is_empty() {
			return true;
		}
		if let Some((_, _, hit)) = self
			.histories
			.borrow()
			.iter()
			.find(|(seen, seen_authored, _)| Arc::ptr_eq(seen, record) && seen_authored == authored)
		{
			return *hit;
		}
		let agrees = self.replays_agree(ctx, km, attacker, &diffs, authored);
		self.histories
			.borrow_mut()
			.push((Arc::clone(record), authored.to_vec(), agrees));
		agrees
	}

	fn replays_agree(
		&self,
		ctx: &VerifyContext,
		km: &ProtocolTrace,
		attacker: &AttackerState,
		diffs: &[(PrincipalId, SlotIdx, Value)],
		authored: &[usize],
	) -> bool {
		for origin in ctx.principal_states() {
			if origin.id == self.principal {
				continue;
			}
			let watched: Vec<usize> = (0..origin.values.len())
				.filter(|&at| {
					self.forwarded.get(at).is_some_and(Option::is_some)
						&& !authored.contains(&at)
						&& km
							.slots
							.get(at)
							.is_some_and(|slot| slot.creator == origin.id)
				})
				.collect();
			if watched.is_empty() {
				continue;
			}
			let installs: Vec<(SlotIdx, Value)> = diffs
				.iter()
				.filter(|(state, slot, _)| {
					*state == origin.id
						&& origin.meta.get(slot.get()).is_some_and(|meta| {
							meta.creator != origin.id && meta.wire.contains(&origin.id)
						})
				})
				.map(|(_, slot, value)| (*slot, value.clone()))
				.collect();
			if installs.is_empty() {
				continue;
			}
			let Ok(out) = reexecute(&origin.clone_for_depth(true), &installs, attacker, km) else {
				continue;
			};
			for at in watched {
				let Some(Some(honest)) = self.forwarded.get(at) else {
					continue;
				};
				if at >= out.values.len()
					|| out.slot_unreached(at)
					|| !reduce_once(&out.values[at].value).equivalent(honest, true)
				{
					return false;
				}
			}
		}
		true
	}

	fn forwards(
		&self,
		km: &ProtocolTrace,
		attacker: &AttackerState,
		held: usize,
		at: usize,
		authored: &[usize],
	) -> bool {
		if authored.contains(&at) {
			return true;
		}
		let Some(from) = attacker.record(KnownIdx(held)).map(|r| r.principal_id) else {
			return true;
		};
		let Some(Some(forwarded)) = self.forwarded.get(at) else {
			return true;
		};
		if !km
			.slots
			.get(at)
			.is_some_and(|slot| from == slot.creator || from == self.principal)
		{
			return true;
		}
		reduce_once(&attacker.known[held]).equivalent(forwarded, true)
	}
}

fn authored_hash(authored: &[usize], known: *const Vec<Value>, size: usize) -> u64 {
	let mut hash = 0xcbf2_9ce4_8422_2325u64;
	let mut mix = |word: u64| {
		hash ^= word;
		hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
	};
	mix(known as u64);
	mix(size as u64);
	for slot in authored {
		mix(*slot as u64);
	}
	hash
}

pub(crate) struct Guards<'a> {
	pub(crate) controllable: &'a Controllable,
	pub(crate) bound: &'a TermBound,
	pub(crate) order: &'a CausalOrder,
	pub(crate) history: &'a Coherence,
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
	if !km
		.mutation_phase(idx)
		.is_some_and(|phase| phase <= attacker.current_phase)
	{
		return false;
	}
	if !km.constant_used_by(ps.id, &meta.constant) && meta.sent_at.is_none() {
		return false;
	}
	true
}

pub(crate) fn governing_attacker(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	installs: &[(SlotIdx, Value)],
	ambient: &AttackerState,
) -> AttackerState {
	let earliest = installs
		.iter()
		.filter_map(|(slot, _)| km.mutation_phase(slot.get()))
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
	reexecute_with(ps_base, installs, &[], attacker, km)
}

fn reexecute_with(
	ps_base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	forwarded: &[(SlotIdx, Value)],
	attacker: &AttackerState,
	km: &ProtocolTrace,
) -> VResult<PrincipalState> {
	let mut ps = ps_base.clone();
	let relayed = relayed_installs(&ps, installs);
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
	for (slot, value) in forwarded {
		if slot.get() < ps.values.len() {
			install_forwarded(&mut ps, slot.get(), value.clone());
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

	if !relays_are_forwarded(&ps, km, &relayed, &failures, attacker) {
		return Err(VerifpalError::resolution(
			"a guarded value's forwarder halts before forwarding it".into(),
		));
	}

	let foreign = foreign_halts(&ps, &failures);

	if let Some(bypassed) = try_guard_bypass(&ps_pre, &ps, &failures, attacker)? {
		ps = bypassed;
	} else {
		ps = halt_at(ps, &failures);
	}
	ps.foreign_halts = foreign;
	ps.forwarded = !forwarded.is_empty();
	Ok(ps)
}

pub(crate) fn execute_forward(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	base: &PrincipalState,
	installs: &[(SlotIdx, Value)],
	attacker: &AttackerState,
) -> VResult<Vec<PrincipalState>> {
	let first = reexecute(base, installs, attacker, km)?;
	let mut out = vec![first];
	forward_to_fixpoint(ctx, km, &mut out, &[], Some(base.id), attacker);
	Ok(out)
}

pub(crate) type Seeds = Vec<(PrincipalId, Vec<(SlotIdx, Value)>)>;

fn forward_to_fixpoint(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	out: &mut Vec<PrincipalState>,
	seeds: &[(PrincipalId, Vec<(SlotIdx, Value)>)],
	skip: Option<PrincipalId>,
	attacker: &AttackerState,
) {
	let mut applied: Vec<(PrincipalId, Vec<(SlotIdx, Value)>)> = Vec::new();
	for _ in 0..ctx.principal_states().len() {
		let mut changed = false;
		for pristine in ctx.principal_states() {
			if skip == Some(pristine.id) {
				continue;
			}
			let seed: &[(SlotIdx, Value)] = seeds
				.iter()
				.find(|(principal, _)| *principal == pristine.id)
				.map(|(_, mine)| mine.as_slice())
				.unwrap_or(&[]);
			let forwarded: Vec<(SlotIdx, Value)> = forwarded_installs(km, out, pristine, attacker)
				.into_iter()
				.filter(|(slot, _)| !seed.iter().any(|(held, _)| held == slot))
				.collect();
			if forwarded.is_empty() {
				continue;
			}
			if applied
				.iter()
				.any(|(id, seen)| *id == pristine.id && same_installs(seen, &forwarded))
			{
				continue;
			}
			let Ok(state) = reexecute_with(
				&pristine.clone_for_depth(true),
				seed,
				&forwarded,
				attacker,
				km,
			) else {
				continue;
			};
			match applied.iter_mut().find(|(id, _)| *id == pristine.id) {
				Some((_, seen)) => *seen = forwarded,
				None => applied.push((pristine.id, forwarded)),
			}
			match out.iter_mut().find(|held| held.id == pristine.id) {
				Some(held) => *held = state,
				None => out.push(state),
			}
			changed = true;
		}
		if !changed {
			break;
		}
	}
}

/// Replay a recorded substitution as the one execution it describes.
///
/// A `MutationRecord` names the slots the attacker had changed when a value
/// was read, not the principal each change was delivered to; a merged record
/// carries diffs from several. Every principal that receives one of the
/// changed slots is run under the diffs that reach it, and the runs are then
/// carried forward together to a fixed point, so that what the substitution
/// did to the rest of the protocol is present in the result. It is one
/// execution, not one per principal: a principal that was handed a value on a
/// leg keeps it, whatever its honest peer would have emitted there, since that
/// delivery is what the substitution *is*. Running the recipients separately
/// and letting the last one's consequences win was how a man-in-the-middle
/// run of Bob got replaced by a Bob fed Alice's honest flight.
pub(crate) fn replay_diffs(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	seeds: &[(PrincipalId, Vec<(SlotIdx, Value)>)],
	attacker: &AttackerState,
) -> Option<Vec<PrincipalState>> {
	let mut out: Vec<PrincipalState> = Vec::new();
	let mut installed: Seeds = Vec::new();
	for (principal, mine) in seeds {
		let pristine = ctx
			.principal_states()
			.iter()
			.find(|state| state.id == *principal)?;
		let mine: Vec<(SlotIdx, Value)> = mine
			.iter()
			.filter(|(slot, _)| {
				pristine.meta.get(slot.get()).is_some_and(|meta| {
					meta.creator != pristine.id && meta.wire.contains(&pristine.id)
				})
			})
			.cloned()
			.collect();
		if mine.is_empty() {
			continue;
		}
		let state = reexecute(&pristine.clone_for_depth(true), &mine, attacker, km).ok()?;
		out.push(state);
		installed.push((*principal, mine));
	}
	if out.is_empty() {
		return Some(out);
	}
	forward_to_fixpoint(ctx, km, &mut out, &installed, None, attacker);
	Some(out)
}

pub(crate) fn same_installs(a: &[(SlotIdx, Value)], b: &[(SlotIdx, Value)]) -> bool {
	a.len() == b.len()
		&& a.iter()
			.zip(b.iter())
			.all(|((sa, va), (sb, vb))| sa == sb && va.equivalent(vb, true))
}

fn forwarded_installs(
	km: &ProtocolTrace,
	executed: &[PrincipalState],
	target: &PrincipalState,
	attacker: &AttackerState,
) -> Vec<(SlotIdx, Value)> {
	let mut out: Vec<(SlotIdx, Value)> = Vec::new();
	for source in executed {
		if source.id == target.id {
			continue;
		}
		for at in 0..target.values.len() {
			if out.iter().any(|(slot, _)| slot.get() == at) {
				continue;
			}
			let Some(slot) = km.slots.get(at) else {
				continue;
			};
			let sent = slot.sent_by.iter().any(|event| {
				event.sender == source.id
					&& event.recipient == target.id
					&& event.phase <= attacker.current_phase
					&& source.event_reached(km, source.id, event.declared_at)
			});
			if !sent || at >= source.values.len() || source.slot_unreached(at) {
				continue;
			}
			let emitted = &source.values[at].value;
			if !attacker_authored(emitted, at, km, target) {
				continue;
			}
			out.push((SlotIdx(at), emitted.clone()));
		}
	}
	out
}

fn install_forwarded(ps: &mut PrincipalState, slot: usize, value: Value) {
	let sv = &mut ps.values[slot];
	sv.pre_rewrite = value.clone();
	sv.value = value;
	sv.provenance.attacker_tainted = true;
}

fn relayed_installs(
	ps: &PrincipalState,
	installs: &[(SlotIdx, Value)],
) -> Vec<(usize, PrincipalId)> {
	installs
		.iter()
		.filter_map(|(slot, _)| {
			let i = slot.get();
			let meta = ps.meta.get(i)?;
			let sender = ps.values.get(i)?.provenance.sender;
			(meta.guard && sender != ps.id && sender != ATTACKER_ID).then_some((i, sender))
		})
		.collect()
}

fn relays_are_forwarded(
	ps: &PrincipalState,
	km: &ProtocolTrace,
	relayed: &[(usize, PrincipalId)],
	failures: &[(Primitive, usize)],
	attacker: &AttackerState,
) -> bool {
	relayed.iter().all(|&(slot, sender)| {
		let send = km.slots.get(slot).and_then(|s| {
			s.sent_by
				.iter()
				.find(|event| event.sender == sender && event.recipient == ps.id)
		});
		let Some(send) = send else {
			return true;
		};
		failures.iter().all(|(prim, idx)| {
			!prim.instance_check
				|| ps.values[*idx].provenance.creator != sender
				|| ps.meta[*idx].declared_at >= send.declared_at
				|| bypass_is_constructible(prim, ps, attacker)
		})
	})
}

pub(crate) fn halt_at_failed_checks(
	mut ps: PrincipalState,
	failures: &[(Primitive, usize)],
) -> PrincipalState {
	let foreign = foreign_halts(&ps, failures);
	ps = halt_at(ps, failures);
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

fn keyed_position(prim: &Primitive) -> Option<usize> {
	match primitive_get(prim.id).ok()?.bypass_key? {
		BypassKeyKind::Direct(at) => Some(at),
		BypassKeyKind::Derived { arg, .. } => Some(arg),
	}
}

fn bypass_is_constructible(
	prim: &Primitive,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> bool {
	let Some(key) = primitive_extract_bypass_key(prim) else {
		return false;
	};
	if !obtainable(&key, ps, attacker) {
		return false;
	}
	let Ok(spec) = primitive_get(prim.id) else {
		return false;
	};
	let Some(rule) = spec.rewrite.as_ref() else {
		return false;
	};
	let keyed = keyed_position(prim);
	rule.matching.iter().all(|(outer, _)| {
		Some(*outer) == keyed
			|| prim
				.arguments
				.get(*outer)
				.is_some_and(|a| obtainable(a, ps, attacker))
	})
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
				&& bypass_is_constructible(prim, ps_resolved, attacker)
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
			if bypass_is_constructible(prim, &ps, attacker) {
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
	Ok(Some(halt_at(ps, &remaining)))
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

fn halt_at(mut ps: PrincipalState, failures: &[(Primitive, usize)]) -> PrincipalState {
	if let Some((truncate_at, halted_at)) = truncation_point(&ps, failures) {
		ps = drop_after_index(ps, truncate_at);
		ps.halted_at = Some(halted_at);
	}
	ps
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

	fn coherence_fixture(
		delivered: &crate::types::Value,
	) -> (crate::types::ProtocolTrace, PrincipalState) {
		use crate::types::*;
		let c = make_constant("coh_e");
		let constant = c.as_constant().expect("constant").clone();
		let trace = ProtocolTrace {
			principals: vec!["Alice".to_string(), "Bob".to_string()],
			principal_ids: vec![1, 2],
			slots: vec![TraceSlot {
				declared_span: Span::default(),
				constant: constant.clone(),
				initial_value: delivered.clone(),
				creator: 1,
				known_by: vec![(2, 1)],
				sent_by: vec![SendEvent {
					sender: 1,
					recipient: 2,
					declared_at: 1,
					phase: 0,
					guarded: false,
				}],
				declared_at: 0,
				phases: vec![0],
			}],
			index: {
				let mut m = IdMap::default();
				m.insert(constant.id, 0);
				m
			},
			max_phase: 0,
			used_by: IdMap::default(),
			leaks: std::sync::Arc::new(Vec::new()),
			session_siblings: IdMap::default(),
			interchangeable: IdMap::default(),
			actors: IdMap::default(),
		};
		let ps = make_principal_state(
			"Bob",
			2,
			vec![make_slot_meta(&constant, false)],
			vec![make_slot_values(delivered, 1)],
		);
		(trace, ps)
	}

	fn coherence_context() -> crate::context::VerifyContext {
		let src = "attacker[active]\nprincipal Alice[\nknows private coh_ctx_m\n]\nqueries[\nconfidentiality? coh_ctx_m\n]\n";
		let m = crate::parser::parse_string("coh.vp", src).expect("parse");
		crate::context::VerifyContext::new(&m, &[], Vec::new(), 1, None, Vec::new())
	}

	fn coherence_attacker(
		held: &crate::types::Value,
		from: crate::types::PrincipalId,
	) -> crate::types::AttackerState {
		use crate::types::*;
		let mut map: IdMap<u64, Vec<usize>> = IdMap::default();
		map.entry(held.hash_value()).or_default().push(0);
		AttackerState {
			current_phase: 0,
			known: std::sync::Arc::new(vec![held.clone()]),
			known_map: std::sync::Arc::new(map),
			mutation_records: std::sync::Arc::new(vec![std::sync::Arc::new(MutationRecord {
				diffs: vec![],
				principal_id: from,
				phase: 0,
			})]),
			derivations: std::sync::Arc::new(vec![DerivationRecord::Obtained { slot: SlotIdx(0) }]),
			alternates: std::sync::Arc::new(vec![Vec::new()]),
		}
	}

	#[test]
	fn a_term_read_out_of_a_different_execution_of_the_sender_is_refused() {
		let honest = make_constant("coh_honest");
		let other = make_constant("coh_other");
		let (km, ps) = coherence_fixture(&honest);
		let history = super::Coherence::of(&km, &ps);
		let attacker = coherence_attacker(&other, 1);
		let restricted = history
			.compatible(&coherence_context(), &km, &ps, &[], &attacker)
			.expect("the incompatible term is dropped");
		assert!(
			restricted.knows(&other).is_none(),
			"a term obtained at a slot in the sender's own run, where that run produced \
			 something other than what this principal is being handed, belongs to an \
			 execution this one excludes"
		);
	}

	#[test]
	fn the_same_term_is_kept_where_the_attacker_authors_what_is_delivered() {
		let honest = make_constant("coh_honest_b");
		let other = make_constant("coh_other_b");
		let forged = make_constant("coh_forged_b");
		let (km, ps) = coherence_fixture(&honest);
		let history = super::Coherence::of(&km, &ps);
		let attacker = coherence_attacker(&other, 1);
		let delivered = [(0usize, forged, true)];
		assert!(
			history
				.compatible(&coherence_context(), &km, &ps, &delivered, &attacker)
				.is_none(),
			"authoring what the recipient is handed claims nothing about what the sender \
			 produced, so the sender's other execution is not contradicted"
		);
	}

	#[test]
	fn a_term_read_while_walking_a_third_principal_is_kept() {
		let honest = make_constant("coh_honest_c");
		let other = make_constant("coh_other_c");
		let (km, ps) = coherence_fixture(&honest);
		let history = super::Coherence::of(&km, &ps);
		let attacker = coherence_attacker(&other, 3);
		assert!(
			history
				.compatible(&coherence_context(), &km, &ps, &[], &attacker)
				.is_none(),
			"a read performed while walking some other recipient says what that one was \
			 handed, and the attacker may hand two recipients different values"
		);
	}

	#[test]
	fn a_foreign_halt_never_names_the_state_it_is_recorded_on() {
		use crate::types::{Capabilities, HashCell, Primitive};
		let own = make_constant("fh_own");
		let mut ps = make_principal_state(
			"Alice",
			1,
			vec![make_slot_meta(own.as_constant().expect("constant"), true)],
			vec![make_slot_values(&own, 1)],
		);
		ps.values[0].provenance.creator = 1;
		let failing = Primitive {
			id: crate::primitive::PRIM_ASSERT,
			arguments: vec![own.clone(), own],
			output: 0,
			instance_check: true,
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		};
		let halts = super::creator_halts(&ps, &[(failing.clone(), 0)]);
		assert_eq!(halts, vec![(1, 0)], "the creator's own halt is recorded");
		assert!(
			super::foreign_halts(&ps, &[(failing, 0)]).is_empty(),
			"`foreign_halts` filters the state's own principal out, which is what \
			 makes `slot_unreached` false for every slot the state itself created"
		);
	}
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
	fn a_relay_is_controllable_only_when_its_own_delivery_phase_is_reached() {
		use crate::parser::parse_string;
		let src = "attacker[active]\nprincipal Alice[\nknows private rp_m\n]\nAlice -> Bob: [rp_m]\nphase[1]\nprincipal Bob[\n_ = HASH(rp_m)\n]\nBob -> Charlie: rp_m\nprincipal Charlie[\n_ = HASH(rp_m)\n]\nqueries[\nauthentication? Bob -> Charlie: rp_m\n]\n";
		let m = parse_string("relay-phase.vp", src).expect("parse");
		let (km, states) = crate::sanity::sanity(&m).expect("sanity");
		let charlie = states
			.iter()
			.find(|state| state.name == "Charlie")
			.expect("Charlie");
		let slot = charlie
			.meta
			.iter()
			.position(|meta| meta.constant.name.as_ref() == "rp_m")
			.expect("rp_m");
		let mut attacker = make_attacker_state(Vec::new());
		assert!(!super::attacker_controllable(slot, &km, charlie, &attacker));
		attacker.current_phase = 1;
		assert!(super::attacker_controllable(slot, &km, charlie, &attacker));
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
