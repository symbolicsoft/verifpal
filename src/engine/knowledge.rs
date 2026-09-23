/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::primitive::{Reveal, primitive_core_reveals_args, reuse_rule};
use crate::theory::{
	can_break_weak, can_decompose, can_recompose, can_reconstruct_primitive, can_rewrite,
	obtainable, reduce_once, reused_pair,
};
use crate::types::*;

#[derive(Clone, Debug)]
pub(crate) enum Origin {
	Initial,
	Wire { run: usize, slot: usize },
	Leak { run: usize, slot: usize },
	Derived(DerivationRecord),
}

#[derive(Clone, Default)]
struct Candidates {
	recon: Vec<Value>,
	forward: Vec<(Value, Value)>,
	splits: Vec<Value>,
	seen: IdMap<u64, Vec<Value>>,
	seen_forward: IdMap<u64, Vec<Value>>,
}

impl Candidates {
	fn note(&mut self, value: &Value, pre: &Value) {
		self.walk(value);
		if let Value::Primitive(p) = pre {
			let (reduces, reduced) = can_rewrite(p);
			if reduces && !reduced.equivalent(pre, true) {
				let bucket = self.seen_forward.entry(pre.hash_value()).or_default();
				if !bucket.iter().any(|held| held.equivalent(pre, true)) {
					bucket.push(pre.clone());
					self.forward.push((pre.clone(), reduced));
				}
			}
		}
	}

	fn walk(&mut self, value: &Value) {
		let Value::Primitive(p) = value else {
			return;
		};
		let bucket = self.seen.entry(value.hash_value()).or_default();
		if bucket.iter().any(|held| held.equivalent(value, true)) {
			return;
		}
		bucket.push(value.clone());
		for arg in &p.arguments {
			self.walk(arg);
		}
		if p.threshold > 0
			&& crate::primitive::primitive_get(p.id).is_ok_and(|spec| spec.recompose.is_some())
			&& !self.splits.iter().any(|held| held.equivalent(value, false))
		{
			self.splits.push(value.clone());
		}
		self.recon.push(value.clone());
	}
}

#[derive(Clone)]
pub(crate) struct Knowledge {
	pub(crate) state: Arc<AttackerState>,
	pub(crate) origins: Arc<Vec<Origin>>,
	pub(crate) protocol: Arc<Vec<(Value, Value, bool)>>,
	pub(crate) built: Arc<IdMap<u64, Vec<Value>>>,
	built_len: usize,
	candidates: Arc<Candidates>,
	closed: usize,
	closed_protocol: usize,
	closed_built: usize,
	closed_phase: i32,
}

impl Knowledge {
	pub(crate) fn new(phase: i32) -> Knowledge {
		let mut state = AttackerState::new();
		state.current_phase = phase;
		Knowledge {
			state: Arc::new(state),
			origins: Arc::new(Vec::new()),
			protocol: Arc::new(Vec::new()),
			built: Arc::new(IdMap::default()),
			built_len: 0,
			candidates: Arc::new(Candidates::default()),
			closed: 0,
			closed_protocol: 0,
			closed_built: 0,
			closed_phase: phase,
		}
	}

	pub(crate) fn len(&self) -> usize {
		self.state.known.len()
	}

	pub(crate) fn phase(&self) -> i32 {
		self.state.current_phase
	}

	pub(crate) fn set_phase(&mut self, phase: i32) {
		if self.state.current_phase != phase {
			let state = Arc::make_mut(&mut self.state);
			state.current_phase = phase;
			state.chain = next_chain();
		}
	}

	pub(crate) fn knows(&self, v: &Value) -> Option<usize> {
		self.state.knows(v).map(|i| i.get())
	}

	pub(crate) fn origin(&self, i: usize) -> &Origin {
		&self.origins[i]
	}

	pub(crate) fn learn(&mut self, v: &Value, origin: Origin) -> bool {
		if self.state.knows(v).is_some() {
			return false;
		}
		let derivation = match &origin {
			Origin::Derived(d) => d.clone(),
			Origin::Wire { slot, .. } => DerivationRecord::Obtained {
				slot: SlotIdx(*slot),
			},
			Origin::Leak { slot, .. } => DerivationRecord::Leaked {
				slot: SlotIdx(*slot),
			},
			Origin::Initial => DerivationRecord::Initial,
		};
		let state = Arc::make_mut(&mut self.state);
		let at = state.known.len();
		Arc::make_mut(&mut state.known).push(v.clone());
		Arc::make_mut(&mut state.known_map)
			.entry(v.hash_value())
			.or_default()
			.push(at);
		Arc::make_mut(&mut state.derivations).push(derivation);
		state.chain = next_chain();
		Arc::make_mut(&mut self.origins).push(origin);
		true
	}

	pub(crate) fn note_protocol(&mut self, value: &Value, pre: &Value, own: bool) {
		Arc::make_mut(&mut self.protocol).push((value.clone(), pre.clone(), own));
		Arc::make_mut(&mut self.candidates).note(value, pre);
	}

	pub(crate) fn note_computed(&mut self, declared: &Value, pre: &Value, value: &Value) {
		let mut built = Vec::new();
		applied(declared, pre, &mut built);
		if !value.same_term(pre) {
			let mut inputs: IdMap<u64, Vec<&Value>> = IdMap::default();
			for term in crate::value::subterms(pre) {
				inputs.entry(term.hash_value()).or_default().push(term);
			}
			reassembled(value, &inputs, &mut IdSet::default(), &mut built);
		}
		for term in &built {
			self.note_built(term);
		}
	}

	pub(crate) fn note_built(&mut self, term: &Value) {
		let key = term.hash_value();
		if self
			.built
			.get(&key)
			.is_some_and(|bucket| bucket.iter().any(|held| held.equivalent(term, true)))
		{
			return;
		}
		Arc::make_mut(&mut self.built)
			.entry(key)
			.or_default()
			.push(term.clone());
		self.built_len += 1;
	}

	pub(crate) fn is_closed(&self) -> bool {
		self.closed == self.len()
			&& self.closed_protocol == self.protocol.len()
			&& self.closed_built == self.built_len
			&& self.closed_phase == self.phase()
	}

	pub(crate) fn derivable(&mut self, v: &Value, ps: &PrincipalState) -> bool {
		self.close(ps);
		obtainable(v, ps, &self.state)
	}

	pub(crate) fn close(&mut self, ps: &PrincipalState) {
		if self.is_closed() {
			return;
		}
		loop {
			let snapshot = Arc::clone(&self.state);
			let candidates = Arc::clone(&self.candidates);
			let learned = {
				let _memo = crate::theory::DeductionMemo::scoped(ps, &snapshot);
				pass(ps, &snapshot, &candidates)
			};
			let mut progress = false;
			for (v, origin) in learned {
				progress |= self.learn(&v, origin);
			}
			let pairs = reuse_pairs(ps, &self.state, &self.built);
			for pair in pairs {
				if !self.state.reused.iter().any(|held| {
					held[0].equivalent(&pair[0], true) && held[1].equivalent(&pair[1], true)
				}) {
					let state = Arc::make_mut(&mut self.state);
					Arc::make_mut(&mut state.reused).push(pair.clone());
					state.chain = next_chain();
					progress = true;
				}
				let Value::Primitive(p) = &pair[0] else {
					continue;
				};
				let Some(rule) = reuse_rule(p.id) else {
					continue;
				};
				for reveal in &rule.reveals {
					let revealed = match *reveal {
						Reveal::Argument(index) => match p.arguments.get(index) {
							Some(argument) => reduce_once(argument),
							None => continue,
						},
						Reveal::Output(output) => Value::Primitive(Arc::new(p.with_output(output))),
					};
					progress |= self.learn(
						&revealed,
						Origin::Derived(DerivationRecord::Reused {
							of: pair[0].clone(),
							with: pair[1].clone(),
						}),
					);
				}
			}
			if !progress {
				break;
			}
		}
		self.closed = self.len();
		self.closed_protocol = self.protocol.len();
		self.closed_built = self.built_len;
		self.closed_phase = self.phase();
	}
}

fn pass(
	ps: &PrincipalState,
	attacker: &AttackerState,
	candidates: &Candidates,
) -> Vec<(Value, Origin)> {
	let mut out: Vec<(Value, Origin)> = Vec::new();
	let push = |out: &mut Vec<(Value, Origin)>, v: Value, d: DerivationRecord| {
		if attacker.knows(&v).is_none() && !out.iter().any(|(held, _)| held.equivalent(&v, true)) {
			out.push((v, Origin::Derived(d)));
		}
	};
	for known in attacker.known.iter() {
		let Value::Primitive(p) = known else {
			continue;
		};
		if let Some(result) = can_decompose(p, ps, attacker) {
			for revealed in result.revealed {
				push(
					&mut out,
					revealed,
					DerivationRecord::Decomposed {
						of: known.clone(),
						using: result.used.clone(),
					},
				);
			}
		}
		if let Some(revealed) = can_break_weak(p, ps, attacker) {
			for r in revealed {
				push(
					&mut out,
					r,
					DerivationRecord::Broken {
						of: known.clone(),
						capability: Capability::Weak,
						using: vec![],
					},
				);
			}
		}
		for (v, d) in rewrite_build(known, p, ps, attacker) {
			push(&mut out, v, d);
		}
		if primitive_core_reveals_args(p.id) {
			for arg in &p.arguments {
				push(
					&mut out,
					arg.clone(),
					DerivationRecord::Fragment { of: known.clone() },
				);
			}
		}
	}
	for value in &candidates.recon {
		let Value::Primitive(p) = value else {
			continue;
		};
		if attacker.knows(value).is_some() {
			continue;
		}
		let Some(built) = can_reconstruct_primitive(p, ps, attacker) else {
			continue;
		};
		let derivation = match built.forged {
			Some(Forged::Assumption { capability, of }) => DerivationRecord::Broken {
				of,
				capability,
				using: built.from,
			},
			Some(Forged::Reuse(with)) => DerivationRecord::ReusedForge {
				with,
				using: built.from,
			},
			None if built.combined => DerivationRecord::Combined { from: built.from },
			None => DerivationRecord::Reconstructed { from: built.from },
		};
		push(&mut out, value.clone(), derivation);
	}
	for value in &candidates.splits {
		let Value::Primitive(p) = value else {
			continue;
		};
		if let Some(rule) = crate::primitive::primitive_get(p.id)
			.ok()
			.and_then(|spec| spec.recompose.as_ref())
			&& p.arguments
				.get(rule.reveal)
				.is_some_and(|secret| attacker.knows(secret).is_some())
		{
			continue;
		}
		if let Some(result) = can_recompose(p, attacker) {
			push(
				&mut out,
				result.revealed,
				DerivationRecord::Recomposed {
					of: value.clone(),
					using: result.used,
				},
			);
		}
	}
	for (pre, reduced) in &candidates.forward {
		if attacker.knows(reduced).is_some() {
			continue;
		}
		let Value::Primitive(p) = pre else {
			continue;
		};
		if p.arguments.iter().all(|arg| obtainable(arg, ps, attacker)) {
			push(
				&mut out,
				reduced.clone(),
				DerivationRecord::Rewritten {
					of: pre.clone(),
					using: p.arguments.clone(),
					built: false,
				},
			);
		}
	}
	out
}

fn rewrite_build(
	value: &Value,
	inner: &Arc<Primitive>,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> Vec<(Value, DerivationRecord)> {
	let mut out = Vec::new();
	if can_decompose(inner, ps, attacker).is_some() {
		return out;
	}
	for spec in crate::primitive::primitives_rewriting(inner.id) {
		let Some(rule) = spec.rewrite.as_ref() else {
			continue;
		};
		if spec.definition_check
			&& spec.rebuild.is_none()
			&& spec.combine.is_empty()
			&& let crate::primitive::RewriteTo::Fixed(result) = &rule.to
			&& attacker.knows(result).is_some()
		{
			continue;
		}
		if rule
			.from_output
			.is_some_and(|output| output != inner.output)
		{
			continue;
		}
		let mut pool: Vec<Value> = Vec::new();
		for (_, positions) in &rule.matching {
			for &at in positions {
				let Some(pinned) = inner.arguments.get(at) else {
					continue;
				};
				let mut candidates = vec![pinned.clone()];
				if let Value::Primitive(p) = pinned {
					candidates.extend(p.arguments.iter().cloned());
				}
				for candidate in candidates {
					if obtainable(&candidate, ps, attacker)
						&& !pool.iter().any(|held| held.equivalent(&candidate, true))
					{
						pool.push(candidate);
					}
				}
			}
		}
		if pool.is_empty() {
			continue;
		}
		for &arity in &spec.arity {
			let arity = arity as usize;
			if rule.from >= arity {
				continue;
			}
			let open: Vec<usize> = (0..arity).filter(|&at| at != rule.from).collect();
			let mut choice = vec![0usize; open.len()];
			loop {
				let mut args = vec![value.clone(); arity];
				for (&at, &pick) in open.iter().zip(choice.iter()) {
					args[at] = pool[pick].clone();
				}
				let built = Value::primitive(spec.id, args, 0);
				if let Value::Primitive(p) = &built {
					let (reduces, reduced) = can_rewrite(p);
					if reduces
						&& !reduced.equivalent(&built, true)
						&& attacker.knows(&reduced).is_none()
					{
						out.push((
							reduced,
							DerivationRecord::Rewritten {
								of: built.clone(),
								using: p.arguments.clone(),
								built: true,
							},
						));
					}
				}
				let mut digit = 0;
				loop {
					if digit == choice.len() {
						break;
					}
					choice[digit] += 1;
					if choice[digit] < pool.len() {
						break;
					}
					choice[digit] = 0;
					digit += 1;
				}
				if digit == choice.len() {
					break;
				}
			}
		}
	}
	out
}

fn reuse_pairs(
	ps: &PrincipalState,
	attacker: &AttackerState,
	built: &IdMap<u64, Vec<Value>>,
) -> Vec<[Value; 2]> {
	let _memo = crate::theory::DeductionMemo::ensure(ps, attacker);
	let mut buckets: IdMap<u64, Vec<usize>> = IdMap::default();
	for (i, known) in attacker.known.iter().enumerate() {
		let Value::Primitive(p) = known else {
			continue;
		};
		let Some(rule) = reuse_rule(p.id) else {
			continue;
		};
		if rule.fixed.iter().all(|&at| {
			p.arguments
				.get(at)
				.is_some_and(|a| obtainable(a, ps, attacker))
		}) {
			continue;
		}
		let mints = can_reconstruct_primitive(p, ps, attacker).is_some_and(|b| b.forged.is_some());
		if mints
			&& !built
				.get(&known.hash_value())
				.is_some_and(|terms| terms.iter().any(|term| term.equivalent(known, true)))
		{
			continue;
		}
		let mut key = u64::from(p.id);
		for &at in &rule.fixed {
			let Some(argument) = p.arguments.get(at) else {
				continue;
			};
			key = key.rotate_left(17).wrapping_add(argument.hash_value());
		}
		buckets.entry(key).or_default().push(i);
	}
	let mut pairs = Vec::new();
	for members in buckets.values() {
		if members.len() < 2 {
			continue;
		}
		for &i in members {
			let of = &attacker.known[i];
			let Some(&j) = members
				.iter()
				.find(|&&j| reused_pair(of, &attacker.known[j]))
			else {
				continue;
			};
			pairs.push([of.clone(), attacker.known[j].clone()]);
		}
	}
	pairs
}

fn applied(declared: &Value, pre: &Value, out: &mut Vec<Value>) {
	let (Value::Primitive(d), Value::Primitive(p)) = (declared, pre) else {
		return;
	};
	out.push(pre.clone());
	for (d, p) in d.arguments.iter().zip(&p.arguments) {
		applied(d, p, out);
	}
}

fn reassembled(
	value: &Value,
	inputs: &IdMap<u64, Vec<&Value>>,
	seen: &mut IdSet<usize>,
	out: &mut Vec<Value>,
) {
	let Value::Primitive(p) = value else {
		return;
	};
	if !seen.insert(Arc::as_ptr(p) as usize) {
		return;
	}
	if inputs
		.get(&value.hash_value())
		.is_some_and(|bucket| bucket.iter().any(|input| input.equivalent(value, true)))
	{
		return;
	}
	out.push(value.clone());
	for argument in &p.arguments {
		reassembled(argument, inputs, seen, out);
	}
}
