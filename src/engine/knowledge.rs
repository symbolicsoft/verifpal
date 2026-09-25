/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::hashing::TermSet;
use crate::primitive::{primitive_core_reveals_args, recompose_rule, reuse_rule};
use crate::theory::{
	can_break_weak, can_decompose, can_recompose, can_reconstruct_primitive, can_rewrite,
	obtainable, reused_pair, revealed,
};
use crate::types::*;

#[derive(Clone, Debug)]
pub(crate) enum Origin {
	Initial,
	Wire { run: usize, slot: usize },
	Leak { run: usize, slot: usize },
	Derived(DerivationRecord),
}

impl Origin {
	fn record(&self) -> DerivationRecord {
		match self {
			Origin::Initial => DerivationRecord::Initial,
			Origin::Wire { slot, .. } => DerivationRecord::Obtained {
				slot: SlotIdx(*slot),
			},
			Origin::Leak { slot, .. } => DerivationRecord::Leaked {
				slot: SlotIdx(*slot),
			},
			Origin::Derived(record) => record.clone(),
		}
	}
}

#[derive(Clone, Default)]
struct Candidates {
	recon: Vec<Value>,
	forward: Vec<(Value, Value)>,
	splits: Vec<Value>,
	seen: TermSet,
	seen_forward: TermSet,
}

impl Candidates {
	fn note(&mut self, value: &Value, pre: &Value) {
		self.walk(value);
		if let Value::Primitive(p) = pre {
			let (reduces, reduced) = can_rewrite(p);
			if reduces && !reduced.equivalent(pre, true) && self.seen_forward.insert(pre.clone()) {
				self.forward.push((pre.clone(), reduced));
			}
		}
	}

	fn walk(&mut self, value: &Value) {
		let Value::Primitive(p) = value else {
			return;
		};
		if !self.seen.insert(value.clone()) {
			return;
		}
		for arg in &p.arguments {
			self.walk(arg);
		}
		if p.threshold > 0
			&& recompose_rule(p.id).is_some()
			&& !self.splits.iter().any(|held| held.equivalent(value, false))
		{
			self.splits.push(value.clone());
		}
		self.recon.push(value.clone());
		for rule in crate::primitive::combines_from(p.id) {
			let Some(Value::Primitive(share)) = p.arguments.get(rule.share) else {
				continue;
			};
			let Some(recompose) = recompose_rule(share.id) else {
				continue;
			};
			let Some(secret) = share.arguments.get(recompose.reveal) else {
				continue;
			};
			if share.id != rule.split || share.threshold == 0 {
				continue;
			}
			let mut arguments = vec![secret.clone()];
			arguments.extend(
				rule.carry
					.iter()
					.filter_map(|&at| p.arguments.get(at).cloned()),
			);
			let whole = Value::primitive(rule.whole, arguments, 0);
			if self.seen.insert(whole.clone()) {
				self.recon.push(whole);
			}
		}
	}
}

#[derive(Clone)]
pub(crate) struct Knowledge {
	pub(crate) state: Arc<AttackerState>,
	origins: Arc<Vec<Origin>>,
	pub(crate) protocol: Arc<Vec<(Value, Value, bool)>>,
	pub(crate) built: Arc<TermSet>,
	candidates: Arc<Candidates>,
	closed: bool,
}

impl Knowledge {
	pub(crate) fn new(phase: i32) -> Knowledge {
		Knowledge {
			state: Arc::new(AttackerState {
				current_phase: phase,
				..AttackerState::default()
			}),
			origins: Arc::new(Vec::new()),
			protocol: Arc::new(Vec::new()),
			built: Arc::new(TermSet::default()),
			candidates: Arc::new(Candidates::default()),
			closed: true,
		}
	}

	pub(crate) fn len(&self) -> usize {
		self.state.known.len()
	}

	pub(crate) fn set_phase(&mut self, phase: i32) {
		if self.state.current_phase != phase {
			let state = Arc::make_mut(&mut self.state);
			state.current_phase = phase;
			state.chain = next_chain();
			self.closed = false;
		}
	}

	pub(crate) fn knows(&self, v: &Value) -> Option<usize> {
		self.state.knows(v).map(|i| i.get())
	}

	pub(crate) fn origin(&self, i: usize) -> &Origin {
		&self.origins[i]
	}

	pub(crate) fn learn(&mut self, v: &Value, origin: Origin) -> bool {
		if let Some(at) = self.state.knows(v) {
			if !matches!(origin, Origin::Derived(_))
				&& !self.state.derivations[at.get()].ingredients().is_empty()
			{
				let state = Arc::make_mut(&mut self.state);
				Arc::make_mut(&mut state.derivations)[at.get()] = origin.record();
				state.chain = next_chain();
			}
			return false;
		}
		let state = Arc::make_mut(&mut self.state);
		let at = state.known.len();
		Arc::make_mut(&mut state.known).push(v.clone());
		Arc::make_mut(&mut state.known_map)
			.entry(v.hash_value())
			.or_default()
			.push(at);
		Arc::make_mut(&mut state.derivations).push(origin.record());
		state.chain = next_chain();
		Arc::make_mut(&mut self.origins).push(origin);
		self.closed = false;
		true
	}

	pub(crate) fn has_reused(&self, pair: &[Value; 2]) -> bool {
		self.state
			.reused
			.iter()
			.any(|held| held[0].equivalent(&pair[0], true) && held[1].equivalent(&pair[1], true))
	}

	pub(crate) fn note_reused(&mut self, pair: &[Value; 2]) -> bool {
		if self.has_reused(pair) {
			return false;
		}
		let state = Arc::make_mut(&mut self.state);
		Arc::make_mut(&mut state.reused).push(pair.clone());
		state.chain = next_chain();
		self.closed = false;
		true
	}

	pub(crate) fn note_protocol(&mut self, value: &Value, pre: &Value, own: bool) {
		Arc::make_mut(&mut self.protocol).push((value.clone(), pre.clone(), own));
		Arc::make_mut(&mut self.candidates).note(value, pre);
		self.closed = false;
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
		if !self.built.contains(term) {
			Arc::make_mut(&mut self.built).insert(term.clone());
			self.closed = false;
		}
	}

	pub(crate) fn derivable(&mut self, v: &Value, capabilities: &CapabilityIndex) -> bool {
		self.close(capabilities);
		obtainable(v, capabilities, &self.state)
	}

	pub(crate) fn close(&mut self, capabilities: &CapabilityIndex) {
		if self.closed {
			return;
		}
		loop {
			let snapshot = Arc::clone(&self.state);
			let candidates = Arc::clone(&self.candidates);
			let built = Arc::clone(&self.built);
			let learned = {
				let _memo = crate::theory::DeductionMemo::scoped(capabilities, &snapshot);
				pass(capabilities, &snapshot, &candidates, &built)
			};
			let mut progress = false;
			for (v, record) in learned {
				progress |= self.learn(&v, Origin::Derived(record));
			}
			let pairs = reuse_pairs(capabilities, &self.state, &self.built);
			for pair in pairs {
				progress |= self.note_reused(&pair);
				let Value::Primitive(p) = &pair[0] else {
					continue;
				};
				let Some(rule) = reuse_rule(p.id) else {
					continue;
				};
				for revealed in revealed(p, &rule.reveals) {
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
		self.closed = true;
	}
}

fn pass(
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
	candidates: &Candidates,
	built: &TermSet,
) -> Vec<(Value, DerivationRecord)> {
	let mut out: Vec<(Value, DerivationRecord)> = Vec::new();
	let push = |out: &mut Vec<(Value, DerivationRecord)>, v: Value, d: DerivationRecord| {
		if attacker.knows(&v).is_none() && !out.iter().any(|(held, _)| held.equivalent(&v, true)) {
			out.push((v, d));
		}
	};
	for (at, known) in attacker.known.iter().enumerate() {
		let Value::Primitive(p) = known else {
			continue;
		};
		if let Some(result) = can_decompose(p, capabilities, attacker)
			&& !forged(at, attacker)
			&& !minted(p, known, capabilities, attacker, built)
		{
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
		if let Some(revealed) = can_break_weak(p, capabilities, attacker) {
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
		for (v, d) in rewrite_build(known, p, capabilities, attacker) {
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
		let Some(built) = can_reconstruct_primitive(p, capabilities, attacker) else {
			continue;
		};
		push(&mut out, value.clone(), reconstruction(built));
	}
	for value in &candidates.splits {
		let Value::Primitive(p) = value else {
			continue;
		};
		if let Some(rule) = recompose_rule(p.id)
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
		if p.arguments
			.iter()
			.all(|arg| obtainable(arg, capabilities, attacker))
		{
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

pub(crate) fn reconstruction(built: ReconstructResult) -> DerivationRecord {
	match built.forged {
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
	}
}

fn rewrite_build(
	value: &Value,
	inner: &Arc<Primitive>,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Vec<(Value, DerivationRecord)> {
	let mut out = Vec::new();
	if can_decompose(inner, capabilities, attacker).is_some() {
		return out;
	}
	for (spec, rule) in crate::primitive::primitives_rewriting(inner.id) {
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
					if obtainable(&candidate, capabilities, attacker)
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
				if !advance(&mut choice, pool.len()) {
					break;
				}
			}
		}
	}
	out
}

fn advance(choice: &mut [usize], base: usize) -> bool {
	for digit in choice {
		*digit += 1;
		if *digit < base {
			return true;
		}
		*digit = 0;
	}
	false
}

fn forged(at: usize, attacker: &AttackerState) -> bool {
	matches!(
		attacker.derivations.get(at),
		Some(
			DerivationRecord::Broken {
				capability: Capability::Forgeable,
				..
			} | DerivationRecord::ReusedForge { .. }
		)
	)
}

fn minted(
	p: &Arc<Primitive>,
	held: &Value,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
	built: &TermSet,
) -> bool {
	!built.contains(held)
		&& can_reconstruct_primitive(p, capabilities, attacker).is_some_and(|b| b.forged.is_some())
}

fn reuse_pairs(
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
	built: &TermSet,
) -> Vec<[Value; 2]> {
	let _memo = crate::theory::DeductionMemo::ensure(capabilities, attacker);
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
				.is_some_and(|a| obtainable(a, capabilities, attacker))
		}) {
			continue;
		}
		if minted(p, known, capabilities, attacker, built) {
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::engine::exec::{Context, Installs, execute};
	use crate::engine::program::Program;

	fn share_disclosed(src: &str, forge: bool) -> bool {
		let _generation = crate::context::GenerationGuard::enter();
		let m = crate::parser::parse_string("kmf.vp", src).expect("parses");
		let km = crate::sanity::sanity(&m).expect("sane");
		let program = Program::of(&m, &km);
		let cx = Context::new(&program, &km);
		let honest = |name: &str| {
			let slot = km
				.slots
				.iter()
				.find(|s| s.constant.name.as_ref() == name)
				.expect("declared");
			crate::theory::reduce_once(&crate::value::resolve_trace_constant(&slot.constant, &km))
		};
		let installs: Installs = if forge {
			let partial = Value::primitive(
				crate::primitive::PRIM_THRESHOLD_SIGN,
				vec![
					honest("kmf_s1"),
					crate::value::value_nil(),
					honest("kmf_ca"),
					honest("kmf_m"),
				],
				0,
			);
			let run = program
				.runs
				.iter()
				.position(|r| r.name == "Coordinator")
				.expect("run");
			let slot = km
				.slots
				.iter()
				.position(|s| s.constant.name.as_ref() == "kmf_p")
				.expect("declared");
			vec![(run, slot, partial)]
		} else {
			Vec::new()
		};
		let ex = execute(&cx, &installs);
		assert!(ex.stuck.is_empty());
		obtainable(&honest("kmf_s1"), &km.capabilities, &ex.knowledge.state)
	}

	#[test]
	fn a_minted_partial_does_not_reveal_the_share_it_was_forged_over() {
		let model = |leak: &str| {
			format!(
				"attacker[active]\n\
				principal Alice[\n\
				generates kmf_k, kmf_na, kmf_m\n\
				kmf_s1, kmf_s2 = THRESHOLD_SPLIT[2](kmf_k)\n\
				kmf_ca = PUBKEY(kmf_na)\n\
				kmf_p = THRESHOLD_SIGN[forgeable](kmf_s1, kmf_na, kmf_ca, kmf_m)\n\
				{leak}\
				]\n\
				Alice -> Coordinator: kmf_ca, kmf_m, kmf_p\n\
				principal Coordinator[\n\
				_ = HASH(kmf_p)\n\
				]\n\
				queries[\n\
				confidentiality? kmf_s1\n\
				]\n"
			)
		};
		assert!(!share_disclosed(&model(""), false));
		assert!(!share_disclosed(&model(""), true));
		assert!(share_disclosed(&model("leaks kmf_na\n"), false));
	}
}
