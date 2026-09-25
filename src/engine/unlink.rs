/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use super::exec::{Context, Execution, Held};
use super::program::Event;
use crate::context::Generational;
use crate::primitive::{
	PrimitiveSpec, RewriteRule, primitive_check_undoing, primitive_core_reveals_args,
	primitive_name,
};
use crate::theory::{can_recompose, can_reconstruct_primitive, obtainable};
use crate::types::*;

#[derive(Clone, Copy, Debug)]
pub(crate) enum LinkKind {
	SharedSecret,
	IdentifyingCheck(PrimitiveId),
	ObservedEquality,
	RecognizedSecret(PrimitiveId),
}

#[derive(Clone, Debug)]
pub(crate) struct Link {
	pub(crate) kind: LinkKind,
	pub(crate) value: Value,
	pub(crate) components: Option<[Value; 2]>,
}

struct Scope<'a> {
	km: &'a ProtocolTrace,
	attacker: &'a AttackerState,
}

impl Scope<'_> {
	fn secret(&self, v: &Value) -> bool {
		depends_on_secret(v, self.km)
	}

	fn obtainable(&self, v: &Value) -> bool {
		obtainable(v, &self.km.capabilities, self.attacker)
	}
}

pub(crate) fn link(
	cx: &Context,
	ex: &Execution,
	[(a, ha), (b, hb)]: [(usize, &Held); 2],
) -> Option<Link> {
	if ha.authored || hb.authored {
		return None;
	}
	let km = cx.km;
	let scope = Scope {
		km,
		attacker: &ex.knowledge.state,
	};
	let (av, bv) = (&ha.value, &hb.value);
	let observed = observed(&scope, cx, ex);
	if !observable(&scope, &observed, av) || !observable(&scope, &observed, bv) {
		return None;
	}
	let honest = |slot: usize| {
		crate::theory::reduce_once(&crate::value::resolve_trace_constant(
			&km.slots[slot].constant,
			km,
		))
	};
	let same = honest(a).equivalent(&honest(b), true);
	let shared = shared_secret_leaves(&scope, a, b);
	if !same && shared.is_empty() {
		return None;
	}
	let valid = |w: &Value, kind: LinkKind| {
		scope.secret(w)
			&& !supplied(ex, w)
			&& (matches!(kind, LinkKind::ObservedEquality)
				|| w.constant_leaves().any(|c| shared.contains(&c.id)))
	};
	let (ta, tb) = (ties(&scope, av, None), ties(&scope, bv, None));
	if let Some(link) = strongest(&scope, [av, bv], [&ta, &tb], same, &valid) {
		return Some(link);
	}
	let (pa, pb) = (with_parts(&scope, av, ta), with_parts(&scope, bv, tb));
	strongest(&scope, [av, bv], [&pa, &pb], same, &valid)
}

#[derive(Clone, Copy)]
enum Tie {
	Itself,
	Built,
	Key(PrimitiveId),
	Confirms(PrimitiveId),
}

struct Tied {
	term: Value,
	tie: Tie,
	via: Option<Value>,
}

fn ties(scope: &Scope, v: &Value, via: Option<&Value>) -> Vec<Tied> {
	let known = scope.attacker.knows(v).is_some();
	let mut out: Vec<Tied> = Vec::new();
	let mut tie = |term: Value, tie: Tie| {
		out.push(Tied {
			term,
			tie,
			via: via.cloned(),
		})
	};
	if known {
		tie(v.clone(), Tie::Itself);
	}
	for leaf in origin_leaves(scope, v).unwrap_or_default() {
		tie(leaf, Tie::Built);
	}
	let Value::Primitive(p) = v else {
		return out;
	};
	let Some((check, rule)) = primitive_check_undoing(p.id) else {
		return out;
	};
	if !runnable(scope, check, rule, p) {
		return out;
	}
	if let Some(&identifying) = check.identifying_positions.first()
		&& let Some(&key) = rule
			.matching
			.iter()
			.find(|(position, _)| *position == identifying)
			.and_then(|(_, targets)| targets.first())
		&& let Some(identifier) = p
			.arguments
			.get(key)
			.and_then(|produced| check_input(check, rule, identifying, key, produced))
		&& scope.obtainable(&identifier)
	{
		tie(identifier, Tie::Key(check.id));
	}
	if known {
		for arg in rule
			.matching
			.iter()
			.flat_map(|(_, targets)| targets.iter().filter_map(|&t| p.arguments.get(t)))
		{
			if crate::primitive::value_is_key_derivation(arg) || !scope.obtainable(arg) {
				continue;
			}
			tie(arg.clone(), Tie::Confirms(check.id));
			for leaf in origin_leaves(scope, arg).unwrap_or_default() {
				tie(leaf, Tie::Confirms(check.id));
			}
		}
	}
	out
}

fn with_parts(scope: &Scope, v: &Value, mut tied: Vec<Tied>) -> Vec<Tied> {
	for part in parts(scope, v) {
		if !part.equivalent(v, true) {
			tied.extend(ties(scope, &part, Some(&part)));
		}
	}
	tied
}

fn strongest(
	scope: &Scope,
	[av, bv]: [&Value; 2],
	[ta, tb]: [&[Tied]; 2],
	same: bool,
	valid: &dyn Fn(&Value, LinkKind) -> bool,
) -> Option<Link> {
	let mut best: Option<(u8, Link)> = None;
	for a in ta {
		for b in tb {
			let w = &a.term;
			if !w.equivalent(&b.term, true) {
				continue;
			}
			let (sa, sb) = (a.via.as_ref().unwrap_or(av), b.via.as_ref().unwrap_or(bv));
			let fresh = !w.equivalent(sa, true) && !w.equivalent(sb, true);
			let via = a.via.is_some() || b.via.is_some();
			let joined = match (a.tie, b.tie) {
				(Tie::Itself, Tie::Itself) if same => Some((0, LinkKind::ObservedEquality)),
				(Tie::Key(i), Tie::Key(j)) if i == j => Some((1, LinkKind::IdentifyingCheck(i))),
				(Tie::Built, Tie::Built)
					if !via && fresh && [av, bv].iter().any(|v| held_without(scope, w, v)) =>
				{
					Some((2, LinkKind::SharedSecret))
				}
				(Tie::Itself, Tie::Built) | (Tie::Built, Tie::Itself) => {
					Some((3, LinkKind::SharedSecret))
				}
				(Tie::Confirms(i), Tie::Built | Tie::Confirms(_))
				| (Tie::Built, Tie::Confirms(i))
					if fresh =>
				{
					Some((4, LinkKind::RecognizedSecret(i)))
				}
				(Tie::Key(i) | Tie::Confirms(i), Tie::Itself)
				| (Tie::Itself, Tie::Key(i) | Tie::Confirms(i))
				| (Tie::Key(i), Tie::Built)
				| (Tie::Built, Tie::Key(i)) => Some((4, LinkKind::RecognizedSecret(i))),
				_ => None,
			};
			let Some((rank, kind)) = joined else {
				continue;
			};
			let rank = match kind {
				_ if !via => rank,
				LinkKind::IdentifyingCheck(_) | LinkKind::RecognizedSecret(_) => 5,
				LinkKind::ObservedEquality | LinkKind::SharedSecret => continue,
			};
			if best.as_ref().is_some_and(|(held, _)| *held <= rank) || !valid(w, kind) {
				continue;
			}
			let components = via.then(|| [sa.clone(), sb.clone()]);
			best = Some((
				rank,
				Link {
					kind,
					value: w.clone(),
					components,
				},
			));
		}
	}
	best.map(|(_, link)| link)
}

impl Link {
	pub(crate) fn describe(&self, render: impl Fn(&Value) -> String) -> String {
		let term = render(&self.value);
		let through = |[a, b]: &[Value; 2]| format!("through {} and {}", render(a), render(b));
		match (self.kind, &self.components) {
			(LinkKind::ObservedEquality, _) => format!("because both are the same value ({term})"),
			(LinkKind::SharedSecret, _) => format!("via {term}"),
			(LinkKind::IdentifyingCheck(id), None) => {
				format!(
					"because {} succeeds for both under {term}",
					primitive_name(id)
				)
			}
			(LinkKind::IdentifyingCheck(id), Some(components)) => format!(
				"{}, for which {} succeeds under {term}",
				through(components),
				primitive_name(id)
			),
			(LinkKind::RecognizedSecret(id), None) => {
				format!("via {term}, which {} confirms", primitive_name(id))
			}
			(LinkKind::RecognizedSecret(id), Some(components)) => format!(
				"{}, linked via {term}, which {} confirms",
				through(components),
				primitive_name(id)
			),
		}
	}
}

pub(crate) fn depends_on_secret(v: &Value, km: &ProtocolTrace) -> bool {
	v.constant_leaves().any(|c| secret_constant(c, km))
}

fn secret_constant(c: &Constant, km: &ProtocolTrace) -> bool {
	c.fresh
		|| c.qualifier == Some(Qualifier::Private)
		|| km.index_of(c).is_some_and(|i| {
			let declared = &km.slots[i].constant;
			declared.fresh || declared.qualifier == Some(Qualifier::Private)
		})
}

fn public(v: &Value, km: &ProtocolTrace) -> bool {
	matches!(v, Value::Constant(c) if km
		.index_of(c)
		.is_some_and(|i| km.slots[i].constant.qualifier == Some(Qualifier::Public)))
}

fn observed(scope: &Scope, cx: &Context, ex: &Execution) -> crate::hashing::TermSet {
	let mut pending: Vec<Value> = ex.sent.iter().flatten().flatten().cloned().collect();
	for &(run, step, _) in &ex.order {
		if let Event::Leak(slot) = cx.program.runs[run].steps[step].event
			&& let Some(held) = ex.runs[run].held(slot)
		{
			pending.push(held.value.clone());
		}
	}
	let attacker = scope.attacker;
	let mut seen = crate::hashing::TermSet::default();
	while let Some(value) = pending.pop() {
		if seen.contains(&value) {
			continue;
		}
		seen.insert(value.clone());
		let Value::Primitive(p) = &value else {
			continue;
		};
		if primitive_core_reveals_args(p.id) {
			pending.extend(p.arguments.iter().cloned());
		}
		if let Some(opened) = crate::theory::can_decompose(p, &scope.km.capabilities, attacker) {
			pending.extend(opened.revealed);
		}
		if let Some(revealed) = crate::theory::can_break_weak(p, &scope.km.capabilities, attacker) {
			pending.extend(revealed);
		}
		if let Some(rule) = crate::primitive::reuse_rule(p.id)
			&& attacker.reused.iter().any(|pair| {
				pair.iter().any(|member| member.equivalent(&value, true))
					&& pair.iter().all(|member| attacker.knows(member).is_some())
			}) {
			pending.extend(crate::theory::revealed(p, &rule.reveals));
		}
	}
	seen
}

fn observable(scope: &Scope, observed: &crate::hashing::TermSet, v: &Value) -> bool {
	if scope.attacker.knows(v).is_none() {
		return false;
	}
	if observed.contains(v) || public(v, scope.km) {
		return true;
	}
	matches!(v, Value::Primitive(p) if primitive_core_reveals_args(p.id)
		&& p.arguments.iter().all(|arg| observable(scope, observed, arg)))
}

fn shared_secret_leaves(scope: &Scope, a: usize, b: usize) -> IdSet<ValueId> {
	let km = scope.km;
	let of = |slot: usize| {
		crate::value::subterms(&crate::value::resolve_trace_constant(
			&km.slots[slot].constant,
			km,
		))
		.cloned()
		.collect::<Vec<Value>>()
	};
	let (of_a, of_b) = (of(a), of(b));
	of_b.iter()
		.filter(|t| {
			scope.secret(t)
				&& of_a
					.iter()
					.any(|s| s.hash_value() == t.hash_value() && s.equivalent(t, true))
		})
		.flat_map(Value::constant_leaves)
		.filter(|c| secret_constant(c, km))
		.map(|c| c.id)
		.collect()
}

fn supplied(ex: &Execution, v: &Value) -> bool {
	ex.runs
		.iter()
		.flat_map(|run| run.env.iter().flatten())
		.any(|h| h.authored && h.pre.equivalent(v, true))
}

fn parts(scope: &Scope, v: &Value) -> Vec<Value> {
	let mut out = origin_leaves(scope, v).unwrap_or_default();
	let mut pending = vec![v.clone()];
	let mut seen = crate::hashing::TermSet::default();
	while let Some(value) = pending.pop() {
		if seen.contains(&value) {
			continue;
		}
		seen.insert(value.clone());
		if let Value::Primitive(p) = &value
			&& primitive_core_reveals_args(p.id)
		{
			pending.extend(p.arguments.iter().cloned());
		}
		push_leaf(&mut out, &value);
	}
	out
}

fn held_without(scope: &Scope, w: &Value, of: &Value) -> bool {
	let attacker = scope.attacker;
	let mut dropped = vec![false; attacker.known.len()];
	if let Some(idx) = attacker.knows(of) {
		dropped[idx.get()] = true;
	}
	for i in 0..attacker.known.len() {
		if !dropped[i] {
			dropped[i] = attacker.derivation(KnownIdx(i)).is_some_and(|derivation| {
				derivation.ingredients().iter().any(|ingredient| {
					attacker
						.knows(ingredient)
						.is_some_and(|at| dropped[at.get()])
				})
			});
		}
	}
	let keep: Vec<bool> = dropped.iter().map(|d| !d).collect();
	let restricted = attacker.retaining(&keep);
	let restricted = restricted.as_deref().unwrap_or(attacker);
	restricted.knows(w).is_some()
		|| obtainable(w, &scope.km.capabilities, restricted)
		|| restricted.known.iter().any(|known| match known {
			Value::Primitive(q) => {
				can_recompose(q, restricted).is_some_and(|r| r.revealed.equivalent(w, true))
			}
			_ => false,
		})
}

fn check_input(
	check: &PrimitiveSpec,
	rule: &RewriteRule,
	position: usize,
	target: usize,
	produced: &Value,
) -> Option<Value> {
	let arity = *check.arity.last()? as usize;
	for candidate in [
		Some(produced.clone()),
		crate::primitive::key_derivation_of(produced.clone()),
		crate::primitive::key_derivation_inner(produced).cloned(),
	]
	.into_iter()
	.flatten()
	{
		let mut arguments = vec![produced.clone(); arity];
		if position >= arguments.len() {
			return None;
		}
		arguments[position] = candidate.clone();
		let probe = Primitive::new(check.id, arguments, 0);
		let (filtered, valid) = (rule.filter)(&probe, &candidate, target);
		if valid && filtered.equivalent(produced, true) {
			return Some(candidate);
		}
	}
	None
}

fn runnable(scope: &Scope, check: &PrimitiveSpec, rule: &RewriteRule, p: &Primitive) -> bool {
	if rule.id != p.id || rule.from_output.is_some_and(|output| output != p.output) {
		return false;
	}
	let Some(&arity) = check.arity.last() else {
		return false;
	};
	let mut arguments = vec![crate::value::value_nil(); arity as usize];
	let Some(source) = arguments.get_mut(rule.from) else {
		return false;
	};
	*source = Value::Primitive(Arc::new(p.clone()));
	let mut candidates = vec![(arguments, Vec::new())];
	for (position, targets) in &rule.matching {
		let inputs: Vec<_> = targets
			.iter()
			.filter_map(|&target| {
				let input = check_input(check, rule, *position, target, p.arguments.get(target)?)?;
				scope.obtainable(&input).then_some((target, input))
			})
			.collect();
		let mut next = Vec::new();
		for (arguments, taken) in &candidates {
			for (target, input) in &inputs {
				if taken.contains(target) || *position >= arguments.len() {
					continue;
				}
				let mut arguments = arguments.clone();
				arguments[*position] = input.clone();
				let mut taken = taken.clone();
				taken.push(*target);
				next.push((arguments, taken));
			}
		}
		if next.is_empty() {
			return false;
		}
		candidates = next;
	}
	candidates.into_iter().any(|(arguments, _)| {
		crate::theory::can_rewrite(&Arc::new(Primitive::new(check.id, arguments, 0))).0
	})
}

type Leaves = Generational<
	crate::context::Recent<crate::context::KnowledgeKey, u64, Vec<(Value, Option<Vec<Value>>)>>,
>;

thread_local! {
	static LEAVES: std::cell::RefCell<Leaves> =
		std::cell::RefCell::new(Generational::default());
}

fn origin_leaves(scope: &Scope, v: &Value) -> Option<Vec<Value>> {
	let key = v.hash_value();
	let group = crate::context::KnowledgeKey::of(scope.attacker);
	let remembered = LEAVES.with(|memo| {
		memo.borrow_mut()
			.fresh()
			.group(group)
			.get(&key)
			.and_then(|bucket| {
				bucket
					.iter()
					.find(|(seen, _)| crate::theory::structurally_identical(seen, v))
					.map(|(_, leaves)| leaves.clone())
			})
	});
	if let Some(leaves) = remembered {
		return leaves;
	}
	let keep: Vec<bool> = scope
		.attacker
		.known
		.iter()
		.map(|known| known.hash_value() != key || !known.equivalent(v, true))
		.collect();
	let without = scope.attacker.retaining(&keep);
	let without = without.as_deref().unwrap_or(scope.attacker);
	let mut out = Vec::new();
	let leaves = collect_leaves(
		v,
		&scope.km.capabilities,
		without,
		&mut Vec::new(),
		&mut out,
	)
	.then_some(out);
	LEAVES.with(|memo| {
		memo.borrow_mut()
			.fresh()
			.group(group)
			.entry(key)
			.or_default()
			.push((v.clone(), leaves.clone()));
	});
	leaves
}

fn collect_leaves(
	v: &Value,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
	expanded: &mut Vec<Value>,
	out: &mut Vec<Value>,
) -> bool {
	let held = attacker.knows(v).is_some();
	if held {
		push_leaf(out, v);
	}
	let Value::Primitive(p) = v else {
		return held;
	};
	if expanded.iter().any(|seen| seen.equivalent(v, true)) {
		return held;
	}
	expanded.push(v.clone());
	let Some(used) = can_reconstruct_primitive(p, capabilities, attacker)
		.map(|r| r.from)
		.or_else(|| can_recompose(p, attacker).map(|r| r.used))
	else {
		return held;
	};
	for arg in &used {
		collect_leaves(arg, capabilities, attacker, expanded, out);
	}
	true
}

fn push_leaf(out: &mut Vec<Value>, v: &Value) {
	if !out.iter().any(|k| k.equivalent(v, true)) {
		out.push(v.clone());
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::engine::exec::{Installs, execute};
	use crate::engine::program::Program;

	fn observed_in(src: &str, install: Option<(&str, &str)>, phase: i32, target: &str) -> bool {
		let _generation = crate::context::GenerationGuard::enter();
		let m = crate::parser::parse_string("ul.vp", src).expect("parses");
		let km = crate::sanity::sanity(&m).expect("sane");
		let program = Program::of(&m, &km);
		let cx = Context::new(&program, &km);
		let slot = |name: &str| {
			km.slots
				.iter()
				.position(|s| s.constant.name.as_ref() == name)
				.expect("declared")
		};
		let installs: Installs = install
			.map(|(principal, name)| {
				let run = program
					.runs
					.iter()
					.position(|r| r.name == principal)
					.expect("run");
				(run, slot(name), crate::value::value_nil())
			})
			.into_iter()
			.collect();
		let ex = execute(&cx, &installs);
		let ex = ex.at(phase);
		let scope = Scope {
			km: &km,
			attacker: &ex.knowledge.state,
		};
		let value = crate::theory::reduce_once(&crate::value::resolve_trace_constant(
			&km.slots[slot(target)].constant,
			&km,
		));
		observable(&scope, &observed(&scope, &cx, ex), &value)
	}

	#[test]
	fn a_later_phase_disclosure_is_not_observed_at_an_earlier_barrier() {
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private ulp_k\n\
			generates ulp_m\n\
			ulp_e = ENC(ulp_k, ulp_m)\n\
			leaks ulp_k\n\
			]\n\
			phase[1]\n\
			Alice -> Bob: ulp_e\n\
			principal Bob[\n\
			knows private ulp_k\n\
			_ = DEC(ulp_k, ulp_e)\n\
			]\n\
			queries[\n\
			confidentiality? ulp_m\n\
			]\n";
		assert!(!observed_in(src, None, 0, "ulp_m"));
		assert!(observed_in(src, None, 1, "ulp_m"));
		assert!(observed_in(src, None, 1, "ulp_e"));
	}

	#[test]
	fn a_halted_sender_discloses_nothing_after_its_halt() {
		let src = "attacker[active]\n\
			principal Carol[\n\
			generates ulh_x\n\
			ulh_h = HASH(ulh_x)\n\
			]\n\
			Carol -> Alice: ulh_x, [ulh_h]\n\
			principal Alice[\n\
			knows private ulh_k\n\
			generates ulh_m\n\
			_ = ASSERT(HASH(ulh_x), ulh_h)?\n\
			ulh_e = CONCAT(ulh_m, ulh_k)\n\
			]\n\
			Alice -> Bob: ulh_e\n\
			principal Bob[\n\
			_ = HASH(ulh_e)\n\
			]\n\
			queries[\n\
			confidentiality? ulh_m\n\
			]\n";
		assert!(observed_in(src, None, 0, "ulh_m"));
		assert!(!observed_in(src, Some(("Alice", "ulh_x")), 0, "ulh_m"));
	}
}
