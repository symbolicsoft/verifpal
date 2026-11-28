/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::{OnceCell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use super::exec::{Context, Execution, Held, Taken};
use super::knowledge::{Knowledge, Origin};
use super::program::{Event, RunIdx};
use crate::primitive::{CapabilityIndex, PrimitiveSpec, RewriteRule};
use crate::protocol::ProtocolTrace;
use crate::protocol::SlotIdx;
use crate::syntax::Qualifier;
use crate::term::equivalence::structurally_identical;
use crate::term::hashing::TermSet;
use crate::term::{Constant, Primitive, PrimitiveId, Value, ValueId};
use crate::theory::{AttackerState, can_break_weak, can_reconstruct_primitive, obtainable};
use crate::util::{IdMap, IdSet};

#[derive(Clone, Copy, Debug)]
pub(crate) enum LinkKind {
	Equal,
	SameKey(PrimitiveId),
	Shared,
	Contained,
	Confirmed(PrimitiveId),
}

impl LinkKind {
	fn preference(self) -> u8 {
		match self {
			LinkKind::Equal => 0,
			LinkKind::SameKey(_) => 1,
			LinkKind::Shared => 2,
			LinkKind::Contained => 3,
			LinkKind::Confirmed(_) => 4,
		}
	}
}

#[derive(Clone, Debug)]
pub(crate) struct Leg {
	pub(crate) from: Value,
	pub(crate) to: Value,
	pub(crate) check: Option<Value>,
}

#[derive(Clone, Debug)]
pub(crate) struct Link {
	pub(crate) kind: LinkKind,
	pub(crate) value: Value,
	pub(crate) legs: [Vec<Leg>; 2],
}

impl Link {
	pub(crate) fn describe(&self, render: impl Fn(&Value) -> String) -> String {
		let term = render(&self.value);
		let [a, b] = self.legs.each_ref().map(|legs| {
			let whole = legs.first().map_or(&self.value, |leg| &leg.from);
			let checked = legs.iter().rev().find(|leg| leg.check.is_some());
			(whole, checked.map_or(whole, |leg| &leg.from))
		});
		let through = [a, b]
			.iter()
			.any(|(whole, on)| !on.equivalent(whole, true))
			.then(|| format!("through {} and {}", render(a.1), render(b.1)));
		let name = crate::primitive::name;
		match (self.kind, through) {
			(LinkKind::Equal, _) => format!("because both are the same value ({term})"),
			(LinkKind::Shared | LinkKind::Contained, _) => format!("via {term}"),
			(LinkKind::SameKey(id), None) => {
				format!("because {} succeeds for both under {term}", name(id))
			}
			(LinkKind::SameKey(id), Some(through)) => {
				format!("{through}, for which {} succeeds under {term}", name(id))
			}
			(LinkKind::Confirmed(id), None) => format!("via {term}, which {} confirms", name(id)),
			(LinkKind::Confirmed(id), Some(through)) => {
				format!("{through}, linked via {term}, which {} confirms", name(id))
			}
		}
	}
}

#[derive(Clone, Copy)]
enum How {
	Key(PrimitiveId),
	Confirms(PrimitiveId),
}

struct Tie {
	term: Value,
	from: Option<usize>,
	check: Option<Value>,
	last: Option<How>,
	part: bool,
}

impl Tie {
	fn joins(&self, other: &Tie) -> LinkKind {
		match (self.last, other.last) {
			(None, None) => match (self.from, other.from) {
				(None, None) => LinkKind::Equal,
				(None, _) | (_, None) => LinkKind::Contained,
				_ => LinkKind::Shared,
			},
			(Some(How::Key(i)), Some(How::Key(j)))
				if i == j && self.check.is_some() && other.check.is_some() =>
			{
				LinkKind::SameKey(i)
			}
			(Some(How::Confirms(i)), _)
			| (_, Some(How::Confirms(i)))
			| (Some(How::Key(i)), _)
			| (_, Some(How::Key(i))) => LinkKind::Confirmed(i),
		}
	}
}

fn legs(ties: &[Tie], mut at: usize) -> Vec<Leg> {
	let mut out = Vec::new();
	while let Some(from) = ties[at].from {
		out.push(Leg {
			from: ties[from].term.clone(),
			to: ties[at].term.clone(),
			check: ties[at].check.clone(),
		});
		at = from;
	}
	out.reverse();
	out
}

struct Check {
	run: Arc<Primitive>,
	key: Option<Value>,
	confirms: Vec<Value>,
}

#[derive(Default)]
struct Memo<T>(IdMap<u64, Vec<(Value, T)>>);

impl<T: Clone> Memo<T> {
	fn get(&self, v: &Value) -> Option<T> {
		self.0
			.get(&v.hash_value())?
			.iter()
			.find(|(seen, _)| structurally_identical(seen, v))
			.map(|(_, hit)| hit.clone())
	}

	fn put(&mut self, v: &Value, hit: T) {
		self.0
			.entry(v.hash_value())
			.or_default()
			.push((v.clone(), hit));
	}
}

fn remembered<T: Clone>(memo: &RefCell<Memo<T>>, v: &Value, compute: impl FnOnce() -> T) -> T {
	let hit = memo.borrow().get(v);
	hit.unwrap_or_else(|| {
		let found = compute();
		memo.borrow_mut().put(v, found.clone());
		found
	})
}

pub(crate) struct Linker<'a> {
	cx: &'a Context<'a>,
	ex: &'a Execution,
	observed: OnceCell<TermSet>,
	sealed: RefCell<Memo<Arc<AttackerState>>>,
	below: RefCell<Memo<Rc<[Value]>>>,
}

impl<'a> Linker<'a> {
	pub(crate) fn new(cx: &'a Context<'a>, ex: &'a Execution) -> Self {
		Linker {
			cx,
			ex,
			observed: OnceCell::new(),
			sealed: RefCell::default(),
			below: RefCell::default(),
		}
	}

	fn attacker(&self) -> &AttackerState {
		&self.ex.knowledge.state
	}

	fn capabilities(&self) -> &CapabilityIndex {
		self.ex.knowledge.capabilities()
	}

	fn obtainable(&self, v: &Value) -> bool {
		obtainable(v, self.capabilities(), self.attacker())
	}

	pub(crate) fn link(
		&self,
		[(ra, a, ha), (rb, b, hb)]: [(RunIdx, SlotIdx, &Held); 2],
	) -> Option<Link> {
		let km = self.cx.km;
		let queried = [&ha.value, &hb.value];
		let mut seen = IdMap::default();
		if !queried.iter().all(|v| self.observable(v, &mut seen)) {
			return None;
		}
		let same = honest_reduct(km, a).equivalent(&honest_reduct(km, b), true);
		let shared = shared_secret_leaves(km, a, b);
		if !same && shared.is_empty() {
			return None;
		}
		let installed = self.supplied([(ra, a), (rb, b)]);
		let supplied = |w: &Value| obtainable(w, &CapabilityIndex::default(), &installed.state);
		let witness = |w: &Value, kind: LinkKind| {
			depends_on_secret(w, km)
				&& ((same && matches!(kind, LinkKind::Equal))
					|| w.constant_leaves().any(|c| shared.contains(&c.id)))
				&& (!matches!(kind, LinkKind::Shared)
					|| queried.iter().any(|v| self.independent(w, v)))
		};
		let [ta, tb] = queried.map(|v| self.ties(v, &supplied));
		ta.iter()
			.enumerate()
			.flat_map(|a| tb.iter().enumerate().map(move |b| (a, b)))
			.filter(|((_, a), (_, b))| a.term.equivalent(&b.term, true))
			.map(|((x, a), (y, b))| (a.joins(b), x, y))
			.filter(|&(kind, x, _)| witness(&ta[x].term, kind))
			.min_by_key(|&(kind, x, y)| (ta[x].part || tb[y].part, kind.preference()))
			.map(|(kind, x, y)| Link {
				kind,
				value: ta[x].term.clone(),
				legs: [legs(&ta, x), legs(&tb, y)],
			})
	}

	fn ties(&self, v: &Value, supplied: &dyn Fn(&Value) -> bool) -> Vec<Tie> {
		let mut out = Vec::new();
		let mut walked = [Memo::default(), Memo::default()];
		let whole = Tie {
			term: v.clone(),
			from: None,
			check: None,
			last: None,
			part: false,
		};
		self.reach(whole, supplied, &mut walked, &mut out);
		let mut at = 0;
		while at < out.len() {
			if let Some(Check { run, key, confirms }) = self.check(&out[at].term) {
				let application = Value::Primitive(Arc::clone(&run));
				let key = key.iter().map(|term| (How::Key(run.id), term));
				let confirms = confirms.iter().map(|term| (How::Confirms(run.id), term));
				for (how, term) in key.chain(confirms) {
					let tie = Tie {
						term: term.clone(),
						from: Some(at),
						check: Some(application.clone()),
						last: Some(how),
						part: out[at].from.is_some(),
					};
					self.reach(tie, supplied, &mut walked, &mut out);
				}
			}
			at += 1;
		}
		out
	}

	fn reach(
		&self,
		tie: Tie,
		supplied: &dyn Fn(&Value) -> bool,
		walked: &mut [Memo<()>; 2],
		out: &mut Vec<Tie>,
	) {
		let seen = &mut walked[usize::from(tie.last.is_some())];
		if seen.get(&tie.term).is_some() || supplied(&tie.term) {
			return;
		}
		seen.put(&tie.term, ());
		let (at, last, part) = (out.len(), tie.last, tie.part);
		let below = self.below(&tie.term);
		out.push(tie);
		for term in below.iter() {
			let tie = Tie {
				term: term.clone(),
				from: Some(at),
				check: None,
				last,
				part,
			};
			self.reach(tie, supplied, walked, out);
		}
	}

	fn below(&self, v: &Value) -> Rc<[Value]> {
		remembered(&self.below, v, || self.taken_apart(v).into())
	}

	fn taken_apart(&self, v: &Value) -> Vec<Value> {
		let (capabilities, attacker) = (self.capabilities(), self.attacker());
		let held = |value: &Value| attacker.knows(value).is_some();
		let opened = |value: &Value| opening(value, capabilities, attacker);
		let from = ingredients(v, capabilities, attacker);
		let mut revealed = opened(v);
		if from.is_some()
			&& let Value::Primitive(p) = v
		{
			revealed.extend(crate::theory::decomposition_reveals(p).unwrap_or_default());
		}
		if let Some(from) = from {
			let sealed = self.sealed(v);
			let recognized = || {
				unfolded(revealed.clone(), opened)
					.iter()
					.any(|w| held(w) && obtainable(w, capabilities, &sealed))
			};
			if rebuildable(v, capabilities, &sealed) || recognized() {
				return from;
			}
		}
		revealed.retain(held);
		revealed
	}

	fn sealed(&self, v: &Value) -> Arc<AttackerState> {
		remembered(&self.sealed, v, || self.ex.knowledge.withholding(v).state)
	}

	fn independent(&self, w: &Value, of: &Value) -> bool {
		obtainable(w, self.capabilities(), &self.sealed(of))
	}

	fn check(&self, v: &Value) -> Option<Check> {
		let Value::Primitive(p) = v else {
			return None;
		};
		let (check, rule) = crate::primitive::check_undoing(p.id)?;
		let run = self.runnable(check, rule, p)?;
		let key = check
			.identifying_positions
			.first()
			.and_then(|&at| run.arguments.get(at))
			.cloned();
		let confirms = confirmed(rule, p)
			.filter(|arg| self.obtainable(arg))
			.cloned()
			.collect();
		Some(Check { run, key, confirms })
	}

	fn runnable(
		&self,
		check: &PrimitiveSpec,
		rule: &RewriteRule,
		p: &Primitive,
	) -> Option<Arc<Primitive>> {
		if !undoes(rule, p) {
			return None;
		}
		let &arity = check.arity.last()?;
		let mut arguments = vec![crate::term::value_nil(); arity as usize];
		let source = arguments.get_mut(rule.from)?;
		*source = Value::Primitive(Arc::new(p.clone()));
		let mut candidates = vec![(arguments, Vec::new())];
		for (position, targets) in &rule.matching {
			let inputs: Vec<_> = inputs_at(check, rule, *position, targets, p)
				.filter(|(_, input)| self.obtainable(input))
				.collect();
			candidates = candidates
				.iter()
				.flat_map(|(arguments, taken)| {
					inputs
						.iter()
						.filter(|(target, _)| !taken.contains(target))
						.filter_map(|(target, input)| {
							let mut arguments = arguments.clone();
							*arguments.get_mut(*position)? = input.clone();
							Some((arguments, [&taken[..], &[*target]].concat()))
						})
				})
				.collect();
		}
		candidates.into_iter().find_map(|(arguments, _)| {
			let run = Arc::new(Primitive::new(check.id, arguments, 0));
			crate::theory::can_rewrite(&run).0.then_some(run)
		})
	}

	fn observed(&self) -> &TermSet {
		self.observed.get_or_init(|| {
			let (cx, ex) = (self.cx, self.ex);
			let mut disclosed: Vec<(Value, Option<&Held>)> = cx
				.program
				.sends(&ex.sent)
				.map(|(_, delivery, slot, v)| (v.clone(), ex.runs[delivery.sender].held(slot)))
				.collect();
			for &Taken { run, step, .. } in &ex.order {
				if let Event::Leak(slot) = cx.program.runs[run].steps[step].event
					&& let Some(held) = ex.runs[run].held(slot)
				{
					disclosed.push((held.value.clone(), Some(held)));
				}
			}
			let opened = |value: &Value| opening(value, self.capabilities(), self.attacker());
			let (fed, own): (Vec<_>, Vec<_>) = disclosed
				.into_iter()
				.partition(|(_, held)| held.is_some_and(|held| !held.fed.is_empty()));
			let mut observed: TermSet = unfolded(own.into_iter().map(|(v, _)| v).collect(), opened)
				.into_iter()
				.collect();
			for (value, held) in fed {
				let supplied: TermSet = held
					.into_iter()
					.flat_map(|held| self.supplied_into(held))
					.cloned()
					.collect();
				let kept = |values: Vec<Value>| -> Vec<Value> {
					values
						.into_iter()
						.filter(|value| !supplied.contains(value))
						.collect()
				};
				observed.extend(unfolded(kept(vec![value]), |value| kept(opened(value))));
			}
			observed
		})
	}

	fn supplied_into(&self, held: &'a Held) -> impl Iterator<Item = &'a Value> {
		super::exec::installed_into(&self.ex.runs, held)
			.filter_map(|install| install.installed.as_deref())
			.flatten()
	}

	fn observable(&self, v: &Value, seen: &mut IdMap<usize, bool>) -> bool {
		if self.attacker().knows(v).is_none() {
			return false;
		}
		if self.observed().contains(v) || public(v, self.cx.km) {
			return true;
		}
		let (Value::Primitive(p), [_, ..]) = (v, fields(v)) else {
			return false;
		};
		let key = Arc::as_ptr(p) as usize;
		if let Some(&hit) = seen.get(&key) {
			return hit;
		}
		let out = fields(v).iter().all(|field| self.observable(field, seen));
		seen.insert(key, out);
		out
	}

	fn supplied(&self, holders: [(RunIdx, SlotIdx); 2]) -> Knowledge {
		let (cx, ex) = (self.cx, self.ex);
		let mut supplied = cx.initial.clone();
		supplied.set_phase(ex.knowledge.state.current_phase);
		for held in holders
			.into_iter()
			.filter_map(|(run, slot)| ex.runs[run].held(slot))
		{
			for component in self.supplied_into(held) {
				supplied.learn(component, Origin::Initial);
			}
		}
		supplied
	}
}

pub(crate) fn honest_reduct(km: &ProtocolTrace, slot: SlotIdx) -> Value {
	crate::theory::reduce_once(&crate::protocol::trace::resolve_trace_constant(
		&km.slots[slot].constant,
		km,
	))
}

pub(crate) fn depends_on_secret(v: &Value, km: &ProtocolTrace) -> bool {
	v.constant_leaves().any(|c| secret_constant(c, km))
}

fn secret_constant(c: &Constant, km: &ProtocolTrace) -> bool {
	c.fresh || c.qualifier == Some(Qualifier::Private) || declared_secret(c, km)
}

pub(crate) fn declared_secret(c: &Constant, km: &ProtocolTrace) -> bool {
	km.index_of(c).is_some_and(|i| {
		let declared = &km.slots[i].constant;
		declared.fresh || declared.qualifier == Some(Qualifier::Private)
	})
}

fn public(v: &Value, km: &ProtocolTrace) -> bool {
	matches!(v, Value::Constant(c) if km
		.index_of(c)
		.is_some_and(|i| km.slots[i].constant.qualifier == Some(Qualifier::Public)))
}

fn projected(v: &Value, memo: &mut IdMap<usize, Value>) -> Value {
	let Value::Primitive(p) = v else {
		return v.clone();
	};
	let key = Arc::as_ptr(p) as usize;
	if let Some(hit) = memo.get(&key) {
		return hit.clone();
	}
	let rebuilt = match p.map_arguments(|a| {
		let r = projected(a, memo);
		(!r.same_term(a)).then_some(r)
	}) {
		Some(mapped) => Arc::new(mapped),
		None => p.clone(),
	};
	let out = match crate::primitive::is_projection(p.id) {
		true => match crate::theory::can_rewrite(&rebuilt) {
			(true, value) => value,
			(false, _) => Value::Primitive(rebuilt),
		},
		false => Value::Primitive(rebuilt),
	};
	memo.insert(key, out.clone());
	out
}

fn shared_secret_leaves(km: &ProtocolTrace, a: SlotIdx, b: SlotIdx) -> IdSet<ValueId> {
	let mut memo = IdMap::default();
	let mut of = |slot: SlotIdx| {
		crate::term::subterms(&projected(
			&crate::protocol::trace::resolve_trace_constant(&km.slots[slot].constant, km),
			&mut memo,
		))
		.cloned()
		.collect::<Vec<Value>>()
	};
	let (of_a, of_b) = (of(a), of(b));
	of_b.iter()
		.filter(|t| {
			depends_on_secret(t, km)
				&& of_a
					.iter()
					.any(|s| s.hash_value() == t.hash_value() && s.equivalent(t, true))
		})
		.flat_map(Value::constant_leaves)
		.filter(|c| secret_constant(c, km))
		.map(|c| c.id)
		.collect()
}

fn push_leaf(out: &mut Vec<Value>, v: &Value) {
	if !out.iter().any(|k| k.equivalent(v, true)) {
		out.push(v.clone());
	}
}

fn unfolded(from: Vec<Value>, step: impl Fn(&Value) -> Vec<Value>) -> Vec<Value> {
	let mut out = Vec::new();
	let mut pending = from;
	let mut seen = TermSet::default();
	while let Some(value) = pending.pop() {
		if seen.insert(value.clone()) {
			pending.extend(step(&value));
			out.push(value);
		}
	}
	out
}

fn fields(v: &Value) -> &[Value] {
	match v {
		Value::Primitive(p) if crate::primitive::core_reveals_arguments(p.id) => &p.arguments,
		_ => &[],
	}
}

fn opening(value: &Value, capabilities: &CapabilityIndex, attacker: &AttackerState) -> Vec<Value> {
	let mut out = fields(value).to_vec();
	let Value::Primitive(p) = value else {
		return out;
	};
	if let Some(opened) = crate::theory::can_decompose(p, capabilities, attacker) {
		out.extend(opened.revealed);
	}
	if let Some(revealed) = can_break_weak(p, capabilities, attacker) {
		out.extend(revealed);
	}
	if attacker.reused.iter().any(|pair| {
		pair.iter().any(|member| member.equivalent(value, true))
			&& pair.iter().all(|member| attacker.knows(member).is_some())
	}) {
		out.extend(
			crate::theory::opened(p, capabilities, attacker)
				.iter()
				.map(crate::theory::reduce_once),
		);
	}
	out
}

fn rebuilt_from(
	p: &Arc<Primitive>,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<Vec<Value>> {
	can_reconstruct_primitive(p, capabilities, attacker).map(|built| built.supplied().to_vec())
}

fn rebuildable(v: &Value, capabilities: &CapabilityIndex, attacker: &AttackerState) -> bool {
	matches!(v, Value::Primitive(p) if rebuilt_from(p, capabilities, attacker).is_some())
}

fn ingredients(
	v: &Value,
	capabilities: &CapabilityIndex,
	attacker: &AttackerState,
) -> Option<Vec<Value>> {
	let Value::Primitive(p) = v else {
		return None;
	};
	let mut pending = rebuilt_from(p, capabilities, attacker)?;
	pending.reverse();
	let mut expanded = TermSet::from_iter([v.clone()]);
	let mut held = Vec::new();
	while let Some(used) = pending.pop() {
		if attacker.knows(&used).is_some() {
			push_leaf(&mut held, &used);
		} else if let Value::Primitive(q) = &used
			&& expanded.insert(used.clone())
			&& let Some(inner) = rebuilt_from(q, capabilities, attacker)
		{
			pending.extend(inner.into_iter().rev());
		}
	}
	Some(held)
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

fn undoes(rule: &RewriteRule, p: &Primitive) -> bool {
	rule.id == p.id && rule.from_output.is_none_or(|output| output == p.output)
}

fn inputs_at(
	check: &PrimitiveSpec,
	rule: &RewriteRule,
	position: usize,
	targets: &[usize],
	p: &Primitive,
) -> impl Iterator<Item = (usize, Value)> {
	targets.iter().filter_map(move |&target| {
		let input = check_input(check, rule, position, target, p.arguments.get(target)?)?;
		Some((target, input))
	})
}

fn confirmed<'p>(rule: &RewriteRule, p: &'p Primitive) -> impl Iterator<Item = &'p Value> {
	rule.matching
		.iter()
		.filter_map(|(_, targets)| match targets[..] {
			[target] => p.arguments.get(target),
			_ => None,
		})
}

pub(crate) fn check_confirms(p: &Primitive) -> Vec<Value> {
	match crate::primitive::check_undoing(p.id) {
		Some((_, rule)) if undoes(rule, p) => confirmed(rule, p).cloned().collect(),
		_ => Vec::new(),
	}
}

pub(crate) fn check_inputs(p: &Primitive) -> Vec<Value> {
	let Some((check, rule)) = crate::primitive::check_undoing(p.id) else {
		return Vec::new();
	};
	if !undoes(rule, p) {
		return Vec::new();
	}
	let mut out: Vec<Value> = Vec::new();
	for (position, targets) in &rule.matching {
		for (_, input) in inputs_at(check, rule, *position, targets, p) {
			push_leaf(&mut out, &input);
		}
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::engine::exec::{Install, Installs, execute};
	use crate::engine::program::Program;
	use crate::primitive::PRIM_HASH;

	#[test]
	fn supplied_components_use_the_knowledge_at_the_receive() {
		let _generation = crate::util::generation::GenerationGuard::enter();
		let model = crate::syntax::parser::parse_string(
			"supplied.vp",
			include_str!("../../examples/test/unlink_supplied_wrapper_late_key.vp"),
		)
		.expect("parses");
		let km = crate::protocol::sanity::sanity(&model).expect("sane");
		let program = Program::of(&model, &km);
		let cx = Context::new(&program, &km);
		let bob = program.runs.position(|r| r.name == "Bob").unwrap();
		let slot = |name: &str| {
			km.slots
				.position(|s| s.constant.name.as_ref() == name)
				.unwrap()
		};
		let honest = execute(&cx, &vec![]).expect("uncancelled");
		let y = honest.runs[bob].held(slot("y")).unwrap().value.clone();
		let s = crate::testing::trace_constant(&km, "s");
		let wrap = |v: Value| Value::primitive(PRIM_HASH, vec![v, crate::term::value_nil()], 0);
		let inner = wrap(y.clone());
		for value in [y.clone(), wrap(inner.clone())] {
			let ex = execute(
				&cx,
				&vec![Install::Value {
					run: bob,
					slot: slot("x"),
					value: value.clone(),
				}],
			)
			.expect("uncancelled");
			assert!(ex.runs[bob].held(slot("x")).unwrap().installed.is_some());
			assert!(ex.knowledge.state.knows(&s).is_some());
			let supplied = Linker::new(&cx, &ex).supplied([(bob, slot("a")), (bob, slot("b"))]);
			let supplied = |v: &Value| supplied.knows(v).is_some();
			assert!(supplied(&value));
			assert!(supplied(&y));
			assert!(!supplied(&s));
			assert_eq!(supplied(&inner), !value.equivalent(&y, true));
			let known = ex
				.order
				.iter()
				.find(|taken| {
					taken.run == bob
						&& matches!(
							program.runs[taken.run].steps[taken.step].event,
							Event::Recv(_)
						)
				})
				.unwrap()
				.known;
			assert!(
				ex.knowledge.state.known[..known]
					.iter()
					.all(|v| !v.equivalent(&s, true) && !v.equivalent(&inner, true))
			);
		}
	}

	fn linked(src: &str, forced: bool) -> bool {
		let _generation = crate::util::generation::GenerationGuard::enter();
		let m = crate::syntax::parser::parse_string("forced.vp", src).expect("parses");
		let km = crate::protocol::sanity::sanity(&m).expect("sane");
		let program = Program::of(&m, &km);
		let cx = Context::new(&program, &km);
		let bob = program.runs.position(|r| r.name == "Bob").unwrap();
		let slot = |name: &str| {
			km.slots
				.position(|s| s.constant.name.as_ref() == name)
				.unwrap()
		};
		let gb = execute(&cx, &vec![]).expect("uncancelled").runs[bob]
			.held(slot("gb"))
			.unwrap()
			.value
			.clone();
		let installs: Installs = forced
			.then(|| Install::Value {
				run: bob,
				slot: slot("c"),
				value: Value::primitive(crate::primitive::PRIM_PKE_ENC, vec![gb.clone(), gb], 0),
			})
			.into_iter()
			.collect();
		let ex = execute(&cx, &installs).expect("uncancelled");
		assert!(ex.stuck.is_empty());
		let claims = |_| Some(0);
		crate::engine::judgment::Judge::at(&cx, &ex, 0, &claims)
			.evaluate(&m.queries[0])
			.is_some()
	}

	#[test]
	fn a_key_the_attacker_builds_from_what_it_supplied_links_nothing() {
		let source = include_str!("../../examples/test/unlink_forced_key_carries_no_secret.vp");
		assert!(!linked(source, true));
		assert!(linked(
			&source.replace("k = HASH(seed_b)", "k = HASH(gb)"),
			false
		));
	}

	fn observed_in(src: &str, install: Option<(&str, &str)>, phase: i32, target: &str) -> bool {
		let _generation = crate::util::generation::GenerationGuard::enter();
		let m = crate::syntax::parser::parse_string("ul.vp", src).expect("parses");
		let km = crate::protocol::sanity::sanity(&m).expect("sane");
		let program = Program::of(&m, &km);
		let cx = Context::new(&program, &km);
		let slot = |name: &str| {
			km.slots
				.position(|s| s.constant.name.as_ref() == name)
				.expect("declared")
		};
		let installs: Installs = install
			.map(|(principal, name)| {
				let run = program.runs.position(|r| r.name == principal).expect("run");
				Install::Value {
					run,
					slot: slot(name),
					value: crate::term::value_nil(),
				}
			})
			.into_iter()
			.collect();
		let ex = execute(&cx, &installs).expect("uncancelled");
		let ex = ex.at(phase);
		let value = crate::theory::reduce_once(&crate::protocol::trace::resolve_trace_constant(
			&km.slots[slot(target)].constant,
			&km,
		));
		Linker::new(&cx, ex).observable(&value, &mut IdMap::default())
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

	#[test]
	fn a_cycle_of_made_steps_is_walked_once() {
		let _generation = crate::util::generation::GenerationGuard::enter();
		let model = crate::syntax::parser::parse_string(
			"cycle.vp",
			include_str!("../../examples/test/unlink_shamir_origin.vp"),
		)
		.expect("parses");
		let km = crate::protocol::sanity::sanity(&model).expect("sane");
		let program = Program::of(&model, &km);
		let cx = Context::new(&program, &km);
		let ex = execute(&cx, &vec![]).expect("uncancelled");
		let alice = program.runs.position(|r| r.name == "Alice").unwrap();
		let held = |name: &str| {
			let slot = km
				.slots
				.position(|s| s.constant.name.as_ref() == name)
				.unwrap();
			ex.runs[alice].held(slot).unwrap().value.clone()
		};
		let linker = Linker::new(&cx, &ex);
		let ties = linker.ties(&held("tok_a"), &|_| false);
		let reaches = |name: &str| {
			ties.iter()
				.any(|tie| tie.term.equivalent(&held(name), true))
		};
		assert_eq!(ties.len(), 3);
		assert!(reaches("secret_shared") && reaches("tok_b") && reaches("tok_a"));
		assert_eq!(linker.ties(&held("solo_a"), &|_| false).len(), 1);
		assert!(linker.ties(&held("tok_a"), &|_| true).is_empty());
	}
}
