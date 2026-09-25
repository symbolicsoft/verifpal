/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::borrow::Cow;
use std::cmp::Reverse;
use std::sync::Arc;

use crate::sanity::MAX_PRINCIPALS;
use crate::sessions::{ModelCopy, map_constants};
use crate::types::*;
use crate::util::{base_name, did_you_mean, quoted_list};
use crate::value::MAX_COPIES;
use crate::verify::Expansion;

pub(crate) fn expand_scenarios(m: &Model, sessions: u8) -> VResult<Expansion> {
	let count = m.scenarios.len();
	if count == 0 {
		return Ok(Expansion {
			model: m.clone(),
			corrupt_from: None,
			scenarios: Vec::new(),
			variants: Vec::new(),
			siblings: IdMap::default(),
			interchangeable: IdMap::default(),
			actors: IdMap::default(),
			bound: IdSet::default(),
		});
	}
	sanity_scenarios(m)?;
	let analyzed = count as u32 * sessions as u32;
	if analyzed > MAX_COPIES + 1 {
		return Err(VerifpalError::sanity(
			format!(
				"{count} scenarios at {sessions} sessions would analyze {analyzed} copies \
				 of every principal, which exceeds the {} the id space holds",
				MAX_COPIES + 1
			)
			.into(),
		)
		.note("scenarios and sessions multiply: each scenario runs every session")
		.help(format!(
			"declare fewer scenarios, or analyze with `--sessions {}` or fewer",
			((MAX_COPIES + 1) / count as u32).max(1)
		)));
	}
	let principals = m.declared_principals();
	let expanded = principals.len() * count;
	if expanded > MAX_PRINCIPALS {
		return Err(VerifpalError::sanity(
			format!(
				"model declares {} principals; {count} scenarios would analyze {expanded}, \
				 which exceeds the {MAX_PRINCIPALS}-principal cap",
				principals.len()
			)
			.into(),
		));
	}

	let corruption = Corruption::of(m);
	let mut scenarios: Vec<(&Scenario, i32)> = m
		.scenarios
		.iter()
		.map(|s| (s, corruption.corrupt_from(s)))
		.collect();
	scenarios.sort_by_key(|&(_, corrupt_from)| Reverse(corrupt_from));
	let freshen = m.freshened_constants();
	let copies: Vec<ModelCopy> = std::iter::once(ModelCopy::original(&freshen))
		.chain(ModelCopy::numbered(
			m,
			&freshen,
			(1..count).map(|k| (format!("@{}", k + 1), k as u32 * sessions as u32)),
			"scenario",
		)?)
		.collect();

	let mut blocks: Vec<Block> = Vec::with_capacity(m.blocks.len() * count);
	for block in &m.blocks {
		match block {
			Block::Principal(p) => {
				blocks.extend(copies.iter().zip(&scenarios).map(|(copy, (scenario, _))| {
					Block::Principal(copy.principal(&bound(p, scenario)))
				}));
			}
			Block::Message(msg) => {
				blocks.extend(copies.iter().map(|copy| Block::Message(copy.message(msg))));
			}
			Block::Phase(_) => blocks.push(block.clone()),
		}
	}

	let mut corrupt_from: IdMap<PrincipalId, i32> = IdMap::default();
	for (copy, &(_, from)) in copies.iter().zip(&scenarios) {
		if from > 0 {
			for &(id, _) in &principals {
				corrupt_from.insert(copy.principal_id(id), from);
			}
		}
	}

	let any_honest = scenarios[0].1 > 0;
	let query_variants: Vec<Vec<Query>> = m
		.queries
		.iter()
		.map(|query| {
			copies
				.iter()
				.zip(&scenarios)
				.skip(1)
				.filter(|&(_, &(_, corrupt_from))| !any_honest || corrupt_from > 0)
				.map(|(copy, _)| copy.query(query))
				.filter(|variant| !query.same_shape(variant))
				.collect()
		})
		.collect();

	let summaries: Vec<ScenarioSummary> = scenarios
		.iter()
		.map(|&(s, corrupt_from)| ScenarioSummary {
			principal: Arc::clone(&s.principal_name),
			bindings: s
				.bindings
				.iter()
				.map(|(t, v)| (Arc::clone(&t.name), Arc::clone(&v.name)))
				.collect(),
			corrupt_from: Some(corrupt_from).filter(|&phase| phase != i32::MAX),
		})
		.collect();

	let corrupt = summaries
		.iter()
		.filter(|s| s.corrupt_from.is_some())
		.count();
	crate::info::info_message(
		&format!(
			"Analyzing {count} peer scenarios per principal, {corrupt} of them with a \
			 corrupt peer; per-scenario values and principals are suffixed @2 onward.",
		),
		InfoLevel::Info,
	);

	Ok(Expansion {
		model: Model {
			blocks,
			scenarios: Vec::new(),
			..m.clone()
		},
		corrupt_from: Some(corrupt_from),
		scenarios: summaries,
		variants: query_variants,
		siblings: IdMap::default(),
		interchangeable: interchangeable_clones(&principals, &scenarios, &copies),
		actors: principals
			.iter()
			.flat_map(|&(id, _)| copies.iter().map(move |copy| (copy.principal_id(id), id)))
			.collect(),
		bound: scenarios
			.iter()
			.flat_map(|(s, _)| rebindings(s))
			.map(|(_, value)| value.id)
			.collect(),
	})
}

fn rebindings(scenario: &Scenario) -> impl Iterator<Item = &(Constant, Constant)> {
	scenario
		.bindings
		.iter()
		.filter(|(target, value)| target.id != value.id)
}

fn bound<'p>(p: &'p Principal, scenario: &Scenario) -> Cow<'p, Principal> {
	if scenario.principal != p.id {
		return Cow::Borrowed(p);
	}
	let bind = |c: &Constant| match scenario
		.bindings
		.iter()
		.find(|(target, _)| target.id == c.id)
	{
		Some((_, value)) => Constant {
			guard: c.guard,
			..value.clone()
		},
		None => c.clone(),
	};
	let mut out = p.clone();
	out.expressions.retain_mut(|expr| {
		let declared = !expr.constants.is_empty();
		if expr.kind == Declaration::Knows {
			expr.constants
				.retain(|c| !rebindings(scenario).any(|(target, _)| target.id == c.id));
		}
		if declared && expr.constants.is_empty() {
			return false;
		}
		for c in &mut expr.constants {
			*c = bind(c);
		}
		if let Some(value) = &mut expr.assigned {
			*value = map_constants(value, &bind);
		}
		true
	});
	Cow::Owned(out)
}

fn peer_binding_key(scenario: &Scenario, principal: PrincipalId) -> Vec<(ValueId, ValueId)> {
	if scenario.principal != principal {
		return Vec::new();
	}
	let mut out: Vec<(ValueId, ValueId)> = rebindings(scenario)
		.map(|(target, value)| (target.id, value.id))
		.collect();
	out.sort_unstable();
	out
}

fn interchangeable_clones(
	principals: &[(PrincipalId, String)],
	scenarios: &[(&Scenario, i32)],
	copies: &[ModelCopy],
) -> IdMap<PrincipalId, PrincipalId> {
	let mut out = IdMap::default();
	for &(id, _) in principals {
		let keys: Vec<Vec<(ValueId, ValueId)>> = scenarios
			.iter()
			.map(|(s, _)| peer_binding_key(s, id))
			.collect();
		for (k, key) in keys.iter().enumerate() {
			let canonical = keys.iter().position(|other| other == key).unwrap_or(k);
			out.insert(
				copies[k].principal_id(id),
				copies[canonical].principal_id(id),
			);
		}
	}
	out
}

#[cfg(test)]
pub(crate) fn honesty_profile(m: &Model) -> std::collections::BTreeMap<String, i32> {
	let corruption = Corruption::of(m);
	m.scenarios
		.iter()
		.map(|s| {
			let bindings: Vec<String> = s
				.bindings
				.iter()
				.map(|(target, value)| format!("{} = {}", target.name, value.name))
				.collect();
			(
				format!("{}[{}]", s.principal_name, bindings.join(", ")),
				corruption.corrupt_from(s),
			)
		})
		.collect()
}

struct Corruption {
	compromised: IdMap<ValueId, i32>,
	mentions: IdMap<ValueId, Vec<ValueId>>,
	keyed: IdSet<ValueId>,
}

impl Corruption {
	fn of(m: &Model) -> Corruption {
		Corruption {
			compromised: compromised_constants(m),
			mentions: assignment_mentions(m),
			keyed: key_material_constants(m),
		}
	}

	fn corrupt_from(&self, scenario: &Scenario) -> i32 {
		rebindings(scenario)
			.flat_map(|(target, value)| {
				let keyed = |id: &ValueId| self.keyed.contains(id);
				let value_keyed = keyed(&target.id) || keyed(&value.id);
				value_keyed.then_some(value.id).into_iter().chain(
					self.mentions
						.get(&value.id)
						.into_iter()
						.flatten()
						.copied()
						.filter(keyed),
				)
			})
			.filter_map(|id| self.compromised.get(&id).copied())
			.min()
			.unwrap_or(i32::MAX)
	}
}

fn expressions(m: &Model) -> impl Iterator<Item = &Expression> {
	m.blocks
		.iter()
		.filter_map(|block| match block {
			Block::Principal(p) => Some(&p.expressions),
			_ => None,
		})
		.flatten()
}

fn declared_ids(expr: &Expression) -> impl Iterator<Item = ValueId> + '_ {
	expr.constants.iter().map(|c| c.id)
}

fn assignment_mentions(m: &Model) -> IdMap<ValueId, Vec<ValueId>> {
	let mut out: IdMap<ValueId, Vec<ValueId>> = IdMap::default();
	for expression in expressions(m) {
		let Some(value) = &expression.assigned else {
			continue;
		};
		let ids: Vec<ValueId> = value.constant_leaves().map(|c| c.id).collect();
		for id in declared_ids(expression) {
			out.entry(id).or_insert_with(|| ids.clone());
		}
	}
	out
}

fn sanity_scenarios(m: &Model) -> VResult<()> {
	let principals = m.declared_principals();
	let declared = declared_constants(m);
	for scenario in &m.scenarios {
		let Some(&(id, _)) = principals
			.iter()
			.find(|(_, name)| name.as_str() == &*scenario.principal_name)
		else {
			let names: Vec<String> = principals.iter().map(|(_, n)| n.clone()).collect();
			let mut e = VerifpalError::sanity(
				format!(
					"scenario names principal `{}`, which the model does not declare",
					scenario.principal_name
				)
				.into(),
			)
			.note(
				"a scenario binds constants inside a principal that exists, so a name no \
				 principal carries would substitute nothing and silently analyze the model \
				 as written",
			);
			match did_you_mean(&scenario.principal_name, names.iter().map(|n| n.as_str())) {
				Some(suggestion) => e = e.help(format!("did you mean `{suggestion}`?")),
				None => e = e.help(format!("declared principals: {}", quoted_list(&names))),
			}
			return Err(e.or_span(scenario.span));
		};
		let known = known_constants(m, id);
		let mut bound: Vec<ValueId> = Vec::new();
		for (target, value) in &scenario.bindings {
			if !known.contains(&target.id) {
				let names: Vec<String> = declared
					.iter()
					.filter(|(cid, _)| known.contains(cid))
					.map(|(_, name)| name.clone())
					.collect();
				let mut e = VerifpalError::sanity(
					format!(
						"scenario binds `{}`, which {} does not declare with `knows`",
						target.name, scenario.principal_name
					)
					.into(),
				)
				.note(
					"a scenario replaces a constant the principal is given, so the target \
					 must be one that principal `knows`",
				);
				match did_you_mean(&target.name, names.iter().map(|n| n.as_str())) {
					Some(suggestion) => e = e.help(format!("did you mean `{suggestion}`?")),
					None if !names.is_empty() => {
						e = e.help(format!(
							"{} knows {}",
							scenario.principal_name,
							quoted_list(&names)
						));
					}
					None => {}
				}
				return Err(e.or_span(scenario.span));
			}
			if !declared.iter().any(|(cid, _)| *cid == value.id) {
				let names: Vec<String> = declared.iter().map(|(_, name)| name.clone()).collect();
				let mut e = VerifpalError::sanity(
					format!(
						"scenario binds `{}` to `{}`, which no principal declares",
						target.name, value.name
					)
					.into(),
				)
				.note(
					"a scenario substitutes one of the model's own constants, so the value \
					 must be introduced by `knows`, `generates`, or an assignment",
				);
				if let Some(suggestion) =
					did_you_mean(&value.name, names.iter().map(|n| n.as_str()))
				{
					e = e.help(format!("did you mean `{suggestion}`?"));
				}
				return Err(e.or_span(scenario.span));
			}
			if let Some(sender) = message_carrying(m, target.id) {
				return Err(VerifpalError::sanity(
					format!(
						"scenario binds `{}`, which {} sends over the wire",
						target.name,
						base_name(&sender)
					)
					.into(),
				)
				.note(
					"a scenario replaces a constant inside one principal, so a recipient \
					 would go on naming the constant the sender no longer has",
				)
				.help(format!(
					"bind a constant `{}` keeps to itself, or send the peer's value \
					 under a name the recipient also uses",
					scenario.principal_name
				))
				.or_span(scenario.span));
			}
			if bound.contains(&target.id) {
				return Err(VerifpalError::sanity(
					format!(
						"scenario binds `{}` twice; a constant takes one value per scenario",
						target.name
					)
					.into(),
				)
				.or_span(scenario.span));
			}
			bound.push(target.id);
		}
	}
	Ok(())
}

fn message_carrying(m: &Model, target: ValueId) -> Option<String> {
	m.blocks.iter().find_map(|block| {
		let Block::Message(msg) = block else {
			return None;
		};
		msg.constants
			.iter()
			.any(|c| c.id == target)
			.then(|| msg.sender_name.to_string())
	})
}

fn known_constants(m: &Model, principal: PrincipalId) -> IdSet<ValueId> {
	m.blocks
		.iter()
		.filter_map(|block| match block {
			Block::Principal(p) if p.id == principal => Some(&p.expressions),
			_ => None,
		})
		.flatten()
		.filter(|expr| expr.kind == Declaration::Knows)
		.flat_map(declared_ids)
		.collect()
}

fn declared_constants(m: &Model) -> Vec<(ValueId, String)> {
	let mut out: Vec<(ValueId, String)> = Vec::new();
	for expr in expressions(m) {
		if !matches!(
			expr.kind,
			Declaration::Knows | Declaration::Generates | Declaration::Assignment
		) {
			continue;
		}
		for c in &expr.constants {
			if !out.iter().any(|(id, _)| *id == c.id) {
				out.push((c.id, c.name.to_string()));
			}
		}
	}
	out
}

fn secret_declarations(m: &Model) -> IdSet<ValueId> {
	let mut out: IdSet<ValueId> = IdSet::default();
	for expr in expressions(m) {
		if expr.declares_secret() {
			out.extend(declared_ids(expr));
		}
		for term in expr.assigned.iter().flat_map(crate::value::subterms) {
			if let Value::Primitive(inner) = term
				&& crate::primitive::primitive_is_key_derivation(inner.id)
				&& let Some(Value::Constant(c)) = inner.arguments.first()
			{
				out.insert(c.id);
			}
		}
	}
	out
}

fn key_material_constants(m: &Model) -> IdSet<ValueId> {
	let mut out: IdSet<ValueId> = IdSet::default();
	for expr in expressions(m) {
		if expr.kind == Declaration::Knows && expr.qualifier == Some(Qualifier::Private) {
			out.extend(declared_ids(expr));
		}
		for term in expr.assigned.iter().flat_map(crate::value::subterms) {
			let Value::Primitive(inner) = term else {
				continue;
			};
			for at in crate::primitive::secret_positions(inner.id) {
				match inner.arguments.get(at) {
					Some(Value::Constant(c)) => {
						out.insert(c.id);
					}
					Some(Value::Primitive(_)) => out.extend(declared_ids(expr)),
					None => {}
				}
			}
		}
	}
	loop {
		let before = out.len();
		for expr in expressions(m) {
			if let Some(Value::Primitive(inner)) = &expr.assigned
				&& crate::primitive::primitive_is_key_derivation(inner.id)
				&& let Some(Value::Constant(c)) = inner.arguments.first()
				&& out.contains(&c.id)
			{
				out.extend(declared_ids(expr));
			}
		}
		if out.len() == before {
			return out;
		}
	}
}

fn compromised_constants(m: &Model) -> IdMap<ValueId, i32> {
	let secret = secret_declarations(m);
	let mut disclosures: Vec<(ValueId, i32)> = Vec::new();
	let mut phase = 0i32;
	for block in &m.blocks {
		match block {
			Block::Phase(p) => phase = p.number,
			Block::Principal(p) => {
				for expression in &p.expressions {
					if expression.kind == Declaration::Leaks {
						disclosures.extend(declared_ids(expression).map(|id| (id, phase)));
					}
				}
			}
			Block::Message(message) => {
				disclosures.extend(message.constants.iter().map(|c| (c.id, phase)));
			}
		}
	}
	let mut attacker = Disclosure {
		assignments: expressions(m)
			.filter_map(|expression| expression.assigned.as_ref().map(|v| (expression, v)))
			.flat_map(|(expression, value)| declared_ids(expression).map(move |id| (id, value)))
			.collect(),
		public: expressions(m)
			.filter(|expr| {
				expr.kind == Declaration::Knows && expr.qualifier == Some(Qualifier::Public)
			})
			.flat_map(declared_ids)
			.collect(),
		compromised: IdMap::default(),
	};
	loop {
		let mut changed = false;
		for &(id, phase) in &disclosures {
			for (exposed, at) in attacker.exposed(id, phase) {
				if secret.contains(&exposed)
					&& attacker
						.compromised
						.get(&exposed)
						.is_none_or(|&known| at < known)
				{
					attacker.compromised.insert(exposed, at);
					changed = true;
				}
			}
		}
		for expression in expressions(m) {
			let Some(value) = &expression.assigned else {
				continue;
			};
			let Some(from) = attacker.computable(value) else {
				continue;
			};
			for id in declared_ids(expression) {
				if attacker.compromised.get(&id).is_none_or(|&at| at > from) {
					attacker.compromised.insert(id, from);
					changed = true;
				}
			}
		}
		if !changed {
			return attacker.compromised;
		}
	}
}

struct Disclosure<'m> {
	assignments: IdMap<ValueId, &'m Value>,
	public: IdSet<ValueId>,
	compromised: IdMap<ValueId, i32>,
}

impl<'m> Disclosure<'m> {
	fn exposed(&self, id: ValueId, phase: i32) -> IdMap<ValueId, i32> {
		let mut seen: IdMap<ValueId, i32> = IdMap::from_iter([(id, phase)]);
		let mut primitives = IdSet::default();
		let mut pending: Vec<(&'m Value, i32)> = self
			.assignments
			.get(&id)
			.map(|v| (*v, phase))
			.into_iter()
			.collect();
		while let Some((value, at)) = pending.pop() {
			match value {
				Value::Constant(c) => {
					if seen.get(&c.id).is_none_or(|&known| at < known) {
						seen.insert(c.id, at);
						pending.extend(self.assignments.get(&c.id).map(|v| (*v, at)));
					}
				}
				Value::Primitive(p) if primitives.insert(Arc::as_ptr(p) as usize) => {
					if crate::primitive::primitive_core_reveals_args(p.id) {
						pending.extend(p.arguments.iter().map(|a| (a, at)));
					} else if let Some((opened, reveals)) = self.opened(p) {
						pending.extend(reveals.into_iter().map(|a| (a, at.max(opened))));
					}
				}
				_ => {}
			}
		}
		seen
	}

	fn opened<'a>(&self, p: &'a Primitive) -> Option<(i32, Vec<&'a Value>)> {
		let rule = crate::primitive::primitive_get(p.id)
			.ok()?
			.decompose
			.as_ref()?;
		if rule.output.is_some_and(|output| output != p.output) {
			return None;
		}
		let mut at = 0;
		for &idx in &rule.given {
			let mut argument = p.arguments.get(idx)?;
			let mut hops = 0;
			while let Value::Constant(c) = argument
				&& let Some(assigned) = self.assignments.get(&c.id)
				&& hops < self.assignments.len()
			{
				argument = assigned;
				hops += 1;
			}
			let (key, valid) = (rule.filter)(p, argument, idx);
			if !valid {
				return None;
			}
			at = at.max(self.computable(&key)?);
		}
		let reveals = rule
			.reveals
			.iter()
			.filter_map(|reveal| match *reveal {
				crate::primitive::Reveal::Argument(i) => p.arguments.get(i),
				crate::primitive::Reveal::Output(_) => None,
			})
			.collect();
		Some((at, reveals))
	}

	fn computable(&self, v: &Value) -> Option<i32> {
		let mut at = 0;
		for c in v.constant_leaves() {
			if c.is_nil() || self.public.contains(&c.id) {
				continue;
			}
			at = at.max(self.compromised.get(&c.id).copied()?);
		}
		Some(at)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::parser::parse_string;

	fn starts_honest(s: &ScenarioSummary) -> bool {
		s.corrupt_from.is_none_or(|phase| phase > 0)
	}

	const SRC: &str = "attacker[active]\n\
		principal Alice[\n\
		knows private scx_a\n\
		knows public scx_gpeer\n\
		generates scx_ni\n\
		scx_m1 = PKE_ENC(scx_gpeer, scx_ni)\n\
		]\n\
		principal Bob[\n\
		knows private scx_b\n\
		scx_gb = PUBKEY(scx_b)\n\
		]\n\
		principal Mallory[\n\
		knows private scx_mk\n\
		scx_gm = PUBKEY(scx_mk)\n\
		leaks scx_mk\n\
		]\n\
		Alice -> Bob: scx_m1\n\
		scenarios[\n\
		Alice[scx_gpeer = scx_gb]\n\
		Alice[scx_gpeer = scx_gm]\n\
		]\n\
		queries[\n\
		confidentiality? scx_ni\n\
		]\n";

	#[test]
	fn a_two_scenario_model_clones_every_principal_once_per_scenario() {
		let m = parse_string("scx.vp", SRC).expect("parses");
		let e = expand_scenarios(&m, 1).expect("expands");
		let principals = e
			.model
			.blocks
			.iter()
			.filter(|b| matches!(b, Block::Principal(_)))
			.count();
		assert_eq!(principals, 6);
	}

	#[test]
	fn a_scenario_bound_to_a_leaked_peer_is_not_honest() {
		let m = parse_string("scx.vp", SRC).expect("parses");
		let e = expand_scenarios(&m, 1).expect("expands");
		assert_eq!(e.corrupt_from.map(|c| c.len()), Some(3));
	}

	#[test]
	fn a_scenario_naming_a_principal_the_model_does_not_declare_is_an_error() {
		let src = SRC.replace("Alice[scx_gpeer = scx_gm]", "Carol[scx_gpeer = scx_gm]");
		let m = parse_string("scx.vp", &src).expect("parses");
		let Err(e) = expand_scenarios(&m, 1) else {
			panic!("must be rejected");
		};
		assert!(e.message.contains("does not declare"), "{}", e.message);
	}

	#[test]
	fn a_scenario_binding_a_constant_the_principal_does_not_know_is_an_error() {
		let src = SRC.replace("Alice[scx_gpeer = scx_gb]", "Alice[scx_ni = scx_gb]");
		let m = parse_string("scx.vp", &src).expect("parses");
		let Err(e) = expand_scenarios(&m, 1) else {
			panic!("must be rejected");
		};
		assert!(e.message.contains("`knows`"), "{}", e.message);
	}

	#[test]
	fn a_scenario_binding_to_a_constant_no_principal_declares_is_an_error() {
		let src = SRC.replace("Alice[scx_gpeer = scx_gb]", "Alice[scx_gpeer = scx_absent]");
		let m = parse_string("scx.vp", &src).expect("parses");
		let Err(e) = expand_scenarios(&m, 1) else {
			panic!("must be rejected");
		};
		assert!(e.message.contains("no principal declares"), "{}", e.message);
	}

	#[test]
	fn a_scenario_set_with_no_honest_member_is_still_analysable() {
		let src = SRC.replace("Alice[scx_gpeer = scx_gb]\n", "");
		let m = parse_string("scx.vp", &src).expect("parses");
		let e = expand_scenarios(&m, 1).expect("expands");
		assert!(e.corrupt_from.as_ref().is_some_and(|c| c.is_empty()));
		assert_eq!(e.scenarios.len(), 1);
		assert!(!starts_honest(&e.scenarios[0]));
	}

	#[test]
	fn a_scenario_binding_a_constant_to_itself_keeps_its_declaration() {
		let src = SRC.replace("Alice[scx_gpeer = scx_gb]", "Alice[scx_gpeer = scx_gpeer]");
		let m = parse_string("scx.vp", &src).expect("parses");
		let e = expand_scenarios(&m, 1).expect("expands");
		let kept = e.model.blocks.iter().any(|b| match b {
			Block::Principal(p) => p.expressions.iter().any(|expr| {
				expr.kind == Declaration::Knows
					&& expr.constants.iter().any(|c| &*c.name == "scx_gpeer")
			}),
			_ => false,
		});
		assert!(kept, "an identity binding must not drop the declaration");
	}

	#[test]
	fn a_scenario_binding_a_constant_that_travels_is_an_error() {
		let src = SRC.replace(
			"Alice -> Bob: scx_m1\n",
			"Alice -> Bob: scx_m1\nAlice -> Bob: scx_gpeer\n",
		);
		let m = parse_string("scx.vp", &src).expect("parses");
		let Err(e) = expand_scenarios(&m, 1) else {
			panic!("must be rejected");
		};
		assert!(e.message.contains("over the wire"), "{}", e.message);
	}

	#[test]
	fn a_knows_line_keeps_the_constants_the_scenario_does_not_bind() {
		let src = SRC.replace(
			"knows public scx_gpeer\n",
			"knows public scx_gpeer, scx_tag\n",
		);
		let m = parse_string("scx.vp", &src).expect("parses");
		let e = expand_scenarios(&m, 1).expect("expands");
		let mut kept = 0;
		let mut dropped = 0;
		for block in &e.model.blocks {
			let Block::Principal(p) = block else {
				continue;
			};
			for expr in &p.expressions {
				if expr.kind != Declaration::Knows {
					continue;
				}
				for c in &expr.constants {
					match &*c.name {
						"scx_tag" => kept += 1,
						"scx_gpeer" => dropped += 1,
						_ => {}
					}
				}
			}
		}
		assert_eq!(kept, 2, "the unbound constant must survive in both clones");
		assert_eq!(dropped, 0, "the bound constant must not stay declared");
	}

	#[test]
	fn leaking_a_public_key_does_not_make_a_scenario_corrupt() {
		let src = SRC.replace("leaks scx_mk", "leaks scx_gm");
		let m = parse_string("scx.vp", &src).expect("parses");
		let e = expand_scenarios(&m, 1).expect("expands");
		assert!(
			e.scenarios.iter().all(starts_honest),
			"only a leaked secret marks a peer corrupt: {:?}",
			e.scenarios
		);
	}

	#[test]
	fn an_inline_derived_private_key_marks_its_peer_only_once_its_seed_leaks() {
		let inline = SRC.replace("scx_gm = PUBKEY(scx_mk)", "scx_gm = PUBKEY(HASH(scx_mk))");
		let m = parse_string("scx.vp", &inline).expect("parses");
		let e = expand_scenarios(&m, 1).expect("expands");
		assert!(
			!starts_honest(&e.scenarios[1]),
			"HASH(scx_mk) is Mallory's private key and scx_mk leaks: {:?}",
			e.scenarios
		);
		let kept = inline.replace("leaks scx_mk", "leaks scx_gm");
		let m = parse_string("scx.vp", &kept).expect("parses");
		let e = expand_scenarios(&m, 1).expect("expands");
		assert!(
			e.scenarios.iter().all(starts_honest),
			"leaking the public key computes nothing: {:?}",
			e.scenarios
		);
	}

	#[test]
	fn a_key_wrapped_under_a_computable_key_is_disclosed_with_it() {
		let wrapped = |wrap: &str, extra: &str| {
			SRC.replace(
				"leaks scx_mk",
				&format!("{extra}scx_w = {wrap}\n\t\tleaks scx_w"),
			)
		};
		for (wrap, extra, honest) in [
			("ENC(scx_wk, scx_mk)", "knows public scx_wk\n\t\t", false),
			("ENC(scx_wk, scx_mk)", "knows private scx_wk\n\t\t", true),
			(
				"PKE_ENC(scx_gw, scx_mk)",
				"knows private scx_wk\n\t\tscx_gw = PUBKEY(scx_wk)\n\t\tleaks scx_wk\n\t\t",
				false,
			),
			(
				"PKE_ENC(scx_gw, scx_mk)",
				"knows private scx_wk\n\t\tscx_gw = PUBKEY(scx_wk)\n\t\t",
				true,
			),
		] {
			let src = wrapped(wrap, extra);
			let m = parse_string("scx.vp", &src).expect("parses");
			let e = expand_scenarios(&m, 1).expect("expands");
			assert_eq!(
				starts_honest(&e.scenarios[1]),
				honest,
				"{wrap} with {extra:?}: {:?}",
				e.scenarios
			);
		}
	}

	#[test]
	fn a_bound_value_at_a_key_position_is_key_material() {
		let src = "attacker[active]\n\
			principal Mallory[\n\
			generates sbk_sm\n\
			]\n\
			Mallory -> Alice: sbk_sm\n\
			principal Alice[\n\
			knows private sbk_kb\n\
			sbk_km = HASH(sbk_sm)\n\
			knows private sbk_kpeer\n\
			generates sbk_m, sbk_n\n\
			sbk_e = AEAD_ENC(sbk_kpeer, sbk_n, sbk_m, nil)\n\
			]\n\
			scenarios[\n\
			Alice[sbk_kpeer = sbk_kb]\n\
			Alice[sbk_kpeer = sbk_km]\n\
			]\n\
			queries[\n\
			confidentiality? sbk_m\n\
			]\n";
		let m = parse_string("sbk.vp", src).expect("parses");
		let e = expand_scenarios(&m, 1).expect("expands");
		assert!(starts_honest(&e.scenarios[0]));
		assert!(
			!starts_honest(&e.scenarios[1]),
			"sbk_km becomes Alice's key once bound there, and its only ingredient \
			 goes out in the clear: {:?}",
			e.scenarios
		);
		let m =
			parse_string("sbk.vp", &src.replace("Mallory -> Alice: sbk_sm\n", "")).expect("parses");
		let e = expand_scenarios(&m, 1).expect("expands");
		assert!(
			e.scenarios.iter().all(starts_honest),
			"an ingredient never disclosed leaves the bound key secret: {:?}",
			e.scenarios
		);
	}

	#[test]
	fn a_leaked_derived_private_key_makes_its_scenario_corrupt() {
		let src = SRC
			.replace(
				"scx_gm = PUBKEY(scx_mk)",
				"scx_mk2 = HASH(scx_mk)\n\t\tscx_gm = PUBKEY(scx_mk2)",
			)
			.replace("leaks scx_mk", "leaks scx_mk2");
		let m = parse_string("scx.vp", &src).expect("parses");
		let e = expand_scenarios(&m, 1).expect("expands");
		assert!(starts_honest(&e.scenarios[0]));
		assert!(
			!starts_honest(&e.scenarios[1]),
			"a leaked assignment standing as a private key marks its peer corrupt: {:?}",
			e.scenarios
		);
	}

	#[test]
	fn a_wrapped_key_is_compromised_at_its_first_disclosure_phase() {
		let source = include_str!("../examples/test/scenario_corrupt_by_leaked_wrapped_key.vp")
			.replace("\tleaks scl_wrap\n", "");
		for disclosure in [
			"principal Mallory[\nleaks scl_wrap\n]",
			"Mallory -> Bob: [scl_wrap]",
		] {
			let source = source.replace(
				"scenarios[",
				&format!(
					"phase[1]\n{disclosure}\nphase[2]\n\
					 principal Mallory[\nleaks scl_mk2\n]\nscenarios["
				),
			);
			let model = parse_string("wrapped_later.vp", &source).expect("parses");
			let profile = honesty_profile(&model);
			assert_eq!(profile["Alice[scl_gpeer = scl_gb]"], i32::MAX);
			assert_eq!(profile["Alice[scl_gpeer = scl_gm]"], 1, "{disclosure}");
		}
	}

	#[test]
	fn a_disclosed_tuple_keeps_keys_inside_opaque_arguments_secret() {
		let source = include_str!("../examples/test/scenario_corrupt_by_leaked_wrapped_key.vp");
		for opaque in [
			"HASH(scl_mk2)",
			"PUBKEY(scl_mk2)",
			"ENC(scl_mk, scl_mk2)",
			"PKE_ENC(scl_gm, scl_mk2)",
		] {
			let source = source.replace(
				"CONCAT(scl_mk2, scl_pad)",
				&format!("CONCAT({opaque}, scl_pad)"),
			);
			let model = parse_string("wrapped_opaque.vp", &source).expect("parses");
			assert!(
				honesty_profile(&model).values().all(|&at| at == i32::MAX),
				"{opaque} does not disclose its private inputs"
			);
		}
	}

	#[test]
	fn a_leaked_private_key_still_makes_its_scenario_corrupt() {
		let m = parse_string("scx.vp", SRC).expect("parses");
		let e = expand_scenarios(&m, 1).expect("expands");
		assert!(starts_honest(&e.scenarios[0]));
		assert!(!starts_honest(&e.scenarios[1]));
	}

	#[test]
	fn a_peer_compromised_later_is_honest_until_then() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private pcl_a\n\
			knows public pcl_gpeer\n\
			generates pcl_m\n\
			pcl_e = PKE_ENC(pcl_gpeer, pcl_m)\n\
			]\n\
			principal Bob[\n\
			knows private pcl_b\n\
			pcl_gb = PUBKEY(pcl_b)\n\
			]\n\
			principal Mallory[\n\
			knows private pcl_mk\n\
			pcl_gm = PUBKEY(pcl_mk)\n\
			leaks pcl_mk\n\
			]\n\
			Alice -> Bob: pcl_e\n\
			principal Bob[\n\
			_ = HASH(pcl_e)\n\
			]\n\
			phase[1]\n\
			principal Bob[\n\
			leaks pcl_b\n\
			]\n\
			scenarios[\n\
			Alice[pcl_gpeer = pcl_gb]\n\
			Alice[pcl_gpeer = pcl_gm]\n\
			]\n\
			queries[\n\
			confidentiality? pcl_m\n\
			]\n";
		let m = parse_string("pcl.vp", src).expect("parses");
		let corruption = Corruption::of(&m);
		let corrupt_from = |i: usize| corruption.corrupt_from(&m.scenarios[i]);

		assert_eq!(
			corrupt_from(1),
			0,
			"Mallory's key is leaked at phase 0, so a run with her as peer is corrupt \
			 from the start"
		);
		assert_eq!(
			corrupt_from(0),
			1,
			"Bob's key is leaked at phase 1, so a run with him as peer is honest at \
			 phase 0 and only stops being so at phase 1. Reading the leak without its \
			 phase marked that run corrupt from the start and dropped every claim it \
			 could have answered"
		);

		let e = expand_scenarios(&m, 1).expect("expands");
		assert!(
			e.corrupt_from
				.as_ref()
				.is_some_and(|c| c.values().any(|&at| at == 1)),
			"the honest set records when a run stops being honest, not just whether"
		);
		assert!(
			starts_honest(&e.scenarios[0]) && !starts_honest(&e.scenarios[1]),
			"the block is normalised honest-first, so the run the written query names \
			 is one that is honest at phase 0 whenever the model declares any"
		);
		assert!(
			e.variants[0].is_empty(),
			"the only other scenario is corrupt from phase 0, so it gets no instance \
			 of the query: its claims are not the protocol's to keep"
		);
	}

	#[test]
	fn every_session_clone_of_an_honest_scenario_stays_honest() {
		let m = parse_string("scx.vp", SRC).expect("parses");
		let expanded = crate::verify::expand(&m, 2).expect("expands");
		let honest = expanded.corrupt_from.expect("scenarios mark honesty");
		assert_eq!(honest.len(), 6);
		let corrupt = expanded
			.model
			.blocks
			.iter()
			.filter(|b| match b {
				Block::Principal(p) => !honest.contains_key(&p.id),
				_ => false,
			})
			.count();
		assert_eq!(
			corrupt, 6,
			"the corrupt scenario's clones must all stay corrupt"
		);
	}

	#[test]
	fn scenario_and_session_copies_never_share_an_id() {
		let m = parse_string("scx.vp", SRC).expect("parses");
		let expanded = crate::verify::expand(&m, 2).expect("expands");
		let mut seen: IdSet<ValueId> = IdSet::default();
		for block in &expanded.model.blocks {
			let Block::Principal(p) = block else {
				continue;
			};
			for expr in &p.expressions {
				if !matches!(expr.kind, Declaration::Generates) {
					continue;
				}
				for c in &expr.constants {
					assert!(seen.insert(c.id), "{} reuses an id", c.name);
				}
			}
		}
		assert_eq!(seen.len(), 4);
	}
}
