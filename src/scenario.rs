/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::Arc;

use crate::sanity::MAX_PRINCIPALS;
use crate::types::*;
use crate::util::{base_name, did_you_mean, quoted_list};
use crate::value::{MAX_COPIES, copy_value_id};

pub(crate) struct ScenarioExpansion {
	pub(crate) model: Model,
	pub(crate) honest: IdMap<PrincipalId, i32>,
	pub(crate) summaries: Vec<ScenarioSummary>,
	pub(crate) query_variants: Vec<Vec<Query>>,
	pub(crate) interchangeable: Vec<(PrincipalId, PrincipalId)>,
	pub(crate) actors: Vec<(PrincipalId, PrincipalId)>,
}

pub(crate) fn expand_scenarios(m: &Model, sessions: u8) -> VResult<ScenarioExpansion> {
	let count = m.scenarios.len();
	if count == 0 {
		return Ok(ScenarioExpansion {
			model: m.clone(),
			honest: IdMap::default(),
			summaries: Vec::new(),
			query_variants: Vec::new(),
			interchangeable: Vec::new(),
			actors: Vec::new(),
		});
	}
	sanity_scenarios(m)?;
	let copies = count as u32 * sessions as u32;
	if copies > MAX_COPIES + 1 {
		return Err(VerifpalError::sanity(
			format!(
				"{count} scenarios at {sessions} sessions would analyze {copies} copies \
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

	let freshen = m.freshened_constants();
	let compromised = compromised_constants(m);
	let declared = honest_first(&m.scenarios, &compromised);
	let m = &Model {
		scenarios: declared,
		..m.clone()
	};
	let pids = clone_principal_ids(&principals, count, m.highest_referenced_principal())?;

	let mut blocks: Vec<Block> = Vec::with_capacity(m.blocks.len() * count);
	for block in &m.blocks {
		match block {
			Block::Principal(p) => {
				for k in 0..count {
					blocks.push(Block::Principal(clone_principal(
						p, k, sessions, &freshen, &pids, m,
					)));
				}
			}
			Block::Message(msg) => {
				for k in 0..count {
					blocks.push(Block::Message(clone_message(
						msg, k, sessions, &freshen, &pids,
					)));
				}
			}
			Block::Phase(p) => blocks.push(Block::Phase(p.clone())),
		}
	}

	let mut honest: IdMap<PrincipalId, i32> = IdMap::default();
	for k in 0..count {
		let corrupt_from = scenario_corrupt_from(&m.scenarios[k], &compromised);
		if corrupt_from <= 0 {
			continue;
		}
		for (id, _) in &principals {
			honest.insert(mapped_principal(*id, k, &pids), corrupt_from);
		}
	}

	let mut query_variants: Vec<Vec<Query>> = Vec::with_capacity(m.queries.len());
	for query in &m.queries {
		let mut variants = Vec::new();
		for k in 1..count {
			if scenario_corrupt_from(&m.scenarios[k], &compromised) <= 0 {
				continue;
			}
			let variant = clone_query(query, k, sessions, &freshen, &pids);
			if !query.same_shape(&variant) {
				variants.push(variant);
			}
		}
		query_variants.push(variants);
	}

	let model = Model {
		blocks,
		scenarios: Vec::new(),
		scenarios_leading_comments: Vec::new(),
		scenarios_header_trailing: None,
		scenarios_tail_comments: Vec::new(),
		scenarios_closing_trailing: None,
		..m.clone()
	};

	let summaries: Vec<ScenarioSummary> = m
		.scenarios
		.iter()
		.map(|s| ScenarioSummary {
			principal: Arc::clone(&s.principal_name),
			bindings: s
				.bindings
				.iter()
				.map(|(t, v)| (Arc::clone(&t.name), Arc::clone(&v.name)))
				.collect(),
			honest: scenario_corrupt_from(s, &compromised) > 0,
		})
		.collect();

	let corrupt = summaries.iter().filter(|s| !s.honest).count();
	crate::info::info_message(
		&format!(
			"Analyzing {count} peer scenarios per principal, {corrupt} of them with a \
			 corrupt peer; per-scenario values and principals are suffixed @2 onward.",
		),
		InfoLevel::Info,
		false,
	);

	Ok(ScenarioExpansion {
		model,
		honest,
		summaries,
		query_variants,
		interchangeable: interchangeable_clones(m, &principals, count, &pids),
		actors: principals
			.iter()
			.flat_map(|&(id, _)| (0..count).map(move |k| (id, k)))
			.map(|(id, k)| (mapped_principal(id, k, &pids), id))
			.collect(),
	})
}

fn peer_binding_key(m: &Model, k: usize, principal: PrincipalId) -> Vec<(ValueId, ValueId)> {
	let scenario = &m.scenarios[k];
	if scenario.principal != principal {
		return Vec::new();
	}
	let mut out: Vec<(ValueId, ValueId)> = scenario
		.bindings
		.iter()
		.filter(|(target, value)| target.id != value.id)
		.map(|(target, value)| (target.id, value.id))
		.collect();
	out.sort_unstable();
	out
}

fn interchangeable_clones(
	m: &Model,
	principals: &[(PrincipalId, String)],
	count: usize,
	pids: &HashMap<(PrincipalId, usize), (PrincipalId, String)>,
) -> Vec<(PrincipalId, PrincipalId)> {
	let mut out = Vec::new();
	for &(id, _) in principals {
		let keys: Vec<Vec<(ValueId, ValueId)>> =
			(0..count).map(|k| peer_binding_key(m, k, id)).collect();
		for k in 0..count {
			let canonical = keys.iter().position(|key| *key == keys[k]).unwrap_or(k);
			out.push((
				mapped_principal(id, k, pids),
				mapped_principal(id, canonical, pids),
			));
		}
	}
	out
}

#[cfg(test)]
pub(crate) fn honesty_profile(m: &Model) -> std::collections::BTreeMap<String, i32> {
	let compromised = compromised_constants(m);
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
				scenario_corrupt_from(s, &compromised),
			)
		})
		.collect()
}

fn honest_first(scenarios: &[Scenario], compromised: &IdMap<ValueId, i32>) -> Vec<Scenario> {
	let mut out: Vec<Scenario> = scenarios.to_vec();
	out.sort_by_key(|s| std::cmp::Reverse(scenario_corrupt_from(s, compromised)));
	out
}

fn scenario_corrupt_from(scenario: &Scenario, compromised: &IdMap<ValueId, i32>) -> i32 {
	scenario
		.bindings
		.iter()
		.filter_map(|(_, value)| compromised.get(&value.id).copied())
		.min()
		.unwrap_or(i32::MAX)
}

fn sanity_scenarios(m: &Model) -> VResult<()> {
	let principals = m.declared_principals();
	let known = known_constants(m);
	let declared = declared_constants(m);
	for scenario in &m.scenarios {
		let Some((id, _)) = principals
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
		let mut bound: Vec<ValueId> = Vec::new();
		for (target, value) in &scenario.bindings {
			if !known.get(id).is_some_and(|set| set.contains(&target.id)) {
				let names: Vec<String> = known
					.get(id)
					.map(|set| {
						declared
							.iter()
							.filter(|(cid, _)| set.contains(cid))
							.map(|(_, name)| name.clone())
							.collect()
					})
					.unwrap_or_default();
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

fn known_constants(m: &Model) -> IdMap<PrincipalId, IdSet<ValueId>> {
	let mut out: IdMap<PrincipalId, IdSet<ValueId>> = IdMap::default();
	for block in &m.blocks {
		let Block::Principal(p) = block else {
			continue;
		};
		let entry = out.entry(p.id).or_default();
		for expr in &p.expressions {
			if expr.kind != Declaration::Knows {
				continue;
			}
			for c in &expr.constants {
				entry.insert(c.id);
			}
		}
	}
	out
}

fn declared_constants(m: &Model) -> Vec<(ValueId, String)> {
	let mut out: Vec<(ValueId, String)> = Vec::new();
	for block in &m.blocks {
		let Block::Principal(p) = block else {
			continue;
		};
		for expr in &p.expressions {
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
	}
	out
}

fn secret_declarations(m: &Model) -> IdSet<ValueId> {
	let mut out: IdSet<ValueId> = IdSet::default();
	for block in &m.blocks {
		let Block::Principal(p) = block else {
			continue;
		};
		for expr in &p.expressions {
			let secret = match expr.kind {
				Declaration::Generates => true,
				Declaration::Knows => matches!(expr.qualifier, Some(Qualifier::Private)),
				_ => false,
			};
			if !secret {
				continue;
			}
			for c in &expr.constants {
				out.insert(c.id);
			}
		}
	}
	out
}

fn compromised_constants(m: &Model) -> IdMap<ValueId, i32> {
	let secret = secret_declarations(m);
	let mut out: IdMap<ValueId, i32> = IdMap::default();
	let mut phase = 0i32;
	for block in &m.blocks {
		match block {
			Block::Phase(p) => phase = p.number,
			Block::Principal(p) => {
				for expression in &p.expressions {
					if expression.kind != Declaration::Leaks {
						continue;
					}
					for c in &expression.constants {
						if !secret.contains(&c.id) {
							continue;
						}
						let at = out.entry(c.id).or_insert(phase);
						*at = (*at).min(phase);
					}
				}
			}
			Block::Message(_) => {}
		}
	}
	loop {
		let mut changed = false;
		for block in &m.blocks {
			let Block::Principal(p) = block else {
				continue;
			};
			for expression in &p.expressions {
				let Some(value) = &expression.assigned else {
					continue;
				};
				let Some(from) = earliest_mentioned(value, &out) else {
					continue;
				};
				for c in &expression.constants {
					match out.get(&c.id) {
						Some(&at) if at <= from => {}
						_ => {
							out.insert(c.id, from);
							changed = true;
						}
					}
				}
			}
		}
		if !changed {
			break;
		}
	}
	out
}

fn earliest_mentioned(v: &Value, ids: &IdMap<ValueId, i32>) -> Option<i32> {
	match v {
		Value::Constant(c) => ids.get(&c.id).copied(),
		Value::Primitive(p) => p
			.arguments
			.iter()
			.filter_map(|a| earliest_mentioned(a, ids))
			.min(),
	}
}

fn clone_principal_ids(
	principals: &[(PrincipalId, String)],
	count: usize,
	highest: PrincipalId,
) -> VResult<HashMap<(PrincipalId, usize), (PrincipalId, String)>> {
	let mut next = principals
		.iter()
		.map(|&(id, _)| id)
		.max()
		.unwrap_or(0)
		.max(highest);
	let mut out = HashMap::new();
	for k in 1..count {
		for (id, name) in principals {
			next = next.checked_add(1).ok_or_else(|| {
				VerifpalError::internal("scenario expansion exhausted principal ids".into())
			})?;
			out.insert((*id, k), (next, format!("{name}@{}", k + 1)));
		}
	}
	Ok(out)
}

fn mapped_principal(
	id: PrincipalId,
	k: usize,
	pids: &HashMap<(PrincipalId, usize), (PrincipalId, String)>,
) -> PrincipalId {
	pids.get(&(id, k)).map(|&(id, _)| id).unwrap_or(id)
}

fn scenario_value_id(base: ValueId, k: usize, sessions: u8) -> ValueId {
	copy_value_id(base, k as u32 * sessions as u32)
}

fn map_constant(c: &Constant, k: usize, sessions: u8, freshen: &IdSet<ValueId>) -> Constant {
	if k == 0 || !freshen.contains(&c.id) {
		return c.clone();
	}
	Constant {
		name: Arc::from(format!("{}@{}", c.name, k + 1)),
		id: scenario_value_id(c.id, k, sessions),
		..c.clone()
	}
}

fn map_value(v: &Value, k: usize, sessions: u8, freshen: &IdSet<ValueId>) -> Value {
	match v {
		Value::Constant(c) => Value::Constant(map_constant(c, k, sessions, freshen)),
		Value::Primitive(p) => {
			let arguments = p
				.arguments
				.iter()
				.map(|a| map_value(a, k, sessions, freshen))
				.collect();
			Value::Primitive(Arc::new(p.with_arguments(arguments)))
		}
	}
}

fn bind(c: &Constant, scenario: &Scenario, principal: PrincipalId) -> Constant {
	if scenario.principal != principal {
		return c.clone();
	}
	for (target, value) in &scenario.bindings {
		if target.id == c.id {
			return Constant {
				guard: c.guard,
				..value.clone()
			};
		}
	}
	c.clone()
}

fn bind_value(v: &Value, scenario: &Scenario, principal: PrincipalId) -> Value {
	match v {
		Value::Constant(c) => Value::Constant(bind(c, scenario, principal)),
		Value::Primitive(p) => {
			let arguments = p
				.arguments
				.iter()
				.map(|a| bind_value(a, scenario, principal))
				.collect();
			Value::Primitive(Arc::new(p.with_arguments(arguments)))
		}
	}
}

fn clone_principal(
	p: &Principal,
	k: usize,
	sessions: u8,
	freshen: &IdSet<ValueId>,
	pids: &HashMap<(PrincipalId, usize), (PrincipalId, String)>,
	m: &Model,
) -> Principal {
	let (id, name) = pids
		.get(&(p.id, k))
		.cloned()
		.unwrap_or((p.id, p.name.clone()));
	let scenario = &m.scenarios[k];
	Principal {
		name,
		id,
		span: p.span,
		expressions: p
			.expressions
			.iter()
			.filter_map(|expr| {
				let constants: Vec<Constant> = expr
					.constants
					.iter()
					.filter(|c| !rebinds(expr, scenario, p.id, c))
					.map(|c| map_constant(&bind(c, scenario, p.id), k, sessions, freshen))
					.collect();
				if constants.is_empty() && !expr.constants.is_empty() {
					return None;
				}
				Some(Expression {
					span: expr.span,
					kind: expr.kind,
					qualifier: expr.qualifier,
					constants,
					assigned: expr
						.assigned
						.as_ref()
						.map(|v| map_value(&bind_value(v, scenario, p.id), k, sessions, freshen)),
					leading_comments: Vec::new(),
					trailing_comment: None,
				})
			})
			.collect(),
		leading_comments: Vec::new(),
		header_trailing: None,
		tail_comments: Vec::new(),
		closing_trailing: None,
	}
}

fn rebinds(expr: &Expression, scenario: &Scenario, principal: PrincipalId, c: &Constant) -> bool {
	scenario.principal == principal
		&& expr.kind == Declaration::Knows
		&& scenario
			.bindings
			.iter()
			.any(|(t, v)| t.id == c.id && v.id != c.id)
}

fn clone_query(
	q: &Query,
	k: usize,
	sessions: u8,
	freshen: &IdSet<ValueId>,
	pids: &HashMap<(PrincipalId, usize), (PrincipalId, String)>,
) -> Query {
	Query {
		span: q.span,
		kind: q.kind,
		constants: q
			.constants
			.iter()
			.map(|c| map_constant(c, k, sessions, freshen))
			.collect(),
		message: clone_message(&q.message, k, sessions, freshen, pids),
		options: q
			.options
			.iter()
			.map(|o| QueryOption {
				kind: o.kind,
				message: clone_message(&o.message, k, sessions, freshen, pids),
				leading_comments: Vec::new(),
				trailing_comment: None,
			})
			.collect(),
		leading_comments: Vec::new(),
		trailing_comment: None,
	}
}

fn clone_message(
	msg: &Message,
	k: usize,
	sessions: u8,
	freshen: &IdSet<ValueId>,
	pids: &HashMap<(PrincipalId, usize), (PrincipalId, String)>,
) -> Message {
	let (sender, sender_name) = pids
		.get(&(msg.sender, k))
		.map(|(id, name)| (*id, Arc::<str>::from(name.as_str())))
		.unwrap_or((msg.sender, Arc::clone(&msg.sender_name)));
	let (recipient, recipient_name) = pids
		.get(&(msg.recipient, k))
		.map(|(id, name)| (*id, Arc::<str>::from(name.as_str())))
		.unwrap_or((msg.recipient, Arc::clone(&msg.recipient_name)));
	Message {
		span: msg.span,
		sender,
		sender_name,
		recipient,
		recipient_name,
		constants: msg
			.constants
			.iter()
			.map(|c| map_constant(c, k, sessions, freshen))
			.collect(),
		leading_comments: Vec::new(),
		trailing_comment: None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::parser::parse_string;

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
		assert_eq!(e.honest.len(), 3);
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
		assert!(e.honest.is_empty());
		assert_eq!(e.summaries.len(), 1);
		assert!(!e.summaries[0].honest);
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
			e.summaries.iter().all(|s| s.honest),
			"only a leaked secret marks a peer corrupt: {:?}",
			e.summaries
		);
	}

	#[test]
	fn a_leaked_private_key_still_makes_its_scenario_corrupt() {
		let m = parse_string("scx.vp", SRC).expect("parses");
		let e = expand_scenarios(&m, 1).expect("expands");
		assert!(e.summaries[0].honest);
		assert!(!e.summaries[1].honest);
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
		let compromised = compromised_constants(&m);
		let corrupt_from = |i: usize| scenario_corrupt_from(&m.scenarios[i], &compromised);

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
			e.honest.values().any(|&at| at == 1),
			"the honest set records when a run stops being honest, not just whether"
		);
		assert!(
			e.summaries[0].honest && !e.summaries[1].honest,
			"the block is normalised honest-first, so the run the written query names \
			 is one that is honest at phase 0 whenever the model declares any"
		);
		assert!(
			e.query_variants[0].is_empty(),
			"the only other scenario is corrupt from phase 0, so it gets no instance \
			 of the query: its claims are not the protocol's to keep"
		);
	}

	#[test]
	fn every_session_clone_of_an_honest_scenario_stays_honest() {
		let m = parse_string("scx.vp", SRC).expect("parses");
		let e = expand_scenarios(&m, 2).expect("expands");
		let expanded =
			crate::sessions::expand_sessions(&e.model, 2, &e.query_variants).expect("expands");
		let mut honest = e.honest.clone();
		for &(original, clone) in &expanded.principal_clones {
			if let Some(&corrupt_from) = honest.get(&original) {
				honest.insert(clone, corrupt_from);
			}
		}
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
		let e = expand_scenarios(&m, 2).expect("expands");
		let expanded =
			crate::sessions::expand_sessions(&e.model, 2, &e.query_variants).expect("expands");
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
