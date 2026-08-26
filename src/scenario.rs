/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::Arc;

use crate::sanity::MAX_PRINCIPALS;
use crate::types::*;
use crate::value::{MAX_COPIES, copy_value_id};

pub(crate) struct ScenarioExpansion {
	pub(crate) model: Model,
	pub(crate) honest: IdSet<PrincipalId>,
}

pub(crate) fn expand_scenarios(m: &Model, sessions: u8) -> VResult<ScenarioExpansion> {
	let count = m.scenarios.len();
	if count == 0 {
		return Ok(ScenarioExpansion {
			model: m.clone(),
			honest: IdSet::default(),
		});
	}
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
	let principals = declared_principals(m);
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

	let freshen = freshened_constants(m);
	let compromised = compromised_constants(m);
	let pids = clone_principal_ids(&principals, count, highest_referenced_principal(m))?;

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

	let mut honest: IdSet<PrincipalId> = IdSet::default();
	for k in 0..count {
		if scenario_is_honest(&m.scenarios[k], &compromised) {
			for (id, _) in &principals {
				honest.insert(mapped_principal(*id, k, &pids).0);
			}
		}
	}

	let model = Model {
		file_name: m.file_name.clone(),
		source: m.source.clone(),
		attacker: m.attacker,
		blocks,
		scenarios: Vec::new(),
		scenarios_leading_comments: Vec::new(),
		scenarios_header_trailing: None,
		scenarios_tail_comments: Vec::new(),
		scenarios_closing_trailing: None,
		queries: m.queries.clone(),
		pre_attacker_comments: m.pre_attacker_comments.clone(),
		attacker_trailing: m.attacker_trailing.clone(),
		queries_leading_comments: m.queries_leading_comments.clone(),
		queries_header_trailing: m.queries_header_trailing.clone(),
		queries_tail_comments: m.queries_tail_comments.clone(),
		queries_closing_trailing: m.queries_closing_trailing.clone(),
		tail_comments: m.tail_comments.clone(),
	};

	let corrupt = count - honest_scenario_count(m, &compromised);
	crate::info::info_message(
		&format!(
			"Analyzing {count} peer scenarios per principal, {corrupt} of them with a \
			 corrupt peer; per-scenario values and principals are suffixed @2 onward.",
		),
		InfoLevel::Info,
		false,
	);

	Ok(ScenarioExpansion { model, honest })
}

fn honest_scenario_count(m: &Model, compromised: &IdSet<ValueId>) -> usize {
	m.scenarios
		.iter()
		.filter(|s| scenario_is_honest(s, compromised))
		.count()
}

fn scenario_is_honest(scenario: &Scenario, compromised: &IdSet<ValueId>) -> bool {
	!scenario
		.bindings
		.iter()
		.any(|(_, value)| compromised.contains(&value.id))
}

fn compromised_constants(m: &Model) -> IdSet<ValueId> {
	let mut out: IdSet<ValueId> = IdSet::default();
	for block in &m.blocks {
		let Block::Principal(p) = block else {
			continue;
		};
		for expression in &p.expressions {
			if expression.kind == Declaration::Leaks {
				for c in &expression.constants {
					out.insert(c.id);
				}
			}
		}
	}
	loop {
		let before = out.len();
		for block in &m.blocks {
			let Block::Principal(p) = block else {
				continue;
			};
			for expression in &p.expressions {
				let Some(value) = &expression.assigned else {
					continue;
				};
				if !mentions_any(value, &out) {
					continue;
				}
				for c in &expression.constants {
					out.insert(c.id);
				}
			}
		}
		if out.len() == before {
			break;
		}
	}
	out
}

fn mentions_any(v: &Value, ids: &IdSet<ValueId>) -> bool {
	match v {
		Value::Constant(c) => ids.contains(&c.id),
		Value::Primitive(p) => p.arguments.iter().any(|a| mentions_any(a, ids)),
	}
}

fn declared_principals(m: &Model) -> Vec<(PrincipalId, String)> {
	let mut out: Vec<(PrincipalId, String)> = Vec::new();
	for block in &m.blocks {
		if let Block::Principal(p) = block
			&& !out.iter().any(|(id, _)| *id == p.id)
		{
			out.push((p.id, p.name.clone()));
		}
	}
	out
}

fn freshened_constants(m: &Model) -> IdSet<ValueId> {
	let mut out = IdSet::default();
	for block in &m.blocks {
		let Block::Principal(p) = block else {
			continue;
		};
		for expr in &p.expressions {
			if matches!(expr.kind, Declaration::Generates | Declaration::Assignment) {
				for c in &expr.constants {
					out.insert(c.id);
				}
			}
		}
	}
	out
}

fn highest_referenced_principal(m: &Model) -> PrincipalId {
	let mut highest = 0;
	for block in &m.blocks {
		match block {
			Block::Principal(p) => highest = highest.max(p.id),
			Block::Message(msg) => highest = highest.max(msg.sender).max(msg.recipient),
			Block::Phase(_) => {}
		}
	}
	for query in &m.queries {
		highest = highest
			.max(query.message.sender)
			.max(query.message.recipient);
	}
	for scenario in &m.scenarios {
		highest = highest.max(scenario.principal);
	}
	highest
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
) -> (PrincipalId, String) {
	pids.get(&(id, k))
		.cloned()
		.unwrap_or((id, String::new()))
		.clone()
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
			return value.clone();
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
			.filter(|expr| !binds_target(expr, scenario, p.id))
			.map(|expr| Expression {
				span: expr.span,
				kind: expr.kind,
				qualifier: expr.qualifier,
				constants: expr
					.constants
					.iter()
					.map(|c| map_constant(&bind(c, scenario, p.id), k, sessions, freshen))
					.collect(),
				assigned: expr
					.assigned
					.as_ref()
					.map(|v| map_value(&bind_value(v, scenario, p.id), k, sessions, freshen)),
				leading_comments: Vec::new(),
				trailing_comment: None,
			})
			.collect(),
		leading_comments: Vec::new(),
		header_trailing: None,
		tail_comments: Vec::new(),
		closing_trailing: None,
	}
}

fn binds_target(expr: &Expression, scenario: &Scenario, principal: PrincipalId) -> bool {
	if scenario.principal != principal || expr.kind != Declaration::Knows {
		return false;
	}
	expr.constants
		.iter()
		.all(|c| scenario.bindings.iter().any(|(t, _)| t.id == c.id))
		&& !expr.constants.is_empty()
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
	fn scenario_and_session_copies_never_share_an_id() {
		let m = parse_string("scx.vp", SRC).expect("parses");
		let e = expand_scenarios(&m, 2).expect("expands");
		let expanded = crate::sessions::expand_sessions(&e.model, 2).expect("expands");
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
