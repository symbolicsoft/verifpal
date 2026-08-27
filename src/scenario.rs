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
	pub(crate) honest: IdSet<PrincipalId>,
	pub(crate) summaries: Vec<ScenarioSummary>,
}

pub(crate) fn expand_scenarios(m: &Model, sessions: u8) -> VResult<ScenarioExpansion> {
	let count = m.scenarios.len();
	if count == 0 {
		return Ok(ScenarioExpansion {
			model: m.clone(),
			honest: IdSet::default(),
			summaries: Vec::new(),
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

	let mut honest: IdSet<PrincipalId> = IdSet::default();
	for k in 0..count {
		if scenario_is_honest(&m.scenarios[k], &compromised) {
			for (id, _) in &principals {
				honest.insert(mapped_principal(*id, k, &pids));
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
			honest: scenario_is_honest(s, &compromised),
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
	})
}

fn scenario_is_honest(scenario: &Scenario, compromised: &IdSet<ValueId>) -> bool {
	!scenario
		.bindings
		.iter()
		.any(|(_, value)| compromised.contains(&value.id))
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
				Declaration::Knows => matches!(
					expr.qualifier,
					Some(Qualifier::Private) | Some(Qualifier::Password)
				),
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

fn compromised_constants(m: &Model) -> IdSet<ValueId> {
	let secret = secret_declarations(m);
	let mut out: IdSet<ValueId> = IdSet::default();
	for block in &m.blocks {
		let Block::Principal(p) = block else {
			continue;
		};
		for expression in &p.expressions {
			if expression.kind == Declaration::Leaks {
				for c in &expression.constants {
					if secret.contains(&c.id) {
						out.insert(c.id);
					}
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
	fn every_session_clone_of_an_honest_scenario_stays_honest() {
		let m = parse_string("scx.vp", SRC).expect("parses");
		let e = expand_scenarios(&m, 2).expect("expands");
		let expanded = crate::sessions::expand_sessions(&e.model, 2).expect("expands");
		let mut honest = e.honest.clone();
		for &(original, clone) in &expanded.principal_clones {
			if honest.contains(&original) {
				honest.insert(clone);
			}
		}
		assert_eq!(honest.len(), 6);
		let corrupt = expanded
			.model
			.blocks
			.iter()
			.filter(|b| match b {
				Block::Principal(p) => !honest.contains(&p.id),
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
