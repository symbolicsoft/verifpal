/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::construct::*;
use crate::pretty::{pretty_arity, pretty_constants};
use crate::primitive::*;
use crate::principal::*;
use crate::types::*;
use crate::util::*;
use crate::value::*;

pub(crate) fn sanity(m: &Model) -> VResult<(ProtocolTrace, Vec<PrincipalState>)> {
	sanity_phases(m)?;
	let (principals, principal_ids) = sanity_declared_principals(m)?;
	let km = construct_protocol_trace(m, &principals, &principal_ids)?;
	sanity_queries(m, &km)?;
	let ps = construct_principal_states(m, &km);
	Ok((km, ps))
}

fn sanity_phases(m: &Model) -> VResult<()> {
	let mut phase = 0;
	for block in &m.blocks {
		if let Block::Phase(p) = block {
			if p.number <= phase {
				return Err(VerifpalError::Sanity(
					format!(
						"phase being declared ({}) must be superior to last declared phase ({})",
						p.number, phase
					)
					.into(),
				));
			}
			if p.number != phase + 1 {
				return Err(VerifpalError::Sanity(
					format!(
						"phase being declared ({}) skips phases since last declared phase ({})",
						p.number, phase
					)
					.into(),
				));
			}
			phase = p.number;
		}
	}
	Ok(())
}

#[allow(clippy::only_used_in_recursion)]
pub(crate) fn sanity_assignment_constants(
	right: &Value,
	existing: &[Constant],
	km: &ProtocolTrace,
) -> VResult<Vec<Constant>> {
	let mut constants: Vec<Constant> = existing.to_vec();
	match right {
		Value::Constant(c) => {
			if !constants.iter().any(|existing| c.equivalent(existing)) {
				constants.push(c.clone());
			}
		}
		Value::Primitive(p) => {
			let arity = primitive_get_arity(p)?;
			let arg_count = p.arguments.len() as i32;
			if arg_count == 0 {
				return Err(VerifpalError::Sanity("primitive has no inputs".into()));
			}
			if !arity.contains(&arg_count) {
				return Err(VerifpalError::Sanity(
					format!(
						"primitive has {} inputs, expecting {}",
						arg_count,
						pretty_arity(arity)
					)
					.into(),
				));
			}
			for arg in &p.arguments {
				constants = sanity_assignment_constants(arg, &constants, km)?;
			}
		}
		Value::Equation(e) => {
			for val in &e.values {
				if let Value::Constant(c) = val {
					if !constants.iter().any(|existing| c.equivalent(existing)) {
						constants.push(c.clone());
					}
				}
			}
		}
	}
	Ok(constants)
}

pub(crate) fn sanity_primitive(p: &Primitive, outputs: &[Constant]) -> VResult<()> {
	let (output, definition_check) = primitive_output_spec(p.id)?;
	if !output.contains(&(outputs.len() as i32)) {
		return Err(VerifpalError::Sanity(
			format!(
				"primitive has {} outputs, expecting {}",
				outputs.len(),
				pretty_arity(output)
			)
			.into(),
		));
	}
	if p.instance_check && !definition_check {
		return Err(VerifpalError::Sanity(
			"primitive is checked but does not support checking".into(),
		));
	}
	sanity_check_primitive_argument_outputs(p)
}

fn sanity_queries(m: &Model, km: &ProtocolTrace) -> VResult<()> {
	for query in &m.queries {
		match query.kind {
			QueryKind::Authentication => sanity_queries_authentication(query, km)?,
			QueryKind::Confidentiality | QueryKind::Freshness => {
				sanity_queries_single_constant(query, km, query.kind.name())?
			}
			QueryKind::Unlinkability | QueryKind::Equivalence => {
				sanity_queries_multi_constant(query, km, query.kind.name())?
			}
		}
		sanity_query_options(query, km)?;
	}
	Ok(())
}

fn sanity_queries_single_constant(query: &Query, km: &ProtocolTrace, kind: &str) -> VResult<()> {
	if km.index_of(&query.constants[0]).is_none() {
		return Err(VerifpalError::Sanity(
			format!(
				"{} query ({}) refers to unknown constant ({})",
				kind, query, query.constants[0]
			)
			.into(),
		));
	}
	Ok(())
}

fn sanity_queries_authentication(query: &Query, km: &ProtocolTrace) -> VResult<()> {
	if query.message.constants.is_empty() {
		return Err(VerifpalError::Sanity(
			format!("authentication query ({}) has no constants", query).into(),
		));
	}
	if km.index_of(&query.message.constants[0]).is_none() {
		return Err(VerifpalError::Sanity(
			format!(
				"authentication query ({}) refers to unknown constant ({})",
				query, query.message.constants[0]
			)
			.into(),
		));
	}
	if query.message.constants.len() != 1 {
		return Err(VerifpalError::Sanity(
			format!(
				"authentication query ({}) has more than one constant",
				query
			)
			.into(),
		));
	}
	let c = &query.message.constants[0];
	sanity_queries_check_message_principals(&query.message)?;
	sanity_queries_check_known(query, &query.message, c, km)
}

fn sanity_queries_multi_constant(query: &Query, km: &ProtocolTrace, kind: &str) -> VResult<()> {
	if query.constants.len() < 2 {
		return Err(VerifpalError::Sanity(
			format!(
				"{} query ({}) must specify at least two constants",
				kind, query
			)
			.into(),
		));
	}
	for (i, c) in query.constants.iter().enumerate() {
		if km.index_of(c).is_none() {
			return Err(VerifpalError::Sanity(
				format!(
					"{} query ({}) refers to unknown constant ({})",
					kind, query, c
				)
				.into(),
			));
		}
		if find_equivalent_constant(c, &query.constants[..i]).is_some() {
			return Err(VerifpalError::Sanity(
				format!(
					"{} query ({}) refers to same constant more than once ({})",
					kind, query, c
				)
				.into(),
			));
		}
	}
	Ok(())
}

fn sanity_query_options(query: &Query, km: &ProtocolTrace) -> VResult<()> {
	for option in &query.options {
		match option.kind {
			QueryOptionKind::Precondition => {
				if option.message.constants.len() != 1 {
					return Err(VerifpalError::Sanity(
						format!(
							"precondition option message ({}) has more than one constant",
							query
						)
						.into(),
					));
				}
				let c = &option.message.constants[0];
				sanity_queries_check_message_principals(&option.message)?;
				sanity_queries_check_known(query, &option.message, c, km)?;
			}
		}
	}
	Ok(())
}

fn sanity_queries_check_message_principals(message: &Message) -> VResult<()> {
	if message.sender == message.recipient {
		return Err(VerifpalError::Sanity(
			format!(
				"query with message ({} -> {}: {}) has identical sender and recipient",
				principal_get_name_from_id(message.sender),
				principal_get_name_from_id(message.recipient),
				pretty_constants(&message.constants)
			)
			.into(),
		));
	}
	Ok(())
}

fn sanity_queries_check_known(
	query: &Query,
	m: &Message,
	c: &Constant,
	km: &ProtocolTrace,
) -> VResult<()> {
	let idx = match km.index_of(&m.constants[0]) {
		Some(idx) => idx,
		None => {
			return Err(VerifpalError::Sanity(
				format!(
					"query ({}) refers to unknown constant ({})",
					query, m.constants[0]
				)
				.into(),
			))
		}
	};
	let sender_knows = km.slots[idx].known_by_principal(m.sender);
	let recipient_knows = km.slots[idx].known_by_principal(m.recipient);
	let used = km.constant_used_by(m.recipient, &m.constants[0]);
	if !sender_knows {
		return Err(VerifpalError::Sanity(
			format!(
			"authentication query ({}) depends on {} sending a constant ({}) that they do not know",
			query,
			principal_get_name_from_id(m.sender),
			c
		)
			.into(),
		));
	}
	if !recipient_knows {
		return Err(VerifpalError::Sanity(format!("authentication query ({}) depends on {} receiving a constant ({}) that they never receive",
            query, principal_get_name_from_id(m.recipient), c).into()));
	}
	if !used {
		return Err(VerifpalError::Sanity(format!("authentication query ({}) depends on {} using a constant ({}) in a primitive, but this never happens",
            query, principal_get_name_from_id(m.recipient), c).into()));
	}
	Ok(())
}

fn sanity_declared_principals(m: &Model) -> VResult<(Vec<String>, Vec<PrincipalId>)> {
	let mut declared_names: Vec<String> = vec![];
	let mut declared_ids: Vec<PrincipalId> = vec![];
	let mut principals: Vec<PrincipalId> = vec![];
	for block in &m.blocks {
		if let Block::Principal(p) = block {
			append_unique(&mut principals, p.id);
			append_unique(&mut declared_names, p.name.clone());
			append_unique(&mut declared_ids, p.id);
		}
	}
	for block in &m.blocks {
		if let Block::Message(msg) = block {
			append_unique(&mut principals, msg.sender);
			append_unique(&mut principals, msg.recipient);
		}
	}
	for query in &m.queries {
		if query.kind == QueryKind::Authentication {
			append_unique(&mut principals, query.message.sender);
			append_unique(&mut principals, query.message.recipient);
		}
	}
	for &p in &principals {
		if !declared_ids.contains(&p) {
			return Err(VerifpalError::Sanity("principal does not exist".into()));
		}
	}
	if declared_names.len() > 64 {
		return Err(VerifpalError::Sanity(
			format!(
				"more than 64 principals ({}) declared",
				declared_names.len()
			)
			.into(),
		));
	}
	Ok((declared_names, declared_ids))
}

pub(crate) fn sanity_fail_on_failed_checked_primitive_rewrite(
	failures: &[(Primitive, usize)],
) -> VResult<()> {
	for (p, _) in failures {
		if p.instance_check {
			return Err(VerifpalError::Sanity(
				format!("checked primitive fails: {}", p).into(),
			));
		}
	}
	Ok(())
}

fn sanity_check_primitive_argument_outputs(p: &Primitive) -> VResult<()> {
	for arg in &p.arguments {
		if let Value::Primitive(arg_prim) = arg {
			let (output, _) = primitive_output_spec(arg_prim.id)?;
			if !output.contains(&1) {
				return Err(VerifpalError::Sanity(format!("primitive {} cannot have {} as an argument, since {} necessarily produces more than one output",
                    p, arg_prim, arg_prim).into()));
			}
		}
	}
	Ok(())
}

pub(crate) fn sanity_check_equation_root_generator(e: &Equation) -> VResult<()> {
	if e.values.len() > 3 {
		return Err(VerifpalError::Sanity(
			format!("too many layers in equation ({}), maximum is 2", e).into(),
		));
	}
	let g_id: ValueId = 0; // g is always id 0
	for (i, c) in e.values.iter().enumerate() {
		if let Value::Constant(con) = c {
			if i == 0 && con.id != g_id {
				return Err(VerifpalError::Sanity(
					format!("equation ({}) does not use 'g' as generator", e).into(),
				));
			}
			if i > 0 && con.id == g_id {
				return Err(VerifpalError::Sanity(
					format!("equation ({}) uses 'g' not as a generator", e).into(),
				));
			}
		}
	}
	Ok(())
}

pub(crate) fn sanity_check_equation_generators(value: &Value) -> VResult<()> {
	match value {
		Value::Primitive(p) => {
			for arg in &p.arguments {
				match arg {
					Value::Primitive(_) => sanity_check_equation_generators(arg)?,
					Value::Equation(e) => sanity_check_equation_root_generator(e)?,
					_ => {}
				}
			}
		}
		Value::Equation(e) => {
			sanity_check_equation_root_generator(e)?;
		}
		_ => {}
	}
	Ok(())
}
