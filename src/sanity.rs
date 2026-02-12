/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::construct::*;
use crate::pretty::{pretty_arity, pretty_constants};
use crate::primitive::*;
use crate::principal::*;
use crate::types::*;
use crate::util::*;
use crate::value::*;

pub fn sanity(m: &Model) -> VResult<(ProtocolTrace, Vec<PrincipalState>)> {
	sanity_phases(m)?;
	let (principals, principal_ids) = sanity_declared_principals(m)?;
	let km = construct_protocol_trace(m, &principals, &principal_ids)?;
	sanity_queries(m, &km)?;
	let ps = construct_principal_states(m, &km);
	Ok((km, ps))
}

fn sanity_phases(m: &Model) -> VResult<()> {
	let mut phase = 0;
	for blck in &m.blocks {
		if let Block::Phase(p) = blck {
			if p.number <= phase {
				return Err(VerifpalError::Sanity(format!(
					"phase being declared ({}) must be superior to last declared phase ({})",
					p.number, phase
				)));
			}
			if p.number != phase + 1 {
				return Err(VerifpalError::Sanity(format!(
					"phase being declared ({}) skips phases since last declared phase ({})",
					p.number, phase
				)));
			}
			phase = p.number;
		}
	}
	Ok(())
}

#[allow(clippy::only_used_in_recursion)]
pub fn sanity_assignment_constants(
	right: &Value,
	existing: &[Constant],
	km: &ProtocolTrace,
) -> VResult<Vec<Constant>> {
	let mut constants: Vec<Constant> = existing.to_vec();
	match right {
		Value::Constant(c) => {
			if !constants.iter().any(|x| c.equivalent(x)) {
				constants.push(c.clone());
			}
		}
		Value::Primitive(p) => {
			let arity = primitive_get_arity(p)?;
			let n = p.arguments.len() as i32;
			if n == 0 {
				return Err(VerifpalError::Sanity("primitive has no inputs".to_string()));
			}
			if !arity.contains(&n) {
				return Err(VerifpalError::Sanity(format!(
					"primitive has {} inputs, expecting {}",
					n,
					pretty_arity(arity)
				)));
			}
			for a in &p.arguments {
				constants = sanity_assignment_constants(a, &constants, km)?;
			}
		}
		Value::Equation(e) => {
			for v in &e.values {
				if let Value::Constant(c) = v {
					if !constants.iter().any(|x| c.equivalent(x)) {
						constants.push(c.clone());
					}
				}
			}
		}
	}
	Ok(constants)
}

pub fn sanity_primitive(p: &Primitive, outputs: &[Constant]) -> VResult<()> {
	let (output, check) = primitive_output_spec(p.id)?;
	if !output.contains(&(outputs.len() as i32)) {
		return Err(VerifpalError::Sanity(format!(
			"primitive has {} outputs, expecting {}",
			outputs.len(),
			pretty_arity(output)
		)));
	}
	if p.check && !check {
		return Err(VerifpalError::Sanity("primitive is checked but does not support checking".to_string()));
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

fn sanity_queries_single_constant(
	query: &Query,
	km: &ProtocolTrace,
	kind: &str,
) -> VResult<()> {
	if km.index_of(&query.constants[0]).is_none() {
		return Err(VerifpalError::Sanity(format!(
			"{} query ({}) refers to unknown constant ({})",
			kind,
			query,
			query.constants[0]
		)));
	}
	Ok(())
}

fn sanity_queries_authentication(query: &Query, km: &ProtocolTrace) -> VResult<()> {
	if query.message.constants.is_empty() {
		return Err(VerifpalError::Sanity(format!(
			"authentication query ({}) has no constants",
			query
		)));
	}
	let i = km.index_of(&query.message.constants[0]);
	if i.is_none() {
		return Err(VerifpalError::Sanity(format!(
			"authentication query ({}) refers to unknown constant ({})",
			query,
			query.message.constants[0]
		)));
	}
	if query.message.constants.len() != 1 {
		return Err(VerifpalError::Sanity(format!(
			"authentication query ({}) has more than one constant",
			query
		)));
	}
	let c = &query.message.constants[0];
	sanity_queries_check_message_principals(&query.message)?;
	sanity_queries_check_known(query, &query.message, c, km)
}

fn sanity_queries_multi_constant(
	query: &Query,
	km: &ProtocolTrace,
	kind: &str,
) -> VResult<()> {
	if query.constants.len() < 2 {
		return Err(VerifpalError::Sanity(format!(
			"{} query ({}) must specify at least two constants",
			kind,
			query
		)));
	}
	for (i, c) in query.constants.iter().enumerate() {
		if km.index_of(c).is_none() {
			return Err(VerifpalError::Sanity(format!(
				"{} query ({}) refers to unknown constant ({})",
				kind,
				query,
				c
			)));
		}
		if find_equivalent_constant(c, &query.constants[..i]).is_some() {
			return Err(VerifpalError::Sanity(format!(
				"{} query ({}) refers to same constant more than once ({})",
				kind,
				query,
				c
			)));
		}
	}
	Ok(())
}

fn sanity_query_options(query: &Query, km: &ProtocolTrace) -> VResult<()> {
	for option in &query.options {
		match option.kind {
			QueryOptionKind::Precondition => {
				if option.message.constants.len() != 1 {
					return Err(VerifpalError::Sanity(format!(
						"precondition option message ({}) has more than one constant",
						query
					)));
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
		return Err(VerifpalError::Sanity(format!(
			"query with message ({} -> {}: {}) has identical sender and recipient",
			principal_get_name_from_id(message.sender),
			principal_get_name_from_id(message.recipient),
			pretty_constants(&message.constants)
		)));
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
			return Err(VerifpalError::Sanity(format!(
				"query ({}) refers to unknown constant ({})",
				query,
				m.constants[0]
			)))
		}
	};
	let sender_knows = km.slots[idx].known_by_principal(m.sender);
	let recipient_knows = km.slots[idx].known_by_principal(m.recipient);
	let used = km.constant_used_by(m.recipient, &m.constants[0]);
	if !sender_knows {
		return Err(VerifpalError::Sanity(format!(
			"authentication query ({}) depends on {} sending a constant ({}) that they do not know",
			query,
			principal_get_name_from_id(m.sender),
			c
		)));
	}
	if !recipient_knows {
		return Err(VerifpalError::Sanity(format!("authentication query ({}) depends on {} receiving a constant ({}) that they never receive",
            query, principal_get_name_from_id(m.recipient), c)));
	}
	if !used {
		return Err(VerifpalError::Sanity(format!("authentication query ({}) depends on {} using a constant ({}) in a primitive, but this never happens",
            query, principal_get_name_from_id(m.recipient), c)));
	}
	Ok(())
}

fn sanity_declared_principals(m: &Model) -> VResult<(Vec<String>, Vec<PrincipalId>)> {
	let mut declared_names: Vec<String> = vec![];
	let mut declared_ids: Vec<PrincipalId> = vec![];
	let mut principals: Vec<PrincipalId> = vec![];
	for block in &m.blocks {
		if let Block::Principal(p) = block {
			append_unique_principal_enum(&mut principals, p.id);
			append_unique_string(&mut declared_names, p.name.clone());
			append_unique_principal_enum(&mut declared_ids, p.id);
		}
	}
	for block in &m.blocks {
		if let Block::Message(msg) = block {
			append_unique_principal_enum(&mut principals, msg.sender);
			append_unique_principal_enum(&mut principals, msg.recipient);
		}
	}
	for query in &m.queries {
		if query.kind == QueryKind::Authentication {
			append_unique_principal_enum(&mut principals, query.message.sender);
			append_unique_principal_enum(&mut principals, query.message.recipient);
		}
	}
	for &p in &principals {
		if !declared_ids.contains(&p) {
			return Err(VerifpalError::Sanity("principal does not exist".to_string()));
		}
	}
	if declared_names.len() > 64 {
		return Err(VerifpalError::Sanity(format!(
			"more than 64 principals ({}) declared",
			declared_names.len()
		)));
	}
	Ok((declared_names, declared_ids))
}

pub fn sanity_fail_on_failed_checked_primitive_rewrite(
	failures: &[(Primitive, usize)],
) -> VResult<()> {
	for (p, _) in failures {
		if p.check {
			return Err(VerifpalError::Sanity(format!("checked primitive fails: {}", p)));
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
                    p, arg_prim, arg_prim)));
			}
		}
	}
	Ok(())
}

pub fn sanity_check_equation_root_generator(e: &Equation) -> VResult<()> {
	if e.values.len() > 3 {
		return Err(VerifpalError::Sanity(format!(
			"too many layers in equation ({}), maximum is 2",
			e
		)));
	}
	let g_id = value_g().as_constant().expect("g is Constant").id;
	for (i, c) in e.values.iter().enumerate() {
		if let Value::Constant(con) = c {
			if i == 0 && con.id != g_id {
				return Err(VerifpalError::Sanity(format!(
					"equation ({}) does not use 'g' as generator",
					e
				)));
			}
			if i > 0 && con.id == g_id {
				return Err(VerifpalError::Sanity(format!(
					"equation ({}) uses 'g' not as a generator",
					e
				)));
			}
		}
	}
	Ok(())
}

pub fn sanity_check_equation_generators(a: &Value) -> VResult<()> {
	match a {
		Value::Primitive(p) => {
			for va in &p.arguments {
				match va {
					Value::Primitive(_) => sanity_check_equation_generators(va)?,
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
