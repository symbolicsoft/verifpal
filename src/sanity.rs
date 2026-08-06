/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::construct::*;
use crate::pretty::{pretty_arity, pretty_constants};
use crate::primitive::*;
use crate::types::*;
use crate::util::*;
use crate::value::*;

pub(crate) fn sanity(m: &Model) -> VResult<(ProtocolTrace, Vec<PrincipalState>)> {
	sanity_phases(m)?;
	let (principals, principal_ids) = sanity_declared_principals(m)?;
	let km = construct_protocol_trace(m, &principals, &principal_ids)?;
	sanity_capabilities(m, &km)?;
	sanity_queries(m, &km)?;
	let ps = construct_principal_states(m, &km);
	Ok((km, ps))
}

fn sanity_capabilities(m: &Model, km: &ProtocolTrace) -> VResult<()> {
	for block in &m.blocks {
		let Block::Principal(p) = block else {
			continue;
		};
		for expression in &p.expressions {
			let Some(value) = &expression.assigned else {
				continue;
			};
			sanity_capabilities_value(value, km).map_err(|e| e.or_span(expression.span))?;
		}
	}
	Ok(())
}

fn sanity_capabilities_value(v: &Value, km: &ProtocolTrace) -> VResult<()> {
	let Value::Primitive(p) = v else {
		return Ok(());
	};
	for (cap, onset) in p.capabilities.iter() {
		if !crate::capability::supports(p.id, cap) {
			return Err(VerifpalError::sanity(
				crate::capability::unsupported_message(p.id, cap).into(),
			));
		}
		if onset > km.max_phase {
			return Err(VerifpalError::sanity(
				format!(
					"`{}` on {} comes into force at phase {}, which is never reached",
					cap.name(),
					crate::primitive::primitive_name(p.id),
					onset
				)
				.into(),
			));
		}
	}
	for arg in &p.arguments {
		sanity_capabilities_value(arg, km)?;
	}
	Ok(())
}

fn sanity_phases(m: &Model) -> VResult<()> {
	let mut phase = 0;
	for block in &m.blocks {
		if let Block::Phase(p) = block {
			if p.number <= phase {
				return Err(VerifpalError::sanity(
					format!(
						"phase being declared ({}) must be superior to last declared phase ({})",
						p.number, phase
					)
					.into(),
				));
			}
			if p.number != phase + 1 {
				return Err(VerifpalError::sanity(
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
				return Err(VerifpalError::sanity("primitive has no inputs".into()));
			}
			if !arity.contains(&arg_count) {
				return Err(VerifpalError::sanity(
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
	}
	Ok(constants)
}

pub(crate) fn sanity_primitive(p: &Primitive, outputs: &[Constant]) -> VResult<()> {
	let (output, definition_check) = primitive_output_spec(p.id)?;
	if !output.contains(&(outputs.len() as i32)) {
		return Err(VerifpalError::sanity(
			format!(
				"primitive has {} outputs, expecting {}",
				outputs.len(),
				pretty_arity(output)
			)
			.into(),
		));
	}
	if p.instance_check && !definition_check {
		return Err(VerifpalError::sanity(
			"primitive is checked but does not support checking".into(),
		));
	}
	sanity_check_primitive_argument_outputs(p)
}

fn sanity_queries(m: &Model, km: &ProtocolTrace) -> VResult<()> {
	for query in &m.queries {
		let located = |e: VerifpalError| e.or_span(query.span);
		match query.kind {
			QueryKind::Authentication => {
				sanity_queries_authentication(query, km).map_err(located)?
			}
			QueryKind::Confidentiality | QueryKind::Freshness => {
				sanity_queries_single_constant(query, km, query.kind.name()).map_err(located)?
			}
			QueryKind::Unlinkability | QueryKind::Equivalence => {
				sanity_queries_multi_constant(query, km, query.kind.name()).map_err(located)?
			}
		}
		sanity_query_options(query, km).map_err(located)?;
	}
	Ok(())
}

fn sanity_queries_single_constant(query: &Query, km: &ProtocolTrace, kind: &str) -> VResult<()> {
	let subject = query.subject()?;
	if km.index_of(subject).is_none() {
		return Err(VerifpalError::sanity(
			format!(
				"{} query ({}) refers to unknown constant ({})",
				kind, query, subject
			)
			.into(),
		));
	}
	Ok(())
}

fn sanity_queries_authentication(query: &Query, km: &ProtocolTrace) -> VResult<()> {
	if query.message.constants.is_empty() {
		return Err(VerifpalError::sanity(
			format!("authentication query ({}) has no constants", query).into(),
		));
	}
	let c = query.message.constant()?;
	if km.index_of(c).is_none() {
		return Err(VerifpalError::sanity(
			format!(
				"authentication query ({}) refers to unknown constant ({})",
				query, c
			)
			.into(),
		));
	}
	if query.message.constants.len() != 1 {
		return Err(VerifpalError::sanity(
			format!(
				"authentication query ({}) has more than one constant",
				query
			)
			.into(),
		));
	}
	sanity_queries_check_message_principals(&query.message)?;
	sanity_queries_check_known(query, &query.message, c, km)
}

fn sanity_queries_multi_constant(query: &Query, km: &ProtocolTrace, kind: &str) -> VResult<()> {
	if query.constants.len() < 2 {
		return Err(VerifpalError::sanity(
			format!(
				"{} query ({}) must specify at least two constants",
				kind, query
			)
			.into(),
		));
	}
	for (i, c) in query.constants.iter().enumerate() {
		if km.index_of(c).is_none() {
			return Err(VerifpalError::sanity(
				format!(
					"{} query ({}) refers to unknown constant ({})",
					kind, query, c
				)
				.into(),
			));
		}
		if find_equivalent_constant(c, &query.constants[..i]).is_some() {
			return Err(VerifpalError::sanity(
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
					return Err(VerifpalError::sanity(
						format!(
							"precondition option message ({}) has more than one constant",
							query
						)
						.into(),
					));
				}
				let c = option.message.constant()?;
				sanity_queries_check_message_principals(&option.message)?;
				sanity_queries_check_known(query, &option.message, c, km)?;
			}
		}
	}
	Ok(())
}

fn sanity_queries_check_message_principals(message: &Message) -> VResult<()> {
	if message.sender == message.recipient {
		return Err(VerifpalError::sanity(
			format!(
				"query with message ({} -> {}: {}) has identical sender and recipient",
				message.sender_name,
				message.recipient_name,
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
	let idx = match km.index_of(c) {
		Some(idx) => idx,
		None => {
			return Err(VerifpalError::sanity(
				format!("query ({}) refers to unknown constant ({})", query, c).into(),
			));
		}
	};
	let sender_knows = km.slots[idx].known_by_principal(m.sender);
	let recipient_knows = km.slots[idx].known_by_principal(m.recipient);
	let used = km.constant_used_by(m.recipient, c);
	if !sender_knows {
		return Err(VerifpalError::sanity(
			format!(
				"authentication query ({}) depends on {} sending a constant ({}) that they do not know",
				query, m.sender_name, c
			)
			.into(),
		));
	}
	if !recipient_knows {
		return Err(VerifpalError::sanity(
			format!(
				"authentication query ({}) depends on {} receiving a constant ({}) that they never receive",
				query, m.recipient_name, c
			)
			.into(),
		));
	}
	if !used {
		return Err(VerifpalError::sanity(format!("authentication query ({}) depends on {} using a constant ({}) in a primitive, but this never happens",
            query, m.recipient_name, c).into()));
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
			return Err(VerifpalError::sanity("principal does not exist".into()));
		}
	}
	if declared_names.len() > 64 {
		return Err(VerifpalError::sanity(
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
			return Err(VerifpalError::sanity(
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
				return Err(VerifpalError::sanity(format!("primitive {} cannot have {} as an argument, since {} necessarily produces more than one output",
                    p, arg_prim, arg_prim).into()));
			}
		}
	}
	Ok(())
}

pub(crate) fn sanity_check_argument_restrictions(value: &Value) -> VResult<()> {
	let Value::Primitive(p) = value else {
		return Ok(());
	};
	for (position, banned) in argument_restrictions(p.id) {
		if let Some(Value::Primitive(inner)) = p.arguments.get(*position)
			&& banned.contains(&inner.id)
		{
			return Err(VerifpalError::sanity(
				format!(
					"{} cannot take {} as argument {}",
					primitive_name(p.id),
					primitive_name(inner.id),
					position + 1
				)
				.into(),
			));
		}
	}
	for arg in &p.arguments {
		sanity_check_argument_restrictions(arg)?;
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testutil::*;

	fn pubkey(inner: Value) -> Value {
		make_primitive(primitive_get_enum("PUBKEY").unwrap(), vec![inner], 0)
	}

	fn dh_kex(a: Value, b: Value) -> Value {
		make_primitive(primitive_get_enum("DH_KEX").unwrap(), vec![a, b], 0)
	}

	#[test]
	fn dh_kex_rejects_public_key_in_secret_position() {
		let x = make_constant("arj_x");
		let y = make_constant("arj_y");
		let bad = dh_kex(pubkey(x), pubkey(y));
		assert!(sanity_check_argument_restrictions(&bad).is_err());
	}

	fn kem_encap(ek: Value, r: Value, output: usize) -> Value {
		make_primitive(
			primitive_get_enum("KEM_ENCAP").unwrap(),
			vec![ek, r],
			output,
		)
	}

	fn kem_decap(dk: Value, ct: Value) -> Value {
		make_primitive(primitive_get_enum("KEM_DECAP").unwrap(), vec![dk, ct], 0)
	}

	#[test]
	fn kem_decap_rejects_public_key_in_secret_position() {
		let x = make_constant("krp_x");
		let y = make_constant("krp_y");
		let r = make_constant("krp_r");
		let ct = kem_encap(pubkey(y), r, 1);
		let bad = kem_decap(pubkey(x), ct);
		assert!(sanity_check_argument_restrictions(&bad).is_err());
	}

	#[test]
	fn kem_encap_rejects_key_exchange_as_encapsulation_key() {
		let x = make_constant("kre_x");
		let y = make_constant("kre_y");
		let r = make_constant("kre_r");
		let bad = kem_encap(dh_kex(pubkey(x), y), r, 0);
		assert!(sanity_check_argument_restrictions(&bad).is_err());
	}

	#[test]
	fn kem_encap_accepts_a_public_key() {
		let x = make_constant("kra_x");
		let r = make_constant("kra_r");
		let good = kem_encap(pubkey(x), r, 0);
		assert!(sanity_check_argument_restrictions(&good).is_ok());
	}

	#[test]
	fn dh_kex_rejects_nested_key_exchange() {
		let x = make_constant("arn_x");
		let y = make_constant("arn_y");
		let z = make_constant("arn_z");
		let inner = dh_kex(pubkey(x), y);
		let bad = dh_kex(inner, z);
		assert!(sanity_check_argument_restrictions(&bad).is_err());
	}

	#[test]
	fn pubkey_rejects_a_public_key_argument() {
		let x = make_constant("arp_x");
		let bad = pubkey(pubkey(x));
		assert!(sanity_check_argument_restrictions(&bad).is_err());
	}

	#[test]
	fn dh_kex_accepts_a_bare_secret() {
		let x = make_constant("ark_x");
		let y = make_constant("ark_y");
		let good = dh_kex(pubkey(x), y);
		assert!(sanity_check_argument_restrictions(&good).is_ok());
	}

	#[test]
	fn restrictions_reach_nested_arguments() {
		let x = make_constant("arq_x");
		let y = make_constant("arq_y");
		let bad = make_primitive(PRIM_HASH, vec![dh_kex(pubkey(x), pubkey(y))], 0);
		assert!(sanity_check_argument_restrictions(&bad).is_err());
	}

	#[test]
	fn unrelated_primitives_are_unrestricted() {
		let x = make_constant("aru_x");
		let ok = make_primitive(PRIM_HASH, vec![make_primitive(PRIM_HASH, vec![x], 0)], 0);
		assert!(sanity_check_argument_restrictions(&ok).is_ok());
	}
}
