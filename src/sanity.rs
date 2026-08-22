/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::construct::*;
use crate::pretty::{pretty_arity, pretty_constants};
use crate::primitive::*;
use crate::types::*;
use crate::util::*;
use crate::value::*;

pub(crate) fn trace_constant_names(km: &ProtocolTrace) -> Vec<&str> {
	let mut names: Vec<&str> = km
		.slots
		.iter()
		.map(|slot| base_name(slot.constant.name.as_ref()))
		.collect();
	names.sort_unstable();
	names.dedup();
	names
}

fn ordinal(n: usize) -> &'static str {
	match n {
		1 => "first",
		2 => "second",
		3 => "third",
		4 => "fourth",
		_ => "fifth",
	}
}

fn restriction_note(outer: PrimitiveId, inner: PrimitiveId, position: usize) -> String {
	let outer_name = primitive_name(outer);
	let inner_name = primitive_name(inner);
	if outer_name == "DH_KEX" && position == 1 {
		return "the second argument to `DH_KEX` is a private exponent, not a public \
		        value; keeping it that way is what makes the Diffie-Hellman \
		        assumption structural rather than a special rule"
			.to_string();
	}
	if outer_name == "PUBKEY" {
		return "`PUBKEY` derives a public value from a private one, so its argument \
		        cannot already be public"
			.to_string();
	}
	format!(
		"the term space stays finite only if `{}` is never applied on top of `{}` here",
		outer_name, inner_name
	)
}

fn plural(n: usize) -> &'static str {
	if n == 1 { "" } else { "s" }
}

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
			)
			.narrow(cap.name())
			.note(
				"a weakening assumption has to name a property the primitive actually \
				 has, or the analysis would run under an assumption that does nothing",
			));
		}
		if onset > km.max_phase {
			return Err(VerifpalError::sanity(
				format!(
					"`{}` on {} comes into force at phase {}, which the model never reaches",
					cap.name(),
					crate::primitive::primitive_name(p.id),
					onset
				)
				.into(),
			)
			.narrow(cap.name())
			.note(format!(
				"the last phase this model declares is phase {}",
				km.max_phase
			))
			.help(format!(
				"either add `phase[{}]` to the model, or lower the phase in this annotation",
				onset
			)));
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
					format!("phase {} is declared after phase {}", p.number, phase).into(),
				)
				.at(p.span)
				.marking(p.span, "phase numbers must increase")
				.help(format!("renumber this to `phase[{}]`", phase + 1)));
			}
			if p.number != phase + 1 {
				return Err(VerifpalError::sanity(
					format!(
						"phase {} follows phase {}, skipping {}",
						p.number,
						phase,
						if p.number - phase == 2 {
							format!("phase {}", phase + 1)
						} else {
							format!("phases {} to {}", phase + 1, p.number - 1)
						}
					)
					.into(),
				)
				.at(p.span)
				.note("phases model time, and must increment by exactly 1")
				.help(format!("renumber this to `phase[{}]`", phase + 1)));
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
				return Err(VerifpalError::sanity(
					format!("`{}` is called with no arguments", primitive_name(p.id)).into(),
				)
				.narrow(primitive_name(p.id))
				.note(format!("its signature is `{}`", primitive_signature(p.id))));
			}
			if !arity.contains(&arg_count) {
				return Err(VerifpalError::sanity(
					format!(
						"`{}` takes {} argument{}, but {} {} given",
						primitive_name(p.id),
						pretty_arity(arity),
						if arity == [1] { "" } else { "s" },
						arg_count,
						if arg_count == 1 { "was" } else { "were" }
					)
					.into(),
				)
				.narrow(primitive_name(p.id))
				.note(format!("its signature is `{}`", primitive_signature(p.id))));
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
				"`{}` produces {} outputs, but {} constant{} bound here",
				primitive_name(p.id),
				pretty_arity(output),
				outputs.len(),
				if outputs.len() == 1 { " is" } else { "s are" }
			)
			.into(),
		)
		.narrow(primitive_name(p.id))
		.note(format!("its signature is `{}`", primitive_signature(p.id)))
		.help(format!(
			"bind {} on the left of the `=`, e.g. `{} = {}(…)`",
			match output.first() {
				Some(1) => "one constant".to_string(),
				Some(n) => format!("{} constants", n),
				None => "the right number of constants".to_string(),
			},
			(0..*output.first().unwrap_or(&1))
				.map(|i| format!("out{}", i + 1))
				.collect::<Vec<String>>()
				.join(", "),
			primitive_name(p.id)
		)));
	}
	if p.instance_check && !definition_check {
		return Err(VerifpalError::sanity(
			format!("`{}` cannot be checked with `?`", primitive_name(p.id)).into(),
		)
		.narrow(primitive_name(p.id))
		.note(format!(
			"only a primitive that can fail may be checked: {}",
			quoted_list(&primitive_checkable_names())
		))
		.help("remove the `?`"));
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
		let _ = kind;
		return Err(unknown_constant(
			&subject.name,
			km,
			"not declared by any principal".to_string(),
		));
	}
	Ok(())
}

pub(crate) fn unknown_constant(name: &str, km: &ProtocolTrace, context: String) -> VerifpalError {
	VerifpalError::sanity(format!("unknown constant `{}`", name).into())
		.narrow(name.to_string())
		.labelled(context)
		.note(
			"a constant must be introduced by `knows`, `generates`, or an \
			 assignment before anything can refer to it",
		)
		.suggest(did_you_mean(name, trace_constant_names(km)))
}

fn sanity_queries_authentication(query: &Query, km: &ProtocolTrace) -> VResult<()> {
	if query.message.constants.is_empty() {
		return Err(
			VerifpalError::sanity("authentication query names no constant".into())
				.note("an authentication query asks about one value on one message")
				.help("write it as `authentication? Alice -> Bob: m`"),
		);
	}
	let c = query.message.constant()?;
	if km.index_of(c).is_none() {
		return Err(unknown_constant(
			&c.name,
			km,
			"not declared by any principal".to_string(),
		));
	}
	if query.message.constants.len() != 1 {
		return Err(VerifpalError::sanity(
			format!(
				"authentication query names {} constants, but asks about one message",
				query.message.constants.len()
			)
			.into(),
		)
		.note(
			"authentication is a property of a single value: which principal \
			 really produced it",
		)
		.help(format!(
			"split this into {} queries, one per constant",
			query.message.constants.len()
		)));
	}
	sanity_queries_check_message_principals(&query.message)?;
	sanity_queries_check_known(query, &query.message, c, km)
}

fn sanity_queries_multi_constant(query: &Query, km: &ProtocolTrace, kind: &str) -> VResult<()> {
	if query.constants.len() < 2 {
		return Err(VerifpalError::sanity(
			format!(
				"{} query names {} constant{}, but compares values against each other",
				kind,
				query.constants.len(),
				plural(query.constants.len())
			)
			.into(),
		)
		.note(match kind {
			"unlinkability" => {
				"unlinkability asks whether the attacker can tell two values apart, \
				 so it needs at least two"
			}
			_ => {
				"equivalence asks whether two values resolve to the same thing, \
				 so it needs at least two"
			}
		})
		.help(format!("write it as `{}? a, b`", kind)));
	}
	for (i, c) in query.constants.iter().enumerate() {
		if km.index_of(c).is_none() {
			return Err(unknown_constant(
				&c.name,
				km,
				"not declared by any principal".to_string(),
			));
		}
		if find_equivalent_constant(c, &query.constants[..i]).is_some() {
			return Err(VerifpalError::sanity(
				format!("`{}` is named twice in this {} query", c, kind).into(),
			)
			.narrow_occurrence(
				c.name.to_string(),
				query.constants[..i]
					.iter()
					.filter(|prior| prior.name == c.name)
					.count(),
			)
			.labelled("named again here")
			.note(format!(
				"a value is always {} itself, so the comparison would be trivially true",
				if kind == "equivalence" {
					"equivalent to"
				} else {
					"linkable to"
				}
			))
			.help("name a different constant here"));
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
							"precondition names {} constants, but describes one message",
							option.message.constants.len()
						)
						.into(),
					)
					.note(
						"a precondition annotates a failing query with one message that still went out",
					)
					.help("write it as `precondition[ Bob -> Alice: ack ]`"));
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
				"{} both sends and receives this message",
				message.sender_name
			)
			.into(),
		)
		.note("a message travels between two different principals")
		.help(format!(
			"name the other principal as the recipient, e.g. \
			 `{} -> Bob: {}`",
			message.sender_name,
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
	let idx = match km.index_of(c) {
		Some(idx) => idx,
		None => {
			return Err(unknown_constant(
				&c.name,
				km,
				"not declared by any principal".to_string(),
			));
		}
	};
	let sender_knows = km.slots[idx].known_by_principal(m.sender);
	let recipient_knows = km.slots[idx].known_by_principal(m.recipient);
	let used = km.constant_used_by(m.recipient, c);
	let _ = query;
	if !sender_knows {
		return Err(
			VerifpalError::sanity(format!("{} never knows `{}`", m.sender_name, c).into())
				.narrow(c.name.to_string())
				.note(format!(
					"this query claims {} is the true origin of `{}`, but {} never \
			 declares, generates, computes or receives it",
					m.sender_name, c, m.sender_name
				))
				.help("name the principal that actually produces this value as the sender"),
		);
	}
	if !recipient_knows {
		return Err(VerifpalError::sanity(
			format!("{} never receives `{}`", m.recipient_name, c).into(),
		)
		.narrow(c.name.to_string())
		.note(format!(
			"authentication asks whether {} can be fooled about who sent `{}`, \
			 which only means something if `{}` reaches {}",
			m.recipient_name, c, c, m.recipient_name
		))
		.help(format!(
			"add a message carrying `{}` to {}, or query the principal that does receive it",
			c, m.recipient_name
		)));
	}
	if !used {
		return Err(VerifpalError::sanity(
			format!("{} receives `{}` but never uses it", m.recipient_name, c).into(),
		)
		.narrow(c.name.to_string())
		.note(format!(
			"a principal only commits to a received value by computing with it; \
			 {} stores `{}` and never passes it to a primitive, so there is no \
			 authentication to break",
			m.recipient_name, c
		))
		.help(format!(
			"have {} check or use `{}`, for example inside an `AEAD_DEC(…)?` or `SIGNVERIF(…)?`",
			m.recipient_name, c
		)));
	}
	Ok(())
}

fn sanity_declared_principals(m: &Model) -> VResult<(Vec<String>, Vec<PrincipalId>)> {
	let mut declared_names: Vec<String> = vec![];
	let mut declared_ids: Vec<PrincipalId> = vec![];
	let mut principals: Vec<PrincipalId> = vec![];
	let mut seen_names: Vec<(PrincipalId, String, Span)> = vec![];
	for block in &m.blocks {
		if let Block::Principal(p) = block {
			seen_names.push((p.id, p.name.clone(), p.span));
			append_unique(&mut principals, p.id);
			append_unique(&mut declared_names, p.name.clone());
			append_unique(&mut declared_ids, p.id);
		}
	}
	for block in &m.blocks {
		if let Block::Message(msg) = block {
			seen_names.push((msg.sender, msg.sender_name.to_string(), msg.span));
			seen_names.push((msg.recipient, msg.recipient_name.to_string(), msg.span));
			append_unique(&mut principals, msg.sender);
			append_unique(&mut principals, msg.recipient);
		}
	}
	for query in &m.queries {
		if query.kind == QueryKind::Authentication {
			seen_names.push((
				query.message.sender,
				query.message.sender_name.to_string(),
				query.span,
			));
			seen_names.push((
				query.message.recipient,
				query.message.recipient_name.to_string(),
				query.span,
			));
			append_unique(&mut principals, query.message.sender);
			append_unique(&mut principals, query.message.recipient);
		}
	}
	for &p in &principals {
		if !declared_ids.contains(&p) {
			let (name, span) = seen_names
				.iter()
				.find(|(id, _, _)| *id == p)
				.map(|(_, name, span)| (base_name(name).to_string(), *span))
				.unwrap_or_default();
			let declared: Vec<&str> = declared_names
				.iter()
				.map(|n| base_name(n))
				.collect::<std::collections::BTreeSet<&str>>()
				.into_iter()
				.collect();
			return Err(VerifpalError::sanity(
				format!("`{}` is never declared as a principal", name).into(),
			)
			.at(span)
			.narrow(name.clone())
			.labelled("no block declares this principal")
			.note(format!(
				"this model declares {}",
				quoted_list(
					&declared
						.iter()
						.map(|n| (*n).to_string())
						.collect::<Vec<String>>()
				)
			))
			.help(format!(
				"add a block for it, e.g. `principal {}[ … ]`",
				name
			))
			.suggest(did_you_mean(&name, declared)));
		}
	}
	if declared_names.len() > MAX_PRINCIPALS {
		return Err(VerifpalError::sanity(
			format!(
				"this model declares {} principals, and the limit is {}",
				declared_names.len(),
				MAX_PRINCIPALS
			)
			.into(),
		)
		.note(
			"the limit is not a representation limit; a model with this many \
			 principals is far more likely to have been generated by accident \
			 than written on purpose",
		));
	}
	Ok((declared_names, declared_ids))
}

/// A guard against a model that is a mistake rather than a protocol.
///
/// It is not a representation limit: `PrincipalId` is a `u8` and nothing packs
/// principals into a word. It has no semantic content either, and the semantics
/// in the paper do not mention it — a model with a hundred principals would be
/// analyzed exactly as one with ten, only slower. It exists because a model that
/// declares this many principals is far more likely to be generated by accident
/// than written on purpose.
pub(crate) const MAX_PRINCIPALS: usize = 128;

pub(crate) fn sanity_fail_on_failed_checked_primitive_rewrite(
	failures: &[(Primitive, usize)],
) -> VResult<()> {
	for (p, _) in failures {
		if p.instance_check {
			return Err(VerifpalError::sanity(
				format!("`{}` cannot succeed as written", primitive_name(p.id)).into(),
			)
			.narrow(primitive_name(p.id))
			.labelled("this check fails in the honest run")
			.note(format!(
				"`{}` is checked with `?`, so the principal halts when it fails; \
				 here it fails even with no attacker, which makes the model \
				 describe a protocol that never completes",
				p
			))
			.help(
				"check that the key, message and any additional data match what \
				 the other principal used",
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
				return Err(VerifpalError::sanity(
					format!(
						"`{}` produces more than one output, so it cannot be an \
						 argument to `{}`",
						primitive_name(arg_prim.id),
						primitive_name(p.id)
					)
					.into(),
				)
				.narrow(primitive_name(arg_prim.id))
				.note(format!(
					"`{}` has to be bound first, so that each of its outputs has a name",
					primitive_name(arg_prim.id)
				))
				.help(format!(
					"assign it on its own line, e.g. `{} = {}` and then pass those names",
					(0..*output.first().unwrap_or(&1))
						.map(|i| format!("out{}", i + 1))
						.collect::<Vec<String>>()
						.join(", "),
					arg_prim
				)));
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
					"`{}` cannot take `{}` as its {} argument",
					primitive_name(p.id),
					primitive_name(inner.id),
					ordinal(*position + 1)
				)
				.into(),
			)
			.narrow(primitive_name(inner.id))
			.note(restriction_note(p.id, inner.id, *position))
			.help(format!(
				"pass a value the principal holds directly; the signature is `{}`",
				primitive_signature(p.id)
			)));
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
