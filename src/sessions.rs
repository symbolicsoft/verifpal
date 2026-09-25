/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! Session expansion: `--sessions k` analyzes a model as if every principal
//! ran k interleaved sessions.
//!
//! The mechanism is deliberately dumb: sessions are cloned principals,
//! produced at the parsed-`Model` level before `sanity` ever runs. This
//! automates the workaround modelers already use — writing `Alice2` with
//! `na2` by hand — which is also the soundness argument: the expanded model
//! is an ordinary Verifpal model the user could have written, `sanity`
//! re-validates all of it, and everything downstream is the unchanged
//! engine. A report about the expanded model is a report about a legal
//! model; the feature inherits the engine's attack-soundness wholesale.
//!
//! The freshening rule is derived from syntax the language already has:
//! `generates` constants and assignment outputs are per-session (renamed
//! `c#s`, rebanded per [`COPY_BASE`]), while `knows
//! public|private` constants are shared — exactly the
//! long-term/per-session split `new` vs free names encodes in other tools.
//! Guards stay session-pinned: `[c]` in session s protects that session's
//! delivery only, the conservative reading under attack-soundness.
//!
//! Clones are emitted *in place* (each block followed by its session
//! copies). No generality is lost to this lockstep layout: within a phase
//! the attacker's knowledge is atemporal — `attacker_phase_update` seeds
//! every reached wire value up front — so relative block order never
//! constrains which session's traffic can be routed into which. Phase
//! blocks stay single; sessions run inside the same phase structure.
//!
//! The user's queries are kept verbatim (session 1 is the unrenamed
//! original) and each also receives per-session *variants* — the same query
//! mapped into session s — which resolve the original query index, so
//! result codes keep one entry per written query and an attack on any
//! session resolves it. Variants that map to themselves (all-shared
//! constants, no principals) are dropped.

use std::sync::Arc;

use crate::info::info_message;
use crate::sanity::MAX_PRINCIPALS;
use crate::types::*;
use crate::value::{copy_index_of, copy_value_id};
use crate::verify::Expansion;

pub(crate) const MAX_SESSIONS: u8 = 16;

pub(crate) const DEFAULT_SESSIONS: u8 = 2;

pub(crate) fn expand_sessions(mut e: Expansion, sessions: u8) -> VResult<Expansion> {
	if !(2..=MAX_SESSIONS).contains(&sessions) {
		return Err(VerifpalError::sanity(
			format!("session expansion supports 2 to {MAX_SESSIONS} sessions").into(),
		));
	}
	let m = &e.model;
	let principals = m.declared_principals();
	let expanded_count = principals.len() * sessions as usize;
	if expanded_count > MAX_PRINCIPALS {
		return Err(VerifpalError::sanity(
			format!(
				"model declares {} principals; --sessions {} would analyze {}, \
				 which exceeds the {}-principal cap",
				principals.len(),
				sessions,
				expanded_count,
				MAX_PRINCIPALS
			)
			.into(),
		)
		.note("session expansion clones every principal once per session")
		.help(format!(
			"analyze it with `--sessions {}` or fewer",
			(MAX_PRINCIPALS / principals.len().max(1)).max(1)
		)));
	}

	let freshen = m.freshened_constants();
	let copies = ModelCopy::numbered(
		m,
		&freshen,
		(2..=sessions).map(|s| (format!("#{s}"), s as u32 - 1)),
		"session",
	)?;

	let mut blocks: Vec<Block> = Vec::with_capacity(m.blocks.len() * sessions as usize);
	for block in &m.blocks {
		blocks.push(block.clone());
		match block {
			Block::Principal(p) => {
				blocks.extend(
					copies
						.iter()
						.map(|copy| Block::Principal(copy.principal(p))),
				);
			}
			Block::Message(msg) => {
				blocks.extend(copies.iter().map(|copy| Block::Message(copy.message(msg))));
			}
			Block::Phase(_) => {}
		}
	}

	let mut query_variants: Vec<Vec<Query>> = Vec::with_capacity(m.queries.len());
	for (i, query) in m.queries.iter().enumerate() {
		let scenarios: &[Query] = e.variants.get(i).map(Vec::as_slice).unwrap_or(&[]);
		let mut variants: Vec<Query> = scenarios.to_vec();
		for seed in std::iter::once(query).chain(scenarios.iter()) {
			for copy in &copies {
				let variant = copy.query(seed);
				if !seed.same_shape(&variant) && !variants.iter().any(|v| v.same_shape(&variant)) {
					variants.push(variant);
				}
			}
		}
		query_variants.push(variants);
	}

	let mut siblings: IdMap<ValueId, Arc<Vec<ValueId>>> = IdMap::default();
	for &base in &freshen {
		let group: Arc<Vec<ValueId>> = Arc::new(
			std::iter::once(base)
				.chain(copies.iter().map(|copy| copy.value_id(base)))
				.collect(),
		);
		for &member in group.iter() {
			siblings.insert(member, Arc::clone(&group));
		}
	}

	let naming = if sessions == 2 {
		"suffixed #2".to_string()
	} else {
		format!("suffixed #2 through #{sessions}")
	};
	info_message(
		&format!(
			"Analyzing {sessions} parallel sessions per principal; \
			 per-session values and principals are {naming}.",
		),
		InfoLevel::Info,
	);

	for (&original, &(clone, _)) in copies.iter().flat_map(|copy| copy.principals.iter()) {
		if let Some(corrupt_from) = e.corrupt_from.as_mut()
			&& let Some(&from) = corrupt_from.get(&original)
		{
			corrupt_from.insert(clone, from);
		}
		let canonical = e
			.interchangeable
			.get(&original)
			.copied()
			.unwrap_or(original);
		e.interchangeable.insert(clone, canonical);
		e.interchangeable.entry(original).or_insert(canonical);
		let actor = e.actors.get(&original).copied().unwrap_or(original);
		e.actors.insert(clone, actor);
		e.actors.entry(original).or_insert(actor);
	}
	e.model.blocks = blocks;
	e.variants = query_variants;
	e.siblings = siblings;
	Ok(e)
}

pub(crate) struct ModelCopy<'a> {
	freshen: &'a IdSet<ValueId>,
	suffix: String,
	offset: u32,
	principals: IdMap<PrincipalId, (PrincipalId, String)>,
}

impl<'a> ModelCopy<'a> {
	pub(crate) fn original(freshen: &'a IdSet<ValueId>) -> Self {
		ModelCopy {
			freshen,
			suffix: String::new(),
			offset: 0,
			principals: IdMap::default(),
		}
	}

	pub(crate) fn numbered(
		m: &Model,
		freshen: &'a IdSet<ValueId>,
		labels: impl Iterator<Item = (String, u32)>,
		expansion: &str,
	) -> VResult<Vec<Self>> {
		let principals = m.declared_principals();
		let mut next = m.highest_referenced_principal();
		labels
			.map(|(suffix, offset)| {
				let principals = principals
					.iter()
					.map(|(id, name)| {
						next = next.checked_add(1).ok_or_else(|| {
							VerifpalError::internal(
								format!("{expansion} expansion exhausted principal ids").into(),
							)
						})?;
						Ok((*id, (next, format!("{name}{suffix}"))))
					})
					.collect::<VResult<_>>()?;
				Ok(ModelCopy {
					freshen,
					suffix,
					offset,
					principals,
				})
			})
			.collect()
	}

	pub(crate) fn principal_id(&self, id: PrincipalId) -> PrincipalId {
		self.principals.get(&id).map_or(id, |&(copy, _)| copy)
	}

	fn value_id(&self, id: ValueId) -> ValueId {
		let (copy, root) = copy_index_of(id);
		copy_value_id(root, copy + self.offset)
	}

	fn constant(&self, c: &Constant) -> Constant {
		if self.offset == 0 || !self.freshen.contains(&c.id) {
			return c.clone();
		}
		Constant {
			name: Arc::from(format!("{}{}", c.name, self.suffix)),
			id: self.value_id(c.id),
			..c.clone()
		}
	}

	fn rename(&self, constants: &mut [Constant]) {
		for c in constants {
			*c = self.constant(c);
		}
	}

	fn readdress(&self, msg: &mut Message) {
		if let Some((id, name)) = self.principals.get(&msg.sender) {
			msg.sender = *id;
			msg.sender_name = Arc::from(name.as_str());
		}
		if let Some((id, name)) = self.principals.get(&msg.recipient) {
			msg.recipient = *id;
			msg.recipient_name = Arc::from(name.as_str());
		}
		self.rename(&mut msg.constants);
	}

	pub(crate) fn principal(&self, p: &Principal) -> Principal {
		let mut copy = p.clone();
		if let Some((id, name)) = self.principals.get(&p.id) {
			copy.id = *id;
			copy.name = name.clone();
		}
		for expr in &mut copy.expressions {
			self.rename(&mut expr.constants);
			if let Some(value) = &mut expr.assigned {
				*value = map_constants(value, &|c| self.constant(c));
			}
		}
		copy
	}

	pub(crate) fn message(&self, msg: &Message) -> Message {
		let mut copy = msg.clone();
		self.readdress(&mut copy);
		copy
	}

	pub(crate) fn query(&self, q: &Query) -> Query {
		let mut copy = q.clone();
		self.rename(&mut copy.constants);
		self.readdress(&mut copy.message);
		for option in &mut copy.options {
			self.readdress(&mut option.message);
		}
		copy
	}
}

pub(crate) fn map_constants(v: &Value, f: &impl Fn(&Constant) -> Constant) -> Value {
	match v {
		Value::Constant(c) => Value::Constant(f(c)),
		Value::Primitive(p) => Value::Primitive(Arc::new(
			p.with_arguments(p.arguments.iter().map(|a| map_constants(a, f)).collect()),
		)),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::parser::parse_string;
	use crate::value::COPY_BASE;

	const SRC: &str = "attacker[active]\n\
		principal Alice[\n\
		knows private psk\n\
		generates na\n\
		se_e1 = ENC(psk, na)\n\
		]\n\
		Alice -> Bob: [se_e1]\n\
		principal Bob[\n\
		knows private psk\n\
		se_nb = DEC(psk, se_e1)\n\
		]\n\
		queries[\n\
		confidentiality? psk\n\
		confidentiality? na\n\
		authentication? Alice -> Bob: se_e1\n\
		]\n";

	fn expanded() -> Expansion {
		let m = parse_string("sessions.vp", SRC).expect("parse");
		crate::verify::expand(&m, 2).expect("expand")
	}

	fn principal<'e>(e: &'e Expansion, name: &str) -> &'e Principal {
		e.model
			.blocks
			.iter()
			.find_map(|b| match b {
				Block::Principal(p) if p.name == name => Some(p),
				_ => None,
			})
			.unwrap_or_else(|| panic!("no principal named {name}"))
	}

	#[test]
	fn expansion_duplicates_principals_and_messages_in_place() {
		let e = expanded();
		let names: Vec<&str> = e
			.model
			.blocks
			.iter()
			.filter_map(|b| match b {
				Block::Principal(p) => Some(p.name.as_str()),
				_ => None,
			})
			.collect();
		assert_eq!(names, ["Alice", "Alice#2", "Bob", "Bob#2"]);
		let messages: Vec<(&str, &str)> = e
			.model
			.blocks
			.iter()
			.filter_map(|b| match b {
				Block::Message(m) => Some((&*m.sender_name, &*m.recipient_name)),
				_ => None,
			})
			.collect();
		assert_eq!(messages, [("Alice", "Bob"), ("Alice#2", "Bob#2")]);
		assert_eq!(e.model.queries.len(), 3, "originals kept verbatim");
	}

	#[test]
	fn generates_and_assignments_freshen_while_knows_is_shared() {
		let e = expanded();
		let alice = principal(&e, "Alice");
		let clone = principal(&e, "Alice#2");
		assert_ne!(alice.id, clone.id);
		for (expr, cexpr) in alice.expressions.iter().zip(&clone.expressions) {
			match expr.kind {
				Declaration::Knows => {
					assert_eq!(expr.constants[0].id, cexpr.constants[0].id);
					assert_eq!(&*cexpr.constants[0].name, "psk");
				}
				Declaration::Generates => {
					assert_eq!(cexpr.constants[0].id, COPY_BASE + expr.constants[0].id);
					assert_eq!(&*cexpr.constants[0].name, "na#2");
					assert!(cexpr.constants[0].fresh || !expr.constants[0].fresh);
				}
				Declaration::Assignment => {
					assert_eq!(cexpr.constants[0].id, COPY_BASE + expr.constants[0].id);
					let Some(Value::Primitive(p)) = &cexpr.assigned else {
						panic!("assignment lost its value");
					};
					let Value::Constant(key) = &p.arguments[0] else {
						panic!("ENC key inlined unexpectedly");
					};
					assert_eq!(&*key.name, "psk", "shared key stays shared inside terms");
					let Value::Constant(nonce) = &p.arguments[1] else {
						panic!("ENC plaintext inlined unexpectedly");
					};
					assert_eq!(&*nonce.name, "na#2");
				}
				Declaration::Leaks => {}
			}
		}
	}

	#[test]
	fn guards_survive_cloning() {
		let e = expanded();
		let clone_msg = e
			.model
			.blocks
			.iter()
			.find_map(|b| match b {
				Block::Message(m) if &*m.sender_name == "Alice#2" => Some(m),
				_ => None,
			})
			.expect("clone message");
		assert!(clone_msg.constants[0].guard);
		assert_eq!(&*clone_msg.constants[0].name, "se_e1#2");
	}

	#[test]
	fn expanded_model_and_variants_pass_sanity() {
		let e = expanded();
		crate::sanity::sanity(&e.model).expect("expanded model is a legal model");
		let mut with_variants = e.model.clone();
		with_variants.queries = e.variants.concat();
		crate::sanity::sanity(&with_variants).expect("variants are legal queries");
	}

	#[test]
	fn variants_map_sessions_and_drop_identities() {
		let e = expanded();
		assert!(
			e.variants[0].is_empty(),
			"confidentiality? psk is all-shared: no variant"
		);
		assert_eq!(e.variants[1].len(), 1);
		assert_eq!(&*e.variants[1][0].constants[0].name, "na#2");
		assert_eq!(e.variants[2].len(), 1);
		let auth = &e.variants[2][0];
		assert_eq!(&*auth.message.sender_name, "Alice#2");
		assert_eq!(&*auth.message.recipient_name, "Bob#2");
		assert_eq!(&*auth.message.constants[0].name, "se_e1#2");
	}

	#[test]
	fn siblings_group_every_member_together() {
		let e = expanded();
		let m = parse_string("sessions.vp", SRC).expect("parse");
		let na_id = m
			.blocks
			.iter()
			.find_map(|b| match b {
				Block::Principal(p) => p
					.expressions
					.iter()
					.find(|x| x.kind == Declaration::Generates)
					.map(|x| x.constants[0].id),
				_ => None,
			})
			.expect("na");
		let group = e.siblings.get(&na_id).expect("group for na");
		assert_eq!(group.len(), 2);
		let clone_id = COPY_BASE + na_id;
		assert!(Arc::ptr_eq(
			group,
			e.siblings.get(&clone_id).expect("clone")
		));
	}

	#[test]
	fn principal_cap_is_enforced_with_a_sessions_message() {
		let mut src = String::from("attacker[active]\n");
		for i in 0..65 {
			src += &format!(
				"principal Cap{i}[\nknows private cap_s{i}\ncap_h{i} = HASH(cap_s{i})\n]\n"
			);
		}
		src += "queries[\nconfidentiality? cap_s0\n]\n";
		let m = parse_string("cap.vp", &src).expect("parse");
		let Err(err) = crate::verify::expand(&m, 2) else {
			panic!("65 * 2 > 128");
		};
		assert!(format!("{err}").contains("--sessions"));
	}
}
