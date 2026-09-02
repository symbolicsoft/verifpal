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
//! public|private|password` constants are shared — exactly the
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

use std::collections::HashMap;
use std::sync::Arc;

use crate::info::info_message;
use crate::sanity::MAX_PRINCIPALS;
use crate::types::*;
use crate::value::{copy_index_of, copy_value_id};

/// Sessions are one axis of the expansion-copy id space `value.rs` bands, and
/// scenarios are the other: [`crate::value::MAX_COPIES`] bounds their product,
/// so raising this past 16 means checking that bound, not this one.
pub(crate) const MAX_SESSIONS: u8 = 16;

/// Sessions analyzed per principal when nothing says otherwise.
///
/// Two, not one: concurrency is what deployment looks like, and a single
/// session cannot express an attack that needs two of a role's fresh values
/// to coexist at all — the tool would not be *failing* to find those attacks
/// so much as unable to state them. Two is where that class starts, and it
/// is enough for the ones that show up in practice (nonce swaps, oracle
/// interleavings, reflections between role instances). It costs roughly 4x;
/// `--sessions 1` buys that back where a model is large enough to care, and
/// higher counts are available for deeper coverage.
///
/// This is still a bound, not a proof: passing at k sessions means no attack
/// was found within k, never that none exists.
pub(crate) const DEFAULT_SESSIONS: u8 = 2;

#[derive(Debug)]
pub(crate) struct SessionExpansion {
	pub(crate) model: Model,
	pub(crate) query_variants: Vec<Vec<Query>>,
	pub(crate) siblings: IdMap<ValueId, Arc<Vec<ValueId>>>,
	pub(crate) principal_clones: Vec<(PrincipalId, PrincipalId)>,
}

fn session_value_id(base: ValueId, s: u8) -> ValueId {
	let (scenario_copy, root) = copy_index_of(base);
	copy_value_id(root, scenario_copy + s as u32 - 1)
}

pub(crate) fn expand_sessions(
	m: &Model,
	sessions: u8,
	seeded: &[Vec<Query>],
) -> VResult<SessionExpansion> {
	if !(2..=MAX_SESSIONS).contains(&sessions) {
		return Err(VerifpalError::sanity(
			format!("session expansion supports 2 to {MAX_SESSIONS} sessions").into(),
		));
	}
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
	let pids = clone_principal_ids(&principals, sessions, m.highest_referenced_principal())?;
	let principal_clones: Vec<(PrincipalId, PrincipalId)> = pids
		.iter()
		.map(|(&(original, _), (clone, _))| (original, *clone))
		.collect();

	let mut blocks: Vec<Block> = Vec::with_capacity(m.blocks.len() * sessions as usize);
	for block in &m.blocks {
		match block {
			Block::Principal(p) => {
				blocks.push(Block::Principal(p.clone()));
				for s in 2..=sessions {
					blocks.push(Block::Principal(clone_principal(p, s, &freshen, &pids)));
				}
			}
			Block::Message(msg) => {
				blocks.push(Block::Message(msg.clone()));
				for s in 2..=sessions {
					blocks.push(Block::Message(clone_message(msg, s, &freshen, &pids)));
				}
			}
			Block::Phase(p) => blocks.push(Block::Phase(p.clone())),
		}
	}

	let mut query_variants: Vec<Vec<Query>> = Vec::with_capacity(m.queries.len());
	for (i, query) in m.queries.iter().enumerate() {
		let scenarios: &[Query] = seeded.get(i).map(Vec::as_slice).unwrap_or(&[]);
		let mut variants: Vec<Query> = scenarios.to_vec();
		for seed in std::iter::once(query).chain(scenarios.iter()) {
			for s in 2..=sessions {
				let variant = clone_query(seed, s, &freshen, &pids);
				if !seed.same_shape(&variant) && !variants.iter().any(|v| v.same_shape(&variant)) {
					variants.push(variant);
				}
			}
		}
		query_variants.push(variants);
	}

	let mut siblings: IdMap<ValueId, Arc<Vec<ValueId>>> = IdMap::default();
	for &base in &freshen {
		let mut group = Vec::with_capacity(sessions as usize);
		group.push(base);
		for s in 2..=sessions {
			group.push(session_value_id(base, s));
		}
		let group = Arc::new(group);
		for &member in group.iter() {
			siblings.insert(member, Arc::clone(&group));
		}
	}

	let model = Model {
		blocks,
		..m.clone()
	};

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
		false,
	);

	Ok(SessionExpansion {
		model,
		query_variants,
		siblings,
		principal_clones,
	})
}

fn clone_principal_ids(
	principals: &[(PrincipalId, String)],
	sessions: u8,
	highest: PrincipalId,
) -> VResult<HashMap<(PrincipalId, u8), (PrincipalId, String)>> {
	let mut next = principals
		.iter()
		.map(|&(id, _)| id)
		.max()
		.unwrap_or(0)
		.max(highest);
	let mut out = HashMap::new();
	for s in 2..=sessions {
		for (id, name) in principals {
			next = next.checked_add(1).ok_or_else(|| {
				VerifpalError::internal("session expansion exhausted principal ids".into())
			})?;
			out.insert((*id, s), (next, format!("{name}#{s}")));
		}
	}
	Ok(out)
}

fn map_constant(c: &Constant, s: u8, freshen: &IdSet<ValueId>) -> Constant {
	if !freshen.contains(&c.id) {
		return c.clone();
	}
	Constant {
		name: Arc::from(format!("{}#{s}", c.name)),
		id: session_value_id(c.id, s),
		..c.clone()
	}
}

fn map_value(v: &Value, s: u8, freshen: &IdSet<ValueId>) -> Value {
	match v {
		Value::Constant(c) => Value::Constant(map_constant(c, s, freshen)),
		Value::Primitive(p) => {
			let arguments = p
				.arguments
				.iter()
				.map(|a| map_value(a, s, freshen))
				.collect();
			Value::Primitive(Arc::new(p.with_arguments(arguments)))
		}
	}
}

fn clone_principal(
	p: &Principal,
	s: u8,
	freshen: &IdSet<ValueId>,
	pids: &HashMap<(PrincipalId, u8), (PrincipalId, String)>,
) -> Principal {
	let (id, name) = pids
		.get(&(p.id, s))
		.cloned()
		.unwrap_or((p.id, p.name.clone()));
	Principal {
		name,
		id,
		span: p.span,
		expressions: p
			.expressions
			.iter()
			.map(|expr| Expression {
				span: expr.span,
				kind: expr.kind,
				qualifier: expr.qualifier,
				constants: expr
					.constants
					.iter()
					.map(|c| map_constant(c, s, freshen))
					.collect(),
				assigned: expr.assigned.as_ref().map(|v| map_value(v, s, freshen)),
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

fn clone_message(
	msg: &Message,
	s: u8,
	freshen: &IdSet<ValueId>,
	pids: &HashMap<(PrincipalId, u8), (PrincipalId, String)>,
) -> Message {
	let (sender, sender_name) = pids
		.get(&(msg.sender, s))
		.map(|(id, name)| (*id, Arc::<str>::from(name.as_str())))
		.unwrap_or((msg.sender, Arc::clone(&msg.sender_name)));
	let (recipient, recipient_name) = pids
		.get(&(msg.recipient, s))
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
			.map(|c| map_constant(c, s, freshen))
			.collect(),
		leading_comments: Vec::new(),
		trailing_comment: None,
	}
}

fn clone_query(
	q: &Query,
	s: u8,
	freshen: &IdSet<ValueId>,
	pids: &HashMap<(PrincipalId, u8), (PrincipalId, String)>,
) -> Query {
	Query {
		span: q.span,
		kind: q.kind,
		constants: q
			.constants
			.iter()
			.map(|c| map_constant(c, s, freshen))
			.collect(),
		message: clone_message(&q.message, s, freshen, pids),
		options: q
			.options
			.iter()
			.map(|o| QueryOption {
				kind: o.kind,
				message: clone_message(&o.message, s, freshen, pids),
				leading_comments: Vec::new(),
				trailing_comment: None,
			})
			.collect(),
		leading_comments: Vec::new(),
		trailing_comment: None,
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

	fn expanded() -> SessionExpansion {
		let m = parse_string("sessions.vp", SRC).expect("parse");
		expand_sessions(&m, 2, &[]).expect("expand")
	}

	fn principal<'e>(e: &'e SessionExpansion, name: &str) -> &'e Principal {
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
		with_variants.queries = e.query_variants.concat();
		crate::sanity::sanity(&with_variants).expect("variants are legal queries");
	}

	#[test]
	fn variants_map_sessions_and_drop_identities() {
		let e = expanded();
		assert!(
			e.query_variants[0].is_empty(),
			"confidentiality? psk is all-shared: no variant"
		);
		assert_eq!(e.query_variants[1].len(), 1);
		assert_eq!(&*e.query_variants[1][0].constants[0].name, "na#2");
		assert_eq!(e.query_variants[2].len(), 1);
		let auth = &e.query_variants[2][0];
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
		let clone_id = session_value_id(na_id, 2);
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
		let err = expand_sessions(&m, 2, &[]).expect_err("65 * 2 > 128");
		assert!(format!("{err}").contains("--sessions"));
	}
}
