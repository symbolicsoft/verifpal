/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use super::ProtocolTrace;
use crate::syntax::{Block, LineComments, Message, Model, Query, QueryKind, Span};
use crate::term::Constant;

pub(crate) fn auto_queries(m: &Model, km: &ProtocolTrace) -> Vec<Query> {
	let mut out: Vec<Query> = secret_constants(m)
		.into_iter()
		.filter(|c| km.index_of(c).is_some() && !c.is_nil())
		.map(|c| generated(QueryKind::Confidentiality, vec![c], Message::default()))
		.collect();
	for slot in &km.slots {
		for &(recipient, sender) in &slot.known_by {
			if sender == recipient
				|| slot.constant.is_nil()
				|| !slot.known_by_principal(sender)
				|| !slot.known_by_principal(recipient)
				|| !crate::protocol::trace::principal_uses_constant(km, recipient, &slot.constant)
			{
				continue;
			}
			out.push(generated(
				QueryKind::Authentication,
				Vec::new(),
				Message {
					sender,
					sender_name: km.principal_name(sender).into(),
					recipient,
					recipient_name: km.principal_name(recipient).into(),
					constants: vec![slot.constant.clone()],
					..Message::default()
				},
			));
		}
	}
	for slot in &km.slots {
		if slot.sent_by.is_empty()
			|| slot.constant.is_nil()
			|| !crate::protocol::trace::constant_used_by_any_principal(km, &slot.constant)
		{
			continue;
		}
		out.push(generated(
			QueryKind::Freshness,
			vec![slot.constant.clone()],
			Message::default(),
		));
	}
	out
}

fn secret_constants(m: &Model) -> Vec<Constant> {
	let mut out: Vec<Constant> = Vec::new();
	for block in &m.blocks {
		let Block::Principal(p) = block else {
			continue;
		};
		for expression in p.expressions.iter().filter(|e| e.declares_secret()) {
			for c in &expression.constants {
				if super::scenario::keeps(m, p.id, c.id)
					&& !out.iter().any(|prior| prior.id == c.id)
				{
					out.push(c.clone());
				}
			}
		}
	}
	out
}

fn generated(kind: QueryKind, constants: Vec<Constant>, message: Message) -> Query {
	Query {
		span: Span::default(),
		kind,
		constants,
		message,
		options: Vec::new(),
		comments: LineComments::default(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn model_and_trace(path: &str) -> (Model, ProtocolTrace) {
		let m = crate::syntax::parser::parse_file(path).expect("parses");
		let km = crate::protocol::sanity::sanity(&m).expect("sane");
		(m, km)
	}

	#[test]
	fn every_secret_constant_gets_a_confidentiality_query() {
		let (m, km) = model_and_trace("examples/test/hmac_ok.vp");
		let queries = auto_queries(&m, &km);
		assert!(
			queries.iter().any(|q| q.kind == QueryKind::Confidentiality),
			"expected at least one confidentiality query"
		);
	}

	#[test]
	fn generated_queries_all_pass_sanity() {
		let mut checked = 0;
		for entry in std::fs::read_dir("examples/test").expect("reads examples/test") {
			let path = entry.expect("entry").path();
			if path.extension().and_then(|e| e.to_str()) != Some("vp") {
				continue;
			}
			let display = path.display().to_string();
			let Ok(mut m) = crate::syntax::parser::parse_file(&display) else {
				continue;
			};
			let Ok(km) = crate::protocol::sanity::sanity(&m) else {
				continue;
			};
			m.queries = auto_queries(&m, &km);
			crate::protocol::sanity::sanity(&m).unwrap_or_else(|e| {
				panic!("generated queries must pass sanity for {display}: {e}")
			});
			checked += 1;
		}
		assert!(checked > 300, "expected the corpus sweep, got {checked}");
	}

	#[test]
	fn an_auto_query_set_asks_more_than_the_model_wrote() {
		let (m, km) = model_and_trace("examples/test/hmac_ok.vp");
		let written = m.queries.len();
		let generated = auto_queries(&m, &km).len();
		assert!(
			generated > written,
			"auto queries ({generated}) should exceed the {written} written by hand"
		);
	}

	fn asked(source: &str) -> Vec<String> {
		let m = crate::syntax::parser::parse_string("aq.vp", source).expect("parses");
		let km = crate::protocol::sanity::sanity(&m).expect("sane");
		auto_queries(&m, &km)
			.iter()
			.filter(|q| q.kind == QueryKind::Confidentiality)
			.map(|q| q.constants[0].name.to_string())
			.collect()
	}

	const PEERS: &str = "attacker[active]\n\
		principal Bob[\n\
		knows private aq_b\n\
		aq_gb = PUBKEY(aq_b)\n\
		]\n\
		principal Mallory[\n\
		knows private aq_x\n\
		aq_gx = PUBKEY(aq_x)\n\
		leaks aq_x\n\
		]\n\
		Bob -> Alice: [aq_gb]\n\
		Mallory -> Alice: [aq_gx]\n\
		principal Alice[\n\
		knows private aq_peer, aq_m\n\
		aq_e = PKE_ENC(aq_peer, aq_m)\n\
		]\n\
		Alice -> Bob: aq_e\n";

	#[test]
	fn a_scenario_target_is_asked_about_wherever_a_copy_still_holds_it() {
		let every = |scenarios: &str| {
			asked(&format!(
				"{PEERS}scenarios[{scenarios}]\nqueries[\nconfidentiality? aq_m\n]\n"
			))
		};
		assert_eq!(
			every("Alice[aq_peer = aq_gb] Alice[aq_peer = aq_gx]"),
			["aq_b", "aq_x", "aq_m"],
			"a placeholder every copy of its holder rebinds is in no copy, and a query on \
			 it would not pass sanity"
		);
		assert_eq!(
			every("Alice[aq_peer = aq_gb] Bob[aq_b = aq_b]"),
			["aq_b", "aq_x", "aq_peer", "aq_m"],
			"an identity binding rebinds nothing, and Bob's scenario leaves Alice's \
			 placeholder in place"
		);
		assert_eq!(
			every("Alice[aq_peer = aq_peer]"),
			["aq_b", "aq_x", "aq_peer", "aq_m"]
		);
	}

	#[test]
	fn generated_queries_cover_what_the_written_ones_find_under_scenarios() {
		for model in [
			"auto_queries_identity_scenario.vp",
			"auto_queries_shared_rebound.vp",
		] {
			let path = format!("examples/test/{model}");
			for sessions in [1, 2] {
				let (_, written) =
					crate::verify::verify_with_sessions(&path, sessions).expect("verifies");
				assert_eq!(written, "c1", "{model} at {sessions}");
				let (results, _) =
					crate::verify::verify_auto_queries(&path, sessions).expect("verifies");
				let secret = results
					.iter()
					.find(|r| r.query.to_string() == "confidentiality? secret")
					.unwrap_or_else(|| panic!("{model}: no generated query asks about secret"));
				assert!(
					secret.resolved,
					"{model} at {sessions}: the leaked secret must be found disclosed"
				);
			}
			let m = crate::syntax::parser::parse_file(&path).expect("parses");
			let without = crate::syntax::Model {
				scenarios: Vec::new(),
				..m.clone()
			};
			let generated = |m: &Model| {
				let km = crate::protocol::sanity::sanity(m).expect("sane");
				let mut queries: Vec<String> = auto_queries(m, &km)
					.iter()
					.map(ToString::to_string)
					.collect();
				queries.sort();
				queries
			};
			assert_eq!(
				generated(&m),
				generated(&without),
				"{model}: every secret survives the binding"
			);
		}
	}
}
