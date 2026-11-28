/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::atomic::AtomicBool;

use super::TraceSlot;
use super::sanity::sanity;
use super::scenario::expand_scenarios;
use super::trace::principal_uses_constant;
use crate::syntax::{
	Block, LineComments, Message, Model, PrincipalId, Query, QueryKind, Span, VResult,
};
use crate::term::{Constant, copy_index_of};
use crate::util::collections::append_unique;

pub(crate) fn auto_queries(m: &Model) -> VResult<Vec<Query>> {
	let _generation = crate::util::generation::GenerationGuard::enter();
	let e = expand_scenarios(m, 1, &AtomicBool::new(false))?;
	let km = sanity(&e.model)?;
	let actor = |p: PrincipalId| e.actors.get(&p).copied().unwrap_or(p);
	let uses = |p: PrincipalId, slot: &TraceSlot| {
		e.answers(p) && principal_uses_constant(&km, p, &slot.constant)
	};
	let written = || {
		km.slots
			.iter()
			.filter(|slot| !slot.constant.is_nil() && copy_index_of(slot.constant.id).0 == 0)
	};
	let copies = |slot: &TraceSlot| {
		let written = slot.constant.id;
		km.slots
			.iter()
			.filter(move |copy| copy_index_of(copy.constant.id).1 == written)
	};
	let mut out: Vec<Query> = secret_constants(m)
		.into_iter()
		.filter(|c| km.index_of(c).is_some() && !c.is_nil())
		.map(|c| generated(QueryKind::Confidentiality, vec![c], Message::default()))
		.collect();
	for slot in written() {
		let mut deliveries: Vec<(PrincipalId, PrincipalId)> = Vec::new();
		for &(recipient, sender) in &slot.known_by {
			if sender != recipient {
				append_unique(&mut deliveries, (actor(recipient), actor(sender)));
			}
		}
		for (recipient, sender) in deliveries {
			let used = copies(slot).any(|copy| {
				copy.known_by.iter().any(|&(to, from)| {
					to != from && actor(to) == recipient && actor(from) == sender && uses(to, copy)
				})
			});
			if !used {
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
	for slot in written() {
		if !slot.sent_by.is_empty()
			&& copies(slot).any(|copy| km.principal_ids.iter().any(|&p| uses(p, copy)))
		{
			out.push(generated(
				QueryKind::Freshness,
				vec![slot.constant.clone()],
				Message::default(),
			));
		}
	}
	Ok(out)
}

fn secret_constants(m: &Model) -> Vec<Constant> {
	let mut out: Vec<Constant> = Vec::new();
	for block in &m.blocks {
		let Block::Principal(p) = block else {
			continue;
		};
		for expression in p.expressions.iter().filter(|e| e.declares_secret()) {
			for c in &expression.constants {
				if !out.iter().any(|prior| prior.id == c.id) {
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

	fn parsed(path: &str) -> Model {
		crate::syntax::parser::parse_file(path).expect("parses")
	}

	fn asked(m: &Model) -> Vec<String> {
		auto_queries(m)
			.expect("generates")
			.iter()
			.map(ToString::to_string)
			.collect()
	}

	#[test]
	fn every_secret_constant_gets_a_confidentiality_query() {
		let queries = auto_queries(&parsed("examples/test/hmac_ok.vp")).expect("generates");
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
			let Ok(queries) = auto_queries(&m) else {
				continue;
			};
			m.queries = queries;
			for sessions in [1, 2] {
				crate::verify::expand(&m, sessions, &AtomicBool::new(false))
					.and_then(|e| sanity(&e.model))
					.unwrap_or_else(|e| {
						panic!("generated queries must pass sanity for {display}: {e}")
					});
			}
			checked += 1;
		}
		assert!(checked > 300, "expected the corpus sweep, got {checked}");
	}

	#[test]
	fn an_auto_query_set_asks_more_than_the_model_wrote() {
		let m = parsed("examples/test/hmac_ok.vp");
		let written = m.queries.len();
		let generated = auto_queries(&m).expect("generates").len();
		assert!(
			generated > written,
			"auto queries ({generated}) should exceed the {written} written by hand"
		);
	}

	fn confidential(source: &str) -> Vec<String> {
		let m = crate::syntax::parser::parse_string("aq.vp", source).expect("parses");
		auto_queries(&m)
			.expect("generates")
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
			confidential(&format!(
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
	fn a_bound_value_is_asked_about_where_a_copy_that_answers_uses_it() {
		let expected = [
			"confidentiality? b",
			"confidentiality? c",
			"confidentiality? n",
			"authentication? Bob -> Alice: gb",
			"authentication? Carol -> Alice: gc",
			"authentication? Alice -> Bob: e",
			"freshness? gb",
			"freshness? gc",
			"freshness? e",
		];
		for model in [
			"scenario_query_each_entry.vp",
			"scenario_query_each_entry_reversed.vp",
		] {
			let m = parsed(&format!("examples/test/{model}"));
			assert_eq!(
				asked(&m),
				expected,
				"{model}: Alice uses each key under one scenario only, and the set and \
				 its order are those of the model as written, whichever entry comes first"
			);
			let without = Model {
				scenarios: Vec::new(),
				queries: Vec::new(),
				..m
			};
			assert!(
				!asked(&without).iter().any(|q| q.ends_with("gb")),
				"as written, Alice uses only the placeholder"
			);
		}
	}

	#[test]
	fn a_value_used_only_beside_a_corrupt_peer_is_not_asked_about() {
		let m = crate::syntax::parser::parse_string(
			"aq.vp",
			&format!(
				"{PEERS}scenarios[Alice[aq_peer = aq_gb] Alice[aq_peer = aq_gx]]\n\
				 queries[\nconfidentiality? aq_m\n]\n"
			),
		)
		.expect("parses");
		let asked = asked(&m);
		assert!(
			asked.contains(&"authentication? Bob -> Alice: aq_gb".to_string()),
			"{asked:?}"
		);
		assert!(
			!asked.iter().any(|q| q.ends_with("aq_gx")),
			"Mallory leaks her key, so the copy bound to it answers no query, and one \
			 asked about it would be sane nowhere: {asked:?}"
		);
	}

	#[test]
	fn the_written_queries_are_checked_in_their_scenario_copies_before_they_are_replaced() {
		let m = parsed("examples/test/scenario_query_each_entry_reversed.vp");
		assert!(
			auto_queries(&m).is_ok(),
			"each written query is sane in one copy, though not in the model as written"
		);
		let error = auto_queries(&parsed("examples/test/scenario_query_no_entry.vp"))
			.expect_err("no scenario uses gd");
		assert!(error.message.contains("never uses it"), "{error}");
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
			let m = parsed(&path);
			let without = crate::syntax::Model {
				scenarios: Vec::new(),
				..m.clone()
			};
			let sorted = |m: &Model| {
				let mut queries = asked(m);
				queries.sort();
				queries
			};
			assert_eq!(
				sorted(&m),
				sorted(&without),
				"{model}: every secret survives the binding"
			);
		}
	}
}
