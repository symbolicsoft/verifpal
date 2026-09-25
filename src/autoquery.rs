/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::*;

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
				|| !crate::resolution::principal_uses_constant(km, recipient, &slot.constant)
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
			|| !crate::resolution::constant_used_by_any_principal(km, &slot.constant)
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
	let rebound: Vec<ValueId> = m
		.scenarios
		.iter()
		.flat_map(|scenario| scenario.bindings.iter().map(|(target, _)| target.id))
		.collect();
	for block in &m.blocks {
		let Block::Principal(p) = block else {
			continue;
		};
		for expression in p.expressions.iter().filter(|e| e.declares_secret()) {
			for c in &expression.constants {
				if !rebound.contains(&c.id) && !out.iter().any(|prior| prior.id == c.id) {
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
		let m = crate::parser::parse_file(path).expect("parses");
		let km = crate::sanity::sanity(&m).expect("sane");
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
			let Ok(mut m) = crate::parser::parse_file(&display) else {
				continue;
			};
			let Ok(km) = crate::sanity::sanity(&m) else {
				continue;
			};
			m.queries = auto_queries(&m, &km);
			crate::sanity::sanity(&m).unwrap_or_else(|e| {
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
}
