/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::*;

pub(crate) fn auto_queries(m: &Model, km: &ProtocolTrace) -> Vec<Query> {
	let mut out = Vec::new();
	for c in secret_constants(m) {
		if km.index_of(&c).is_none() || c.is_nil() {
			continue;
		}
		out.push(single_constant_query(QueryKind::Confidentiality, c));
	}
	for slot in &km.slots {
		for &(recipient, sender) in &slot.known_by {
			if sender == recipient || slot.constant.is_nil() {
				continue;
			}
			if !slot.known_by_principal(sender) || !slot.known_by_principal(recipient) {
				continue;
			}
			if !km.constant_used_by(recipient, &slot.constant) {
				continue;
			}
			out.push(authentication_query(km, sender, recipient, &slot.constant));
		}
	}
	for slot in &km.slots {
		if slot.sent_by.is_empty() || slot.constant.is_nil() {
			continue;
		}
		if !km.constant_used_by_any(&slot.constant) {
			continue;
		}
		out.push(single_constant_query(
			QueryKind::Freshness,
			slot.constant.clone(),
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
		for expression in &p.expressions {
			let secret = match expression.kind {
				Declaration::Generates => true,
				Declaration::Knows => matches!(
					expression.qualifier,
					Some(Qualifier::Private) | Some(Qualifier::Password)
				),
				_ => false,
			};
			if !secret {
				continue;
			}
			for c in &expression.constants {
				if !out.iter().any(|prior| prior.id == c.id) {
					out.push(c.clone());
				}
			}
		}
	}
	out
}

fn single_constant_query(kind: QueryKind, c: Constant) -> Query {
	Query {
		span: Span::default(),
		kind,
		constants: vec![c],
		message: Message::default(),
		options: Vec::new(),
		leading_comments: Vec::new(),
		trailing_comment: None,
	}
}

fn authentication_query(
	km: &ProtocolTrace,
	sender: PrincipalId,
	recipient: PrincipalId,
	c: &Constant,
) -> Query {
	Query {
		span: Span::default(),
		kind: QueryKind::Authentication,
		constants: Vec::new(),
		message: Message {
			span: Span::default(),
			sender,
			sender_name: km.principal_name(sender).into(),
			recipient,
			recipient_name: km.principal_name(recipient).into(),
			constants: vec![c.clone()],
			leading_comments: Vec::new(),
			trailing_comment: None,
		},
		options: Vec::new(),
		leading_comments: Vec::new(),
		trailing_comment: None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn model_and_trace(path: &str) -> (Model, ProtocolTrace) {
		let m = crate::parser::parse_file(path).expect("parses");
		let (km, _) = crate::sanity::sanity(&m).expect("sane");
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
			let Ok((km, _)) = crate::sanity::sanity(&m) else {
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
