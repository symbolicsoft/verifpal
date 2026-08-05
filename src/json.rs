/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::parser::parse_string;
use crate::pretty::{pretty_constants, pretty_model};
use crate::principal::principal_get_name_from_id;
use crate::sanity::sanity;
use crate::solve::verify_active;
use crate::types::*;
use crate::verify::verify_passive;

// ---------------------------------------------------------------------------
// JSON utilities
// ---------------------------------------------------------------------------

pub fn json_escape(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for c in s.chars() {
		match c {
			'"' => out.push_str("\\\""),
			'\\' => out.push_str("\\\\"),
			'\n' => out.push_str("\\n"),
			'\r' => out.push_str("\\r"),
			'\t' => out.push_str("\\t"),
			c if c < '\u{20}' => out.push_str(&format!("\\u{:04x}", c as u32)),
			c => out.push(c),
		}
	}
	out
}

/// Render `items` as a JSON array, formatting each element with `f`.
pub fn json_array<T>(items: impl IntoIterator<Item = T>, f: impl Fn(T) -> String) -> String {
	let mut out = String::from("[");
	for (i, item) in items.into_iter().enumerate() {
		if i > 0 {
			out.push(',');
		}
		out.push_str(&f(item));
	}
	out.push(']');
	out
}

pub fn json_string_array(arr: &[String]) -> String {
	json_array(arr, |s| format!(r#""{}""#, json_escape(s)))
}

// ---------------------------------------------------------------------------
// Knowledge map serialization
// ---------------------------------------------------------------------------

pub fn json_knowledge_map(trace: &ProtocolTrace) -> String {
	let constants = json_array(trace.slots.iter(), |slot| {
		format!(r#"{{"Name":"{}"}}"#, json_escape(&slot.constant.name))
	});
	let creators = json_array(trace.slots.iter(), |slot| {
		format!(
			r#""{}""#,
			json_escape(&principal_get_name_from_id(slot.creator))
		)
	});
	let assigned = json_array(trace.slots.iter(), |slot| {
		format!(r#""{}""#, json_escape(&slot.initial_value.to_string()))
	});
	// KnownBy: [[{"Bob": "Alice"}], ...]
	let known_by = json_array(trace.slots.iter(), |slot| {
		json_array(slot.known_by.iter(), |&(recipient, sender)| {
			format!(
				r#"{{"{}":"{}"}}"#,
				json_escape(&principal_get_name_from_id(recipient)),
				json_escape(&principal_get_name_from_id(sender)),
			)
		})
	});
	let principals = json_string_array(&trace.principals);
	let phases = json_array(trace.slots.iter(), |slot| {
		json_array(slot.phases.iter(), |ph| ph.to_string())
	});

	format!(
		r#"{{"Constants":{},"Creator":{},"Assigned":{},"KnownBy":{},"Principals":{},"Phase":{},"MaxPhase":{}}}"#,
		constants, creators, assigned, known_by, principals, phases, trace.max_phase,
	)
}

// ---------------------------------------------------------------------------
// Verify results serialization
// ---------------------------------------------------------------------------

fn json_query_display(q: &Query) -> String {
	match q.kind {
		QueryKind::Authentication => format!(
			"authentication? {} -> {}: {}",
			principal_get_name_from_id(q.message.sender),
			principal_get_name_from_id(q.message.recipient),
			pretty_constants(&q.message.constants),
		),
		_ => format!("{}? {}", q.kind.name(), pretty_constants(&q.constants)),
	}
}

fn json_query_constants(q: &Query) -> Vec<String> {
	match q.kind {
		QueryKind::Authentication => q
			.message
			.constants
			.iter()
			.map(|c| c.name.to_string())
			.collect(),
		_ => q.constants.iter().map(|c| c.name.to_string()).collect(),
	}
}

pub fn json_verify_results(results: &[VerifyResult]) -> String {
	let mut out = String::from("[");
	for (i, r) in results.iter().enumerate() {
		if i > 0 {
			out.push(',');
		}
		let query_str = json_query_display(&r.query);
		let constants = json_query_constants(&r.query);
		out.push_str(&format!(
			r#"{{"Query":"{}","Resolved":{},"Summary":"{}","Constants":{}}}"#,
			json_escape(&query_str),
			r.resolved,
			json_escape(&r.summary),
			json_string_array(&constants),
		));
	}
	out.push(']');
	out
}

// ---------------------------------------------------------------------------
// Sequence diagram generation
// ---------------------------------------------------------------------------

pub fn pretty_diagram(m: &Model) -> VResult<String> {
	let mut output = String::new();
	for block in &m.blocks {
		match block {
			Block::Principal(p) => {
				for expr in &p.expressions {
					output.push_str(&format!("Note over {}: {}\n", p.name, expr));
				}
			}
			Block::Message(msg) => {
				let sender = principal_get_name_from_id(msg.sender);
				let recipient = principal_get_name_from_id(msg.recipient);
				output.push_str(&format!(
					"{}->{}:{}\n",
					sender,
					recipient,
					pretty_constants(&msg.constants),
				));
			}
			Block::Phase(phase) => {
				output.push_str(&format!("Note right of : phase[{}]\n", phase.number));
			}
		}
	}
	Ok(output)
}

// ---------------------------------------------------------------------------
// Internal-JSON command handlers
// ---------------------------------------------------------------------------

pub fn handle_internal_json(subcommand: &str, input: &str) {
	crate::reset_global_state();
	let result = match subcommand {
		"knowledgeMap" => handle_knowledge_map(input),
		"verify" => handle_verify(input),
		"prettyPrint" => handle_pretty_print(input),
		"prettyDiagram" => handle_pretty_diagram(input),
		_ => {
			eprintln!("Error: unknown internal-json subcommand: {}", subcommand);
			std::process::exit(1);
		}
	};
	match result {
		Ok(output) => print!("{}", output),
		Err(e) => {
			eprintln!("Error: {}", e);
			std::process::exit(1);
		}
	}
}

fn handle_knowledge_map(input: &str) -> VResult<String> {
	let m = parse_string("editor.vp", input)?;
	let (trace, _) = sanity(&m)?;
	Ok(json_knowledge_map(&trace))
}

fn handle_verify(input: &str) -> VResult<String> {
	let m = parse_string("editor.vp", input)?;
	let (km, ps) = sanity(&m)?;
	let ctx = VerifyContext::new(&m, &ps);
	match m.attacker {
		AttackerKind::Passive => verify_passive(&ctx, &km, &ps)?,
		AttackerKind::Active => verify_active(&ctx, &km, &ps)?,
	}
	let results = ctx.results_get();
	Ok(json_verify_results(&results))
}

fn handle_pretty_print(input: &str) -> VResult<String> {
	let m = parse_string("editor.vp", input)?;
	pretty_model(&m)
}

fn handle_pretty_diagram(input: &str) -> VResult<String> {
	let m = parse_string("editor.vp", input)?;
	pretty_diagram(&m)
}
