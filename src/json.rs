/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::parser::parse_string;
use crate::pretty::{pretty_constants, pretty_model};
use crate::principal::principal_get_name_from_id;
use crate::sanity::sanity;
use crate::types::*;
use crate::verify::verify_passive;
use crate::verifyactive::verify_active;

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

pub fn json_string_array(arr: &[String]) -> String {
	let mut out = String::from("[");
	for (i, s) in arr.iter().enumerate() {
		if i > 0 {
			out.push(',');
		}
		out.push('"');
		out.push_str(&json_escape(s));
		out.push('"');
	}
	out.push(']');
	out
}

// ---------------------------------------------------------------------------
// Knowledge map serialization
// ---------------------------------------------------------------------------

pub fn json_knowledge_map(trace: &ProtocolTrace) -> String {
	// Constants: [{Name: "x"}, ...]
	let mut constants = String::from("[");
	for (i, slot) in trace.slots.iter().enumerate() {
		if i > 0 {
			constants.push(',');
		}
		constants.push_str(&format!(
			r#"{{"Name":"{}"}}"#,
			json_escape(&slot.constant.name)
		));
	}
	constants.push(']');

	// Creator: ["Alice", ...]
	let creators: Vec<String> = trace
		.slots
		.iter()
		.map(|slot| principal_get_name_from_id(slot.creator).to_string())
		.collect();
	let creators_json = json_string_array(&creators);

	// Assigned: ["x", "G^a", "ENC(k, m)"] (pre-formatted display strings)
	let assigned: Vec<String> = trace
		.slots
		.iter()
		.map(|slot| slot.initial_value.to_string())
		.collect();
	let assigned_json = json_string_array(&assigned);

	// KnownBy: [[{"Bob": "Alice"}], ...]
	let mut known_by = String::from("[");
	for (i, slot) in trace.slots.iter().enumerate() {
		if i > 0 {
			known_by.push(',');
		}
		known_by.push('[');
		for (j, &(recipient, sender)) in slot.known_by.iter().enumerate() {
			if j > 0 {
				known_by.push(',');
			}
			let r_name = principal_get_name_from_id(recipient);
			let s_name = principal_get_name_from_id(sender);
			known_by.push_str(&format!(
				r#"{{"{}":"{}"}}"#,
				json_escape(&r_name),
				json_escape(&s_name),
			));
		}
		known_by.push(']');
	}
	known_by.push(']');

	// Principals
	let principals_json = json_string_array(&trace.principals);

	// Phase: [[], [0], ...]
	let mut phases = String::from("[");
	for (i, slot) in trace.slots.iter().enumerate() {
		if i > 0 {
			phases.push(',');
		}
		phases.push('[');
		for (j, &ph) in slot.phases.iter().enumerate() {
			if j > 0 {
				phases.push(',');
			}
			phases.push_str(&ph.to_string());
		}
		phases.push(']');
	}
	phases.push(']');

	format!(
		r#"{{"Constants":{},"Creator":{},"Assigned":{},"KnownBy":{},"Principals":{},"Phase":{},"MaxPhase":{}}}"#,
		constants, creators_json, assigned_json, known_by, principals_json, phases, trace.max_phase,
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
	let ctx = VerifyContext::new(&m);
	match m.attacker {
		AttackerKind::Passive => verify_passive(&ctx, &km, &ps)?,
		AttackerKind::Active => verify_active(&ctx, &km, &ps)?,
	}
	let results = ctx.results_get();
	// Leading newline ensures JSON starts on a fresh line, since
	// info_analysis progress messages use \r without \n and would
	// otherwise leave the cursor mid-line in piped output.
	Ok(format!("\n{}", json_verify_results(&results)))
}

fn handle_pretty_print(input: &str) -> VResult<String> {
	let m = parse_string("editor.vp", input)?;
	pretty_model(&m)
}

fn handle_pretty_diagram(input: &str) -> VResult<String> {
	let m = parse_string("editor.vp", input)?;
	pretty_diagram(&m)
}
