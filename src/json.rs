/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::parser::parse_string;
use crate::pretty::{pretty_constants, pretty_model};
use crate::sanity::sanity;
use crate::types::*;
use crate::verify::analyze;

pub(crate) fn json_escape(s: &str) -> String {
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

pub(crate) fn json_array<T>(items: impl IntoIterator<Item = T>, f: impl Fn(T) -> String) -> String {
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

pub(crate) fn json_string_array(arr: &[String]) -> String {
	json_array(arr, |s| format!(r#""{}""#, json_escape(s)))
}

pub(crate) fn json_knowledge_map(trace: &ProtocolTrace) -> String {
	let constants = json_array(trace.slots.iter(), |slot| {
		format!(r#"{{"Name":"{}"}}"#, json_escape(&slot.constant.name))
	});
	let creators = json_array(trace.slots.iter(), |slot| {
		format!(r#""{}""#, json_escape(trace.principal_name(slot.creator)))
	});
	let assigned = json_array(trace.slots.iter(), |slot| {
		format!(r#""{}""#, json_escape(&slot.initial_value.to_string()))
	});
	let known_by = json_array(trace.slots.iter(), |slot| {
		json_array(slot.known_by.iter(), |&(recipient, sender)| {
			format!(
				r#"{{"{}":"{}"}}"#,
				json_escape(trace.principal_name(recipient)),
				json_escape(trace.principal_name(sender)),
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

fn json_query_display(q: &Query) -> String {
	match q.kind {
		QueryKind::Authentication => format!(
			"authentication? {} -> {}: {}",
			q.message.sender_name,
			q.message.recipient_name,
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

pub(crate) fn json_verify_results(
	results: &[VerifyResult],
	assumptions: &[(Value, Capability, i32)],
) -> String {
	let rendered = json_assumptions(assumptions);
	let mut out = String::from("[");
	for (i, r) in results.iter().enumerate() {
		if i > 0 {
			out.push(',');
		}
		let query_str = json_query_display(&r.query);
		let constants = json_query_constants(&r.query);
		out.push_str(&format!(
			r#"{{"Query":"{}","Resolved":{},"Summary":"{}","Constants":{},"Assumptions":{}}}"#,
			json_escape(&query_str),
			r.resolved,
			json_escape(&r.summary),
			json_string_array(&constants),
			rendered,
		));
	}
	out.push(']');
	out
}

fn json_assumptions(assumptions: &[(Value, Capability, i32)]) -> String {
	let mut out = String::from("[");
	for (i, (term, cap, onset)) in assumptions.iter().enumerate() {
		if i > 0 {
			out.push(',');
		}
		out.push_str(&format!(
			r#"{{"Term":"{}","Capability":"{}","FromPhase":{}}}"#,
			json_escape(&term.to_string()),
			cap.name(),
			onset,
		));
	}
	out.push(']');
	out
}

pub(crate) fn pretty_diagram(m: &Model) -> VResult<String> {
	let anchor = m.blocks.iter().find_map(|block| match block {
		Block::Principal(p) => Some(p.name.clone()),
		Block::Message(msg) => Some(msg.sender_name.to_string()),
		Block::Phase(_) => None,
	});
	let mut output = String::new();
	for block in &m.blocks {
		match block {
			Block::Principal(p) => {
				for expr in &p.expressions {
					output.push_str(&format!("Note over {}: {}\n", p.name, expr));
				}
			}
			Block::Message(msg) => {
				output.push_str(&format!(
					"{}->{}:{}\n",
					msg.sender_name,
					msg.recipient_name,
					pretty_constants(&msg.constants),
				));
			}
			Block::Phase(phase) => {
				if let Some(anchor) = &anchor {
					output.push_str(&format!(
						"Note right of {}: phase[{}]\n",
						anchor, phase.number
					));
				}
			}
		}
	}
	Ok(output)
}

pub fn handle_internal_json(subcommand: &str, input: &str) {
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

fn located<T>(m: &Model, r: VResult<T>) -> VResult<T> {
	r.map_err(|e| e.located(&m.file_name, &m.source))
}

fn handle_knowledge_map(input: &str) -> VResult<String> {
	let m = parse_string("editor.vp", input)?;
	let (trace, _) = located(&m, sanity(&m))?;
	Ok(json_knowledge_map(&trace))
}

fn handle_verify(input: &str) -> VResult<String> {
	let m = parse_string("editor.vp", input)?;
	let ctx = located(&m, analyze(&m))?;
	Ok(json_verify_results(
		&ctx.results_get(),
		&ctx.capability_assumptions(),
	))
}

fn handle_pretty_print(input: &str) -> VResult<String> {
	let m = parse_string("editor.vp", input)?;
	located(&m, pretty_model(&m))
}

fn handle_pretty_diagram(input: &str) -> VResult<String> {
	let m = parse_string("editor.vp", input)?;
	located(&m, pretty_diagram(&m))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn internal_json_reports_declared_assumptions() {
		let out = handle_verify(
			"attacker[passive]\n\
			principal Alice[\n\
			knows private jcap_m\n\
			jcap_h = HASH[weak](jcap_m)\n\
			]\n\
			Alice -> Bob: jcap_h\n\
			principal Bob[\n\
			_ = HASH(jcap_h)\n\
			]\n\
			queries[\n\
			confidentiality? jcap_m\n\
			]\n",
		)
		.expect("verifies");
		assert!(out.contains("\"Assumptions\""), "{out}");
		assert!(out.contains("weak"), "{out}");
	}

	#[test]
	fn internal_json_omits_assumptions_when_none_declared() {
		let out = handle_verify(
			"attacker[passive]\n\
			principal Alice[\n\
			knows private jnoc_m\n\
			jnoc_h = HASH(jnoc_m)\n\
			]\n\
			Alice -> Bob: jnoc_h\n\
			principal Bob[\n\
			_ = HASH(jnoc_h)\n\
			]\n\
			queries[\n\
			confidentiality? jnoc_m\n\
			]\n",
		)
		.expect("verifies");
		assert!(out.contains("\"Assumptions\":[]"), "{out}");
	}

	#[test]
	fn phase_notes_name_a_participant() {
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private pd_x\n\
			]\n\
			phase[1]\n\
			principal Alice[\n\
			leaks pd_x\n\
			]\n\
			queries[\n\
			confidentiality? pd_x\n\
			]\n";
		let m = parse_string("pd.vp", src).expect("parse");
		let out = pretty_diagram(&m).expect("diagram");
		assert!(out.contains("Note right of Alice: phase[1]"), "{out}");
		assert!(!out.contains("of :"), "{out}");
	}
}
