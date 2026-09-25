/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::engine::query::Verdict;
use crate::types::*;
use crate::value::resolve_trace_constant;

pub(crate) fn record_verdict(ctx: &VerifyContext, result: &VerifyResult, verdict: &Verdict) {
	if ctx.results_put(result, verdict) {
		if result.subtype == Some(Subtype::ReplayableFirstFlight) {
			note_origin_only(&result.query);
		}
		let headline = crate::pretty::query_line(&result.query);
		let qualifier = result.subtype.map(Subtype::qualifier).unwrap_or_default();
		crate::info::info_analysis_result(&headline, || {
			format!("{}{}{}", headline, qualifier, result.summary)
		});
	}
}

fn note_origin_only(query: &Query) {
	crate::info::info_message(
		&format!(
			"{} reports a duplicate that {} cannot rule out on its own: it contributes \
			 nothing to {} before accepting it, so any run of it takes the same message \
			 twice. Read it as a replay-protection question about this flight rather \
			 than as a forgery.",
			crate::pretty::query_display(query),
			query.message.recipient_name,
			query
				.message
				.constants
				.first()
				.map(|c| c.name.to_string())
				.unwrap_or_default(),
		),
		InfoLevel::Info,
	);
}

fn sibling_values_in(
	groups: &IdMap<ValueId, std::sync::Arc<Vec<ValueId>>>,
	c: &Constant,
	km: &ProtocolTrace,
) -> Vec<Value> {
	let Some(group) = groups.get(&c.id) else {
		return Vec::new();
	};
	group
		.iter()
		.filter(|&&sid| sid != c.id)
		.filter_map(|&sid| {
			let &slot = km.index.get(&sid)?;
			Some(resolve_trace_constant(&km.slots[slot].constant, km))
		})
		.collect()
}

pub(crate) fn session_sibling_values(c: &Constant, km: &ProtocolTrace) -> Vec<Value> {
	sibling_values_in(&km.session_siblings, c, km)
}

#[cfg(test)]
mod tcb_tests {
	use std::fs;
	use std::path::{Path, PathBuf};

	const TEST_ONLY: [&str; 2] = ["model_tests.rs", "testutil.rs"];

	fn engine_sources() -> Vec<PathBuf> {
		fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
			for entry in fs::read_dir(dir).expect("read src/").flatten() {
				let path = entry.path();
				if path.is_dir() {
					walk(&path, out);
				} else if path.extension().is_some_and(|e| e == "rs") {
					let name = path.file_name().unwrap_or_default().to_string_lossy();
					if !TEST_ONLY.contains(&name.as_ref()) {
						out.push(path);
					}
				}
			}
		}
		let mut out = Vec::new();
		walk(
			Path::new(env!("CARGO_MANIFEST_DIR")).join("src").as_path(),
			&mut out,
		);
		out.sort();
		out
	}

	fn shipping_lines(path: &Path) -> Vec<(usize, String)> {
		let text = fs::read_to_string(path).expect("read source");
		let lines: Vec<&str> = text.lines().collect();
		let mut out = Vec::new();
		let mut i = 0;
		while i < lines.len() {
			let is_test_attr = lines[i].trim() == "#[cfg(test)]";
			let opens_mod = lines
				.get(i + 1)
				.is_some_and(|l| l.trim_start().starts_with("mod ") && l.trim_end().ends_with('{'));
			if is_test_attr && opens_mod {
				let mut depth = 0i32;
				i += 1;
				while i < lines.len() {
					depth += lines[i].matches('{').count() as i32;
					depth -= lines[i].matches('}').count() as i32;
					i += 1;
					if depth <= 0 {
						break;
					}
				}
				continue;
			}
			out.push((i + 1, lines[i].to_string()));
			i += 1;
		}
		out
	}

	fn relative(path: &Path) -> String {
		path.strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
			.unwrap_or(path)
			.to_string_lossy()
			.into_owned()
	}

	fn engine_source(relative_path: &str) -> PathBuf {
		Path::new(env!("CARGO_MANIFEST_DIR"))
			.join("src")
			.join(relative_path)
	}

	fn block_lines(path: &Path, is_header: impl Fn(&str) -> bool) -> Vec<(usize, String)> {
		let lines = shipping_lines(path);
		let Some(start) = lines
			.iter()
			.position(|(_, line)| is_header(line.trim_start()))
		else {
			return Vec::new();
		};
		let mut depth = 0i32;
		let mut opened = false;
		let mut out = Vec::new();
		for entry in &lines[start..] {
			depth += entry.1.matches('{').count() as i32;
			depth -= entry.1.matches('}').count() as i32;
			out.push(entry.clone());
			opened |= depth > 0;
			if opened && depth <= 0 {
				break;
			}
		}
		out
	}

	fn body_hits(body: &[(usize, String)], needle: &str) -> Vec<usize> {
		body.iter()
			.enumerate()
			.filter(|(_, (_, line))| line.contains(needle))
			.map(|(i, _)| i)
			.collect()
	}

	fn call_site_files(name: &str) -> Vec<(String, usize)> {
		let mut counts: Vec<(String, usize)> = Vec::new();
		for site in call_sites(name) {
			let file = site
				.rsplit_once(':')
				.map(|(f, _)| f.to_string())
				.unwrap_or(site);
			match counts.iter_mut().find(|(f, _)| *f == file) {
				Some((_, n)) => *n += 1,
				None => counts.push((file, 1)),
			}
		}
		counts.sort();
		counts
	}

	fn call_sites(name: &str) -> Vec<String> {
		let needle = format!("{name}(");
		let mut sites = Vec::new();
		for path in engine_sources() {
			let rel = relative(&path);
			for (number, line) in shipping_lines(&path) {
				if !line.contains(&needle) {
					continue;
				}
				let trimmed = line.trim_start();
				if trimmed.starts_with("use ") || trimmed.contains(&format!("fn {name}")) {
					continue;
				}
				sites.push(format!("{rel}:{number}"));
			}
		}
		sites
	}

	#[test]
	fn a_query_result_has_exactly_one_write_path() {
		assert_eq!(
			call_site_files("results_put"),
			vec![("query.rs".to_string(), 1)],
			"`results_put` is the only way to record a query result, and it must keep \
			 exactly one caller."
		);
	}

	#[test]
	fn results_are_recorded_only_by_the_execution_judge() {
		assert_eq!(
			call_site_files("record_verdict"),
			vec![("engine/mod.rs".to_string(), 1)],
			"a result is recorded only where a violation found in an execution is reported"
		);
	}

	#[test]
	fn a_verdict_is_minted_only_by_the_evaluator() {
		let mut mints: Vec<String> = Vec::new();
		for path in engine_sources() {
			for (number, line) in shipping_lines(&path) {
				if line.contains("Verdict(())") {
					mints.push(format!("{}:{number}", relative(&path)));
				}
			}
		}
		assert!(
			!mints.is_empty()
				&& mints
					.iter()
					.all(|site| site.starts_with("engine/query.rs:")),
			"only the evaluator may construct the token that records a result, found {mints:?}"
		);
	}

	#[test]
	fn the_evaluator_judges_nothing_but_an_execution() {
		let judge = engine_source("engine/query.rs");
		let fields = block_lines(&judge, |header| {
			header.starts_with("pub(crate) struct Judge")
		});
		assert!(
			fields
				.iter()
				.any(|(_, line)| line.contains("ex: &'a Execution")),
			"the evaluator must be handed one execution"
		);
		assert!(
			!fields
				.iter()
				.any(|(_, line)| line.contains("VerifyContext")),
			"the evaluator must not reach shared analysis state"
		);
		assert_eq!(
			call_site_files("execute"),
			vec![
				("engine/mod.rs".to_string(), 2),
				("engine/search.rs".to_string(), 1),
			],
			"executions come only from the executor, called by the root run, the minimizer \
			 and the search"
		);
	}

	#[test]
	fn an_install_is_delivered_only_once_it_is_derivable() {
		let exec = engine_source("engine/exec.rs");
		let body = block_lines(&exec, |header| header.starts_with("fn step_run"));
		let receive = body_hits(&body, "Event::Recv(d) =>");
		let gate = body_hits(&body, ".derivable(t, &cx.km.capabilities)");
		assert!(
			!receive.is_empty() && !gate.is_empty(),
			"the receive arm must gate installs"
		);
		assert!(
			gate.iter().all(|&at| at > receive[0]),
			"the derivability gate belongs to the receive"
		);
	}

	#[test]
	fn a_forwarded_value_is_only_ever_what_its_sender_sent() {
		let exec = engine_source("engine/exec.rs");
		let body = block_lines(&exec, |header| header.starts_with("fn step_run"));
		assert!(
			!body_hits(&body, "let sent = ex.sent[d].clone();").is_empty(),
			"a receive without an install takes the value the sender's executed send recorded"
		);
		assert!(
			!body_hits(&body, "ex.sent[d] = Some(values);").is_empty(),
			"a send records exactly the values the sender held"
		);
	}
}
