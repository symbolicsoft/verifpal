/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::context::VerifyContext;
use crate::info::*;
use crate::narrate::{Narration, narrate_attack};
use crate::primitive::*;
use crate::principal::*;
use crate::theory::*;
use crate::types::*;
use crate::value::*;
use crate::witness::{in_minimization, minimize_witness};

fn attack_trace(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	query_index: usize,
	target: &Value,
	seed: &[(SlotIdx, Value)],
) -> Narration {
	if in_minimization() {
		return Narration::none();
	}
	let witness = minimize_witness(ctx, km, ps, query_index, seed);
	narrate_attack(km, &witness, target)
}

fn recorded_mutations(attacker: &AttackerState, attacker_idx: KnownIdx) -> Vec<(SlotIdx, Value)> {
	attacker
		.mutation_records
		.get(attacker_idx.get())
		.map(|record| {
			record
				.diffs
				.iter()
				.filter(|d| d.tainted)
				.map(|d| (d.index, d.value.clone()))
				.collect()
		})
		.unwrap_or_default()
}

pub(crate) fn query_start(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> VResult<()> {
	let attacker = ctx.attacker_snapshot();
	match query.kind {
		QueryKind::Confidentiality => {
			query_confidentiality(ctx, query, query_index, km, ps, &attacker)?;
		}
		QueryKind::Authentication => {
			query_authentication(ctx, query, query_index, km, ps, &attacker)?;
		}
		QueryKind::Freshness => {
			query_freshness(ctx, query, query_index, km, ps, &attacker)?;
		}
		QueryKind::Unlinkability => {
			query_unlinkability(ctx, query, query_index, km, ps, &attacker)?;
		}
		QueryKind::Equivalence => {
			query_equivalence(ctx, query, query_index, km, ps, &attacker)?;
		}
	}
	Ok(())
}

pub(crate) struct QueryVerdict(());

#[cfg(test)]
impl QueryVerdict {
	pub(crate) fn for_test() -> QueryVerdict {
		QueryVerdict(())
	}
}

fn emit_query_result(ctx: &VerifyContext, result: &VerifyResult) {
	if ctx.results_put(result, &QueryVerdict(())) {
		info_message(
			&format!("{}{}", result.query, result.summary),
			InfoLevel::Result,
			true,
		);
	}
}

fn query_confidentiality(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> VResult<VerifyResult> {
	let mut result = VerifyResult::new(query, query_index);
	let subject = query.subject()?;
	let slot_idx = match ps.index_of(subject) {
		Some(idx) => idx,
		None => return Ok(result),
	};
	let resolved_value = &ps.values[slot_idx].value;
	let attacker_idx = match attacker.knows(resolved_value) {
		Some(idx) => idx,
		None => return Ok(result),
	};
	let seed = recorded_mutations(attacker, attacker_idx);
	let mutated_info = attack_trace(ctx, km, ps, query_index, resolved_value, &seed);
	result.resolved = true;
	result.summary = info_verify_result_summary(
		&mutated_info.trace,
		&format!(
			"{} ({}) is obtained by Attacker.",
			subject,
			mutated_info.term(&attacker.known[attacker_idx.get()]),
		),
		&result.options,
	);
	result = query_precondition(result, ps);
	emit_query_result(ctx, &result);
	Ok(result)
}

fn query_authentication(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> VResult<VerifyResult> {
	let mut result = VerifyResult::new(query, query_index);
	if query.message.recipient != ps.id {
		return Ok(result);
	}
	let (indices, sender, c) = query_authentication_get_pass_indices(query, km, ps)?;
	for &index in &indices {
		if query.message.sender == sender {
			continue;
		}
		result.resolved = true;
		let assigned = &ps.values[index].value;
		let before = &ps.values[index].pre_rewrite;
		let seed = attacker
			.knows(assigned)
			.map(|i| recorded_mutations(attacker, i))
			.unwrap_or_default();
		let mutated_info = attack_trace(ctx, km, ps, query_index, assigned, &seed);
		result = query_precondition(result, ps);
		return Ok(query_authentication_handle_pass(
			ctx,
			result,
			&c,
			before,
			&mutated_info,
			km.principal_name(sender),
			ps,
		));
	}
	Ok(result)
}

fn query_find_constant_usage_indices(
	c: &Constant,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> Option<Vec<usize>> {
	let mut indices = Vec::new();
	for slot in &km.slots {
		if slot.creator != ps.id {
			continue;
		}
		if !matches!(&slot.initial_value, Value::Primitive(_)) {
			continue;
		}
		if !find_constant_in_trace_primitive(c, &slot.initial_value, km) {
			continue;
		}
		let (_, slot_idx) = ps.resolve_constant(&slot.constant, true);
		let slot_idx = slot_idx?;
		let before = &ps.values[slot_idx].pre_rewrite;
		let before_prim = match before {
			Value::Primitive(p) => p,
			_ => continue,
		};
		if !primitive_has_rewrite_rule(before_prim.id) {
			indices.push(slot_idx);
			continue;
		}
		let (pass, _) = can_rewrite(before_prim, ps, 0);
		if pass || !before_prim.instance_check {
			indices.push(slot_idx);
		}
	}
	Some(indices)
}

fn query_authentication_get_pass_indices(
	query: &Query,
	km: &ProtocolTrace,
	ps: &PrincipalState,
) -> VResult<(Vec<usize>, PrincipalId, Constant)> {
	let empty_c = Constant::default();
	let (_, idx) = ps.resolve_constant(query.message.constant()?, true);
	let idx = match idx {
		Some(i) => i,
		None => return Ok((vec![], 0, empty_c)),
	};
	let c = km.slots[idx].constant.clone();
	let sender = ps.values[idx].provenance.sender;
	if sender == ATTACKER_ID {
		let v = &ps.values[idx].original;
		if v.equivalent(&ps.values[idx].value, true) {
			return Ok((vec![], sender, c));
		}
	}
	let indices = query_find_constant_usage_indices(&c, km, ps).unwrap_or_default();
	Ok((indices, sender, c))
}

fn query_authentication_handle_pass(
	ctx: &VerifyContext,
	mut result: VerifyResult,
	c: &Constant,
	b: &Value,
	mutated_info: &Narration,
	sender_name: &str,
	ps: &PrincipalState,
) -> VerifyResult {
	let (resolved, _) = ps.resolve_constant(c, true);
	result.summary = info_verify_result_summary(
		&mutated_info.trace,
		&format!(
			"{} ({}), sent by {} and not by {}, is successfully used in {} within {}'s state.",
			c,
			mutated_info.term(&resolved),
			sender_name,
			result.query.message.sender_name,
			mutated_info.term(b),
			result.query.message.recipient_name,
		),
		&result.options,
	);
	emit_query_result(ctx, &result);
	result
}

fn query_freshness(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	_attacker: &AttackerState,
) -> VResult<VerifyResult> {
	let mut result = VerifyResult::new(query, query_index);
	let subject = query.subject()?;
	let freshness_found = value_constant_contains_fresh_values(subject, ps)?;
	if freshness_found {
		return Ok(result);
	}
	let indices = match query_find_constant_usage_indices(subject, km, ps) {
		Some(v) => v,
		None => return Ok(result),
	};
	if indices.is_empty() {
		return Ok(result);
	}
	let (resolved, _) = ps.resolve_constant(subject, true);
	let mutated_info = attack_trace(ctx, km, ps, query_index, &resolved, &[]);
	result.resolved = true;
	result.summary = info_verify_result_summary(
		&mutated_info.trace,
		&format!(
			"{} ({}) is used by {} in {} despite not being a fresh value.",
			subject,
			mutated_info.term(&resolved),
			ps.name,
			mutated_info.term(&ps.values[indices[0]].pre_rewrite),
		),
		&result.options,
	);
	result = query_precondition(result, ps);
	emit_query_result(ctx, &result);
	Ok(result)
}

fn query_unlinkability(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
) -> VResult<VerifyResult> {
	let mut result = VerifyResult::new(query, query_index);
	for (i, a) in query.constants.iter().enumerate() {
		for b in query.constants.iter().skip(i + 1) {
			let Some(witness) = crate::unlink::find_link_witness(a, b, ps, attacker) else {
				continue;
			};
			let mutated_info = attack_trace(ctx, km, ps, query_index, &witness.value, &[]);
			let clause = witness.describe(&mutated_info.term(&witness.value));
			result.resolved = true;
			result.summary = info_verify_result_summary(
				&mutated_info.trace,
				&format!("Attacker links {a} and {b} {clause}."),
				&result.options,
			);
			result = query_precondition(result, ps);
			emit_query_result(ctx, &result);
			return Ok(result);
		}
	}
	Ok(result)
}

fn query_equivalence(
	ctx: &VerifyContext,
	query: &Query,
	query_index: usize,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	_attacker: &AttackerState,
) -> VResult<VerifyResult> {
	let mut result = VerifyResult::new(query, query_index);
	let values: Vec<Value> = query
		.constants
		.iter()
		.map(|c| ps.resolve_constant(c, false).0)
		.collect();
	let all_equivalent = values.windows(2).all(|w| w[0].equivalent(&w[1], true));
	if all_equivalent {
		return Ok(result);
	}
	let empty = Value::Constant(Constant::default());
	let mutated_info = attack_trace(ctx, km, ps, query_index, &empty, &[]);
	result.resolved = true;
	result.summary = info_verify_result_summary(
		&mutated_info.trace,
		&format!(
			"{} are not equivalent.",
			values
				.iter()
				.map(|v| mutated_info.term(v))
				.collect::<Vec<_>>()
				.join(", "),
		),
		&result.options,
	);
	result = query_precondition(result, ps);
	emit_query_result(ctx, &result);
	Ok(result)
}

fn query_precondition(mut result: VerifyResult, ps: &PrincipalState) -> VerifyResult {
	if !result.resolved {
		return result;
	}
	for option in &result.query.options {
		let mut option_result = QueryOptionResult {
			resolved: false,
			summary: String::new(),
		};
		let Ok(option_constant) = option.message.constant() else {
			result.options.push(option_result);
			continue;
		};
		let (_, slot_idx) = ps.resolve_constant(option_constant, true);
		let idx = match slot_idx {
			Some(idx) => idx,
			None => {
				result.options.push(option_result);
				continue;
			}
		};
		let sender = ps.meta[idx].known_by.iter().find_map(|&(recipient, from)| {
			if recipient == option.message.recipient {
				Some(from)
			} else {
				None
			}
		});
		if sender == Some(option.message.sender) {
			option_result.resolved = true;
			option_result.summary = format!(
				"{} sends {} to {} despite the query failing.",
				option.message.sender_name, option_constant, option.message.recipient_name,
			);
		}
		result.options.push(option_result);
	}
	result
}

#[cfg(test)]
mod tcb_tests {
	use std::fs;
	use std::path::{Path, PathBuf};

	/// Whole files declared `#[cfg(test)] mod ...` in lib.rs: no shipping code.
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

	/// The lines of `path` that ship, with `#[cfg(test)]` modules removed.
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

	/// The files containing shipping call sites of `name`, with a count each.
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

	/// Every shipping call site of `name`, excluding its definition and `use`.
	fn call_sites(name: &str) -> Vec<String> {
		let needle = format!("{name}(");
		let mut sites = Vec::new();
		for path in engine_sources() {
			let rel = path
				.strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
				.unwrap_or(&path)
				.to_string_lossy()
				.into_owned();
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
			"`results_put` is the only way to record a query result, and it must \
			 keep exactly one caller. Adding a second write path invalidates fact \
			 (i) of the soundness theorem."
		);
	}

	#[test]
	fn results_are_recorded_only_by_query_evaluation() {
		assert_eq!(
			call_site_files("emit_query_result"),
			vec![("query.rs".to_string(), 5)],
			"fact (ii) of the soundness theorem: one call per query kind, every \
			 one of them inside query.rs."
		);
	}

	#[test]
	fn query_evaluation_is_entered_only_over_an_executed_state() {
		assert_eq!(
			call_site_files("verify_resolve_queries"),
			vec![
				("solve/validate.rs".to_string(), 1),
				("verify.rs".to_string(), 1),
				("witness.rs".to_string(), 1),
			],
			"fact (iv) of the soundness theorem: query evaluation runs over the \
			 honest run (verify.rs), over a re-executed state (validate.rs), or \
			 over a minimizer probe against a scratch context (witness.rs), and \
			 nowhere else. A new call site must be shown to hand it a state that \
			 was concretely executed."
		);
	}

	#[test]
	fn the_solver_holds_no_shared_cell_over_analysis_state() {
		const ALLOWED: [&str; 4] = ["memo:", "active:", "cycles_cut:", "fresh:"];
		let mut offenders: Vec<String> = Vec::new();
		for path in engine_sources() {
			if !path.to_string_lossy().contains("/solve/") {
				continue;
			}
			let rel = path
				.strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
				.unwrap_or(&path)
				.to_string_lossy()
				.into_owned();
			for (number, line) in shipping_lines(&path) {
				let trimmed = line.trim_start();
				let shared = ["RefCell<", "Cell<", "Mutex<", "RwLock<", "static mut"]
					.iter()
					.any(|needle| trimmed.contains(needle));
				if !shared || trimmed.starts_with("use ") {
					continue;
				}
				if ALLOWED.iter().any(|field| trimmed.starts_with(field)) {
					continue;
				}
				offenders.push(format!("{rel}:{number}: {trimmed}"));
			}
		}
		assert!(
			offenders.is_empty(),
			"the solver's interior mutability is confined to its own memo tables; 			 a cell over analysis state would let a search bug reach past the 			 validator: {offenders:?}"
		);
	}

	#[test]
	fn the_solver_cannot_reach_query_evaluation_except_through_the_validator() {
		let offenders: Vec<String> = engine_sources()
			.into_iter()
			.filter(|p| p.to_string_lossy().contains("/solve/"))
			.filter(|p| !p.ends_with("validate.rs"))
			.filter(|p| {
				shipping_lines(p).iter().any(|(_, line)| {
					line.contains("verify_resolve_queries")
						|| line.contains("results_put")
						|| line.contains("emit_query_result")
				})
			})
			.map(|p| p.to_string_lossy().into_owned())
			.collect();
		assert!(
			offenders.is_empty(),
			"the search is outside the trusted base only for as long as it cannot \
			 record anything: {offenders:?}"
		);
	}
}
