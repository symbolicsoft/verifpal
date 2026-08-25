/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::info::InfoQuiet;
use crate::types::*;

const SESSIONS: u8 = 1;

fn code_of(model: &Model, sessions: u8) -> Option<String> {
	let rendered = crate::pretty::pretty_model(model);
	let reparsed = crate::parser::parse_string(&model.file_name, &rendered).ok()?;
	let _quiet = InfoQuiet::new();
	let ctx = crate::verify::analyze_sessions(&reparsed, sessions).ok()?;
	Some(VerifyResult::results_code(&ctx.results_get()))
}

fn code_direct(model: &Model, sessions: u8) -> Option<String> {
	let _quiet = InfoQuiet::new();
	let ctx = crate::verify::analyze_sessions(model, sessions).ok()?;
	Some(VerifyResult::results_code(&ctx.results_get()))
}

fn corpus() -> Vec<(String, Model)> {
	crate::model_tests::swept_models()
		.into_iter()
		.filter_map(|(name, path)| {
			let source = std::fs::read_to_string(&path).ok()?;
			let model = crate::parser::parse_string(&name, &source).ok()?;
			Some((name, model))
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn rendering_and_reparsing_a_model_preserves_every_verdict() {
		let mut drifted = Vec::new();
		let mut compared = 0usize;
		for (name, model) in corpus() {
			let Some(direct) = code_direct(&model, SESSIONS) else {
				continue;
			};
			compared += 1;
			match code_of(&model, SESSIONS) {
				Some(round_tripped) if round_tripped == direct => {}
				other => drifted.push(format!("{name}: direct={direct} round-tripped={other:?}")),
			}
		}
		assert!(
			compared > 300,
			"only {compared} models reached the comparison, so this test is passing \
			 vacuously and every property built on the pipeline is measuring nothing"
		);
		assert!(
			drifted.is_empty(),
			"a model analysed differently after being rendered and re-parsed, so every \
			 metamorphic result below would be measuring the printer rather than the \
			 engine:\n  {}",
			drifted.join("\n  ")
		);
	}
}
