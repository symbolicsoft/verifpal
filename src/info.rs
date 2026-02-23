/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::borrow::Cow;

use crate::primitive::primitive_has_single_output;
use crate::types::*;
use crate::util::color_output_support;
use crate::value::*;
use colored::*;

// ---------------------------------------------------------------------------
// Banner and separators
// ---------------------------------------------------------------------------

pub(crate) fn info_banner(version: &str) {
	if color_output_support() {
		println!("{}", "\u{2500}".repeat(50).dimmed());
		println!(
			"  {} {} {} {}",
			"\u{25c6}".green(),
			"Verifpal".green().bold(),
			version.dimmed(),
			"\u{00b7} https://verifpal.com".dimmed()
		);
		println!("{}", "\u{2500}".repeat(50).dimmed());
	} else {
		println!("Verifpal {} - https://verifpal.com", version);
	}
}

pub(crate) fn info_separator() {
	if color_output_support() {
		println!("{}", "\u{2500}".repeat(50).dimmed());
	} else {
		println!("{}", "-".repeat(50));
	}
}

// ---------------------------------------------------------------------------
// Core message output
// ---------------------------------------------------------------------------

pub(crate) fn info_message(msg: &str, level: InfoLevel, show_analysis: bool) {
	if crate::tui::tui_enabled() {
		crate::tui::tui_message(msg, level);
		return;
	}
	let analysis_count = if show_analysis {
		crate::context::analysis_count_get()
	} else {
		0
	};
	if color_output_support() {
		info_message_color(msg, level, analysis_count);
	} else {
		info_message_regular(msg, level, analysis_count);
	}
}

fn info_message_regular(msg: &str, level: InfoLevel, analysis_count: usize) {
	let info_string = if analysis_count > 0 {
		format!(" (Analysis {})", analysis_count)
	} else {
		String::new()
	};
	match level {
		InfoLevel::Verifpal => println!(" Verifpal * {}{}", msg, info_string),
		InfoLevel::Info => println!("     Info . {}{}", msg, info_string),
		InfoLevel::Analysis => println!(" Analysis > {}{}", msg, info_string),
		InfoLevel::Deduction => println!("Deduction > {}{}", msg, info_string),
		InfoLevel::Result => println!("     FAIL x {}{}", msg, info_string),
		InfoLevel::Pass => println!("     PASS + {}{}", msg, info_string),
		InfoLevel::Warning => println!("  Warning ! {}{}", msg, info_string),
	}
}

fn info_message_color(msg: &str, level: InfoLevel, analysis_count: usize) {
	let info_string = if analysis_count > 0 {
		format!(
			" {}",
			format!("(Analysis {})", analysis_count).dimmed().italic()
		)
	} else {
		String::new()
	};
	match level {
		InfoLevel::Verifpal => {
			println!(
				" {} {} {}{}",
				"Verifpal".green().bold(),
				"\u{25c6}".green(),
				msg,
				info_string
			);
		}
		InfoLevel::Info => {
			println!(
				"     {} {} {}{}",
				"Info".cyan().bold(),
				"\u{25cf}".cyan(),
				msg,
				info_string
			);
		}
		InfoLevel::Analysis => {
			println!(
				" {} {} {}{}",
				"Analysis".blue().bold(),
				"\u{25b8}".blue(),
				msg.dimmed(),
				info_string
			);
		}
		InfoLevel::Deduction => {
			println!(
				"{} {} {}{}",
				"Deduction".yellow(),
				"\u{203a}".yellow(),
				msg.dimmed(),
				info_string
			);
		}
		InfoLevel::Result => {
			println!(
				"     {} {} {}{}",
				"Fail".red().bold(),
				"\u{2717}".red().bold(),
				msg,
				info_string
			);
		}
		InfoLevel::Pass => {
			println!(
				"     {} {} {}{}",
				"Pass".green().bold(),
				"\u{2713}".green().bold(),
				msg,
				info_string
			);
		}
		InfoLevel::Warning => {
			println!(
				"  {} {} {}{}",
				"Warning".yellow().bold(),
				"\u{25b2}".yellow().bold(),
				msg,
				info_string
			);
		}
	}
}

// ---------------------------------------------------------------------------
// Result summary formatting
// ---------------------------------------------------------------------------

pub(crate) fn info_verify_result_summary(
	mutated_info: &str,
	summary: &str,
	option_results: &[QueryOptionResult],
) -> String {
	let indent = "            "; // 12 spaces — aligns with message column

	if color_output_support() {
		let mut output = String::new();

		if !mutated_info.is_empty() {
			output.push_str(&format!(
				"\n{}{} {}",
				indent,
				"\u{256d}\u{2500}".dimmed(),
				"Attack trace:".dimmed().italic()
			));

			for line in mutated_info.split('\n') {
				let trimmed = line.trim();
				if trimmed.is_empty() {
					continue;
				}
				if trimmed.starts_with("In another session:") {
					output.push_str(&format!("\n{}{}", indent, "\u{2502}".dimmed()));
					output.push_str(&format!(
						"\n{}{} {}",
						indent,
						"\u{2502}".dimmed(),
						trimmed.italic().dimmed()
					));
				} else {
					output.push_str(&format!("\n{}{} {}", indent, "\u{2502}".dimmed(), trimmed));
				}
			}
			output.push_str(&format!(
				"\n{}{} {}",
				indent,
				"\u{2570}\u{25b8}".dimmed(),
				summary.on_red().white().bold()
			));
		} else {
			output.push_str(&format!("\n{}{}", indent, summary.on_red().white().bold()));
		}

		for o_result in option_results {
			if !o_result.resolved {
				continue;
			}
			output.push_str(&format!(
				"\n{}{} {}",
				indent,
				"\u{25b2}".yellow(),
				o_result.summary.yellow().italic()
			));
		}

		output
	} else {
		let mut output = String::new();

		if !mutated_info.is_empty() {
			output.push_str(&format!("\n{}Attack trace:", indent));
			for line in mutated_info.split('\n') {
				let trimmed = line.trim();
				if trimmed.is_empty() {
					continue;
				}
				output.push_str(&format!("\n{}| {}", indent, trimmed));
			}
			output.push_str(&format!("\n{}> {}", indent, summary));
		} else {
			output.push_str(&format!("\n{}{}", indent, summary));
		}

		for o_result in option_results {
			if !o_result.resolved {
				continue;
			}
			output.push_str(&format!("\n{}! {}", indent, o_result.summary));
		}

		output
	}
}

// ---------------------------------------------------------------------------
// Analysis progress
// ---------------------------------------------------------------------------

pub(crate) fn info_analysis(stage: i32) {
	let analysis_count = crate::context::analysis_count_get();
	// Throttle updates — only print at intervals proportional to count
	let interval = match analysis_count {
		c if c > 100000 => 10000,
		c if c > 10000 => 1000,
		c if c > 1000 => 100,
		c if c > 100 => 10,
		_ => 1,
	};
	if interval > 1 && !analysis_count.is_multiple_of(interval) {
		return;
	}
	let owned;
	let s: &str = match stage {
		1 => "1",
		2 | 3 => "2-3",
		4 | 5 => "4-5",
		_ => {
			owned = stage.to_string();
			&owned
		}
	};
	if crate::tui::tui_enabled() {
		crate::tui::tui_progress(s, analysis_count);
		return;
	}
	if color_output_support() {
		let progress = format!(
			"  {} Stage {}, Analysis {}...",
			"\u{25b8}".blue(),
			s,
			analysis_count
		)
		.dimmed()
		.italic();
		print!("{}", progress);
	} else {
		print!("  Stage {}, Analysis {}...", s, analysis_count);
	}
	print!("\r");
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

pub(crate) fn info_literal_number(n: usize, title_case: bool) -> Cow<'static, str> {
	if n > 9 {
		return format!("{}th", n).into();
	}
	let words = if title_case {
		&[
			"First", "Second", "Third", "Fourth", "Fifth", "Sixth", "Seventh", "Eighth", "Ninth",
			"Tenth",
		]
	} else {
		&[
			"first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth", "ninth",
			"tenth",
		]
	};
	Cow::Borrowed(words[n])
}

pub(crate) fn info_output_text(revealed: &Value) -> String {
	match revealed {
		Value::Constant(_) | Value::Equation(_) => revealed.to_string(),
		Value::Primitive(p) => {
			if primitive_has_single_output(p.id) {
				format!("Output of {}", revealed)
			} else {
				let prefix = format!("{} output", info_literal_number(p.output, true));
				format!("{} of {}", prefix, revealed)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Mutation trace output
// ---------------------------------------------------------------------------

pub(crate) fn info_query_mutated_values(
	trace: &ProtocolTrace,
	diffs: &[SlotDiff],
	val_attacker_state: &AttackerState,
	target_value: &Value,
	info_depth: usize,
) -> String {
	let mut mutated: Vec<Value> = Vec::new();
	let target_info = "In another session:";
	let mut mutated_info = String::new();
	let mut relevant = false;

	for diff in diffs {
		let is_target = target_value.equivalent(&diff.assigned, false);
		let attacker_knows = val_attacker_state.knows(target_value).is_some();

		let (diff_info, diff_relevant) =
			info_query_mutated_value(trace, diff, is_target, attacker_knows);
		if diff_relevant {
			relevant = true;
		}
		mutated_info.push_str("\n            ");
		mutated_info.push_str(&diff_info);

		if is_target && attacker_knows {
			// target obtained
		} else if diff.mutated && find_equivalent(&diff.assigned, &mutated).is_none() {
			mutated.push(diff.assigned.clone());
		}
	}
	if !relevant {
		return String::new();
	}
	if info_depth >= 2 {
		return mutated_info;
	}
	for m_val in &mutated {
		let attacker_idx = match val_attacker_state.knows(m_val) {
			Some(idx) => idx,
			None => continue,
		};
		let nested_info = info_query_mutated_values(
			trace,
			&val_attacker_state.mutation_records[attacker_idx].diffs,
			val_attacker_state,
			m_val,
			info_depth + 1,
		);
		if !nested_info.is_empty() {
			mutated_info = format!(
				"{}\n\n            {}{}",
				nested_info, target_info, mutated_info
			);
		}
	}
	mutated_info
}

fn info_query_mutated_value(
	trace: &ProtocolTrace,
	diff: &SlotDiff,
	is_target_value: bool,
	attacker_knows: bool,
) -> (String, bool) {
	let constant_str = diff.constant.to_string();
	let assigned_str = diff.assigned.to_string();
	let mut relevant = false;
	let suffix;
	if is_target_value && attacker_knows && !diff.mutated {
		relevant = true;
		if color_output_support() {
			suffix = format!(
				" {} {}",
				"\u{2190}".red(),
				"obtained by Attacker".red().bold()
			);
		} else {
			suffix = " <- obtained by Attacker".to_string();
		}
	} else if diff.mutated {
		relevant = true;
		if color_output_support() {
			suffix = format!(
				" {} {} {}",
				"\u{2190}".red(),
				"mutated by Attacker".red().bold(),
				format!("(was: {})", trace.slots[diff.index].initial_value).dimmed()
			);
		} else {
			suffix = format!(
				" <- mutated by Attacker (originally {})",
				trace.slots[diff.index].initial_value,
			);
		}
	} else {
		suffix = String::new();
	}
	if color_output_support() {
		(
			format!(
				"{} {} {}{}",
				constant_str,
				"\u{2192}".dimmed(),
				assigned_str,
				suffix
			),
			relevant,
		)
	} else {
		(
			format!("{} -> {}{}", constant_str, assigned_str, suffix),
			relevant,
		)
	}
}
