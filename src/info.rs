/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::borrow::Cow;
use std::cell::Cell;
use std::sync::{LazyLock, Mutex};

use crate::primitive::primitive_has_single_output;
use crate::types::*;
#[cfg(feature = "cli")]
use crate::util::color_output_support;
#[cfg(feature = "cli")]
use colored::*;

const DEDUCTION_MESSAGE_LIMIT: usize = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
	Silent,
	Quiet,
	Normal,
	Verbose,
}

thread_local! {
	static QUIET_DEPTH: Cell<usize> = const { Cell::new(0) };
	static DEDUCTIONS_SHOWN: Cell<usize> = const { Cell::new(0) };
	static DEDUCTIONS_SUPPRESSED: Cell<usize> = const { Cell::new(0) };
	static VERBOSITY: Cell<Verbosity> = const { Cell::new(Verbosity::Normal) };
}

#[cfg(feature = "cli")]
thread_local! {
	static STATUS_DRAWN: Cell<bool> = const { Cell::new(false) };
	static STATUS_LAST: Cell<Option<std::time::Instant>> = const { Cell::new(None) };
	static STATUS_START: Cell<Option<std::time::Instant>> = const { Cell::new(None) };
}

#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "cli")))]
thread_local! {
	static WASM_STATUS_START: Cell<Option<f64>> = const { Cell::new(None) };
}

#[cfg(feature = "cli")]
const STATUS_INTERVAL: std::time::Duration = std::time::Duration::from_millis(80);

#[cfg(feature = "cli")]
const STATUS_WIDTH: usize = 96;

pub fn set_verbosity(level: Verbosity) {
	VERBOSITY.set(level);
}

pub(crate) fn verbosity() -> Verbosity {
	VERBOSITY.get()
}

fn level_is_visible(level: InfoLevel) -> bool {
	match verbosity() {
		Verbosity::Silent => false,
		Verbosity::Quiet => matches!(
			level,
			InfoLevel::Result | InfoLevel::Pass | InfoLevel::Warning
		),
		Verbosity::Normal => !matches!(level, InfoLevel::Analysis | InfoLevel::Deduction),
		Verbosity::Verbose => true,
	}
}

fn chrome_is_visible() -> bool {
	verbosity() >= Verbosity::Normal && !info_is_quiet()
}

pub(crate) fn info_is_quiet() -> bool {
	QUIET_DEPTH.get() > 0
}

fn emit(line: String) {
	use std::io::Write as _;
	let _ = writeln!(std::io::stdout().lock(), "{line}");
}

#[cfg(feature = "cli")]
fn status_enabled() -> bool {
	!cfg!(test)
		&& !info_is_quiet()
		&& verbosity() >= Verbosity::Normal
		&& crate::util::stderr_is_terminal()
}

pub(crate) fn info_status_begin() {
	#[cfg(feature = "cli")]
	{
		STATUS_START.set(Some(std::time::Instant::now()));
		STATUS_LAST.set(None);
	}
	#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "cli")))]
	WASM_STATUS_START.set(Some(js_sys::Date::now()));
}

#[cfg(feature = "cli")]
pub(crate) fn info_status_elapsed() -> Option<std::time::Duration> {
	STATUS_START.get().map(|start| start.elapsed())
}

#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "cli")))]
pub(crate) fn info_status_elapsed() -> Option<std::time::Duration> {
	let start = WASM_STATUS_START.get()?;
	std::time::Duration::try_from_secs_f64((js_sys::Date::now() - start).max(0.0) / 1000.0).ok()
}

#[cfg(not(any(feature = "cli", all(feature = "wasm", target_arch = "wasm32"))))]
pub(crate) fn info_status_elapsed() -> Option<std::time::Duration> {
	None
}

pub(crate) fn info_status_update(_text: impl FnOnce() -> String) {
	#[cfg(feature = "cli")]
	{
		if !status_enabled() {
			return;
		}
		let now = std::time::Instant::now();
		if let Some(last) = STATUS_LAST.get()
			&& now.duration_since(last) < STATUS_INTERVAL
		{
			return;
		}
		STATUS_LAST.set(Some(now));
		status_draw(&_text());
	}
	#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
	crate::wasm::progress_status(_text);
}

#[cfg(feature = "cli")]
fn status_draw(text: &str) {
	use std::io::Write;
	let trimmed: String = text.chars().take(STATUS_WIDTH).collect();
	let _ = std::io::stdout().flush();
	let mut err = std::io::stderr();
	let _ = write!(err, "\r\u{1b}[2K{}", trimmed.dimmed());
	let _ = err.flush();
	STATUS_DRAWN.set(true);
}

fn info_status_erase() {
	#[cfg(feature = "cli")]
	{
		if !STATUS_DRAWN.get() {
			return;
		}
		use std::io::Write;
		let mut err = std::io::stderr();
		let _ = write!(err, "\r\u{1b}[2K");
		let _ = err.flush();
		STATUS_DRAWN.set(false);
	}
}

pub(crate) fn info_status_end() {
	info_status_erase();
	#[cfg(feature = "cli")]
	STATUS_LAST.set(None);
	#[cfg(all(feature = "wasm", target_arch = "wasm32", not(feature = "cli")))]
	WASM_STATUS_START.set(None);
}

pub(crate) fn info_elapsed_text(elapsed: std::time::Duration) -> String {
	let seconds = elapsed.as_secs_f64();
	if seconds >= 1.0 {
		return format!("{:.2}s", seconds);
	}
	format!("{}ms", elapsed.as_millis())
}

pub(crate) fn info_blank_line() {
	if cfg!(target_arch = "wasm32") || !chrome_is_visible() {
		return;
	}
	info_status_erase();
	emit(String::new());
}

pub(crate) fn info_reset_deductions() {
	DEDUCTIONS_SHOWN.set(0);
	DEDUCTIONS_SUPPRESSED.set(0);
}

pub(crate) fn info_deductions_suppressed() -> usize {
	DEDUCTIONS_SUPPRESSED.get()
}

pub(crate) fn info_deduction(message: impl FnOnce() -> String) {
	if info_is_quiet() || !level_is_visible(InfoLevel::Deduction) {
		return;
	}
	let shown = DEDUCTIONS_SHOWN.get();
	if shown >= DEDUCTION_MESSAGE_LIMIT {
		let suppressed = DEDUCTIONS_SUPPRESSED.get() + 1;
		DEDUCTIONS_SUPPRESSED.set(suppressed);
		if suppressed == 1 {
			info_message(
				&format!(
					"Further deductions are being suppressed after {} messages; the analysis continues in full.",
					DEDUCTION_MESSAGE_LIMIT
				),
				InfoLevel::Info,
			);
		}
		return;
	}
	DEDUCTIONS_SHOWN.set(shown + 1);
	info_line(&message(), InfoLevel::Deduction, true);
}

pub(crate) fn info_analysis_result(headline: &str, full: impl FnOnce() -> String) {
	match verbosity() {
		Verbosity::Silent | Verbosity::Quiet => {}
		Verbosity::Normal => info_line(headline, InfoLevel::Result, true),
		Verbosity::Verbose => info_line(&full(), InfoLevel::Result, true),
	}
}

#[cfg(any(test, feature = "wasm"))]
pub(crate) struct InfoQuiet;

#[cfg(any(test, feature = "wasm"))]
impl InfoQuiet {
	pub(crate) fn new() -> InfoQuiet {
		QUIET_DEPTH.set(QUIET_DEPTH.get() + 1);
		InfoQuiet
	}
}

#[cfg(any(test, feature = "wasm"))]
impl Drop for InfoQuiet {
	fn drop(&mut self) {
		QUIET_DEPTH.set(QUIET_DEPTH.get().saturating_sub(1));
	}
}

static WASM_MSG_BUF: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(Vec::new()));

#[cfg(feature = "wasm")]
pub(crate) fn wasm_messages_init() {
	WASM_MSG_BUF
		.lock()
		.unwrap_or_else(|e| e.into_inner())
		.clear();
}

#[cfg(feature = "wasm")]
pub(crate) fn wasm_messages_drain() -> Vec<String> {
	WASM_MSG_BUF
		.lock()
		.unwrap_or_else(|e| e.into_inner())
		.drain(..)
		.collect()
}

fn wasm_push(msg: String) {
	#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
	crate::wasm::progress_message(&msg);
	WASM_MSG_BUF
		.lock()
		.unwrap_or_else(|e| e.into_inner())
		.push(msg);
}

pub fn info_banner(version: &str) {
	let plain = format!("Verifpal {version} - https://verifpal.com");
	if cfg!(target_arch = "wasm32") {
		wasm_push(plain);
		return;
	}
	if !chrome_is_visible() {
		return;
	}
	#[cfg(feature = "cli")]
	if color_output_support() {
		emit(rule());
		emit(format!(
			"  {} {} {} {}",
			"\u{25c6}".green(),
			"Verifpal".green().bold(),
			version.dimmed(),
			"\u{00b7} https://verifpal.com".dimmed()
		));
		emit(rule());
		return;
	}
	emit(plain);
}

pub(crate) fn info_separator() {
	if cfg!(target_arch = "wasm32") || !chrome_is_visible() {
		return;
	}
	info_status_erase();
	#[cfg(feature = "cli")]
	if color_output_support() {
		emit(rule());
		return;
	}
	emit("-".repeat(50));
}

#[cfg(feature = "cli")]
fn rule() -> String {
	"\u{2500}".repeat(50).dimmed().to_string()
}

fn level_columns(
	level: InfoLevel,
) -> (
	&'static str,
	&'static str,
	&'static str,
	&'static str,
	&'static str,
) {
	match level {
		InfoLevel::Verifpal => (" ", "Verifpal", "*", "Verifpal", "\u{25c6}"),
		InfoLevel::Info => ("     ", "Info", ".", "Info", "\u{25cf}"),
		InfoLevel::Analysis => (" ", "Analysis", ">", "Analysis", "\u{25b8}"),
		InfoLevel::Deduction => ("", "Deduction", ">", "Deduction", "\u{203a}"),
		InfoLevel::Result => ("     ", "FAIL", "x", "Fail", "\u{2717}"),
		InfoLevel::Pass => ("     ", "PASS", "+", "Pass", "\u{2713}"),
		InfoLevel::Warning => ("  ", "Warning", "!", "Warning", "\u{25b2}"),
	}
}

#[cfg(feature = "cli")]
fn level_styling(level: InfoLevel) -> (Color, bool, bool, bool) {
	match level {
		InfoLevel::Verifpal => (Color::Green, true, false, false),
		InfoLevel::Info => (Color::Cyan, true, false, false),
		InfoLevel::Analysis => (Color::Blue, true, false, true),
		InfoLevel::Deduction => (Color::Yellow, false, false, true),
		InfoLevel::Result => (Color::Red, true, true, false),
		InfoLevel::Pass => (Color::Green, true, true, false),
		InfoLevel::Warning => (Color::Yellow, true, true, false),
	}
}

pub fn info_message(msg: &str, level: InfoLevel) {
	info_line(msg, level, false);
}

fn info_line(msg: &str, level: InfoLevel, show_analysis: bool) {
	if info_is_quiet() {
		return;
	}
	let (indent, plain_label, plain_symbol, ..) = level_columns(level);
	if cfg!(target_arch = "wasm32") {
		wasm_push(format!("[{}] {}", plain_label, msg));
		return;
	}
	if !level_is_visible(level) {
		return;
	}
	info_status_erase();
	let analysis_count = if show_analysis {
		crate::context::analysis_count_get()
	} else {
		0
	};
	#[cfg(feature = "cli")]
	if color_output_support() {
		info_message_color(msg, level, analysis_count);
		return;
	}
	let suffix = if analysis_count > 0 {
		format!(" (Analysis {})", analysis_count)
	} else {
		String::new()
	};
	emit(format!(
		"{indent}{plain_label} {plain_symbol} {msg}{suffix}"
	));
}

#[cfg(feature = "cli")]
fn info_message_color(msg: &str, level: InfoLevel, analysis_count: usize) {
	let (indent, _, _, label, symbol) = level_columns(level);
	let (color, label_bold, symbol_bold, dim_message) = level_styling(level);
	let paint = |text: &str, bold: bool| {
		let painted = text.color(color);
		if bold { painted.bold() } else { painted }
	};
	let suffix = if analysis_count > 0 {
		format!(
			" {}",
			format!("(Analysis {})", analysis_count).dimmed().italic()
		)
	} else {
		String::new()
	};
	emit(format!(
		"{}{} {} {}{}",
		indent,
		paint(label, label_bold),
		paint(symbol, symbol_bold),
		if dim_message {
			msg.dimmed()
		} else {
			msg.normal()
		},
		suffix
	));
}

const TRACE_INDENT: &str = "            ";

pub(crate) fn info_verify_result_summary(
	mutated_info: &str,
	summary: &str,
	option_results: &[QueryOptionResult],
) -> String {
	#[cfg(feature = "cli")]
	if color_output_support() {
		return info_verify_result_summary_color(mutated_info, summary, option_results);
	}
	info_verify_result_summary_plain(mutated_info, summary, option_results)
}

fn trace_lines(mutated_info: &str) -> impl Iterator<Item = &str> {
	mutated_info
		.split('\n')
		.map(str::trim)
		.filter(|line| !line.is_empty())
}

fn info_verify_result_summary_plain(
	mutated_info: &str,
	summary: &str,
	option_results: &[QueryOptionResult],
) -> String {
	let mut output = String::new();
	if !mutated_info.is_empty() {
		output.push_str(&format!("\n{TRACE_INDENT}Attack trace:"));
		for line in trace_lines(mutated_info) {
			output.push_str(&format!("\n{TRACE_INDENT}| {line}"));
		}
		output.push_str(&format!("\n{TRACE_INDENT}> {summary}"));
	} else {
		output.push_str(&format!("\n{TRACE_INDENT}{summary}"));
	}
	for o in option_results {
		output.push_str(&format!("\n{TRACE_INDENT}! {}", o.summary));
	}
	output
}

#[cfg(feature = "cli")]
fn info_verify_result_summary_color(
	mutated_info: &str,
	summary: &str,
	option_results: &[QueryOptionResult],
) -> String {
	let mut output = String::new();
	if !mutated_info.is_empty() {
		output.push_str(&format!(
			"\n{TRACE_INDENT}{} {}",
			"\u{256d}\u{2500}".dimmed(),
			"Attack trace:".dimmed().italic()
		));
		for line in trace_lines(mutated_info) {
			output.push_str(&format!("\n{TRACE_INDENT}{} {line}", "\u{2502}".dimmed()));
		}
		output.push_str(&format!(
			"\n{TRACE_INDENT}{} {}",
			"\u{2570}\u{25b8}".dimmed(),
			summary.on_red().white().bold()
		));
	} else {
		output.push_str(&format!(
			"\n{TRACE_INDENT}{}",
			summary.on_red().white().bold()
		));
	}
	for o in option_results {
		output.push_str(&format!(
			"\n{TRACE_INDENT}{} {}",
			"\u{25b2}".yellow(),
			o.summary.yellow().italic()
		));
	}
	output
}

fn ordinal(n: usize) -> Cow<'static, str> {
	const WORDS: [&str; 10] = [
		"First", "Second", "Third", "Fourth", "Fifth", "Sixth", "Seventh", "Eighth", "Ninth",
		"Tenth",
	];
	if let Some(word) = WORDS.get(n) {
		return Cow::Borrowed(word);
	}
	let ordinal = n + 1;
	let suffix = match (ordinal % 10, ordinal % 100) {
		(_, 11..=13) => "th",
		(1, _) => "st",
		(2, _) => "nd",
		(3, _) => "rd",
		_ => "th",
	};
	format!("{ordinal}{suffix}").into()
}

pub(crate) fn info_output_text(revealed: &Value) -> String {
	match revealed {
		Value::Constant(_) => revealed.to_string(),
		Value::Primitive(p) if primitive_has_single_output(p.id) => {
			format!("Output of {revealed}")
		}
		Value::Primitive(p) => format!("{} output of {revealed}", ordinal(p.output)),
	}
}

#[cfg(test)]
mod tests {

	#[test]
	fn verbosity_decides_which_levels_reach_the_terminal() {
		use crate::info::{Verbosity, level_is_visible, set_verbosity};
		use crate::types::InfoLevel;
		set_verbosity(Verbosity::Normal);
		assert!(level_is_visible(InfoLevel::Result));
		assert!(level_is_visible(InfoLevel::Info));
		assert!(!level_is_visible(InfoLevel::Analysis));
		assert!(!level_is_visible(InfoLevel::Deduction));
		set_verbosity(Verbosity::Verbose);
		assert!(level_is_visible(InfoLevel::Deduction));
		set_verbosity(Verbosity::Quiet);
		assert!(level_is_visible(InfoLevel::Result));
		assert!(level_is_visible(InfoLevel::Warning));
		assert!(!level_is_visible(InfoLevel::Info));
		set_verbosity(Verbosity::Silent);
		assert!(!level_is_visible(InfoLevel::Result));
		set_verbosity(Verbosity::Normal);
	}

	#[test]
	fn elapsed_text_switches_unit_at_one_second() {
		use crate::info::info_elapsed_text;
		use std::time::Duration;
		assert_eq!(info_elapsed_text(Duration::from_millis(7)), "7ms");
		assert_eq!(info_elapsed_text(Duration::from_millis(999)), "999ms");
		assert_eq!(info_elapsed_text(Duration::from_millis(1400)), "1.40s");
	}

	#[test]
	fn info_quiet_guard_nests_and_restores() {
		use crate::info::{InfoQuiet, info_is_quiet};
		assert!(!info_is_quiet());
		{
			let _outer = InfoQuiet::new();
			assert!(info_is_quiet());
			{
				let _inner = InfoQuiet::new();
				assert!(info_is_quiet());
			}
			assert!(info_is_quiet(), "inner guard must not un-quiet the outer");
		}
		assert!(!info_is_quiet());
	}
}
