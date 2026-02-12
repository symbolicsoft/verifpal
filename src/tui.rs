/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, RwLock};
use std::time::Instant;

use colored::*;

use crate::narrative::{self, NarrativeContext};
use crate::pretty::pretty_constants;
use crate::principal::principal_get_name_from_id;
use crate::types::*;
use crate::util::color_output_support;

// ── ANSI escape codes ──────────────────────────────────────────────────────

const ESC_HOME: &str = "\x1b[H";
const ESC_HIDE_CURSOR: &str = "\x1b[?25l";
const ESC_SHOW_CURSOR: &str = "\x1b[?25h";
const ESC_ALT_SCREEN: &str = "\x1b[?1049h";
const ESC_NORMAL_SCREEN: &str = "\x1b[?1049l";
const ESC_CLEAR_LINE: &str = "\x1b[2K";
const ESC_CLEAR_TO_EOL: &str = "\x1b[K";

// ── Global state ───────────────────────────────────────────────────────────

static TUI_MODE: AtomicBool = AtomicBool::new(false);
static TUI_OUT: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static LAST_REDRAW_MS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn set_tui_mode(enabled: bool) {
	TUI_MODE.store(enabled, Ordering::Relaxed);
}

pub(crate) fn tui_mode() -> bool {
	TUI_MODE.load(Ordering::Relaxed)
}

fn now_ms() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_millis() as u64)
		.unwrap_or(0)
}

fn should_redraw() -> bool {
	let now = now_ms();
	let last = LAST_REDRAW_MS.load(Ordering::Relaxed);
	if now.saturating_sub(last) < 50 {
		return false;
	}
	LAST_REDRAW_MS.store(now, Ordering::Relaxed);
	true
}

// ── TUI data types ─────────────────────────────────────────────────────────

struct TuiPrincipal {
	name: String,
	n_private: usize,
	n_generated: usize,
	n_computed: usize,
}

struct TuiMsg {
	sender: String,
	recipient: String,
	constants: String,
}

#[derive(Clone)]
enum QStatus {
	Pending,
	Pass,
	Fail,
}

struct TuiQuery {
	text: String,
	status: QStatus,
}

struct TuiState {
	enabled: bool,
	width: usize,
	finished: bool,
	// model
	file_name: String,
	attacker_type: AttackerKind,
	principals: Vec<TuiPrincipal>,
	messages: Vec<TuiMsg>,
	queries: Vec<TuiQuery>,
	// live
	stage: String,
	phase: i32,
	analysis_count: usize,
	total_deductions: usize,
	deductions: Vec<String>,
	frame: usize,
	start_time: Option<Instant>,
	// rich attacker tracking
	attacker_known_count: usize,
	scan_principal: String,
	scan_weight: usize,
	scan_max_weight: usize,
	scan_budget_used: u32,
	scan_budget_total: u32,
	worthwhile_count: usize,
	last_mutations: Vec<String>,
	last_knowledge: Vec<String>,
	narrative: String,
	mitm_target: String,
}

static TUI: LazyLock<RwLock<TuiState>> = LazyLock::new(|| {
	RwLock::new(TuiState {
		enabled: false,
		width: 80,
		finished: false,
		file_name: String::new(),
		attacker_type: AttackerKind::Passive,
		principals: vec![],
		messages: vec![],
		queries: vec![],
		stage: "0".to_string(),
		phase: 0,
		analysis_count: 0,
		total_deductions: 0,
		deductions: vec![],
		frame: 0,
		start_time: None,
		attacker_known_count: 0,
		scan_principal: String::new(),
		scan_weight: 0,
		scan_max_weight: 0,
		scan_budget_used: 0,
		scan_budget_total: 80000,
		worthwhile_count: 0,
		last_mutations: vec![],
		last_knowledge: vec![],
		narrative: String::new(),
		mitm_target: String::new(),
	})
});

// ── Public API ─────────────────────────────────────────────────────────────

pub(crate) fn tui_init(m: &Model) {
	if !color_output_support() || !tui_mode() {
		return;
	}

	let w = terminal_width().max(60);
	let mut st = TUI.write().unwrap_or_else(|e| e.into_inner());
	st.enabled = true;
	st.finished = false;
	st.width = w;
	st.start_time = Some(Instant::now());
	st.file_name = m.file_name.clone();
	st.attacker_type = m.attacker;
	st.phase = 0;
	st.attacker_known_count = 0;
	st.scan_principal.clear();
	st.scan_weight = 0;
	st.scan_max_weight = 0;
	st.scan_budget_used = 0;
	st.scan_budget_total = 80000;
	st.worthwhile_count = 0;
	st.last_mutations.clear();
	st.last_knowledge.clear();
	st.mitm_target.clear();

	for block in &m.blocks {
		match block {
			Block::Principal(principal) => {
				// Deduplicate principals by name, summing stats
				let existing = st
					.principals
					.iter_mut()
					.find(|p| p.name == principal.name);
				let p = if let Some(p) = existing {
					p
				} else {
					st.principals.push(TuiPrincipal {
						name: principal.name.clone(),
						n_private: 0,
						n_generated: 0,
						n_computed: 0,
					});
					// SAFETY: just pushed, so last_mut is always Some
				st.principals.last_mut().unwrap_or_else(|| unreachable!())
				};
				for expr in &principal.expressions {
					match expr.kind {
						Declaration::Knows => {
							p.n_private += expr.constants.len();
						}
						Declaration::Generates => {
							p.n_generated += expr.constants.len();
						}
						Declaration::Assignment => {
							p.n_computed += 1;
						}
						Declaration::Leaks => {}
					}
				}
			}
			Block::Message(message) => {
				st.messages.push(TuiMsg {
					sender: principal_get_name_from_id(message.sender),
					recipient: principal_get_name_from_id(message.recipient),
					constants: pretty_constants(&message.constants),
				});
			}
			Block::Phase(_) => {}
		}
	}

	for query in &m.queries {
		st.queries.push(TuiQuery {
			text: query.to_string(),
			status: QStatus::Pending,
		});
	}

	// Initial narrative
	if st.attacker_type == AttackerKind::Passive {
		st.narrative = narrative::pick_narrative(NarrativeContext::Passive, 0);
	} else {
		st.narrative = narrative::pick_narrative(NarrativeContext::Init, 0);
	}

	// Install panic hook to restore terminal
	let prev = std::panic::take_hook();
	std::panic::set_hook(Box::new(move |info| {
		eprint!("{}{}", ESC_SHOW_CURSOR, ESC_NORMAL_SCREEN);
		prev(info);
	}));

	let _lock = TUI_OUT.lock().unwrap_or_else(|e| e.into_inner());
	print!("{}{}", ESC_ALT_SCREEN, ESC_HIDE_CURSOR);
	drop(st);
	redraw_locked();
	io::stdout().flush().ok();
}

/// Handle an info_message call in TUI mode.
pub(crate) fn tui_message(msg: &str, msg_type: InfoLevel) {
	{
		let mut st = TUI.write().unwrap_or_else(|e| e.into_inner());
		if !st.enabled {
			return;
		}

		match msg_type {
			InfoLevel::Result => {
				for q in st.queries.iter_mut() {
					if msg.starts_with(&q.text) {
						q.status = QStatus::Fail;
						let seed = st.frame as u64 ^ (st.total_deductions as u64);
						st.narrative = narrative::pick_narrative(NarrativeContext::QueryFail, seed);
						break;
					}
				}
			}
			InfoLevel::Deduction => {
				st.total_deductions += 1;
				let max_len = st.width.saturating_sub(10);
				let display = trunc(msg, max_len);
				st.deductions.push(display);
				if st.deductions.len() > 5 {
					st.deductions.remove(0);
				}
				// Extract compact knowledge description
				let compact = compact_knowledge_desc(msg);
				if !compact.is_empty() {
					st.last_knowledge.push(compact);
					if st.last_knowledge.len() > 3 {
						st.last_knowledge.remove(0);
					}
				}
			}
			InfoLevel::Analysis => {
				if msg.contains("Mutation map for") {
					// Extract principal name from "Mutation map for Bob at stage..."
					if let Some(rest) = msg.strip_prefix("Mutation map for ") {
						if let Some(name) = rest.split_whitespace().next() {
							st.scan_principal = name.to_string();
							st.mitm_target = name.to_string();
							let seed = st.frame as u64 ^ (name.len() as u64 * 31);
							st.narrative = narrative::narrative_for_mutation(name, seed);
						}
					}
				} else if msg.contains("Constructed skeleton") {
					// skeleton info — no separate line needed
				} else if msg.contains("Initializing Stage") {
					if let Some(rest) = msg.strip_prefix("Initializing Stage ") {
						if let Some(num) = rest.split_whitespace().next() {
							let stage_str = num.trim_end_matches(',');
							st.stage = stage_str.to_string();
							let seed = stage_str.parse::<u64>().unwrap_or(0);
							st.narrative =
								narrative::pick_narrative(NarrativeContext::Escalation, seed);
						}
					}
				}
			}
			InfoLevel::Info => {
				if msg.starts_with("Running at phase") {
					if let Some(rest) = msg.strip_prefix("Running at phase ") {
						if let Some(num) = rest.strip_suffix('.') {
							st.phase = num.parse().unwrap_or(0);
						}
					}
				}
			}
			_ => {}
		}
	}
	// High-priority events always redraw (result = query failure)
	if msg_type == InfoLevel::Result {
		force_redraw();
	} else {
		tui_redraw();
	}
}

/// Handle an info_analysis progress tick in TUI mode.
pub(crate) fn tui_progress(stage_str: &str, count: usize) {
	{
		let mut st = TUI.write().unwrap_or_else(|e| e.into_inner());
		if !st.enabled {
			return;
		}
		st.stage = stage_str.to_string();
		st.analysis_count = count;
	}
	tui_redraw();
}

/// Update attacker known value count (called from attacker_state_put_write).
pub(crate) fn tui_attacker_known(count: usize) {
	{
		let mut st = TUI.write().unwrap_or_else(|e| e.into_inner());
		if !st.enabled {
			return;
		}
		st.attacker_known_count = count;
		if count > 0 {
			let seed = count as u64;
			st.narrative = narrative::pick_narrative(NarrativeContext::Deduction, seed);
		}
	}
	if should_redraw() {
		tui_redraw();
	}
}

/// Update scan progress (called from verify_active_scan_at_weight).
pub(crate) fn tui_scan_update(
	principal: &str,
	weight: usize,
	max_weight: usize,
	budget_used: u32,
	budget_total: u32,
) {
	{
		let mut st = TUI.write().unwrap_or_else(|e| e.into_inner());
		if !st.enabled {
			return;
		}
		st.scan_principal = principal.to_string();
		st.scan_weight = weight;
		st.scan_max_weight = max_weight;
		st.scan_budget_used = budget_used;
		st.scan_budget_total = budget_total;
		st.mitm_target = principal.to_string();
		if budget_used == 0 {
			let seed = st.frame as u64 ^ (principal.len() as u64 * 37);
			st.narrative = narrative::narrative_for_mutation(principal, seed);
		}
	}
	if should_redraw() {
		tui_redraw();
	}
}

/// Record a worthwhile mutation description (called on worthwhile mutations).
pub(crate) fn tui_mutation_detail(desc: &str) {
	{
		let mut st = TUI.write().unwrap_or_else(|e| e.into_inner());
		if !st.enabled {
			return;
		}
		st.worthwhile_count += 1;
		st.last_mutations.push(desc.to_string());
		if st.last_mutations.len() > 3 {
			st.last_mutations.remove(0);
		}
	}
	// Worthwhile mutations are rare — always redraw
	force_redraw();
}

/// Update stage (called at stage transitions).
pub(crate) fn tui_stage_update(stage: i32) {
	{
		let mut st = TUI.write().unwrap_or_else(|e| e.into_inner());
		if !st.enabled {
			return;
		}
		st.stage = stage.to_string();
		st.worthwhile_count = 0;
		st.last_mutations.clear();
		let seed = stage as u64;
		st.narrative = narrative::pick_narrative(NarrativeContext::Escalation, seed);
	}
	// Stage change is high-priority
	force_redraw();
}

/// Leave the TUI and restore the normal terminal.
pub(crate) fn tui_finish() {
	{
		let mut st = TUI.write().unwrap_or_else(|e| e.into_inner());
		if !st.enabled {
			return;
		}
		for q in st.queries.iter_mut() {
			if matches!(q.status, QStatus::Pending) {
				q.status = QStatus::Pass;
			}
		}
		let any_fail = st.queries.iter().any(|q| matches!(q.status, QStatus::Fail));
		st.finished = true;
		st.narrative = if any_fail {
			narrative::pick_narrative(NarrativeContext::Finished, 0)
		} else {
			narrative::pick_narrative(NarrativeContext::QueryPass, 0)
		};
	}
	force_redraw();
	std::thread::sleep(std::time::Duration::from_millis(800));

	let _lock = TUI_OUT.lock().unwrap_or_else(|e| e.into_inner());
	print!("{}{}", ESC_SHOW_CURSOR, ESC_NORMAL_SCREEN);
	io::stdout().flush().ok();

	TUI.write().unwrap_or_else(|e| e.into_inner()).enabled = false;
}

pub(crate) fn tui_enabled() -> bool {
	if !tui_mode() {
		return false;
	}
	TUI.read().map(|s| s.enabled).unwrap_or(false)
}

// ── Redraw ─────────────────────────────────────────────────────────────────

fn tui_redraw() {
	let _lock = TUI_OUT.lock().unwrap_or_else(|e| e.into_inner());
	redraw_locked();
	io::stdout().flush().ok();
}

fn force_redraw() {
	LAST_REDRAW_MS.store(0, Ordering::Relaxed);
	tui_redraw();
}

fn redraw_locked() {
	let mut st = TUI.write().unwrap_or_else(|e| e.into_inner());
	if !st.enabled {
		return;
	}
	st.frame += 1;
	let w = st.width;
	let frame = st.frame;
	let finished = st.finished;

	let mut buf = String::with_capacity(16384);
	buf.push_str(ESC_HOME);
	draw_header(&mut buf, &st, w, frame, finished);
	draw_protocol(&mut buf, &st, w, frame, finished);
	draw_attacker(&mut buf, &st, w, frame, finished);
	draw_queries(&mut buf, &st, w, frame);
	draw_deductions(&mut buf, &st, w);
	draw_footer(&mut buf, &st, w, finished);
	// Clear any leftover lines below
	for _ in 0..4 {
		buf.push_str(ESC_CLEAR_LINE);
		buf.push('\n');
	}
	print!("{}", buf);
}

// ── Drawing helpers ────────────────────────────────────────────────────────
//
// IMPORTANT: Only use characters from these safe Unicode ranges in
// alignment-critical positions (anything measured by vis_len for padding):
//   - ASCII (U+0020–U+007E)               — always 1 cell
//   - Box Drawing (U+2500–U+257F)         — always 1 cell
//   - Block Elements (U+2580–U+259F)      — always 1 cell
//   - Geometric Shapes (U+25A0–U+25FF)    — always 1 cell
//   - General Punctuation (U+2000–U+206F) — always 1 cell
//
// NEVER use Miscellaneous Symbols (U+2600+), Dingbats (U+2700+), or
// emoji in alignment-critical content — their terminal width varies.

fn vis_len(s: &str) -> usize {
	let mut n = 0;
	let mut esc = false;
	for c in s.chars() {
		if esc {
			if c == 'm' {
				esc = false;
			}
		} else if c == '\x1b' {
			esc = true;
		} else {
			n += 1;
		}
	}
	n
}

fn trunc(s: &str, max: usize) -> String {
	if vis_len(s) <= max {
		return s.to_string();
	}
	let mut vis = 0;
	let mut byte_end = 0;
	let mut esc = false;
	for (i, c) in s.char_indices() {
		if esc {
			if c == 'm' {
				esc = false;
			}
			byte_end = i + c.len_utf8();
			continue;
		}
		if c == '\x1b' {
			esc = true;
			byte_end = i + c.len_utf8();
			continue;
		}
		vis += 1;
		byte_end = i + c.len_utf8();
		if vis >= max.saturating_sub(1) {
			break;
		}
	}
	format!("{}~", &s[..byte_end])
}

/// Wrap content in │...│ padded to width w. Truncates if content exceeds inner width.
fn bline(content: &str, w: usize) -> String {
	let inner = w.saturating_sub(2);
	let clipped = trunc(content, inner);
	let pad = inner.saturating_sub(vis_len(&clipped));
	format!(
		"{}{}{}{}{}\n",
		"\u{2502}".dimmed(),
		clipped,
		" ".repeat(pad),
		"\u{2502}".dimmed(),
		ESC_CLEAR_TO_EOL
	)
}

/// Format content inside the attacker inner box: "    │<content><padding>│", wrapped by bline.
fn inbox_line(buf: &mut String, content: &str, box_inner: usize, w: usize) {
	let pad = box_inner.saturating_sub(vis_len(content));
	let line = format!(
		"    {}{}{}{}",
		"\u{2502}".dimmed(),
		content,
		" ".repeat(pad),
		"\u{2502}".dimmed()
	);
	buf.push_str(&bline(&line, w));
}

fn border_top(w: usize) -> String {
	let inner = w.saturating_sub(2);
	format!(
		"{}{}{}{}\n",
		"\u{256d}".dimmed(),
		"\u{2500}".repeat(inner).dimmed(),
		"\u{256e}".dimmed(),
		ESC_CLEAR_TO_EOL
	)
}

fn border_bot(w: usize) -> String {
	let inner = w.saturating_sub(2);
	format!(
		"{}{}{}{}\n",
		"\u{2570}".dimmed(),
		"\u{2500}".repeat(inner).dimmed(),
		"\u{256f}".dimmed(),
		ESC_CLEAR_TO_EOL
	)
}

fn border_mid(label: &str, w: usize) -> String {
	let inner = w.saturating_sub(2);
	if label.is_empty() {
		return format!(
			"{}{}{}{}\n",
			"\u{251c}".dimmed(),
			"\u{2500}".repeat(inner).dimmed(),
			"\u{2524}".dimmed(),
			ESC_CLEAR_TO_EOL
		);
	}
	let lab = format!(" {} ", label);
	let lab_len = vis_len(&lab);
	let left_dash = 3;
	let right_dash = inner.saturating_sub(left_dash + lab_len);
	format!(
		"{}{}{}{}{}{}\n",
		"\u{251c}".dimmed(),
		"\u{2500}".repeat(left_dash).dimmed(),
		lab.dimmed(),
		"\u{2500}".repeat(right_dash).dimmed(),
		"\u{2524}".dimmed(),
		ESC_CLEAR_TO_EOL
	)
}

// ── Utility ────────────────────────────────────────────────────────────────

/// Extract a compact knowledge description from a deduction message.
/// e.g. "Output of AEAD_DEC(...) obtained by decomposing..." -> "AEAD_DEC via decompose"
fn compact_knowledge_desc(msg: &str) -> String {
	// Try to extract the method
	let method = if msg.contains("decomposing") {
		"decompose"
	} else if msg.contains("reconstructing") {
		"reconstruct"
	} else if msg.contains("recomposing") {
		"recompose"
	} else if msg.contains("equivalizing") {
		"equivalize"
	} else if msg.contains("password") {
		"password"
	} else if msg.contains("concatenated") {
		"concat"
	} else if msg.contains("associated data") {
		"assoc. data"
	} else {
		return String::new();
	};
	// Try to extract the value name — first word or primitive name
	let val_name = if let Some(rest) = msg.strip_prefix("Output of ") {
		rest.split('(').next().unwrap_or("?").to_string()
	} else {
		msg.split_whitespace().next().unwrap_or("?").to_string()
	};
	let val_short = if val_name.chars().count() > 12 {
		let truncated: String = val_name.chars().take(11).collect();
		format!("{}~", truncated)
	} else {
		val_name
	};
	format!("{} via {}", val_short, method)
}

/// Determine deduction color category from a deduction message string.
fn deduction_color(msg: &str) -> &'static str {
	if msg.contains("decomposing") {
		"blue"
	} else if msg.contains("reconstructing") {
		"cyan"
	} else if msg.contains("recomposing") {
		"magenta"
	} else if msg.contains("equivalizing") {
		"yellow"
	} else if msg.contains("password") {
		"red"
	} else if msg.contains("concatenated") {
		"white"
	} else if msg.contains("associated data") {
		"green"
	} else {
		"white"
	}
}

fn color_str(s: &str, color: &str) -> String {
	match color {
		"blue" => s.blue().to_string(),
		"cyan" => s.cyan().to_string(),
		"magenta" => s.magenta().to_string(),
		"yellow" => s.yellow().to_string(),
		"red" => s.red().to_string(),
		"green" => s.green().to_string(),
		_ => s.white().to_string(),
	}
}

// ── Section drawers ────────────────────────────────────────────────────────

fn draw_header(buf: &mut String, st: &TuiState, w: usize, frame: usize, finished: bool) {
	buf.push_str(&border_top(w));

	// Title line
	let left = format!(
		" {} {}",
		"\u{25c6} VERIFPAL".green().bold(),
		env!("CARGO_PKG_VERSION").dimmed()
	);
	let right = if finished {
		format!("{} ", "complete".green().bold())
	} else {
		format!("{} {} ", "analyzing".dimmed().italic(), st.file_name.cyan())
	};
	let gap = (w - 2).saturating_sub(vis_len(&left) + vis_len(&right));
	let title_line = format!("{}{}{}", left, " ".repeat(gap), right);
	buf.push_str(&bline(&title_line, w));

	// Progress bar with richer info
	let inner = w.saturating_sub(2);
	let elapsed = st.start_time.map(|t| t.elapsed().as_secs()).unwrap_or(0);
	let timer = format!(
		"{:02}:{:02}:{:02}",
		elapsed / 3600,
		(elapsed % 3600) / 60,
		elapsed % 60
	);
	let phase_str = if st.phase > 0 {
		format!(" Phase {} |", st.phase)
	} else {
		String::new()
	};
	let info_str = format!(" Stage {} |{} {}", st.stage, phase_str, timer);
	let info_vis = vis_len(&info_str);
	let bar_chars = inner.saturating_sub(2 + info_vis); // 2 for leading "  "
	let scan_pos = if finished || bar_chars == 0 {
		bar_chars
	} else {
		(frame * 3) % (bar_chars * 2) // bounce animation
	};
	let mut bar = String::new();
	bar.push_str("  ");
	for i in 0..bar_chars {
		if finished {
			bar.push_str(&"\u{2501}".green().to_string());
		} else {
			let pos = if scan_pos < bar_chars {
				scan_pos
			} else {
				bar_chars * 2 - scan_pos
			};
			let d = (i as isize - pos as isize).unsigned_abs();
			if d == 0 {
				bar.push_str(&"\u{2588}".cyan().bold().to_string());
			} else if d <= 1 {
				bar.push_str(&"\u{2593}".cyan().to_string());
			} else if d <= 3 {
				bar.push_str(&"\u{2592}".blue().to_string());
			} else if d <= 5 {
				bar.push_str(&"\u{2591}".blue().dimmed().to_string());
			} else {
				bar.push_str(&"\u{2500}".dimmed().to_string());
			}
		}
	}
	if finished {
		let done_info = " done".green().bold().to_string();
		bar.push_str(&format!(" {}", done_info));
		let remaining = inner.saturating_sub(vis_len(&bar));
		bar.push_str(&" ".repeat(remaining));
	} else {
		bar.push_str(&info_str.dimmed().italic().to_string());
	}
	buf.push_str(&bline(&bar, w));

	buf.push_str(&border_mid("", w));
}

fn draw_protocol(buf: &mut String, st: &TuiState, w: usize, frame: usize, finished: bool) {
	buf.push_str(&bline("", w));

	if st.principals.len() == 2 {
		draw_protocol_two(buf, st, w, frame, finished);
	} else {
		draw_protocol_list(buf, st, w, frame, finished);
	}

	buf.push_str(&bline("", w));
}

fn draw_protocol_two(buf: &mut String, st: &TuiState, w: usize, frame: usize, finished: bool) {
	let p1 = &st.principals[0];
	let p2 = &st.principals[1];
	let n1 = p1.name.to_uppercase();
	let n2 = p2.name.to_uppercase();
	let inner = w.saturating_sub(2);

	// Principal header
	let sum1 = format!("{}p {}g {}c", p1.n_private, p1.n_generated, p1.n_computed);
	let sum2 = format!("{}p {}g {}c", p2.n_private, p2.n_generated, p2.n_computed);
	let left_header = format!("  {} {}", n1.cyan().bold(), sum1.dimmed());
	let right_header = format!("{} {}  ", sum2.dimmed(), n2.cyan().bold());
	let hgap = inner.saturating_sub(vis_len(&left_header) + vis_len(&right_header));
	let header_line = format!("{}{}{}", left_header, " ".repeat(hgap), right_header);
	buf.push_str(&bline(&header_line, w));

	// Messages as arrows between principals — with animated dots and MITM
	let indent = vis_len(&n1) + 4;
	let arrow_space = inner.saturating_sub(indent + vis_len(&n2) + 4);

	for (mi, msg) in st.messages.iter().enumerate() {
		let is_right = msg.sender == p1.name; // left->right
		let recipient = if is_right {
			&msg.recipient
		} else {
			&msg.sender
		};
		let is_intercepted =
			!finished && !st.mitm_target.is_empty() && recipient == &st.mitm_target;

		let mitm_label = "\u{25c6} MITM";
		let mitm_vis = 6; // "◆ MITM" = 6 chars
		let available_for_label = if is_intercepted {
			arrow_space.saturating_sub(mitm_vis + 3)
		} else {
			arrow_space.saturating_sub(4)
		};
		let label = trunc(&msg.constants, available_for_label);
		let label_vis = vis_len(&label);

		if is_intercepted {
			// Animated intercepted arrow
			let arrow_fill = arrow_space.saturating_sub(label_vis + 2 + mitm_vis + 1);
			let lf = arrow_fill / 2;
			let rf = arrow_fill.saturating_sub(lf);

			// Pulsing MITM indicator
			let mitm_colored = if frame % 4 < 2 {
				mitm_label.red().bold().to_string()
			} else {
				mitm_label.red().dimmed().to_string()
			};

			// Animated dot position
			let dot_pos = ((frame * 2 + mi * 7) % (lf + rf + 1)) as usize;

			let mut arrow = String::new();
			arrow.push_str(&" ".repeat(indent));

			if is_right {
				// left->right intercepted
				for j in 0..lf {
					if j == dot_pos {
						arrow.push_str(&"\u{2219}".red().bold().to_string());
					} else {
						arrow.push_str(&"\u{2500}".red().dimmed().to_string());
					}
				}
				arrow.push_str(&format!(" {} ", label).red().bold().to_string());
				arrow.push_str(&mitm_colored);
				arrow.push(' ');
				for j in 0..rf {
					if j + lf == dot_pos {
						arrow.push_str(&"\u{2219}".red().bold().to_string());
					} else {
						arrow.push_str(&"\u{2500}".red().dimmed().to_string());
					}
				}
				arrow.push_str(&"\u{25b6}".red().to_string());
			} else {
				// right->left intercepted
				arrow.push_str(&"\u{25c0}".red().to_string());
				for j in 0..lf {
					if j == dot_pos {
						arrow.push_str(&"\u{2219}".red().bold().to_string());
					} else {
						arrow.push_str(&"\u{2500}".red().dimmed().to_string());
					}
				}
				arrow.push_str(&mitm_colored);
				arrow.push(' ');
				arrow.push_str(&format!(" {} ", label).red().bold().to_string());
				for j in 0..rf {
					if j + lf == dot_pos {
						arrow.push_str(&"\u{2219}".red().bold().to_string());
					} else {
						arrow.push_str(&"\u{2500}".red().dimmed().to_string());
					}
				}
			}
			buf.push_str(&bline(&arrow, w));
		} else {
			// Normal arrow with animated dots
			let fill = arrow_space.saturating_sub(label_vis + 2);
			let lf = fill / 2;
			let rf = fill.saturating_sub(lf);
			let dot_pos = if finished {
				usize::MAX
			} else {
				((frame * 2 + mi * 5) % (lf + rf + 1)) as usize
			};

			let mut arrow = String::new();
			arrow.push_str(&" ".repeat(indent));

			if is_right {
				for j in 0..lf {
					if j == dot_pos {
						arrow.push_str(&"\u{2219}".yellow().bold().to_string());
					} else {
						arrow.push_str(&"\u{2500}".yellow().dimmed().to_string());
					}
				}
				arrow.push_str(&format!(" {} ", label).yellow().bold().to_string());
				for j in 0..rf {
					if j + lf + 1 == dot_pos {
						arrow.push_str(&"\u{2219}".yellow().bold().to_string());
					} else {
						arrow.push_str(&"\u{2500}".yellow().dimmed().to_string());
					}
				}
				arrow.push_str(&"\u{25b6}".yellow().to_string());
			} else {
				arrow.push_str(&"\u{25c0}".yellow().to_string());
				for j in 0..lf {
					if j == dot_pos {
						arrow.push_str(&"\u{2219}".yellow().bold().to_string());
					} else {
						arrow.push_str(&"\u{2500}".yellow().dimmed().to_string());
					}
				}
				arrow.push_str(&format!(" {} ", label).yellow().bold().to_string());
				for j in 0..rf {
					if j + lf + 1 == dot_pos {
						arrow.push_str(&"\u{2219}".yellow().bold().to_string());
					} else {
						arrow.push_str(&"\u{2500}".yellow().dimmed().to_string());
					}
				}
			}
			buf.push_str(&bline(&arrow, w));
		}
	}
}

fn draw_protocol_list(buf: &mut String, st: &TuiState, w: usize, _frame: usize, _finished: bool) {
	let inner = w.saturating_sub(2);

	// Build principal entries and wrap across multiple lines if needed
	let entries: Vec<String> = st
		.principals
		.iter()
		.map(|p| {
			let sum = format!("{}p {}g {}c", p.n_private, p.n_generated, p.n_computed);
			format!("{} {}", p.name.to_uppercase().cyan().bold(), sum.dimmed())
		})
		.collect();

	// Pack entries into rows that fit within the box
	let sep = " | ";
	let sep_vis = 3;
	let indent_size = 2; // leading "  "
	let mut row = String::new();
	let mut row_vis = indent_size;
	row.push_str("  ");

	for (i, entry) in entries.iter().enumerate() {
		let entry_vis = vis_len(entry);
		let needed = if i == 0 {
			entry_vis
		} else {
			sep_vis + entry_vis
		};
		if row_vis + needed > inner && row_vis > indent_size {
			buf.push_str(&bline(&row, w));
			row = format!("  {}", entry);
			row_vis = indent_size + entry_vis;
		} else {
			if i > 0 {
				row.push_str(&sep.dimmed().to_string());
				row_vis += sep_vis;
			}
			row.push_str(entry);
			row_vis += entry_vis;
		}
	}
	if row_vis > indent_size {
		buf.push_str(&bline(&row, w));
	}
	buf.push_str(&bline("", w));

	let max_msgs = 5;
	for (i, msg) in st.messages.iter().enumerate() {
		if i >= max_msgs {
			buf.push_str(&bline(
				&format!("    {} more messages...", st.messages.len() - max_msgs)
					.dimmed()
					.to_string(),
				w,
			));
			break;
		}
		let label = trunc(&msg.constants, w.saturating_sub(30));
		let line = format!(
			"    {} {}{}{} {}",
			msg.sender.cyan(),
			"\u{2500}\u{2500}\u{25b6} ".yellow(),
			label.yellow().bold(),
			" \u{2500}\u{2500}\u{25b6}".yellow(),
			msg.recipient.cyan()
		);
		buf.push_str(&bline(&line, w));
	}
}

fn draw_attacker(buf: &mut String, st: &TuiState, w: usize, frame: usize, finished: bool) {
	buf.push_str(&bline("", w));

	// Inner box: 4-space margins on each side within the outer │...│
	let box_inner = w.saturating_sub(12);

	// Attacker box top with pulsing border and knowledge count
	let known_text = format!(" {} known ", st.attacker_known_count);
	let label_text = format!(" ATTACKER ({}) ", st.attacker_type);
	let label_colored = if finished {
		label_text.green().bold().to_string()
	} else if frame % 6 < 3 {
		label_text.red().bold().to_string()
	} else {
		label_text.red().to_string()
	};
	let label_vis = vis_len(&label_text);
	let known_vis = vis_len(&known_text);
	let left_dashes = 3;
	let right_dashes = box_inner.saturating_sub(left_dashes + label_vis + known_vis);
	let known_colored = known_text.dimmed().to_string();
	let right_border = format!(
		"{}{}{}",
		"\u{2500}".repeat(right_dashes).dimmed(),
		known_colored,
		"\u{2510}".dimmed()
	);
	let top_line = format!(
		"    {}{}{}{}",
		"\u{250c}".dimmed(),
		"\u{2500}".repeat(left_dashes).dimmed(),
		label_colored,
		right_border
	);
	buf.push_str(&bline(&top_line, w));

	// Narrative line (1-2 lines of contextual prose)
	let narrative = trunc(&st.narrative, box_inner.saturating_sub(4));
	if !narrative.is_empty() {
		inbox_line(
			buf,
			&format!(" {}", narrative.italic().dimmed()),
			box_inner,
			w,
		);
	}

	// Empty separator line
	inbox_line(buf, "", box_inner, w);

	if st.attacker_type == AttackerKind::Active && !finished {
		// Search progress bar
		let pct = if st.scan_budget_total > 0 {
			((st.scan_budget_used as f64 / st.scan_budget_total as f64) * 100.0) as usize
		} else {
			0
		};
		let bar_label = format!(
			"  SEARCH {}/{}  {}%  wt {}/{}  {} viable",
			st.scan_budget_used,
			st.scan_budget_total,
			pct,
			st.scan_weight,
			st.scan_max_weight,
			st.worthwhile_count
		);
		let bar_label_vis = vis_len(&bar_label);
		let bar_avail = box_inner.saturating_sub(4);
		if bar_label_vis <= bar_avail {
			inbox_line(buf, &format!(" {}", bar_label.dimmed()), box_inner, w);
		}

		// Visual progress bar
		let prog_width = box_inner.saturating_sub(4);
		let filled = (prog_width * pct) / 100;
		let mut prog = String::new();
		prog.push_str("  ");
		for i in 0..prog_width {
			if i < filled {
				prog.push_str(&"\u{2593}".cyan().to_string());
			} else {
				prog.push_str(&"\u{2591}".dimmed().to_string());
			}
		}
		inbox_line(buf, &format!(" {}", prog), box_inner, w);

		// Separator
		inbox_line(buf, "", box_inner, w);

		// Dual-column: MUTATIONS (left) | KNOWLEDGE GAINED (right)
		let half = box_inner.saturating_sub(3) / 2;
		let left_label = " MUTATIONS";
		let right_label = "KNOWLEDGE GAINED ";
		let left_label_pad = half.saturating_sub(vis_len(left_label));
		let right_label_pad = half.saturating_sub(vis_len(right_label));
		let col_header_inner = format!(
			" {}{}{}{}{}{}",
			left_label.dimmed().bold(),
			" ".repeat(left_label_pad),
			" \u{2502} ".dimmed(),
			right_label.dimmed().bold(),
			" ".repeat(right_label_pad),
			""
		);
		inbox_line(buf, &col_header_inner, box_inner, w);

		// 3 rows of dual-column data
		for row_idx in 0..3 {
			let left_content = if row_idx < st.last_mutations.len() {
				let prefix = if row_idx == st.last_mutations.len() - 1 {
					"\u{25b8}".red().to_string()
				} else {
					" ".to_string()
				};
				let mt = trunc(&st.last_mutations[row_idx], half.saturating_sub(3));
				format!(" {} {}", prefix, mt.dimmed())
			} else {
				String::new()
			};
			let right_content = if row_idx < st.last_knowledge.len() {
				let kn = trunc(&st.last_knowledge[row_idx], half.saturating_sub(4));
				let color = deduction_color(&kn);
				format!(" {} {}", color_str("\u{25cf}", color), kn.dimmed())
			} else {
				String::new()
			};

			let lv = vis_len(&left_content);
			let rv = vis_len(&right_content);
			let left_pad = half.saturating_sub(lv);
			let right_pad = half.saturating_sub(rv);

			let row_inner = format!(
				" {}{}{}{}{}",
				left_content,
				" ".repeat(left_pad),
				" \u{2502} ".dimmed(),
				right_content,
				" ".repeat(right_pad),
			);
			inbox_line(buf, &row_inner, box_inner, w);
		}
	} else if finished {
		// Finished state
		inbox_line(
			buf,
			&format!(" {}", "Analysis complete.".green()),
			box_inner,
			w,
		);
	} else {
		// Passive attacker — just show knowledge
		if !st.last_knowledge.is_empty() {
			for kn in &st.last_knowledge {
				let kn_trunc = trunc(kn, box_inner.saturating_sub(6));
				inbox_line(
					buf,
					&format!(" \u{25cf} {}", kn_trunc.dimmed()),
					box_inner,
					w,
				);
			}
		}
	}

	// Attacker box bottom
	let bot_line = format!(
		"    {}{}{}",
		"\u{2514}".dimmed(),
		"\u{2500}".repeat(box_inner).dimmed(),
		"\u{2518}".dimmed()
	);
	buf.push_str(&bline(&bot_line, w));
}

fn draw_queries(buf: &mut String, st: &TuiState, w: usize, frame: usize) {
	buf.push_str(&border_mid("QUERIES", w));

	let inner = w.saturating_sub(2);

	for q in &st.queries {
		// All icons are safe 1-wide characters from Geometric Shapes
		let (icon, status_text) = match &q.status {
			QStatus::Pending => {
				let spinners = ["\u{25dc}", "\u{25dd}", "\u{25de}", "\u{25df}"];
				let s = spinners[frame % spinners.len()];
				(s.cyan().to_string(), "...".dimmed().italic().to_string())
			}
			QStatus::Pass => (
				"+".green().bold().to_string(),
				"PASS".green().bold().to_string(),
			),
			QStatus::Fail => (
				"x".red().bold().to_string(),
				"FAIL".red().bold().to_string(),
			),
		};
		let status_vis = vis_len(&status_text);
		let right_pad = 3;
		let q_max = inner.saturating_sub(4 + status_vis + right_pad);
		let q_text = trunc(&q.text, q_max);
		let q_vis = vis_len(&q_text);
		// Layout: "  " icon " " q_text gap status_text right_pad
		let gap = inner.saturating_sub(4 + q_vis + status_vis + right_pad);
		let line = format!("  {} {} {}{}", icon, q_text, " ".repeat(gap), status_text,);
		buf.push_str(&bline(&line, w));
	}

	if st.queries.is_empty() {
		buf.push_str(&bline(&"  No queries defined.".dimmed().to_string(), w));
	}
}

fn draw_deductions(buf: &mut String, st: &TuiState, w: usize) {
	buf.push_str(&border_mid("DEDUCTIONS", w));

	if st.deductions.is_empty() {
		buf.push_str(&bline(
			&"  Waiting for analysis...".dimmed().italic().to_string(),
			w,
		));
	} else {
		for (i, d) in st.deductions.iter().enumerate() {
			let dt = trunc(d, w.saturating_sub(8));
			let opacity = st.deductions.len() - 1 - i;
			let color = deduction_color(d);
			let marker = color_str("\u{203a}", color);
			let line = if opacity == 0 {
				format!("  {} {}", marker.bold(), dt)
			} else {
				format!("  {} {}", marker, dt.dimmed())
			};
			buf.push_str(&bline(&line, w));
		}
	}

	// Fill remaining space to prevent flickering
	let used = st.deductions.len().max(1);
	for _ in used..5 {
		buf.push_str(&bline("", w));
	}
}

fn draw_footer(buf: &mut String, st: &TuiState, w: usize, finished: bool) {
	buf.push_str(&border_mid("", w));

	let pass_count = st
		.queries
		.iter()
		.filter(|q| matches!(q.status, QStatus::Pass))
		.count();
	let fail_count = st
		.queries
		.iter()
		.filter(|q| matches!(q.status, QStatus::Fail))
		.count();
	let total = st.queries.len();

	let elapsed = st.start_time.map(|t| t.elapsed().as_secs()).unwrap_or(0);
	let timer = format!(
		"{:02}:{:02}:{:02}",
		elapsed / 3600,
		(elapsed % 3600) / 60,
		elapsed % 60
	);

	let info = if finished {
		let result = if fail_count == 0 {
			format!("All {} queries pass", total)
				.green()
				.bold()
				.to_string()
		} else {
			format!("{} of {} failed", fail_count, total)
				.red()
				.bold()
				.to_string()
		};
		format!(
			"  {} | {} deductions | {}",
			result,
			st.total_deductions,
			timer.dimmed(),
		)
	} else {
		let status = if fail_count > 0 {
			format!("{}x", fail_count).red().bold().to_string()
		} else {
			format!("{}+", pass_count).green().to_string()
		};
		format!(
			"  {} {} | {} {}/{} queries | #{} analyses | {} known | {}",
			st.total_deductions.to_string().bold(),
			"deductions".dimmed(),
			status,
			pass_count + fail_count,
			total,
			st.analysis_count.to_string().dimmed(),
			st.attacker_known_count.to_string().bold(),
			timer.dimmed(),
		)
	};
	buf.push_str(&bline(&info, w));
	buf.push_str(&border_bot(w));
}

// ── Utility ────────────────────────────────────────────────────────────────

fn terminal_width() -> usize {
	std::process::Command::new("tput")
		.arg("cols")
		.output()
		.ok()
		.and_then(|o| String::from_utf8(o.stdout).ok())
		.and_then(|s| s.trim().parse().ok())
		.unwrap_or(80)
}
