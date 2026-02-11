/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex, RwLock};
use std::time::Instant;

use colored::*;

use crate::pretty::*;
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

pub fn set_tui_mode(enabled: bool) {
    TUI_MODE.store(enabled, Ordering::Relaxed);
}

pub fn tui_mode() -> bool {
    TUI_MODE.load(Ordering::Relaxed)
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
    attacker_type: String,
    principals: Vec<TuiPrincipal>,
    messages: Vec<TuiMsg>,
    queries: Vec<TuiQuery>,
    // live
    stage: String,
    analysis_count: usize,
    total_deductions: usize,
    deductions: Vec<String>,
    attacker_line1: String,
    attacker_line2: String,
    frame: usize,
    start_time: Option<Instant>,
}

static TUI: LazyLock<RwLock<TuiState>> = LazyLock::new(|| {
    RwLock::new(TuiState {
        enabled: false,
        width: 80,
        finished: false,
        file_name: String::new(),
        attacker_type: String::new(),
        principals: vec![],
        messages: vec![],
        queries: vec![],
        stage: "0".to_string(),
        analysis_count: 0,
        total_deductions: 0,
        deductions: vec![],
        attacker_line1: String::new(),
        attacker_line2: String::new(),
        frame: 0,
        start_time: None,
    })
});

// ── Public API ─────────────────────────────────────────────────────────────

pub fn tui_init(m: &Model) {
    if !color_output_support() || !tui_mode() {
        return;
    }

    let w = terminal_width().max(60);
    let mut st = TUI.write().expect("TUI state lock");
    st.enabled = true;
    st.finished = false;
    st.width = w;
    st.start_time = Some(Instant::now());
    st.file_name = m.file_name.clone();
    st.attacker_type = m.attacker.clone();

    for block in &m.blocks {
        if block.kind == "principal" {
            // Deduplicate principals by name, summing stats
            let existing = st.principals.iter_mut().find(|p| p.name == block.principal.name);
            let p = if let Some(p) = existing {
                p
            } else {
                st.principals.push(TuiPrincipal {
                    name: block.principal.name.clone(),
                    n_private: 0,
                    n_generated: 0,
                    n_computed: 0,
                });
                st.principals.last_mut().expect("just pushed principal")
            };
            for expr in &block.principal.expressions {
                match expr.kind {
                    TypesEnum::Knows => {
                        p.n_private += expr.constants.len();
                    }
                    TypesEnum::Generates => {
                        p.n_generated += expr.constants.len();
                    }
                    TypesEnum::Assignment => {
                        p.n_computed += 1;
                    }
                    _ => {}
                }
            }
        } else if block.kind == "message" {
            st.messages.push(TuiMsg {
                sender: principal_get_name_from_id(block.message.sender),
                recipient: principal_get_name_from_id(block.message.recipient),
                constants: pretty_constants(&block.message.constants),
            });
        }
    }

    for query in &m.queries {
        st.queries.push(TuiQuery {
            text: pretty_query(query),
            status: QStatus::Pending,
        });
    }

    st.attacker_line1 = format!("Initializing {} attacker...", st.attacker_type);
    st.attacker_line2 = String::new();

    // Install panic hook to restore terminal
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        eprint!("{}{}", ESC_SHOW_CURSOR, ESC_NORMAL_SCREEN);
        prev(info);
    }));

    let _lock = TUI_OUT.lock().expect("TUI output lock");
    print!("{}{}", ESC_ALT_SCREEN, ESC_HIDE_CURSOR);
    drop(st);
    redraw_locked();
    io::stdout().flush().ok();
}

/// Handle an info_message call in TUI mode.
pub fn tui_message(msg: &str, msg_type: &str) {
    {
        let mut st = TUI.write().expect("TUI state lock");
        if !st.enabled {
            return;
        }

        match msg_type {
            "result" => {
                for q in st.queries.iter_mut() {
                    if msg.starts_with(&q.text) {
                        q.status = QStatus::Fail;
                        break;
                    }
                }
            }
            "deduction" => {
                st.total_deductions += 1;
                let max_len = st.width.saturating_sub(10);
                let display = trunc(msg, max_len);
                st.deductions.push(display);
                if st.deductions.len() > 5 {
                    st.deductions.remove(0);
                }
            }
            "analysis" => {
                if msg.contains("Mutation map for") {
                    st.attacker_line1 = trunc(msg, st.width.saturating_sub(16));
                } else if msg.contains("Constructed skeleton") {
                    st.attacker_line2 = trunc(msg, st.width.saturating_sub(16));
                } else if msg.contains("Initializing Stage") {
                    if let Some(rest) = msg.strip_prefix("Initializing Stage ") {
                        if let Some(num) = rest.split_whitespace().next() {
                            st.stage = num.trim_end_matches(',').to_string();
                        }
                    }
                    st.attacker_line2 = trunc(msg, st.width.saturating_sub(16));
                }
            }
            "info" => {
                if msg.starts_with("Attacker is configured") {
                    st.attacker_line1 = msg.to_string();
                } else if msg.starts_with("Running at phase") {
                    st.attacker_line2 = msg.to_string();
                }
            }
            _ => {}
        }
    }
    tui_redraw();
}

/// Handle an info_analysis progress tick in TUI mode.
pub fn tui_progress(stage_str: &str, count: usize) {
    {
        let mut st = TUI.write().expect("TUI state lock");
        if !st.enabled {
            return;
        }
        st.stage = stage_str.to_string();
        st.analysis_count = count;
    }
    tui_redraw();
}

/// Leave the TUI and restore the normal terminal.
pub fn tui_finish() {
    {
        let mut st = TUI.write().expect("TUI state lock");
        if !st.enabled {
            return;
        }
        for q in st.queries.iter_mut() {
            if matches!(q.status, QStatus::Pending) {
                q.status = QStatus::Pass;
            }
        }
        st.finished = true;
        st.attacker_line1 = "Analysis complete.".to_string();
        st.attacker_line2 = String::new();
    }
    tui_redraw();
    std::thread::sleep(std::time::Duration::from_millis(800));

    let _lock = TUI_OUT.lock().expect("TUI output lock");
    print!("{}{}", ESC_SHOW_CURSOR, ESC_NORMAL_SCREEN);
    io::stdout().flush().ok();

    TUI.write().expect("TUI state lock").enabled = false;
}

pub fn tui_enabled() -> bool {
    if !tui_mode() {
        return false;
    }
    TUI.read().map(|s| s.enabled).unwrap_or(false)
}

// ── Redraw ─────────────────────────────────────────────────────────────────

fn tui_redraw() {
    let _lock = TUI_OUT.lock().expect("TUI output lock");
    redraw_locked();
    io::stdout().flush().ok();
}

fn redraw_locked() {
    let mut st = TUI.write().expect("TUI state lock");
    if !st.enabled {
        return;
    }
    st.frame += 1;
    let w = st.width;
    let frame = st.frame;
    let finished = st.finished;

    let mut buf = String::with_capacity(8192);
    buf.push_str(ESC_HOME);
    draw_header(&mut buf, &st, w, frame, finished);
    draw_protocol(&mut buf, &st, w);
    draw_attacker(&mut buf, &st, w, finished);
    draw_queries(&mut buf, &st, w, frame);
    draw_deductions(&mut buf, &st, w);
    draw_footer(&mut buf, &st, w, finished);
    // Clear any leftover lines below
    for _ in 0..3 {
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
    let vl = vis_len(content);
    if vl > inner {
        let clipped = trunc(content, inner);
        let cvl = vis_len(&clipped);
        let pad = inner.saturating_sub(cvl);
        format!(
            "{}{}{}{}{}\n",
            "\u{2502}".dimmed(),
            clipped,
            " ".repeat(pad),
            "\u{2502}".dimmed(),
            ESC_CLEAR_TO_EOL
        )
    } else {
        let pad = inner - vl;
        format!(
            "{}{}{}{}{}\n",
            "\u{2502}".dimmed(),
            content,
            " ".repeat(pad),
            "\u{2502}".dimmed(),
            ESC_CLEAR_TO_EOL
        )
    }
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

    // Progress bar
    let inner = w.saturating_sub(2);
    let info_str = format!(" Stage {} | #{}", st.stage, st.analysis_count);
    let info_vis = vis_len(&info_str);
    let bar_chars = inner.saturating_sub(2 + info_vis); // 2 for leading "  "
    let scan_pos = if finished {
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
            let pos = if scan_pos < bar_chars { scan_pos } else { bar_chars * 2 - scan_pos };
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

fn draw_protocol(buf: &mut String, st: &TuiState, w: usize) {
    buf.push_str(&bline("", w));

    if st.principals.len() == 2 {
        draw_protocol_two(buf, st, w);
    } else {
        draw_protocol_list(buf, st, w);
    }

    buf.push_str(&bline("", w));
}

fn draw_protocol_two(buf: &mut String, st: &TuiState, w: usize) {
    let p1 = &st.principals[0];
    let p2 = &st.principals[1];
    let n1 = p1.name.to_uppercase();
    let n2 = p2.name.to_uppercase();
    let inner = w.saturating_sub(2);

    // Principal header
    let sum1 = format!("{}p {}g {}c", p1.n_private, p1.n_generated, p1.n_computed);
    let sum2 = format!("{}p {}g {}c", p2.n_private, p2.n_generated, p2.n_computed);
    let left_header = format!(
        "  {} {}",
        n1.cyan().bold(),
        sum1.dimmed()
    );
    let right_header = format!(
        "{} {}  ",
        sum2.dimmed(),
        n2.cyan().bold()
    );
    let hgap = inner.saturating_sub(vis_len(&left_header) + vis_len(&right_header));
    let header_line = format!("{}{}{}", left_header, " ".repeat(hgap), right_header);
    buf.push_str(&bline(&header_line, w));

    // Messages as arrows between principals
    let indent = vis_len(&n1) + 4;
    let arrow_space = inner.saturating_sub(indent + vis_len(&n2) + 4);

    for msg in &st.messages {
        let label = trunc(&msg.constants, arrow_space.saturating_sub(4));
        let label_vis = vis_len(&label);
        let fill = arrow_space.saturating_sub(label_vis + 2);
        let lf = fill / 2;
        let rf = fill.saturating_sub(lf);

        let line = if msg.sender == p1.name {
            format!(
                "{}{}{}{}",
                " ".repeat(indent),
                "\u{2500}".repeat(lf).yellow().to_string(),
                format!(" {} ", label).yellow().bold().to_string(),
                format!("{}\u{25b6}", "\u{2500}".repeat(rf)).yellow().to_string()
            )
        } else {
            format!(
                "{}{}{}{}",
                " ".repeat(indent),
                format!("\u{25c0}{}", "\u{2500}".repeat(lf)).yellow().to_string(),
                format!(" {} ", label).yellow().bold().to_string(),
                "\u{2500}".repeat(rf).yellow().to_string()
            )
        };
        buf.push_str(&bline(&line, w));
    }
}

fn draw_protocol_list(buf: &mut String, st: &TuiState, w: usize) {
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
    let indent = 2; // leading "  "
    let mut row = String::new();
    let mut row_vis = indent;
    row.push_str("  ");

    for (i, entry) in entries.iter().enumerate() {
        let entry_vis = vis_len(entry);
        let needed = if i == 0 { entry_vis } else { sep_vis + entry_vis };
        if row_vis + needed > inner && row_vis > indent {
            buf.push_str(&bline(&row, w));
            row = format!("  {}", entry);
            row_vis = indent + entry_vis;
        } else {
            if i > 0 {
                row.push_str(&sep.dimmed().to_string());
                row_vis += sep_vis;
            }
            row.push_str(entry);
            row_vis += entry_vis;
        }
    }
    if row_vis > indent {
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
            format!(" \u{2500}\u{2500}\u{25b6}").yellow(),
            msg.recipient.cyan()
        );
        buf.push_str(&bline(&line, w));
    }
}

fn draw_attacker(buf: &mut String, st: &TuiState, w: usize, finished: bool) {
    buf.push_str(&bline("", w));

    // Inner box: 4-space margins on each side within the outer │...│
    let box_inner = w.saturating_sub(12);

    // Attacker box top — all box-drawing chars, no emoji
    let label_text = format!(" ATTACKER ({}) ", st.attacker_type);
    let label_colored = if finished {
        label_text.green().bold().to_string()
    } else {
        label_text.red().bold().to_string()
    };
    let label_vis = vis_len(&label_text); // measure the plain text
    let left_dashes = 3;
    let right_dashes = box_inner.saturating_sub(left_dashes + label_vis);
    let top_line = format!(
        "    {}{}{}{}",
        "\u{250c}".dimmed(),
        "\u{2500}".repeat(left_dashes).dimmed(),
        label_colored,
        format!("{}{}", "\u{2500}".repeat(right_dashes), "\u{2510}").dimmed()
    );
    buf.push_str(&bline(&top_line, w));

    // Activity line 1 — use ▸ (U+25B8, Geometric Shapes, safe 1-wide)
    let indicator = if finished {
        "\u{2500}".dimmed().to_string()
    } else {
        "\u{25b8}".red().to_string()
    };
    let l1 = trunc(&st.attacker_line1, box_inner.saturating_sub(4));
    let l1_inner = format!(" {} {}", indicator, l1);
    let l1_pad = box_inner.saturating_sub(vis_len(&l1_inner));
    let l1_line = format!(
        "    {}{}{}{}",
        "\u{2502}".dimmed(),
        l1_inner,
        " ".repeat(l1_pad),
        "\u{2502}".dimmed()
    );
    buf.push_str(&bline(&l1_line, w));

    // Activity line 2
    let l2 = trunc(&st.attacker_line2, box_inner.saturating_sub(4));
    if !l2.is_empty() {
        let l2_inner = format!(" {} {}", "\u{2500}".dimmed(), l2.dimmed());
        let l2_pad = box_inner.saturating_sub(vis_len(&l2_inner));
        let l2_line = format!(
            "    {}{}{}{}",
            "\u{2502}".dimmed(),
            l2_inner,
            " ".repeat(l2_pad),
            "\u{2502}".dimmed()
        );
        buf.push_str(&bline(&l2_line, w));
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
                (
                    s.cyan().to_string(),
                    "...".dimmed().italic().to_string(),
                )
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
        let q_max = inner.saturating_sub(8 + status_vis);
        let q_text = trunc(&q.text, q_max);
        let q_vis = vis_len(&q_text);
        // Layout: "  " icon " " q_text gap status_text " "
        // = 2 + 1 + 1 + q_vis + gap + status_vis + 1 = inner
        let gap = inner.saturating_sub(5 + q_vis + status_vis);
        let line = format!(
            "  {} {} {}{}{}",
            icon,
            q_text,
            " ".repeat(gap),
            status_text,
            " "
        );
        buf.push_str(&bline(&line, w));
    }

    if st.queries.is_empty() {
        buf.push_str(&bline(
            &"  No queries defined.".dimmed().to_string(),
            w,
        ));
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
            let line = if opacity == 0 {
                format!("  {} {}", "\u{203a}".yellow().bold(), dt)
            } else {
                format!("  {} {}", "\u{203a}".yellow(), dt.dimmed())
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

    let pass_count = st.queries.iter().filter(|q| matches!(q.status, QStatus::Pass)).count();
    let fail_count = st.queries.iter().filter(|q| matches!(q.status, QStatus::Fail)).count();
    let total = st.queries.len();

    let elapsed = st.start_time.map(|t| t.elapsed().as_secs()).unwrap_or(0);
    let hours = elapsed / 3600;
    let minutes = (elapsed % 3600) / 60;
    let seconds = elapsed % 60;
    let timer = format!("{:02}:{:02}:{:02}", hours, minutes, seconds);

    let info = if finished {
        let result = if fail_count == 0 {
            format!("All {} queries pass", total).green().bold().to_string()
        } else {
            format!("{} of {} failed", fail_count, total).red().bold().to_string()
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
            "  {} {} | {} {}/{} queries | {}",
            st.total_deductions.to_string().bold(),
            "deductions".dimmed(),
            status,
            pass_count + fail_count,
            total,
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
