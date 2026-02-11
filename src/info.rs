/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use colored::*;
use crate::types::*;
use crate::pretty::*;
use crate::primitive::*;
use crate::value::*;
use crate::util::color_output_support;

// ---------------------------------------------------------------------------
// Banner and separators
// ---------------------------------------------------------------------------

pub fn info_banner(version: &str) {
    if color_output_support() {
        println!("{}", "\u{2500}".repeat(50).dimmed());
        println!("  {} {} {} {}",
            "\u{25c6}".green(),
            "Verifpal".green().bold(),
            version.dimmed(),
            "\u{00b7} https://verifpal.com".dimmed());
        println!("{}", "\u{2500}".repeat(50).dimmed());
    } else {
        println!("Verifpal {} - https://verifpal.com", version);
    }
}

pub fn info_separator() {
    if color_output_support() {
        println!("{}", "\u{2500}".repeat(50).dimmed());
    } else {
        println!("{}", "-".repeat(50));
    }
}

// ---------------------------------------------------------------------------
// Core message output
// ---------------------------------------------------------------------------

pub fn info_message(m: &str, t: &str, show_analysis: bool) {
    if crate::tui::tui_enabled() {
        crate::tui::tui_message(m, t);
        return;
    }
    let analysis_count = if show_analysis {
        crate::verifyanalysis::verify_analysis_count_get()
    } else {
        0
    };
    if color_output_support() {
        info_message_color(m, t, analysis_count);
    } else {
        info_message_regular(m, t, analysis_count);
    }
}

fn info_message_regular(m: &str, t: &str, analysis_count: usize) {
    let info_string = if analysis_count > 0 {
        format!(" (Analysis {})", analysis_count)
    } else {
        String::new()
    };
    match t {
        "verifpal"  => print!(" Verifpal * {}{}\n", m, info_string),
        "info"      => print!("     Info . {}{}\n", m, info_string),
        "analysis"  => print!(" Analysis > {}{}\n", m, info_string),
        "deduction" => print!("Deduction > {}{}\n", m, info_string),
        "result"    => print!("     FAIL x {}{}\n", m, info_string),
        "pass"      => print!("     PASS + {}{}\n", m, info_string),
        "warning"   => print!("  Warning ! {}{}\n", m, info_string),
        _ => {}
    }
}

fn info_message_color(m: &str, t: &str, analysis_count: usize) {
    let info_string = if analysis_count > 0 {
        format!(" {}", format!("(Analysis {})", analysis_count).dimmed().italic())
    } else {
        String::new()
    };
    match t {
        "verifpal" => {
            print!(" {} {} {}{}\n",
                "Verifpal".green().bold(),
                "\u{25c6}".green(),
                m, info_string);
        }
        "info" => {
            print!("     {} {} {}{}\n",
                "Info".cyan().bold(),
                "\u{25cf}".cyan(),
                m, info_string);
        }
        "analysis" => {
            print!(" {} {} {}{}\n",
                "Analysis".blue().bold(),
                "\u{25b8}".blue(),
                m.dimmed(), info_string);
        }
        "deduction" => {
            print!("{} {} {}{}\n",
                "Deduction".yellow(),
                "\u{203a}".yellow(),
                m.dimmed(), info_string);
        }
        "result" => {
            print!("     {} {} {}{}\n",
                "Fail".red().bold(),
                "\u{2717}".red().bold(),
                m, info_string);
        }
        "pass" => {
            print!("     {} {} {}{}\n",
                "Pass".green().bold(),
                "\u{2713}".green().bold(),
                m, info_string);
        }
        "warning" => {
            print!("  {} {} {}{}\n",
                "Warning".yellow().bold(),
                "\u{25b2}".yellow().bold(),
                m, info_string);
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Result summary formatting
// ---------------------------------------------------------------------------

pub fn info_verify_result_summary(
    mutated_info: &str, summary: &str, o_results: &[QueryOptionResult],
) -> String {
    let indent = "            "; // 12 spaces — aligns with message column

    if color_output_support() {
        let mut output = String::new();

        if !mutated_info.is_empty() {
            output.push_str(&format!("\n{}{} {}",
                indent,
                "\u{256d}\u{2500}".dimmed(),
                "Attack trace:".dimmed().italic()));

            for line in mutated_info.split('\n') {
                let trimmed = line.trim();
                if trimmed.is_empty() { continue; }
                if trimmed.starts_with("In another session:") {
                    output.push_str(&format!("\n{}{}", indent, "\u{2502}".dimmed()));
                    output.push_str(&format!("\n{}{} {}",
                        indent, "\u{2502}".dimmed(), trimmed.italic().dimmed()));
                } else {
                    output.push_str(&format!("\n{}{} {}",
                        indent, "\u{2502}".dimmed(), trimmed));
                }
            }
            output.push_str(&format!("\n{}{} {}",
                indent,
                "\u{2570}\u{25b8}".dimmed(),
                summary.on_red().white().bold()));
        } else {
            output.push_str(&format!("\n{}{}",
                indent, summary.on_red().white().bold()));
        }

        for o_result in o_results {
            if !o_result.resolved { continue; }
            output.push_str(&format!("\n{}{} {}",
                indent, "\u{25b2}".yellow(), o_result.summary.yellow().italic()));
        }

        output
    } else {
        let mut output = String::new();

        if !mutated_info.is_empty() {
            output.push_str(&format!("\n{}Attack trace:", indent));
            for line in mutated_info.split('\n') {
                let trimmed = line.trim();
                if trimmed.is_empty() { continue; }
                output.push_str(&format!("\n{}| {}", indent, trimmed));
            }
            output.push_str(&format!("\n{}> {}", indent, summary));
        } else {
            output.push_str(&format!("\n{}{}", indent, summary));
        }

        for o_result in o_results {
            if !o_result.resolved { continue; }
            output.push_str(&format!("\n{}! {}", indent, o_result.summary));
        }

        output
    }
}

// ---------------------------------------------------------------------------
// Analysis progress
// ---------------------------------------------------------------------------

pub fn info_analysis(stage: i32) {
    let analysis_count = crate::verifyanalysis::verify_analysis_count_get();
    // Throttle updates
    match analysis_count {
        c if c > 100000 => { if c % 10000 != 0 { return; } }
        c if c > 10000 => { if c % 1000 != 0 { return; } }
        c if c > 1000 => { if c % 100 != 0 { return; } }
        c if c > 100 => { if c % 10 != 0 { return; } }
        _ => {}
    }
    let s = match stage {
        1 => "1".to_string(),
        2 | 3 => "2-3".to_string(),
        4 | 5 => "4-5".to_string(),
        _ => format!("{}", stage),
    };
    if crate::tui::tui_enabled() {
        crate::tui::tui_progress(&s, analysis_count);
        return;
    }
    if color_output_support() {
        let a = format!("  {} Stage {}, Analysis {}...",
            "\u{25b8}".blue(), s, analysis_count).dimmed().italic();
        print!("{}", a);
    } else {
        print!("  Stage {}, Analysis {}...", s, analysis_count);
    }
    print!("\r");
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

pub fn info_literal_number(n: usize, title_case: bool) -> String {
    if n > 9 {
        return format!("{}th", n);
    }
    let words = if title_case {
        &["First", "Second", "Third", "Fourth", "Fifth",
          "Sixth", "Seventh", "Eighth", "Ninth", "Tenth"]
    } else {
        &["first", "second", "third", "fourth", "fifth",
          "sixth", "seventh", "eighth", "ninth", "tenth"]
    };
    words[n].to_string()
}

pub fn info_output_text(revealed: &Value) -> String {
    let output_text = pretty_value(revealed);
    match revealed {
        Value::Constant(_) => output_text,
        Value::Primitive(p) => {
            let one_output = if primitive_is_core(p.id) {
                if let Ok(prim) = primitive_core_get(p.id) {
                    prim.output.len() == 1 && prim.output[0] == 1
                } else { false }
            } else {
                if let Ok(prim) = primitive_get(p.id) {
                    prim.output.len() == 1 && prim.output[0] == 1
                } else { false }
            };
            if one_output {
                format!("Output of {}", output_text)
            } else {
                let prefix = format!("{} output", info_literal_number(p.output, true));
                format!("{} of {}", prefix, output_text)
            }
        }
        Value::Equation(_) => output_text,
    }
}

// ---------------------------------------------------------------------------
// Mutation trace output
// ---------------------------------------------------------------------------

pub fn info_query_mutated_values(
    val_knowledge_map: &KnowledgeMap,
    val_principal_state: &PrincipalState,
    val_attacker_state: &AttackerState,
    target_value: &Value,
    info_depth: usize,
) -> String {
    let mut mutated: Vec<Value> = Vec::new();
    let target_info = "In another session:".to_string();
    let mut mutated_info = String::new();
    let mut relevant = false;

    let n = val_principal_state.before_rewrite.len().min(val_knowledge_map.assigned.len());
    for i in 0..n {
        if value_equivalent_values(&val_principal_state.before_rewrite[i], &val_knowledge_map.assigned[i], false) {
            continue;
        }
        let is_target = value_equivalent_values(target_value, &val_principal_state.assigned[i], false);
        let attacker_knows = value_equivalent_value_in_values_map(
            target_value, &val_attacker_state.known, &val_attacker_state.known_map,
        ) >= 0;

        let (m_info, m_relevant) = info_query_mutated_value(
            val_knowledge_map, val_principal_state, i, is_target, attacker_knows,
        );
        if m_relevant {
            relevant = true;
        }
        mutated_info = format!("{}\n            {}", mutated_info, m_info);

        if is_target && attacker_knows {
            // target obtained
        } else if val_principal_state.mutated[i] {
            if value_equivalent_value_in_values(&val_principal_state.assigned[i], &mutated) < 0 {
                mutated.push(val_principal_state.assigned[i].clone());
            }
        }
    }
    if !relevant {
        return String::new();
    }
    if info_depth >= 2 {
        return mutated_info;
    }
    for m_val in &mutated {
        let ai = value_equivalent_value_in_values_map(m_val, &val_attacker_state.known, &val_attacker_state.known_map);
        if ai < 0 { continue; }
        let mm_info = info_query_mutated_values(
            val_knowledge_map, &val_attacker_state.principal_state[ai as usize],
            val_attacker_state, m_val, info_depth + 1,
        );
        if !mm_info.is_empty() {
            mutated_info = format!("{}\n\n            {}{}", mm_info, target_info, mutated_info);
        }
    }
    mutated_info
}

fn info_query_mutated_value(
    val_knowledge_map: &KnowledgeMap,
    val_principal_state: &PrincipalState,
    index: usize,
    is_target_value: bool,
    attacker_knows: bool,
) -> (String, bool) {
    let pc = pretty_constant(&val_principal_state.constants[index]);
    let pa = pretty_value(&val_principal_state.assigned[index]);
    let mut relevant = false;
    let suffix;
    if is_target_value && attacker_knows && !val_principal_state.mutated[index] {
        relevant = true;
        if color_output_support() {
            suffix = format!(" {} {}",
                "\u{2190}".red(),
                "obtained by Attacker".red().bold());
        } else {
            suffix = " <- obtained by Attacker".to_string();
        }
    } else if val_principal_state.mutated[index] {
        relevant = true;
        if color_output_support() {
            suffix = format!(" {} {} {}",
                "\u{2190}".red(),
                "mutated by Attacker".red().bold(),
                format!("(was: {})", pretty_value(&val_knowledge_map.assigned[index])).dimmed());
        } else {
            suffix = format!(" <- mutated by Attacker (originally {})",
                pretty_value(&val_knowledge_map.assigned[index]),
            );
        }
    } else {
        suffix = String::new();
    }
    if color_output_support() {
        (format!("{} {} {}{}", pc, "\u{2192}".dimmed(), pa, suffix), relevant)
    } else {
        (format!("{} -> {}{}", pc, pa, suffix), relevant)
    }
}
