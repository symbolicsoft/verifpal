/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorChoice {
	Auto,
	Always,
	Never,
}

static COLOR_CHOICE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

static COLOR_AUTO: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub fn set_color_choice(choice: ColorChoice) {
	let encoded = match choice {
		ColorChoice::Auto => 0,
		ColorChoice::Always => 1,
		ColorChoice::Never => 2,
	};
	COLOR_CHOICE.store(encoded, std::sync::atomic::Ordering::Relaxed);
	colored::control::set_override(color_output_support());
}

fn env_is_set(name: &str) -> bool {
	match std::env::var_os(name) {
		Some(value) => !value.is_empty() && value != "0",
		None => false,
	}
}

fn color_auto_detect() -> bool {
	use std::io::IsTerminal;
	if cfg!(target_arch = "wasm32") {
		return false;
	}
	if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
		return false;
	}
	if std::env::var_os("TERM").is_some_and(|v| v == "dumb") {
		return false;
	}
	if env_is_set("CLICOLOR_FORCE") || env_is_set("FORCE_COLOR") {
		return true;
	}
	std::io::stdout().is_terminal()
}

pub(crate) fn color_output_support() -> bool {
	match COLOR_CHOICE.load(std::sync::atomic::Ordering::Relaxed) {
		1 => true,
		2 => false,
		_ => *COLOR_AUTO.get_or_init(|| {
			let detected = color_auto_detect();
			colored::control::set_override(detected);
			detected
		}),
	}
}

pub(crate) fn stdout_is_terminal() -> bool {
	use std::io::IsTerminal;
	std::io::stdout().is_terminal()
}

pub(crate) fn stderr_is_terminal() -> bool {
	use std::io::IsTerminal;
	if cfg!(target_arch = "wasm32") {
		return false;
	}
	std::io::stderr().is_terminal()
}
