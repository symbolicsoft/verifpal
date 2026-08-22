/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::*;

pub(crate) fn append_unique<T: PartialEq>(vec: &mut Vec<T>, value: T) -> bool {
	if !vec.contains(&value) {
		vec.push(value);
		true
	} else {
		false
	}
}

pub(crate) fn min_int_in_slice(slice: &[i32]) -> VResult<i32> {
	slice
		.iter()
		.min()
		.copied()
		.ok_or_else(|| VerifpalError::internal("slice has no integers".into()))
}

#[cfg(feature = "cli")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorChoice {
	Auto,
	Always,
	Never,
}

#[cfg(feature = "cli")]
static COLOR_CHOICE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(feature = "cli")]
static COLOR_AUTO: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

#[cfg(feature = "cli")]
pub fn set_color_choice(choice: ColorChoice) {
	let encoded = match choice {
		ColorChoice::Auto => 0,
		ColorChoice::Always => 1,
		ColorChoice::Never => 2,
	};
	COLOR_CHOICE.store(encoded, std::sync::atomic::Ordering::Relaxed);
	match choice {
		ColorChoice::Auto => colored::control::unset_override(),
		ColorChoice::Always => colored::control::set_override(true),
		ColorChoice::Never => colored::control::set_override(false),
	}
}

#[cfg(feature = "cli")]
fn env_is_set(name: &str) -> bool {
	match std::env::var_os(name) {
		Some(value) => !value.is_empty() && value != "0",
		None => false,
	}
}

#[cfg(feature = "cli")]
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

#[cfg(feature = "cli")]
pub(crate) fn color_output_support() -> bool {
	match COLOR_CHOICE.load(std::sync::atomic::Ordering::Relaxed) {
		1 => true,
		2 => false,
		_ => *COLOR_AUTO.get_or_init(color_auto_detect),
	}
}

#[cfg(feature = "cli")]
pub(crate) fn stderr_is_terminal() -> bool {
	use std::io::IsTerminal;
	if cfg!(target_arch = "wasm32") {
		return false;
	}
	std::io::stderr().is_terminal()
}
