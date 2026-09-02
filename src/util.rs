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

pub(crate) fn edit_distance(left: &str, right: &str) -> usize {
	let left: Vec<char> = left.chars().collect();
	let right: Vec<char> = right.chars().collect();
	if left.is_empty() {
		return right.len();
	}
	if right.is_empty() {
		return left.len();
	}
	let mut previous: Vec<usize> = (0..=right.len()).collect();
	let mut current = vec![0usize; right.len() + 1];
	for (i, l) in left.iter().enumerate() {
		current[0] = i + 1;
		for (j, r) in right.iter().enumerate() {
			let cost = usize::from(l != r);
			current[j + 1] = (previous[j + 1] + 1)
				.min(current[j] + 1)
				.min(previous[j] + cost);
		}
		std::mem::swap(&mut previous, &mut current);
	}
	previous[right.len()]
}

pub(crate) fn did_you_mean<'a>(
	name: &str,
	candidates: impl IntoIterator<Item = &'a str>,
) -> Option<String> {
	let lowered = name.to_lowercase();
	let mut best: Option<(usize, &str)> = None;
	for candidate in candidates {
		if candidate.is_empty() {
			continue;
		}
		let other = candidate.to_lowercase();
		if other == lowered {
			continue;
		}
		let distance = edit_distance(&lowered, &other);
		let longest = lowered.chars().count().max(other.chars().count());
		let limit = (longest / 3).max(1);
		if distance > limit {
			continue;
		}
		if best.is_none_or(|(seen, _)| distance < seen) {
			best = Some((distance, candidate));
		}
	}
	best.map(|(_, candidate)| candidate.to_string())
}

pub(crate) fn base_name(name: &str) -> &str {
	name.split('#').next().unwrap_or(name)
}

pub(crate) fn copy_base_name(name: &str) -> &str {
	let end = name.find(['#', '@']).unwrap_or(name.len());
	&name[..end]
}

pub(crate) const ANONYMOUS_PREFIX: &str = "unnamed";

pub(crate) fn is_anonymous_name(name: &str) -> bool {
	copy_base_name(name).starts_with(ANONYMOUS_PREFIX)
}

pub(crate) fn quoted_list(items: &[String]) -> String {
	items
		.iter()
		.map(|item| format!("`{}`", item))
		.collect::<Vec<String>>()
		.join(", ")
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

pub(crate) fn article(word: &str) -> &'static str {
	match word.chars().next() {
		Some('a' | 'e' | 'i' | 'o' | 'u' | 'A' | 'E' | 'I' | 'O' | 'U') => "an",
		_ => "a",
	}
}

pub(crate) fn plural(n: usize) -> &'static str {
	if n == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn append_unique_keeps_the_first_of_each() {
		let mut v = vec![1, 2];
		assert!(append_unique(&mut v, 3));
		assert!(!append_unique(&mut v, 2));
		assert_eq!(v, vec![1, 2, 3]);
	}

	#[test]
	fn edit_distance_counts_single_character_edits() {
		assert_eq!(edit_distance("", ""), 0);
		assert_eq!(edit_distance("abc", ""), 3);
		assert_eq!(edit_distance("", "abc"), 3);
		assert_eq!(edit_distance("abc", "abc"), 0);
		assert_eq!(edit_distance("abc", "abd"), 1);
		assert_eq!(edit_distance("abc", "ac"), 1);
		assert_eq!(edit_distance("abc", "abcd"), 1);
		assert_eq!(edit_distance("kitten", "sitting"), 3);
		assert_eq!(edit_distance("\u{e9}t\u{e9}", "ete"), 2);
	}

	#[test]
	fn did_you_mean_suggests_only_within_a_third_of_the_longer_name() {
		assert_eq!(
			did_you_mean("AEAD_ENCC", ["AEAD_ENC"]),
			Some("AEAD_ENC".into())
		);
		assert_eq!(did_you_mean("hasq", ["HASH"]), Some("HASH".into()));
		assert_eq!(
			did_you_mean("hsah", ["HASH"]),
			None,
			"a four-letter name allows one edit, and a transposition costs two"
		);
		assert_eq!(did_you_mean("zzz", ["HASH"]), None);
		assert_eq!(
			did_you_mean("HASH", ["HASH"]),
			None,
			"an exact match is not a suggestion"
		);
		assert_eq!(
			did_you_mean("x", [""]),
			None,
			"an empty candidate is skipped"
		);
		assert_eq!(
			did_you_mean("enk", ["ENC", "DEC"]),
			Some("ENC".into()),
			"the nearest candidate wins"
		);
	}

	#[test]
	fn a_copy_suffix_is_stripped_by_the_name_helpers() {
		assert_eq!(base_name("alice#2"), "alice");
		assert_eq!(base_name("alice"), "alice");
		assert_eq!(
			base_name("alice@3"),
			"alice@3",
			"base_name strips only the session suffix"
		);
		assert_eq!(copy_base_name("alice#2"), "alice");
		assert_eq!(copy_base_name("alice@3"), "alice");
		assert_eq!(copy_base_name("alice"), "alice");
	}

	#[test]
	fn an_anonymous_name_is_recognised_through_its_copy_suffix() {
		assert!(is_anonymous_name("unnamed_0"));
		assert!(is_anonymous_name("unnamed_0#2"));
		assert!(is_anonymous_name("unnamed_0@3"));
		assert!(
			is_anonymous_name("unnamedish"),
			"the prefix is what `check_reserved` refuses, so anything carrying it counts"
		);
		assert!(!is_anonymous_name("named_0"));
		assert!(!is_anonymous_name(""));
	}

	#[test]
	fn min_int_in_slice_refuses_an_empty_slice_rather_than_guessing() {
		assert_eq!(min_int_in_slice(&[3, 1, 2]).expect("a minimum"), 1);
		assert_eq!(min_int_in_slice(&[-1, 0]).expect("a minimum"), -1);
		assert!(min_int_in_slice(&[]).is_err());
	}

	#[test]
	fn quoted_list_and_the_prose_helpers() {
		assert_eq!(quoted_list(&[]), "");
		assert_eq!(quoted_list(&["a".to_string()]), "`a`");
		assert_eq!(quoted_list(&["a".to_string(), "b".to_string()]), "`a`, `b`");
		assert_eq!(article("active"), "an");
		assert_eq!(article("passive"), "a");
		assert_eq!(article(""), "a");
		assert_eq!(plural(1), "");
		assert_eq!(plural(0), "s");
		assert_eq!(plural(2), "s");
	}
}
