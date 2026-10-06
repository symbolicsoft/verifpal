/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

fn edit_distance(left: &str, right: &str) -> usize {
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

pub(crate) fn and_list(items: &[&str]) -> String {
	match items {
		[] => String::new(),
		[only] => only.to_string(),
		[init @ .., last] => format!("{} and {last}", init.join(", ")),
	}
}

pub(crate) fn quoted_list(items: &[String]) -> String {
	items
		.iter()
		.map(|item| format!("`{}`", item))
		.collect::<Vec<String>>()
		.join(", ")
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
