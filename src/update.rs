/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use colored::*;

use crate::util::color_output_support;

const TAGS_URL: &str = "https://api.github.com/repos/symbolicsoft/verifpal/tags";
const TAGS_ACCEPT: &str = "application/vnd.github+json";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_LIMIT: u64 = 256 * 1024;
const NAME_KEY: &str = "\"name\"";

pub struct UpdateCheck {
	receiver: Receiver<String>,
	current: String,
}

pub fn update_check_start(version: &str) -> UpdateCheck {
	let (sender, receiver) = mpsc::channel();
	let current = version.to_string();
	let user_agent = format!("verifpal/{}", version);
	let requested = current.clone();
	thread::spawn(move || {
		let Some(body) = update_fetch_tags(&user_agent) else {
			return;
		};
		if let Some(newer) = update_newer_version(&body, &requested) {
			let _ = sender.send(newer);
		}
	});
	UpdateCheck { receiver, current }
}

pub fn update_check_report(check: &UpdateCheck) {
	let Ok(newer) = check.receiver.try_recv() else {
		return;
	};
	update_alert(&newer, &check.current);
}

fn update_fetch_tags(user_agent: &str) -> Option<String> {
	let agent: ureq::Agent = ureq::Agent::config_builder()
		.timeout_global(Some(REQUEST_TIMEOUT))
		.user_agent(user_agent)
		.accept(TAGS_ACCEPT)
		.build()
		.into();
	let mut response = agent.get(TAGS_URL).call().ok()?;
	response
		.body_mut()
		.with_config()
		.limit(RESPONSE_LIMIT)
		.read_to_string()
		.ok()
}

fn update_alert(newer: &str, current: &str) {
	let message = format!(
		"Verifpal {} is available; you have {}. Get it at https://verifpal.com/",
		newer, current
	);
	if color_output_support() {
		eprintln!(
			"  {} {} {}",
			"Update".red().bold(),
			"\u{25b2}".red().bold(),
			message.red()
		);
		return;
	}
	eprintln!("  Update ! {}", message);
}

fn update_newer_version(body: &str, current: &str) -> Option<String> {
	let current_components = update_parse_version(current)?;
	let mut newest: Option<(Vec<u64>, String)> = None;
	for name in update_tag_names(body) {
		let Some(components) = update_parse_version(name) else {
			continue;
		};
		if !update_version_is_newer(&components, &current_components) {
			continue;
		}
		let supersedes = match &newest {
			Some((best, _)) => update_version_is_newer(&components, best),
			None => true,
		};
		if supersedes {
			newest = Some((components, update_version_display(name).to_string()));
		}
	}
	newest.map(|(_, name)| name)
}

fn update_version_display(name: &str) -> &str {
	let trimmed = name.trim();
	trimmed.strip_prefix('v').unwrap_or(trimmed)
}

fn update_parse_version(text: &str) -> Option<Vec<u64>> {
	let digits = update_version_display(text);
	if digits.is_empty() {
		return None;
	}
	let mut components = Vec::new();
	for part in digits.split('.') {
		components.push(part.parse::<u64>().ok()?);
	}
	Some(components)
}

fn update_version_is_newer(candidate: &[u64], current: &[u64]) -> bool {
	for index in 0..candidate.len().max(current.len()) {
		let left = candidate.get(index).copied().unwrap_or(0);
		let right = current.get(index).copied().unwrap_or(0);
		if left != right {
			return left > right;
		}
	}
	false
}

fn update_tag_names(body: &str) -> Vec<&str> {
	let mut names = Vec::new();
	let mut rest = body;
	while let Some(key) = rest.find(NAME_KEY) {
		rest = &rest[key + NAME_KEY.len()..];
		let Some(colon) = rest.find(':') else {
			break;
		};
		let after = rest[colon + 1..].trim_start();
		let Some(opened) = after.strip_prefix('"') else {
			rest = &rest[colon + 1..];
			continue;
		};
		let Some(closed) = opened.find('"') else {
			break;
		};
		names.push(&opened[..closed]);
		rest = &opened[closed + 1..];
	}
	names
}

#[cfg(test)]
mod tests {
	use super::*;

	const TAGS_FIXTURE: &str = r#"[
  {
    "name": "v1.0.0",
    "zipball_url": "https://api.github.com/repos/symbolicsoft/verifpal/zipball/refs/tags/v1.0.0",
    "commit": {
      "sha": "c9c7a6006a3629f5a10cde6d2d6e726f212e9e64",
      "url": "https://api.github.com/repos/symbolicsoft/verifpal/commits/c9c7a6006a3629f5a10cde6d2d6e726f212e9e64"
    },
    "node_id": "MDM6UmVmMzU1NDcxNTUwOnJlZnMvdGFncy92MS4wLjA="
  },
  {
    "name": "v0.80.1",
    "commit": {
      "sha": "76b3860589052d14ce6739b903ef79ff2b061b42"
    }
  }
]"#;

	#[test]
	fn update_parses_a_tag_name_into_components() {
		assert_eq!(update_parse_version("v1.0.0"), Some(vec![1, 0, 0]));
		assert_eq!(update_parse_version("1.0.0"), Some(vec![1, 0, 0]));
		assert_eq!(update_parse_version("  v0.80.1 "), Some(vec![0, 80, 1]));
		assert_eq!(update_parse_version("2"), Some(vec![2]));
	}

	#[test]
	fn update_refuses_anything_that_is_not_purely_numeric() {
		assert_eq!(update_parse_version("v1.0.0-beta"), None);
		assert_eq!(update_parse_version("v1.0.0rc1"), None);
		assert_eq!(update_parse_version("release-1.0.0"), None);
		assert_eq!(update_parse_version("v"), None);
		assert_eq!(update_parse_version(""), None);
		assert_eq!(update_parse_version("1..0"), None);
	}

	#[test]
	fn update_compares_versions_component_wise() {
		assert!(update_version_is_newer(&[1, 0, 1], &[1, 0, 0]));
		assert!(update_version_is_newer(&[1, 1, 0], &[1, 0, 9]));
		assert!(update_version_is_newer(&[2, 0, 0], &[1, 99, 99]));
		assert!(update_version_is_newer(&[1, 10, 0], &[1, 9, 0]));
		assert!(!update_version_is_newer(&[1, 0, 0], &[1, 0, 0]));
		assert!(!update_version_is_newer(&[1, 0, 0], &[1, 0, 1]));
		assert!(!update_version_is_newer(&[1, 0], &[1, 0, 0]));
		assert!(!update_version_is_newer(&[1, 0, 0], &[1, 0]));
	}

	#[test]
	fn update_reads_only_tag_names_out_of_the_response() {
		assert_eq!(update_tag_names(TAGS_FIXTURE), vec!["v1.0.0", "v0.80.1"]);
		assert!(update_tag_names("[]").is_empty());
		assert!(update_tag_names("not json at all").is_empty());
		assert!(update_tag_names("{\"name\"").is_empty());
		assert!(update_tag_names("{\"name\":").is_empty());
		assert!(update_tag_names("{\"name\": 7, \"name\": \"v2.0.0\"}") == vec!["v2.0.0"]);
	}

	#[test]
	fn update_reports_only_a_strictly_newer_release() {
		assert_eq!(
			update_newer_version(TAGS_FIXTURE, "0.80.0"),
			Some("1.0.0".to_string())
		);
		assert_eq!(update_newer_version(TAGS_FIXTURE, "1.0.0"), None);
		assert_eq!(update_newer_version(TAGS_FIXTURE, "1.0.1"), None);
		assert_eq!(update_newer_version(TAGS_FIXTURE, "2.0.0"), None);
		assert_eq!(update_newer_version("[]", "1.0.0"), None);
	}

	#[test]
	fn update_ignores_prerelease_tags_and_takes_the_highest() {
		let body = r#"[{"name": "v1.2.0-rc1"}, {"name": "v1.1.0"}, {"name": "v1.10.0"}, {"name": "nightly"}]"#;
		assert_eq!(
			update_newer_version(body, "1.0.0"),
			Some("1.10.0".to_string())
		);
	}

	#[test]
	fn update_reports_nothing_when_the_running_version_is_unparseable() {
		assert_eq!(update_newer_version(TAGS_FIXTURE, "unknown"), None);
	}
}
