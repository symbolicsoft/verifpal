/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use colored::*;

use super::terminal::color_output_support;

const TAGS_URL: &str = "https://api.github.com/repos/symbolicsoft/verifpal/tags";
const TAGS_ACCEPT: &str = "application/vnd.github+json";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_LIMIT: u64 = 256 * 1024;

pub struct UpdateCheck {
	receiver: Receiver<String>,
	current: String,
}

impl UpdateCheck {
	pub fn start(version: &str) -> UpdateCheck {
		let (sender, receiver) = mpsc::channel();
		let current = version.to_string();
		if !crate::console::terminal::stdout_is_terminal() {
			return UpdateCheck { receiver, current };
		}
		let user_agent = format!("verifpal/{}", version);
		let requested = current.clone();
		thread::spawn(move || {
			let Some(body) = fetch_tags(&user_agent) else {
				return;
			};
			if let Some(newer) = newer_version(&body, &requested) {
				let _ = sender.send(newer);
			}
		});
		UpdateCheck { receiver, current }
	}

	pub fn report(&self) {
		let Ok(newer) = self.receiver.try_recv() else {
			return;
		};
		alert(&newer, &self.current);
	}
}

fn fetch_tags(user_agent: &str) -> Option<String> {
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

fn alert(newer: &str, current: &str) {
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

fn newer_version(body: &str, current: &str) -> Option<String> {
	let current = parse_version(current)?;
	let mut newest: Option<(Vec<u64>, String)> = None;
	for name in tag_names(body) {
		let Some(components) = parse_version(&name) else {
			continue;
		};
		let best = newest.as_ref().map_or(&current, |(best, _)| best);
		if version_is_newer(&components, best) {
			newest = Some((components, version_display(&name).to_string()));
		}
	}
	newest.map(|(_, name)| name)
}

fn version_display(name: &str) -> &str {
	let trimmed = name.trim();
	trimmed.strip_prefix('v').unwrap_or(trimmed)
}

fn parse_version(text: &str) -> Option<Vec<u64>> {
	let digits = version_display(text);
	if digits.is_empty() {
		return None;
	}
	let mut components = Vec::new();
	for part in digits.split('.') {
		components.push(part.parse::<u64>().ok()?);
	}
	Some(components)
}

fn version_is_newer(candidate: &[u64], current: &[u64]) -> bool {
	for index in 0..candidate.len().max(current.len()) {
		let left = candidate.get(index).copied().unwrap_or(0);
		let right = current.get(index).copied().unwrap_or(0);
		if left != right {
			return left > right;
		}
	}
	false
}

fn tag_names(body: &str) -> Vec<String> {
	let Ok(serde_json::Value::Array(tags)) = serde_json::from_str(body) else {
		return Vec::new();
	};
	tags.into_iter()
		.filter_map(|tag| tag.get("name")?.as_str().map(str::to_string))
		.collect()
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
	fn parses_a_tag_name_into_components() {
		assert_eq!(parse_version("v1.0.0"), Some(vec![1, 0, 0]));
		assert_eq!(parse_version("1.0.0"), Some(vec![1, 0, 0]));
		assert_eq!(parse_version("  v0.80.1 "), Some(vec![0, 80, 1]));
		assert_eq!(parse_version("2"), Some(vec![2]));
	}

	#[test]
	fn refuses_anything_that_is_not_purely_numeric() {
		assert_eq!(parse_version("v1.0.0-beta"), None);
		assert_eq!(parse_version("v1.0.0rc1"), None);
		assert_eq!(parse_version("release-1.0.0"), None);
		assert_eq!(parse_version("v"), None);
		assert_eq!(parse_version(""), None);
		assert_eq!(parse_version("1..0"), None);
	}

	#[test]
	fn compares_versions_component_wise() {
		assert!(version_is_newer(&[1, 0, 1], &[1, 0, 0]));
		assert!(version_is_newer(&[1, 1, 0], &[1, 0, 9]));
		assert!(version_is_newer(&[2, 0, 0], &[1, 99, 99]));
		assert!(version_is_newer(&[1, 10, 0], &[1, 9, 0]));
		assert!(!version_is_newer(&[1, 0, 0], &[1, 0, 0]));
		assert!(!version_is_newer(&[1, 0, 0], &[1, 0, 1]));
		assert!(!version_is_newer(&[1, 0], &[1, 0, 0]));
		assert!(!version_is_newer(&[1, 0, 0], &[1, 0]));
	}

	#[test]
	fn reads_only_tag_names_out_of_the_response() {
		assert_eq!(tag_names(TAGS_FIXTURE), vec!["v1.0.0", "v0.80.1"]);
		assert!(tag_names("[]").is_empty());
		assert!(tag_names("not json at all").is_empty());
		assert!(tag_names("{\"name\"").is_empty());
		assert!(tag_names("{\"name\":").is_empty());
		assert!(tag_names("{\"name\": \"v2.0.0\"}").is_empty());
		assert_eq!(
			tag_names("[{\"name\": 7}, {\"name\": \"v2.0.0\"}]"),
			vec!["v2.0.0"]
		);
		assert_eq!(
			tag_names(r#"[{"commit":{"name":"v9.0.0"},"name":"v1.0.0"}]"#),
			vec!["v1.0.0"]
		);
	}

	#[test]
	fn reports_only_a_strictly_newer_release() {
		assert_eq!(
			newer_version(TAGS_FIXTURE, "0.80.0"),
			Some("1.0.0".to_string())
		);
		assert_eq!(newer_version(TAGS_FIXTURE, "1.0.0"), None);
		assert_eq!(newer_version(TAGS_FIXTURE, "1.0.1"), None);
		assert_eq!(newer_version(TAGS_FIXTURE, "2.0.0"), None);
		assert_eq!(newer_version("[]", "1.0.0"), None);
	}

	#[test]
	fn ignores_prerelease_tags_and_takes_the_highest() {
		let body = r#"[{"name": "v1.2.0-rc1"}, {"name": "v1.1.0"}, {"name": "v1.10.0"}, {"name": "nightly"}]"#;
		assert_eq!(newer_version(body, "1.0.0"), Some("1.10.0".to_string()));
	}

	#[test]
	fn reports_nothing_when_the_running_version_is_unparseable() {
		assert_eq!(newer_version(TAGS_FIXTURE, "unknown"), None);
	}
}
