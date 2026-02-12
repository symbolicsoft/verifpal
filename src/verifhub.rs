/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::info::info_message;
use crate::pretty::pretty_model;
use crate::types::*;
use std::sync::atomic::AtomicBool;

pub static VERIFHUB_SCHEDULED: AtomicBool = AtomicBool::new(false);

pub fn verifhub(m: &Model, file_name: &str, results_code: &str) -> VResult<()> {
	info_message(
		"Your model will now be submitted to VerifHub.",
		InfoLevel::Verifpal,
		false,
	);
	let pretty = pretty_model(m)?;
	let model = urlencoding_encode(&pretty);
	let encoded_name = urlencoding_encode(file_name);
	let link = format!(
		"https://verifhub.verifpal.com/submit?name={}&model={}&results={}",
		encoded_name, model, results_code
	);
	open_browser(&link)
}

fn urlencoding_encode(s: &str) -> String {
	// Simple percent encoding
	let mut result = String::new();
	for b in s.bytes() {
		match b {
			b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
				result.push(b as char);
			}
			_ => {
				result.push_str(&format!("%{:02X}", b));
			}
		}
	}
	result
}

fn open_browser(url: &str) -> VResult<()> {
	#[cfg(target_os = "macos")]
	{
		std::process::Command::new("open")
			.arg(url)
			.spawn()
			.map_err(|e| VerifpalError::Internal(e.to_string()))?;
	}
	#[cfg(target_os = "linux")]
	{
		std::process::Command::new("xdg-open")
			.arg(url)
			.spawn()
			.map_err(|e| VerifpalError::Internal(e.to_string()))?;
	}
	#[cfg(target_os = "windows")]
	{
		std::process::Command::new("rundll32")
			.args(["url.dll,FileProtocolHandler", url])
			.spawn()
			.map_err(|e| VerifpalError::Internal(e.to_string()))?;
	}
	Ok(())
}
