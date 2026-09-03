/* SPDX-FileCopyrightText: © 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use serde::{Deserialize, Serialize};

use crate::report::Analysis;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AnalyzeArgs {
	pub uri: String,
	#[serde(default)]
	pub sessions: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UriArg {
	pub uri: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Accepted {
	pub accepted: bool,
	pub token: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Cancelled {
	pub cancelled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagramResult {
	pub mermaid: String,
	pub readable: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AnalysisReport {
	pub uri: String,
	pub version: i32,
	pub token: String,
	pub ok: bool,
	pub cancelled: bool,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
	#[serde(flatten, skip_serializing_if = "Option::is_none")]
	pub analysis: Option<Analysis>,
}
