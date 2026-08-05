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
pub(crate) fn color_output_support() -> bool {
	if cfg!(target_arch = "wasm32") {
		return false;
	}
	!cfg!(target_os = "windows")
}
