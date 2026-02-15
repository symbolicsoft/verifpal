/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::*;

pub(crate) fn append_unique_string(vec: &mut Vec<String>, value: String) -> bool {
	if !vec.contains(&value) {
		vec.push(value);
		true
	} else {
		false
	}
}

pub(crate) fn append_unique_int(vec: &mut Vec<i32>, value: i32) -> bool {
	if !vec.contains(&value) {
		vec.push(value);
		true
	} else {
		false
	}
}

pub(crate) fn append_unique_principal_enum(vec: &mut Vec<PrincipalId>, value: PrincipalId) -> bool {
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
		.ok_or_else(|| VerifpalError::Internal("slice has no integers".to_string()))
}

pub(crate) fn color_output_support() -> bool {
	!cfg!(target_os = "windows")
}

pub(crate) fn int_nth_root(val: i32, n: i32) -> i32 {
	if n <= 1 || val <= 1 {
		return val;
	}
	let (mut lo, mut hi) = (1i32, val);
	while lo < hi {
		let mid = lo + (hi - lo) / 2;
		let mut power = 1i64;
		let mut overflow = false;
		for _ in 0..n {
			if power > (val as i64) / (mid as i64) {
				overflow = true;
				break;
			}
			power *= mid as i64;
		}
		if overflow || power > val as i64 {
			hi = mid;
		} else {
			lo = mid + 1;
		}
	}
	lo - 1
}
