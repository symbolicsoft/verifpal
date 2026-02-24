/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::*;

pub fn append_unique<T: PartialEq>(vec: &mut Vec<T>, value: T) -> bool {
	if !vec.contains(&value) {
		vec.push(value);
		true
	} else {
		false
	}
}

pub fn min_int_in_slice(slice: &[i32]) -> VResult<i32> {
	slice
		.iter()
		.min()
		.copied()
		.ok_or_else(|| VerifpalError::Internal("slice has no integers".into()))
}

pub fn color_output_support() -> bool {
	if cfg!(target_arch = "wasm32") {
		return false;
	}
	!cfg!(target_os = "windows")
}

pub fn int_nth_root(val: i32, n: i32) -> i32 {
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
