/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::types::PrincipalId;

pub fn str_in_slice(x: &str, a: &[String]) -> bool {
    a.iter().any(|n| n == x)
}

pub fn int_in_slice(x: i32, a: &[i32]) -> bool {
    a.contains(&x)
}

pub fn principal_enum_in_slice(x: PrincipalId, a: &[PrincipalId]) -> bool {
    a.contains(&x)
}

pub fn append_unique_string(a: &mut Vec<String>, x: String) -> bool {
    if !str_in_slice(&x, a) {
        a.push(x);
        true
    } else {
        false
    }
}

pub fn append_unique_int(a: &mut Vec<i32>, x: i32) -> bool {
    if !int_in_slice(x, a) {
        a.push(x);
        true
    } else {
        false
    }
}

pub fn append_unique_principal_enum(a: &mut Vec<PrincipalId>, x: PrincipalId) -> bool {
    if !principal_enum_in_slice(x, a) {
        a.push(x);
        true
    } else {
        false
    }
}

pub fn min_int_in_slice(v: &[i32]) -> Result<i32, String> {
    if v.is_empty() {
        return Err("slice has no integers".to_string());
    }
    Ok(*v.iter().min().expect("non-empty slice has a minimum"))
}

pub fn color_output_support() -> bool {
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
