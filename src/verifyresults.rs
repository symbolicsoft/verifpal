/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::{LazyLock, RwLock};
use std::sync::atomic::{AtomicI32, Ordering};
use crate::types::*;

struct VerifyResultsState {
    results: Vec<VerifyResult>,
    file_name: String,
}

static VERIFY_RESULTS: LazyLock<RwLock<VerifyResultsState>> = LazyLock::new(|| {
    RwLock::new(VerifyResultsState {
        results: vec![],
        file_name: String::new(),
    })
});

static UNRESOLVED: AtomicI32 = AtomicI32::new(0);

pub fn verify_results_init(m: &Model) {
    let mut state = VERIFY_RESULTS.write().unwrap_or_else(|e| e.into_inner());
    state.results = m.queries.iter().enumerate().map(|(i, q)| VerifyResult {
        query: q.clone(),
        query_index: i,
        resolved: false,
        summary: String::new(),
        options: vec![],
    }).collect();
    state.file_name = m.file_name.clone();
    UNRESOLVED.store(m.queries.len() as i32, Ordering::SeqCst);
}

pub fn verify_results_get_read() -> (Vec<VerifyResult>, String) {
    let state = VERIFY_RESULTS.read().unwrap_or_else(|e| e.into_inner());
    (state.results.clone(), state.file_name.clone())
}

pub fn verify_results_put_write(result: &VerifyResult) -> bool {
    let mut state = VERIFY_RESULTS.write().unwrap_or_else(|e| e.into_inner());
    if let Some(vr) = state.results.get_mut(result.query_index) {
        if !vr.resolved {
            vr.resolved = result.resolved;
            vr.summary = result.summary.clone();
            vr.options = result.options.clone();
            if result.resolved {
                UNRESOLVED.fetch_sub(1, Ordering::SeqCst);
            }
            return true;
        }
    }
    false
}

pub fn verify_results_all_resolved() -> bool {
    UNRESOLVED.load(Ordering::SeqCst) <= 0
}
