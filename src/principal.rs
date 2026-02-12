/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::types::PrincipalId;

struct PrincipalNamesState {
	map: HashMap<String, PrincipalId>,
	names: Vec<String>,
}

/// Global because principal IDs must be unique across the entire process.
/// Every `PrincipalState` and `SlotMeta` references principals by numeric ID,
/// so the name-to-ID mapping must be process-wide.
static PRINCIPAL_STATE: LazyLock<Mutex<PrincipalNamesState>> = LazyLock::new(|| {
	let mut map = HashMap::new();
	map.insert("Attacker".to_string(), 0);
	Mutex::new(PrincipalNamesState {
		map,
		names: vec!["Attacker".to_string()],
	})
});

pub(crate) fn principal_names_map_add(name: &str) -> PrincipalId {
	let mut state = PRINCIPAL_STATE.lock().unwrap_or_else(|e| e.into_inner());
	if let Some(&id) = state.map.get(name) {
		return id;
	}
	let id = state.names.len() as PrincipalId;
	state.map.insert(name.to_string(), id);
	state.names.push(name.to_string());
	id
}

pub(crate) fn principal_get_name_from_id(id: PrincipalId) -> String {
	let state = PRINCIPAL_STATE.lock().unwrap_or_else(|e| e.into_inner());
	state.names.get(id as usize).cloned().unwrap_or_default()
}

pub(crate) fn principal_get_attacker_id() -> PrincipalId {
	0
}
