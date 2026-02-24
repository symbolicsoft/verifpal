/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use crate::types::PrincipalId;

struct PrincipalNamesState {
	map: HashMap<Arc<str>, PrincipalId>,
	names: Vec<Arc<str>>,
}

/// Global because principal IDs must be unique across the entire process.
/// Every `PrincipalState` and `SlotMeta` references principals by numeric ID,
/// so the name-to-ID mapping must be process-wide.
static PRINCIPAL_STATE: LazyLock<Mutex<PrincipalNamesState>> = LazyLock::new(|| {
	let mut map = HashMap::new();
	map.insert(Arc::from("Attacker"), 0);
	Mutex::new(PrincipalNamesState {
		map,
		names: vec![Arc::from("Attacker")],
	})
});

pub fn principal_names_map_add(name: &str) -> PrincipalId {
	let mut state = PRINCIPAL_STATE.lock().unwrap_or_else(|e| e.into_inner());
	if let Some(&id) = state.map.get(name) {
		return id;
	}
	let id = state.names.len() as PrincipalId;
	let arc_name: Arc<str> = Arc::from(name);
	state.map.insert(arc_name.clone(), id);
	state.names.push(arc_name);
	id
}

pub fn principal_get_name_from_id(id: PrincipalId) -> Arc<str> {
	let state = PRINCIPAL_STATE.lock().unwrap_or_else(|e| e.into_inner());
	state
		.names
		.get(id as usize)
		.cloned()
		.unwrap_or_else(|| Arc::from(""))
}

pub const ATTACKER_ID: PrincipalId = 0;

pub fn principal_names_reset() {
	let mut state = PRINCIPAL_STATE.lock().unwrap_or_else(|e| e.into_inner());
	state.map.clear();
	state.map.insert(Arc::from("Attacker"), 0);
	state.names.clear();
	state.names.push(Arc::from("Attacker"));
}
