/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::types::PrincipalId;

struct PrincipalNamesState {
	map: HashMap<String, PrincipalId>,
	names: Vec<String>,
}

static PRINCIPAL_STATE: LazyLock<Mutex<PrincipalNamesState>> = LazyLock::new(|| {
	let mut map = HashMap::new();
	map.insert("Attacker".to_string(), 0);
	Mutex::new(PrincipalNamesState {
		map,
		names: vec!["Attacker".to_string()],
	})
});

pub fn principal_names_map_add(name: &str) -> PrincipalId {
	let mut state = PRINCIPAL_STATE.lock().expect("principal state lock");
	if let Some(&id) = state.map.get(name) {
		return id;
	}
	let id = state.names.len() as PrincipalId;
	state.map.insert(name.to_string(), id);
	state.names.push(name.to_string());
	id
}

pub fn principal_get_name_from_id(id: PrincipalId) -> String {
	let state = PRINCIPAL_STATE.lock().expect("principal state lock");
	state.names.get(id as usize).cloned().unwrap_or_default()
}

pub fn principal_get_attacker_id() -> PrincipalId {
	0
}
