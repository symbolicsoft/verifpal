/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::types::PrincipalId;

struct PrincipalNamesState {
    map: HashMap<String, PrincipalId>,
    counter: PrincipalId,
}

static PRINCIPAL_STATE: LazyLock<Mutex<PrincipalNamesState>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    map.insert("Attacker".to_string(), 0);
    Mutex::new(PrincipalNamesState { map, counter: 1 })
});

pub fn principal_names_map_add(name: &str) -> PrincipalId {
    let mut state = PRINCIPAL_STATE.lock().expect("principal state lock");
    if let Some(&id) = state.map.get(name) {
        return id;
    }
    let id = state.counter;
    state.map.insert(name.to_string(), id);
    state.counter += 1;
    id
}

pub fn principal_names_map_get(name: &str) -> Option<PrincipalId> {
    let state = PRINCIPAL_STATE.lock().expect("principal state lock");
    state.map.get(name).copied()
}

pub fn principal_get_name_from_id(id: PrincipalId) -> String {
    let state = PRINCIPAL_STATE.lock().expect("principal state lock");
    for (k, &v) in state.map.iter() {
        if v == id {
            return k.clone();
        }
    }
    String::new()
}

pub fn principal_get_attacker_id() -> PrincipalId {
    principal_names_map_get("Attacker").unwrap_or(0)
}
