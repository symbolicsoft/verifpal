/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;
use std::sync::RwLock;
use std::sync::LazyLock;
use std::collections::{HashMap, HashSet};
use crate::types::*;
use crate::value::{value_hash, value_equivalent_value_in_values_map};
use crate::inject::primitive_skeleton_hash_of;
use crate::construct::construct_principal_state_clone;
use crate::util::*;

static STATE: LazyLock<RwLock<AttackerState>> = LazyLock::new(|| {
    RwLock::new(AttackerState {
        current_phase: 0,
        exhausted: false,
        known: Arc::new(vec![]),
        known_map: Arc::new(HashMap::new()),
        skeleton_hashes: Arc::new(HashSet::new()),
        principal_state: Arc::new(vec![]),
    })
});

pub fn attacker_state_init() {
    let mut state = STATE.write().expect("attacker state lock");
    *state = AttackerState {
        current_phase: 0,
        exhausted: false,
        known: Arc::new(vec![]),
        known_map: Arc::new(HashMap::new()),
        skeleton_hashes: Arc::new(HashSet::new()),
        principal_state: Arc::new(vec![]),
    };
}

/// Returns a cheap snapshot of the attacker state (O(1) — just Arc increments).
pub fn attacker_state_get_read() -> AttackerState {
    STATE.read().expect("attacker state lock").clone()
}

pub fn attacker_state_get_exhausted() -> bool {
    STATE.read().expect("attacker state lock").exhausted
}

pub fn attacker_state_get_known_count() -> usize {
    STATE.read().expect("attacker state lock").known.len()
}

/// Appends a new known value in-place. O(1) amortized — Arc::make_mut only
/// clones the inner collections once per snapshot cycle (when readers hold
/// Arc references), then subsequent writes within the same cycle are pure appends.
pub fn attacker_state_put_write(known: &Value, val_principal_state: &PrincipalState) -> bool {
    // Fast check with read lock
    {
        let state = STATE.read().expect("attacker state lock");
        if value_equivalent_value_in_values_map(known, &state.known, &state.known_map) >= 0 {
            return false;
        }
    }
    // Prepare the clone outside the write lock
    let clone = Arc::new(construct_principal_state_clone(val_principal_state, false));
    // Write lock: double-check and append in-place
    let mut state = STATE.write().expect("attacker state lock");
    if value_equivalent_value_in_values_map(known, &state.known, &state.known_map) >= 0 {
        return false;
    }
    let idx = state.known.len();
    Arc::make_mut(&mut state.known).push(known.clone());
    let h = value_hash(known);
    Arc::make_mut(&mut state.known_map).entry(h).or_default().push(idx);
    if let Value::Primitive(p) = known {
        Arc::make_mut(&mut state.skeleton_hashes).insert(primitive_skeleton_hash_of(p));
    }
    Arc::make_mut(&mut state.principal_state).push(clone);
    true
}

pub fn attacker_state_put_phase_update(
    val_knowledge_map: &KnowledgeMap,
    val_principal_state: &PrincipalState,
    phase: i32,
) -> Result<(), String> {
    {
        let mut state = STATE.write().expect("attacker state lock");
        state.current_phase = phase;
    }
    attacker_state_absorb_phase_values(val_knowledge_map, val_principal_state)
}

pub fn attacker_state_put_exhausted() {
    let mut state = STATE.write().expect("attacker state lock");
    state.exhausted = true;
}

fn attacker_state_absorb_phase_values(
    val_knowledge_map: &KnowledgeMap,
    val_principal_state: &PrincipalState,
) -> Result<(), String> {
    let mut state = STATE.write().expect("attacker state lock");
    let current_phase = state.current_phase;

    // Public constants
    for i in 0..val_principal_state.constants.len() {
        if let Value::Constant(c) = &val_principal_state.assigned[i] {
            if c.qualifier != TypesEnum::Public {
                continue;
            }
            if let Ok(earliest) = min_int_in_slice(&val_principal_state.phase[i]) {
                if earliest > current_phase {
                    continue;
                }
            }
            if !crate::value::value_constant_is_used_by_at_least_one_principal(val_knowledge_map, c) {
                continue;
            }
            let assigned = &val_principal_state.assigned[i];
            if value_equivalent_value_in_values_map(assigned, &state.known, &state.known_map) < 0 {
                let clone = Arc::new(construct_principal_state_clone(val_principal_state, false));
                let idx = state.known.len();
                Arc::make_mut(&mut state.known).push(assigned.clone());
                let h = value_hash(assigned);
                Arc::make_mut(&mut state.known_map).entry(h).or_default().push(idx);
                Arc::make_mut(&mut state.principal_state).push(clone);
            }
        }
    }

    // Wire/leaked values
    for (i, c) in val_principal_state.constants.iter().enumerate() {
        let cc = Value::Constant(c.clone());
        let a = &val_principal_state.assigned[i];
        if val_principal_state.wire[i].is_empty() && !val_principal_state.constants[i].leaked {
            continue;
        }
        if val_principal_state.constants[i].qualifier == TypesEnum::Public {
            continue;
        }
        let earliest = min_int_in_slice(&val_principal_state.phase[i])?;
        if earliest > current_phase {
            continue;
        }
        if value_equivalent_value_in_values_map(&cc, &state.known, &state.known_map) < 0 {
            let clone = Arc::new(construct_principal_state_clone(val_principal_state, false));
            let idx = state.known.len();
            Arc::make_mut(&mut state.known).push(cc.clone());
            let h = value_hash(&cc);
            Arc::make_mut(&mut state.known_map).entry(h).or_default().push(idx);
            Arc::make_mut(&mut state.principal_state).push(clone);
        }
        if value_equivalent_value_in_values_map(a, &state.known, &state.known_map) < 0 {
            let clone = Arc::new(construct_principal_state_clone(val_principal_state, false));
            let idx = state.known.len();
            Arc::make_mut(&mut state.known).push(a.clone());
            let h = value_hash(a);
            Arc::make_mut(&mut state.known_map).entry(h).or_default().push(idx);
            Arc::make_mut(&mut state.principal_state).push(clone);
        }
    }

    Ok(())
}
