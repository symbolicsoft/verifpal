/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub(crate) mod attacker;
mod decompose;
mod memo;
mod obtain;
mod reuse;
mod rewrite;
#[cfg(test)]
mod tests;

pub(crate) use attacker::{AttackerState, DerivationRecord, KnownIdx};
pub(crate) use decompose::{
	can_break_weak, can_decompose, decompose_rule, decomposition_reveals, revealed,
};
pub(crate) use memo::{DeductionMemo, SavedMemo};
pub(crate) use obtain::{KnowledgeInputs, can_recompose, can_reconstruct_primitive, obtainable};
pub(crate) use reuse::{forgeable_by_reuse, reused, reused_pair, same_fixed};
pub(crate) use rewrite::{can_rewrite, combine_binding_values, combine_bindings_hold, reduce_once};
