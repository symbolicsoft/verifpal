/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

pub(crate) mod collections;
pub(crate) mod generation;
pub(crate) mod index;
pub(crate) mod parallel;
pub(crate) mod sync;
pub(crate) mod text;

pub(crate) use collections::{IdHasher, IdMap, IdSet};
