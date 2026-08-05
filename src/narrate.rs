/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Narrating an attack
//!
//! Renders a minimized witness as numbered causal steps: what the attacker
//! substituted, which checks that got past, and how the goal was then
//! derived.  The derivation is read from the [`DerivationRecord`]s the
//! engine recorded while learning each value, so the narration describes the
//! run that happened rather than a plausible reconstruction of it.

use std::sync::Arc;

use crate::primitive::primitive_name;
use crate::types::*;
use crate::witness::Witness;

/// Maps values to the names of the slots holding them.
///
/// Substituting a slot's name for its value is lossless: the definition is
/// either in the model or earlier in the same trace.  It is what lets the
/// narration print full structure — nothing is ever elided by depth — while
/// staying readable.
pub(crate) struct NameTable {
	entries: Vec<(Value, Arc<str>)>,
}

impl NameTable {
	/// A table that names nothing, for callers with no witness to draw on.
	pub(crate) fn empty() -> NameTable {
		NameTable { entries: vec![] }
	}

	pub(crate) fn from_state(ps: &PrincipalState) -> NameTable {
		let mut entries: Vec<(Value, Arc<str>)> = Vec::new();
		for (sm, sv) in ps.meta.iter().zip(ps.values.iter()) {
			// Naming a constant after itself says nothing.
			if matches!(&sv.value, Value::Constant(_)) {
				continue;
			}
			// First declaration of a value wins: it is the one the reader
			// meets first.
			if entries.iter().any(|(v, _)| v.equivalent(&sv.value, true)) {
				continue;
			}
			entries.push((sv.value.clone(), Arc::clone(&sm.constant.name)));
		}
		NameTable { entries }
	}

	/// Render `v`, replacing every maximal subterm that names a slot.
	pub(crate) fn compress(&self, v: &Value) -> String {
		self.compress_excluding(v, &[])
	}

	/// As [`Self::compress`], but never collapsing to any name in `exclude`.
	///
	/// Rendering what a slot *now holds* must not answer with that slot's own
	/// name: after a mutation the table maps the slot's new value to the slot,
	/// so "Attacker replaces ms_ga with ms_ga" is what an unguarded compress
	/// produces.  A step that mutates several slots to the same term has the
	/// same problem across slots — the second `G^nil` would print as the name
	/// of the first slot that got one — so callers exclude every slot the step
	/// touches, not only the one being described.
	pub(crate) fn compress_excluding(&self, v: &Value, exclude: &[&str]) -> String {
		let named = self
			.entries
			.iter()
			.find(|(known, _)| known.equivalent(v, true))
			.map(|(_, name)| name);
		if let Some(name) = named
			&& !exclude.contains(&&**name)
		{
			return name.to_string();
		}
		match v {
			Value::Constant(c) => c.to_string(),
			Value::Primitive(p) => {
				let args: Vec<String> = p
					.arguments
					.iter()
					.map(|a| self.compress_excluding(a, exclude))
					.collect();
				format!(
					"{}({}){}",
					primitive_name(p.id),
					args.join(", "),
					if p.instance_check { "?" } else { "" }
				)
			}
			Value::Equation(e) => e
				.values
				.iter()
				.map(|ev| self.compress_excluding(ev, exclude))
				.collect::<Vec<_>>()
				.join("^"),
		}
	}
}

/// One attacker substitution.
#[derive(Clone, Debug)]
pub(crate) struct MutationItem {
	pub name: Arc<str>,
	pub new_value: String,
	pub old_value: String,
	pub guarded: bool,
}

/// One narrated step of an attack.
#[derive(Clone, Debug)]
pub(crate) enum Step {
	/// Substitutions the attacker made in a single wire message.
	Mutations {
		sender: Arc<str>,
		recipient: Arc<str>,
		items: Vec<MutationItem>,
	},
	/// A checked primitive that passed despite attacker-controlled inputs.
	Gate {
		principal: Arc<str>,
		primitive: String,
	},
	/// One derivation the attacker performed.
	Derive { text: String },
}

/// Substitutions in `ps`, grouped into the wire messages they belong to.
///
/// Grouping is by `(sender, recipient, declared_at)`: values that travelled
/// together are one action by the attacker, and reading them as one line is
/// how a protocol designer thinks about them.
pub(crate) fn mutation_steps(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	table: &NameTable,
) -> Vec<Step> {
	let mutated: Vec<&str> = ps
		.values
		.iter()
		.enumerate()
		.filter(|(_, sv)| sv.provenance.attacker_tainted)
		.map(|(i, _)| &*ps.meta[i].constant.name)
		.collect();
	let mut groups: Vec<(PrincipalId, PrincipalId, i32, Vec<MutationItem>)> = Vec::new();
	for (i, sv) in ps.values.iter().enumerate() {
		if !sv.provenance.attacker_tainted {
			continue;
		}
		let sm = &ps.meta[i];
		let sender = km
			.slots
			.get(i)
			.map(|slot| slot.creator)
			.unwrap_or(sv.provenance.creator);
		// Excluding every mutated slot's name is what stops the line reading
		// "Attacker replaces ms_ga with ms_ga".
		let own = mutated.as_slice();
		let item = MutationItem {
			name: Arc::clone(&sm.constant.name),
			new_value: table.compress_excluding(&sv.pre_rewrite, own),
			old_value: km
				.slots
				.get(i)
				.map(|slot| table.compress_excluding(&slot.initial_value, own))
				.unwrap_or_default(),
			guarded: sm.guard,
		};
		match groups
			.iter_mut()
			.find(|(s, r, d, _)| *s == sender && *r == ps.id && *d == sm.declared_at)
		{
			Some((_, _, _, items)) => items.push(item),
			None => groups.push((sender, ps.id, sm.declared_at, vec![item])),
		}
	}
	groups
		.into_iter()
		.map(|(sender, recipient, _, items)| Step::Mutations {
			sender: Arc::from(km.principal_name(sender)),
			recipient: Arc::from(km.principal_name(recipient)),
			items,
		})
		.collect()
}

/// Checked primitives this principal computed that passed even though the
/// attacker controlled their inputs.
///
/// These are the steps a reader is most likely to disbelieve — "surely the
/// signature check catches that" — so they are called out explicitly.
pub(crate) fn gate_steps(ps: &PrincipalState, table: &NameTable) -> Vec<Step> {
	let mut steps = Vec::new();
	for (i, sv) in ps.values.iter().enumerate() {
		let Value::Primitive(p) = &sv.pre_rewrite else {
			continue;
		};
		if !p.instance_check || sv.provenance.creator != ps.id {
			continue;
		}
		if !p.arguments.iter().any(|a| value_is_tainted(a, ps)) {
			continue;
		}
		// Same reason as in `mutation_steps`: naming the check after the slot
		// that holds it would print "m1_d passes" instead of the AEAD_DEC.
		let own = [&*ps.meta[i].constant.name];
		let own = own.as_slice();
		steps.push(Step::Gate {
			principal: Arc::from(ps.name.as_str()),
			primitive: table.compress_excluding(&sv.pre_rewrite, own),
		});
	}
	steps
}

/// Whether `v` contains any value the attacker substituted in `ps`.
fn value_is_tainted(v: &Value, ps: &PrincipalState) -> bool {
	if ps
		.values
		.iter()
		.any(|sv| sv.provenance.attacker_tainted && sv.pre_rewrite.equivalent(v, true))
	{
		return true;
	}
	match v {
		Value::Primitive(p) => p.arguments.iter().any(|a| value_is_tainted(a, ps)),
		Value::Equation(e) => e.values.iter().any(|ev| value_is_tainted(ev, ps)),
		Value::Constant(_) => false,
	}
}

/// How the attacker built `target`, as ordered steps: ingredients first, the
/// target last.
///
/// Chains that bottom out in values the attacker simply had — public
/// constants, `nil`, skeletons it can shape freely — end silently.  Narrating
/// "the attacker knows nil" would bury the steps that matter.
///
/// `home` is the principal whose session is being narrated.  A value the
/// attacker learned while running a *different* principal gets its line
/// prefixed with that session, so a reader is never told the attacker
/// obtained something in a session where it could not have.  Attribution is
/// per line rather than a mode switch: a marker that changed the meaning of
/// every step after it would mislabel the ones that belong to `home`.
pub(crate) fn derivation_steps(
	km: &ProtocolTrace,
	attacker: &AttackerState,
	target: &Value,
	table: &NameTable,
	home: PrincipalId,
) -> Vec<Step> {
	let mut seen: Vec<KnownIdx> = Vec::new();
	let mut steps: Vec<Step> = Vec::new();
	walk(km, attacker, target, table, home, &mut seen, &mut steps);
	steps
}

#[allow(clippy::too_many_arguments)]
fn walk(
	km: &ProtocolTrace,
	attacker: &AttackerState,
	value: &Value,
	table: &NameTable,
	home: PrincipalId,
	seen: &mut Vec<KnownIdx>,
	steps: &mut Vec<Step>,
) {
	let Some(idx) = attacker.knows(value) else {
		return;
	};
	if seen.contains(&idx) {
		return;
	}
	seen.push(idx);
	let Some(derivation) = attacker.derivation(idx) else {
		return;
	};

	// Ingredients first, so a step never mentions a value the reader has not
	// been told how the attacker got.
	for ingredient in derivation
		.ingredients()
		.into_iter()
		.cloned()
		.collect::<Vec<_>>()
	{
		walk(km, attacker, &ingredient, table, home, seen, steps);
	}

	if let Some(text) = describe(derivation, value, table) {
		let session = attacker
			.record(idx)
			.filter(|r| r.principal_id != home)
			.map(|r| {
				format!(
					"In an earlier session with {} (phase {}), ",
					km.principal_name(r.principal_id),
					r.phase,
				)
			});
		let text = match session {
			// Lower-case the sentence that now follows a prefix.
			Some(prefix) => format!("{}{}{}", prefix, lowercase_first(&text), ""),
			None => text,
		};
		steps.push(Step::Derive { text });
	}
}

fn lowercase_first(s: &str) -> String {
	let mut chars = s.chars();
	match chars.next() {
		Some(c) => c.to_lowercase().collect::<String>() + chars.as_str(),
		None => String::new(),
	}
}

/// One line of prose for a derivation, or `None` when it is not worth a step.
///
/// A record with no template of its own still renders — in the raw form the
/// `Deduction ›` line uses — because a step the reader cannot see is worse
/// than a step that reads mechanically.
fn describe(derivation: &DerivationRecord, value: &Value, table: &NameTable) -> Option<String> {
	let v = table.compress(value);
	Some(match derivation {
		// Values the attacker simply had are not events.
		DerivationRecord::Initial | DerivationRecord::Injected => return None,
		DerivationRecord::Leaked { .. } => {
			format!("Attacker is handed {} by a leaks declaration.", v)
		}
		DerivationRecord::Obtained { .. } => format!("Attacker observes {} on the wire.", v),
		DerivationRecord::Decomposed { of, using } if using.is_empty() => {
			format!("Attacker reads {} out of {}.", v, table.compress(of))
		}
		DerivationRecord::Decomposed { of, using } => format!(
			"Attacker opens {} with {}, obtaining {}.",
			table.compress(of),
			join_terms(using, table),
			v,
		),
		DerivationRecord::Reconstructed { from } if from.is_empty() => {
			format!("Attacker constructs {}.", v)
		}
		DerivationRecord::Reconstructed { from } => {
			format!(
				"Attacker constructs {} from {}.",
				v,
				join_terms(from, table)
			)
		}
		DerivationRecord::Recomposed { of, using } => format!(
			"Attacker recomposes {} from enough shares of {} ({}).",
			v,
			table.compress(of),
			join_terms(using, table),
		),
		DerivationRecord::PasswordExtracted { from } => format!(
			"Attacker recovers the password {} used unhashed inside {}.",
			v,
			table.compress(from),
		),
		DerivationRecord::ConcatFragment { of } => {
			format!("Attacker splits {} and takes {}.", table.compress(of), v)
		}
	})
}

fn join_terms(values: &[Value], table: &NameTable) -> String {
	values
		.iter()
		.map(|v| table.compress(v))
		.collect::<Vec<_>>()
		.join(", ")
}

/// A narrated attack, and the vocabulary it was written in.
///
/// The goal line quotes the same terms the steps do, so it is written with the
/// same table: a summary that spells out in full what step 13 called `akenc1`
/// makes the reader match two pages of nested HKDF by eye.
pub(crate) struct Narration {
	pub trace: String,
	table: NameTable,
}

impl Narration {
	/// No trace and no vocabulary, for a probe that will not be read.
	pub(crate) fn none() -> Narration {
		Narration {
			trace: String::new(),
			table: NameTable::empty(),
		}
	}

	/// Render `v` in the vocabulary of this trace.
	pub(crate) fn term(&self, v: &Value) -> String {
		self.table.compress(v)
	}
}

/// Render a minimized witness as numbered attack steps.
///
/// The trace is empty when there is nothing to narrate — a query that fails
/// without the attacker doing anything is fully explained by its goal line.
pub(crate) fn narrate_attack(km: &ProtocolTrace, witness: &Witness, target: &Value) -> Narration {
	let table = NameTable::from_state(&witness.ps);
	let mut steps = mutation_steps(km, &witness.ps, &table);
	steps.extend(gate_steps(&witness.ps, &table));
	steps.extend(derivation_steps(
		km,
		&witness.attacker,
		target,
		&table,
		witness.ps.id,
	));
	Narration {
		trace: render(&steps),
		table,
	}
}

fn render(steps: &[Step]) -> String {
	let mut out = String::new();
	for (i, step) in steps.iter().enumerate() {
		let text = match step {
			Step::Mutations {
				sender,
				recipient,
				items,
			} => render_mutations(sender, recipient, items),
			Step::Gate {
				principal,
				primitive,
			} => format!(
				"{}'s {} passes — its inputs are attacker-controlled.",
				principal, primitive,
			),
			Step::Derive { text } => text.clone(),
		};
		out.push_str(&format!("\n            {}. {}", i + 1, text));
	}
	out
}

fn render_mutations(sender: &str, recipient: &str, items: &[MutationItem]) -> String {
	// A substitution whose term is indistinguishable from the honest one is
	// not a replacement — it is the attacker sending the message itself.  For
	// authentication that *is* the attack, and "replaces e1 with e1" would
	// describe it as a no-op.
	let (replaced, impersonated): (Vec<&MutationItem>, Vec<&MutationItem>) =
		items.iter().partition(|i| i.new_value != i.old_value);

	let mut parts: Vec<String> = Vec::new();
	if !replaced.is_empty() {
		let names: Vec<String> = replaced.iter().map(|i| i.name.to_string()).collect();
		let values: Vec<String> = replaced.iter().map(|i| i.new_value.clone()).collect();
		let mut text = format!(
			"Attacker replaces {} (sent by {} to {}) with {}.",
			names.join(", "),
			sender,
			recipient,
			values.join(", "),
		);
		let originals: Vec<String> = replaced
			.iter()
			.filter(|i| !i.old_value.is_empty())
			.map(|i| format!("{} was {}", i.name, i.old_value))
			.collect();
		if !originals.is_empty() {
			text.push_str(&format!(" ({})", originals.join("; ")));
		}
		parts.push(text);
	}
	if !impersonated.is_empty() {
		let names: Vec<String> = impersonated.iter().map(|i| i.name.to_string()).collect();
		parts.push(format!(
			"Attacker, not {}, is what sends {} to {}.",
			sender,
			names.join(", "),
			recipient,
		));
	}
	if items.iter().any(|i| i.guarded) {
		parts.push("The guard is bypassed: Attacker holds its key.".to_string());
	}
	parts.join(" ")
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::parser::parse_string;
	use crate::primitive::*;
	use crate::testutil::*;

	fn name_table_state() -> PrincipalState {
		// nt_k = HASH(nt_a); nt_e = HASH(nt_k, nt_b)
		let a = make_constant("nt_a");
		let b = make_constant("nt_b");
		let k = make_constant("nt_k");
		let e = make_constant("nt_e");
		let hash_a = make_primitive(PRIM_HASH, vec![a.clone()], 0);
		let hash_kb = make_primitive(PRIM_HASH, vec![hash_a.clone(), b.clone()], 0);
		let meta = vec![
			make_slot_meta(a.as_constant().expect("c"), true),
			make_slot_meta(b.as_constant().expect("c"), true),
			make_slot_meta(k.as_constant().expect("c"), true),
			make_slot_meta(e.as_constant().expect("c"), true),
		];
		let values = vec![
			make_slot_values(&a, 0),
			make_slot_values(&b, 0),
			make_slot_values(&hash_a, 0),
			make_slot_values(&hash_kb, 0),
		];
		make_principal_state("Alice", 0, meta, values)
	}

	#[test]
	fn name_table_compresses_whole_term_to_slot_name() {
		use crate::narrate::NameTable;
		let ps = name_table_state();
		let table = NameTable::from_state(&ps);
		let hash_a = make_primitive(PRIM_HASH, vec![make_constant("nt_a")], 0);
		assert_eq!(table.compress(&hash_a), "nt_k");
	}

	#[test]
	fn name_table_compresses_subterms_only() {
		use crate::narrate::NameTable;
		let ps = name_table_state();
		let table = NameTable::from_state(&ps);
		// A term that is not itself a named slot keeps its shape, but its
		// named subterm collapses.
		let hash_a = make_primitive(PRIM_HASH, vec![make_constant("nt_a")], 0);
		let outer = make_primitive(PRIM_HASH, vec![hash_a, make_constant("nt_x")], 0);
		assert_eq!(table.compress(&outer), "HASH(nt_k, nt_x)");
	}

	#[test]
	fn name_table_respects_output_index() {
		use crate::narrate::NameTable;
		let ps = name_table_state();
		let table = NameTable::from_state(&ps);
		// Same shape, different output index: not the same value, not the name.
		let other_output = make_primitive(PRIM_HASH, vec![make_constant("nt_a")], 1);
		assert_eq!(table.compress(&other_output), "HASH(nt_a)");
	}

	#[test]
	fn name_table_never_names_a_term_after_itself() {
		use crate::narrate::NameTable;
		let ps = name_table_state();
		let table = NameTable::from_state(&ps);
		let hash_a = make_primitive(PRIM_HASH, vec![make_constant("nt_a")], 0);
		// Describing what slot nt_k now holds must not answer "nt_k".
		assert_eq!(table.compress_excluding(&hash_a, &["nt_k"]), "HASH(nt_a)");
		// Excluding an unrelated name changes nothing.
		assert_eq!(table.compress_excluding(&hash_a, &["nt_e"]), "nt_k");
	}

	#[test]
	fn mutation_steps_group_by_message_and_report_old_value() {
		use crate::narrate::{NameTable, Step, mutation_steps};
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private ms_a\n\
			ms_ga = G^ms_a\n\
			]\n\
			Alice -> Bob: ms_ga\n\
			principal Bob[\n\
			knows private ms_b\n\
			ms_s = ms_ga^ms_b\n\
			]\n\
			queries[\n\
			confidentiality? ms_s\n\
			]\n";
		let m = parse_string("ms.vp", src).expect("parse");
		let (km, states) = crate::sanity::sanity(&m).expect("sanity");
		// Bob's state, with the wire value replaced by the attacker.
		let bob = states
			.iter()
			.find(|p| p.name == "Bob")
			.expect("Bob")
			.clone();
		let slot = bob
			.index_of(
				&km.slots
					.iter()
					.find(|s| &*s.constant.name == "ms_ga")
					.expect("slot")
					.constant,
			)
			.expect("index");
		let mut mutated = bob.clone();
		crate::reexec::install(&mut mutated, slot, crate::value::value_g_nil(), true);

		let table = NameTable::from_state(&mutated);
		let steps = mutation_steps(&km, &mutated, &table);
		assert_eq!(steps.len(), 1, "one message mutated, one step");
		match &steps[0] {
			Step::Mutations { items, .. } => {
				assert_eq!(items.len(), 1);
				assert_eq!(&*items[0].name, "ms_ga");
				assert_eq!(items[0].new_value, "G^nil");
				assert_eq!(items[0].old_value, "G^ms_a");
			}
			other => panic!("expected Mutations, got {:?}", other),
		}
	}

	#[test]
	fn derivation_steps_walk_ancestors_before_target() {
		use crate::context::VerifyContext;
		use crate::narrate::{NameTable, Step, derivation_steps};
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private dw_m\n\
			knows private dw_k\n\
			dw_e = ENC(dw_k, dw_m)\n\
			leaks dw_k\n\
			]\n\
			principal Bob[\n\
			knows private dw_b\n\
			]\n\
			Alice -> Bob: dw_e\n\
			queries[\n\
			confidentiality? dw_m\n\
			]\n";
		let m = parse_string("dw.vp", src).expect("parse");
		let (km, states) = crate::sanity::sanity(&m).expect("sanity");
		let ctx = VerifyContext::new(&m, &states);
		let mut pure = states[0].clone_for_depth(true);
		pure.resolve_all_values(&ctx.attacker_snapshot())
			.expect("resolve");
		ctx.attacker_phase_update(&km, &pure, 0).expect("phase");
		crate::verify::verify_standard_run(&ctx, &km, &states).expect("run");

		let attacker = ctx.attacker_snapshot();
		let target = trace_constant(&km, "dw_m");
		let table = NameTable::from_state(&pure);
		let steps = derivation_steps(&km, &attacker, &target, &table, pure.id);

		assert!(!steps.is_empty(), "the attacker learned dw_m somehow");
		let text: Vec<String> = steps
			.iter()
			.map(|s| match s {
				Step::Derive { text } => text.clone(),
				other => panic!("expected Derive, got {:?}", other),
			})
			.collect();
		assert!(
			text.iter().any(|t| t.contains("dw_m")),
			"a step must reach the target: {:?}",
			text
		);
		// The key was leaked, and that must be narrated before the step that
		// uses it to open the ciphertext.
		let leaked = text.iter().position(|t| t.contains("leaks declaration"));
		let opened = text.iter().position(|t| t.contains("dw_m"));
		assert!(
			leaked.is_some() && opened.is_some() && leaked < opened,
			"ingredients must precede the step that consumes them: {:?}",
			text
		);
	}

	#[test]
	fn derivation_steps_stay_silent_on_unknown_values() {
		use crate::narrate::{NameTable, derivation_steps};
		// A value the attacker never learned has no derivation to narrate.
		let ps = name_table_state();
		let table = NameTable::from_state(&ps);
		let attacker = make_attacker_state(vec![]);
		let unknown = make_constant("dw_absent");
		let trace = make_trace();
		assert!(derivation_steps(&trace, &attacker, &unknown, &table, 0).is_empty());
	}
}
