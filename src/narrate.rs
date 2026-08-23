/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::sync::Arc;

use crate::primitive::primitive_name;
use crate::principal::ATTACKER_ID;
use crate::theory::can_rewrite;
use crate::types::*;
use crate::witness::Witness;

pub(crate) struct NameTable {
	entries: Vec<(Value, Arc<str>)>,
}

impl NameTable {
	pub(crate) fn empty() -> NameTable {
		NameTable { entries: vec![] }
	}

	pub(crate) fn from_state(ps: &PrincipalState) -> NameTable {
		let mut entries: Vec<(Value, Arc<str>)> = Vec::new();
		for (sm, sv) in ps.meta.iter().zip(ps.values.iter()) {
			if matches!(&sv.value, Value::Constant(_)) {
				continue;
			}
			if entries.iter().any(|(v, _)| v.equivalent(&sv.value, true)) {
				continue;
			}
			entries.push((sv.value.clone(), Arc::clone(&sm.constant.name)));
		}
		NameTable { entries }
	}

	pub(crate) fn compress(&self, v: &Value) -> String {
		self.compress_excluding(v, &[])
	}

	pub(crate) fn without(&self, names: &[&str]) -> NameTable {
		NameTable {
			entries: self
				.entries
				.iter()
				.filter(|(_, n)| !names.contains(&&**n))
				.cloned()
				.collect(),
		}
	}

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
		}
	}
}

#[derive(Clone, Debug)]
pub(crate) struct MutationItem {
	pub name: Arc<str>,
	pub new_value: String,
	pub old_value: String,
	pub guarded: bool,
	#[cfg(test)]
	pub installed: Value,
}

#[derive(Clone, Debug)]
pub(crate) enum Step {
	Mutations {
		sender: Arc<str>,
		recipient: Arc<str>,
		items: Vec<MutationItem>,
	},
	Bypass {
		principal: Arc<str>,
		slot: Arc<str>,
		check: String,
		key: String,
		#[cfg(test)]
		key_term: Option<Value>,
	},
	Replay {
		sender: Arc<str>,
		recipient: Arc<str>,
		name: Arc<str>,
		value: String,
		#[cfg(test)]
		installed: Value,
	},
	Resolves {
		name: Arc<str>,
		value: String,
		#[cfg(test)]
		slot: SlotIdx,
		#[cfg(test)]
		term: Value,
	},
	Static {
		name: Arc<str>,
		leaves: String,
		#[cfg(test)]
		terms: Vec<Value>,
	},
	Received {
		name: Arc<str>,
		sender: Arc<str>,
		recipient: Arc<str>,
		#[cfg(test)]
		slot: SlotIdx,
	},
	Gate {
		principal: Arc<str>,
		primitive: String,
		#[cfg(test)]
		term: Value,
		#[cfg(test)]
		slot: SlotIdx,
	},
	Derive {
		text: String,
		#[cfg(test)]
		target: Value,
		#[cfg(test)]
		ingredients: Vec<Value>,
		#[cfg(test)]
		record: DerivationRecord,
	},
}

fn reportable(sv: &SlotValues) -> bool {
	sv.provenance.sender == ATTACKER_ID || sv.provenance.bypass_injected || replayed(sv)
}

fn replayed(sv: &SlotValues) -> bool {
	sv.provenance.creator == ATTACKER_ID
		&& sv.provenance.attacker_tainted
		&& sv.provenance.sender != ATTACKER_ID
		&& !sv.provenance.bypass_injected
}

pub(crate) fn constant_leaves(v: &Value) -> Vec<Constant> {
	let mut out: Vec<Constant> = Vec::new();
	fn walk_leaves(v: &Value, out: &mut Vec<Constant>) {
		match v {
			Value::Constant(c) => {
				if !out.iter().any(|e| e.id == c.id) {
					out.push(c.clone());
				}
			}
			Value::Primitive(p) => {
				for a in p.arguments.iter() {
					walk_leaves(a, out);
				}
			}
		}
	}
	walk_leaves(v, &mut out);
	out
}

#[cfg(test)]
pub(crate) fn narrated_installs(ps: &PrincipalState) -> Vec<SlotIdx> {
	ps.values
		.iter()
		.enumerate()
		.filter(|(_, sv)| sv.provenance.sender == ATTACKER_ID || replayed(sv))
		.map(|(i, _)| SlotIdx(i))
		.collect()
}

/// Does `v` mention any constant in `ids`?
fn mentions(v: &Value, ids: &IdSet<u32>) -> bool {
	match v {
		Value::Constant(c) => ids.contains(&c.id),
		Value::Primitive(p) => p.arguments.iter().any(|a| mentions(a, ids)),
	}
}

fn shadowed_names(km: &ProtocolTrace, ps: &PrincipalState) -> Vec<Arc<str>> {
	let mut ids: IdSet<u32> = ps
		.values
		.iter()
		.enumerate()
		.filter(|(_, sv)| reportable(sv))
		.map(|(i, _)| ps.meta[i].constant.id)
		.collect();
	loop {
		let before = ids.len();
		for slot in km.slots.iter() {
			if !ids.contains(&slot.constant.id) && mentions(&slot.initial_value, &ids) {
				ids.insert(slot.constant.id);
			}
		}
		if ids.len() == before {
			break;
		}
	}
	ps.meta
		.iter()
		.filter(|sm| ids.contains(&sm.constant.id))
		.map(|sm| Arc::clone(&sm.constant.name))
		.collect()
}

pub(crate) fn mutation_steps(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	table: &NameTable,
) -> Vec<Step> {
	let shadowed = shadowed_names(km, ps);
	let mutated: Vec<&str> = shadowed.iter().map(|s| &**s).collect();
	let mut groups: Vec<(PrincipalId, PrincipalId, i32, Vec<MutationItem>)> = Vec::new();
	let mut bypasses: Vec<Step> = Vec::new();
	let mut replays: Vec<Step> = Vec::new();
	for (i, sv) in ps.values.iter().enumerate() {
		if !reportable(sv) {
			continue;
		}
		let sm = &ps.meta[i];
		if sv.provenance.bypass_injected && sv.provenance.sender != ATTACKER_ID {
			let declared = km.slots.get(i).map(|slot| &slot.initial_value);
			let bypass_key = match declared {
				Some(Value::Primitive(p)) => {
					let shallow = shallow_resolve(ps, p);
					crate::primitive::primitive_extract_bypass_key(&shallow)
				}
				_ => None,
			};
			bypasses.push(Step::Bypass {
				principal: Arc::from(ps.name.as_str()),
				slot: Arc::clone(&sm.constant.name),
				#[cfg(test)]
				key_term: bypass_key.clone(),
				check: declared
					.map(|v| table.compress_excluding(v, mutated.as_slice()))
					.unwrap_or_else(|| sm.constant.name.to_string()),
				key: bypass_key
					.map(|k| table.compress_excluding(&k, mutated.as_slice()))
					.unwrap_or_default(),
			});
			continue;
		}
		let (sender, recipient) = wire_leg(km, ps, i);
		let own = mutated.as_slice();
		if replayed(sv) || crate::query::session_sibling_replay(&sm.constant, &sv.pre_rewrite, km) {
			replays.push(Step::Replay {
				sender: Arc::from(km.principal_name(sender)),
				recipient: Arc::from(km.principal_name(recipient)),
				name: Arc::clone(&sm.constant.name),
				value: table.compress_excluding(&sv.pre_rewrite, own),
				#[cfg(test)]
				installed: sv.pre_rewrite.clone(),
			});
			continue;
		}
		let item = MutationItem {
			#[cfg(test)]
			installed: sv.pre_rewrite.clone(),
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
			.find(|(s, r, d, _)| *s == sender && *r == recipient && *d == sm.declared_at)
		{
			Some((_, _, _, items)) => items.push(item),
			None => groups.push((sender, recipient, sm.declared_at, vec![item])),
		}
	}
	groups
		.into_iter()
		.map(|(sender, recipient, _, items)| Step::Mutations {
			sender: Arc::from(km.principal_name(sender)),
			recipient: Arc::from(km.principal_name(recipient)),
			items,
		})
		.chain(replays)
		.chain(bypasses)
		.collect()
}

fn deep_resolve(ps: &PrincipalState, v: &Value) -> Value {
	match v {
		Value::Constant(c) => {
			let (resolved, _) = ps.resolve_constant(c, false);
			match &resolved {
				Value::Constant(r) if r.id == c.id => resolved,
				other => deep_resolve(ps, other),
			}
		}
		Value::Primitive(p) => {
			let arguments = p.arguments.iter().map(|a| deep_resolve(ps, a)).collect();
			Value::Primitive(std::sync::Arc::new(p.with_arguments(arguments)))
		}
	}
}

fn shallow_resolve(ps: &PrincipalState, p: &Primitive) -> Primitive {
	let arguments = p.arguments.iter().map(|a| deep_resolve(ps, a)).collect();
	p.with_arguments(arguments)
}

fn wire_leg(km: &ProtocolTrace, ps: &PrincipalState, i: usize) -> (PrincipalId, PrincipalId) {
	let meta = &ps.meta[i];
	if let Some(&(_, from)) = meta.known_by.iter().find(|&&(to, _)| to == ps.id) {
		return (from, ps.id);
	}
	if let Some(&(to, from)) = meta.known_by.first() {
		return (from, to);
	}
	let creator = km
		.slots
		.get(i)
		.map(|slot| slot.creator)
		.unwrap_or(ps.values[i].provenance.creator);
	(creator, ps.id)
}

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
		if !can_rewrite(p).0 {
			continue;
		}
		let own = [&*ps.meta[i].constant.name];
		let own = own.as_slice();
		let primitive = table.compress_excluding(&sv.pre_rewrite, own);
		if steps
			.iter()
			.any(|s| matches!(s, Step::Gate { primitive: p, .. } if *p == primitive))
		{
			continue;
		}
		steps.push(Step::Gate {
			principal: Arc::from(ps.name.as_str()),
			primitive,
			#[cfg(test)]
			term: sv.pre_rewrite.clone(),
			#[cfg(test)]
			slot: SlotIdx(i),
		});
	}
	steps
}

pub(crate) fn value_is_tainted(v: &Value, ps: &PrincipalState) -> bool {
	if ps
		.values
		.iter()
		.any(|sv| sv.provenance.attacker_tainted && sv.pre_rewrite.equivalent(v, true))
	{
		return true;
	}
	match v {
		Value::Primitive(p) => p.arguments.iter().any(|a| value_is_tainted(a, ps)),
		Value::Constant(_) => false,
	}
}

pub(crate) fn derivation_steps(
	km: &ProtocolTrace,
	attacker: &AttackerState,
	target: &Value,
	table: &NameTable,
	home: PrincipalId,
	carried: &[CarriedIn],
	seen: &mut Vec<KnownIdx>,
) -> Vec<Step> {
	let mut steps: Vec<Step> = Vec::new();
	walk(km, attacker, target, table, home, carried, seen, &mut steps);
	steps
}

#[allow(clippy::too_many_arguments)]
fn walk(
	km: &ProtocolTrace,
	attacker: &AttackerState,
	value: &Value,
	table: &NameTable,
	home: PrincipalId,
	carried: &[CarriedIn],
	seen: &mut Vec<KnownIdx>,
	steps: &mut Vec<Step>,
) {
	let Some(idx) = attacker.knows(value) else {
		if let Value::Primitive(p) = value {
			for argument in p.arguments.iter() {
				walk(km, attacker, argument, table, home, carried, seen, steps);
			}
		}
		return;
	};
	if seen.contains(&idx) {
		return;
	}
	seen.push(idx);
	let Some(derivation) = attacker.derivation(idx) else {
		return;
	};

	for ingredient in derivation.ingredients() {
		walk(km, attacker, ingredient, table, home, carried, seen, steps);
	}

	if let Some(text) = describe(km, derivation, value, table, carried) {
		let session = attacker
			.record(idx)
			.and_then(|r| session_prefix(km, r, home));
		let text = match session {
			Some(prefix) => format!("{}{}", prefix, lowercase_first(&text)),
			None => text,
		};
		steps.push(Step::Derive {
			text,
			#[cfg(test)]
			target: value.clone(),
			#[cfg(test)]
			ingredients: derivation.ingredients().into_iter().cloned().collect(),
			#[cfg(test)]
			record: derivation.clone(),
		});
	}
}

/// Where a derivation happened, when that is not the session being narrated.
fn session_prefix(km: &ProtocolTrace, r: &MutationRecord, home: PrincipalId) -> Option<String> {
	if r.principal_id == home {
		return None;
	}
	Some(format!(
		"In an earlier session with {} (phase {}), ",
		km.principal_name(r.principal_id),
		r.phase,
	))
}

fn lowercase_first(s: &str) -> String {
	let mut chars = s.chars();
	match chars.next() {
		Some(c) => c.to_lowercase().collect::<String>() + chars.as_str(),
		None => String::new(),
	}
}

fn describe(
	km: &ProtocolTrace,
	derivation: &DerivationRecord,
	value: &Value,
	table: &NameTable,
	carried: &[CarriedIn],
) -> Option<String> {
	let v = table.compress(value);
	Some(match derivation {
		DerivationRecord::Initial | DerivationRecord::Injected => return None,
		DerivationRecord::Leaked { .. } => {
			format!("Attacker is handed {} by a leaks declaration.", v)
		}
		DerivationRecord::Obtained { .. }
			if let Some(c) = carried.iter().find(|c| c.value.equivalent(value, true)) =>
		{
			let via = c
				.via
				.iter()
				.map(|(name, value)| format!("{name} with {}", table.compress(value)))
				.collect::<Vec<_>>()
				.join(", ");
			match (via.is_empty(), c.origin.clone()) {
				(true, Some(name)) if name == v => {
					format!("Attacker observes {name} on the wire in an earlier session.")
				}
				(true, Some(name)) => format!(
					"Attacker observes {name} on the wire in an earlier session, where it is {}.",
					v
				),
				(true, None) => format!("Attacker holds {} from an earlier session.", v),
				(false, Some(name)) => format!(
					"In an earlier session in which the attacker replaced {via}, {name} \
					 resolved to {}.",
					v
				),
				(false, None) => format!(
					"In an earlier session in which the attacker replaced {via}, {} became \
					 available.",
					v
				),
			}
		}
		DerivationRecord::Obtained { slot } => {
			let travelled = km.slots.get(slot.get()).is_some_and(|s| {
				!s.sent_by.is_empty()
					|| s.constant.leaked
					|| s.constant.qualifier == Some(Qualifier::Public)
			});
			if travelled {
				format!("Attacker observes {} on the wire.", v)
			} else {
				format!(
					"Attacker obtains {}: a value it already holds resolves to it here.",
					v
				)
			}
		}
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
		DerivationRecord::Broken {
			of,
			capability,
			using,
		} if using.is_empty() => format!(
			"Attacker breaks {} under the declared `{}` assumption, obtaining {}.",
			table.compress(of),
			capability.name(),
			v,
		),
		DerivationRecord::Broken {
			of,
			capability,
			using,
		} => format!(
			"Attacker breaks {} under the declared `{}` assumption using {}, obtaining {}.",
			table.compress(of),
			capability.name(),
			join_terms(using, table),
			v,
		),
	})
}

fn join_terms(values: &[Value], table: &NameTable) -> String {
	values
		.iter()
		.map(|v| table.compress(v))
		.collect::<Vec<_>>()
		.join(", ")
}

impl Step {
	pub(crate) fn kind(&self) -> &'static str {
		match self {
			Step::Mutations { .. } => "mutations",
			Step::Bypass { .. } => "bypass",
			Step::Replay { .. } => "replay",
			Step::Resolves { .. } => "resolves",
			Step::Static { .. } => "static",
			Step::Received { .. } => "received",
			Step::Gate { .. } => "gate",
			Step::Derive { .. } => "derive",
		}
	}
}

pub(crate) struct Narration {
	pub trace: String,
	pub steps: Vec<Step>,
	table: NameTable,
	state: Option<PrincipalState>,
}

impl Narration {
	pub(crate) fn none() -> Narration {
		Narration {
			trace: String::new(),
			steps: Vec::new(),
			table: NameTable::empty(),
			state: None,
		}
	}

	pub(crate) fn term(&self, v: &Value) -> String {
		self.table.compress(v)
	}

	pub(crate) fn installed(&self, c: &Constant) -> Option<Value> {
		let state = self.state.as_ref()?;
		let (value, idx) = state.resolve_constant(c, false);
		idx.map(|_| value)
	}

	pub(crate) fn term_excluding(&self, v: &Value, exclude: &[&str]) -> String {
		self.table.compress_excluding(v, exclude)
	}

	pub(crate) fn kinded(&self) -> Vec<crate::types::TraceStep> {
		self.steps
			.iter()
			.map(|s| crate::types::TraceStep {
				kind: s.kind(),
				text: render_one(s),
			})
			.collect()
	}
}

pub(crate) struct CarriedIn {
	pub value: Value,
	pub via: Vec<(String, Value)>,
	pub origin: Option<String>,
}

fn carried_in(km: &ProtocolTrace, ps: &PrincipalState, ambient: &AttackerState) -> Vec<CarriedIn> {
	ps.values
		.iter()
		.filter(|sv| {
			sv.provenance.attacker_tainted && sv.provenance.sender == crate::principal::ATTACKER_ID
		})
		.map(|sv| {
			let record = ambient
				.knows(&sv.pre_rewrite)
				.and_then(|idx| ambient.record(idx));
			let origin = ambient
				.knows(&sv.pre_rewrite)
				.and_then(|idx| ambient.derivation(idx))
				.and_then(|d| match d {
					DerivationRecord::Obtained { slot } | DerivationRecord::Leaked { slot } => km
						.slots
						.get(slot.get())
						.map(|s| s.constant.name.to_string()),
					_ => None,
				});
			CarriedIn {
				value: sv.pre_rewrite.clone(),
				via: record
					.map(|r| {
						r.diffs
							.iter()
							.filter(|d| d.tainted && !d.value.equivalent(&sv.pre_rewrite, true))
							.map(|d| (d.constant.name.to_string(), d.value.clone()))
							.collect()
					})
					.unwrap_or_default(),
				origin,
			}
		})
		.collect()
}

const NOT_MINIMIZED: &str = "\n            Note: these are the substitutions \
the search recorded; no subset of them was confirmed to reproduce the \
violation on its own, so this trace is not a minimized witness.";

fn not_separated(who: &str, shares: &[String]) -> String {
	format!(
		"\n            Note: this trace reproduces only because sessions of \
		 {who} share {}. Under per-session freshness this witness does not \
		 reproduce; an attack may still exist by another route.",
		join_names(shares)
	)
}

fn join_names(names: &[String]) -> String {
	match names {
		[] => String::new(),
		[one] => one.clone(),
		[rest @ .., last] => format!("{} and {}", rest.join(", "), last),
	}
}

pub(crate) fn narrate_attack(
	km: &ProtocolTrace,
	witness: &Witness,
	target: &Value,
	ambient: &AttackerState,
	prelude: Vec<Step>,
) -> Narration {
	let table = NameTable::from_state(&witness.ps);
	let mut seen: Vec<KnownIdx> = Vec::new();
	let shadowed = shadowed_names(km, &witness.ps);
	let shadowed_refs: Vec<&str> = shadowed.iter().map(|s| &**s).collect();
	let pre_table = table.without(&shadowed_refs);
	let carried = carried_in(km, &witness.ps, ambient);
	let mut steps: Vec<Step> = Vec::new();
	for sv in witness.ps.values.iter().filter(|sv| reportable(sv)) {
		steps.extend(derivation_steps(
			km,
			&witness.attacker,
			&sv.pre_rewrite,
			&pre_table,
			witness.ps.id,
			&carried,
			&mut seen,
		));
	}

	steps.extend(mutation_steps(km, &witness.ps, &table));
	steps.extend(gate_steps(&witness.ps, &table));

	steps.extend(derivation_steps(
		km,
		&witness.attacker,
		target,
		&table,
		witness.ps.id,
		&carried,
		&mut seen,
	));

	let mut steps = {
		let mut all = prelude;
		all.extend(steps);
		all
	};
	steps.dedup_by(|a, b| render_one(a) == render_one(b));
	let mut trace = render(&steps);
	if !witness.reproduced {
		trace.push_str(NOT_MINIMIZED);
	} else if !witness.shares.is_empty() {
		trace.push_str(&not_separated(&witness.ps.name, &witness.shares));
	}
	Narration {
		trace,
		steps,
		table,
		state: Some(witness.ps.clone()),
	}
}

fn render(steps: &[Step]) -> String {
	let mut out = String::new();
	for (i, step) in steps.iter().enumerate() {
		let text = render_one(step);
		out.push_str(&format!("\n            {}. {}", i + 1, text));
	}
	out
}

fn render_one(step: &Step) -> String {
	match step {
		Step::Mutations {
			sender,
			recipient,
			items,
		} => render_mutations(sender, recipient, items),
		Step::Bypass {
			principal,
			slot,
			check,
			key,
			..
		} if !key.is_empty() => format!(
			"{}'s {} does not halt at {}: Attacker holds {}, so it can supply a value \
				 this check accepts.",
			principal, check, slot, key,
		),
		Step::Bypass {
			principal,
			slot,
			check,
			..
		} => format!(
			"{}'s {} does not halt at {}: its inputs are attacker-controlled.",
			principal, check, slot,
		),
		Step::Replay {
			sender,
			recipient,
			name,
			value,
			..
		} => format!(
			"Attacker replays {} ({} to {}) from another session, where it is {}.",
			name, sender, recipient, value,
		),
		Step::Resolves { name, value, .. } => {
			format!("In this state {} resolves to {}.", name, value)
		}
		Step::Static { name, leaves, .. } => format!(
			"Every value {} is built from is fixed: {} is not generated fresh.",
			name, leaves
		),
		Step::Received {
			name,
			sender,
			recipient,
			..
		} => format!("{} received {} from {}.", recipient, name, sender),
		Step::Gate {
			principal,
			primitive,
			..
		} => format!(
			"{}'s {} passes — its inputs are attacker-controlled.",
			principal, primitive,
		),
		Step::Derive { text, .. } => text.clone(),
	}
}

fn render_mutations(sender: &str, recipient: &str, items: &[MutationItem]) -> String {
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

	#[test]
	fn every_narrated_step_carries_its_kind() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private nsk_a\n\
			nsk_ga = PUBKEY(nsk_a)\n\
			generates nsk_m\n\
			]\n\
			Alice -> Bob: nsk_ga\n\
			principal Bob[\n\
			knows private nsk_b\n\
			nsk_gb = PUBKEY(nsk_b)\n\
			nsk_k = DH_KEX(nsk_ga, nsk_b)\n\
			generates nsk_n\n\
			nsk_e = AEAD_ENC(nsk_k, nsk_n, nil)\n\
			]\n\
			Bob -> Alice: nsk_gb, nsk_e\n\
			queries[\n\
			confidentiality? nsk_n\n\
			]\n";
		let m = parse_string("nsk.vp", src).expect("parses");
		let ctx = crate::verify::analyze(&m).expect("analyzes");
		let results = ctx.results_get();
		let attacked = results.iter().find(|r| r.resolved).expect("an attack");

		assert!(!attacked.steps.is_empty(), "an attack must narrate steps");
		assert_eq!(
			attacked.steps.len(),
			attacked.trace.len(),
			"one kind per rendered trace line"
		);
		const KINDS: &[&str] = &[
			"mutations",
			"bypass",
			"replay",
			"resolves",
			"static",
			"received",
			"gate",
			"derive",
		];
		for step in &attacked.steps {
			assert!(KINDS.contains(&step.kind), "unknown kind {:?}", step.kind);
			assert!(!step.text.is_empty(), "a step must render to text");
		}
	}

	fn name_table_state() -> PrincipalState {
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
		let hash_a = make_primitive(PRIM_HASH, vec![make_constant("nt_a")], 0);
		let outer = make_primitive(PRIM_HASH, vec![hash_a, make_constant("nt_x")], 0);
		assert_eq!(table.compress(&outer), "HASH(nt_k, nt_x)");
	}

	#[test]
	fn name_table_respects_output_index() {
		use crate::narrate::NameTable;
		let ps = name_table_state();
		let table = NameTable::from_state(&ps);
		let other_output = make_primitive(PRIM_HASH, vec![make_constant("nt_a")], 1);
		assert_eq!(table.compress(&other_output), "HASH(nt_a)");
	}

	#[test]
	fn name_table_never_names_a_term_after_itself() {
		use crate::narrate::NameTable;
		let ps = name_table_state();
		let table = NameTable::from_state(&ps);
		let hash_a = make_primitive(PRIM_HASH, vec![make_constant("nt_a")], 0);
		assert_eq!(table.compress_excluding(&hash_a, &["nt_k"]), "HASH(nt_a)");
		assert_eq!(table.compress_excluding(&hash_a, &["nt_e"]), "nt_k");
	}

	#[test]
	fn mutation_steps_group_by_message_and_report_old_value() {
		use crate::narrate::{NameTable, Step, mutation_steps};
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private ms_a\n\
			ms_ga = PUBKEY(ms_a)\n\
			]\n\
			Alice -> Bob: ms_ga\n\
			principal Bob[\n\
			knows private ms_b\n\
			ms_s = DH_KEX(ms_ga, ms_b)\n\
			]\n\
			queries[\n\
			confidentiality? ms_s\n\
			]\n";
		let m = parse_string("ms.vp", src).expect("parse");
		let (km, states) = crate::sanity::sanity(&m).expect("sanity");
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
		let attacker_key = crate::primitive::attacker_public_key();
		crate::reexec::install(&mut mutated, slot, attacker_key, true);

		let table = NameTable::from_state(&mutated);
		let steps = mutation_steps(&km, &mutated, &table);
		assert_eq!(steps.len(), 1, "one message mutated, one step");
		match &steps[0] {
			Step::Mutations { items, .. } => {
				assert_eq!(items.len(), 1);
				assert_eq!(&*items[0].name, "ms_ga");
				assert_eq!(items[0].new_value, "PUBKEY(nil)");
				assert_eq!(items[0].old_value, "PUBKEY(ms_a)");
			}
			other => panic!("expected Mutations, got {:?}", other),
		}
	}

	#[test]
	fn mutation_steps_attribute_the_wire_sender_not_the_creator() {
		use crate::narrate::{NameTable, Step, mutation_steps};
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private ws_a\n\
			ws_gx = PUBKEY(ws_a)\n\
			]\n\
			Alice -> Server: ws_gx\n\
			principal Server[\n\
			ws_h = HASH(ws_gx)\n\
			]\n\
			Server -> Bob: ws_gx\n\
			principal Bob[\n\
			knows private ws_b\n\
			ws_s = DH_KEX(ws_gx, ws_b)\n\
			]\n\
			queries[\n\
			confidentiality? ws_s\n\
			]\n";
		let m = parse_string("ws.vp", src).expect("parse");
		let (km, states) = crate::sanity::sanity(&m).expect("sanity");
		let bob = states
			.iter()
			.find(|p| p.name == "Bob")
			.expect("Bob")
			.clone();
		let slot = bob
			.index_of(
				&km.slots
					.iter()
					.find(|s| &*s.constant.name == "ws_gx")
					.expect("slot")
					.constant,
			)
			.expect("index");
		let mut mutated = bob.clone();
		crate::reexec::install(
			&mut mutated,
			slot,
			crate::primitive::attacker_public_key(),
			true,
		);

		let table = NameTable::from_state(&mutated);
		let steps = mutation_steps(&km, &mutated, &table);
		assert_eq!(steps.len(), 1);
		match &steps[0] {
			Step::Mutations { sender, .. } => {
				assert_eq!(
					&**sender, "Server",
					"the substitution happened on the Server -> Bob delivery; \
					 naming the creator instead attributes it to a message that \
					 was never touched"
				);
			}
			other => panic!("expected Mutations, got {:?}", other),
		}
	}

	#[test]
	fn a_bypass_injection_is_narrated_as_a_defeated_check_not_a_wire_replacement() {
		use crate::narrate::{NameTable, Step, mutation_steps, render};
		let k = make_constant("bwn_k");
		let e = make_constant("bwn_e");
		let chk = make_constant("bwn_chk");
		let dec = Primitive {
			id: PRIM_AEAD_DEC,
			arguments: vec![k.clone(), e.clone(), crate::value::value_nil()],
			output: 0,
			instance_check: true,
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		};
		let meta = vec![
			make_slot_meta(k.as_constant().expect("c"), true),
			make_slot_meta(e.as_constant().expect("c"), false),
			make_slot_meta(chk.as_constant().expect("c"), true),
		];
		let mut values = vec![
			make_slot_values(&k, 1),
			make_slot_values(&e, 1),
			make_slot_values(&Value::Primitive(Arc::new(dec)), 1),
		];
		values[2].override_all_bypassed(crate::primitive::attacker_public_key());
		let ps = make_principal_state("Alice", 1, meta, values);

		let table = NameTable::from_state(&ps);
		let steps = mutation_steps(&make_trace(), &ps, &table);
		assert!(
			!steps.iter().any(|s| matches!(s, Step::Mutations { .. })),
			"the injected key never crossed a wire, so it is not a replacement \
			 the attacker performed: {:?}",
			steps
		);
		let text = render(&steps);
		assert!(
			text.contains("does not halt at bwn_chk"),
			"a defeated check must be narrated as such, or the reader cannot \
			 tell why the principal did not halt: {}",
			text
		);
	}

	fn gate_state(second: &str) -> PrincipalState {
		let a = make_constant("gs_a");
		let b = make_constant(second);
		let chk = make_constant("gs_chk");
		let assert_prim = Primitive {
			id: PRIM_ASSERT,
			arguments: vec![a.clone(), b.clone()],
			output: 0,
			instance_check: true,
			capabilities: Capabilities::default(),
			hash: HashCell::default(),
		};
		let meta = vec![
			make_slot_meta(a.as_constant().expect("c"), true),
			make_slot_meta(b.as_constant().expect("c"), true),
			make_slot_meta(chk.as_constant().expect("c"), true),
		];
		let mut tainted = make_slot_values(&a, 0);
		tainted.provenance.attacker_tainted = true;
		let values = vec![
			tainted,
			make_slot_values(&b, 0),
			make_slot_values(&Value::Primitive(Arc::new(assert_prim)), 0),
		];
		make_principal_state("Alice", 0, meta, values)
	}

	#[test]
	fn gate_steps_only_report_checks_that_pass() {
		use crate::narrate::{NameTable, gate_steps};
		let failing = gate_state("gs_b");
		let table = NameTable::from_state(&failing);
		assert!(
			gate_steps(&failing, &table).is_empty(),
			"a check that does not pass must not be narrated as passing"
		);

		let passing = gate_state("gs_a");
		let table = NameTable::from_state(&passing);
		assert_eq!(gate_steps(&passing, &table).len(), 1);
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
		let ctx = VerifyContext::new(&m, &states, Vec::new());
		let mut pure = states[0].clone_for_depth(true);
		pure.resolve_all_values().expect("resolve");
		ctx.attacker_phase_update(&km, &pure, 0).expect("phase");
		crate::verify::verify_standard_run(&ctx, &km, &states).expect("run");

		let attacker = ctx.attacker_snapshot();
		let target = trace_constant(&km, "dw_m");
		let table = NameTable::from_state(&pure);
		let steps = derivation_steps(
			&km,
			&attacker,
			&target,
			&table,
			pure.id,
			&[],
			&mut Vec::new(),
		);

		assert!(!steps.is_empty(), "the attacker learned dw_m somehow");
		let text: Vec<String> = steps
			.iter()
			.map(|s| match s {
				Step::Derive { text, .. } => text.clone(),
				other => panic!("expected Derive, got {:?}", other),
			})
			.collect();
		assert!(
			text.iter().any(|t| t.contains("dw_m")),
			"a step must reach the target: {:?}",
			text
		);
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
		let ps = name_table_state();
		let table = NameTable::from_state(&ps);
		let attacker = make_attacker_state(vec![]);
		let unknown = make_constant("dw_absent");
		let trace = make_trace();
		assert!(
			derivation_steps(&trace, &attacker, &unknown, &table, 0, &[], &mut Vec::new())
				.is_empty()
		);
	}
}
