/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::principal::*;
use crate::sanity::{
	sanity_assignment_constants, sanity_message_principals, sanity_primitive, unknown_constant,
};
use crate::types::*;
use crate::util::*;
use crate::value::*;
use std::sync::Arc;

fn declared_as(c: &Constant) -> String {
	match (c.declaration, c.qualifier) {
		(Some(Declaration::Generates), _) => "generated".to_string(),
		(Some(Declaration::Assignment), _) => "assigned".to_string(),
		(Some(Declaration::Leaks), _) => "leaked".to_string(),
		(Some(Declaration::Knows), Some(Qualifier::Public)) => "known publicly".to_string(),
		(Some(Declaration::Knows), Some(Qualifier::Private)) => "known privately".to_string(),
		_ => "declared".to_string(),
	}
}

fn holders_of(trace: &ProtocolTrace, idx: usize) -> String {
	let slot = &trace.slots[idx];
	let mut names: Vec<String> = vec![base_name(trace.principal_name(slot.creator)).to_string()];
	for &(recipient, _) in &slot.known_by {
		let name = base_name(trace.principal_name(recipient)).to_string();
		if !names.contains(&name) {
			names.push(name);
		}
	}
	quoted_list(&names)
}

pub(crate) fn builtin_nil_error(c: &Constant, verb: &str) -> Option<VerifpalError> {
	if !c.is_nil() {
		return None;
	}
	Some(
		VerifpalError::sanity(format!("`nil` is built in and cannot be {verb}").into())
			.narrow(c.name.to_string())
			.labelled("`nil` already names the empty value")
			.note(
				"every model carries `nil`, the value a primitive takes where the protocol \
				 has nothing to put; it is public and known to every principal from the \
				 start, so a declaration of it could only contradict that",
			)
			.help("pick a different name"),
	)
}

pub(crate) fn construct_protocol_trace(
	m: &Model,
	principals: &[String],
	principal_ids: &[PrincipalId],
) -> VResult<ProtocolTrace> {
	let mut trace = ProtocolTrace {
		principals: principals.to_vec(),
		principal_ids: principal_ids.to_vec(),
		..ProtocolTrace::default()
	};
	let declared = model_declarations(m);
	let mut declared_at = 0i32;
	let mut current_phase = 0i32;

	if let Value::Constant(nil) = value_nil() {
		let known_by: Vec<_> = principal_ids.iter().map(|&pid| (pid, pid)).collect();
		trace_declare(
			&mut trace,
			TraceSlot {
				declared_span: Span::default(),
				initial_value: Value::Constant(nil.clone()),
				constant: nil,
				creator: ATTACKER_ID,
				known_by,
				sent_by: vec![],
				declared_at,
				phases: vec![current_phase],
				mutatable_to: vec![],
				delivery_phase: None,
			},
		);
	}

	for block in &m.blocks {
		match block {
			Block::Principal(principal) => {
				declared_at = construct_trace_render_principal(
					&mut trace,
					&declared,
					principal,
					declared_at,
					current_phase,
				)?;
			}
			Block::Message(message) => {
				declared_at += 1;
				construct_trace_render_message(
					&mut trace,
					&declared,
					message,
					current_phase,
					declared_at,
				)
				.map_err(|e| e.or_span(message.span))?;
			}
			Block::Phase(phase) => {
				current_phase = phase.number;
			}
		}
	}
	trace.max_phase = current_phase;
	trace.used_by = construct_trace_used_by(&trace);
	for slot in &mut trace.slots {
		for event in &slot.sent_by {
			if !event.guarded || slot.mutatable_to.contains(&event.sender) {
				append_unique(&mut slot.mutatable_to, event.recipient);
			}
		}
		slot.delivery_phase = slot
			.mutatable_to
			.iter()
			.filter_map(|&who| slot.substitution_phase(who))
			.min();
	}
	trace.capabilities = construct_capability_index(&trace);
	Ok(trace)
}

fn construct_capability_index(trace: &ProtocolTrace) -> CapabilityIndex {
	let mut index = CapabilityIndex::default();
	for slot in &trace.slots {
		for term in crate::value::subterms(&slot.initial_value) {
			if !matches!(term, Value::Primitive(p) if !p.capabilities.is_empty()) {
				continue;
			}
			index.insert(term);
			index.insert(&crate::resolution::resolve_trace_term(term, trace));
		}
	}
	index
}

type MentionMemo = IdMap<ValueId, Arc<IdSet<ValueId>>>;

fn construct_trace_used_by(trace: &ProtocolTrace) -> IdMap<ValueId, IdSet<PrincipalId>> {
	let mut memo: MentionMemo = IdMap::default();
	let mut used_by: IdMap<ValueId, IdSet<PrincipalId>> = IdMap::default();
	for slot in &trace.slots {
		if !matches!(&slot.initial_value, Value::Primitive(_)) {
			continue;
		}
		let mut mentioned = IdSet::default();
		collect_mentions(&slot.initial_value, trace, &mut memo, &mut mentioned);
		for id in mentioned {
			used_by.entry(id).or_default().insert(slot.creator);
		}
	}
	used_by
}

fn collect_mentions(
	value: &Value,
	trace: &ProtocolTrace,
	memo: &mut MentionMemo,
	out: &mut IdSet<ValueId>,
) {
	match value {
		Value::Constant(c) => out.extend(mentions_of_constant(c, trace, memo).iter().copied()),
		Value::Primitive(p) => {
			for argument in &p.arguments {
				collect_mentions(argument, trace, memo, out);
			}
		}
	}
}

fn mentions_of_constant(
	c: &Constant,
	trace: &ProtocolTrace,
	memo: &mut MentionMemo,
) -> Arc<IdSet<ValueId>> {
	if let Some(hit) = memo.get(&c.id) {
		return Arc::clone(hit);
	}
	let mut out: IdSet<ValueId> = IdSet::default();
	out.insert(c.id);
	memo.insert(c.id, Arc::new(out.clone()));
	if let Some(idx) = trace.index_of(c) {
		match &trace.slots[idx].initial_value {
			Value::Constant(resolved) => {
				out.insert(resolved.id);
			}
			assigned @ Value::Primitive(_) => collect_mentions(assigned, trace, memo, &mut out),
		}
	}
	let out = Arc::new(out);
	memo.insert(c.id, Arc::clone(&out));
	out
}

fn construct_trace_render_principal(
	trace: &mut ProtocolTrace,
	declared: &Declarations,
	principal: &Principal,
	mut declared_at: i32,
	current_phase: i32,
) -> VResult<i32> {
	for expr in &principal.expressions {
		let located = |e: VerifpalError| e.or_span(expr.span);
		match expr.kind {
			Declaration::Knows => {
				construct_trace_render_knows(trace, principal, declared_at, expr)
					.map_err(located)?;
			}
			Declaration::Generates => {
				construct_trace_render_generates(trace, principal, declared_at, expr)
					.map_err(located)?;
			}
			Declaration::Assignment => {
				construct_trace_render_assignment(trace, declared, principal, declared_at, expr)
					.map_err(located)?;
			}
			Declaration::Leaks => {
				declared_at += 1;
				construct_trace_render_leaks(
					trace,
					declared,
					principal,
					expr,
					current_phase,
					declared_at,
				)
				.map_err(located)?;
			}
		}
	}
	Ok(declared_at)
}

fn construct_trace_render_knows(
	trace: &mut ProtocolTrace,
	principal: &Principal,
	declared_at: i32,
	expr: &Expression,
) -> VResult<()> {
	for c in &expr.constants {
		if let Some(idx) = trace.index_of(c) {
			let existing = &trace.slots[idx].constant;
			if existing.declaration != Some(Declaration::Knows)
				|| existing.qualifier != expr.qualifier
				|| existing.fresh
			{
				if let Some(e) = builtin_nil_error(c, "declared") {
					return Err(e);
				}
				let was = declared_as(existing);
				let now = declared_as(&declared_constant(c, Declaration::Knows, expr.qualifier));
				return Err(VerifpalError::sanity(
					format!("`{}` is introduced in two different ways", c).into(),
				)
				.narrow(c.name.to_string())
				.labelled(format!("here it is {}", now))
				.label(
					trace.slots[idx].declared_span,
					format!("but here it is {}", was),
				)
				.note(
					"every principal that knows a constant has to agree on where it \
					 came from, because that is what decides whether the attacker \
					 knows it too",
				)
				.help("use the same declaration in both places"));
			}
			if trace.slots[idx]
				.known_by
				.iter()
				.any(|&(holder, sender)| holder == principal.id && sender != principal.id)
			{
				return Err(VerifpalError::sanity(
					format!("{} already knows `{}`", principal.name, c).into(),
				)
				.narrow(c.name.to_string())
				.labelled(format!(
					"{} received it before this declaration",
					principal.name
				))
				.label(
					trace.slots[idx].declared_span,
					format!("`{}` is first declared here", c),
				)
				.note(
					"a principal holds a constant one way: a value it was sent cannot also be \
					 something it knew from the start",
				)
				.help("remove the declaration, or the message that delivers it"));
			}
			trace.slots[idx].known_by.push((principal.id, principal.id));
			continue;
		}
		let constant = declared_constant(c, Declaration::Knows, expr.qualifier);
		let slot_idx = declare_by(
			trace,
			principal,
			expr,
			declared_at,
			Value::Constant(constant.clone()),
			constant,
		);
		if expr.qualifier != Some(Qualifier::Public) {
			continue;
		}
		for &pid in &trace.principal_ids {
			if pid != principal.id {
				trace.slots[slot_idx].known_by.push((pid, pid));
			}
		}
	}
	Ok(())
}

fn trace_declare(trace: &mut ProtocolTrace, slot: TraceSlot) -> usize {
	trace.index.insert(slot.constant.id, trace.slots.len());
	trace.slots.push(slot);
	trace.slots.len() - 1
}

fn declare_by(
	trace: &mut ProtocolTrace,
	principal: &Principal,
	expr: &Expression,
	declared_at: i32,
	initial_value: Value,
	constant: Constant,
) -> usize {
	trace_declare(
		trace,
		TraceSlot {
			declared_span: expr.span,
			constant,
			initial_value,
			creator: principal.id,
			known_by: vec![],
			sent_by: vec![],
			declared_at,
			phases: vec![],
			mutatable_to: vec![],
			delivery_phase: None,
		},
	)
}

fn declared_constant(
	c: &Constant,
	declaration: Declaration,
	qualifier: Option<Qualifier>,
) -> Constant {
	Constant {
		fresh: declaration == Declaration::Generates,
		leaked: false,
		declaration: Some(declaration),
		qualifier,
		..c.clone()
	}
}

type Declarations = IdMap<ValueId, (String, Span)>;

fn model_declarations(m: &Model) -> Declarations {
	let mut out: Declarations = IdMap::default();
	for block in &m.blocks {
		let Block::Principal(p) = block else {
			continue;
		};
		for expr in &p.expressions {
			if matches!(expr.kind, Declaration::Leaks) {
				continue;
			}
			for c in &expr.constants {
				out.entry(c.id)
					.or_insert((base_name(&p.name).to_string(), expr.span));
			}
		}
	}
	out
}

fn trace_slot_of(trace: &ProtocolTrace, declared: &Declarations, c: &Constant) -> VResult<usize> {
	if let Some(idx) = trace.index_of(c) {
		return Ok(idx);
	}
	if let Some((principal, span)) = declared.get(&c.id) {
		return Err(VerifpalError::sanity(
			format!("`{}` is used before it is declared", c.name).into(),
		)
		.narrow(c.name.to_string())
		.labelled("used here")
		.label(*span, format!("{principal} declares it further down"))
		.note(
			"a model reads top to bottom, so a block can only name values that \
			 already exist where it appears",
		)
		.help(format!(
			"move {principal}'s block above this one, and have {principal} send \
			 `{}` before it is used",
			c.name
		)));
	}
	Err(unknown_constant(c, trace))
}

fn construct_trace_render_generates(
	trace: &mut ProtocolTrace,
	principal: &Principal,
	declared_at: i32,
	expr: &Expression,
) -> VResult<()> {
	for c in &expr.constants {
		if let Some(idx) = trace.index_of(c) {
			if let Some(e) = builtin_nil_error(c, "generated") {
				return Err(e);
			}
			return Err(
				VerifpalError::sanity(format!("`{}` already exists", c).into())
					.narrow(c.name.to_string())
					.labelled("generated again here")
					.label(
						trace.slots[idx].declared_span,
						format!("already {} here", declared_as(&trace.slots[idx].constant)),
					)
					.note(
						"`generates` introduces a value that exists nowhere else, so its name must be new",
					)
					.help("pick a name no principal has used yet"),
			);
		}
		let constant = declared_constant(c, Declaration::Generates, Some(Qualifier::Private));
		declare_by(
			trace,
			principal,
			expr,
			declared_at,
			Value::Constant(constant.clone()),
			constant,
		);
	}
	Ok(())
}

fn construct_trace_render_assignment(
	trace: &mut ProtocolTrace,
	declared: &Declarations,
	principal: &Principal,
	declared_at: i32,
	expr: &Expression,
) -> VResult<()> {
	let assigned = expr.assigned.as_ref().ok_or_else(|| {
		VerifpalError::sanity("assignment has nothing on the right of the `=`".into())
			.help("write the value being computed, e.g. `x = HASH(m)`")
	})?;
	let constants = sanity_assignment_constants(assigned, &[])?;
	if let Value::Primitive(p) = assigned {
		sanity_primitive(p, &expr.constants)?;
	}
	for c in &constants {
		let idx = trace_slot_of(trace, declared, c)?;
		let knows = trace.slots[idx].known_by_principal(principal.id);
		if !knows {
			return Err(VerifpalError::sanity(
				format!("{} does not know `{}`", principal.name, c).into(),
			)
			.narrow(c.name.to_string())
			.labelled(format!("{} cannot compute with this value", principal.name))
			.label(
				trace.slots[idx].declared_span,
				format!("`{}` is held only by {}", c, holders_of(trace, idx)),
			)
			.note(
				"a principal can use a value only if it declares, generates, \
				 computes or receives it",
			)
			.help(format!(
				"send it first, e.g. `{} -> {}: {}`",
				base_name(trace.principal_name(trace.slots[idx].creator)),
				principal.name,
				c
			)));
		}
	}
	for (output_idx, c) in expr.constants.iter().enumerate() {
		if let Some(idx) = trace.index_of(c) {
			if let Some(e) = builtin_nil_error(c, "assigned") {
				return Err(e);
			}
			return Err(
				VerifpalError::sanity(format!("`{}` is assigned twice", c).into())
					.narrow(c.name.to_string())
					.labelled("assigned again here")
					.label(
						trace.slots[idx].declared_span,
						format!("already {} here", declared_as(&trace.slots[idx].constant)),
					)
					.note(
						"a constant names one value for the whole model, so it can never \
				 be rebound; this is what lets a query name a value without saying \
				 when it means",
					)
					.help("give this one a different name"),
			);
		}
		let mut initial_value = assigned.clone();
		if let Value::Primitive(ref mut p) = initial_value {
			let mutable = Arc::make_mut(p);
			mutable.output = output_idx;
			if crate::primitive::primitive_get(mutable.id)
				.is_ok_and(|spec| spec.distinct_per_assignment)
				&& let Some(first) = expr.constants.first()
			{
				mutable.instance = crate::value::copy_index_of(first.id).1;
			}
			mutable.hash.clear();
		}
		declare_by(
			trace,
			principal,
			expr,
			declared_at,
			initial_value,
			declared_constant(c, Declaration::Assignment, Some(Qualifier::Private)),
		);
	}
	Ok(())
}

fn construct_trace_render_leaks(
	trace: &mut ProtocolTrace,
	declared: &Declarations,
	principal: &Principal,
	expr: &Expression,
	current_phase: i32,
	declared_at: i32,
) -> VResult<()> {
	for c in &expr.constants {
		let idx = trace_slot_of(trace, declared, c)?;
		let known = trace.slots[idx].known_by_principal(principal.id);
		if !known {
			return Err(VerifpalError::sanity(
				format!(
					"{} does not know `{}`, so cannot leak it",
					principal.name, c
				)
				.into(),
			)
			.narrow(c.name.to_string())
			.label(
				trace.slots[idx].declared_span,
				format!("`{}` is held only by {}", c, holders_of(trace, idx)),
			)
			.note("`leaks` hands the attacker a value the principal already holds")
			.help(format!(
				"leak it from {} instead",
				base_name(trace.principal_name(trace.slots[idx].creator))
			)));
		}
		trace.slots[idx].constant.leaked = true;
		append_unique(&mut trace.slots[idx].phases, current_phase);
		trace.leaks.push(LeakEvent {
			constant_id: c.id,
			principal_id: principal.id,
			declared_at,
		});
	}
	Ok(())
}

fn construct_trace_render_message(
	trace: &mut ProtocolTrace,
	declared: &Declarations,
	message: &Message,
	current_phase: i32,
	declared_at: i32,
) -> VResult<()> {
	sanity_message_principals(message)?;
	for c in &message.constants {
		let idx = trace_slot_of(trace, declared, c)?;
		let sender_knows = trace.slots[idx].known_by_principal(message.sender);
		let recipient_knows = trace.slots[idx].known_by_principal(message.recipient);
		if !sender_knows {
			return Err(VerifpalError::sanity(
				format!("{} does not know `{}`", message.sender_name, c).into(),
			)
			.narrow(c.name.to_string())
			.labelled(format!("{} has nothing to send here", message.sender_name))
			.label(
				trace.slots[idx].declared_span,
				format!("`{}` is held only by {}", c, holders_of(trace, idx)),
			)
			.note("a principal can only send a value it declares, generates, computes or receives")
			.help(format!(
				"have {} send it, or give {} a way to obtain it first",
				base_name(trace.principal_name(trace.slots[idx].creator)),
				message.sender_name
			)));
		}
		if recipient_knows {
			if let Some(e) = builtin_nil_error(c, "sent") {
				return Err(e);
			}
			return Err(VerifpalError::sanity(
				format!("{} already knows `{}`", message.recipient_name, c).into(),
			)
			.narrow(c.name.to_string())
			.labelled("nothing new arrives here")
			.label(
				trace.slots[idx].declared_span,
				format!("{} already holds `{}` from here", message.recipient_name, c),
			)
			.note(
				"a constant names one value for the whole model, so re-sending it \
				 tells the recipient nothing it did not already have; sending a \
				 second, different value means giving it its own name",
			)
			.help("drop this constant from the message, or send a differently named value"));
		}
		trace.slots[idx]
			.known_by
			.push((message.recipient, message.sender));
		trace.slots[idx].sent_by.push(SendEvent {
			sender: message.sender,
			recipient: message.recipient,
			declared_at,
			phase: current_phase,
			guarded: c.guard,
		});
		append_unique(&mut trace.slots[idx].phases, current_phase);
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use crate::types::*;

	const SRC: &str = "attacker[active]\n\
		principal Alice[\n\
		knows public cst_ctx\n\
		knows private cst_a\n\
		cst_ga = PUBKEY(cst_a)\n\
		generates cst_n\n\
		]\n\
		Alice -> Bob: cst_ga, [cst_n]\n\
		principal Bob[\n\
		knows private cst_b\n\
		cst_k = DH_KEX(cst_ga, cst_b)\n\
		_ = HASH(cst_k, cst_n, cst_ctx)\n\
		]\n\
		queries[\n\
		confidentiality? cst_a\n\
		]\n";

	fn fixture() -> ProtocolTrace {
		let m = crate::parser::parse_string("cst.vp", SRC).expect("parses");
		crate::sanity::sanity(&m).expect("passes sanity")
	}

	#[test]
	fn capability_collection_leaves_unannotated_transcripts_unexpanded() {
		let mut source = String::from(
			"attacker[passive]\nprincipal Alice[\nknows private secret\nknows public h0\n",
		);
		for i in 1..=1000 {
			source.push_str(&format!("h{i} = HASH(h{}, h{})\n", i - 1, i - 1));
		}
		source.push_str("]\nqueries[confidentiality? secret]\n");
		let model = crate::parser::parse_string("capability-transcript.vp", &source).unwrap();
		let trace = crate::sanity::sanity(&model).unwrap();
		assert!(trace.capabilities.is_empty());
	}

	fn slot(km: &ProtocolTrace, name: &str) -> usize {
		km.slots
			.iter()
			.position(|s| &*s.constant.name == name)
			.unwrap_or_else(|| panic!("no slot named {name}"))
	}

	#[test]
	fn every_trace_opens_with_the_built_in_nil_every_principal_holds() {
		let km = fixture();
		let nil = &km.slots[0];
		assert!(nil.constant.is_nil());
		assert_eq!(nil.constant.qualifier, Some(Qualifier::Public));
		for &pid in &km.principal_ids {
			assert!(
				nil.known_by_principal(pid),
				"nil is the value a primitive takes where there is nothing to put, so \
				 every principal has to hold it without declaring it"
			);
		}
	}

	#[test]
	fn a_public_constant_is_known_to_every_principal_from_its_declaration() {
		let km = fixture();
		let ctx = &km.slots[slot(&km, "cst_ctx")];
		for &pid in &km.principal_ids {
			assert!(ctx.known_by_principal(pid));
		}
		let private = &km.slots[slot(&km, "cst_a")];
		assert!(private.known_by_principal(private.creator));
		assert_eq!(
			private.known_by.len(),
			0,
			"a private constant reaches nobody until it is sent"
		);
	}

	#[test]
	fn only_an_unguarded_delivery_makes_a_slot_mutatable_to_its_recipient() {
		let km = fixture();
		let bob = km.principal_ids[km.principals.iter().position(|p| p == "Bob").expect("Bob")];
		let ga = &km.slots[slot(&km, "cst_ga")];
		assert!(ga.sent_by.iter().any(|event| event.recipient == bob));
		assert!(
			ga.mutation_reaches(bob),
			"cst_ga travels unguarded, so the attacker can replace it on the way"
		);
		let n = &km.slots[slot(&km, "cst_n")];
		assert!(n.guarded_for(bob), "cst_n is written in guard brackets");
		assert!(
			!n.mutation_reaches(bob),
			"a guarded delivery is not a substitution the attacker may make"
		);
	}
}
