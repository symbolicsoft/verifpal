/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use crate::narrate::Step;
use crate::types::*;

fn justified_without_a_step(attacker: &AttackerState, value: &Value) -> Option<bool> {
	let idx = attacker.knows(value)?;
	let derivation = attacker.derivation(idx)?;
	Some(matches!(
		derivation,
		DerivationRecord::Initial | DerivationRecord::Injected
	))
}

fn is_justified(
	value: &Value,
	produced: &[&Value],
	installed: &[&Value],
	attacker: &AttackerState,
) -> bool {
	if produced.iter().any(|v| v.equivalent(value, true))
		|| installed.iter().any(|v| v.equivalent(value, true))
		|| justified_without_a_step(attacker, value) == Some(true)
	{
		return true;
	}
	match value {
		Value::Primitive(p) => p
			.arguments
			.iter()
			.all(|a| is_justified(a, produced, installed, attacker)),
		Value::Constant(_) => false,
	}
}

pub(crate) fn derivation_problems(steps: &[Step], attacker: &AttackerState) -> Vec<String> {
	let mut produced: Vec<&Value> = Vec::new();
	let mut installed: Vec<&Value> = Vec::new();
	let mut problems: Vec<String> = Vec::new();

	for step in steps {
		let Step::Derive {
			target,
			ingredients,
			text,
			..
		} = step
		else {
			match step {
				Step::Mutations { items, .. } => {
					for item in items {
						installed.push(&item.installed);
					}
				}
				Step::Replay { installed: v, .. } => installed.push(v),
				_ => {}
			}
			continue;
		};
		for ingredient in ingredients {
			if is_justified(ingredient, &produced, &installed, attacker) {
				continue;
			}
			match justified_without_a_step(attacker, ingredient) {
				Some(true) => continue,
				Some(false) => problems.push(format!(
					"step `{}` consumes {} before any step produces it",
					text.trim(),
					ingredient
				)),
				None => problems.push(format!(
					"step `{}` consumes {}, which the attacker never held",
					text.trim(),
					ingredient
				)),
			}
		}
		produced.push(target);
	}
	problems
}

pub(crate) fn reaches(steps: &[Step], target: &Value) -> bool {
	let direct = steps.iter().any(|step| match step {
		Step::Derive { target: t, .. } => t.equivalent(target, true),
		Step::Mutations { items, .. } => items.iter().any(|i| i.installed.equivalent(target, true)),
		Step::Replay { installed, .. } => installed.equivalent(target, true),
		_ => false,
	});
	if direct {
		return true;
	}
	match target {
		Value::Primitive(p) => {
			!p.arguments.is_empty() && p.arguments.iter().all(|a| reaches(steps, a))
		}
		Value::Constant(_) => false,
	}
}

pub(crate) fn step_problems(
	steps: &[Step],
	km: &ProtocolTrace,
	ps: &PrincipalState,
	attacker: &AttackerState,
	phase: i32,
) -> Vec<String> {
	let mut problems = Vec::new();
	for step in steps {
		if let Step::Resolves {
			name, slot, term, ..
		} = step
		{
			if ps
				.values
				.get(slot.get())
				.is_some_and(|sv| !sv.value.equivalent(term, true))
			{
				problems.push(format!(
					"step `In this state {} resolves to ...` names a resolution the state does \
					 not hold",
					name
				));
			}
			continue;
		}
		if let Step::Static { name, terms, .. } = step {
			let fresh: Vec<String> = terms
				.iter()
				.filter_map(|t| match t {
					Value::Constant(c) if c.fresh => Some(c.name.to_string()),
					_ => None,
				})
				.collect();
			if !fresh.is_empty() {
				problems.push(format!(
					"step `Every value {} is built from is fixed` names {}, which the model does \
					 generate fresh",
					name,
					fresh.join(", ")
				));
			}
			continue;
		}
		if let Step::Received { name, slot, .. } = step {
			if ps
				.values
				.get(slot.get())
				.is_some_and(|sv| sv.provenance.sender == crate::principal::ATTACKER_ID)
			{
				problems.push(format!(
					"step `... received {}` names an honest sender for a value the attacker sent",
					name
				));
			}
			continue;
		}
		if let Step::Gate {
			principal,
			primitive,
			term,
			slot,
		} = step
		{
			match term {
				Value::Primitive(p) if p.instance_check && crate::theory::can_rewrite(p).0 => {
					if **principal != *ps.name {
						problems.push(format!(
							"step `{}` attributes the check to {}, but the state it was drawn \
							 from belongs to {}",
							primitive, principal, ps.name
						));
					}
					if ps
						.values
						.get(slot.get())
						.is_some_and(|sv| sv.provenance.creator != ps.id)
					{
						problems.push(format!(
							"step `{}` reports a check {} did not compute",
							primitive, principal
						));
					}
					if !p
						.arguments
						.iter()
						.any(|a| crate::narrate::value_is_tainted(a, ps))
					{
						problems.push(format!(
							"step `{}` says the check passed on attacker-controlled inputs, but \
							 none of its arguments is attacker-tainted",
							primitive
						));
					}
				}
				_ => problems.push(format!(
					"step `{}` reports a checked primitive that passed, but {} is not a checked \
					 primitive whose rewrite succeeds",
					primitive, primitive
				)),
			}
			continue;
		}
		if let Step::Bypass {
			check,
			key_term: Some(key),
			..
		} = step && !crate::theory::obtainable(key, ps, attacker)
		{
			problems.push(format!(
				"step `{}` says the attacker holds the key that defeats the check, but that key \
				 is not obtainable from what it knows",
				check
			));
		}
		let Step::Derive {
			target,
			text,
			record,
			..
		} = step
		else {
			continue;
		};
		let wrong = |why: &str| format!("step `{}` {}", text.trim(), why);
		match record {
			DerivationRecord::Leaked { slot } => {
				let leaked = km.slots.get(slot.get()).is_some_and(|s| s.constant.leaked);
				if !leaked {
					problems.push(wrong(
						"claims a leaks declaration for a value the model never leaks",
					));
				}
				let reached = ps.leaks.iter().any(|l| {
					km.slots
						.get(slot.get())
						.is_some_and(|s| s.constant.id == l.constant_id)
				});
				if leaked && !reached {
					problems.push(wrong("claims a leaks declaration this run never reached"));
				}
			}
			DerivationRecord::Obtained { slot } => {
				let travelled = km.slots.get(slot.get()).is_some_and(|s| {
					!s.sent_by.is_empty()
						|| s.constant.leaked
						|| s.constant.qualifier == Some(Qualifier::Public)
				});
				let holds = ps
					.values
					.get(slot.get())
					.is_some_and(|sv| sv.value.equivalent(target, true));
				if !travelled && !holds {
					problems.push(wrong(
						"claims a value that neither travelled nor is held at the slot it names",
					));
				}
			}
			DerivationRecord::ConcatFragment { of } => match of {
				Value::Primitive(p) if p.id == crate::primitive::PRIM_CONCAT => {
					if !p.arguments.iter().any(|a| a.equivalent(target, true)) {
						problems.push(wrong(
							"takes a fragment that is not in the CONCAT it splits",
						));
					}
				}
				_ => problems.push(wrong("splits something that is not a CONCAT")),
			},
			DerivationRecord::PasswordExtracted { from } => {
				let mut obtainable = Vec::new();
				crate::theory::find_obtainable_passwords(
					from,
					false,
					true,
					attacker,
					ps,
					&mut obtainable,
				);
				if !obtainable.iter().any(|v| v.equivalent(target, true)) {
					problems.push(wrong(
						"recovers a password the offline-guessing rule does not make obtainable \
						 from the term it names",
					));
				}
			}
			DerivationRecord::Recomposed { of, .. } => match of {
				Value::Primitive(p) => {
					if !crate::theory::can_recompose(p, attacker)
						.is_some_and(|r| r.revealed.equivalent(target, true))
					{
						problems.push(wrong(
							"recomposes a value the shares it names do not rebuild",
						));
					}
				}
				_ => problems.push(wrong("recomposes something that is not a primitive")),
			},
			DerivationRecord::Decomposed { of, .. } => match of {
				Value::Primitive(p) => {
					let yields = crate::theory::can_decompose(p, ps, attacker)
						.is_some_and(|r| r.revealed.equivalent(target, true));
					if !yields {
						problems.push(wrong(
							"opens a term that does not yield what the step claims",
						));
					}
				}
				_ => problems.push(wrong("opens something that is not a primitive")),
			},
			DerivationRecord::Reconstructed { from } => match target {
				Value::Primitive(p) => {
					let swapped = crate::primitive::commutativity_swap(p);
					let accounted = |f: &Value| {
						p.arguments.iter().any(|a| a.equivalent(f, true))
							|| swapped
								.as_ref()
								.is_some_and(|q| q.arguments.iter().any(|a| a.equivalent(f, true)))
					};
					let missing: Vec<String> = from
						.iter()
						.filter(|f| !accounted(f))
						.map(|f| f.to_string())
						.collect();
					if !missing.is_empty() {
						problems.push(wrong(&format!(
							"builds a term out of {}, which are not among its arguments",
							missing.join(", ")
						)));
					}
				}
				_ => problems.push(wrong(
					"reconstructs a constant, which has no parts to build from",
				)),
			},
			DerivationRecord::Broken { of, capability, .. } => match of {
				Value::Primitive(p) => {
					if !ps.capabilities.in_force(p, *capability, phase) {
						problems.push(wrong(
							"invokes a weakening assumption the model does not declare, or does \
							 not declare yet at this phase",
						));
					}
				}
				_ => problems.push(wrong("breaks something that is not a primitive")),
			},
			DerivationRecord::Initial | DerivationRecord::Injected => {}
		}
	}
	problems
}

pub(crate) struct TraceUnderTest<'a> {
	pub file_name: &'a str,
	pub query: &'a Query,
	pub query_index: usize,
	pub steps: &'a [Step],
	pub km: &'a ProtocolTrace,
	pub ps: &'a PrincipalState,
	pub attacker: &'a AttackerState,
	pub target: &'a Value,
	pub phase: i32,
}

pub(crate) fn assert_trace_is_well_founded(t: &TraceUnderTest<'_>) {
	let TraceUnderTest {
		file_name,
		query,
		query_index,
		steps,
		km,
		ps,
		attacker,
		target,
		phase,
	} = *t;
	let mut problems = derivation_problems(steps, attacker);
	problems.extend(step_problems(steps, km, ps, attacker, phase));
	assert!(
		problems.is_empty(),
		"TRACE • {} query {} ({}) prints a derivation that does not stand up. A reader \
		 following it top to bottom reaches a step whose inputs no earlier step supplies, so \
		 the trace is not a derivation of the violation it claims:\n  {}\n",
		file_name,
		query_index,
		query,
		problems.join("\n  ")
	);
	if query.kind == QueryKind::Confidentiality {
		assert!(
			steps.is_empty() || reaches(steps, target),
			"TRACE • {} query {} ({}) prints {} step(s), none of which produces {} — the value \
			 the attacker is claimed to have learned. A trace that never reaches its own target \
			 explains something else.\n",
			file_name,
			query_index,
			query,
			steps.len(),
			target
		);
	}
	if query.kind == QueryKind::Authentication && !steps.is_empty() {
		assert!(
			steps.iter().any(|s| matches!(
				s,
				Step::Mutations { .. }
					| Step::Replay { .. }
					| Step::Bypass { .. }
					| Step::Gate { .. }
					| Step::Received { .. }
			)),
			"TRACE • {} query {} ({}) reports that the recipient accepted a value the declared \
			 sender did not author, but prints {} step(s) that are all derivations: nothing in \
			 the trace shows the attacker acting on the wire or names who did send it.\n",
			file_name,
			query_index,
			query,
			steps.len()
		);
	}
}

pub(crate) fn assert_holds_were_searched(
	ctx: &crate::context::VerifyContext,
	attacker: AttackerKind,
	file_name: &str,
) {
	if attacker != AttackerKind::Active || !ctx.search_reached_a_controllable_slot() {
		return;
	}
	for result in ctx.results_get() {
		if result.resolved || result.query.kind == QueryKind::Freshness {
			continue;
		}
		assert!(
			ctx.goals_for(result.query_index) > 0,
			"HOLD • {} query {} ({}) is reported as holding, but the solver never once aimed \
			 at it, though the model does offer the attacker a slot it controls. A hold nothing \
			 was ever aimed at is an untested claim, not a result.\n",
			file_name,
			result.query_index,
			result.query
		);
	}
}

pub(crate) fn assert_holds_survive_final_knowledge(
	ctx: &crate::context::VerifyContext,
	km: &ProtocolTrace,
	file_name: &str,
) {
	let _guard = crate::witness::minimization_guard();
	let _quiet = crate::info::InfoQuiet::new();
	for result in ctx.results_get() {
		if result.resolved {
			continue;
		}
		for state in ctx.principal_states() {
			let scratch = ctx.scratch_for_query(result.query_index);
			let ambient = scratch.attacker_snapshot();
			let Ok(honest) = crate::verify::generate_trace(&scratch, km, state, &ambient) else {
				continue;
			};
			let _ = crate::deduction::compute_knowledge_closure(&scratch, km, &honest);
			let _ =
				crate::query::query_start(&scratch, &result.query, result.query_index, km, &honest);
			assert!(
				!scratch.query_is_resolved(result.query_index),
				"HOLD • {} query {} ({}) is reported as holding, but re-evaluating it against \
				 {}'s state with everything the attacker knew by the end of the run resolves \
				 it. The verdict was reached before the knowledge that defeats it existed, so \
				 the report is stale rather than true.\n",
				file_name,
				result.query_index,
				result.query,
				honest.name
			);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::narrate::MutationItem;
	use crate::testutil::*;
	use std::sync::Arc;

	fn hashed(v: &Value) -> Value {
		make_primitive(crate::primitive::PRIM_HASH, vec![v.clone()], 0)
	}

	fn derive(target: Value, ingredients: Vec<Value>) -> Step {
		Step::Derive {
			text: format!("Attacker constructs {}", target),
			target,
			ingredients,
			record: DerivationRecord::Initial,
		}
	}

	#[test]
	fn a_step_may_consume_what_an_earlier_step_produced() {
		let a = make_constant("tc_a");
		let b = hashed(&a);
		let steps = vec![derive(a.clone(), vec![]), derive(b, vec![a.clone()])];
		let attacker = make_attacker_state(vec![a]);
		assert!(derivation_problems(&steps, &attacker).is_empty());
	}

	#[test]
	fn a_step_may_not_consume_what_nothing_supplies() {
		let a = make_constant("tc_b");
		let b = make_constant("tc_c");
		let out = hashed(&b);
		let steps = vec![derive(out, vec![b])];
		let attacker = make_attacker_state(vec![a]);
		let problems = derivation_problems(&steps, &attacker);
		assert_eq!(problems.len(), 1, "{:?}", problems);
		assert!(problems[0].contains("never held"), "{:?}", problems);
	}

	#[test]
	fn an_installed_value_supplies_the_steps_that_use_it() {
		let injected = make_constant("tc_d");
		let out = hashed(&injected);
		let steps = vec![
			Step::Mutations {
				sender: Arc::from("Attacker"),
				recipient: Arc::from("Bob"),
				items: vec![MutationItem {
					name: Arc::from("tc_d"),
					new_value: "tc_d".to_string(),
					old_value: "honest".to_string(),
					guarded: false,
					installed: injected,
				}],
			},
			derive(out.clone(), vec![make_constant("tc_d")]),
		];
		let attacker = make_attacker_state(vec![]);
		assert!(derivation_problems(&steps, &attacker).is_empty());
		assert!(reaches(&steps, &out));
	}
}
