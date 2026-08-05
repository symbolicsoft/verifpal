/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Goal-directed active attacker search
//!
//! Verifpal's active attacker.  The question it answers is "what would the
//! attacker need in order to learn this, and can it arrange that" — solved
//! backwards from each query, rather than forwards by trying substitutions and
//! seeing what falls out.
//!
//! The distinction decides what is findable.  Enumerating forwards means
//! enumerating combinations of wire substitutions, and the number of those
//! grows so fast that a search has to be bounded by depth and per-principal
//! budgets.  Those bounds then decide, unpredictably, which attacks the tool
//! can reach: Signal's X3DH man-in-the-middle needs three public keys replaced
//! at once, and no affordable budget reliably reaches it.
//!
//! Solving backwards has no such cliff.  An attack requiring four simultaneous
//! wire substitutions is not found by considering four-element subsets; it is
//! the union of four bindings, each forced independently by a deducibility
//! requirement.  Nothing enumerates, so nothing needs a budget, and there is no
//! depth at which the engine stops looking.
//!
//! Termination comes from the search space instead of from a cap on it:
//! goals are memoised, a goal that reaches itself is cut as a cycle, and the
//! rules that could invent unboundedly many new terms are restricted to a
//! finite basis drawn from the protocol.
//!
//! ## Shape of a run
//!
//! ```text
//! for each phase
//!   seed attacker knowledge, run the passive baseline
//!   repeat until knowledge stops growing
//!     for each principal
//!       build the symbolic view          symbolic.rs
//!       for each unresolved query
//!         turn it into a goal            this module, `goals_for_query`
//!         solve the goal                 deduce.rs / diverge.rs
//!       validate every proposal          validate.rs
//! ```
//!
//! The outer repeat exists because validation grows attacker knowledge, which
//! can unlock goals that were previously unreachable.  It terminates on a
//! knowledge fixed point, the same monotone argument
//! [`crate::deduction::compute_knowledge_closure`] relies on.
//!
//! ## Soundness
//!
//! No module in this directory can record a query result.  Every proposal goes
//! through `validate.rs`, which materialises it, re-executes the principal
//! through the ordinary pipeline, and re-checks the query against real attacker
//! knowledge.  A bug in the solver costs a missed attack, never a false one.

pub mod deduce;
pub mod diverge;
pub mod matching;
pub mod symbolic;
pub mod validate;
pub mod vars;

use std::collections::HashSet;

use crate::context::VerifyContext;
use crate::hashing::collect_subterm_hashes;
use crate::info::info_message;
use crate::types::*;
use crate::value::{push_unique_value, resolve_trace_values};
use crate::verify::verify_standard_run;

use deduce::Deducer;
use symbolic::SymbolicState;
use vars::{Substitution, dedupe};

/// Run the active attacker against every phase of the model.
pub fn verify_active(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	principal_states: &[PrincipalState],
) -> VResult<()> {
	info_message("Attacker is configured as active.", InfoLevel::Info, false);

	for phase in 0..=km.max_phase {
		info_message(
			&format!("Running at phase {phase}."),
			InfoLevel::Info,
			false,
		);
		ctx.attacker_init();
		let mut ps_pure_resolved = principal_states[0].clone_for_depth(true);
		ps_pure_resolved.resolve_all_values(&ctx.attacker_snapshot())?;
		ctx.attacker_phase_update(km, &ps_pure_resolved, phase)?;

		// Passive baseline: everything derivable without touching the wire.
		verify_standard_run(ctx, km, principal_states)?;

		// Goal-directed rounds, to a knowledge fixed point.
		loop {
			if ctx.all_resolved() {
				break;
			}
			let before = ctx.attacker_known_count();

			// Targeted proposals for every principal come first.  An attack is
			// often explained by one principal's computation while another
			// principal happens to offer a large pile of constructible values;
			// interleaving the two per-principal would let that pile delay, or
			// in a big model effectively prevent, ever looking at the principal
			// that matters.
			for ps in principal_states {
				solve_principal(ctx, km, ps, Pass::Targeted)?;
				if ctx.all_resolved() {
					break;
				}
			}
			if !ctx.all_resolved() {
				for ps in principal_states {
					solve_principal(ctx, km, ps, Pass::Constructed)?;
					if ctx.all_resolved() {
						break;
					}
				}
			}

			if ctx.attacker_known_count() == before {
				break;
			}
		}
	}
	Ok(())
}

/// Which family of proposals to try.
///
/// Splitting the two is about ordering across principals, not about limiting
/// what gets tried: both passes run before the engine gives up.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
	/// Derived from a query goal or a checked primitive — few and precise.
	Targeted,
	/// Assembled or replayed values for a controlled slot — broad and costly.
	Constructed,
}

/// Propose and validate substitutions against one principal.
fn solve_principal(
	ctx: &VerifyContext,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	pass: Pass,
) -> VResult<()> {
	let attacker = ctx.attacker_snapshot();
	let sym = symbolic::build(km, ps, &attacker);
	if sym.var_slots.is_empty() {
		return Ok(());
	}

	let deducer = Deducer::new(ps, &attacker, &sym);
	let empty = Substitution::new();
	let mut proposals: Vec<Substitution> = Vec::new();

	for result in ctx.results_get() {
		if result.resolved || pass != Pass::Targeted {
			continue;
		}
		proposals.extend(goals_for_query(
			&result.query,
			km,
			ps,
			&sym,
			&deducer,
			&empty,
		));
	}

	// Satisfying the model's checked primitives is worth proposing regardless of
	// what any query asks.  A check the attacker can satisfy is a check that
	// does not halt the principal, which is what keeps the rest of the
	// computation — and therefore the rest of the attack — reachable.
	if pass == Pass::Targeted {
		proposals.extend(deducer.constraint_goals(&sym, &empty));
	}

	// The canonical man-in-the-middle: every wire value the attacker controls
	// becomes its own.  This is not a search — it is a single substitution, so
	// it costs exactly one validation — but it is the shape most protocol
	// attacks take, and offering it unconditionally means the engine never
	// depends on the goal analysis being complete to find it.  It restores by
	// construction what the deleted `verify_active_equation_bypass` pass did by
	// hand.
	let blanket = blanket_substitution(&sym);
	if pass == Pass::Targeted && !blanket.is_empty() {
		proposals.push(blanket.clone());

		// Tampering with exactly one message, leaving the rest of the run
		// untouched.  The blanket changes everything at once, which is the wrong
		// move whenever some *other* message is covered by a check the attacker
		// cannot satisfy: replacing it too halts the principal before it reaches
		// the message that mattered.  A recipient that consumes a value without
		// checking it — decrypting without a `?` — accepts anything, and then
		// the minimal action is the whole attack.
		//
		// One proposal per controlled slot, so this is linear in the model.
		for &slot in &sym.var_slots {
			if let Some(term) = &sym.var_terms[slot] {
				let mut single = Substitution::new();
				vars::ground_remaining(term, &mut single);
				if !single.is_empty() {
					proposals.push(single);
				}
			}
		}
	}

	// Some slots are broken not by a derived value but by a *built* one: the
	// attacker assembles a primitive of the right shape out of what it holds, or
	// replays one it already has, and posts it.  Goal analysis says which slots
	// matter and why; for what to put in one, reuse the existing injection
	// engine.
	//
	// These come last, and deliberately so.  They are the broadest and the most
	// expensive proposals, while the goal-derived ones above are few and
	// precise.  Ordering them behind the targeted proposals means a model whose
	// attack the goal analysis can explain never pays for them, because the loop
	// stops as soon as every query is resolved.
	//
	// The set stays linear in slots.  A combinatorial blow-up would come from
	// taking products *across* slots; here each slot is offered its candidates
	// independently, paired only with the single blanket substitution.
	// Every controlled slot bound to the value it actually carried.  Forwarding
	// a message unchanged is still the attacker forwarding it, and a recipient
	// cannot tell the difference — so when one message in a run is genuinely
	// tampered with, the others in that run are attacker-relayed too, and the
	// recipient accepting them is an authentication failure for them as well.
	let relayed = relay_substitution(km, ps, &sym);

	let protocol = if pass == Pass::Constructed {
		protocol_terms(km, ps)
	} else {
		HashSet::new()
	};
	for &slot in &sym.var_slots {
		if pass != Pass::Constructed {
			break;
		}
		let Some(meta) = ps.meta.get(slot) else {
			continue;
		};
		let (honest, _) = resolve_trace_values(&Value::Constant(meta.constant.clone()), km);
		for candidate in slot_candidates(
			&attacker, &sym, &deducer, &protocol, &honest, &blanket, slot,
		) {
			let var_id = vars::attacker_var_id(slot);
			let mut alone = Substitution::new();
			alone.insert(var_id, candidate.clone());
			proposals.push(alone);
			if !blanket.is_empty() {
				let mut combined = blanket.clone();
				combined.insert(var_id, candidate.clone());
				proposals.push(combined);
			}
			// The same choice, but with the rest of the run relayed rather than
			// left untouched.
			let mut with_relay = relayed.clone();
			with_relay.insert(var_id, candidate);
			proposals.push(with_relay);
		}
	}

	for proposal in dedupe(proposals) {
		if ctx.all_resolved() {
			break;
		}
		// Variables the solver never bound are deliberately left free: the
		// attacker has no reason to touch that wire value, so it forwards the
		// honest message.  `validate` skips unbound slots for exactly this
		// reason.  Grounding them here instead would be actively harmful — in a
		// model where a signature is checked, replacing an untargeted signature
		// with `nil` fails the check and halts the principal before it ever
		// computes the value the attack was aiming at.
		let ran = validate::validate(ctx, km, ps, &sym, &attacker, &proposal)?;
		trace_proposal(ps, &sym, &proposal, ran);
	}
	Ok(())
}

/// Turn a query into the goal(s) whose solutions would break it.
///
/// The mapping follows what each query actually tests (`query.rs`):
/// confidentiality is already a pure knowledge lookup, authentication is a
/// forgery the recipient accepts, equivalence is a divergence, and freshness is
/// a static property of the model that no attacker choice affects.
fn goals_for_query(
	query: &Query,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
	deducer: &Deducer,
	base: &Substitution,
) -> Vec<Substitution> {
	match query.kind {
		QueryKind::Confidentiality => match slot_term(query.constants.first(), ps, sym) {
			Some(term) => deducer.solve(&term, base),
			None => Vec::new(),
		},
		QueryKind::Authentication => authentication_goals(query, km, ps, sym, deducer, base),
		QueryKind::Unlinkability => {
			// Only the "same primitive, and the attacker can obtain it" half is
			// attacker-dependent; the freshness half is static.
			let mut out = Vec::new();
			for c in &query.constants {
				if let Some(term) = slot_term(Some(c), ps, sym) {
					out.extend(deducer.solve(&term, base));
				}
			}
			out
		}
		QueryKind::Equivalence => {
			let mut out = Vec::new();
			let terms: Vec<Value> = query
				.constants
				.iter()
				.filter_map(|c| slot_term(Some(c), ps, sym))
				.collect();
			for pair in terms.windows(2) {
				out.extend(diverge::solve_divergent(&pair[0], &pair[1], base));
			}
			out
		}
		// Freshness never consults the attacker: it asks whether a value
		// transitively contains a `fresh` constant, which no substitution
		// changes.  The passive baseline already settles it.
		QueryKind::Freshness => Vec::new(),
	}
}

/// Authentication fails when the recipient successfully uses a value the
/// attacker sent.  So the goal is a forgery: some term the attacker can build
/// that lands in the queried wire slot.
///
/// Two candidates are offered.  Reconstructing the honest value is the strong
/// case — if the attacker can build what the sender would have sent, the
/// recipient cannot tell the difference and every downstream check passes.  The
/// blanket proposal in `solve_principal` covers the weak case where merely
/// substituting the attacker's own key is enough.
fn authentication_goals(
	query: &Query,
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
	deducer: &Deducer,
	base: &Substitution,
) -> Vec<Substitution> {
	if query.message.recipient != ps.id {
		return Vec::new();
	}
	let Some(c) = query.message.constants.first() else {
		return Vec::new();
	};
	let Some(slot) = ps.index_of(c) else {
		return Vec::new();
	};
	if !sym.is_var_slot(slot) {
		return Vec::new();
	}
	let Some(var_term) = &sym.var_terms[slot] else {
		return Vec::new();
	};
	let mut out = Vec::new();

	// Forgery: build something the recipient's rewrite rule accepts but the
	// sender never sent.  This is the case that actually breaks authentication,
	// because a replay of the honest value is indistinguishable to the
	// recipient and `validate` rightly refuses to call it an attack.
	for shape in deducer.forgeable_shapes(sym, vars::attacker_var_id(slot)) {
		for candidate in deducer.solve(&shape, base) {
			let forged = vars::apply(&shape, &candidate);
			if vars::contains_var(&forged) {
				continue;
			}
			if let Some(bound) = matching::match_value(var_term, &forged, &candidate) {
				out.push(bound);
			}
		}
	}

	// Reconstruction: if the attacker can rebuild what the sender would have
	// sent, it can inject it on its own authority.  Kept as a fallback for
	// values consumed by primitives with no rewrite rule to invert.
	let (honest, _) = resolve_trace_values(&Value::Constant(c.clone()), km);
	for candidate in deducer.solve_forgeable(&honest, base) {
		// `match_value` rather than a raw insert, so a shaped variable (`G^$x`)
		// binds its exponent instead of being overwritten wholesale.
		if let Some(bound) = matching::match_value(var_term, &honest, &candidate) {
			out.push(bound);
		}
	}
	out
}

/// Every attacker-controlled wire value replaced by one of the attacker's own.
fn blanket_substitution(sym: &SymbolicState) -> Substitution {
	let mut out = Substitution::new();
	for &slot in &sym.var_slots {
		if let Some(term) = &sym.var_terms[slot] {
			vars::ground_remaining(term, &mut out);
		}
	}
	out
}

/// Report a proposal and whether it was executed.
///
/// Enabled by setting `VERIFPAL_SOLVE_DEBUG`; silent otherwise.  Attacks are
/// diagnosed by asking which substitutions were tried and which were rejected
/// as indistinguishable replays, and that is tedious to reconstruct after the
/// fact.
fn trace_proposal(ps: &PrincipalState, sym: &SymbolicState, proposal: &Substitution, ran: bool) {
	let debug = std::env::var_os("VERIFPAL_SOLVE_DEBUG").is_some();
	// A proposal that did not run changed nothing, so it is worth the cost of
	// rendering only when someone asked to see the rejected ones too.
	if !debug && !ran {
		return;
	}
	let bindings = binding_summary(ps, sym, proposal);
	if debug {
		eprintln!("[solve] {} ran={ran} [{}]", ps.name, bindings.join(" "));
	}
}

/// Each bound slot rendered as `name=value`, for display only.
fn binding_summary(
	ps: &PrincipalState,
	sym: &SymbolicState,
	proposal: &Substitution,
) -> Vec<String> {
	sym.var_slots
		.iter()
		.filter_map(|&slot| {
			let term = sym.var_terms[slot].as_ref()?;
			let ground = vars::ground_free(&vars::apply(term, proposal));
			if vars::contains_var(&ground) {
				None
			} else {
				Some(format!("{}={}", ps.meta[slot].constant.name, ground))
			}
		})
		.collect()
}

/// Every controlled slot bound to the value the honest run put on the wire.
///
/// On its own this changes nothing and `validate` will reject it as not
/// worthwhile.  Its purpose is to be combined with a binding that *does* change
/// something: the resulting run has one forged message and the rest relayed,
/// which is what a real interception looks like.
fn relay_substitution(
	km: &ProtocolTrace,
	ps: &PrincipalState,
	sym: &SymbolicState,
) -> Substitution {
	let mut out = Substitution::new();
	for &slot in &sym.var_slots {
		let Some(meta) = ps.meta.get(slot) else {
			continue;
		};
		let (honest, _) = resolve_trace_values(&Value::Constant(meta.constant.clone()), km);
		out.insert(vars::attacker_var_id(slot), honest);
	}
	out
}

/// Hashes of every ground term the protocol itself puts on the wire, and every
/// subterm of those.
///
/// This is the set candidate selection draws from, and the reason it can do so
/// without any cap. Attacker knowledge grows with every derivation, so
/// selecting from it needs pruning and any pruning is a limit; the terms the
/// *model* mentions are fixed by the model, so selecting from them needs none.
fn protocol_terms(km: &ProtocolTrace, ps: &PrincipalState) -> HashSet<u64> {
	let mut out = HashSet::new();
	for meta in ps.meta.iter() {
		let (v, _) = resolve_trace_values(&Value::Constant(meta.constant.clone()), km);
		collect_subterm_hashes(&v, &mut out);
	}
	out
}

/// Values the attacker could put in `slot`, derived rather than catalogued.
///
/// Two sources, both finite by construction and neither capped, size-ordered or
/// depth-filtered.
///
/// **Terms of the protocol that the attacker holds.** A substitution attack
/// replaces one message with another, and the messages are a fixed set given by
/// the model. A ciphertext from one slot can be admissible in another whenever
/// the two share a key, which no goal analysis would ever derive, so this
/// source cannot be dispensed with — but restricting it to protocol terms is
/// what keeps it bounded by the model's size rather than by how long the search
/// has run.
///
/// **Shapes the recipient's own rules demand.** Where a slot feeds a primitive
/// with a rewrite rule, that rule dictates what would be accepted there, and
/// inverting it yields the shape directly. Each is then required to be
/// *constructible*: offering one unchecked would let the engine send a
/// ciphertext under a key derived from a secret it never had, and report the
/// recipient accepting it as an attack.
fn slot_candidates(
	attacker: &AttackerState,
	sym: &SymbolicState,
	deducer: &Deducer,
	protocol: &HashSet<u64>,
	honest: &Value,
	blanket: &Substitution,
	slot: usize,
) -> Vec<Value> {
	let mut out = Vec::new();

	for candidate in attacker.known.iter() {
		if !protocol.contains(&candidate.hash_value()) || candidate.equivalent(honest, true) {
			continue;
		}
		// A sort condition, not a size one: a term of the wrong shape fails
		// every rewrite the recipient performs, and that outcome is already
		// covered by the canonical `nil` substitution.
		let compatible = match (honest, candidate) {
			(Value::Primitive(h), Value::Primitive(k)) => k.id == h.id,
			(Value::Equation(h), Value::Equation(k)) => h.values.len() == k.values.len(),
			(Value::Constant(_), Value::Constant(k)) => !k.is_g_or_nil(),
			_ => false,
		};
		if compatible {
			push_unique_value(&mut out, candidate.clone());
		}
	}

	// Solved under the blanket as well as on its own.  A shape's key is often
	// only computable once some *other* slot has been taken over — the forged
	// ciphertext for one message is encrypted under a key that exists only
	// because the attacker replaced a public value in another.  Solving in
	// isolation would judge such a shape unbuildable and discard it, when it is
	// buildable in exactly the run it would be used in.
	let mut contexts = vec![Substitution::new()];
	if !blanket.is_empty() {
		contexts.push(blanket.clone());
	}
	for shape in deducer.forgeable_shapes(sym, vars::attacker_var_id(slot)) {
		for context in &contexts {
			for solution in deducer.solve(&shape, context) {
				let applied = vars::apply(&shape, &solution);
				for filler in [crate::value::value_nil(), crate::value::value_g_nil()] {
					let built = vars::ground_free_as(&applied, &filler);
					if !vars::contains_var(&built) {
						push_unique_value(&mut out, built);
					}
				}
			}
		}
	}
	out
}

/// The symbolic term a queried constant denotes in this principal.
fn slot_term(c: Option<&Constant>, ps: &PrincipalState, sym: &SymbolicState) -> Option<Value> {
	let c = c?;
	let slot = ps.index_of(c)?;
	sym.terms.get(slot).cloned()
}
