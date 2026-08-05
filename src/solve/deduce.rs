/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

//! # Deducibility goals
//!
//! Given a term the attacker wants, work out which attacker choices would make
//! it derivable.  This inverts the forward rules in [`crate::theory`]: where
//! `can_reconstruct_equation` *tests* whether an exponent is known, this
//! *binds* it when the exponent is an attacker variable.
//!
//! ## The lazy principle
//!
//! Variables are never enumerated over.  A variable is bound only when
//! something forces it — either the surrounding rule requires a particular
//! shape, or the goal has been reduced to the variable itself, at which point
//! the canonical attacker constant `nil` discharges it.  This is what removes
//! the combinatorics: a four-substitution attack is not found by considering
//! four-element subsets, it is the union of four independently forced bindings.
//!
//! ## What this module does *not* have to do
//!
//! It does not reimplement Verifpal's full derivation theory.  Every proposal
//! is re-executed by `validate.rs`, which runs
//! [`crate::deduction::compute_knowledge_closure`] — the real monotone
//! fixed-point over every rule, including recompose, rebuild, password
//! extraction and concat splitting.  This module only has to be good enough to
//! *propose the right substitution*; the closure finds everything that follows
//! from it.  So the rules inverted here are the ones where an attacker choice
//! actually changes what is derivable: DH equations and decomposition chains.
//!
//! ## Termination
//!
//! There is no depth limit, deliberately.  A depth limit would silently drop
//! attacks whenever a chain ran one step longer than the number allowed, which
//! is precisely the defect this design exists to remove — relocating it from a
//! scan budget into a recursion counter would not be a fix.
//!
//! Termination rests on three facts instead.
//!
//! *The goal space is finite.*  Most rules decompose a goal into strictly
//! smaller pieces, so they cannot run away.  Two rules are **generative**
//! though: asking a principal to decrypt to `v` builds a term *containing* `v`.
//! Left alone that regresses forever, each term larger than the last and none
//! ever repeating.  Both are therefore confined to goals drawn from `basis` —
//! the subterms the protocol actually mentions, plus what the attacker holds.
//! This is the finite-basis restriction that makes constraint solving over a
//! bounded trace decidable, and it costs nothing real: the attacker wants
//! protocol values, not ciphertexts of ciphertexts it invented.
//!
//! *Cycles are cut.*  A goal reappearing while it is still being solved
//! contributes nothing, and that branch stops.
//!
//! *Each goal is solved once.*  Results are memoised by goal, storing the
//! bindings a goal additionally requires, so a goal reached by several routes
//! is computed a single time.
//!

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::equivalence::equivalent_primitives;
use crate::hashing::collect_subterm_hashes;
use crate::primitive::*;
use crate::types::*;
use crate::value::{value_g, value_nil};

use super::matching::match_value;
use super::symbolic::SymbolicState;
use super::vars::{Substitution, apply, as_var, bind, compose, contains_var, dedupe};

/// Cache key for a goal.
///
/// The raw hash is not injective across kinds: `equation_hash` folds the base
/// first, and `g` has id 0, so `G^x` hashes to exactly the same value as the
/// bare constant `x`.  Keying the memo on it alone conflates the two — solving
/// `x` fails, because it is a principal's secret, and the cached failure is
/// then returned for `G^x`, which the attacker knows perfectly well.  Values of
/// different kinds are never equivalent, so mixing the kind into the key is
/// sound and restores injectivity.
fn goal_key(v: &Value) -> u64 {
	let tag: u64 = match v {
		Value::Constant(_) => 0x0000_0000_0000_0001,
		Value::Primitive(_) => 0x9E37_79B9_7F4A_7C15,
		Value::Equation(_) => 0xBF58_476D_1CE4_E5B9,
	};
	v.hash_value().wrapping_mul(31).wrapping_add(tag)
}

pub(crate) struct Deducer<'a> {
	attacker: &'a AttackerState,
	/// Symbolic terms carried on the wire, available for decomposition.
	wire_terms: Vec<Value>,
	/// The additional bindings each solved goal requires, keyed by goal.
	memo: RefCell<HashMap<u64, Vec<Substitution>>>,
	/// Goals currently being solved, innermost last.  A goal that reappears
	/// while it is still being solved is a cycle, and the branch that reached it
	/// contributes nothing.
	active: RefCell<Vec<u64>>,
	/// Number of cycles cut so far, used to decide whether a result is complete
	/// enough to cache.
	cycles_cut: Cell<usize>,
	/// Hashes of every subterm occurring in the protocol or in the attacker's
	/// knowledge — the finite basis the search is allowed to range over.
	basis: HashSet<u64>,
	/// Counter handing out free-choice variables.
	fresh: Cell<u32>,
}

impl<'a> Deducer<'a> {
	pub(crate) fn new(
		ps: &PrincipalState,
		attacker: &'a AttackerState,
		sym: &'a SymbolicState,
	) -> Self {
		let mut wire_terms = Vec::new();
		for (idx, meta) in ps.meta.iter().enumerate() {
			if meta.wire.is_empty() && !meta.constant.leaked {
				continue;
			}
			// A slot the attacker controls is one it *supplies*, not one it
			// receives.  Reading knowledge out of it would be circular — it
			// would let the attacker "learn" a secret by sending that secret,
			// which it cannot do precisely because it does not know it.  Only
			// values a principal genuinely computes and transmits count.
			if sym.is_var_slot(idx) {
				continue;
			}
			if let Some(term) = sym.terms.get(idx) {
				wire_terms.push(term.clone());
			}
		}
		// The finite basis: every subterm the protocol mentions, plus everything
		// the attacker already holds.  Generative rules are confined to it.
		let mut basis = HashSet::new();
		for term in &sym.terms {
			collect_subterm_hashes(term, &mut basis);
		}
		for known in attacker.known.iter() {
			collect_subterm_hashes(known, &mut basis);
		}

		Deducer {
			attacker,
			wire_terms,
			basis,
			memo: RefCell::new(HashMap::new()),
			active: RefCell::new(Vec::new()),
			cycles_cut: Cell::new(0),
			fresh: Cell::new(0),
		}
	}

	/// Substitutions under which the attacker can derive `goal`.
	///
	/// An empty result means "not derivable by any choice this solver can see".
	/// A result containing the input substitution unchanged means "already
	/// derivable, no choice needed".
	pub(crate) fn solve(&self, goal: &Value, s: &Substitution) -> Vec<Substitution> {
		let mut out = Vec::new();
		self.solve_into(goal, s, &mut out);
		dedupe(out)
	}

	/// Solve `goal`, memoising the result and cutting cycles.
	fn solve_into(&self, goal: &Value, s: &Substitution, out: &mut Vec<Substitution>) {
		let g = apply(goal, s);

		// Keyed on the goal alone, not on the goal plus the choices made so far.
		// Those choices proliferate — every branch carries a slightly different
		// substitution — so including them in the key means a cache that never
		// hits and a search that redoes the same work exponentially.  What is
		// cached instead is the *additional* bindings a goal requires, which
		// depend only on the goal; replaying them against a different starting
		// substitution is a matter of checking they do not conflict.
		let key = goal_key(&g);

		if self.active.borrow().contains(&key) {
			self.cycles_cut.set(self.cycles_cut.get() + 1);
			return;
		}
		if let Some(deltas) = self.memo.borrow().get(&key) {
			for delta in deltas {
				if let Some(merged) = compose(s, delta) {
					out.push(merged);
				}
			}
			return;
		}

		let cycles_before = self.cycles_cut.get();
		self.active.borrow_mut().push(key);
		let mut local = Vec::new();
		self.solve_rules(&g, s, &mut local);
		self.active.borrow_mut().pop();
		local = dedupe(local);

		// Only cache a result computed without cutting a cycle.  A truncated
		// branch may be incomplete for the goal it was cut at, and caching it
		// could deny a later, non-circular route to the same goal.
		if self.cycles_cut.get() == cycles_before {
			let deltas: Vec<Substitution> = local
				.iter()
				.map(|full| {
					full.iter()
						.filter(|(id, _)| !s.contains_key(*id))
						.map(|(id, v)| (*id, v.clone()))
						.collect()
				})
				.collect();
			self.memo.borrow_mut().insert(key, deltas);
		}
		out.extend(local);
	}

	/// A variable standing for a position some rule leaves to the attacker.
	fn fresh_var(&self) -> Value {
		let n = self.fresh.get();
		self.fresh.set(n + 1);
		super::vars::free_var(n)
	}

	fn rewrite_shape(&self, outer: &Primitive, spec: &PrimitiveSpec) -> Option<Value> {
		self.rewrite_shapes(outer, spec).into_iter().next()
	}

	fn rewrite_shapes(&self, outer: &Primitive, spec: &PrimitiveSpec) -> Vec<Value> {
		build_rewrite_shapes_with(outer, spec, || self.fresh_var())
	}

	fn rewrite_shape_yielding(
		&self,
		outer: &Primitive,
		spec: &PrimitiveSpec,
		fill: &Value,
	) -> Option<Value> {
		build_rewrite_shapes_with(outer, spec, || fill.clone())
			.into_iter()
			.next()
	}

	fn solve_rules(&self, g: &Value, s: &Substitution, out: &mut Vec<Substitution>) {
		if !contains_var(g) && self.attacker.knows(g).is_some() {
			out.push(s.clone());
			return;
		}

		// The goal has been reduced to a bare attacker choice.  `nil` is the
		// canonical constant the attacker always knows; inside the `G^X` shape
		// from `symbolic.rs` this is precisely "use my own DH key".
		if let Some(id) = as_var(g) {
			// A *free* position is trivially satisfiable and must stay free.
			// Committing it to `nil` here would be premature: another check on
			// the same forged message may still require a particular value
			// there, and two solutions that have each already chosen `nil`
			// cannot be merged into the one message satisfying both.  Whatever
			// is still free at materialisation becomes `nil` then.
			if super::vars::is_free_var_id(id) {
				out.push(s.clone());
				return;
			}
			let mut extended = s.clone();
			extended.insert(id, value_nil());
			out.push(extended);
			return;
		}

		// The goal may still mention choices the attacker has not made.  If some
		// value it already holds *is* an instance of the pattern, those choices
		// are settled by reading them off, and the attacker is done having
		// derived nothing: it simply forwards the value it has.
		//
		// This is what makes a replay work.  A recipient checking
		// `AEAD_DEC(k, $x, ad)?` needs `$x = AEAD_ENC(k, ?, ad)`; the attacker
		// cannot build that from parts, having no `k`, but it may be holding a
		// ciphertext from elsewhere in the run under the very same key.
		if let Value::Primitive(pattern) = g
			&& contains_var(g)
		{
			for known in self.attacker.known.iter() {
				// Cheap structural pre-filter: only a same-shaped primitive can
				// match, and testing every entry in full is what would make this
				// rule expensive.
				let Value::Primitive(candidate) = known else {
					continue;
				};
				if candidate.id != pattern.id
					|| candidate.arguments.len() != pattern.arguments.len()
				{
					continue;
				}
				if let Some(bound) = match_value(g, known, s) {
					// Only *slot* bindings carry an obligation here.  The
					// instantiated pattern is the held value itself, so its
					// internal positions are covered by holding it — requiring
					// each to be separately constructible would reject every
					// replay of a ciphertext whose plaintext is secret, which is
					// precisely the interesting case.  A slot binding is
					// different: that value has to be put on the wire, so it
					// must be one the attacker can actually produce.
					out.extend(self.require_constructible(&bound, s, true));
				}
			}
		}

		// Everything crossing the wire lands in the attacker's hands.  So if some
		// choice of the attacker's own makes a transmitted term *become* the
		// goal, the goal is derivable by simply reading it off the network.
		//
		// This is what breaks an oracle: where a principal returns `MAC(k, m)`
		// for an `m` the attacker supplies, asking for `MAC(k, c0)` unifies with
		// the transmitted term and binds `m := c0`.  No key is ever derived; the
		// principal is induced to compute the answer.
		self.solve_by_wire(g, s, out);

		match g {
			Value::Equation(e) => self.solve_equation(e, s, out),
			Value::Primitive(p) => self.solve_primitive(p, s, out),
			Value::Constant(_) => {}
		}

		self.solve_by_decomposition(g, s, out);
	}

	fn solve_by_wire(&self, goal: &Value, s: &Substitution, out: &mut Vec<Substitution>) {
		for term in &self.wire_terms {
			if !contains_var(term) {
				// No choice to make: either the attacker already knows it, which
				// the caller checked, or this term cannot become the goal.
				continue;
			}
			if let Some(bound) = match_value(term, goal, s) {
				// Unification is happy to bind a variable to anything at all,
				// including the secret being hunted.  Every choice it made has
				// to be something the attacker can actually put on the wire.
				out.extend(self.require_constructible(&bound, s, false));
			}
			self.solve_by_oracle(term, goal, s, out);
			self.solve_by_rewrite_match(term, goal, s, out);
		}
	}

	/// Make a principal's own rewrite succeed, so that what it transmits is the
	/// goal.
	///
	/// Distinct from [`Self::solve_by_oracle`], which supplies the ciphertext.
	/// Here the ciphertext is fixed and the attacker influences the *other*
	/// arguments — typically the key.  A principal computing
	/// `AEAD_DEC(k2, AEAD_ENC(k1, m, c), c)` sends `m` if and only if `k2` and
	/// `k1` coincide, so an attacker that can steer whatever `k2` was derived
	/// from gets the plaintext without ever holding a key.
	///
	/// The rule is the rewrite's own matching constraints, solved rather than
	/// tested.
	fn solve_by_rewrite_match(
		&self,
		term: &Value,
		goal: &Value,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let Value::Primitive(p) = term else {
			return;
		};
		let Ok(spec) = primitive_get(p.id) else {
			return;
		};
		if !spec.rewrite.has_rule {
			return;
		}
		let Some(Value::Primitive(inner)) = p.arguments.get(spec.rewrite.from) else {
			return;
		};
		if inner.id != spec.rewrite.id {
			return;
		}
		let (Some(to_fn), Some(filter)) = (spec.rewrite.to, spec.rewrite.filter) else {
			return;
		};

		// Would this rewrite, if it fired, yield what we are after?
		let Some(mut current) = match_value(&to_fn(inner), goal, s) else {
			return;
		};

		// Then make it fire: every matching constraint becomes a unification.
		for (outer_idx, inner_idxs) in &spec.rewrite.matching {
			let Some(outer_arg) = p.arguments.get(*outer_idx) else {
				return;
			};
			let mut satisfied = false;
			for &inner_idx in inner_idxs {
				let Some(inner_arg) = inner.arguments.get(inner_idx) else {
					continue;
				};
				let (filtered, valid) = filter(p, outer_arg, inner_idx);
				if !valid {
					continue;
				}
				// Variables may sit on either side, so try both directions.
				if let Some(next) = match_value(&filtered, inner_arg, &current)
					.or_else(|| match_value(inner_arg, &filtered, &current))
				{
					current = next;
					satisfied = true;
					break;
				}
			}
			if !satisfied {
				return;
			}
		}

		out.extend(self.require_constructible(&current, s, false));
	}

	/// Induce a principal to compute the goal and transmit it.
	///
	/// A principal that decrypts something the attacker chose, and then sends
	/// the result onward, is a decryption oracle.  If a transmitted term is
	/// `AEAD_DEC(k, $x, ad)` with `$x` the attacker's to pick, then choosing
	/// `$x = AEAD_ENC(k, goal, ad)` makes the principal hand back the goal —
	/// provided the attacker can build that ciphertext, which it often can by
	/// replaying one it already holds.
	///
	/// The attacker never learns `k` here.  It does not need to: the principal
	/// does the work.
	fn solve_by_oracle(
		&self,
		term: &Value,
		goal: &Value,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let Value::Primitive(p) = term else {
			return;
		};
		let Ok(spec) = primitive_get(p.id) else {
			return;
		};
		if !spec.rewrite.has_rule {
			return;
		}
		let Some(from) = p.arguments.get(spec.rewrite.from) else {
			return;
		};
		let Some(var_id) = as_var(from) else {
			return;
		};
		// Asking an oracle to produce `goal` builds a term that *contains* the
		// goal.  Left unrestricted that is generative: the constructed shape can
		// become the next goal, be wrapped again, and grow without bound — every
		// term distinct, so no cycle is ever detected and the search does not
		// terminate.
		//
		// Confining the rule to goals drawn from the protocol's own subterms
		// removes the regress and costs nothing real: the attacker wants
		// protocol values, not ciphertexts of ciphertexts it invented.  This is
		// the standard finite-basis restriction that makes constraint solving
		// over a bounded trace decidable, and it is a statement about the term
		// algebra rather than a tunable limit.
		if !self.basis.contains(&goal.hash_value()) {
			return;
		}
		let Some(shape) = self.rewrite_shape_yielding(p, spec, goal) else {
			return;
		};
		for candidate in self.solve(&shape, s) {
			let ground = apply(&shape, &candidate);
			if contains_var(&ground) {
				continue;
			}
			let mut extended = candidate;
			if bind(&mut extended, var_id, ground) {
				out.push(extended);
			}
		}
	}

	/// Invert `can_reconstruct_equation`.
	///
	/// `G^a` needs `a`.  `G^a^b` needs both exponents, or one exponent plus the
	/// complementary public value — the latter being the case that matters,
	/// since it is how `G^nil^ae3` becomes derivable from `nil` and the wire
	/// value `G^ae3`.
	fn solve_equation(&self, e: &Equation, s: &Substitution, out: &mut Vec<Substitution>) {
		match e.values.len() {
			2 => self.solve_into(&e.values[1], s, out),
			3 => {
				let a = &e.values[1];
				let b = &e.values[2];
				let base = &e.values[0];
				let pub_a = partial(base, a);
				let pub_b = partial(base, b);

				// Both exponents.
				self.solve_pair(a, b, s, out);
				// One exponent plus the other side's public value.
				self.solve_pair(a, &pub_b, s, out);
				self.solve_pair(&pub_a, b, s, out);
			}
			_ => {}
		}
	}

	/// Both goals must hold under one consistent substitution.
	fn solve_pair(
		&self,
		first: &Value,
		second: &Value,
		s: &Substitution,
		out: &mut Vec<Substitution>,
	) {
		let mut firsts = Vec::new();
		self.solve_into(first, s, &mut firsts);
		for s1 in firsts {
			self.solve_into(second, &s1, out);
		}
	}

	/// Invert `can_reconstruct_primitive`: buildable when every argument is.
	fn solve_primitive(&self, p: &Primitive, s: &Substitution, out: &mut Vec<Substitution>) {
		let mut frontier = vec![s.clone()];
		for arg in &p.arguments {
			let mut next = Vec::new();
			for candidate in &frontier {
				self.solve_into(arg, candidate, &mut next);
			}
			if next.is_empty() {
				return;
			}
			frontier = dedupe(next);
		}
		out.extend(frontier);
	}

	/// Invert `can_decompose`: a wire term yields its hidden argument once the
	/// spec's `given` arguments are derivable.
	///
	/// This is the step that starts the chain for a confidentiality goal —
	/// `m3` is reachable because `AEAD_ENC(akenc5, m3, ad)` is on the wire, so
	/// the real question becomes whether `akenc5` is derivable.
	fn solve_by_decomposition(&self, goal: &Value, s: &Substitution, out: &mut Vec<Substitution>) {
		for term in &self.wire_terms {
			let Value::Primitive(p) = term else {
				continue;
			};
			if primitive_is_core(p.id) {
				continue;
			}
			let Ok(spec) = primitive_get(p.id) else {
				continue;
			};
			if !spec.decompose.has_rule {
				continue;
			}
			let Some(reveal) = p.arguments.get(spec.decompose.reveal) else {
				continue;
			};
			// Does opening this term actually yield what we want?
			let Some(aligned) = match_value(reveal, goal, s) else {
				continue;
			};
			let Some(filter_fn) = spec.decompose.filter else {
				continue;
			};

			// Every `given` argument must be derivable under one substitution.
			let mut frontier = vec![aligned];
			let mut viable = true;
			for (filter_i, &arg_idx) in spec.decompose.given.iter().enumerate() {
				let Some(arg) = p.arguments.get(arg_idx) else {
					viable = false;
					break;
				};
				let (filtered, valid) = filter_fn(p, arg, filter_i);
				if !valid {
					viable = false;
					break;
				}
				let mut next = Vec::new();
				for candidate in &frontier {
					self.solve_into(&filtered, candidate, &mut next);
				}
				if next.is_empty() {
					viable = false;
					break;
				}
				frontier = dedupe(next);
			}
			if viable {
				out.extend(frontier);
			}
		}
	}

	/// Substitutions under which the attacker can itself construct `term`.
	///
	/// Used for authentication goals, where forging means producing a value the
	/// recipient's primitive will accept.
	pub(crate) fn solve_forgeable(&self, term: &Value, s: &Substitution) -> Vec<Substitution> {
		self.solve(term, s)
	}

	/// The term shapes that would satisfy a rewrite rule consuming `var_id`.
	///
	/// Open positions become *fresh variables*, not `nil`: a later constraint may
	/// require a particular value there, and a position already committed to
	/// `nil` could not then be reconciled with it.
	pub(crate) fn forgeable_shapes(&self, sym: &SymbolicState, var_id: ValueId) -> Vec<Value> {
		let mut out = Vec::new();
		for term in &sym.terms {
			self.collect_forgeable(term, var_id, &mut out);
		}
		out
	}

	fn collect_forgeable(&self, v: &Value, var_id: ValueId, out: &mut Vec<Value>) {
		match v {
			Value::Primitive(p) => {
				if let Ok(spec) = primitive_get(p.id)
					&& spec.rewrite.has_rule
					&& let Some(from) = p.arguments.get(spec.rewrite.from)
					&& as_var(from) == Some(var_id)
				{
					for shape in self.rewrite_shapes(p, spec) {
						if !out
							.iter()
							.any(|existing: &Value| existing.equivalent(&shape, true))
						{
							out.push(shape);
						}
					}
				}
				for a in &p.arguments {
					self.collect_forgeable(a, var_id, out);
				}
			}
			Value::Equation(e) => {
				for a in &e.values {
					self.collect_forgeable(a, var_id, out);
				}
			}
			Value::Constant(_) => {}
		}
	}

	/// Substitutions that make every checked primitive in this principal's
	/// computation succeed.
	///
	/// A checked primitive is the attacker's obstacle *and* its opportunity.
	/// Left alone it halts the principal, discarding whatever the attack was
	/// aiming at; satisfied, it means the principal accepted something the
	/// attacker chose, which is precisely what an authentication query asks
	/// about.  Solving the check as a constraint handles both at once, and does
	/// so for every checked primitive in the model rather than only the one a
	/// particular query names.
	pub(crate) fn constraint_goals(
		&self,
		sym: &SymbolicState,
		base: &Substitution,
	) -> Vec<Substitution> {
		let mut checked = Vec::new();
		for term in &sym.terms {
			collect_checked(term, &mut checked);
		}
		// Each check is solved on its own, and then all of them are solved
		// together.  Solving them together matters whenever a principal makes
		// several checks on one attacker-supplied value: a forged message that
		// satisfies the first check and fails the second still halts the
		// principal, so only the combined substitution is an attack.
		let mut out = Vec::new();
		let mut combined: Vec<Substitution> = vec![base.clone()];
		for p in &checked {
			let solved = self.satisfy_check(p, base);
			if solved.is_empty() {
				continue;
			}
			combined = combine(&combined, &solved);
			out.extend(solved);
		}
		out.extend(combined);
		dedupe(out)
	}

	/// Choices that make `term` evaluate to `target`.
	///
	/// Direct unification is only the first case.  Where the principal computes
	/// `term` by decrypting and splitting something the attacker supplies, the
	/// question is not "do these terms match" but "what would have to be sent so
	/// that they do", and answering it means running the rewrite rules
	/// backwards: to make `PKE_DEC(a, $x)` yield `v`, send
	/// `$x = PKE_ENC(G^a, v)`; to make `SPLIT(y)[i]` yield `v`, `y` must be a
	/// `CONCAT` carrying `v` at position `i`.
	///
	/// Recursion is on the structure of `term`, which loses a layer at every
	/// step, so this terminates without any imposed bound.
	fn invert(&self, term: &Value, target: &Value, s: &Substitution) -> Vec<Substitution> {
		let mut out = Vec::new();
		if let Some(bound) = match_value(term, target, s) {
			out.push(bound);
		}

		let Value::Primitive(p) = term else {
			return dedupe(out);
		};

		// Backwards through a rewrite rule.
		if let Ok(spec) = primitive_get(p.id)
			&& spec.rewrite.has_rule
			&& let Some(from) = p.arguments.get(spec.rewrite.from)
			&& let Some(shape) = self.rewrite_shape_yielding(p, spec, target)
		{
			out.extend(self.invert(from, &shape, s));
		}

		// Backwards through SPLIT: its argument has to be a CONCAT carrying the
		// target at this instance's output position.  The other positions are
		// the attacker's to choose, so they are left as `nil`; the arity is not
		// recorded on the SPLIT, so every arity CONCAT admits is offered.
		// `primitive_def` rather than `primitive_get`: CONCAT is a core
		// primitive and so lives in the other registry.
		if p.id == PRIM_SPLIT
			&& let Some(inner) = p.arguments.first()
			&& let Ok(concat_spec) = primitive_def(PRIM_CONCAT)
		{
			for arity in concat_spec.arity().iter().map(|a| *a as usize) {
				if p.output >= arity {
					continue;
				}
				let mut arguments: Vec<Value> = (0..arity).map(|_| self.fresh_var()).collect();
				arguments[p.output] = target.clone();
				let candidate = Value::Primitive(Arc::new(Primitive {
					id: PRIM_CONCAT,
					arguments,
					output: 0,
					instance_check: false,
				}));
				out.extend(self.invert(inner, &candidate, s));
			}
		}

		dedupe(out)
	}

	fn satisfy_check(&self, p: &Primitive, base: &Substitution) -> Vec<Substitution> {
		// `ASSERT(x, y)?` succeeds exactly when the two arguments agree, so the
		// constraint is a unification.  Where one side is a value the attacker
		// supplies and the other is something the principal computed, this binds
		// the attacker's side to whatever it would have to be — the recipient's
		// own expected tag, for instance.
		if p.id == PRIM_ASSERT && p.arguments.len() == 2 {
			let mut out = Vec::new();
			for (pattern, target) in [(0usize, 1usize), (1, 0)] {
				// `invert`, not a plain match: the side the attacker influences
				// is usually reached through a decryption and a split, so the
				// question is what to send such that the two sides agree.
				for bound in self.invert(&p.arguments[pattern], &p.arguments[target], base) {
					out.extend(self.require_constructible(&bound, base, false));
				}
			}
			return dedupe(out);
		}

		// Rewrite-rule checks (`AEAD_DEC?`, `SIGNVERIF?`, …): the consumed
		// argument must have the shape the rule demands.
		let Ok(spec) = primitive_get(p.id) else {
			return Vec::new();
		};
		if !spec.rewrite.has_rule {
			return Vec::new();
		}
		let Some(from) = p.arguments.get(spec.rewrite.from) else {
			return Vec::new();
		};
		let Some(var_id) = as_var(from) else {
			return Vec::new();
		};
		let Some(shape) = self.rewrite_shape(p, spec) else {
			return Vec::new();
		};

		let mut out = Vec::new();
		for candidate in self.solve(&shape, base) {
			let ground = apply(&shape, &candidate);
			if contains_var(&ground) {
				continue;
			}
			let mut extended = candidate;
			if bind(&mut extended, var_id, ground) {
				out.push(extended);
			}
		}
		out
	}

	/// Keep only the extensions of `s` under which every term `s` binds is
	/// something the attacker can actually build.
	///
	/// Unification will happily bind a variable to a term full of values the
	/// attacker has never seen.  This is the step that turns such a binding into
	/// a real obligation, and it is what forces the DH substitution: the tag the
	/// attacker must produce contains the session key, so the key has to become
	/// derivable, so the public value it came from has to become the attacker's.
	///
	/// `slots_only` narrows the obligation to slot variables — the values that
	/// actually have to be transmitted.  Callers pass it where the bindings came
	/// from matching a value the attacker already holds: the term as a whole is
	/// in hand, so its internal choices need no separate justification, and
	/// demanding one would reject every replay of a ciphertext whose plaintext is
	/// secret.
	fn require_constructible(
		&self,
		s: &Substitution,
		base: &Substitution,
		slots_only: bool,
	) -> Vec<Substitution> {
		let obligations: Vec<Value> = s
			.iter()
			.filter(|(id, _)| {
				!base.contains_key(*id) && !(slots_only && super::vars::is_free_var_id(**id))
			})
			.map(|(_, v)| v.clone())
			.collect();

		let mut frontier = vec![s.clone()];
		for obligation in obligations {
			let mut next = Vec::new();
			for candidate in &frontier {
				self.solve_into(&obligation, candidate, &mut next);
			}
			if next.is_empty() {
				return Vec::new();
			}
			frontier = dedupe(next);
		}
		frontier
	}
}

fn collect_checked(v: &Value, out: &mut Vec<Primitive>) {
	match v {
		Value::Primitive(p) => {
			if p.instance_check
				&& !out
					.iter()
					.any(|q| equivalent_primitives(q, p, true).equivalent)
			{
				out.push((**p).clone());
			}
			for a in &p.arguments {
				collect_checked(a, out);
			}
		}
		Value::Equation(e) => {
			for a in &e.values {
				collect_checked(a, out);
			}
		}
		Value::Constant(_) => {}
	}
}

/// Build the inner primitive a rewrite rule demands, from the outer primitive's
/// arguments.
///
/// `fill` supplies the positions the rule leaves unconstrained.  Two callers
/// want different things there: satisfying a check only needs *some* value, so
/// it passes `nil`; making the rewrite *yield* a particular term passes that
/// term, because for the decryption family the unconstrained position is
/// exactly the plaintext the rule returns.
fn build_rewrite_shapes_with(
	outer: &Primitive,
	spec: &PrimitiveSpec,
	mut fill: impl FnMut() -> Value,
) -> Vec<Value> {
	let Ok(inner_spec) = primitive_get(spec.rewrite.id) else {
		return Vec::new();
	};
	let Some(&arity) = inner_spec.arity.first() else {
		return Vec::new();
	};
	let arity = arity as usize;
	let Some(filter) = spec.rewrite.filter else {
		return Vec::new();
	};

	// A matching constraint may admit several inner positions — a ring
	// signature's verifier accepts its key in any ring slot — so every
	// assignment is built, not just the first.  The count is a property of the
	// primitive's own spec, fixed by `primitive/spec.rs`, so this does not grow
	// with the model.
	// Assignments are injective: each constraint claims a distinct inner
	// position.  Two outer arguments landing on the same one would describe a
	// term where one silently overwrote the other, which is not a term the rule
	// actually accepts — and offering it would manufacture forgeries.
	let mut partials: Vec<(Vec<Value>, Vec<usize>)> =
		vec![((0..arity).map(|_| fill()).collect(), Vec::new())];
	for (outer_idx, inner_idxs) in &spec.rewrite.matching {
		let Some(outer_arg) = outer.arguments.get(*outer_idx) else {
			return Vec::new();
		};
		let mut next = Vec::new();
		for (base, taken) in &partials {
			for &inner_idx in inner_idxs {
				if inner_idx >= arity || taken.contains(&inner_idx) {
					continue;
				}
				let (filtered, valid) = filter(outer, outer_arg, inner_idx);
				if !valid {
					continue;
				}
				let mut candidate = base.clone();
				candidate[inner_idx] = filtered;
				let mut claimed = taken.clone();
				claimed.push(inner_idx);
				next.push((candidate, claimed));
			}
		}
		if next.is_empty() {
			return Vec::new();
		}
		partials = next;
	}

	partials
		.into_iter()
		.map(|(arguments, _)| arguments)
		.map(|arguments| {
			Value::Primitive(Arc::new(Primitive {
				id: spec.rewrite.id,
				arguments,
				output: 0,
				instance_check: false,
			}))
		})
		.collect()
}

/// `G^x` from a base and an exponent.
fn partial(base: &Value, exponent: &Value) -> Value {
	Value::Equation(Arc::new(Equation {
		values: vec![
			if matches!(base, Value::Constant(_)) {
				base.clone()
			} else {
				value_g()
			},
			exponent.clone(),
		],
	}))
}

/// Merge a set of substitutions pairwise, keeping every consistent combination.
///
/// Used when one query needs several independent goals discharged in the *same*
/// session — the bindings must not contradict each other.
pub(crate) fn combine(left: &[Substitution], right: &[Substitution]) -> Vec<Substitution> {
	let mut out = Vec::new();
	for a in left {
		for b in right {
			// `merge` rather than `compose`: two partial solutions constraining
			// different parts of the same forged message must be unified into
			// one message, not rejected as contradictory.
			if let Some(merged) = super::matching::merge(a, b) {
				out.push(merged);
			}
		}
	}
	dedupe(out)
}
