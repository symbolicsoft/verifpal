/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::types::*;

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
	lock.read().unwrap_or_else(|e| e.into_inner())
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
	lock.write().unwrap_or_else(|e| e.into_inner())
}

thread_local! {
	static ANALYSIS_COUNT: Cell<u32> = const { Cell::new(0) };
	static CURRENT_GENERATION: Cell<u64> = const { Cell::new(0) };
}

static ANALYSIS_GENERATION: AtomicU64 = AtomicU64::new(0);

static LIVE_GENERATIONS: RwLock<Vec<u64>> = RwLock::new(Vec::new());

#[cfg(feature = "cli")]
pub(crate) fn live_generations() -> usize {
	read_lock(&LIVE_GENERATIONS).len()
}

pub(crate) fn next_generation() -> u64 {
	ANALYSIS_GENERATION.fetch_add(1, Ordering::Relaxed) + 1
}

pub(crate) fn enter_generation(generation: u64) {
	CURRENT_GENERATION.with(|g| g.set(generation));
}

pub(crate) fn current_generation() -> u64 {
	CURRENT_GENERATION.with(|g| g.get())
}

pub(crate) struct GenerationGuard(u64);

impl GenerationGuard {
	pub(crate) fn enter() -> GenerationGuard {
		let generation = next_generation();
		write_lock(&LIVE_GENERATIONS).push(generation);
		enter_generation(generation);
		GenerationGuard(generation)
	}
}

impl Drop for GenerationGuard {
	fn drop(&mut self) {
		write_lock(&LIVE_GENERATIONS).retain(|&live| live != self.0);
	}
}

pub(crate) struct Generational<T> {
	generation: u64,
	inner: T,
}

impl<T: Default> Default for Generational<T> {
	fn default() -> Self {
		Generational {
			generation: 0,
			inner: T::default(),
		}
	}
}

impl<T: Default> Generational<T> {
	pub(crate) fn fresh(&mut self) -> &mut T {
		let now = current_generation();
		if self.generation != now {
			self.generation = now;
			self.inner = T::default();
		}
		&mut self.inner
	}
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct KnowledgeKey {
	chain: u64,
	known: usize,
	phase: i32,
	reused: usize,
}

impl KnowledgeKey {
	pub(crate) fn of(attacker: &AttackerState) -> KnowledgeKey {
		KnowledgeKey {
			chain: attacker.chain,
			known: attacker.known.len(),
			phase: attacker.current_phase,
			reused: attacker.reused.len(),
		}
	}
}

const RECENT_GROUPS: usize = 8;

pub(crate) struct Recent<G, K, V> {
	groups: Vec<(G, IdMap<K, V>)>,
}

impl<G, K, V> Default for Recent<G, K, V> {
	fn default() -> Self {
		Recent { groups: Vec::new() }
	}
}

impl<G: PartialEq, K: std::hash::Hash + Eq, V> Recent<G, K, V> {
	pub(crate) fn group(&mut self, group: G) -> &mut IdMap<K, V> {
		match self.groups.iter().position(|(seen, _)| *seen == group) {
			Some(0) => {}
			Some(at) => {
				let found = self.groups.remove(at);
				self.groups.insert(0, found);
			}
			None => {
				self.groups.truncate(RECENT_GROUPS - 1);
				self.groups.insert(0, (group, IdMap::default()));
			}
		}
		&mut self.groups[0].1
	}
}

pub(crate) fn analysis_count_get() -> usize {
	ANALYSIS_COUNT.with(|c| c.get()) as usize
}

fn analysis_count_reset() {
	ANALYSIS_COUNT.with(|c| c.set(0));
}

pub(crate) struct VerifyContext {
	results: RwLock<Vec<VerifyResult>>,
	unresolved: AtomicUsize,
	file_name: String,
	truncations: RwLock<BTreeMap<Truncation, Vec<usize>>>,
	sessions: u8,
	corrupt_from: Option<IdMap<PrincipalId, i32>>,
	scenarios: Vec<ScenarioSummary>,
	assumptions: Vec<(Value, Capability, i32)>,
	basis: RwLock<(u64, i32, usize, crate::hashing::TermSet)>,
	term_bound: std::sync::OnceLock<crate::solve::control::TermBound>,
	cancel: Arc<AtomicBool>,
}

impl VerifyContext {
	pub(crate) fn new(
		m: &Model,
		variants: Vec<Vec<Query>>,
		sessions: u8,
		corrupt_from: Option<IdMap<PrincipalId, i32>>,
		scenarios: Vec<ScenarioSummary>,
		assumptions: Vec<(Value, Capability, i32)>,
	) -> Self {
		let results: Vec<VerifyResult> = m
			.queries
			.iter()
			.enumerate()
			.map(|(i, q)| {
				let mut r = VerifyResult::new(q, i);
				r.variants = variants.get(i).cloned().unwrap_or_default();
				r
			})
			.collect();
		analysis_count_reset();
		VerifyContext {
			unresolved: AtomicUsize::new(results.len()),
			results: RwLock::new(results),
			file_name: m.file_name.clone(),
			truncations: RwLock::new(BTreeMap::new()),
			sessions,
			corrupt_from,
			scenarios,
			assumptions,
			basis: RwLock::new((0, -1, 0, crate::hashing::TermSet::default())),
			term_bound: std::sync::OnceLock::new(),
			cancel: Arc::new(AtomicBool::new(false)),
		}
	}

	pub(crate) fn set_cancel(&mut self, cancel: Arc<AtomicBool>) {
		self.cancel = cancel;
	}

	pub(crate) fn cancelled(&self) -> bool {
		self.cancel.load(Ordering::Relaxed)
	}

	pub(crate) fn note_truncation(&self, kind: Truncation) {
		if read_lock(&self.truncations).contains_key(&kind) {
			return;
		}
		let outstanding: Vec<usize> = read_lock(&self.results)
			.iter()
			.filter(|result| !result.resolved)
			.map(|result| result.query_index)
			.collect();
		write_lock(&self.truncations)
			.entry(kind)
			.or_insert(outstanding);
	}

	pub(crate) fn claims_at(&self, principal: PrincipalId, phase: i32) -> Option<i32> {
		let Some(corrupt_from) = self.corrupt_from.as_ref().filter(|c| !c.is_empty()) else {
			return Some(phase);
		};
		let &from = corrupt_from.get(&principal)?;
		Some(phase.min(from - 1))
	}

	pub(crate) fn is_honest_at(&self, principal: PrincipalId, phase: i32) -> bool {
		self.corrupt_from.as_ref().is_none_or(|corrupt_from| {
			corrupt_from
				.get(&principal)
				.is_some_and(|&corrupt_from| phase < corrupt_from)
		})
	}

	pub(crate) fn scenarios(&self) -> &[ScenarioSummary] {
		&self.scenarios
	}

	#[cfg(test)]
	pub(crate) fn truncations(&self) -> Vec<Truncation> {
		read_lock(&self.truncations).keys().copied().collect()
	}

	pub(crate) fn finalize_envelopes(&self) {
		let truncations = read_lock(&self.truncations).clone();
		for vr in write_lock(&self.results).iter_mut() {
			vr.envelope = Envelope {
				sessions: self.sessions,
				truncations: truncations
					.iter()
					.filter(|(_, reached)| reached.contains(&vr.query_index))
					.map(|(&kind, _)| kind)
					.collect(),
			};
		}
	}

	pub(crate) fn term_bound(&self, km: &ProtocolTrace) -> &crate::solve::control::TermBound {
		self.term_bound
			.get_or_init(|| crate::solve::control::TermBound::of(km))
	}

	pub(crate) fn known_subterms(&self, attacker: &AttackerState) -> crate::hashing::TermSet {
		let mut basis = write_lock(&self.basis);
		let (chain, phase, covered, set) = &mut *basis;
		if *chain != attacker.chain
			|| *phase != attacker.current_phase
			|| *covered > attacker.known.len()
		{
			*chain = attacker.chain;
			*phase = attacker.current_phase;
			*covered = 0;
			set.clear();
		}
		for known in &attacker.known[*covered..] {
			crate::hashing::collect_subterms(known, set);
		}
		*covered = attacker.known.len();
		set.clone()
	}

	pub(crate) fn assumptions(&self) -> &[(Value, Capability, i32)] {
		&self.assumptions
	}

	pub(crate) fn results_get(&self) -> Vec<VerifyResult> {
		read_lock(&self.results).clone()
	}

	pub(crate) fn results_file_name(&self) -> &str {
		&self.file_name
	}

	pub(crate) fn results_put(
		&self,
		result: &VerifyResult,
		_verdict: &crate::engine::query::Verdict,
	) -> bool {
		let mut state = write_lock(&self.results);
		if let Some(vr) = state.get_mut(result.query_index)
			&& !vr.resolved
		{
			vr.resolved = result.resolved;
			vr.summary = result.summary.clone();
			vr.conclusion = result.conclusion.clone();
			vr.subtype = result.subtype;
			vr.trace = result.trace.clone();
			vr.notes = result.notes.clone();
			vr.steps = result.steps.clone();
			vr.options = result.options.clone();
			if result.resolved {
				self.unresolved.fetch_sub(1, Ordering::SeqCst);
			}
			return true;
		}
		false
	}

	pub(crate) fn query_counts(&self) -> (usize, usize) {
		let total = read_lock(&self.results).len();
		(total - self.unresolved.load(Ordering::SeqCst), total)
	}

	pub(crate) fn all_resolved(&self) -> bool {
		self.unresolved.load(Ordering::SeqCst) == 0
	}

	pub(crate) fn analysis_count_increment(&self) {
		if !crate::info::info_is_quiet() {
			ANALYSIS_COUNT.with(|c| c.set(c.get() + 1));
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::parser::parse_string;
	use std::sync::Arc;

	#[test]
	fn a_cancelled_analysis_returns_an_error_and_no_results() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private cx_a\n\
			cx_ga = PUBKEY(cx_a)\n\
			]\n\
			Alice -> Bob: cx_ga\n\
			principal Bob[\n\
			knows private cx_b\n\
			cx_gb = PUBKEY(cx_b)\n\
			cx_k = DH_KEX(cx_ga, cx_b)\n\
			generates cx_m, cx_n\n\
			cx_e = AEAD_ENC(cx_k, cx_n, cx_m, nil)\n\
			]\n\
			Bob -> Alice: cx_gb, cx_n, cx_e\n\
			queries[\n\
			confidentiality? cx_m\n\
			]\n";
		let m = parse_string("cx.vp", src).expect("parses");

		let cancel = Arc::new(AtomicBool::new(true));
		let outcome = crate::verify::analyze_sessions_cancellable(&m, 1, cancel);

		let err = outcome.err().expect("a cancelled analysis is an error");
		assert_eq!(err.kind, ErrorKind::Cancelled);
	}

	#[test]
	fn an_uncancelled_analysis_still_succeeds() {
		let src = "attacker[passive]\n\
			principal Alice[\n\
			knows private cy_m\n\
			cy_h = HASH(cy_m)\n\
			]\n\
			Alice -> Bob: cy_h\n\
			principal Bob[\n\
			_ = HASH(cy_h)\n\
			]\n\
			queries[\n\
			confidentiality? cy_m\n\
			]\n";
		let m = parse_string("cy.vp", src).expect("parses");
		let cancel = Arc::new(AtomicBool::new(false));
		let ctx = crate::verify::analyze_sessions_cancellable(&m, 1, cancel)
			.expect("an uncancelled analysis succeeds");
		assert_eq!(ctx.results_get().len(), 1);
	}

	#[test]
	fn cancelling_mid_run_yields_no_verdicts_at_all() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private cz_a\n\
			cz_ga = PUBKEY(cz_a)\n\
			]\n\
			Alice -> Bob: cz_ga\n\
			principal Bob[\n\
			knows private cz_b\n\
			cz_gb = PUBKEY(cz_b)\n\
			cz_k = DH_KEX(cz_ga, cz_b)\n\
			generates cz_m, cz_n\n\
			cz_e = AEAD_ENC(cz_k, cz_n, cz_m, nil)\n\
			]\n\
			Bob -> Alice: cz_gb, cz_n, cz_e\n\
			principal Alice[\n\
			cz_k2 = DH_KEX(cz_gb, cz_a)\n\
			cz_d = AEAD_DEC(cz_k2, cz_n, cz_e, nil)\n\
			]\n\
			queries[\n\
			confidentiality? cz_m\n\
			authentication? Bob -> Alice: cz_e\n\
			]\n";
		let cancel = Arc::new(AtomicBool::new(false));
		let flag = Arc::clone(&cancel);

		let worker = std::thread::spawn(move || {
			let m = parse_string("cz.vp", src).expect("parses");
			crate::verify::analyze_sessions_cancellable(&m, 1, cancel).map(|ctx| ctx.results_get())
		});
		flag.store(true, Ordering::Relaxed);

		match worker.join().expect("the worker did not panic") {
			Ok(results) => assert_eq!(results.len(), 2),
			Err(e) => assert_eq!(e.kind, ErrorKind::Cancelled),
		}
	}

	#[test]
	fn a_context_with_no_truncation_reports_an_exhausted_search() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private trc_m\n\
			knows private trc_k\n\
			trc_e = ENC(trc_k, trc_m)\n\
			]\n\
			queries[\n\
			confidentiality? trc_m\n\
			]\n";
		let m = parse_string("trc.vp", src).expect("parse");
		let ctx = VerifyContext::new(&m, Vec::new(), 2, None, Vec::new(), Vec::new());
		ctx.finalize_envelopes();
		assert!(ctx.truncations().is_empty());
		assert!(ctx.results_get()[0].envelope.exhausted());
		assert_eq!(ctx.results_get()[0].envelope.sessions, 2);
	}

	#[test]
	fn a_depth_cut_truncates_the_search() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private tdc_m\n\
			knows private tdc_k\n\
			tdc_e = ENC(tdc_k, tdc_m)\n\
			]\n\
			queries[\n\
			confidentiality? tdc_m\n\
			]\n";
		let m = parse_string("tdc.vp", src).expect("parse");
		let ctx = VerifyContext::new(&m, Vec::new(), 2, None, Vec::new(), Vec::new());
		ctx.note_truncation(Truncation::TermDepth);
		ctx.finalize_envelopes();
		assert_eq!(ctx.truncations(), vec![Truncation::TermDepth]);
		assert!(!ctx.results_get()[0].envelope.exhausted());
	}

	#[test]
	fn a_depth_cut_qualifies_only_the_queries_it_could_still_have_answered() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private tdq_m\n\
			knows private tdq_n\n\
			knows private tdq_k\n\
			tdq_e = ENC(tdq_k, tdq_m)\n\
			tdq_f = ENC(tdq_k, tdq_n)\n\
			leaks tdq_m\n\
			]\n\
			queries[\n\
			confidentiality? tdq_m\n\
			confidentiality? tdq_n\n\
			]\n";
		let m = parse_string("tdq.vp", src).expect("parse");
		let ctx = VerifyContext::new(&m, Vec::new(), 2, None, Vec::new(), Vec::new());
		let mut resolved = crate::types::VerifyResult::new(&m.queries[0], 0);
		resolved.resolved = true;
		assert!(ctx.results_put(&resolved, &crate::engine::query::Verdict::for_test()));
		ctx.note_truncation(Truncation::TermDepth);
		ctx.finalize_envelopes();
		let results = ctx.results_get();
		assert!(
			results[0].envelope.exhausted(),
			"the first query was already answered when the search turned a term away, so \
			 that refusal cost it nothing and its verdict must not be qualified by it"
		);
		assert!(
			!results[1].envelope.exhausted(),
			"the second query was still open, so the term the search declined is a term it \
			 never got to try against this query and the hold has to say so"
		);
	}

	#[test]
	fn only_an_honest_run_records_a_verdict_unless_every_scenario_is_corrupt() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private cat_m\n\
			knows private cat_k\n\
			cat_e = ENC(cat_k, cat_m)\n\
			]\n\
			queries[\n\
			confidentiality? cat_m\n\
			]\n";
		let m = parse_string("cat.vp", src).expect("parse");

		let plain = VerifyContext::new(&m, Vec::new(), 2, None, Vec::new(), Vec::new());
		assert_eq!(plain.claims_at(1, 0), Some(0));
		assert_eq!(plain.claims_at(9, 1), Some(1));

		let mut honest: IdMap<PrincipalId, i32> = IdMap::default();
		honest.insert(1, i32::MAX);
		honest.insert(3, 2);
		let mixed = VerifyContext::new(&m, Vec::new(), 2, Some(honest), Vec::new(), Vec::new());
		assert_eq!(mixed.claims_at(1, 0), Some(0));
		assert_eq!(mixed.claims_at(2, 0), None);
		assert_eq!(mixed.claims_at(3, 1), Some(1));
		assert_eq!(
			mixed.claims_at(3, 2),
			Some(1),
			"a run corrupt from a later phase answers for what it held while honest"
		);

		let corrupt = VerifyContext::new(
			&m,
			Vec::new(),
			2,
			Some(IdMap::default()),
			Vec::new(),
			Vec::new(),
		);
		assert_eq!(
			corrupt.claims_at(2, 0),
			Some(0),
			"a model with nothing honest to relativise against must not hold vacuously"
		);
		assert!(
			!corrupt.is_honest_at(2, 0),
			"the honest-run check stays relaxed there even so"
		);
	}

	#[test]
	fn finalizing_envelopes_never_resolves_a_query() {
		let src = "attacker[active]\n\
			principal Alice[\n\
			knows private fev_m\n\
			knows private fev_k\n\
			fev_e = ENC(fev_k, fev_m)\n\
			]\n\
			queries[\n\
			confidentiality? fev_m\n\
			]\n";
		let m = parse_string("fev.vp", src).expect("parse");
		let ctx = VerifyContext::new(&m, Vec::new(), 2, None, Vec::new(), Vec::new());
		assert!(!ctx.all_resolved());
		ctx.finalize_envelopes();
		assert!(!ctx.all_resolved());
		assert!(!ctx.results_get()[0].resolved);
		assert_eq!(ctx.results_get()[0].summary, "");
	}
}
