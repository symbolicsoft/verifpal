/* SPDX-FileCopyrightText: (c) 2019-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: GPL-3.0-only */

#[cfg(feature = "cli")]
mod pool {
	use std::sync::LazyLock;

	static POOL: LazyLock<rayon::ThreadPool> = LazyLock::new(|| build(configured_threads()));

	fn configured_threads() -> usize {
		std::env::var("VERIFPAL_THREADS")
			.ok()
			.and_then(|threads| threads.parse::<usize>().ok())
			.filter(|&threads| threads >= 1)
			.unwrap_or_else(|| {
				std::thread::available_parallelism()
					.map(|threads| threads.get())
					.unwrap_or(1)
			})
	}

	pub(super) fn build(threads: usize) -> rayon::ThreadPool {
		rayon::ThreadPoolBuilder::new()
			.num_threads(threads)
			.thread_name(|index| format!("verifpal-worker-{index}"))
			.start_handler(|_| crate::info::set_verbosity(crate::info::Verbosity::Silent))
			.build()
			.expect("a thread pool builds")
	}

	pub(super) fn current() -> &'static rayon::ThreadPool {
		&POOL
	}
}

#[cfg(feature = "cli")]
fn threads() -> usize {
	if rayon::current_thread_index().is_some() {
		rayon::current_num_threads()
	} else {
		pool::current().current_num_threads()
	}
}

#[cfg(feature = "cli")]
pub(crate) fn map_ordered<T: Send, R: Send>(
	items: Vec<T>,
	f: impl Fn(T) -> R + Sync + Send,
) -> Vec<R> {
	use rayon::prelude::*;
	if items.len() < 2 || threads() == 1 {
		return items.into_iter().map(f).collect();
	}
	let generation = crate::context::current_generation();
	let run = |item: T| {
		crate::context::enter_generation(generation);
		f(item)
	};
	if rayon::current_thread_index().is_some() {
		return items.into_par_iter().map(run).collect();
	}
	if crate::context::live_generations() > 1 {
		return items.into_iter().map(f).collect();
	}
	pool::current().install(|| items.into_par_iter().map(run).collect())
}

#[cfg(all(feature = "cli", test))]
pub(crate) fn with_threads<R: Send>(threads: usize, f: impl FnOnce() -> R + Send) -> R {
	let generation = crate::context::current_generation();
	pool::build(threads.max(1)).install(move || {
		crate::context::enter_generation(generation);
		f()
	})
}

#[cfg(not(feature = "cli"))]
pub(crate) fn map_ordered<T, R>(items: Vec<T>, f: impl Fn(T) -> R) -> Vec<R> {
	items.into_iter().map(f).collect()
}

#[cfg(all(not(feature = "cli"), test))]
pub(crate) fn with_threads<R>(_threads: usize, f: impl FnOnce() -> R) -> R {
	f()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn map_ordered_preserves_order_and_length() {
		let items: Vec<usize> = (0..10_000).collect();
		let out = map_ordered(items.clone(), |i| i * 2);
		assert_eq!(out.len(), items.len());
		assert!(out.iter().enumerate().all(|(i, &v)| v == i * 2));
	}

	#[test]
	fn map_ordered_is_the_same_under_one_thread_and_many() {
		let items: Vec<u64> = (0..5_000).collect();
		let one = with_threads(1, || {
			map_ordered(items.clone(), |i| i.wrapping_mul(0x9E37_79B9))
		});
		let many = with_threads(4, || {
			map_ordered(items.clone(), |i| i.wrapping_mul(0x9E37_79B9))
		});
		assert_eq!(one, many);
	}

	#[test]
	fn workers_are_silent() {
		let seen = with_threads(4, || {
			map_ordered(vec![(); 64], |()| crate::info::verbosity())
		});
		assert!(
			seen.iter()
				.all(|level| *level == crate::info::Verbosity::Silent)
		);
	}

	#[test]
	fn workers_run_under_the_callers_analysis_generation() {
		let generation = crate::context::next_generation();
		crate::context::enter_generation(generation);
		let seen = with_threads(4, || {
			map_ordered(vec![(); 64], |()| crate::context::current_generation())
		});
		assert!(seen.iter().all(|g| *g == generation));
	}

	#[cfg(feature = "cli")]
	#[test]
	fn a_single_thread_setting_disables_the_pool() {
		assert_eq!(with_threads(1, threads), 1);
	}

	#[cfg(feature = "cli")]
	#[test]
	fn an_analysis_is_identical_under_one_thread_and_many() {
		for model in ["examples/test/exa.vp", "examples/transport-layer/piknik.vp"] {
			let one = with_threads(1, || crate::verify::verify_report(model, 2)).expect("analyses");
			let many =
				with_threads(4, || crate::verify::verify_report(model, 2)).expect("analyses");
			assert_eq!(one.code, many.code, "{model}");
			assert_eq!(one.results.len(), many.results.len(), "{model}");
			for (a, b) in one.results.iter().zip(many.results.iter()) {
				assert_eq!(a.resolved, b.resolved, "{model}");
				assert_eq!(a.subtype, b.subtype, "{model}");
				assert_eq!(a.summary, b.summary, "{model}");
				assert_eq!(a.conclusion, b.conclusion, "{model}");
				assert_eq!(a.trace, b.trace, "{model}");
				assert_eq!(a.notes, b.notes, "{model}");
			}
		}
	}

	#[test]
	fn everything_a_worker_borrows_is_sync() {
		fn assert_sync<T: Sync>() {}
		assert_sync::<crate::context::VerifyContext>();
		assert_sync::<crate::types::ProtocolTrace>();
		assert_sync::<crate::types::PrincipalState>();
		assert_sync::<crate::types::AttackerState>();
		assert_sync::<crate::solve::symbolic::SymbolicState>();
		assert_sync::<crate::types::Value>();
		assert_sync::<crate::reexec::TermBound>();
	}
}
