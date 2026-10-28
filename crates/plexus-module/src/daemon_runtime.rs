//! The ck-plexus daemon Tokio runtime.
//!
//! The runtime's worker and blocking-pool threads carry distinct `plexus-*`
//! names so a profiler (macOS `sample`, Linux `perf`) can tell the daemon's
//! async workers apart from the threads running its blocking store and vendor
//! calls. Tokio starts multi-thread workers through the same pool — and the
//! same name closure — as blocking threads, so the closure numbers pool
//! threads in spawn order: the workers all start first while the runtime is
//! being built, and every thread spawned after that is a blocking thread.
//! Threads that `block_in_place` spawns to cover a worker also draw from the
//! blocking side of the numbering, which is where their CPU belongs.

use std::num::NonZeroUsize;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// Name prefix for the runtime's async worker threads (`plexus-worker-0`, ...).
pub const WORKER_THREAD_PREFIX: &str = "plexus-worker";
/// Name prefix for the runtime's blocking-pool threads (`plexus-blocking-0`, ...).
pub const BLOCKING_THREAD_PREFIX: &str = "plexus-blocking";

/// Name the pool thread with spawn `sequence` when the runtime starts
/// `worker_threads` workers at build time. Kept pure so tests can pin the
/// worker/blocking split without starting a runtime.
fn thread_name(sequence: usize, worker_threads: usize) -> String {
    if sequence < worker_threads {
        format!("{WORKER_THREAD_PREFIX}-{sequence}")
    } else {
        format!("{BLOCKING_THREAD_PREFIX}-{}", sequence - worker_threads)
    }
}

/// How many workers the daemon runtime starts: Tokio's own default, which is
/// `TOKIO_WORKER_THREADS` when that parses as a positive number and the
/// machine's parallelism otherwise. Read here only so the naming closure below
/// knows how many of the first-spawned pool threads are workers; the worker
/// count itself stays Tokio's default, so thread counts cannot drift from it.
fn default_worker_threads() -> usize {
    std::env::var("TOKIO_WORKER_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, NonZeroUsize::get))
}

/// The daemon runtime builder: a multi-thread runtime with every driver
/// enabled and named worker and blocking threads. Thread counts are Tokio's
/// defaults, exactly as `#[tokio::main]` built before; only the names are new.
pub fn builder() -> tokio::runtime::Builder {
    let worker_threads = default_worker_threads();
    let spawned = Arc::new(AtomicUsize::new(0));
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    builder.thread_name_fn(move || {
        let sequence = spawned.fetch_add(1, Ordering::SeqCst);
        thread_name(sequence, worker_threads)
    });
    builder
}

/// Build the daemon runtime. Fails only when the OS refuses the threads, in
/// which case there is no daemon to run.
pub fn build() -> std::io::Result<tokio::runtime::Runtime> {
    builder().build()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worker/blocking split is a naming convention, not a type: without
    /// the `thread_name_fn` above both sides read `tokio-rt-worker` and a
    /// profile cannot separate them.
    #[test]
    fn daemon_runtime_names_workers_and_blocking_threads_distinctly() {
        let runtime = build().expect("daemon test runtime builds");
        let worker = runtime.block_on(async {
            // `block_on` polls its future on the calling thread, so hop onto
            // the pool to observe a worker thread's name.
            tokio::task::spawn(async {
                std::thread::current()
                    .name()
                    .unwrap_or("<unnamed>")
                    .to_string()
            })
            .await
            .expect("worker probe runs")
        });
        let blocking = runtime.block_on(async {
            tokio::task::spawn_blocking(|| {
                std::thread::current()
                    .name()
                    .unwrap_or("<unnamed>")
                    .to_string()
            })
            .await
            .expect("blocking probe runs")
        });
        assert!(
            worker.starts_with(WORKER_THREAD_PREFIX),
            "async work runs on a daemon worker thread, got {worker:?}",
        );
        assert!(
            blocking.starts_with(BLOCKING_THREAD_PREFIX),
            "blocking work runs on a daemon blocking thread, got {blocking:?}",
        );
    }

    #[test]
    fn thread_name_numbers_workers_first_then_blocking() {
        assert_eq!(thread_name(0, 4), "plexus-worker-0");
        assert_eq!(thread_name(3, 4), "plexus-worker-3");
        assert_eq!(thread_name(4, 4), "plexus-blocking-0");
        assert_eq!(thread_name(6, 4), "plexus-blocking-2");
    }
}
