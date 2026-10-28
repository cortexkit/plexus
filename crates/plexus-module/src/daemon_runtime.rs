//! The ck-plexus daemon Tokio runtime.
//!
//! The runtime's pool threads carry `plexus-rt-*` names so a profiler (macOS
//! `sample`, Linux `perf`) can identify the daemon runtime. Tokio shares the
//! naming callback between async workers and blocking threads; callback order
//! does not reliably identify a thread's role, so the names do not claim one.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// Name prefix for all daemon runtime pool threads (`plexus-rt-0`, ...).
pub const RUNTIME_THREAD_PREFIX: &str = "plexus-rt";

fn thread_name(sequence: usize) -> String {
    format!("{RUNTIME_THREAD_PREFIX}-{sequence}")
}

/// The daemon runtime builder: a multi-thread runtime with every driver
/// enabled and named worker and blocking threads. Thread counts are Tokio's
/// defaults, exactly as `#[tokio::main]` built before; only the names are new.
pub fn builder() -> tokio::runtime::Builder {
    let spawned = Arc::new(AtomicUsize::new(0));
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    builder.thread_name_fn(move || {
        let sequence = spawned.fetch_add(1, Ordering::SeqCst);
        thread_name(sequence)
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

    #[test]
    fn daemon_runtime_names_workers_and_blocking_threads_without_claiming_roles() {
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
        for (role, name) in [("async", worker), ("blocking", blocking)] {
            let sequence = name
                .strip_prefix("plexus-rt-")
                .and_then(|suffix| suffix.parse::<usize>().ok());
            assert!(
                sequence.is_some(),
                "{role} work runs on a numbered daemon runtime thread, got {name:?}",
            );
        }
    }

    #[test]
    fn thread_name_numbers_all_pool_threads_without_a_worker_boundary() {
        assert_eq!(thread_name(0), "plexus-rt-0");
        assert_eq!(thread_name(1), "plexus-rt-1");
        assert_eq!(thread_name(4), "plexus-rt-4");
        assert_eq!(thread_name(6), "plexus-rt-6");
    }
}
