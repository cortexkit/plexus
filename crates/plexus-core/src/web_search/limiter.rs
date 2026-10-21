//! In-memory token buckets for `web_search`: one per caller and one per
//! backend. State is per process and resets on restart, which is acceptable
//! for a per-minute limit: a restart forgets at most one minute of history.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

use crate::storage::web_search_store::WebSearchLimits;

/// Per-caller limit when the operator has set none for the backend.
pub const DEFAULT_PER_CALLER_PER_MINUTE: u32 = 30;
/// Whole-backend limit when the operator has set none for the backend.
pub const DEFAULT_PER_BACKEND_PER_MINUTE: u32 = 120;

const WINDOW_MS: f64 = 60_000.0;
/// Once this many caller buckets exist, full ones are dropped: a full bucket
/// behaves exactly like a missing one, so forgetting it changes nothing.
const PRUNE_THRESHOLD: usize = 10_000;
const PRUNE_INTERVAL_MS: i64 = 1_000;

pub fn default_limits() -> WebSearchLimits {
    WebSearchLimits {
        per_caller_per_minute: DEFAULT_PER_CALLER_PER_MINUTE,
        per_backend_per_minute: DEFAULT_PER_BACKEND_PER_MINUTE,
    }
}

/// Who a per-caller bucket belongs to: the module principal, plus the agent
/// when the daemon-provided route scope names an agent. Two agents behind one module
/// therefore get separate buckets, and neither can spend the other's.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallerKey {
    pub principal: String,
    pub agent_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum BucketKey {
    Caller { backend: String, caller: CallerKey },
    Backend { backend: String },
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    updated_ms: i64,
    capacity: u32,
}

impl Bucket {
    /// Refill for the time elapsed since the last update, capped at
    /// `capacity`. A capacity lowered by the operator takes effect at once.
    ///
    /// The clock is the wall clock, which can step backwards (an NTP
    /// correction, a manual change). A backward step refills nothing, and the
    /// bucket re-anchors at the new time so refill resumes from there. Keeping
    /// the later timestamp instead would freeze refill until real time caught
    /// up with it, refusing every search for the length of the step.
    fn refill(&mut self, capacity: u32, now_ms: i64) {
        self.capacity = capacity;
        let elapsed = now_ms.saturating_sub(self.updated_ms).max(0) as f64;
        let rate = f64::from(capacity) / WINDOW_MS;
        self.tokens = (self.tokens + elapsed * rate).min(f64::from(capacity));
        self.updated_ms = now_ms;
    }

    /// Milliseconds until one whole token is available; zero when it is now.
    fn wait_ms(&self, capacity: u32) -> u64 {
        if self.tokens >= 1.0 {
            return 0;
        }
        let rate = f64::from(capacity) / WINDOW_MS;
        ((1.0 - self.tokens) / rate).ceil().max(1.0) as u64
    }
}

pub struct RateLimiter {
    buckets: Mutex<HashMap<BucketKey, Bucket>>,
    last_pruned_ms: AtomicI64,
    #[cfg(test)]
    prune_visits: std::sync::atomic::AtomicUsize,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            last_pruned_ms: AtomicI64::new(i64::MIN),
            #[cfg(test)]
            prune_visits: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl RateLimiter {
    /// Take one token from the caller's bucket and one from the backend's, or
    /// neither. On refusal, return how long until both could be taken.
    ///
    /// Taking neither on refusal matters: a caller turned away by the backend
    /// cap must not also lose its own allowance, or a busy neighbour would
    /// drain it.
    pub fn try_acquire(
        &self,
        backend: &str,
        caller: &CallerKey,
        limits: WebSearchLimits,
        now_ms: i64,
    ) -> Result<(), u64> {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let last_pruned_ms = self.last_pruned_ms.load(Ordering::Relaxed);
        // A clock that stepped back behind the last scan counts as due, so a
        // backward step cannot postpone pruning for its whole length.
        if buckets.len() > PRUNE_THRESHOLD
            && (now_ms.saturating_sub(last_pruned_ms) >= PRUNE_INTERVAL_MS
                || now_ms < last_pruned_ms)
        {
            // The map lock serializes this timestamp with pruning. Refill each
            // backend at its own capacity, and scan at most once per second.
            self.last_pruned_ms.store(now_ms, Ordering::Relaxed);
            buckets.retain(|key, bucket| {
                #[cfg(test)]
                self.prune_visits.fetch_add(1, Ordering::Relaxed);
                matches!(key, BucketKey::Backend { .. }) || {
                    let mut copy = *bucket;
                    let capacity = copy.capacity;
                    copy.refill(capacity, now_ms);
                    copy.tokens < f64::from(capacity)
                }
            });
        }
        let caller_key = BucketKey::Caller {
            backend: backend.to_string(),
            caller: caller.clone(),
        };
        let backend_key = BucketKey::Backend {
            backend: backend.to_string(),
        };
        let pair = [
            (caller_key, limits.per_caller_per_minute),
            (backend_key, limits.per_backend_per_minute),
        ]
        .map(|(key, capacity)| {
            let mut bucket = buckets.get(&key).copied().unwrap_or(Bucket {
                tokens: f64::from(capacity),
                updated_ms: now_ms,
                capacity,
            });
            bucket.refill(capacity, now_ms);
            (key, capacity, bucket)
        });
        let wait = pair
            .iter()
            .map(|(_, capacity, bucket)| bucket.wait_ms(*capacity))
            .max()
            .unwrap_or(0);
        if wait > 0 {
            for (key, _, bucket) in pair {
                buckets.insert(key, bucket);
            }
            return Err(wait);
        }
        for (key, _, mut bucket) in pair {
            bucket.tokens -= 1.0;
            buckets.insert(key, bucket);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pruning_does_not_walk_the_map_on_every_call() {
        let limiter = RateLimiter::default();
        for index in 0..=PRUNE_THRESHOLD {
            limiter
                .try_acquire(
                    "exa",
                    &caller(&index.to_string(), None),
                    limits(1, 100_000),
                    0,
                )
                .unwrap();
        }
        let visits = limiter.prune_visits.load(Ordering::Relaxed);
        assert!(visits > 0, "the fixture must execute a real pruning scan");
        limiter
            .try_acquire("exa", &caller("late", None), limits(1, 100_000), 10)
            .unwrap();
        assert_eq!(
            limiter.prune_visits.load(Ordering::Relaxed),
            visits,
            "pruning must not revisit every bucket on each call"
        );
        limiter
            .try_acquire("exa", &caller("later", None), limits(1, 100_000), 1_000)
            .unwrap();
        assert!(limiter.prune_visits.load(Ordering::Relaxed) > visits);
    }

    #[test]
    fn pruning_does_not_reset_another_backends_allowance() {
        let limiter = RateLimiter::default();
        let who = caller("high", None);
        limiter
            .try_acquire("high", &who, limits(100, 100_000), 0)
            .unwrap();
        for index in 0..PRUNE_THRESHOLD {
            limiter
                .try_acquire(
                    "low",
                    &caller(&index.to_string(), None),
                    limits(1, 100_000),
                    0,
                )
                .unwrap();
        }
        for _ in 1..100 {
            limiter
                .try_acquire("high", &who, limits(100, 100_000), 0)
                .unwrap();
        }
        assert!(
            limiter
                .try_acquire("high", &who, limits(100, 100_000), 0)
                .is_err(),
            "pruning must preserve another backend's spent tokens"
        );
    }

    fn caller(principal: &str, agent: Option<&str>) -> CallerKey {
        CallerKey {
            principal: principal.to_string(),
            agent_id: agent.map(str::to_string),
        }
    }

    fn limits(per_caller: u32, per_backend: u32) -> WebSearchLimits {
        WebSearchLimits {
            per_caller_per_minute: per_caller,
            per_backend_per_minute: per_backend,
        }
    }

    #[test]
    fn a_caller_is_refused_past_its_allowance_and_refills_over_the_minute() {
        let limiter = RateLimiter::default();
        let one = caller("direct", None);
        for _ in 0..3 {
            limiter.try_acquire("exa", &one, limits(3, 100), 0).unwrap();
        }
        let wait = limiter
            .try_acquire("exa", &one, limits(3, 100), 0)
            .unwrap_err();
        assert_eq!(wait, 20_000, "one token of three per minute takes 20s");
        assert!(limiter
            .try_acquire("exa", &one, limits(3, 100), 19_999)
            .is_err());
        assert!(limiter
            .try_acquire("exa", &one, limits(3, 100), 20_000)
            .is_ok());
    }

    #[test]
    fn a_backward_clock_step_does_not_freeze_refill() {
        let limiter = RateLimiter::default();
        let one = caller("direct", None);
        let later = 10_000_000;
        for _ in 0..3 {
            limiter
                .try_acquire("exa", &one, limits(3, 100), later)
                .unwrap();
        }
        // The wall clock steps back by far more than a minute.
        let stepped_back = later - 5_000_000;
        assert!(limiter
            .try_acquire("exa", &one, limits(3, 100), stepped_back)
            .is_err());
        // A third of a minute after the step one token has refilled, as it
        // would have without the step.
        assert!(
            limiter
                .try_acquire("exa", &one, limits(3, 100), stepped_back + 20_000)
                .is_ok(),
            "refill must resume from the stepped-back time"
        );
    }

    #[test]
    fn agents_behind_one_principal_have_separate_buckets() {
        let limiter = RateLimiter::default();
        limiter
            .try_acquire("exa", &caller("m", Some("a")), limits(1, 100), 0)
            .unwrap();
        assert!(limiter
            .try_acquire("exa", &caller("m", Some("a")), limits(1, 100), 0)
            .is_err());
        assert!(limiter
            .try_acquire("exa", &caller("m", Some("b")), limits(1, 100), 0)
            .is_ok());
        assert!(limiter
            .try_acquire("exa", &caller("m", None), limits(1, 100), 0)
            .is_ok());
    }

    #[test]
    fn a_backend_refusal_spends_nothing_from_the_caller() {
        let limiter = RateLimiter::default();
        limiter
            .try_acquire("exa", &caller("a", None), limits(5, 1), 0)
            .unwrap();
        assert_eq!(
            limiter.try_acquire("exa", &caller("b", None), limits(5, 1), 0),
            Err(60_000)
        );
        let buckets = limiter.buckets.lock().unwrap();
        let b = buckets[&BucketKey::Caller {
            backend: "exa".to_string(),
            caller: caller("b", None),
        }];
        assert_eq!(
            b.tokens, 5.0,
            "the refused caller keeps its whole allowance"
        );
    }
}
