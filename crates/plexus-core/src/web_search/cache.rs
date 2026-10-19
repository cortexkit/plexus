//! A small in-memory result cache for `web_search`.
//!
//! Entries are shared across callers because search results are public data.
//! Sharing is safe only because a hit never skips governance: the caller's
//! grants are checked and its rate limit is charged before a hit is served.
//! In chain mode the entry also records the serving provider, and a hit is
//! served only to a caller who could use that provider right now.

use std::collections::HashMap;
use std::sync::Mutex;

use super::backend::WebSearchResult;
use super::query::{Recency, WebSearchQuery};

/// How long an entry is served.
pub const CACHE_TTL_MS: i64 = 10 * 60 * 1000;
/// Most entries held at once.
pub const CACHE_CAPACITY: usize = 1_000;
/// Maximum result heap storage retained for one key. Oversized replies are still served,
/// but not retained across calls; titles and URLs are never truncated.
const MAX_ENTRY_TEXT_BYTES: usize = 64 * 1024;

/// Everything that changes what the vendor would return. The query is trimmed
/// and case-folded, the domains are already sorted, and `max_results` is the
/// effective value, so the default and an explicit 8 share one entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    backend: String,
    query: String,
    include_domains: Vec<String>,
    max_results: u8,
    recency: Option<Recency>,
}

/// The backend component of every chain-mode key. Any provider in the order
/// may have served the entry, so the key cannot name one; the entry records
/// which provider did. No provider is named `chain`, so chain keys never
/// collide with the compatibility keys, which carry the backend's own name.
pub const CHAIN_CACHE_BACKEND: &str = "chain";

impl CacheKey {
    pub fn new(backend: &str, query: &WebSearchQuery) -> Self {
        Self {
            backend: backend.to_string(),
            query: query.query.trim().to_lowercase(),
            include_domains: query.include_domains.clone(),
            max_results: query.max_results,
            recency: query.recency,
        }
    }
}

struct Entry {
    results: Vec<WebSearchResult>,
    stored_at_ms: i64,
    served: Option<ServedBy>,
}

/// Which provider produced a chain-mode entry. Compatibility entries have
/// none: their key already names the one backend.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ServedBy {
    /// The provider's order name.
    pub provider: String,
    /// For a provider whose endpoint is set per connection (SearXNG), the
    /// SHA-256 hex digest of the serving connection's normalized instance URL.
    /// Results from one instance must never answer a caller on another. It is
    /// compared only, never printed, so the address stays out of every log.
    pub instance_digest: Option<String>,
}

/// A chain-mode entry as a hit candidate.
pub(crate) struct ServedEntry {
    pub results: Vec<WebSearchResult>,
    pub served: ServedBy,
}

#[derive(Default)]
pub struct ResultCache {
    entries: Mutex<HashMap<CacheKey, Entry>>,
}

impl ResultCache {
    /// The cached results for `key`, if stored less than the TTL ago. Each
    /// result keeps the `fetched_at` of the vendor reply it came from.
    pub fn get(&self, key: &CacheKey, now_ms: i64) -> Option<Vec<WebSearchResult>> {
        self.live(key, now_ms, |entry| entry.results.clone())
    }

    /// The live chain-mode entry for `key` with the provider that served it.
    /// An entry stored without a serving provider is never a chain hit.
    pub(crate) fn get_served(&self, key: &CacheKey, now_ms: i64) -> Option<ServedEntry> {
        self.live(key, now_ms, |entry| {
            entry.served.clone().map(|served| ServedEntry {
                results: entry.results.clone(),
                served,
            })
        })
        .flatten()
    }

    fn live<R>(&self, key: &CacheKey, now_ms: i64, read: impl FnOnce(&Entry) -> R) -> Option<R> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match entries.get(key) {
            Some(entry) if now_ms.saturating_sub(entry.stored_at_ms) < CACHE_TTL_MS => {
                Some(read(entry))
            }
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        }
    }

    /// Store results, making room first: expired entries go, then the oldest
    /// entry if the cache is still full.
    pub fn put(&self, key: CacheKey, results: Vec<WebSearchResult>, now_ms: i64) {
        self.insert(key, results, None, now_ms);
    }

    /// Store a chain-mode entry with the provider that served it. A later
    /// serve of the same key replaces it, whichever provider served.
    pub(crate) fn put_served(
        &self,
        key: CacheKey,
        results: Vec<WebSearchResult>,
        served: ServedBy,
        now_ms: i64,
    ) {
        self.insert(key, results, Some(served), now_ms);
    }

    fn insert(
        &self,
        key: CacheKey,
        results: Vec<WebSearchResult>,
        served: Option<ServedBy>,
        now_ms: i64,
    ) {
        let bytes = results.iter().fold(
            results
                .capacity()
                .saturating_mul(std::mem::size_of::<WebSearchResult>()),
            |bytes, result| {
                bytes
                    .saturating_add(result.url.capacity())
                    .saturating_add(result.title.capacity())
                    .saturating_add(result.excerpt.capacity())
                    .saturating_add(result.fetched_at.capacity())
                    .saturating_add(result.published_at.as_ref().map_or(0, String::capacity))
            },
        );
        if bytes > MAX_ENTRY_TEXT_BYTES {
            return;
        }
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !entries.contains_key(&key) && entries.len() >= CACHE_CAPACITY {
            entries.retain(|_, entry| now_ms.saturating_sub(entry.stored_at_ms) < CACHE_TTL_MS);
            if entries.len() >= CACHE_CAPACITY {
                if let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.stored_at_ms)
                    .map(|(key, _)| key.clone())
                {
                    entries.remove(&oldest);
                }
            }
        }
        entries.insert(
            key,
            Entry {
                results,
                stored_at_ms: now_ms,
                served,
            },
        );
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_vendor_fields_are_not_retained() {
        let cache = ResultCache::default();
        let key = CacheKey::new("exa", &query("oversized", 8));
        let mut reply = result("https://a.example/");
        reply.title = "x".repeat(MAX_ENTRY_TEXT_BYTES + 1);
        cache.put(key.clone(), vec![reply], 0);
        assert!(
            cache.get(&key, 0).is_none(),
            "oversized vendor fields must not be retained"
        );
    }

    #[test]
    #[ignore = "performance measurement"]
    fn measure_full_cache_inserts() {
        let cache = ResultCache::default();
        for index in 0..CACHE_CAPACITY {
            cache.put(
                CacheKey::new("exa", &query(&format!("q{index}"), 8)),
                vec![],
                index as i64,
            );
        }
        let started = std::time::Instant::now();
        for index in CACHE_CAPACITY..CACHE_CAPACITY + 10_000 {
            cache.put(
                CacheKey::new("exa", &query(&format!("q{index}"), 8)),
                vec![],
                index as i64,
            );
        }
        println!("10,000 full-cache inserts: {:?}", started.elapsed());
        assert_eq!(cache.len(), CACHE_CAPACITY);
    }

    fn query(text: &str, max_results: u8) -> WebSearchQuery {
        WebSearchQuery {
            query: text.to_string(),
            max_results,
            include_domains: vec![],
            recency: None,
        }
    }

    fn result(url: &str) -> WebSearchResult {
        WebSearchResult {
            url: url.to_string(),
            title: String::new(),
            excerpt: String::new(),
            published_at: None,
            fetched_at: "2026-01-01T00:00:00.000Z".to_string(),
        }
    }

    #[test]
    fn the_key_folds_case_but_keeps_every_result_shaping_argument() {
        assert_eq!(
            CacheKey::new("exa", &query("Rust Async", 8)),
            CacheKey::new("exa", &query("rust async", 8))
        );
        assert_ne!(
            CacheKey::new("exa", &query("rust", 8)),
            CacheKey::new("exa", &query("rust", 9))
        );
        assert_ne!(
            CacheKey::new("exa", &query("rust", 8)),
            CacheKey::new("other", &query("rust", 8))
        );
    }

    #[test]
    fn entries_expire_after_the_ttl() {
        let cache = ResultCache::default();
        let key = CacheKey::new("exa", &query("q", 8));
        cache.put(key.clone(), vec![result("https://a.example/")], 1_000);
        assert!(cache.get(&key, 1_000 + CACHE_TTL_MS - 1).is_some());
        assert!(cache.get(&key, 1_000 + CACHE_TTL_MS).is_none());
        assert_eq!(cache.len(), 0, "an expired entry is removed when read");
    }

    #[test]
    fn a_full_cache_evicts_the_oldest_entry() {
        let cache = ResultCache::default();
        for index in 0..CACHE_CAPACITY {
            cache.put(
                CacheKey::new("exa", &query(&format!("q{index}"), 8)),
                vec![],
                index as i64,
            );
        }
        let newest = CacheKey::new("exa", &query("new", 8));
        cache.put(newest.clone(), vec![], CACHE_CAPACITY as i64);
        assert_eq!(cache.len(), CACHE_CAPACITY);
        assert!(cache
            .get(
                &CacheKey::new("exa", &query("q0", 8)),
                CACHE_CAPACITY as i64
            )
            .is_none());
        assert!(cache
            .get(
                &CacheKey::new("exa", &query("q1", 8)),
                CACHE_CAPACITY as i64
            )
            .is_some());
        assert!(cache.get(&newest, CACHE_CAPACITY as i64).is_some());
    }
}
