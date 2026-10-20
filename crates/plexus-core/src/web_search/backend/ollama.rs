//! Ollama's cloud web search API: `catalog/ollama_rest.jsonc`, action
//! `search` (`POST https://ollama.com/api/web_search`, `Authorization: Bearer
//! <key>`). This is the hosted search API on ollama.com, not a local Ollama
//! server, and plexus runs no model through it.
//!
//! Field names come from Ollama's web search documentation
//! (<https://docs.ollama.com/capabilities/web-search>) and its official Python
//! client (<https://github.com/ollama/ollama-python>, `ollama/_client.py` and
//! `ollama/_types.py`): request `query` and `max_results` (at most 10); reply
//! `results[]` with `title`, `url` and `content`. Ollama has no domain field,
//! so requested domains travel as `site:` operators inside `query`. It has no
//! date filter, so a search with a recency window skips Ollama.

use serde_json::{json, Value};

use super::{
    truncate_chars, ReplyShapeError, WebSearchBackend, WebSearchResult, EXCERPT_MAX_CHARS,
};
use crate::poller::iso8601;
use crate::web_search::capability::*;
use crate::web_search::query::{WebSearchQuery, MAX_INCLUDE_DOMAINS, MAX_QUERY_CHARS};

/// Ollama's documented `max_results` maximum.
pub const OLLAMA_MAX_RESULTS: u8 = 10;
/// The longest final `query` sent to Ollama, in characters, counted after the
/// `site:` operators for requested domains are added. Ollama documents no
/// query limit, so this is the web_search tool's own query limit
/// (`MAX_QUERY_CHARS`), which is also the `maxLength` in the reviewed schema.
pub const OLLAMA_MAX_QUERY_CHARS: usize = MAX_QUERY_CHARS;

#[derive(Debug, Clone, Copy, Default)]
pub struct OllamaRestBackend;

impl WebSearchBackend for OllamaRestBackend {
    fn name(&self) -> &'static str {
        "ollama"
    }

    fn app_key(&self) -> &'static str {
        "ollama_rest"
    }

    fn action(&self) -> &'static str {
        "search"
    }

    fn capability(&self) -> WebSearchCapability {
        // Domains have no request field of their own and become `site:`
        // operators in `query`; the length limit applies to that final
        // string, so a long query with many domains skips Ollama instead of
        // being cut short. Ollama documents no date filter and no date
        // operator, so a recency window skips Ollama rather than being
        // answered with results of any age.
        WebSearchCapability {
            query_length: QueryLengthLimit {
                max: OLLAMA_MAX_QUERY_CHARS,
                unit: QueryLengthUnit::UnicodeScalars,
            },
            max_results: OLLAMA_MAX_RESULTS,
            domains: DomainCapability {
                max_domains: MAX_INCLUDE_DOMAINS,
                encoding: FilterEncoding::QueryOperators,
            },
            recency: RecencyCapability {
                supported: &[],
                encoding: FilterEncoding::Native,
            },
        }
    }

    /// Ollama documents no query operators at all. The domains are appended
    /// as `terms site:a OR site:b`, the plain form most web search engines
    /// accept, instead of the shared composition, which wraps both parts in
    /// parentheses that an engine without grouping would search for as text.
    /// The shared check then applies the length, recency and result-count
    /// rules to that final string.
    fn prepare(
        &self,
        query: &WebSearchQuery,
        now_ms: i64,
    ) -> Result<PreparedSearch, CapabilitySkip> {
        let capability = self.capability();
        if query.include_domains.len() > capability.domains.max_domains {
            return Err(CapabilitySkip {
                provider: self.name(),
                reason: CapabilitySkipReason::Capability,
                failed: CapabilityFailure::DomainFilter,
            });
        }
        let mut composed = query.clone();
        composed.query = ollama_query(query);
        // The domains are already in `composed.query`. Declaring them native
        // here stops the shared check from adding them a second time, while it
        // still applies the length, recency and result-count rules.
        let admission = WebSearchCapability {
            domains: DomainCapability {
                encoding: FilterEncoding::Native,
                ..capability.domains
            },
            ..capability
        };
        let prepared = admission.prepare_query(self.name(), &composed, now_ms)?;
        let vendor_args = self.vendor_args(&prepared, now_ms);
        Ok(PreparedSearch {
            query: prepared,
            vendor_args,
        })
    }

    fn vendor_args(&self, query: &WebSearchQuery, _now_ms: i64) -> Value {
        // `query.query` already carries any domain operators (see `prepare`);
        // Ollama has no other filter field.
        json!({
            "query": query.query,
            "max_results": query.max_results,
        })
    }

    fn map_reply(
        &self,
        reply: &Value,
        max_results: usize,
        fetched_at_ms: i64,
    ) -> Result<Vec<WebSearchResult>, ReplyShapeError> {
        let items = reply
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| ReplyShapeError("reply has no results array".to_string()))?;
        let fetched_at = iso8601::format_millis(fetched_at_ms);
        let mut results = Vec::new();
        for item in items {
            // A result with no URL cannot be cited or fetched, so it is dropped
            // rather than returned with an empty link.
            let Some(url) = item
                .get("url")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|url| !url.is_empty())
            else {
                continue;
            };
            let text = |field: &str| {
                item.get(field)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            };
            results.push(WebSearchResult {
                url: url.to_string(),
                title: text("title"),
                // `content` is page text that can run long; only its start is
                // kept, like every other provider's excerpt.
                excerpt: truncate_chars(&text("content"), EXCERPT_MAX_CHARS),
                // Ollama's reply carries no date.
                published_at: None,
                fetched_at: fetched_at.clone(),
            });
            if results.len() == max_results {
                break;
            }
        }
        Ok(results)
    }
}

/// `query` for Ollama: the caller's terms followed by one `site:` operator per
/// requested domain, joined by `OR`.
fn ollama_query(query: &WebSearchQuery) -> String {
    if query.include_domains.is_empty() {
        return query.query.clone();
    }
    let sites = query
        .include_domains
        .iter()
        .map(|domain| format!("site:{domain}"))
        .collect::<Vec<_>>();
    format!("{} {}", query.query, sites.join(" OR "))
}

#[cfg(test)]
mod tests;
