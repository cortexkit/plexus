//! DeepSeek's Search API: `catalog/deepseek_rest.jsonc`, action `search`
//! (`POST https://api.deepseek.com/v1/tools/search`, `Authorization: Bearer
//! <key>`).
//!
//! Field names come from DeepSeek's Search & Fetch guide
//! (<https://api-docs.deepseek.com/guides/search/>) and its Search reference
//! (<https://api-docs.deepseek.com/api/search/>): request `query` (1 to 128
//! Unicode characters) and `count` (1 to 50); reply `results[]` with
//! `title`, `url`, `summary`, `snippet` and `date`. DeepSeek has no
//! domain or date field, so requested domains travel as `site:` operators and
//! a recency window as an `after:` operator inside `query`.

use serde_json::{json, Value};

use super::{
    rfc3339_date, truncate_chars, ReplyShapeError, WebSearchBackend, WebSearchResult,
    EXCERPT_MAX_CHARS,
};
use crate::poller::iso8601;
use crate::web_search::capability::*;
use crate::web_search::query::{WebSearchQuery, MAX_INCLUDE_DOMAINS};

/// DeepSeek's documented `count` maximum.
pub const DEEPSEEK_MAX_COUNT: u8 = 50;
/// DeepSeek's documented `query` maximum, in Unicode characters. DeepSeek does
/// not say whether operators count toward it, so it is checked on the final
/// string sent, after the `site:` and `after:` operators for requested domains
/// and recency are added: a query DeepSeek might refuse is never sent.
pub const DEEPSEEK_MAX_QUERY_CHARS: usize = 128;

#[derive(Debug, Clone, Copy, Default)]
pub struct DeepSeekRestBackend;

impl WebSearchBackend for DeepSeekRestBackend {
    fn name(&self) -> &'static str {
        "deepseek"
    }

    fn app_key(&self) -> &'static str {
        "deepseek_rest"
    }

    fn action(&self) -> &'static str {
        "search"
    }

    fn capability(&self) -> WebSearchCapability {
        // Both filters become operators in `query`, and the 128-character
        // limit applies to that final string, so a long query with domains or
        // a recency window skips DeepSeek instead of being cut short.
        WebSearchCapability {
            query_length: QueryLengthLimit {
                max: DEEPSEEK_MAX_QUERY_CHARS,
                unit: QueryLengthUnit::UnicodeScalars,
            },
            max_results: DEEPSEEK_MAX_COUNT,
            domains: DomainCapability {
                max_domains: MAX_INCLUDE_DOMAINS,
                encoding: FilterEncoding::QueryOperators,
            },
            recency: RecencyCapability {
                supported: ALL_RECENCIES,
                encoding: FilterEncoding::QueryOperators,
            },
        }
    }

    /// DeepSeek's guide combines operators by appending them to the terms, as
    /// in `DeepSeek site:github.com OR site:huggingface.co lang:en after:2025`,
    /// and documents no grouping with parentheses. The shared composition wraps
    /// each part in parentheses, so DeepSeek builds its own `query` in the
    /// documented form and then runs the shared length, recency and
    /// result-count checks on that final string.
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
        composed.query = deepseek_query(query, now_ms);
        // The operators are already in `composed.query`. Declaring both
        // filters native here stops the shared check from adding them a second
        // time, while it still applies the length and result-count rules.
        let admission = WebSearchCapability {
            domains: DomainCapability {
                encoding: FilterEncoding::Native,
                ..capability.domains
            },
            recency: RecencyCapability {
                encoding: FilterEncoding::Native,
                ..capability.recency
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
        // `query.query` already carries any domain and recency operators (see
        // `prepare`); DeepSeek has no other filter field.
        json!({
            "query": query.query,
            "count": query.max_results,
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
            let Some(url) = item.get("url").and_then(Value::as_str) else {
                continue;
            };
            let text = |field: &str| {
                item.get(field)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            };
            // `summary` is DeepSeek's longer page summary. `snippet`, a shorter
            // excerpt every result also carries, fills in when it is empty.
            let excerpt = Some(text("summary"))
                .filter(|summary| !summary.is_empty())
                .unwrap_or_else(|| text("snippet"));
            results.push(WebSearchResult {
                url: url.to_string(),
                title: text("title"),
                excerpt: truncate_chars(&excerpt, EXCERPT_MAX_CHARS),
                // `date` is RFC 3339, or null when DeepSeek knows no date.
                published_at: item
                    .get("date")
                    .and_then(Value::as_str)
                    .and_then(|date| rfc3339_date(date.trim())),
                fetched_at: fetched_at.clone(),
            });
            if results.len() == max_results {
                break;
            }
        }
        Ok(results)
    }
}

/// `query` for DeepSeek: the caller's terms, then one `site:` operator per
/// requested domain joined by `OR`, then `after:YYYY-MM-DD` for a recency
/// window, the forms DeepSeek's guide documents.
fn deepseek_query(query: &WebSearchQuery, now_ms: i64) -> String {
    let mut parts = vec![query.query.clone()];
    if !query.include_domains.is_empty() {
        let sites = query
            .include_domains
            .iter()
            .map(|domain| format!("site:{domain}"))
            .collect::<Vec<_>>();
        parts.push(sites.join(" OR "));
    }
    if let Some(recency) = query.recency {
        parts.push(format!(
            "after:{}",
            window_start_day(now_ms, recency.days())
        ));
    }
    parts.join(" ")
}

/// The UTC calendar day `days` days before `now_ms`, as `YYYY-MM-DD`.
fn window_start_day(now_ms: i64, days: i64) -> String {
    let start = iso8601::format_millis(now_ms.saturating_sub(days * 86_400_000));
    start
        .split('T')
        .next()
        .expect("formatted timestamp has a date")
        .to_string()
}

#[cfg(test)]
mod tests;
