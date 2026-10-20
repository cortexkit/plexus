//! Kagi's Search API: `catalog/kagi_rest.jsonc`, action `search`
//! (`POST https://kagi.com/api/v1/search`, `Authorization: Bearer <key>`).
//! Search only: Kagi's Summarizer and FastGPT answer endpoints are not used.
//!
//! Field names come from Kagi's published OpenAPI document
//! (<https://redocly-api-docs.kagi.com/api/docs/_bundle/openapi.yaml>, the
//! `search` operation): request `query`, `workflow`, `limit`,
//! `lens.sites_included` and `filters.after`; reply `data.search[]` with
//! `url`, `title`, `snippet` and `time`. Domains and the recency window use
//! those native fields, because Kagi documents no date operator for the query
//! and its lens options take precedence over operators in the query.

use serde_json::{json, Value};

use super::{
    rfc3339_date, truncate_chars, ReplyShapeError, WebSearchBackend, WebSearchResult,
    EXCERPT_MAX_CHARS,
};
use crate::poller::iso8601;
use crate::web_search::capability::*;
use crate::web_search::query::{
    WebSearchQuery, MAX_INCLUDE_DOMAINS, MAX_QUERY_CHARS, MAX_RESULTS_LIMIT,
};

/// The most results asked of Kagi. Kagi accepts a `limit` of up to 1024; the
/// reviewed schema stops at the tool's own maximum of 20.
pub const KAGI_MAX_LIMIT: u8 = MAX_RESULTS_LIMIT;

#[derive(Debug, Clone, Copy, Default)]
pub struct KagiRestBackend;

impl WebSearchBackend for KagiRestBackend {
    fn name(&self) -> &'static str {
        "kagi"
    }

    fn app_key(&self) -> &'static str {
        "kagi_rest"
    }

    fn action(&self) -> &'static str {
        "search"
    }

    fn capability(&self) -> WebSearchCapability {
        // Kagi documents no query-length limit, so the tool's own limit is
        // used. Domains go in `lens.sites_included` and the recency window in
        // `filters.after`, both native fields, so nothing is added to the
        // query text and every recency window is honoured.
        WebSearchCapability {
            query_length: QueryLengthLimit {
                max: MAX_QUERY_CHARS,
                unit: QueryLengthUnit::UnicodeScalars,
            },
            max_results: KAGI_MAX_LIMIT,
            domains: DomainCapability {
                max_domains: MAX_INCLUDE_DOMAINS,
                encoding: FilterEncoding::Native,
            },
            recency: RecencyCapability {
                supported: ALL_RECENCIES,
                encoding: FilterEncoding::Native,
            },
        }
    }

    fn vendor_args(&self, query: &WebSearchQuery, now_ms: i64) -> Value {
        // `workflow: "search"` is added by the manifest as a reviewed constant.
        let mut args = json!({
            "query": query.query,
            "limit": query.max_results,
        });
        if !query.include_domains.is_empty() {
            args["lens"] = json!({"sites_included": query.include_domains});
        }
        if let Some(recency) = query.recency {
            args["filters"] = json!({"after": window_start_day(now_ms, recency.days())});
        }
        args
    }

    fn map_reply(
        &self,
        reply: &Value,
        max_results: usize,
        fetched_at_ms: i64,
    ) -> Result<Vec<WebSearchResult>, ReplyShapeError> {
        let data = reply
            .get("data")
            .and_then(Value::as_object)
            .ok_or_else(|| ReplyShapeError("reply has no data object".to_string()))?;
        // Kagi's schema makes every result bucket optional, so a `data` object
        // without `search` found no web results. Only `search` is read:
        // `direct_answer`, `infobox` and the other buckets carry answers and
        // side panels, not result links.
        let items = match data.get("search") {
            None => return Ok(Vec::new()),
            Some(search) => search
                .as_array()
                .ok_or_else(|| ReplyShapeError("data.search is not an array".to_string()))?,
        };
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
            results.push(WebSearchResult {
                url: url.to_string(),
                title: text("title"),
                excerpt: truncate_chars(&text("snippet"), EXCERPT_MAX_CHARS),
                // `time` is when the page was created or last updated, as
                // RFC 3339; anything unparseable is dropped.
                published_at: item
                    .get("time")
                    .and_then(Value::as_str)
                    .and_then(|time| rfc3339_date(time.trim())),
                fetched_at: fetched_at.clone(),
            });
            if results.len() == max_results {
                break;
            }
        }
        Ok(results)
    }
}

/// The UTC calendar day `days` days before `now_ms`, as `YYYY-MM-DD`, the
/// `format: date` Kagi's `filters.after` takes.
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
