//! Tavily over its REST API: `catalog/tavily_rest.jsonc`, action `search`
//! (`POST https://api.tavily.com/search`, `Authorization: Bearer <key>`).
//!
//! Field names come from Tavily's published API reference at
//! <https://docs.tavily.com/documentation/api-reference/endpoint/search>:
//! request `query`, `max_results` (0 to 20), `include_domains` (at most 300),
//! `time_range` (`day`, `week`, `month`, `year`), `include_published_date` and
//! `filter_by_published_date`; reply `results[]` with `title`, `url`,
//! `content` and `published_date`. The reply's `answer` is an LLM summary and
//! is never read: web search returns links, not a synthesized answer.

use serde_json::{json, Value};
use std::time::UNIX_EPOCH;

use super::{
    rfc3339_date, truncate_chars, ReplyShapeError, WebSearchBackend, WebSearchResult,
    EXCERPT_MAX_CHARS,
};
use crate::poller::iso8601;
use crate::web_search::capability::*;
use crate::web_search::query::{Recency, WebSearchQuery, MAX_QUERY_CHARS};

/// Tavily's documented `max_results` maximum.
pub const TAVILY_MAX_RESULTS: u8 = 20;
/// Tavily's documented `include_domains` maximum.
pub const TAVILY_MAX_INCLUDE_DOMAINS: usize = 300;

#[derive(Debug, Clone, Copy, Default)]
pub struct TavilyRestBackend;

impl WebSearchBackend for TavilyRestBackend {
    fn name(&self) -> &'static str {
        "tavily"
    }

    fn app_key(&self) -> &'static str {
        "tavily_rest"
    }

    fn action(&self) -> &'static str {
        "search"
    }

    fn capability(&self) -> WebSearchCapability {
        // Tavily publishes no hard query maximum; its search guide only advises
        // keeping queries under 1500 characters. The cap here is the tool's own
        // argument limit, which sits inside that advice, not a vendor limit.
        // Domains and the four recency windows are native request fields.
        WebSearchCapability {
            query_length: QueryLengthLimit {
                max: MAX_QUERY_CHARS,
                unit: QueryLengthUnit::UnicodeScalars,
            },
            max_results: TAVILY_MAX_RESULTS,
            domains: DomainCapability {
                max_domains: TAVILY_MAX_INCLUDE_DOMAINS,
                encoding: FilterEncoding::Native,
            },
            recency: RecencyCapability {
                supported: ALL_RECENCIES,
                encoding: FilterEncoding::Native,
            },
        }
    }

    fn vendor_args(&self, query: &WebSearchQuery, _now_ms: i64) -> Value {
        // Tavily only returns `published_date` for general-topic searches when
        // asked to; without it every result would come back undated.
        let mut args = json!({
            "query": query.query,
            "max_results": query.max_results,
            "include_published_date": true,
        });
        if !query.include_domains.is_empty() {
            args["include_domains"] = json!(query.include_domains);
        }
        if let Some(recency) = query.recency {
            args["time_range"] = Value::String(time_range(recency).to_string());
            // By default Tavily keeps results with no detectable publication
            // date inside a time range. The caller asked for recent results
            // only, so undated ones are removed rather than passed through.
            args["filter_by_published_date"] = Value::Bool(true);
        }
        args
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
            results.push(WebSearchResult {
                url: url.to_string(),
                title: text("title"),
                excerpt: truncate_chars(&text("content"), EXCERPT_MAX_CHARS),
                published_at: item
                    .get("published_date")
                    .and_then(Value::as_str)
                    .and_then(published_date),
                fetched_at: fetched_at.clone(),
            });
            if results.len() == max_results {
                break;
            }
        }
        Ok(results)
    }
}

fn time_range(recency: Recency) -> &'static str {
    match recency {
        Recency::Day => "day",
        Recency::Week => "week",
        Recency::Month => "month",
        Recency::Year => "year",
    }
}

/// Tavily documents `published_date` as an HTTP date
/// (`Tue, 11 Mar 2025 17:00:00 GMT`). An ISO 8601 date or timestamp is also
/// accepted in case a reply carries one; anything else is dropped.
fn published_date(value: &str) -> Option<String> {
    if let Ok(date) = httpdate::parse_http_date(value.trim()) {
        let millis = date.duration_since(UNIX_EPOCH).ok()?.as_millis();
        return Some(iso8601::format_millis(i64::try_from(millis).ok()?));
    }
    rfc3339_date(value)
}

#[cfg(test)]
mod tests;
