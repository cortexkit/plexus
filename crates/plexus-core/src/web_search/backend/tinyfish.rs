//! TinyFish's keyed GET Search API, dispatched through its reviewed manifest.

use serde_json::{json, Value};

use super::{
    rfc3339_date, truncate_chars, ReplyShapeError, WebSearchBackend, WebSearchResult,
    EXCERPT_MAX_CHARS,
};
use crate::poller::iso8601;
use crate::web_search::capability::*;
use crate::web_search::query::{WebSearchQuery, MAX_INCLUDE_DOMAINS, MAX_RESULTS_LIMIT};

pub const TINYFISH_MAX_QUERY_CHARS: usize = 2000;

#[derive(Debug, Clone, Copy, Default)]
pub struct TinyFishRestBackend;

impl WebSearchBackend for TinyFishRestBackend {
    fn name(&self) -> &'static str {
        "tinyfish"
    }

    fn app_key(&self) -> &'static str {
        "tinyfish_rest"
    }

    fn action(&self) -> &'static str {
        "search"
    }

    fn capability(&self) -> WebSearchCapability {
        WebSearchCapability {
            query_length: QueryLengthLimit {
                max: TINYFISH_MAX_QUERY_CHARS,
                unit: QueryLengthUnit::UnicodeScalars,
            },
            // TinyFish documents no count parameter or domain-count maximum.
            // These are tool bounds, not claimed vendor limits; count is local.
            max_results: MAX_RESULTS_LIMIT,
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

    fn vendor_args(&self, query: &WebSearchQuery, _now_ms: i64) -> Value {
        let mut args = json!({"query": query.query});
        if !query.include_domains.is_empty() {
            args["include_domains"] = json!(query.include_domains.join(","));
        }
        if let Some(recency) = query.recency {
            args["recency_minutes"] = json!(recency.days() * 24 * 60);
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
        Ok(items
            .iter()
            .filter_map(|item| {
                let url = item
                    .get("url")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|url| !url.is_empty())?;
                let text = |field: &str| {
                    item.get(field)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .trim()
                };
                Some(WebSearchResult {
                    url: url.to_string(),
                    title: text("title").to_string(),
                    excerpt: truncate_chars(text("snippet"), EXCERPT_MAX_CHARS),
                    published_at: rfc3339_date(text("date")),
                    fetched_at: fetched_at.clone(),
                })
            })
            .take(max_results.min(MAX_RESULTS_LIMIT as usize))
            .collect())
    }
}

#[cfg(test)]
mod tests;
