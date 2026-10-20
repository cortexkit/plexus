//! Parallel's keyed Search REST API, governed by `catalog/parallel_rest.jsonc`.
//! Only result sources are mapped; no synthesized answer is returned.

use serde_json::{json, Value};

use super::{
    rfc3339_date, truncate_chars, ReplyShapeError, WebSearchBackend, WebSearchResult,
    EXCERPT_MAX_CHARS,
};
use crate::poller::iso8601;
use crate::web_search::capability::*;
use crate::web_search::query::{WebSearchQuery, MAX_INCLUDE_DOMAINS};

/// Parallel's public Search result-count cap.
pub const PARALLEL_MAX_RESULTS: u8 = 20;
/// GA Search permits at most 200 characters per search_queries entry.
pub const PARALLEL_MAX_QUERY_CHARS: usize = 200;

#[derive(Debug, Clone, Copy, Default)]
pub struct ParallelRestBackend;

impl WebSearchBackend for ParallelRestBackend {
    fn name(&self) -> &'static str {
        "parallel"
    }

    fn app_key(&self) -> &'static str {
        "parallel_rest"
    }

    fn action(&self) -> &'static str {
        "search"
    }

    fn capability(&self) -> WebSearchCapability {
        WebSearchCapability {
            // Keep the caller's literal query within the GA search_queries
            // limit. Native filters add no operators to that query.
            query_length: QueryLengthLimit {
                max: PARALLEL_MAX_QUERY_CHARS,
                unit: QueryLengthUnit::UnicodeScalars,
            },
            max_results: PARALLEL_MAX_RESULTS,
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
        let mut args = json!({
            "search_queries": [query.query],
            "advanced_settings": {"max_results": query.max_results},
        });
        let mut policy = json!({});
        if !query.include_domains.is_empty() {
            policy["include_domains"] = json!(query.include_domains);
        }
        if let Some(recency) = query.recency {
            let start = now_ms.saturating_sub(recency.days() * 86_400_000);
            let timestamp = iso8601::format_millis(start);
            policy["after_date"] = json!(timestamp.split('T').next().unwrap());
        }
        if policy.as_object().is_some_and(|policy| !policy.is_empty()) {
            args["advanced_settings"]["source_policy"] = policy;
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
                let excerpts = item
                    .get("excerpts")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .filter(|text| !text.is_empty())
                    .collect::<Vec<_>>()
                    .join("\n");
                Some(WebSearchResult {
                    url: url.to_string(),
                    title: text("title").to_string(),
                    excerpt: truncate_chars(&excerpts, EXCERPT_MAX_CHARS),
                    published_at: rfc3339_date(text("publish_date")),
                    fetched_at: fetched_at.clone(),
                })
            })
            .take(max_results)
            .collect())
    }
}

#[cfg(test)]
mod tests;
