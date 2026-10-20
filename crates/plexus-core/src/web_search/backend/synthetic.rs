//! Synthetic's keyed Search API, dispatched through `catalog/synthetic_rest.jsonc`.

use serde_json::{json, Value};

use super::{
    rfc3339_date, truncate_chars, ReplyShapeError, WebSearchBackend, WebSearchResult,
    EXCERPT_MAX_CHARS,
};
use crate::poller::iso8601;
use crate::web_search::capability::*;
use crate::web_search::query::{WebSearchQuery, MAX_QUERY_CHARS, MAX_RESULTS_LIMIT};

#[derive(Debug, Clone, Copy, Default)]
pub struct SyntheticRestBackend;

impl WebSearchBackend for SyntheticRestBackend {
    fn name(&self) -> &'static str {
        "synthetic"
    }

    fn app_key(&self) -> &'static str {
        "synthetic_rest"
    }

    fn action(&self) -> &'static str {
        "search"
    }

    fn capability(&self) -> WebSearchCapability {
        WebSearchCapability {
            // Synthetic publishes no query-length or result-count maximum.
            // Keep the tool's 500-character query and 20-result limits;
            // enforce the result-count limit when mapping the reply.
            query_length: QueryLengthLimit {
                max: MAX_QUERY_CHARS,
                unit: QueryLengthUnit::UnicodeScalars,
            },
            max_results: MAX_RESULTS_LIMIT,
            domains: DomainCapability {
                max_domains: 0,
                encoding: FilterEncoding::Native,
            },
            recency: RecencyCapability {
                supported: &[],
                encoding: FilterEncoding::Native,
            },
        }
    }

    fn vendor_args(&self, query: &WebSearchQuery, _now_ms: i64) -> Value {
        json!({"query": query.query})
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
                    excerpt: truncate_chars(text("text"), EXCERPT_MAX_CHARS),
                    published_at: rfc3339_date(text("published")),
                    fetched_at: fetched_at.clone(),
                })
            })
            .take(max_results)
            .collect())
    }
}

#[cfg(test)]
mod tests;
