//! Perplexity's keyed Search API, governed by `catalog/perplexity_rest.jsonc`.
//! Search result links are mapped; chat completions and generated answers are not.

use serde_json::{json, Value};

use super::{
    rfc3339_date, truncate_chars, ReplyShapeError, WebSearchBackend, WebSearchResult,
    EXCERPT_MAX_CHARS,
};
use crate::poller::iso8601;
use crate::web_search::capability::*;
use crate::web_search::query::{Recency, WebSearchQuery, MAX_QUERY_CHARS};

/// The Search API's web-search result cap; people search's larger cap is not used.
pub const PERPLEXITY_MAX_RESULTS: u8 = 20;
/// Maximum number of entries in the native domain allowlist.
pub const PERPLEXITY_MAX_DOMAINS: usize = 20;

#[derive(Debug, Clone, Copy, Default)]
pub struct PerplexityRestBackend;

impl WebSearchBackend for PerplexityRestBackend {
    fn name(&self) -> &'static str {
        "perplexity"
    }

    fn app_key(&self) -> &'static str {
        "perplexity_rest"
    }

    fn action(&self) -> &'static str {
        "search"
    }

    fn capability(&self) -> WebSearchCapability {
        WebSearchCapability {
            // The vendor documents no query-length maximum. Keep the tool's
            // character limit; native filters do not enlarge the query string.
            query_length: QueryLengthLimit {
                max: MAX_QUERY_CHARS,
                unit: QueryLengthUnit::UnicodeScalars,
            },
            max_results: PERPLEXITY_MAX_RESULTS,
            domains: DomainCapability {
                max_domains: PERPLEXITY_MAX_DOMAINS,
                encoding: FilterEncoding::Native,
            },
            recency: RecencyCapability {
                supported: ALL_RECENCIES,
                encoding: FilterEncoding::Native,
            },
        }
    }

    fn vendor_args(&self, query: &WebSearchQuery, _now_ms: i64) -> Value {
        let mut args = json!({
            "query": query.query,
            "max_results": query.max_results,
        });
        if !query.include_domains.is_empty() {
            args["search_domain_filter"] = json!(query.include_domains);
        }
        if let Some(recency) = query.recency {
            args["search_recency_filter"] = json!(match recency {
                Recency::Day => "day",
                Recency::Week => "week",
                Recency::Month => "month",
                Recency::Year => "year",
            });
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
            .take(max_results)
            .collect())
    }
}

#[cfg(test)]
mod tests;
