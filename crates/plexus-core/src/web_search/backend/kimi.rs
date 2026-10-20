//! Kimi Code's web search API: `catalog/kimi_rest.jsonc`, action `search`
//! (`POST https://api.kimi.com/coding/v1/search`, `Authorization: Bearer
//! <key>`). Only the API-key path is used; Kimi's login-session path and its
//! chat completions endpoint are not.
//!
//! Field names come from Kimi's own CLI (<https://github.com/MoonshotAI/kimi-cli>,
//! `src/kimi_cli/tools/web/search.py`) and the matching Kimi API Platform
//! reference (<https://platform.kimi.ai/docs/api/tools-search>): request
//! `text_query` and `limit` (1 to 20); reply `search_results[]` with `title`,
//! `url`, `snippet` and `date`. Kimi documents no domain or date filter, so a
//! search that asks for either skips Kimi.

use serde_json::{json, Value};

use super::{
    rfc3339_date, truncate_chars, ReplyShapeError, WebSearchBackend, WebSearchResult,
    EXCERPT_MAX_CHARS,
};
use crate::poller::iso8601;
use crate::web_search::capability::*;
use crate::web_search::query::{WebSearchQuery, MAX_QUERY_CHARS};

/// Kimi's documented `limit` maximum.
pub const KIMI_MAX_LIMIT: u8 = 20;

#[derive(Debug, Clone, Copy, Default)]
pub struct KimiRestBackend;

impl WebSearchBackend for KimiRestBackend {
    fn name(&self) -> &'static str {
        "kimi"
    }

    fn app_key(&self) -> &'static str {
        "kimi_rest"
    }

    fn action(&self) -> &'static str {
        "search"
    }

    fn capability(&self) -> WebSearchCapability {
        // Kimi documents no query-length limit, so the tool's own limit is
        // used. It documents no domain filter, no date filter and no query
        // operator for either: a search with domains or a recency window
        // skips Kimi rather than being answered from any site or of any age.
        WebSearchCapability {
            query_length: QueryLengthLimit {
                max: MAX_QUERY_CHARS,
                unit: QueryLengthUnit::UnicodeScalars,
            },
            max_results: KIMI_MAX_LIMIT,
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
        json!({
            "text_query": query.query,
            "limit": query.max_results,
        })
    }

    fn map_reply(
        &self,
        reply: &Value,
        max_results: usize,
        fetched_at_ms: i64,
    ) -> Result<Vec<WebSearchResult>, ReplyShapeError> {
        let items = reply
            .get("search_results")
            .and_then(Value::as_array)
            .ok_or_else(|| ReplyShapeError("reply has no search_results array".to_string()))?;
        let fetched_at = iso8601::format_millis(fetched_at_ms);
        let mut results = Vec::new();
        for item in items {
            // A result with no URL cannot be cited or fetched, so it is dropped
            // rather than returned with an empty link. Kimi returns "" for a
            // field it has no data for, so an empty URL is dropped too.
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
                excerpt: truncate_chars(&text("snippet"), EXCERPT_MAX_CHARS),
                // `date` is documented only as "Date of the search result";
                // the example is a bare YYYY-MM-DD day. Anything that does not
                // parse as a date, including "", is dropped.
                published_at: rfc3339_date(&text("date")),
                fetched_at: fetched_at.clone(),
            });
            if results.len() == max_results {
                break;
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests;
