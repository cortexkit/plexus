//! Firecrawl's Search API: `catalog/firecrawl_rest.jsonc`, action `search`
//! (`POST https://api.firecrawl.dev/v2/search`, `Authorization: Bearer
//! <key>`).
//!
//! Field names come from Firecrawl's API reference
//! (<https://docs.firecrawl.dev/api-reference/endpoint/search>) and Search
//! guide (<https://docs.firecrawl.dev/features/search>): request `query` (at
//! most 500 long), `limit` (1 to 100), `sources` (`[{"type": "web"}]` asks for web results
//! only), `includeDomains` and `tbs` (`qdr:d`, `qdr:w`, `qdr:m`, `qdr:y`);
//! reply `data.web[]` with `title`, `url` and `description`. Results are
//! search listings only: no `scrapeOptions` are sent, so Firecrawl fetches no
//! page content and charges no scrape credits.

use serde_json::{json, Value};

use super::{
    truncate_chars, ReplyShapeError, WebSearchBackend, WebSearchResult, EXCERPT_MAX_CHARS,
};
use crate::poller::iso8601;
use crate::web_search::capability::*;
use crate::web_search::query::{Recency, WebSearchQuery, MAX_INCLUDE_DOMAINS};

/// Firecrawl's documented `limit` maximum.
pub const FIRECRAWL_MAX_LIMIT: u8 = 100;
/// Firecrawl's documented `query` maximum. The reference gives `maxLength:
/// 500` without naming a unit; Firecrawl's API runs on JavaScript, whose
/// string lengths count UTF-16 code units, so the limit is counted in those,
/// the stricter reading: a query of 500 characters that are mostly emoji or
/// other characters outside the Basic Multilingual Plane skips Firecrawl
/// instead of risking a refusal. Requested domains travel in
/// `includeDomains`, not in `query`, so the check covers the caller's terms
/// alone.
pub const FIRECRAWL_MAX_QUERY_UTF16: usize = 500;

#[derive(Debug, Clone, Copy, Default)]
pub struct FirecrawlRestBackend;

impl WebSearchBackend for FirecrawlRestBackend {
    fn name(&self) -> &'static str {
        "firecrawl"
    }

    fn app_key(&self) -> &'static str {
        "firecrawl_rest"
    }

    fn action(&self) -> &'static str {
        "search"
    }

    fn capability(&self) -> WebSearchCapability {
        // Firecrawl publishes no `includeDomains` count limit; the domain cap
        // is the tool's own argument limit, not a vendor limit. Domains travel
        // in `includeDomains`, which Firecrawl turns into `site:` operators on
        // its side, and the four recency windows map onto `tbs`; both are
        // native request fields, so nothing is added to `query`.
        WebSearchCapability {
            query_length: QueryLengthLimit {
                max: FIRECRAWL_MAX_QUERY_UTF16,
                unit: QueryLengthUnit::Utf16CodeUnits,
            },
            max_results: FIRECRAWL_MAX_LIMIT,
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
        // `sources` is sent explicitly so the reply's shape does not depend on
        // Firecrawl's default: only `data.web` is read.
        let mut args = json!({
            "query": query.query,
            "limit": query.max_results,
            "sources": [{"type": "web"}],
        });
        if !query.include_domains.is_empty() {
            args["includeDomains"] = json!(query.include_domains);
        }
        if let Some(recency) = query.recency {
            args["tbs"] = Value::String(tbs(recency).to_string());
        }
        args
    }

    fn map_reply(
        &self,
        reply: &Value,
        max_results: usize,
        fetched_at_ms: i64,
    ) -> Result<Vec<WebSearchResult>, ReplyShapeError> {
        let items = web_results(reply)?;
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
            // Web results carry `description`; Firecrawl's news results name
            // the same text `snippet`, which fills in if a web result ever
            // arrives with it instead.
            let excerpt = Some(text("description"))
                .filter(|description| !description.is_empty())
                .unwrap_or_else(|| text("snippet"));
            results.push(WebSearchResult {
                url: url.to_string(),
                title: text("title"),
                excerpt: truncate_chars(&excerpt, EXCERPT_MAX_CHARS),
                // Firecrawl's web results carry no publication date.
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

/// The `data.web` array of a reply. Firecrawl leaves a source's array out of
/// `data` when that source found nothing, so a successful reply whose `data`
/// object has no `web` key is an empty result. A reply without a `data`
/// object, or whose `web` is not an array, has the wrong shape.
fn web_results(reply: &Value) -> Result<&[Value], ReplyShapeError> {
    let data = reply
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| ReplyShapeError("reply has no data object".to_string()))?;
    match data.get("web") {
        None => Ok(&[]),
        Some(web) => web
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| ReplyShapeError("data.web is not an array".to_string())),
    }
}

/// Firecrawl's `tbs` time filters: past day, week, month or year.
fn tbs(recency: Recency) -> &'static str {
    match recency {
        Recency::Day => "qdr:d",
        Recency::Week => "qdr:w",
        Recency::Month => "qdr:m",
        Recency::Year => "qdr:y",
    }
}

#[cfg(test)]
mod tests;
