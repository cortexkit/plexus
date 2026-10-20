//! Jina's Search API: `catalog/jina_rest.jsonc`, action `search`
//! (`GET https://s.jina.ai/<url-encoded query>`, `Authorization: Bearer
//! <key>`). Search only: Jina Reader, which fetches one page, is not used.
//!
//! Field names come from Jina's OpenAPI document
//! (<https://s.jina.ai/openapi.json>), the Search section of
//! <https://jina.ai/reader/> and the search source of Jina's open-source
//! server (<https://github.com/jina-ai/reader>): the query is the whole URL
//! path, `count` (at most 20) is a query parameter and one site filter
//! travels in the `X-Site` header; the reply's `data[]` carries `title`,
//! `url`, `description` and, when page content is fetched, `content`.

use serde_json::{json, Value};

use super::{
    rfc3339_date, truncate_chars, ReplyShapeError, WebSearchBackend, WebSearchResult,
    EXCERPT_MAX_CHARS,
};
use crate::poller::iso8601;
use crate::web_search::capability::*;
use crate::web_search::query::{WebSearchQuery, MAX_QUERY_CHARS};

/// Jina's documented `count` maximum.
pub const JINA_MAX_COUNT: u8 = 20;
/// Jina takes one site filter, in the `X-Site` header.
pub const JINA_MAX_DOMAINS: usize = 1;

#[derive(Debug, Clone, Copy, Default)]
pub struct JinaRestBackend;

impl WebSearchBackend for JinaRestBackend {
    fn name(&self) -> &'static str {
        "jina"
    }

    fn app_key(&self) -> &'static str {
        "jina_rest"
    }

    fn action(&self) -> &'static str {
        "search"
    }

    fn capability(&self) -> WebSearchCapability {
        // Jina documents no query-length limit, so the tool's own limit is
        // used. The one domain goes in the `X-Site` header, a native field, so
        // nothing is added to the query. Jina documents no date filter: a
        // search with a recency window skips Jina rather than being answered
        // with results of any age.
        WebSearchCapability {
            query_length: QueryLengthLimit {
                max: MAX_QUERY_CHARS,
                unit: QueryLengthUnit::UnicodeScalars,
            },
            max_results: JINA_MAX_COUNT,
            domains: DomainCapability {
                max_domains: JINA_MAX_DOMAINS,
                encoding: FilterEncoding::Native,
            },
            recency: RecencyCapability {
                supported: &[],
                encoding: FilterEncoding::Native,
            },
        }
    }

    fn vendor_args(&self, query: &WebSearchQuery, _now_ms: i64) -> Value {
        // `q` becomes the URL path and `site` the `X-Site` header; the
        // manifest's `text_path_parameters` and `header_parameters` say so.
        let mut args = json!({
            "q": query.query,
            "count": query.max_results,
        });
        if let Some(site) = query.include_domains.first() {
            args["site"] = Value::String(site.clone());
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
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| ReplyShapeError("reply has no data array".to_string()))?;
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
            // `description` is the search listing's snippet. `content`, the
            // fetched page text, fills in only when a result has no
            // description.
            let excerpt = Some(text("description"))
                .filter(|description| !description.is_empty())
                .unwrap_or_else(|| text("content"));
            // The OpenAPI result schema names the date `publishedTime`; the
            // server's search listings name it `date`. Either is used when it
            // is a parseable date.
            let published_at = ["date", "publishedTime"].into_iter().find_map(|field| {
                item.get(field)
                    .and_then(Value::as_str)
                    .and_then(rfc3339_date)
            });
            results.push(WebSearchResult {
                url: url.to_string(),
                title: text("title"),
                excerpt: truncate_chars(&excerpt, EXCERPT_MAX_CHARS),
                published_at,
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
