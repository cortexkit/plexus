//! Operator-hosted SearXNG JSON search, always sent through governed REST.

use serde_json::{json, Value};

use super::{
    rfc3339_date, truncate_chars, ReplyShapeError, WebSearchBackend, WebSearchResult,
    EXCERPT_MAX_CHARS,
};
use crate::poller::iso8601;
use crate::web_search::capability::*;
use crate::web_search::query::{Recency, WebSearchQuery, MAX_QUERY_CHARS, MAX_RESULTS_LIMIT};

#[derive(Debug, Clone, Copy, Default)]
pub struct SearxngRestBackend;

impl WebSearchBackend for SearxngRestBackend {
    fn name(&self) -> &'static str {
        "searxng"
    }
    fn app_key(&self) -> &'static str {
        "searxng_rest"
    }
    fn action(&self) -> &'static str {
        "search"
    }

    fn capability(&self) -> WebSearchCapability {
        WebSearchCapability {
            // SearXNG publishes no query/count limit. These are local tool bounds.
            query_length: QueryLengthLimit {
                max: MAX_QUERY_CHARS,
                unit: QueryLengthUnit::UnicodeScalars,
            },
            max_results: MAX_RESULTS_LIMIT,
            // Engines need not support site: syntax, and the API has no domain field.
            domains: DomainCapability {
                max_domains: 0,
                encoding: FilterEncoding::Native,
            },
            recency: RecencyCapability {
                supported: &[Recency::Day, Recency::Month, Recency::Year],
                encoding: FilterEncoding::Native,
            },
        }
    }

    fn vendor_args(&self, query: &WebSearchQuery, _now_ms: i64) -> Value {
        let mut args = json!({"q": query.query, "format": "json", "language": "all"});
        if let Some(recency) = query.recency {
            args["time_range"] = json!(match recency {
                Recency::Day => "day",
                Recency::Month => "month",
                Recency::Year => "year",
                Recency::Week => unreachable!("capability admission rejects week"),
            });
        }
        args
    }

    fn instance_url(&self, connection: &crate::storage::ConnectionRecord) -> Option<String> {
        connection
            .instance_url
            .as_ref()
            .map(|url| url.as_str().to_string())
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
            .ok_or_else(|| ReplyShapeError("reply has no results array".into()))?;
        let fetched_at = iso8601::format_millis(fetched_at_ms);
        Ok(items
            .iter()
            .filter_map(|item| {
                let text = |key: &str| {
                    item.get(key)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .trim()
                };
                let url = text("url");
                if url.is_empty() {
                    return None;
                }
                Some(WebSearchResult {
                    url: url.into(),
                    title: text("title").into(),
                    excerpt: truncate_chars(text("content"), EXCERPT_MAX_CHARS),
                    published_at: published_date(text("publishedDate")),
                    fetched_at: fetched_at.clone(),
                })
            })
            .take(max_results.min(MAX_RESULTS_LIMIT as usize))
            .collect())
    }
}

fn published_date(value: &str) -> Option<String> {
    // The result model declares a datetime, not a JSON wire format. Accept both
    // ISO timestamps and HTTP dates used by Python JSON datetime serializers.
    rfc3339_date(value).or_else(|| {
        let millis = httpdate::parse_http_date(value)
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis();
        Some(iso8601::format_millis(i64::try_from(millis).ok()?))
    })
}

#[cfg(test)]
mod tests;
