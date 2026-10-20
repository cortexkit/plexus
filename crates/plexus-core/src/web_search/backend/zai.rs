//! Z.AI search over the governed remote MCP transport.

use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Mutex;

use super::{
    rfc3339_date, truncate_chars, ReplyShapeError, WebSearchBackend, WebSearchResult,
    EXCERPT_MAX_CHARS,
};
use crate::poller::iso8601;
use crate::web_search::capability::*;
use crate::web_search::query::{WebSearchQuery, MAX_QUERY_CHARS, MAX_RESULTS_LIMIT};

#[derive(Debug, Default)]
pub struct ZaiMcpBackend {
    unsupported_connections: Mutex<HashSet<String>>,
}

impl WebSearchBackend for ZaiMcpBackend {
    fn name(&self) -> &'static str {
        "zai"
    }

    fn app_key(&self) -> &'static str {
        "zai"
    }

    fn action(&self) -> &'static str {
        "web_search_prime"
    }

    fn capability(&self) -> WebSearchCapability {
        WebSearchCapability {
            // The MCP overview publishes no query/count ceiling. Use the
            // neutral tool's bounds, not an invented vendor limit.
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
        json!({"query": query.query, "count": query.max_results})
    }

    fn prepare_reviewed(
        &self,
        mut prepared: PreparedSearch,
        reviewed_schema: Option<&Value>,
        connection_id: &str,
    ) -> Result<PreparedSearch, CapabilitySkip> {
        let fields = reviewed_schema
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object);
        let declares = |name| fields.is_some_and(|fields| fields.contains_key(name));
        let query_field = if declares("query") {
            "query"
        } else if declares("search_query") {
            "search_query"
        } else {
            if self
                .unsupported_connections
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(connection_id.to_string())
            {
                eprintln!(warn web_search:
                    "Z.AI connection {connection_id} skipped: reviewed web_search_prime schema declares neither query nor search_query"
                );
            }
            return Err(CapabilitySkip {
                provider: "zai",
                reason: CapabilitySkipReason::Capability,
                failed: CapabilityFailure::Schema,
            });
        };
        let mut args = json!({query_field: prepared.query.query});
        if declares("count") {
            args["count"] = json!(prepared.query.max_results);
        }
        prepared.vendor_args = args;
        Ok(prepared)
    }

    fn map_reply(
        &self,
        reply: &Value,
        max_results: usize,
        fetched_at_ms: i64,
    ) -> Result<Vec<WebSearchResult>, ReplyShapeError> {
        let items = reply
            .as_array()
            .or_else(|| reply.get("results").and_then(Value::as_array))
            .ok_or_else(|| ReplyShapeError("reply has no search results array".into()))?;
        let fetched_at = iso8601::format_millis(fetched_at_ms);
        Ok(items
            .iter()
            .filter_map(|item| {
                let text = |field: &str| {
                    item.get(field)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .trim()
                };
                let link = text("link");
                let url = if link.is_empty() { text("url") } else { link };
                if url.is_empty() {
                    return None;
                }
                Some(WebSearchResult {
                    url: url.to_string(),
                    title: text("title").to_string(),
                    excerpt: truncate_chars(text("content"), EXCERPT_MAX_CHARS),
                    published_at: rfc3339_date(text("publish_date")),
                    fetched_at: fetched_at.clone(),
                })
            })
            .take(max_results.min(MAX_RESULTS_LIMIT as usize))
            .collect())
    }
}

#[cfg(test)]
mod tests;
