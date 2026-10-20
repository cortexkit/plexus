//! Ollama's cloud web search API: `catalog/ollama_rest.jsonc`, action
//! `search` (`POST https://ollama.com/api/web_search`, `Authorization: Bearer
//! <key>`). This is the hosted search API on ollama.com, not a local Ollama
//! server, and plexus runs no model through it.
//!
//! Field names come from Ollama's web search documentation
//! (<https://docs.ollama.com/capabilities/web-search>) and its official Python
//! client (<https://github.com/ollama/ollama-python>, `ollama/_client.py` and
//! `ollama/_types.py`): request `query` and `max_results` (at most 10); reply
//! `results[]` with `title`, `url` and `content`. Ollama documents no domain
//! filter, no date filter and no query operator for either, so a search that
//! asks for domains or a recency window skips Ollama.

use serde_json::{json, Value};

use super::{
    truncate_chars, ReplyShapeError, WebSearchBackend, WebSearchResult, EXCERPT_MAX_CHARS,
};
use crate::poller::iso8601;
use crate::web_search::capability::*;
use crate::web_search::query::{WebSearchQuery, MAX_QUERY_CHARS};

/// Ollama's documented `max_results` maximum.
pub const OLLAMA_MAX_RESULTS: u8 = 10;
/// The longest `query` sent to Ollama, in characters. The query is sent
/// exactly as the caller wrote it. Ollama documents no query limit, so this is
/// the web_search tool's own query limit (`MAX_QUERY_CHARS`), which is also the
/// `maxLength` in the reviewed schema.
pub const OLLAMA_MAX_QUERY_CHARS: usize = MAX_QUERY_CHARS;

#[derive(Debug, Clone, Copy, Default)]
pub struct OllamaRestBackend;

impl WebSearchBackend for OllamaRestBackend {
    fn name(&self) -> &'static str {
        "ollama"
    }

    fn app_key(&self) -> &'static str {
        "ollama_rest"
    }

    fn action(&self) -> &'static str {
        "search"
    }

    fn capability(&self) -> WebSearchCapability {
        // Ollama documents no domain filter, no date filter and no query
        // operator for either. A `site:` operator it might silently ignore
        // would return unfiltered results as if they were filtered, so a
        // search with domains or a recency window skips Ollama and the chain
        // moves on.
        WebSearchCapability {
            query_length: QueryLengthLimit {
                max: OLLAMA_MAX_QUERY_CHARS,
                unit: QueryLengthUnit::UnicodeScalars,
            },
            max_results: OLLAMA_MAX_RESULTS,
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
            "query": query.query,
            "max_results": query.max_results,
        })
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
                // `content` is page text that can run long; only its start is
                // kept, like every other provider's excerpt.
                excerpt: truncate_chars(&text("content"), EXCERPT_MAX_CHARS),
                // Ollama's reply carries no date.
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

#[cfg(test)]
mod tests;
