//! Web search backends: how the neutral tool contract maps onto one vendor.
//!
//! A backend names the catalog app and action it rides on, and translates in
//! both directions. It never talks to the vendor itself: every call goes
//! through the governance engine, which owns the credential and the transport.
//! Adding a vendor is a new impl of [`WebSearchBackend`] plus its reviewed
//! catalog manifest; the tool contract does not change.

use serde::Serialize;
use serde_json::{json, Value};

use super::query::WebSearchQuery;
use crate::poller::iso8601;

mod tavily;
pub use tavily::{TavilyRestBackend, TAVILY_MAX_INCLUDE_DOMAINS, TAVILY_MAX_RESULTS};

/// Longest excerpt returned per result, in characters.
pub const EXCERPT_MAX_CHARS: usize = 600;

/// One neutral search result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WebSearchResult {
    pub url: String,
    pub title: String,
    pub excerpt: String,
    /// RFC 3339, present only when the vendor reported a parseable date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
    /// RFC 3339 time plexus received the vendor reply this result came from.
    pub fetched_at: String,
}

/// Why a vendor reply could not be mapped. The detail goes to the log only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyShapeError(pub String);

pub trait WebSearchBackend: Send + Sync {
    /// The neutral backend name reported to callers (`"exa"`).
    fn name(&self) -> &'static str;
    /// The catalog app whose connections can serve this backend.
    fn app_key(&self) -> &'static str;
    /// The catalog action a search dispatches.
    fn action(&self) -> &'static str;
    /// The request envelope and filter encodings this backend can honour.
    fn capability(&self) -> super::capability::WebSearchCapability;
    /// Chain admission, before any connection, allowance or cooldown work.
    /// A skip is a complete record; no vendor argument mapping runs on failure.
    fn prepare(
        &self,
        query: &WebSearchQuery,
        now_ms: i64,
    ) -> Result<super::capability::PreparedSearch, super::capability::CapabilitySkip> {
        let query = self
            .capability()
            .prepare_query(self.name(), query, now_ms)?;
        let vendor_args = self.vendor_args(&query, now_ms);
        Ok(super::capability::PreparedSearch { query, vendor_args })
    }
    /// The vendor arguments for one validated query. `now_ms` anchors a
    /// recency window. In chain mode `prepare` already composed query operators:
    /// forward `query.query` unchanged and map native filter fields here.
    fn vendor_args(&self, query: &WebSearchQuery, now_ms: i64) -> Value;
    /// Map a vendor reply onto neutral results, at most `max_results` of them.
    fn map_reply(
        &self,
        reply: &Value,
        max_results: usize,
        fetched_at_ms: i64,
    ) -> Result<Vec<WebSearchResult>, ReplyShapeError>;
    /// The instance address `connection` searches, for a backend whose endpoint
    /// is chosen per connection (SearXNG), as stored on the connection. Chain
    /// cache entries record a digest of its normalized form, so results from
    /// one instance never answer a caller on another. Backends with one fixed
    /// vendor endpoint return `None`. The address is never logged.
    fn instance_url(&self, _connection: &crate::storage::ConnectionRecord) -> Option<String> {
        None
    }
}

/// Exa over its REST API: `catalog/exa_rest.jsonc`, action `search`
/// (`POST /search`).
///
/// Request and response field names are taken from Exa's published OpenAPI
/// spec at <https://exa.ai/docs/reference/search>: `numResults`,
/// `includeDomains`, `startPublishedDate`, and the `contents` object with
/// `highlights` and `text`, each bounded by `maxCharacters`; results carry
/// `url`, `title`, `publishedDate`, `highlights` and `text`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExaRestBackend;

impl WebSearchBackend for ExaRestBackend {
    fn name(&self) -> &'static str {
        "exa"
    }

    fn app_key(&self) -> &'static str {
        "exa_rest"
    }

    fn action(&self) -> &'static str {
        "search"
    }

    fn capability(&self) -> super::capability::WebSearchCapability {
        use super::capability::*;
        // https://exa.ai/docs/exa-spec.yaml (SearchRequest): numResults <= 100,
        // includeDomains <= 1200; no query maximum is published. The query cap
        // is our existing tool envelope, not a claimed vendor maximum. Native
        // filters leave the existing request mapping intact.
        WebSearchCapability {
            query_length: QueryLengthLimit {
                max: super::query::MAX_QUERY_CHARS,
                unit: QueryLengthUnit::UnicodeScalars,
            },
            max_results: 100,
            domains: DomainCapability {
                max_domains: 1200,
                encoding: FilterEncoding::Native,
            },
            recency: RecencyCapability {
                supported: ALL_RECENCIES,
                encoding: FilterEncoding::Native,
            },
        }
    }

    fn vendor_args(&self, query: &WebSearchQuery, now_ms: i64) -> Value {
        // Both content kinds are requested so a result without highlights can
        // still fall back to the start of its text; each is capped at the
        // excerpt length because nothing beyond it is ever returned.
        let mut args = json!({
            "query": query.query,
            "numResults": query.max_results,
            "contents": {
                "highlights": {"maxCharacters": EXCERPT_MAX_CHARS},
                "text": {"maxCharacters": EXCERPT_MAX_CHARS}
            }
        });
        if !query.include_domains.is_empty() {
            args["includeDomains"] = json!(query.include_domains);
        }
        if let Some(recency) = query.recency {
            let start = now_ms.saturating_sub(recency.days() * 86_400_000);
            args["startPublishedDate"] = Value::String(iso8601::format_millis(start));
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
        let mut results = Vec::new();
        for item in items {
            // A result with no URL cannot be cited or fetched, so it is dropped
            // rather than returned with an empty link.
            let Some(url) = item.get("url").and_then(Value::as_str) else {
                continue;
            };
            let title = item
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let highlights = item
                .get("highlights")
                .and_then(Value::as_array)
                .map(|highlights| {
                    highlights
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::trim)
                        .filter(|highlight| !highlight.is_empty())
                        .collect::<Vec<_>>()
                        .join(" … ")
                })
                .filter(|joined| !joined.is_empty());
            let excerpt = highlights.unwrap_or_else(|| {
                item.get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            });
            results.push(WebSearchResult {
                url: url.to_string(),
                title: title.trim().to_string(),
                excerpt: truncate_chars(&excerpt, EXCERPT_MAX_CHARS),
                published_at: item
                    .get("publishedDate")
                    .and_then(Value::as_str)
                    .and_then(rfc3339_date),
                fetched_at: fetched_at.clone(),
            });
            if results.len() == max_results {
                break;
            }
        }
        Ok(results)
    }
}

/// Normalize a vendor publication date to RFC 3339 UTC. Exa documents the
/// field as `YYYY-MM-DD` while its examples carry a full timestamp, so both
/// are accepted; a bare date is read as midnight UTC. Anything else is
/// dropped rather than passed through unchecked.
fn rfc3339_date(value: &str) -> Option<String> {
    let millis = iso8601::parse_to_millis(value).or_else(|| {
        (value.len() == 10)
            .then(|| iso8601::parse_to_millis(&format!("{value}T00:00:00Z")))
            .flatten()
    })?;
    Some(iso8601::format_millis(millis))
}

fn truncate_chars(value: &str, limit: usize) -> String {
    match value.char_indices().nth(limit) {
        Some((cut, _)) => value[..cut].to_string(),
        None => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_search::query::{Recency, WebSearchQuery};

    fn query(recency: Option<Recency>, domains: &[&str]) -> WebSearchQuery {
        WebSearchQuery {
            query: "Latest LLM developments".to_string(),
            max_results: 5,
            include_domains: domains.iter().map(|domain| domain.to_string()).collect(),
            recency,
        }
    }

    #[test]
    fn vendor_args_use_exas_published_field_names() {
        let now = iso8601::parse_to_millis("2026-09-28T12:00:00Z").unwrap();
        let args = ExaRestBackend.vendor_args(&query(Some(Recency::Week), &["arxiv.org"]), now);
        assert_eq!(
            args,
            json!({
                "query": "Latest LLM developments",
                "numResults": 5,
                "includeDomains": ["arxiv.org"],
                "startPublishedDate": "2026-09-21T12:00:00.000Z",
                "contents": {
                    "highlights": {"maxCharacters": 600},
                    "text": {"maxCharacters": 600}
                }
            })
        );
        let bare = ExaRestBackend.vendor_args(&query(None, &[]), now);
        assert!(bare.get("includeDomains").is_none());
        assert!(bare.get("startPublishedDate").is_none());
    }

    #[test]
    fn excerpts_fall_back_to_text_and_are_bounded() {
        let long = "é".repeat(700);
        let reply = json!({"results": [
            {"url": "https://a.example/", "title": "A", "text": long, "highlights": []},
            {"title": "no url is dropped"},
            {"url": "https://b.example/", "title": " B ", "publishedDate": "2024-02-29"},
            {"url": "https://c.example/", "publishedDate": "not a date"}
        ]});
        let results = ExaRestBackend.map_reply(&reply, 10, 0).unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].excerpt.chars().count(), EXCERPT_MAX_CHARS);
        assert_eq!(results[1].title, "B");
        assert_eq!(results[1].excerpt, "");
        assert_eq!(
            results[1].published_at.as_deref(),
            Some("2024-02-29T00:00:00.000Z")
        );
        assert_eq!(results[2].published_at, None);
        assert_eq!(results[2].title, "");
        assert_eq!(results[0].fetched_at, "1970-01-01T00:00:00.000Z");
        assert_eq!(ExaRestBackend.map_reply(&reply, 1, 0).unwrap().len(), 1);
    }

    #[test]
    fn a_reply_without_results_is_a_shape_error() {
        assert!(ExaRestBackend
            .map_reply(&json!({"error": "x"}), 5, 0)
            .is_err());
        assert!(ExaRestBackend.map_reply(&json!("text"), 5, 0).is_err());
    }
}
