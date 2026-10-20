//! Brave over its REST API: `catalog/brave_rest.jsonc`, action `search`
//! (`GET https://api.search.brave.com/res/v1/web/search`, key in the
//! `X-Subscription-Token` header).
//!
//! Field names come from Brave's Web Search API reference at
//! <https://api-dashboard.search.brave.com/api-reference/web/search/get>:
//! query parameters `q` (at most 600 characters and 75 words), `count` (1 to
//! 20), `freshness` (`pd`, `pw`, `pm`, `py`), `extra_snippets` and
//! `text_decorations`; reply `web.results[]` with `title`, `url`,
//! `description`, `extra_snippets`, `age` and `page_age`. Brave has no domain
//! parameter, so requested domains travel as `site:` operators inside `q`.

use serde_json::{json, Value};

use super::{
    rfc3339_date, truncate_chars, ReplyShapeError, WebSearchBackend, WebSearchResult,
    EXCERPT_MAX_CHARS,
};
use crate::poller::iso8601;
use crate::web_search::capability::*;
use crate::web_search::query::{Recency, WebSearchQuery, MAX_INCLUDE_DOMAINS};

/// Brave's documented `count` maximum.
pub const BRAVE_MAX_COUNT: u8 = 20;
/// The longest final `q` sent to Brave, in characters, counted after the
/// `site:` operators for requested domains are added. Brave documents 600;
/// this is the tool's own query limit, which keeps inside it.
pub const BRAVE_MAX_QUERY_CHARS: usize = 500;
/// Brave's documented maximum number of words in `q`, operators included.
pub const BRAVE_MAX_QUERY_WORDS: usize = 75;

#[derive(Debug, Clone, Copy, Default)]
pub struct BraveRestBackend;

impl WebSearchBackend for BraveRestBackend {
    fn name(&self) -> &'static str {
        "brave"
    }

    fn app_key(&self) -> &'static str {
        "brave_rest"
    }

    fn action(&self) -> &'static str {
        "search"
    }

    fn capability(&self) -> WebSearchCapability {
        // Domains have no request field of their own and become `site:`
        // operators in `q`; the length limit applies to that final string, so
        // a long query with many domains skips Brave instead of being cut
        // short. The four recency windows map onto Brave's `freshness`.
        WebSearchCapability {
            query_length: QueryLengthLimit {
                max: BRAVE_MAX_QUERY_CHARS,
                unit: QueryLengthUnit::UnicodeScalars,
            },
            max_results: BRAVE_MAX_COUNT,
            domains: DomainCapability {
                max_domains: MAX_INCLUDE_DOMAINS,
                encoding: FilterEncoding::QueryOperators,
            },
            recency: RecencyCapability {
                supported: ALL_RECENCIES,
                encoding: FilterEncoding::Native,
            },
        }
    }

    /// Brave's operator guide documents site alternatives as
    /// `electric vehicles site:reuters.com OR site:bloomberg.com 2025` and
    /// documents no grouping with parentheses. The shared composition wraps
    /// both parts in parentheses, so Brave composes its own `q` in the
    /// documented form and then runs the shared length check on that final
    /// string. Brave also limits `q` to 75 words, which the shared check does
    /// not count; a longer query skips Brave as too long.
    fn prepare(
        &self,
        query: &WebSearchQuery,
        now_ms: i64,
    ) -> Result<PreparedSearch, CapabilitySkip> {
        let capability = self.capability();
        let skip = |failed| CapabilitySkip {
            provider: self.name(),
            reason: CapabilitySkipReason::Capability,
            failed,
        };
        if query.include_domains.len() > capability.domains.max_domains {
            return Err(skip(CapabilityFailure::DomainFilter));
        }
        let mut composed = query.clone();
        composed.query = brave_query(query);
        // The domains are already in `composed.query`. Declaring them native
        // here stops the shared check from adding them a second time, while it
        // still applies the length, recency and result-count rules.
        let admission = WebSearchCapability {
            domains: DomainCapability {
                encoding: FilterEncoding::Native,
                ..capability.domains
            },
            ..capability
        };
        let prepared = admission.prepare_query(self.name(), &composed, now_ms)?;
        if prepared.query.split_whitespace().count() > BRAVE_MAX_QUERY_WORDS {
            return Err(skip(CapabilityFailure::Length));
        }
        let vendor_args = self.vendor_args(&prepared, now_ms);
        Ok(PreparedSearch {
            query: prepared,
            vendor_args,
        })
    }

    fn vendor_args(&self, query: &WebSearchQuery, _now_ms: i64) -> Value {
        // `query.query` already carries any domain operators (see `prepare`).
        // Decorations are turned off so titles and descriptions arrive without
        // highlighting markup.
        let mut args = json!({
            "q": query.query,
            "count": query.max_results,
            "extra_snippets": true,
            "text_decorations": false,
        });
        if let Some(recency) = query.recency {
            args["freshness"] = Value::String(freshness(recency).to_string());
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
            let field = |name: &str| item.get(name).and_then(Value::as_str);
            results.push(WebSearchResult {
                url: url.to_string(),
                title: plain_text(field("title").unwrap_or_default()),
                excerpt: truncate_chars(&excerpt(item), EXCERPT_MAX_CHARS),
                // `page_age` is a date-time; `age` is mostly relative text and
                // only fills in when `page_age` is missing or unreadable.
                published_at: field("page_age")
                    .and_then(page_age)
                    .or_else(|| field("age").and_then(age)),
                fetched_at: fetched_at.clone(),
            });
            if results.len() == max_results {
                break;
            }
        }
        Ok(results)
    }
}

/// `q` for Brave: the caller's query followed by one `site:` operator per
/// requested domain, joined by `OR`, the form Brave's operator guide shows.
fn brave_query(query: &WebSearchQuery) -> String {
    if query.include_domains.is_empty() {
        return query.query.clone();
    }
    let sites = query
        .include_domains
        .iter()
        .map(|domain| format!("site:{domain}"))
        .collect::<Vec<_>>();
    format!("{} {}", query.query, sites.join(" OR "))
}

/// The `web.results` array of a reply. Brave documents the `web` section as
/// optional, so a search reply (`"type": "search"`) without it found no web
/// pages and is an empty result; any other reply has the wrong shape.
fn web_results(reply: &Value) -> Result<&[Value], ReplyShapeError> {
    match reply.get("web") {
        Some(web) => web
            .get("results")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .ok_or_else(|| ReplyShapeError("web section has no results array".to_string())),
        None if reply.get("type").and_then(Value::as_str) == Some("search") => Ok(&[]),
        None => Err(ReplyShapeError(
            "reply is not a web search reply".to_string(),
        )),
    }
}

/// The result's description followed by its extra snippets, separated the
/// same way Exa highlights are joined.
fn excerpt(item: &Value) -> String {
    let description = item.get("description").and_then(Value::as_str);
    let snippets = item
        .get("extra_snippets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    description
        .into_iter()
        .chain(snippets)
        .map(plain_text)
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join(" … ")
}

fn freshness(recency: Recency) -> &'static str {
    match recency {
        Recency::Day => "pd",
        Recency::Week => "pw",
        Recency::Month => "pm",
        Recency::Year => "py",
    }
}

/// Brave highlights matched terms with `<strong>` unless decorations are off,
/// which every request asks for. The tags are still removed in case a reply
/// carries them anyway, so results stay plain text.
fn plain_text(value: &str) -> String {
    value
        .replace("<strong>", "")
        .replace("</strong>", "")
        .trim()
        .to_string()
}

/// `page_age` is "the page's date, based on its published or last modified
/// date". Brave's replies carry it as an ISO 8601 date-time, often without a
/// zone; one without a zone is read as UTC.
fn page_age(value: &str) -> Option<String> {
    let value = value.trim();
    rfc3339_date(value).or_else(|| rfc3339_date(&format!("{value}Z")))
}

/// `age` is documented as human-readable ("2 days ago"). Only an absolute
/// date is used: an ISO 8601 date, or the `August 4, 2023` form. A relative
/// age is dropped rather than turned into a guessed date.
fn age(value: &str) -> Option<String> {
    let value = value.trim();
    if let Some(date) = rfc3339_date(value) {
        return Some(date);
    }
    const MONTHS: [&str; 12] = [
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
    ];
    let (month, rest) = value.split_once(' ')?;
    let (day, year) = rest.split_once(", ")?;
    let month = MONTHS
        .iter()
        .position(|name| name.eq_ignore_ascii_case(month))?
        + 1;
    let day: u8 = day.parse().ok()?;
    let year: u16 = year.parse().ok()?;
    rfc3339_date(&format!("{year:04}-{month:02}-{day:02}"))
}

#[cfg(test)]
mod tests;
