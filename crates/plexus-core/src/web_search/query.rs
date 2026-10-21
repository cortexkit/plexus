//! The vendor-neutral `web_search` arguments and their validation.

use serde_json::{Map, Value};

use super::WebSearchRefusal;

/// Longest query accepted, in characters after trimming.
pub(crate) const MAX_QUERY_CHARS: usize = 500;
/// Result count used when the caller names none.
const DEFAULT_MAX_RESULTS: u8 = 8;
/// Largest result count a caller may ask for.
pub(crate) const MAX_RESULTS_LIMIT: u8 = 20;
/// Most domains one call may restrict the search to.
pub(crate) const MAX_INCLUDE_DOMAINS: usize = 20;

/// The argument names the tool accepts. Anything else is refused by name.
const KNOWN_FIELDS: &[&str] = &["query", "max_results", "include_domains", "recency"];

/// How recent a result's publication date must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Recency {
    Day,
    Week,
    Month,
    Year,
}

impl Recency {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "day" => Some(Self::Day),
            "week" => Some(Self::Week),
            "month" => Some(Self::Month),
            "year" => Some(Self::Year),
            _ => None,
        }
    }

    /// The argument value that names this window.
    pub fn name(self) -> &'static str {
        match self {
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
            Self::Year => "year",
        }
    }

    /// The window as a whole number of days. A month is 30 days and a year 365:
    /// the filter is a coarse freshness bound, not a calendar query.
    pub fn days(self) -> i64 {
        match self {
            Self::Day => 1,
            Self::Week => 7,
            Self::Month => 30,
            Self::Year => 365,
        }
    }
}

/// One validated search request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSearchQuery {
    /// The query as the caller wrote it, with surrounding whitespace removed.
    pub query: String,
    /// The effective result count: the caller's value or the default.
    pub max_results: u8,
    /// Lower-cased bare hostnames, sorted and de-duplicated.
    pub include_domains: Vec<String>,
    pub recency: Option<Recency>,
}

impl WebSearchQuery {
    /// The filters the caller set, normalized, for the search's audit row:
    /// `include_domains` when any, `recency` when set, and `max_results` when
    /// it differs from the default. These name what a search reads and are
    /// public, so they are recorded as they are.
    pub(crate) fn audited_filters(&self) -> serde_json::Map<String, Value> {
        let mut filters = serde_json::Map::new();
        if !self.include_domains.is_empty() {
            filters.insert(
                "include_domains".into(),
                self.include_domains.clone().into(),
            );
        }
        if let Some(recency) = self.recency {
            filters.insert("recency".into(), recency.name().into());
        }
        if self.max_results != DEFAULT_MAX_RESULTS {
            filters.insert("max_results".into(), self.max_results.into());
        }
        filters
    }

    /// Validate the tool arguments. Every unknown key is refused by name so a
    /// misspelled filter never silently widens a search.
    pub fn parse(arguments: &Map<String, Value>) -> Result<Self, WebSearchRefusal> {
        let invalid = |field: &str| WebSearchRefusal::InvalidQuery {
            field: field.to_string(),
        };
        let mut unknown: Vec<&String> = arguments
            .keys()
            .filter(|key| !KNOWN_FIELDS.contains(&key.as_str()))
            .collect();
        unknown.sort();
        if let Some(field) = unknown.first() {
            return Err(invalid(field));
        }

        let query = match arguments.get("query") {
            Some(Value::String(query)) => query.trim(),
            _ => return Err(invalid("query")),
        };
        let length = query.chars().count();
        if length == 0 || length > MAX_QUERY_CHARS {
            return Err(invalid("query"));
        }

        let max_results = match arguments.get("max_results") {
            None | Some(Value::Null) => DEFAULT_MAX_RESULTS,
            Some(value) => match value.as_u64() {
                Some(count) if (1..=u64::from(MAX_RESULTS_LIMIT)).contains(&count) => count as u8,
                _ => return Err(invalid("max_results")),
            },
        };

        let include_domains = match arguments.get("include_domains") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(entries)) if entries.len() <= MAX_INCLUDE_DOMAINS => {
                let mut domains = Vec::with_capacity(entries.len());
                for entry in entries {
                    match entry.as_str().and_then(bare_hostname) {
                        Some(domain) => domains.push(domain),
                        None => return Err(invalid("include_domains")),
                    }
                }
                domains.sort();
                domains.dedup();
                domains
            }
            Some(_) => return Err(invalid("include_domains")),
        };

        let recency = match arguments.get("recency") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) => match Recency::parse(value) {
                Some(recency) => Some(recency),
                None => return Err(invalid("recency")),
            },
            Some(_) => return Err(invalid("recency")),
        };

        Ok(Self {
            query: query.to_string(),
            max_results,
            include_domains,
            recency,
        })
    }
}

/// Accept a bare DNS hostname (`example.com`, `docs.rs`) and return it
/// lower-cased. A scheme, path, port, wildcard, or single label is refused:
/// the filter is a hostname allowlist, and anything shaped like a URL means
/// the caller expected a different kind of filter than it would get.
fn bare_hostname(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 253 {
        return None;
    }
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    let valid_label = |label: &&str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    };
    labels
        .iter()
        .all(valid_label)
        .then(|| value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(value: Value) -> Result<WebSearchQuery, WebSearchRefusal> {
        WebSearchQuery::parse(value.as_object().expect("object"))
    }

    fn field(result: Result<WebSearchQuery, WebSearchRefusal>) -> String {
        match result {
            Err(WebSearchRefusal::InvalidQuery { field }) => field,
            other => panic!("expected invalid_query, got {other:?}"),
        }
    }

    #[test]
    fn defaults_apply_and_the_query_is_trimmed() {
        let query = parse(json!({"query": "  rust async  "})).unwrap();
        assert_eq!(query.query, "rust async");
        assert_eq!(query.max_results, DEFAULT_MAX_RESULTS);
        assert!(query.include_domains.is_empty());
        assert_eq!(query.recency, None);
    }

    #[test]
    fn domains_are_lower_cased_sorted_and_de_duplicated() {
        let query = parse(json!({
            "query": "q",
            "include_domains": ["Docs.rs", "arxiv.org", "docs.rs"],
            "recency": "week",
            "max_results": 20
        }))
        .unwrap();
        assert_eq!(query.include_domains, vec!["arxiv.org", "docs.rs"]);
        assert_eq!(query.recency, Some(Recency::Week));
        assert_eq!(query.max_results, 20);
    }

    #[test]
    fn each_bad_argument_is_refused_by_its_own_name() {
        assert_eq!(field(parse(json!({}))), "query");
        assert_eq!(field(parse(json!({"query": "   "}))), "query");
        assert_eq!(field(parse(json!({"query": 7}))), "query");
        assert_eq!(field(parse(json!({"query": "x".repeat(501)}))), "query");
        assert!(parse(json!({"query": "x".repeat(500)})).is_ok());
        assert_eq!(
            field(parse(json!({"query": "q", "max_results": 0}))),
            "max_results"
        );
        assert_eq!(
            field(parse(json!({"query": "q", "max_results": 21}))),
            "max_results"
        );
        assert_eq!(
            field(parse(json!({"query": "q", "max_results": 2.5}))),
            "max_results"
        );
        for domain in [
            "https://docs.rs",
            "docs.rs/tokio",
            "*.docs.rs",
            "docs.rs:443",
            "localhost",
            "-bad.com",
        ] {
            assert_eq!(
                field(parse(json!({"query": "q", "include_domains": [domain]}))),
                "include_domains",
                "{domain}"
            );
        }
        let many: Vec<String> = (0..21).map(|index| format!("d{index}.com")).collect();
        assert_eq!(
            field(parse(json!({"query": "q", "include_domains": many}))),
            "include_domains"
        );
        assert_eq!(
            field(parse(json!({"query": "q", "recency": "decade"}))),
            "recency"
        );
        assert_eq!(
            field(parse(json!({"query": "q", "numResults": 3}))),
            "numResults"
        );
        assert_eq!(field(parse(json!({"query": "q", "op": "search"}))), "op");
    }
}
