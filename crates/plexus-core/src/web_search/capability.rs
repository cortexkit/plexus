//! Pure provider admission: compose every requested filter before checking size.
//!
//! Preparation has no engine, store, clock or transport access. A rejected
//! provider therefore cannot dispatch, reserve allowance or start a cooldown.

use serde::Serialize;
use serde_json::Value;

use super::query::{Recency, WebSearchQuery};
use crate::poller::iso8601;

pub const ALL_RECENCIES: &[Recency] = &[Recency::Day, Recency::Week, Recency::Month, Recency::Year];

/// The units used by the vendor, not the caller-side argument validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryLengthUnit {
    UnicodeScalars,
    Utf8Bytes,
    Utf16CodeUnits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryLengthLimit {
    pub max: usize,
    pub unit: QueryLengthUnit,
}

impl QueryLengthLimit {
    fn accepts(self, query: &str) -> bool {
        let length = match self.unit {
            QueryLengthUnit::UnicodeScalars => query.chars().count(),
            QueryLengthUnit::Utf8Bytes => query.len(),
            QueryLengthUnit::Utf16CodeUnits => query.encode_utf16().count(),
        };
        length <= self.max
    }
}

/// Native fields are mapped by `vendor_args`. Operators use grouped `site:`
/// alternatives for domains and an `after:YYYY-MM-DD` publication bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterEncoding {
    Native,
    QueryOperators,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainCapability {
    /// Zero means unsupported; one admits a single-domain vendor header.
    pub max_domains: usize,
    pub encoding: FilterEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecencyCapability {
    /// An empty list means no recency filter is supported.
    pub supported: &'static [Recency],
    pub encoding: FilterEncoding,
}

/// The supported request envelope of a backend. A backend may use a smaller
/// envelope than the vendor's limit, but must never promise a larger one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebSearchCapability {
    pub query_length: QueryLengthLimit,
    pub max_results: u8,
    pub domains: DomainCapability,
    pub recency: RecencyCapability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityFailure {
    Length,
    DomainFilter,
    Recency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySkipReason {
    Capability,
}

/// A chain can record this skip directly, without retaining query text or
/// reconstructing which provider check failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilitySkip {
    pub provider: &'static str,
    pub reason: CapabilitySkipReason,
    pub failed: CapabilityFailure,
}

/// Only admitted requests reach vendor argument mapping. Keep `query` for the
/// clamped reply bound as well as for fixture assertions about final operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedSearch {
    pub query: WebSearchQuery,
    pub vendor_args: Value,
}

impl WebSearchCapability {
    pub fn prepare_query(
        self,
        provider: &'static str,
        query: &WebSearchQuery,
        now_ms: i64,
    ) -> Result<WebSearchQuery, CapabilitySkip> {
        let skip = |failed| CapabilitySkip {
            provider,
            reason: CapabilitySkipReason::Capability,
            failed,
        };
        if query.include_domains.len() > self.domains.max_domains {
            return Err(skip(CapabilityFailure::DomainFilter));
        }
        if query
            .recency
            .is_some_and(|recency| !self.recency.supported.contains(&recency))
        {
            return Err(skip(CapabilityFailure::Recency));
        }

        let mut prepared = query.clone();
        if self.domains.encoding == FilterEncoding::QueryOperators
            && !query.include_domains.is_empty()
        {
            let sites = query
                .include_domains
                .iter()
                .map(|domain| format!("site:{domain}"))
                .collect::<Vec<_>>();
            prepared.query = format!("({}) ({})", prepared.query, sites.join(" OR "));
        }
        if self.recency.encoding == FilterEncoding::QueryOperators {
            if let Some(recency) = query.recency {
                let start = now_ms.saturating_sub(recency.days() * 86_400_000);
                let timestamp = iso8601::format_millis(start);
                let day = timestamp
                    .split('T')
                    .next()
                    .expect("formatted timestamp has a date");
                prepared.query = format!("({}) after:{day}", prepared.query);
            }
        }
        // Size must include all operators. Truncating to fit would silently
        // widen the search by dropping terms, domains or the publication bound.
        if !self.query_length.accepts(&prepared.query) {
            return Err(skip(CapabilityFailure::Length));
        }
        prepared.max_results = prepared.max_results.min(self.max_results);
        Ok(prepared)
    }
}

#[cfg(test)]
mod tests;
