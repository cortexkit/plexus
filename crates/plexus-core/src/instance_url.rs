//! Private per-connection REST addresses. Parsing and outbound admission precede storage.

use std::fmt;

#[derive(Clone, PartialEq, Eq)]
pub struct InstanceUrl(String);

impl InstanceUrl {
    /// Reject inline credentials, query strings and fragments: auth belongs in the
    /// vault, while query parameters belong to the reviewed search operation.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        if !crate::manifest::transport_url_is_acceptable(value) {
            return Err("instance_url must use HTTPS, or HTTP to loopback");
        }
        let mut url = reqwest::Url::parse(value).map_err(|_| "instance_url is invalid")?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("instance_url must not contain credentials, a query, or a fragment");
        }
        // The transport appends /search, so a trailing slash is immaterial.
        let path = url.path().trim_end_matches('/').to_string();
        url.set_path(&path);
        Ok(Self(url.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for InstanceUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstanceUrl([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn searxng_address_validation_parses_before_outbound_admission() {
        for url in [
            "http://remote.invalid",
            "http://localhost:80@remote.invalid",
            "http://127.0.0.1.evil.invalid",
            "ftp://localhost",
            "not a URL",
            " https://example.org",
            "https://user:pass@example.org",
            "https://example.org?token=x",
            "https://example.org/#x",
        ] {
            assert!(InstanceUrl::parse(url).is_err(), "unsafe address admitted");
        }
        for url in [
            "https://remote.invalid",
            "http://localhost:8080",
            "http://127.0.0.2",
            "http://[::1]:8888",
            "http://2130706433",
        ] {
            assert!(InstanceUrl::parse(url).is_ok(), "safe address rejected");
        }
        assert_eq!(
            InstanceUrl::parse("https://EXAMPLE.org:443/base///")
                .unwrap()
                .as_str(),
            "https://example.org/base"
        );
    }

    #[test]
    fn searxng_instance_debug_never_discloses_the_address() {
        let url =
            InstanceUrl::parse("https://private-instance-canary.invalid/secret-path").unwrap();
        let rendered = format!("{url:?}");
        assert!(rendered.contains("InstanceUrl"));
        assert!(!rendered.contains("private-instance-canary"));
        assert!(!rendered.contains("secret-path"));
    }
}
