//! Provider identities shared by order, allowance, limits and health consumers.
//! Existing Tavily and Firecrawl MCP connections are not REST search candidates.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultCredential {
    Required(&'static str),
    /// SearXNG instances may allow unauthenticated searches.
    Optional(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderName {
    /// The order name, which must equal `WebSearchBackend::name()`.
    pub name: &'static str,
    pub app_key: &'static str,
    pub manifest: &'static str,
    pub action: &'static str,
    pub credential: VaultCredential,
    /// The connection id `add-web-search-provider` creates or reuses for this
    /// provider. Fixed here so a rerun finds the same connection instead of
    /// creating a second candidate for the same provider.
    pub connection_id: &'static str,
}

macro_rules! rest_provider {
    ($name:literal) => {
        ProviderName {
            name: $name,
            app_key: concat!($name, "_rest"),
            manifest: concat!("catalog/", $name, "_rest.jsonc"),
            action: "search",
            credential: VaultCredential::Required(concat!("apikey:", $name)),
            connection_id: concat!("conn-web-search-", $name),
        }
    };
}

/// Recognized names do not imply an installed manifest or backend. REST search
/// uses `*_rest` app keys, distinct from the existing `tavily` and `firecrawl`
/// MCP app keys, so those MCP connections cannot be selected for REST search.
/// Exa keeps its existing credential reference, `apikey:exa`, and its existing
/// deployed connection, `conn-exa-rest`.
pub const PROVIDER_NAMES: &[ProviderName] = &[
    ProviderName {
        connection_id: "conn-exa-rest",
        ..rest_provider!("exa")
    },
    rest_provider!("tavily"),
    rest_provider!("brave"),
    rest_provider!("deepseek"),
    rest_provider!("firecrawl"),
    rest_provider!("jina"),
    rest_provider!("kagi"),
    ProviderName {
        // Search uses the Kimi Code Console key, not a Moonshot platform key.
        credential: VaultCredential::Required("apikey:kimi-for-coding"),
        ..rest_provider!("kimi")
    },
    ProviderName {
        credential: VaultCredential::Required("apikey:ollama-cloud"),
        ..rest_provider!("ollama")
    },
    rest_provider!("parallel"),
    rest_provider!("perplexity"),
    rest_provider!("synthetic"),
    rest_provider!("tinyfish"),
    ProviderName {
        name: "searxng",
        credential: VaultCredential::Optional("apikey:searxng"),
        ..rest_provider!("searxng")
    },
    ProviderName {
        name: "zai",
        app_key: "zai",
        manifest: "catalog/zai.jsonc",
        // Runtime MCP action; the vendor overview calls it webSearchPrime.
        // https://docs.z.ai/devpack/mcp/search-mcp-server#supported-tools
        action: "web_search_prime",
        credential: VaultCredential::Required("apikey:zai"),
        connection_id: "conn-web-search-zai",
    },
];

pub fn provider_named(name: &str) -> Option<&'static ProviderName> {
    PROVIDER_NAMES.iter().find(|provider| provider.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_search::{ExaRestBackend, WebSearchBackend};

    #[test]
    fn provider_table_pins_names_and_bindings() {
        assert_eq!(
            PROVIDER_NAMES
                .iter()
                .map(|provider| provider.name)
                .collect::<Vec<_>>(),
            [
                "exa",
                "tavily",
                "brave",
                "deepseek",
                "firecrawl",
                "jina",
                "kagi",
                "kimi",
                "ollama",
                "parallel",
                "perplexity",
                "synthetic",
                "tinyfish",
                "searxng",
                "zai"
            ]
        );
        for provider in &PROVIDER_NAMES[..14] {
            assert_eq!(provider.app_key, format!("{}_rest", provider.name));
            assert_eq!(
                provider.manifest,
                format!("catalog/{}_rest.jsonc", provider.name)
            );
            assert_eq!(provider.action, "search");
            match provider.name {
                "kimi" => assert_eq!(
                    provider.credential,
                    VaultCredential::Required("apikey:kimi-for-coding")
                ),
                "ollama" => assert_eq!(
                    provider.credential,
                    VaultCredential::Required("apikey:ollama-cloud")
                ),
                "searxng" => assert_eq!(
                    provider.credential,
                    VaultCredential::Optional("apikey:searxng")
                ),
                _ => {
                    let VaultCredential::Required(name) = provider.credential else {
                        panic!("only SearXNG permits no credential")
                    };
                    assert_eq!(name, format!("apikey:{}", provider.name));
                }
            }
            assert_eq!(provider_named(provider.name), Some(provider));
            let connection = if provider.name == "exa" {
                "conn-exa-rest".to_string()
            } else {
                format!("conn-web-search-{}", provider.name)
            };
            assert_eq!(provider.connection_id, connection);
        }
        let exa = provider_named(ExaRestBackend.name()).unwrap();
        assert_eq!(exa.app_key, ExaRestBackend.app_key());
        assert_eq!(exa.action, ExaRestBackend.action());
        assert_eq!(exa.credential, VaultCredential::Required("apikey:exa"));
        assert_eq!(
            provider_named("zai"),
            Some(&ProviderName {
                name: "zai",
                app_key: "zai",
                manifest: "catalog/zai.jsonc",
                action: "web_search_prime",
                credential: VaultCredential::Required("apikey:zai"),
                connection_id: "conn-web-search-zai",
            })
        );
        for unknown in ["", "EXA", "exa_rest", "tavily_rest", "google", "public"] {
            assert!(
                provider_named(unknown).is_none(),
                "{unknown} is not an order name"
            );
        }
    }
}
