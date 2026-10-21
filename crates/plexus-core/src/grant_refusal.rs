//! Stable capability names for grant refusals and restoration checks.
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    Module,
    Agent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cause {
    Missing,
    Expired,
    ActionSelector,
    RiskCeiling,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantTarget {
    pub layer: Layer,
    pub grantee: String,
    pub tool: String,
    pub connection: Option<String>,
    pub action: String,
}

impl GrantTarget {
    pub fn new(
        layer: Layer,
        grantee: &str,
        tool: &str,
        connection: Option<&str>,
        action: &str,
    ) -> Self {
        Self {
            layer,
            grantee: grantee.into(),
            tool: tool.into(),
            connection: connection.map(str::to_owned),
            action: action.into(),
        }
    }
    pub fn reference(&self) -> String {
        let bytes =
            crate::jcs::canonicalize(&serde_json::to_value(self).expect("grant target JSON"));
        // The tuple is non-secret metadata. Encoding it lets a restoration check
        // resolve a deleted grant without writing a separate lookup table.
        format!(
            "g1.{}",
            encode(&bytes.expect("grant target canonical JSON"))
        )
    }
    pub fn decode(reference: &str) -> Option<Self> {
        let bytes = decode(reference.strip_prefix("g1.")?)?;
        let target: Self = serde_json::from_slice(&bytes).ok()?;
        (target.reference() == reference).then_some(target)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GrantDetail {
    pub grant: String,
    pub grant_label: String,
    pub layer: Layer,
    pub connection: Option<String>,
    pub action: String,
    pub cause: Cause,
}

/// A layer code cannot be constructed separately from its mandatory detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRefusal {
    detail: GrantDetail,
}
impl GrantRefusal {
    pub fn new(target: GrantTarget, cause: Cause) -> Self {
        let layer = match target.layer {
            Layer::Module => "module",
            Layer::Agent => "agent",
        };
        let capability = if target.tool == "web_search" {
            "web search".into()
        } else {
            format!(
                "{}: {} on {}",
                target.tool,
                target.action,
                target.connection.as_deref().unwrap_or("unknown connection")
            )
        };
        Self {
            detail: GrantDetail {
                grant: target.reference(),
                grant_label: format!("{capability} ({layer} grant for {})", target.grantee),
                layer: target.layer,
                connection: target.connection,
                action: target.action,
                cause,
            },
        }
    }
    pub fn code(&self) -> &'static str {
        match self.detail.layer {
            Layer::Module => "module_grant_absent",
            Layer::Agent => "agent_grant_absent",
        }
    }
    pub fn detail(&self) -> &GrantDetail {
        &self.detail
    }
    pub fn wire(&self) -> Value {
        serde_json::json!({"code":self.code(), "detail":self.detail})
    }
}

/// Grant references use base64url without padding, decoded strictly: padding,
/// characters outside the URL-safe alphabet, impossible lengths and non-zero
/// trailing bits are all refused, so each reference has exactly one spelling.
fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
fn decode(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grant_refs_use_canonical_base64url_and_round_trip() {
        for (bytes, expected) in [
            (b"f".as_slice(), "Zg"),
            (b"fo".as_slice(), "Zm8"),
            (b"foo".as_slice(), "Zm9v"),
            (b"foob".as_slice(), "Zm9vYg"),
        ] {
            assert_eq!(encode(bytes), expected);
            assert_eq!(decode(expected).unwrap(), bytes);
        }
        let target = GrantTarget::new(
            Layer::Agent,
            "agent_unicode_ü",
            "github",
            Some("conn/with spaces"),
            "create_issue",
        );
        assert_eq!(
            GrantTarget::decode(&target.reference()),
            Some(target.clone())
        );
        assert_eq!(decode("Zg="), None);
        assert_eq!(decode("Zh"), None);
        assert!(GrantTarget::decode("g1.e30").is_none());
        let decoded = decode(target.reference().strip_prefix("g1.").unwrap()).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "{\"action\":\"create_issue\",\"connection\":\"conn/with spaces\",\"grantee\":\"agent_unicode_ü\",\"layer\":\"agent\",\"tool\":\"github\"}");
    }

    /// The hand-written codec grant references used before the `base64` crate,
    /// kept as the reference the crate's strict URL-safe engine must match.
    mod replaced {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        pub(super) fn encode(bytes: &[u8]) -> String {
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let n = (u32::from(chunk[0]) << 16)
                    | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                    | u32::from(*chunk.get(2).unwrap_or(&0));
                for shift in [18, 12, 6, 0].into_iter().take(chunk.len() + 1) {
                    out.push(ALPHABET[((n >> shift) & 63) as usize] as char);
                }
            }
            out
        }
        pub(super) fn decode(text: &str) -> Option<Vec<u8>> {
            if text.len() % 4 == 1 {
                return None;
            }
            let mut out = Vec::new();
            let mut accumulator = 0u32;
            let mut bits = 0;
            for byte in text.bytes() {
                let digit = ALPHABET.iter().position(|b| *b == byte)? as u32;
                accumulator = (accumulator << 6) | digit;
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push((accumulator >> bits) as u8);
                }
            }
            (encode(&out) == text).then_some(out)
        }
    }

    #[test]
    fn grant_reference_codec_matches_the_replaced_codec() {
        // Encoding: every byte string up to two bytes, and longer pseudo-random
        // ones, including the grant targets refusals actually carry.
        let mut inputs: Vec<Vec<u8>> = vec![vec![]];
        for a in 0..=255u8 {
            inputs.push(vec![a]);
            for b in 0..=255u8 {
                inputs.push(vec![a, b]);
            }
        }
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            seed >> 33
        };
        for length in 3..=96 {
            for _ in 0..64 {
                inputs.push((0..length).map(|_| next() as u8).collect());
            }
        }
        for (layer, tool, connection) in [
            (Layer::Module, "github", Some("github-app")),
            (Layer::Agent, "github", Some("conn/with spaces")),
            (Layer::Module, "web_search", None),
            (Layer::Module, "code_search", Some("grep_app")),
        ] {
            let target = GrantTarget::new(layer, "broca", tool, connection, "searchGitHub");
            let bytes = crate::jcs::canonicalize(&serde_json::to_value(&target).unwrap()).unwrap();
            assert_eq!(
                target.reference(),
                format!("g1.{}", replaced::encode(&bytes))
            );
            inputs.push(bytes);
        }
        for bytes in &inputs {
            assert_eq!(encode(bytes), replaced::encode(bytes), "{bytes:?}");
        }

        // Decoding: every text up to three characters over the URL-safe
        // alphabet plus padding, the standard alphabet's `+` and `/`, and
        // other bytes; every four-character text over a smaller set; and
        // pseudo-random longer texts. Whatever the replaced codec refused
        // must still be refused, and everything else must decode the same.
        let mut symbols: Vec<char> =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                .chars()
                .collect();
        symbols.extend(['=', '+', '/', ' ', '.', '\n', 'é']);
        let mut texts = vec![String::new()];
        for a in &symbols {
            texts.push(a.to_string());
            for b in &symbols {
                texts.push(format!("{a}{b}"));
                for c in &symbols {
                    texts.push(format!("{a}{b}{c}"));
                }
            }
        }
        let small = ['A', 'B', 'Q', 'g', 'w', '_', '-', '=', '+'];
        for a in small {
            for b in small {
                for c in small {
                    for d in small {
                        texts.push(format!("{a}{b}{c}{d}"));
                    }
                }
            }
        }
        for length in 4..=16 {
            for _ in 0..2_000 {
                texts.push(
                    (0..length)
                        .map(|_| symbols[next() as usize % symbols.len()])
                        .collect(),
                );
            }
        }
        for bytes in &inputs {
            let text = replaced::encode(bytes);
            texts.push(format!("{text}="));
            texts.push(format!("{text}=="));
            texts.push(text);
        }
        let mut refused = 0;
        for text in &texts {
            let expected = replaced::decode(text);
            refused += usize::from(expected.is_none());
            assert_eq!(
                decode(text),
                expected,
                "{text:?} must decode as the replaced codec did"
            );
        }
        assert!(
            refused > texts.len() / 2,
            "the corpus must exercise refusals"
        );
    }
}
