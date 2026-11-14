//! Shared normalization for federated caller identity and display metadata.

use serde_json::json;
use subc_protocol::scope::RemoteClaim;

pub mod card;
pub mod matcher;

/// The paired computer and its remote claim, copied from the daemon's bind
/// stamp. These facts identify a caller for consent and audit; remote agent ids
/// never select this computer's agent grants, policies, recipient lists or bots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedCaller {
    pub attributes: subc_protocol::scope::FederatedAttributes,
    pub claim: CanonicalClaim,
}

impl FederatedCaller {
    pub fn from_attributes(
        attributes: subc_protocol::scope::FederatedAttributes,
    ) -> Result<Self, UnsupportedClaim> {
        let claim = canonicalize_claim(attributes.remote_claim.as_ref())?;
        Ok(Self { attributes, claim })
    }
}

/// A claim's key and display data, normalized together so omitted names cannot
/// reappear in stored claims or labels. The kind is separate from the canonical JSON text:
/// an agent and a run may carry the same id but are different callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalClaim {
    pub claim_kind: &'static str,
    pub canonical_claim_identity: String,
    pub claim: Option<RemoteClaim>,
}

/// A future protocol claim must not collapse into the claimless identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedClaim;

impl std::fmt::Display for UnsupportedClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("unsupported federated claim kind")
    }
}

impl std::error::Error for UnsupportedClaim {}

/// Canonicalize only daemon-stamped claims, never requester-supplied identity.
/// Display names and worker attribution are deliberately absent from the key.
pub fn canonicalize_claim(claim: Option<&RemoteClaim>) -> Result<CanonicalClaim, UnsupportedClaim> {
    let Some(claim) = claim else {
        return Ok(CanonicalClaim {
            claim_kind: "",
            canonical_claim_identity: String::new(),
            claim: None,
        });
    };
    let mut claim = claim.clone();
    let (claim_kind, identity) = match &mut claim {
        RemoteClaim::Agent {
            agent_id,
            agent_name,
            ..
        } => {
            sanitize_name(agent_name);
            ("agent", json!({"agent_id": agent_id}))
        }
        RemoteClaim::Run {
            agent_id,
            agent_name,
            ..
        } => {
            sanitize_name(agent_name);
            ("run", json!({"agent_id": agent_id}))
        }
        RemoteClaim::Worker {
            owner_module_id,
            worker_ref,
            on_behalf_of,
            agent_name,
            ..
        } => {
            if on_behalf_of.is_none() {
                *agent_name = None;
            } else {
                sanitize_name(agent_name);
            }
            (
                "worker",
                json!({"owner_module_id": owner_module_id, "worker_ref": worker_ref}),
            )
        }
        RemoteClaim::Flow {
            flow_id,
            flow_version,
            flow_install_id,
            flow_code_hash,
            flow_name,
            ..
        } => {
            sanitize_name(flow_name);
            (
                "flow",
                json!({"flow_id": flow_id, "flow_version": flow_version,
                "flow_install_id": flow_install_id, "flow_code_hash": flow_code_hash}),
            )
        }
        _ => return Err(UnsupportedClaim),
    };
    // Identity contains strings and a protocol-validated, exactly representable
    // flow version, so it cannot contain a value the JSON canonicalizer rejects.
    let canonical_claim_identity = String::from_utf8(
        crate::jcs::canonicalize(&identity).expect("claim identity is representable as JCS"),
    )
    .expect("JCS is UTF-8");
    Ok(CanonicalClaim {
        claim_kind,
        canonical_claim_identity,
        claim: Some(claim),
    })
}

impl CanonicalClaim {
    /// Contract holder label, or no label for a non-grantable/invalid selector.
    /// Names are rechecked through the same normalization used before storage.
    pub fn holder_label(&self, peer_name: &str, selector: &str) -> Option<String> {
        let clean = canonicalize_claim(self.claim.as_ref()).ok()?;
        let detail = match (selector, clean.claim.as_ref()) {
            (_, Some(RemoteClaim::Run { .. })) => return None,
            ("all_claims", None) => "everything on it".into(),
            ("claimless", None) => "any program".into(),
            (
                "exact_claim",
                Some(RemoteClaim::Agent {
                    agent_id,
                    agent_name,
                    ..
                }),
            ) => named_id(agent_id, agent_name.as_deref()),
            (
                "exact_claim",
                Some(RemoteClaim::Worker {
                    on_behalf_of,
                    agent_name,
                    ..
                }),
            ) => match on_behalf_of {
                Some(agent) => format!("worker for {}", named_id(agent, agent_name.as_deref())),
                None => "worker".into(),
            },
            (
                "exact_claim",
                Some(RemoteClaim::Flow {
                    flow_id,
                    flow_version,
                    flow_name,
                    ..
                }),
            ) => {
                format!(
                    "flow {} v{flow_version}",
                    named_id(flow_id, flow_name.as_deref())
                )
            }
            _ => return None,
        };
        let label = format!("{peer_name} · {detail}");
        Some(crate::text::prefix_within_chars(&label, 80).0.to_owned())
    }
}

fn named_id(id: &str, name: Option<&str>) -> String {
    match name {
        Some(name) => format!("“{name}” ({id})"),
        None => id.to_owned(),
    }
}

fn sanitize_name(name: &mut Option<String>) {
    if name.as_deref().is_some_and(|name| !valid_name(name)) {
        *name = None;
    }
}

fn valid_name(name: &str) -> bool {
    (1..=80).contains(&name.chars().count())
        && !name.chars().any(|ch| {
            ch.is_control()
                || matches!(ch, '\u{061c}' | '\u{200e}'..='\u{200f}' |
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
}

/// Mint a fresh, stored row id. Never derive it from a grant key: replaying an
/// old revocation must not remove a subsequent re-grant of the same key.
pub fn new_row_id() -> String {
    crate::storage::new_id("plxf")
}

#[cfg(test)]
mod tests;
