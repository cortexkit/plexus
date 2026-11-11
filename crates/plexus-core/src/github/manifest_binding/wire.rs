//! The manifest-binding ManagementSurface replies. Error frames and domain
//! refusals stay separate: a malformed request is not a repository verdict.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remedy {
    Retry,
    TerminalRepository,
    Stop,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
    pub code: String,
    pub class: String,
    pub version: Option<i64>,
    pub manifest_sha256: Option<String>,
    pub remedy_member: Option<String>,
}

impl Refusal {
    pub fn remedy(&self) -> Remedy {
        let (class, remedy) = match self.code.as_str() {
            "one_tap_disabled"
            | "identity_unavailable"
            | "github_unavailable"
            | "stale_base"
            | "store_error"
            | "pairing_unavailable"
            | "home_unavailable"
            | "unknown_version" => ("transient", Remedy::Retry),
            // already_bound carries a stored version to follow to readiness;
            // superseded needs a fresh proposal on the next discovery pass.
            "already_bound" | "superseded" => ("permanent", Remedy::Retry),
            "not_installed" | "installation_all" | "bound_to_other_agent" | "expired" => {
                ("permanent", Remedy::TerminalRepository)
            }
            "not_found"
            | "manifest_setup_incomplete"
            | "identity_mismatch"
            | "installation_unusable"
            | "installation_too_large"
            | "not_reproducible"
            | "phone_not_registered"
            | "secret_home_elsewhere"
            | "remote_setup_incomplete"
            | "approval_invalid"
            | "secret_setup_incomplete" => ("permanent", Remedy::Stop),
            _ => return Remedy::Stop,
        };
        if self.class != class {
            return Remedy::Stop;
        }
        if self.code == "already_bound"
            && !matches!((&self.version, &self.manifest_sha256), (Some(v), Some(h)) if *v > 0 && valid_hash(h))
        {
            return Remedy::Stop;
        }
        remedy
    }
}

pub fn transport_remedy(code: &str) -> Remedy {
    match code {
        "unknown_method"
        | "invalid_params"
        | "invalid_request"
        | "flow_scopes_unsupported"
        | "invalid_control_body"
        | "unknown_module" => Remedy::Stop,
        _ => Remedy::Retry,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    Domain(Refusal),
    Transport(String),
    InvalidReply,
}

impl Failure {
    pub fn remedy(&self) -> Remedy {
        match self {
            Self::Domain(refusal) => refusal.remedy(),
            Self::Transport(code) => transport_remedy(code),
            Self::InvalidReply => Remedy::Stop,
        }
    }
    pub fn code(&self) -> &str {
        match self {
            Self::Domain(refusal) => &refusal.code,
            Self::Transport(code) => code,
            Self::InvalidReply => "invalid_manifest_reply",
        }
    }
}

pub fn response<T: DeserializeOwned>(value: Value) -> Result<T, Failure> {
    if value.get("code").is_some() && value.get("result").is_none() {
        return Err(Failure::Transport(
            value["code"].as_str().ok_or(Failure::InvalidReply)?.into(),
        ));
    }
    let result = value.get("result").ok_or(Failure::InvalidReply)?;
    if let Some(error) = result.get("error") {
        return Err(Failure::Domain(
            serde_json::from_value(error.clone()).map_err(|_| Failure::InvalidReply)?,
        ));
    }
    serde_json::from_value(result.clone()).map_err(|_| Failure::InvalidReply)
}

pub fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub status: String,
    pub proposal_id: String,
    pub statement_b64url: String,
    pub manifest_version: i64,
    pub manifest_sha256: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub v: String,
    pub proposal_id: String,
    pub agent_id: String,
    pub app_slug: String,
    pub repo: String,
    pub installation_permissions: std::collections::BTreeMap<String, String>,
    pub manifest_version: i64,
    pub manifest_sha256: String,
    pub prior_version: i64,
    pub prior_sha256: String,
    pub expires_at_ms: i64,
}

impl Proposal {
    pub fn statement(&self, agent: &str, slug: &str, repo: &str) -> Result<Statement, Failure> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.statement_b64url)
            .map_err(|_| Failure::InvalidReply)?;
        let statement: Statement =
            serde_json::from_slice(&bytes).map_err(|_| Failure::InvalidReply)?;
        if self.status != "approval_required"
            || self.proposal_id.len() != 26
            || !self
                .proposal_id
                .bytes()
                .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
            || self.manifest_version <= 0
            || !valid_hash(&self.manifest_sha256)
            || statement.v != "ck-manifest-binding-statement/v1"
            || statement.proposal_id != self.proposal_id
            || statement.agent_id != agent
            || statement.app_slug != slug
            || !statement.repo.eq_ignore_ascii_case(repo)
            || statement.manifest_version != self.manifest_version
            || statement.manifest_sha256 != self.manifest_sha256
            || statement.expires_at_ms != self.expires_at_ms
            || statement.prior_version <= 0
            || statement.prior_version.checked_add(1) != Some(self.manifest_version)
            || !valid_hash(&statement.prior_sha256)
            || statement
                .installation_permissions
                .values()
                .any(|v| !matches!(v.as_str(), "read" | "write" | "admin"))
        {
            return Err(Failure::InvalidReply);
        }
        Ok(statement)
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Notice {
    pub kind: String,
    pub epoch: String,
    pub seq: u64,
    pub version: Option<i64>,
    pub manifest_sha256: Option<String>,
}

impl Notice {
    pub fn decode(value: Value) -> Result<Self, Failure> {
        let notice: Self = serde_json::from_value(value).map_err(|_| Failure::InvalidReply)?;
        if notice.kind != "changed"
            || notice.seq == 0
            || notice.epoch.is_empty()
            || !matches!(
                (&notice.version, &notice.manifest_sha256),
                (None, None) | (Some(1..), Some(_))
            )
            || notice
                .manifest_sha256
                .as_deref()
                .is_some_and(|h| !valid_hash(h))
        {
            return Err(Failure::InvalidReply);
        }
        Ok(notice)
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActiveStatus {
    pub version: i64,
    pub manifest_sha256: String,
    pub ready: bool,
    pub computers: Vec<Computer>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Computer {
    pub member_id: String,
    pub version: Option<i64>,
    pub payload_sha256: Option<String>,
    pub verdict: Option<String>,
    pub reason: Option<String>,
    pub reported_at_ms: Option<i64>,
}

impl ActiveStatus {
    pub fn ready_for(&self, version: i64, hash: &str) -> bool {
        self.ready
            && self.version == version
            && self.manifest_sha256 == hash
            && valid_hash(hash)
            && !self.computers.is_empty()
            && self
                .computers
                .windows(2)
                .all(|w| w[0].member_id < w[1].member_id)
            && self.computers.iter().all(|c| {
                !c.member_id.is_empty()
                    && c.version == Some(version)
                    && c.payload_sha256.as_deref() == Some(hash)
                    && c.verdict.as_deref() == Some("valid")
                    && c.reported_at_ms.is_some()
                    && c.reason.is_none()
            })
    }
}
