use super::model::{lower_hex, AgentPolicy, MAX_INTEGER};
use crate::credentials::CkcredRoutePeer;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFailure {
    Unsupported,
    Unreadable,
}

#[derive(Debug)]
pub struct ActivePolicy {
    pub policy: AgentPolicy,
    pub policy_sha256: String,
    pub manifest_version: i64,
    pub rollout: Option<PolicyRollout>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRollout {
    pub manifest_version: u64,
    pub policy_version: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    result: ActiveFields,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveFields {
    #[serde(deserialize_with = "Deserialize::deserialize")]
    version: Option<i64>,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    policy_sha256: Option<String>,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    manifest_version: Option<i64>,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    policy_text: Option<String>,
    rollout: Option<PolicyRollout>,
}

pub fn read_active(peer: &dyn CkcredRoutePeer) -> Result<Option<ActivePolicy>, ReadFailure> {
    let reply = peer.policy_active().map_err(|_| ReadFailure::Unreadable)?;
    decode_active(reply)
}

pub(super) fn decode_active(reply: Value) -> Result<Option<ActivePolicy>, ReadFailure> {
    refuse(&reply)?;
    let Some(fields) = reply.get("result").and_then(Value::as_object) else {
        return Err(ReadFailure::Unreadable);
    };
    if fields
        .get("rollout")
        .is_some_and(|value| !value.is_object())
    {
        return Err(ReadFailure::Unreadable);
    }
    let Reply { result } = serde_json::from_value(reply).map_err(|_| ReadFailure::Unreadable)?;
    match (
        result.version,
        result.policy_sha256,
        result.manifest_version,
        result.policy_text,
    ) {
        // A vault that has stored a newer pair before any pair is ready names it
        // in `rollout` beside an all-null active pair. There is still no active
        // policy to apply; only the rollout's own values are checked.
        (None, None, None, None) => match result.rollout {
            Some(rollout) if rollout.manifest_version == 0 || rollout.policy_version == 0 => {
                Err(ReadFailure::Unreadable)
            }
            _ => Ok(None),
        },
        (Some(version), Some(policy_sha256), Some(manifest_version), Some(text))
            if (1..=MAX_INTEGER).contains(&manifest_version) =>
        {
            if result.rollout.is_some_and(|rollout| {
                rollout.manifest_version <= manifest_version.cast_unsigned()
                    || rollout.policy_version == 0
            }) {
                return Err(ReadFailure::Unreadable);
            }
            let policy = AgentPolicy::parse(&text).map_err(|_| ReadFailure::Unreadable)?;
            if version != policy.version || policy_sha256 != format!("{:x}", Sha256::digest(text)) {
                return Err(ReadFailure::Unreadable);
            }
            Ok(Some(ActivePolicy {
                policy,
                policy_sha256,
                manifest_version,
                rollout: result.rollout,
            }))
        }
        _ => Err(ReadFailure::Unreadable),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchNotice {
    kind: WatchKind,
    pub epoch: String,
    pub seq: u64,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub version: Option<i64>,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub policy_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WatchKind {
    Changed,
}

impl WatchNotice {
    pub fn decode(value: Value) -> Result<Self, ReadFailure> {
        refuse(&value)?;
        if !value.is_object() {
            return Err(ReadFailure::Unreadable);
        }
        let notice: Self = serde_json::from_value(value).map_err(|_| ReadFailure::Unreadable)?;
        let paired = match (&notice.version, &notice.policy_sha256) {
            (None, None) => true,
            (Some(version), Some(hash)) => {
                (1..=MAX_INTEGER).contains(version) && lower_hex(hash, 64)
            }
            _ => false,
        };
        if matches!(notice.kind, WatchKind::Changed)
            && lower_hex(&notice.epoch, 32)
            && notice.seq > 0
            && paired
        {
            Ok(notice)
        } else {
            Err(ReadFailure::Unreadable)
        }
    }
}

fn refuse(value: &Value) -> Result<(), ReadFailure> {
    for path in ["/code", "/error", "/result/error"] {
        if let Some(error) = value.pointer(path) {
            let code = error.as_str().or_else(|| error["code"].as_str());
            return Err(match code {
                Some("unknown_method" | "unsupported_method") => ReadFailure::Unsupported,
                _ => ReadFailure::Unreadable,
            });
        }
    }
    Ok(())
}
