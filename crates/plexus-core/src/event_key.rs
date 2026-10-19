//! Transport-independent identity for GitHub notices. Body and routing hints are
//! deliberately excluded so polls and a future webhook reader share identities.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const GITHUB_ISSUE_CHANGED: &str = "github_issue_changed";
pub const GITHUB_PR_CHANGED: &str = "github_pr_changed";
pub const GITHUB_PR_REVIEW_SUBMITTED: &str = "github_pr_review_submitted";
pub const GITHUB_PR_REVIEW_COMMENT_CREATED: &str = "github_pr_review_comment_created";
pub const GITHUB_RELEASE_PUBLISHED: &str = "github_release_published";
pub const GITHUB_CI_JOB_FAILED: &str = "github_ci_job_failed";
pub const GITHUB_CI_JOB_COMPLETED: &str = "github_ci_job_completed";
pub const GITHUB_CI_RUN_COMPLETED: &str = "github_ci_run_completed";

/// Names and filter headers accepted by the outbox and declared in HELLO.
/// Publisher mappings use these names so an outbox event cannot be publishable
/// without also being present in the module's event declarations.
///
/// Each event declares only the headers its producers can set: issue and
/// release notices carry no pull request, branch or conclusion, so declaring
/// those would promise flow authors filters that never match. Widening a list
/// is additive; narrowing one later would break a flow that filters on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedEvent {
    pub name: &'static str,
    pub headers: &'static [&'static str],
    pub summary: &'static str,
}

pub const PUBLISHED_EVENT_VERSIONS: &[u8] = &[1, 2];
pub const V2_EVENT_KEY_HEADER: &str = "event_key";

impl PublishedEvent {
    pub fn versions(&self) -> &'static [u8] {
        if is_review_notice(self.name) {
            &[1]
        } else {
            PUBLISHED_EVENT_VERSIONS
        }
    }

    pub fn headers_for_version(&self, version: u8) -> Vec<&'static str> {
        self.headers
            .iter()
            .copied()
            .chain((version == 2).then_some(V2_EVENT_KEY_HEADER))
            .collect()
    }
}

pub const PUBLISHED_EVENTS: &[PublishedEvent] = &[
    PublishedEvent {
        name: GITHUB_ISSUE_CHANGED,
        headers: &["repo", "project"],
        summary: "An issue changed in a watched GitHub repository.",
    },
    PublishedEvent {
        name: GITHUB_PR_CHANGED,
        headers: &["repo", "project", "pr"],
        summary: "A pull request changed in a watched GitHub repository.",
    },
    PublishedEvent {
        name: GITHUB_RELEASE_PUBLISHED,
        headers: &["repo", "project"],
        summary: "A release was published in a watched GitHub repository.",
    },
    PublishedEvent {
        name: GITHUB_CI_JOB_FAILED,
        headers: &["repo", "project", "pr", "branch", "conclusion"],
        summary: "A GitHub Actions job failed in a watched repository.",
    },
    PublishedEvent {
        name: GITHUB_CI_JOB_COMPLETED,
        headers: &["repo", "project", "pr", "branch", "conclusion"],
        summary: "A GitHub Actions job completed in a watched repository.",
    },
    PublishedEvent {
        name: GITHUB_CI_RUN_COMPLETED,
        headers: &["repo", "project", "pr", "branch", "conclusion"],
        summary: "A GitHub Actions workflow run completed in a watched repository.",
    },
    PublishedEvent {
        name: GITHUB_PR_REVIEW_SUBMITTED,
        headers: &["repo", "project", "pr"],
        summary: "A review was submitted on a watched GitHub pull request.",
    },
    PublishedEvent {
        name: GITHUB_PR_REVIEW_COMMENT_CREATED,
        headers: &["repo", "project", "pr"],
        summary: "A review comment was created on a watched GitHub pull request.",
    },
];

pub(crate) fn is_review_notice(kind: &str) -> bool {
    matches!(
        kind,
        GITHUB_PR_REVIEW_SUBMITTED | GITHUB_PR_REVIEW_COMMENT_CREATED
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKeyError {
    UnknownKind,
    InvalidField(&'static str),
    Canonicalization(crate::jcs::JcsError),
}

impl std::fmt::Display for EventKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownKind => f.write_str("unknown GitHub event name"),
            Self::InvalidField(field) => {
                write!(f, "missing or invalid event identity field: {field}")
            }
            Self::Canonicalization(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for EventKeyError {}

#[derive(Clone, Copy)]
pub(crate) enum GithubEventKind {
    Issue,
    PullRequest,
    CiJob,
    CiRun,
    Release,
}

impl GithubEventKind {
    pub(crate) fn parse(name: &str) -> Result<Self, EventKeyError> {
        Ok(match name {
            GITHUB_ISSUE_CHANGED => Self::Issue,
            GITHUB_PR_CHANGED => Self::PullRequest,
            GITHUB_CI_JOB_FAILED | GITHUB_CI_JOB_COMPLETED => Self::CiJob,
            GITHUB_CI_RUN_COMPLETED => Self::CiRun,
            GITHUB_RELEASE_PUBLISHED => Self::Release,
            _ => return Err(EventKeyError::UnknownKind),
        })
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::PullRequest => "pull_request",
            Self::CiJob => "ci_job",
            Self::CiRun => "ci_run",
            Self::Release => "release",
        }
    }
}

/// Hash exactly the identity fields for `kind`. Integer fields must be JSON
/// integers and are kept exact at any size; strings are kept verbatim,
/// including vendor timestamp spelling.
/// Additional fields (action, actor, body, routing hints) have no effect.
pub fn derive_event_key(kind: &str, fields: &Value) -> Result<String, EventKeyError> {
    let (integers, strings): (&[&'static str], &[&'static str]) = match kind {
        GITHUB_PR_REVIEW_SUBMITTED => (&["repo_id", "review_id"], &[]),
        GITHUB_PR_REVIEW_COMMENT_CREATED => (&["repo_id", "comment_id"], &[]),
        _ => match GithubEventKind::parse(kind)? {
            GithubEventKind::Issue | GithubEventKind::PullRequest => {
                (&["repo_id", "number"], &["updated_at"])
            }
            GithubEventKind::Release => (&["repo_id", "release_id"], &[]),
            GithubEventKind::CiJob => (&["repo_id", "job_id", "run_attempt"], &["conclusion"]),
            GithubEventKind::CiRun => (&["repo_id", "run_id", "run_attempt"], &["conclusion"]),
        },
    };
    let mut identity = Map::new();
    identity.insert("kind".into(), Value::String(kind.into()));
    for &name in integers {
        let value = fields
            .get(name)
            .filter(|v| v.is_i64() || v.is_u64())
            .ok_or(EventKeyError::InvalidField(name))?;
        identity.insert(name.into(), value.clone());
    }
    for &name in strings {
        let value = fields
            .get(name)
            .filter(|v| v.is_string())
            .ok_or(EventKeyError::InvalidField(name))?;
        identity.insert(name.into(), value.clone());
    }
    // Exact integers, not RFC 8785's doubles: past 2^53 two distinct vendor
    // ids would otherwise share a key and one notice would be dropped as a
    // duplicate of the other. Only plexus computes this key (consumers read
    // it from the notice), so it need not match any other canonicalizer, and
    // below 2^53 the bytes are RFC 8785's, so no existing key moves.
    let bytes = crate::jcs::canonicalize_exact_integers(&Value::Object(identity))
        .map_err(EventKeyError::Canonicalization)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_vectors_and_webhook_projections_share_all_six_keys() {
        let vectors: Value = serde_json::from_str(include_str!("event_key_vectors.json")).unwrap();
        let vectors = vectors.as_array().unwrap();
        assert_eq!(vectors.len(), 6);
        for vector in vectors {
            let kind = vector["input"]["kind"].as_str().unwrap();
            let key = derive_event_key(kind, &vector["input"]).unwrap();
            assert_eq!(key, vector["expected"].as_str().unwrap(), "{kind}");
            assert_eq!(key.len(), 64);
            assert!(key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
            // A webhook's action and sender are not part of the semantic identity.
            let mut webhook = vector["input"].clone();
            webhook["action"] = Value::String("edited".into());
            webhook["sender"] = serde_json::json!({"login": "different-actor"});
            assert_eq!(derive_event_key(kind, &webhook).unwrap(), key);
        }
    }

    #[test]
    fn distinct_updates_and_verbatim_strings_do_not_collapse() {
        let input =
            serde_json::json!({"repo_id": 101, "number": 7, "updated_at": "2026-10-07T00:00:00Z"});
        let mut later = input.clone();
        later["updated_at"] = Value::String("2026-10-07T00:00:01Z".into());
        assert_ne!(
            derive_event_key("github_issue_changed", &input).unwrap(),
            derive_event_key("github_issue_changed", &later).unwrap()
        );
        later["number"] = serde_json::json!(7.0);
        assert_eq!(
            derive_event_key("github_issue_changed", &later),
            Err(EventKeyError::InvalidField("number"))
        );
        assert_eq!(
            derive_event_key("unknown", &input),
            Err(EventKeyError::UnknownKind)
        );
    }

    /// Two notices that differ only in an id past 2^53 are different notices.
    /// RFC 8785 would write both ids through the same double, giving them one
    /// key, and the second would be dropped as a duplicate of the first.
    #[test]
    fn ids_past_2_pow_53_keep_distinct_keys() {
        let two_pow_53: u64 = 1 << 53;
        let first = serde_json::json!({"repo_id": 101, "release_id": two_pow_53});
        let second = serde_json::json!({"repo_id": 101, "release_id": two_pow_53 + 1});
        assert_ne!(
            derive_event_key(GITHUB_RELEASE_PUBLISHED, &first).unwrap(),
            derive_event_key(GITHUB_RELEASE_PUBLISHED, &second).unwrap(),
            "release ids past 2^53 must keep distinct keys"
        );
        let first = serde_json::json!({
            "repo_id": two_pow_53 + 2, "job_id": 1, "run_attempt": 1, "conclusion": "failure"
        });
        let mut second = first.clone();
        second["repo_id"] = serde_json::json!(two_pow_53 + 3);
        assert_ne!(
            derive_event_key(GITHUB_CI_JOB_FAILED, &first).unwrap(),
            derive_event_key(GITHUB_CI_JOB_FAILED, &second).unwrap(),
            "repository ids past 2^53 must keep distinct keys"
        );
    }
}
