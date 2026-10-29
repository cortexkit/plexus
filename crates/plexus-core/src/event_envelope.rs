//! Insert-time normalization for the immutable GitHub v2 fetch body.

use crate::actor_attribution::{ActorAttribution, ActorUnknown, ActorUnknownCode};
use crate::event_key::*;
use serde_json::{json, Value};

/// Metadata available without changing the legacy vendor payload or making reads.
#[derive(Debug, Clone, Default)]
pub struct EnvelopeContext {
    pub source: EnvelopeSource,
    pub comment: Option<Value>,
    /// Who started the workflow run a CI job belongs to, and from where. A
    /// stored job object does not carry these values, so the inserter passes
    /// them from the job's run: the poller from the run it read just before the
    /// jobs, the relay from its in-memory cache of `workflow_run` webhooks.
    /// `None` puts nulls in the job envelope. CI-run envelopes ignore this and
    /// read the run object they are built from.
    pub ci_run: Option<CiRunAttribution>,
}

/// The four run-level values every `ci_run` and `ci_job` v2 envelope carries.
/// `None` becomes JSON `null`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CiRunAttribution {
    /// `actor.login`: who pushed the commit or opened the change.
    pub actor: Option<String>,
    /// `triggering_actor.login`: who started this run attempt. Kept separate
    /// from `actor`; a re-run changes this one only.
    pub triggering_actor: Option<String>,
    /// The run's `event`, such as `push` or `pull_request`.
    pub event: Option<String>,
    /// Whether the run's head repository differs from its base repository,
    /// compared ASCII case-insensitively. `None` when either name is missing.
    pub head_repo_is_fork: Option<bool>,
}

impl CiRunAttribution {
    /// Read the values from a GitHub workflow-run object, as returned by the
    /// REST API and carried in `workflow_run` webhooks. Missing, empty or
    /// non-string values become `None`; there is no fallback between fields.
    pub fn from_run(run: &Value) -> Self {
        let text = |pointer: &str| {
            run.pointer(pointer)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        let head = text("/head_repository/full_name");
        let base = text("/repository/full_name");
        Self {
            actor: text("/actor/login"),
            triggering_actor: text("/triggering_actor/login"),
            event: text("/event"),
            head_repo_is_fork: head
                .zip(base)
                .map(|(head, base)| !head.eq_ignore_ascii_case(&base)),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub enum EnvelopeSource {
    #[default]
    Poll,
    Webhook(Option<String>),
}

pub(crate) fn envelope(
    event_key: &str,
    event_name: &str,
    repo: &str,
    item: &Value,
    actor: &ActorAttribution,
    context: &EnvelopeContext,
    observed_at_ms: i64,
) -> Result<String, EventKeyError> {
    // Review and dequeue notices start at v1 with a normalized body, unlike the legacy
    // events whose v1 body is the vendor object. Do not reshape that body.
    if is_normalized_notice(event_name) {
        return crate::jcs::canonicalize_exact_integers(item)
            .map(|bytes| String::from_utf8(bytes).expect("JCS is UTF-8"))
            .map_err(EventKeyError::Canonicalization);
    }
    let event_kind = GithubEventKind::parse(event_name)?;
    let action = match &context.source {
        EnvelopeSource::Webhook(action) => json!(action),
        EnvelopeSource::Poll if matches!(event_kind, GithubEventKind::Release) => {
            json!("published")
        }
        EnvelopeSource::Poll => json!(if item["created_at"].is_string()
            && item["created_at"] == item["updated_at"]
        {
            "opened"
        } else {
            "updated"
        }),
    };
    let mut body = json!({"event_key":event_key,"kind":event_kind.as_str(),"repo":repo.to_ascii_lowercase(),
        "action":action,"actor_logins":null,"actor_unknown":null,
        "observed_at":crate::poller::iso8601::format_millis(observed_at_ms)});
    let fields: &[(&str, &str)] = match event_kind {
        GithubEventKind::Issue | GithubEventKind::PullRequest => &[
            ("number", "number"),
            ("title", "title"),
            ("updated_at", "updated_at"),
        ],
        GithubEventKind::CiJob | GithubEventKind::CiRun => &[
            ("id", "id"),
            ("name", "name"),
            ("conclusion", "conclusion"),
            ("status", "status"),
            ("head_branch", "head_branch"),
            ("head_sha", "head_sha"),
            ("url", "html_url"),
            ("run_id", "run_id"),
            ("run_attempt", "run_attempt"),
            ("completed_at", "completed_at"),
        ],
        GithubEventKind::Release => &[
            ("id", "id"),
            ("tag", "tag_name"),
            ("name", "name"),
            ("url", "html_url"),
            ("published_at", "published_at"),
        ],
    };
    for &(target, source) in fields {
        body[target] = item[source].clone();
    }
    if matches!(event_kind, GithubEventKind::CiRun) {
        body["run_id"] = item["id"].clone();
        body["workflow_id"] = item["workflow_id"].clone();
        body["workflow_path"] = item["path"].clone();
        // Workflow runs lack completed_at; updated_at is their completion time
        // only once GitHub marks the run completed. Jobs use their own field.
        body["completed_at"] = if item["status"] == "completed" {
            item["updated_at"].clone()
        } else {
            Value::Null
        };
    }
    if matches!(event_kind, GithubEventKind::CiRun | GithubEventKind::CiJob) {
        let ci = if matches!(event_kind, GithubEventKind::CiRun) {
            CiRunAttribution::from_run(item)
        } else {
            context.ci_run.clone().unwrap_or_default()
        };
        body["actor"] = json!(ci.actor);
        body["triggering_actor"] = json!(ci.triggering_actor);
        body["event"] = json!(ci.event);
        body["head_repo_is_fork"] = json!(ci.head_repo_is_fork);
    }
    if matches!(event_kind, GithubEventKind::CiJob) {
        body["workflow_name"] = item["workflow_name"]
            .as_str()
            .filter(|name| !name.is_empty())
            .map(|name| json!(name))
            .unwrap_or(Value::Null);
        body["runner_name"] = item["runner_name"]
            .as_str()
            .filter(|name| !name.is_empty())
            .map(|name| json!(name))
            .unwrap_or(Value::Null);
        body["steps_run"] = json!(item["steps"]
            .as_array()
            .map(|steps| steps
                .iter()
                .filter(|step| step["conclusion"].as_str().is_some())
                .count())
            .unwrap_or_default());
        for field in ["run_id", "run_attempt", "head_branch"] {
            if body[field].is_null() {
                body[field] = item["run"][field].clone();
            }
        }
    }
    if matches!(
        event_kind,
        GithubEventKind::Issue | GithubEventKind::PullRequest
    ) {
        body["state"] = item["state"]
            .as_str()
            .map(|state| json!(state.to_lowercase()))
            .unwrap_or(Value::Null);
        body["url"] = item["html_url"]
            .as_str()
            .map(|url| json!(url))
            .unwrap_or_else(|| {
                item["number"]
                    .as_u64()
                    .map(|number| {
                        json!(format!(
                            "https://github.com/{}/{}/{number}",
                            repo.to_ascii_lowercase(),
                            if matches!(event_kind, GithubEventKind::Issue) {
                                "issues"
                            } else {
                                "pull"
                            }
                        ))
                    })
                    .unwrap_or(Value::Null)
            });
        body["author"] = item
            .pointer("/user/login")
            .or_else(|| item.pointer("/author/login"))
            .cloned()
            .unwrap_or(Value::Null);
        match actor {
            ActorAttribution::Known(logins) => body["actor_logins"] = json!(logins),
            ActorAttribution::Unknown { code, .. } => {
                body["actor_unknown"] = json!(ActorUnknown::from_code(*code))
            }
            ActorAttribution::NotEnriched => {
                body["actor_unknown"] = json!(ActorUnknown::from_code(
                    ActorUnknownCode::ActorSourceUnbound
                ))
            }
        }
        body["comment_url"] = context
            .comment
            .as_ref()
            .and_then(|c| c.get("html_url").or_else(|| c.get("url")))
            .cloned()
            .unwrap_or(Value::Null);
        body["comment_author"] = context
            .comment
            .as_ref()
            .and_then(|c| {
                c.pointer("/user/login")
                    .or_else(|| c.pointer("/author/login"))
                    .or_else(|| c.get("author").filter(|author| author.is_string()))
            })
            .cloned()
            .unwrap_or(Value::Null);
        if matches!(event_kind, GithubEventKind::PullRequest) {
            body["draft"] = item["draft"].clone();
            body["merged"] = item["merged"].clone();
            body["head_ref"] = item.pointer("/head/ref").cloned().unwrap_or(Value::Null);
            body["base_ref"] = item.pointer("/base/ref").cloned().unwrap_or(Value::Null);
        }
    }
    crate::jcs::canonicalize_exact_integers(&body)
        .map(|bytes| String::from_utf8(bytes).expect("JCS is UTF-8"))
        .map_err(EventKeyError::Canonicalization)
}

/// Stamp normalized v1 notices on insertion, never vendor objects or stored bodies on read.
pub(crate) fn observed_notice(item: &Value, observed_at_ms: i64) -> Value {
    let mut body = item.clone();
    body["observed_at"] = json!(crate::poller::iso8601::format_millis(observed_at_ms));
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBSERVED_AT_MS: i64 = 1_000_000_000_123;
    const OBSERVED_AT: &str = "2001-09-09T01:46:40.123Z";

    #[test]
    fn every_v2_kind_uses_the_injected_observation_time() {
        for event in [
            GITHUB_ISSUE_CHANGED,
            GITHUB_PR_CHANGED,
            GITHUB_CI_JOB_COMPLETED,
            GITHUB_CI_JOB_FAILED,
            GITHUB_CI_RUN_COMPLETED,
            GITHUB_RELEASE_PUBLISHED,
        ] {
            for source in [EnvelopeSource::Poll, EnvelopeSource::Webhook(None)] {
                let item = json!({"updated_at":"1999-01-01T00:00:00Z"});
                let original = item.clone();
                let body = envelope(
                    KEY,
                    event,
                    "org/repo",
                    &item,
                    &ActorAttribution::NotEnriched,
                    &EnvelopeContext {
                        source,
                        ..Default::default()
                    },
                    OBSERVED_AT_MS,
                )
                .unwrap();
                let body: Value = serde_json::from_str(&body).unwrap();
                assert_eq!(
                    body["observed_at"], OBSERVED_AT,
                    "{event} must use the injected observation time"
                );
                assert_eq!(item, original, "v1 vendor objects must stay untouched");
            }
        }
    }

    #[test]
    fn large_event_ids_survive_the_envelope() {
        let id = 9_007_199_254_740_993_u64;
        let body = envelope(
            KEY,
            GITHUB_CI_JOB_COMPLETED,
            "Org/Repo",
            &json!({"id":id,"run_id":id,"run_attempt":id}),
            &ActorAttribution::NotEnriched,
            &EnvelopeContext::default(),
            OBSERVED_AT_MS,
        )
        .unwrap();
        let body: Value = serde_json::from_str(&body).unwrap();
        for field in ["id", "run_id", "run_attempt"] {
            assert_eq!(
                body[field].as_u64(),
                Some(id),
                "event envelope must preserve exact IDs"
            );
        }
    }

    #[test]
    fn ci_job_workflow_name_is_null_when_missing_or_empty() {
        for item in [json!({}), json!({"workflow_name": ""})] {
            let body = envelope(
                KEY,
                GITHUB_CI_JOB_COMPLETED,
                "org/repo",
                &item,
                &ActorAttribution::NotEnriched,
                &EnvelopeContext::default(),
                OBSERVED_AT_MS,
            )
            .unwrap();
            let parsed: Value = serde_json::from_str(&body).unwrap();
            assert!(parsed["workflow_name"].is_null());
            assert!(body.contains(r#""workflow_name":null"#));
        }
    }

    #[test]
    fn ci_job_runner_name_is_null_when_missing_or_empty() {
        for item in [
            json!({}),
            json!({"runner_name": null}),
            json!({"runner_name": ""}),
            json!({"runner_name": 7}),
        ] {
            let body = envelope(
                KEY,
                GITHUB_CI_JOB_COMPLETED,
                "org/repo",
                &item,
                &ActorAttribution::NotEnriched,
                &EnvelopeContext::default(),
                OBSERVED_AT_MS,
            )
            .unwrap();
            let parsed: Value = serde_json::from_str(&body).unwrap();
            assert!(parsed["runner_name"].is_null());
            assert!(body.contains(r#""runner_name":null"#));
        }
    }

    #[test]
    fn ci_job_steps_run_counts_only_steps_with_a_conclusion() {
        let item = json!({"steps":[
            {"conclusion":"success"},
            {"conclusion":"failure"},
            {"conclusion":""},
            {"conclusion":null},
            {},
            {"conclusion":7}
        ]});
        let body = envelope(
            KEY,
            GITHUB_CI_JOB_COMPLETED,
            "org/repo",
            &item,
            &ActorAttribution::NotEnriched,
            &EnvelopeContext::default(),
            OBSERVED_AT_MS,
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["steps_run"], 3);

        for item in [
            json!({}),
            json!({"steps": []}),
            json!({"steps": {"step": 1}}),
        ] {
            let body = envelope(
                KEY,
                GITHUB_CI_JOB_COMPLETED,
                "org/repo",
                &item,
                &ActorAttribution::NotEnriched,
                &EnvelopeContext::default(),
                OBSERVED_AT_MS,
            )
            .unwrap();
            let parsed: Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["steps_run"], 0);
        }
    }

    #[test]
    fn ci_job_never_started_failure_has_no_runner_or_steps() {
        let item = json!({
            "conclusion":"failure",
            "status":"completed",
            "runner_name":null,
            "steps":[],
            "started_at":"2026-10-11T00:30:15Z",
            "completed_at":"2026-10-11T00:30:15Z"
        });
        assert_eq!(item["started_at"], item["completed_at"]);
        let body = envelope(
            KEY,
            GITHUB_CI_JOB_COMPLETED,
            "org/repo",
            &item,
            &ActorAttribution::NotEnriched,
            &EnvelopeContext::default(),
            OBSERVED_AT_MS,
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert!(parsed["runner_name"].is_null());
        assert_eq!(parsed["steps_run"], 0);
    }

    #[test]
    fn ci_job_setup_failure_has_runner_and_no_steps() {
        let item = json!({
            "conclusion":"failure",
            "status":"completed",
            "runner_name":"GitHub Actions 1000008996",
            "steps":[]
        });
        let body = envelope(
            KEY,
            GITHUB_CI_JOB_COMPLETED,
            "org/repo",
            &item,
            &ActorAttribution::NotEnriched,
            &EnvelopeContext::default(),
            OBSERVED_AT_MS,
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["runner_name"], "GitHub Actions 1000008996");
        assert_eq!(parsed["steps_run"], 0);
    }

    #[test]
    fn ci_job_normal_failure_has_runner_and_concluded_steps() {
        let item = json!({
            "conclusion":"failure",
            "status":"completed",
            "runner_name":"GitHub Actions 1000008996",
            "steps":[
                {"conclusion":"success"},
                {"conclusion":"failure"},
                {"conclusion":null}
            ]
        });
        let body = envelope(
            KEY,
            GITHUB_CI_JOB_COMPLETED,
            "org/repo",
            &item,
            &ActorAttribution::NotEnriched,
            &EnvelopeContext::default(),
            OBSERVED_AT_MS,
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["runner_name"], "GitHub Actions 1000008996");
        assert_eq!(parsed["steps_run"], 2);
    }

    #[test]
    fn completed_ci_run_uses_updated_at_for_both_sources() {
        for source in [
            EnvelopeSource::Poll,
            EnvelopeSource::Webhook(Some("completed".into())),
        ] {
            let item = json!({"id":7,"status":"completed","updated_at":"2026-10-15T23:52:00Z"});
            let original = item.clone();
            let body = envelope(
                KEY,
                GITHUB_CI_RUN_COMPLETED,
                "org/repo",
                &item,
                &ActorAttribution::NotEnriched,
                &EnvelopeContext {
                    source,
                    ..Default::default()
                },
                OBSERVED_AT_MS,
            )
            .unwrap();
            let parsed: Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                parsed["completed_at"], "2026-10-15T23:52:00Z",
                "completed CI runs must expose updated_at as completed_at"
            );
            assert_eq!(parsed["event_key"], KEY);
            assert_eq!(item, original, "normalization must not alter the v1 source");
        }
    }

    #[test]
    fn in_progress_ci_run_has_null_completed_at_for_both_sources() {
        for source in [
            EnvelopeSource::Poll,
            EnvelopeSource::Webhook(Some("in_progress".into())),
        ] {
            let item = json!({"id":7,"status":"in_progress","updated_at":"2026-10-15T23:52:00Z",
                "completed_at":"not a run completion time"});
            let body = envelope(
                KEY,
                GITHUB_CI_RUN_COMPLETED,
                "org/repo",
                &item,
                &ActorAttribution::NotEnriched,
                &EnvelopeContext {
                    source,
                    ..Default::default()
                },
                OBSERVED_AT_MS,
            )
            .unwrap();
            let parsed: Value = serde_json::from_str(&body).unwrap();
            assert!(parsed["completed_at"].is_null());
            assert!(body.contains(r#""completed_at":null"#));
        }
    }

    #[test]
    fn unknown_envelope_event_is_an_error_not_a_panic() {
        assert!(
            envelope(
                KEY,
                "unknown",
                "org/repo",
                &json!({}),
                &ActorAttribution::NotEnriched,
                &EnvelopeContext::default(),
                OBSERVED_AT_MS,
            )
            .is_err(),
            "unknown envelope event must return an error"
        );
    }

    #[test]
    fn polled_release_is_published() {
        let body = envelope(
            KEY,
            GITHUB_RELEASE_PUBLISHED,
            "org/repo",
            &capture("poll_release"),
            &ActorAttribution::NotEnriched,
            &EnvelopeContext::default(),
            OBSERVED_AT_MS,
        )
        .unwrap();
        let body: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            body["action"], "published",
            "a polled published release must be labelled published"
        );
    }

    const KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fn capture(name: &str) -> Value {
        let bytes = match name {
            "webhook_issue" => {
                include_str!("../tests/fixtures/event-envelope-v2/webhook_issue.json")
            }
            "poll_issue" => include_str!("../tests/fixtures/event-envelope-v2/poll_issue.json"),
            "webhook_pull_request" => {
                include_str!("../tests/fixtures/event-envelope-v2/webhook_pull_request.json")
            }
            "poll_pull_request" => {
                include_str!("../tests/fixtures/event-envelope-v2/poll_pull_request.json")
            }
            "webhook_ci_job" => {
                include_str!("../tests/fixtures/event-envelope-v2/webhook_ci_job.json")
            }
            "poll_ci_job" => include_str!("../tests/fixtures/event-envelope-v2/poll_ci_job.json"),
            "webhook_ci_run" => {
                include_str!("../tests/fixtures/event-envelope-v2/webhook_ci_run.json")
            }
            "poll_ci_run" => include_str!("../tests/fixtures/event-envelope-v2/poll_ci_run.json"),
            "poll_release" => include_str!("../tests/fixtures/event-envelope-v2/poll_release.json"),
            _ => panic!("unknown capture"),
        };
        serde_json::from_str(bytes).unwrap()
    }

    fn golden(name: &str, event: &str, kind: &str, repo: &str, action: &str, expected: Value) {
        golden_with_run(name, event, kind, repo, action, None, expected)
    }

    fn golden_with_run(
        name: &str,
        event: &str,
        kind: &str,
        repo: &str,
        action: &str,
        ci_run: Option<CiRunAttribution>,
        mut expected: Value,
    ) {
        let item = capture(name);
        let is_webhook = name.starts_with("webhook_");
        // Only the item is captured. The wrapper reconstructs documented relay
        // fields that the legacy store did not retain, not a captured delivery.
        let constructed_wrapper_around_captured_item = json!({"action":action,
            "sender":{"login":"fixture-actor","type":"User"},
            "repository":{"full_name":repo,"id":101}, "item":item});
        let context = EnvelopeContext {
            source: if is_webhook {
                EnvelopeSource::Webhook(Some(action.to_owned()))
            } else {
                EnvelopeSource::Poll
            },
            comment: None,
            ci_run,
        };
        let actor = ActorAttribution::Known(vec!["fixture-actor".into()]);
        let actual = envelope(
            KEY,
            event,
            &repo.to_uppercase(),
            &constructed_wrapper_around_captured_item["item"],
            &actor,
            &context,
            OBSERVED_AT_MS,
        )
        .unwrap();
        expected["observed_at"] = json!(OBSERVED_AT);
        expected["event_key"] = json!(KEY);
        expected["kind"] = json!(kind);
        expected["repo"] = json!(repo);
        expected["action"] = json!(action);
        expected["actor_logins"] = if matches!(kind, "issue" | "pull_request") {
            json!(["fixture-actor"])
        } else {
            Value::Null
        };
        expected["actor_unknown"] = Value::Null;
        assert_eq!(
            serde_json::from_str::<Value>(&actual).unwrap(),
            expected,
            "every envelope field, including nulls, must match the captured-shape golden"
        );
        assert_eq!(
            actual.as_bytes(),
            crate::jcs::canonicalize(&expected).unwrap()
        );
    }

    #[test]
    fn captured_webhook_issue_constructed_wrapper_golden() {
        golden(
            "webhook_issue",
            GITHUB_ISSUE_CHANGED,
            "issue",
            "cortexkit/magic-context",
            "created",
            json!({
                "number":655,"title":"fix(kite): select paper colours and ribbons from the toy workshop","state":"open",
                "url":"https://github.com/cortexkit/magic-context/pull/655","author":"octo-quartz",
                "updated_at":"2026-10-10T21:48:03Z","comment_url":null,"comment_author":null
            }),
        );
    }
    #[test]
    fn captured_poll_issue_golden_includes_unknown_null_fields() {
        golden(
            "poll_issue",
            GITHUB_ISSUE_CHANGED,
            "issue",
            "cortexkit/magic-context",
            "opened",
            json!({
                "number":658,"title":"Toy lantern warnings race the imaginary workshop bell","state":"open",
                "url":"https://github.com/cortexkit/magic-context/issues/658","author":"octo-quartz",
                "updated_at":"2026-10-10T20:37:55Z","comment_url":null,"comment_author":null
            }),
        );
    }
    #[test]
    fn captured_webhook_pr_constructed_wrapper_golden() {
        golden(
            "webhook_pull_request",
            GITHUB_PR_CHANGED,
            "pull_request",
            "cortexkit/basal",
            "synchronize",
            json!({
                "number":13,"title":"Workshop only: paper kite checks, ribbon lists and lantern guides","state":"open",
                "url":"https://github.com/cortexkit/basal/pull/13","author":"basal-alfonso[bot]",
                "updated_at":"2026-10-11T00:33:09Z","comment_url":null,"comment_author":null,
                "draft":true,"merged":false,"head_ref":"ci/windows-s10","base_ref":"integration/windows"
            }),
        );
    }
    #[test]
    fn captured_poll_pr_golden() {
        golden(
            "poll_pull_request",
            GITHUB_PR_CHANGED,
            "pull_request",
            "cortexkit/basal",
            "updated",
            json!({
                "number":13,"title":"Workshop only: paper kite checks, ribbon lists and lantern guides","state":"open",
                "url":"https://github.com/cortexkit/basal/pull/13","author":"basal-alfonso[bot]",
                "updated_at":"2026-10-11T00:33:17Z","comment_url":null,"comment_author":null,
                "draft":true,"merged":false,"head_ref":"ci/windows-s10","base_ref":"integration/windows"
            }),
        );
    }
    #[test]
    fn captured_webhook_job_constructed_wrapper_golden() {
        golden(
            "webhook_ci_job",
            GITHUB_CI_JOB_COMPLETED,
            "ci_job",
            "cortexkit/aft",
            "completed",
            json!({
                "id":114349743680_i64,"name":"Search quality binary (Linux x64)","conclusion":"success","status":"completed",
                "head_branch":"train/callgraph-dirty-restart","head_sha":"e56c0d525fa9f387dc8fa00354851e90cf52ed0e",
                "url":"https://github.com/cortexkit/aft/actions/runs/38098639025/job/114349743680",
                "run_id":38098639025_i64,"run_attempt":1,"completed_at":"2026-10-11T00:45:44Z",
                "workflow_name":"Tests","runner_name":"GitHub Actions 1000008996","steps_run":11,
                // No run context was supplied: a job whose run the relay has
                // not cached keeps all four run fields, as nulls.
                "actor":null,"triggering_actor":null,"event":null,"head_repo_is_fork":null
            }),
        );
    }
    #[test]
    fn captured_poll_job_golden() {
        golden(
            "poll_ci_job",
            GITHUB_CI_JOB_COMPLETED,
            "ci_job",
            "cortexkit/magic-context",
            "updated",
            json!({
                "id":114305774943_i64,"name":"design-gate / design-approved-sync","conclusion":"skipped","status":"completed",
                "head_branch":"fix/pi-model-discovery-readiness","head_sha":"f65b17d9d2bcd48126557b3afbe9df84691852e9",
                "url":"https://github.com/cortexkit/magic-context/actions/runs/38083735257/job/114305774943",
                "run_id":38083735257_i64,"run_attempt":1,"completed_at":"2026-10-10T20:26:10Z",
                "workflow_name":"Design gate","runner_name":null,"steps_run":0,
                "actor":null,"triggering_actor":null,"event":null,"head_repo_is_fork":null
            }),
        );
    }
    #[test]
    fn captured_webhook_run_constructed_wrapper_golden() {
        golden(
            "webhook_ci_run",
            GITHUB_CI_RUN_COMPLETED,
            "ci_run",
            "cortexkit/aft",
            "completed",
            json!({
                "id":38097281838_i64,"name":"Tests","conclusion":"success","status":"completed",
                "head_branch":"train/check-persist-wait","head_sha":"3c8a2c3c7ca8e3407c60b7953c1267920b482a1b",
                "url":"https://github.com/cortexkit/aft/actions/runs/38097281838","run_id":38097281838_i64,
                "run_attempt":2,"completed_at":"2026-10-11T00:41:42Z",
                "workflow_id":271019280,"workflow_path":".github/workflows/tests.yml",
                // A push run inside the repository.
                "actor":"octo-lantern","triggering_actor":"octo-lantern","event":"push",
                "head_repo_is_fork":false
            }),
        );
    }
    #[test]
    fn captured_poll_run_golden() {
        golden(
            "poll_ci_run",
            GITHUB_CI_RUN_COMPLETED,
            "ci_run",
            "cortexkit/magic-context",
            "updated",
            json!({
                "id":38083743687_i64,"name":"Harness coverage advisory","conclusion":"success","status":"completed",
                "head_branch":"fix/pi-model-discovery-readiness","head_sha":"f65b17d9d2bcd48126557b3afbe9df84691852e9",
                "url":"https://github.com/cortexkit/magic-context/actions/runs/38083743687","run_id":38083743687_i64,
                "run_attempt":1,"completed_at":"2026-10-10T20:26:40Z",
                "workflow_id":362227872,"workflow_path":".github/workflows/harness-coverage-check.yml",
                // A pull request from the octo-quartz fork.
                "actor":"octo-checks[bot]","triggering_actor":"octo-checks[bot]",
                "event":"pull_request_target","head_repo_is_fork":true
            }),
        );
    }
    /// The polled job's own run: the captured fork pull-request run, which is
    /// a sibling of the job's run on the same pull request, given the job's run
    /// id. The poller passes the values read from this object.
    fn poll_job_run() -> Value {
        let mut run = capture("poll_ci_run");
        run["id"] = json!(38083735257_i64);
        run
    }

    #[test]
    fn captured_poll_job_golden_carries_its_fork_run_attribution() {
        golden_with_run(
            "poll_ci_job",
            GITHUB_CI_JOB_COMPLETED,
            "ci_job",
            "cortexkit/magic-context",
            "updated",
            Some(CiRunAttribution::from_run(&poll_job_run())),
            json!({
                "id":114305774943_i64,"name":"design-gate / design-approved-sync","conclusion":"skipped","status":"completed",
                "head_branch":"fix/pi-model-discovery-readiness","head_sha":"f65b17d9d2bcd48126557b3afbe9df84691852e9",
                "url":"https://github.com/cortexkit/magic-context/actions/runs/38083735257/job/114305774943",
                "run_id":38083735257_i64,"run_attempt":1,"completed_at":"2026-10-10T20:26:10Z",
                "workflow_name":"Design gate","runner_name":null,"steps_run":0,
                "actor":"octo-checks[bot]","triggering_actor":"octo-checks[bot]",
                "event":"pull_request_target","head_repo_is_fork":true
            }),
        );
    }

    #[test]
    fn captured_webhook_job_golden_carries_its_cached_push_run_attribution() {
        let mut run = capture("webhook_ci_run");
        run["id"] = json!(38098639025_i64);
        run["run_attempt"] = json!(1);
        golden_with_run(
            "webhook_ci_job",
            GITHUB_CI_JOB_COMPLETED,
            "ci_job",
            "cortexkit/aft",
            "completed",
            Some(CiRunAttribution::from_run(&run)),
            json!({
                "id":114349743680_i64,"name":"Search quality binary (Linux x64)","conclusion":"success","status":"completed",
                "head_branch":"train/callgraph-dirty-restart","head_sha":"e56c0d525fa9f387dc8fa00354851e90cf52ed0e",
                "url":"https://github.com/cortexkit/aft/actions/runs/38098639025/job/114349743680",
                "run_id":38098639025_i64,"run_attempt":1,"completed_at":"2026-10-11T00:45:44Z",
                "workflow_name":"Tests","runner_name":"GitHub Actions 1000008996","steps_run":11,
                "actor":"octo-lantern","triggering_actor":"octo-lantern","event":"push",
                "head_repo_is_fork":false
            }),
        );
    }

    /// When the operator re-runs a contributor's run, GitHub keeps the
    /// contributor as `actor` and names the operator as `triggering_actor`.
    /// Both envelopes report each login from its own field.
    #[test]
    fn rerun_reports_actor_and_triggering_actor_separately() {
        let mut run = capture("webhook_ci_run");
        run["run_attempt"] = json!(3);
        run["triggering_actor"]["login"] = json!("ualtinok");
        let attribution = CiRunAttribution::from_run(&run);
        assert_eq!(
            attribution,
            CiRunAttribution {
                actor: Some("octo-lantern".into()),
                triggering_actor: Some("ualtinok".into()),
                event: Some("push".into()),
                head_repo_is_fork: Some(false),
            },
            "a re-run must keep the pusher as actor and name the re-runner as triggering_actor"
        );
        let run_body: Value = serde_json::from_str(
            &envelope(
                KEY,
                GITHUB_CI_RUN_COMPLETED,
                "cortexkit/aft",
                &run,
                &ActorAttribution::NotEnriched,
                &EnvelopeContext::default(),
                OBSERVED_AT_MS,
            )
            .unwrap(),
        )
        .unwrap();
        let job_body: Value = serde_json::from_str(
            &envelope(
                KEY,
                GITHUB_CI_JOB_FAILED,
                "cortexkit/aft",
                &capture("webhook_ci_job"),
                &ActorAttribution::NotEnriched,
                &EnvelopeContext {
                    ci_run: Some(attribution),
                    ..Default::default()
                },
                OBSERVED_AT_MS,
            )
            .unwrap(),
        )
        .unwrap();
        for body in [run_body, job_body] {
            assert_eq!(
                (&body["actor"], &body["triggering_actor"]),
                (&json!("octo-lantern"), &json!("ualtinok")),
                "a re-run must keep the pusher as actor: {body}"
            );
        }
    }

    #[test]
    fn fork_detection_ignores_ascii_case_and_is_null_when_a_name_is_missing() {
        let fork = |run: Value| CiRunAttribution::from_run(&run).head_repo_is_fork;
        let named = |head: &str, base: &str| json!({"head_repository":{"full_name":head},"repository":{"full_name":base}});
        const SAME_OR_FORK: &str =
            "fork detection must compare head and base repository names case-insensitively";
        assert_eq!(
            fork(named("CortexKit/AFT", "cortexkit/aft")),
            Some(false),
            "{SAME_OR_FORK}"
        );
        assert_eq!(
            fork(named("octo-quartz/aft", "cortexkit/aft")),
            Some(true),
            "{SAME_OR_FORK}"
        );
        assert_eq!(
            fork(json!({"repository":{"full_name":"cortexkit/aft"}})),
            None
        );
        assert_eq!(
            fork(json!({"head_repository":null,"repository":{"full_name":"cortexkit/aft"}})),
            None
        );
        assert_eq!(
            fork(json!({"head_repository":{"full_name":"cortexkit/aft"}})),
            None
        );
        assert_eq!(fork(named("", "cortexkit/aft")), None);
        // A run with none of the source fields keeps every value null, and the
        // envelope still carries all four keys.
        let body = envelope(
            KEY,
            GITHUB_CI_RUN_COMPLETED,
            "org/repo",
            &json!({"id":7,"actor":{"login":""},"triggering_actor":null,"event":7}),
            &ActorAttribution::NotEnriched,
            &EnvelopeContext::default(),
            OBSERVED_AT_MS,
        )
        .unwrap();
        for field in ["actor", "triggering_actor", "event", "head_repo_is_fork"] {
            assert!(
                body.contains(&format!(r#""{field}":null"#)),
                "{field} must be present and null: {body}"
            );
        }
    }

    #[test]
    fn captured_poll_release_golden() {
        golden(
            "poll_release",
            GITHUB_RELEASE_PUBLISHED,
            "release",
            "cortexkit/subconscious",
            "published",
            json!({
                "id":398604125,"tag":"subc-core-v0.20.41","name":"subc-core-v0.20.41",
                "url":"https://github.com/cortexkit/subconscious/releases/tag/subc-core-v0.20.41","published_at":"2026-09-28T20:40:06Z"
            }),
        );
    }

    #[test]
    fn sparse_pr_and_actor_unknown_always_include_nullable_fields() {
        let actor = ActorAttribution::Unknown {
            code: ActorUnknownCode::TransportFailure,
        };
        let body: Value = serde_json::from_str(
            &envelope(
                KEY,
                GITHUB_PR_CHANGED,
                "owner/repo",
                &json!({"number":3}),
                &actor,
                &Default::default(),
                OBSERVED_AT_MS,
            )
            .unwrap(),
        )
        .unwrap();
        for field in [
            "title",
            "state",
            "author",
            "updated_at",
            "comment_url",
            "comment_author",
            "draft",
            "merged",
            "head_ref",
            "base_ref",
            "actor_logins",
        ] {
            assert_eq!(
                body.get(field),
                Some(&Value::Null),
                "{field} must be present even when unknown"
            );
        }
        assert_eq!(
            body["actor_unknown"],
            json!({"reason":"transport_failure","class":"transient"})
        );
        assert_eq!(body["url"], "https://github.com/owner/repo/pull/3");
        assert!(!body.to_string().contains("private vendor text"));
    }

    #[test]
    fn unknown_webhook_action_is_null_not_a_poll_action() {
        let context = EnvelopeContext {
            source: EnvelopeSource::Webhook(None),
            comment: None,
            ci_run: None,
        };
        let body: Value = serde_json::from_str(
            &envelope(
                KEY,
                GITHUB_ISSUE_CHANGED,
                "owner/repo",
                &json!({"number":1}),
                &ActorAttribution::NotEnriched,
                &context,
                OBSERVED_AT_MS,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(body.get("action"), Some(&Value::Null));
        assert_eq!(
            body["actor_unknown"],
            json!({"reason":"actor_source_unbound","class":"unexpected"})
        );
    }
}
