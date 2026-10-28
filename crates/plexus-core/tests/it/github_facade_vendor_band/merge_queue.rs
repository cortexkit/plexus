use super::v22::Run;
use super::*;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const URL: &str = "https://github.com/org/repo/pull/7";
const READ: &str = "query($owner: String!, $repo: String!, $number: Int!) { repository(owner: $owner, name: $repo) { pullRequest(number: $number) { id url number author { login __typename } headRefOid state isInMergeQueue } } }";
const ENQUEUE: &str = "mutation($pullRequestId: ID!, $expectedHeadOid: GitObjectID!) { enqueuePullRequest(input: {pullRequestId: $pullRequestId, expectedHeadOid: $expectedHeadOid}) { mergeQueueEntry { pullRequest { id url number headRefOid isInMergeQueue } } } }";
const DEQUEUE: &str = "mutation($pullRequestId: ID!) { dequeuePullRequest(input: {pullRequestId: $pullRequestId}) { mergeQueueEntry { pullRequest { id url number headRefOid isInMergeQueue } } } }";

fn request(enqueue: bool) -> Value {
    let mut request = json!({"operation":"gh.route", "gh_route_schema":1,
        "manifest_version":22, "rung_as_of_unix_secs":1793066213,
        "metadata":{"agent_id":"alfonso-aft", "pid":4242},
        "action":if enqueue {"pr enqueue"} else {"pr dequeue"},
        "repository":"org/repo", "target":{"number":7}});
    if enqueue {
        request["body"] = json!({"expected_head_sha":SHA});
    }
    request
}

fn pr(queued: bool) -> Value {
    json!({"id":"PR_node_7", "url":URL, "number":7,
        "author":{"login":"app-fixture[bot]", "__typename":"Bot"},
        "headRefOid":SHA, "state":"OPEN", "isInMergeQueue":queued})
}

fn read(pr: Value) -> Value {
    json!({"data":{"repository":{"pullRequest":pr}}})
}

fn mutation(enqueue: bool) -> Value {
    let name = if enqueue {
        "enqueuePullRequest"
    } else {
        "dequeuePullRequest"
    };
    json!({"data":{name:{"mergeQueueEntry":{"pullRequest":pr(enqueue)}}}})
}

type ReplyCase = (&'static str, Value, Vec<(u16, Value)>);

pub(super) fn reply_cases() -> Vec<ReplyCase> {
    let mut cases = Vec::new();
    for (enqueue, own, not_own, closed, errors) in [
        (
            true,
            "pr-enqueue-own",
            "pr-enqueue-not-own",
            "pr-enqueue-closed",
            "pr-enqueue-graphql-errors",
        ),
        (
            false,
            "pr-dequeue-own",
            "pr-dequeue-not-own",
            "pr-dequeue-closed",
            "pr-dequeue-graphql-errors",
        ),
    ] {
        cases.push((
            own,
            request(enqueue),
            vec![(200, read(pr(!enqueue))), (200, mutation(enqueue))],
        ));
        let mut human = pr(!enqueue);
        human["author"] = json!({"login":"human", "__typename":"User"});
        cases.push((not_own, request(enqueue), vec![(200, read(human))]));
        let mut pr_closed = pr(!enqueue);
        pr_closed["state"] = json!("CLOSED");
        cases.push((closed, request(enqueue), vec![(200, read(pr_closed))]));
        cases.push((errors, request(enqueue), vec![(200, read(pr(!enqueue))), (200, json!({"errors":[{"type":"FORBIDDEN", "message":"Resource not accessible by integration"}]}))]));
    }
    let mut moved = pr(false);
    moved["headRefOid"] = json!(OTHER_SHA);
    cases.push((
        "pr-enqueue-head-moved",
        request(true),
        vec![(200, read(moved))],
    ));
    cases
}

#[test]
fn merge_queue_owned_writes_exact_reviewed_documents_and_replays() {
    for enqueue in [true, false] {
        let run = Run::new(vec![read(pr(!enqueue)), mutation(enqueue)]);
        let request = request(enqueue);
        let first = run.call(&request);
        assert_eq!(
            first["result"],
            json!({"status":"completed", "result":{
            "url":URL, "number":7, "queued":enqueue, "head_sha":SHA}}),
            "{first}"
        );
        let mut variables = json!({"pullRequestId":"PR_node_7"});
        if enqueue {
            variables["expectedHeadOid"] = json!(SHA);
        }
        assert_eq!(
            run.wire(),
            vec![
                (
                    "POST /graphql HTTP/1.1".into(),
                    json!({"query":READ, "variables":{"owner":"org", "repo":"repo", "number":7}})
                ),
                (
                    "POST /graphql HTTP/1.1".into(),
                    json!({"query":if enqueue {ENQUEUE} else {DEQUEUE}, "variables":variables})
                ),
            ]
        );
        assert_eq!(run.call(&request)["result"], first["result"]);
        assert_eq!(run.wire().len(), 2, "nonce replay must not send again");
        run.server.join().unwrap();
    }
}

#[test]
fn merge_queue_not_owned_uses_pr_edit_refusal_before_mutation() {
    for enqueue in [true, false] {
        let mut human = pr(!enqueue);
        human["author"] = json!({"login":"human", "__typename":"User"});
        let run = Run::new(vec![read(human)]);
        let first = run.call(&request(enqueue));
        assert_eq!(
            first["result"]["refusal_code"], "pr_edit_not_own",
            "{first}"
        );
        assert!(first["result"]["detail"]["message"]
            .as_str()
            .unwrap()
            .contains("human"));
        assert_eq!(run.call(&request(enqueue))["result"], first["result"]);
        assert_eq!(run.wire().len(), 1);
        run.server.join().unwrap();
    }
}

#[test]
fn merge_queue_head_moved_refuses_before_mutation_even_if_already_queued() {
    for queued in [true, false] {
        let mut moved = pr(queued);
        moved["headRefOid"] = json!(OTHER_SHA);
        let run = Run::new(vec![read(moved)]);
        let reply = run.call(&request(true));
        assert_eq!(
            reply["result"]["refusal_code"], "pull_request_head_moved",
            "{reply}"
        );
        assert_eq!(
            reply["result"]["detail"],
            json!({"expected_head_sha":SHA, "actual_head_sha":OTHER_SHA})
        );
        assert_eq!(run.wire().len(), 1);
        run.server.join().unwrap();
    }
}

#[test]
fn merge_queue_already_requested_state_is_a_replayed_noop() {
    for enqueue in [true, false] {
        let run = Run::new(vec![read(pr(enqueue))]);
        let reply = run.call(&request(enqueue));
        assert_eq!(
            reply["result"],
            json!({"status":"completed", "result":{
            "url":URL, "number":7, "queued":enqueue, "head_sha":SHA}}),
            "{reply}"
        );
        assert_eq!(run.call(&request(enqueue))["result"], reply["result"]);
        assert_eq!(run.wire().len(), 1);
        run.server.join().unwrap();
    }
}

#[test]
fn merge_queue_closed_and_merged_refuse_even_for_noops() {
    for enqueue in [true, false] {
        for state in ["CLOSED", "MERGED"] {
            let mut closed = pr(enqueue);
            closed["state"] = json!(state);
            let run = Run::new(vec![read(closed)]);
            let reply = run.call(&request(enqueue));
            assert_eq!(
                reply["result"]["refusal_code"], "pull_request_not_open",
                "{reply}"
            );
            assert_eq!(run.wire().len(), 1);
            run.server.join().unwrap();
        }
    }
}

#[test]
fn merge_queue_permission_refusals_do_not_expose_headers_or_vendor_text() {
    for enqueue in [true, false] {
        for status in [200, 401, 403] {
            let run = Run::with_headers(
                vec![
                    (200, read(pr(!enqueue))),
                    (
                        status,
                        json!({"errors":[{"type":"FORBIDDEN", "message":"Resource not accessible by integration PRIVATE_MARKER"}]}),
                    ),
                ],
                "X-Accepted-GitHub-Permissions: merge_queues=write\r\n",
            );
            let first = run.call(&request(enqueue));
            assert_eq!(first["result"]["status"], "refused", "{first}");
            if status == 200 {
                assert_eq!(
                    first["result"]["refusal_code"],
                    "vendor_rejected{status: 422}"
                );
            }
            for private in [
                "PRIVATE_MARKER",
                "merge_queues",
                "X-Accepted",
                "Resource not accessible",
            ] {
                assert!(!first.to_string().contains(private), "{first}");
            }
            assert_eq!(run.call(&request(enqueue))["result"], first["result"]);
            assert_eq!(run.wire().len(), 2);
            run.server.join().unwrap();
        }
    }
}

#[test]
fn merge_queue_incomplete_read_never_mutates_and_ambiguous_write_is_unknown() {
    for enqueue in [true, false] {
        let run = Run::new(vec![read(json!({"id":"PR_node_7"}))]);
        let reply = run.call(&request(enqueue));
        assert_eq!(
            reply["result"]["refusal_code"],
            "pre_dispatch_read_incomplete{reason: invalid_response}",
            "{reply}"
        );
        assert_eq!(run.wire().len(), 1);
        run.server.join().unwrap();
        for response in [json!({"data":null}), mutation(!enqueue)] {
            let run = Run::new(vec![read(pr(!enqueue)), response]);
            let first = run.call(&request(enqueue));
            assert_eq!(first["result"]["status"], "outcome_unknown", "{first}");
            assert_eq!(
                run.call(&request(enqueue))["result"]["status"],
                "outcome_unknown"
            );
            assert_eq!(run.wire().len(), 2);
            run.server.join().unwrap();
        }
    }
}

#[test]
fn merge_queue_unbound_repository_never_contacts_github() {
    for enqueue in [true, false] {
        let run = Run::new(vec![]);
        let mut request = request(enqueue);
        request["repository"] = json!("foreign/repo");
        let reply = run.call(&request);
        assert_eq!(
            reply["result"]["refusal_code"], "repository_unbound",
            "{reply}"
        );
        assert!(run.wire().is_empty());
        run.server.join().unwrap();
    }
}

#[test]
fn merge_queue_unknown_fields_and_invalid_heads_never_contact_github() {
    for enqueue in [true, false] {
        let run = Run::new(vec![]);
        for (location, field, value) in [
            ("", "query", json!("mutation {}")),
            ("", "jump", json!(true)),
            ("target", "head", json!(SHA)),
            ("target", "number", json!(2147483648_u64)),
        ] {
            let mut request = request(enqueue);
            if location.is_empty() {
                request[field] = value;
            } else {
                request[location][field] = value;
            }
            let reply = run.call(&request);
            assert_eq!(
                reply["result"]["refusal_code"],
                format!("request_field_forbidden{{field: {field}}}"),
                "{reply}"
            );
        }
        if enqueue {
            for sha in [
                json!(""),
                json!("a".repeat(39)),
                json!("z".repeat(40)),
                Value::Null,
                json!(7),
            ] {
                let mut request = request(true);
                request["body"]["expected_head_sha"] = sha;
                let reply = run.call(&request);
                assert_eq!(
                    reply["result"]["refusal_code"],
                    "request_field_forbidden{field: expected_head_sha}",
                    "{reply}"
                );
            }
            let mut request = request(true);
            request["body"]["jump"] = json!(true);
            assert_eq!(
                run.call(&request)["result"]["refusal_code"],
                "request_field_forbidden{field: jump}"
            );
        } else {
            let mut request = request(false);
            request["body"] = json!({});
            assert_eq!(
                run.call(&request)["result"]["refusal_code"],
                "request_field_forbidden{field: body}"
            );
        }
        assert!(run.wire().is_empty());
        run.server.join().unwrap();
    }
}
