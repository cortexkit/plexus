use std::cell::Cell;
use std::sync::Mutex;

use plexus_core::credentials::ResolvedCredential;
use plexus_core::github::pagination::{
    may_dispatch, walk, ListRead, PageRequest, WalkError, MAX_PAGES, PER_PAGE,
};
use plexus_core::transport::{Transport, TransportRequest, TransportResponse};
use serde_json::{json, Value};

#[derive(Default)]
struct RecordingTransport {
    requests: Mutex<Vec<TransportRequest>>,
}

impl RecordingTransport {
    fn requests(&self) -> Vec<TransportRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl Transport for RecordingTransport {
    fn dispatch(&self, request: TransportRequest, _: &ResolvedCredential) -> TransportResponse {
        let page = request.args["page"].as_u64().unwrap() as usize;
        self.requests.lock().unwrap().push(request.clone());
        match request.action.as_str() {
            "github.issue_comments.list" => {
                let mut comments: Vec<Value> = (0..PER_PAGE)
                    .map(|id| json!({"id": id + page * PER_PAGE, "user": {"login":"other[bot]", "type":"Bot"}}))
                    .collect();
                if page == 1 {
                    comments[0] = json!({"id": 1, "user": {"login":"app[bot]", "type":"Bot"}});
                }
                if page == 2 {
                    comments.clear();
                    comments.push(json!({"id": 200, "user": {"login":"app[bot]", "type":"User"}}));
                    comments.push(json!({"id": 201, "user": {"login":"app[bot]", "type":"Bot"}}));
                    comments.push(json!({"id": 202, "user": {"login":"app[bot]", "type":"Bot"}}));
                }
                TransportResponse::success(Value::Array(comments))
            }
            "GET /installation/repositories" => {
                let repositories = if page == 1 {
                    (0..PER_PAGE)
                        .map(|n| json!({"full_name":format!("o/r{n}")}))
                        .collect::<Vec<_>>()
                } else {
                    vec![json!({"full_name":"o/last"})]
                };
                TransportResponse::success(json!({"repositories": repositories, "total_count":101}))
            }
            _ => panic!("unexpected action"),
        }
    }
}

fn recorded_walk(
    transport: &RecordingTransport,
    read: ListRead,
    principal: &str,
    clock: &Cell<i64>,
) -> Result<plexus_core::github::pagination::CompletedWalk, WalkError> {
    walk(
        read,
        clock.get(),
        || clock.get(),
        |page: PageRequest| {
            clock.set(clock.get() + 1000);
            let request = TransportRequest {
                request_id: format!("{principal}-{}", page.page),
                connection_id: "app-installation".into(),
                action: page.read.action().into(),
                args: json!({"method":"GET", "path":match read {
                ListRead::IssueComments => "/repos/o/r/issues/7/comments",
                ListRead::InstallationRepositories => "/installation/repositories",
            }, "page":page.page, "per_page":page.per_page}),
                credential_fingerprint: "sha256:fixture".into(),
            };
            let response = transport.dispatch(request, &ResolvedCredential::anonymous());
            response.response.ok_or(WalkError::ReadFailed)
        },
    )
}

#[test]
fn last_page_bot_comment_is_newest_for_facade_and_prefrontal() {
    for principal in [
        plexus_core::github::AFT_PRINCIPAL,
        plexus_core::github::PREFRONTAL_PRINCIPAL,
    ] {
        let transport = RecordingTransport::default();
        let clock = Cell::new(0);
        assert!(!may_dispatch(&[ListRead::IssueComments], &[]));
        let result = recorded_walk(&transport, ListRead::IssueComments, principal, &clock).unwrap();
        assert_eq!(result.newest_bot_comment("app").unwrap()["id"], 202);
        assert_eq!(result.items().len(), PER_PAGE + 3);
        assert!(may_dispatch(&[ListRead::IssueComments], &[result]));
        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests
                .iter()
                .map(|r| r.args["page"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(requests
            .iter()
            .all(|r| r.action == "github.issue_comments.list"
                && r.args["method"] == "GET"
                && r.args["per_page"] == PER_PAGE));
        assert!(clock.get() < plexus_core::github::receipt::DEFAULT_CLAIM_LEASE_SECONDS * 1000);
    }
}

#[test]
fn probe_walks_all_installation_repositories_without_mutation() {
    let transport = RecordingTransport::default();
    let result = recorded_walk(
        &transport,
        ListRead::InstallationRepositories,
        "direct",
        &Cell::new(0),
    )
    .unwrap();
    assert_eq!(result.items().len(), 101);
    assert_eq!(result.items().last().unwrap()["full_name"], "o/last");
    let requests = transport.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests
            .iter()
            .map(|r| r.args["page"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(requests
        .iter()
        .all(|r| r.action == "GET /installation/repositories"
            && r.args["method"] == "GET"
            && r.args["path"] == "/installation/repositories"));
}

#[test]
fn full_page_at_bound_is_incomplete_not_not_found_and_cannot_dispatch() {
    let mut requested = Vec::new();
    let result = walk(
        ListRead::IssueComments,
        0,
        || 0,
        |page| {
            requested.push(page.page);
            Ok(json!((0..PER_PAGE)
                .map(|_| json!({"user":{"login":"app[bot]", "type":"Bot"}}))
                .collect::<Vec<_>>()))
        },
    );
    assert!(matches!(result, Err(WalkError::Incomplete)));
    assert_eq!(requested, (1..=MAX_PAGES).collect::<Vec<_>>());
    assert!(!may_dispatch(&[ListRead::IssueComments], &[]));
    let empty = walk(ListRead::IssueComments, 0, || 0, |_| Ok(json!([]))).unwrap();
    assert!(empty.newest_bot_comment("app").is_none());
    assert!(may_dispatch(&[ListRead::IssueComments], &[empty]));
}

#[test]
fn fixed_clock_expires_before_a_slow_edit_last_walk_can_dispatch() {
    let clock = Cell::new(0);
    let result = walk(
        ListRead::IssueComments,
        clock.get(),
        || clock.get(),
        |_| {
            clock.set(clock.get() + 60_000);
            Ok(json!((0..PER_PAGE).map(|_| json!({})).collect::<Vec<_>>()))
        },
    );
    assert!(matches!(result, Err(WalkError::LeaseExpired)));
    assert_eq!(
        clock.get(),
        plexus_core::github::receipt::DEFAULT_CLAIM_LEASE_SECONDS * 1000
    );
    assert!(!may_dispatch(&[ListRead::IssueComments], &[]));
}

#[test]
fn malformed_list_and_failed_read_cannot_create_completion_proof() {
    assert!(matches!(
        walk(
            ListRead::IssueComments,
            0,
            || 0,
            |_| Ok(json!({"items":[]}))
        ),
        Err(WalkError::InvalidResponse)
    ));
    assert!(matches!(
        walk(
            ListRead::InstallationRepositories,
            0,
            || 0,
            |_| Err(WalkError::ReadFailed)
        ),
        Err(WalkError::ReadFailed)
    ));
}
