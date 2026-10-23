use super::*;
use plexus_core::rest_api::{RestConfig, RestTransport};
use std::sync::Mutex;

const ACTION: &str = "github.pulls.open";
const QUERY: &str = "query($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { pullRequests(first: 100, states: OPEN) { nodes { number headRefName headRefOid updatedAt mergeable isInMergeQueue reviewThreads(first: 100) { nodes { isResolved } pageInfo { hasNextPage } } } pageInfo { hasNextPage } } } }";

#[test]
fn pulls_open_wire_uses_fixed_query_and_bound_bot_token() {
    let (_scratch, store, _, _, scope) = setup("pulls-open-wire", &[(ACTION, "read")]);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sent = captured.clone();
    let (endpoint, server) = validation_http::FixedRequestServer::start(
        1,
        "open pulls",
        move |_, raw| {
            captured.lock().unwrap().push(raw.to_owned());
            let body = json!({"data":{"repository":{"pullRequests":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}}).to_string();
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())
        },
    );
    let manifest = github_manifest();
    let config = RestConfig::new(endpoint)
        .with_bindings(manifest.credential_bindings.clone())
        .with_actions(
            manifest
                .actions_baseline
                .into_iter()
                .map(|action| (action.name, action.http.unwrap()))
                .collect(),
        );
    let engine = GovernanceEngine::new(
        store.clone(),
        Arc::new(plexus_core::credentials::StubCredentialSource::default()),
        Arc::new(RestTransport::new(config)),
    )
    .with_governance_seams(Arc::new(GithubGovernanceSeams {
        store: store.clone(),
        credential_provider: Some(Arc::new(super::review_threads::ReviewToken)),
    }))
    .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
    let result = plexus_core::github::reads::bot::read(
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        ACTION,
        &json!("Org/Repo"),
        &json!({"head_prefix":"land/"}),
        Some(&scope),
        None,
    )
    .unwrap();
    assert_eq!(
        result,
        json!({"repository":"org/repo","prs":[],"truncated":false})
    );
    server.join().unwrap();
    let sent = sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].starts_with("POST /graphql HTTP/1.1\r\n"));
    assert!(sent[0]
        .to_ascii_lowercase()
        .contains("authorization: bearer review-bot-canary\r\n"));
    let body: Value = serde_json::from_str(sent[0].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(
        body,
        json!({"query":QUERY,"variables":{"owner":"org","repo":"repo"}})
    );
    assert_eq!(
        store
            .github_bot_reads_in_window("app-fixture", plexus_core::now_ms())
            .unwrap(),
        1
    );
}
