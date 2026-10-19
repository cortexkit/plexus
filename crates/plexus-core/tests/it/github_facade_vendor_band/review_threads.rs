use super::*;
use plexus_core::rest_api::{RestConfig, RestTransport};
use std::sync::Mutex;
use std::time::Duration;

const ACTION: &str = "github.pr.review_threads";
const QUERY: &str = "query($owner: String!, $repo: String!, $pr: Int!, $after: String) { repository(owner: $owner, name: $repo) { pullRequest(number: $pr) { reviewThreads(first: 100, after: $after) { nodes { id isResolved isOutdated path line comments(first: 1) { nodes { author { login __typename } body url } } } pageInfo { hasNextPage endCursor } } } } }";

struct ReviewToken;
impl HandleCredentialProvider for ReviewToken {
    fn prepare(&self, _: &str, _: i64, _: &str) -> Result<ResolvedCredential, &'static str> {
        Ok(ResolvedCredential::new(
            b"review-bot-canary".to_vec(),
            None,
            1,
        ))
    }
    fn vendor_status(&self, _: &str, _: i64, _: &str, _: u16) {}
}

#[test]
fn review_threads_wire_uses_only_fixed_query_and_bound_app_token_on_every_page() {
    let (_scratch, store, _, _, scope) = setup("review-threads-wire", &[(ACTION, "read")]);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sent = captured.clone();
    let (endpoint, server) = validation_http::FixedRequestServer::start_with_deadline(
        3,
        "review threads",
        Duration::from_secs(15),
        move |index, raw| {
            captured.lock().unwrap().push(raw.to_owned());
            let body = json!({"data":{"repository":{"pullRequest":{"reviewThreads":{
                "nodes":[],"pageInfo":{"hasNextPage":index < 2,"endCursor":format!("cursor-{index}")}
            }}}}}).to_string();
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
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
        store,
        credential_provider: Some(Arc::new(ReviewToken)),
    }))
    .with_scope_reader(Arc::new(LiveScopeReader(scope.clone())));
    let reply = plexus_core::github::reads::read_scoped(
        &engine,
        plexus_core::github::AFT_PRINCIPAL,
        ACTION,
        &json!("Org/Repo"),
        &json!({"pr":7}),
        Some(&scope),
    )
    .unwrap();
    assert_eq!(
        reply,
        json!({"repository":"org/repo","pr":7,"threads":[],"incomplete":false})
    );
    server.join().unwrap();
    let sent = sent.lock().unwrap();
    assert_eq!(sent.len(), 3);
    for (index, raw) in sent.iter().enumerate() {
        assert!(raw.starts_with("POST /graphql HTTP/1.1\r\n"));
        assert!(raw
            .to_ascii_lowercase()
            .contains("authorization: bearer review-bot-canary\r\n"));
        let body: Value = serde_json::from_str(raw.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(
            body,
            json!({"query":QUERY,"variables":{"owner":"org","repo":"repo","pr":7,
            "after":if index == 0 {Value::Null} else {json!(format!("cursor-{}", index-1))}}})
        );
    }
}
