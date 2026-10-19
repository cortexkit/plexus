use super::*;
use crate::rest_api::tests::{config, http_op, request, start_server};
use serde_json::json;

fn reply(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

const LIMIT_HEADERS: &str = "x-ratelimit-remaining: 4321\r\nx-ratelimit-reset: 1700000000\r\n";

fn repo_get(endpoint: String) -> RestTransport {
    RestTransport::new(config(
        endpoint,
        vec![(
            "github.repo.get",
            http_op(HttpMethod::Get, "/repos/{owner}/{repo}"),
        )],
    ))
}

fn dispatch(transport: &RestTransport, action: &str, args: Value) -> TransportResponse {
    transport.dispatch(
        request("bot", action, args),
        &ResolvedCredential::new(b"bot-token".to_vec(), None, 0),
    )
}

#[test]
fn repo_get_sends_the_validated_path_query_and_accept_and_keeps_the_headers() {
    let (endpoint, server) = start_server(1, |_, received| {
        assert_eq!(
            received.lines().next().unwrap(),
            "GET /repos/o/x/pulls?state=open HTTP/1.1"
        );
        assert!(received
            .to_ascii_lowercase()
            .contains("accept: application/vnd.github+json"));
        reply(
            "200 OK",
            &format!("{LIMIT_HEADERS}Link: <https://api.github.com/repositories/1/pulls?state=open&page=3>; rel=\"next\"\r\nContent-Type: application/json\r\n"),
            r#"[{"number":1}]"#,
        )
    });
    let result = dispatch(
        &repo_get(endpoint),
        "github.repo.get",
        json!({"owner":"o","repo":"x","path":"pulls","query":{"state":"open"},
            "accept":"application/vnd.github+json"}),
    );
    server.join().unwrap();
    assert_eq!(
        result.response.unwrap(),
        json!({"status":200,"body":[{"number":1}],"next_page":3,
            "rate_limit":{"remaining":4321,"reset_at_ms":1_700_000_000_000_i64}})
    );
}

#[test]
fn the_empty_path_is_the_repository_and_a_diff_is_returned_as_text() {
    let (endpoint, server) = start_server(2, |index, received| {
        let line = received.lines().next().unwrap();
        if index == 0 {
            assert_eq!(line, "GET /repos/o/x HTTP/1.1");
            reply("200 OK", "", r#"{"full_name":"o/x"}"#)
        } else {
            assert_eq!(line, "GET /repos/o/x/pulls/7 HTTP/1.1");
            assert!(received
                .to_ascii_lowercase()
                .contains("accept: application/vnd.github.diff"));
            reply("200 OK", "", "diff --git a/x b/x\n")
        }
    });
    let transport = repo_get(endpoint);
    let root = dispatch(
        &transport,
        "github.repo.get",
        json!({"owner":"o","repo":"x","path":"","accept":"application/vnd.github+json"}),
    );
    assert_eq!(root.response.unwrap()["body"], json!({"full_name":"o/x"}));
    let diff = dispatch(
        &transport,
        "github.repo.get",
        json!({"owner":"o","repo":"x","path":"pulls/7","accept":"application/vnd.github.diff"}),
    );
    server.join().unwrap();
    let diff = diff.response.unwrap();
    assert_eq!(diff["body"], "diff --git a/x b/x\n");
    assert_eq!(diff["next_page"], Value::Null);
    assert_eq!(diff["rate_limit"], Value::Null);
}

#[test]
fn a_refused_path_or_media_type_never_reaches_the_wire() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let transport = repo_get(endpoint);
    for args in [
        json!({"owner":"o","repo":"x","path":"/user","accept":"application/vnd.github+json"}),
        json!({"owner":"o","repo":"x","path":"pulls/../../user","accept":"application/vnd.github+json"}),
        json!({"owner":"o","repo":"x","path":"a%2fb","accept":"application/vnd.github+json"}),
        json!({"owner":"o","repo":"x","path":"pulls","accept":"text/html"}),
        json!({"owner":"o","repo":"x","path":"pulls","accept":"application/vnd.github+json","query":{"page":1}}),
    ] {
        let result = dispatch(&transport, "github.repo.get", args.clone());
        assert_eq!(result.transmission, TransmissionState::NotSent, "{args}");
    }
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "nothing may connect"
    );
}

#[test]
fn a_body_over_one_mebibyte_is_refused_not_truncated() {
    let body = "x".repeat(crate::github::reads::bot::MAX_BOT_READ_BODY_BYTES + 1);
    let (endpoint, server) = start_server(1, move |_, _| reply("200 OK", "", &body));
    let result = dispatch(
        &repo_get(endpoint),
        "github.repo.get",
        json!({"owner":"o","repo":"x","path":"pulls/7","accept":"application/vnd.github.patch"}),
    );
    server.join().unwrap();
    assert_eq!(result.transmission, TransmissionState::Sent);
    assert!(result.response.is_none());
    assert_eq!(result.error_code.as_deref(), Some("response_too_large"));
}

#[test]
fn github_refusals_keep_their_status_and_only_a_401_names_the_credential() {
    for (status, code) in [
        ("404 Not Found", "http_404"),
        ("403 Forbidden", "http_403"),
        ("401 Unauthorized", "http_401"),
        ("503 Service Unavailable", "http_503"),
        ("301 Moved Permanently", "http_301"),
    ] {
        let (endpoint, server) = start_server(1, move |_, _| {
            reply(
                status,
                &format!("{LIMIT_HEADERS}Location: https://api.github.com/repositories/9\r\n"),
                "{}",
            )
        });
        let result = dispatch(
            &repo_get(endpoint),
            "github.repo.get",
            json!({"owner":"o","repo":"x","path":"","accept":"application/vnd.github+json"}),
        );
        server.join().unwrap();
        assert_eq!(result.transmission, TransmissionState::Sent, "{status}");
        assert_eq!(result.error_code.as_deref(), Some(code), "{status}");
        let projection: Value =
            serde_json::from_str(result.error_message.as_deref().unwrap()).unwrap();
        assert_eq!(
            projection["rate_limit"],
            json!({"remaining":4321,"reset_at_ms":1_700_000_000_000_i64})
        );
        assert_eq!(
            result.provider_auth_status(),
            (code == "http_401").then_some(401),
            "only a 401 is a credential failure: {status}"
        );
    }
}

#[test]
fn search_sends_only_q_and_paging_never_the_repository_context() {
    let (endpoint, server) = start_server(1, |_, received| {
        let line = received.lines().next().unwrap();
        assert!(line.starts_with("GET /search/code?"), "{line}");
        assert!(line.contains("q=x%20repo%3Ao%2Fx"), "{line}");
        assert!(line.contains("per_page=5"), "{line}");
        assert!(
            !line.contains("owner=") && !line.contains("repo=o"),
            "{line}"
        );
        reply(
            "200 OK",
            "",
            r#"{"total_count":0,"incomplete_results":false,"items":[]}"#,
        )
    });
    let transport = RestTransport::new(config(
        endpoint,
        vec![(
            "github.search.code",
            http_op(HttpMethod::Get, "/search/code"),
        )],
    ));
    let result = dispatch(
        &transport,
        "github.search.code",
        json!({"owner":"o","repo":"x","q":"x repo:o/x","per_page":5}),
    );
    server.join().unwrap();
    assert_eq!(result.response.unwrap()["body"]["total_count"], 0);
}
