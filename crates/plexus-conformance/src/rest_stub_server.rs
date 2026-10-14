//! In-process REST stub server for conformance fixtures.
//!
//! Mirrors `stub_server.rs` (which does this for MCP): a long-lived local HTTP
//! server that answers the routes a fixture's manifest declares. It also
//! enforces the credential header when one is expected — a transport that
//! silently drops auth gets a 401 here instead of passing every check that only
//! looks at status codes.

use crate::http_wire::http_json;

use serde_json::Value;

/// One route the stub REST server answers. `path_template` may contain
/// `{placeholder}` segments, which match any single path segment.
#[derive(Debug, Clone)]
pub struct StubRestRoute {
    pub method: String,
    pub path_template: String,
    pub status: u16,
    pub body: Value,
}

impl StubRestRoute {
    pub fn new(
        method: impl Into<String>,
        path_template: impl Into<String>,
        status: u16,
        body: Value,
    ) -> Self {
        Self {
            method: method.into(),
            path_template: path_template.into(),
            status,
            body,
        }
    }

    fn matches(&self, method: &str, path: &str) -> bool {
        if !self.method.eq_ignore_ascii_case(method) {
            return false;
        }
        let template_segments: Vec<&str> = self.path_template.split('/').collect();
        let path_segments: Vec<&str> = path.split('/').collect();
        if template_segments.len() != path_segments.len() {
            return false;
        }
        template_segments
            .iter()
            .zip(path_segments.iter())
            .all(|(template, actual)| {
                template.starts_with('{') && template.ends_with('}') || template == actual
            })
    }
}

/// Long-lived local REST stub with a fixed HTTP worker pool.
pub struct StubRestServer {
    server: crate::http_wire::StubHttpServer,
}

impl StubRestServer {
    pub fn start(
        routes: Vec<StubRestRoute>,
        expected_authorization: Option<ExpectedCredential>,
    ) -> Result<Self, String> {
        let server = crate::http_wire::StubHttpServer::start("", move |request| {
            response_for_request(request, &routes, &expected_authorization)
        })?;
        Ok(Self { server })
    }

    pub fn endpoint(&self) -> &str {
        self.server.endpoint()
    }
}

fn response_for_request(
    request: &str,
    routes: &[StubRestRoute],
    expected_authorization: &Option<ExpectedCredential>,
) -> String {
    let (method, target) = match request
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()[..]
    {
        [method, target, _] => (method.to_ascii_uppercase(), target.to_string()),
        _ => return http_json(400, r#"{"error":"malformed_request"}"#),
    };
    // The credential assertion comes first: a request without the expected
    // header must never reach route handling, whatever it asks for.
    if let Some(expected) = expected_authorization {
        match credential_header(request, &expected.header) {
            Some(actual) if actual == expected.value => {}
            _ => return http_json(401, r#"{"error":"unauthorized"}"#),
        }
    }
    let path = target.split('?').next().unwrap_or("/");
    let Some(route) = routes.iter().find(|route| route.matches(&method, path)) else {
        return http_json(404, r#"{"error":"not_found"}"#);
    };
    // Body-carrying methods must actually carry a JSON body: a transport that
    // forgot the body would otherwise pass on status codes alone.
    if matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
        let body = request
            .find("\r\n\r\n")
            .map(|index| &request[index + 4..])
            .unwrap_or("");
        match serde_json::from_str::<Value>(body) {
            Ok(Value::Object(_)) => {}
            _ => return http_json(400, r#"{"error":"missing_json_body"}"#),
        }
    }
    http_json(route.status, &route.body.to_string())
}

/// The credential the stub demands: which header carries it, and the exact
/// value expected there. Both come from the vendor's reviewed manifest, so the
/// stub asserts the manifest's contract rather than a convention.
#[derive(Debug, Clone)]
pub struct ExpectedCredential {
    pub header: String,
    pub value: String,
}

/// Read the value of the header the vendor's manifest actually binds its
/// credential to.
///
/// The header NAME comes from the manifest rather than being fixed to
/// `Authorization`, because vendors differ: Exa's REST API takes a bare
/// `x-api-key`, Context7 takes `CONTEXT7_API_KEY`. A stub that only ever
/// looked for `Authorization` would report success for a transport that sent
/// the credential under the wrong header name entirely — it would be asserting
/// its own assumption rather than the manifest's contract.
fn credential_header(request: &str, header_name: &str) -> Option<String> {
    let headers = request.split("\r\n\r\n").next()?;
    headers.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case(header_name) {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lowercase_write_methods_require_a_json_body() {
        let route = StubRestRoute::new("POST", "/items", 200, json!({}));
        let response = response_for_request("post /items HTTP/1.1\r\n\r\n", &[route], &None);
        assert!(
            response.contains("missing_json_body"),
            "lowercase write must still require JSON"
        );
    }

    #[test]
    fn route_matching_is_segment_wise_with_placeholder_wildcards() {
        let route = StubRestRoute::new("GET", "/v1/issues/{issue_id}", 200, json!({}));
        assert!(route.matches("GET", "/v1/issues/42"));
        assert!(route.matches("get", "/v1/issues/abc-123"));
        assert!(!route.matches("GET", "/v1/issues"));
        assert!(!route.matches("GET", "/v1/issues/42/comments"));
        assert!(!route.matches("POST", "/v1/issues/42"));
        assert!(!route.matches("GET", "/v2/issues/42"));
    }

    #[test]
    fn authorization_gate_refuses_missing_and_wrong_headers() {
        let routes = vec![StubRestRoute::new(
            "GET",
            "/v1/issues/{id}",
            200,
            json!({"ok":true}),
        )];
        let expected = Some(ExpectedCredential {
            header: "Authorization".to_string(),
            value: "Bearer good-token".to_string(),
        });
        let request_line = "GET /v1/issues/1 HTTP/1.1";
        let with_good = format!("{request_line}\r\nAuthorization: Bearer good-token\r\n\r\n");
        let with_bad = format!("{request_line}\r\nAuthorization: Bearer evil\r\n\r\n");
        let with_none = format!("{request_line}\r\n\r\n");
        assert!(response_for_request(&with_good, &routes, &expected).starts_with("HTTP/1.1 200"));
        assert!(response_for_request(&with_bad, &routes, &expected).starts_with("HTTP/1.1 401"));
        assert!(response_for_request(&with_none, &routes, &expected).starts_with("HTTP/1.1 401"));
    }

    /// A vendor whose manifest binds its credential to a header other than
    /// `Authorization` must be checked against THAT header. Without this, the
    /// stub would answer 401 for a correct request (as it did for Exa's REST
    /// API, which takes a bare `x-api-key`) and — worse — would answer 200 for
    /// a transport that wrongly sent the credential as `Authorization`.
    #[test]
    fn credential_gate_honors_a_non_authorization_header() {
        let routes = vec![StubRestRoute::new(
            "POST",
            "/search",
            200,
            json!({"ok":true}),
        )];
        let expected = Some(ExpectedCredential {
            header: "x-api-key".to_string(),
            value: "exa-key".to_string(),
        });
        let line = "POST /search HTTP/1.1";
        let correct = format!("{line}\r\nx-api-key: exa-key\r\n\r\n{{}}");
        let wrong_header = format!("{line}\r\nAuthorization: Bearer exa-key\r\n\r\n{{}}");
        assert!(response_for_request(&correct, &routes, &expected).starts_with("HTTP/1.1 200"));
        assert!(
            response_for_request(&wrong_header, &routes, &expected).starts_with("HTTP/1.1 401"),
            "a credential sent under the wrong header name must be refused"
        );
    }

    #[test]
    fn body_carrying_methods_require_a_json_body() {
        let routes = vec![StubRestRoute::new(
            "POST",
            "/v1/issues",
            200,
            json!({"ok":true}),
        )];
        let post = "POST /v1/issues HTTP/1.1\r\nContent-Length: 15\r\n\r\n{\"title\":\"hello\"}";
        let post_no_body = "POST /v1/issues HTTP/1.1\r\n\r\n";
        assert!(response_for_request(post, &routes, &None).starts_with("HTTP/1.1 200"));
        assert!(response_for_request(post_no_body, &routes, &None).starts_with("HTTP/1.1 400"));
    }
}
