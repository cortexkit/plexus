use super::{run_on, ResolvedCredential, SubcCkcredRoutePeer, WipingValue};
use serde_json::{json, Value};
use zeroize::Zeroizing;

pub(super) const OPERATION: &str = "credential.policy_token";

pub(super) fn params(identity: &str, kind: &str, resource: &str, policy_version: i64) -> Value {
    json!({"identity":identity, "service":"github", "kind":kind, "resource":resource,
        "policy_version":policy_version})
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyTokenFailure {
    Unsupported,
    NotFound,
    VersionNotActive,
    ApprovalRequired,
    ApprovalPolicyChanged,
    Unavailable,
    AuthRequired,
    NotInstalled,
    InvalidReply,
}

fn unsupported(code: &str) -> bool {
    matches!(code, "unknown_method" | "unsupported_method")
}

pub(super) fn decode(reply: WipingValue) -> Result<ResolvedCredential, PolicyTokenFailure> {
    use PolicyTokenFailure::*;
    let body = &reply.0;
    if body.get("result").is_none() && body["code"].as_str().is_some_and(unsupported) {
        return Err(Unsupported);
    }
    let result = body["result"].as_object().ok_or(InvalidReply)?;
    if let Some(error) = result.get("error") {
        if result.len() != 1 {
            return Err(InvalidReply);
        }
        return Err(match (error["code"].as_str(), error["class"].as_str()) {
            (Some("not_found"), Some("permanent")) => NotFound,
            (Some("policy_version_not_active"), Some("permanent")) => VersionNotActive,
            (Some("approval_required"), Some("permanent")) => ApprovalRequired,
            (Some("approval_policy_changed"), Some("permanent")) => ApprovalPolicyChanged,
            (Some("github_unavailable" | "store_error"), Some("transient")) => Unavailable,
            (Some("needs_reauth"), Some("auth_required")) => AuthRequired,
            (Some("not_installed"), Some("permanent")) => NotInstalled,
            _ => InvalidReply,
        });
    }
    if result.len() != 4
        || !body["result"]["permissions"]
            .as_object()
            .is_some_and(|permissions| permissions.values().all(Value::is_string))
        || !body["result"]["repositories"]
            .as_array()
            .is_some_and(|repositories| repositories.iter().all(Value::is_string))
    {
        return Err(InvalidReply);
    }
    let token = body["result"]["token"]
        .as_str()
        .filter(|token| !token.is_empty())
        .ok_or(InvalidReply)?;
    let expiry = body["result"]["expires_at_ms"]
        .as_i64()
        .ok_or(InvalidReply)?;
    // The vault keeps the record version; Plexus uses this credential for only one leg.
    Ok(ResolvedCredential::new(
        token.as_bytes().to_vec(),
        Some(expiry),
        0,
    ))
}

impl SubcCkcredRoutePeer {
    pub(super) fn call_policy_token(
        &self,
        params: Value,
    ) -> Result<ResolvedCredential, PolicyTokenFailure> {
        use PolicyTokenFailure::{Unavailable, Unsupported};
        let runtime = self.runtime.as_ref().ok_or(Unavailable)?;
        let consumer = self.consumer.clone();
        let target = self.target.clone();
        let identity = self.identity.clone();
        let (route, consumer) = run_on(runtime, async move {
            let route = consumer
                .open_route(target.clone(), identity.clone(), Default::default())
                .await
                .map_err(|_| super::CkcredRouteError::NotSent)?;
            Ok((route, consumer))
        })
        .map_err(|_| Unavailable)?;
        if *self
            .unsupported_policy_token_route
            .lock()
            .map_err(|_| Unavailable)?
            == Some(route)
        {
            return Err(Unsupported);
        }
        let body = serde_json::to_vec(&json!({"method": OPERATION, "params": params}))
            .map_err(|_| Unavailable)?;
        let response = run_on(runtime, async move {
            Ok(
                match consumer.request(&route, body, Default::default()).await {
                    Ok(bytes) => {
                        let bytes = Zeroizing::new(bytes);
                        serde_json::from_slice(&bytes)
                            .map_err(|_| Unavailable)
                            .and_then(|reply| decode(WipingValue(reply)))
                    }
                    Err(subc_client_rs::CallError::Module(error)) if unsupported(&error.code) => {
                        Err(Unsupported)
                    }
                    Err(_) => Err(Unavailable),
                },
            )
        })
        .map_err(|_| Unavailable)?;
        if matches!(response, Err(Unsupported)) {
            // The route handle changes when the vault reconnects; only this
            // connection is allowed to fall back without probing again.
            let mut previous = self
                .unsupported_policy_token_route
                .lock()
                .map_err(|_| Unavailable)?;
            if *previous != Some(route) {
                crate::diag!(warn transport: "vault does not serve credential.policy_token; using scoped credentials until the vault route reconnects");
                *previous = Some(route);
            }
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decodes_every_vendored_policy_token_case() {
        use PolicyTokenFailure::*;
        let vectors: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/vault-policy-token-v1/cases.json"
        ))
        .unwrap();
        let cases = vectors["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 9);
        for case in cases {
            assert_eq!(case["method"], "credential.policy_token");
            let name = case["name"].as_str().unwrap();
            let result = decode(WipingValue(case["body"].clone()));
            let expected = match name {
                "issue_none_kind" => {
                    assert_eq!(
                        params("github_app:plex-alfonso", "add_issue_comment", "org/r", 2),
                        case["params"]
                    );
                    let token = result.unwrap();
                    assert!(token.payload() == b"fixture-token-3");
                    assert_eq!(token.expires_at_ms, Some(4102444800000));
                    assert!(!format!("{token:?}").contains("fixture-token-3"));
                    continue;
                }
                "issue_ungranted"
                | "issue_wrong_service"
                | "issue_unbound_resource_without_approval" => NotFound,
                "issue_old_policy_without_proof" => VersionNotActive,
                "issue_no_approval_members" => ApprovalRequired,
                "issue_policy_changed" => ApprovalPolicyChanged,
                "issue_provider_error" | "issue_store_error" => Unavailable,
                _ => panic!("unrecognized vector {name}"),
            };
            assert_eq!(result.unwrap_err(), expected, "{name}");
        }
    }

    #[test]
    fn malformed_secret_reply_has_only_a_fixed_error() {
        const TEST: &str =
            "credentials::policy_token::tests::malformed_secret_reply_has_only_a_fixed_error";
        const CANARY: &str = "canary-never-print-me";
        if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_none() {
            let output = crate::test_http::bounded::child_test_output(
                TEST,
                &[("PLEXUS_LOG_STDERR_CHILD", "1")],
                std::time::Duration::from_secs(10),
                "policy token diagnostic",
            );
            assert!(output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stderr.contains("policy token diagnostic control: InvalidReply"));
            assert!(!stderr.contains(CANARY) && !stdout.contains(CANARY));
            return;
        }
        crate::test_logging::init_child();
        let reply =
            WipingValue(json!({"result":{"token":"canary-never-print-me", "expires_at_ms":"bad"}}));
        let failure = decode(reply).unwrap_err();
        assert_eq!(failure, PolicyTokenFailure::InvalidReply);
        crate::diag!(warn transport: "policy token diagnostic control: {failure:?}");
    }
}
