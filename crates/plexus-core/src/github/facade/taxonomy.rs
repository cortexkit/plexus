//! Stable facade refusals from governed authorization and transport outcomes.
use crate::governance::{self, Denial, TransportOutcome};
use serde_json::Value;

pub(super) fn denial(denial: &Denial, gate: &str) -> String {
    if let Denial::GrantRefusal(refusal) = denial {
        return refusal.wire().to_string();
    }
    governance::pipeline_denial(denial, gate)
}

pub(super) fn dispatch(outcome: TransportOutcome) -> Result<Value, String> {
    match outcome {
        TransportOutcome::Completed { response } => Ok(response.unwrap_or(Value::Null)),
        TransportOutcome::VendorFailed { code, .. }
            if code == "handle_credential_rejected" || code == "http_401" =>
        {
            Err("handle_credential_rejected".into())
        }
        TransportOutcome::VendorFailed { code, message } => {
            if code == "http_422" {
                let errors = super::validation::errors(&message);
                if !errors.is_empty() {
                    return Err(format!(
                        "vendor_rejected{{status: 422, errors: {}}}",
                        serde_json::to_string(&errors).expect("validation errors are JSON")
                    ));
                }
            }
            let status = code.strip_prefix("http_").unwrap_or(&code);
            Err(format!("vendor_rejected{{status: {status}}}"))
        }
        // A handle credential refusal already carries its failure class and
        // is the caller-facing spelling.
        TransportOutcome::NotSent { code, .. }
            if code.starts_with("handle_credential_unresolvable{") =>
        {
            Err(code)
        }
        TransportOutcome::NotSent { code, .. } => Err(match code.as_str() {
            "aborted_stale_authorization" => {
                "stale_authority{dimension: authorization_snapshot_stale}"
            }
            "grant_hash_mismatch" => "stale_authority{dimension: grant_hash_mismatch}",
            "reservation_expired" => "stale_authority{dimension: reservation_expired}",
            // The bot handle has no credential configured, or its credential
            // cannot be resolved. Retrying cannot fix that; an operator has to
            // repair the handle's credential.
            "credential_missing" | "handle_credential_unresolvable" => {
                crate::github::credential::UNRESOLVABLE_PERMANENT
            }
            "nonce_in_flight" => "nonce_in_flight",
            "store_failure" | "store_error" => "store_failure",
            _ => "transport_not_sent",
        }
        .into()),
        TransportOutcome::OutcomeUnknown => Err("outcome_unknown".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_known_not_sent_codes_have_facade_spellings() {
        for (raw, mapped) in [
            (
                "aborted_stale_authorization",
                "stale_authority{dimension: authorization_snapshot_stale}",
            ),
            (
                "grant_hash_mismatch",
                "stale_authority{dimension: grant_hash_mismatch}",
            ),
            (
                "reservation_expired",
                "stale_authority{dimension: reservation_expired}",
            ),
            (
                "credential_missing",
                "handle_credential_unresolvable{class: permanent}",
            ),
            (
                "handle_credential_unresolvable{class: auth_required}",
                "handle_credential_unresolvable{class: auth_required}",
            ),
            (
                "handle_credential_unresolvable{class: transient}",
                "handle_credential_unresolvable{class: transient}",
            ),
            ("nonce_in_flight", "nonce_in_flight"),
            ("rate_limited", "transport_not_sent"),
            ("store_failure", "store_failure"),
        ] {
            assert_eq!(
                dispatch(TransportOutcome::NotSent {
                    code: raw.into(),
                    message: "ignored".into()
                }),
                Err(mapped.into())
            );
        }
    }
}
