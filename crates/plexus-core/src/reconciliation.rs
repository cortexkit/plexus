//! Execute declared write-reconciliation classes for `outcome_unknown` records.
//!
//! Reconciliation is not prose: each write action may declare correlation
//! fields, a read-back action, and a timeout. The read-back runs through the
//! full governance path so revoked connections and other gates still fail closed.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::credentials::CredentialSource;
use crate::governance::{AuthorizationRequest, GovernanceEngine, TransportOutcome};
use crate::storage::AuditRecord;
use crate::transport::{Retryability, Transport};

/// A write whose vendor outcome was not definitive.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutcomeUnknownRecord {
    pub request_id: String,
    pub principal: String,
    /// Original caller, whose current grants must authorize the later read-back.
    pub acting_principal: String,
    pub actor: String,
    pub connection_id: String,
    pub action: String,
    pub args: Value,
    pub occurred_at_ms: i64,
}

/// Declared reconciliation class loaded from the catalog/manifest.
pub type ReconciliationClass = crate::manifest::Reconciliation;

/// Result of running reconciliation for one outcome_unknown write.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ReconcileResult {
    Confirmed {
        evidence: Value,
    },
    NotFound,
    Ambiguous {
        reason: String,
    },
    /// Read-back itself was denied (e.g. connection revoked) — fail closed.
    Denied {
        reason_code: String,
    },
    /// The read-back could not reach a verdict this time (the vendor failed or
    /// its outcome was unknown). The record stays queued and the next sweep
    /// reads back again, until the declared timeout settles it as ambiguous.
    Retrying {
        reason: String,
    },
}

impl ReconcileResult {
    fn as_status(&self) -> &'static str {
        match self {
            Self::Confirmed { .. } => "confirmed",
            Self::NotFound => "not_found",
            Self::Ambiguous { .. } => "ambiguous",
            Self::Denied { .. } => "denied",
            Self::Retrying { .. } => "pending",
        }
    }
}

/// Parse a catalog/manifest reconciliation object into the typed class.
pub fn parse_reconciliation_class(value: &Value) -> Option<ReconciliationClass> {
    let class: ReconciliationClass = serde_json::from_value(value.clone()).ok()?;
    class.valid().then_some(class)
}

impl<C, T> GovernanceEngine<C, T>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    /// Reconcile an `outcome_unknown` write against its declared read-back class.
    pub fn reconcile(&self, record: &OutcomeUnknownRecord) -> ReconcileResult {
        let now = crate::storage::now_ms();
        let action = match self.store().catalog_action(
            &record.principal,
            &record.connection_id,
            &record.action,
        ) {
            Ok(Some(action)) => action,
            Err(_) => {
                return ReconcileResult::Retrying {
                    reason: "catalog_store_failed".into(),
                }
            }
            Ok(None) => {
                return self.finish_reconcile(
                    record,
                    ReconcileResult::Ambiguous {
                        reason: "original_action_missing".to_string(),
                    },
                );
            }
        };
        let Some(class) = action
            .reconciliation
            .as_ref()
            .and_then(parse_reconciliation_class)
        else {
            return self.finish_reconcile(
                record,
                ReconcileResult::Ambiguous {
                    reason: "reconciliation_class_missing".to_string(),
                },
            );
        };

        let elapsed_ms = now.saturating_sub(record.occurred_at_ms);
        let timeout_ms = i64::try_from(class.timeout_s)
            .unwrap_or(i64::MAX)
            .saturating_mul(1_000);
        if elapsed_ms >= timeout_ms {
            return self.finish_reconcile(
                record,
                ReconcileResult::Ambiguous {
                    reason: "timeout_exceeded".to_string(),
                },
            );
        }

        if class.read_back_action == record.action {
            return self.finish_reconcile(
                record,
                ReconcileResult::Denied {
                    reason_code: "reconciliation_self_target".to_string(),
                },
            );
        }
        // Discovery and review can change risk after manifest ingest. Only the
        // current catalog can establish that the read-back still reads.
        let read_back = self.store().catalog_action(
            &record.principal,
            &record.connection_id,
            &class.read_back_action,
        );
        if read_back.is_err() {
            return ReconcileResult::Retrying {
                reason: "catalog_store_failed".into(),
            };
        }
        if !matches!(read_back, Ok(Some(ref target)) if target.risk == "read") {
            return self.finish_reconcile(
                record,
                ReconcileResult::Denied {
                    reason_code: "reconciliation_target_not_read".to_string(),
                },
            );
        }

        if class
            .correlation_fields
            .iter()
            .any(|field| record.args.get(field).is_none())
        {
            return self.finish_reconcile(
                record,
                ReconcileResult::Ambiguous {
                    reason: "correlation_field_missing_from_write".into(),
                },
            );
        }
        let read_args = correlation_args(&record.args, &class.correlation_fields);
        let authorization = AuthorizationRequest::new(
            record.acting_principal.clone(),
            record.connection_id.clone(),
            class.read_back_action.clone(),
            read_args,
        )
        .with_actor(record.actor.clone());

        let reservation = match self.authorize(authorization) {
            Ok(reservation) => reservation,
            Err(denial) => {
                return self.finish_reconcile(
                    record,
                    ReconcileResult::Denied {
                        reason_code: denial.reason_code().to_string(),
                    },
                );
            }
        };
        // Connection IDs are owner-scoped. A caller may now resolve the same ID
        // to a different owner's connection; never read that connection instead.
        if reservation.principal != record.principal {
            if let Err(error) = self
                .store()
                .abandon_reservation(&reservation.principal, &reservation.reservation_id)
            {
                crate::diag!(warn governance: "reconciliation reservation cleanup failed: {error}");
            }
            return self.finish_reconcile(
                record,
                ReconcileResult::Denied {
                    reason_code: "reconciliation_owner_changed".to_string(),
                },
            );
        }
        // Authorization reloads the catalog. Check its snapshot too, closing
        // the race between the preflight lookup and authorization; dispatch
        // revalidation rejects any subsequent catalog generation change.
        if reservation.risk != crate::manifest::Risk::Read {
            if let Err(error) = self
                .store()
                .abandon_reservation(&reservation.principal, &reservation.reservation_id)
            {
                crate::diag!(warn governance: "reconciliation reservation cleanup failed: {error}");
            }
            return self.finish_reconcile(
                record,
                ReconcileResult::Denied {
                    reason_code: "reconciliation_target_not_read".to_string(),
                },
            );
        }
        let outcome = self.revalidate_and_dispatch(&reservation);
        let result = correlate_dispatch(
            &outcome.outcome,
            outcome.retryability,
            &record.args,
            &class.correlation_fields,
        );
        if let ReconcileResult::Retrying { reason } = &result {
            // Settling now would delete the queued record after a single
            // failed read, although the vendor may answer on the next sweep.
            crate::diag!(info governance: "write reconciliation read-back will be retried: request_id={:?} reason={reason}", record.request_id);
            return result;
        }
        self.finish_reconcile(record, result)
    }

    fn finish_reconcile(
        &self,
        record: &OutcomeUnknownRecord,
        result: ReconcileResult,
    ) -> ReconcileResult {
        let status = result.as_status();
        let reason = match &result {
            ReconcileResult::Ambiguous { reason } => Some(reason.as_str()),
            ReconcileResult::Denied { reason_code } => Some(reason_code.as_str()),
            _ => None,
        };
        if let Err(error) = self
            .store()
            .finish_write_reconciliation(record, status, reason)
        {
            eprintln!(warn governance: "write reconciliation completion failed: {error}");
            return ReconcileResult::Retrying {
                reason: "completion_store_failed".into(),
            };
        }

        if let Err(error) = self.store().append_audit(&AuditRecord {
            principal: record.principal.clone(),
            actor: record.actor.clone(),
            acting_principal: record.acting_principal.clone(),
            agent_id: None,
            app_handle_id: None,
            agent_handle: None,
            connection_id: Some(record.connection_id.clone()),
            app_key: None,
            action: Some(record.action.clone()),
            risk: None,
            severity: None,
            decision: "allow".to_string(),
            reason_code: match &result {
                ReconcileResult::Denied { reason_code }
                    if reason_code.starts_with("reconciliation_") =>
                {
                    reason_code.clone()
                }
                ReconcileResult::Ambiguous { reason } => format!("reconciliation_{reason}"),
                _ => format!("reconciliation_{status}"),
            },
            gate: Some("reconciliation".to_string()),
            args_redaction_summary: Some(format!("reconciliation_of:{}", record.request_id)),
            outcome: Some(status.to_string()),
            latency_ms: None,
            request_id: Some(format!("recon_{}", record.request_id)),
            credential_fingerprint: None,
            provider_account_fingerprint: None,
            attempt_no: Some(1),
            vendor_request_id: None,
            idempotency_key_fingerprint: None,
            response_class: None,
            reconciliation_of: Some(record.request_id.clone()),
        }) {
            eprintln!(error governance: "audit append failed: reconciliation status={status:?} principal={:?} actor={:?} request_id={:?}: {error}", record.principal, record.actor, record.request_id);
        }
        result
    }
}

fn correlation_args(original: &Value, fields: &[String]) -> Value {
    let mut map = serde_json::Map::new();
    for field in fields {
        if let Some(value) = original.get(field) {
            map.insert(field.clone(), value.clone());
        }
    }
    Value::Object(map)
}

fn correlate_outcome(
    outcome: &TransportOutcome,
    original_args: &Value,
    fields: &[String],
) -> ReconcileResult {
    match outcome {
        TransportOutcome::Completed {
            response: Some(response),
        } => correlate_response(response, original_args, fields),
        // A read-back that returned no body says nothing about whether the
        // write landed, so it cannot be the definitive "not found".
        TransportOutcome::Completed { response: None } => ReconcileResult::Ambiguous {
            reason: "read_back_empty_body".to_string(),
        },
        TransportOutcome::OutcomeUnknown => ReconcileResult::Retrying {
            reason: "read_back_outcome_unknown".to_string(),
        },
        TransportOutcome::VendorFailed { code, .. } => ReconcileResult::Retrying {
            reason: format!("read_back_vendor_failed:{code}"),
        },
        TransportOutcome::NotSent { code, .. } => ReconcileResult::Denied {
            reason_code: code.clone(),
        },
    }
}

fn correlate_dispatch(
    outcome: &TransportOutcome,
    retryability: Retryability,
    original: &Value,
    fields: &[String],
) -> ReconcileResult {
    if let TransportOutcome::NotSent { code, .. } = outcome {
        if retryability != Retryability::Terminal {
            return ReconcileResult::Retrying {
                reason: format!("read_back_not_sent:{code}"),
            };
        }
    }
    correlate_outcome(outcome, original, fields)
}

fn correlate_response(
    response: &Value,
    original_args: &Value,
    fields: &[String],
) -> ReconcileResult {
    if fields.is_empty() {
        return ReconcileResult::Ambiguous {
            reason: "no_correlation_fields".to_string(),
        };
    }
    // Without every correlation value from the original write there is
    // nothing to compare against, so no candidate could ever match and
    // "not found" would be a guess.
    if fields
        .iter()
        .any(|field| original_args.get(field).is_none())
    {
        return ReconcileResult::Ambiguous {
            reason: "correlation_field_missing_from_write".to_string(),
        };
    }
    let candidates = match response {
        Value::Array(items) => items.as_slice(),
        other => std::slice::from_ref(other),
    };
    if candidates.is_empty() {
        return ReconcileResult::Retrying {
            reason: "read_back_empty_search".into(),
        };
    }
    // A read-back whose items carry none of the correlation fields has a
    // shape the declaration does not describe; it cannot rule the write out.
    if !candidates
        .iter()
        .any(|candidate| fields.iter().all(|field| candidate.get(field).is_some()))
    {
        return ReconcileResult::Ambiguous {
            reason: "correlation_field_missing_from_read_back".to_string(),
        };
    }
    let matches = candidates
        .iter()
        .filter(|candidate| fields_match(candidate, original_args, fields))
        .cloned()
        .collect::<Vec<_>>();
    match matches.len() {
        0 => ReconcileResult::NotFound,
        1 => ReconcileResult::Confirmed {
            evidence: matches.into_iter().next().unwrap_or(Value::Null),
        },
        _ => ReconcileResult::Ambiguous {
            reason: "multiple_matches".to_string(),
        },
    }
}

fn fields_match(candidate: &Value, original_args: &Value, fields: &[String]) -> bool {
    fields.iter().all(|field| {
        let expected = original_args.get(field);
        let actual = candidate.get(field);
        match (expected, actual) {
            (Some(left), Some(right)) => left == right,
            _ => false,
        }
    })
}

/// Argument-free disposition visible to the caller and connection owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteReconciliationStatus {
    pub request_id: String,
    pub connection_id: String,
    pub action: String,
    pub status: String,
    pub reason: Option<String>,
}

pub(crate) struct PendingWriteReconciliation {
    pub record: OutcomeUnknownRecord,
    pub expires_at_ms: i64,
}

impl<C: CredentialSource + ?Sized, T: Transport + ?Sized> GovernanceEngine<C, T> {
    pub(crate) fn queue_unknown_write(
        &self,
        reservation: &crate::governance::Reservation,
    ) -> WriteReconciliationStatus {
        let record = OutcomeUnknownRecord {
            request_id: reservation.request_id.clone(),
            principal: reservation.principal.clone(),
            acting_principal: reservation.acting_principal.clone(),
            actor: reservation.actor.clone(),
            connection_id: reservation.connection_id.clone(),
            action: reservation.action.clone(),
            args: reservation.args.clone(),
            occurred_at_ms: crate::storage::now_ms(),
        };
        let lookup =
            self.store()
                .catalog_action(&record.principal, &record.connection_id, &record.action);
        let lookup_failed = lookup.is_err();
        let class = lookup
            .ok()
            .flatten()
            .and_then(|action| action.reconciliation)
            .as_ref()
            .and_then(parse_reconciliation_class);
        let mut status = WriteReconciliationStatus {
            request_id: record.request_id.clone(),
            connection_id: record.connection_id.clone(),
            action: record.action.clone(),
            status: "pending".to_string(),
            reason: None,
        };
        if class.is_none() && !lookup_failed {
            status.status = "unreconcilable".to_string();
            status.reason = Some("reconciliation_class_missing".to_string());
        }
        let saved = if class.is_some() || lookup_failed {
            self.store()
                .enqueue_write_reconciliation(&record, reservation.intent_id.as_deref())
        } else {
            self.store().finish_write_reconciliation_with_intent(
                &record,
                reservation.intent_id.as_deref(),
                &status.status,
                status.reason.as_deref(),
            )
        };
        if let Err(error) = saved {
            eprintln!(warn governance: "unknown write reconciliation persistence failed: {error}");
            status.status = "unreconcilable".to_string();
            status.reason = Some(
                if crate::secret_input::contains_secret_input(&record.args) {
                    "secret_input_rejected"
                } else {
                    "reconciliation_store_failed"
                }
                .to_string(),
            );
            if let Err(error) = self.store().finish_write_reconciliation_with_intent(
                &record,
                reservation.intent_id.as_deref(),
                &status.status,
                status.reason.as_deref(),
            ) {
                crate::diag!(warn governance: "unknown write fallback persistence failed: {error}");
            }
        }

        status
    }

    /// Check uncertain writes on every scheduler tick, before their timeout expires.
    /// Discard argument payloads after one day even if the declared timeout is longer.
    /// Settled results, which hold no arguments, are kept for the operator's
    /// audit retention window so they age out together with the audit rows
    /// that name them.
    pub fn sweep_write_reconciliations(
        &self,
        now_ms: i64,
        result_retention_window_ms: i64,
    ) -> Result<usize, cortexkit_store::StoreError> {
        let pending = self.store().pending_write_reconciliations_at(now_ms)?;
        let count = pending.len().min(8);
        // Bound vendor work so a backlog cannot consume a whole poll pass.
        for pending in pending.into_iter().take(8) {
            let result = if now_ms >= pending.expires_at_ms {
                self.finish_reconcile(
                    &pending.record,
                    ReconcileResult::Ambiguous {
                        reason: "retention_expired".to_string(),
                    },
                )
            } else {
                self.reconcile(&pending.record)
            };
            if matches!(result, ReconcileResult::Retrying { .. }) {
                if let Err(error) = self
                    .store()
                    .backoff_write_reconciliation(&pending.record, now_ms)
                {
                    crate::diag!(warn governance: "write reconciliation backoff failed: {error}");
                }
            }
        }
        self.store()
            .prune_write_reconciliation_results(now_ms, result_retention_window_ms)?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn transient_not_sent_read_back_remains_retryable() {
        let outcome = TransportOutcome::NotSent {
            code: "connect_failed".into(),
            message: "offline".into(),
        };
        assert!(matches!(
            correlate_dispatch(&outcome, Retryability::AutoRetryable, &json!({}), &[]),
            ReconcileResult::Retrying { .. }
        ));
        assert!(matches!(
            correlate_dispatch(&outcome, Retryability::Terminal, &json!({}), &[]),
            ReconcileResult::Denied { .. }
        ));
    }

    #[test]
    fn reconciliation_parser_refuses_malformed_fields_and_overflowing_timeout() {
        for fields in [json!([]), json!([5]), json!([""])] {
            assert!(parse_reconciliation_class(
                &json!({"correlation_fields":fields,"read_back_action":"search","timeout_s":60})
            )
            .is_none());
        }
        assert!(parse_reconciliation_class(&json!({"correlation_fields":["title"],"read_back_action":"search","timeout_s":u64::MAX})).is_none());
    }

    #[test]
    fn parse_class_requires_timeout_and_read_back() {
        assert!(parse_reconciliation_class(&json!({
            "correlation_fields": ["title"],
            "read_back_action": "search",
            "timeout_s": 60
        }))
        .is_some());
        assert!(parse_reconciliation_class(&json!({
            "correlation_fields": ["title"],
            "read_back_action": "",
            "timeout_s": 60
        }))
        .is_none());
    }

    #[test]
    fn correlation_matches_single_object() {
        let response = json!({"title": "A", "team": "core"});
        let original = json!({"title": "A", "team": "core", "body": "x"});
        let result = correlate_response(
            &response,
            &original,
            &["title".to_string(), "team".to_string()],
        );
        assert!(matches!(result, ReconcileResult::Confirmed { .. }));
    }

    /// "Not found" is a definitive verdict that the write did not land, so
    /// only a read-back that could have shown the write may produce it. A
    /// failed or unknown read-back is retried; an empty body or a missing
    /// correlation value is ambiguous.
    #[test]
    fn only_a_conclusive_read_back_settles_as_not_found() {
        let fields = ["title".to_string(), "team".to_string()];
        let original = json!({"title": "A", "team": "core"});
        let verdict = |outcome: TransportOutcome, original: &Value| {
            correlate_outcome(&outcome, original, &fields)
        };
        assert_eq!(
            verdict(
                TransportOutcome::Completed {
                    response: Some(json!([{"title": "B", "team": "core"}]))
                },
                &original
            ),
            ReconcileResult::NotFound,
            "positive control: items that carry the fields but differ are a real not-found"
        );
        assert_eq!(
            verdict(TransportOutcome::Completed { response: None }, &original),
            ReconcileResult::Ambiguous {
                reason: "read_back_empty_body".into()
            },
            "an empty read-back body must not settle as not found"
        );
        assert_eq!(
            verdict(
                TransportOutcome::Completed {
                    response: Some(json!([{"id": 7}]))
                },
                &original
            ),
            ReconcileResult::Ambiguous {
                reason: "correlation_field_missing_from_read_back".into()
            }
        );
        assert_eq!(
            verdict(
                TransportOutcome::Completed {
                    response: Some(json!([{"title": "A", "team": "core"}]))
                },
                &json!({"title": "A"})
            ),
            ReconcileResult::Ambiguous {
                reason: "correlation_field_missing_from_write".into()
            }
        );
        assert_eq!(
            verdict(
                TransportOutcome::VendorFailed {
                    code: "http_503".into(),
                    message: "unavailable".into()
                },
                &original
            ),
            ReconcileResult::Retrying {
                reason: "read_back_vendor_failed:http_503".into()
            }
        );
        assert_eq!(
            verdict(TransportOutcome::OutcomeUnknown, &original),
            ReconcileResult::Retrying {
                reason: "read_back_outcome_unknown".into()
            }
        );
    }
}
