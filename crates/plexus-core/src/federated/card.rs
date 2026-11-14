//! Body construction and call-bound tracking data for federated consent.
//! Filing, waiting and applying answers belong to the authorization path.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::FederatedCaller;
use crate::consent_card::{request_body, service_label, ParkedApproval};
use crate::jcs::{self, JcsError};
use crate::scope::CallScope;
use crate::storage::{CatalogAction, ConnectionRecord, PlexusStore};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Read,
    Write,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// Only identity fields participate; names, attribution and route epochs do not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerIdentity {
    pub peer_fingerprint: String,
    pub pairing_id: String,
    pub peer_class: String,
    pub claim_kind: String,
    pub canonical_claim_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallBinding {
    pub caller: CallerIdentity,
    pub owner_principal: String,
    pub subject: String,
    pub action: String,
    pub args_digest: String,
}

impl CallBinding {
    /// SHA-256 over the RFC 8785 object containing the entire binding and scope.
    /// The schema hash is checked separately when finding a pending record.
    pub fn dedup_key(&self, scope: Scope) -> Result<String, JcsError> {
        jcs::jcs_sha256(&json!({"binding": self, "scope": scope}))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Pending,
    Consumed,
    Declined,
    Expired,
    Withdrawn,
    Committed,
    Retired,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Consumed => "consumed",
            Self::Declined => "declined",
            Self::Expired => "expired",
            Self::Withdrawn => "withdrawn",
            Self::Committed => "committed",
            Self::Retired => "retired",
        }
    }
}

/// One requester correlation id, one call binding and at most one Cingulate ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub id: String,
    pub binding: CallBinding,
    pub selector: String,
    pub scope: Scope,
    pub filed_scope: Value,
    pub schema_hash: Option<String>,
    pub state: State,
    pub card_ref: Option<String>,
    /// Persist the original choice set; later row changes cannot widen it.
    pub standing_choices_offered: bool,
}

/// Context from the admitted route, not from tool arguments. A standing allow
/// with effective `ask_first` sets `per_call_only`, suppressing standing choices.
pub struct Context<'a> {
    pub caller: &'a FederatedCaller,
    pub filed_scope: &'a CallScope,
    pub expires_in_ms: i64,
    pub per_call_only: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum Search {
    Web,
    Code,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    UnsupportedRisk,
    UnsupportedPeerClass,
    Jcs(JcsError),
}

impl From<JcsError> for BuildError {
    fn from(error: JcsError) -> Self {
        Self::Jcs(error)
    }
}

#[derive(Debug, Clone)]
pub struct PreparedCard {
    pub record: Record,
    pub body: Value,
}

impl PreparedCard {
    /// Construct an unfiled pending record and its body. This makes no store
    /// change, liveness query or requester call, including for flow/run claims.
    pub fn invoke(
        store: &PlexusStore,
        context: &Context<'_>,
        connection: &ConnectionRecord,
        action: &CatalogAction,
        args: &Value,
        complete_preview: bool,
    ) -> Result<Self, BuildError> {
        let scope = match action.risk.as_str() {
            "read" => Scope::Read,
            "write" => Scope::Write,
            _ => return Err(BuildError::UnsupportedRisk),
        };
        let service = service_label(store, &connection.app_key);
        let verb = match scope {
            Scope::Read => "read from",
            Scope::Write => "make changes in",
        };
        let prompt = format!("{verb} {service} ({})", action.name);
        Self::build(
            context,
            Inputs {
                owner_principal: &connection.principal,
                subject: &connection.connection_id,
                action: &action.name,
                action_label: crate::governance::action_label(action, &action.name),
                service_label: &service,
                scope,
                schema_hash: Some(&action.schema_hash),
                prompt: &prompt,
                args,
                complete_preview,
            },
        )
    }

    /// Construct a search card from the tool's arguments, never a backend's
    /// action or arguments. Searches have an empty owner and read scope.
    pub fn search(context: &Context<'_>, search: Search, args: &Value) -> Result<Self, BuildError> {
        let (tool, label, prompt) = match search {
            Search::Web => ("web_search", "Web search", "search the web"),
            Search::Code => ("code_search", "Code search", "search public code on GitHub"),
        };
        Self::build(
            context,
            Inputs {
                owner_principal: "",
                subject: tool,
                action: tool,
                action_label: tool,
                service_label: label,
                scope: Scope::Read,
                schema_hash: None,
                prompt,
                args,
                complete_preview: false,
            },
        )
    }

    fn build(context: &Context<'_>, input: Inputs<'_>) -> Result<Self, BuildError> {
        if context.caller.attributes.peer_class
            != subc_protocol::scope::FederatedPeerClass::Computer
        {
            return Err(BuildError::UnsupportedPeerClass);
        }
        let claim = &context.caller.claim;
        let binding = CallBinding {
            caller: CallerIdentity {
                peer_fingerprint: context.caller.attributes.peer_fingerprint.clone(),
                pairing_id: context.caller.attributes.pairing_id.clone(),
                peer_class: "computer".into(),
                claim_kind: claim.claim_kind.into(),
                canonical_claim_identity: claim.canonical_claim_identity.clone(),
            },
            owner_principal: input.owner_principal.into(),
            subject: input.subject.into(),
            action: input.action.into(),
            args_digest: jcs::jcs_sha256(input.args)?,
        };
        let dedup_key = binding.dedup_key(input.scope)?;
        let record = Record {
            id: crate::storage::new_id("fedcard"),
            binding,
            selector: if claim.claim_kind.is_empty() {
                "claimless"
            } else {
                "exact_claim"
            }
            .into(),
            scope: input.scope,
            filed_scope: serde_json::to_value(context.filed_scope)
                .expect("CallScope contains only JSON-representable fields"),
            schema_hash: input.schema_hash.map(str::to_owned),
            state: State::Pending,
            card_ref: None,
            standing_choices_offered: !context.per_call_only
                && matches!(claim.claim_kind, "" | "agent" | "flow"),
        };
        let standing = !context.per_call_only && matches!(claim.claim_kind, "" | "agent" | "flow");
        let options = if standing {
            json!([
                {"id":"allow_once","label":"Allow this time","effect":"grant"},
                {"id":"allow_always","label":"Always allow","effect":"grant"},
                {"id":"deny_once","label":"Don't allow","effect":"decline"},
                {"id":"deny_always","label":"Don't allow, and don't ask again","effect":"decline"}
            ])
        } else {
            json!([
                {"id":"allow_once","label":"Allow this time","effect":"grant"},
                {"id":"deny_once","label":"Don't allow","effect":"decline"}
            ])
        };
        let body = request_body(
            &ParkedApproval {
                request_id: &record.id,
                dedup_key: &dedup_key,
                action_label: input.action_label,
                service_label: input.service_label,
                risk: input.scope.as_str(),
                args: input.args,
                complete_preview: input.complete_preview,
                args_digest: &record.binding.args_digest,
                expires_in_ms: context.expires_in_ms,
            },
            input.prompt,
            options,
            "deny_once",
        );
        Ok(Self { record, body })
    }
}

struct Inputs<'a> {
    owner_principal: &'a str,
    subject: &'a str,
    action: &'a str,
    action_label: &'a str,
    service_label: &'a str,
    scope: Scope,
    schema_hash: Option<&'a str>,
    prompt: &'a str,
    args: &'a Value,
    complete_preview: bool,
}

#[cfg(test)]
mod tests;
