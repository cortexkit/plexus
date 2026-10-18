//! Resolve repository bindings before reading GitHub data through governed actions.

use crate::github::pagination::{self, ListRead};
use crate::github::resolver::{self, Binding, ResolvedRepositories};
use crate::governance::{
    AuthorizationRequest, CatalogDenial, Denial, GovernanceEngine, ResolverDenial, TransportOutcome,
};
use crate::storage::{github_store::GithubHandle, AuditRecord, PlexusStore};
use crate::{credentials::CredentialSource, transport::Transport};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

macro_rules! read_actions {
    ($($bot:literal),* ; $($ci:literal),*) => {
        pub(crate) const BOT_ACTIONS: &[&str] = &[$($bot),*];
        pub const ACTIONS: &[&str] = &[$($bot),*, $($ci),*];
    };
}
read_actions!("github.issue.get", "github.issue_comments.list", "github.issue.search";
    "github.actions.job_log", "github.actions.artifact_file", "github.actions.run.superseded");

/// Mark only a binding-checked selection as internal search authority. Raw
/// caller arguments never become this marker merely by naming repositories.
pub(crate) fn prepare_search_request(
    mut request: AuthorizationRequest,
    resolved: &ResolvedRepositories,
) -> Result<AuthorizationRequest, crate::governance::ResolverDenial> {
    let terms = request.args["terms"].as_str().unwrap_or("");
    request.args["q"] = json!(resolver::search_query(resolved, terms)?);
    Ok(request.with_resolved_github_search(resolved.repositories.clone()))
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReadError {
    UnsupportedAction,
    Denied(Denial),
    Dispatch(TransportOutcome),
    InvalidResponse,
    PageBound,
    LeaseExpired,
    Refused(&'static str),
    QuotaExhausted { retry_after_ms: i64 },
}

fn check_repository_visibility(
    store: &PlexusStore,
    principal: &str,
    repository: &str,
    scope: Option<&crate::scope::CallScope>,
) -> Result<(), ReadError> {
    if let Some(agent) = crate::scope::basal_flow_read_agent(principal, scope) {
        let handle = store
            .github_handle_for_repo(&crate::github::canonical_repository(repository))
            .map_err(|_| ReadError::Denied(Denial::StoreFailure))?;
        if !handle.is_some_and(|handle| handle.agent_id == agent && handle.status == "enabled") {
            return Err(ReadError::Refused("repository_not_visible"));
        }
    }
    Ok(())
}

fn walk_error(error: pagination::WalkError) -> ReadError {
    match error {
        pagination::WalkError::Incomplete => ReadError::PageBound,
        pagination::WalkError::LeaseExpired => ReadError::LeaseExpired,
        pagination::WalkError::InvalidResponse | pagination::WalkError::ReadFailed => {
            ReadError::InvalidResponse
        }
    }
}

/// Resolve the entire selection from the binding table before loading any
/// connection. Installation reachability is not evidence of a binding.
#[cfg(any(test, feature = "test-support"))]
pub fn resolve_read(
    store: &PlexusStore,
    action: &str,
    repository: &Value,
    args: &Value,
) -> Result<ResolvedRepositories, ReadError> {
    resolve_read_with_handle(store, action, repository, args).map(|(resolved, _)| resolved)
}

fn resolve_read_with_handle(
    store: &PlexusStore,
    action: &str,
    repository: &Value,
    args: &Value,
) -> Result<(ResolvedRepositories, GithubHandle), ReadError> {
    if !ACTIONS.contains(&action) {
        return Err(ReadError::UnsupportedAction);
    }
    // Repository names resolve, route and are sent in canonical (lowercase)
    // form, the form the binding table stores.
    let canonical = match repository {
        Value::String(name) => Value::String(crate::github::canonical_repository(name)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| match item {
                    Value::String(name) => Value::String(crate::github::canonical_repository(name)),
                    other => other.clone(),
                })
                .collect(),
        ),
        other => other.clone(),
    };
    let repository = &canonical;
    let names: Vec<&str> = match repository {
        Value::String(name) => vec![name],
        Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    };
    let mut handles = BTreeMap::new();
    for name in names {
        if let Some(handle) = store
            .github_handle_for_repo(name)
            .map_err(|_| ReadError::Denied(Denial::StoreFailure))?
        {
            handles.insert(name.to_owned(), handle);
        }
    }
    let mut fields = args
        .as_object()
        .cloned()
        .ok_or(ReadError::Denied(Denial::Resolver(
            ResolverDenial::RepositoryUnbound,
        )))?;
    let selection = if action == "github.issue.search" {
        "repositories"
    } else {
        "repository"
    };
    // The routing field is the only path selector. A second field is never a
    // substitute for the bound repository, even when GitHub can see it.
    if fields.contains_key(selection) {
        return Err(ReadError::Denied(Denial::Resolver(
            ResolverDenial::RequestFieldForbidden {
                field: selection.into(),
            },
        )));
    }
    fields.insert(selection.into(), repository.clone());
    let first = if action == "github.issue.search" {
        repository
            .as_array()
            .and_then(|items| items.first())
            .and_then(Value::as_str)
    } else {
        repository.as_str()
    };
    let first_handle = first.and_then(|repo| handles.get(repo));
    let connection = first_handle
        .map(|handle| handle.connection_id.clone())
        .unwrap_or_default();
    // The governance seam resolves again before authorization loads a connection.
    // Keep that independent check: a stale or substituted binding must still fail closed.
    let resolved = resolver::resolve(&Value::Object(fields), &connection, |repo| {
        Ok(handles.get(repo).map(|handle| Binding {
            app_handle_id: handle.app_handle_id.clone(),
            connection_id: handle.connection_id.clone(),
        }))
    })
    .map_err(|reason| ReadError::Denied(Denial::Resolver(reason)))?;
    let handle = first_handle
        .cloned()
        .ok_or(ReadError::Denied(Denial::Resolver(
            ResolverDenial::RepositoryUnbound,
        )))?;
    Ok((resolved, handle))
}

fn audit_resolver(
    store: &PlexusStore,
    principal: &str,
    action: &str,
    denial: &Denial,
) -> Result<(), ReadError> {
    let record = AuditRecord {
        principal: principal.into(),
        actor: principal.into(),
        acting_principal: principal.into(),
        agent_id: None,
        app_handle_id: None,
        agent_handle: None,
        connection_id: None,
        app_key: None,
        action: Some(action.into()),
        risk: None,
        severity: None,
        decision: "deny".into(),
        reason_code: denial.reason_code().into(),
        gate: Some("resolver".into()),
        args_redaction_summary: None,
        outcome: Some("not_sent".into()),
        latency_ms: None,
        request_id: None,
        credential_fingerprint: None,
        provider_account_fingerprint: None,
        attempt_no: Some(1),
        vendor_request_id: None,
        idempotency_key_fingerprint: None,
        response_class: None,
        reconciliation_of: None,
    };
    store
        .append_audit(&record)
        .map_err(|_| ReadError::Denied(Denial::StoreFailure))
}

/// Each page uses the normal invoke reservation, scoped credential, and audit.
/// Repository reads use the same transport and credential path as other governed actions.
#[cfg(any(test, feature = "test-support"))]
pub fn read<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    principal: &str,
    action: &str,
    repository: &Value,
    args: &Value,
) -> Result<Value, ReadError> {
    read_scoped(engine, principal, action, repository, args, None)
}

pub fn read_scoped<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    principal: &str,
    action: &str,
    repository: &Value,
    args: &Value,
    scope: Option<&crate::scope::CallScope>,
) -> Result<Value, ReadError> {
    read_with_attribution(engine, principal, action, repository, args, scope, None)
}

/// Read on a codemode route. The run's stamped agent is audit attribution,
/// never an additional source of authority or an agent-grant requirement.
pub fn read_codemode<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    principal: &str,
    action: &str,
    repository: &Value,
    args: &Value,
    scope: Option<&crate::scope::CallScope>,
) -> Result<Value, ReadError> {
    read_with_attribution(
        engine,
        principal,
        action,
        repository,
        args,
        scope,
        scope.and_then(|scope| scope.agent_id.as_deref()),
    )
}

fn read_with_attribution<C: CredentialSource + ?Sized, T: Transport + ?Sized>(
    engine: &GovernanceEngine<C, T>,
    principal: &str,
    action: &str,
    repository: &Value,
    args: &Value,
    scope: Option<&crate::scope::CallScope>,
    attributed_agent: Option<&str>,
) -> Result<Value, ReadError> {
    if action == "github.actions.job_log" {
        return job_log::read(engine, principal, repository, args, scope, attributed_agent);
    }
    if action == "github.actions.artifact_file" {
        return artifact_file::read(engine, principal, repository, args, scope, attributed_agent);
    }
    if action == "github.actions.run.superseded" {
        return run_superseded::read(engine, principal, repository, args, scope, attributed_agent);
    }
    let visible = || -> Result<(), ReadError> {
        if BOT_ACTIONS.contains(&action) {
            let repositories: Vec<&str> = match repository {
                Value::String(name) => vec![name],
                Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
                _ => vec![],
            };
            for repository in repositories {
                check_repository_visibility(engine.store(), principal, repository, scope)?;
            }
        }
        Ok(())
    };
    // Reject the entire selection before resolving connections or checking grants.
    visible()?;
    let (resolved, handle) =
        match resolve_read_with_handle(engine.store(), action, repository, args) {
            Ok(resolved) => resolved,
            Err(ReadError::Denied(denial @ Denial::Resolver(_))) => {
                audit_resolver(engine.store(), principal, action, &denial)?;
                return Err(ReadError::Denied(denial));
            }
            Err(error) => return Err(error),
        };
    // The handle connection's owner, needed to find the manifest that declares
    // each read's arguments.
    let connection_principal = handle.connection_principal;
    let invoke = |page: Option<usize>| -> Result<Value, ReadError> {
        visible()?;
        let mut mapped = if action == "github.issue.search" {
            let terms = args.get("terms").and_then(Value::as_str).unwrap_or("");
            Map::from_iter([
                ("repositories".into(), json!(resolved.repositories)),
                ("terms".into(), json!(terms)),
                (
                    "q".into(),
                    json!(resolver::search_query(&resolved, terms)
                        .map_err(|reason| ReadError::Denied(Denial::Resolver(reason)))?),
                ),
            ])
        } else {
            let mut mapped = resolver::path_args(&resolved, resolved.repositories.first().unwrap())
                .map_err(|reason| ReadError::Denied(Denial::Resolver(reason)))?;
            for field in ["issue_number", "since"] {
                if let Some(value) = args.get(field) {
                    mapped.insert(field.into(), value.clone());
                }
            }
            mapped
        };
        if let Some(page) = page {
            mapped.insert("page".into(), json!(page));
            mapped.insert("per_page".into(), json!(pagination::PER_PAGE));
        }
        // Only the arguments this read's action declares reach the vendor; a
        // `since` asked of a read that does not take one is dropped here.
        let args = resolver::declared_args(
            engine.store(),
            &connection_principal,
            &resolved.binding.connection_id,
            action,
            &Value::Object(mapped),
        )
        .map_err(|error| {
            ReadError::Denied(match error {
                resolver::DeclaredArgsError::Store => Denial::StoreFailure,
                resolver::DeclaredArgsError::NotDeclared => {
                    Denial::Catalog(CatalogDenial::NotFound)
                }
            })
        })?;
        let mut request =
            AuthorizationRequest::new(principal, &resolved.binding.connection_id, action, args)
                .with_diagnostic_tool("github");
        if let Some(scope) = scope {
            request = request.with_scope_attribution_only(scope.clone());
        }
        if let Some(agent) = attributed_agent {
            request = request.with_attributed_agent(agent);
        }
        if action != "github.issue.search" {
            // The repository was resolved above; route by it without sending it.
            request = request.with_resolved_repository(resolved.repositories[0].clone());
        } else {
            request = prepare_search_request(request, &resolved)
                .map_err(|reason| ReadError::Denied(Denial::Resolver(reason)))?;
        }
        let reservation = engine.authorize(request).map_err(ReadError::Denied)?;
        // Repository ownership or bot status can change during authorization;
        // recheck the agent's current bindings before sending this page.
        visible()?;
        match engine.revalidate_and_dispatch(&reservation).outcome {
            TransportOutcome::Completed {
                response: Some(result),
            } => Ok(result),
            other => Err(ReadError::Dispatch(other)),
        }
    };
    if action == "github.issue_comments.list" {
        let started = crate::storage::now_ms();
        let mut failure = None;
        let walk = pagination::walk(
            ListRead::IssueComments,
            started,
            crate::storage::now_ms,
            |page| {
                invoke(Some(page.page)).map_err(|error| {
                    failure = Some(error);
                    pagination::WalkError::ReadFailed
                })
            },
        )
        .map_err(|error| failure.unwrap_or_else(|| walk_error(error)))?;
        return Ok(json!(walk.items()));
    }
    let mut response = invoke(None)?;
    if action == "github.issue.search" {
        let items = response
            .get_mut("items")
            .and_then(Value::as_array_mut)
            .ok_or(ReadError::InvalidResponse)?;
        resolver::filter_search_results(&resolved, items);
        let count = items.len();
        response["total_count"] = json!(count);
        // A page cannot prove the size or completeness of the bound result set.
        response["incomplete_results"] = json!(true);
        response["incomplete"] = json!(true);
    }
    Ok(response)
}

mod artifact_file;
mod ci;
mod job_log;
mod run_superseded;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn caller_repository_arguments_cannot_set_the_private_search_marker() {
        let request = AuthorizationRequest::new(
            "caller",
            "connection",
            "github.issue.search",
            json!({
                "repositories":["other/private"], "resolved_github_search_repositories":["other/private"], "resolved_github_search":true,
            }),
        );
        assert_eq!(request.resolved_github_search_repositories(), None);
    }
    #[test]
    fn read_lease_expiry_has_its_own_error() {
        assert_eq!(
            walk_error(pagination::WalkError::LeaseExpired),
            ReadError::LeaseExpired,
            "lease expiry must not be reported as invalid vendor data"
        );
    }
}
