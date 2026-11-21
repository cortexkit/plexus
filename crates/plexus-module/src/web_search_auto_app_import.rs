use super::{MIN_RETRY_MS, OWNER};
use crate::agent_policy::{ImportIssue, ImportStatus};
use crate::ModuleState;
use plexus_core::agent_registry::AgentLookup;
use plexus_core::credentials::valid_credential_id;
use plexus_core::diag;
use plexus_core::github::control::{self, AttestedApp, AttestedImport, ExistingAttestedApp};
use plexus_core::storage::relay::canonical_app_id;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const HEALTH_LIMIT_PER_KIND: usize = 10;

#[derive(Default)]
pub(super) struct Reconciler {
    logged: BTreeSet<(String, &'static str)>,
    next_retry: Option<i64>,
}

impl Reconciler {
    pub(super) fn due(&self, now: i64) -> bool {
        self.next_retry.is_some_and(|next| now >= next)
    }

    pub(super) fn defer_retry(&mut self, now: i64) {
        if self.due(now) {
            self.next_retry = Some(now.saturating_add(MIN_RETRY_MS));
        }
    }

    pub(super) fn reconcile(
        &mut self,
        state: &ModuleState,
        reply: &Value,
        clock: &dyn Fn() -> i64,
    ) {
        self.defer_retry(clock());
        let Some(rows) = reply
            .pointer("/result/credentials")
            .and_then(Value::as_array)
        else {
            return;
        };
        let mut candidates = BTreeMap::new();
        for row in rows {
            let Some((record, slug)) = row["id"].as_str().and_then(|record| {
                record
                    .strip_prefix("github_app:")
                    .map(|slug| (record, slug))
            }) else {
                continue;
            };
            let metadata = &row["github_app"];
            if metadata["created_by"] == "vault" {
                let candidate = parse(record, slug, metadata);
                candidates
                    .entry(slug)
                    .and_modify(|entry| *entry = Err("duplicate_attestation"))
                    .or_insert(candidate);
            }
        }
        self.logged
            .retain(|(slug, _)| candidates.contains_key(slug.as_str()));
        let mut health = ImportStatus::default();
        let mut next_retry = None;
        for (slug, candidate) in candidates {
            if !state.runtime.connector_home.held() {
                return;
            }
            let outcome = match candidate {
                Ok(app) => reconcile_app(state, &app, clock),
                Err(reason) => {
                    self.log_once(slug, reason);
                    continue;
                }
            };
            match outcome {
                Outcome::Imported => push_bounded(&mut health.imported, || slug.to_owned()),
                Outcome::Pending(reason, retry_at) => {
                    next_retry = next_retry.into_iter().chain(retry_at).min();
                    push_bounded(&mut health.pending, || ImportIssue {
                        slug: slug.to_owned(),
                        reason,
                    });
                }
                Outcome::Conflict(reason) => {
                    self.log_once(slug, reason);
                    push_bounded(&mut health.conflicts, || ImportIssue {
                        slug: slug.to_owned(),
                        reason,
                    });
                }
                Outcome::NotHome => return,
            }
        }
        if state.runtime.connector_home.held() {
            self.next_retry = next_retry;
            state
                .health
                .agent_policy
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .imports = health;
        }
    }

    fn log_once(&mut self, slug: &str, reason: &'static str) {
        if self.logged.insert((slug.to_owned(), reason)) {
            let label: String = slug.chars().take(100).collect();
            diag!(warn governance: "vault App {label:?} refused for automatic import: {reason}");
        }
    }
}

fn push_bounded<T>(items: &mut Vec<T>, item: impl FnOnce() -> T) {
    if items.len() < HEALTH_LIMIT_PER_KIND {
        items.push(item());
    }
}

fn parse<'a>(
    record: &str,
    slug: &'a str,
    metadata: &'a Value,
) -> Result<AttestedApp<'a>, &'static str> {
    if !valid_credential_id(record) {
        return Err("invalid_record_id");
    }
    if metadata["slug"].as_str() != Some(slug) {
        return Err("app_slug_mismatch");
    }
    let app_id = metadata["app_id"]
        .as_str()
        .and_then(canonical_app_id)
        .ok_or("invalid_app_id")?;
    let agent = metadata["agent"]
        .as_str()
        .filter(|agent| {
            agent.strip_prefix("agent_").is_some_and(|hex| {
                hex.len() == 16
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        })
        .ok_or("invalid_agent_id")?;
    Ok(AttestedApp {
        slug,
        agent,
        app_id,
    })
}

enum Outcome {
    Imported,
    Pending(&'static str, Option<i64>),
    Conflict(&'static str),
    NotHome,
}

fn existing_outcome(existing: ExistingAttestedApp) -> Outcome {
    match existing {
        ExistingAttestedApp::Enabled => Outcome::Imported,
        ExistingAttestedApp::Disabled { next_probe_at_ms } => {
            Outcome::Pending("handle_disabled", next_probe_at_ms)
        }
        ExistingAttestedApp::Conflict => Outcome::Conflict("handle_identity_conflict"),
    }
}

fn reconcile_app(state: &ModuleState, app: &AttestedApp<'_>, clock: &dyn Fn() -> i64) -> Outcome {
    let retry = |reason| Outcome::Pending(reason, Some(clock().saturating_add(MIN_RETRY_MS)));
    let current = || match app.existing(state.store()) {
        Ok(Some(existing)) => existing_outcome(existing),
        _ => retry("import_store_failed"),
    };
    let reprobe = match app.existing(state.store()) {
        Ok(Some(ExistingAttestedApp::Disabled {
            next_probe_at_ms: Some(next),
        })) if clock() >= next => true,
        Ok(Some(existing)) => return existing_outcome(existing),
        Ok(None) => false,
        Err(_) => return retry("import_store_failed"),
    };
    let held = || state.runtime.connector_home.held();
    if !held() {
        return Outcome::NotHome;
    }
    match state.runtime.agent_registry.lookup(app.agent) {
        AgentLookup::Known => {}
        AgentLookup::Retired => return retry("agent_retired"),
        AgentLookup::Unknown => return retry("agent_unknown"),
        AgentLookup::Unavailable => return retry("agent_registry_unavailable"),
    }
    if !held() {
        return Outcome::NotHome;
    }
    let reader = crate::github_control_reader(state);
    let provider = state.runtime.github_handle_credentials.as_deref();
    if reprobe {
        let Some(provider) = provider else {
            return retry("handle_disabled");
        };
        return match app.reprobe(state.store(), provider, reader.as_ref(), clock(), &held) {
            Ok(true) if held() => {
                let connection_id = control::handle_connection_id(app.slug);
                if !state.runtime.rest_transport.has_connection(&connection_id) {
                    crate::register_handle_connection_transports(state, OWNER, &[connection_id]);
                }
                wake_binders(state);
                Outcome::Imported
            }
            Ok(true) => Outcome::NotHome,
            Ok(false) => current(),
            Err(_) => retry("import_store_failed"),
        };
    }
    match app.import(state.store(), provider, reader.as_ref(), clock(), &held) {
        Ok(AttestedImport::Imported { proven }) => {
            if !held() {
                return Outcome::NotHome;
            }
            crate::register_handle_connection_transports(
                state,
                OWNER,
                &[control::handle_connection_id(app.slug)],
            );
            if proven {
                wake_binders(state);
                Outcome::Imported
            } else {
                current()
            }
        }
        Ok(AttestedImport::AlreadyImported) => current(),
        Err(code) => match code.as_str() {
            "connector_home_not_held" => Outcome::NotHome,
            "handle_identity_conflict" => Outcome::Conflict("handle_identity_conflict"),
            "handle_import_conflict" => Outcome::Conflict("handle_import_conflict"),
            _ => retry("import_store_failed"),
        },
    }
}

fn wake_binders(state: &ModuleState) {
    state.health.agent_policy_wake.notify_one();
    state.runtime.manifest_binding_wake.notify_one();
}
