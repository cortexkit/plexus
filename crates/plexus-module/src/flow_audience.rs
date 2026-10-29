//! Flows without an agent stamp use Basal's module grants. Core's approved
//! audience additionally limits which watched repositories those flows may use.
use super::*;
use plexus_core::github_identity::SubcPrefrontalRoutePeer;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, serde::Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Audience {
    Global,
    Workspace {
        workspace_id: String,
        project_ids: Vec<String>,
    },
    Agent {
        agent_id: String,
    },
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Answer {
    pub flow_id: String,
    pub audience: Audience,
    pub revision: String,
}

fn unavailable(cause: impl ToString) -> Value {
    json!({"error":{"code":"flow_audience_unavailable", "message":"flow audience unavailable",
        "cause":cause.to_string(), "transmission":"not_sent"}})
}

pub fn parse(flow_id: &str, reply: Value) -> Result<Answer, Value> {
    if let Some(error) = reply
        .get("error")
        .or_else(|| reply.get("code").map(|_| &reply))
    {
        if !error.is_object() {
            return Err(unavailable("malformed refusal"));
        }
        let code = error.get("code").and_then(Value::as_str).unwrap_or("");
        return Err(match code {
            "flow_unknown" | "flow_not_approved" | "flow_audience_conflict" => {
                let mut error = error.clone();
                error["transmission"] = json!("not_sent");
                json!({"error":error})
            }
            _ => unavailable(error),
        });
    }
    let answer: Answer = serde_json::from_value(reply.get("result").unwrap_or(&reply).clone())
        .map_err(|error| unavailable(format!("malformed reply: {error}")))?;
    let valid = answer.flow_id == flow_id
        && !answer.revision.is_empty()
        && match &answer.audience {
            Audience::Global => true,
            Audience::Agent { agent_id } => !agent_id.is_empty(),
            Audience::Workspace {
                workspace_id,
                project_ids,
            } => {
                !workspace_id.is_empty()
                    && !project_ids.is_empty()
                    && project_ids.iter().all(|id| !id.is_empty())
                    && project_ids.windows(2).all(|ids| ids[0] < ids[1])
            }
        };
    if !valid {
        return Err(unavailable(
            "malformed reply: invalid audience, revision or flow_id",
        ));
    }
    Ok(answer)
}

type AudienceLookup = Mutex<Option<Result<Answer, Value>>>;

pub struct FlowAudiences {
    peer: Option<Arc<SubcPrefrontalRoutePeer>>,
    cache: Mutex<HashMap<String, (Instant, Answer, Instant)>>,
    lookups: Mutex<HashMap<String, std::sync::Weak<AudienceLookup>>>,
    #[cfg(any(test, feature = "test-support"))]
    global_fixture: bool,
}

impl FlowAudiences {
    pub fn new(peer: Option<SubcPrefrontalRoutePeer>) -> Self {
        Self {
            peer: peer.map(Arc::new),
            cache: Mutex::new(HashMap::new()),
            lookups: Mutex::new(HashMap::new()),
            #[cfg(any(test, feature = "test-support"))]
            global_fixture: false,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn global_fixture() -> Self {
        Self {
            global_fixture: true,
            ..Self::new(None)
        }
    }

    fn cached(&self, flow_id: &str) -> Result<Option<Answer>, Value> {
        let now = Instant::now();
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| unavailable("cache lock poisoned"))?;
        if let Some((at, answer, used)) = cache.get_mut(flow_id) {
            if now.duration_since(*at) < Duration::from_secs(30) {
                *used = now;
                return Ok(Some(answer.clone()));
            }
        }
        cache.remove(flow_id);
        Ok(None)
    }

    pub fn lookup(&self, flow_id: &str) -> Result<Answer, Value> {
        if let Some(answer) = self.cached(flow_id)? {
            return Ok(answer);
        }
        let lookup = {
            let mut lookups = self
                .lookups
                .lock()
                .map_err(|_| unavailable("lookup lock poisoned"))?;
            lookups.retain(|_, lookup| lookup.strong_count() > 0);
            match lookups.get(flow_id).and_then(std::sync::Weak::upgrade) {
                Some(lookup) => lookup,
                None => {
                    let lookup = Arc::new(Mutex::new(None));
                    lookups.insert(flow_id.into(), Arc::downgrade(&lookup));
                    lookup
                }
            }
        };
        // Serialize only misses for this flow; unrelated flows can resolve in parallel.
        let mut result = lookup
            .lock()
            .map_err(|_| unavailable("lookup lock poisoned"))?;
        if let Some(answer) = result.as_ref() {
            return answer.clone();
        }
        let answer = match self.cached(flow_id)? {
            Some(answer) => Ok(answer),
            None => self.fetch(flow_id),
        };
        *result = Some(answer.clone());
        answer
    }

    fn fetch(&self, flow_id: &str) -> Result<Answer, Value> {
        #[cfg(any(test, feature = "test-support"))]
        if self.global_fixture {
            return parse(
                flow_id,
                json!({"flow_id":flow_id,"audience":{"kind":"global"},"revision":"fixture"}),
            );
        }
        let peer = self
            .peer
            .as_ref()
            .ok_or_else(|| unavailable("prefrontal route not configured"))?;
        // Like agent.resolve, this lookup acts as Plexus itself without borrowing
        // the flow's scope. call_service preserves ERROR-frame refusal details,
        // including the approved versions whose audiences conflict.
        let reply = peer
            .call_service("flow.audience", json!({"flow_id":flow_id}))
            .unwrap_or_else(|error| json!({"error":error}));
        let answer = parse(flow_id, reply)?;
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| unavailable("cache lock poisoned"))?;
        let now = Instant::now();
        if cache.len() >= 1024 {
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, (_, _, used))| *used)
                .map(|(key, _)| key.clone())
            {
                cache.remove(&oldest);
            }
        }
        cache.insert(flow_id.into(), (now, answer.clone(), now));
        Ok(answer)
    }

    pub fn for_route(
        &self,
        principal: &str,
        scope: Option<&CallScope>,
    ) -> Result<Option<Audience>, Value> {
        let Some(scope) = scope.filter(|scope| {
            principal == principal::BASAL_PRINCIPAL
                && scope.flow_id.is_some()
                && scope.agent_id.is_none()
        }) else {
            return Ok(None);
        };
        self.for_agentless_flow(scope.flow_id.as_deref().expect("flow scope"))
            .map(Some)
    }

    pub fn for_agentless_flow(&self, flow_id: &str) -> Result<Audience, Value> {
        let answer = self.lookup(flow_id)?;
        if matches!(answer.audience, Audience::Agent { .. }) {
            return Err(json!({"error":{"code":"flow_audience_mismatch",
                "message":"agent-audience flow requires an agent stamp", "transmission":"not_sent"}}));
        }
        Ok(answer.audience)
    }
}

pub fn repository_allowed(store: &PlexusStore, audience: &Audience, repository: &str) -> bool {
    match try_repository_allowed(store, audience, repository) {
        Ok(allowed) => allowed,
        Err(error) => {
            eprintln!(warn governance: "flow audience repository lookup failed: {error}");
            false
        }
    }
}

/// Event readers must distinguish a failed lookup from a real exclusion so a
/// transient store error does not cause the consumer to discard the event.
pub(crate) fn try_repository_allowed(
    store: &PlexusStore,
    audience: &Audience,
    repository: &str,
) -> Result<bool, cortexkit_store::StoreError> {
    let Audience::Workspace { project_ids, .. } = audience else {
        return Ok(true);
    };
    store
        .entorhinal_repository_project(repository)
        .map(|project| project.is_some_and(|project| project_ids.contains(&project)))
}

fn excludes(repository: &str) -> Value {
    json!({"error":{"code":"flow_audience_excludes_repository", "repository":repository,
        "message":"flow audience excludes repository", "transmission":"not_sent"}})
}

// The REST search catalog declares terms and q; MCP search schemas are
// discovered at runtime, so query is rejected too. Free text can contain repository
// qualifiers independent of an otherwise valid owner/repo selection.
const GITHUB_QUERY_FIELDS: &[&str] = &["query", "q", "terms"];

fn has_github_query_field(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            GITHUB_QUERY_FIELDS.contains(&key.as_str()) || has_github_query_field(value)
        }),
        Value::Array(values) => values.iter().any(has_github_query_field),
        _ => false,
    }
}

pub(crate) fn check_call(
    state: &ModuleState,
    audience: &Audience,
    name: &str,
    args: &serde_json::Map<String, Value>,
) -> Result<(), Value> {
    if !matches!(audience, Audience::Workspace { .. }) {
        return Ok(());
    }
    let github_search_read = name == manifest::GITHUB_READ_TOOL
        && args.get("action").and_then(Value::as_str) == Some("github.issue.search");
    if github_search_read && args.get("args").is_some_and(has_github_query_field) {
        return Err(excludes("<unresolved>"));
    }
    let repository = match name {
        manifest::GITHUB_READ_TOOL => Some(args.get("repository").cloned().unwrap_or(Value::Null)),
        manifest::GITHUB_REACT_TOOL => Some(args.get("repository").cloned().unwrap_or(Value::Null)),
        manifest::GITHUB_TOOL => match args.get("op").and_then(Value::as_str) {
            Some("bot_request") => Some(
                args.get("request")
                    .and_then(|request| request.get("repository"))
                    .cloned()
                    .unwrap_or(Value::Null),
            ),
            Some("bindings.read" | "bindings.read_for_agent") => {
                return Err(excludes("<unresolved>"))
            }
            _ => None,
        },
        manifest::INVOKE_TOOL => {
            let connection = args.get("connection").and_then(Value::as_str).unwrap_or("");
            let connection = state
                .store()
                .connection_for_invoke(principal::BASAL_PRINCIPAL, connection)
                .map_err(|_| unavailable("connection lookup failed"))?;
            if connection.is_some_and(|connection| {
                matches!(
                    connection.app_key.as_str(),
                    "github" | "github_actions" | "github_rest"
                )
            }) {
                let fields = args.get("args").unwrap_or(&Value::Null);
                if has_github_query_field(fields) {
                    return Err(excludes("<unresolved>"));
                }
                // Handle-backed calls use repository/repositories, ordinary REST
                // connections use owner/repo. Every supplied selector is checked.
                let mut repositories = Vec::new();
                for key in ["repository", "repositories"] {
                    if let Some(value) = fields.get(key) {
                        repositories.extend(
                            value
                                .as_array()
                                .cloned()
                                .unwrap_or_else(|| vec![value.clone()]),
                        );
                    }
                }
                if fields.get("owner").is_some() || fields.get("repo").is_some() {
                    repositories.push(match (fields["owner"].as_str(), fields["repo"].as_str()) {
                        (Some(owner), Some(repo)) => json!(format!("{owner}/{repo}")),
                        _ => Value::Null,
                    });
                }
                Some(Value::Array(repositories))
            } else {
                None
            }
        }
        // A Classic-mode route can also carry a flow stamp. Connections and
        // approval requests can reveal stored repository arguments but accept
        // no repository selector with which to narrow those results.
        manifest::CONNECTIONS_TOOL | manifest::REQUESTS_TOOL => {
            return Err(excludes("<unresolved>"));
        }
        _ => None,
    };
    if let Some(selection) = repository {
        let repositories = selection
            .as_array()
            .cloned()
            .unwrap_or_else(|| vec![selection]);
        if repositories.is_empty() {
            return Err(excludes("<unresolved>"));
        }
        for repository in repositories {
            let repository = repository.as_str().unwrap_or("<unresolved>");
            if !repository_allowed(state.store(), audience, repository) {
                return Err(excludes(repository));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "flow_audience_tests.rs"]
mod tests;

#[cfg(test)]
mod repository_lookup_tests {
    use super::*;

    async fn fetch(state: &Arc<ModuleState>, key: &str, version: u8) -> Value {
        crate::test_support::send_tool_call(
            state,
            Principal::Reserved {
                module_id: "basal".into(),
            },
            Some(CallScope {
                owner: "basal".into(),
                scope_ref: "scope-a".into(),
                scope_epoch: 1,
                kind: None,
                parent: None,
                parent_state: None,
                agent_id: None,
                flow_id: Some("flow-a".into()),
                delegates: false,
                owner_authorized: true,
            }),
            Some(CallMode::Flow),
            manifest::EVENTS_GET_TOOL,
            json!({"event_key":key,"event_name":"github_issue_changed","version":version}),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn events_get_repository_lookup_failure_is_retryable() {
        let scratch = plexus_core::test_scratch::Scratch::database("event-audience-lookup-error");
        let store = Arc::new(crate::test_support::open_file_store(scratch.path()));
        let (key, _) = crate::events_get_tests::seed_test_events(scratch.path(), &store);
        store
            .insert_grant(&plexus_core::GrantInput {
                grant_id: "basal-consume".into(),
                principal: "direct".into(),
                connection_id: "conn-github".into(),
                grantee_principal: "reserved:basal".into(),
                risk_ceiling: "read".into(),
                action_selectors: vec!["list_issues".into()],
                authority_kind: "events_consume".into(),
                expires_at: None,
            })
            .unwrap();
        let db = rusqlite::Connection::open(scratch.path()).unwrap();
        db.execute("UPDATE trigger_subscriptions SET project_id='outside',project_source='entorhinal',fixed_args='{\"owner\":\"owner\",\"repo\":\"repo\"}' WHERE subscription_id='issue-sub-1'", []).unwrap();
        let audience = Audience::Workspace {
            workspace_id: "workspace-a".into(),
            project_ids: vec!["project-a".into()],
        };
        let audiences = FlowAudiences::new(None);
        let now = Instant::now();
        audiences.cache.lock().unwrap().insert(
            "flow-a".into(),
            (
                now,
                Answer {
                    flow_id: "flow-a".into(),
                    audience: audience.clone(),
                    revision: "r1".into(),
                },
                now,
            ),
        );
        let mut runtime = runtime_for_test(store.clone());
        runtime.flow_audiences = audiences;
        let state = Arc::new(ModuleState {
            health: Arc::new(health::HealthState::new()),
            runtime,
        });

        for version in [1, 2] {
            let excluded = fetch(&state, &key, version).await;
            let unknown = fetch(&state, &"f".repeat(64), version).await;
            assert_eq!(excluded["error"]["code"], "event_not_visible");
            assert_eq!(excluded["error"]["retryable"], false);
            assert_eq!(excluded, unknown);
        }
        db.execute("UPDATE trigger_subscriptions SET project_id='project-a' WHERE subscription_id='issue-sub-1'", []).unwrap();
        for version in [1, 2] {
            assert!(fetch(&state, &key, version).await.get("result").is_some());
        }
        db.execute_batch("ALTER TABLE connections RENAME COLUMN app_key TO unavailable_app_key")
            .unwrap();
        assert!(store.entorhinal_repository_project("owner/repo").is_err());
        for version in [1, 2] {
            assert!(matches!(
                store
                    .event_by_key_version(
                        &key,
                        EventReader::Consumer {
                            principal: principal::BASAL_PRINCIPAL
                        },
                        plexus_core::now_ms(),
                        version
                    )
                    .unwrap(),
                EventLookupOutcome::Found(_)
            ));
            let reply = fetch(&state, &key, version).await;
            assert_eq!(reply["error"]["code"], "store_failure", "{reply}");
            assert_eq!(reply["error"]["retryable"], true, "{reply}");
            assert_eq!(reply["error"].as_object().unwrap().len(), 3);
            assert_eq!(reply["error"]["message"], "event could not be read");
        }
        assert!(!repository_allowed(&store, &audience, "owner/repo"));
        let refusal = check_call(
            &state,
            &audience,
            manifest::GITHUB_READ_TOOL,
            json!({"action":"github.issue.get","repository":"owner/repo","args":{}})
                .as_object()
                .unwrap(),
        )
        .unwrap_err();
        assert_eq!(
            refusal["error"]["code"],
            "flow_audience_excludes_repository"
        );
    }
}
