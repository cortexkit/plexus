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

pub struct FlowAudiences {
    peer: Option<Arc<SubcPrefrontalRoutePeer>>,
    cache: Mutex<HashMap<String, (Instant, Answer)>>,
    #[cfg(any(test, feature = "test-support"))]
    global_fixture: bool,
}

impl FlowAudiences {
    pub fn new(peer: Option<SubcPrefrontalRoutePeer>) -> Self {
        Self {
            peer: peer.map(Arc::new),
            cache: Mutex::new(HashMap::new()),
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

    pub fn lookup(&self, flow_id: &str) -> Result<Answer, Value> {
        let now = Instant::now();
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| unavailable("cache lock poisoned"))?;
            cache.retain(|_, (at, _)| now.duration_since(*at) < Duration::from_secs(30));
            if let Some((_, answer)) = cache.get(flow_id) {
                return Ok(answer.clone());
            }
        }
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
        if cache.len() >= 1024 {
            cache.clear();
        }
        cache.insert(flow_id.into(), (now, answer.clone()));
        Ok(answer)
    }

    pub fn for_route(
        &self,
        principal: &str,
        scope: Option<&CallScope>,
    ) -> Result<Option<Audience>, Value> {
        let Some(scope) = scope.filter(|scope| {
            principal == "reserved:basal" && scope.flow_id.is_some() && scope.agent_id.is_none()
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
    let Audience::Workspace { project_ids, .. } = audience else {
        return true;
    };
    store
        .entorhinal_repository_project(repository)
        .ok()
        .flatten()
        .is_some_and(|project| project_ids.contains(&project))
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
        manifest::GITHUB_TOOL => match args.get("op").and_then(Value::as_str) {
            Some("bot_request") => Some(
                args.get("request")
                    .and_then(|request| request.get("repository"))
                    .cloned()
                    .unwrap_or(Value::Null),
            ),
            Some("bindings.read") => return Err(excludes("<unresolved>")),
            _ => None,
        },
        manifest::INVOKE_TOOL => {
            let connection = args.get("connection").and_then(Value::as_str).unwrap_or("");
            let connection = state
                .store()
                .connection_for_invoke("reserved:basal", connection)
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
