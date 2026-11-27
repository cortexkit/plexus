//! Facade subscriptions, byte-paged event lists and individual event retrieval.

use super::*;

pub(super) const MAX_PROBE_SCRIPT_BYTES: usize = 64 * 1024;
const MAX_PROBE_ACTIONS: usize = 100;

pub(super) fn facade_events_register_probe(
    call: &FacadeArguments<'_>,
) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let mut missing =
            missing_string_fields(arguments, &["connection", "name", "script_source"])
                .unwrap_or_default();
        let cadence = arguments.get("cadence_s").and_then(Value::as_i64);
        if cadence.is_none_or(|value| value <= 0) {
            missing.push("cadence_s".to_string());
        }
        let actions = arguments.get("actions").and_then(Value::as_array);
        if actions.is_none() {
            missing.push("actions".to_string());
        }
        if arguments.get("return_schema").is_none() {
            missing.push("return_schema".to_string());
        }
        if arguments.get("rearm").and_then(Value::as_str).is_none() {
            missing.push("rearm".to_string());
        }
        if !missing.is_empty() {
            return Ok(json!({"error": {
                "code": "invalid_request",
                "message": format!("register_probe requires {}", missing.join(" and ")),
                "missing": missing
            }}));
        }
        let connection_id = arguments
            .get("connection")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let name = arguments
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let script_source = arguments
            .get("script_source")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if script_source.len() > MAX_PROBE_SCRIPT_BYTES
            || actions.is_some_and(|items| items.len() > MAX_PROBE_ACTIONS)
        {
            return Ok(tool_error(
                "invalid_request",
                "probe script exceeds 64 KiB or actions exceed 100",
            ));
        }
        let rearm = arguments
            .get("rearm")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let action_names = actions
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if action_names.len() != actions.map_or(0, Vec::len) {
            return Ok(json!({"error": {
                "code": "invalid_request",
                "message": "actions must contain only strings"
            }}));
        }
        let return_schema = arguments
            .get("return_schema")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let fixed_args = arguments
            .get("fixed_args")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let cursor_state = arguments
            .get("cursor_state")
            .cloned()
            .unwrap_or_else(|| json!({}));
        match state.store().register_probe(
            principal_key,
            connection_id,
            plexus_core::ProbeRegistration {
                name,
                actions: &action_names,
                script_source,
                return_schema: &return_schema,
                rearm,
                cadence_s: cadence.unwrap_or_default(),
                fixed_args: &fixed_args,
                cursor_state: &cursor_state,
            },
        ) {
            Ok(Ok(subscription)) => json!({"result": {"subscription": subscription}}),
            Ok(Err(refusal)) => json!({
                "error": {
                    "code": refusal.code(),
                    "message": refusal.to_string()
                }
            }),
            Err(error) => crate::wire::store_failure(
                "probe registered",
                "probe could not be registered",
                &error,
            ),
        }
    })
}

pub(super) fn facade_events_subscribe(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let mut missing =
            missing_string_fields(arguments, &["connection", "action"]).unwrap_or_default();
        let cadence = arguments.get("cadence_s").and_then(Value::as_i64);
        if cadence.is_none_or(|value| value <= 0) {
            missing.push("cadence_s".to_string());
        }
        let mut invalid = Vec::new();
        if arguments
            .get("fixed_args")
            .is_some_and(|value| !value.is_object())
        {
            invalid.push("fixed_args".to_string());
        }
        if !missing.is_empty() || !invalid.is_empty() {
            let mut reasons = Vec::new();
            if !missing.is_empty() {
                reasons.push(format!("requires {}", missing.join(" and ")));
            }
            if !invalid.is_empty() {
                reasons.push(format!("{} must be an object", invalid.join(" and ")));
            }
            return Ok(json!({"error": {
                "code": "invalid_request",
                "message": format!("subscribe {}", reasons.join("; ")),
                "missing": missing,
                "invalid": invalid,
                "example": {"op": "subscribe", "connection": "conn-exa", "action": "web_search_exa", "cadence_s": 300, "fixed_args": {}}
            }}));
        }
        let connection_id = arguments
            .get("connection")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let action = arguments
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let cadence_s = cadence.unwrap_or_default();
        let cursor_state = arguments
            .get("cursor_state")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let fixed_args = arguments
            .get("fixed_args")
            .cloned()
            .unwrap_or_else(|| json!({}));
        match state.store().subscribe_with_cursor_state(
            principal_key,
            connection_id,
            action,
            cadence_s,
            &cursor_state,
            &fixed_args,
        ) {
            Ok(Ok(subscription)) => json!({"result": {"subscription": subscription}}),
            Ok(Err(refusal)) => json!({
                "error": {
                    "code": refusal.code(),
                    "message": refusal.to_string()
                }
            }),
            Err(error) => crate::wire::store_failure(
                "subscription created",
                "subscription could not be created",
                &error,
            ),
        }
    })
}

pub(super) fn facade_events_resume(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(subscription_id) = subscription_id_arg(arguments) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "resume requires subscription_id"}}),
            );
        };
        match state.store().resume(principal_key, subscription_id) {
            Ok(Ok(subscription)) => json!({"result": {"subscription": subscription}}),
            Ok(Err(refusal)) => json!({
                "error": {
                    "code": refusal.code(),
                    "message": refusal.to_string()
                }
            }),
            Err(error) => crate::wire::store_failure(
                "subscription resumed",
                "subscription could not be resumed",
                &error,
            ),
        }
    })
}

/// Row-count upper bound when `events op:list` has no explicit `limit`.
/// The rendered byte budget can end a page before this many rows fit.
pub(super) const DEFAULT_EVENTS_LIST_LIMIT: usize = 500;

pub(super) fn events_list_reply_fits(reply: &Value) -> bool {
    reply_guard::EffectiveFormat::Legacy.fits(&with_call_tool_result_with_repo(
        Some(manifest::EVENTS_TOOL),
        reply.clone(),
        None,
        false,
    ))
}

pub(super) fn events_page_prefix(metadata: &Value, events: &[Value], has_more: bool) -> Value {
    let mut result = metadata["result"].as_object().unwrap().clone();
    result.insert("events".to_string(), json!(events));
    if has_more {
        let event = events.last().unwrap();
        result.insert(
            "next_after".to_string(),
            json!({
                "created_at_ms": event["created_at_ms"], "event_id": event["event_id"]
            }),
        );
    }
    json!({"result": result})
}

pub(super) fn byte_budget_events_page(store: &PlexusStore, reply: Value, has_more: bool) -> Value {
    byte_budget_events_page_with_measure(store, reply, has_more, events_list_reply_fits)
}

pub(super) fn byte_budget_events_page_with_measure(
    store: &PlexusStore,
    mut reply: Value,
    has_more: bool,
    mut fits: impl FnMut(&Value) -> bool,
) -> Value {
    let events = std::mem::take(reply["result"]["events"].as_array_mut().unwrap());
    // Subscriptions and grants are complete authority metadata, not event rows.
    // Trimming either could make a missing entry look like absent authority.
    if !fits(&reply) {
        return remaining_tool_guard::completed_fallback();
    }
    let count = events.len();
    if count == 0 {
        return reply;
    }
    // Try the full prefix first because terminal pages omit the cursor. Normal
    // generated IDs make prefix fit monotonic, so binary search avoids rendering
    // every row. Odd-length stored IDs can make the search miss a larger fit;
    // only return an actually measured prefix, so that can shorten a page but
    // never make it oversized or skip events.
    let full = events_page_prefix(&reply, &events, has_more);
    if fits(&full) {
        return full;
    }
    let (mut low, mut high) = (0, count);
    let mut retained = None;
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        let candidate = events_page_prefix(&reply, &events[..middle], true);
        if fits(&candidate) {
            low = middle;
            retained = Some(candidate);
        } else {
            high = middle;
        }
    }
    if let Some(retained) = retained {
        return retained;
    }
    // A row that cannot fit alone must still advance the cursor. Keep its
    // identity intact and disclose whether an exact outbox copy is readable.
    let mut event = events[0].clone();
    let key = match store.event_key_for_trigger_event(event["event_id"].as_str().unwrap()) {
        Ok(key) => key,
        Err(error) => {
            return crate::wire::store_failure(
                "event identity read",
                "event identity could not be read",
                &error,
            )
        }
    };
    let message = if key.is_some() {
        "Read this event with events op:get or events_get using event_key."
    } else {
        "This event's body is too large to list and has no stored outbox copy to read separately."
    };
    event.as_object_mut().unwrap().remove("payload");
    event["event_key"] = json!(key);
    event["error"] = json!({"code": "event_body_too_large", "message": message});
    let candidate = events_page_prefix(&reply, &[event], has_more || count > 1);
    if fits(&candidate) {
        candidate
    } else {
        remaining_tool_guard::completed_fallback()
    }
}

pub(super) fn facade_events_list(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let limit = match arguments.get("limit") {
            None => Some(DEFAULT_EVENTS_LIST_LIMIT),
            Some(value) => match value.as_u64().filter(|size| (1..=1000).contains(size)) {
                Some(size) => Some(size as usize),
                None => {
                    return Ok(tool_error(
                        "invalid_request",
                        "limit must be an integer from 1 to 1000",
                    ))
                }
            },
        };
        let after = match arguments.get("after") {
            None => None,
            Some(value) => match (
                value.get("created_at_ms").and_then(Value::as_i64),
                value.get("event_id").and_then(Value::as_str),
            ) {
                (Some(at), Some(id))
                    if !id.is_empty()
                        && value.as_object().is_some_and(|cursor| cursor.len() == 2) =>
                {
                    Some((at, id))
                }
                _ => {
                    return Ok(tool_error(
                        "invalid_request",
                        "after requires only created_at_ms and event_id",
                    ))
                }
            },
        };
        let connection_id = arguments.get("connection").and_then(Value::as_str);
        let subscription_id = subscription_id_arg(arguments);
        // Log the principal resolved from the route stamp so an operator can
        // distinguish a quiet feed from a consumer using the wrong identity.
        // The caller's intended identity does not establish its actual authority.
        eprintln!(info governance:
            "events list from principal '{principal_key}' (connection={}, subscription={})",
            connection_id.unwrap_or("<any>"),
            subscription_id.unwrap_or("<any>")
        );
        // This projection names every grant the caller can exercise, so a
        // principal and connection absent from `grants` has no consume grant.
        // It reveals none of another principal's authority. Keep each stored
        // grant separate: one connection can be live while another is
        // expired, and a caller-wide scalar would hide that failure.
        let now = plexus_core::now_ms();
        match (
            state.store().list_events_page_with_consume_authority(
                principal_key,
                connection_id,
                subscription_id,
                now,
                limit,
                after,
            ),
            state.store().list_subscriptions_including_granted(
                principal_key,
                connection_id,
                subscription_id,
                now,
            ),
        ) {
            (Ok((listing, has_more)), Ok(subscriptions)) => {
                let reply = json!({"result": {
                    "events": listing.events,
                    "subscriptions": subscriptions,
                    "events_consume_authority": {"grants": listing.consume_authority}
                }});
                byte_budget_events_page(state.store(), reply, has_more)
            }
            // Each failed read is logged with its cause; the reply stays
            // the same generic store_failure.
            (Err(error), _) => {
                crate::wire::store_failure("events listed", "events could not be read", &error)
            }
            (Ok(_), Err(error)) => crate::wire::store_failure(
                "subscriptions listed",
                "events could not be read",
                &error,
            ),
        }
    })
}

pub(super) fn facade_events_ack(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(event_ids) = arguments.get("event_ids").and_then(Value::as_array) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "ack requires event_ids"}}),
            );
        };
        let event_ids = event_ids
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>();
        if event_ids.len() != arguments["event_ids"].as_array().map_or(0, Vec::len) {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "event_ids must contain only strings"}}),
            );
        }
        let mut event_ids = event_ids;
        event_ids.sort();
        event_ids.dedup();
        let ack_now = plexus_core::now_ms();
        match state
            .store()
            .ack_events_including_granted(principal_key, &event_ids, ack_now)
        {
            // Report the count AND which ids did not land. A consumer acks
            // what it has delivered, so an id that acks nothing means the
            // two sides disagree about what exists: a wrong id, another
            // principal's event, or one already acked. Returning only a
            // count makes that indistinguishable from success -- the caller
            // would have to compare it against its own request length to
            // notice, and the failure is silent redelivery forever while
            // both sides report healthy.
            //
            // Not an error: a partial ack genuinely acked something, and
            // failing the whole call would make one stale id block a batch
            // of good ones. The unacked list is the actionable half.
            Ok(acked) if acked == event_ids.len() => {
                json!({"result": {"acked": acked, "unacked": []}})
            }
            Ok(acked) => partial_ack_reply(
                acked,
                state
                    .store()
                    .unacked_of_at(principal_key, &event_ids, ack_now),
            ),
            Err(error) => crate::wire::store_failure(
                "events acknowledged",
                "events could not be acknowledged",
                &error,
            ),
        }
    })
}

pub(super) fn facade_events_unsubscribe(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(subscription_id) = subscription_id_arg(arguments) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "unsubscribe requires subscription_id"}}),
            );
        };
        match state.store().unsubscribe(principal_key, subscription_id) {
            Ok(true) => json!({"result": {"unsubscribed": true}}),
            Ok(false) => {
                json!({"error": {"code": "subscription_not_found", "message": "subscription was not found"}})
            }
            Err(error) => crate::wire::store_failure(
                "subscription removed",
                "subscription could not be removed",
                &error,
            ),
        }
    })
}

pub(super) fn facade_events_set_project(call: &FacadeArguments<'_>) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(subscription_id) = subscription_id_arg(arguments) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "set_project requires subscription_id"}}),
            );
        };
        // An explicit null clears the binding. An absent `project_id` is
        // refused rather than read as a clear: otherwise a misspelled
        // field name (projectId, project) would silently wipe the binding
        // the caller meant to set. Any other value is refused for the same
        // reason.
        let project_id = match arguments.get("project_id") {
            None => {
                return Ok(json!({"error": {
                    "code": "invalid_request",
                    "message": "set_project requires project_id (a string, or null to clear)",
                    "missing": ["project_id"],
                }}));
            }
            Some(Value::Null) => None,
            Some(Value::String(project_id)) if project_id.chars().any(char::is_control) => {
                return Ok(json!({"error": {
                    "code": "invalid_request",
                    "message": "project_id must not contain control characters",
                }}));
            }
            Some(Value::String(project_id)) => Some(project_id.as_str()),
            Some(_) => {
                return Ok(json!({"error": {
                    "code": "invalid_request",
                    "message": "project_id must be a string, or null to clear",
                }}));
            }
        };
        match state
            .store()
            .set_subscription_project(principal_key, subscription_id, project_id)
        {
            Ok(true) => json!({"result": {
                "subscription_id": subscription_id,
                "project_id": project_id
            }}),
            Ok(false) => {
                json!({"error": {"code": "subscription_not_found", "message": "subscription was not found"}})
            }
            Err(error) => crate::wire::store_failure(
                "subscription project set",
                "subscription project could not be set",
                &error,
            ),
        }
    })
}

pub(super) fn facade_events_set_deliver_to(
    call: &FacadeArguments<'_>,
) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let mut missing = Vec::new();
        // Prefer `subscription_id` over its `subscription` alias, as the
        // other operations do. Calls supplying both fields must act on the
        // same subscription regardless of the operation.
        let subscription_id = subscription_id_arg(arguments).filter(|value| !value.is_empty());
        if subscription_id.is_none() {
            missing.push("subscription_id".to_string());
        }
        let deliver_to = match arguments.get("deliver_to") {
            Some(Value::Null) => Some(None),
            Some(Value::String(agent_id)) => Some(Some(agent_id.as_str())),
            Some(_) => None,
            None => {
                missing.push("deliver_to".to_string());
                None
            }
        };
        if !missing.is_empty() {
            return Ok(json!({"error": {
                "code": "invalid_request",
                "message": format!("set_deliver_to requires {}", missing.join(" and ")),
                "missing": missing,
            }}));
        }
        let Some(subscription_id) = subscription_id else {
            unreachable!("missing subscription returned above");
        };
        let Some(deliver_to) = deliver_to else {
            return Ok(json!({"error": {
                "code": "invalid_request",
                "message": "deliver_to must be a string or null",
            }}));
        };
        match deliver_to {
            Some(agent_id) => match state.runtime.agent_registry.lookup(agent_id) {
                plexus_core::AgentLookup::Known => {
                    match state.store().set_subscription_deliver_to(
                        principal_key,
                        subscription_id,
                        Some(agent_id),
                    ) {
                        Ok(true) => json!({"result": {
                            "subscription_id": subscription_id,
                            "deliver_to": agent_id,
                        }}),
                        Ok(false) => {
                            json!({"error": {"code": "subscription_not_found", "message": "subscription was not found"}})
                        }
                        Err(error) => crate::wire::store_failure(
                            "subscription delivery target set",
                            "subscription delivery target could not be set",
                            &error,
                        ),
                    }
                }
                plexus_core::AgentLookup::Unknown => json!({"error": {
                    "code": "deliver_to_unknown_agent",
                    "message": "deliver_to does not name a known agent",
                }}),
                plexus_core::AgentLookup::Retired => json!({"error": {
                    "code": "deliver_to_agent_retired",
                    "message": "deliver_to names a retired agent",
                }}),
                plexus_core::AgentLookup::Unavailable => json!({"error": {
                    "code": "agent_registry_unavailable",
                    "message": "agent registry is unavailable; retry later",
                }}),
            },
            None => match state.store().set_subscription_deliver_to(
                principal_key,
                subscription_id,
                None,
            ) {
                Ok(true) => json!({"result": {
                    "subscription_id": subscription_id,
                    "deliver_to": Value::Null,
                }}),
                Ok(false) => {
                    json!({"error": {"code": "subscription_not_found", "message": "subscription was not found"}})
                }
                Err(error) => crate::wire::store_failure(
                    "subscription delivery target cleared",
                    "subscription delivery target could not be cleared",
                    &error,
                ),
            },
        }
    })
}

pub(super) fn facade_events_set_actor_source(
    call: &FacadeArguments<'_>,
) -> Result<Value, ModuleError> {
    let state = call.state;
    let arguments = call.arguments;
    let principal_key = call.principal_key;
    Ok({
        let Some(subscription_id) = subscription_id_arg(arguments) else {
            return Ok(
                json!({"error": {"code": "invalid_request", "message": "set_actor_source requires subscription_id"}}),
            );
        };
        // An explicit null clears; a missing key is refused, matching
        // `set_project` and `set_deliver_to`, so a misspelled field cannot
        // wipe the binding. An object is decoded through the closed
        // ActorSource shape before any store write, so malformed types or
        // unknown fields cannot be persisted as a complete-looking binding.
        let actor_source = match arguments.get("actor_source") {
            None => {
                return Ok(json!({"error": {
                    "code": "invalid_request",
                    "message": "set_actor_source requires actor_source (an object, or null to clear)",
                    "missing": ["actor_source"],
                }}));
            }
            Some(Value::Null) => None,
            Some(value) => match serde_json::from_value::<ActorSource>(value.clone()) {
                Ok(source) => Some(source),
                Err(error) => {
                    return Ok(json!({"error": {
                        "code": "invalid_request",
                        "message": format!("actor_source is invalid: {}", plexus_core::text::refusal_echo(&error.to_string()))
                    }}));
                }
            },
        };
        match state.store().set_subscription_actor_source(
            principal_key,
            subscription_id,
            actor_source.as_ref(),
        ) {
            Ok(true) => json!({"result": {
                "subscription_id": subscription_id,
                "actor_source": actor_source
            }}),
            Ok(false) => {
                json!({"error": {"code": "subscription_not_found", "message": "subscription was not found"}})
            }
            Err(error) => crate::wire::store_failure(
                "subscription actor source set",
                "subscription actor source could not be set",
                &error,
            ),
        }
    })
}

fn subscription_id_arg(arguments: &serde_json::Map<String, Value>) -> Option<&str> {
    arguments
        .get("subscription_id")
        .or_else(|| arguments.get("subscription"))
        .and_then(Value::as_str)
}

/// Build the reply when a call acknowledges fewer events than it requested.
///
/// Return an error if reading the remaining unacknowledged IDs fails. An empty
/// `unacked` list would falsely claim that the call acknowledged every named
/// event. Include the count already acknowledged because those changes have
/// committed even though the follow-up read failed.
pub(super) fn partial_ack_reply<E: std::fmt::Display>(
    acked: usize,
    unacked: Result<Vec<String>, E>,
) -> Value {
    match unacked {
        Ok(unacked) => json!({"result": {"acked": acked, "unacked": unacked}}),
        Err(error) => {
            let mut reply = crate::wire::store_failure(
                "unacknowledged events read",
                "some events were acknowledged, but which ones were not could not be read; list the events to see what remains",
                &error,
            );
            reply["error"]["acked"] = json!(acked);
            reply
        }
    }
}

pub(super) fn event_get_reply(
    store: &PlexusStore,
    arguments: &serde_json::Map<String, Value>,
    principal_key: &str,
    route_scope: Option<&CallScope>,
    audience: Option<&flow_audience::Audience>,
) -> Value {
    let is_basal_flow = principal_key == principal::BASAL_PRINCIPAL
        && route_scope.is_some_and(|scope| scope.flow_id.is_some());
    let is_prefrontal = plexus_core::github::is_prefrontal(principal_key);
    if !is_basal_flow && !is_prefrontal {
        return tool_error(
            "events_get_carrier_refused",
            "events.get is restricted to reserved:basal on a flow route or reserved:prefrontal",
        );
    }
    let Some(event_key) = arguments.get("event_key").and_then(Value::as_str) else {
        return json!({
            "error": {
                "code": "invalid_request",
                "field": "event_key",
                "message": "get requires event_key",
            }
        });
    };
    if event_key.len() != 64
        || !event_key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return json!({
            "error": {
                "code": "invalid_request",
                "field": "event_key",
                "message": "event_key must be 64 lowercase hex characters",
            }
        });
    }
    let Some(event_name) = arguments.get("event_name").and_then(Value::as_str) else {
        return json!({
            "error": {
                "code": "invalid_request",
                "field": "event_name",
                "message": "get requires event_name",
            }
        });
    };
    // The source body is the default. V2 is an immutable stored envelope;
    // absent envelopes are refused without falling back to another version.
    let version = match arguments.get("version") {
        None => 1,
        Some(value) => match value.as_u64() {
            Some(version @ (1 | 2)) => version,
            _ => {
                return json!({
                    "error": {
                        "code": "invalid_request",
                        "field": "version",
                        "message": "version must be 1 or 2",
                    }
                });
            }
        },
    };

    // Who may see the event decides which reader is used:
    // - a flow run by Basal (the flow module) whose session the daemon stamped
    //   with an agent reads as that agent, so it sees only events from
    //   repositories bound to that agent's GitHub bot and items watched by
    //   that exact flow;
    // - every other caller, Prefrontal core included, reads only through its own
    //   events_consume grants, even on a route that carries an agent, so an
    //   agent's scope never widens a module's access.
    let reader = if let (Some(agent_id), Some(flow_id)) = (
        plexus_core::scope::basal_flow_read_agent(principal_key, route_scope),
        route_scope.and_then(|scope| scope.flow_id.as_deref()),
    ) {
        EventReader::AgentFlow { agent_id, flow_id }
    } else {
        EventReader::Consumer {
            principal: principal_key,
        }
    };
    match store.event_by_key_version(event_key, reader, plexus_core::now_ms(), version as u8) {
        Ok(EventLookupOutcome::Found(event)) => {
            if let Some(audience) = audience {
                match flow_audience::try_repository_allowed(store, audience, &event.headers.repo) {
                    Ok(true) => {}
                    Ok(false) => return tool_error("event_not_visible", "event not visible"),
                    Err(error) => {
                        return crate::wire::store_failure(
                            "check event repository audience",
                            "event could not be read",
                            &error,
                        );
                    }
                }
            }
            let (body, digest, published_at) = if version == 2 {
                let (Some(body), Some(digest)) = (&event.envelope_v2, &event.digest_v2) else {
                    return tool_error("event_not_visible", "event not visible");
                };
                (body, digest, event.published_v2_at_ms)
            } else {
                (&event.body, &event.digest, event.published_at_ms)
            };
            if event.event_name != event_name {
                tool_error(
                    "event_name_mismatch",
                    &format!(
                        "event_name mismatch: expected {}, got {}",
                        plexus_core::text::refusal_echo(&event.event_name),
                        plexus_core::text::refusal_echo(event_name)
                    ),
                )
            } else {
                json!({
                    "result": {
                        "body": body,
                        "digest": digest,
                        "event_key": event.event_key,
                        "event_name": event.event_name,
                        "repo": event.headers.repo,
                        "published_at": published_at,
                    }
                })
            }
        }
        Ok(EventLookupOutcome::NotFound) | Ok(EventLookupOutcome::NotVisible) => {
            tool_error("event_not_visible", "event not visible")
        }
        Err(error) => crate::wire::store_failure("read event", "event could not be read", &error),
    }
}
