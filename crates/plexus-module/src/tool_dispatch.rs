//! Tool-frame dispatch, request execution and reply delivery.

use super::*;

pub(super) async fn handle_frame(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<bool, ModuleError> {
    if startup::is_stop_notice(&frame) {
        return Ok(false);
    }
    match frame.header.ty {
        FrameType::Ping if frame.header.channel == 0 => {
            let response = Frame::build_with_version(
                frame.header.ver,
                FrameType::Pong,
                frame.header.flags,
                0,
                0,
                frame.header.corr,
                Vec::new(),
            )
            .map_err(|error| ModuleError::Message(error.to_string()))?;
            send(writer, response).await?;
            Ok(true)
        }
        FrameType::Goodbye if frame.header.channel == 0 => Ok(false),
        FrameType::Goodbye => {
            route_bindings.remove(frame.header.channel, frame.header.epoch)?;
            Ok(true)
        }
        FrameType::Request if frame.header.channel == 0 => {
            handle_control_request(frame, writer, state, route_bindings).await?;
            Ok(true)
        }
        FrameType::Request => {
            let budget = request_execution::RequestBudget::new();
            let binding = route_bindings.binding(frame.header.channel, frame.header.epoch);
            let federated_route = matches!(&binding, Ok(Some(binding))
                if federated::is_callosum(Some(&binding.principal)));
            if !federated_route && frame.body.len() > MAX_REQUEST_BYTES {
                send_tool_error(
                    writer,
                    frame.header.ver,
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                    "invalid_request",
                    "request body exceeds the 1 MiB limit",
                )
                .await?;
                return Ok(true);
            }
            let binding = match binding {
                Ok(Some(binding)) => binding,
                Ok(None) => {
                    send_tool_error(
                        writer,
                        frame.header.ver,
                        frame.header.channel,
                        frame.header.epoch,
                        frame.header.corr,
                        "route_not_bound",
                        "plexus tools require an accepted route.bind",
                    )
                    .await?;
                    return Ok(true);
                }
                Err(error) => {
                    eprintln!(error wire: "request on channel {} epoch {} correlation {} failed before its reply was sent: {error}", frame.header.channel, frame.header.epoch, frame.header.corr);
                    send_tool_error(
                        writer,
                        frame.header.ver,
                        frame.header.channel,
                        frame.header.epoch,
                        frame.header.corr,
                        "internal_error",
                        "plexus failed while serving this request; the module log names the cause",
                    )
                    .await?;
                    return Ok(true);
                }
            };
            // Classify federated frames as soon as the binding is known, before
            // capacity, deadline, identity validation or method/tool dispatch.
            if federated_route {
                let body = (frame.body.len() <= MAX_REQUEST_BYTES)
                    .then(|| serde_json::from_slice::<Value>(&frame.body).ok())
                    .flatten();
                let object = body.as_ref().and_then(Value::as_object);
                if !object.is_some_and(federated::serves) {
                    send_tool_response(
                        writer,
                        frame.header.ver,
                        frame.header.channel,
                        frame.header.epoch,
                        frame.header.corr,
                        federated::caller_not_allowed(),
                    )
                    .await?;
                    return Ok(true);
                }
            }
            let principal_permit = binding.admission.try_acquire_owned();
            let permit = route_bindings.in_flight.clone().try_acquire_owned();
            let (Ok(permit), Ok(principal_permit)) = (permit, principal_permit) else {
                let response = Frame::build_with_version(
                    frame.header.ver, FrameType::Error, wire::control_flags(),
                    frame.header.channel, frame.header.epoch, frame.header.corr,
                    serde_json::to_vec(&remaining_tool_guard::error_frame(json!({"code":"resource_exhausted", "retryable":true,
                        "retry_after_ms":1000, "message":"Plexus request capacity is full; retry in one second."})))
                        .map_err(ModuleError::Json)?,
                ).map_err(|error| ModuleError::Message(error.to_string()))?;
                send(writer, response).await?;
                return Ok(true);
            };
            let writer = writer.clone();
            let state = Arc::clone(state);
            let route_bindings = Arc::clone(route_bindings);
            tokio::spawn(async move {
                let _permit = permit;
                let _principal_permit = principal_permit;
                let coordinates = (
                    frame.header.ver,
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                );
                let queue_deadline = tokio::time::Instant::from_std(budget.deadline)
                    .min(tokio::time::Instant::now() + std::time::Duration::from_secs(5));
                let Ok(Ok(blocking)) = tokio::time::timeout_at(
                    queue_deadline,
                    route_bindings.blocking.clone().acquire_owned(),
                )
                .await
                else {
                    let _ = send_tool_error(
                        &writer,
                        coordinates.0,
                        coordinates.1,
                        coordinates.2,
                        coordinates.3,
                        "resource_exhausted",
                        "request expired while waiting for work capacity; nothing was sent",
                    )
                    .await;
                    return;
                };
                let failure_writer = writer.clone();
                // All synchronous route/store/vendor work, including denial and
                // agent resolution, runs on the blocking pool. The async sends
                // can still await writer capacity without occupying a worker.
                let runtime = tokio::runtime::Handle::current();
                let worker_result = tokio::task::spawn_blocking(move || {
                    let _blocking = request_execution::RequestSlot::enter(
                        route_bindings.blocking.clone(),
                        blocking,
                        budget.clone(),
                    );
                    runtime.block_on(async {
                        serve_tool_request(frame, &writer, &state, &route_bindings, budget).await;
                    })
                })
                .await;
                answer_worker_failure(worker_result, coordinates, &failure_writer).await;
            });
            Ok(true)
        }
        _ => Ok(true),
    }
}

pub(super) async fn answer_worker_failure(
    result: Result<(), tokio::task::JoinError>,
    coordinates: (u8, u16, u32, u64),
    writer: &mpsc::Sender<Frame>,
) {
    if let Err(error) = result {
        eprintln!(warn wire: "request worker failed: {error}");
        if let Err(error) = send_tool_error(
            writer,
            coordinates.0,
            coordinates.1,
            coordinates.2,
            coordinates.3,
            "internal_error",
            "request worker failed; the module log names the cause",
        )
        .await
        {
            eprintln!(error wire: "could not send request worker failure: {error}");
        }
    }
}

/// Serve one route request so that it always gets an answer.
///
/// `handle_tool_request` returns `Err` only when it could not send its own
/// reply: a store or lock failure before the reply was built, or a failed
/// send. Dropped silently, the caller waits for an answer that never comes and
/// the module log has nothing. So the error is logged and the caller gets an
/// `internal_error` reply; if that send fails too (the route is gone), that is
/// logged as well.
pub(super) async fn serve_tool_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    budget: Arc<request_execution::RequestBudget>,
) {
    let version = frame.header.ver;
    let channel = frame.header.channel;
    let epoch = frame.header.epoch;
    let correlation = frame.header.corr;
    let Err(error) =
        handle_tool_request_with_budget(frame, writer, state, route_bindings, budget).await
    else {
        return;
    };
    eprintln!(error wire:
        "request on channel {channel} epoch {epoch} correlation {correlation} failed before its reply was sent: {error}"
    );
    if let Err(send_error) = send_tool_error(
        writer,
        version,
        channel,
        epoch,
        correlation,
        "internal_error",
        "plexus failed while serving this request; the module log names the cause",
    )
    .await
    {
        eprintln!(error wire:
            "could not send the internal_error reply on channel {channel} epoch {epoch} correlation {correlation}: {send_error}"
        );
    }
}

#[cfg(any(test, feature = "test-support"))]
pub(super) async fn handle_tool_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    handle_tool_request_with_budget(
        frame,
        writer,
        state,
        route_bindings,
        request_execution::RequestBudget::new(),
    )
    .await
}

pub(super) async fn handle_tool_request_with_budget(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    budget: Arc<request_execution::RequestBudget>,
) -> Result<(), ModuleError> {
    handle_tool_request_with_web_search_reader(
        frame,
        writer,
        state,
        route_bindings,
        budget,
        CORE_WEB_SEARCH_TOOL_RESULT_V1_READER_READY,
    )
    .await
}

pub(super) async fn handle_tool_request_with_web_search_reader(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    budget: Arc<request_execution::RequestBudget>,
    core_web_search_reader_ready: bool,
) -> Result<(), ModuleError> {
    handle_tool_request_with_reply_guard(
        frame,
        writer,
        state,
        route_bindings,
        budget,
        core_web_search_reader_ready,
        remaining_tool_guard::ENABLED,
    )
    .await
}

pub(super) async fn handle_tool_request_with_reply_guard(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
    budget: Arc<request_execution::RequestBudget>,
    core_web_search_reader_ready: bool,
    remaining_guard_enabled: bool,
) -> Result<(), ModuleError> {
    let channel = frame.header.channel;
    let epoch = frame.header.epoch;
    let correlation = frame.header.corr;
    if budget.expired() {
        // No bot write handler has run, so nothing was sent and the same nonce
        // remains safe to retry. Event reads also retain their retry hint.
        let expired = match serde_json::from_slice::<Value>(&frame.body)
            .ok()
            .and_then(|body| body.as_object().cloned())
        {
            Some(object) if is_bot_request_call(&object) => {
                with_bot_retry_flag(request_expired_reply())
            }
            Some(object) if is_event_get_call(&object) => {
                with_event_get_retryable(request_expired_reply())
            }
            _ => request_expired_reply(),
        };
        return send_tool_response(
            writer,
            frame.header.ver,
            channel,
            epoch,
            correlation,
            remaining_tool_guard::early(&frame, expired, remaining_guard_enabled),
        )
        .await;
    }
    // Record entry to the body handler before its validation and authority
    // gates. Saturated requests are refused earlier by handle_frame, so an
    // absent entry log can also mean admission capacity was exhausted.
    // Log only shape and wire coordinates: arguments can contain vendor data.
    eprintln!(debug wire:
        "tool frame received on channel {channel} epoch {epoch} ({} bytes)",
        frame.body.len()
    );
    if frame.body.len() > MAX_REQUEST_BYTES {
        return send_tool_error(
            writer,
            frame.header.ver,
            channel,
            epoch,
            correlation,
            "invalid_request",
            "request body exceeds the 1 MiB limit",
        )
        .await;
    }
    let value: Value = match serde_json::from_slice(&frame.body) {
        Ok(value) => value,
        Err(error) => {
            return send_tool_error(
                writer,
                frame.header.ver,
                channel,
                epoch,
                correlation,
                "invalid_request",
                &format!("request body not decodable: {error}"),
            )
            .await;
        }
    };
    let object = match value.as_object() {
        Some(object) => object,
        None => {
            return send_tool_error(
                writer,
                frame.header.ver,
                channel,
                epoch,
                correlation,
                "invalid_request",
                "tool request must be an object",
            )
            .await;
        }
    };
    // Bulk reads use the facade's identical validation and refusal rendering.
    if object.contains_key("method")
        && object.get("method").and_then(Value::as_str)
            != Some(plexus_core::github::reads::bot::BULK_METHOD)
    {
        if let Some(field) = object
            .get("params")
            .and_then(Value::as_object)
            .and_then(retired_identity_field)
        {
            return send_tool_response(
                writer,
                frame.header.ver,
                channel,
                epoch,
                correlation,
                retired_identity_refusal(field),
            )
            .await;
        }
    }
    // Management-surface calls arrive on the same route frame type as tool calls
    // but carry {method, params} rather than {name, arguments}.
    if object.get("method").and_then(Value::as_str)
        == Some(plexus_core::github::reads::bot::BULK_METHOD)
    {
        // Programmatic bulk reads reuse the facade's stamped route and all of
        // its authority checks. Keep the legacy result/error envelope for AFT's
        // gh-shim bulk-read decoder; this method is not a tool invocation.
        let reply = blocking_section(|| {
            facade_tool_reply_with_budget(&frame, object, state, route_bindings, budget)
        })?;
        return send_tool_response(
            writer,
            frame.header.ver,
            channel,
            epoch,
            correlation,
            with_call_tool_result_with_repo(Some(manifest::GITHUB_READ_TOOL), reply, None, false),
        )
        .await;
    }
    if object.get("method").and_then(Value::as_str) == Some(grants_would_ask::METHOD) {
        let reply = match route_bindings.binding(channel, epoch)? {
            Some(binding) => blocking_section(|| {
                grants_would_ask::run(
                    state,
                    &principal::principal_key(&binding.principal),
                    binding.scope.as_ref(),
                    object,
                )
            }),
            None => tool_error(
                "route_not_bound",
                "grants.would_ask requires an accepted route.bind",
            ),
        };
        return send_tool_response(writer, frame.header.ver, channel, epoch, correlation, reply)
            .await;
    }
    // permissions/v1 operations are route operations served to cingulate and
    // the local operator; `permissions::run` admits the caller.
    if let Some(method) = object
        .get("method")
        .and_then(Value::as_str)
        .filter(|method| permissions::is_method(method))
    {
        let reply = match route_bindings.binding(channel, epoch)? {
            Some(binding) => blocking_section(|| {
                permissions::run(
                    state,
                    &principal::principal_key(&binding.principal),
                    Some(&binding.mode),
                    binding.scope.as_ref(),
                    method,
                    object,
                )
            }),
            None => tool_error(
                "route_not_bound",
                "permissions operations require an accepted route.bind",
            ),
        };
        return send_tool_response(writer, frame.header.ver, channel, epoch, correlation, reply)
            .await;
    }
    if let Some(method) = object.get("method").and_then(Value::as_str) {
        let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
        return handle_management_request(
            RouteFrameContext {
                version: frame.header.ver,
                channel,
                epoch,
                correlation,
            },
            method,
            &params,
            writer,
            state,
            route_bindings,
        )
        .await;
    }
    let tool = object.get("name").and_then(Value::as_str);
    let reply = blocking_section(|| {
        facade_tool_reply_with_budget(&frame, object, state, route_bindings, budget)
    })?;
    if tool.is_some_and(tool_provider::is_metadata_op) {
        // Role metadata is not an MCP tool result: consumers decode the role's
        // answer directly, and refusals are terminal ERROR frames.
        let (kind, body) = match reply.get("error") {
            Some(error) => (FrameType::Error, error),
            None => (FrameType::Response, &reply),
        };
        let response = Frame::build_with_version(
            frame.header.ver,
            kind,
            Flags::new(false, Priority::Interactive, false),
            channel,
            epoch,
            correlation,
            serde_json::to_vec(body).map_err(ModuleError::Json)?,
        )
        .map_err(|error| ModuleError::Message(error.to_string()))?;
        return send(writer, response).await;
    }
    // GitHub programs read the facade directly. Do not duplicate it into MCP
    // fields: every copy counts toward the legacy tool's model-visible limit.
    // The bulk operation returned above deliberately keeps its old wrapper.
    let reads_tool_result_v1 = route_bindings
        .binding(channel, epoch)?
        .is_some_and(|binding| binding.reads_tool_result_v1);
    let guarded_facade =
        (remaining_guard_enabled && remaining_tool_guard::covers(tool)).then(|| reply.clone());
    // Local code-search errors keep their legacy bytes. Federated callers also
    // need the structured consent and liveness members, not only rendered text.
    let federated_code_error = if tool == Some(manifest::CODE_SEARCH_TOOL)
        && route_bindings
            .binding(channel, epoch)?
            .is_some_and(|binding| binding.federated_caller.is_some())
    {
        reply.get("error").cloned()
    } else {
        None
    };
    let federated_search_pending = matches!(
        tool,
        Some(manifest::WEB_SEARCH_TOOL | manifest::CODE_SEARCH_TOOL)
    ) && reply["error"]["code"] == "access_pending"
        && route_bindings
            .binding(channel, epoch)?
            .is_some_and(|binding| binding.federated_caller.is_some());
    let mut reply = if tool == Some(manifest::GITHUB_READ_TOOL) {
        let action = object
            .get("arguments")
            .and_then(|arguments| arguments.get("action"))
            .and_then(Value::as_str)
            .unwrap_or("");
        github_read_tool::guard(
            action,
            github_read_tool::shape_tail(action, reply),
            reads_tool_result_v1,
        )
    } else if federated_search_pending {
        // Keep the full search error envelope. The legacy access_pending branch
        // in with_call_tool_result_for_route rebuilds structuredContent and
        // omits other refusal fields.
        search_content_result(
            tool.expect("a pending federated search has a tool"),
            reply,
            None,
            if tool == Some(manifest::WEB_SEARCH_TOOL)
                && reads_tool_result_v1
                && core_web_search_reader_ready
            {
                reply_guard::EffectiveFormat::ToolResultV1
            } else {
                reply_guard::EffectiveFormat::Legacy
            },
        )
    } else {
        with_call_tool_result_for_route(
            tool,
            reply,
            object
                .get("arguments")
                .and_then(|arguments| arguments.get("repo"))
                .and_then(Value::as_str),
            reads_tool_result_v1,
            core_web_search_reader_ready,
        )
    };
    if let Some(error) = federated_code_error {
        reply["structuredContent"] = error;
    }
    let reply = match guarded_facade {
        Some(facade) => remaining_tool_guard::guard(tool, facade, reply),
        None => reply,
    };
    send_tool_response(writer, frame.header.ver, channel, epoch, correlation, reply).await
}
