//! Route bindings, admission and daemon-stamped scope and relay-origin handling.

use super::*;

/// One accepted route bind: the principal the daemon stamped, and the daemon
/// scope the route was opened under when the bind carried one.
#[derive(Clone)]
pub(super) struct RouteBinding {
    pub(super) admission: Arc<tokio::sync::Semaphore>,
    pub(super) principal: Principal,
    pub(super) scope: Option<CallScope>,
    pub(super) mode: CallMode,
    /// Bind-scoped format support, not authority or a per-call option.
    pub(super) reads_tool_result_v1: bool,
    pub(super) held_reply_v1: bool,
    /// A worker scope's `on_behalf_of_agent` from the bind stamp: the agent
    /// whose bot serves the worker's GitHub bot reads. Kept beside the scope,
    /// not in it, so nothing that reads the scope's agent can mistake it for
    /// one. It chooses a bot, charges its read budget and limits reads to its
    /// repositories; it grants no write and no authority to act as the agent.
    pub(super) on_behalf_of_agent: Option<String>,
    pub(super) federated_caller: Option<plexus_core::federated::FederatedCaller>,
}

// Held approval calls live for up to 110 seconds and share this budget with
// bursty searches. Blocking jobs have a separate, smaller budget: waiting
// requests do not occupy blocking threads, and controls acquire neither permit.
pub(super) const MAX_IN_FLIGHT_REQUESTS: usize = 256;
pub(super) const MAX_BLOCKING_REQUESTS: usize = 32;
// One caller may retain a quarter of admission, leaving room for other modules.
pub(super) const MAX_PRINCIPAL_REQUESTS: usize = 64;
// A quiet route still carries authority; bound retention instead of expiring it.
pub(super) const MAX_ROUTE_BINDINGS: usize = 4096;

#[derive(Clone)]
pub struct RouteBindings {
    pub(super) control_replies: Arc<PendingControlReplies>,
    pub(super) inner: Arc<RwLock<HashMap<(u16, u32), RouteBinding>>>,
    pub(super) in_flight: Arc<tokio::sync::Semaphore>,
    pub(super) blocking: Arc<tokio::sync::Semaphore>,
    last_capacity_warning: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
    principals: Arc<std::sync::Mutex<HashMap<String, std::sync::Weak<tokio::sync::Semaphore>>>>,
}

impl Default for RouteBindings {
    fn default() -> Self {
        Self {
            control_replies: Arc::default(),
            inner: Arc::default(),
            in_flight: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT_REQUESTS)),
            blocking: Arc::new(tokio::sync::Semaphore::new(MAX_BLOCKING_REQUESTS)),
            last_capacity_warning: Arc::default(),
            principals: Arc::default(),
        }
    }
}

impl RouteBindings {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn insert_mode(
        &self,
        channel: u16,
        epoch: u32,
        principal: Principal,
        scope: Option<CallScope>,
        mode: CallMode,
    ) -> Result<(), ModuleError> {
        self.insert_bound(
            (channel, epoch),
            principal,
            scope,
            mode,
            None,
            false,
            false,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn insert_bound(
        &self,
        (channel, epoch): (u16, u32),
        principal: Principal,
        scope: Option<CallScope>,
        mode: CallMode,
        on_behalf_of_agent: Option<String>,
        reads_tool_result_v1: bool,
        held_reply_v1: bool,
        federated_caller: Option<plexus_core::federated::FederatedCaller>,
    ) -> Result<(), ModuleError> {
        let mut routes = self
            .inner
            .write()
            .map_err(|_| ModuleError::Message("route binding state was poisoned".to_string()))?;
        // The daemon's bind for a reused channel supersedes its released epoch.
        routes.retain(|(bound_channel, _), _| *bound_channel != channel);
        if routes.len() >= MAX_ROUTE_BINDINGS {
            if self.should_log_route_capacity(std::time::Instant::now()) {
                eprintln!(warn wire: "route binding capacity exhausted ({MAX_ROUTE_BINDINGS} open routes); daemon close notifications may be missing");
            }
            return Err(ModuleError::RouteCapacity);
        }
        let admission = {
            let mut principals = self.principals.lock().map_err(|_| {
                ModuleError::Message("principal capacity state was poisoned".into())
            })?;
            principals.retain(|_, semaphore| semaphore.strong_count() > 0);
            let key = principal::principal_key(&principal);
            match principals.get(&key).and_then(std::sync::Weak::upgrade) {
                Some(semaphore) => semaphore,
                None => {
                    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_PRINCIPAL_REQUESTS));
                    principals.insert(key, Arc::downgrade(&semaphore));
                    semaphore
                }
            }
        };
        routes.insert(
            (channel, epoch),
            RouteBinding {
                admission,
                principal,
                scope,
                mode,
                on_behalf_of_agent,
                reads_tool_result_v1,
                held_reply_v1,
                federated_caller,
            },
        );
        Ok(())
    }

    pub(super) fn should_log_route_capacity(&self, now: std::time::Instant) -> bool {
        let mut last = self
            .last_capacity_warning
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if last.is_some_and(|at| {
            now.saturating_duration_since(at) < std::time::Duration::from_secs(60)
        }) {
            return false;
        }
        *last = Some(now);
        true
    }

    /// The whole binding on `(channel, epoch)`: principal, daemon scope and
    /// call mode, read under one lock. A caller that needs more than the
    /// principal reads them together here, because separate reads could
    /// straddle a re-bind and pair one bind's principal with another's scope.
    pub(super) fn binding(
        &self,
        channel: u16,
        epoch: u32,
    ) -> Result<Option<RouteBinding>, ModuleError> {
        let routes = self
            .inner
            .read()
            .map_err(|_| ModuleError::Message("route binding state was poisoned".to_string()))?;
        Ok(routes.get(&(channel, epoch)).cloned())
    }

    fn clear(&self) {
        self.control_replies.clear();
        self.inner
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
    }

    pub(super) fn remove(&self, channel: u16, epoch: u32) -> Result<(), ModuleError> {
        self.inner
            .write()
            .map_err(|_| ModuleError::Message("route binding state was poisoned".into()))?
            .remove(&(channel, epoch));
        Ok(())
    }
}

/// A daemon connection owns its bindings; every loop exit invalidates the cache.
pub(super) struct ClearBindingsOnClose(pub(super) Arc<RouteBindings>);
impl Drop for ClearBindingsOnClose {
    fn drop(&mut self) {
        self.0.clear();
    }
}

pub(super) async fn handle_control_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    state: &Arc<ModuleState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    if frame.body.len() > MAX_REQUEST_BYTES {
        let response = wire::build_error_frame(
            frame.header.ver,
            0,
            0,
            frame.header.corr,
            "invalid_request",
            "control request body exceeds the 1 MiB limit",
        )?;
        return send(writer, response).await;
    }
    let request: ModuleControlRequest = match serde_json::from_slice(&frame.body) {
        Ok(request) => request,
        Err(error) => {
            if let Some(principal) = federated::unknown_claim_bind(&frame.body) {
                return send_principal_denied(
                    writer,
                    frame.header.ver,
                    frame.header.corr,
                    &principal,
                )
                .await;
            }
            eprintln!(warn wire: "refused undecodable control request: {error}");
            let response = wire::build_error_frame(
                frame.header.ver,
                0,
                0,
                frame.header.corr,
                "invalid_request",
                &format!("cannot decode control request: {error}"),
            )?;
            return send(writer, response).await;
        }
    };
    let body = match request {
        ModuleControlRequest::RouteBind {
            route_channel,
            epoch,
            principal,
            scope,
            call_mode,
            consumer_capabilities,
            ..
        } => {
            if !state
                .runtime
                .federated_admission
                .admits_scope(&principal, scope.as_ref())
            {
                return send_principal_denied(
                    writer,
                    frame.header.ver,
                    frame.header.corr,
                    &principal,
                )
                .await;
            }
            let mode = call_mode.unwrap_or_else(|| derive_call_mode(scope.as_ref()));
            if matches!(mode, CallMode::Unknown(_)) {
                let refusal = tool_provider::mode_refusal("route.bind", &mode)
                    .expect("unknown call modes are refused");
                let response = Frame::build_with_version(
                    frame.header.ver,
                    FrameType::Error,
                    wire::control_flags(),
                    0,
                    0,
                    frame.header.corr,
                    serde_json::to_vec(&refusal).map_err(ModuleError::Json)?,
                )
                .map_err(|error| ModuleError::Message(error.to_string()))?;
                return send(writer, response).await;
            }
            // Federated admission was checked against the stamp above. It does
            // not put Callosum on the first-party list.
            let bind_label = principal
                .as_ref()
                .map(principal::principal_key)
                .unwrap_or_else(|| "absent".into());
            if !federated::is_callosum(principal.as_ref())
                && !principal::trust_for_principal(&principal).is_first_party()
            {
                eprintln!(info wire:
                    "route bind from principal '{bind_label}' on channel {route_channel}: REFUSED (not first-party)"
                );
                return send_principal_denied(
                    writer,
                    frame.header.ver,
                    frame.header.corr,
                    &principal,
                )
                .await;
            }
            eprintln!(debug wire:
                "route bind from principal '{bind_label}' on channel {route_channel}: ACCEPTED"
            );
            let accepted = principal.ok_or_else(|| {
                ModuleError::Message("route admission lost principal".to_string())
            })?;
            // The daemon stamps the scope a route was opened under: the
            // session it belongs to and the agent it may act for. Plexus takes
            // that identity only from this stamp, never from a request
            // payload. A bind without a stamp behaves exactly as before.
            let on_behalf_of_agent = scope
                .as_ref()
                .and_then(|stamp| stamp.attributes.on_behalf_of_agent.clone());
            let federated_caller = scope
                .as_ref()
                .and_then(|stamp| stamp.attributes.federated.clone())
                .map(plexus_core::federated::FederatedCaller::from_attributes)
                .transpose()
                .map_err(|error| ModuleError::Message(error.to_string()))?;
            let scope = scope.as_ref().map(CallScope::from_stamp);
            // One line per scoped bind is per-call routing detail, like the
            // unscoped ACCEPTED line above, so it logs at debug: core now opens
            // every worker preflight and tool route under a scope, which made
            // this the most frequent line in the log.
            if let Some(scope) = &scope {
                eprintln!(debug wire:
                    "route bind on channel {route_channel} is under scope {}/{}@{} (agent {}, delegates {}, owner authorized {})",
                    scope.owner,
                    scope.scope_ref,
                    scope.scope_epoch,
                    scope.agent_id.as_deref().unwrap_or("none"),
                    scope.delegates,
                    scope.owner_authorized
                );
            }
            match route_bindings.insert_bound(
                (route_channel, epoch),
                accepted,
                scope,
                mode,
                on_behalf_of_agent,
                cortexkit_role_tool_provider::consumer_reads_tool_result_v1(
                    consumer_capabilities.as_deref(),
                ),
                consumer_capabilities
                    .as_deref()
                    .is_some_and(|caps| caps.iter().any(|cap| cap == "held-reply/v1")),
                federated_caller,
            ) {
                Ok(()) => {}
                Err(ModuleError::RouteCapacity) => {
                    let response = wire::build_error_frame(
                        frame.header.ver,
                        0,
                        0,
                        frame.header.corr,
                        "resource_exhausted",
                        "route binding capacity exhausted",
                    )?;
                    return send(writer, response).await;
                }
                Err(error) => return Err(error),
            }
            ModuleControlResponse::RouteBindAck {}
        }
        ModuleControlRequest::HealthCheck {} => {
            // The supervisor gives this inline dispatch-loop handler five
            // seconds to answer. A probe makes sequential blocking vendor calls
            // across every connection, so it runs on the scheduler task and this
            // path reports the last observed state instead.
            connector_home_health(state)
        }
    };
    let body = serde_json::to_vec(&body).map_err(ModuleError::Json)?;
    let response = Frame::build_with_version(
        frame.header.ver,
        FrameType::Response,
        wire::control_flags(),
        0,
        0,
        frame.header.corr,
        body,
    )
    .map_err(|error| ModuleError::Message(error.to_string()))?;
    send(writer, response).await
}

pub(super) async fn send_principal_denied(
    writer: &mpsc::Sender<Frame>,
    version: u8,
    correlation: u64,
    principal: &Option<Principal>,
) -> Result<(), ModuleError> {
    let label = principal
        .as_ref()
        .map(principal::principal_key)
        .unwrap_or_else(|| "absent".to_string());
    let frame = wire::build_error_frame(
        version,
        0,
        0,
        correlation,
        "principal_denied",
        &format!(
            "plexus connector tools are first-party only; principal '{label}' is not eligible"
        ),
    )?;
    send(writer, frame).await
}

/// Where a route frame came from: the wire coordinates every response must echo.
#[derive(Debug, Clone, Copy)]
pub(super) struct RouteFrameContext {
    pub(super) version: u8,
    pub(super) channel: u16,
    pub(super) epoch: u32,
    pub(super) correlation: u64,
}

/// Why a tool request's `call_key` member is refused, or `None` when it is
/// absent, `null`, or a string the protocol's validator accepts.
pub(super) fn call_key_refusal(call_key: Option<&Value>) -> Option<String> {
    match call_key {
        None | Some(Value::Null) => None,
        Some(Value::String(key)) => validate_call_key(key).err().map(|error| error.to_string()),
        Some(_) => Some(format!("{CALL_KEY_FIELD} must be a string")),
    }
}

/// The top-level tool-call member naming the call a relayed call came from:
/// `{"carrier": <principal>, "call_key": <that carrier's key>}`.
const ORIGIN_FIELD: &str = "origin";
const ORIGIN_CARRIER_FIELD: &str = "origin.carrier";
const ORIGIN_CALL_KEY_FIELD: &str = "origin.call_key";

/// Why a tool request's `origin` was refused: the field to name, and a
/// message that describes the fault without repeating the value.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct OriginRefusal {
    pub(super) field: &'static str,
    pub(super) message: String,
}

impl OriginRefusal {
    fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }
}

/// Read and check a tool request's top-level `origin`: absent or `null` is
/// no origin; otherwise it must be an object with `carrier`, a
/// subc-protocol [`Principal`] object such as
/// `{"kind": "reserved", "module_id": "broca"}`, and `call_key`, a string the
/// protocol's call-key validator accepts, plus the protocol's optional
/// `message_position`, which is checked and ignored. The carrier is returned in the
/// stored principal form (`reserved:broca`), the same form as the carrier
/// principal every record is keyed on.
///
/// A relay always keys the call it sends on, so an `origin` without a
/// top-level `call_key` is refused too. The shape of that `call_key` is
/// checked separately, before this runs.
///
/// Parsed from the raw request rather than through subc-protocol's typed
/// `ToolCallRequest.origin` (added in 0.28), so each malformed shape keeps
/// its own named refusal code instead of one generic decode error. All of
/// the parsing lives in this one function, so adopting the typed
/// field later replaces only this function.
pub(super) fn relay_origin_of(
    object: &serde_json::Map<String, Value>,
) -> Result<Option<plexus_core::RelayOrigin>, OriginRefusal> {
    let origin = match object.get(ORIGIN_FIELD) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Object(origin)) => origin,
        Some(_) => {
            return Err(OriginRefusal::new(
                ORIGIN_FIELD,
                "origin must be an object with carrier and call_key",
            ))
        }
    };
    if origin
        .keys()
        .any(|member| !matches!(member.as_str(), "carrier" | "call_key" | "message_position"))
    {
        return Err(OriginRefusal::new(
            ORIGIN_FIELD,
            "origin must have only the members carrier, call_key and message_position",
        ));
    }
    // The protocol's optional position of the call within the model message.
    // Plexus orders nothing by it, so it is checked for shape and then ignored;
    // a forwarder can send one origin shape to every module.
    if let Some(position) = origin.get("message_position") {
        let valid =
            serde_json::from_value::<subc_protocol::tool_call::MessagePosition>(position.clone())
                .ok()
                .is_some_and(|position| validate_call_key(&position.message_id).is_ok());
        if !valid {
            return Err(OriginRefusal::new(
                subc_protocol::tool_call::ORIGIN_MESSAGE_ID_FIELD,
                "origin.message_position must be {message_id, index} with a valid message_id",
            ));
        }
    }
    let carrier = origin
        .get("carrier")
        .and_then(|carrier| serde_json::from_value::<Principal>(carrier.clone()).ok())
        .map(|carrier| principal::principal_key(&carrier))
        .ok_or_else(|| {
            OriginRefusal::new(
                ORIGIN_CARRIER_FIELD,
                "origin.carrier must be a principal object",
            )
        })?;
    // The stored form is an identifier like every other key column: non-empty
    // printable ASCII, at most 256 bytes. A reserved principal's module id
    // could otherwise carry anything.
    if carrier.is_empty()
        || carrier.len() > 256
        || !carrier.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(OriginRefusal::new(
            ORIGIN_CARRIER_FIELD,
            "origin.carrier must name a principal in printable ASCII of at most 256 bytes",
        ));
    }
    let call_key = match origin.get("call_key") {
        Some(Value::String(call_key)) => match validate_call_key(call_key) {
            Ok(()) => call_key.clone(),
            // The validator's message names `call_key` and states the fault
            // (empty, length, or the index of a bad byte), never the value.
            Err(error) => {
                return Err(OriginRefusal::new(
                    ORIGIN_CALL_KEY_FIELD,
                    format!("{ORIGIN_FIELD}.{error}"),
                ))
            }
        },
        _ => {
            return Err(OriginRefusal::new(
                ORIGIN_CALL_KEY_FIELD,
                "origin.call_key must be a string",
            ))
        }
    };
    if !matches!(object.get(CALL_KEY_FIELD), Some(Value::String(_))) {
        return Err(OriginRefusal::new(
            ORIGIN_FIELD,
            "origin requires a top-level call_key",
        ));
    }
    Ok(Some(plexus_core::RelayOrigin { carrier, call_key }))
}
