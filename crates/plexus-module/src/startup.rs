//! Synchronous initialization, isolated from the daemon connection reader.

use super::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::sync::oneshot;

pub(super) struct Initialized {
    pub state: Arc<ModuleState>,
    timings: Option<Timings>,
}

struct Timings {
    started: Instant,
    store: std::time::Duration,
    composition: std::time::Duration,
    discovery: std::time::Duration,
    registration: std::time::Duration,
}

impl Initialized {
    #[cfg(test)]
    pub fn existing(state: Arc<ModuleState>) -> Self {
        Self {
            state,
            timings: None,
        }
    }

    pub fn log_timings(&self, dispatch_entered: Instant) {
        if let Some(t) = &self.timings {
            eprintln!(info wire:
                "startup phases: store_open_catalog_ingest_ms={} composition_ms={} principal_discovery_ms={} transport_registration_ms={} hello_to_dispatch_loop_ms={} hello_to_ready_ms={}",
                t.store.as_millis(), t.composition.as_millis(),
                t.discovery.as_millis(), t.registration.as_millis(),
                dispatch_entered.duration_since(t.started).as_millis(),
                t.started.elapsed().as_millis(),
            );
        }
    }
}

pub(super) struct Startup {
    result: oneshot::Receiver<Result<Initialized, ModuleError>>,
    cancelled: Arc<AtomicBool>,
    writer: Arc<std::sync::Mutex<Option<mpsc::Sender<Frame>>>>,
}

impl Future for Startup {
    type Output = Result<Initialized, ModuleError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.result).poll(cx).map(|result| {
            result.unwrap_or_else(|_| {
                Err(ModuleError::Message(
                    "startup worker stopped without a result".into(),
                ))
            })
        })
    }
}

impl Drop for Startup {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        self.result.close();
        if let Ok(result) = self.result.try_recv() {
            // Dropping a composed runtime can drop blocking HTTP clients. Keep
            // that cleanup off the reader, including a stop racing completion.
            tokio::task::spawn_blocking(move || drop(result));
        }
    }
}

pub(super) fn spawn(
    hello_ack: ModuleHelloAckBody,
    connection_file: PathBuf,
    health: Arc<health::HealthState>,
    writer: mpsc::Sender<Frame>,
    control_replies: Arc<PendingControlReplies>,
    compose: impl FnOnce(Arc<PlexusStore>, &Path) -> ModuleRuntime + Send + 'static,
    started: Instant,
) -> Result<Startup, ModuleError> {
    let (sender, result) = oneshot::channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let writer = Arc::new(std::sync::Mutex::new(Some(writer)));
    let worker_writer = Arc::clone(&writer);
    let runtime = tokio::runtime::Handle::current();
    // A Tokio blocking-pool task cannot be cancelled once it starts, and runtime
    // shutdown waits for it. A dedicated thread lets a stop close the daemon
    // connection without waiting for a slow store open or peer connection.
    // Cancellation is checked between phases; only the reader starts pollers.
    std::thread::Builder::new()
        .name("plexus-startup".into())
        .spawn(move || {
            let _entered = runtime.enter();
            let initialize = || {
                let check_cancelled = || {
                    if worker_cancelled.load(Ordering::Acquire) {
                        Err(ModuleError::Message("startup cancelled".into()))
                    } else {
                        Ok(())
                    }
                };
                check_cancelled()?;
                let store_started = Instant::now();
                let (store, data_directory) = initialize_store(&hello_ack)?;
                check_cancelled()?;
                if let Some(data_directory) = data_directory {
                    engram_catalog::write_best_effort(&data_directory);
                }
                ingest_catalog(&store)?;
                let store_elapsed = store_started.elapsed();
                check_cancelled()?;

                let composition_started = Instant::now();
                let runtime = compose(Arc::new(store), &connection_file);
                let composition_elapsed = composition_started.elapsed();
                check_cancelled()?;
                let state = ModuleState { health, runtime };

                let discovery_started = Instant::now();
                let principals = health_probe_principals(&state);
                let discovery_elapsed = discovery_started.elapsed();
                check_cancelled()?;
                // Endpoint configuration is process-local. Register every stored
                // principal before the scheduler can poll: an empty endpoint
                // would waste the first attempt and consume a full poll cadence.
                let registration_started = Instant::now();
                for principal in principals {
                    check_cancelled()?;
                    let registered = state.runtime.reconciler.register_transports(&principal);
                    if registered > 0 {
                        eprintln!(info transport:
                            "registered {registered} transport endpoint(s) for principal '{principal}' before scheduling"
                        );
                    }
                }
                let registration_elapsed = registration_started.elapsed();
                check_cancelled()?;
                let writer = worker_writer
                    .lock().unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_ref().cloned()
                    .ok_or_else(|| ModuleError::Message("startup cancelled".into()))?;
                let mut state = state;
                // Approval rechecks use this connection after readiness. Do not
                // hold a writer clone during slow initialization: a stop must
                // be able to close and drain the daemon connection immediately.
                state.runtime.engine = state.runtime.engine.clone().with_scope_reader(Arc::new(
                    DaemonScopeReader::new(writer, PROTOCOL_VERSION, control_replies),
                ));
                // Gauges remain absent until the scheduler's first eligible
                // refresh; optional aggregate reads are not readiness work.
                Ok(Initialized {
                    state: Arc::new(state),
                    timings: Some(Timings {
                        started, store: store_elapsed, composition: composition_elapsed,
                        discovery: discovery_elapsed, registration: registration_elapsed,
                    }),
                })
            };
            // If the reader has stopped, send returns the composed state here,
            // where its blocking clients can be safely dropped.
            let _ = sender.send(initialize());
        })
        .map_err(|error| ModuleError::Message(format!("spawn startup worker: {error}")))?;
    Ok(Startup {
        result,
        cancelled,
        writer,
    })
}

pub(super) fn is_stop_notice(frame: &Frame) -> bool {
    frame.header.channel == 0
        && frame.header.ty == FrameType::Push
        && matches!(
            serde_json::from_slice::<subc_protocol::session::ModuleControlCommand>(&frame.body),
            Ok(subc_protocol::session::ModuleControlCommand::Draining { .. })
        )
}

pub(super) async fn handle_warming_frame(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health: &health::HealthState,
) -> Result<bool, ModuleError> {
    if is_stop_notice(&frame)
        || (frame.header.channel == 0 && frame.header.ty == FrameType::Goodbye)
    {
        return Ok(false);
    }
    let (ty, body) = match frame.header.ty {
        FrameType::Ping if frame.header.channel == 0 => (FrameType::Pong, Vec::new()),
        FrameType::Request => {
            if frame.body.len() > MAX_REQUEST_BYTES {
                let response = wire::build_error_frame(
                    frame.header.ver,
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                    "invalid_request",
                    "request body exceeds the 1 MiB limit",
                )?;
                send(writer, response).await?;
                return Ok(true);
            }
            if frame.header.channel == 0 {
                match serde_json::from_slice::<ModuleControlRequest>(&frame.body) {
                    Ok(ModuleControlRequest::HealthCheck {}) => {
                        let ModuleControlResponse::HealthCheck { metrics, .. } =
                            health.report_with_transports(None)
                        else {
                            unreachable!("health report is a health.check response");
                        };
                        let mut metrics = metrics.unwrap_or_else(|| json!({}));
                        metrics["ready"] = json!(false);
                        let body = ModuleControlResponse::HealthCheck {
                            status: subc_protocol::session::HealthStatus::Degraded,
                            detail: Some(subc_protocol::error_codes::MODULE_WARMING.into()),
                            metrics: Some(metrics),
                        };
                        let response = Frame::build_with_version(
                            frame.header.ver,
                            FrameType::Response,
                            wire::control_flags(),
                            0,
                            0,
                            frame.header.corr,
                            serde_json::to_vec(&body).map_err(ModuleError::Json)?,
                        )
                        .map_err(|error| ModuleError::Message(error.to_string()))?;
                        send(writer, response).await?;
                        return Ok(true);
                    }
                    Ok(ModuleControlRequest::RouteBind { .. }) => {}
                    Err(error) => {
                        let response = wire::build_error_frame(
                            frame.header.ver,
                            0,
                            0,
                            frame.header.corr,
                            "invalid_request",
                            &format!("cannot decode control request: {error}"),
                        )?;
                        send(writer, response).await?;
                        return Ok(true);
                    }
                }
            }
            // Use the protocol's retryable code and ErrorBody, not a tool
            // result: no bind is accepted and no tool side effect has run.
            let body = ErrorBody {
                code: subc_protocol::error_codes::MODULE_WARMING.into(),
                message: "Plexus is initializing; retry shortly".into(),
                detail: Some(json!({"reason": "module_initializing"})),
            };
            (
                FrameType::Error,
                serde_json::to_vec(&body).map_err(ModuleError::Json)?,
            )
        }
        _ => return Ok(true),
    };
    let response = Frame::build_with_version(
        frame.header.ver,
        ty,
        wire::control_flags(),
        frame.header.channel,
        frame.header.epoch,
        frame.header.corr,
        body,
    )
    .map_err(|error| ModuleError::Message(error.to_string()))?;
    send(writer, response).await?;
    Ok(true)
}
