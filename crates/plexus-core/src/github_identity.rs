//! Shared client for calls to prefrontal over subc. Production bot identity is
//! selected from Plexus's stored agent-to-GitHub-App bindings, not from remote
//! identity replies.

use std::sync::Arc;

use serde_json::Value;

/// Errors raised while carrying a prefrontal request over the subc route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefrontalRouteError {
    NotSent,
    Refused,
    OutcomeUnknown,
    Transport,
}

/// Narrow route seam used by the prefrontal adapter. Production code supplies
/// the subc peer; tests can exercise the operation shape without a daemon.
pub trait PrefrontalRoutePeer: Send + Sync {
    fn call(&self, operation: &str, params: Value) -> Result<Value, PrefrontalRouteError>;
}

/// Production route peer backed by the shared subc Rust client. Its long-lived
/// runtime owns the consumer's background I/O; calls hop through a helper
/// thread so this synchronous seam is safe from async module handlers.
pub struct SubcPrefrontalRoutePeer {
    consumer: Arc<subc_client_rs::SubcConsumer>,
    target: subc_protocol::RouteTarget,
    identity: subc_protocol::BindIdentity,
    runtime: Option<Arc<tokio::runtime::Runtime>>,
    /// The deadline for one whole call; the subc client's default when unset.
    call_timeout: Option<std::time::Duration>,
    call_options: Option<subc_client_rs::CallOptions>,
}

/// How one call over [`SubcPrefrontalRoutePeer`] failed.
enum RouteCallFailure {
    NotSent,
    OutcomeUnknown,
    Transport,
    /// Prefrontal answered with an error frame carrying a code.
    Module {
        code: String,
        message: String,
        detail: Option<Value>,
    },
}

impl Drop for SubcPrefrontalRoutePeer {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            if let Some(owned) = Arc::into_inner(runtime) {
                // Runtime shutdown can block, which is illegal if this source is
                // released by an async handler.
                owned.shutdown_background();
            }
        }
    }
}

impl SubcPrefrontalRoutePeer {
    /// Connect to prefrontal's management surface. `module_id` is supplied by
    /// Plexus configuration so a prefrontal rename does not require this crate
    /// to hardcode or release a replacement identifier.
    pub fn connect(
        connection_file: &std::path::Path,
        module_id: impl Into<String>,
        identity: subc_protocol::BindIdentity,
    ) -> Result<Self, PrefrontalRouteError> {
        Self::connect_target(
            connection_file,
            subc_protocol::RouteTarget::ManagementSurface {
                module_id: module_id.into(),
            },
            identity,
        )
    }

    /// Connect to an explicit route target, including an internal service.
    fn connect_target(
        connection_file: &std::path::Path,
        target: subc_protocol::RouteTarget,
        identity: subc_protocol::BindIdentity,
    ) -> Result<Self, PrefrontalRouteError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map(Arc::new)
            .map_err(|_| PrefrontalRouteError::Transport)?;
        let connection_file = connection_file.to_path_buf();
        let connected = run_on(&runtime, async move {
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                subc_client_rs::SubcConsumer::connect(
                    &connection_file,
                    subc_client_rs::ConsumerOptions::default(),
                ),
            )
            .await
            .map_err(|_| PrefrontalRouteError::NotSent)?
            .map_err(|_| PrefrontalRouteError::NotSent)
        });
        let consumer = match connected {
            Ok(consumer) => consumer,
            Err(error) => {
                if let Some(owned) = Arc::into_inner(runtime) {
                    owned.shutdown_background();
                }
                return Err(error);
            }
        };
        Ok(Self {
            runtime: Some(runtime),
            consumer: Arc::new(consumer),
            target,
            identity,
            call_timeout: None,
            call_options: None,
        })
    }

    /// Bound every call on this peer by `timeout` instead of the subc
    /// client's default.
    pub fn with_call_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.call_timeout = Some(timeout);
        self
    }

    /// Override the subc client's call options, including explicit module
    /// credentials. The daemon still checks which module is calling against
    /// the launch code it handed that module at start, so these options can't
    /// claim another module's identity.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_call_options(mut self, options: subc_client_rs::CallOptions) -> Self {
        self.call_options = Some(options);
        self
    }

    /// Preserve service refusal codes and details rather than flattening them to transport errors.
    pub fn call_service(
        &self,
        operation: &str,
        params: Value,
    ) -> Result<Value, subc_protocol::ErrorBody> {
        self.call_value(operation, params)
            .map_err(|failure| match failure {
                RouteCallFailure::Module {
                    code,
                    message,
                    detail,
                } => subc_protocol::ErrorBody {
                    code,
                    message,
                    detail,
                },
                _ => subc_protocol::ErrorBody {
                    code: "unavailable".into(),
                    message: "route unavailable or timed out".into(),
                    detail: None,
                },
            })
    }

    fn call_value(&self, operation: &str, params: Value) -> Result<Value, RouteCallFailure> {
        self.call_value_scoped(operation, params, None, self.call_timeout)
    }

    fn call_value_scoped(
        &self,
        operation: &str,
        params: Value,
        scope: Option<subc_protocol::scope::ScopeSelector>,
        timeout: Option<std::time::Duration>,
    ) -> Result<Value, RouteCallFailure> {
        // Prefrontal's management surface follows the same route envelope as
        // claustrum: management operation under `method`, arguments under
        // `params`.
        let body = serde_json::to_vec(&serde_json::json!({
            "method": operation,
            "params": params,
        }))
        .map_err(|_| RouteCallFailure::Transport)?;
        let consumer = Arc::clone(&self.consumer);
        let target = self.target.clone();
        let identity = self.identity.clone();
        let mut options = self.call_options.clone().unwrap_or_default();
        if let Some(timeout) = timeout {
            options.timeout = timeout;
        }
        let Some(runtime) = self.runtime.as_ref() else {
            return Err(RouteCallFailure::Transport);
        };

        // A route call waits on a helper thread and can release transport-owned
        // runtime state. Move that blocking wait off a Tokio worker whenever the
        // source is invoked by a module handler.
        blocking_route_call(|| {
            let bytes = run_on(runtime, async move {
                let answer = match scope {
                    Some(scope) => {
                        let deadline = tokio::time::Instant::now() + options.timeout;
                        let route = consumer
                            .open_route_scoped(target, identity, scope, options.clone())
                            .await;
                        match route {
                            Ok(route) => {
                                options.timeout =
                                    deadline.saturating_duration_since(tokio::time::Instant::now());
                                consumer.request(&route, body, options).await
                            }
                            Err(error) => Err(error),
                        }
                    }
                    None => consumer.call(target, identity, body, options).await,
                };
                Ok(answer.map_err(|error| {
                    if let Some(body) = error.route_open_refusal() {
                        return RouteCallFailure::Module {
                            code: body.code.clone(),
                            message: body.message.clone(),
                            detail: body.detail.clone(),
                        };
                    }
                    match error {
                        subc_client_rs::CallError::NotSent(_) => RouteCallFailure::NotSent,
                        subc_client_rs::CallError::Module(body) => RouteCallFailure::Module {
                            code: body.code,
                            message: body.message,
                            detail: body.detail,
                        },
                        _ => RouteCallFailure::OutcomeUnknown,
                    }
                }))
            })
            .map_err(|_| RouteCallFailure::OutcomeUnknown)??;
            serde_json::from_slice(&bytes).map_err(|_| RouteCallFailure::Transport)
        })
    }
}

fn route_error(failure: RouteCallFailure) -> PrefrontalRouteError {
    match failure {
        RouteCallFailure::NotSent => PrefrontalRouteError::NotSent,
        RouteCallFailure::Transport => PrefrontalRouteError::Transport,
        RouteCallFailure::OutcomeUnknown => PrefrontalRouteError::OutcomeUnknown,
        RouteCallFailure::Module { .. } => PrefrontalRouteError::Refused,
    }
}

impl PrefrontalRoutePeer for SubcPrefrontalRoutePeer {
    fn call(&self, operation: &str, params: Value) -> Result<Value, PrefrontalRouteError> {
        self.call_value(operation, params).map_err(route_error)
    }
}

/// Elicitation operations over the same route. Prefrontal core answers a
/// success as `{"result": value}` and a refusal as an error frame with an
/// `elicitation_*` code, which is kept so the caller can log and branch on it.
impl crate::consent_card::ElicitationRoute for SubcPrefrontalRoutePeer {
    fn call_scoped(
        &self,
        scope: &crate::scope::CallScope,
        operation: &str,
        params: Value,
        timeout: std::time::Duration,
    ) -> Result<Value, crate::consent_card::ElicitationCallError> {
        use crate::consent_card::ElicitationCallError;
        let owner =
            crate::scope::parse_scope_owner(&scope.owner).ok_or(ElicitationCallError::NotSent)?;
        let selector = subc_protocol::scope::ScopeSelector::new(
            owner,
            scope.scope_ref.clone(),
            Some(scope.scope_epoch),
        );
        match self.call_value_scoped(operation, params, Some(selector), Some(timeout)) {
            Ok(mut reply) => Ok(reply.get_mut("result").map(Value::take).unwrap_or(reply)),
            Err(RouteCallFailure::Module { code, message, .. }) => {
                Err(ElicitationCallError::Refused { code, message })
            }
            Err(RouteCallFailure::NotSent) => Err(ElicitationCallError::NotSent),
            Err(RouteCallFailure::OutcomeUnknown) => Err(ElicitationCallError::OutcomeUnknown),
            Err(RouteCallFailure::Transport) => Err(ElicitationCallError::Transport),
        }
    }
}

/// Run a blocking route wait from whatever context the caller is in. On a
/// multi-thread Tokio worker the wait moves off the worker with
/// `block_in_place`. That call panics on a current-thread runtime, which has
/// no other worker to hand its tasks to, so there the wait simply blocks the
/// calling thread: the route future itself runs on the peer's own runtime
/// (see `run_on`), so nothing it needs is stuck behind this thread.
fn blocking_route_call<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(work)
        }
        _ => work(),
    }
}

/// Run a route future on its connection-owning runtime without calling
/// `Runtime::block_on` from an async worker. The consumer's background tasks
/// stay on the runtime that created them; a bounded channel carries the result
/// back to the synchronous caller without creating another OS thread.
fn run_on<F, T>(
    runtime: &Arc<tokio::runtime::Runtime>,
    future: F,
) -> Result<T, PrefrontalRouteError>
where
    F: std::future::Future<Output = Result<T, PrefrontalRouteError>> + Send + 'static,
    T: Send + 'static,
{
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    runtime.spawn(async move {
        let _ = send.send(future.await);
    });
    receive
        .recv()
        .map_err(|_| PrefrontalRouteError::OutcomeUnknown)?
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "manual route-call scheduling measurement"]
    fn measure_route_hop() {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap(),
        );
        let start = std::time::Instant::now();
        for _ in 0..200 {
            run_on(&runtime, async { Ok(()) }).unwrap();
        }
        println!("200 real run_on hops: {:?}", start.elapsed());
        let start = std::time::Instant::now();
        for _ in 0..200 {
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            runtime.spawn(async move {
                tx.send(()).unwrap();
            });
            rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        }
        println!("200 runtime task/channel hops: {:?}", start.elapsed());
    }

    #[test]
    fn module_route_refusal_is_not_an_unknown_outcome() {
        let error = route_error(RouteCallFailure::Module {
            code: "denied".into(),
            message: "refused".into(),
            detail: None,
        });
        assert_eq!(
            format!("{error:?}"),
            "Refused",
            "a definite module refusal must not be reported as outcome unknown"
        );
    }

    use super::*;
    /// A route wait may be reached from a plain thread, a multi-thread Tokio
    /// worker or a current-thread runtime; it completes in each and never
    /// panics.
    #[test]
    fn a_blocking_route_wait_completes_on_every_runtime_flavor() {
        assert_eq!(blocking_route_call(|| 1), 1);
        let multi = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .expect("multi-thread runtime");
        // Spawned, so the wait runs on one of the runtime's worker threads.
        let on_worker = multi.block_on(async {
            tokio::spawn(async { blocking_route_call(|| 2) })
                .await
                .expect("worker task")
        });
        assert_eq!(on_worker, 2);
        let current = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime");
        assert_eq!(current.block_on(async { blocking_route_call(|| 3) }), 3);
    }
}
