//! Plexus settings, and the exchange with the daemon that declares, reviews and
//! applies them over Plexus's registered connection.

use super::*;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use subc_client_rs::config::*;
use tokio::sync::Notify;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const CATALOG_DIR_ENV: &str = "PLEXUS_CATALOG_DIR";
pub(super) const AUDIT_RETENTION_DAYS_ENV: &str = "PLEXUS_AUDIT_RETENTION_DAYS";
const MIN_RETENTION_DAYS: i64 = AUDIT_DELETE_FLOOR_DAYS + 1;
const MAX_RETENTION_DAYS: i64 = i64::MAX / AUDIT_MILLIS_PER_DAY;
const FIELDS: [(&str, ApplyKind); 2] = [
    ("/audit_retention_days", ApplyKind::Live),
    ("/catalog_dir", ApplyKind::ModuleRestart),
];

fn settings_schema() -> Value {
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "unevaluatedProperties": false,
        "properties": {
            "audit_retention_days": {
                "type": "integer",
                "description": "Days to keep audit records. The store already keeps at least 7 days, so this setting must be longer than that.",
                "default": DEFAULT_AUDIT_RETENTION_DAYS,
                "minimum": MIN_RETENTION_DAYS,
                "maximum": MAX_RETENTION_DAYS,
                "x-ck-apply": "live",
                "x-ck-layers": ["user"]
            },
            "catalog_dir": {
                "type": "string",
                "description": "Directory containing the vendor catalog. Relative paths are resolved from the Plexus data directory.",
                "default": "catalog",
                "minLength": 1,
                "x-ck-apply": "module_restart",
                "x-ck-layers": ["user"]
            }
        }
    });
    schema.sort_all_objects();
    schema
}

fn schema() -> &'static Schema {
    static SCHEMA: std::sync::OnceLock<Schema> = std::sync::OnceLock::new();
    SCHEMA.get_or_init(|| Schema::new(settings_schema()).expect("valid Plexus settings schema"))
}

fn config_declaration(
    config_home: &Path,
    module_id: &str,
) -> Result<ConfigDeclareRequest, ModuleError> {
    let path = config_home
        .join("cortexkit")
        .join(format!("{module_id}.jsonc"));
    let path = path
        .to_str()
        .filter(|_| path.is_absolute())
        .ok_or_else(|| {
            ModuleError::Message("managed settings require an absolute, UTF-8 config home".into())
        })?;
    Ok(ConfigDeclareRequest::new(settings_schema(), path, vec![]))
}

fn config_review(module_id: &str, request: ConfigReviewRequest) -> ConfigReviewReply {
    let layers = request
        .layers
        .iter()
        .filter_map(|layer| {
            layer.bytes.as_deref().map(|bytes| {
                let kind = layer.layer.known_layer().ok_or_else(|| {
                    ConfigReviewRefusal::new(
                        "layer_forbidden",
                        vec![String::new()],
                        vec!["Unknown settings layer".into()],
                    )
                })?;
                let value = std::str::from_utf8(bytes)
                    .ok()
                    .and_then(|text| subc_jsonc::jsonc_to_json(text).ok())
                    .and_then(|text| serde_json::from_str(&text).ok())
                    .ok_or_else(|| {
                        ConfigReviewRefusal::new(
                            "value_invalid",
                            vec![String::new()],
                            vec!["Settings must be valid JSONC".into()],
                        )
                    })?;
                Ok(LayerValue::new(kind, value))
            })
        })
        .collect::<Result<Vec<_>, _>>();
    let tuple = layers.and_then(|layers| {
        schema()
            .review_tuple(&layers, &ValidationContext::new(module_id, None))
            .map_err(|refusal| {
                let code = serde_json::to_value(refusal.code).expect("refusal code serializes");
                ConfigReviewRefusal::new(
                    code.as_str().expect("refusal code is a string"),
                    vec![refusal.path],
                    vec!["Value does not meet the settings schema".into()],
                )
            })
    });
    let tuple = match tuple {
        Ok(tuple) => tuple,
        Err(refusal) => return ConfigReviewReply::new(vec![], vec![refusal]),
    };
    let fields = FIELDS
        .into_iter()
        .filter_map(|(path, apply)| {
            let old = request
                .base
                .as_ref()
                .and_then(|view| view.effective.pointer(path))
                .unwrap_or(&Value::Null);
            let new = tuple
                .effective
                .pointer(path)
                .expect("declared field has a default");
            let old_source = request
                .base
                .as_ref()
                .and_then(|view| view.sources.get(path))
                .copied()
                .unwrap_or(Layer::Default);
            let new_source = tuple.sources[path];
            if old == new && old_source == new_source {
                return None;
            }
            let mut change = FieldChange::new(
                module_id,
                path,
                RecordedValue::new(old.clone()),
                RecordedValue::new(new.clone()),
                apply,
            );
            change.old_source = old_source;
            change.new_source = new_source;
            Some(change)
        })
        .collect();
    ConfigReviewReply::new(fields, vec![])
}

pub(super) fn audit_retention_window_ms(configured: Option<OsString>) -> Result<i64, ModuleError> {
    let days = match configured {
        None => DEFAULT_AUDIT_RETENTION_DAYS,
        Some(value) => {
            let text = value.to_str().ok_or_else(|| {
                ModuleError::Message(format!(
                    "{AUDIT_RETENTION_DAYS_ENV} is not valid Unicode and cannot be parsed as days"
                ))
            })?;
            text.parse::<i64>().map_err(|_| {
                ModuleError::Message(format!(
                    "{AUDIT_RETENTION_DAYS_ENV} value {text:?} cannot be parsed as whole days"
                ))
            })?
        }
    };
    if days < MIN_RETENTION_DAYS {
        return Err(ModuleError::Message(format!(
            "{AUDIT_RETENTION_DAYS_ENV} must be greater than the audit delete floor \
             (configured window: {days} days; floor: {AUDIT_DELETE_FLOOR_DAYS} days)"
        )));
    }
    days.checked_mul(AUDIT_MILLIS_PER_DAY).ok_or_else(|| {
        ModuleError::Message(format!(
            "{AUDIT_RETENTION_DAYS_ENV} value {days} days is too large"
        ))
    })
}

pub(super) struct BootSettings {
    pub catalog_dir: PathBuf,
    pub audit_window_ms: i64,
}

pub(super) fn config_files() -> Result<BootSettings, ModuleError> {
    Ok(BootSettings {
        audit_window_ms: audit_retention_window_ms(std::env::var_os(AUDIT_RETENTION_DAYS_ENV))?,
        catalog_dir: catalog_directory(std::env::var_os(CATALOG_DIR_ENV), cfg!(debug_assertions))?,
    })
}

fn config_apply(view: &ConfigView, data_dir: Option<&Path>) -> Result<BootSettings, String> {
    schema()
        .validate_layer(Layer::User, &view.effective, &ValidationContext::default())
        .map_err(|error| format!("invalid effective setting at {}", error.path))?;
    let catalog_dir = view.effective["catalog_dir"]
        .as_str()
        .ok_or("missing effective catalog_dir")?;
    let catalog_dir = Path::new(catalog_dir);
    let catalog_dir = if catalog_dir.is_absolute() {
        catalog_dir.to_path_buf()
    } else {
        data_dir
            .filter(|dir| dir.is_absolute())
            .ok_or("relative catalog_dir requires a daemon-assigned data directory")?
            .join(catalog_dir)
    };
    // The schema admits integral JSON numbers (including 30.0). Its maximum
    // is below the exact-integer limit of f64 and bounds the multiplication.
    let days = view.effective["audit_retention_days"]
        .as_f64()
        .ok_or("missing effective audit_retention_days")? as i64;
    Ok(BootSettings {
        catalog_dir,
        audit_window_ms: days * AUDIT_MILLIS_PER_DAY,
    })
}

#[derive(Clone)]
pub(super) struct AuditRetention(Arc<AtomicI64>);

impl From<i64> for AuditRetention {
    fn from(window_ms: i64) -> Self {
        Self::new(window_ms)
    }
}

impl AuditRetention {
    pub fn new(window_ms: i64) -> Self {
        Self(Arc::new(AtomicI64::new(window_ms)))
    }

    pub fn window_ms(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }

    fn apply(&self, window_ms: i64) {
        self.0.store(window_ms, Ordering::Relaxed);
    }
}

/// A config exchange shares the existing control-reply table with readiness and
/// scope reads. The main loop must keep reading while an exchange awaits a reply.
pub(super) struct ConfigConnection {
    writer: mpsc::Sender<Frame>,
    replies: Arc<PendingControlReplies>,
    version: u8,
    module_id: String,
    data_dir: Option<PathBuf>,
    changed: Notify,
}

struct ReplyWaiter<'a>(&'a PendingControlReplies, u64);

impl Drop for ReplyWaiter<'_> {
    fn drop(&mut self) {
        self.0.forget(self.1);
    }
}

impl ConfigConnection {
    pub fn from_hello(
        hello: &ModuleHelloAckBody,
        module_id: &str,
        writer: mpsc::Sender<Frame>,
        replies: Arc<PendingControlReplies>,
    ) -> Result<Option<Self>, ModuleError> {
        if !hello
            .subc_capabilities
            .iter()
            .any(|cap| cap == CONFIG_GATE_CAPABILITY)
        {
            return Ok(None);
        }
        Ok(Some(Self {
            writer,
            replies,
            version: hello.negotiated_ver,
            module_id: module_id.into(),
            data_dir: engram_catalog::data_directory(&storage_descriptor(hello)?),
            changed: Notify::new(),
        }))
    }

    async fn call(&self, op: &str, body: impl Serialize) -> Result<Value, ConfigError> {
        let body =
            serde_json::to_vec(&body).map_err(|err| ConfigError::Protocol(err.to_string()))?;
        let (corr, receiver) = self
            .replies
            .register()
            .map_err(|_| ConfigError::ConnectionClosed)?;
        let _waiter = ReplyWaiter(&self.replies, corr);
        let frame = Frame::build_with_version(
            self.version,
            FrameType::Request,
            wire::control_flags(),
            0,
            0,
            corr,
            body,
        )
        .map_err(|err| ConfigError::Protocol(err.to_string()))?;
        let reply = tokio::time::timeout(CONTROL_TIMEOUT, async {
            send(&self.writer, frame)
                .await
                .map_err(|_| ConfigError::ConnectionClosed)?;
            tokio::task::spawn_blocking(move || receiver.recv())
                .await
                .map_err(|_| ConfigError::ConnectionClosed)?
                .map_err(|_| ConfigError::ConnectionClosed)
        })
        .await
        .map_err(|_| ConfigError::Timeout)??;
        if reply.header.ty == FrameType::Error {
            let refusal = serde_json::from_slice(&reply.body)
                .map_err(|err| ConfigError::Protocol(err.to_string()))?;
            return Err(ConfigError::Refused(refusal));
        }
        let body: Value = serde_json::from_slice(&reply.body)
            .map_err(|err| ConfigError::Protocol(err.to_string()))?;
        if body.get("op").and_then(Value::as_str) != Some(op) {
            return Err(ConfigError::Protocol(format!("unexpected reply to {op}")));
        }
        Ok(body)
    }

    async fn get(&self) -> Result<ConfigGetReply, ConfigError> {
        let reply: ConfigGetReply =
            serde_json::from_value(self.call(CONFIG_GET_OP, ConfigGetRequest::new()).await?)
                .map_err(|err| ConfigError::Protocol(err.to_string()))?;
        let valid = |view: &ConfigView| {
            view.project_id.is_none()
                && view
                    .layers
                    .iter()
                    .all(|layer| layer.layer.known_layer().is_some())
        };
        if reply.active.is_none() && reply.pending.is_none()
            || reply.active.as_ref().is_some_and(|view| {
                !valid(view)
                    || !matches!(view.status, ConfigStatus::Active | ConfigStatus::Unstamped)
            })
            || reply.pending.as_ref().is_some_and(|view| {
                !valid(view) || view.status != ConfigStatus::Pending || view.attempt.is_none()
            })
        {
            return Err(ConfigError::Protocol(
                "config.get returned an invalid module view".into(),
            ));
        }
        Ok(reply)
    }

    pub async fn initial(
        &self,
    ) -> Result<(BootSettings, Option<ConfigAppliedRequest>), ModuleError> {
        let home = cortexkit_store_types::resolve_config_home();
        let declaration = config_declaration(Path::new(&home), &self.module_id)?;
        self.call(CONFIG_DECLARE_OP, declaration)
            .await
            .map_err(config_error)?;
        loop {
            let reply = match self.get().await {
                Ok(reply) => reply,
                Err(ConfigError::Refused(body))
                    if matches!(
                        body.code.as_str(),
                        "anchor_pending" | "config_gated" | "not_delivery_target"
                    ) =>
                {
                    plexus_core::diag!(warn wire: "waiting for managed settings ({})", body.code);
                    self.changed.notified().await;
                    continue;
                }
                Err(error) => return Err(config_error(error)),
            };
            if let Some(view) = &reply.pending {
                match config_apply(view, self.data_dir.as_deref()) {
                    Ok(settings) => return Ok((settings, Some(report(view, Ok(()))))),
                    Err(reason) => self
                        .submit(&report(view, Err(reason)))
                        .await
                        .map_err(config_error)?,
                }
            }
            let active = reply
                .active
                .ok_or_else(|| ModuleError::Message("no usable managed settings view".into()))?;
            let settings =
                config_apply(&active, self.data_dir.as_deref()).map_err(ModuleError::Message)?;
            return Ok((settings, None));
        }
    }

    pub async fn nack_startup(&self, mut report: ConfigAppliedRequest) {
        report.result = ConfigApplyResult::Nack;
        report.reasons = vec!["Plexus could not initialize with the delivered settings".into()];
        if let Err(error) = self.submit(&report).await {
            plexus_core::diag!(warn wire: "reporting startup configuration failure: {error}");
        }
    }

    async fn submit(&self, report: &ConfigAppliedRequest) -> Result<(), ConfigError> {
        self.call(CONFIG_APPLIED_OP, report).await?;
        Ok(())
    }

    async fn report_or_retry(&self, report: ConfigAppliedRequest) -> Option<ConfigAppliedRequest> {
        match self.submit(&report).await {
            Ok(()) => None,
            Err(error) => {
                plexus_core::diag!(warn wire: "reporting managed settings: {error}");
                // `anchor_pending` means the daemon hasn't finished recording
                // this view's approval yet. The SDK allows sending the same
                // report again on the next change notice, so keep it for then.
                matches!(&error, ConfigError::Refused(body) if body.code == "anchor_pending")
                    .then_some(report)
            }
        }
    }

    pub async fn watch(&self, mut live: LiveSettings) {
        let mut retry = match live.pending_report.take() {
            Some(report) => self.report_or_retry(report).await,
            None => None,
        };
        loop {
            self.changed.notified().await;
            if let Some(report) = retry.take() {
                retry = self.report_or_retry(report).await;
                if retry.is_some() {
                    continue;
                }
            }
            let reply = match self.get().await {
                Ok(reply) => reply,
                Err(error) => {
                    plexus_core::diag!(warn wire: "refreshing managed settings: {error}");
                    continue;
                }
            };
            let view = reply
                .pending
                .as_ref()
                .or(reply.active.as_ref())
                .expect("validated get reply has a view");
            let result = live.apply(view, self.data_dir.as_deref());
            if reply.pending.is_some() {
                retry = self.report_or_retry(report(view, result)).await;
            } else if let Err(reason) = result {
                plexus_core::diag!(warn wire: "retaining previous managed settings: {reason}");
            }
        }
    }

    pub fn handle_frame(
        &self,
        frame: &Frame,
        reviews: &mut tokio::task::JoinSet<Result<(), ModuleError>>,
    ) -> bool {
        if frame.header.channel != 0
            || !matches!(frame.header.ty, FrameType::Request | FrameType::Push)
        {
            return false;
        }
        #[derive(Deserialize)]
        struct Op<'a> {
            op: &'a str,
        }
        let Ok(op) = serde_json::from_slice::<Op<'_>>(&frame.body) else {
            return false;
        };
        match (frame.header.ty, op.op) {
            (FrameType::Push, CONFIG_CHANGED_OP) => {
                match serde_json::from_slice::<ConfigChanged>(&frame.body) {
                    Ok(hint) if hint.project_id.is_none() => self.changed.notify_one(),
                    Ok(_) => {}
                    Err(_) => {
                        plexus_core::diag!(warn wire: "ignoring malformed config.changed")
                    }
                }
                true
            }
            (FrameType::Request, CONFIG_REVIEW_OP) => {
                let writer = self.writer.clone();
                let module_id = self.module_id.clone();
                let frame = frame.clone();
                reviews.spawn(async move {
                    let (ty, body) =
                        blocking_section(|| match serde_json::from_slice(&frame.body) {
                            Ok(request) => (
                                FrameType::Response,
                                serde_json::to_vec(&config_review(&module_id, request)),
                            ),
                            Err(_) => (
                                FrameType::Error,
                                serde_json::to_vec(&ErrorBody::new(
                                    "invalid_request",
                                    "invalid config.review snapshots",
                                )),
                            ),
                        });
                    let reply = Frame::build_with_version(
                        frame.header.ver,
                        ty,
                        wire::control_flags(),
                        0,
                        0,
                        frame.header.corr,
                        body.map_err(ModuleError::Json)?,
                    )
                    .map_err(|error| ModuleError::Message(error.to_string()))?;
                    send(&writer, reply).await
                });
                true
            }
            _ => false,
        }
    }
}

pub(super) struct LiveSettings {
    pub catalog_dir: PathBuf,
    pub audit_retention: AuditRetention,
    pub pending_report: Option<ConfigAppliedRequest>,
}

impl LiveSettings {
    fn apply(&self, view: &ConfigView, data_dir: Option<&Path>) -> Result<(), String> {
        let settings = config_apply(view, data_dir)?;
        if settings.catalog_dir != self.catalog_dir {
            return Err("catalog_dir cannot change without restarting Plexus".into());
        }
        self.audit_retention.apply(settings.audit_window_ms);
        Ok(())
    }
}

fn report(view: &ConfigView, result: Result<(), String>) -> ConfigAppliedRequest {
    let (result, reasons) = match result {
        Ok(()) => (ConfigApplyResult::Ack, vec![]),
        Err(reason) => (ConfigApplyResult::Nack, vec![reason]),
    };
    ConfigAppliedRequest::new(
        view.generation,
        view.attempt.expect("validated pending view has an attempt"),
        result,
        reasons,
    )
}

fn config_error(error: ConfigError) -> ModuleError {
    ModuleError::Message(format!("managed settings: {error}"))
}

#[cfg(test)]
mod tests;
