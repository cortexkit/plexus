//! Module entry, daemon handshake, frame-reading loop and egress writer.

use super::*;
use settings::{AuditRetention, BootSettings, ConfigConnection, LiveSettings};

pub(super) const HELLO_CORRELATION: u64 = 1;
const EGRESS_BUFFER: usize = 64;
/// Refresh the diagnostic heartbeat age even while the dispatcher is idle.
const IDLE_HEARTBEAT_WAKE: std::time::Duration = std::time::Duration::from_millis(1_000);

pub(super) struct ModuleConfig {
    pub(super) connection_file_path: PathBuf,
    pub(super) module_id: String,
    pub(super) registration_channel: bool,
}

impl ModuleConfig {
    pub(super) fn from_env() -> Result<Self, ModuleError> {
        let connection_file_path = parse_subc_arg(std::env::args_os().skip(1))?;
        let module_id = std::env::var(SUBC_MODULE_ID_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_MODULE_ID.to_string());
        Ok(Self {
            connection_file_path,
            module_id,
            registration_channel: false,
        })
    }
}

/// The build identity `ck-plexus --version` prints: crate version, the commit
/// the binary was built from and its lock digest, the same values health
/// reports as `buildCommit` and `lockDigest`.
pub fn version_line() -> String {
    format!(
        "ck-plexus {} (commit {}, lock {})",
        env!("CARGO_PKG_VERSION"),
        env!("PLEXUS_BUILD_COMMIT"),
        env!("PLEXUS_LOCK_DIGEST")
    )
}

/// The JSON `ck-plexus --manifest` prints: the manifest this module registers,
/// including its `provenance` object. Under a supervisor the module id comes
/// from `SUBC_MODULE_ID`; a placement check runs without one and gets the
/// default id.
pub fn printed_manifest() -> String {
    let module_id = std::env::var(SUBC_MODULE_ID_ENV)
        .ok()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| DEFAULT_MODULE_ID.to_string());
    serde_json::to_string(&manifest::build(&module_id)).expect("module manifest serializes")
}

/// Binary entry point used by `ck-plexus`.
pub async fn run_entry() -> Result<(), ModuleError> {
    // Placement scripts check a staged binary before the supervisor launches
    // it, where there is no module id, launch nonce or connection file. The
    // version answer must not depend on any of them, so it is handled before
    // the logger and the module config read their environment.
    // `args_os`, not `args`: `args` panics on an argument that is not UTF-8,
    // which would turn a bad command line into a crash with no usable message.
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--version") {
        println!("{}", version_line());
        return Ok(());
    }
    // SUBC's placement gate runs a staged binary with only `--manifest`, with
    // no daemon, store, network or stdin and a short alarm, and reads the
    // build provenance from the printed JSON. It is the manifest this module
    // registers, so it is answered here, before anything reads the supervisor
    // environment or opens a store.
    if args.first().is_some_and(|arg| arg == "--manifest") {
        if args.len() != 1 {
            std::eprintln!("usage: ck-plexus --manifest");
            std::process::exit(2);
        }
        println!("{}", printed_manifest());
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "--check-catalog") {
        if args.len() != 2 {
            std::eprintln!("usage: ck-plexus --check-catalog <dir>");
            std::process::exit(2);
        }
        std::process::exit(check_catalog(Path::new(&args[1])));
    }
    // Staging and post-placement checks run `--smoke-probe` on a freshly
    // signed file with no supervisor, so, like `--version`, it is answered
    // before the logger and module config read any supervisor environment.
    if args.first().is_some_and(|arg| arg == "--smoke-probe") {
        if args.len() != 1 {
            std::eprintln!("usage: ck-plexus --smoke-probe");
            std::process::exit(2);
        }
        // Inside `blocking_section`, like the scheduler's real probe runs: the
        // sandbox's synchronous WASI layer drives tokio itself, which panics
        // on an async worker thread.
        match blocking_section(smoke::smoke_probe) {
            Ok(line) => {
                println!("{line}");
                return Ok(());
            }
            Err(reason) => {
                std::eprintln!("ck-plexus smoke-probe FAILED: {reason}");
                std::process::exit(1);
            }
        }
    }
    if args
        .first()
        .is_some_and(|arg| arg == "--help" || arg == "-h")
    {
        println!("usage: ck-plexus [--version | --help | --manifest | --check-catalog <dir> | --smoke-probe]\n\n  --manifest             Print the module manifest with its build provenance as JSON, without supervisor, store or network access\n  --check-catalog <dir>  Validate catalog manifests without supervisor, store or network access\n                        Exit 0: all ok; 1: refused manifest; 2: usage or I/O error\n  --smoke-probe          Run one guest through the probe sandbox without supervisor, store or network access\n                        Exit 0: the guest ran and answered correctly; 1: it did not; 2: usage error");
        return Ok(());
    }
    // Only the executable owns the subscriber; library hosts install their own.
    let _logger = crate::bus::init_logger_from_env()
        .map_err(|error| ModuleError::Message(format!("initializing fleet logger: {error}")))?;
    let config = ModuleConfig::from_env()?;
    run(config).await
}

pub(super) async fn run(mut config: ModuleConfig) -> Result<(), ModuleError> {
    let channel = subc_client_rs::registration::adopt_channel()
        .map_err(|error| ModuleError::Message(format!("adopt registration channel: {error}")))?;
    config.registration_channel = channel.is_some();
    let stream: Box<dyn subc_client_rs::ModuleStream> = if let Some(mut channel) = channel {
        let connection = connection_file::read(&config.connection_file_path)
            .map_err(|error| ModuleError::Message(format!("reading connection file: {error}")))?;
        authenticate_client(&mut channel, &connection, std::time::Duration::from_secs(5))
            .await
            .map_err(|error| {
                ModuleError::Message(format!("authenticate registration channel: {error}"))
            })?;
        channel
    } else {
        Box::new(connect_to_subc(&config.connection_file_path).await?)
    };
    let (mut reader, writer_half) = tokio::io::split(stream);
    let (writer, receiver) = mpsc::channel::<Frame>(EGRESS_BUFFER);
    let writer_task = tokio::spawn(drain_writer(writer_half, receiver));
    let health = Arc::new(health::HealthState::new().with_poller_credential_repair());
    let route_bindings = Arc::new(RouteBindings::new());
    let loop_result =
        module_loop(&mut reader, writer.clone(), &config, health, route_bindings).await;
    drop(writer);

    let writer_result = writer_task
        .await
        .map_err(|error| ModuleError::Message(error.to_string()))?;
    match (loop_result, writer_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) => Err(error),
    }
}

async fn connect_to_subc(connection_file_path: &Path) -> Result<TcpStream, ModuleError> {
    let connection = connection_file::read(connection_file_path)
        .map_err(|error| ModuleError::Message(format!("reading connection file: {error}")))?;
    let endpoint = connection
        .endpoints
        .first()
        .ok_or_else(|| ModuleError::Message("connection file has no endpoints".to_string()))?;
    let address = format!("{}:{}", endpoint.host, endpoint.port);
    let mut stream = TcpStream::connect(&address)
        .await
        .map_err(|error| ModuleError::Message(format!("connect {address}: {error}")))?;
    authenticate_client(&mut stream, &connection, std::time::Duration::from_secs(5))
        .await
        .map_err(|error| ModuleError::Message(format!("authenticate: {error}")))?;
    Ok(stream)
}

async fn module_loop<R>(
    reader: &mut R,
    writer: mpsc::Sender<Frame>,
    config: &ModuleConfig,
    health: Arc<health::HealthState>,
    route_bindings: Arc<RouteBindings>,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
{
    module_loop_with_composition(
        reader,
        writer,
        config,
        health,
        route_bindings,
        ModuleRuntime::production,
    )
    .await
}

pub(super) async fn module_loop_with_composition<R>(
    reader: &mut R,
    writer: mpsc::Sender<Frame>,
    config: &ModuleConfig,
    health: Arc<health::HealthState>,
    route_bindings: Arc<RouteBindings>,
    compose: impl FnOnce(Arc<PlexusStore>, &Path) -> ModuleRuntime + Send + 'static,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
{
    let startup_started = std::time::Instant::now();
    let provides = send_hello(&writer, config).await?;
    let hello_ack = expect_hello_ack(reader).await?;
    let negotiated_ver = hello_ack.negotiated_ver;
    let control_replies = Arc::clone(&route_bindings.control_replies);
    let _registration = if config.registration_channel {
        Some(registration::install(
            &writer,
            negotiated_ver,
            Arc::clone(&control_replies),
        )?)
    } else {
        None
    };
    let managed = ConfigConnection::from_hello(
        &hello_ack,
        &config.module_id,
        writer.clone(),
        Arc::clone(&control_replies),
    )?;
    let managed = managed.as_ref();
    let ready_writer = writer.clone();
    let ready_replies = Arc::clone(&control_replies);
    let startup_health = Arc::clone(&health);
    let startup = async move {
        let (
            BootSettings {
                catalog_dir,
                audit_window_ms,
            },
            pending_report,
        ) = match managed {
            Some(managed) => managed.initial().await?,
            None => (settings::config_files()?, None),
        };
        let initialized = async {
            let initialized = startup::spawn(
                hello_ack,
                config.connection_file_path.clone(),
                startup_health,
                ready_writer.clone(),
                Arc::clone(&ready_replies),
                compose,
                (startup_started, catalog_dir.clone()),
            )?
            .await?;
            startup::finish(
                initialized,
                &ready_writer,
                negotiated_ver,
                provides,
                ready_replies,
            )
            .await
        }
        .await;
        match initialized {
            Ok(initialized) => Ok((
                initialized,
                Some(LiveSettings {
                    catalog_dir,
                    audit_retention: AuditRetention::new(audit_window_ms),
                    pending_report,
                }),
            )),
            Err(error) => {
                if let (Some(managed), Some(report)) = (managed, pending_report) {
                    managed.nack_startup(report).await;
                }
                Err(error)
            }
        }
    };
    dispatch_loop_starting(
        reader,
        writer,
        health,
        route_bindings,
        control_replies,
        startup,
        Some(DispatchSettings {
            connection_file: &config.connection_file_path,
            managed,
        }),
    )
    .await
}

/// The frame-handling loop: read a frame (with an idle heartbeat wake), dispatch
/// it, repeat until the peer closes the route or says goodbye.
#[cfg(test)]
pub(super) async fn dispatch_loop<R>(
    reader: &mut R,
    writer: mpsc::Sender<Frame>,
    state: Arc<ModuleState>,
    route_bindings: Arc<RouteBindings>,
    control_replies: Arc<PendingControlReplies>,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
{
    dispatch_loop_starting(
        reader,
        writer,
        Arc::clone(&state.health),
        route_bindings,
        control_replies,
        std::future::ready(Ok((startup::Initialized::existing(state), None))),
        None,
    )
    .await
}

struct DispatchSettings<'a> {
    connection_file: &'a Path,
    managed: Option<&'a ConfigConnection>,
}

async fn dispatch_loop_starting<R>(
    reader: &mut R,
    writer: mpsc::Sender<Frame>,
    health: Arc<health::HealthState>,
    route_bindings: Arc<RouteBindings>,
    control_replies: Arc<PendingControlReplies>,
    startup: impl std::future::Future<
        Output = Result<(startup::Initialized, Option<LiveSettings>), ModuleError>,
    >,
    settings: Option<DispatchSettings<'_>>,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
{
    let dispatch_entered = std::time::Instant::now();
    let _clear_on_exit = ClearBindingsOnClose(route_bindings.clone());
    let mut startup = std::pin::pin!(startup);
    let managed = settings.as_ref().and_then(|settings| settings.managed);
    let mut reviews = tokio::task::JoinSet::new();
    let mut watch = None;
    let mut state = None;
    let mut background = None;
    let result = async {
      loop {
        // Keep the diagnostic heartbeat age fresh while idle.
        //
        // The read future is pinned and polled through select! rather than
        // wrapped in `timeout()`: a timeout would DROP the future on expiry,
        // corrupting the stream if it fired while a frame was mid-read
        // (read_exact is not cancellation-safe). Re-polling the same pinned
        // future preserves partial-read state across idle wakes.
        health.stamp_heartbeat();
        let read = std::pin::pin!(read_frame(reader));
        let mut read = read;
        let frame = loop {
            let mut idle_wake = std::pin::pin!(tokio::time::sleep(IDLE_HEARTBEAT_WAKE));
            tokio::select! {
                biased;
                result = &mut startup, if state.is_none() => {
                    let (initialized, live) = result?;
                    initialized.log_timings(dispatch_entered);
                    // The registered connection's startup future includes the
                    // readiness ACK. Until then health and stray requests use
                    // the same local warming gate, even after initialization.
                    if let (Some(settings), Some(live)) = (&settings, live) {
                        background = Some(spawn_background_tasks(
                            Arc::clone(&initialized.state), settings.connection_file, live.audit_retention.clone(),
                        ));
                        watch = managed.map(|managed| Box::pin(managed.watch(live)));
                    }
                    state = Some(initialized.state);
                }
                () = async {
                    match watch.as_mut() {
                        Some(watch) => watch.await,
                        None => std::future::pending().await,
                    }
                } => { watch = None; }
                Some(result) = reviews.join_next(), if !reviews.is_empty() => {
                    result.map_err(|error| ModuleError::Message(error.to_string()))??;
                }
                result = &mut read => {
                    let Some(frame) =
                        result.map_err(|error| ModuleError::Message(error.to_string()))?
                    else {
                        return Ok(());
                    };
                    break frame;
                }
                _ = &mut idle_wake => {
                    health.stamp_heartbeat();
                }
            }
        };
        // Replies to module-originated controls, including operator confirmation,
        // wake only the caller waiting on their correlation id.
        if frame.header.channel == 0
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
        {
            if !control_replies.complete(frame) {
                eprintln!(warn wire: "unmatched control reply (late, duplicate or unknown correlation)");
            }
            continue;
        }
        if managed.is_some_and(|managed| managed.handle_frame(&frame, &mut reviews)) {
            continue;
        }
        let keep_reading = match &state {
            Some(state) => handle_frame(frame, &writer, state, &route_bindings).await?,
            None => startup::handle_warming_frame(frame, &writer, &health).await?,
        };
        if !keep_reading {
            return Ok(());
        }
      }
    }.await;
    drop(reviews);
    if let Some(background) = background {
        background.stop().await;
    }
    result
}

pub(super) async fn drain_writer<W>(
    writer_half: W,
    mut receiver: mpsc::Receiver<Frame>,
) -> Result<(), ModuleError>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = BufWriter::new(writer_half);
    while let Some(frame) = receiver.recv().await {
        write_frame(&mut writer, &frame)
            .await
            .map_err(|error| ModuleError::Message(error.to_string()))?;
        while let Ok(frame) = receiver.try_recv() {
            write_frame(&mut writer, &frame)
                .await
                .map_err(|error| ModuleError::Message(error.to_string()))?;
        }
        writer
            .flush()
            .await
            .map_err(|error| ModuleError::Message(error.to_string()))?;
    }
    writer
        .flush()
        .await
        .map_err(|error| ModuleError::Message(error.to_string()))?;
    Ok(())
}

pub(super) async fn send_hello(
    writer: &mpsc::Sender<Frame>,
    config: &ModuleConfig,
) -> Result<Vec<subc_protocol::manifest::ProviderRole>, ModuleError> {
    // A channel HELLO authenticates the inherited connection itself. Only the
    // legacy connection reads the cached nonce accessor: consuming its pipe
    // directly would leave the SDK's later outbound route binds without it.
    // An unreadable nonce descriptor stops legacy startup rather than sending
    // an unattested HELLO that conceals the descriptor failure.
    let launch_nonce = if config.registration_channel {
        None
    } else {
        subc_os::launch_nonce().map_err(launch_nonce_refused)?
    };
    // When registration_channel is not enabled in the daemon configuration,
    // the supervisor may hand over both a channel and a legacy launch nonce.
    // As in the SDK serving loop, retain only its source as provenance on the
    // channel path; the nonce itself never enters that HELLO.
    let launch_nonce_source = if config.registration_channel {
        subc_client_rs::launch_nonce_source()
    } else {
        launch_nonce.as_ref().map(|nonce| {
            subc_protocol::manifest::LaunchNonceSource::from_wire_name(nonce.source().as_str())
        })
    };
    let mut manifest =
        manifest::build_with_launch_nonce_source(&config.module_id, launch_nonce_source);
    manifest.ready = Some(false);
    let provides = manifest.provides.clone();
    let hello = ModuleHelloBody {
        manifest,
        protocol_ver: PROTOCOL_VERSION,
        control_ops: Some(vec![
            "route.bind".to_string(),
            MODULE_CONTROL_OP_HEALTH_CHECK.to_string(),
            subc_client_rs::config::CONFIG_REVIEW_OP.to_string(),
        ]),
        launch_nonce: launch_nonce.map(|nonce| nonce.value().to_string()),
    };
    let body = serde_json::to_vec(&hello).map_err(ModuleError::Json)?;
    let frame = Frame::build(
        FrameType::Hello,
        wire::control_flags(),
        0,
        0,
        HELLO_CORRELATION,
        body,
    )
    .map_err(|error| ModuleError::Message(error.to_string()))?;
    send(writer, frame).await?;
    Ok(provides)
}

/// The startup error for a launch nonce the accessor refused.
///
/// It carries the refusal's variant and fields (`NotOpen { fd: 3, errno: 9 }`)
/// as well as its prose, so the one line `ck-plexus` prints to stderr on exit
/// says which check failed without anyone matching prose back to a variant.
/// Neither form contains the nonce: every variant describes the descriptor or
/// the `SUBC_LAUNCH_NONCE_FD` value (`<fd>:<inode>`), never the pipe's bytes.
pub(super) fn launch_nonce_refused(error: subc_os::LaunchNonceError) -> ModuleError {
    ModuleError::Message(format!("read launch nonce: refused as {error:?}: {error}"))
}

pub(super) async fn expect_hello_ack<R>(reader: &mut R) -> Result<ModuleHelloAckBody, ModuleError>
where
    R: AsyncRead + Unpin,
{
    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), read_frame(reader))
        .await
        .map_err(|_| ModuleError::Message("HELLO_ACK timeout".into()))?
        .map_err(|error| ModuleError::Message(error.to_string()))?
        .ok_or_else(|| ModuleError::Message("connection closed before HELLO_ACK".to_string()))?;
    match frame.header.ty {
        FrameType::HelloAck => serde_json::from_slice(&frame.body).map_err(ModuleError::Json),
        FrameType::Error => {
            let body: ErrorBody = serde_json::from_slice(&frame.body).map_err(ModuleError::Json)?;
            Err(ModuleError::Message(format!(
                "subc rejected HELLO: {} — {}",
                body.code, body.message
            )))
        }
        frame_type => Err(ModuleError::Message(format!(
            "unexpected frame {frame_type:?} awaiting HELLO_ACK"
        ))),
    }
}

fn parse_subc_arg(args: impl IntoIterator<Item = OsString>) -> Result<PathBuf, ModuleError> {
    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        if argument == "--subc" {
            let value = args
                .next()
                .ok_or_else(|| ModuleError::Message("--subc requires a value".to_string()))?;
            return Ok(PathBuf::from(value));
        }
        if let Some(raw) = argument
            .to_str()
            .and_then(|value| value.strip_prefix("--subc="))
        {
            if raw.is_empty() {
                return Err(ModuleError::Message("--subc= requires a value".to_string()));
            }
            return Ok(PathBuf::from(raw));
        }
    }
    Err(ModuleError::Message(
        "--subc <connection-file> is required".to_string(),
    ))
}
