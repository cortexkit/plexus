use super::*;
use crate::manifest::CredentiallessTail;
use serde_json::json;
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;

// Public test-only TLS identity; it is never used by a deployed connection.
pub(in crate::rest_api) const CERT: &[u8] =
    include_bytes!("../../../tests/fixtures/job-log-tls/cert.der");
const KEY: &[u8] = include_bytes!("../../../tests/fixtures/job-log-tls/key.der");

pub(in crate::rest_api) struct Storage {
    pub(in crate::rest_api) url: String,
    pub(in crate::rest_api) requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Storage {
    pub(in crate::rest_api) fn start(handler: impl Fn(&str) -> String + Send + 'static) -> Self {
        Self::start_bytes(move |request| handler(request).into_bytes())
    }
    pub(in crate::rest_api) fn start_bytes(
        handler: impl Fn(&str) -> Vec<u8> + Send + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!(
            "https://localhost:{}/log?sig=SIGNED-URL-SECRET",
            listener.local_addr().unwrap().port()
        );
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(CERT.to_vec())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                KEY.to_vec(),
            )),
        )
        .unwrap();
        let config = Arc::new(config);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&requests);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !stopped.load(Ordering::Relaxed) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((socket, _)) => {
                        socket
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        socket
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let connection =
                            rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
                        let mut stream = rustls::StreamOwned::new(connection, socket);
                        let mut request = Vec::new();
                        let mut byte = [0u8; 1];
                        while !request.ends_with(b"\r\n\r\n") && request.len() < 16_384 {
                            match stream.read(&mut byte) {
                                Ok(1) => request.push(byte[0]),
                                _ => break,
                            }
                        }
                        let request = String::from_utf8_lossy(&request).into_owned();
                        if !request.is_empty() {
                            observed.lock().unwrap().push(request.clone());
                            let reply = handler(&request);
                            use std::io::Write;
                            let _ = stream.write_all(&reply);
                            stream.conn.send_close_notify();
                            let _ = stream.flush();
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::park_timeout(Duration::from_millis(2))
                    }
                    Err(error) => panic!("storage accept: {error}"),
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Storage {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}
pub(in crate::rest_api) fn response(status: u16, headers: &str, body: &str) -> String {
    format!("HTTP/1.1 {status} Test\r\n{headers}Connection: close\r\n\r\n{body}")
}
fn run(url: &str, allowed_hosts: Vec<String>, max_bytes: usize) -> TransportResponse {
    let url = url.to_owned();
    let (api, server) = super::super::tests::start_server(1, move |_, request| {
        assert!(request.to_ascii_lowercase().contains(
            "authorization: bearer API-CREDENTIAL"
                .to_ascii_lowercase()
                .as_str()
        ));
        assert!(request.to_ascii_lowercase().contains(
            "x-api-secret: custom API-CREDENTIAL"
                .to_ascii_lowercase()
                .as_str()
        ));
        assert!(!request.lines().next().unwrap().contains("max_bytes"));
        response(
            302,
            &format!("Location: {url}\r\nContent-Length: 0\r\n"),
            "",
        )
    });
    let mut op = super::super::tests::http_op(
        HttpMethod::Get,
        "/repos/{owner}/{repo}/actions/jobs/{job_id}/logs",
    );
    op.credentialless_tail = Some(CredentiallessTail { allowed_hosts });
    let mut config = super::super::tests::config(api, vec![("github.actions.job_log", op)]);
    config.credential_bindings.push(CredentialBinding {
        ref_role: "credential".into(),
        placement: "header".into(),
        key: "X-Api-Secret".into(),
        prefix: "custom ".into(),
        required: true,
    });
    config.test_root_certificate = Some(CERT.to_vec());
    config.request_timeout = Duration::from_secs(3);
    let transport = RestTransport::new(config);
    let result = transport.dispatch(
        super::super::tests::request(
            "ci",
            "github.actions.job_log",
            json!({"owner":"o","repo":"r","job_id":42,"max_bytes":max_bytes}),
        ),
        &ResolvedCredential::new(b"API-CREDENTIAL".to_vec(), None, 0),
    );
    server.join().unwrap();
    result
}

#[test]
fn range_store_returns_bounded_tail_without_credentials() {
    let log = "prefix ignored\n\u{1b}[31mtest FAILED\u{1b}[0m\n";
    let total = log.len();
    let max = 21;
    let storage = Storage::start(move |request| {
        if request.starts_with("HEAD ") {
            return response(200, &format!("Content-Length: {total}\r\n"), "");
        }
        assert!(request
            .to_ascii_lowercase()
            .contains(&format!("range: bytes={}-", total - max)));
        let tail = &log[total - max..];
        response(
            206,
            &format!(
                "Content-Length: {}\r\nContent-Range: bytes {}-{}/{total}\r\n",
                tail.len(),
                total - max,
                total - 1
            ),
            tail,
        )
    });
    let result = run(&storage.url, vec!["localhost".into()], max);
    let body = result.response.unwrap();
    assert_eq!(
        body,
        json!({"total_bytes":total,"truncated":true,"text":"test FAILED\n"})
    );
    let requests = storage.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests.iter().all(
            |request| !request.to_ascii_lowercase().contains("authorization:")
                && !request.to_ascii_lowercase().contains("x-api-secret:")
        ),
        "{requests:?}"
    );
}

#[test]
fn ignoring_range_streams_only_the_tail() {
    let log = format!("{}failure summary\n", "x".repeat(100_000));
    let total = log.len();
    let storage = Storage::start(move |request| {
        response(
            200,
            &format!("Content-Length: {total}\r\n"),
            if request.starts_with("HEAD ") {
                ""
            } else {
                &log
            },
        )
    });
    let result = run(&storage.url, vec!["localhost".into()], 16);
    assert_eq!(
        result.response.unwrap(),
        json!({"total_bytes":total,"truncated":true,"text":"failure summary\n"})
    );
}

#[test]
fn unlisted_storage_host_is_refused() {
    let storage = Storage::start(|_| response(200, "Content-Length: 3\r\n", "log"));
    let result = run(&storage.url, vec!["*.blob.core.windows.net".into()], 20);
    assert_eq!(
        result.error_code.as_deref(),
        Some("job_log_redirect_refused")
    );
    assert!(storage.requests.lock().unwrap().is_empty());
}

#[test]
fn plaintext_storage_redirect_is_refused() {
    let (storage, server) = super::super::tests::start_server(0, |_, _| unreachable!());
    let result = run(
        &format!("{storage}/log?sig=SIGNED-URL-SECRET"),
        vec!["127.0.0.1".into()],
        20,
    );
    assert_eq!(
        result.error_code.as_deref(),
        Some("job_log_redirect_refused")
    );
    server.join().unwrap();
}

#[test]
fn second_storage_redirect_is_refused() {
    let storage = Storage::start(|request| {
        if request.starts_with("HEAD ") {
            response(200, "Content-Length: 3\r\n", "")
        } else {
            response(
                302,
                "Location: https://localhost/other?sig=SIGNED-URL-SECRET\r\nContent-Length: 0\r\n",
                "",
            )
        }
    });
    let result = run(&storage.url, vec!["localhost".into()], 20);
    assert_eq!(
        result.error_code.as_deref(),
        Some("job_log_redirect_refused")
    );
    assert_eq!(storage.requests.lock().unwrap().len(), 2);
}

#[test]
fn log_read_cap_refuses_large_ignored_ranges() {
    let storage = Storage::start(|request| {
        response(
            200,
            &format!("Content-Length: {}\r\n", MAX_LOG_READ_BYTES + 1),
            if request.starts_with("HEAD ") {
                ""
            } else {
                "log"
            },
        )
    });
    let result = run(&storage.url, vec!["localhost".into()], 20);
    assert_eq!(result.error_code.as_deref(), Some("job_log_read_limit"));
}

#[test]
fn empty_log_is_a_named_refusal() {
    let storage = Storage::start(|_| response(200, "Content-Length: 0\r\n", ""));
    let result = run(&storage.url, vec!["localhost".into()], 20);
    assert_eq!(result.error_code.as_deref(), Some("job_log_unavailable"));
}

#[test]
fn signed_url_and_known_credentials_are_not_returned() {
    let body = Arc::new(Mutex::new(String::new()));
    let served = Arc::clone(&body);
    let storage = Storage::start(move |request| {
        let log = served.lock().unwrap();
        response(
            200,
            &format!("Content-Length: {}\r\n", log.len()),
            if request.starts_with("HEAD ") {
                ""
            } else {
                &log
            },
        )
    });
    *body.lock().unwrap() = format!("{} API-CREDENTIAL", storage.url);
    let result = run(&storage.url, vec!["localhost".into()], 4096);
    let text = result.response.unwrap()["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(text, "[signed URL redacted] [credential redacted]");
}

#[test]
fn allowlist_matches_one_account_label_and_no_userinfo() {
    let hosts = vec!["*.blob.core.windows.net".into()];
    assert!(destination_allowed(
        &"https://account.blob.core.windows.net/log?sig=secret"
            .parse()
            .unwrap(),
        &hosts
    ));
    for url in [
        "https://blob.core.windows.net/log",
        "https://a.b.blob.core.windows.net/log",
        "https://badblob.core.windows.net/log",
        "https://a.blob.core.windows.net.evil.test/log",
        "https://user:secret@account.blob.core.windows.net/log",
    ] {
        assert!(!destination_allowed(&url.parse().unwrap(), &hosts), "{url}");
    }
}

#[test]
fn partial_range_that_is_not_a_tail_is_refused() {
    let storage = Storage::start(|request| {
        if request.starts_with("HEAD ") {
            response(200, "Content-Length: 100\r\n", "")
        } else {
            response(
                206,
                "Content-Length: 3\r\nContent-Range: bytes 0-2/100\r\n",
                "log",
            )
        }
    });
    let result = run(&storage.url, vec!["localhost".into()], 20);
    assert_eq!(
        result.error_code.as_deref(),
        Some("job_log_download_failed")
    );
    assert!(result.response.is_none());
}

#[test]
fn expired_storage_log_is_a_named_refusal() {
    let storage = Storage::start(|request| {
        if request.starts_with("HEAD ") {
            response(200, "Content-Length: 3\r\n", "")
        } else {
            response(404, "Content-Length: 3\r\n", "bad")
        }
    });
    let result = run(&storage.url, vec!["localhost".into()], 20);
    assert_eq!(result.error_code.as_deref(), Some("job_log_unavailable"));
    assert!(result.response.is_none());
}

#[test]
fn signed_url_never_appears_in_operator_diagnostics() {
    const TEST: &str = "rest_api::job_log::tests::signed_url_never_appears_in_operator_diagnostics";
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
        super::super::tests::logging::init_child();
        let storage = Storage::start(|request| {
            if request.starts_with("HEAD ") {
                response(200, "Content-Length: 3\r\n", "")
            } else {
                response(500, "Content-Length: 17\r\n", "SIGNED-URL-SECRET")
            }
        });
        let result = run(&storage.url, vec!["localhost".into()], 20);
        assert_eq!(
            result.error_code.as_deref(),
            Some("job_log_download_failed")
        );
        assert!(!format!("{result:?}").contains("SIGNED-URL-SECRET"));
        return;
    }
    let output = crate::test_http::bounded::child_output(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("PLEXUS_LOG_STDERR_CHILD", "1"),
        Duration::from_secs(20),
        "job log diagnostic child",
    )
    .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("REST log storage failed: status=500 destination=[signed URL redacted]"),
        "{stderr}"
    );
    assert!(!stderr.contains("SIGNED-URL-SECRET"), "{stderr}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SIGNED-URL-SECRET"));
}

fn body_response(body: String) -> (Response, crate::test_http::FixedRequestServer) {
    let (url, server) = super::super::tests::start_server(1, move |_, _| response(200, "", &body));
    (Client::new().get(url).send().unwrap(), server)
}

#[test]
fn stream_cap_refuses_unknown_length_logs() {
    let (response, server) = body_response("x".repeat(16_384));
    assert_eq!(
        read_tail(response, 10, Instant::now(), 8192),
        Err("job_log_read_limit")
    );
    server.join().unwrap();
}

#[test]
fn expired_download_deadline_refuses_before_body_read() {
    let (response, server) = body_response("log".into());
    assert_eq!(
        read_tail(
            response,
            10,
            Instant::now() - LOG_DEADLINE,
            MAX_LOG_READ_BYTES
        ),
        Err("job_log_read_limit")
    );
    server.join().unwrap();
}

#[test]
fn unknown_length_tail_reports_read_bytes_and_lossy_utf8() {
    let (response, server) = body_response("ignored\nrégression FAILED".into());
    let (tail, read) = read_tail(response, 16, Instant::now(), MAX_LOG_READ_BYTES).unwrap();
    assert_eq!(read, 26);
    assert_eq!(strip_ansi(&tail), "�gression FAILED");
    server.join().unwrap();
}
