use super::super::job_log::tests::{assert_reply_omits, response, Storage, CERT};
use super::*;
use crate::manifest::CredentiallessTail;
use serde_json::json;
use std::io::Write;

fn archive(entries: &[(&str, &[u8])], method: zip::CompressionMethod) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, body) in entries {
        writer
            .start_file(
                *name,
                zip::write::SimpleFileOptions::default().compression_method(method),
            )
            .unwrap();
        writer.write_all(body).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn zip_response(bytes: &[u8]) -> Vec<u8> {
    let mut reply = response(200, &format!("Content-Length: {}\r\n", bytes.len()), "").into_bytes();
    reply.extend_from_slice(bytes);
    reply
}

fn run(url: &str, allowed_hosts: Vec<String>, path: &str, max_bytes: usize) -> TransportResponse {
    run_with_api_status(url, allowed_hosts, path, max_bytes, 302)
}

fn run_with_api_status(
    url: &str,
    allowed_hosts: Vec<String>,
    path: &str,
    max_bytes: usize,
    status: u16,
) -> TransportResponse {
    let url = url.to_owned();
    let (api, server) = super::super::tests::start_server(1, move |_, request| {
        assert!(request.starts_with("GET /repos/o/r/actions/artifacts/7/zip "));
        let headers = request.to_ascii_lowercase();
        assert!(headers.contains("authorization: bearer api-credential"));
        assert!(headers.contains("x-api-secret: custom api-credential"));
        response(
            status,
            &format!("Location: {url}\r\nContent-Length: 0\r\n"),
            "",
        )
    });
    let mut op = super::super::tests::http_op(
        HttpMethod::Get,
        "/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip",
    );
    op.credentialless_tail = Some(CredentiallessTail {
        allowed_hosts,
        kind: crate::manifest::CredentiallessTailKind::ArtifactFile,
    });
    let mut config = super::super::tests::config(api, vec![("github.actions.artifact_file", op)]);
    config.credential_bindings.push(CredentialBinding {
        ref_role: "credential".into(),
        placement: "header".into(),
        key: "X-Api-Secret".into(),
        prefix: "custom ".into(),
        required: true,
    });
    config.test_root_certificate = Some(CERT.to_vec());
    config.request_timeout = Duration::from_secs(5);
    let result = RestTransport::new(config).dispatch(
        super::super::tests::request(
            "ci",
            "github.actions.artifact_file",
            json!({"owner":"o","repo":"r","artifact_id":7,"path":path,"max_bytes":max_bytes}),
        ),
        &ResolvedCredential::new(b"API-CREDENTIAL".to_vec(), None, 0),
    );
    server.join().unwrap();
    result
}

fn serve(bytes: Vec<u8>, path: &str) -> TransportResponse {
    let storage = Storage::start_bytes(move |_| zip_response(&bytes));
    run(&storage.url, vec!["localhost".into()], path, 65_536)
}

#[test]
fn named_entry_returns_only_its_tail_without_storage_credentials() {
    for method in [
        zip::CompressionMethod::Stored,
        zip::CompressionMethod::Deflated,
    ] {
        let bytes = archive(
            &[
                ("other.log", b"do not return"),
                (
                    "logs/shard.log",
                    b"prefix ignored\n\x1b[31mtest FAILED\x1b[0m\n",
                ),
            ],
            method,
        );
        let storage = Storage::start_bytes(move |_| zip_response(&bytes));
        let result = run(&storage.url, vec!["localhost".into()], "logs/shard.log", 21);
        assert_eq!(
            result.response.unwrap(),
            json!({"total_bytes":36,"truncated":true,"text":"test FAILED\n"})
        );
        let requests = storage.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests.iter().all(
                |request| !request.to_ascii_lowercase().contains("authorization:")
                    && !request.to_ascii_lowercase().contains("x-api-secret:")
            ),
            "{requests:?}"
        );
    }
}

#[test]
fn missing_file_has_a_named_refusal() {
    let result = serve(
        archive(
            &[("other.log", b"contents")],
            zip::CompressionMethod::Stored,
        ),
        "log",
    );
    assert_eq!(
        result.error_code.as_deref(),
        Some("artifact_file_not_found")
    );
}

#[test]
fn invalid_zip_has_a_named_refusal() {
    assert_eq!(
        serve(b"not a zip".to_vec(), "log").error_code.as_deref(),
        Some("artifact_invalid_zip")
    );
}

#[test]
fn advertised_download_over_64_mib_is_refused() {
    let storage = Storage::start(|_| response(200, "Content-Length: 67108865\r\n", "small"));
    assert_eq!(
        run(&storage.url, vec!["localhost".into()], "log", 20)
            .error_code
            .as_deref(),
        Some("artifact_too_large")
    );
}

#[test]
fn high_compression_ratio_is_refused() {
    let bytes = archive(
        &[("log", &vec![b'x'; 1_000_000])],
        zip::CompressionMethod::Deflated,
    );
    assert_eq!(
        serve(bytes, "log").error_code.as_deref(),
        Some("artifact_too_large")
    );
}

#[test]
fn oversized_entry_count_is_refused() {
    let names: Vec<_> = (0..10_001).map(|i| format!("{i}.log")).collect();
    let entries: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), b"".as_slice()))
        .collect();
    let bytes = archive(&entries, zip::CompressionMethod::Stored);
    assert_eq!(
        serve(bytes, "0.log").error_code.as_deref(),
        Some("artifact_too_large")
    );
}

#[test]
fn traversal_in_any_entry_name_is_refused() {
    for name in ["../bad", "/absolute", "folder\\bad", "folder/../bad"] {
        let bytes = archive(
            &[("log", b"healthy"), (name, b"bad")],
            zip::CompressionMethod::Stored,
        );
        assert_eq!(
            serve(bytes, "log").error_code.as_deref(),
            Some("artifact_invalid_zip"),
            "{name}"
        );
    }
}

fn patch_central(bytes: &mut [u8], offset: usize, value: &[u8]) {
    let central = bytes
        .windows(4)
        .position(|signature| signature == b"PK\x01\x02")
        .unwrap();
    bytes[central + offset..central + offset + value.len()].copy_from_slice(value);
}

#[test]
fn encrypted_entry_is_refused_even_when_not_selected() {
    let mut bytes = archive(
        &[("other", b"bad"), ("log", b"healthy")],
        zip::CompressionMethod::Stored,
    );
    patch_central(&mut bytes, 8, &1u16.to_le_bytes());
    assert_eq!(
        serve(bytes, "log").error_code.as_deref(),
        Some("artifact_invalid_zip")
    );
}

#[test]
fn unsupported_compression_is_refused_even_when_not_selected() {
    let mut bytes = archive(
        &[("other", b"bad"), ("log", b"healthy")],
        zip::CompressionMethod::Stored,
    );
    patch_central(&mut bytes, 10, &12u16.to_le_bytes());
    assert_eq!(
        serve(bytes, "log").error_code.as_deref(),
        Some("artifact_invalid_zip")
    );
}

#[test]
fn unlisted_artifact_storage_host_is_refused() {
    let bytes = archive(&[("log", b"healthy")], zip::CompressionMethod::Stored);
    let storage = Storage::start_bytes(move |_| zip_response(&bytes));
    let result = run(
        &storage.url,
        vec!["*.blob.core.windows.net".into()],
        "log",
        20,
    );
    assert_eq!(
        result.error_code.as_deref(),
        Some("artifact_redirect_refused")
    );
    assert!(storage.requests.lock().unwrap().is_empty());
}

#[test]
fn plaintext_artifact_storage_is_refused() {
    let result = run(
        "http://localhost/log?sig=SIGNED-URL-SECRET",
        vec!["localhost".into()],
        "log",
        20,
    );
    assert_eq!(
        result.error_code.as_deref(),
        Some("artifact_redirect_refused")
    );
}

#[test]
fn second_artifact_storage_redirect_is_refused() {
    let storage = Storage::start(|_| {
        response(
            302,
            "Location: https://localhost/other?sig=SIGNED-URL-SECRET\r\nContent-Length: 0\r\n",
            "",
        )
    });
    let result = run(&storage.url, vec!["localhost".into()], "log", 20);
    assert_eq!(
        result.error_code.as_deref(),
        Some("artifact_redirect_refused")
    );
    assert_eq!(storage.requests.lock().unwrap().len(), 1);
}

#[test]
fn artifact_download_failure_has_a_named_refusal() {
    let storage = Storage::start(|_| response(500, "Content-Length: 17\r\n", "SIGNED-URL-SECRET"));
    assert_eq!(
        run(&storage.url, vec!["localhost".into()], "log", 20)
            .error_code
            .as_deref(),
        Some("artifact_download_failed")
    );
}

fn governed_engine(
    api: String,
) -> crate::GovernanceEngine<crate::StubCredentialSource, RestTransport> {
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
    let store = Arc::new(
        crate::PlexusStore::open(&StorageDescriptor {
            module_id: "plexus".into(),
            storage_namespace: format!("artifact-tests-{}", crate::storage::new_id("store")),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: ":memory:".into(),
            },
        })
        .unwrap(),
    );
    let source = include_str!("../../../../../catalog/github_actions.jsonc");
    let manifest = crate::ingest_value(
        serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap(),
    )
    .unwrap();
    store.upsert_manifest("system", &manifest).unwrap();
    let connection = crate::poller::GITHUB_ACTIONS_CONNECTION;
    store
        .insert_connection(
            "direct",
            connection,
            "github_actions",
            "pending",
            &json!({"required":[],"optional":["owner","repo"],"write_enabling":[]}),
        )
        .unwrap();
    let ticket = store
        .create_binding_ticket("direct", connection, b"test:actions")
        .unwrap();
    store
        .connect_with_ticket("direct", &ticket.ticket_id)
        .unwrap()
        .unwrap();
    for action in &manifest.manifest.actions_baseline {
        let schema = action.http.as_ref().unwrap().args_schema.clone();
        store
            .upsert_catalog_action(&crate::CatalogActionInput {
                principal: "direct".into(),
                connection_id: connection.into(),
                name: action.name.clone(),
                title: None,
                schema_hash: crate::jcs_sha256(&schema).unwrap(),
                schema,
                risk: "read".into(),
                severity: "read".into(),
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: None,
                ask_first: false,
            })
            .unwrap();
    }
    store
        .insert_grant(&crate::GrantInput {
            grant_id: "artifact-grant".into(),
            principal: "direct".into(),
            connection_id: connection.into(),
            grantee_principal: "reserved:basal".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec![
                "list_workflow_run_artifacts".into(),
                "github.actions.artifact_file".into(),
            ],
            authority_kind: "invoke".into(),
            expires_at: None,
        })
        .unwrap();
    let mut config = RestConfig::new(api)
        .with_bindings(manifest.manifest.credential_bindings.clone())
        .with_actions(actions_from_manifest(&manifest.manifest));
    config
        .actions
        .get_mut("github.actions.artifact_file")
        .unwrap()
        .credentialless_tail
        .as_mut()
        .unwrap()
        .allowed_hosts = vec!["localhost".into()];
    config.test_root_certificate = Some(CERT.to_vec());
    crate::GovernanceEngine::new(
        store,
        Arc::new(crate::StubCredentialSource::with_default_success(
            b"API-CREDENTIAL".to_vec(),
        )),
        Arc::new(RestTransport::new(config)),
    )
}

fn artifact(id: u64, created: &str, expired: bool, size: u64) -> Value {
    json!({"id":id,"name":"shard-1","created_at":created,"expired":expired,"size_in_bytes":size})
}

fn full_read(
    engine: &crate::GovernanceEngine<crate::StubCredentialSource, RestTransport>,
) -> Result<Value, crate::github::reads::ReadError> {
    crate::github::reads::read(
        engine,
        "reserved:basal",
        "github.actions.artifact_file",
        &json!("O/R"),
        &json!({"run_id":42,"artifact":"shard-1","path":"logs/shard.log","max_bytes":16}),
    )
}

#[test]
fn governed_artifact_read_lists_by_name_and_returns_the_newest_entries_tail() {
    let bytes = archive(
        &[
            ("other.log", b"ignored"),
            ("logs/shard.log", b"ignored prefix\nfailure summary\n"),
        ],
        zip::CompressionMethod::Deflated,
    );
    let size = bytes.len() as u64;
    let storage = Storage::start_bytes(move |_| zip_response(&bytes));
    let location = storage.url.clone();
    let (api, server) = super::super::tests::start_server(2, move |index, request| {
        if index == 0 {
            assert!(request.starts_with("GET /repos/o/r/actions/runs/42/artifacts?"));
            assert!(request.lines().next().unwrap().contains("name=shard-1"));
            let body = json!({"total_count":2,"artifacts":[artifact(7,"2026-10-12T00:00:00Z",false,size),artifact(6,"2026-10-11T00:00:00Z",false,size)]}).to_string();
            response(200, &format!("Content-Length: {}\r\n", body.len()), &body)
        } else {
            assert!(request.starts_with("GET /repos/o/r/actions/artifacts/7/zip "));
            response(
                302,
                &format!("Location: {location}\r\nContent-Length: 0\r\n"),
                "",
            )
        }
    });
    let result = full_read(&governed_engine(api)).unwrap();
    server.join().unwrap();
    assert_eq!(
        result,
        json!({"repository":"o/r","run_id":42,"artifact":"shard-1","path":"logs/shard.log","total_bytes":31,"truncated":true,"text":"failure summary\n"})
    );
}

fn list_refusal(entries: Vec<Value>, code: &'static str) {
    let (api, server) = super::super::tests::start_server(1, move |_, _| {
        let body = json!({"total_count":entries.len(),"artifacts":entries}).to_string();
        response(200, &format!("Content-Length: {}\r\n", body.len()), &body)
    });
    let result = full_read(&governed_engine(api));
    server.join().unwrap();
    assert_eq!(result, Err(crate::github::reads::ReadError::Refused(code)));
}

#[test]
fn artifact_not_found_has_a_named_refusal() {
    list_refusal(Vec::new(), "artifact_not_found");
}

#[test]
fn expired_artifact_is_refused_before_download() {
    list_refusal(
        vec![artifact(7, "2026-10-12T00:00:00Z", true, 123)],
        "artifact_expired",
    );
}

#[test]
fn listed_artifact_over_64_mib_is_refused_before_download() {
    list_refusal(
        vec![artifact(7, "2026-10-12T00:00:00Z", false, 67_108_865)],
        "artifact_too_large",
    );
}

#[test]
fn artifact_signed_url_and_credentials_are_redacted_in_the_reply() {
    let body = Arc::new(Mutex::new(Vec::new()));
    let served = Arc::clone(&body);
    let storage = Storage::start_bytes(move |_| zip_response(&served.lock().unwrap()));
    *body.lock().unwrap() = archive(
        &[("log", format!("{} API-CREDENTIAL", storage.url).as_bytes())],
        zip::CompressionMethod::Stored,
    );
    let result = run(&storage.url, vec!["localhost".into()], "log", 4096);
    assert_eq!(
        result.response.unwrap()["text"],
        "[signed URL redacted] [credential redacted]"
    );
}

#[test]
fn artifact_signed_url_never_appears_in_operator_diagnostics() {
    const TEST: &str =
        "rest_api::artifact_file::tests::artifact_signed_url_never_appears_in_operator_diagnostics";
    if std::env::var_os("PLEXUS_LOG_STDERR_CHILD").is_some() {
        super::super::tests::logging::init_child();
        let storage =
            Storage::start(|_| response(500, "Content-Length: 17\r\n", "SIGNED-URL-SECRET"));
        let result = run(&storage.url, vec!["localhost".into()], "log", 20);
        assert_eq!(
            result.error_code.as_deref(),
            Some("artifact_download_failed")
        );
        assert_reply_omits(&result, "SIGNED-URL-SECRET");
        return;
    }
    let output = crate::test_http::bounded::child_test_output(
        TEST,
        &[("PLEXUS_LOG_STDERR_CHILD", "1")],
        Duration::from_secs(20),
        "artifact diagnostic child",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("REST log storage failed: status=500 destination=[signed URL redacted]"),
        "{stderr}"
    );
    assert!(!stderr.contains("SIGNED-URL-SECRET"), "{stderr}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SIGNED-URL-SECRET"));
}

#[test]
fn unknown_length_archive_over_64_mib_is_refused() {
    let storage = Storage::start_bytes(|_| {
        let mut reply = response(200, "", "").into_bytes();
        reply.resize(reply.len() + 67_108_865, b'x');
        reply
    });
    assert_eq!(
        run(&storage.url, vec!["localhost".into()], "log", 20)
            .error_code
            .as_deref(),
        Some("artifact_too_large")
    );
}

#[test]
fn decompressed_file_over_64_mib_is_refused() {
    // A repeated pseudorandom block compresses below 200:1, isolating the byte cap.
    let mut state = 17u32;
    let block: Vec<_> = (0..16_384)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "log",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
    for _ in 0..4096 {
        writer.write_all(&block).unwrap();
    }
    writer.write_all(b"x").unwrap();
    let bytes = writer.finish().unwrap().into_inner();
    let metadata = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
    let entry = metadata.by_index_data(0).unwrap();
    assert!(entry.size() <= entry.compressed_size() * 200);
    assert!(bytes.len() < 67_108_864);
    assert_eq!(
        serve(bytes, "log").error_code.as_deref(),
        Some("artifact_too_large")
    );
}

#[test]
fn expired_artifact_body_deadline_is_refused() {
    let (api, server) =
        super::super::tests::start_server(1, |_, _| response(200, "Content-Length: 3\r\n", "zip"));
    let response = Client::new().get(api).send().unwrap();
    assert_eq!(
        read_archive(
            response,
            Instant::now() - Duration::from_secs(30),
            Duration::from_secs(30),
            MAX_ARTIFACT_BYTES
        ),
        Err("artifact_read_limit")
    );
    server.join().unwrap();
}

#[test]
fn empty_files_and_lossy_utf8_are_valid_artifact_tails() {
    let empty = serve(
        archive(&[("log", b"")], zip::CompressionMethod::Stored),
        "log",
    );
    assert_eq!(
        empty.response.unwrap(),
        json!({"total_bytes":0,"truncated":false,"text":""})
    );
    let bytes = archive(
        &[("log", b"prefix\n\xffFAIL\n")],
        zip::CompressionMethod::Stored,
    );
    let storage = Storage::start_bytes(move |_| zip_response(&bytes));
    assert_eq!(
        run(&storage.url, vec!["localhost".into()], "log", 6)
            .response
            .unwrap(),
        json!({"total_bytes":13,"truncated":true,"text":"\u{fffd}FAIL\n"})
    );
}

#[test]
fn artifact_name_filter_is_enforced_locally() {
    let mut other = artifact(7, "2026-10-12T00:00:00Z", false, 123);
    other["name"] = json!("not-the-requested-artifact");
    list_refusal(vec![other], "artifact_not_found");
}

#[test]
fn incomplete_artifact_page_is_refused() {
    let (api, server) = super::super::tests::start_server(1, |_, _| {
        let body = r#"{"total_count":1,"artifacts":[]}"#;
        response(200, &format!("Content-Length: {}\r\n", body.len()), body)
    });
    assert_eq!(
        full_read(&governed_engine(api)),
        Err(crate::github::reads::ReadError::Refused(
            "job_log_read_limit"
        ))
    );
    server.join().unwrap();
}

#[test]
fn nul_entry_names_are_refused() {
    let mut bytes = archive(
        &[("other", b"bad"), ("log", b"healthy")],
        zip::CompressionMethod::Stored,
    );
    patch_central(&mut bytes, 46, b"nu\0ll");
    assert_eq!(
        serve(bytes, "log").error_code.as_deref(),
        Some("artifact_invalid_zip")
    );
}

#[test]
fn invalid_central_directory_bounds_are_refused() {
    let mut bytes = archive(&[("log", b"healthy")], zip::CompressionMethod::Stored);
    let end = bytes
        .windows(4)
        .position(|signature| signature == b"PK\x05\x06")
        .unwrap();
    bytes[end + 12..end + 16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        serve(bytes, "log").error_code.as_deref(),
        Some("artifact_invalid_zip")
    );
}

#[test]
fn artifact_api_must_return_exactly_one_302_redirect() {
    let bytes = archive(&[("log", b"healthy")], zip::CompressionMethod::Stored);
    let storage = Storage::start_bytes(move |_| zip_response(&bytes));
    assert_eq!(
        run_with_api_status(&storage.url, vec!["localhost".into()], "log", 20, 200)
            .error_code
            .as_deref(),
        Some("artifact_redirect_refused")
    );
    assert!(storage.requests.lock().unwrap().is_empty());
}

#[test]
fn missing_storage_artifact_has_a_named_refusal() {
    let storage = Storage::start(|_| response(404, "Content-Length: 3\r\n", "bad"));
    assert_eq!(
        run(&storage.url, vec!["localhost".into()], "log", 20)
            .error_code
            .as_deref(),
        Some("artifact_unavailable")
    );
}

#[test]
fn conflicting_end_records_are_rejected_before_zip_metadata_allocation() {
    let mut bytes = archive(&[("out.txt", b"safe")], zip::CompressionMethod::Stored);
    let end = bytes.len() - 22;
    bytes[end + 20..end + 22].copy_from_slice(&22u16.to_le_bytes());
    let mut fake = [0u8; 22];
    fake[..4].copy_from_slice(b"PK\x05\x06");
    fake[8..10].copy_from_slice(&10_001u16.to_le_bytes());
    fake[10..12].copy_from_slice(&10_001u16.to_le_bytes());
    fake[20..22].copy_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&fake);
    assert_eq!(
        preflight(&bytes),
        Err("artifact_invalid_zip"),
        "the preflight must validate the same last EOCD signature that the ZIP reader selects"
    );
}
