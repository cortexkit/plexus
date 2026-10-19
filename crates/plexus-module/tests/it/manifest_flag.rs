//! `ck-plexus --manifest` is how SUBC's placement gate reads a staged binary's
//! build provenance. The gate runs it with nothing else: no daemon, no store, no
//! stdin, a throwaway home and a short alarm. It must print the registered
//! manifest as JSON with a `provenance` object, and must not create anything
//! under the home it is given.

use super::bounded;

use std::process::{Command, Stdio};

use cortexkit_test_support::ckdev_binary;
use plexus_core::test_scratch::Scratch;

fn run_manifest(home: &std::path::Path) -> std::process::Output {
    let binary = ckdev_binary(env!("CARGO_BIN_EXE_ck-plexus"));
    bounded::child_output(
        Command::new(&binary)
            .arg("--manifest")
            .env_clear()
            .env("HOME", home)
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_STATE_HOME", home.join("state"))
            .env("XDG_CONFIG_HOME", home.join("config"))
            .stdin(Stdio::null()),
        std::time::Duration::from_secs(60),
        "test binary command",
    )
    .expect("run ck-plexus --manifest")
}

#[test]
fn manifest_prints_the_registered_manifest_with_provenance_and_no_daemon() {
    let scratch = Scratch::directory("manifest-flag-home");
    let output = run_manifest(scratch.path());
    assert!(
        output.status.success(),
        "--manifest exited {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let printed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("--manifest prints one JSON document");
    let registered =
        serde_json::to_value(plexus_module::manifest::build(plexus_module::DEFAULT_MODULE_ID))
            .expect("manifest serializes");
    assert_eq!(
        printed, registered,
        "--manifest prints the manifest plexus registers"
    );
    assert!(
        printed.get("cli_faces").is_none(),
        "plexus has no operator faces"
    );
    let provenance = printed["provenance"]
        .as_object()
        .expect("the manifest carries a provenance object");
    let commit = env!("PLEXUS_BUILD_COMMIT");
    match commit.strip_suffix("-dirty") {
        _ if commit == "unavailable" => assert_eq!(
            provenance.get("build_git_sha_absence_reason"),
            Some(&serde_json::json!("no_git_dir"))
        ),
        Some(_) => {
            assert!(provenance.get("build_git_sha").is_none(), "{provenance:?}");
            assert_eq!(
                provenance.get("build_git_sha_absence_reason"),
                Some(&serde_json::json!("declined_dirty")),
                "a dirty build never stamps a commit"
            );
        }
        None => {
            let sha = provenance["build_git_sha"].as_str().expect("clean builds stamp a sha");
            assert_eq!(sha, commit);
            assert!(sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()));
            assert!(provenance.get("build_git_sha_absence_reason").is_none());
        }
    }
}

#[test]
fn manifest_creates_nothing_under_the_home_it_is_given() {
    let scratch = Scratch::directory("manifest-flag-untouched");
    let output = run_manifest(scratch.path());
    assert!(output.status.success());
    let entries: Vec<_> = std::fs::read_dir(scratch.path())
        .expect("scratch home is readable")
        .collect();
    assert!(
        entries.is_empty(),
        "--manifest must not create stores, logs or config: {entries:?}"
    );
}

#[test]
fn manifest_refuses_extra_arguments() {
    let binary = ckdev_binary(env!("CARGO_BIN_EXE_ck-plexus"));
    let output = bounded::child_output(
        Command::new(&binary)
            .args(["--manifest", "extra"])
            .env_clear(),
        std::time::Duration::from_secs(60),
        "test binary command",
    )
    .expect("run ck-plexus --manifest extra");
    assert_eq!(output.status.code(), Some(2));
}
