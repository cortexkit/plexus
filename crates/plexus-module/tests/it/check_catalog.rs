use super::bounded;

use cortexkit_test_support::ckdev_binary;
use plexus_core::test_scratch::Scratch;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn shipped() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog")
}

fn check(path: &Path) -> Output {
    let binary = ckdev_binary(env!("CARGO_BIN_EXE_ck-plexus"));
    bounded::child_output(
        Command::new(&binary)
            .arg("--check-catalog")
            .arg(path)
            .env_clear(),
        std::time::Duration::from_secs(60),
        "test binary command",
    )
    .unwrap()
}

fn invalid_catalog(path: &Path) {
    fs::create_dir_all(path).unwrap();
    let source = fs::read_to_string(shipped().join("github_rest.jsonc")).unwrap();
    fs::write(path.join("valid.jsonc"), &source).unwrap();
    let normalized = subc_jsonc::jsonc_to_json(&source).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&normalized).unwrap();
    value["future_unknown_field"] = true.into();
    fs::write(path.join("bad.jsonc"), serde_json::to_vec(&value).unwrap()).unwrap();
}

#[test]
fn shipped_catalog_checks_without_supervisor_environment() {
    let output = check(&shipped());
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let mut count = 0;
    for entry in fs::read_dir(shipped()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "jsonc") {
            assert!(stdout
                .lines()
                .any(|line| line == format!("ok {}", path.display())));
            count += 1;
        }
    }
    assert!(count >= 10);
    assert!(stdout.contains(&format!("catalog: {count} ok, 0 refused, 0 I/O errors")));
}

#[test]
fn unknown_field_is_refused_by_real_binary() {
    let scratch = Scratch::directory("check-catalog-invalid");
    invalid_catalog(scratch.path());
    let output = check(scratch.path());
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.lines().any(|line| line.starts_with("refused ")
        && line.contains("bad.jsonc")
        && line.contains("future_unknown_field")));
    assert!(stdout
        .lines()
        .any(|line| line.starts_with("ok ") && line.contains("valid.jsonc")));
    assert!(stdout.contains("catalog: 1 ok, 1 refused, 0 I/O errors"));
}

#[test]
fn missing_directory_and_usage_exit_two() {
    let scratch = Scratch::directory("check-catalog-missing");
    assert_eq!(check(&scratch.path().join("absent")).status.code(), Some(2));
    for args in [
        vec!["--check-catalog"],
        vec!["--check-catalog", ".", "extra"],
    ] {
        let binary = ckdev_binary(env!("CARGO_BIN_EXE_ck-plexus"));
        let output = bounded::child_output(
            Command::new(&binary).args(args).env_clear(),
            std::time::Duration::from_secs(60),
            "test binary command",
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
    let binary = ckdev_binary(env!("CARGO_BIN_EXE_ck-plexus"));
    let output = bounded::child_output(
        Command::new(&binary).arg("--help").env_clear(),
        std::time::Duration::from_secs(60),
        "test binary command",
    )
    .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("--check-catalog <dir>"));
}

#[cfg(unix)]
#[test]
fn staging_refuses_catalog_before_signing_or_publication() {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::directory("stage-catalog-refusal");
    let root = scratch.path();
    for dir in [
        "scripts/lib",
        "target/release",
        "staging",
        "shim",
        "catalog",
        ".config/cortexkit",
    ] {
        fs::create_dir_all(root.join(dir)).unwrap();
    }
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/stage-binaries.sh"),
        root.join("scripts/stage-binaries.sh"),
    )
    .unwrap();
    for helper in ["private-copy.sh", "embedded-commit.py"] {
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../scripts/lib")
                .join(helper),
            root.join("scripts/lib").join(helper),
        )
        .unwrap();
    }
    let candidate = ckdev_binary(env!("CARGO_BIN_EXE_ck-plexus"));
    fs::copy(&candidate, root.join("target/release/ck-plexus")).unwrap();
    fs::write(
        root.join("target/release/ck-plexus-admin"),
        "#!/bin/sh\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(
        root.join("target/release/ck-plexus-admin"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    invalid_catalog(&root.join("catalog"));
    fs::write(root.join("staging/ck-plexus.current"), "old currency\n").unwrap();
    fs::write(root.join("staging/SIGNED.ck-plexus.old"), "old bytes\n").unwrap();
    // Isolate provenance and platform signing from the real candidate/catalog check.
    for (name, body) in [
        (
            "git",
            "case \"$*\" in *--porcelain*) ;; *) echo fixture-revision ;; esac",
        ),
        ("strings", "echo fixture-revision"),
        (
            "cp",
            "printf '%s\\n' \"$2\" > \"$HOME/catalog-copy-path\"; exec /bin/cp \"$@\"",
        ),
        ("codesign", "exit 77"),
    ] {
        let path = root.join("shim").join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let snapshot = || {
        let mut entries: Vec<_> = fs::read_dir(root.join("staging"))
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (
                    path.file_name().unwrap().to_owned(),
                    Sha256::digest(fs::read(path).unwrap()),
                )
            })
            .collect();
        entries.sort();
        entries
    };
    let before = snapshot();
    let run = |override_dir: bool| {
        let mut cmd = Command::new("bash");
        cmd.arg(root.join("scripts/stage-binaries.sh"))
            .args(["--marker", "none"])
            .env("HOME", root)
            .env("PLEXUS_STAGING_DIR", root.join("staging"))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    root.join("shim").display(),
                    std::env::var("PATH").unwrap()
                ),
            );
        if override_dir {
            cmd.arg("--catalog-dir").arg(root.join("catalog"));
        }
        bounded::child_output(
            &mut cmd,
            std::time::Duration::from_secs(60),
            "test binary command",
        )
        .unwrap()
    };
    let assert_refusal = |output: Output| {
        let copied = fs::read_to_string(root.join("catalog-copy-path"))
            .expect("the actual copy destination must be recorded");
        let copy = Path::new(copied.trim());
        assert_eq!(copy.file_name().unwrap(), "ckdev-plexus");
        let directory = copy.parent().unwrap();
        let temp_root = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        assert_eq!(directory.parent(), Some(temp_root.as_path()));
        assert!(
            directory
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("plexus-exec.")
        );
        let removed = !directory.exists();
        // Remove any captured copy before asserting, so a failed assertion
        // cannot leave a temporary executable behind.
        let _ = fs::remove_dir_all(directory);
        assert!(
            removed,
            "staging must remove its temporary ckdev catalog-check copy"
        );
        assert!(
            !root.join("target/release/ckdev-plexus").exists(),
            "the catalog check must not run from target/"
        );
        assert_eq!(
            snapshot(),
            before,
            "catalog refusal must leave staging listing and bytes unchanged"
        );
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("refusing: ck-plexus cannot check the deployed catalog"),
            "{stderr}"
        );
        assert!(
            stderr.contains("refused ")
                && stderr.contains("bad.jsonc")
                && stderr.contains("future_unknown_field"),
            "{stderr}"
        );
    };
    assert_refusal(run(true));
    let config = format!("{{ // deployed config\n\"modules\": {{\"plexus\": {{\"env\": {{\"PLEXUS_CATALOG_DIR\": {},}},}},}},}}", serde_json::to_string(&root.join("catalog")).unwrap());
    fs::write(root.join(".config/cortexkit/subc.jsonc"), config).unwrap();
    assert_refusal(run(false));
    fs::remove_file(root.join(".config/cortexkit/subc.jsonc")).unwrap();
    let output = run(false);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot check the deployed catalog"));
    assert_eq!(snapshot(), before);
}
