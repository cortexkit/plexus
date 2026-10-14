use std::{env, error::Error, fs, path::Path, process::Command};

use serde_json::Value;

pub(super) type BellardReport = Value;

pub(super) fn run() -> Result<BellardReport, Box<dyn Error>> {
    if let Some(path) = env::var_os("BELLARD_RESULT_PATH") {
        return Ok(serde_json::from_slice(&fs::read(path)?)?);
    }

    let binary = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/release/bellard-eval");
    if !binary.is_file() {
        return Err(format!(
            "Bellard evaluator is missing at {}. Run `cargo build -p bellard-eval --release` first.",
            binary.display()
        )
        .into());
    }

    let output = Command::new(binary).output()?;
    if !output.status.success() {
        return Err(format!(
            "bellard-eval failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}
