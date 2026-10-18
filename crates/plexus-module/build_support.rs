use std::{path::Path, process::Command};

pub fn dirty_command(workspace: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .current_dir(workspace)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args([
            "status",
            "--porcelain",
            "--",
            "crates",
            "Cargo.toml",
            "Cargo.lock",
        ]);
    command
}
