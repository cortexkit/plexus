use std::path::Path;

use subc_daemon::bootstrap::BootstrapConfig;

pub fn launcher(built: &Path) -> std::path::PathBuf {
    cortexkit_test_support::ckdev_binary(built)
}

pub fn daemon_config(connection: &Path, built: &Path) -> BootstrapConfig {
    let config = BootstrapConfig::new(connection, 0);
    #[cfg(target_os = "macos")]
    // The test launcher also implements the daemon's privacy trampoline
    // entry point. Use the original build for the trampoline and the ckdev
    // copy for the module: subc requires those to be distinct files.
    let config = config.with_privacy_trampoline(built);
    #[cfg(not(target_os = "macos"))]
    let _ = built;
    config
}
