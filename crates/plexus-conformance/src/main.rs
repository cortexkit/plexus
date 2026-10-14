//! CLI entry for the plexus conformance harness.
//!
//! ```text
//! plexus-conformance run --fixture stub [--output evidence.json]
//! plexus-conformance run --fixture exa --live --credential-id apikey:exa \
//!     --subc-connection /path/to/subc.sock [--wire-trace trace.jsonl]
//! ```
//!
//! Default runs are stub-target and need no flags beyond `--fixture`. Live runs
//! (`--live` / `--endpoint`) exercise a real vendor endpoint with an
//! operator-provisioned vault reference supplied via `--credential-id`. Vendor
//! secrets are resolved over the vault route and never persisted by the harness.

#![forbid(unsafe_code)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use plexus_conformance::{
    record_route_connect, run_fixture_with_options, ConnectorFixture, RunOptions, TracingRoutePeer,
    TransportTarget, WireTraceSink,
};
use plexus_core::{CkcredCredentialSource, CredentialSource, SubcCkcredRoutePeer};
use serde_json::json;
use subc_protocol::BindIdentity;
use zeroize::Zeroizing;

fn main() -> ExitCode {
    // If a supervised CortexKit process launches this CLI, the inherited
    // SUBC_* variables identify that parent process to subc. Remove them so
    // this new process connects independently, not with its parent's credentials.
    // Scrub before argument parsing can construct any runtime or worker thread.
    env::remove_var("SUBC_MODULE_ID");
    env::remove_var("SUBC_LAUNCH_NONCE");
    env::remove_var("SUBC_LAUNCH_NONCE_FD");
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    run_args(env::args().skip(1).collect())
}

fn run_args(mut args: Vec<String>) -> Result<ExitCode, String> {
    if args.is_empty() {
        print_usage();
        return Ok(ExitCode::from(2));
    }
    let command = args.remove(0);
    match command.as_str() {
        "run" => {
            let mut fixture_name = None;
            let mut output = None;
            let mut live = false;
            let mut endpoint: Option<String> = None;
            let mut credential_id: Option<String> = None;
            let mut subc_connection: Option<PathBuf> = None;
            let mut wire_trace: Option<PathBuf> = None;
            let mut schema_out: Option<PathBuf> = None;
            let mut index = 0;
            while index < args.len() {
                match args[index].as_str() {
                    "--fixture" => fixture_name = Some(flag_value(&args, &mut index)?),
                    "--output" => output = Some(PathBuf::from(flag_value(&args, &mut index)?)),
                    "--live" => live = true,
                    "--endpoint" => endpoint = Some(flag_value(&args, &mut index)?),
                    "--credential-id" => credential_id = Some(flag_value(&args, &mut index)?),
                    "--subc-connection" => {
                        subc_connection = Some(PathBuf::from(flag_value(&args, &mut index)?));
                    }
                    "--schema-out" => {
                        schema_out = Some(PathBuf::from(flag_value(&args, &mut index)?));
                    }
                    "--wire-trace" => {
                        wire_trace = Some(PathBuf::from(flag_value(&args, &mut index)?));
                    }
                    "--help" | "-h" => {
                        print_usage();
                        return Ok(ExitCode::SUCCESS);
                    }
                    other => return Err(format!("unknown argument '{other}'")),
                }
                index += 1;
            }

            let fixture_name =
                fixture_name.ok_or_else(|| "--fixture <name> is required".to_string())?;
            let fixture = ConnectorFixture::by_name(&fixture_name)?;
            validate_subc_connection(subc_connection.is_some(), credential_id.is_some())?;

            // --live and --endpoint both override the transport target and are
            // mutually exclusive.
            if live && endpoint.is_some() {
                return Err("--live and --endpoint are mutually exclusive".to_string());
            }
            // A live vendor run needs operator credentials; refuse to run with
            // stubs so a missing reference is never masked by a green stub run.
            if live && credential_id.is_none() {
                return Err(
                    "live mode requires operator credentials; pass --credential-id <id>"
                        .to_string(),
                );
            }
            // A credential is only meaningful when the run can reach a real
            // vendor, so refuse it for an in-process stub run.
            //
            // Accepting it is not harmlessly redundant: the reference would be
            // resolved through the live vault credential route, fetching a real
            // vault credential to feed a stub server that cannot use it.
            //
            // It also keeps a worse shape unreachable. This command is invoked
            // once per fixture in a loop, by CI and by hand, so a credential
            // flag tolerated here is one edit away from being added to that
            // loop — at which point a single credential is sent to every
            // fixture's endpoint in turn. Refusing the meaningless combination
            // is what stops the dangerous one from being easy to write.
            if credential_id.is_some() && !live && endpoint.is_none() {
                return Err(
                    "--credential-id is only meaningful with --live or --endpoint; a stub run \
                     resolves no credential"
                        .to_string(),
                );
            }
            // The wire trace shadows vault credential route calls, which only happen with a
            // real (operator) credential source; an empty trace would be
            // misleading, so require a credential reference.
            if wire_trace.is_some() && credential_id.is_none() {
                return Err(
                    "--wire-trace requires live operator mode; pass --credential-id <id>"
                        .to_string(),
                );
            }

            let transport_override = if live {
                Some(TransportTarget::ManifestEndpoint)
            } else {
                endpoint.map(TransportTarget::Endpoint)
            };

            let (operator_credential_id, credential_source) = match &credential_id {
                Some(id) => {
                    if !plexus_core::credentials::valid_credential_id(id) {
                        return Err("invalid --credential-id".into());
                    }
                    let reference = id.clone();
                    let source =
                        build_live_credential_source(&subc_connection, wire_trace.as_deref())?;
                    (Some(reference), Some(source))
                }
                None => (None, None),
            };

            let options = RunOptions {
                transport_override,
                operator_credential_id,
                credential_source,
                schema_out,
            };
            let evidence = run_fixture_with_options(&fixture, options)?;
            let json = serde_json::to_string_pretty(&evidence)
                .map_err(|error| format!("serialize evidence: {error}"))?;
            if let Some(path) = output {
                // Evidence carries credential fingerprints and audit topology:
                // owner-only like the wire trace, enforced (not umask-derived).
                use std::io::Write;
                plexus_conformance::open_owner_only(&path)
                    .and_then(|mut file| file.write_all(json.as_bytes()))
                    .map_err(|error| format!("write evidence file: {error}"))?;
                eprintln!("wrote {}", path.display());
            } else {
                println!("{json}");
            }
            eprintln!("{}", evidence.human_summary());
            if evidence.passed {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(1))
            }
        }
        // Compare reviewed manifests against the vendors they describe. Kept a
        // separate command from `run` because it answers a different question:
        // `run` proves the governance pipeline behaves correctly given a
        // manifest, this asks whether the manifest is still true. A green
        // conformance suite says nothing about the second, since its stub
        // presents whatever the fixture declares.
        "drift" => {
            let mut catalog_dir: Option<PathBuf> = None;
            let mut manifest: Option<PathBuf> = None;
            let mut token_file: Option<PathBuf> = None;
            let mut index = 0;
            while index < args.len() {
                match args[index].as_str() {
                    "--catalog" => {
                        catalog_dir = Some(PathBuf::from(flag_value(&args, &mut index)?));
                    }
                    "--manifest" => manifest = Some(PathBuf::from(flag_value(&args, &mut index)?)),
                    "--token-file" => {
                        token_file = Some(PathBuf::from(flag_value(&args, &mut index)?));
                    }
                    "--help" | "-h" => {
                        print_usage();
                        return Ok(ExitCode::SUCCESS);
                    }
                    other => return Err(format!("unknown argument '{other}'")),
                }
                index += 1;
            }
            if catalog_dir.is_some() && manifest.is_some() {
                return Err("--catalog and --manifest are mutually exclusive".to_string());
            }
            // A token belongs to ONE vendor, so it may only be supplied for a
            // run that talks to one vendor.
            //
            // Without this, `drift --token-file <t>` sweeps the whole catalog
            // and sends that token to EVERY endpoint in it. Done once by
            // accident here: a GitHub token was sent to thirteen unrelated
            // vendors including resend.com and supabase.com. Nothing in the
            // output said so — the sweep simply reported more vendors as
            // reachable, which reads as better coverage.
            //
            // Refused rather than warned, because the damage is done by the
            // time any output is printed, and refused at argument parsing
            // rather than per-vendor because there is no safe partial version
            // of this: the first request has already left.
            if token_file.is_some() && manifest.is_none() {
                return Err(
                    "--token-file requires --manifest: a vendor credential must not be \
                     broadcast to every endpoint in the catalog"
                        .to_string(),
                );
            }
            // A raw vendor token, not a ckh_ capability handle: this check talks
            // to the vendor directly and never opens a store or a vault route,
            // so there is nothing here that could resolve a handle.
            let token = match &token_file {
                Some(path) => Some(read_token_file(path)?),
                None => None,
            };
            let token_bytes = token.as_ref().map(|value| value.as_slice());

            let paths = match (&catalog_dir, &manifest) {
                (Some(directory), _) => plexus_conformance::catalog_manifests(directory)?,
                (None, Some(path)) => vec![path.clone()],
                (None, None) => {
                    let default = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
                    plexus_conformance::catalog_manifests(&default)?
                }
            };

            println!(
                "checking {} manifest(s) against live vendors\n",
                paths.len()
            );
            let reports: Vec<_> = paths
                .iter()
                .map(|path| plexus_conformance::check_manifest(path, token_bytes))
                .collect();
            Ok(ExitCode::from(plexus_conformance::drift::render(&reports)))
        }
        "list" => {
            for name in ConnectorFixture::known_names() {
                println!("{name}");
            }
            Ok(ExitCode::SUCCESS)
        }
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command '{other}'")),
    }
}

/// Take the value of the flag at `args[*index]`, advancing past it.
///
/// A flag at the end of the line, or one followed by another flag, has no
/// value, and that is refused by name. Reading "the next argument, whatever it
/// is" let `--fixture --live` take `--live` as the fixture name and silently
/// drop the live switch, and let a trailing `--output` vanish, so the run went
/// ahead doing something other than what was typed.
fn flag_value(args: &[String], index: &mut usize) -> Result<String, String> {
    let flag = &args[*index];
    match args.get(*index + 1) {
        Some(value) if !value.starts_with("--") => {
            *index += 1;
            Ok(value.clone())
        }
        _ => Err(format!("{flag} needs a value")),
    }
}

/// Read a vendor token for the single-vendor drift probe without retaining it.
fn read_token_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut bytes = std::fs::read(path)
        .map_err(|error| format!("read token file '{}': {error}", path.display()))?;
    while matches!(bytes.last(), Some(b'\n' | b'\r' | b' ' | b'\t')) {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(format!("token file '{}' is empty", path.display()));
    }
    Ok(Zeroizing::new(bytes))
}

/// Build the real vault-backed credential source for a live run, optionally
/// wrapped in a wire-trace decorator. Mirrors the production composition: the
/// route module id comes from `PLEXUS_CKCRED_MODULE_ID` and the bind identity
/// from `PLEXUS_PROJECT_ROOT`; a missing route fails fast rather than falling
/// back to a stub.
fn build_live_credential_source(
    subc_connection: &Option<PathBuf>,
    wire_trace: Option<&Path>,
) -> Result<Arc<dyn CredentialSource>, String> {
    let connection_file = subc_connection.clone().ok_or_else(|| {
        "live mode requires --subc-connection <path> to the subc route".to_string()
    })?;
    let module_id = env::var("PLEXUS_CKCRED_MODULE_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "live mode requires PLEXUS_CKCRED_MODULE_ID to be set (the CKCRED route module id)"
                .to_string()
        })?;
    let identity = BindIdentity::new(
        env::var("PLEXUS_PROJECT_ROOT").unwrap_or_else(|_| "/".to_string()),
        "plexus",
        "conformance",
    );

    let connect_started = Instant::now();
    let connect_result =
        SubcCkcredRoutePeer::connect(&connection_file, module_id.clone(), identity);
    let connect_latency_ms =
        u64::try_from(connect_started.elapsed().as_millis()).unwrap_or(u64::MAX);

    match wire_trace {
        Some(trace_path) => {
            let sink = Arc::new(
                WireTraceSink::open(trace_path)
                    .map_err(|error| format!("open wire-trace file: {error}"))?,
            );
            let peer = match connect_result {
                Ok(peer) => {
                    record_route_connect(
                        &sink,
                        json!({
                            "connection_file": connection_file.display().to_string(),
                            "module_id": module_id,
                        }),
                        "ok",
                        connect_latency_ms,
                    );
                    peer
                }
                Err(error) => {
                    record_route_connect(
                        &sink,
                        json!({
                            "connection_file": connection_file.display().to_string(),
                            "module_id": module_id,
                        }),
                        &format!("error: {error:?}"),
                        connect_latency_ms,
                    );
                    return Err(format!("connect CKCRED route: {error:?}"));
                }
            };
            let tracing = TracingRoutePeer::new(Arc::new(peer), sink);
            Ok(Arc::new(CkcredCredentialSource::new(Arc::new(tracing))))
        }
        None => {
            let peer =
                connect_result.map_err(|error| format!("connect CKCRED route: {error:?}"))?;
            Ok(Arc::new(CkcredCredentialSource::new(Arc::new(peer))))
        }
    }
}

fn print_usage() {
    let fixtures = ConnectorFixture::known_names().join("|");
    eprintln!(
        "Usage:\n  plexus-conformance run --fixture <{fixtures}> [options]\n  plexus-conformance drift [--catalog <dir> | --manifest <path>]
  plexus-conformance drift --manifest <path> --token-file <path>\n  plexus-conformance list\n\n\
drift compares each reviewed manifest's declared actions against the tools its\nvendor actually serves. Exit 0 clean, 1 drift found, 2 the check could not run\n— an UNCHECKED vendor is never counted as clean.\n\n\
Options:\n  --fixture <name>          fixture to run (required)\n  --output <path>         write evidence JSON to a file\n  --live                  run against the reviewed manifest endpoint (requires --credential-id)\n  --endpoint <url>        run against an explicit endpoint (mutually exclusive with --live)\n  --credential-id <id>    vault reference (for example apikey:exa), not a secret or file path\n  --subc-connection <path> subc route connection file for the CKCRED route (live mode)\n  --wire-trace <path>     write a redacted CKCRED wire trace (0600, JSON lines; live mode)\n  --schema-out <path>     write the vendor's observed tool schemas (0600); the input for\n                          writing a manifest poll shape, which must never be guessed\n                          from vendor API docs\n  --token-file <path>     raw vendor token for drift discovery. REQUIRES --manifest:\n                          a token belongs to ONE vendor, and a catalog-wide sweep\n                          would send it to every endpoint in the catalog\n\n\
Live mode also reads PLEXUS_CKCRED_MODULE_ID (route module id) and optionally\nPLEXUS_PROJECT_ROOT from the environment."
    );
}

fn validate_subc_connection(has_connection: bool, has_credential: bool) -> Result<(), String> {
    if has_connection && !has_credential {
        Err("--subc-connection requires --credential-id".into())
    } else {
        Ok(())
    }
}

#[test]
fn a_subc_connection_without_a_credential_is_refused() {
    let error = run_args(vec![
        "run".into(),
        "--fixture".into(),
        "stub".into(),
        "--subc-connection".into(),
        "unused.sock".into(),
    ])
    .expect_err("unused subc connection must be refused");
    assert!(error.contains("--subc-connection requires --credential-id"));
    assert!(
        validate_subc_connection(true, false).is_err(),
        "unused subc connection must be refused"
    );
    assert!(validate_subc_connection(true, true).is_ok());
    assert!(validate_subc_connection(false, false).is_ok());
}

#[cfg(test)]
mod tests {
    use super::flag_value;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn a_flag_never_swallows_the_next_flag_or_vanishes_at_the_end() {
        let line = args(&["--fixture", "--live"]);
        let mut index = 0;
        assert_eq!(
            flag_value(&line, &mut index),
            Err("--fixture needs a value".to_string()),
            "a flag swallowed the next flag as its value"
        );

        let line = args(&["--fixture", "stub", "--output"]);
        let mut index = 0;
        assert_eq!(flag_value(&line, &mut index), Ok("stub".to_string()));
        assert_eq!(index, 1, "the value is consumed with its flag");
        let mut index = 2;
        assert_eq!(
            flag_value(&line, &mut index),
            Err("--output needs a value".to_string())
        );
    }
}
