//! `ck-plexus-admin` — the operator client for the plexus ceremony.
//!
//! Connections, grants, and the credential bindings behind them cannot be
//! created from the agent-facing tool surface by design: the enrollment secret
//! must never be a tool argument, and no agent may mint its own authority. They
//! live on the module's ManagementSurface role instead, and this is the client
//! that drives it.
//!
//! Ceremony commands use the running module's management surface. The offline
//! `import-store` exception acquires the source store's exclusive lease, so the
//! module must be stopped before durable state can cross to a fresh store.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{json, Value};

const DEFAULT_MODULE_ID: &str = "plexus";

/// Exit codes are distinguishable so a script can tell "the ceiling refused
/// this" from "the daemon was unreachable".
const EXIT_REFUSED: u8 = 1;
const EXIT_TRANSPORT: u8 = 2;
const EXIT_UNKNOWN: u8 = 3;
const EXIT_USAGE: u8 = 64;

fn main() -> ExitCode {
    // This is a standalone operator client, never a supervised module. When it
    // runs from a shell that is itself inside the fleet (an agent session), the
    // parent module's identity leaks in through the environment; the subc client
    // would present it as a consumer identity and the daemon would refuse the
    // mismatched launch nonce. Scrubbing them makes the connection a plain
    // Direct consumer, which is also the principal the ceremony requires.
    //
    // The nonce itself now reaches a module as a pipe named by
    // SUBC_LAUNCH_NONCE_FD, and a shell inside the fleet inherits that name
    // without the pipe. Removing SUBC_MODULE_ID already keeps the subc client
    // from reading a nonce at all; the descriptor name goes too so nothing in
    // this process is pointed at a descriptor it was never handed.
    std::env::remove_var("SUBC_MODULE_ID");
    std::env::remove_var("SUBC_LAUNCH_NONCE");
    std::env::remove_var("SUBC_LAUNCH_NONCE_FD");

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("{}", failure.message);
            ExitCode::from(failure.code)
        }
    }
}

#[derive(Debug)]
struct Failure {
    code: u8,
    message: String,
}

impl Failure {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_USAGE,
            message: message.into(),
        }
    }

    fn transport(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_TRANSPORT,
            message: message.into(),
        }
    }

    fn refused(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_REFUSED,
            message: message.into(),
        }
    }

    fn unknown(message: impl fmt::Display) -> Self {
        Self {
            code: EXIT_UNKNOWN,
            message: format!("outcome unknown: {message}; inspect daemon state before retrying"),
        }
    }
}

const USAGE: &str = "\
ck-plexus-admin — operator ceremony for the connectors plane

usage: ck-plexus-admin <command> --subc <connection file> [flags]

commands:
  recipients-add     widen send authority (preview by default, --apply to write)
  recipients-remove narrow send authority (preview by default, --apply to write)
  recipients-list   read a connection and agent's allowlist
  connector-home status
                 read the live Entorhinal role and plexus gate
  import-store   offline cutover to a new store (no --subc required)
  issue-ticket   place a vault credential reference and issue a binding ticket
  rebind-credential replace a connection's credential reference (preview by default)
  grant          mint authority for a connection, bounded by its ceiling
  widen-ceiling  add reviewed actions to a connection ceiling (preview by default)
  revoke-grant   remove a grant (idempotent)
  list-grants    show every grant held, with its vendor and state
  set-policy     create or update a policy for matching actions
  list-policies  show policies with their vendor and derived state
  remove-policy  remove a policy (idempotent)
  review-action  show the pinned and current schema, with property-level diff
  repin-action   re-pin one action after reviewing its current schema
  handle-grant   add write abilities (or, with --kind poll, poll reads) to one
                 imported GitHub handle
  handle-unbind  remove one repository from a GitHub handle
  handle-bind    bind more repositories to one imported GitHub handle
  delete-connection
                 delete a connection that has no live grants left
  set-web-search-limit
                 set a web search backend's calls per minute

import-store --from <old.db> --to <new.db>
    Stop the module first; the source lease enforces this. The destination must
    not exist. Carries durable authority and undelivered work, rehashes under JCS,
    and scrubs spent authority and audit history. Keep the old store as archive.
    Vault references are carried unchanged; revoked legacy bindings are scrubbed.

common flags (online commands):
  --subc <path>      daemon connection file (required)
  --module <id>      plexus module id (default: plexus)
  --version         print the client version without contacting the daemon

Grant, set-policy and remove-policy apply immediately; they do not support a
preview or --apply. Inspect list-grants/list-policies before changing authority.
Transport exit 2 means no daemon connection was made; exit 3 means the outcome
is unknown after submission. Inspect state before retrying an exit-3 operation.

recipients-add|recipients-remove --connection <id> [--agent <id>] --recipient <id> [--apply]
recipients-list --connection <id> [--agent <id>]
    Omit --agent for the module-only (SQL NULL) key, not all agents.
    Email addresses are trimmed and lowercased. Phone identifiers are only trimmed.
    Add/remove previews and applied changes are audited. Approval never adds an entry.

issue-ticket --app <key> --actions a,b,c|'*' [--credential-id <id>]
             [--risk read|write|destructive] [--connection <id>]
   Supply a vault credential id. Omit it when the
  reviewed manifest declares auth.mode=none. A reference must be readable by reserved:plexus.
  --risk and --actions set the connection's initial authority ceiling;
  every later grant must fit inside it. --actions is required; pass '*' to
  request every action the vendor declares, stored as a concrete list.

widen-ceiling --connection <id> --actions a,b,c [--apply]
    Adds only named, active reviewed actions within the existing risk ceiling.
    Without --apply, prints the current, added, unchanged and resulting actions
    and writes nothing. Grants are issued separately with grant. GitHub bot
    handle connections must use handle-grant instead.

grant --connection <id> --actions a,b,c|'*' [--grantee <principal>]
      [--kind invoke|connection_admin|poll|events_consume] [--risk ...]
      [--expires-ms <epoch_ms>]
    --actions is required; '*' grants everything the connection's ceiling
    allows.
    --kind poll authorizes a background trigger subscription. --expires-ms is
    OPTIONAL for every kind: a grant with no deadline runs until revoked, which
    is what an operator usually wants. Pass it only for authority you want to
    lapse on its own, and remember that a lapse stops the work SILENTLY -- the
    watches simply stop collecting, with no error anywhere. Revoking is the
    normal way to end a grant; use revoke-grant, or the grants list in the app.
  --kind events_consume lets another principal read and ack the events this
   connection already collected; --grantee is required (e.g. a supervised
  module as reserved:<module-id>). It grants no polling and no invoking.

revoke-grant --grant <id>

list-grants [--connection <id>] [--all]
    Every grant you hold, with the vendor named and its state derived
    (until_revoked | live | expired). Omit --connection for all of them.
    Poll authority need not expire, so revocation is how a watch ends --
    which only works if you can see what to revoke.
    Expired grants are hidden by default and counted in the summary line;
    --all shows them. They stay until their connection is deleted
    (delete-connection).

set-policy --connection <id> --action <selector> --effect allow|ask_first|block
           [--expires-ms <epoch_ms>]
    Set the matching policy. `allow` removes the approval requirement for
    matching actions; use it only when that is the intended posture. `*` matches
    every action on the connection.

list-policies [--connection <id>] [--all]
    Every policy you hold, with the vendor named and state derived
    (until_revoked | live | expired). Omit --connection for all of them.
    Expired policies are hidden and counted by default; --all includes them.

remove-policy --policy <id>

review-action --connection <id> --action <name>
    Shows the prior pinned hash, current hash, and added, removed, or type-changed
    input properties. Review this output before re-pinning.

repin-action --connection <id> --action <name> --expected-hash <hash>
    Re-pinning asserts that the operator has reviewed the current schema change.
    The expected hash must be the current hash shown by review-action.

handle-grant --handle <app_handle_id> --actions a,b,c --carrier <principal>
             --effect allow|ask_first|block [--apply]
    Adds the listed writes, plus every read and leg they imply, to the handle's
    connection ceiling, its agent's grants and the named module's grant (e.g.
    reserved:aft), with policies at the given effect. Without --apply this is a
    dry run that prints the plan and writes nothing. Remove authority with
    revoke-grant and remove-policy.

handle-grant --handle <app_handle_id> --actions a,b --kind poll [--apply]
    Grants scheduled-poll authority for the listed reviewed reads (for example
    github.issue_timeline.list) on the handle's connection, to the principal
    that owns the subscriptions. Widens the connection ceiling by exactly those
    reads. Writes are refused. Takes no --carrier or --effect. Without --apply
    this is a dry run that prints the plan and writes nothing.

handle-unbind --handle <app_handle_id> --repo <owner/name> [--apply]
  Preview by default; removing the last repository is allowed. Grants and policies stay.

handle-bind --handle <app_handle_id> --repositories owner/a,owner/b [--apply]
    Binds the listed repositories to the handle, so its agent's writes reach
    them. Each must share the handle's owner, be bound to no other handle, and
    be listed by the handle's own installation. All are bound or none is.
    Without --apply this is a dry run that prints the plan and writes nothing.

rebind-credential --connection <id> --credential-id <id> [--apply]
  Preview the current binding kind and new vault reference. --apply proves a
  vault read as reserved:plexus before replacing the binding; no bytes are printed.

delete-connection --connection <id> [--apply]
    Deletes the connection and every row keyed by it: catalog actions, expired
    grants, policies, requests, reservations, tickets, subscriptions, events
    and reconciliations. Its audit entries and grant revocations are kept;
    grant revocations remain durable, while audit rows age out with retention.
    Refused while any grant on it is live;
    revoke those first (list-grants --connection <id>, then revoke-grant).
    Refused for a GitHub App handle's connection (github-handle-*), which
    ends with its handle. Any status may be deleted, a revoked one included.
    Without --apply this is a dry run that prints the row counts it would
    delete and writes nothing.

set-web-search-limit --backend <name> --per-caller <n> --per-backend <n> [--apply]
    Sets how many web_search calls one caller (a principal, plus its agent
    when the call carries one) and all callers together may make per minute
    through a backend from the provider name table. Without a stored row the limits
    are 30 per caller and 120 per backend. Takes effect on the next search.
    Without --apply this is a dry run that prints the current and proposed
    limits and writes nothing.

set-web-search-order <name>... [--apply]
set-web-search-order --clear [--apply]
    Sets a nonempty order of distinct provider names. --clear takes no names
    and restores Exa compatibility mode. Without --apply, previews only.

set-web-search-allowance <name> <count> [--apply]
set-web-search-allowance <name> --clear [--apply]
    Sets one provider's monthly allowance, an integer from 1 to 10,000,000.
    --clear removes only that provider's allowance, retaining usage counts.
    Allowances are stored without an order but apply only in an order.
    Without --apply, previews only. There is no clear-all.
";

fn run(arguments: &[String]) -> Result<(), Failure> {
    let Some(command) = arguments.first() else {
        eprintln!("{USAGE}");
        return Err(Failure::usage("a command is required"));
    };
    if command == "--help" || command == "-h" || command == "help" {
        println!("{USAGE}");
        return Ok(());
    }
    if command == "--version" {
        println!("ck-plexus-admin {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let connector_position = if command == "connector-home" {
        let mut index = 1;
        while let Some(argument) = arguments.get(index) {
            if !argument.starts_with('-') {
                break;
            }
            index += if matches!(argument.as_str(), "--help" | "-h" | "--all" | "--apply") {
                1
            } else {
                2
            };
        }
        Some(index)
    } else {
        None
    };
    let connector_command = connector_position
        .map(|index| {
            arguments
                .get(index)
                .map(String::as_str)
                .ok_or_else(|| Failure::usage("connector-home requires status"))
        })
        .transpose()?;
    if connector_command == Some("claim") {
        return Err(Failure::usage(
            "connector-home claim was removed; use ck roles take connector_home",
        ));
    }
    let flag_arguments: Vec<String> = arguments
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(index, _)| Some(*index) != connector_position)
        .map(|(_, value)| value.clone())
        .collect();
    let flags = if matches!(
        command.as_str(),
        "set-web-search-order" | "set-web-search-allowance"
    ) {
        Flags::parse_positionals(&flag_arguments, true)?
    } else {
        Flags::parse(&flag_arguments)?
    };
    if flags.help {
        println!("{USAGE}");
        return Ok(());
    }
    if command == "import-store" {
        if let Some(flag) = flags.bare.first() {
            return Err(Failure::usage(format!("unknown import-store flag {flag}")));
        }
        for (flag, _) in &flags.values {
            if !matches!(flag.as_str(), "--from" | "--to") {
                return Err(Failure::usage(format!("unknown import-store flag {flag}")));
            }
            if flags.values.iter().filter(|(name, _)| name == flag).count() != 1 {
                return Err(Failure::usage(format!(
                    "duplicate import-store flag {flag}"
                )));
            }
        }
        let summary = plexus_core::import_store::import_store(
            Path::new(flags.required("--from")?),
            Path::new(flags.required("--to")?),
        )
        .map_err(Failure::refused)?;
        println!("table\tread\tcarried\tscrubbed\trecomputed (carried rows)");
        let mut totals = [0_u64; 4];
        for row in summary {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                row.table, row.read, row.carried, row.scrubbed, row.recomputed
            );
            for (total, count) in
                totals
                    .iter_mut()
                    .zip([row.read, row.carried, row.scrubbed, row.recomputed])
            {
                *total += count;
            }
        }
        println!(
            "TOTAL\t{}\t{}\t{}\t{}",
            totals[0], totals[1], totals[2], totals[3]
        );
        return Ok(());
    }
    if let Some(accepted) = accepted_flags(command) {
        flags.refuse_unknown(accepted)?;
    }
    if command == "issue-ticket" {
        validate_ticket_flags(&flags)?;
        let connection_file = flags.required("--subc")?;
        let module_id = flags.value("--module").unwrap_or(DEFAULT_MODULE_ID);
        let app = flags.required("--app")?;
        let auth_mode = catalog_app_auth_mode(Path::new(connection_file), module_id, app)?;
        let (method, params) = issue_ticket_request(&flags, &auth_mode)?;
        let response = call_management(Path::new(connection_file), module_id, method, params)?;
        return report(command, &response, &flags);
    }

    let (method, params) = match command.as_str() {
        "connector-home" => connector_home_request(connector_command.unwrap(), &flags)?,
        "grant" => grant_request(&flags)?,
        "widen-ceiling" => widen_ceiling_request(&flags)?,
        "revoke-grant" => revoke_grant_request(&flags)?,
        "list-grants" => list_grants_request(&flags)?,
        "set-policy" => set_policy_request(&flags)?,
        "list-policies" => list_policies_request(&flags)?,
        "remove-policy" => remove_policy_request(&flags)?,
        "review-action" => review_action_request(&flags)?,
        "repin-action" => repin_action_request(&flags)?,
        "handle-grant" => handle_grant_request(&flags)?,
        "handle-bind" => handle_bind_request(&flags)?,
        "handle-unbind" => handle_unbind_request(&flags)?,
        "delete-connection" => delete_connection_request(&flags)?,
        "rebind-credential" => rebind_credential_request(&flags)?,
        "set-web-search-limit" => set_web_search_limit_request(&flags)?,
        "set-web-search-order" => set_web_search_order_request(&flags)?,
        "set-web-search-allowance" => set_web_search_allowance_request(&flags)?,
        "recipients-add" | "recipients-remove" | "recipients-list" => {
            recipients_request(command, &flags)?
        }
        other => {
            eprintln!("{USAGE}");
            return Err(Failure::usage(format!("unknown command '{other}'")));
        }
    };
    let connection_file = flags.required("--subc")?;
    let module_id = flags.value("--module").unwrap_or(DEFAULT_MODULE_ID);
    let response = call_management(Path::new(connection_file), module_id, method, params)?;
    report(command, &response, &flags)
}

fn recipients_request(command: &str, flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let mut params =
        json!({"connection":flags.required("--connection")?,"agent":flags.value("--agent")});
    let method = match command {
        "recipients-add" => plexus_module::manifest::ADMIN_RECIPIENTS_ADD_OP,
        "recipients-remove" => plexus_module::manifest::ADMIN_RECIPIENTS_REMOVE_OP,
        "recipients-list" => {
            return Ok((plexus_module::manifest::ADMIN_RECIPIENTS_LIST_OP, params))
        }
        _ => unreachable!(),
    };
    params["recipient"] = json!(flags.required("--recipient")?);
    params["dry_run"] = json!(!flags.has("--apply"));
    Ok((method, params))
}

fn connector_home_request(command: &str, _flags: &Flags) -> Result<(&'static str, Value), Failure> {
    match command {
        "status" => Ok((plexus_module::connector_home::STATUS_OP, json!({}))),
        other => Err(Failure::usage(format!("unknown connector-home subcommand '{other}'; use ck roles take connector_home to take the role"))),
    }
}

/// Flags every online command accepts: the daemon connection file and the
/// module to call.
const COMMON_FLAGS: &[&str] = &["--subc", "--module"];

/// The command-specific flags, in addition to [`COMMON_FLAGS`]. Unknown flags
/// are refused so a mistyped selector cannot silently use a wider default.
fn accepted_flags(command: &str) -> Option<&'static [&'static str]> {
    Some(match command {
        "connector-home" => &[],
        // Accept --handle-file only to explain that --credential-id replaced it.
        "issue-ticket" => &[
            "--app",
            "--actions",
            "--credential-id",
            "--risk",
            "--connection",
            "--handle-file",
        ],
        "grant" => &[
            "--connection",
            "--actions",
            "--grantee",
            "--kind",
            "--risk",
            "--expires-ms",
        ],
        "revoke-grant" => &["--grant"],
        "widen-ceiling" => &["--connection", "--actions", "--apply"],
        "list-grants" => &["--connection", "--all"],
        "set-policy" => &["--connection", "--action", "--effect", "--expires-ms"],
        "list-policies" => &["--connection", "--all"],
        "remove-policy" => &["--policy"],
        "review-action" => &["--connection", "--action"],
        "repin-action" => &["--connection", "--action", "--expected-hash"],
        "handle-grant" => &[
            "--handle",
            "--actions",
            "--kind",
            "--carrier",
            "--effect",
            "--apply",
        ],
        "handle-bind" => &["--handle", "--repositories", "--apply"],
        "handle-unbind" => &["--handle", "--repo", "--apply"],
        "delete-connection" => &["--connection", "--apply"],
        "rebind-credential" => &["--connection", "--credential-id", "--apply"],
        "set-web-search-limit" => &["--backend", "--per-caller", "--per-backend", "--apply"],
        "set-web-search-order" | "set-web-search-allowance" => &["--clear", "--apply"],
        "recipients-add" | "recipients-remove" => {
            &["--connection", "--agent", "--recipient", "--apply"]
        }
        "recipients-list" => &["--connection", "--agent"],
        _ => return None,
    })
}

/// Parsed command line: flags with values, plus bare `--help`.
/// Flags that take no value. An allowlist, so a mistyped value-taking flag
/// still refuses rather than being read as a boolean.
const BARE_FLAGS: &[&str] = &["--all", "--apply", "--clear"];

struct Flags {
    values: Vec<(String, String)>,
    bare: Vec<String>,
    help: bool,
    positionals: Vec<String>,
}

impl Flags {
    fn parse(arguments: &[String]) -> Result<Self, Failure> {
        Self::parse_positionals(arguments, false)
    }

    fn parse_positionals(arguments: &[String], allow_positionals: bool) -> Result<Self, Failure> {
        let mut values = Vec::new();
        let mut bare = Vec::new();
        let mut help = false;
        let mut positionals = Vec::new();
        let mut index = 0;
        while index < arguments.len() {
            let argument = &arguments[index];
            if argument == "--help" || argument == "-h" {
                help = true;
                index += 1;
                continue;
            }
            if !argument.starts_with("--") {
                if allow_positionals {
                    positionals.push(argument.clone());
                    index += 1;
                    continue;
                }
                return Err(Failure::usage(format!("unexpected argument '{argument}'")));
            }
            // Value-less flags are an explicit allowlist rather than "any flag with
            // no value following it". A general rule would silently accept a
            // mistyped value-taking flag as a boolean and run with the default,
            // which is the reachability shape this CLI keeps producing.
            if BARE_FLAGS.contains(&argument.as_str()) {
                bare.push(argument.clone());
                index += 1;
                continue;
            }
            let Some(value) = arguments.get(index + 1) else {
                return Err(Failure::usage(format!("{argument} requires a value")));
            };
            if value.starts_with("--") {
                return Err(Failure::usage(format!(
                    "{argument} requires a value, got flag {value}"
                )));
            }
            values.push((argument.clone(), value.clone()));
            index += 2;
        }
        Ok(Self {
            values,
            bare,
            help,
            positionals,
        })
    }

    fn has(&self, name: &str) -> bool {
        self.bare.iter().any(|flag| flag == name)
    }

    /// Refuse any flag outside `accepted` and [`COMMON_FLAGS`], and any flag
    /// given twice. Both would otherwise be dropped silently: an unknown flag
    /// is never read, and `value` reads only the first of a repeated one.
    fn refuse_unknown(&self, accepted: &[&str]) -> Result<(), Failure> {
        let names = self
            .values
            .iter()
            .map(|(flag, _)| flag)
            .chain(self.bare.iter());
        let mut seen = BTreeSet::new();
        for flag in names {
            if !accepted.contains(&flag.as_str()) && !COMMON_FLAGS.contains(&flag.as_str()) {
                return Err(Failure::usage(format!(
                    "unknown flag {flag} for this command; see --help"
                )));
            }
            if !seen.insert(flag.as_str()) {
                return Err(Failure::usage(format!("duplicate flag {flag}")));
            }
        }
        Ok(())
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(flag, _)| flag == name)
            .map(|(_, value)| value.as_str())
    }

    fn required(&self, name: &str) -> Result<&str, Failure> {
        self.value(name)
            .ok_or_else(|| Failure::usage(format!("{name} is required")))
    }

    /// The required `--actions` list. There is no default: a missing flag
    /// once meant "every action the ceiling allows", so a typo in the flag
    /// name widened authority silently. An explicit `*` still asks for
    /// everything, and the module expands it to a concrete list before
    /// storing it.
    fn action_selectors(&self) -> Result<Vec<String>, Failure> {
        let actions: Vec<String> = self
            .required("--actions")?
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
        if actions.is_empty() {
            return Err(Failure::usage("--actions must name at least one action"));
        }
        Ok(actions)
    }
}

fn widen_ceiling_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let actions = flags.action_selectors()?;
    if actions.iter().any(|action| action.contains('*')) {
        return Err(Failure::usage(
            "--actions must name explicit actions, not '*'",
        ));
    }
    Ok((
        plexus_module::manifest::ADMIN_WIDEN_CEILING_OP,
        json!({
            "connection_id": flags.required("--connection")?,
            "actions": actions,
            "dry_run": !flags.has("--apply"),
        }),
    ))
}

fn widen_ceiling_lines(result: &Value) -> Vec<String> {
    vec![
        format!("connection: {}", text(&result["connection_id"])),
        format!("dry_run:    {}", result["dry_run"]),
        format!("applied:    {}", result["applied"]),
        format!("risk:       {} (unchanged)", text(&result["ceiling_risk"])),
        format!("current:    {}", list(&result["current_ceiling"])),
        format!("add:        {}", list(&result["added_actions"])),
        format!("unchanged:  {}", list(&result["unchanged_actions"])),
        format!("resulting:  {}", list(&result["resulting_ceiling"])),
        "Grants are separate; use grant to issue authority within this ceiling.".into(),
    ]
}

fn rebind_credential_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let id = flags.required("--credential-id")?;
    if !plexus_core::credentials::valid_credential_id(id) {
        return Err(Failure::usage("invalid --credential-id"));
    }
    Ok((
        plexus_module::manifest::ADMIN_REBIND_CREDENTIAL_OP,
        json!({
            "connection_id": flags.required("--connection")?,
            "credential_id": id,
            "apply": flags.has("--apply"),
        }),
    ))
}

fn rebind_credential_lines(result: &Value) -> Vec<String> {
    vec![
        format!("connection: {}", text(&result["connection_id"])),
        format!(
            "current binding kind: {}",
            text(&result["current_binding_kind"])
        ),
        format!("new reference: {}", text(&result["credential_id"])),
        if result["applied"].as_bool() == Some(true) {
            "applied".into()
        } else {
            "dry run; pass --apply to prove and replace".into()
        },
    ]
}

fn issue_ticket_request(flags: &Flags, auth_mode: &str) -> Result<(&'static str, Value), Failure> {
    let app = flags.required("--app")?;
    let credential_free = auth_mode.eq_ignore_ascii_case("none");
    if flags.value("--handle-file").is_some() {
        return Err(Failure::usage(
            "handle_bindings_removed: use --credential-id",
        ));
    }
    if credential_free && flags.value("--credential-id").is_some() {
        return Err(Failure::usage(
            "this vendor requires no credential; do not supply credential_id",
        ));
    }

    let mut params = json!({
        "app_key": app,
        "risk_ceiling": flags.value("--risk").unwrap_or("read"),
    });
    if let Some(id) = flags.value("--credential-id") {
        if !plexus_core::credentials::valid_credential_id(id) {
            return Err(Failure::usage("invalid --credential-id"));
        }
        params["credential_id"] = json!(id);
    } else if !credential_free {
        return Err(Failure::usage("required --credential-id"));
    }
    params["action_selectors"] = json!(flags.action_selectors()?);
    if let Some(connection) = flags.value("--connection") {
        params["connection_id"] = json!(connection);
    }
    Ok((plexus_module::manifest::ADMIN_ISSUE_TICKET_OP, params))
}

fn validate_ticket_flags(flags: &Flags) -> Result<(), Failure> {
    flags.required("--app")?;
    flags.action_selectors()?;
    if flags.value("--handle-file").is_some() {
        return Err(Failure::usage(
            "handle_bindings_removed: use --credential-id",
        ));
    }
    if let Some(id) = flags.value("--credential-id") {
        if !plexus_core::credentials::valid_credential_id(id) {
            return Err(Failure::usage("invalid --credential-id"));
        }
    }
    if !matches!(
        flags.value("--risk").unwrap_or("read"),
        "read" | "write" | "destructive"
    ) {
        return Err(Failure::usage(
            "--risk must be one of: read, write, destructive",
        ));
    }
    Ok(())
}

/// The grant kinds (`--kind`) this CLI will mint.
///
/// This one list is used for the membership check and the refusal message,
/// and a test checks it against the `--help` usage text. The check, the
/// message and the usage text once drifted apart: `poll` was added to the
/// check but not to the usage, so the CLI accepted a kind its own `--help`
/// said did not exist. A capability that works but cannot be discovered
/// looks absent to anyone reading the help.
///
/// - `invoke` lets the grantee call the connection's actions, and
///   `connection_admin` lets it configure or revoke the connection.
/// - `poll` authorizes a background trigger subscription that polls the
///   vendor on a timer. Only an operator can mint it: this CLI talks to the
///   module's operator-only management interface, which agents cannot reach
///   through the MCP gateway, so an agent cannot grant itself a standing
///   background loop. The expiry is optional; a grant without one lasts
///   until it is revoked.
/// - `events_consume` lets a NAMED OTHER principal read and acknowledge the
///   events that a connection's subscriptions already collected. Every read
///   in the store is limited to the principal that owns the row, so without
///   this grant a supervising consumer correctly sees no events, and its only
///   alternative is to set up its own subscription that polls the same vendor
///   a second time. It is less authority than the other three kinds (no
///   polling, no invoking, no credential use), because the vendor call
///   already happened under someone else's authority.
const GRANT_KINDS: [&str; 4] = ["invoke", "connection_admin", "poll", "events_consume"];
const POLICY_EFFECTS: [&str; 3] = ["allow", "ask_first", "block"];

fn grant_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let connection = flags.required("--connection")?;
    let kind = flags.value("--kind").unwrap_or("invoke");
    if !GRANT_KINDS.contains(&kind) {
        // Built from the same list the check uses, so a kind can never be
        // accepted while the refusal message denies it exists.
        return Err(Failure::usage(format!(
            "--kind must be one of: {}",
            GRANT_KINDS.join(", ")
        )));
    }
    if kind == "events_consume" {
        flags.required("--grantee")?;
    }
    let mut params = json!({
        "connection_id": connection,
        "authority_kind": kind,
        "risk_ceiling": flags.value("--risk").unwrap_or("read"),
        "action_selectors": flags.action_selectors()?,
    });
    if let Some(grantee) = flags.value("--grantee") {
        params["grantee_principal"] = json!(grantee);
    }
    if let Some(expires) = flags.value("--expires-ms") {
        let expires = future_expiry(expires)?;
        params["expires_at"] = json!(expires);
    }
    Ok((plexus_module::manifest::ADMIN_GRANT_OP, params))
}

/// Read every grant the operator holds, optionally narrowed to one connection.
/// Poll grants may have no deadline, so listing must make explicit revocation
/// possible without hiding the identities of the live grants.
fn list_grants_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let params = match flags.value("--connection") {
        Some(connection) => json!({ "connection_id": connection }),
        None => json!({}),
    };
    Ok((plexus_module::manifest::ADMIN_LIST_GRANTS_OP, params))
}

fn revoke_grant_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let grant = flags.required("--grant")?;
    Ok((
        plexus_module::manifest::ADMIN_REVOKE_GRANT_OP,
        json!({ "grant_id": grant }),
    ))
}

fn set_policy_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let connection = flags.required("--connection")?;
    let action_selector = flags.required("--action")?;
    let effect = flags.required("--effect")?;
    if !POLICY_EFFECTS.contains(&effect) {
        return Err(Failure::usage(
            "--effect must be one of: allow, ask_first, block",
        ));
    }
    let mut params = json!({
        "connection_id": connection,
        "action_selector": action_selector,
        "effect": effect,
    });
    if let Some(expires) = flags.value("--expires-ms") {
        let expires = future_expiry(expires)?;
        params["expires_at"] = json!(expires);
    }
    Ok((plexus_module::manifest::ADMIN_SET_POLICY_OP, params))
}

fn future_expiry(value: &str) -> Result<i64, Failure> {
    let expires: i64 = value
        .parse()
        .map_err(|_| Failure::usage("--expires-ms must be a future epoch milliseconds integer"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| {
            Failure::usage("cannot validate --expires-ms: system clock is before the epoch")
        })?;
    if i128::from(expires) <= now.as_millis() as i128 {
        return Err(Failure::usage(
            "--expires-ms must be in the future, in epoch milliseconds (not seconds)",
        ));
    }
    Ok(expires)
}

fn list_policies_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let params = match flags.value("--connection") {
        Some(connection) => json!({ "connection_id": connection }),
        None => json!({}),
    };
    Ok((plexus_module::manifest::ADMIN_LIST_POLICIES_OP, params))
}

fn remove_policy_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let policy = flags.required("--policy")?;
    Ok((
        plexus_module::manifest::ADMIN_REMOVE_POLICY_OP,
        json!({ "policy_id": policy }),
    ))
}

fn review_action_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let connection = flags.required("--connection")?;
    let action = flags.required("--action")?;
    Ok((
        plexus_module::manifest::ADMIN_REVIEW_ACTION_OP,
        json!({"connection_id": connection, "action": action}),
    ))
}

fn repin_action_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let connection = flags.required("--connection")?;
    let action = flags.required("--action")?;
    let expected_hash = flags.required("--expected-hash")?;
    Ok((
        plexus_module::manifest::ADMIN_REPIN_ACTION_OP,
        json!({
            "connection_id": connection,
            "action": action,
            "expected_schema_hash": expected_hash,
        }),
    ))
}

fn handle_grant_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let handle = flags.required("--handle")?;
    let actions = flags.action_selectors()?;
    match flags.value("--kind") {
        None | Some("invoke") => {}
        Some("poll") => {
            // The poll grant's grantee is the handle connection's own
            // principal and it mints no policy, so a carrier or effect would
            // be ignored; refuse them instead.
            for flag in ["--carrier", "--effect"] {
                if flags.value(flag).is_some() {
                    return Err(Failure::usage(format!(
                        "{flag} does not apply to --kind poll"
                    )));
                }
            }
            return Ok((
                plexus_module::manifest::GITHUB_GRANT_OP,
                json!({
                    "kind": "poll",
                    "app_handle_id": handle,
                    "actions": actions,
                    "dry_run": !flags.has("--apply"),
                }),
            ));
        }
        Some(_) => return Err(Failure::usage("--kind must be invoke or poll")),
    }
    // `--carrier`, not `--module`: `--module` is the common flag naming the
    // plexus module to call, so reusing it sent this op to a module named
    // after the carrier principal.
    let module = flags.required("--carrier")?;
    let effect = flags.required("--effect")?;
    if !POLICY_EFFECTS.contains(&effect) {
        return Err(Failure::usage(
            "--effect must be one of: allow, ask_first, block",
        ));
    }
    Ok((
        plexus_module::manifest::GITHUB_GRANT_OP,
        json!({
            "app_handle_id": handle,
            "actions": actions,
            "module": module,
            "effect": effect,
            "dry_run": !flags.has("--apply"),
        }),
    ))
}

fn handle_unbind_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    Ok((
        plexus_module::manifest::GITHUB_UNBIND_OP,
        json!({
            "app_handle_id": flags.required("--handle")?,
            "repository": flags.required("--repo")?,
            "dry_run": !flags.has("--apply"),
        }),
    ))
}

/// The repository shape is checked by the module, which refuses by name; the
/// CLI only splits the list. The command reads no `--module` of its own:
/// that is the common flag naming the plexus module to call.
fn handle_bind_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let handle = flags.required("--handle")?;
    let repositories: Vec<String> = flags
        .required("--repositories")?
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    if repositories.is_empty() {
        return Err(Failure::usage(
            "--repositories must name at least one owner/name",
        ));
    }
    Ok((
        plexus_module::manifest::GITHUB_BIND_OP,
        json!({
            "app_handle_id": handle,
            "repositories": repositories,
            "dry_run": !flags.has("--apply"),
        }),
    ))
}

/// Names the connection with `--connection`, never `--module`: that is the
/// common flag naming the plexus module to call.
fn delete_connection_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let connection = flags.required("--connection")?;
    Ok((
        plexus_module::manifest::ADMIN_DELETE_CONNECTION_OP,
        json!({
            "connection_id": connection,
            "dry_run": !flags.has("--apply"),
        }),
    ))
}

fn set_web_search_limit_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let backend = flags.required("--backend")?;
    let per_minute = |flag: &str| -> Result<u64, Failure> {
        let value = flags.required(flag)?;
        value
            .parse::<u64>()
            .ok()
            .filter(|count| *count > 0)
            .ok_or_else(|| Failure::usage(format!("{flag} must be a positive whole number")))
    };
    Ok((
        plexus_module::manifest::ADMIN_SET_WEB_SEARCH_LIMIT_OP,
        json!({
            "backend": backend,
            "per_caller_per_minute": per_minute("--per-caller")?,
            "per_backend_per_minute": per_minute("--per-backend")?,
            "dry_run": !flags.has("--apply"),
        }),
    ))
}

fn set_web_search_order_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let clear = flags.has("--clear");
    if clear && !flags.positionals.is_empty() {
        return Err(Failure::usage("--clear takes no provider names"));
    }
    if !clear && flags.positionals.is_empty() {
        return Err(Failure::usage(
            "set-web-search-order requires at least one name",
        ));
    }
    Ok((
        plexus_module::manifest::ADMIN_SET_WEB_SEARCH_ORDER_OP,
        json!({"providers": flags.positionals, "clear": clear, "dry_run": !flags.has("--apply")}),
    ))
}

fn set_web_search_allowance_request(flags: &Flags) -> Result<(&'static str, Value), Failure> {
    let clear = flags.has("--clear");
    if flags.positionals.len() != if clear { 1 } else { 2 } {
        return Err(Failure::usage(
            "set-web-search-allowance requires <name> <count>, or <name> --clear",
        ));
    }
    let mut params = json!({
        "provider": flags.positionals[0], "clear": clear, "dry_run": !flags.has("--apply"),
    });
    if !clear {
        let count = flags.positionals[1]
            .parse::<u32>()
            .ok()
            .filter(|count| {
                (1..=plexus_core::storage::web_search_store::MAX_WEB_SEARCH_ALLOWANCE)
                    .contains(count)
            })
            .ok_or_else(|| Failure::usage("count must be an integer from 1 to 10,000,000"))?;
        params["count"] = json!(count);
    }
    Ok((
        plexus_module::manifest::ADMIN_SET_WEB_SEARCH_ALLOWANCE_OP,
        params,
    ))
}

fn catalog_app_auth_mode(
    connection_file: &Path,
    module_id: &str,
    app_key: &str,
) -> Result<String, Failure> {
    let response = call_module(
        connection_file,
        subc_protocol::RouteTarget::ToolProvider {
            module_id: module_id.to_string(),
        },
        json!({"name": "catalog", "arguments": {"op": "apps"}}),
        "catalog call",
    )?;
    if let Some(error) = response.get("error") {
        let code = error["code"].as_str().unwrap_or("unknown_error");
        let message = error["message"].as_str().unwrap_or("no message");
        return Err(Failure::refused(format!("{code}: {message}")));
    }
    let apps = response["result"]["apps"]
        .as_array()
        .ok_or_else(|| Failure::transport("catalog response has no apps array"))?;
    let app = apps
        .iter()
        .find(|candidate| candidate["key"].as_str() == Some(app_key))
        .ok_or_else(|| {
            Failure::refused(format!(
                "unknown_app: app '{app_key}' is not in the connectable catalog"
            ))
        })?;
    app["auth_mode"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Failure::transport(format!("catalog app '{app_key}' has no auth_mode")))
}

fn call_management(
    connection_file: &Path,
    module_id: &str,
    method: &str,
    params: Value,
) -> Result<Value, Failure> {
    call_module(
        connection_file,
        subc_protocol::RouteTarget::ManagementSurface {
            module_id: module_id.to_string(),
        },
        json!({"method": method, "params": params}),
        "management call",
    )
}

/// Drive one module operation.
///
/// The connection discipline mirrors `plexus_core::credentials::SubcCkcredRoutePeer`:
/// a dedicated runtime owns the consumer's background I/O tasks for the whole
/// call, because a runtime dropped after connect leaves a dead connection whose
/// next call fails as NotSent.
fn call_module(
    connection_file: &Path,
    target: subc_protocol::RouteTarget,
    request: Value,
    operation: &str,
) -> Result<Value, Failure> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(|error| Failure::transport(format!("start runtime: {error}")))?;
    let body = serde_json::to_vec(&request)
        .map_err(|error| Failure::transport(format!("serialize request: {error}")))?;
    let connection_file = connection_file.to_path_buf();
    let operation = operation.to_string();
    runtime.block_on(async move {
        let consumer = subc_client_rs::SubcConsumer::connect(
            &connection_file,
            subc_client_rs::ConsumerOptions::default(),
        )
        .await
        .map_err(|error| {
            Failure::transport(format!("connect {}: {error}", connection_file.display()))
        })?;
        let bytes = consumer
            .call(
                target,
                subc_protocol::BindIdentity::new(
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
                    "ck-plexus-admin",
                    "operator",
                ),
                body,
                subc_client_rs::CallOptions::default(),
            )
            .await
            .map_err(|error| Failure::unknown(format!("{operation}: {error}")))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| Failure::unknown(format!("decode response: {error}")))
    })
}

/// Splits the complete grant list the module returned into the grants this
/// listing prints (expired grants are left out unless `--all` is given) and
/// the number left out. Kept separate from the printing so a test can check
/// both without capturing stdout; the count is the part that must stay in
/// step with the filter.
fn partition_grants(grants: &[Value], show_all: bool) -> (Vec<&Value>, usize) {
    let shown: Vec<&Value> = grants
        .iter()
        .filter(|grant| show_all || text(&grant["state"]) != "expired")
        .collect();
    let hidden = grants.len() - shown.len();
    (shown, hidden)
}

/// Always names what was withheld. A filter that says nothing is
/// indistinguishable from an empty set.
fn grants_summary(shown: usize, hidden: usize) -> String {
    if hidden == 0 {
        format!("{shown} grant(s)")
    } else {
        format!("{shown} grant(s); {hidden} expired hidden, --all to show")
    }
}

/// Print a refusal from the module as its own code and message, unchanged, so
/// an operator can tell a request the module refused on its merits (for
/// example `risk_above_ceiling`, a grant asking for more risk than the
/// connection allows) from a store that could not be reached.
fn report(command: &str, response: &Value, flags: &Flags) -> Result<(), Failure> {
    // A warning rides beside the real answer (for example: the change was
    // applied but its audit row could not be written), so it is printed
    // whether the answer is a result or a refusal.
    if let Some(warning) = response.get("warning") {
        eprintln!(
            "warning: {}: {}",
            warning["code"].as_str().unwrap_or("unknown_warning"),
            warning["message"].as_str().unwrap_or("no message")
        );
    }
    if let Some(error) = response.get("error") {
        let code = error["code"].as_str().unwrap_or("unknown_error");
        let message = error["message"].as_str().unwrap_or("no message");
        return Err(Failure::refused(format!("{code}: {message}")));
    }
    let result = response
        .get("result")
        .filter(|value| value.is_object())
        .ok_or_else(|| {
            Failure::unknown("malformed management response: expected result object or error")
        })?;
    match command {
        "recipients-add" | "recipients-remove" | "recipients-list" => println!(
            "{}",
            serde_json::to_string_pretty(result).expect("recipient response JSON")
        ),
        "issue-ticket" => {
            println!("ticket_id:     {}", text(&result["ticket_id"]));
            println!("connection_id: {}", text(&result["connection_id"]));
            println!("expires_at:    {}", text(&result["expires_at"]));
            println!(
                "ceiling:       risk={} actions={}",
                text(&result["ceiling"]["risk"]),
                list(&result["ceiling"]["action_selectors"])
            );
            // Both spellings, because the operator's next call lands on
            // whichever surface they are holding: the module advertises
            // `connections`, and the MCP gateway exposes it as
            // `{namespace}_{tool}` with the namespace defaulting to the module
            // id. Naming only one sends half the readers to a tool that does
            // not exist on their side.
            println!("next:          connections op=connect with this ticket_id");
            println!("               (over MCP the tool is named plexus_connections)");
        }
        "grant" => {
            for line in grant_lines(&result["grant"]) {
                println!("{line}");
            }
        }
        "list-grants" => {
            let grants = result["grants"].as_array().cloned().unwrap_or_default();
            if grants.is_empty() {
                println!("no grants");
                return Ok(());
            }
            // Expired grants are hidden unless --all. This list is READ TO DECIDE
            // WHAT TO REVOKE, and an expired grant carries no authority, so it is
            // never the answer to that question -- while the rows crowd out the ones
            // that are. Nothing is deleted: a grant row is the only record that
            // authority was once held, and audit entries reference grant ids.
            //
            // The wire still returns every grant. A DATA SURFACE SHOULD BE COMPLETE
            // AND A VIEW SHOULD FILTER, so an app rendering the same op decides for
            // itself rather than inheriting this terminal's choice.
            let (shown, hidden) = partition_grants(&grants, flags.has("--all"));
            // One line per grant, widest-first, because this is read to decide
            // WHAT TO REVOKE: the vendor and what it authorizes are the fields an
            // operator scans, and the id is what they then paste into revoke-grant.
            for grant in &shown {
                println!(
                    "{}  {}  {}  {}  {}",
                    text(&grant["grant_id"]),
                    text(&grant["app_key"]),
                    text(&grant["authority_kind"]),
                    text(&grant["state"]),
                    list(&grant["action_selectors"]),
                );
            }
            // A filter that says nothing is indistinguishable from an empty set, so
            // the hidden count is always reported -- the same reason a zero needs its
            // denominator. Without it, "3 grant(s)" on a box holding 63 reads as the
            // whole truth.
            println!("{}", grants_summary(shown.len(), hidden));
        }
        "set-policy" => {
            let policy = &result["policy"];
            println!("policy_id:       {}", text(&policy["policy_id"]));
            println!("connection_id:   {}", text(&policy["connection_id"]));
            println!("action_selector: {}", text(&policy["action_selector"]));
            println!("effect:          {}", text(&policy["effect"]));
            println!("expires_at:      {}", text(&policy["expires_at"]));
        }
        "list-policies" => {
            let policies = result["policies"].as_array().cloned().unwrap_or_default();
            if policies.is_empty() {
                println!("no policies");
                return Ok(());
            }
            let (shown, hidden) = partition_grants(&policies, flags.has("--all"));
            for policy in &shown {
                println!(
                    "{}  {}  {}  {}  {}  {}",
                    text(&policy["policy_id"]),
                    text(&policy["app_key"]),
                    text(&policy["action_selector"]),
                    text(&policy["effect"]),
                    text(&policy["state"]),
                    text(&policy["expires_at"]),
                );
            }
            println!(
                "{} policy(s), {hidden} expired hidden (use --all)",
                shown.len()
            );
        }
        "remove-policy" => {
            if result["removed"].as_bool().unwrap_or(false) {
                println!("policy removed");
            } else {
                println!("no such policy (already removed)");
            }
        }
        "review-action" => {
            for line in review_lines(result) {
                println!("{line}");
            }
        }
        "handle-grant" => {
            for line in handle_grant_lines(result) {
                println!("{line}");
            }
        }
        "widen-ceiling" => {
            for line in widen_ceiling_lines(result) {
                println!("{line}");
            }
        }
        "handle-unbind" => {
            println!(
                "{}",
                serde_json::to_string_pretty(result).unwrap_or_default()
            );
        }
        "handle-bind" => {
            for line in handle_bind_lines(result) {
                println!("{line}");
            }
        }
        "rebind-credential" => {
            for line in rebind_credential_lines(result) {
                println!("{line}");
            }
        }
        "delete-connection" => {
            for line in delete_connection_lines(result) {
                println!("{line}");
            }
        }
        "set-web-search-limit" => {
            for line in web_search_limit_lines(result) {
                println!("{line}");
            }
        }
        "set-web-search-order" | "set-web-search-allowance" => {
            for line in web_search_change_lines(result) {
                println!("{line}");
            }
        }
        "repin-action" => {
            println!("action re-pinned: {}", text(&result["action"]));
            println!("status:          {}", text(&result["status"]));
            println!("schema_hash:     {}", text(&result["schema_hash"]));
        }
        "connector-home" => {
            println!(
                "{}",
                serde_json::to_string_pretty(result).unwrap_or_default()
            );
        }
        "revoke-grant" => {
            let removed = result["revoked"].as_bool().unwrap_or(false);
            if removed {
                println!("grant revoked");
            } else {
                println!("no such grant (already revoked)");
            }
        }
        // A command with no renderer prints the raw reply. Before this arm
        // existed, every unmatched command fell into the revoke-grant
        // wording and reported "no such grant" for replies that had
        // nothing to do with grants.
        _ => {
            println!(
                "{}",
                serde_json::to_string_pretty(result).unwrap_or_default()
            );
        }
    }
    Ok(())
}

/// The lines the `grant` command prints, built rather than printed.
///
/// Extracted so the mint-time drain notice can be ASSERTED. A bare `println!`
/// is invisible to every test, so a warning that exists only as a print can be
/// deleted in a refactor with the whole suite green -- and this particular
/// warning is the only place an operator learns what the grant actually does.
fn grant_lines(grant: &Value) -> Vec<String> {
    let mut lines = vec![
        format!("grant_id:      {}", text(&grant["grant_id"])),
        format!("connection_id: {}", text(&grant["connection_id"])),
        format!("grantee:       {}", text(&grant["grantee_principal"])),
        format!("authority:     {}", text(&grant["authority_kind"])),
        format!(
            "ceiling:       risk={} actions={}",
            text(&grant["risk_ceiling"]),
            list(&grant["action_selectors"])
        ),
    ];
    // The drain consequence is INVISIBLE IN THE FLAG SYNTAX, so it is stated at
    // the moment of minting rather than left to documentation.
    // `--kind events_consume` reads like a read capability; what it actually
    // does is hand acknowledgement of this connection's events to another
    // principal, and because ack clears the payload, rows the grantee drains
    // leave the OWNER's view too.
    //
    // An operator who did not intend to designate a drainer needs to learn that
    // here, while the decision is still in front of them, rather than from a
    // surprised reader wondering where the events went.
    if text(&grant["authority_kind"]) == plexus_core::AUTHORITY_EVENTS_CONSUME {
        lines.push(String::new());
        lines.push(format!(
            "  NOTE: this designates {} as the DRAINER of {} events.",
            text(&grant["grantee_principal"]),
            text(&grant["connection_id"])
        ));
        lines.push(
            "  Acknowledging clears an event's payload, so rows it acks leave this".to_string(),
        );
        lines.push("  connection's own view as well. Mint it for one consumer.".to_string());
    }
    lines
}

/// The lines `handle-grant` prints for a plan, applied or not.
fn handle_grant_lines(plan: &Value) -> Vec<String> {
    let mut lines = vec![
        format!(
            "{}  {}",
            if plan["dry_run"].as_bool().unwrap_or(true) {
                "dry run (nothing written; rerun with --apply):"
            } else {
                "applied:"
            },
            text(&plan["app_handle_id"])
        ),
        format!("connection_id:     {}", text(&plan["connection_id"])),
        format!("expanded actions:  {}", list(&plan["expanded"])),
        format!("ceiling additions: {}", list(&plan["ceiling_additions"])),
    ];
    for grant in plan["grants"].as_array().into_iter().flatten() {
        lines.push(format!(
            "grant  {} {} {} {}",
            text(&grant["level"]),
            text(&grant["op"]),
            text(&grant["grant_id"]),
            if grant["actions"].is_null() {
                text(&grant["action"])
            } else {
                list(&grant["actions"])
            }
        ));
    }
    for policy in plan["policies"].as_array().into_iter().flatten() {
        lines.push(format!(
            "policy {} {} {} {}",
            text(&policy["level"]),
            text(&policy["op"]),
            text(&policy["action"]),
            text(&policy["effect"])
        ));
    }
    lines
}

/// The lines `handle-bind` prints for a plan, applied or not.
fn handle_bind_lines(plan: &Value) -> Vec<String> {
    let generation = &plan["repo_binding_generation"];
    vec![
        format!(
            "{}  {}",
            if plan["dry_run"].as_bool().unwrap_or(true) {
                "dry run (nothing written; rerun with --apply):"
            } else {
                "applied:"
            },
            text(&plan["app_handle_id"])
        ),
        format!("connection_id:      {}", text(&plan["connection_id"])),
        format!("bind:               {}", list(&plan["add"])),
        format!("already bound:      {}", list(&plan["already_bound"])),
        format!(
            "binding generation: {} -> {} (+{})",
            text(&generation["before"]),
            text(&generation["after"]),
            text(&generation["delta"])
        ),
    ]
}

/// The lines `delete-connection` prints, applied or dry run: a headline, the
/// connection's vendor and status, then one line per table it deletes from.
fn delete_connection_lines(result: &Value) -> Vec<String> {
    let (headline, verb) = match text(&result["outcome"]).as_str() {
        "deleted" => ("applied:", "deleted"),
        _ => (
            "dry run (nothing written; rerun with --apply):",
            "would delete",
        ),
    };
    let mut lines = vec![
        format!("{headline}  {}", text(&result["connection_id"])),
        format!("app_key: {}", text(&result["app_key"])),
        format!("status:  {}", text(&result["status"])),
    ];
    if let Some(rows) = result["rows"].as_object() {
        for (table, count) in rows {
            lines.push(format!("{verb} {table}: {}", text(count)));
        }
    }
    lines.push("kept: audit_journal and grant_revocations rows (audit retention)".to_string());
    lines
}

/// The lines `set-web-search-limit` prints, dry run or applied.
fn web_search_limit_lines(result: &Value) -> Vec<String> {
    let applied = !result["dry_run"].as_bool().unwrap_or(true);
    let (before, before_source, after) = if applied {
        (
            &result["previous"],
            &result["previous_source"],
            &result["current"],
        )
    } else {
        (
            &result["current"],
            &result["current_source"],
            &result["proposed"],
        )
    };
    vec![
        format!(
            "{}  {}",
            if applied {
                "applied:"
            } else {
                "dry run (nothing written; rerun with --apply):"
            },
            text(&result["backend"])
        ),
        format!(
            "per caller per minute:  {} -> {}",
            text(&before["per_caller_per_minute"]),
            text(&after["per_caller_per_minute"])
        ),
        format!(
            "per backend per minute: {} -> {}",
            text(&before["per_backend_per_minute"]),
            text(&after["per_backend_per_minute"])
        ),
        format!("previous values were:  {}", text(before_source)),
    ]
}

fn web_search_change_lines(result: &Value) -> Vec<String> {
    vec![
        format!(
            "{} {}",
            if result["dry_run"].as_bool().unwrap_or(true) {
                "dry run (nothing written; rerun with --apply):"
            } else {
                "applied:"
            },
            result
                .get("provider")
                .and_then(Value::as_str)
                .unwrap_or("provider order")
        ),
        format!("previous: {}", result["previous"]),
        format!("new:      {}", result["new"]),
    ]
}

fn text(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn list(value: &Value) -> String {
    value
        .as_array()
        .map(|values| values.iter().map(text).collect::<Vec<_>>().join(","))
        .unwrap_or_else(|| text(value))
}

/// Render the review decision from raw JSON schemas instead of relying on a
/// vendor-specific schema renderer. Properties are the only shape the operator
/// can compare uniformly across the catalog, and a type change there can make a
/// previously valid poll argument unsafe even when its key still exists.
fn review_lines(result: &Value) -> Vec<String> {
    let mut lines = vec![
        format!("pinned_hash:  {}", text(&result["pinned_schema_hash"])),
        format!("current_hash: {}", text(&result["current_schema_hash"])),
    ];
    let Some(previous) = result["reviewed_schema_json"].as_object() else {
        lines.push("property diff: unavailable (no prior schema was recorded)".to_string());
        return lines;
    };
    let current = &result["current_schema_json"];
    let previous = Value::Object(previous.clone());
    let (added, removed, type_changed) = schema_property_diff(&previous, current);
    if added.is_empty() && removed.is_empty() && type_changed.is_empty() {
        lines.push("property diff: no added, removed, or type-changed top-level keys; required, enum and nested schema changes are not shown".to_string());
        return lines;
    }
    for key in added {
        lines.push(format!("added:        {key}"));
    }
    for key in removed {
        lines.push(format!("removed:      {key}"));
    }
    for (key, before, after) in type_changed {
        lines.push(format!("type changed: {key} ({before} -> {after})"));
    }
    lines
}

type PropertyDiff = (Vec<String>, Vec<String>, Vec<(String, String, String)>);

fn schema_property_diff(previous: &Value, current: &Value) -> PropertyDiff {
    let previous_properties = previous.get("properties").and_then(Value::as_object);
    let current_properties = current.get("properties").and_then(Value::as_object);
    let keys: BTreeSet<&str> = previous_properties
        .iter()
        .flat_map(|properties| properties.keys().map(String::as_str))
        .chain(
            current_properties
                .iter()
                .flat_map(|properties| properties.keys().map(String::as_str)),
        )
        .collect();
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut type_changed = Vec::new();
    for key in keys {
        match (
            previous_properties.and_then(|properties| properties.get(key)),
            current_properties.and_then(|properties| properties.get(key)),
        ) {
            (None, Some(_)) => added.push(key.to_string()),
            (Some(_), None) => removed.push(key.to_string()),
            (Some(before), Some(after)) if schema_type(before) != schema_type(after) => {
                type_changed.push((key.to_string(), schema_type(before), schema_type(after)));
            }
            _ => {}
        }
    }
    (added, removed, type_changed)
}

fn schema_type(schema: &Value) -> String {
    schema
        .get("type")
        .map(text)
        .unwrap_or_else(|| "unspecified".to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_does_not_contact_the_daemon() {
        super::run(&["--version".to_owned()]).unwrap();
    }
    #[test]
    fn post_submission_failures_warn_against_blind_retries() {
        let error = super::Failure::unknown("connection closed before reply");
        assert_eq!(error.code, 3);
        assert!(error.message.contains("outcome unknown"));
        assert!(error
            .message
            .contains("inspect daemon state before retrying"));
        assert_eq!(super::Failure::transport("connect failed").code, 2);
    }
    #[test]
    fn malformed_management_replies_are_not_success() {
        for response in [serde_json::json!({}), serde_json::json!({"result": null})] {
            let error = super::report("grant", &response, &flags(&[])).unwrap_err();
            assert_eq!(error.code, super::EXIT_UNKNOWN);
        }
    }

    #[test]
    fn import_store_refuses_unconsumed_bare_flags_before_opening_a_store() {
        for bare in ["--all", "--apply"] {
            let args = [
                "import-store",
                "--from",
                "/absent/from",
                "--to",
                "/absent/to",
                bare,
            ]
            .map(str::to_owned);
            let error = super::run(&args).unwrap_err();
            assert_eq!(error.code, super::EXIT_USAGE);
            assert!(error.message.contains(bare), "{}", error.message);
        }
    }

    #[test]
    fn consume_grants_require_an_explicit_grantee() {
        let error = super::grant_request(&flags(&[
            "--connection",
            "c",
            "--actions",
            "*",
            "--kind",
            "events_consume",
        ]))
        .unwrap_err();
        assert!(error.message.contains("--grantee"));
    }

    #[test]
    fn expiry_must_be_a_future_epoch_millisecond_timestamp() {
        for expiry in ["0", "-1", "1767225600", "1000000000000"] {
            for command in ["grant", "set-policy"] {
                let flags = flags(&[
                    "--connection",
                    "c",
                    "--actions",
                    "*",
                    "--action",
                    "a",
                    "--effect",
                    "allow",
                    "--expires-ms",
                    expiry,
                ]);
                let result = if command == "grant" {
                    super::grant_request(&flags)
                } else {
                    super::set_policy_request(&flags)
                };
                assert!(result.is_err(), "{command} accepted {expiry}");
            }
        }
    }

    #[test]
    fn ticket_flags_are_validated_before_catalog_contact() {
        let args = [
            "issue-ticket",
            "--subc",
            "/absent/daemon",
            "--app",
            "linear",
        ]
        .map(str::to_owned);
        let error = super::run(&args).unwrap_err();
        assert_eq!(error.code, super::EXIT_USAGE);
        assert!(error.message.contains("--actions"));
    }

    #[test]
    fn connector_home_accepts_common_flags_before_its_subcommand() {
        let args = ["connector-home", "--subc", "/absent/daemon", "claim"].map(str::to_owned);
        let error = super::run(&args).unwrap_err();
        assert_eq!(error.code, super::EXIT_USAGE);
        assert!(
            error.message.contains("claim was removed"),
            "{}",
            error.message
        );
    }
    use super::*;

    #[test]
    fn value_flags_cannot_consume_the_following_flag() {
        let error = Flags::parse(&["--reason".into(), "--apply".into()])
            .err()
            .expect("missing reason value must be refused");
        assert_eq!(error.code, EXIT_USAGE);
        assert!(
            error.message.contains("requires a value"),
            "a value-taking flag must not swallow --apply"
        );
        let parsed =
            Flags::parse(&["--reason".into(), "bootstrap".into(), "--apply".into()]).unwrap();
        assert_eq!(parsed.value("--reason"), Some("bootstrap"));
        assert!(parsed.has("--apply"));
    }

    #[test]
    fn import_store_is_offline_and_requires_distinct_path_flags() {
        let args = |values: &[&str]| values.iter().map(|v| v.to_string()).collect::<Vec<_>>();
        let missing = run(&args(&["import-store"])).unwrap_err();
        assert_eq!(missing.code, EXIT_USAGE);
        assert!(missing.message.contains("--from"));
        let missing = run(&args(&["import-store", "--from", "old.db"])).unwrap_err();
        assert!(missing.message.contains("--to"));
        let refused = run(&args(&[
            "import-store",
            "--from",
            "nonexistent-import-source.db",
            "--to",
            "new.db",
        ]))
        .unwrap_err();
        assert_eq!(refused.code, EXIT_REFUSED);
        assert!(refused.message.contains("source"));
        assert!(!refused.message.contains("--subc"));
        let duplicate = run(&args(&[
            "import-store",
            "--from",
            "a",
            "--from",
            "b",
            "--to",
            "c",
        ]))
        .unwrap_err();
        assert!(duplicate.message.contains("duplicate"));
        let online = run(&args(&["import-store", "--subc", "daemon"])).unwrap_err();
        assert!(online.message.contains("unknown import-store flag"));
    }

    fn flags(pairs: &[&str]) -> Flags {
        Flags::parse(
            &pairs
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        )
        .expect("flags parse")
    }

    /// The drain notice appears for `events_consume` and for no other kind.
    ///
    /// Both arms, because the notice's value is that it is SPECIFIC. One arm
    /// would pass against a renderer that prints it unconditionally, and a
    /// warning shown on every grant is one an operator learns to skip -- which
    /// costs more than never having printed it, since it also dilutes the
    /// warnings that are load-bearing.
    ///
    /// Asserted on the substance rather than on exact wording: the grantee, the
    /// connection, and that acking removes rows from this connection's own view.
    /// Pinning the sentence would make every copy edit a test failure while
    /// proving nothing more.
    #[test]
    fn the_drain_notice_is_shown_only_for_a_consume_grant() {
        let grant = |kind: &str| {
            serde_json::json!({
                "grant_id": "grant-1",
                "connection_id": "conn-github",
                "grantee_principal": "reserved:prefrontal-core",
                "authority_kind": kind,
                "risk_ceiling": "read",
                "action_selectors": ["list_issues"],
            })
        };

        let consume = grant_lines(&grant("events_consume")).join("\n");
        assert!(
            consume.contains("DRAINER"),
            "a consume grant must state that it designates a drainer: {consume}"
        );
        assert!(
            consume.contains("reserved:prefrontal-core") && consume.contains("conn-github"),
            "the notice must name WHO drains WHAT: {consume}"
        );
        assert!(
            consume.contains("leave this"),
            "the notice must say the rows leave this connection's own view: {consume}"
        );

        // Every other kind must stay quiet.
        for kind in ["invoke", "connection_admin", "poll"] {
            let other = grant_lines(&grant(kind)).join("\n");
            assert!(
                !other.contains("DRAINER"),
                "{kind} must not carry the drain notice: {other}"
            );
        }
    }

    /// `--actions` has no default on `grant` or `issue-ticket`. A missing
    /// flag used to mean `*`, so a typo in the flag name granted every action
    /// up to the requested risk; an explicit `*` is the only way to ask for
    /// everything now.
    #[test]
    fn omitted_actions_are_refused_and_an_explicit_wildcard_is_kept() {
        let grant = grant_request(&flags(&["--connection", "conn-1", "--risk", "write"]))
            .expect_err("a grant with no --actions must be refused");
        assert_eq!(grant.code, EXIT_USAGE);
        assert!(grant.message.contains("--actions"), "{}", grant.message);

        let ticket = issue_ticket_request(&flags(&["--app", "deepwiki"]), "None")
            .expect_err("a ticket with no --actions must be refused");
        assert_eq!(ticket.code, EXIT_USAGE);
        assert!(ticket.message.contains("--actions"), "{}", ticket.message);

        let (_, params) =
            grant_request(&flags(&["--connection", "conn-1", "--actions", "*"])).expect("grant");
        assert_eq!(params["action_selectors"], json!(["*"]));
        let (_, params) =
            issue_ticket_request(&flags(&["--app", "deepwiki", "--actions", "*"]), "None")
                .expect("ticket");
        assert_eq!(params["action_selectors"], json!(["*"]));

        let empty = grant_request(&flags(&["--connection", "conn-1", "--actions", " , "]))
            .expect_err("an empty --actions list must be refused");
        assert_eq!(empty.code, EXIT_USAGE);
    }

    /// Reject unknown flags by name before sending any command. In particular,
    /// reject `--action` instead of `--actions`: silently ignoring that typo
    /// could create a grant for every action rather than the requested subset.
    #[test]
    fn an_unknown_or_repeated_flag_is_refused_by_name_before_any_call() {
        let args = |values: &[&str]| values.iter().map(|v| v.to_string()).collect::<Vec<_>>();
        let refused = run(&args(&[
            "grant",
            "--subc",
            "/nonexistent/conn.json",
            "--connection",
            "conn-1",
            "--risk",
            "write",
            "--action",
            "create_issue",
        ]))
        .expect_err("an unknown flag must be refused");
        assert_eq!(refused.code, EXIT_USAGE);
        assert!(
            refused.message.contains("unknown flag --action "),
            "an unknown flag must be refused by name: {}",
            refused.message
        );

        let refused = run(&args(&[
            "issue-ticket",
            "--subc",
            "/nonexistent/conn.json",
            "--app",
            "exa",
            "--action",
            "web_search_exa",
        ]))
        .expect_err("issue-ticket must refuse an unknown flag before reading the catalog");
        assert_eq!(refused.code, EXIT_USAGE);
        assert!(refused.message.contains("--action "), "{}", refused.message);

        // A bare flag is refused where the command does not read it.
        let refused = run(&args(&["list-policies", "--subc", "x", "--apply"]))
            .expect_err("--apply is not a list-policies flag");
        assert!(refused.message.contains("--apply"), "{}", refused.message);

        let refused = run(&args(&[
            "grant",
            "--subc",
            "x",
            "--connection",
            "a",
            "--actions",
            "read_item",
            "--actions",
            "*",
        ]))
        .expect_err("a repeated flag must be refused");
        assert_eq!(refused.code, EXIT_USAGE);
        assert!(
            refused.message.contains("duplicate flag --actions"),
            "{}",
            refused.message
        );

        let refused = run(&args(&[
            "connector-home",
            "status",
            "--subc",
            "x",
            "--reson",
            "r",
        ]))
        .expect_err("connector-home status must refuse an unknown flag");
        assert!(refused.message.contains("--reson"), "{}", refused.message);
    }

    /// Every flag the usage text documents for a command is one that command
    /// accepts, so the allowlist cannot refuse a documented invocation.
    #[test]
    fn every_documented_flag_is_accepted_by_its_command() {
        let mut checked = 0;
        for block in USAGE.split("\n\n") {
            let Some(head) = block.split_whitespace().next() else {
                continue;
            };
            for command in head.split('|') {
                let Some(accepted) = accepted_flags(command) else {
                    continue;
                };
                for word in block.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
                    if word.starts_with("--") && word.len() > 2 && word != "--help" {
                        assert!(
                            accepted.contains(&word) || COMMON_FLAGS.contains(&word),
                            "{command} documents {word} but refuses it"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked > 40, "the usage scan found only {checked} flags");
    }

    #[test]
    fn actions_are_split_and_trimmed() {
        assert_eq!(
            flags(&["--actions", "search, write_item"])
                .action_selectors()
                .expect("actions"),
            vec!["search".to_string(), "write_item".to_string()]
        );
    }

    #[test]
    fn grant_defaults_to_invoke_authority_at_read_risk() {
        let (method, params) = grant_request(&flags(&["--connection", "conn-1", "--actions", "*"]))
            .expect("grant request");
        assert_eq!(method, "plexus.admin.grant");
        assert_eq!(params["authority_kind"], "invoke");
        assert_eq!(params["risk_ceiling"], "read");
        assert_eq!(params["connection_id"], "conn-1");
    }

    /// Every kind this CLI accepts is documented, and every kind it documents is
    /// accepted.
    ///
    /// These drifted once: `poll` was added to the membership check and not to
    /// the usage text, so the CLI accepted a kind its own --help denied. An
    /// operator reading the help would conclude the capability did not exist,
    /// which for them is the same as it not existing -- and the trigger plane it
    /// authorizes is not reachable any other way.
    ///
    /// Both directions are asserted because they fail differently. An accepted
    /// but undocumented kind is invisible; a documented but unaccepted kind
    /// sends someone to type a command that is refused. The first is the one
    /// that happened.
    ///
    /// Mutation-proved: removing `poll` from the usage text fails the first leg,
    /// and adding an undocumented kind to GRANT_KINDS fails it too.
    #[test]
    fn set_policy_sends_the_operator_selected_scope_and_expiry() {
        let (method, params) = set_policy_request(&flags(&[
            "--connection",
            "conn-1",
            "--action",
            "create_issue",
            "--effect",
            "allow",
            "--expires-ms",
            "1900000000000",
        ]))
        .expect("set policy request");
        assert_eq!(method, "plexus.admin.set_policy");
        assert_eq!(params["connection_id"], "conn-1");
        assert_eq!(params["action_selector"], "create_issue");
        assert_eq!(params["effect"], "allow");
        assert_eq!(params["expires_at"], 1_900_000_000_000_i64);
    }

    #[test]
    fn policy_commands_are_documented_with_allows_approval_effect() {
        for command in ["set-policy", "list-policies", "remove-policy"] {
            assert!(USAGE.contains(command), "{command} missing from --help");
        }
        assert!(
            USAGE.contains("removes the approval requirement"),
            "--help must state what allow changes"
        );
    }

    #[test]
    fn the_accepted_grant_kinds_and_the_documented_ones_agree() {
        for kind in GRANT_KINDS {
            assert!(
                USAGE.contains(kind),
                "grant kind '{kind}' is accepted but absent from --help, so nobody \
                 reading the usage can discover it"
            );
            // Accepted in fact, not merely listed: a constant nobody consults
            // would satisfy the line above on its own.
            let flags = Flags::parse(&[
                "--connection".to_string(),
                "c1".to_string(),
                "--kind".to_string(),
                kind.to_string(),
                "--grantee".to_string(),
                "module:consumer".to_string(),
                "--expires-ms".to_string(),
                "1900000000000".to_string(),
                "--actions".to_string(),
                "*".to_string(),
            ])
            .expect("flags parse");
            let (_, params) = grant_request(&flags)
                .unwrap_or_else(|error| panic!("documented kind '{kind}' was refused: {error:?}"));
            assert_eq!(params["authority_kind"], kind);
        }

        // The reverse guard: an undocumented kind must be refused, or the check
        // is satisfied by accepting everything.
        let flags = Flags::parse(&[
            "--connection".to_string(),
            "c1".to_string(),
            "--kind".to_string(),
            "sudo".to_string(),
        ])
        .expect("flags parse");
        let failure = grant_request(&flags).expect_err("an unknown kind must be refused");
        assert_eq!(failure.code, EXIT_USAGE);
        assert!(
            failure.message.contains("poll"),
            "the refusal must name the kinds that DO work: {}",
            failure.message
        );
    }

    #[test]
    fn grant_rejects_an_unknown_authority_kind() {
        let failure = grant_request(&flags(&["--connection", "c", "--kind", "root"]))
            .expect_err("unknown kind must be refused");
        assert_eq!(failure.code, EXIT_USAGE);
    }

    #[test]
    fn review_and_repin_requests_name_one_action_and_reviewed_hash() {
        let (review_method, review_params) = review_action_request(&flags(&[
            "--connection",
            "conn-github",
            "--action",
            "list_issues",
        ]))
        .expect("review request");
        assert_eq!(review_method, "plexus.admin.review_action");
        assert_eq!(review_params["connection_id"], "conn-github");
        assert_eq!(review_params["action"], "list_issues");

        let (repin_method, repin_params) = repin_action_request(&flags(&[
            "--connection",
            "conn-github",
            "--action",
            "list_issues",
            "--expected-hash",
            "sha256:reviewed",
        ]))
        .expect("re-pin request");
        assert_eq!(repin_method, "plexus.admin.repin_action");
        assert_eq!(repin_params["expected_schema_hash"], "sha256:reviewed");
    }

    #[test]
    fn review_action_prints_added_removed_and_type_changed_properties() {
        let rendered = review_lines(&json!({
            "pinned_schema_hash": "sha256:before",
            "current_schema_hash": "sha256:after",
            "reviewed_schema_json": {
                "type": "object",
                "properties": {
                    "removed": {"type": "string"},
                    "changed": {"type": "string"}
                }
            },
            "current_schema_json": {
                "type": "object",
                "properties": {
                    "added": {"type": "array"},
                    "changed": {"type": "integer"}
                }
            }
        }))
        .join("\n");
        assert!(
            rendered.contains("pinned_hash:  sha256:before"),
            "{rendered}"
        );
        assert!(
            rendered.contains("current_hash: sha256:after"),
            "{rendered}"
        );
        assert!(rendered.contains("added:        added"), "{rendered}");
        assert!(rendered.contains("removed:      removed"), "{rendered}");
        assert!(
            rendered.contains("type changed: changed (string -> integer)"),
            "{rendered}"
        );
    }

    #[test]
    fn review_and_repin_help_explain_the_operator_assertion() {
        for command in ["review-action", "repin-action"] {
            assert!(USAGE.contains(command), "{command} missing from --help");
        }
        assert!(
            USAGE.contains("asserts that the operator has reviewed"),
            "re-pin help must state its review assertion"
        );
    }

    #[test]
    fn a_missing_required_flag_names_the_flag() {
        let failure = revoke_grant_request(&flags(&[])).expect_err("missing --grant must fail");
        assert!(failure.message.contains("--grant"), "{}", failure.message);
        assert_eq!(failure.code, EXIT_USAGE);
    }

    #[test]
    fn a_reference_is_sent_without_reading_a_file() {
        let (method, params) = issue_ticket_request(
            &flags(&[
                "--app",
                "linear",
                "--credential-id",
                "apikey:linear",
                "--actions",
                "*",
            ]),
            "ApiKey",
        )
        .unwrap();
        assert_eq!(method, "plexus.admin.issue_ticket");
        assert_eq!(params["credential_id"], "apikey:linear");
        assert!(params.get("handle").is_none());
    }

    #[test]
    fn the_removed_handle_file_flag_is_refused_without_reading_a_file() {
        let failure = issue_ticket_request(
            &flags(&["--app", "linear", "--handle-file", "/not/read"]),
            "ApiKey",
        )
        .expect_err("the removed flag must be refused");
        assert_eq!(failure.code, EXIT_USAGE);
        assert!(failure.message.contains("handle_bindings_removed"));
    }

    #[test]
    fn a_credential_requiring_app_requires_a_reference() {
        let failure = issue_ticket_request(&flags(&["--app", "linear"]), "ApiKey")
            .expect_err("credentialed apps must require --credential-id");
        assert_eq!(failure.code, EXIT_USAGE);
        assert!(failure.message.contains("--credential-id"), "{failure:?}");
    }

    #[test]
    fn a_credential_free_app_omits_the_handle() {
        let (method, params) =
            issue_ticket_request(&flags(&["--app", "deepwiki", "--actions", "*"]), "None")
                .expect("credential-free apps need no handle file");
        assert_eq!(method, "plexus.admin.issue_ticket");
        assert_eq!(params["app_key"], "deepwiki");
        assert!(params.get("handle").is_none(), "{params}");
    }

    #[test]
    fn a_credential_free_app_refuses_a_supplied_handle_locally() {
        let failure = issue_ticket_request(
            &flags(&[
                "--app",
                "deepwiki",
                "--handle-file",
                "/not/read/because-the-manifest-forbids-it",
            ]),
            "None",
        )
        .expect_err("credential-free apps must refuse a supplied handle");
        assert_eq!(failure.code, EXIT_USAGE);
        assert_eq!(
            failure.message,
            "handle_bindings_removed: use --credential-id"
        );
    }

    /// The grants list is read to decide WHAT TO REVOKE, and an expired grant
    /// carries no authority, so it is never the answer while its row crowds out
    /// the ones that are. A long-lived store can easily hold dozens of grants,
    /// several of them expired.
    #[test]
    fn the_default_grants_view_hides_expired_and_says_how_many() {
        let grants = vec![
            json!({"grant_id": "g1", "state": "until_revoked"}),
            json!({"grant_id": "g2", "state": "expired"}),
            json!({"grant_id": "g3", "state": "live"}),
            json!({"grant_id": "g4", "state": "expired"}),
        ];

        let (shown, hidden) = partition_grants(&grants, false);
        assert_eq!(hidden, 2, "both expired grants must be withheld");
        assert_eq!(
            shown
                .iter()
                .map(|grant| text(&grant["grant_id"]))
                .collect::<Vec<_>>(),
            vec!["g1", "g3"],
            "only non-expired grants are shown, in wire order"
        );

        // The withheld count must reach the reader. Silence here is the failure
        // this change exists to avoid: "2 grant(s)" on a box holding four.
        assert_eq!(
            grants_summary(shown.len(), hidden),
            "2 grant(s); 2 expired hidden, --all to show"
        );
    }

    #[test]
    fn all_shows_every_grant_and_withholds_nothing() {
        let grants = vec![
            json!({"grant_id": "g1", "state": "until_revoked"}),
            json!({"grant_id": "g2", "state": "expired"}),
        ];

        let (shown, hidden) = partition_grants(&grants, true);
        assert_eq!(shown.len(), 2);
        assert_eq!(hidden, 0);
        // No trailing clause when nothing was withheld, so the line cannot imply
        // a filter that did not run.
        assert_eq!(grants_summary(shown.len(), hidden), "2 grant(s)");
    }

    /// `--all` takes no value, so the parser must admit it as a bare flag. A
    /// value-taking parse would refuse the command outright.
    #[test]
    fn all_parses_as_a_bare_flag_and_unknown_flags_still_need_values() {
        let flags = Flags::parse(&[
            "--subc".to_string(),
            "/tmp/conn.json".to_string(),
            "--all".to_string(),
        ])
        .expect("--all must parse without a value");
        assert!(flags.has("--all"));
        assert_eq!(flags.value("--subc"), Some("/tmp/conn.json"));
        assert!(
            !flags.has("--connection"),
            "absent bare flags read as false"
        );

        let Err(failure) = Flags::parse(&["--connection".to_string()]) else {
            panic!("a value-taking flag with no value must still refuse");
        };
        assert_eq!(failure.code, EXIT_USAGE);
    }

    #[test]
    fn a_refusal_surfaces_the_module_error_code_verbatim() {
        let failure = report(
            "grant",
            &json!({"error": {"code": "risk_above_ceiling", "message": "risk 'write' exceeds the ceiling 'read'"}}),
            &Flags::parse(&[]).expect("empty flags parse"),
        )
        .expect_err("an error response must fail");
        assert_eq!(failure.code, EXIT_REFUSED);
        assert!(
            failure.message.starts_with("risk_above_ceiling:"),
            "{}",
            failure.message
        );
    }

    /// `handle-grant` is dispatched by `run`, names the management op the
    /// module serves, and sends the parameters that op decodes. Without
    /// `--apply` it is a dry run.
    #[test]
    fn handle_grant_sends_the_management_op_and_defaults_to_a_dry_run() {
        let args = [
            "--handle",
            "example-bot",
            "--actions",
            "create_issue, edit_issue",
            "--carrier",
            "reserved:aft",
            "--effect",
            "allow",
        ];
        let (method, params) = handle_grant_request(&flags(&args)).expect("request");
        assert_eq!(method, plexus_module::manifest::GITHUB_GRANT_OP);
        assert_eq!(
            params,
            json!({"app_handle_id":"example-bot","actions":["create_issue","edit_issue"],
                "module":"reserved:aft","effect":"allow","dry_run":true})
        );
        let mut applied = args.to_vec();
        applied.push("--apply");
        let (_, params) = handle_grant_request(&flags(&applied)).expect("request");
        assert_eq!(params["dry_run"], false);

        // `run` routes the command: with every op flag present it gets as far
        // as needing the daemon connection, rather than calling it unknown.
        let mut command = vec!["handle-grant"];
        command.extend(args);
        let command: Vec<String> = command.iter().map(|value| value.to_string()).collect();
        let failure = run(&command).unwrap_err();
        assert_eq!(failure.code, EXIT_USAGE);
        assert!(failure.message.contains("--subc"), "{}", failure.message);
        assert!(USAGE.contains("handle-grant"));

        // The carrier must not travel in `--module`, which names the plexus
        // module this command calls; the call has to stay on the default.
        assert_eq!(flags(&args).value("--module"), None);

        for (missing, value) in [("--carrier", "reserved:aft"), ("--effect", "allow")] {
            let partial: Vec<&str> = args
                .chunks(2)
                .filter(|pair| pair[0] != missing)
                .flatten()
                .copied()
                .collect();
            let failure = handle_grant_request(&flags(&partial)).unwrap_err();
            assert!(
                failure.message.contains(missing),
                "{value}: {}",
                failure.message
            );
        }
        let mut bad = args.to_vec();
        bad[7] = "always";
        assert_eq!(
            handle_grant_request(&flags(&bad)).unwrap_err().code,
            EXIT_USAGE
        );
    }

    #[test]
    fn widen_ceiling_previews_by_default_and_requires_explicit_actions() {
        let preview = flags(&[
            "--connection",
            "conn-github-actions",
            "--actions",
            "get_job, get_run",
        ]);
        preview
            .refuse_unknown(accepted_flags("widen-ceiling").unwrap())
            .unwrap();
        let (method, params) = widen_ceiling_request(&preview).unwrap();
        assert_eq!(method, "plexus.admin.widen_ceiling");
        assert_eq!(
            params,
            json!({"connection_id": "conn-github-actions", "actions": ["get_job", "get_run"], "dry_run": true})
        );
        let apply = flags(&[
            "--connection",
            "conn-github-actions",
            "--actions",
            "get_job",
            "--apply",
        ]);
        assert_eq!(widen_ceiling_request(&apply).unwrap().1["dry_run"], false);
        for actions in ["*", "get_job,*", "", " , "] {
            assert!(
                widen_ceiling_request(&flags(&["--connection", "c", "--actions", actions]))
                    .is_err()
            );
        }
        assert!(widen_ceiling_request(&flags(&["--connection", "c"])).is_err());
        assert!(USAGE.contains("widen-ceiling --connection <id> --actions a,b,c [--apply]"));
        let lines = widen_ceiling_lines(&json!({
            "connection_id": "c", "dry_run": true, "applied": false, "ceiling_risk": "read",
            "current_ceiling": ["poll"], "added_actions": ["get_job"],
            "unchanged_actions": ["poll"], "resulting_ceiling": ["get_job", "poll"]
        }))
        .join("\n");
        for expected in [
            "current:    poll",
            "add:        get_job",
            "unchanged:  poll",
            "resulting:  get_job,poll",
            "Grants are separate",
        ] {
            assert!(lines.contains(expected), "{lines}");
        }
    }

    /// `handle-grant --kind poll` sends the poll form: no carrier or effect,
    /// and a dry run unless `--apply` is given. A carrier or effect is refused
    /// rather than dropped.
    #[test]
    fn handle_grant_poll_form_sends_kind_poll_and_refuses_carrier_or_effect() {
        let args = [
            "--handle",
            "magic-alfonso",
            "--actions",
            "github.issue_timeline.list",
            "--kind",
            "poll",
        ];
        let (method, params) = handle_grant_request(&flags(&args)).expect("request");
        assert_eq!(method, plexus_module::manifest::GITHUB_GRANT_OP);
        assert_eq!(
            params,
            json!({"kind":"poll","app_handle_id":"magic-alfonso",
                "actions":["github.issue_timeline.list"],"dry_run":true})
        );
        let mut applied = args.to_vec();
        applied.push("--apply");
        let (_, params) = handle_grant_request(&flags(&applied)).expect("request");
        assert_eq!(params["dry_run"], false);
        for extra in [["--carrier", "reserved:aft"], ["--effect", "allow"]] {
            let mut with_extra = args.to_vec();
            with_extra.extend(extra);
            let failure = handle_grant_request(&flags(&with_extra)).unwrap_err();
            assert_eq!(failure.code, EXIT_USAGE);
            assert!(failure.message.contains(extra[0]), "{}", failure.message);
        }
        let mut bad = args.to_vec();
        bad[5] = "forever";
        assert_eq!(
            handle_grant_request(&flags(&bad)).unwrap_err().code,
            EXIT_USAGE
        );
    }

    /// `handle-bind` is dispatched by `run`, names the management op the
    /// module serves, and sends the parameters that op decodes. Without
    /// `--apply` it is a dry run, and `--module` stays unset so the call goes
    /// to the default plexus module.
    #[test]
    fn handle_bind_sends_the_management_op_and_defaults_to_a_dry_run() {
        let args = [
            "--handle",
            "subc",
            "--repositories",
            "cortexkit/commons, cortexkit/entorhinal",
        ];
        let (method, params) = handle_bind_request(&flags(&args)).expect("request");
        assert_eq!(method, plexus_module::manifest::GITHUB_BIND_OP);
        assert_eq!(
            params,
            json!({"app_handle_id":"subc",
                "repositories":["cortexkit/commons","cortexkit/entorhinal"],"dry_run":true})
        );
        let mut applied = args.to_vec();
        applied.push("--apply");
        let (_, params) = handle_bind_request(&flags(&applied)).expect("request");
        assert_eq!(params["dry_run"], false);

        // `run` routes the command: with every op flag present it gets as far
        // as needing the daemon connection, rather than calling it unknown.
        let mut command = vec!["handle-bind"];
        command.extend(args);
        let command: Vec<String> = command.iter().map(|value| value.to_string()).collect();
        let failure = run(&command).unwrap_err();
        assert_eq!(failure.code, EXIT_USAGE);
        assert!(failure.message.contains("--subc"), "{}", failure.message);
        assert!(USAGE.contains("handle-bind"));
        assert_eq!(flags(&args).value("--module"), None);

        for missing in ["--handle", "--repositories"] {
            let partial: Vec<&str> = args
                .chunks(2)
                .filter(|pair| pair[0] != missing)
                .flatten()
                .copied()
                .collect();
            let failure = handle_bind_request(&flags(&partial)).unwrap_err();
            assert!(failure.message.contains(missing), "{}", failure.message);
        }
        let empty = ["--handle", "subc", "--repositories", " , "];
        assert_eq!(
            handle_bind_request(&flags(&empty)).unwrap_err().code,
            EXIT_USAGE
        );
    }

    #[test]
    fn handle_unbind_cli_defaults_to_preview() {
        let args = ["--handle", "subc", "--repo", "cortexkit/entorhinal"];
        let (method, params) = handle_unbind_request(&flags(&args)).unwrap();
        assert_eq!(method, plexus_module::manifest::GITHUB_UNBIND_OP);
        assert_eq!(
            params,
            json!({"app_handle_id":"subc", "repository":"cortexkit/entorhinal", "dry_run":true})
        );
        let mut apply = args.to_vec();
        apply.push("--apply");
        assert_eq!(
            handle_unbind_request(&flags(&apply)).unwrap().1["dry_run"],
            false
        );
        assert!(handle_unbind_request(&flags(&["--handle", "subc"])).is_err());
        assert!(handle_unbind_request(&flags(&["--repo", "org/repo"])).is_err());
        let failure = run(&[
            "handle-unbind".into(),
            "--handle".into(),
            "subc".into(),
            "--repo".into(),
            "org/repo".into(),
        ])
        .unwrap_err();
        assert!(failure.message.contains("--subc"), "{}", failure.message);
    }

    #[test]
    fn rebind_credential_cli_defaults_to_preview_and_renders_only_safe_fields() {
        let args = ["--connection", "conn-exa", "--credential-id", "apikey:exa"];
        let (method, params) = rebind_credential_request(&flags(&args)).unwrap();
        assert_eq!(method, plexus_module::manifest::ADMIN_REBIND_CREDENTIAL_OP);
        assert_eq!(
            params,
            json!({"connection_id":"conn-exa", "credential_id":"apikey:exa", "apply":false})
        );
        let mut applied = args.to_vec();
        applied.push("--apply");
        assert_eq!(
            rebind_credential_request(&flags(&applied)).unwrap().1["apply"],
            true
        );
        let mut command = vec!["rebind-credential"];
        command.extend(args);
        let failure = run(&command.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap_err();
        assert!(failure.message.contains("--subc"));
        let lines = rebind_credential_lines(&json!({"connection_id":"conn-exa",
            "current_binding_kind":"handle", "credential_id":"apikey:exa", "applied":false,
            "handle":"ckh_never_print", "payload":"secret-never-print"}))
        .join("\n");
        assert!(lines.contains("current binding kind: handle"));
        assert!(lines.contains("new reference: apikey:exa"));
        assert!(lines.contains("dry run"));
        assert!(!lines.contains("never_print") && !lines.contains("secret-never-print"));
        assert!(
            USAGE.contains("rebind-credential --connection <id> --credential-id <id> [--apply]")
        );
        let reference = flags(&[
            "--app",
            "exa",
            "--credential-id",
            "apikey:exa",
            "--actions",
            "*",
        ]);
        assert_eq!(
            issue_ticket_request(&reference, "api_key").unwrap().1["credential_id"],
            "apikey:exa"
        );
        assert!(issue_ticket_request(&reference, "none").is_err());
        assert!(issue_ticket_request(
            &flags(&[
                "--app",
                "exa",
                "--credential-id",
                "apikey:exa",
                "--handle-file",
                "unused"
            ]),
            "api_key"
        )
        .is_err());
    }

    /// `delete-connection` is dispatched by `run`, names the management op
    /// the module serves, and is a dry run unless `--apply` is given. The
    /// connection travels as `--connection`, so `--module` keeps naming the
    /// plexus module to call.
    #[test]
    fn delete_connection_sends_the_management_op_and_defaults_to_a_dry_run() {
        let args = ["--connection", "conn-demo-rest"];
        let (method, params) = delete_connection_request(&flags(&args)).expect("request");
        assert_eq!(method, plexus_module::manifest::ADMIN_DELETE_CONNECTION_OP);
        assert_eq!(
            params,
            json!({"connection_id":"conn-demo-rest","dry_run":true})
        );
        let applied = ["--connection", "conn-demo-rest", "--apply"];
        let (_, params) = delete_connection_request(&flags(&applied)).expect("request");
        assert_eq!(
            params,
            json!({"connection_id":"conn-demo-rest","dry_run":false})
        );
        assert_eq!(flags(&applied).value("--module"), None);

        let mut command = vec!["delete-connection"];
        command.extend(args);
        let command: Vec<String> = command.iter().map(|value| value.to_string()).collect();
        let failure = run(&command).unwrap_err();
        assert_eq!(failure.code, EXIT_USAGE);
        assert!(failure.message.contains("--subc"), "{}", failure.message);
        assert!(USAGE.contains("delete-connection --connection <id>"));
        assert!(!USAGE.contains("retire-connection"));

        let failure = delete_connection_request(&flags(&[])).unwrap_err();
        assert!(
            failure.message.contains("--connection"),
            "{}",
            failure.message
        );
    }

    /// `set-web-search-limit` names the management op, sends both limits as
    /// numbers, is a dry run unless `--apply` is given, and refuses a
    /// non-positive or non-numeric limit before calling the module.
    #[test]
    fn set_web_search_limit_sends_the_management_op_and_defaults_to_a_dry_run() {
        let args = [
            "--backend",
            "exa",
            "--per-caller",
            "10",
            "--per-backend",
            "40",
        ];
        let (method, params) = set_web_search_limit_request(&flags(&args)).expect("request");
        assert_eq!(
            method,
            plexus_module::manifest::ADMIN_SET_WEB_SEARCH_LIMIT_OP
        );
        assert_eq!(
            params,
            json!({"backend":"exa","per_caller_per_minute":10,
                "per_backend_per_minute":40,"dry_run":true})
        );
        let mut applied = args.to_vec();
        applied.push("--apply");
        let (_, params) = set_web_search_limit_request(&flags(&applied)).expect("request");
        assert_eq!(params["dry_run"], false);
        for bad in ["0", "-1", "ten"] {
            let args = [
                "--backend",
                "exa",
                "--per-caller",
                bad,
                "--per-backend",
                "40",
            ];
            assert_eq!(
                set_web_search_limit_request(&flags(&args))
                    .unwrap_err()
                    .code,
                EXIT_USAGE,
                "{bad}"
            );
        }
        assert!(USAGE.contains("set-web-search-limit --backend <name>"));

        let dry = web_search_limit_lines(&json!({"backend":"exa","outcome":"would_set",
            "current":{"per_caller_per_minute":30,"per_backend_per_minute":120},
            "current_source":"default",
            "proposed":{"per_caller_per_minute":10,"per_backend_per_minute":40},
            "dry_run":true}));
        assert!(dry[0].starts_with("dry run"), "{dry:?}");
        assert_eq!(dry[1], "per caller per minute:  30 -> 10");
        assert_eq!(dry[3], "previous values were:  default");
        let done = web_search_limit_lines(&json!({"backend":"exa","outcome":"set",
            "previous":{"per_caller_per_minute":30,"per_backend_per_minute":120},
            "previous_source":"default",
            "current":{"per_caller_per_minute":10,"per_backend_per_minute":40},
            "dry_run":false}));
        assert!(done[0].starts_with("applied:"), "{done:?}");
        assert_eq!(done[2], "per backend per minute: 120 -> 40");
    }

    /// Each outcome prints a headline an operator cannot misread as another,
    /// and the per-table counts say whether they were or would be deleted.
    #[test]
    fn delete_connection_lines_name_the_outcome() {
        let dry = delete_connection_lines(&json!({"connection_id":"c","app_key":"a",
            "outcome":"would_delete","status":"revoked","rows":{"catalog_actions":20},
            "dry_run":true}));
        assert!(dry[0].starts_with("dry run"), "{dry:?}");
        assert_eq!(dry[2], "status:  revoked");
        assert_eq!(dry[3], "would delete catalog_actions: 20");
        let applied = delete_connection_lines(&json!({"connection_id":"c","app_key":"a",
            "outcome":"deleted","status":"revoked","rows":{"catalog_actions":20},
            "dry_run":false}));
        assert!(applied[0].starts_with("applied:"), "{applied:?}");
        assert_eq!(applied[3], "deleted catalog_actions: 20");
        assert!(applied[4].starts_with("kept: audit_journal"), "{applied:?}");
    }
}

#[cfg(test)]
mod connector_home_cli_tests {
    use super::*;
    #[test]
    fn connector_home_claim_is_refused_by_name() {
        for args in [
            vec!["connector-home".into(), "claim".into()],
            vec!["connector-home".into(), "claim".into(), "--apply".into()],
        ] {
            let error = run(&args).unwrap_err();
            assert_eq!(error.code, EXIT_USAGE);
            assert!(error.message.contains("connector-home claim"));
            assert!(error.message.contains("ck roles take connector_home"));
        }
    }
    #[test]
    fn connector_home_status_reads_the_live_role() {
        let (method, params) =
            connector_home_request("status", &Flags::parse(&[]).unwrap()).unwrap();
        assert_eq!(method, plexus_module::connector_home::STATUS_OP);
        assert_eq!(params, json!({}));
    }
}

#[cfg(test)]
mod recipient_cli_tests {
    use super::*;

    #[test]
    fn recipients_commands_preview_by_default_and_select_explicit_agent_or_null() {
        let flags = |args: &[&str]| {
            Flags::parse(&args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()).unwrap()
        };
        for command in ["recipients-add", "recipients-remove"] {
            let base = flags(&["--connection", "mail", "--recipient", "Alice@Example.COM"]);
            let (_, params) = recipients_request(command, &base).unwrap();
            assert_eq!(params["dry_run"], true);
            assert_eq!(params["agent"], Value::Null);
            let applied = flags(&[
                "--connection",
                "mail",
                "--recipient",
                "Alice@Example.COM",
                "--agent",
                "agent-one",
                "--apply",
            ]);
            let (_, params) = recipients_request(command, &applied).unwrap();
            assert_eq!(params["dry_run"], false);
            assert_eq!(params["agent"], "agent-one");
        }
        let (method, params) =
            recipients_request("recipients-list", &flags(&["--connection", "mail"])).unwrap();
        assert_eq!(method, plexus_module::manifest::ADMIN_RECIPIENTS_LIST_OP);
        assert!(params.get("dry_run").is_none());
        assert!(USAGE.contains("recipients-add|recipients-remove"));
    }
}

#[cfg(test)]
mod web_search_chain_cli_tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    fn parsed(items: &[&str]) -> Flags {
        Flags::parse_positionals(&args(items), true).unwrap()
    }

    #[test]
    fn order_cli_sends_positional_names_or_clear_and_previews_unless_applied() {
        for apply in [false, true] {
            for clear in [false, true] {
                let mut items = if clear {
                    vec!["--clear"]
                } else {
                    vec!["exa", "tavily"]
                };
                items.extend(["--subc", "operator.json", "--module", "plexus"]);
                if apply {
                    items.push("--apply");
                }
                let flags = parsed(&items);
                flags
                    .refuse_unknown(accepted_flags("set-web-search-order", None).unwrap())
                    .unwrap();
                let (method, params) = set_web_search_order_request(&flags).unwrap();
                assert_eq!(
                    method,
                    plexus_module::manifest::ADMIN_SET_WEB_SEARCH_ORDER_OP
                );
                assert_eq!(
                    params,
                    json!({"providers": if clear { json!([]) } else { json!(["exa", "tavily"]) }, "clear": clear, "dry_run": !apply})
                );
            }
        }
        for items in [
            vec![],
            vec!["--apply"],
            vec!["exa", "--clear"],
            vec!["--clear", "tavily"],
        ] {
            assert!(
                set_web_search_order_request(&parsed(&items)).is_err(),
                "{items:?}"
            );
            let mut command = vec!["set-web-search-order"];
            command.extend(items);
            assert_eq!(run(&args(&command)).unwrap_err().code, EXIT_USAGE);
        }
        let lines =
            web_search_change_lines(&json!({"previous": ["exa"], "new": null, "dry_run": true}))
                .join("\n");
        assert!(lines.contains("nothing written"));
        assert!(lines.contains("previous: [\"exa\"]"));
        assert!(lines.contains("new:      null"));
    }

    #[test]
    fn allowance_cli_requires_one_provider_and_count_or_clear_with_bounded_integer() {
        for count in ["1", "10000000"] {
            for apply in [false, true] {
                let mut items = vec!["tavily", count];
                if apply {
                    items.push("--apply");
                }
                let (method, params) = set_web_search_allowance_request(&parsed(&items)).unwrap();
                assert_eq!(
                    method,
                    plexus_module::manifest::ADMIN_SET_WEB_SEARCH_ALLOWANCE_OP
                );
                assert_eq!(
                    params,
                    json!({"provider": "tavily", "count": count.parse::<u32>().unwrap(), "clear": false, "dry_run": !apply})
                );
            }
        }
        for apply in [false, true] {
            let mut items = vec!["--clear", "exa"];
            if apply {
                items.push("--apply");
            }
            let (_, params) = set_web_search_allowance_request(&parsed(&items)).unwrap();
            assert_eq!(
                params,
                json!({"provider": "exa", "clear": true, "dry_run": !apply})
            );
        }
        for items in [
            vec![],
            vec!["--clear"],
            vec!["exa"],
            vec!["exa", "2", "--clear"],
            vec!["exa", "2", "tavily"],
            vec!["exa", "0"],
            vec!["exa", "-1"],
            vec!["exa", "1.5"],
            vec!["exa", "10000001"],
            vec!["exa", "18446744073709551615"],
        ] {
            assert!(
                set_web_search_allowance_request(&parsed(&items)).is_err(),
                "{items:?}"
            );
        }
        let lines = web_search_change_lines(
            &json!({"provider": "tavily", "previous": 2, "new": null, "dry_run": false}),
        )
        .join("\n");
        assert!(lines.contains("applied: tavily"));
        assert!(lines.contains("previous: 2"));
        assert!(lines.contains("new:      null"));
    }

    #[test]
    fn positional_commands_keep_flag_allowlists_and_other_commands_stay_flag_only() {
        for command in ["set-web-search-order", "set-web-search-allowance"] {
            for items in [
                vec!["--clear", "--clear"],
                vec!["--apply", "--apply"],
                vec!["--typo", "exa"],
                vec!["--all"],
            ] {
                let flags = parsed(&items);
                assert!(flags
                    .refuse_unknown(accepted_flags(command, None).unwrap())
                    .is_err());
            }
        }
        assert!(Flags::parse(&args(&["exa"])).is_err());
        assert!(run(&args(&["set-web-search-limit", "--clear"]))
            .unwrap_err()
            .message
            .contains("unknown flag --clear"));
        assert!(USAGE.contains("set-web-search-order <name>..."));
        assert!(USAGE.contains("set-web-search-allowance <name> --clear"));
    }
}
