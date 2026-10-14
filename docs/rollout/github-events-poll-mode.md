# GitHub events: poll-mode rollout

Plexus caps its GitHub Actions requests at **600 per trailing hour**. The cap
covers CI watch cycles and repository identity reads (`get_repository`). It is
this low because the same GitHub token can also serve other clients, and GitHub
allows a token 5,000 REST requests an hour, so CI polling is held to a small
share of it. Each CI watch polls
every **`max(300, R × 48)` seconds**, where R is the number of active CI
watches. A CI cycle reserves 8 requests, so this spacing keeps all watches
together under 600 an hour.

## Prerequisites (pending: run at deploy)

Run from the reviewed, clean checkout. Supply the following paths and values;
none of them is a token literal. Keep evidence outside `target/` and other build
caches. Protect evidence containing event bodies as operator data.

```sh
export SUBC=/absolute/path/to/subc-connection.json
export LIVE_STORE=/absolute/path/to/live/store.db
export LIVE_BIN=/absolute/path/to/deployed/bin
export LIVE_CATALOG=/absolute/path/to/deployed/catalog
export STAGED_DAEMON=/absolute/path/to/signed/ck-plexus
export STAGED_ADMIN=/absolute/path/to/signed/ck-plexus-admin
export EVIDENCE=/absolute/path/to/private/rollout-evidence
export SCRATCH_REPO=owner/scratch-repo
export SCRATCH_BRANCH=github-events-probe
export ACCT=local_bus_account
export BUS_URL=nats://127.0.0.1:4222
export BUS_OBSERVER_CREDS=/absolute/path/to/private/observer.creds
export FLOW_CALL=/absolute/path/to/operator-flow-tool-call
umask 077
mkdir -p "$EVIDENCE"
```

The operator supplies a scratch repo and workflow that can safely fail, an
admitted **reserved:basal flow route**, and bus observer credentials permitted to
subscribe to `ck.$ACCT.event.plexus.>` on the local bus. `FLOW_CALL` is the
operator's authenticated route client: it accepts one tool-call JSON argument,
prints the JSON reply and has a bounded timeout. It must use the daemon-stamped
flow scope, not a forged `agent_id` argument. The repository's `facade_call`
example cannot substitute for this client. It opens an unscoped operator route
with no flow scope, and `events.get` refuses that caller.

The vault credential **`apikey:github`** must be readable by `reserved:plexus`.
The token behind it needs Actions read access to every watched repository,
private ones included, and to the scratch repo. Without it, GitHub refuses CI
reads with "Resource not accessible by personal access token".

**Pass:** every path is supplied and readable, the observer can subscribe, the
flow route is admitted, and the scratch workflow/repo is disposable. Missing
credentials or a missing flow route is a stop, not an empty successful check.

## 1. Rehearse migrations 44 and 45 (pending: run at deploy)

Before the first upgraded daemon opens the live store, record the live store's
schema version
and rehearse the actual `PlexusStore::open` migration path on a SQLite `.backup`.
Never rehearse by opening the live database for migration, or by copying only the
main file of a WAL-mode database.

```sh
sqlite3 -readonly "$LIVE_STORE" \
  'SELECT * FROM cortexkit_schema_version;' > "$EVIDENCE/schema-before.txt"
cargo run --locked -p plexus-core --example migration_rehearsal -- \
  --backup-live "$LIVE_STORE" > "$EVIDENCE/migration-rehearsal.txt" 2>&1
```

**Pass:** exit 0; report shows `tables with row drift: 0`, `integrity_check: ok`,
`outbox depth: 0`, `first drain notices: 0`, and `second migration run: unchanged`.
The reported event count **before migration** must equal the NULL `event_key`
count afterward: migration never backfills keys on those old rows. Require a
non-empty pre-upgrade store for this rehearsal. Existing subscription
and event values are compared, not just counts. The starting version must be
below 44 to exercise these migrations; rehearsing an already upgraded database
is not proof of an upgrade. The first-drain observation is an empty pending-set
check on the backup, **not** a publish through the live bus (the copy has no live
lease). Stop on a failed assertion, missing report line or an already-migrated
input. Save a retained `.backup` before deployment as well:

```sh
sqlite3 "$LIVE_STORE" ".backup '$EVIDENCE/pre-upgrade.db'"
```

## 2. Deploy the binary, then the catalog (pending: run at deploy)

Build and stage the reviewed commit using the three commands below. These are
macOS signing/staging commands; do not substitute Linux artifacts for the signed
local deployment. `--marker none` explicitly uses the sidecar/UUID provenance
chain instead of asserting an unverified literal marker.

```sh
bash scripts/rust-test-gate.sh
scripts/release-binaries.sh
scripts/stage-binaries.sh --catalog-dir "$LIVE_CATALOG" --marker none
```

Use the signed artifact paths printed by `scripts/stage-binaries.sh` for
`STAGED_DAEMON` and
`STAGED_ADMIN`. Save the old binaries and catalog before placing replacements:

```sh
cp -p "$LIVE_BIN/ck-plexus" "$EVIDENCE/ck-plexus.before"
cp -p "$LIVE_BIN/ck-plexus-admin" "$EVIDENCE/ck-plexus-admin.before"
cp -R "$LIVE_CATALOG" "$EVIDENCE/catalog.before"
ck module stop plexus
install -m 755 "$STAGED_DAEMON" "$LIVE_BIN/ck-plexus.next"
install -m 755 "$STAGED_ADMIN" "$LIVE_BIN/ck-plexus-admin.next"
mv "$LIVE_BIN/ck-plexus.next" "$LIVE_BIN/ck-plexus"
mv "$LIVE_BIN/ck-plexus-admin.next" "$LIVE_BIN/ck-plexus-admin"
```

Only **after** the new binary is placed, install the reviewed Actions manifest,
`catalog/github_actions.jsonc`. That manifest uses two fields the old binary
does not know. `ci_runs` is the new watch type, set as `poll.cursor_kind`.
`http.request_constants` holds fixed request values, such as `per_page: 100`.
If the old binary reads this manifest, it rejects the unknown field and value
and refuses to boot. That is why the binary goes in before the catalog.

```sh
install -m 644 catalog/github_actions.jsonc "$LIVE_CATALOG/github_actions.jsonc"
ck module start plexus
scripts/verify-deployed-binary.sh "$LIVE_BIN/ck-plexus"
ck --json module status plexus > "$EVIDENCE/module-after.json"
ck --json --verbose health > "$EVIDENCE/health-after.json"
```

**Pass:** signing/staging and inode/provenance checks succeed; the running module
is ready, its build commit matches the reviewed deployment commit, connector
home is held, and its events schema includes `get`, `event_key` and `event_name`.
Do not accept merely finding a new file on disk or a stale process's health.

## 3. Connect and grant (pending: run at deploy)

Start the one-hour bus observer from step 4 in another terminal **before**
connecting or minting poll authority here. That observer is the `python3`
script that runs `nats sub` and stops it after 3,600 seconds of wall-clock
time. If it starts later, it can miss the first notices. Don't run the conformance `drift` command for this manifest. It compares a
manifest against the vendor's own MCP tool list, and a REST manifest such as
`github_actions.jsonc` has none. So it reports the manifest as `SKIPPED` and
exits 2, which proves nothing about the four actions. The first live poll after
connecting, checked in step 4, is the compatibility check for this manifest.

Issue a connection ticket owned by principal **`direct`**. `direct` is the
identity the daemon gives a plain operator client. `ck-plexus-admin` connects
this way, and so does the `facade_call` example used below. A ticket belongs to
the principal that issues it, and so does the connection made from it. So
`direct` owns `conn-github-actions` and the poll subscriptions on it, not an
agent or a reserved module. The `--actions` list sets the connection's ceiling
to the four reviewed reads. Every later grant on this connection is bounded by
that ceiling, so no other GitHub Actions call can gain authority through it:

```sh
"$LIVE_BIN/ck-plexus-admin" issue-ticket --subc "$SUBC" \
  --app github_actions --connection conn-github-actions \
  --credential-id apikey:github --risk read \
  --actions list_workflow_runs,get_workflow_run,list_jobs_for_workflow_run_attempt,get_repository
```

Set `TICKET_ID` to the returned ticket. Then consume it with the repository's
`facade_call` example. It opens an unscoped operator route and connects as
`direct`, the same principal that issued the ticket:

```sh
export TICKET_ID=returned-ticket-id
cargo run --locked -p plexus-module --example facade_call -- "$SUBC" \
  "{\"name\":\"connections\",\"arguments\":{\"op\":\"connect\",\"ticket_id\":\"$TICKET_ID\"}}" \
  > "$EVIDENCE/connect.json"
"$LIVE_BIN/ck-plexus-admin" grant --subc "$SUBC" \
  --connection conn-github-actions --grantee direct --kind poll --risk read \
  --actions list_workflow_runs,get_workflow_run,list_jobs_for_workflow_run_attempt,get_repository \
  > "$EVIDENCE/poll-grant.txt"
"$LIVE_BIN/ck-plexus-admin" grant --subc "$SUBC" \
  --connection conn-github-actions --grantee reserved:basal \
  --kind events_consume --risk read --actions list_workflow_runs \
  > "$EVIDENCE/basal-consume-grant.txt"
"$LIVE_BIN/ck-plexus-admin" list-grants --subc "$SUBC" \
  --connection conn-github-actions --all > "$EVIDENCE/grants-all.txt"
sqlite3 -readonly -json "$LIVE_STORE" \
  "SELECT principal,grantee_principal,authority_kind,action_selectors FROM grants WHERE connection_id='conn-github-actions';" \
  > "$EVIDENCE/grants-all.json"
```

**Pass:** connection result is `conn-github-actions`, active with a successful
discovery; owner is `direct`. The live poll grant covers exactly the four reads,
and the live consume grant is owned by `direct`, addressed to `reserved:basal`
and selects `list_workflow_runs`. Inspect **all** grants, including expired
ones: no row on this connection may have `grantee_principal` equal to
`reserved:prefrontal-core` or the literal configuration value `*`. The wildcard
selector and wildcard **grantee** are different fields. Do not mint a core or
wildcard-grantee grant to make a failing body fetch pass. Record returned grant
IDs for rollback; on retry, list existing grants rather than blindly minting
another one. The admin list is text, not a JSON CLI; the read-only SQL provides
a complete machine-readable cross-check.

## 4. Observe the first hour (pending: run at deploy)

Start the bus observer **before** the probe or watch-enabling change. Capture
subjects, headers and bodies (not `--raw` or `--subjects-only`); use a wall-clock
deadline, since NATS `--wait` is an idle timeout, not an hour-long window:

```sh
python3 - "$EVIDENCE/bus-hour.txt" "$BUS_URL" "$BUS_OBSERVER_CREDS" "$ACCT" <<'PY'
import subprocess, sys, time
with open(sys.argv[1], 'w') as log:
    started = time.time()
    process = subprocess.Popen(['nats', '--server', sys.argv[2], '--creds', sys.argv[3],
        'sub', 'ck.' + sys.argv[4] + '.event.plexus.>', '--timestamp'], stdout=log, stderr=log)
    try:
        code = process.wait(timeout=3600)
        raise SystemExit('observer exited before a full hour: ' + str(code))
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    log.write('\nobservation_seconds=' + str(time.time() - started) + '\n')
PY
```

In another terminal, snapshot before/after and during the hour. The query counts
**units**, not ledger rows: an admitted CI cycle reserves 8 even if unused; a
`get_repository` reserves 1. Capture once per poll and whenever a repository is
added, retaining samples because old ledger entries are pruned:

```sh
ck --json --verbose health > "$EVIDENCE/health-sample.json"
sqlite3 -readonly -json "$LIVE_STORE" <<'SQL' > "$EVIDENCE/store-sample.json"
SELECT subscription_id,principal,connection_id,fixed_args,cadence_s,status
FROM trigger_subscriptions WHERE cursor_kind='ci_runs';
SELECT COALESCE(SUM(requests),0) AS reserved_last_hour
FROM github_actions_quota
WHERE reserved_at_ms >= CAST(strftime('%s','now') AS INTEGER)*1000-3600000;
SELECT name,value FROM event_outbox_counters;
SELECT COUNT(*) AS total_markers,
       SUM(published_at_ms IS NOT NULL) AS published,
       SUM(published_at_ms IS NULL) AS pending FROM event_outbox;
SELECT action,outcome,COUNT(*) AS dispatch_audit_rows FROM audit_journal
WHERE app_key='github_actions' AND reason_code='dispatched'
  AND ts >= CAST(strftime('%s','now') AS INTEGER)*1000-3600000
GROUP BY action,outcome;
SQL
```

Rename each sample with its UTC timestamp; do not overwrite the only sample.
Record R, the count of all active `ci_runs` watches (hand-made included), used
in `max(300,48*R)` to calculate the fleet cadence. Also record newly created CI
subscriptions, the stored cadence and health's `effectiveCiCadenceS`, the change in `ciRuns.ci_polls_deferred`, identity-read deferrals
(`repositoryIdentity.repo_id_deferred` and `repositoryIdentity.repo_id_refresh_deferred`),
quota units, dispatch audit rows by action/outcome **including
`get_repository`**, and outbox
published/pending changes. Match watched issue/PR pairs to exactly one active
CI subscription each, owned by `direct`, with the issue watch's project stamp.

**Pass:** a full 3,600-second local observation, each stored active cadence and
health cadence equals `max(300,48*R)` after reconcile, every sampled trailing
quota sum is at most 600, and all notices have subject
`ck.$ACCT.event.plexus.{name}.v1`, with `{name}` in:

- `github_issue_changed`
- `github_pr_changed`
- `github_release_published`
- `github_ci_job_failed`
- `github_ci_job_completed`
- `github_ci_run_completed`

Require at least the failing-probe notices below, a healthy observer connection,
no last publish error at quiescence, and outbox depth 0 after the drain catches
up. Dispatch audit rows include `not_sent`, `failed`, `unknown` and `completed`
outcomes; they are not an HTTP-completion count or a substitute for the
pre-dispatch committed ledger. Record an independent dispatch-time request
counter/trace from the operator's HTTP observer to check **every trailing hour**,
not just the first aligned hour. The ledger deliberately overcounts unused
requests. Any missing audit writes, observer disconnect, absent dispatch trace,
quota violation or unknown subject makes the live claim incomplete or failed.
Check the quota ledger sum (`reserved_last_hour`) and the dispatch audit row
counts against the request count from the operator's HTTP observer. Do not
check either total only against its own earlier samples. Do not declare
success from an hour with no traffic.

## 5. Force one failing CI job and fetch its body (pending: run at deploy)

Supply `SCRATCH_WORKFLOW` naming a scratch-only workflow with **one** job whose
only step is `run: exit 1`, and `workflow_dispatch` enabled. The scratch repo
must have an active issue/PR pair so reconcile creates its CI watch; verify the
watch in the store sample before dispatching. Do not re-run the attempt while
counting exactly-once delivery. Record run ID, attempt, job ID and branch.

```sh
export SCRATCH_WORKFLOW=github-events-probe.yml
gh workflow run "$SCRATCH_WORKFLOW" --repo "$SCRATCH_REPO" --ref "$SCRATCH_BRANCH"
gh run list --repo "$SCRATCH_REPO" --workflow "$SCRATCH_WORKFLOW" \
  --branch "$SCRATCH_BRANCH" --limit 5 \
  --json databaseId,status,conclusion,headBranch,createdAt \
  > "$EVIDENCE/scratch-runs.json"
export RUN_ID=the-new-run-id
gh run view "$RUN_ID" --repo "$SCRATCH_REPO" \
  --json databaseId,status,conclusion,headBranch,jobs > "$EVIDENCE/scratch-run.json"
```

Wait with a deadline of `2 * max(300,48*R) + 60` seconds after the
vendor run completes; capture an additional poll beyond first delivery to
expose replay. If that extends beyond the first-hour observer, start a second
bounded observation and report its separate interval. A notice must identify
the run/attempt/job through its fetched body, not just match a repository name.

**Pass:** vendor evidence shows one failed job, one completed run attempt and
`conclusion=failure`. Across the observed discovery and repeat polls there is
exactly **one** `github_ci_job_failed` and **one** `github_ci_run_completed` for
that run attempt; there is no `github_ci_job_completed` for the failed job.
Both notices have the subject `ck.$ACCT.event.plexus.{name}.v1`, that is
`ck.$ACCT.event.plexus.github_ci_job_failed.v1` and
`ck.$ACCT.event.plexus.github_ci_run_completed.v1`. Each also has a bare
lowercase 64-hex event ID/key and digest, `repo` naming the lowercased scratch repo,
`branch` naming the probe branch, `kind` equal to the event name, and
`conclusion=failure`. Missing headers fail even if the subject is correct.

Fetch through **`FLOW_CALL`**, the operator-supplied Basal flow-route client
from Prerequisites. `events.get` accepts only two callers: `reserved:basal` on
a flow route, and `reserved:prefrontal-core`. Do not use the `facade_call`
example. It connects as `direct` with no flow scope, so `events.get` refuses
it with `events_get_carrier_refused`. Do not mint a new `events_consume` grant
to `reserved:prefrontal-core` either. That would let core read event bodies,
which step 3 forbids, and it would not test the Basal flow path this step
proves:

```sh
export JOB_KEY=the-job-notice-event-key
"$FLOW_CALL" \
  "{\"name\":\"events\",\"arguments\":{\"op\":\"get\",\"event_key\":\"$JOB_KEY\",\"event_name\":\"github_ci_job_failed\"}}" \
  > "$EVIDENCE/job-get.json"
export RUN_KEY=the-run-notice-event-key
"$FLOW_CALL" \
  "{\"name\":\"events\",\"arguments\":{\"op\":\"get\",\"event_key\":\"$RUN_KEY\",\"event_name\":\"github_ci_run_completed\"}}" \
  > "$EVIDENCE/run-get.json"
```

**Pass:** both replies have a `result`, `body` is a string, `event_name` matches
and SHA-256 of the **exact UTF-8 body string** matches the notice's bare hex
digest. Parse the job body only after hashing: its `id`, `conclusion` and
`run.run_id`, `run.run_attempt`, `run.head_branch`, `run.repository_id` identify
the probe, and `run.pull_requests` is readable without headers. The run body
must identify the same attempt and failure. Also fetch with a different name:

```sh
"$FLOW_CALL" \
  "{\"name\":\"events\",\"arguments\":{\"op\":\"get\",\"event_key\":\"$JOB_KEY\",\"event_name\":\"github_ci_job_completed\"}}" \
  > "$EVIDENCE/job-wrong-name.json"
```

**Pass:** `error.code=event_name_mismatch`, not a body. The current wire contract
requires `event_name` and returns `event_not_visible` for missing **and**
invisible keys. Older designs had a separate `event_not_found` code; the daemon
does not return it.

Visibility depends on the kind of flow. For an agent-owned flow, the daemon
takes the owner agent's ID from the flow route. It returns the event only if
the event's repository is bound to that agent's enabled GitHub App handle. The
owner agent is the `agent_id` Prefrontal recorded when it installed the flow.
Find that agent's handle in the live store with
`SELECT app_handle_id, status FROM github_app_handle WHERE agent_id = '<owner agent id>';`.
Before binding, make sure AFT's signed `gh` shim manifest already maps the
scratch repo to that same agent, and that this manifest version is active. The
shim compares plexus's repository bindings with its manifest on every bot
write. If they disagree, it refuses every bot write for every repository in the
fleet until they match, and nothing resends the refused writes. So the order is:
AFT prepares the manifest version, the operator approves it, CKCRED signs it,
AFT activates it, and only then you bind. Then bind the scratch repo to the
handle with
`ck-plexus-admin handle-bind --subc "$SUBC" --handle <app_handle_id> --repositories "$SCRATCH_REPO" --apply`.
The repo must share the handle's owner and be listed by the handle's
installation. For a global flow, use step 3's `events_consume` grant (owner
`direct`, grantee `reserved:basal`, selector `list_workflow_runs`). A denial is
not fixed by widening the grant to `*`.

## 6. Roll back safely (pending: run at deploy)

Stop polling and publishing before replacing anything. Revoke only the new
grants recorded in step 3, using their actual IDs. Retain the upgraded database
and evidence; do not delete pending markers or blindly restore a pre-upgrade
database over events collected during the hour.

```sh
ck module stop plexus
export POLL_GRANT_ID=recorded-new-poll-grant-id
export BASAL_GRANT_ID=recorded-new-consume-grant-id
```

The management surface requires the module to be running to revoke grants. If
only stopping the rollout, leave it stopped. If keeping the upgraded module for
diagnosis, run the block below: it starts the module, runs
`ck-plexus-admin revoke-grant` once for each recorded grant ID, saves the
remaining grant list, and stops the module again:

```sh
ck module start plexus
"$LIVE_BIN/ck-plexus-admin" revoke-grant --subc "$SUBC" --grant "$POLL_GRANT_ID"
"$LIVE_BIN/ck-plexus-admin" revoke-grant --subc "$SUBC" --grant "$BASAL_GRANT_ID"
"$LIVE_BIN/ck-plexus-admin" list-grants --subc "$SUBC" \
  --connection conn-github-actions --all > "$EVIDENCE/grants-after-revoke.txt"
ck module stop plexus
```

Revocation removes future authority, but is not a transactional pause of the
outbox: already stored pending notices can publish during this diagnosis
restart. Keep the module stopped if that is unacceptable. To restore the old
software, restore the **old catalog first** while stopped, so the old binary
never sees `ci_runs`:

```sh
rm -f "$LIVE_CATALOG/github_actions.jsonc"
cp -R "$EVIDENCE/catalog.before/." "$LIVE_CATALOG/"
install -m 755 "$EVIDENCE/ck-plexus.before" "$LIVE_BIN/ck-plexus.next"
install -m 755 "$EVIDENCE/ck-plexus-admin.before" "$LIVE_BIN/ck-plexus-admin.next"
mv "$LIVE_BIN/ck-plexus.next" "$LIVE_BIN/ck-plexus"
mv "$LIVE_BIN/ck-plexus-admin.next" "$LIVE_BIN/ck-plexus-admin"
```

**Pass:** stopped supervisor state, retained database/evidence, no forbidden
grants and no incompatible catalog for the restored binary. Database downgrade
is a separate operator recovery decision. Migration 44 adds the `event_key` and
`delivery_id` columns to `trigger_events`. It also creates the `event_outbox`,
`github_repo_id_cache`, `github_actions_quota` and `event_outbox_counters`
tables. Migration 45 rebuilds `trigger_subscriptions` so its `cursor_kind`
column accepts `ci_runs`, copying every existing row. Plexus has no down
migrations. An older binary opens the newer store, logs that the store schema
is ahead of it, and leaves these columns and tables in place. So rolling the
binary back does not undo either migration. Do **not** start an old binary on
the upgraded database until compatibility is established. If reverting to the
retained `.backup`, first archive the post-upgrade database consistently, stop
all writers, and explicitly accept losing post-backup events. No database
restore is automatic in this runbook.

## Offline mutation catalogue and real paths

The mutation catalogue, `mutations.toml` at the repository root, already held
controls for these subsystems before this rollout. This rollout keeps them and
adds 16 more, whose IDs start with `s7-`. A control deliberately breaks one
line of production code and names the test that must fail because of it. Each
new control names the production line it breaks, the test that must catch the
break, `runner = "cargo"`, and a 3,600-second build deadline. The coverage is
additive:

| Property family | What the controls check | Existing controls | Controls added by this rollout |
| --- | --- | --- | --- |
| Exactly-once/canonical identity | Each event is stored once under one canonical key. Notices have stable per-version ids (v1: `event_key`, v2: `<event_key>.v2`); within the stream's deduplication window a publish-before-stamp retry adds no second entry. The outbox stamps both new and duplicate bus receipts, logging acknowledged duplicates at DEBUG, because each id identifies one immutable notice. Outside that window the same retry may create another entry. See [publish receipts and retries](../design/github-event-envelope-v2.md#publish-receipts-and-retries). Migration 45 keeps every subscription. | `s1-key-collision-dedup`, `s1-first-canonical-row`, `s1-key-index`, `s1-delivery-index`, `s3-legacy-body-unchanged`, `s4-ci-marker-discovery-dedup`, `bus-adapter-poll-and-ack` | `s7-drain-after-ack`, `s7-drain-pending-only`, `s7-notice-subject-v1`, `s7-migration-preserves-subscriptions` |
| Retention/deletion | Event bodies and pending markers are kept while they may still be delivered, and are deleted with their subscription or connection. Pruning undelivered rows records a coverage gap. | `s1-body-floor`, `s1-pending-marker-retention`, `s1-full-resume-window`, `s1-published-rows-no-gap`, `s1-unsubscribe-marker-delete`, `s1-connection-marker-delete`, `s1-orphan-marker-drain`, `s1-ack-body-retained` | `s7-sorted-head-boundary-retention`, `s7-retention-gap-observed-interval` |
| Quota/admission | No GitHub Actions request is sent without a committed reservation under the 600-an-hour ceiling. A CI cycle sends at most 8 requests, and watch cadence follows the active-watch count. | `s1-quota-limit`, `s1-quota-name-headroom`, `s1-quota-hour-expiry`, `s3-identity-committed-quota`, `s3-deferred-health-not-attempted`, `s4-ci-committed-quota`, `s4-ci-request-cap`, `s5-ci-fleet-cadence`, `s5-ci-cadence-active-count` | None. The existing controls in the preceding column already cover this family. |
| Authorization | Only admitted callers reach `events.get`. A caller sees an event body only if the repository is bound to its agent, or it holds a live `events_consume` grant on the event's connection. Missing and invisible keys get the same reply. | `s1-agent-binding-owner`, `s1-consumer-action-selector`, `bus-scoped-core-grant`, `bus-denied-metadata-only`, `bus-stamped-agent-identity`, `s3-identity-current-schema`, `s4-ci-pinned-schema`, `s5-ci-all-action-authority` | `s7-events-get-carrier`, `s7-basal-flow-required`, `s7-flow-carrier-admission`, `s7-flow-events-get-only`, `s7-event-name-mismatch`, `s7-invisible-and-missing-uniform`, `s7-agent-binding-case`, `s7-consumer-grant-owner`, `s7-consumer-grant-connection`, `s7-consumer-grant-live` |

Use `ckdev-mutate check` for anchors/exact names and `ckdev-mutate run --only
<control-id> --report <private-evidence-file>` for replay from a clean reviewed
checkout. Ordinary gates are still `cargo fmt --all` and
`bash scripts/rust-test-gate.sh`; a red mutant is not a passing baseline test.

CI keeps the replay results. The `mutations` job in `.github/workflows/ci.yml`
uploads its replay report as the artifact `mutations-<event>-<shard>` on every
run that replays controls: pushes to `main` and `train/**` branches, the nightly
schedule and manual runs. Pull request runs replay nothing; they only run
`ckdev-mutate check` in the Test job. No dependency report or synthetic test
substitutes for the live hour.

## Operator report to complete (pending: run at deploy)

The operator fills in this table after running the steps above. Each Result
cell gets the measured value and the path of the saved command output under
`$EVIDENCE`, for example `$EVIDENCE/migration-rehearsal.txt` or
`$EVIDENCE/bus-hour.txt`. Do not enter expected values. R is the number of
active `ci_runs` watches; it sets each watch's polling interval to R × 48
seconds, with a minimum of 300.

| Observation | Result |
| --- | --- |
| Deployed commit, binary inode/provenance, catalog revision | pending: run at deploy |
| Backup source schema version, pre-existing rows, NULL keys | pending: run at deploy |
| Row-value/count drift, outbox depth, first drain, second migration | pending: run at deploy |
| Poll grant (grantee `direct`) and Basal consume grant IDs; full forbidden-grantee listing | pending: run at deploy |
| Local bus/account, observer continuity, UTC start/end and duration | pending: run at deploy |
| R (active CI watch count) before/after, CI watches created, stored and health cadence | pending: run at deploy |
| Deferred CI cycles and identity reads, maximum trailing quota units | pending: run at deploy |
| Dispatch-time request count and maximum trailing count, get_repository included | pending: run at deploy |
| Notice counts by all six names, unexpected subjects | pending: run at deploy |
| Outbox published/pending before/after, last publish error | pending: run at deploy |
| Scratch repo/branch, run ID/attempt, job ID and vendor failure | pending: run at deploy |
| Exactly-one failed-job/run notices, headers, keys and digest/body fetch | pending: run at deploy |
| Rollback readiness or executed rollback evidence | pending: run at deploy |
