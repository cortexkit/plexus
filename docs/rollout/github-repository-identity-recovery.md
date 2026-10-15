# Repository-name identity changes: deployment and recovery

## What failed, and what was already fixed

The running revision `63a05b3e8b28a9b8818282d53e1e07ce0b1cabbc` suspended
watches directly in relay admission, without updating `github_repo_id_cache`.
Every webhook for the new repository therefore disagreed with the same old ID.
The hourly ownership reconciliation, which creates issue, pull-request and CI
watches for owned repositories, excluded identity-suspended watches and created
another trio;
the next webhook suspended that trio too. No transaction rollback was needed to
cause this loop. The relay drop is a successful transaction: its drop counter,
suspension and relay cursor commit together.

Commit `24e9861baf6e69f8a53403e2a8e951094a8e42b2`, already included in the base of
this change, replaced the direct UPDATE with
`event_outbox::record_repo_id_resolution_on_conn`. That helper commits the cache
update and suspension together. Thus the reported loop is reproducible by
restoring the deployed direct UPDATE, **not** on the current base. The
`webhook_identity_change_survives_ownership_and_later_delivery` test uses a
file-backed store, an independent reader, the real ownership reconciliation,
and subsequent issue, PR and CI webhooks to distinguish these implementations.

The storage warning was absent on the deployed relay path because that path did
not call the storage helper. A successful poll-side `get_repository` could call
it and repair the cache, explaining the reported storage warning that
`cortexkit/broca` changed from ID 1278076757 to 1418105103. Ownership does
not capture a repository ID in each new watch: relay admission and polling use
the shared name cache. The normal webhook cache-seeding UPSERT only updates an
existing row if its ID is NULL. Other writes are the shared resolution helper,
a CI marker's NULL-only seed, and reservation of a lookup timestamp; none
unconditionally restores the old ID. A resolver actually returning an older ID
could still change it back; that is not necessary to explain this defect.

This change removes the redundant relay warning: the shared storage helper is
the single identity-change warning source. After reconciliation has a complete
active replacement issue/PR/CI trio on the standard direct connections, it
retires the obsolete identity-suspended rows and audits each retirement. It
also handles a replacement trio that already existed before deployment.
Retirement changes status and generation only, preserving stored events,
outbox markers, cursors and the suspension reason. It is not `unsubscribe`:
unsubscribe deletes events. Release watches, other principals/connections and
other suspension reasons are not retired by this cleanup. If CI prerequisites
are absent or any replacement is paused, cleanup waits for an active trio.
Historical retired rows remain for event visibility; repeated same-ID webhooks
no longer create more rows.

## Deploy, inspect, and clean up the reported 57 + 18 rows

Live store access was unavailable to the editing worker. The counts, IDs and
times in the incident report are operator observations, not independently
verified here. Do not run any write against a running daemon. Take a consistent
backup using the deployment's normal backup procedure before offline repair.

Preferred cleanup is **deployment plus the next ownership pass** (normally
hourly). It performs the audited retirement automatically. There is no
`ck-plexus-admin` watch-retirement or cursor-rewind command. Do not substitute
`delete-connection`, `events unsubscribe`, or `events resume`.

Run these inspections read-only before and after the next ownership pass:

```sh
sqlite3 -readonly "$HOME/.local/share/cortexkit/plexus/store.db" <<'SQL'
SELECT repo, repo_id, last_attempt_at_ms, resolved_at_ms
FROM github_repo_id_cache
WHERE repo IN ('cortexkit/broca','cortexkit/plexus');
SELECT lower(json_extract(fixed_args,'$.owner') || '/' || json_extract(fixed_args,'$.repo')) AS repo,
       principal, connection_id, action, status, suspended_reason, count(*)
FROM trigger_subscriptions
WHERE lower(json_extract(fixed_args,'$.owner'))='cortexkit'
  AND lower(json_extract(fixed_args,'$.repo')) IN ('broca','plexus')
GROUP BY 1,2,3,4,5,6 ORDER BY 1,2,3,4,5,6;
SQL
```

If manual cleanup is necessary **after deploying the fix**, stop the daemon,
back up the database, and run the following exact transaction using an offline
SQLite connection with bail-on-error enabled (`sqlite3 -bail "$STORE"`). It
mirrors the automatic cleanup but is limited to the two incident repositories.
Preview the selected IDs before proceeding; expect 57 + 18 only if nothing has
changed since the incident snapshot. An incomplete trio intentionally selects
nothing. The transaction retains every event and records ownership audit rows.
If a statement fails, close the connection without committing.

```sql
BEGIN IMMEDIATE;
CREATE TEMP TABLE identity_retire_ids AS
WITH eligible AS (
    SELECT s.*, lower(json_extract(s.fixed_args,'$.owner') || '/' || json_extract(s.fixed_args,'$.repo')) AS repo_name
    FROM trigger_subscriptions s JOIN connections c
      ON c.principal=s.principal AND c.connection_id=s.connection_id
    WHERE s.principal='direct' AND c.status='active' AND (
      (s.connection_id='conn-github' AND c.app_key='github' AND s.action='list_issues') OR
      (s.connection_id='conn-github-prs' AND c.app_key='github' AND s.action='list_pull_requests') OR
      (s.connection_id='conn-github-actions' AND c.app_key='github_actions' AND s.action='list_workflow_runs'))
), replaced AS (
    SELECT repo_name FROM eligible WHERE status='active'
    GROUP BY repo_name HAVING count(DISTINCT action)=3
)
SELECT subscription_id, repo_name FROM eligible
WHERE status='suspended' AND suspended_reason='repository_identity_changed'
  AND repo_name IN ('cortexkit/broca','cortexkit/plexus')
  AND repo_name IN (SELECT repo_name FROM replaced);
SELECT repo_name, count(*) FROM identity_retire_ids GROUP BY repo_name;
SELECT * FROM identity_retire_ids ORDER BY repo_name, subscription_id;
INSERT INTO audit_journal
    (ts,principal,actor,acting_principal,action,decision,reason_code,gate,args_redaction_summary,outcome)
SELECT CAST(strftime('%s','now') AS INTEGER)*1000, 'direct','plexus','direct','retire','allow',
       'repository_ownership','entorhinal_reconcile',
       'subscription ' || subscription_id || ': {"reason":"repository_identity_changed","replacement":"active_trio","operatorCleanup":true}',
       'recorded'
FROM identity_retire_ids;
UPDATE trigger_subscriptions SET status='retired', generation=generation+1
WHERE principal='direct' AND subscription_id IN (SELECT subscription_id FROM identity_retire_ids);
DROP TABLE identity_retire_ids;
COMMIT;
```

Restart the fixed daemon and repeat the read-only inspection. Never edit the
cache entries for `cortexkit/broca` or `cortexkit/plexus` back to their private
repositories' IDs: those names now denote the new public repositories.

## Recovery of the missed interval

Retirement does not recover events missed before the replacement watches were
created. Automatic replacement cursors still seed at creation time. We do not
add automatic catch-up here: neither the identity cache nor a subscription has
a durable first-identity-change timestamp, and old relay suspensions did not
store a coverage-gap event. `resolved_at_ms` is the most recent resolution,
not the start of the outage; watch `created_at_ms` is not its suspension time.
Guessing from either silently under-recovers. Restoring an old watch's cursor
would also mix two different repository identities.

1. Establish the **first suspension for each repository**, from the relay's
   retained webhook/drop records correlated with repository payloads and the
   deployment logs. Use that timestamp (or an earlier conservative bound), not
   the last hourly replacement or broca's 22:24:03Z cache refresh (which marks
   a later successful resolution, not the first suspension). In this
   incident, inspect broca's rename and replacement on **2026-10-13** (warnings already occurred
   at 2026-10-14T00:00Z); use plexus's approximately
   **2026-10-14T15:47:00Z** rename as a conservative plexus bound, rather than
   16:00Z. Confirm the actual first suspension before selecting an exact lower
   bound. The old relay warning did not name a repository, so a warning line
   alone cannot establish per-repository time. If records cannot establish
   broca's first suspension, start before its earliest possible rename.
2. Inspect retained gaps and watch checkpoints as supporting evidence, not as
   proof of the missing interval:

   ```sql
   SELECT json_extract(s.fixed_args,'$.owner') || '/' || json_extract(s.fixed_args,'$.repo') AS repo,
          s.subscription_id, s.created_at_ms, s.last_success_at_ms, s.last_polled_at_ms,
          s.cursor_kind, s.cursor_state, e.observed_at_ms, e.gap_from_ms, e.gap_to_ms, e.gap_reason
   FROM trigger_subscriptions s LEFT JOIN trigger_events e
     ON e.subscription_id=s.subscription_id AND e.principal=s.principal AND e.kind='gap'
   WHERE lower(json_extract(s.fixed_args,'$.owner'))='cortexkit'
     AND lower(json_extract(s.fixed_args,'$.repo')) IN ('broca','plexus')
   ORDER BY repo, s.created_at_ms, e.observed_at_ms;
   ```

3. Verify the active catalog actions and live poll grants required for each
   vendor read instead of making ungoverned vendor requests. Existing
   admin commands include (inspect before creating duplicate grants):

   ```sh
   "$LIVE_BIN/ck-plexus-admin" list-grants --subc "$SUBC" --connection conn-github-actions --all
   "$LIVE_BIN/ck-plexus-admin" grant --subc "$SUBC" --connection conn-github-actions \
     --grantee direct --kind poll --risk read \
      --actions list_workflow_runs,get_workflow_run,list_jobs_for_workflow_run_attempt,get_repository
   ```

   Inspect the corresponding issue/PR and comment-read grants too. Grants
   restore authority; they do **not** rewind cursors or recover history.

4. Do not create temporary recovery watches on the live relay merely to rewind
   a cursor. The existing `events` tool accepts new seeded subscriptions, but
   that is not an in-place rewind or a bounded, self-terminating backfill.
   Issue seeds use `watermark_ms`; PR seeds also accept `watermark_id`; CI seeds
   use `scanned_through_ms` and acquire approved schema pins during polling.
   Duplicating the active issue/PR pair without first coordinating project and
   actor-source stamps can change which watch the relay chooses and can drop
   webhooks when the selected projects disagree. There is also no supported
   event-preserving retirement command for a temporary recovery watch. These
   constraints make a live seeded-watch workaround inappropriate without a
   separately reviewed recovery plan. Do not use `unsubscribe` to stop a
   recovery watch: it can delete the only stored copy of its events.
5. Do not claim exact recovery from seeded polling. Issues drain at most five
   30-item pages per cycle and report page-limit/cursor gaps; PRs inspect only
   the newest 100-item page and report saturation. CI reserves at most eight
   requests per cycle under Plexus's shared 600-request/hour GitHub Actions
   vendor-read budget, rotates a paged rescan,
   has an age floor of seven days minus one hour and a 1,000-result filtered-list
   ceiling, and reports incomplete coverage. Monitor those gap events. Issue/PR list
   responses contain current states, not every intervening historical change.
   If exact historical delivery is required, preserve the relay's retained
   webhook payloads and request a separately reviewed, repository-ID-scoped
   bounded replay through normal event admission (including the dropped first
   webhook); neither an admin rewind nor such a replay command exists today.
   Do not reset the live relay cursor, forge event rows, bypass read grants, or
   raise CI quota to make a catch-up appear complete.
