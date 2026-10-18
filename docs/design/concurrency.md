# Plexus: concurrency and time limits

This is plexus's section of the fleet concurrency spec (`subconscious/docs/specs/ck-concurrency.md`, section 3). Limits below cite source files and symbols rather than unstable line numbers. This page is maintained manually; source and committed dependency lockfiles are authoritative. Measured values are marked as such.

## Admission

| Limit | Value | Source |
|---|---|---|
| Concurrent tool requests | No plexus-side cap. Each request frame runs on its own task, so one slow call never blocks another or the scheduler. Admission is bounded by the daemon's per-connection limits (fleet spec section 1). | `crates/plexus-module/src/lib.rs` |
| `web_search` per caller | 30 calls/min by default (token bucket, starts full, refills over 60 s) | `DEFAULT_PER_CALLER_PER_MINUTE`, `crates/plexus-core/src/web_search/limiter.rs` |
| `web_search` per backend | 120 calls/min by default, shared by all callers of that backend | `DEFAULT_PER_BACKEND_PER_MINUTE`, same file |
| `web_search` operator override | 1 to 100,000 per minute, per backend, stored in `web_search_limits`; takes effect on the next search | `MAX_WEB_SEARCH_LIMIT`, `crates/plexus-module/src/ceremony.rs` |
| `web_search` result cache | 10 min, 1,000 entries, in memory, shared across callers; a hit still checks grants, policy and the rate limit | `CACHE_TTL_MS`, `CACHE_CAPACITY`, `crates/plexus-core/src/web_search/cache.rs` |

A refused `web_search` over its limit carries `retry_after`. Bucket state is in memory and resets on restart.

## A governed call

| Step | Limit | Source |
|---|---|---|
| Reservation (authorize to dispatch) | 60 s | `RESERVATION_TTL_MS`, `crates/plexus-core/src/governance.rs` |
| Approval request (`ask_first`) | expires after 5 min | `APPROVAL_TTL_MS`, `crates/plexus-core/src/governance.rs` |
| Vault credential read | 30 s, no plexus retry | the locked `subc-client-rs` `DEFAULT_CALL_TIMEOUT` via `CallOptions::default()`, `crates/plexus-core/src/credentials.rs` |
| Vendor HTTP connect | 10 s | `DEFAULT_CONNECT_TIMEOUT`, `crates/plexus-core/src/http_support.rs` |
| Vendor HTTP request, whole | 30 s | `DEFAULT_REQUEST_TIMEOUT`, `crates/plexus-core/src/http_support.rs` |
| HTTP connection pool idle eviction | 300 s | `DEFAULT_IDLE_TIMEOUT`, `crates/plexus-core/src/http_support.rs` |

Retries:
- **REST never re-sends a request.** A `Retry-After` from the vendor delays the next dispatch; it does not replay this one (`rest_api.rs`, `337-365`).
- **MCP remote re-sends once, only after an auth or session rejection,** which means the vendor refused before acting (`mcp_remote.rs`). A timeout is never re-sent; it reports `outcome_unknown` (test at `mcp_remote.rs`).
- **A write whose outcome is unknown is never retried automatically.** The caller is told `outcome_unknown`, and governance never turns it into a resend.

## GitHub bot writes

| Limit | Value | Source |
|---|---|---|
| Receipt claim lease | 120 s fixed production lease | `DEFAULT_CLAIM_LEASE_SECONDS`, `crates/plexus-core/src/github/receipt.rs` |
| Pre-dispatch read budget | 120 s (reuses the claim lease), so the walk ends before a retry could take over the receipt | `crates/plexus-core/src/github/pagination.rs` |
| Comment page walk | 100 pages of 100; a full walk reports `incomplete`, never "not found" | `MAX_PAGES`, `PER_PAGE`, `crates/plexus-core/src/github/pagination.rs` |
| Terminal receipt retention | 30 days | `RETENTION_MS`, `crates/plexus-core/src/github/receipt.rs` |

A retry with the same request id while the first attempt holds the lease is answered "in flight"; it never sends a second time.

## Identity

Agent identity is read from the daemon route's session stamp (`scope.rs`). There is no assertion verifier, signing-key lookup, negative-generation cache or assertion clock-skew budget. A bot write requires an authorized delegating scope and rechecks it with `scope.describe` before each write; an unavailable scope refuses rather than falling back.

## Scheduler

| Limit | Value | Source |
|---|---|---|
| Tick | 1 s | `SCHEDULER_TICK`, `crates/plexus-module/src/lib.rs` |
| Poll order | sequential, one subscription at a time, so no two polls of one feed overlap | `crates/plexus-core/src/scheduler.rs`, `258-303` |
| Failure backoff | `cadence × 2^n`, capped at 3,600 s; a cadence above 3,600 s stays the floor | `BACKOFF_BASE`, `BACKOFF_CEILING_S`, `crates/plexus-core/src/scheduler.rs` |
| Circuit breaker | 5 consecutive vendor failures suspend the watch (resumable) | `CIRCUIT_BREAKER_FAILURES`, `crates/plexus-core/src/scheduler.rs` |
| Actor enrichment | 32 governed reads per poll cycle | `ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE`, `crates/plexus-core/src/poller.rs` |
| Ordered-timestamp pages | 5 per poll, then a coverage gap row | `ORDERED_TIMESTAMP_MAX_PAGES_PER_POLL`, `crates/plexus-core/src/poller.rs` |
| Health probes | every 60 s, off the request path | `HEALTH_PROBE_INTERVAL`, `crates/plexus-module/src/lib.rs` |
| Retired-agent sweep | hourly; one Prefrontal lookup per agent holding grants, stopping at the first unanswered lookup | `AGENT_RETIREMENT_SWEEP_INTERVAL_MS`, `crates/plexus-core/src/agent_retirement.rs` |
| Reconciliation sweep | At most 8 queued records per pass; retryable reads and completion-store failures back off | `GovernanceEngine::sweep_write_reconciliations`, `crates/plexus-core/src/reconciliation.rs` |
| Retention prunes | at most 1,000 rows per call, per pass | `AUDIT_RETENTION_BATCH_ROWS`, `RESERVATION_RETENTION_BATCH_ROWS`, `crates/plexus-core/src/storage.rs` |

Poll failures never retry within a pass. The next attempt is the next due time under backoff.

Under the fleet spec's rule 6, polling, health probes, the retired-agent sweep and retention prunes are plexus's owned background work. Each is durable or deduplicated: a poll commits its cursor and events in one transaction, and events are deduplicated on (connection, subscription, vendor id, payload hash). Each is bounded by the limits in the table above.

## Setup and maintenance boundaries

Every agent-requested connector action passes through `GovernanceEngine` before credentialed dispatch. Connector metadata discovery, periodic health probes, and operator-authorized GitHub handle import/probe/bind validation are setup and maintenance exceptions: they may contact vendors with credentials outside the action-governance pipeline. These exceptions do not authorize ordinary agent actions, and their setup/health/control checks and available audit records are separate from invocation decision/dispatch audit pairs.

## Pull event acknowledgements and retention

The events list/ack pull surface is a shared work queue. The connection owner and all overlapping `events_consume` grantees see the same unacknowledged rows; an acknowledgement by any one of them drains those rows for all of them. This is not independent per-consumer broadcast delivery. Acknowledgement retains event payloads and does not affect event-outbox publication. Large acknowledgement requests are processed in idempotent transactions of at most 500 ids; a caller may safely retry the whole request after an ambiguous or partial failure.

Runtime audit rows are immutable, and ordinary retention cannot delete rows within the seven-day SQL floor; the default retention window is thirty days. Migration 40 was a one-time historical exception: for eligible revoked connections it temporarily removed the deletion triggers, purged associated audit and grant-revocation rows, and restored the triggers. Runtime connection deletion leaves both audit evidence and revocation snapshots intact; audit retention removes only sufficiently old audit rows, while revocation snapshots are otherwise retained indefinitely.

## How this nests in the fleet's timeouts (fleet spec section 2)

- **A tool call:** vault read (30 s) and vendor request (30 s) run one after the other, inside a 60 s reservation. So a governed call can take up to about 60 s plus approval time. A caller whose own timeout is shorter gets its reply dropped, and the call itself still completes and is audited. For writes, that's why an unanswered caller must treat the outcome as unknown, never as "not sent".
- **Owned-task shutdown has a bounded grace period.** On EOF the module cancels background work and waits up to `TASK_SHUTDOWN_GRACE` (5 s), then aborts remaining tasks (`crates/plexus-module/src/lib.rs`). Sequential polls or blocking HTTP work may outlast that grace; aborting an async wrapper does not cancel an already-running blocking request. Cursor/event transactions and receipt leases provide crash safety, not a promise that all vendor work drains before exit. An unanswered write must be treated as outcome unknown, never automatically resent.
- **Retired-agent sweep inside a pass:** at most one Prefrontal call timeout (30 s) per sweep, because it stops at the first unanswered lookup.
