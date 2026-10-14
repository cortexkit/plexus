# Plexus: concurrency and time limits

This is plexus's section of the fleet concurrency spec (`subconscious/docs/specs/ck-concurrency.md`, section 3). Every value is quoted from source with its constant and location, so a code change shows up as a difference from this page. Measured values are marked as such.

## Admission

| Limit | Value | Source |
|---|---|---|
| Concurrent tool requests | No plexus-side cap. Each request frame runs on its own task, so one slow call never blocks another or the scheduler. Admission is bounded by the daemon's per-connection limits (fleet spec section 1). | `crates/plexus-module/src/lib.rs:862-868` |
| `web_search` per caller | 30 calls/min by default (token bucket, starts full, refills over 60 s) | `DEFAULT_PER_CALLER_PER_MINUTE`, `crates/plexus-core/src/web_search/limiter.rs:10-15` |
| `web_search` per backend | 120 calls/min by default, shared by all callers of that backend | `DEFAULT_PER_BACKEND_PER_MINUTE`, same file |
| `web_search` operator override | 1 to 100,000 per minute, per backend, stored in `web_search_limits`; takes effect on the next search | `MAX_WEB_SEARCH_LIMIT`, `crates/plexus-module/src/ceremony.rs:753-802` |
| `web_search` result cache | 10 min, 1,000 entries, in memory, shared across callers; a hit still checks grants, policy and the rate limit | `CACHE_TTL_MS`, `CACHE_CAPACITY`, `crates/plexus-core/src/web_search/cache.rs:13-16` |

A refused `web_search` over its limit carries `retry_after`. Bucket state is in memory and resets on restart.

## A governed call

| Step | Limit | Source |
|---|---|---|
| Reservation (authorize to dispatch) | 60 s | inline `now + 60_000`, `crates/plexus-core/src/governance.rs:1530-1539` |
| Approval request (`ask_first`) | expires after 5 min | inline `now + 300_000`, `crates/plexus-core/src/governance.rs:1407-1415` |
| Vault credential read | 30 s, no plexus retry | `subc-client-rs` 0.17.0 `DEFAULT_CALL_TIMEOUT` via `CallOptions::default()`, `crates/plexus-core/src/credentials.rs:759-794` |
| Vendor HTTP connect | 10 s | `DEFAULT_CONNECT_TIMEOUT`, `crates/plexus-core/src/http_support.rs:20-21` |
| Vendor HTTP request, whole | 30 s | `DEFAULT_REQUEST_TIMEOUT`, `crates/plexus-core/src/http_support.rs:22-23` |
| HTTP connection pool idle eviction | 300 s | `DEFAULT_IDLE_TIMEOUT`, `crates/plexus-core/src/http_support.rs:24-25` |

Retries:
- **REST never re-sends a request.** A `Retry-After` from the vendor delays the next dispatch; it does not replay this one (`rest_api.rs:311-318`, `337-365`).
- **MCP remote re-sends once, only after an auth or session rejection,** which means the vendor refused before acting (`mcp_remote.rs:502-529`). A timeout is never re-sent; it reports `outcome_unknown` (test at `mcp_remote.rs:1515-1535`).
- **A write whose outcome is unknown is never retried automatically.** The caller is told `outcome_unknown`, and governance never turns it into a resend.

## GitHub bot writes

| Limit | Value | Source |
|---|---|---|
| Receipt claim lease | 120 s default, 60 s minimum | `DEFAULT_CLAIM_LEASE_SECONDS`, `MIN_CLAIM_LEASE_SECONDS`, `crates/plexus-core/src/github/receipt.rs:40-49` |
| Pre-dispatch read budget | 120 s (reuses the claim lease), so the walk ends before a retry could take over the receipt | `crates/plexus-core/src/github/pagination.rs:89-103` |
| Comment page walk | 100 pages of 100; a full walk reports `incomplete`, never "not found" | `MAX_PAGES`, `PER_PAGE`, `crates/plexus-core/src/github/pagination.rs:9-10` |
| Terminal receipt retention | 30 days | `RETENTION_MS`, `crates/plexus-core/src/github/receipt.rs:40-44` |

A retry with the same request id while the first attempt holds the lease is answered "in flight"; it never sends a second time.

## Identity

Agent identity is read from the daemon route's session stamp (`scope.rs`). There is no assertion verifier, signing-key lookup, negative-generation cache or assertion clock-skew budget. A bot write requires an authorized delegating scope and rechecks it with `scope.describe` before each write; an unavailable scope refuses rather than falling back.

## Scheduler

| Limit | Value | Source |
|---|---|---|
| Tick | 1 s | `SCHEDULER_TICK`, `crates/plexus-module/src/lib.rs:73` |
| Poll order | sequential, one subscription at a time, so no two polls of one feed overlap | `crates/plexus-core/src/scheduler.rs:200-207`, `258-303` |
| Failure backoff | `cadence × 2^n`, capped at 3,600 s; a cadence above 3,600 s stays the floor | `BACKOFF_BASE`, `BACKOFF_CEILING_S`, `crates/plexus-core/src/scheduler.rs:57-77` |
| Circuit breaker | 5 consecutive vendor failures suspend the watch (resumable) | `CIRCUIT_BREAKER_FAILURES`, `crates/plexus-core/src/scheduler.rs:79-91` |
| Actor enrichment | 32 governed reads per poll cycle | `ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE`, `crates/plexus-core/src/poller.rs:99-107` |
| Ordered-timestamp pages | 5 per poll, then a coverage gap row | `ORDERED_TIMESTAMP_MAX_PAGES_PER_POLL`, `crates/plexus-core/src/poller.rs:70-72` |
| Health probes | every 60 s, off the request path | `HEALTH_PROBE_INTERVAL`, `crates/plexus-module/src/lib.rs:84-90` |
| Retired-agent sweep | hourly; one Prefrontal lookup per agent holding grants, stopping at the first unanswered lookup | `AGENT_RETIREMENT_SWEEP_INTERVAL_MS`, `crates/plexus-core/src/agent_retirement.rs` |
| Retention prunes | at most 1,000 rows per call, per pass | `AUDIT_RETENTION_BATCH_ROWS`, `RESERVATION_RETENTION_BATCH_ROWS`, `crates/plexus-core/src/storage.rs:31-37` |

Poll failures never retry within a pass. The next attempt is the next due time under backoff.

Under the fleet spec's rule 6, polling, health probes, the retired-agent sweep and retention prunes are plexus's owned background work. Each is durable or deduplicated: a poll commits its cursor and events in one transaction, and events are deduplicated on (connection, subscription, vendor id, payload hash). Each is bounded by the limits in the table above.

## How this nests in the fleet's timeouts (fleet spec section 2)

- **A tool call:** vault read (30 s) and vendor request (30 s) run one after the other, inside a 60 s reservation. So a governed call can take up to about 60 s plus approval time. A caller whose own timeout is shorter gets its reply dropped, and the call itself still completes and is audited. For writes, that's why an unanswered caller must treat the outcome as unknown, never as "not sent".
- **Drain is not bounded by the module drain window.** On EOF the dispatch loop stops reading and waits for the scheduler's current pass to finish (`lib.rs:330-340`), with no bound. A pass is sequential, so it lasts as long as its due polls together, which can exceed the daemon's 30 s drain window, so plexus may be killed mid-pass. That's safe by construction: each poll commits its cursor and events in one fenced transaction, so an interrupted pass delays wakes and loses nothing. Tool requests in flight at the kill aren't awaited. An authorized call has its authorization audit row already written, and a bot write's receipt reports "in flight" to a retry until its lease runs out, so nothing is sent twice.
- **Retired-agent sweep inside a pass:** at most one Prefrontal call timeout (30 s) per sweep, because it stops at the first unanswered lookup.
