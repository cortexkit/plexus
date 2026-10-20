# Reviewed vendor manifests

`crates/plexus-core/src/manifest.rs` defines the closed JSON model for
`catalog/*.jsonc`. Unknown fields refuse ingest. Deploy the binary before a
catalog that needs its validation or fields; roll back the catalog before the
binary. Parsing is a necessary check, not a substitute for reviewing vendor
semantics.

## Authority and schemas

- Risk is reviewed, never inferred from vendor discovery. Writes and destructive
  actions always ask first; per-action `ask_first` and recipient declarations can
  widen that floor. Re-ingest propagates risk, tier, ask-first and reconciliation
  metadata to existing REST rows, preserving operator quarantine/status and schema
  pins. Changing that metadata increments the catalog row's generation counter,
  invalidating reservations authorized against the previous counter value.
- REST actions declare `http.args_schema`. MCP actions may declare an exact
  `input_schema`; a discovery mismatch quarantines them. Do not invent a partial
  schema merely to make validation pass: it is compared with the whole vendor
  input schema.
- Resource-filter keys are dot-delimited object-property paths, such as `owner`
  or `scope.repo`, in at least one reviewed input schema. Dynamic map keys and
  array traversal are not supported. Ingest refuses paths with no reviewed
  declaration. Runtime governance must refuse a configured allowlist whose path
  is missing from the call, including reads. The pinned input schema remains the
  authority on arguments; a filter does not invent an argument.
- Schema-backed REST filters remain: `github_rest` and `github_actions` use
  `owner`/`repo`, and `posthog_rest` uses `project_id`. MCP
  catalogs without full reviewed schemas no longer advertise synthetic filters.
  Known vendor names for a future schema review include DeepWiki `repoName`,
  Sentry `organizationSlug`/`projectSlug`, and Google Calendar `calendarId`.
  A Resend sender domain is not a `from_domain` argument: domain projection needs
  its own reviewed implementation and cannot be expressed by renaming a key.
- An action returning credential material is **never declared**, even when the
  vendor classifies it as a read. Neon `get_connection_string` returns a URI
  containing a database password and is excluded. A reviewed denylist rejects
  that known action name. It does not detect arbitrary secrets, aliases, new
  vendor actions or later output-contract changes; human output review remains
  mandatory.

## Supported controls and descriptive metadata

Ordinary REST and remote MCP actions may declare a closed `error_signals` list.
Specialized GitHub REST read-envelope, job-log and artifact-file shapes refuse
declarations at ingest, naming the action and shape, because their custom response
paths do not evaluate these predicates. A rule
contains `status`, `signal` (`quota_exhausted`, `credential_rejected`, or
`no_results`), and `matches`: either `{"kind":"json","pointer":"/error/code",
"value":"REVIEWED_CODE"}` or a response `header` with a `name` and `condition`.
Header conditions are `exact` (`value`) or `comma_separated_element` (zero-based
`index` and exact `value`, ignoring only surrounding space/tab). JSON pointers
address the complete REST error body or MCP JSON-RPC envelope, never parsed text
inside an MCP content block. Different fields can coexist, so ingest
conservatively rejects same-status rules unless different exact values of the
same field or header element prove them disjoint. Header names are case-insensitive;
repeated headers never match. Truncated or invalid JSON cannot match a body rule.

Only vendor-documented stable fields belong here, with a dated official citation
in the catalog. No substring, regex, or prose inference is supported. Transports
evaluate only error replies for the dispatched action, before replacing vendor
diagnostics with fixed messages. Only the fixed signal reaches classification.
An HTTP 401 is always treated as a rejected credential, whatever signal a rule
would give. Otherwise a matched signal decides the outcome ahead of the ordinary
status rules (429 throttling with its retry delay, 400 and 422 as a rejected
request). A `credential_rejected` signal reports the same definite failure to
the credential source that an HTTP 401 does. In web search's provider chain,
`quota_exhausted` skips that provider for one hour, and `no_results` returns an
empty result list instead of stopping the search. Undeclared actions
retain their existing behavior. Older binaries reject `error_signals`: deploy the
binary first and restore the old catalog before binary rollback.

`availability` and `reuse_rationale` are display/review metadata, not connection
or governance gates. In particular, `gated` is not an operator admission switch.
No production decision plane is wired: S3/S4 actions refuse regardless of those
labels. `defaults.rate_limit` is accepted and ignored: plexus has no
per-connection call limit. Vendor 429 replies and their Retry-After are what pace
calls, and the search facades have separate implemented limiters. The field is
optional; shipped catalogs still carry it so an older binary, which requires it,
can read them.

`idempotency`, `auth.oauth.profile_digest` and `auth.oauth.requested_scopes` are
deprecated and ignored. Shipped catalogs omit idempotency; the three OAuth
catalogs retain empty digest/scope values solely because older binaries require
those fields to parse. The parser temporarily keeps
accepting them so a binary upgrade can still read a separately deployed older
catalog. They neither enable retries, pin a profile nor request/restrict OAuth
scopes. OAuth authority comes from the registered `profile_id`. Removing the
legacy parser fields requires a later compatibility cutover after old catalogs
are gone.

Credential bindings support required headers using the connection's single
primary credential. `required: false`, unknown roles, invalid header names and
duplicate header names refuse. `primary` is the canonical role; legacy `api_key`
is an alias under API-key auth, `oauth`/`oauth_token`/`access_token` under OAuth,
and `app_install`/`access_token` under App-install auth. These labels never select
an additional credential. Anonymous auth has no bindings; credentialed auth must
have at least one. Header placement is the only supported placement.

## Polling and uncertain writes

Poll shapes require read risk and a nonblank `item_kind`. `snapshot_diff` has no
runtime strategy and refuses ingest. A sorted-head poll must declare a page-size
constant **and a separate ordering constant**; a page size alone does not declare
ordering. Review still has to establish that those constants actually request
the vendor's order.

`defaults.catalog_ttl_s: 0` selects the reconciler's configured TTL fallback;
omitting the field selects the manifest model's 24-hour default. Higher-severity
writes classified S3 cap that age at one hour; the highest severity, S4,
requires fresh discovery for every write.

A reconciliation class requires nonempty correlation fields, a read target and a
timeout of 1–86,400 seconds. When a write schema exists, every correlation field
must be a declared write property. Missing original values settle as ambiguous
without a vendor read. A transient not-sent read remains queued, and completion
store failures back off rather than claiming terminal success. A sweep processes
at most eight queued records, including expired records, so backlogs cannot send
1,000 synchronous read-backs in one pass. Vendor timeouts can still delay that
bounded pass; this is not an asynchronous worker pool.

The existing class uses the same flat field names to construct read arguments
and match response candidates. It cannot synthesize time windows/body hashes or
translate write arguments into vendor-specific read arguments. No shipped
manifest now declares a class. Former fields such as `body_hash` and `time_window`
were not vendor arguments and no code synthesized them, so they could never
establish an outcome. A future declaration needs reviewed read argument and
response semantics, not merely matching property names. Unknown writes are never
automatically re-sent.
