# Recipient gate (service-independent core)

Actions opt in with `recipients`, an array of RFC 6901 JSON pointers into their
arguments, for example `["/to", "/cc"]`. Every pointer must resolve at ingest
through explicit reviewed schema types to a string or an array of strings.
REST actions use `http.args_schema`; MCP actions declaring recipients also
provide `input_schema`, because discovery is not a reviewed manifest schema.
Discovery that disagrees with that schema is quarantined. Ambiguous schemas
without explicit types, union schemas, and unresolved references fail closed.
No shipped vendor manifest opts in as part of this core change.

In `GovernanceEngine::authorize`, after catalog/schema checks and before any
approval or reservation, all declared recipients are resolved and normalized.
After normal grant/policy evaluation, any unlisted recipient changes the
effective policy to `ask_first`, except `block`, which always wins. Missing
pointers, wrong types, blank recipients, and an entirely empty recipient set
refuse with `recipient_argument_invalid`. Empty optional arrays are valid when
another pointer names an actual recipient; missing optional pointers are not.
Listed recipients still need normal grants and policy. Recipient actions start
ask-first until the operator sets an allow policy.

The key is `(connection_id, acting_agent_id, normalized_recipient)`. Module-only
calls use SQL NULL, enforced uniquely by a separate partial index (SQLite's
ordinary UNIQUE index permits duplicate NULLs). An attributed scope without
delegation uses the module-only key, not its attributed agent's list. Email-like
strings containing `@` are trimmed and lowercased; other identifiers are only
trimmed. Phone numbers are otherwise stored as given, without country-code or
punctuation canonicalization. Normalization has one implementation.

Unlisted interactive sends enter the existing approval/consent-card path.
Approval sends once and changes no allowlist entry. Flows refuse with
`consent_unavailable`, naming the action, before creating a request or reservation.
Allowlist edits and recipient declaration changes invalidate outstanding
reservations. Connection deletion removes its allowlist; offline cutover carries
existing entries, while older stores start with an empty list.

Consent cards for recipient actions show the complete secret-filtered argument
preview, including every recipient and all message text. Ordinary actions keep
their existing bounded preview. The pinned elicitation requester contract has no
string-length limit; the actual limit is subc-protocol 0.29.0's 64 MiB frame body.
Before parking a send, Plexus checks the serialized `method`/`params` envelope,
including JSON escaping and metadata. Oversized cards refuse with
`approval_preview_too_long`, action, byte length and byte limit; they are never
truncated. Text remains hashed in audit. Normalized, sorted, deduplicated
recipients are recorded as JSON after `recipients:` in `args_redaction_summary`,
alongside the existing `args_hash:`; malformed sets are marked `recipients:invalid`.

Operator commands, available only on the operator's direct connection:

```text
ck-plexus-admin recipients-add --subc <file> --connection <id> [--agent <id>] --recipient <id> [--apply]
ck-plexus-admin recipients-remove --subc <file> --connection <id> [--agent <id>] --recipient <id> [--apply]
ck-plexus-admin recipients-list --subc <file> --connection <id> [--agent <id>]
```

Omitting agent selects NULL, not a wildcard. Add/remove default to preview and
audit both previews and applies. Adding is a widening operation (mutating
management operation, write risk audit, and `widening: true` in its result).
Listing is read-only. Authority changes and audit records share one fenced
transaction.

## Gmail sent-text custody

Gmail uses the existing approval behavior: subject and body are plaintext in
`action_requests.args_snapshot` only while a request can still execute. Pending
and approved requests need that copy for exact-argument matching and dispatch.
On consumption, denial, expiry or withdrawal, a SQL trigger swaps in a prepared
snapshot in the same transaction, replacing only subject and body with SHA-256
hashes and keeping every recipient and other argument. There is no new manifest
content marker: archiving selects `gmail.send` explicitly. Expired
approvals are terminalized by the scheduler's existing housekeeping pass.

The composed RFC 822 message is separately sealed with RFC 9180 base-mode
X25519/HKDF-SHA256/ChaCha20-Poly1305 before sending. Its row id, connection id
and normalized recipient-set hash are associated data. Only the operator's
direct, unscoped admin route can open it through the vault, and every read
attempt is audited. `sent-text-read --row <id>` returns that composed message;
`sent-text-retention --days <1..3650>` sets an independent retention window
(default 30 days). The audit's original argument hash survives ciphertext expiry.

Scrubbing is logical SQLite deletion, not erasure of old WAL pages, free pages,
or backups captured while an approval was pending. Those temporary plaintext
copies still require the operator's disk and backup protection.

## Approval policy correction

Review of the recipient gate exposed an existing ordinary-approval bypass of
`block`. The operator explicitly requested correcting this for **every** action:
an approved-but-unsent call must respect a later block and remain unconsumed.
The regression exercises both declared and undeclared actions. Existing approval
tests did not assert the bypass; their original single-use and stale-shape claims
are retained.
