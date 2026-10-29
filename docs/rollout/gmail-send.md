# Gmail send backend

Plexus sends plain-text messages with the existing governed invocation path; it
does not add an agent tool, an inbox action, or an OAuth login implementation.
The vault must serve `oauth:gmail` through `credential.get_scoped`, with the
mailbox in `account_id` and a Google send-only OAuth grant. Plexus records that
mailbox when the operator creates the connection. A different or absent account
on a later read refuses the send, without changing the pin.

## Operator setup

Use the existing one-confirmation write-connection ceremony. Its exact filter
flag is **`--resource-filters`**, taking a JSON object:

```sh
ck-plexus-admin add-write-connection \
  --subc "$SUBC_CONNECTION_FILE" \
  --app gmail \
  --connection conn-gmail \
  --actions gmail.send \
  --risk write \
  --credential-id oauth:gmail \
  --grantee "$GRANTEE_PRINCIPAL" \
  --resource-filters '{"write_enabling":["to","cc","bcc"]}' \
  --apply
```

Omit `--apply` to preview. The composite performs the existing ticket, connect,
connection-admin grant, configure and invoke-grant steps. Its ticket step also
records the verified Gmail mailbox. There is no automatic Gmail filter default
at connection creation, and the generic write guard is unchanged. The three
selectors require explicit address lists, including empty lists; they do not
replace the recipient allowlist. No `values` map is needed. Messages to only cc
or bcc recipients remain valid with the other lists empty.

The command deliberately omits `--allow`, so default policy remains ask-first.
`catalog/gmail.jsonc` declares tier `S3`, and Plexus refuses every S3 action
while no decision plane is configured, which is the case in production today.
So no message is sent until the operator lowers the tier or a decision plane
exists; deciding that is part of going live. Standing
recipient authority, if desired, is a separate operator operation:

```sh
ck-plexus-admin recipients-add --subc "$SUBC_CONNECTION_FILE" \
  --connection conn-gmail --agent "$AGENT_ID" \
  --recipient alice@example.com --apply
```

Omitting `--agent` selects the module-only list, not every agent. Every actual
address in to, cc and bcc goes through the existing recipient gate. Approval
authorizes one message and never expands that list. No message is automatically
resent after a 401: Plexus reports the served credential version and re-reads
once. A 403 is a permission refusal, never a credential-failure report. Transport
failures and 5xx responses can leave a write's outcome unknown; reconcile before
retrying a send whose outcome is unknown.

## Sent-text custody

Before sending, Plexus composes the MIME message and seals it locally with
RFC 9180 base mode, X25519/HKDF-SHA256/ChaCha20-Poly1305. It caches only the
public half of `kem:plexus-sent-text:1`, verified against key id
`f0d59c165a515480`. The vault retains the private key. The vault must grant
`reserved:plexus` three things: `read` on `oauth:gmail` (the mailbox's token),
`read` on `kem:plexus-sent-text:1` (its public key), and `open` on
`kem:plexus-sent-text:1` (operator read-back).

An accepted result contains Gmail's message id and `sent_text_row_id`; it is not
a delivery receipt. Read or change retention only over the operator's direct,
unscoped management connection:

```sh
ck-plexus-admin sent-text-read --subc "$SUBC_CONNECTION_FILE" --row "$SENT_TEXT_ROW_ID"
ck-plexus-admin sent-text-retention --subc "$SUBC_CONNECTION_FILE" --days 30
```

Every read attempt is audited. Ciphertext retention defaults to 30 days and is
independent of audit retention; shortening it also shortens existing rows'
expiry. Expired ciphertext is inaccessible immediately and is physically
deleted by bounded scheduler housekeeping. The audit argument hash remains.

Pending approvals temporarily retain subject and body in plaintext for exact
matching and approved dispatch. Terminalization atomically replaces those two
fields with SHA-256 hashes and preserves recipients and all other arguments.
Expiry terminalization runs in housekeeping. SQLite free pages, WAL files and
backups made while approval was pending still need disk and backup protection;
logical scrubbing does not erase those earlier copies. See the
[recipient-gate design](../design/messaging-recipient-gate.md).
