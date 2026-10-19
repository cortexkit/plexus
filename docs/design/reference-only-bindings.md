# Reference-only connection credentials

As of 2026-09-29, `connections.credential_binding` contains a versioned,
non-secret vault id (`plexus:vault-reference:v1\0` followed by the id), or NULL.
Enrollment proves the id through `credential.get_scoped` before writing a row.
Public connect still consumes a single-use ceiling-bearing ticket. Sending
`handle` to either enrollment or connect returns `handle_bindings_removed` with
a `credential_id` remedy. Both CLIs use `--credential-id`, never `--handle-file`.

## Recovery, migration and rollback

Migration 33 runs once under the store's existing version guard. It nulls legacy
blobs **only on revoked connections**. Pending and degraded connections can
recover, and rows in the retired auth_required and disabled statuses (still
admitted by the schema, written by no current code) are kept the same way;
their bindings are not disposable. There is
no `retired` connection status (retirement belongs to app manifests).

Open refuses any non-revoked non-reference binding, naming all offending
connection ids and directing the operator to `ck-plexus-admin rebind-credential`
on the previous build. It never interprets a legacy blob as anonymous authority.
Import applies the same refusal and revoked-only scrub, while carrying references
byte-for-byte. Anonymous access still requires a reviewed `auth.mode = none`.

The store never reads, creates, chmods or deletes `.plexus-binding-key`. An old
file is operator cleanup. `grant-revocations.jsonl` remains in the database's
parent directory, independently located by `grant_journal_path`; journal replay
still precedes serving authority.

The preceding binary at 3684df0 understands the reference envelope. It can serve
all retained references on a migrated store, and NULL on revoked rows grants no
authority. That older binary still has its own key-opening behavior; this change
does not retrofit it. No migration changes reference bytes or active rows.
