# Security

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability
reporting for this repository. Open the repository's **Security** tab, choose
**Report a vulnerability**, and submit a private report:

https://github.com/cortexkit/plexus/security/advisories/new

Include the affected commit, reproduction steps, expected impact and relevant
platform details. Remove credentials, vault references you consider sensitive,
vendor account data and private repository content from logs and examples. Do
not open a public issue for an unpatched vulnerability.

## Threat model

plexus (`ck-plexus`) lets agents call external services without holding the
credentials for them. It runs as a module supervised by the local
subconscious daemon (`ck-subc`), keeps vendor credentials in the claustrum
vault, and puts every vendor call through one governance pipeline that checks
authority and writes an audit record before anything is sent. The
[architecture](ARCHITECTURE.md) describes the pipeline in full; this section
covers what plexus trusts and what it defends.

### Local daemon and route identity

plexus trusts the local subconscious daemon. The module connects to it using a
daemon connection file and proves it was launched by the daemon with a launch
nonce passed on a file descriptor; without a readable nonce it refuses to
start. The daemon supplies each caller's principal (`direct` for an
authenticated client, `reserved:<module_id>` for a supervised module) and a
scope stamp naming the session, agent and delegation flags. plexus does not
compute or accept these from call arguments: identity-token fields such as
`assertion` and `agent_assertion` are refused by name before dispatch. The
daemon's own authentication is outside plexus; see
https://github.com/cortexkit/subconscious.

Management operations (minting grants, issuing binding tickets, setting
policy, re-pinning action schemas) are served only on the management surface,
not on the tool surface agents use, and each handler requires a `direct`
principal. `ck-plexus-admin` is such a client. The daemon connection file it
reads is the credential that makes a process a `direct` client, so protect it
like one.

### Vault credential custody

Vendor credentials live in the claustrum vault
(https://github.com/cortexkit/claustrum), never in the plexus store. A
connection binding holds only a non-secret vault credential reference, or
nothing for a credential-free vendor. plexus resolves the credential by
reference when it dispatches, discovers or health-checks, holds the bytes in a
buffer that is zeroized when dropped, and never persists bearer handles or a
binding encryption key. Credential bytes are kept out of `Debug` output, logs
and agent-visible errors. Arguments that carry credential material are refused.
A vendor's 403 is treated as a permission refusal and never invalidates a
credential; only a 401 is reported to the vault.

### Governed vendor calls

Nothing reaches a vendor except through the governance pipeline, including
poller reads, enrichment calls and reconciliation read-backs. Authority
narrows at each step: reviewed catalog manifest, binding ticket ceiling,
connection, grant, invoke. A missing grant, ceiling, principal or decision
service is a refusal, never a default; unknown severity is treated as the
highest; an action plexus cannot classify is refused. A call's reservation pins
the generations of every row it was authorized against and is revalidated
before dispatch, so a grant revoked or a policy changed in between stops the
call. A write whose outcome is unknown is never re-sent; it is resolved by a
governed read under the caller's current grants. Live vendor discovery pins
each action's input schema by hash, and a changed schema quarantines the action
until an operator re-pins it. Agents see sanitized vendor errors; full
diagnostics go only to the operator log.

### Consent cards

An action whose policy is `ask_first` is held, and plexus files an approval
card through the Cingulate consent module. The card's requester and subject
come from the daemon's scope stamp, never from card content. The card shows a
bounded preview of the arguments, with arguments whose names mark them as
secret withheld. plexus never answers a card itself. An approval is tied to the
held request: when it arrives, plexus re-authorizes the request in full under
the scope it was raised under, re-checks that scope with the daemon, and
refuses to send if the arguments differ from the ones approved. Approvals
expire. A call with no interactive session to file a card under, or whose card
cannot be filed or awaited, is refused with `consent_unavailable` rather than
run; calls made inside an automated flow never get a card.

### Audit log

Each governed call writes an audit row for the decision and one for the
dispatch, correlated by request id, in the module's SQLite store. Audit rows
cannot be updated (a trigger refuses it) and can be deleted only once they are
older than seven days; retention defaults to 30 days
(`PLEXUS_AUDIT_RETENTION_DAYS`). On Unix the store and its write-ahead log are
set to owner-only permissions (mode `0600`) when opened. A grant revocation is
first appended to an owner-only journal beside the database, so restoring an
older store cannot bring the grant back.

### Out of scope

- A compromised local user account. A process running as the same user can
  read owner-readable files, including the store and the daemon connection
  file, and can alter configuration or binaries. Protect the account, the
  daemon, the vault and the module binaries as one trust boundary.
- Vulnerabilities in the subconscious daemon or the claustrum vault
  themselves. Report those to their repositories.
- Behavior of the external services plexus calls, and the content they
  return. plexus governs whether a call is sent; it does not vouch for a
  vendor's reply.
- Actions an operator has authorized. A grant or `allow` policy that an
  operator deliberately minted is the intended authority, not a bypass.
- Test fixtures, stub vendors and examples under `crates/*/tests/` and
  `crates/*/examples/`, unless they show a flaw in shipped code.
