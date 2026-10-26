# Web-search provider chain: rollout and catalog compatibility

## Status and safety boundary

This is an operator runbook, not a deployment record. **All live steps are
pending: run at deploy.** Workers must not connect providers, read or create vault
credentials, mint grants, change order or allowances, replace deployed files, or
start/stop live modules. Offline fixture tests do not prove live vendor access.
Record the reviewed commit, tool versions, commands, exit codes and observations
in a private evidence directory outside build caches at deployment time.

Keep compatibility mode (no order) until connections, credentials, per-caller
grants and optional allowances have been checked. An order does not widen
permissions. Existing Tavily and Firecrawl MCP connections are not REST-chain
candidates; their manifests and grants must remain intact.

The two compatibility checks use the **pre-change deployed catalog**, before any
new manifest is added. Check that catalog with the new binary and actually boot
the still-installed old binary against it under the supervisor. This does not assert
that an old parser understands new manifest fields: parsers retain
`deny_unknown_fields`. Install the new binary before adding new manifests. A
rollback restores the saved catalog before restoring the old binary; never
point an old binary at the expanded catalog as a shortcut.

## Provider inventory and offline release gates

The source of truth is `crates/plexus-core/src/web_search/providers.rs`.
All 15 names below have a backend, a reviewed manifest and fixtures. The new REST
manifests pin vendor documentation, auth placement and mapping decisions in their
comments; those decisions, not the preliminary endpoint table, govern deployment.
Exa keeps its existing reviewed manifest and credential reference. Z.AI uses
`web_search_prime`, not the overview documentation's camel-case tool spelling.

Paths in the backend column are relative to
`crates/plexus-core/src/web_search/`. For every new backend, recorded-shape
fixtures are in `backend/<name>/fixtures.json` and tests in
`backend/<name>/tests.rs`. The capability column identifies skip/serve tests in
that file; all its mapping tests must pass as well. Exa has inline fixtures in
`backend.rs` and its preparation declaration in `capability/tests.rs`.

| Name | Backend type / source | Reviewed manifest | Capability declaration tests | Vault name |
| --- | --- | --- | --- | --- |
| exa | `ExaRestBackend`, `backend.rs` | `catalog/exa_rest.jsonc` | `exa_preparation_preserves_legacy_vendor_arguments` (legacy tool envelope); query validation rejects outside that envelope | `apikey:exa` (unchanged) |
| tavily | `TavilyRestBackend`, `backend/tavily.rs` | `catalog/tavily_rest.jsonc` | `capability_serves_the_whole_tool_envelope_natively`, `capability_skips_what_tavily_cannot_take_before_mapping` | `apikey:tavily` |
| brave | `BraveRestBackend`, `backend/brave.rs` | `catalog/brave_rest.jsonc` | `capability_serves_the_tool_envelope_with_domains_as_site_operators`, `capability_checks_the_final_query_after_site_operators`, `capability_skips_a_final_query_over_brave_word_limit` | `apikey:brave` |
| deepseek | `DeepSeekRestBackend`, `backend/deepseek.rs` | `catalog/deepseek_rest.jsonc` | `capability_skips_a_200_character_query`, `capability_checks_the_final_query_after_operators`, `capability_clamps_count_and_accepts_every_recency_and_domain_count` | `apikey:deepseek` |
| firecrawl | `FirecrawlRestBackend`, `backend/firecrawl.rs` | `catalog/firecrawl_rest.jsonc` | `capability_serves_the_whole_tool_envelope_natively`, `capability_skips_a_query_over_500_utf16_code_units`, `capability_skips_more_domains_than_the_reviewed_schema_takes` | `apikey:firecrawl` |
| jina | `JinaRestBackend`, `backend/jina.rs` | `catalog/jina_rest.jsonc` | `capability_takes_one_domain_and_skips_two`, `capability_skips_every_recency_window`, `capability_clamps_count_to_20` | `apikey:jina` |
| kagi | `KagiRestBackend`, `backend/kagi.rs` | `catalog/kagi_rest.jsonc` | `capability_skips_a_query_or_domain_list_beyond_the_declared_envelope`, `capability_clamps_limit_to_20_and_accepts_every_recency` | `apikey:kagi` |
| kimi | `KimiRestBackend`, `backend/kimi.rs` | `catalog/kimi_rest.jsonc` | `capability_skips_any_domain_or_recency_window`, `capability_skips_a_query_beyond_the_declared_envelope`, `capability_clamps_limit_to_20` | `apikey:kimi-for-coding` |
| ollama | `OllamaRestBackend`, `backend/ollama.rs` | `catalog/ollama_rest.jsonc` | `capability_skips_any_domain_or_recency_window`, `capability_skips_a_query_beyond_the_declared_envelope`, `capability_clamps_max_results_to_10` | `apikey:ollama-cloud` |
| parallel | `ParallelRestBackend`, `backend/parallel.rs` | `catalog/parallel_rest.jsonc` | `capability_serves_the_declared_envelope_and_clamps_result_count`, `capability_skips_outside_the_declared_query_and_domain_envelope` | `apikey:parallel` |
| perplexity | `PerplexityRestBackend`, `backend/perplexity.rs` | `catalog/perplexity_rest.jsonc` | `capability_serves_full_tool_envelope_and_clamps_to_twenty_web_results`, `capability_skips_direct_preparation_beyond_query_and_domain_envelopes` | `apikey:perplexity` |
| synthetic | `SyntheticRestBackend`, `backend/synthetic.rs` | `catalog/synthetic_rest.jsonc` | `capability_serves_unfiltered_queries_with_query_only_and_local_count`, `capability_skips_domains_and_every_recency_instead_of_dropping_filters` | `apikey:synthetic` |
| tinyfish | `TinyFishRestBackend`, `backend/tinyfish.rs` | `catalog/tinyfish_rest.jsonc` | `capability_serves_native_domains_and_every_recency_without_changing_query`, `capability_skips_queries_beyond_2000_characters_and_tool_domain_envelope` | `apikey:tinyfish` |
| searxng | `SearxngRestBackend`, `backend/searxng.rs` | `catalog/searxng_rest.jsonc` | `capability_serves_exact_native_time_ranges_and_language`, `capability_skips_domains_week_and_oversized_queries` | none for anonymous; otherwise `apikey:searxng` |
| zai | `ZaiMcpBackend`, `backend/zai.rs` | `catalog/zai.jsonc` | `capability_serves_unfiltered_and_skips_domains_or_recency`, plus reviewed query/count field tests | `apikey:zai` |

Kimi and Ollama's credential names above are the implemented provider-table
bindings, not the generic `apikey:<order-name>` shorthand. Z.AI fixtures are
explicitly synthetic because the vendor publishes no MCP wire-result schema;
the real governed search below is a deployment prerequisite, not implied by a
green fixture suite. Z.AI RPC/tool error messages mentioning credits or quota
currently classify as `unavailable`, not `quota`; only an actual HTTP 402 retains
the transport's existing quota classification. Do not infer structured quota
signals from free-form vendor error wording.

Run these offline commands on the Linux build server from the reviewed checkout
(serialize Cargo invocations). They require no vault, live store or vendor call:

```sh
cargo --version
rustc --version
cargo test --locked -p plexus-core --lib -- web_search
cargo run --locked -p plexus-module --bin ck-plexus -- --check-catalog catalog
git diff --exit-code 33223121e9fcbbe6d63d0596ce68f3bfbb9a0f32 -- catalog/tavily.jsonc catalog/firecrawl.jsonc
bash scripts/rust-test-gate.sh
```

**Pass:** every provider's backend/fixture and capability skip/serve tests pass,
the provider-name binding test passes, and the complete catalog check accepts
34 manifests with zero refusals/I/O errors (including all 14 new manifests).
The legacy MCP diff is empty against the initial-public-release commit: neither
`catalog/tavily.jsonc` nor `catalog/firecrawl.jsonc` changed. The repository gate
must pass before release; record any infrastructure failure
as a stop, not a successful gate. Offline acceptance never completes a live step.

### Recorded offline verification (not deployment evidence)

On the reviewed implementation, Linux Cargo/rustc 1.99.0 ran the `web_search`
filter above: **339 passed, 0 failed, 2 ignored performance measurements**. This
includes every listed provider's fixture and capability tests and the provider
name/binding test; all 15 have a passing capability declaration. The new binary's
repository catalog check accepted **34/34**, including every new manifest.
The two legacy MCP manifests are unchanged against the recorded baseline.
The four runbook contract tests pass. These are offline checks only; old-binary
boot, deployed-catalog checks, all credentials/connections/grants, provider
probes, order and allowances remain
**pending: run at deploy**.

The mandatory repository gate was attempted on Linux but stopped at the existing
offline guest dependency probe: `rquickjs-macro` was absent from the cache.
Its nine dependency-guard self-tests and preceding static guards passed; later
workspace phases were not reached. Fix that cache prerequisite and rerun the
full gate before release. This runbook does not record that gate as green.

## 0. Supply deployment inputs (pending: run at deploy)

Use one operator shell, in the reviewed checkout. Supply actual absolute paths;
none is a secret. `LIVE_BIN/ck-plexus` must be the supervisor's registered binary,
not another copy on PATH. `LIVE_CATALOG` must equal its configured
`PLEXUS_CATALOG_DIR`. Use signed/staged local artifacts produced by the established
release process (`scripts/release-binaries.sh`, `scripts/stage-binaries.sh`), not
Linux build-server artifacts. Build/sign/stage before touching deployment.

```sh
set -eu
export SUBC=/absolute/path/to/subc-connection.json
export LIVE_BIN=/absolute/path/to/deployed/bin
export LIVE_CATALOG=/absolute/path/to/deployed/catalog
export LIVE_STORE=/absolute/path/to/deployed/plexus.db
export NEW_BIN=/absolute/path/to/signed/ck-plexus
export NEW_ADMIN=/absolute/path/to/signed/ck-plexus-admin
export FACADE_CALL=/absolute/path/to/built/facade_call
export EVIDENCE=/absolute/path/to/private/web-search-rollout-evidence
export NEW_MANIFESTS='tavily_rest brave_rest deepseek_rest firecrawl_rest jina_rest kagi_rest kimi_rest ollama_rest parallel_rest perplexity_rest synthetic_rest tinyfish_rest searxng_rest zai'
umask 077
mkdir -p "$EVIDENCE"
test -r "$SUBC" && test -r "$LIVE_STORE"
test -x "$NEW_BIN" && test -x "$NEW_ADMIN" && test -x "$FACADE_CALL"
git rev-parse HEAD > "$EVIDENCE/reviewed-commit.txt"
"$NEW_BIN" --version > "$EVIDENCE/new-version.txt"
"$NEW_ADMIN" --version > "$EVIDENCE/admin-version.txt"
cp -p "$LIVE_BIN/ck-plexus" "$EVIDENCE/ck-plexus.before"
cp -p "$LIVE_BIN/ck-plexus-admin" "$EVIDENCE/ck-plexus-admin.before"
cp -R "$LIVE_CATALOG" "$EVIDENCE/catalog.before"
sqlite3 "$LIVE_STORE" ".backup '$EVIDENCE/store.before.db'"
export OLD_BIN="$EVIDENCE/ck-plexus.before"
```

**Pass:** all paths exist, evidence is private, versions identify the reviewed
artifacts, the complete pre-change catalog and binaries are retained, and the
SQLite backup (including committed WAL state) passes
`sqlite3 "$EVIDENCE/store.before.db" 'PRAGMA integrity_check;'` with `ok`.
Record the existing order/allowances/grant IDs for rollback from health and the
admin previews before changing them. Stop if deployment is already partly
upgraded; do not overwrite the retained pre-upgrade evidence.

## 1. Prove compatibility on the deployed catalog (pending: run at deploy)

No manifest additions or binary replacements yet. Check the entire deployed
folder, not a copied subset. Then boot the old, still-installed binary through
its real supervisor; `--version` and `--check-catalog` alone are not a boot test.

<!-- deployed-compatibility -->
```sh
"$NEW_BIN" --check-catalog "$LIVE_CATALOG" > "$EVIDENCE/new-on-deployed-catalog.txt" 2>&1
"$OLD_BIN" --check-catalog "$LIVE_CATALOG" > "$EVIDENCE/old-on-deployed-catalog.txt" 2>&1
cmp "$OLD_BIN" "$LIVE_BIN/ck-plexus"
ck --json module status plexus > "$EVIDENCE/old-before-restart-status.json"
ck module stop plexus
ck module start plexus
scripts/verify-deployed-binary.sh "$LIVE_BIN/ck-plexus"
ck --json module status plexus > "$EVIDENCE/old-boot-status.json"
ck --json --verbose health > "$EVIDENCE/old-boot-health.json"
ck module logs plexus > "$EVIDENCE/old-boot-logs.txt"
```

**Pass:** both catalog checks exit 0 and accept every deployed manifest with
zero refusals/I/O errors. The restarted process reaches ready/healthy, loads that
catalog, and its build provenance/inode is the saved old binary's, not a stale
process or the staged new binary. Retain status and startup logs as old-boot
evidence, including a changed process/launch identity across the restart. A
nonce/daemon/storage failure is not a compatibility pass. Stop on
either parser refusal or boot failure; do not add manifests to work around it.

## 2. Place the binary, then add manifests (pending: run at deploy)

First check the reviewed additions in isolation with the new parser. Only after
the new binary has been placed may the deployment catalog gain any of them.
Neither file-placement operation restarts the module.

```sh
mkdir "$EVIDENCE/new-manifests"
for app in $NEW_MANIFESTS; do
  install -m 644 "catalog/$app.jsonc" "$EVIDENCE/new-manifests/$app.jsonc"
done
"$NEW_BIN" --check-catalog "$EVIDENCE/new-manifests" > "$EVIDENCE/new-manifests-check.txt" 2>&1
```

**Pass:** `ck-plexus --check-catalog` exits 0 with exactly 14 accepted, zero
refused and zero I/O errors, one for every new manifest in the inventory.

<!-- deployment-placement -->
```sh
ck module stop plexus
install -m 755 "$NEW_BIN" "$LIVE_BIN/ck-plexus.next"
install -m 755 "$NEW_ADMIN" "$LIVE_BIN/ck-plexus-admin.next"
mv "$LIVE_BIN/ck-plexus.next" "$LIVE_BIN/ck-plexus"
mv "$LIVE_BIN/ck-plexus-admin.next" "$LIVE_BIN/ck-plexus-admin"
for app in $NEW_MANIFESTS; do
  install -m 644 "catalog/$app.jsonc" "$LIVE_CATALOG/$app.jsonc"
done
cmp "$EVIDENCE/catalog.before/tavily.jsonc" "$LIVE_CATALOG/tavily.jsonc"
cmp "$EVIDENCE/catalog.before/firecrawl.jsonc" "$LIVE_CATALOG/firecrawl.jsonc"
"$LIVE_BIN/ck-plexus" --check-catalog "$LIVE_CATALOG" > "$EVIDENCE/expanded-deployed-catalog.txt" 2>&1
ck module start plexus
scripts/verify-deployed-binary.sh "$LIVE_BIN/ck-plexus"
ck --json module status plexus > "$EVIDENCE/new-boot-status.json"
ck --json --verbose health > "$EVIDENCE/new-boot-health.json"
export ADMIN="$LIVE_BIN/ck-plexus-admin"
```

**Pass:** new daemon/admin binaries are in place before the first new manifest,
the expanded complete deployed catalog parses with the placed new binary,
legacy Tavily/Firecrawl MCP files compare byte-for-byte, and the restarted module
is ready on the reviewed binary with connector home held. Catalog checks return
0 only on acceptance; exit 1 is a refusal and exit 2 is usage/I/O failure. Do not
enable an order yet. A failed migration requires a rehearsed store recovery,
not merely switching the executable back.

## 3. Credentials and connections (pending: run at deploy)

**The user's responsibility:** the user stores each provider's key through the
vault's own login flow under the exact vault name in the inventory. Plexus
neither creates keys nor stores secret bytes. No vault command is supplied here:
this repository does not define that login interface. Plexus's vault read
permission covers every web-search key (`apikey:<provider>`) as one category,
so **no per-key vault grant step is needed**. This
existing vault permission is separate from each caller's Plexus invoke grants.
Do not print, export, copy into a manifest, or retrieve a raw key for a probe.

Steps 3 and 4 are one command per provider, `add-web-search-provider`, with
one operator confirmation. It reads the app, action, vault credential name and
connection id from the provider name table (`conn-web-search-<name>`; Exa keeps
`conn-exa-rest`), places the credential reference and issues the ticket,
connects with discovery, then mints every caller's invoke grant at read risk on
exactly the search action, in one transaction, only after discovery completed.
It never sets the order or allowances. Preview first; the preview writes
nothing and contacts no vendor. Without `--grantee`, the grantees are the
callers that already hold a live search grant on your web search provider
connections (today Exa's `reserved:broca`, `reserved:prefrontal-core` and
`reserved:basal`). The step-5 probe runs as `direct`, so the apply below names
those callers and `direct` explicitly; any `--grantee` replaces the default.
The example values are Tavily.

<!-- provider-add -->
```sh
export PROVIDER=tavily
export ACTION=search
export CONNECTION_ID=conn-web-search-tavily
"$FACADE_CALL" "$SUBC" '{"name":"connections","arguments":{"op":"list"}}' > "$EVIDENCE/connections-before.json"
"$ADMIN" add-web-search-provider "$PROVIDER" --subc "$SUBC" \
  > "$EVIDENCE/$PROVIDER-add-preview.txt"
"$ADMIN" add-web-search-provider "$PROVIDER" --subc "$SUBC" \
  --grantee direct --grantee reserved:broca --grantee reserved:prefrontal-core \
  --grantee reserved:basal --apply > "$EVIDENCE/$PROVIDER-add.txt"
```

**Pass:** the preview names the intended connection, app and inventory
credential name (never key bytes), a `read` ceiling on exactly the search action
(`web_search_prime` for Z.AI) and one invoke grant per caller. The apply asks
for exactly one confirmation, whose prompt names the provider, connection,
ceiling and every grantee, and prints `discovery:  complete` with each grant
`minted` (or `already_present` on a rerun). Set `CONNECTION_ID` to the printed
connection for step 5. A connection for the provider that already exists with
the same app and credential, under any id, is reused; one bound to another app,
credential or instance is refused by name and nothing is changed. If discovery
does not complete (`discovery_incomplete`), the connection stays active and no
grant is minted: fix the cause below, then rerun the same command, which
finishes under one new confirmation without duplicating anything. A declined
or unavailable confirmation writes nothing but its refusal audit row.

For **SearXNG**, add `--instance-url "$SEARXNG_INSTANCE"` (see below). It is
anonymous unless `--with-key` binds `apikey:searxng`; every other provider
refuses `--with-key`. The address is stored on the connection and is never
printed, logged or shown in the confirmation prompt.

### Manual fallback: ticket and connect

Use the manual sequence when the command is unavailable or refuses a
connection it does not manage. The exact credential-binding command is the
ticket command below. Repeat for every inventory row, substituting its name,
app and credential. All REST rows use `<name>_rest` and `search`; Z.AI uses
`zai` and `web_search_prime`. Keep existing Exa if it resolves uniquely;
inspect before creating a second eligible connection. The same applies to
retries after a consumed ticket. This sequence asks for one confirmation per
ticket and per grant.

```sh
export PROVIDER=tavily
export APP=tavily_rest
export ACTION=search
export CREDENTIAL_ID=apikey:tavily
export CONNECTION_ID=conn-web-search-tavily
"$FACADE_CALL" "$SUBC" '{"name":"connections","arguments":{"op":"list"}}' > "$EVIDENCE/connections-before.json"
"$ADMIN" issue-ticket --subc "$SUBC" --app "$APP" \
  --connection "$CONNECTION_ID" --actions "$ACTION" --risk read \
  --credential-id "$CREDENTIAL_ID" > "$EVIDENCE/$PROVIDER-ticket.txt"
```

**Pass:** recorded issuance inputs use the intended app and inventory credential
ID; the returned connection ID and ceiling match the requested connection,
read risk and exactly the search action. The ticket reply does not expose app or
credential fields. The final credential pass
is the completed, uncached governed search in step 5, not merely a valid ticket.
The ticket is single-use; do not blindly retry a submitted command after a
timeout. Admin exit 3 means the submission outcome is unknown; inspect state.

For **anonymous SearXNG**, use the following ticket instead, with no
`--credential-id`. For authenticated SearXNG, add
`--credential-id apikey:searxng` to this command. The operator-approved instance
address is stored on the ticket/connection, not in the manifest or search
arguments. Use HTTPS, or HTTP only to loopback; no URL userinfo or inline tokens.
Keep instance addresses out of shared evidence and diagnostics.

```sh
export PROVIDER=searxng APP=searxng_rest ACTION=search
export CONNECTION_ID=conn-web-search-searxng
export SEARXNG_INSTANCE=https://operator-approved-instance.example
"$ADMIN" issue-ticket --subc "$SUBC" --app "$APP" \
  --connection "$CONNECTION_ID" --actions "$ACTION" --risk read \
  --instance-url "$SEARXNG_INSTANCE" > "$EVIDENCE/$PROVIDER-ticket.txt"
```

**Pass:** ticket creation accepts the instance and the intended auth mode. An
anonymous search must pass step 5 **without a key**; a bearer-backed search is
not an anonymous check. If both modes are tested, use separate caller-owned
connections and grants so each caller still resolves exactly one candidate.

For each ticket, set `TICKET_ID` to the returned value, then connect as `direct`,
the ticket's issuing principal:

```sh
export TICKET_ID=returned-ticket-id
"$FACADE_CALL" "$SUBC" "$(jq -nc --arg ticket "$TICKET_ID" \
  '{name:"connections",arguments:{op:"connect",ticket_id:$ticket}}')" \
  > "$EVIDENCE/$PROVIDER-connect.json"
jq -e --arg id "$CONNECTION_ID" \
  '.result.connection.connection_id == $id and .result.discovery == "complete"' \
  "$EVIDENCE/$PROVIDER-connect.json"
```

**Pass:** the connection is active, owned by `direct`, uses the intended
app/credential (or no credential for anonymous SearXNG), and discovery completes.
Missing/unreadable credentials can appear as discovery
`credential_unresolved` even though the ticket was consumed and connection
created; do not mint another connection. At dispatch the governed failure code
is `credential_missing`; a one-provider chain can surface
`web_search_unavailable` with reason `unavailable`. Record the audit code, not
vendor text. Ask the user to fix the stored key and retry the governed
probe only after resolving the failure. A schema quarantine is not a key error.

## 4. Caller grants and reviewed schema (pending: run at deploy)

After `add-web-search-provider`, the grants already exist; only the listing and
schema review below remain. Mint a grant by hand only on the manual fallback
path, or for a caller added later; the `grant` line is that fallback and asks
for one confirmation per caller.

```sh
export CALLER=direct
"$ADMIN" grant --subc "$SUBC" --connection "$CONNECTION_ID" \
  --grantee "$CALLER" --kind invoke --risk read --actions "$ACTION" \
  > "$EVIDENCE/$PROVIDER-invoke-grant.txt"
"$ADMIN" list-grants --subc "$SUBC" --connection "$CONNECTION_ID" --all \
  > "$EVIDENCE/$PROVIDER-grants.txt"
"$ADMIN" review-action --subc "$SUBC" --connection "$CONNECTION_ID" --action "$ACTION" \
  > "$EVIDENCE/$PROVIDER-action-review.txt"
```

**Pass:** each caller has an unexpired invoke grant for exactly the reviewed
search action within the connection's read ceiling, not a wildcard grant or a
grant on the old Tavily/Firecrawl MCP app. `grant` applies immediately; it has no
`--apply` flag. The action is active with its reviewed schema. Record grant IDs
for rollback. A successful
`direct` probe proves only `direct`'s authority, not an agent's or module's.

For Z.AI, compare the discovered tool schema with the pinned query/count field
selection and fixtures. Stop if the vendor shape cannot be mapped. If an
operator has reviewed schema drift and explicitly approves a new pin, the exact
ceremony is below; do not automatically approve whatever hash was observed:

```sh
export REVIEWED_SCHEMA_HASH=operator-reviewed-observed-sha256
"$ADMIN" repin-action --subc "$SUBC" --connection "$CONNECTION_ID" \
  --action "$ACTION" --expected-hash "$REVIEWED_SCHEMA_HASH" \
  > "$EVIDENCE/$PROVIDER-action-repin.txt"
```

**Pass:** the independently reviewed hash matches the observed action and the
ceremony returns it to active. Re-review/retest if query fields or result
mapping differ; fixture success cannot waive this live prerequisite.

## 5. Prove credential access by governed search (pending: run at deploy)

For **each of the 15 providers**, select a temporary one-provider order, then
make a unique ordinary web query with no domains or recency filter. This avoids
capability skips and prevents failover/cache hits from hiding a broken key.
Use the same `PROVIDER` and the `CONNECTION_ID` that `add-web-search-provider`
printed in step 3 (or the manual fallback's connection).
`facade_call` is an unscoped `direct` client; actual caller probes must use their
authenticated route rather than forging a principal field.

```sh
"$ADMIN" set-web-search-order "$PROVIDER" --subc "$SUBC"
"$ADMIN" set-web-search-order "$PROVIDER" --subc "$SUBC" --apply
export AUDIT_START="$(sqlite3 -readonly "$LIVE_STORE" 'SELECT COALESCE(MAX(journal_id),0) FROM audit_journal;')"
export PROBE_QUERY="weather in London $(uuidgen)"
"$FACADE_CALL" "$SUBC" "$(jq -nc --arg q "$PROBE_QUERY" \
  '{name:"web_search",arguments:{query:$q,max_results:1}}')" \
  > "$EVIDENCE/$PROVIDER-search.json"
jq -e --arg provider "$PROVIDER" \
  '.error == null and .result.backend == $provider and .result.cached == false' \
  "$EVIDENCE/$PROVIDER-search.json"
sqlite3 -readonly -json "$LIVE_STORE" \
  "SELECT journal_id,connection_id,app_key,action,gate,outcome,reason_code,query_text FROM audit_journal WHERE journal_id > $AUDIT_START ORDER BY journal_id;" \
  > "$EVIDENCE/$PROVIDER-search-audit.json"
jq -e --arg id "$CONNECTION_ID" --arg q "$PROBE_QUERY" \
  'any(.[]; .connection_id == $id and .gate == "dispatch" and .outcome == "completed") and
   any(.[]; .connection_id == $id and .query_text == $q and .gate == "web_search" and .outcome == "completed" and .reason_code == "web_search_dispatched")' \
  "$EVIDENCE/$PROVIDER-search-audit.json"
```

**Pass:** the reply is uncached, names the selected provider, and both the
governed dispatch and web-search audit entries after the watermark are
`completed` on the intended connection. Zero mapped results is a valid served
reply, not a reason to fail over. This proves the stored key exists and Plexus
can read/use it; for anonymous SearXNG it proves a governed search without any
key. Missing rows, `credential_missing`, quarantine, not-granted, or a refusal
are failures, not partial passes. Vendor quota/rate refusals are not proof of a
dead credential; resolve them before accepting this provider. Keep the one-name
order until each provider passes; do not clear an exhausted allowance merely
to hide a failing probe.

## 6. Allowances and final order (pending: run at deploy)

Allowances are optional. Choose a reviewed monthly count (1–10,000,000) for
each provider to cap; unset means no Plexus monthly cap. Preview before apply.
This example caps Exa at 2 only to show exact syntax; substitute the approved
production count before executing. Do not reset existing usage during rollout.

```sh
"$ADMIN" set-web-search-allowance exa 2 --subc "$SUBC"
"$ADMIN" set-web-search-allowance exa 2 --subc "$SUBC" --apply
"$ADMIN" set-web-search-order exa tavily --subc "$SUBC"
"$ADMIN" set-web-search-order exa tavily --subc "$SUBC" --apply
ck --json --verbose health > "$EVIDENCE/final-health.json"
```

**Pass:** previews and applied ceremony rows show the approved `previous` and
`new` allowance and ordered list. Use only providers/callers already proved in
step 5. Health's `webSearch` section has order `exa,tavily`, with
`order_position`, `connection_present`, `cooldown_remaining_ms`, `allowance_used`
and `allowance_limit` for each row; connections are present, counts are retained
and limits match approval. Health alone does not prove credentials or grants.
Repeat the step-5 unique-query/audit command for the final order: first eligible
provider serves, or `web_search_unavailable` lists each provider and its reason
without vendor prose/instance addresses. Do not induce live quota failures to
retest the offline failover matrix.

To remove one allowance (not all providers' allowances), preview/apply exactly:

```sh
"$ADMIN" set-web-search-allowance exa --clear --subc "$SUBC"
"$ADMIN" set-web-search-allowance exa --clear --subc "$SUBC" --apply
```

**Pass:** only Exa's limit becomes null; the current UTC month's usage remains.
Allowances can be stored with no order but are not consulted in compatibility
mode. Record the intended final value, not both mutually exclusive choices.

## 7. Disable or roll back (pending: run at deploy)

For configuration-only rollback, restore the recorded previous order/allowances
with the commands above. If there was no order, use `--clear`, not an empty list:

```sh
"$ADMIN" set-web-search-order --clear --subc "$SUBC"
"$ADMIN" set-web-search-order --clear --subc "$SUBC" --apply
ck --json --verbose health > "$EVIDENCE/compatibility-mode-health.json"
```

**Pass:** ceremony `new` and health order are null. A fresh step-5 query serves
Exa through the legacy compatibility path, with no chain `served_by`/`skipped`
audit fields. No order does not consult cooldowns or allowances. Existing Exa
grants/refusals remain effective; do not grant new authority to make this pass.

For binary rollback, first stop Plexus and restore the **entire** matching old
catalog, so no new manifests remain when the old binary starts:

```sh
ck module stop plexus
mv "$LIVE_CATALOG" "$EVIDENCE/catalog.rejected"
cp -R "$EVIDENCE/catalog.before" "$LIVE_CATALOG"
"$OLD_BIN" --check-catalog "$LIVE_CATALOG"
install -m 755 "$OLD_BIN" "$LIVE_BIN/ck-plexus"
install -m 755 "$EVIDENCE/ck-plexus-admin.before" "$LIVE_BIN/ck-plexus-admin"
```

**Pass:** the restored catalog matches its snapshot and the old parser accepts
every entry. Before `ck module start plexus`, restore/rehearse the matching
consistent store backup through the deployment's approved storage recovery
procedure if migrations cannot be reversed. File rollback alone makes no
store-downgrade guarantee. After start, repeat step 1's provenance/status/health
checks. Revoke only the recorded new invoke grants if abandoning the rollout:
`"$ADMIN" revoke-grant --subc "$SUBC" --grant "$NEW_GRANT_ID"` (pending: run at
deploy); **pass:** that exact grant is revoked and unrelated grants remain.

## Offline runbook contract tests

These five documentation tests inspect the actual command blocks and provider
inventory above. They do not execute shell blocks or prove live deployment.
Run from the repository root on Linux. Keep the tests here so the fenced runbook
and its checks travel together.

```sh
python3 -B -c 'from pathlib import Path; text = Path("docs/design/web-search-provider-chain-rollout.md").read_text(); exec(text.split("<!-- rollout-contract-tests -->\n```python\n", 1)[1].split("\n```", 1)[0])'
```

<!-- rollout-contract-tests -->
```python
import re
import unittest
from pathlib import Path

DOCUMENT = Path("docs/design/web-search-provider-chain-rollout.md")
TEXT = DOCUMENT.read_text().split("## Offline runbook contract tests", 1)[0]


def shell_block(marker):
    return TEXT.split("<!-- " + marker + " -->\n```sh\n", 1)[1].split("\n```", 1)[0]


class RolloutContract(unittest.TestCase):
    def test_binary_precedes_manifest_installation(self):
        block = shell_block("deployment-placement")
        binary = 'mv "$LIVE_BIN/ck-plexus.next" "$LIVE_BIN/ck-plexus"'
        manifest = 'install -m 644 "catalog/$app.jsonc" "$LIVE_CATALOG/$app.jsonc"'
        self.assertIn(binary, block, "new binary must be placed before new manifests")
        self.assertLess(block.index(binary), block.index(manifest),
                        "new binary must be placed before new manifests")
        self.assertIn('"$LIVE_BIN/ck-plexus" --check-catalog "$LIVE_CATALOG"', block)
        self.assertIn('cmp "$EVIDENCE/catalog.before/tavily.jsonc" "$LIVE_CATALOG/tavily.jsonc"', block)
        self.assertIn('cmp "$EVIDENCE/catalog.before/firecrawl.jsonc" "$LIVE_CATALOG/firecrawl.jsonc"', block)

    def test_old_binary_boot_is_not_only_a_parser_check(self):
        block = shell_block("deployed-compatibility")
        self.assertIn('"$NEW_BIN" --check-catalog "$LIVE_CATALOG"', block)
        self.assertIn('"$OLD_BIN" --check-catalog "$LIVE_CATALOG"', block)
        identity = 'cmp "$OLD_BIN" "$LIVE_BIN/ck-plexus"'
        start = 'ck module start plexus'
        self.assertIn(identity, block)
        self.assertIn(start, block, "old binary must actually boot on the deployed catalog")
        self.assertLess(block.index(identity), block.index(start))
        self.assertIn('scripts/verify-deployed-binary.sh "$LIVE_BIN/ck-plexus"', block)
        self.assertIn('ck --json module status plexus', block)

    def test_inventory_covers_every_declared_provider(self):
        root = Path("crates/plexus-core/src/web_search")
        registry = (root / "providers.rs").read_text().split("#[cfg(test)]", 1)[0]
        names = set(re.findall(r'rest_provider!\("([a-z]+)"\)', registry))
        names.update(re.findall(r'name: "([a-z]+)"', registry))
        rows = [line.split("|")[1:-1] for line in TEXT.splitlines()
                if re.match(r"^\| [a-z]+ \|", line)]
        self.assertEqual(len(rows), len(names), "provider inventory must cover every declared name")
        self.assertEqual({row[0].strip() for row in rows}, names,
                         "provider inventory must cover every declared name")
        for row in rows:
            name = row[0].strip()
            with self.subTest(provider=name):
                backend, source = re.findall(r"`([^`]+)`", row[1])
                self.assertIn("struct " + backend, (root / source).read_text())
                manifest = re.findall(r"`([^`]+)`", row[2])[0]
                expected = "catalog/zai.jsonc" if name == "zai" else f"catalog/{name}_rest.jsonc"
                self.assertEqual(manifest, expected)
                self.assertTrue(Path(manifest).is_file())
                if name == "exa":
                    tests = (root / "capability/tests.rs").read_text()
                    self.assertIn("https://", (root / "backend.rs").read_text())
                else:
                    self.assertTrue((root / f"backend/{name}/fixtures.json").is_file())
                    tests = (root / f"backend/{name}/tests.rs").read_text()
                for test in re.findall(r"`(\w+)`", row[3]):
                    self.assertIn("fn " + test + "(", tests)

    def test_provider_add_is_one_command_before_the_manual_fallback(self):
        block = shell_block("provider-add")
        preview = '"$ADMIN" add-web-search-provider "$PROVIDER" --subc "$SUBC" \\\n  >'
        self.assertIn(preview, block, "preview must precede apply")
        self.assertIn("--apply", block)
        self.assertLess(block.index(preview), block.index("--apply"))
        self.assertNotIn("issue-ticket", block)
        self.assertNotIn("*", block, "the command never names a wildcard grantee")
        self.assertIn("--grantee direct", block, "the step-5 probe runs as direct")
        self.assertLess(TEXT.index("<!-- provider-add -->"),
                        TEXT.index("### Manual fallback: ticket and connect"))

    def test_live_steps_remain_pending_and_governed(self):
        headings = re.findall(r"^## [0-7]\. .+$", TEXT, re.MULTILINE)
        self.assertEqual(len(headings), 8)
        self.assertTrue(all("(pending: run at deploy)" in line for line in headings),
                        "live steps must remain pending until deployment")
        self.assertIn('--credential-id "$CREDENTIAL_ID"', TEXT)
        self.assertIn('--kind invoke --risk read --actions "$ACTION"', TEXT)
        self.assertIn('set-web-search-order "$PROVIDER" --subc "$SUBC" --apply', TEXT)
        self.assertIn('set-web-search-allowance exa 2 --subc "$SUBC" --apply', TEXT)
        self.assertIn('.gate == "dispatch" and .outcome == "completed"', TEXT)
        self.assertIn('an anonymous check', TEXT.lower())


unittest.main(verbosity=2)
```
