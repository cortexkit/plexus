# Catalog validation and credential-surface rollout

The catalog is read at boot. These changes deliberately refuse declarations that
older catalogs accepted: unreviewed resource-filter paths and known
credential-returning actions. Do not restart a new binary against the old
catalog. There is no legacy fail-open ingest mode.

## One restart, with preflight

1. Place the binary without restarting.
2. Copy every changed catalog file.
3. Before restarting, run the new binary's `--check-catalog` on the staged catalog
   folder. Require a successful check of the complete folder, not a subset.
4. Restart once.
5. Roll back by restoring the old catalog files and the old binary together,
   before the next restart. Before that restart, run the old binary's
   `--check-catalog` on the restored folder and require success.

Use `ck-plexus --check-catalog <catalog-folder>` with the actual staged or restored
binary path. Retain both the old binary and the matching complete catalog folder
until the new deployment is accepted. A parse preflight does not prove that a
store migration is reversible; retain and rehearse a consistent store backup
separately.

The binary is placed **before** the catalog; neither placement triggers an
intermediate restart. Transport changes in the same deployment add `parameters`
to `github_rest.jsonc` and `kind` to `github_actions.jsonc`; those require the new
binary. The cleanup changes below are removals and risk reclassifications that
the old parser accepts. Deploy all changes in the same single restart, rather
than assuming the cleanup makes new transport fields backward-compatible.

## Cleanup inventory

| File | Reason |
| --- | --- |
| `browserbase.jsonc` | Remove unreviewed `domain_allowlist`, inert read-back/idempotency declarations; classify stateful `navigate` as write. |
| `deepwiki.jsonc` | Remove `repo_allowlist`: it is not a vendor argument and has no reviewed input schema. The vendor argument `repoName` needs a full reviewed and pinned schema before it can be a filter. |
| `exa.jsonc` | Remove unreviewed conceptual domain/category/limit filters. |
| `gcal.jsonc` | Remove unreviewed calendar/time/attendee filters; empty ignored OAuth metadata for old-parser compatibility. |
| `github.jsonc` | Remove MCP filter declarations without reviewed full schemas; REST filters remain supported. |
| `linear.jsonc` | Remove unreviewed workspace filters and inert read-back/idempotency declarations; retain empty ignored OAuth fields because the old parser requires those fields to be present. |
| `neon.jsonc` | Remove password-returning `get_connection_string`, unreviewed project/branch filters and inert read-back/idempotency declarations; migration application becomes destructive. |
| `notion.jsonc` | Remove unreviewed workspace/page/database/parent filters and inert read-back/idempotency declarations; empty ignored OAuth metadata for old-parser compatibility. |
| `resend.jsonc` | Remove synthetic sender-domain filters and inert read-back/idempotency declarations; irreversible contact/broadcast removal becomes destructive. |
| `sentry.jsonc` | Remove unreviewed org/project/environment/status filters and inert read-back/idempotency declarations. Vendor arguments include `organizationSlug`/`projectSlug`; complete vendor input schemas must be reviewed and pinned before declaring those selectors. |
| `supabase.jsonc` | Remove unreviewed project/organization/branch filters and inert read-back/idempotency declarations. |

No live connection uses a removed filter declaration. The read-only deployment
inventory contained active connections only for `deepwiki` (1), `exa` (1),
`exa_rest` (1), `github` (7), `github_actions` (1), `github_rest` (26) and
`grep_app` (1). The only configured filters were `github_rest` `owner`/`repo` on
its 26 bot connections. Those reviewed keys and action schemas are unchanged by
this cleanup. Core's `live_connected_catalog_schema_hashes_remain_unchanged`
compares all seven apps with a pre-cleanup hash snapshot. It does not authorize
schema changes contributed by another deployment component.

Schema-backed REST filters remain in `github_actions.jsonc` (`owner`/`repo`) and
`posthog_rest.jsonc` (`project_id`) as well; this cleanup leaves both files
byte-identical to their previous versions.

The previous parser required `profile_digest` and `requested_scopes` inside an
OAuth profile. Although neither field was used, simply deleting them broke the
old parser. `gcal`, `linear` and `notion` keep empty values with a compatibility
comment instead. To verify old-parser acceptance without a base worktree, extract
the production portion of `crates/plexus-core/src/manifest.rs` from commit
`16cd87f494750b536bdce4480facbe5f37bbd3af` using `git show`, excluding its unit-test
module. Compile it as a temporary test-only core module, with a test that reads
all `catalog/*.jsonc`, normalizes each with `subc_jsonc::jsonc_to_json`, parses a
JSON value and calls that extracted module's `ingest_value`. Require exactly 20
accepted manifests, then remove the temporary module and restore `lib.rs`.
This exercises the old deserializer and validator, not a replacement schema.

Re-ingest now refreshes risk, tier, ask-first and reconciliation metadata on
existing REST rows without repinning or clearing operator quarantine. New
metadata generations can invalidate in-flight reservations; callers must handle
a retryable not-sent result. Removing unreviewed MCP filter declarations means
new filter configurations using those labels refuse until real schemas are
reviewed. Unknown writes without a declared usable read-back remain
unreconcilable; they are never automatically re-sent.
