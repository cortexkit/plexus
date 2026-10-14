//! A reviewed system manifest for a test fixture's app.
//!
//! Governance reads an app's tier from its system manifest to decide how
//! severe a write is, and an app with no manifest is gated at the strongest
//! tier. A fixture whose writes should run at the ordinary severity installs
//! one with this.

use plexus_core::PlexusStore;
use serde_json::json;

/// Install a minimal reviewed manifest for `app_key` at `tier`. It needs a
/// credential (`api_key`), like the fixtures that bind one, so installing it
/// changes nothing about how a call is authenticated.
pub fn install_system_manifest(store: &PlexusStore, app_key: &str, tier: &str) {
    let manifest = plexus_core::manifest::ingest_value(json!({
        "schema_version": 1,
        "key": app_key,
        "name": app_key,
        "description": "integration-test vendor",
        "reuse_path": "mcp_direct",
        "reuse_rationale": "integration fixture",
        "tier": tier,
        "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
        "auth": {"mode": "api_key"},
        "credential_bindings": [{
            "ref_role": "api_key", "placement": "header", "key": "Authorization",
            "prefix": "Bearer ", "required": true
        }],
        "resource_filters": {"required": [], "optional": [], "write_enabling": []},
        "actions_baseline": [{"name": "fixture_read", "risk": "read"}],
        "defaults": {"ask_first_risk": ["write", "destructive"], "rate_limit": {"calls_per_min": 30}},
        "availability": "ga"
    }))
    .expect("test manifest ingests");
    store
        .upsert_manifest("system", &manifest)
        .expect("store test manifest");
}
