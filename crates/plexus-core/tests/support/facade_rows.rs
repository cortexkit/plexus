//! Raw authority rows for the GitHub facade fixtures.
//!
//! These fixtures write the reviewed manifest, catalog rows and grants
//! straight into the database rather than through the store's ceremonies:
//! storing the manifest through the store would also seed catalog rows from
//! it, and each test pins its own catalog rows and grants. Keeping the column
//! lists here, once, means a new column on any of these tables is added in one
//! place instead of in every fixture that writes the row.

use rusqlite::{params, Connection};

/// The connection every facade fixture writes its rows under.
const PRINCIPAL: &str = "operator";
const CONNECTION: &str = "conn-fixture";

/// Store `manifest_json` as the system's reviewed `github_rest` manifest.
pub fn insert_reviewed_manifest(db: &Connection, manifest_json: &str) {
    db.execute(
        "INSERT INTO app_manifests (principal,key,schema_version,content_hash,manifest_json,ingested_at_ms)
         VALUES ('system','github_rest',1,'fixture',?1,1)",
        params![manifest_json],
    )
    .unwrap();
}

/// An active S1 catalog row for `name` with the given risk and argument schema.
pub fn insert_catalog_action(
    db: &Connection,
    name: &str,
    risk: &str,
    schema_json: &str,
    ask_first: bool,
) {
    db.execute(
        "INSERT INTO catalog_actions (connection_id,principal,name,schema_json,schema_hash,risk,severity,status,first_seen_at_ms,last_seen_at_ms,ask_first)
         VALUES (?1,?2,?3,?4,'schema',?5,'S1','active',1,1,?6)",
        params![CONNECTION, PRINCIPAL, name, schema_json, risk, ask_first],
    )
    .unwrap();
}

/// A write-ceiling invoke grant to `grantee` over the JSON array `selectors`,
/// bound to `agent` when it is an agent grant.
pub fn insert_invoke_grant(
    db: &Connection,
    grant_id: &str,
    grantee: &str,
    selectors: &str,
    agent: Option<&str>,
) {
    db.execute(
        "INSERT INTO grants (grant_id,principal,connection_id,grantee_principal,risk_ceiling,authority_kind,created_at_ms,action_selectors,agent_id)
         VALUES (?1,?2,?3,?4,'write','invoke',1,?5,?6)",
        params![grant_id, PRINCIPAL, CONNECTION, grantee, selectors, agent],
    )
    .unwrap();
}
