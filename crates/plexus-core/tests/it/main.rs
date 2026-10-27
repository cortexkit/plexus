#[path = "../support/bounded.rs"]
mod bounded;
#[path = "../support/facade_rows.rs"]
mod facade_rows;
#[path = "../support/scratch_store.rs"]
mod scratch_store;
#[path = "../support/system_manifest.rs"]
mod system_manifest;

mod call_withdrawal;
mod ceremony;
mod github_catalog;
mod github_control_surface;
mod github_credential;
mod github_event_wake_reads;
mod github_facade_callers;
mod github_facade_gates;
mod github_facade_retry_flag;
mod github_facade_vendor_band;
mod github_handle_placeholder_schemas;
mod github_import_grant_closure;
mod github_pagination;
mod github_receipt;
mod github_resolver;
mod github_store;
mod governance_seams;
mod jcs_golden;
mod reference_only_bindings;
mod scope_approvals;
#[path = "../support/scope.rs"]
mod scope_support;
mod sqlite_build;
mod stored_hash_cutover;
mod write_reconciliation;
