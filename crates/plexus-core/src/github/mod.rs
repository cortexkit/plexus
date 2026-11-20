//! GitHub App bot writes: repository resolution, bounded list pagination, the
//! scoped vault credential used at dispatch, and the receipt ledger that keeps
//! a retried request from being sent twice. Handle, binding and receipt
//! storage, and the store-backed governance projections, live under
//! `storage::github_store`.

pub mod control;
pub mod credential;
pub mod facade;
pub mod manifest_binding;
pub mod moved_bot;
pub mod pagination;
pub mod reads;
pub mod receipt;
pub mod resolver;
pub mod sweeper;

/// The principal that bot requests from AFT's GitHub shim carry when they
/// reach plexus. Each imported handle's write grants name it. Other modules
/// reach the bot-request facade only through a module grant of their own on
/// the handle connection (prefrontal's seen-marker reaction, or one an
/// operator adds with `github.handle.grant`).
pub const AFT_PRINCIPAL: &str = "reserved:aft";

/// The legacy prefrontal principal, retained while rollback binaries use it.
pub const PREFRONTAL_PRINCIPAL: &str = "reserved:prefrontal-core";

/// Exact daemon-issued identities for the same module across its rename.
pub const PREFRONTAL_PRINCIPALS: [&str; 2] = [PREFRONTAL_PRINCIPAL, "reserved:prefrontal"];

pub fn is_prefrontal(principal: &str) -> bool {
    PREFRONTAL_PRINCIPALS.contains(&principal)
}

/// The reserved module ids, in dial order: the new name before the legacy one.
pub fn prefrontal_module_ids() -> impl Iterator<Item = &'static str> {
    PREFRONTAL_PRINCIPALS.into_iter().rev().map(|principal| {
        principal
            .strip_prefix("reserved:")
            .expect("reserved module")
    })
}

/// The one stored and compared form of a GitHub `owner/repo` name: ASCII
/// lowercase. GitHub resolves owner and repository names without regard to
/// case, so `Org/Repo` and `org/repo` are one repository and must find one
/// binding. Event keys, repository ownership and the repository id cache
/// already key on the lowercase name (SQL `lower`, which is ASCII-only, as
/// this is).
pub fn canonical_repository(name: &str) -> String {
    name.to_ascii_lowercase()
}
