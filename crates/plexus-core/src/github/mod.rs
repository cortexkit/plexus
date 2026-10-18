//! GitHub App bot writes: repository resolution, bounded list pagination, the
//! scoped vault credential used at dispatch, and the receipt ledger that keeps
//! a retried request from being sent twice. Handle, binding and receipt
//! storage, and the store-backed governance projections, live under
//! `storage::github_store`.

pub mod control;
pub mod credential;
pub mod facade;
pub mod pagination;
pub mod reads;
pub mod receipt;
pub mod resolver;
pub mod sweeper;

/// The principal that bot requests from AFT's GitHub shim carry when they
/// reach plexus. Each imported handle's write grants name it. Other modules
/// reach the bot-request facade only through a module grant of their own on
/// the handle connection (prefrontal-core's seen-marker reaction, or one an
/// operator adds with `github.handle.grant`).
pub const AFT_PRINCIPAL: &str = "reserved:aft";

/// The principal that read requests from the prefrontal module (module id
/// `prefrontal-core`) carry when they reach plexus. Each imported handle's
/// read grant must name exactly this principal to apply to those reads.
pub const PREFRONTAL_PRINCIPAL: &str = "reserved:prefrontal-core";

/// The one stored and compared form of a GitHub `owner/repo` name: ASCII
/// lowercase. GitHub resolves owner and repository names without regard to
/// case, so `Org/Repo` and `org/repo` are one repository and must find one
/// binding. Event keys, repository ownership and the repository id cache
/// already key on the lowercase name (SQL `lower`, which is ASCII-only, as
/// this is).
pub fn canonical_repository(name: &str) -> String {
    name.to_ascii_lowercase()
}
