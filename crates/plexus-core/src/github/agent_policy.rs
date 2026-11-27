//! Vault-verified agent policy documents and the Plexus GitHub load check.

mod check;
mod model;
pub(crate) mod plan;
mod suffix;
mod wire;

pub use check::{check_github, CheckedGitHub, Unserved};
pub use model::{AgentPolicy, MAX_POLICY_BYTES};
pub use plan::{AgentChange, ApplyPlan, PolicyConflict};
pub use suffix::{repo_get_suffix_template, SuffixMatch};
pub use wire::{read_active, ActivePolicy, PolicyRollout, ReadFailure, WatchNotice};

#[cfg(test)]
mod tests;
