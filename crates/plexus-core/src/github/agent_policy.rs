//! Vault-verified agent policy documents and the Plexus GitHub load check.

mod check;
mod model;
mod wire;

pub use check::{check_github, CheckedGitHub, Unserved};
pub use model::{AgentPolicy, MAX_POLICY_BYTES};
pub use wire::{read_active, ActivePolicy, ReadFailure, WatchNotice};

#[cfg(test)]
mod tests;
