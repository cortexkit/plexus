# Vault `policy.active` handler samples

Replies produced by the Claustrum vault's real `policy.active` handler. They're copied byte for byte with their
`SHA256SUMS` from `crates/credentials-module/tests/vectors/agent-policy-v1/` at claustrum tag
`agent-policy-vectors-v1.1` (commit `ec576326637090697e76844c9ed325ef57c3a59a`).

- `policy.active.ready.json`: an active pair, no `rollout`.
- `policy.active.rollout.json`: the same active pair (manifest 41) plus `rollout` naming the newest
  pair (manifest 42, policy 2), sent while a rollout across computers is running.
- `policy.active.rollout-unready.json`: a newer pair is stored but none is ready yet, so `rollout`
  (manifest 41, policy 1) sits beside the four null members. Plexus reads it as "no active policy".

The older samples in `../agent-policy-v1/` were copied from the vault's wire-contract document and are unchanged.
