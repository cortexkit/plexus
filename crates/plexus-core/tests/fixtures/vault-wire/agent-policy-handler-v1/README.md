# Vault `policy.active` handler samples

Replies produced by the Claustrum vault's real `policy.active` handler, copied byte for byte with their
`SHA256SUMS` from `crates/credentials-module/tests/vectors/agent-policy-v1/` at claustrum commit
`71e2e05e799b6b31f904729167e996e8408eeb90`. That commit isn't on the vault's main yet; the samples will be
tagged when it lands.

- `policy.active.ready.json`: an active pair, no `rollout`.
- `policy.active.rollout.json`: the same active pair (manifest 41) plus `rollout` naming the newest
  pair (manifest 42, policy 2), sent while a rollout across computers is running.

The doc-derived goldens in `../agent-policy-v1/` are older and unchanged.
- `policy.active.rollout-unready.json`: a newer pair is stored but none is ready yet, so `rollout`
  (manifest 41, policy 1) sits beside the four null members. Plexus reads it as "no active policy".
