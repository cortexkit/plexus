# Vault policy token vectors

Source: Claustrum, `crates/credentials-module/tests/vectors/broker-action/cases.json`
at tag `broker-action-vault-vectors-v1` (commit `0656414da3df15e604e8e276cf3f25077e9e5452`).

- Source SHA-256: `d3e7e3568f5f3781007cf8ea0d1fea2accffd0abb7f587caa80ac49dca184ebf`
- Extracted `cases.json` SHA-256: `c2fc4e01e6008c02e646b80dd8dfbefc59492304944956d85c55a3609a502d69`

Keep only `credential.policy_token` cases named `issue_none_kind`, `issue_ungranted`,
`issue_wrong_service`, `issue_unbound_resource_without_approval`, `issue_old_policy_without_proof`,
`issue_no_approval_members`, `issue_policy_changed`, `issue_provider_error`, and `issue_store_error`.
Copy each case object byte for byte (including its indentation) in source order into a new
`{"cases": [...]}` wrapper. Omit all other members and cases, including the approval proof
lifecycle, which Plexus does not implement. Tokens in these vault vectors are synthetic.

The pending `broker-action-vault-vectors-v1.1` supplement will cover credential lifecycle
refusals, including a record replaced during mint. The cases here cover only the v1 wire contract.
