# Vault policy token vectors

Source: Claustrum, `crates/credentials-module/tests/vectors/broker-action/cases.json`
at tag `broker-action-vault-vectors-v1.1` (commit `f53196b5a75cd7e737b411dd25557cc7ea04972e`).

- Source SHA-256: `2957174fcccbc7092f3a19b3c31b75fe12b16f3680c283abfc2df11d6b5eeddd`
- Extracted `cases.json` SHA-256: `c1cde34e9f73e25ad80e71f1ccc62e4750f374d786aa5b3bd27eac2f402da810`

Keep only `credential.policy_token` cases named `issue_none_kind`, `issue_ungranted`,
`issue_wrong_service`, `issue_unbound_resource_without_approval`, `issue_old_policy_without_proof`,
`issue_no_approval_members`, `issue_policy_changed`, `issue_provider_error`, `issue_store_error`,
`issue_needs_reauth`, `issue_retired`, `issue_deleted_record`, `issue_record_replaced_during_mint`,
and `issue_record_changed_twice`.
Copy each case object byte for byte (including its indentation) in source order into a new
`{"cases": [...]}` wrapper. Omit all other members and cases, including the approval proof
lifecycle, which Plexus does not implement. Tokens in these vault vectors are synthetic.
