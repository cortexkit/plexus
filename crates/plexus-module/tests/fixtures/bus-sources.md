# Bus fixture provenance

- `card-settled-v1/` is a byte-for-byte copy of Cingulate's
  `test-vectors/card-settled-v1/` at commit `9866794`. All 26 upstream files are
  retained, including its README and SHA256SUMS. SHA256SUMS itself has SHA-256
  `2718117337670cfccd3b5596cd921325ad614ed7347a4780c952fd8344cebc1d`.
- `github-notice-bus-nats-0.3.0.json` records a GitHub notice captured from
  `cortexkit-bus-nats` 0.3.0 through a real NATS 2.15.0 server supplied by
  `cortexkit-bus-testkit` 0.9.2, before upgrading the backend. The fixture records
  the subject, payload bytes and every header value in sorted-key JSON. Header
  serialization order is not part of this comparison. The live-session test
  substitutes only the test account token (`box_test` to `box_example`).
  The input was fact id `fixture-fact`, digest of `github-wire-fixture`, and
  labels `kind=github_issue_changed`, `repo=owner/repo`, `project=project-a`.
