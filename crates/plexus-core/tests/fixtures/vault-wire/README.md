# Vault wire fixture

`enrollment_wire_contract.json` is copied byte for byte from claustrum commit
`c5b8ee7e66f7853eac6807aa6e5607e536b09212` (tag `list-scoped-vectors-v2`,
tag object `9a5ed8aec45d953b86392f5511138fe29c5bea11`), supplied by CKCRED. SHA-256:
`1f9a48ce76b03cbea143fcdb7f83b940e32884d890dc51f9bdc594045962a941`.
Besides the scoped list/watch additions, this version includes additive
`admin.enroll_approve`, `admin.enroll_revoke` and enrollment display-name examples.

`list-scoped-v2.json` is copied byte for byte from the same commit and tag,
from `crates/credentials-module/tests/vectors/list-scoped-v2.json`. SHA-256:
`e9dfb2140ff4d92ece55de09da5987b27d8ca1a2023f0f9c50439499c3c3d603`.
Its five real-handler cases pin scoped provider/incarnation metadata, opening
and changed watch notices, terminal revocation and an older vault's refusal.
Tests decode `reply_b64url` and verify each `reply_sha256`, not reconstructed JSON.

Its public-key, scoped-token and versioned auth-report examples are protocol
fixtures, not production keys or credentials. Plexus authenticates as the daemon's
reserved module identity, so its requests omit
`enrollment_token`, `reporter_source` and optional `min_ttl_ms` from its requests.
The fixture includes a vault-generated `credential.open` success, five refusal
cases, and the synthetic ephemeral input key material (IKM) used to reproduce its encapsulation and
ciphertext. The open adapter sends exactly `credential_id`, `enc_b64`, `ciphertext_b64`,
`info_b64` and `aad_b64`, with strict padded standard-alphabet base64. The result
contains `plaintext_b64` and `key_id`. The info bytes are `plexus-sent-text/v1`;
the associated data is the row/connection/recipient-hash tuple documented in
`gmail::aad`. Tests reproduce the fixture's ciphertext byte for byte and pass
all six replies through the operator read-back path; the fixture's arbitrary
associated-data bytes are also checked independently of Plexus's row tuple.

The `gmail_rfc9180_a2_1_chacha20_vector` test uses the independent ciphertext
from RFC 9180 Appendix A.2.1.1 (sequence 0), with the recipient key, encapsulation
and info from A.2.1: <https://www.rfc-editor.org/rfc/rfc9180#appendix-A.2.1>.
This fixes mode 0, KEM 0x0020, KDF 0x0001 and AEAD 0x0003 independently of the
round-trip tests.
