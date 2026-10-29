# Vault wire fixture

`enrollment_wire_contract.json` is copied byte for byte from claustrum commit
`bf5405f3059edb023945322ba015b52d3fcab44d`, supplied by CKCRED. SHA-256:
`eb0ef07ed7eb97e7bf9e7aefdd6bfa1322d2253e46b2e4fe91d05b1113523802`.

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
