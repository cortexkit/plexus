# Manifest binding v1

Readers first: phone and desktop renderers must implement this kind before Plexus
files one. A phone advertises `manifest-binding-approval` only after implementing
independent statement decoding and refusing disagreements with the served fields.

`vault-samples.json` copies the statement, envelope, propose reply and approve
request from claustrum tag `manifest-binding-vectors-v1`, commit
`c2a9ce2eaf99da646160eeb0c73d6b11d9341cbf`, from
`crates/credentials-module/tests/vectors/manifest-binding-v1.json` (SHA-256
`8c070db5272be78e6682714a53628453e5bf7fda5a43431d4e73b4d663218433`).
The authority is `docs/wire-contract-v1.md` section 17 at that tag (SHA-256
`63aee2042c1565c47c4f3764f869b248a48a5db8a444cf0c34e2724909e731aa`).
Keys and signatures are TEST ONLY. No build or test reads the claustrum checkout.

All other JSON samples are produced by Cingulate's real request, get, answer and
await handlers, with a fixed clock and temporary store. `phone-refuse-mismatch.json`
is the sole exception: it mutates `repo` on a real served card and explicitly
labels it as a sample the phone MUST refuse, not a card Cingulate serves.
Decline records a local decision only; expired answers are refused.

Regenerate with `cargo run -p cingulate-vectors --example generate_manifest_binding_vectors --locked`.
Add `-- --check` to verify without writing. `SHA256SUMS` covers every corpus file
except itself. The test `manifest_binding_vectors_are_handler_generated_and_hash_pinned`
also compares the handler output and checks every hash.
