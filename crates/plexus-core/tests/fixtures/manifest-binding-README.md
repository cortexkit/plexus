# Manifest binding producer vectors

`manifest-binding-v1.json` is copied byte for byte from claustrum:

- Tag: `manifest-binding-vectors-v1`
- Commit: `c2a9ce2eaf99da646160eeb0c73d6b11d9341cbf`
- Source: `crates/credentials-module/tests/vectors/manifest-binding-v1.json`
- SHA-256: `8c070db5272be78e6682714a53628453e5bf7fda5a43431d4e73b4d663218433`
- Contract: `docs/wire-contract-v1.md`, section 17 at the same tag.

The 45 samples come from the vault's real handlers using test-only keys. No
sample key is trusted in production. Do not regenerate these in Plexus. The
producer's documented generator is `CK_EMIT_MANIFEST_VECTORS=1 cargo test
--locked -p credentials-module --features credentials-core/test-support --bin
ck-claustrum manifest_binding_vectors_and_wire_goldens_are_producer_pinned`.

Plexus decodes propose, watch and active-status replies. Tests also pin the
other operation shapes to the samples without adding a phone approval sender.
The Cingulate requester contract is separate and is not extended by this file.
