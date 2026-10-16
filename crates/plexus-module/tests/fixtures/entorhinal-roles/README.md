# Entorhinal role vectors — pending

The JSON files in this directory must be copied **byte for byte** from
Entorhinal's real-handler vector generator, not generated from Plexus's double.

- Entorhinal source commit: **pending ENTO publication**
- File SHA-256: **pending ENTO publication**

`pending_entorhinal_role_vectors_through_real_reader` skips with a message only
while there are no JSON files. Once any file exists, its case names must match
the Plexus-owned expectations table exactly: `never_read`, `read_unheld`,
`held_here`, `held_elsewhere`, `stale`, `integrity_failed`.

The small `entorhinal_vector_cases` parser currently assumes
`{"cases": [{"name": "…", "reply": {"result": {"…": "…"}}}]}`. Adapt that parser
to ENTO's actual format when copying the producer's file; do not rewrite the
producer's bytes to fit this provisional parser. Plexus owns the admission
expectations and stale-after-confirmed-hold sequence, not the vector schema.
