CREATE TABLE federated_rows (
    id TEXT PRIMARY KEY NOT NULL CHECK (id GLOB 'plxf_*'),
    peer_fingerprint TEXT NOT NULL,
    pairing_id TEXT NOT NULL,
    peer_class TEXT NOT NULL,
    selector TEXT NOT NULL,
    claim_kind TEXT NOT NULL,
    canonical_claim_identity TEXT NOT NULL,
    owner_principal TEXT NOT NULL,
    subject TEXT NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('read', 'write')),
    claim_json TEXT,
    peer_name TEXT NOT NULL,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    granted_at_ms INTEGER NOT NULL,
    card_ref TEXT NOT NULL,
    card_refs_json TEXT NOT NULL,
    UNIQUE (peer_fingerprint, pairing_id, peer_class, selector, claim_kind,
            canonical_claim_identity, owner_principal, subject, scope)
);

CREATE TABLE federated_card_records (
    id TEXT PRIMARY KEY NOT NULL,
    peer_fingerprint TEXT NOT NULL,
    pairing_id TEXT NOT NULL,
    peer_class TEXT NOT NULL,
    claim_kind TEXT NOT NULL,
    canonical_claim_identity TEXT NOT NULL,
    owner_principal TEXT NOT NULL,
    subject TEXT NOT NULL,
    action TEXT NOT NULL,
    args_digest TEXT NOT NULL,
    selector TEXT NOT NULL,
    scope TEXT NOT NULL CHECK (scope IN ('read', 'write')),
    filed_scope_json TEXT NOT NULL,
    schema_hash TEXT,
    state TEXT NOT NULL CHECK (state IN (
        'pending', 'consumed', 'declined', 'expired', 'withdrawn', 'committed', 'retired'
    )),
    card_ref TEXT UNIQUE
);
CREATE INDEX federated_card_records_binding ON federated_card_records (
    peer_fingerprint, pairing_id, peer_class, claim_kind, canonical_claim_identity,
    owner_principal, subject, action, args_digest, scope, schema_hash, state
);

-- Processed refs outlive rows, cards, connections and pairings. No foreign key
-- or cascade may tie their lifetime to those records.
CREATE TABLE federated_processed_cards (
    card_ref TEXT PRIMARY KEY NOT NULL
);

ALTER TABLE audit_journal ADD COLUMN peer_fingerprint TEXT;
ALTER TABLE audit_journal ADD COLUMN pairing_id TEXT;
ALTER TABLE audit_journal ADD COLUMN peer_class TEXT;
ALTER TABLE audit_journal ADD COLUMN claim_kind TEXT;
ALTER TABLE audit_journal ADD COLUMN canonical_claim_identity TEXT;
ALTER TABLE audit_journal ADD COLUMN federated_row_id TEXT;
ALTER TABLE audit_journal ADD COLUMN card_ref TEXT;

ALTER TABLE reservations ADD COLUMN federated_row_id TEXT;
ALTER TABLE reservations ADD COLUMN card_ref TEXT;
