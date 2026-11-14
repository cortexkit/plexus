use super::*;

fn federated_ids(path: &Path) -> Vec<String> {
    rusqlite::Connection::open(path)
        .unwrap()
        .prepare("SELECT id FROM federated_rows ORDER BY id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn processed_refs(path: &Path) -> Vec<String> {
    rusqlite::Connection::open(path)
        .unwrap()
        .prepare("SELECT card_ref FROM federated_processed_cards ORDER BY card_ref")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[tokio::test]
async fn federated_revoke_ignores_liveness_and_deletes_only_named_row_for_both_operators() {
    let vector: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/permissions-federated-v1/federated-revoke.json"
    ))
    .unwrap();
    for principal in [reserved("cingulate"), Principal::Direct] {
        for pairing in ["unknown", "ended"] {
            let f = fixture();
            let reader = Arc::new(FederatedListReader {
                calls: std::sync::atomic::AtomicUsize::new(0),
            });
            let state = federated_list_state(f.store.clone(), reader.clone());
            seed_federated_list_row(&f.scratch, "plxf_target", pairing);
            seed_federated_list_row(&f.scratch, "plxf_keep", "other");
            let local_count = count(&f.scratch, "SELECT count(*) FROM grants");
            for (id, expected) in [
                ("plxf_target".to_owned(), json!({"result": vector["reply"]})),
                (
                    "plxf_target".to_owned(),
                    json!({"result":{"outcome":"not_found"}}),
                ),
                (
                    "plxf_unknown".to_owned(),
                    json!({"result":{"outcome":"not_found"}}),
                ),
                (
                    "plx_unknown".to_owned(),
                    json!({"result":{"outcome":"not_found"}}),
                ),
                (
                    row_id(ALL_AGENT, ALL_CONNECTION, Capability::OpenPullRequests),
                    json!({"result":{"outcome":"revoked"}}),
                ),
            ] {
                let reply = route_call(
                    &state,
                    principal.clone(),
                    CallMode::Classic,
                    json!({"method":"permissions.revoke","params":{"id":id}}),
                )
                .await;
                assert_eq!(reply, expected, "{principal:?}, {pairing}, {id}");
            }
            assert_eq!(reader.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert_eq!(federated_ids(f.scratch.path()), ["plxf_keep"]);
            assert_eq!(
                count(&f.scratch, "SELECT count(*) FROM grants"),
                local_count - 1
            );
            let journal = std::fs::read_to_string(
                f.scratch.path().with_file_name("federated-deletions.jsonl"),
            )
            .unwrap();
            let entries: Vec<Value> = journal
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0]["row_id"], "plxf_target");
        }
    }
}

#[tokio::test]
async fn revoke_id_namespaces_never_resolve_each_others_rows() {
    let f = fixture();
    let local_id = row_id(ALL_AGENT, ALL_CONNECTION, Capability::OpenPullRequests);
    let local_count = count(&f.scratch, "SELECT count(*) FROM grants");
    seed_federated_list_row(&f.scratch, "plxf_only_federated", "normal");
    // Even a malformed stored federated id cannot be reached through a local id.
    seed_federated_list_row(&f.scratch, "plx_only_federated", "malformed");
    seed_federated_list_row(&f.scratch, &local_id, "collision");
    for id in [
        "plx_only_federated".to_owned(),
        local_id.replacen("plx_", "plxf_", 1),
    ] {
        assert_eq!(
            revoke(&f.state, &id).await,
            json!({"result":{"outcome":"not_found"}})
        );
        assert_eq!(
            count(&f.scratch, "SELECT count(*) FROM grants"),
            local_count
        );
        assert_eq!(federated_ids(f.scratch.path()).len(), 3);
    }
    assert_eq!(
        revoke(&f.state, &local_id).await,
        json!({"result":{"outcome":"revoked"}})
    );
    assert!(federated_ids(f.scratch.path()).contains(&local_id));
    assert_eq!(federated_ids(f.scratch.path()).len(), 3);
    let remaining_local = count(&f.scratch, "SELECT count(*) FROM grants");
    assert_eq!(
        revoke(&f.state, "plxf_only_federated").await,
        json!({"result":{"outcome":"revoked"}})
    );
    assert_eq!(
        count(&f.scratch, "SELECT count(*) FROM grants"),
        remaining_local
    );
    assert_eq!(federated_ids(f.scratch.path()).len(), 2);
}

fn seed_card(scratch: &Scratch, row_id: &str, card_id: &str, card_ref: &str, state: &str) {
    sql(scratch).execute("INSERT INTO federated_card_records
        (id,peer_fingerprint,pairing_id,peer_class,selector,claim_kind,canonical_claim_identity,
         owner_principal,subject,scope,action,args_digest,filed_scope_json,schema_hash,state,card_ref,
         standing_choices_offered)
        SELECT ?2,peer_fingerprint,pairing_id,peer_class,selector,claim_kind,canonical_claim_identity,
         owner_principal,subject,scope,'web_search',?2,'{}','schema',?4,?3,1
         FROM federated_rows WHERE id=?1",
        rusqlite::params![row_id,card_id,card_ref,state]).unwrap();
}

#[tokio::test]
async fn federated_revoke_journals_cards_survives_restore_and_preserves_regrant() {
    let f = fixture();
    seed_federated_list_row(&f.scratch, "plxf_old", "unknown");
    seed_federated_list_row(&f.scratch, "plxf_keep", "other");
    sql(&f.scratch)
        .execute(
            "UPDATE federated_rows SET card_refs_json=
        '[\"el_plxf_old\",\"el_reaffirm\"]' WHERE id='plxf_old'",
            [],
        )
        .unwrap();
    sql(&f.scratch)
        .execute(
            "INSERT INTO federated_processed_cards VALUES ('el_preexisting')",
            [],
        )
        .unwrap();
    seed_card(
        &f.scratch,
        "plxf_old",
        "pending_one",
        "el_pending_one",
        "pending",
    );
    seed_card(
        &f.scratch,
        "plxf_old",
        "pending_two",
        "el_pending_two",
        "pending",
    );
    seed_card(
        &f.scratch,
        "plxf_old",
        "terminal",
        "el_terminal",
        "declined",
    );
    seed_card(&f.scratch, "plxf_keep", "other", "el_other", "pending");
    let backup = f.scratch.path().with_file_name("snapshot.db");
    sql(&f.scratch)
        .execute("VACUUM INTO ?1", [backup.to_string_lossy()])
        .unwrap();
    assert_eq!(
        revoke(&f.state, "plxf_old").await,
        json!({"result":{"outcome":"revoked"}})
    );
    let states: Vec<(String, String)> = sql(&f.scratch)
        .prepare("SELECT id,state FROM federated_card_records ORDER BY id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        states,
        [
            ("other".into(), "pending".into()),
            ("pending_one".into(), "retired".into()),
            ("pending_two".into(), "retired".into()),
            ("terminal".into(), "declined".into()),
        ]
    );
    let refs = [
        "el_pending_one",
        "el_pending_two",
        "el_plxf_old",
        "el_preexisting",
        "el_reaffirm",
    ];
    assert_eq!(processed_refs(f.scratch.path()), refs);
    let journal =
        std::fs::read_to_string(f.scratch.path().with_file_name("federated-deletions.jsonl"))
            .unwrap();
    let entries: Vec<Value> = journal
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["row_id"], "plxf_old");
    assert_eq!(
        entries[0]["card_refs"],
        json!([
            "el_pending_one",
            "el_pending_two",
            "el_plxf_old",
            "el_reaffirm"
        ])
    );
    assert!(entries[0]["deleted_at_ms"].as_i64().unwrap() > 0);
    let new_id = plexus_core::federated::new_row_id();
    seed_federated_list_row(&f.scratch, &new_id, "unknown");
    let f = reopen(f);
    assert!(federated_ids(f.scratch.path()).contains(&new_id));
    assert_eq!(
        revoke(&f.state, "plxf_old").await,
        json!({"result":{"outcome":"not_found"}})
    );
    assert!(federated_ids(f.scratch.path()).contains(&new_id));
    assert_eq!(processed_refs(f.scratch.path()), refs);
    drop(f.state);
    drop(f.store);
    assert_eq!(
        federated_ids(&backup),
        ["plxf_keep", "plxf_old"],
        "restore contains the old row before journal replay"
    );
    let restored = Arc::new(PlexusStore::open(&descriptor(&backup)).unwrap());
    let (state, _) = state_for(restored);
    assert_eq!(federated_ids(&backup), ["plxf_keep"]);
    assert_eq!(processed_refs(&backup), refs);
    assert_eq!(
        revoke(&state, "plxf_old").await,
        json!({"result":{"outcome":"not_found"}})
    );
}

#[tokio::test]
async fn federated_revoke_failure_keeps_row_and_pending_cards() {
    let f = fixture();
    seed_federated_list_row(&f.scratch, "plxf_target", "unknown");
    seed_card(
        &f.scratch,
        "plxf_target",
        "pending",
        "el_pending",
        "pending",
    );
    let journal = f.scratch.path().with_file_name("federated-deletions.jsonl");
    std::fs::remove_file(&journal).unwrap();
    std::fs::create_dir(&journal).unwrap();
    assert_eq!(
        revoke(&f.state, "plxf_target").await,
        json!({"error": {
            "code":"store_failure",
            "message":"the grants could not be revoked; already revoked grants stay revoked, and a retry revokes the rest"
        }})
    );
    assert_eq!(federated_ids(f.scratch.path()), ["plxf_target"]);
    assert_eq!(
        count(
            &f.scratch,
            "SELECT count(*) FROM federated_card_records WHERE state='pending'"
        ),
        1
    );
    assert!(processed_refs(f.scratch.path()).is_empty());
}

#[tokio::test]
async fn federated_revoke_keeps_operator_refusal_unchanged() {
    let f = fixture();
    seed_federated_list_row(&f.scratch, "plxf_target", "unknown");
    let refusal = serde_json::from_str::<Value>(REFUSED_AGENT).unwrap()["error"].clone();
    for (principal, mode) in [
        (reserved("aft"), CallMode::Classic),
        (reserved("prefrontal-core"), CallMode::Classic),
        (reserved("broca"), CallMode::Classic),
        (reserved("basal"), CallMode::Flow),
        (reserved("cingulate"), CallMode::Flow),
        (reserved("cingulate"), CallMode::Codemode),
        (Principal::Direct, CallMode::Codemode),
    ] {
        let reply = route_call(
            &f.state,
            principal,
            mode,
            json!({"method":"permissions.revoke","params":{"id":"plxf_target"}}),
        )
        .await;
        assert_eq!(reply, json!({"error":refusal}));
    }
    assert_eq!(federated_ids(f.scratch.path()), ["plxf_target"]);
    assert!(
        std::fs::read(f.scratch.path().with_file_name("federated-deletions.jsonl"))
            .unwrap()
            .is_empty()
    );
}
