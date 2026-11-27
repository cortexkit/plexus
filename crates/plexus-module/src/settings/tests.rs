use super::*;

#[test]
fn declaration_matches_schema_rules_and_wire_fixture() {
    let config_home = Scratch::directory("settings-declaration");
    let declaration = config_declaration(config_home.path(), "plexus").unwrap();
    let schema = Schema::new(declaration.schema.clone()).unwrap();
    assert_eq!(
        schema.defaults(),
        json!({"audit_retention_days": 30, "catalog_dir": "catalog"})
    );
    assert_eq!(schema.normalized()["unevaluatedProperties"], false);
    // The desktop Settings page heads the page with the root title and labels
    // each setting with its title, falling back to the raw key without one.
    assert_eq!(declaration.schema["title"], "Plexus");
    for (field, kind, apply, title) in [
        (
            "audit_retention_days",
            "integer",
            "live",
            "Audit record retention (days)",
        ),
        (
            "catalog_dir",
            "string",
            "module_restart",
            "Vendor catalog folder",
        ),
    ] {
        let property = &declaration.schema["properties"][field];
        assert_eq!(property["title"], title);
        assert_eq!(property["type"], kind);
        assert_eq!(property["x-ck-apply"], apply);
        assert_eq!(property["x-ck-layers"], json!(["user"]));
        assert!(property["description"]
            .as_str()
            .is_some_and(|s| !s.is_empty()));
    }
    let expected = include_str!("../../tests/fixtures/settings/config-declare.json");
    let user_file = config_home.join("cortexkit").join("plexus.jsonc");
    let user_file = serde_json::to_string(user_file.to_str().unwrap()).unwrap();
    // Substitute only the platform-specific path; compare the rest byte for byte.
    let expected = expected.trim_end().replacen(
        r#""/operator/config/cortexkit/plexus.jsonc""#,
        &user_file,
        1,
    );
    assert_eq!(serde_json::to_string(&declaration).unwrap(), expected);
}

fn review(bytes: &[u8], base: Option<ConfigView>) -> ConfigReviewReply {
    config_review(
        "plexus",
        ConfigReviewRequest::new(
            base.as_ref().map_or(0, |view| view.generation),
            vec![ConfigLayerSnapshot::file(
                "plexus",
                ConfigLayer::User,
                "/operator/config/cortexkit/plexus.jsonc",
                Some(bytes.to_vec()),
            )],
            base,
        ),
    )
}

#[test]
fn review_refuses_each_invalid_field_at_its_pointer() {
    for (input, pointer) in [
        (r#"{"audit_retention_days":6}"#, "/audit_retention_days"),
        (r#"{"audit_retention_days":7}"#, "/audit_retention_days"),
        (r#"{"audit_retention_days":"30"}"#, "/audit_retention_days"),
        (r#"{"catalog_dir":42}"#, "/catalog_dir"),
        (r#"{"unknown":true}"#, "/unknown"),
    ] {
        let reply = review(input.as_bytes(), None);
        assert!(reply.fields.is_empty(), "{input}");
        assert_eq!(reply.refusals.len(), 1, "{input}");
        assert_eq!(reply.refusals[0].code, "value_invalid", "{input}");
        assert_eq!(reply.refusals[0].paths, [pointer], "{input}");
    }
}

#[test]
fn review_preserves_old_values_and_reports_source_only_changes() {
    let before = ConfigView::new(
        3,
        json!({"audit_retention_days":30,"catalog_dir":"old"}),
        [
            ("/audit_retention_days".into(), Layer::Default),
            ("/catalog_dir".into(), Layer::User),
        ]
        .into(),
        vec![],
        ConfigStatus::Active,
    );
    let reply = review(
        b"{ // retain the default explicitly\n\"audit_retention_days\":30,}",
        Some(before),
    );
    assert!(reply.refusals.is_empty());
    assert_eq!(reply.fields.len(), 2);
    let retention = &reply.fields[0];
    assert_eq!(retention.path, "/audit_retention_days");
    assert_eq!(retention.apply, ApplyKind::Live);
    assert_eq!(retention.old, retention.new);
    assert_eq!(
        (retention.old_source, retention.new_source),
        (Layer::Default, Layer::User)
    );
    let catalog = &reply.fields[1];
    assert_eq!(catalog.path, "/catalog_dir");
    assert_eq!(catalog.apply, ApplyKind::ModuleRestart);
    assert_eq!(catalog.old, RecordedValue::new(json!("old")));
    assert_eq!(catalog.new, RecordedValue::new(json!("catalog")));
    assert_eq!(
        (catalog.old_source, catalog.new_source),
        (Layer::User, Layer::Default)
    );
}

#[test]
fn applied_retention_reaches_the_running_schedulers_next_pass() {
    let scratch = Scratch::database("managed-retention");
    let store = Arc::new(crate::test_support::open_file_store(scratch.path()));
    let db = rusqlite::Connection::open(scratch.path()).unwrap();
    let now = plexus_core::storage::now_ms();
    for (age_days, reason) in [(12, "over-the-new-window"), (3, "inside-the-new-window")] {
        db.execute("INSERT INTO audit_journal (ts, principal, actor, acting_principal, decision, reason_code) VALUES (?1, 'direct', 'test', 'direct', 'allow', ?2)",
            rusqlite::params![now - age_days * AUDIT_MILLIS_PER_DAY, reason]).unwrap();
    }
    assert_eq!(store.list_audit("direct").unwrap().len(), 2);
    let state = Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(Arc::clone(&store)),
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let window = AuditRetention::new(30 * AUDIT_MILLIS_PER_DAY);
        let (stop, rx) = mpsc::channel(1);
        let task = spawn_trigger_scheduler_every(
            Duration::from_millis(10),
            Arc::clone(&state),
            rx,
            window.clone(),
        );
        // The scheduler captured the old window at construction, but has not
        // reached its first housekeeping pass on this current-thread runtime.
        let delivered = ConfigView::new(
            1,
            json!({"catalog_dir":"catalog","audit_retention_days":8}),
            Default::default(),
            vec![],
            ConfigStatus::Pending,
        );
        let module_data = scratch.owned_directory();
        let live = LiveSettings {
            catalog_dir: module_data.join("catalog"),
            audit_retention: window,
            pending_report: None,
        };
        live.apply(&delivered, Some(module_data)).unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let count = store.list_audit("direct").unwrap().len();
                if count != 2 {
                    assert_eq!(count, 1);
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the scheduler did not prune the row outside the applied window");
        drop(stop);
        task.await.unwrap();
    });
}
