// Store-boundary regressions share the inline storage test fixtures.

#[test]
fn connection_delete_removes_consent_alias_children() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let request_id = store
        .create_action_request(
            "direct",
            "connection",
            "write_action",
            &serde_json::json!({}),
            "schema",
            "caller",
            now_ms() + 60_000,
            None,
            None,
        )
        .unwrap();
    let request = store
        .action_request("direct", &request_id)
        .unwrap()
        .unwrap();
    store.remember_consent_call_key(&request, "alias").unwrap();
    store.revoke_grant("direct", "grant-poll").unwrap();
    assert!(matches!(
        store
            .delete_connection("direct", "connection", true)
            .unwrap(),
        DeleteConnectionOutcome::Deleted { .. }
    ));
    let aliases: i64 = store
        .inner
        .with_read(|conn| {
            conn.query_row("SELECT COUNT(*) FROM consent_call_keys", [], |row| {
                row.get(0)
            })
        })
        .unwrap();
    assert_eq!(aliases, 0);
}

#[test]
fn resume_rechecks_catalog_pin_connection_and_grant_under_the_fence() {
    for change in ["schema", "status", "retired", "connection", "grant"] {
        let store = trigger_store(crate::governance::AUTHORITY_POLL);
        let sub = read_subscription(&store);
        store
            .suspend(
                "direct",
                &sub.subscription_id,
                CIRCUIT_BREAKER_SUSPENSION_REASON,
            )
            .unwrap();
        store.inner.with_conn_fenced(|conn| {
            match change {
                "schema" => { conn.execute("UPDATE catalog_actions SET schema_hash='changed' WHERE name='read_action'", [])?; }
                "status" => { conn.execute("UPDATE catalog_actions SET status='disabled' WHERE name='read_action'", [])?; }
                "retired" => { conn.execute("UPDATE app_manifests SET status='retired'", [])?; }
                "connection" => { conn.execute("UPDATE connections SET status='revoked'", [])?; }
                "grant" => { conn.execute("UPDATE grants SET expires_at=1", [])?; }
                _ => unreachable!(),
            }
            Ok(())
        }).unwrap();
        assert!(
            store
                .resume("direct", &sub.subscription_id)
                .unwrap()
                .is_err(),
            "resume must refuse stale {change}"
        );
        assert_eq!(
            store
                .subscription("direct", &sub.subscription_id)
                .unwrap()
                .unwrap()
                .status,
            "suspended"
        );
    }
}

#[test]
fn resume_reports_live_authority_and_accepts_response_shape_pauses() {
    for reason in [
        CIRCUIT_BREAKER_SUSPENSION_REASON,
        "response_shape_invalid",
        "response_shape_invalid: missing items",
    ] {
        let store = trigger_store(crate::governance::AUTHORITY_POLL);
        let sub = read_subscription(&store);
        store
            .suspend("direct", &sub.subscription_id, reason)
            .unwrap();
        let paused = store
            .subscription("direct", &sub.subscription_id)
            .unwrap()
            .unwrap();
        let resumed = store
            .resume("direct", &sub.subscription_id)
            .unwrap()
            .unwrap();
        assert_eq!(resumed.authority_state, "live");
        assert!(resumed.authority_expires_at_ms.is_some());
        assert_eq!(resumed.cursor_state, paused.cursor_state);
        assert_eq!(resumed.generation, paused.generation + 1);
        assert_eq!(
            store
                .resume("direct", &sub.subscription_id)
                .unwrap()
                .unwrap()
                .generation,
            resumed.generation
        );
    }
}

#[test]
fn subscription_insert_rechecks_retirement_in_the_transaction() {
    for probe in [false, true] {
        let store = std::rc::Rc::new(trigger_store(crate::governance::AUTHORITY_POLL));
        let raced = store.clone();
        set_race_hook(
            if probe {
                "probe_insert"
            } else {
                "subscription_insert"
            },
            move || {
                raced
                    .inner
                    .with_conn_fenced(|conn| {
                        conn.execute("UPDATE app_manifests SET status='retired'", [])
                            .map(|_| ())
                    })
                    .unwrap();
            },
        );
        let result = if probe {
            register_probe_on(
                &store,
                "direct",
                &["read_action"],
                "always",
                &serde_json::json!({}),
            )
        } else {
            store
                .subscribe("direct", "connection", "read_action", 30)
                .unwrap()
        };
        assert!(
            matches!(result, Err(SubscriptionRefusal::ActionUnavailable(ref reason)) if reason == "app_retired")
        );
        assert_eq!(subscription_rows(&store), 0);
    }
}

#[test]
fn a_new_binding_ticket_invalidates_the_previous_pending_binding() {
    let store = reservation_store();
    store
        .insert_connection("direct", "c", "app", "pending", &serde_json::json!({}))
        .unwrap();
    let first = store
        .create_binding_ticket_with_role(
            "direct",
            "c",
            "credential_reference",
            b"vault:first-reference",
        )
        .unwrap();
    let second = store
        .create_binding_ticket_with_role(
            "direct",
            "c",
            "credential_reference",
            b"vault:second-reference",
        )
        .unwrap();
    assert!(
        store
            .connect_with_ticket("direct", &first.ticket_id)
            .unwrap()
            .is_none(),
        "an older ticket must not activate a newer binding"
    );
    assert!(store
        .connect_with_ticket("direct", &second.ticket_id)
        .unwrap()
        .is_some());
}

#[test]
fn expired_unclaimed_reservations_are_reclaimed_but_live_fences_survive() {
    let store = reservation_store();
    let now = now_ms();
    store
        .insert_reservation_at_for_test(
            "p",
            "abandoned",
            "reserved",
            now - 2 * RESERVATION_RETENTION_MS,
        )
        .unwrap();
    store
        .insert_reservation_at_for_test("p", "live", "reserved", now)
        .unwrap();
    assert_eq!(store.prune_reservations(now).unwrap(), 1);
    assert!(store.reservation("p", "abandoned").unwrap().is_none());
    assert_eq!(
        store.reservation("p", "live").unwrap().unwrap().status,
        "reserved"
    );
}

#[test]
fn backwards_clock_steps_do_not_stall_watches_or_reverse_gap_bounds() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let sub = read_subscription(&store);
    let now = now_ms();
    store
        .record_poll_attempt("direct", &sub.subscription_id, now + 60_000)
        .unwrap();
    store
        .record_poll_success(
            "direct",
            &sub.subscription_id,
            &serde_json::json!({}),
            now + 60_000,
        )
        .unwrap();
    assert!(store
        .due_subscriptions("direct", now)
        .unwrap()
        .iter()
        .any(|row| row.subscription_id == sub.subscription_id));
    store
        .suspend(
            "direct",
            &sub.subscription_id,
            CIRCUIT_BREAKER_SUSPENSION_REASON,
        )
        .unwrap();
    let gap = store
        .list_events("direct", None, None)
        .unwrap()
        .pop()
        .unwrap();
    assert!(gap.gap_from_ms.unwrap() <= gap.gap_to_ms.unwrap());
}

#[test]
fn prior_activity_bound_uses_vendor_time_not_host_observation_time() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let sub = read_subscription(&store);
    store
        .commit_poll_success(
            "direct",
            "connection",
            &sub.subscription_id,
            &serde_json::json!({}),
            &[PollEventInput {
                vendor_event_id: "item",
                payload: &serde_json::json!({"id": "item"}),
                observed_at_ms: 9_000,
                item_kind: Some("issue"),
                activity_at_ms: Some(3_000),
                actor: &ActorAttribution::NotEnriched,
            }],
            9_000,
            None,
        )
        .unwrap();
    assert_eq!(
        store
            .previous_event_observed_at("direct", "connection", &sub.subscription_id, "item")
            .unwrap(),
        Some(3_000)
    );
}

#[test]
fn catalog_changes_suspend_probes_that_declare_the_action() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let sub = register_probe_on(
        &store,
        "direct",
        &["read_action"],
        "always",
        &serde_json::json!({}),
    )
    .unwrap();
    store
        .disable_catalog_action("direct", "connection", "read_action")
        .unwrap();
    assert_eq!(
        store
            .subscription("direct", &sub.subscription_id)
            .unwrap()
            .unwrap()
            .status,
        "suspended"
    );
    assert_eq!(
        store
            .list_events("direct", None, Some(&sub.subscription_id))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn invalid_stored_manifest_is_a_subscription_domain_refusal() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute("UPDATE app_manifests SET manifest_json='{}'", [])
                .map(|_| ())
        })
        .unwrap();
    assert!(matches!(
        store
            .subscribe("direct", "connection", "read_action", 30)
            .unwrap(),
        Err(SubscriptionRefusal::ManifestInvalid(_))
    ));
}

#[test]
fn two_consumers_and_the_owner_share_one_acknowledgement_queue() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let sub = read_subscription(&store);
    for consumer in ["first", "second"] {
        insert_grant_with_selectors_for_test(
            &store,
            consumer,
            consumer,
            &["read_action"],
            crate::governance::AUTHORITY_EVENTS_CONSUME,
        );
    }
    store
        .insert_event(
            "direct",
            "connection",
            &sub.subscription_id,
            "shared",
            &serde_json::json!({"id": "shared"}),
            now_ms(),
        )
        .unwrap();
    let now = now_ms();
    let events = store
        .list_events_including_granted("first", None, None, now)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(
        store
            .list_events_including_granted("second", None, None, now)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .ack_events_including_granted("first", &[events[0].event_id.clone()], now)
            .unwrap(),
        1
    );
    for principal in ["direct", "first", "second"] {
        assert!(store
            .list_events_including_granted(principal, None, None, now)
            .unwrap()
            .is_empty());
    }
    let body: String = store
        .inner
        .with_read(|conn| {
            conn.query_row(
                "SELECT payload FROM trigger_events WHERE event_id=?1",
                [&events[0].event_id],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert!(
        body.contains("shared"),
        "shared acks retain the durable event body"
    );
}

#[test]
fn credential_rebind_records_only_the_reference_fingerprint() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let generation = store
        .connection("direct", "connection")
        .unwrap()
        .unwrap()
        .generation;
    assert!(store
        .rebind_credential_reference("direct", "connection", generation, "vault:new-reference")
        .unwrap());
    let rows = store.list_audit("direct").unwrap();
    let row = rows
        .iter()
        .find(|row| row.action.as_deref() == Some("rebind_credential"))
        .unwrap();
    assert_eq!(
        row.credential_fingerprint.as_deref(),
        Some(crate::fingerprint::fingerprint(b"vault:new-reference").as_str())
    );
}

#[test]
fn event_ack_chunks_commit_before_a_later_chunk_fails_and_retry_safely() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let sub = read_subscription(&store);
    let mut ids = Vec::new();
    for index in 0..501 {
        let outcome = store
            .insert_event(
                "direct",
                "connection",
                &sub.subscription_id,
                &index.to_string(),
                &serde_json::json!({"id": index}),
                now_ms(),
            )
            .unwrap();
        let TriggerEventInsertOutcome::Inserted { event_id } = outcome else {
            panic!("expected event");
        };
        ids.push(event_id);
    }
    store
        .inner
        .with_conn_fenced(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER reject_last_ack BEFORE UPDATE OF acked_at_ms ON trigger_events
         WHEN OLD.vendor_event_id='500' BEGIN SELECT RAISE(ABORT,'last chunk rejected'); END;",
            )
        })
        .unwrap();
    let now = now_ms();
    assert!(store
        .ack_events_including_granted("direct", &ids, now)
        .is_err());
    assert!(
        store.unacked_of("direct", &ids[..500]).unwrap().is_empty(),
        "earlier ack chunks must have committed"
    );
    store
        .inner
        .with_conn_fenced(|conn| conn.execute_batch("DROP TRIGGER reject_last_ack"))
        .unwrap();
    assert_eq!(
        store
            .ack_events_including_granted("direct", &ids, now)
            .unwrap(),
        1
    );
    assert!(store.unacked_of("direct", &ids).unwrap().is_empty());
}

#[test]
fn typed_manifest_cache_reuses_current_content_and_reloads_new_hashes() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let first = store
        .parsed_manifest(CATALOG_PRINCIPAL, "trigger_fixture")
        .unwrap()
        .unwrap()
        .unwrap();
    let same = store
        .parsed_manifest(CATALOG_PRINCIPAL, "trigger_fixture")
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(std::sync::Arc::ptr_eq(&first, &same));
    let mut changed = trigger_manifest();
    changed["name"] = serde_json::json!("Changed name");
    let manifest = crate::manifest::ingest_value(changed).unwrap();
    store.upsert_manifest(CATALOG_PRINCIPAL, &manifest).unwrap();
    let next = store
        .parsed_manifest(CATALOG_PRINCIPAL, "trigger_fixture")
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(next.name, "Changed name");
    assert!(!std::sync::Arc::ptr_eq(&first, &next));
}

#[test]
fn unsubscribe_event_queries_use_the_owner_subscription_index() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    store.inner.with_read(|conn| {
        let plan: String = conn.query_row(&format!("EXPLAIN QUERY PLAN SELECT event_id FROM trigger_events WHERE {SUBSCRIPTION_EVENTS_PREDICATE}"),
            ("direct", "watch"), |row| row.get(3))?;
        assert!(plan.contains("idx_trigger_events_subscription"), "unsubscribe needs the owner/subscription index: {plan}");
        Ok(())
    }).unwrap();
}

#[test]
fn the_rust_audit_floor_matches_the_frozen_sql_floor() {
    assert_eq!(AUDIT_DELETE_FLOOR_DAYS * AUDIT_MILLIS_PER_DAY, 604_800_000);
    assert_eq!(DEFAULT_AUDIT_RETENTION_DAYS, 30);
}

#[test]
fn catalog_observation_refusals_do_not_impersonate_sql_binding_errors() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let error = store
        .reconcile_catalog_actions("direct", "connection", &[])
        .unwrap_err();
    assert!(error.to_string().contains("catalog observation refused"));
    assert!(!error.to_string().contains("Invalid parameter name"));
    assert_eq!(
        store
            .catalog_action("direct", "connection", "read_action")
            .unwrap()
            .unwrap()
            .status,
        "active"
    );
}

#[test]
fn reconciliation_listing_reports_truncation_and_keeps_principal_scope() {
    let store = reservation_store();
    store.inner.with_conn_fenced(|conn| {
        let mut insert = conn.prepare("INSERT INTO write_reconciliation_results (principal,request_id,acting_principal,connection_id,action,status,updated_at_ms) VALUES (?1,?2,?1,'c','a','confirmed',?3)")?;
        for index in 0..=RECONCILIATION_BATCH_ROWS {
            insert.execute(rusqlite::params!["owner", format!("r-{index}"), index])?;
        }
        Ok(())
    }).unwrap();
    let (rows, truncated) = store.list_write_reconciliations("owner").unwrap();
    assert_eq!(rows.len(), RECONCILIATION_BATCH_ROWS as usize);
    assert!(truncated);
    let (foreign, truncated) = store.list_write_reconciliations("stranger").unwrap();
    assert!(foreign.is_empty());
    assert!(!truncated);
}

#[test]
fn batched_subscription_visibility_matches_per_lane_reads_for_multiple_owners() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let mut expected = Vec::new();
    for (owner, connection) in [("owner-a", "c1"), ("owner-a", "c2"), ("owner-b", "c3")] {
        store
            .insert_connection(
                owner,
                connection,
                "trigger_fixture",
                "active",
                &serde_json::json!({}),
            )
            .unwrap();
        store
            .upsert_catalog_action(&CatalogActionInput {
                principal: owner.into(),
                connection_id: connection.into(),
                name: "read_action".into(),
                title: None,
                schema: serde_json::json!({"type":"object"}),
                schema_hash: "pin".into(),
                risk: "read".into(),
                severity: "S2".into(),
                ask_first: false,
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .unwrap();
        for (kind, grantee) in [("poll", owner), ("events_consume", "consumer")] {
            store
                .insert_grant(&GrantInput {
                    grant_id: format!("{connection}-{kind}"),
                    principal: owner.into(),
                    connection_id: connection.into(),
                    grantee_principal: grantee.into(),
                    risk_ceiling: "read".into(),
                    action_selectors: vec!["read_action".into()],
                    authority_kind: kind.into(),
                    expires_at: None,
                })
                .unwrap();
        }
        store
            .subscribe(owner, connection, "read_action", 30)
            .unwrap()
            .unwrap();
        expected.extend(
            store
                .list_subscriptions(owner, Some(connection), None)
                .unwrap(),
        );
    }
    expected.sort_by(|a, b| {
        (a.created_at_ms, &a.subscription_id).cmp(&(b.created_at_ms, &b.subscription_id))
    });
    let actual = store
        .list_subscriptions_including_granted("consumer", None, None, now_ms())
        .unwrap();
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    assert!(store
        .list_subscriptions_including_granted("stranger", None, None, now_ms())
        .unwrap()
        .is_empty());
}

#[test]
fn unacked_results_reuse_the_ack_authority_timestamp() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let sub = read_subscription(&store);
    let now = now_ms();
    store
        .insert_grant(&GrantInput {
            grant_id: "short-consumer".into(),
            principal: "direct".into(),
            connection_id: "connection".into(),
            grantee_principal: "consumer".into(),
            risk_ceiling: "read".into(),
            action_selectors: vec!["read_action".into()],
            authority_kind: "events_consume".into(),
            expires_at: Some(now + 10),
        })
        .unwrap();
    let TriggerEventInsertOutcome::Inserted { event_id } = store
        .insert_event(
            "direct",
            "connection",
            &sub.subscription_id,
            "short",
            &serde_json::json!({}),
            now,
        )
        .unwrap()
    else {
        panic!("expected event");
    };
    let ids = [event_id];
    assert_eq!(
        store
            .ack_events_including_granted("consumer", &ids, now)
            .unwrap(),
        1
    );
    assert!(store
        .unacked_of_at("consumer", &ids, now)
        .unwrap()
        .is_empty());
    assert_eq!(
        store.unacked_of_at("consumer", &ids, now + 10).unwrap(),
        ids
    );
}

#[test]
fn wildcard_grantees_do_not_make_a_connection_invoke_visible() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    insert_grant_with_selectors_for_test(&store, "wildcard", "*", &["read_action"], "invoke");
    assert!(store
        .connection_for_invoke("caller", "connection")
        .unwrap()
        .is_none());
    insert_grant_with_selectors_for_test(&store, "named", "caller", &["read_action"], "invoke");
    assert!(store
        .connection_for_invoke("caller", "connection")
        .unwrap()
        .is_some());
}

#[test]
fn waiting_approval_batches_share_a_timestamp_and_rotate_together() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let mut ids = Vec::new();
    for index in 0..3 {
        let id = store
            .create_action_request(
                "direct",
                "connection",
                "write_action",
                &serde_json::json!({"value": index}),
                "schema",
                "caller",
                now_ms() + 60_000,
                None,
                None,
            )
            .unwrap();
        store.inner.with_conn_fenced(|conn| conn.execute(
            "UPDATE action_requests SET status='approved',scope_outcome=?2,created_at_ms=?3 WHERE request_id=?1",
            rusqlite::params![id, crate::scope::APPROVED_WAITING, index],
        ).map(|_| ())).unwrap();
        ids.push(id);
    }
    let batch = store.waiting_scoped_approvals(2).unwrap();
    assert_eq!(batch.len(), 2);
    let checks: Vec<i64> = store
        .inner
        .with_read(|conn| {
            let mut query = conn.prepare(
                "SELECT scope_checked_at_ms FROM action_requests WHERE request_id IN (?1,?2)",
            )?;
            let rows = query.query_map((&batch[0].request_id, &batch[1].request_id), |row| {
                row.get(0)
            })?;
            rows.collect()
        })
        .unwrap();
    assert_eq!(checks[0], checks[1]);
    assert!(checks[0] > 0);
    let next = store.waiting_scoped_approvals(1).unwrap();
    assert_eq!(next.len(), 1);
    assert!(!batch.iter().any(|row| row.request_id == next[0].request_id));
}

#[test]
fn missing_prior_vendor_activity_is_unknown_not_a_first_observation() {
    let store = trigger_store(crate::governance::AUTHORITY_POLL);
    let sub = read_subscription(&store);
    assert_eq!(
        store
            .previous_event_observed_at("direct", "connection", &sub.subscription_id, "item")
            .unwrap(),
        None
    );
    store
        .insert_event(
            "direct",
            "connection",
            &sub.subscription_id,
            "item",
            &serde_json::json!({"id":"item"}),
            9_000,
        )
        .unwrap();
    assert!(store
        .previous_event_observed_at("direct", "connection", &sub.subscription_id, "item")
        .is_err());
}
