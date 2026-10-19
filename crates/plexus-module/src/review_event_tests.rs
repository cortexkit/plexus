fn review_frame(comment: bool) -> Value {
    let body: Value = serde_json::from_str(if comment {
        include_str!("../tests/fixtures/webhook-relay/review-comment-created.json")
    } else {
        include_str!("../tests/fixtures/webhook-relay/review-submitted.json")
    })
    .unwrap();
    json!({"type":"event", "seq":1, "delivery_id":"review-delivery",
        "event":if comment {"pull_request_review_comment"} else {"pull_request_review"},
        "action":body["action"], "installation_id":42, "received_at":TIME,
        "stub":null, "body":body})
}

#[tokio::test]
async fn review_notices_preserve_pr_projection_and_deduplicate_redeliveries() {
    use plexus_core::event_key::*;
    for (comment, kind, id_field, id) in [
        (false, GITHUB_PR_REVIEW_SUBMITTED, "review_id", 501),
        (true, GITHUB_PR_REVIEW_COMMENT_CREATED, "comment_id", 601),
    ] {
        let (_scratch, store, _) = fixture("review-dedup");
        let frame = review_frame(comment);
        replay(store.clone(), vec![hello(), frame.to_string()], true).await;
        let rows = store.drain_event_outbox(10).unwrap();
        assert_eq!(
            rows.len(),
            2,
            "one PR change and one review notice per delivery"
        );
        let legacy = rows
            .iter()
            .find(|row| row.event_name == GITHUB_PR_CHANGED)
            .unwrap();
        assert_eq!(
            legacy.body,
            serde_json::to_string(&frame["body"]["pull_request"]).unwrap()
        );
        let notice = rows.iter().find(|row| row.event_name == kind).unwrap();
        assert_eq!(
            notice.event_key,
            derive_event_key(kind, &json!({"repo_id":101,(id_field):id})).unwrap()
        );
        assert_ne!(notice.event_key, legacy.event_key);
        assert_eq!(notice.headers.repo.to_ascii_lowercase(), "org/repo");
        assert_eq!(notice.headers.pr.as_deref(), Some("7"));
        assert_eq!(notice.headers.project.as_deref(), Some("p1"));
        assert!(
            notice.envelope_v2.is_none(),
            "new review notices publish v1 only"
        );
        assert_eq!(store.drain_event_outbox_version(10, 2).unwrap().len(), 1);
        let body: Value = serde_json::from_str(&notice.body).unwrap();
        assert_eq!(body["repo"], "org/repo");
        assert_eq!(body["pr"], 7);
        assert_eq!(body["head_sha"], "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert_eq!(body["body_truncated"], false);
        if comment {
            assert_eq!(
                body,
                json!({
                    "event_key":notice.event_key,"kind":"pull_request_review_comment","repo":"org/repo","pr":7,
                    "head_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "author_login":"synthetic-human","author_is_bot":false,"path":"src/example.rs",
                    "line":17,"original_line":15,"side":"RIGHT","comment_id":601,"review_id":501,"in_reply_to_id":600,
                    "comment_url":"https://github.com/org/repo/pull/7#discussion_r601","created_at":"2030-10-08T09:00:00Z",
                    "body_excerpt":"Could this use the existing helper?","body_truncated":false
                })
            );
        } else {
            assert_eq!(
                body,
                json!({
                    "event_key":notice.event_key,"kind":"pull_request_review","repo":"org/repo","pr":7,
                    "head_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "reviewer_login":"synthetic-reviewer[bot]","reviewer_is_bot":true,"state":"changes_requested",
                    "review_id":501,"review_url":"https://github.com/org/repo/pull/7#pullrequestreview-501",
                    "submitted_at":"2030-10-08T09:00:00Z","body_excerpt":"Please handle the error before returning.","body_truncated":false
                })
            );
        }
        for row in &rows {
            store
                .mark_event_published(&row.event_key, now_ms())
                .unwrap();
        }
        let mut again = frame;
        again["seq"] = json!(2);
        let event = serde_json::from_value(again.clone()).unwrap();
        store
            .commit_relay_event("github", ORIGINAL_STREAM, &event)
            .unwrap();
        again["seq"] = json!(3);
        again["delivery_id"] = json!("another-delivery");
        store
            .commit_relay_event(
                "github",
                ORIGINAL_STREAM,
                &serde_json::from_value(again).unwrap(),
            )
            .unwrap();
        assert!(
            store.drain_event_outbox(10).unwrap().is_empty(),
            "redelivery emits neither event again"
        );
    }
}

#[tokio::test]
async fn review_notice_action_filters_preserve_other_pr_changes() {
    for comment in [false, true] {
        for action in [
            "edited",
            "deleted",
            "dismissed",
            "created",
            "submitted",
            "unknown",
        ] {
            if (comment && action == "created") || (!comment && action == "submitted") {
                continue;
            }
            let (_scratch, store, _) = fixture("review-action");
            let mut frame = review_frame(comment);
            frame["action"] = json!(action);
            frame["body"]["action"] = json!(action);
            replay(store.clone(), vec![hello(), frame.to_string()], true).await;
            let rows = store.drain_event_outbox(10).unwrap();
            assert_eq!(
                rows.len(),
                1,
                "nonmatching review actions must emit only the existing PR change"
            );
            assert_eq!(rows[0].event_name, "github_pr_changed");
        }
    }
}

#[tokio::test]
async fn review_notice_unicode_excerpt_and_nullable_fields() {
    for comment in [false, true] {
        for (text, expected, truncated) in [
            ("é🦀".repeat(751), "é🦀".repeat(750), true),
            ("界".repeat(1500), "界".repeat(1500), false),
            (String::new(), String::new(), false),
        ] {
            let (_scratch, store, _) = fixture("review-excerpt");
            let mut frame = review_frame(comment);
            frame["body"][if comment { "comment" } else { "review" }]["body"] = json!(text);
            replay(store.clone(), vec![hello(), frame.to_string()], true).await;
            let row = store
                .drain_event_outbox(10)
                .unwrap()
                .into_iter()
                .find(|row| row.event_name != "github_pr_changed")
                .unwrap();
            let body: Value = serde_json::from_str(&row.body).unwrap();
            assert_eq!(
                body["body_excerpt"], expected,
                "review excerpts count Unicode characters, not bytes"
            );
            assert_eq!(body["body_truncated"], truncated);
        }
        let (_scratch, store, _) = fixture("review-null");
        let mut frame = review_frame(comment);
        frame["body"][if comment { "comment" } else { "review" }] = json!({"id":1});
        frame["body"]["pull_request"]
            .as_object_mut()
            .unwrap()
            .remove("head");
        replay(store.clone(), vec![hello(), frame.to_string()], true).await;
        let row = store
            .drain_event_outbox(10)
            .unwrap()
            .into_iter()
            .find(|row| row.event_name != "github_pr_changed")
            .unwrap();
        let body: Value = serde_json::from_str(&row.body).unwrap();
        assert_eq!(
            body.as_object().unwrap().len(),
            if comment { 18 } else { 13 }
        );
        for (key, value) in body.as_object().unwrap() {
            if ![
                "event_key",
                "kind",
                "repo",
                "pr",
                if comment { "comment_id" } else { "review_id" },
            ]
            .contains(&key.as_str())
            {
                assert!(value.is_null(), "unknown {key} must be present and null");
            }
        }
    }
}

#[tokio::test]
async fn review_notice_bot_flag_comes_only_from_user_type() {
    for comment in [false, true] {
        for (login, user_type, expected) in
            [("plain-login", "Bot", true), ("fake[bot]", "User", false)]
        {
            let (_scratch, store, _) = fixture("review-bot");
            let mut frame = review_frame(comment);
            frame["body"][if comment { "comment" } else { "review" }]["user"] =
                json!({"login":login,"type":user_type});
            replay(store.clone(), vec![hello(), frame.to_string()], true).await;
            let row = store
                .drain_event_outbox(10)
                .unwrap()
                .into_iter()
                .find(|row| row.event_name != "github_pr_changed")
                .unwrap();
            let body: Value = serde_json::from_str(&row.body).unwrap();
            assert_eq!(
                body[if comment {
                    "author_is_bot"
                } else {
                    "reviewer_is_bot"
                }],
                expected,
                "bot classification must use user.type"
            );
            assert_eq!(
                body[if comment {
                    "author_login"
                } else {
                    "reviewer_login"
                }],
                login
            );
        }
    }
}
