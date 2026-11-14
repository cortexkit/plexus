use super::*;
use crate::consent_card::consent_request_body;
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use subc_protocol::scope::{FederatedAttributes, FederatedPeerClass};

const ARGS_DIGEST: &str = "sha256:f6ce4b3ca496e0b2287979fe7f16117c27b41d73989d69c8472565d4988bc4ed";

fn caller(claim: Option<Value>) -> FederatedCaller {
    let mut attributes = FederatedAttributes::new(
        FederatedPeerClass::Computer,
        "a".repeat(32),
        "pairing".into(),
        "Peer name never in prompt".into(),
    );
    attributes.remote_claim = claim.map(|value| serde_json::from_value(value).unwrap());
    FederatedCaller::from_attributes(attributes).unwrap()
}

fn claims() -> Vec<(Option<Value>, bool)> {
    vec![
        (None, true),
        (
            Some(json!({"kind":"agent","agent_id":"agent","agent_name":"Name"})),
            true,
        ),
        (
            Some(
                json!({"kind":"worker","owner_module_id":"core","worker_ref":"b".repeat(64),
            "on_behalf_of":"agent","agent_name":"Name"}),
            ),
            false,
        ),
        (
            Some(json!({"kind":"flow","flow_id":"flow","flow_version":1,
            "flow_install_id":"install","flow_code_hash":"c".repeat(64),"flow_name":"Name"})),
            true,
        ),
        (
            Some(json!({"kind":"run","agent_id":"agent","agent_name":"Name"})),
            false,
        ),
    ]
}

fn filed_scope() -> CallScope {
    CallScope {
        owner: "reserved:callosum".into(),
        scope_ref: "fed-claim:reference".into(),
        scope_epoch: 3,
        kind: Some("unknown".into()),
        parent: None,
        parent_state: None,
        agent_id: None,
        flow_id: None,
        delegates: false,
        owner_authorized: false,
    }
}

fn context<'a>(caller: &'a FederatedCaller, scope: &'a CallScope) -> Context<'a> {
    Context {
        caller,
        filed_scope: scope,
        expires_in_ms: 42_000,
        per_call_only: false,
    }
}

fn store() -> PlexusStore {
    PlexusStore::open(&StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: "federated-card-body".into(),
        isolation: Isolation::Module,
        backend: StorageBackend::Sqlite {
            path: crate::test_scratch::store_path(),
        },
    })
    .unwrap()
}

fn connection() -> ConnectionRecord {
    ConnectionRecord {
        connection_id: "connection".into(),
        principal: "direct".into(),
        app_key: "mock".into(),
        status: "active".into(),
        resource_filters: json!({}),
        health_state: json!({}),
        generation: 1,
        has_credential_binding: false,
        instance_url: None,
    }
}

fn action(risk: &str) -> CatalogAction {
    CatalogAction {
        connection_id: "connection".into(),
        principal: "direct".into(),
        name: "list_items".into(),
        title: Some(" List items ".into()),
        schema: json!({"type":"object"}),
        schema_hash: "schema-v1".into(),
        risk: risk.into(),
        severity: "S1".into(),
        ask_first: risk != "read",
        status: "active".into(),
        quarantine_reason: None,
        reconciliation: None,
        generation: 1,
    }
}

fn options(standing: bool) -> Value {
    if standing {
        json!([
            {"id":"allow_once","label":"Allow this time","effect":"grant"},
            {"id":"allow_always","label":"Always allow","effect":"grant"},
            {"id":"deny_once","label":"Don't allow","effect":"decline"},
            {"id":"deny_always","label":"Don't allow, and don't ask again","effect":"decline"}
        ])
    } else {
        json!([
            {"id":"allow_once","label":"Allow this time","effect":"grant"},
            {"id":"deny_once","label":"Don't allow","effect":"decline"}
        ])
    }
}

#[test]
fn invoke_bodies_pin_every_requester_member_for_each_claim_and_scope() {
    let store = store();
    let route = filed_scope();
    for (claim, standing) in claims() {
        let caller = caller(claim);
        for (risk, phrase) in [
            ("read", "read from mock (list_items)"),
            ("write", "make changes in mock (list_items)"),
        ] {
            for per_call_only in [false, true] {
                let context = Context {
                    per_call_only,
                    ..context(&caller, &route)
                };
                let card = PreparedCard::invoke(
                    &store,
                    &context,
                    &connection(),
                    &action(risk),
                    &json!({"query":"rust","limit":2}),
                    false,
                )
                .unwrap();
                assert_eq!(
                    card.body,
                    json!({
                        "kind":"consent","title":"List items on mock","prompt":phrase,
                        "options":options(standing && !per_call_only),"default":"deny_once",
                        "urgency":"normal","on_expiry":"deny","material_damage":risk != "read",
                        "late_execution":"notify_only","target":{"kind":"service","label":"mock"},
                        "expires_in_ms":42_000,"requester_ref":card.record.id,
                        "dedup_key":card.record.binding.dedup_key(card.record.scope).unwrap(),
                        "args_digest":ARGS_DIGEST,"preview":{"label":"Will send","text":"limit: 2\nquery: rust"},
                        "facts":[{"label":"Action","value":"List items"},{"label":"Risk","value":risk}]
                    })
                );
                assert_eq!(card.record.binding.action, "list_items");
                assert_eq!(card.record.binding.subject, "connection");
                assert_eq!(card.record.binding.owner_principal, "direct");
                assert_eq!(card.record.schema_hash.as_deref(), Some("schema-v1"));
                assert_eq!(card.record.state, State::Pending);
                assert_eq!(card.record.card_ref, None);
                assert_eq!(
                    card.record.filed_scope,
                    serde_json::to_value(&route).unwrap()
                );
                assert_eq!(card.record.scope.as_str(), risk);
                assert_eq!(
                    card.record.selector,
                    if caller.claim.claim_kind.is_empty() {
                        "claimless"
                    } else {
                        "exact_claim"
                    }
                );
                assert!(card.body.get("subject_label").is_none());
                assert!(card.body.get("scope_label").is_none());
            }
        }
    }
}

#[test]
fn search_bodies_pin_tool_inputs_and_the_same_requester_members_for_every_claim() {
    let route = filed_scope();
    for (claim, standing) in claims() {
        let caller = caller(claim);
        for (search, tool, label, phrase) in [
            (Search::Web, "web_search", "Web search", "search the web"),
            (
                Search::Code,
                "code_search",
                "Code search",
                "search public code on GitHub",
            ),
        ] {
            for per_call_only in [false, true] {
                let context = Context {
                    per_call_only,
                    ..context(&caller, &route)
                };
                let card =
                    PreparedCard::search(&context, search, &json!({"query":"rust","limit":2}))
                        .unwrap();
                assert_eq!(
                    card.body,
                    json!({
                        "kind":"consent","title":format!("{tool} on {label}"),"prompt":phrase,
                        "options":options(standing && !per_call_only),"default":"deny_once",
                        "urgency":"normal","on_expiry":"deny","material_damage":false,
                        "late_execution":"notify_only","target":{"kind":"service","label":label},
                        "expires_in_ms":42_000,"requester_ref":card.record.id,
                        "dedup_key":card.record.binding.dedup_key(Scope::Read).unwrap(),
                        "args_digest":ARGS_DIGEST,"preview":{"label":"Will send","text":"limit: 2\nquery: rust"},
                        "facts":[{"label":"Action","value":tool},{"label":"Risk","value":"read"}]
                    })
                );
                assert_eq!(card.record.scope, Scope::Read);
                assert_eq!(card.record.schema_hash, None);
                assert_eq!(card.record.binding.owner_principal, "");
                assert_eq!(card.record.binding.subject, tool);
                assert_eq!(card.record.binding.action, tool);
            }
        }
    }
}

#[test]
fn dedup_key_and_args_digest_match_independent_ascii_jcs_hashes() {
    let caller = caller(Some(json!({"kind":"agent","agent_id":"agent"})));
    let route = filed_scope();
    let card = PreparedCard::invoke(
        &store(),
        &context(&caller, &route),
        &connection(),
        &action("read"),
        &json!({"query":"rust","limit":2}),
        false,
    )
    .unwrap();
    // These digests were SHA-256 hashed independently from literal canonical
    // ASCII JSON, not computed with the production JSON canonicalizer.
    assert_eq!(card.record.binding.args_digest, ARGS_DIGEST);
    assert_eq!(
        card.body["dedup_key"],
        "sha256:f66028c11d527c47d1809a1f0c647fdcf61cfb5b45f776e0fc6e9ba780edab27"
    );
    let canonical =
        jcs::canonicalize(&json!({"binding":card.record.binding,"scope":"read"})).unwrap();
    assert_eq!(
        String::from_utf8(canonical).unwrap(),
        r#"{"binding":{"action":"list_items","args_digest":"sha256:f6ce4b3ca496e0b2287979fe7f16117c27b41d73989d69c8472565d4988bc4ed","caller":{"canonical_claim_identity":"{\"agent_id\":\"agent\"}","claim_kind":"agent","pairing_id":"pairing","peer_class":"computer","peer_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"owner_principal":"direct","subject":"connection"},"scope":"read"}"#
    );
}

#[test]
fn every_binding_member_and_scope_changes_dedup_but_display_and_route_do_not() {
    let caller = caller(Some(json!({"kind":"agent","agent_id":"agent"})));
    let route = filed_scope();
    let original = PreparedCard::search(
        &context(&caller, &route),
        Search::Web,
        &json!({"query":"rust"}),
    )
    .unwrap();
    let binding = &original.record.binding;
    let key = binding.dedup_key(Scope::Read).unwrap();
    let mut keys = std::collections::BTreeSet::from([key.clone()]);
    for index in 0..9 {
        let mut other = binding.clone();
        let field = match index {
            0 => &mut other.caller.peer_fingerprint,
            1 => &mut other.caller.pairing_id,
            2 => &mut other.caller.peer_class,
            3 => &mut other.caller.claim_kind,
            4 => &mut other.caller.canonical_claim_identity,
            5 => &mut other.owner_principal,
            6 => &mut other.subject,
            7 => &mut other.action,
            _ => &mut other.args_digest,
        };
        field.push_str(":|\",");
        assert!(
            keys.insert(other.dedup_key(Scope::Read).unwrap()),
            "member {index}"
        );
    }
    assert!(keys.insert(binding.dedup_key(Scope::Write).unwrap()));
    let mut named = caller.clone();
    named.attributes.peer_name = "Other peer display".into();
    named.attributes.remote_claim = Some(
        serde_json::from_value(json!({
            "kind":"agent","agent_id":"agent","agent_name":"Other name"
        }))
        .unwrap(),
    );
    let named = FederatedCaller::from_attributes(named.attributes).unwrap();
    let mut later_route = route.clone();
    later_route.scope_ref = "later-route".into();
    later_route.scope_epoch += 1;
    let replay = PreparedCard::search(
        &context(&named, &later_route),
        Search::Web,
        &json!({"query":"rust"}),
    )
    .unwrap();
    assert_eq!(original.body["dedup_key"], replay.body["dedup_key"]);
    assert_eq!(original.record.binding, replay.record.binding);
    assert_ne!(original.record.id, replay.record.id);
    assert_ne!(original.record.filed_scope, replay.record.filed_scope);
    let changed_args = PreparedCard::search(
        &context(&caller, &route),
        Search::Web,
        &json!({"query":"go"}),
    )
    .unwrap();
    assert_ne!(changed_args.body["dedup_key"], original.body["dedup_key"]);
}

#[test]
fn delimiter_bearing_callers_and_agent_run_kinds_do_not_alias() {
    let route = filed_scope();
    let mut keys = std::collections::BTreeSet::new();
    for kind in ["agent", "run"] {
        for id in ["a:b", "a|b", "a\"b", "a,b", "a:b|c", "a|b:c"] {
            let caller = caller(Some(json!({"kind":kind,"agent_id":id})));
            let card =
                PreparedCard::search(&context(&caller, &route), Search::Web, &json!({})).unwrap();
            assert!(keys.insert(card.body["dedup_key"].as_str().unwrap().to_owned()));
        }
    }
    // A delimiter join would make these two peer/pairing pairs collide.
    for (peer, pairing) in [("a:b", "c"), ("a", "b:c")] {
        let mut caller = caller(None);
        caller.attributes.peer_fingerprint = peer.into();
        caller.attributes.pairing_id = pairing.into();
        let card =
            PreparedCard::search(&context(&caller, &route), Search::Web, &json!({})).unwrap();
        assert!(keys.insert(card.body["dedup_key"].as_str().unwrap().to_owned()));
    }
    assert_eq!(keys.len(), 14);
}

#[test]
fn expiry_preview_and_other_requester_members_reuse_the_local_body() {
    let store = store();
    let caller = caller(None);
    let route = filed_scope();
    let args = json!({"text":"x".repeat(1000),"password":"never shown"});
    for expiry in [-1, 1, 42_000, i64::MAX] {
        for complete_preview in [false, true] {
            let context = Context {
                expires_in_ms: expiry,
                ..context(&caller, &route)
            };
            let card = PreparedCard::invoke(
                &store,
                &context,
                &connection(),
                &action("write"),
                &args,
                complete_preview,
            )
            .unwrap();
            let mut local = consent_request_body(&ParkedApproval {
                request_id: &card.record.id,
                dedup_key: card.body["dedup_key"].as_str().unwrap(),
                action_label: "List items",
                service_label: "mock",
                risk: "write",
                args: &args,
                complete_preview,
                args_digest: &card.record.binding.args_digest,
                expires_in_ms: expiry,
            });
            let mut federated = card.body.clone();
            for key in ["prompt", "options", "default"] {
                local.as_object_mut().unwrap().remove(key);
                federated.as_object_mut().unwrap().remove(key);
            }
            assert_eq!(local, federated);
            assert_eq!(card.body["expires_in_ms"], expiry.clamp(1, 86_400_000));
            assert!(!card.body.to_string().contains("never shown"));
            assert!(!crate::secret_input::contains_secret_input(&card.body));
            if complete_preview {
                assert!(card.body["preview"]["text"]
                    .as_str()
                    .unwrap()
                    .contains(&"x".repeat(1000)));
            }
        }
    }
}

#[test]
fn invalid_risk_peer_class_and_jcs_failure_cannot_construct_a_card() {
    let store = store();
    let caller = caller(None);
    let route = filed_scope();
    for risk in ["destructive", "unknown", ""] {
        assert_eq!(
            PreparedCard::invoke(
                &store,
                &context(&caller, &route),
                &connection(),
                &action(risk),
                &json!({}),
                false
            )
            .unwrap_err(),
            BuildError::UnsupportedRisk
        );
    }
    let mut phone = caller.clone();
    phone.attributes.peer_class = FederatedPeerClass::Phone;
    assert_eq!(
        PreparedCard::search(&context(&phone, &route), Search::Web, &json!({})).unwrap_err(),
        BuildError::UnsupportedPeerClass
    );
    let failed = jcs::with_sha256_failure_on_call(1, || {
        PreparedCard::search(&context(&caller, &route), Search::Code, &json!({}))
    });
    assert_eq!(
        failed.unwrap_err(),
        BuildError::Jcs(JcsError::NonFiniteNumber)
    );
}

#[test]
fn local_request_body_keeps_legacy_members_and_sentence() {
    let body = consent_request_body(&ParkedApproval {
        request_id: "request",
        dedup_key: "requester:call",
        action_label: "List items",
        service_label: "Mock app",
        risk: "read",
        args: &json!({"limit":2,"query":"rust"}),
        complete_preview: false,
        args_digest: ARGS_DIGEST,
        expires_in_ms: 42_000,
    });
    assert_eq!(
        body,
        json!({
            "kind":"consent","title":"List items on Mock app",
            "prompt":"Allow List items to run once on Mock app with the arguments shown? It reads data from Mock app and changes nothing.",
            "options":[{"id":"approve","label":"Approve","effect":"grant"},
                {"id":"deny","label":"Deny","effect":"decline"}],
            "default":"deny","urgency":"normal","on_expiry":"deny","material_damage":false,
            "late_execution":"notify_only","target":{"kind":"service","label":"Mock app"},
            "expires_in_ms":42_000,"requester_ref":"request","dedup_key":"requester:call",
            "args_digest":ARGS_DIGEST,"preview":{"label":"Will send","text":"limit: 2\nquery: rust"},
            "facts":[{"label":"Action","value":"List items"},{"label":"Risk","value":"read"}]
        })
    );
}

#[test]
fn missing_or_blank_action_title_falls_back_to_the_action_name() {
    let store = store();
    let caller = caller(None);
    let route = filed_scope();
    for title in [None, Some(""), Some(" \t")] {
        let mut action = action("read");
        action.title = title.map(str::to_owned);
        let card = PreparedCard::invoke(
            &store,
            &context(&caller, &route),
            &connection(),
            &action,
            &json!({}),
            false,
        )
        .unwrap();
        assert_eq!(card.body["title"], "list_items on mock");
        assert_eq!(card.body["facts"][0]["value"], "list_items");
        assert_eq!(card.body["prompt"], "read from mock (list_items)");
    }
}

#[test]
fn app_display_name_uses_the_local_manifest_name_and_blank_name_fallback() {
    let store = store();
    let caller = caller(None);
    let route = filed_scope();
    for (name, expected) in [
        (" Mock service \t", "Mock service"),
        ("", "mock"),
        ("  ", "mock"),
    ] {
        let manifest = crate::ingest_value(json!({
            "schema_version":1,"key":"mock","name":name,"description":"card fixture",
            "reuse_path":"mcp_direct","reuse_rationale":"in-process test","tier":"S1",
            "transport":{"kind":"mcp_remote","url":"https://example.invalid/mcp"},
            "auth":{"mode":"api_key"},
            "credential_bindings":[{"ref_role":"api_key","placement":"header","key":"Authorization","prefix":"Bearer ","required":true}],
            "resource_filters":{"required":[],"optional":[],"write_enabling":[]},
            "actions_baseline":[{"name":"list_items","risk":"read"}],
            "defaults":{"ask_first_risk":["write","destructive"],"rate_limit":{"calls_per_min":30}},
            "availability":"ga"
        })).unwrap();
        store
            .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &manifest)
            .unwrap();
        let card = PreparedCard::invoke(
            &store,
            &context(&caller, &route),
            &connection(),
            &action("read"),
            &json!({}),
            false,
        )
        .unwrap();
        assert_eq!(
            card.body["prompt"],
            format!("read from {expected} (list_items)")
        );
        assert_eq!(card.body["title"], format!("List items on {expected}"));
        assert_eq!(card.body["target"]["label"], expected);
        assert_eq!(service_label(&store, "mock"), expected);
    }
}
