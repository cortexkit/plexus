use super::*;
use crate::credentials::StubCredentialSource;
use crate::governance::GovernanceEngine;
use crate::scope::{ScopeDescription, ScopeReadError, ScopeReader, ScopeStatus};
use crate::storage::{CatalogActionInput, PlexusStore, CATALOG_PRINCIPAL};
use crate::test_scratch::Scratch;
use crate::transport::{MockResponse, MockTransport};
use crate::web_search::{CacheKey, ExaRestBackend, WebSearchQuery, WebSearchService};
use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use subc_protocol::scope::{FederatedAttributes, FederatedPeerClass};

const NOW: i64 = 1_790_000_000_000;

#[path = "card_tests.rs"]
mod cards;
type Engine = GovernanceEngine<StubCredentialSource, MockTransport>;

#[derive(Clone, Copy, Debug)]
enum Tool {
    Web,
    OrderedWeb,
    Code,
}

impl Tool {
    fn subject(self) -> &'static str {
        if matches!(self, Self::Code) {
            "code_search"
        } else {
            "web_search"
        }
    }
    fn backend(self) -> &'static str {
        if matches!(self, Self::Code) {
            "grep_app"
        } else {
            "exa"
        }
    }
    fn action(self) -> &'static str {
        if matches!(self, Self::Code) {
            "searchGitHub"
        } else {
            "search"
        }
    }
}

struct Reader {
    answer: Result<ScopeDescription, ScopeReadError>,
    calls: Mutex<usize>,
}
impl ScopeReader for Reader {
    fn describe(&self, owner: &str, reference: &str) -> Result<ScopeDescription, ScopeReadError> {
        assert_eq!(owner, "reserved:callosum");
        assert!(reference.starts_with("fed-base:"));
        *self.calls.lock().unwrap() += 1;
        self.answer.clone()
    }
}
fn description(status: ScopeStatus, synced: bool, configured: bool) -> ScopeDescription {
    ScopeDescription {
        status,
        owner_synced: synced,
        owner_configured: configured,
        live: None,
        parent: None,
        expires_at_ms: None,
    }
}
fn caller() -> FederatedCaller {
    FederatedCaller::from_attributes(FederatedAttributes::new(
        FederatedPeerClass::Computer,
        "a".repeat(32),
        "pairing".into(),
        "Peer".into(),
    ))
    .unwrap()
}

struct Fixture {
    engine: Engine,
    db: rusqlite::Connection,
    web: WebSearchService,
    code: crate::code_search::CodeSearchService,
    tool: Tool,
    reader: Arc<Reader>,
    _path: Scratch,
}
impl Fixture {
    fn new(tool: Tool) -> Self {
        let path = Scratch::database("federated-search");
        let store = Arc::new(
            PlexusStore::open(&StorageDescriptor {
                module_id: "plexus".into(),
                storage_namespace: "federated-search".into(),
                isolation: Isolation::Module,
                backend: StorageBackend::Sqlite {
                    path: path.to_string_lossy().into_owned(),
                },
            })
            .unwrap(),
        );
        let source = if matches!(tool, Tool::Code) {
            include_str!("../../../../../catalog/grep_app.jsonc")
        } else {
            include_str!("../../../../../catalog/exa_rest.jsonc")
        };
        let mut manifest: Value =
            serde_json::from_str(&subc_jsonc::jsonc_to_json(source).unwrap()).unwrap();
        manifest["auth"] = json!({"mode":"none"});
        manifest["credential_bindings"] = json!([]);
        store
            .upsert_manifest(CATALOG_PRINCIPAL, &crate::ingest_value(manifest).unwrap())
            .unwrap();
        store
            .insert_connection(
                "direct",
                "backing",
                if matches!(tool, Tool::Code) {
                    "grep_app"
                } else {
                    "exa_rest"
                },
                "active",
                &json!({"required":[],"optional":[],"write_enabling":[]}),
            )
            .unwrap();
        store
            .upsert_catalog_action(&CatalogActionInput {
                principal: "direct".into(),
                connection_id: "backing".into(),
                name: tool.action().into(),
                title: None,
                schema: json!({"type":"object"}),
                schema_hash: "schema".into(),
                risk: "read".into(),
                severity: "S1".into(),
                ask_first: false,
                status: "active".into(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .unwrap();
        if matches!(tool, Tool::OrderedWeb) {
            store.set_web_search_order(&["exa".into()]).unwrap();
        }
        let db = rusqlite::Connection::open(&*path).unwrap();
        db.execute(
            "UPDATE connections SET ceiling_risk='write', ceiling_selectors=?1",
            [json!([tool.action()]).to_string()],
        )
        .unwrap();
        let transport = Arc::new(MockTransport::default());
        transport.set_response(MockResponse::Success(if matches!(tool, Tool::Code) {
            json!({"content":[]})
        } else {
            json!({"results":[]})
        }));
        let reader = Arc::new(Reader {
            answer: Ok(description(ScopeStatus::Live, true, true)),
            calls: Mutex::new(0),
        });
        Self {
            engine: GovernanceEngine::new(
                store,
                Arc::new(StubCredentialSource::default()),
                transport,
            )
            .with_scope_reader(reader.clone()),
            db,
            web: WebSearchService::with_clock(Arc::new(ExaRestBackend), Arc::new(|| NOW)),
            code: crate::code_search::CodeSearchService::with_clock(Arc::new(|| NOW)),
            tool,
            reader,
            _path: path,
        }
    }
    fn seed(&self, owner: &str, subject: &str, scope: &str, effect: &str) -> String {
        let id = crate::federated::new_row_id();
        self.db.execute("INSERT INTO federated_rows (id,peer_fingerprint,pairing_id,peer_class,selector,claim_kind,canonical_claim_identity,owner_principal,subject,scope,peer_name,effect,granted_at_ms,card_ref,card_refs_json) VALUES (?1,?2,'pairing','computer','claimless','','',?3,?4,?5,'Peer',?6,1,'el_mint','[\"el_mint\"]')", rusqlite::params![id,"a".repeat(32),owner,subject,scope,effect]).unwrap();
        id
    }
    fn allow(&self) -> String {
        self.seed("", self.tool.subject(), "read", "allow")
    }
    fn search(&self, caller: &FederatedCaller) -> Result<bool, Value> {
        let args = json!({"query":"rust async book"});
        match self.tool {
            Tool::Code => self
                .code
                .search_federated(&self.engine, caller, args.as_object().unwrap(), None, None)
                .map(|_| false)
                .map_err(|e| e.to_wire()),
            _ => self
                .web
                .search_federated(&self.engine, caller, args.as_object().unwrap(), None, None)
                .map(|r| r.cached)
                .map_err(|e| e.to_wire()),
        }
    }
    fn cache(&self) {
        let query =
            WebSearchQuery::parse(json!({"query":"rust async book"}).as_object().unwrap()).unwrap();
        if matches!(self.tool, Tool::OrderedWeb) {
            self.web.cache.put_served(
                CacheKey::new(crate::web_search::cache::CHAIN_CACHE_BACKEND, &query),
                vec![],
                crate::web_search::cache::ServedBy {
                    provider: "exa".into(),
                    instance_digest: None,
                },
                NOW,
            );
        } else {
            self.web
                .cache
                .put(CacheKey::new("exa", &query), vec![], NOW);
        }
    }
    fn limits(&self, caller: u32, backend: u32) {
        self.engine
            .store()
            .set_web_search_limits(
                self.tool.backend(),
                crate::storage::web_search_store::WebSearchLimits {
                    per_caller_per_minute: caller,
                    per_backend_per_minute: backend,
                },
            )
            .unwrap();
    }
    fn assert_no_cards(&self) {
        for table in ["action_requests", "federated_card_records"] {
            assert_eq!(
                self.db
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
}

#[test]
fn standing_search_rows_serve_without_local_grants_or_cards() {
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        let f = Fixture::new(tool);
        f.allow();
        assert_eq!(f.search(&caller()), Ok(false), "{tool:?}");
        assert_eq!(f.engine.transport().requests().len(), 1);
        assert_eq!(
            *f.reader.calls.lock().unwrap(),
            2,
            "cache admission and dispatch authorize describe independently"
        );
        assert_eq!(f.db.query_row("SELECT principal,connection_id,grant_id IS NULL AND agent_grant_id IS NULL FROM reservations", [], |r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,bool>(2)?))).unwrap(),("direct".into(),"backing".into(),true));
        f.assert_no_cards();
    }
}

#[test]
fn missing_denied_wrong_owner_subject_and_scope_never_serve_cache() {
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        let f = Fixture::new(tool);
        f.cache();
        f.limits(1, 1);
        for (owner, subject, scope) in [
            ("direct", "backing", "read"),
            ("direct", tool.subject(), "read"),
            ("", tool.subject(), "write"),
            (
                "",
                if matches!(tool, Tool::Code) {
                    "web_search"
                } else {
                    "code_search"
                },
                "read",
            ),
        ] {
            let id = f.seed(owner, subject, scope, "allow");
            let wire = f.search(&caller()).unwrap_err();
            assert_eq!(
                wire["error"]["code"], "consent_unavailable",
                "{tool:?} {wire}"
            );
            assert_eq!(wire["error"]["action"], tool.subject());
            assert_eq!(wire["error"]["transmission"], "not_sent");
            f.engine.store().delete_federated_row(&id).unwrap();
        }
        let id = f.seed("", tool.subject(), "read", "deny");
        assert_eq!(
            f.search(&caller()).unwrap_err()["error"]["code"],
            "consent_denied"
        );
        f.engine.store().delete_federated_row(&id).unwrap();
        f.allow();
        assert!(
            f.search(&caller()).is_ok(),
            "refused calls spent no rate tokens"
        );
        f.assert_no_cards();
    }
}

#[test]
fn every_non_grant_gate_precedes_row_rate_and_cache() {
    let cases = [
        ("UPDATE connections SET status='auth_required'", "UPDATE connections SET status='active'", "connection_disabled"),
        ("UPDATE catalog_actions SET status='quarantined'", "UPDATE catalog_actions SET status='active'", "catalog_action_quarantined"),
        ("UPDATE catalog_actions SET risk='destructive'", "UPDATE catalog_actions SET risk='read'", "needs_decision_plane"),
        ("UPDATE connections SET ceiling_risk='invalid'", "UPDATE connections SET ceiling_risk='write'", "grant_risk_ceiling"),
        ("UPDATE catalog_actions SET risk='write'; UPDATE connections SET ceiling_risk='read', resource_filters='{\"write_enabling\":[\"query\"]}'", "UPDATE catalog_actions SET risk='read'; UPDATE connections SET ceiling_risk='write', resource_filters='{}'", "grant_risk_ceiling"),
        ("UPDATE connections SET resource_filters='{\"required\":[\"missing\"]}'", "UPDATE connections SET resource_filters='{}'", "resource_filter_missing"),
        ("UPDATE connections SET ceiling_risk=NULL,ceiling_selectors=NULL", "UPDATE connections SET ceiling_risk='write'", "grant_risk_ceiling"),
        ("UPDATE connections SET ceiling_selectors='[]'", "UPDATE connections SET ceiling_risk='write'", "grant_action_selector"),
        ("UPDATE catalog_actions SET schema_json='{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}'", "UPDATE catalog_actions SET schema_json='{\"type\":\"object\"}'", "argument_undeclared"),
    ];
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        for effect in [None, Some("allow"), Some("deny")] {
            for (mutation, reset, code) in cases {
                let f = Fixture::new(tool);
                if let Some(effect) = effect {
                    f.seed("", tool.subject(), "read", effect);
                }
                f.cache();
                f.limits(1, 1);
                f.db.execute_batch(mutation).unwrap();
                for _ in 0..2 {
                    let wire = f.search(&caller()).unwrap_err();
                    assert_eq!(wire["error"]["code"], code, "{tool:?} {mutation} {wire}");
                    assert_eq!(wire["error"]["transmission"], "not_sent");
                }
                assert_eq!(*f.reader.calls.lock().unwrap(), 0);
                assert!(f.engine.transport().requests().is_empty());
                f.assert_no_cards();
                f.db.execute_batch(reset).unwrap();
                f.db.execute(
                    "UPDATE connections SET ceiling_selectors=?1",
                    [json!([tool.action()]).to_string()],
                )
                .unwrap();
                f.db.execute("DELETE FROM federated_rows", []).unwrap();
                f.allow();
                assert!(
                    f.search(&caller()).is_ok(),
                    "gate refusal spent rate tokens: {tool:?} {mutation}"
                );
            }
        }
    }
}

#[test]
fn search_policy_block_and_ask_first_refuse_without_cards_or_rate_charge() {
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        for effect in [None, Some("allow"), Some("deny")] {
            for policy in ["block", "ask_first"] {
                let f = Fixture::new(tool);
                f.cache();
                f.limits(1, 1);
                if let Some(effect) = effect {
                    f.seed("", tool.subject(), "read", effect);
                }
                f.engine
                    .store()
                    .set_policy("direct", "backing", tool.action(), policy, None)
                    .unwrap();
                let wire = f.search(&caller()).unwrap_err();
                assert_eq!(
                    wire["error"]["code"],
                    if policy == "block" {
                        "policy_blocked"
                    } else {
                        "policy_ask_first"
                    }
                );
                assert_eq!(wire["error"]["terminal"], true);
                assert_eq!(*f.reader.calls.lock().unwrap(), 0);
                f.assert_no_cards();
                f.engine
                    .store()
                    .set_policy("direct", "backing", tool.action(), "allow", None)
                    .unwrap();
                f.db.execute("DELETE FROM federated_rows", []).unwrap();
                f.allow();
                assert!(f.search(&caller()).is_ok());
            }
        }
    }
}

#[test]
fn connector_home_refusal_cannot_serve_cache_or_spend_rate_tokens() {
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        let mut f = Fixture::new(tool);
        f.allow();
        f.cache();
        f.limits(1, 1);
        let live = f.engine.clone();
        f.engine = f
            .engine
            .with_connector_home_guard(Arc::new(|| Some(json!({"state":"unavailable"}))));
        assert_eq!(
            f.search(&caller()).unwrap_err()["error"]["code"],
            "connector_home_not_held"
        );
        assert_eq!(*f.reader.calls.lock().unwrap(), 0);
        f.engine = live;
        assert!(f.search(&caller()).is_ok());
    }
}

#[test]
fn search_liveness_follows_the_contract_for_both_effects() {
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        for effect in ["allow", "deny"] {
            for (status, synced, configured, code, retryable) in [
                (
                    ScopeStatus::Ended,
                    true,
                    true,
                    "federated_pairing_ended",
                    false,
                ),
                (
                    ScopeStatus::NotLive,
                    true,
                    true,
                    "federated_pairing_ended",
                    false,
                ),
                (
                    ScopeStatus::NotLive,
                    false,
                    true,
                    "federated_liveness_unavailable",
                    true,
                ),
                (
                    ScopeStatus::NotLive,
                    true,
                    false,
                    "federated_liveness_unavailable",
                    true,
                ),
                (
                    ScopeStatus::NotLive,
                    false,
                    false,
                    "federated_liveness_unavailable",
                    true,
                ),
            ] {
                let mut f = Fixture::new(tool);
                f.seed("", tool.subject(), "read", effect);
                f.cache();
                f.engine = f.engine.with_scope_reader(Arc::new(Reader {
                    answer: Ok(description(status, synced, configured)),
                    calls: Mutex::new(0),
                }));
                let wire = f.search(&caller()).unwrap_err();
                assert_eq!(wire["error"]["code"], code);
                assert_eq!(wire["error"]["retryable"], retryable);
                assert_eq!(wire["error"]["transmission"], "not_sent");
                assert_eq!(
                    f.db.query_row("SELECT count(*) FROM federated_rows", [], |r| r
                        .get::<_, i64>(0))
                        .unwrap(),
                    1
                );
                assert!(f.engine.transport().requests().is_empty());
                f.assert_no_cards();
            }
        }
    }
}

#[test]
fn caller_identity_buckets_are_separate_and_charged_atomically_with_backend() {
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        let f = Fixture::new(tool);
        f.allow();
        f.cache();
        f.limits(1, 2);
        assert!(f.search(&caller()).is_ok());
        let mut same = caller();
        same.attributes.peer_name = "Renamed".into();
        assert_eq!(
            f.search(&same).unwrap_err()["error"]["code"],
            "rate_limited"
        );
        let mut other = caller();
        other.attributes.peer_fingerprint = "b".repeat(32);
        f.db.execute("INSERT INTO federated_rows SELECT 'plxf_other',?1,pairing_id,peer_class,selector,claim_kind,canonical_claim_identity,owner_principal,subject,scope,claim_json,peer_name,effect,granted_at_ms,card_ref,card_refs_json FROM federated_rows LIMIT 1",["b".repeat(32)]).unwrap();
        assert!(
            f.search(&other).is_ok(),
            "failed caller acquisition must not charge backend"
        );
        let mut third = caller();
        third.attributes.peer_fingerprint = "c".repeat(32);
        f.db.execute("INSERT INTO federated_rows SELECT 'plxf_third',?1,pairing_id,peer_class,selector,claim_kind,canonical_claim_identity,owner_principal,subject,scope,claim_json,peer_name,effect,granted_at_ms,card_ref,card_refs_json FROM federated_rows LIMIT 1",["c".repeat(32)]).unwrap();
        assert_eq!(
            f.search(&third).unwrap_err()["error"]["code"],
            "rate_limited"
        );
    }
}

#[test]
fn revoke_during_each_held_describe_never_dispatches_or_serves_cache() {
    struct Held {
        at: usize,
        calls: Mutex<usize>,
        entered: std::sync::mpsc::Sender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl ScopeReader for Held {
        fn describe(&self, _: &str, _: &str) -> Result<ScopeDescription, ScopeReadError> {
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            if *calls == self.at {
                self.entered.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
            Ok(description(ScopeStatus::Live, true, true))
        }
    }
    for (tool, cached, at) in [
        (Tool::Web, true, 1),
        (Tool::OrderedWeb, true, 1),
        (Tool::Web, false, 1),
        (Tool::Web, false, 2),
        (Tool::OrderedWeb, false, 2),
        (Tool::Code, false, 1),
        (Tool::Code, false, 2),
    ] {
        let mut f = Fixture::new(tool);
        let id = f.allow();
        if cached {
            f.cache();
        }
        let store = f.engine.store().clone();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        f.engine = f.engine.with_scope_reader(Arc::new(Held {
            at,
            calls: Mutex::new(0),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        }));
        let thread = std::thread::spawn(move || {
            let result = f.search(&caller());
            assert!(f.engine.transport().requests().is_empty());
            f.assert_no_cards();
            result
        });
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (deleted_tx, deleted_rx) = std::sync::mpsc::channel();
        let revoke = std::thread::spawn(move || {
            deleted_tx
                .send(store.delete_federated_row(&id).unwrap())
                .unwrap()
        });
        let deleted = deleted_rx.recv_timeout(Duration::from_secs(5));
        release_tx.send(()).unwrap();
        revoke.join().unwrap();
        assert!(deleted.unwrap(), "describe held the writer fence");
        assert_eq!(
            thread.join().unwrap().unwrap_err()["error"]["code"],
            "consent_unavailable"
        );
    }
}

#[test]
fn backend_order_is_unchanged_and_one_search_subject_covers_each_backend() {
    let mut f = Fixture::new(Tool::OrderedWeb);
    let mut manifest: Value = serde_json::from_str(
        &subc_jsonc::jsonc_to_json(include_str!("../../../../../catalog/tavily_rest.jsonc"))
            .unwrap(),
    )
    .unwrap();
    manifest["auth"] = json!({"mode":"none"});
    manifest["credential_bindings"] = json!([]);
    f.engine
        .store()
        .upsert_manifest(CATALOG_PRINCIPAL, &crate::ingest_value(manifest).unwrap())
        .unwrap();
    f.engine
        .store()
        .insert_connection(
            "direct",
            "tavily-backing",
            "tavily_rest",
            "active",
            &json!({}),
        )
        .unwrap();
    f.engine
        .store()
        .upsert_catalog_action(&CatalogActionInput {
            principal: "direct".into(),
            connection_id: "tavily-backing".into(),
            name: "search".into(),
            title: None,
            schema: json!({"type":"object"}),
            schema_hash: "tavily-schema".into(),
            risk: "read".into(),
            severity: "S1".into(),
            ask_first: false,
            status: "active".into(),
            quarantine_reason: None,
            reconciliation: None,
        })
        .unwrap();
    f.db.execute(
        "UPDATE connections SET ceiling_risk='read',ceiling_selectors='[\"search\"]'",
        [],
    )
    .unwrap();
    f.web = f
        .web
        .with_chain_backend(Arc::new(crate::web_search::TavilyRestBackend));
    f.allow();
    for (order, expected) in [
        (["exa", "tavily"], "backing"),
        (["tavily", "exa"], "tavily-backing"),
    ] {
        f.engine
            .store()
            .set_web_search_order(&order.map(str::to_string))
            .unwrap();
        let args = json!({"query":format!("rust async book {expected}")});
        let reply = f
            .web
            .search_federated(&f.engine, &caller(), args.as_object().unwrap(), None, None)
            .unwrap();
        assert_eq!(reply.backend, order[0]);
        assert_eq!(
            f.engine
                .transport()
                .requests()
                .last()
                .unwrap()
                .connection_id,
            expected
        );
    }
    assert_eq!(f.engine.transport().requests().len(), 2);
    f.assert_no_cards();
}

#[test]
fn candidates_use_direct_namespace_and_the_same_ambiguity_and_status_checks() {
    for tool in [Tool::Web, Tool::OrderedWeb, Tool::Code] {
        let f = Fixture::new(tool);
        f.allow();
        let app = if matches!(tool, Tool::Code) {
            "grep_app"
        } else {
            "exa_rest"
        };
        for (owner, id, status) in [
            ("reserved:callosum", "remote-only", "active"),
            ("direct", "pending", "pending"),
            ("direct", "disabled", "disabled"),
        ] {
            f.engine
                .store()
                .insert_connection(owner, id, app, status, &json!({}))
                .unwrap();
            f.engine
                .store()
                .upsert_catalog_action(&CatalogActionInput {
                    principal: owner.into(),
                    connection_id: id.into(),
                    name: tool.action().into(),
                    title: None,
                    schema: json!({"type":"object"}),
                    schema_hash: "schema".into(),
                    risk: "read".into(),
                    severity: "S1".into(),
                    ask_first: false,
                    status: "active".into(),
                    quarantine_reason: None,
                    reconciliation: None,
                })
                .unwrap();
        }
        assert!(f.search(&caller()).is_ok());
        f.db.execute(
            "UPDATE connections SET status='active' WHERE connection_id='disabled'",
            [],
        )
        .unwrap();
        assert_eq!(
            f.search(&caller()).unwrap_err()["error"]["code"],
            if matches!(tool, Tool::OrderedWeb) {
                "web_search_unavailable"
            } else {
                "backend_ambiguous"
            }
        );
        assert_eq!(f.engine.transport().requests().len(), 1);
    }
}

#[test]
fn search_binding_uses_tool_arguments_and_rate_identity_excludes_display_fields() {
    let remote = caller();
    let args = json!({"query":"rust async book","max_results":3});
    let authority =
        SearchAuthorization::new(&remote, SearchTool::Web, args.as_object().unwrap()).unwrap();
    assert_eq!(authority.binding.owner_principal, "");
    assert_eq!(authority.binding.subject, "web_search");
    assert_eq!(authority.binding.action, "web_search");
    assert_ne!(
        authority.binding.args_digest,
        crate::jcs::jcs_sha256(&json!({"query":"vendor query"})).unwrap()
    );
    let mut renamed = remote.clone();
    renamed.attributes.peer_name = "New name".into();
    assert_eq!(
        authority.caller_key().unwrap(),
        SearchAuthorization::new(&renamed, SearchTool::Web, args.as_object().unwrap())
            .unwrap()
            .caller_key()
            .unwrap()
    );
    let mut keys = std::collections::HashSet::new();
    for claim in [
        json!({"kind":"agent","agent_id":"a:b|c"}),
        json!({"kind":"agent","agent_id":"a|b:c"}),
        json!({"kind":"run","agent_id":"a:b|c"}),
        json!({"kind":"worker","owner_module_id":"a:b","worker_ref":"c"}),
    ] {
        let mut attributes = remote.attributes.clone();
        attributes.remote_claim = Some(serde_json::from_value(claim).unwrap());
        let remote = FederatedCaller::from_attributes(attributes).unwrap();
        let key = SearchAuthorization::new(&remote, SearchTool::Web, args.as_object().unwrap())
            .unwrap()
            .caller_key()
            .unwrap();
        assert!(keys.insert(key));
    }
}
