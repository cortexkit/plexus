use super::*;
use cortexkit_role_tool_provider::result::{
    legacy_model_visible_bytes, model_visible_bytes, ToolResult, MAX_MODEL_VISIBLE_BYTES,
};

fn state() -> Arc<ModuleState> {
    Arc::new(ModuleState {
        health: Arc::new(health::HealthState::new()),
        runtime: runtime_for_test(Arc::new(test_support::open_memory_store("refusal-echo"))),
    })
}

fn call(state: &Arc<ModuleState>, tool: &str, arguments: Value) -> Value {
    let object = json!({"name": tool, "arguments": arguments});
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        wire::control_flags(),
        2,
        1,
        8,
        serde_json::to_vec(&object).unwrap(),
    )
    .unwrap();
    let routes = Arc::new(RouteBindings::new());
    routes
        .insert(
            2,
            1,
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
        )
        .unwrap();
    facade_tool_reply(&frame, object.as_object().unwrap(), state, &routes).unwrap()
}

fn names() -> [String; 3] {
    ["typo".into(), "x".repeat(70_000), "🦀".repeat(17_500)]
}

fn assert_echo(echo: &str, original: &str) {
    if original.len() <= 256 {
        assert_eq!(echo, original);
    } else {
        assert!(echo.len() <= 256, "echo has {} bytes", echo.len());
        let prefix = echo
            .strip_suffix("[shortened]")
            .expect("a cut echo must say so");
        assert!(original.starts_with(prefix));
        assert!(
            prefix.len() >= 241,
            "the helper keeps the longest UTF-8 prefix"
        );
    }
}

fn assert_refusal(tool: &str, reply: &Value, code: &str) {
    assert_eq!(reply["error"]["code"], code);
    let legacy = legacy_model_visible_bytes(reply);
    assert!(
        legacy <= MAX_MODEL_VISIBLE_BYTES,
        "legacy refusal bytes: {legacy}"
    );
    let rendered = with_call_tool_result(Some(tool), reply.clone());
    let model = model_visible_bytes(&serde_json::from_value::<ToolResult>(rendered).unwrap());
    assert!(
        model <= MAX_MODEL_VISIBLE_BYTES,
        "model-visible refusal bytes: {model}"
    );
}

#[test]
fn search_unknown_keys_have_bounded_refusal_echoes() {
    for name in names() {
        for (tool, reply) in [
            (
                manifest::CODE_SEARCH_TOOL,
                plexus_core::code_search::CodeSearchQuery::parse(
                    json!({name.clone(): null}).as_object().unwrap(),
                )
                .err()
                .unwrap()
                .to_wire(),
            ),
            (
                manifest::WEB_SEARCH_TOOL,
                plexus_core::web_search::WebSearchQuery::parse(
                    json!({name.clone(): null}).as_object().unwrap(),
                )
                .unwrap_err()
                .to_wire(),
            ),
        ] {
            assert_echo(reply["error"]["field"].as_str().unwrap(), &name);
            assert_refusal(tool, &reply, "invalid_query");
        }
    }
}

#[test]
fn github_binding_unknown_keys_have_bounded_refusal_echoes() {
    let state = state();
    for name in names() {
        for (tool, arguments) in [
            (
                manifest::GITHUB_TOOL,
                json!({"op":"bindings.read_for_agent", "agent_id":"agent", name.clone():null}),
            ),
            (
                manifest::GITHUB_READ_TOOL,
                json!({"action":"github.bindings.list", name.clone():null}),
            ),
        ] {
            let reply = call(&state, tool, arguments);
            assert_echo(reply["error"]["field"].as_str().unwrap(), &name);
            assert_refusal(tool, &reply, "invalid_request");
        }
    }
}

#[test]
fn github_react_unknown_keys_have_bounded_refusal_echoes() {
    for name in names() {
        for nested in [false, true] {
            let mut args = json!({"repository":"o/r", "kind":"issue", "target":{"number":1}, "reaction":"+1", "request_nonce":"nonce"});
            if nested {
                args["target"][&name] = Value::Null;
            } else {
                args[&name] = Value::Null;
            }
            let reply = github_react::reaction_request(args.as_object().unwrap())
                .err()
                .unwrap();
            let original = if nested {
                format!("target.{name}")
            } else {
                name.clone()
            };
            let field = reply["error"]["field"].as_str().unwrap();
            assert_echo(field, &original);
            assert_eq!(
                reply["error"]["message"],
                format!("github_react does not accept the field {field}")
            );
            assert_refusal(manifest::GITHUB_REACT_TOOL, &reply, "invalid_request");
        }
    }
}

#[test]
fn github_read_unknown_actions_have_bounded_refusal_echoes() {
    let state = state();
    for name in names() {
        let reply = call(&state, manifest::GITHUB_READ_TOOL, json!({"action":name}));
        let echo = reply["error"]["action"].as_str().unwrap();
        assert_echo(echo, &name);
        assert_eq!(
            reply["error"]["message"],
            format!("GitHub read action {echo:?} is not supported")
        );
        assert_refusal(
            manifest::GITHUB_READ_TOOL,
            &reply,
            "read_action_unsupported",
        );
    }
}

#[test]
fn configure_filter_keys_have_bounded_refusal_echoes() {
    for name in names() {
        for outcome in [
            ConfigureOutcome::UndeclaredFilter(name.clone()),
            ConfigureOutcome::UnreadFilterKey {
                key: name.clone(),
                accepted: vec!["required".into()],
            },
            ConfigureOutcome::MalformedFilters {
                field: name.clone(),
                expected: "array".into(),
            },
        ] {
            let reply = configure_outcome_response(Ok(outcome));
            let code = reply["error"]["code"].as_str().unwrap();
            let echo = reply["error"]
                .get("key")
                .unwrap_or(&reply["error"]["field"])
                .as_str()
                .unwrap();
            assert_echo(echo, &name);
            let expected = match code {
                "undeclared_filter" => {
                    format!("filter key '{echo}' is not declared by the vendor manifest")
                }
                "unread_filter_key" => format!(
                    "resource_filters key '{echo}' is not read by configure (accepted: required)"
                ),
                "malformed_filters" => format!("resource_filters {echo} must be array"),
                _ => panic!("unexpected code {code}"),
            };
            assert_eq!(reply["error"]["message"], expected);
            assert_refusal(manifest::CONNECTIONS_TOOL, &reply, code);
        }
    }
}

#[test]
fn denial_fields_and_actions_have_bounded_refusal_echoes() {
    for name in names() {
        let reply = denial_response(&plexus_core::Denial::ArgumentUndeclared {
            field: name.clone(),
        });
        assert_echo(reply["error"]["field"].as_str().unwrap(), &name);
        assert_refusal(manifest::INVOKE_TOOL, &reply, "argument_undeclared");
        for denial in [
            plexus_core::Denial::ConsentUnavailable {
                action: name.clone(),
            },
            plexus_core::Denial::ApprovalPreviewTooLong {
                action: name.clone(),
                length: 100_000,
                limit: 65_536,
            },
        ] {
            let reply = denial_response(&denial);
            assert_echo(reply["error"]["action"].as_str().unwrap(), &name);
            assert_refusal(manifest::INVOKE_TOOL, &reply, denial.reason_code());
            assert!(reply["error"]["message"]
                .as_str()
                .unwrap()
                .contains(reply["error"]["action"].as_str().unwrap()));
        }
        let reply = denial_response(&plexus_core::Denial::AccessPending {
            elicitation_id: "e".into(),
            service: name.clone(),
            action: name.clone(),
        });
        let text = reply["error"]["message"].as_str().unwrap();
        if name.len() < 256 {
            assert_eq!(
                text,
                CONSENT_PENDING_TEXT
                    .replace("<service>", &name)
                    .replace("<action>", &name)
            );
        } else {
            assert_eq!(text.matches("[shortened]").count(), 2);
        }
        assert_refusal(manifest::INVOKE_TOOL, &reply, "access_pending");
    }
}

#[test]
fn catalog_metadata_keys_and_diagnostics_have_bounded_refusal_echoes() {
    use cortexkit_role_tool_provider::ops;
    for name in names() {
        for (op, args, original) in [
            (
                ops::ROLE_DESCRIBE,
                json!({name.clone(): null}),
                name.clone(),
            ),
            (ops::TOOL_CATALOG, json!({name.clone(): null}), name.clone()),
            (
                ops::TOOL_CATALOG,
                json!({"params":{name.clone():null}}),
                format!("params.{name}"),
            ),
        ] {
            let reply = serde_json::to_value(
                tool_provider::reply(op, args.as_object().unwrap()).unwrap_err(),
            )
            .unwrap();
            assert_echo(reply["detail"]["field"].as_str().unwrap(), &original);
            assert_eq!(reply["code"], "invalid_request");
            assert!(reply["message"].as_str().unwrap().len() <= MAX_MODEL_VISIBLE_BYTES);
            assert!(legacy_model_visible_bytes(&reply) <= MAX_MODEL_VISIBLE_BYTES);
        }
        let args = json!({"params":{"capabilities":[name.clone()]}});
        let reply = serde_json::to_value(
            tool_provider::reply(ops::TOOL_CATALOG, args.as_object().unwrap()).unwrap_err(),
        )
        .unwrap();
        assert_echo(reply["detail"]["capability"].as_str().unwrap(), &name);
        assert_eq!(reply["code"], "invalid_request");
        assert!(legacy_model_visible_bytes(&reply) <= MAX_MODEL_VISIBLE_BYTES);
        let args = json!({"digest_only":name});
        let reply = serde_json::to_value(
            tool_provider::reply(ops::TOOL_CATALOG, args.as_object().unwrap()).unwrap_err(),
        )
        .unwrap();
        assert_eq!(reply["code"], "invalid_request");
        if name.len() > 256 {
            assert!(reply["message"].as_str().unwrap().ends_with("[shortened]"));
        }
        assert!(legacy_model_visible_bytes(&reply) <= MAX_MODEL_VISIBLE_BYTES);
    }
}

#[test]
fn management_unknown_keys_have_bounded_refusal_echoes() {
    let state = state();
    for name in names() {
        for nested in [false, true] {
            let mut request = json!({"method":"permissions.list", "params":{}});
            if nested {
                request["params"][&name] = Value::Null;
            } else {
                request[&name] = Value::Null;
            }
            let reply = permissions::run(
                &state,
                "direct",
                Some(&CallMode::Classic),
                None,
                "permissions.list",
                request.as_object().unwrap(),
            );
            assert_echo(reply["error"]["field"].as_str().unwrap(), &name);
            assert_refusal(manifest::INVOKE_TOOL, &reply, "invalid_request");
        }
        for level in 0..3 {
            let mut request =
                json!({"method":"grants.would_ask", "params":{"flow_id":"flow", "items":[{}]}});
            match level {
                0 => request[&name] = Value::Null,
                1 => request["params"][&name] = Value::Null,
                _ => request["params"]["items"][0][&name] = Value::Null,
            }
            let reply = grants_would_ask::run(
                &state,
                plexus_core::github::PREFRONTAL_PRINCIPAL,
                None,
                request.as_object().unwrap(),
            );
            assert_echo(reply["error"]["field"].as_str().unwrap(), &name);
            assert_refusal(manifest::INVOKE_TOOL, &reply, "invalid_request");
        }
    }
}

#[test]
fn event_subscription_keys_and_schema_diagnostics_have_bounded_refusal_echoes() {
    use plexus_core::storage::SubscriptionRefusal as R;
    for name in names() {
        let cases = [
            (
                R::CursorStateKeyUnknown {
                    key: name.clone(),
                    accepted: vec!["since".into()],
                },
                format!(
                    "cursor_state key '{name}' is not read by this cursor kind (accepted: since)"
                ),
            ),
            (
                R::FixedArgCursorOwned(name.clone()),
                format!("fixed_args key '{name}' is owned by the cursor strategy"),
            ),
            (
                R::FixedArgRequestConstant(name.clone()),
                format!("fixed_args key '{name}' collides with a manifest request constant"),
            ),
            (
                R::FixedArgNotDeclared(name.clone()),
                format!("fixed_args key '{name}' is not declared by the action schema"),
            ),
            (
                R::FixedArgRequiredMissing(name.clone()),
                format!("the action requires '{name}', which fixed_args must supply"),
            ),
            (
                R::FixedArgTypeMismatch {
                    key: name.clone(),
                    expected: "string".into(),
                    actual: "array".into(),
                },
                format!("fixed_args key '{name}' has type array, expected string"),
            ),
            (
                R::ActionNotCoveredByGrant {
                    action: name.clone(),
                },
                format!("poll grant does not cover action '{name}'"),
            ),
            (
                R::ProbeReturnSchemaInvalid(name.clone()),
                format!("probe return_schema is invalid: {name}"),
            ),
        ];
        for (refusal, ordinary_message) in cases {
            let message = refusal.to_string();
            if name.len() <= 256 {
                assert_eq!(message, ordinary_message);
            } else {
                assert!(message.contains("[shortened]"));
                assert!(
                    message.len() < 400,
                    "{} bytes in {}",
                    message.len(),
                    refusal.code()
                );
            }
            let reply = json!({"error":{"code":refusal.code(), "message":message}});
            assert_refusal(manifest::EVENTS_TOOL, &reply, refusal.code());
        }
    }
}

#[test]
fn event_actor_source_diagnostics_have_bounded_refusal_echoes() {
    let state = state();
    for name in names() {
        let arguments = json!({"subscription_id":"s", "actor_source":{name.clone():null}});
        let original = serde_json::from_value::<ActorSource>(arguments["actor_source"].clone())
            .unwrap_err()
            .to_string();
        let reply = facade_events_set_actor_source(&FacadeArguments {
            state: &state,
            arguments: arguments.as_object().unwrap(),
            principal_key: "direct",
            op: Some("set_actor_source"),
        })
        .unwrap();
        let diagnostic = reply["error"]["message"]
            .as_str()
            .unwrap()
            .strip_prefix("actor_source is invalid: ")
            .unwrap();
        assert_echo(diagnostic, &original);
        assert_refusal(manifest::EVENTS_TOOL, &reply, "invalid_request");
    }
}
