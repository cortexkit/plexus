use super::*;

#[test]
fn the_empty_path_reads_the_repository_itself() {
    assert_eq!(relative_path(""), Some(String::new()));
    assert_eq!(
        relative_path("pulls/12/files"),
        Some("/pulls/12/files".into())
    );
    assert_eq!(
        relative_path("compare/main...topic"),
        Some("/compare/main...topic".into()),
        "three dots in a compare range are not a dot segment"
    );
    assert_eq!(
        relative_path("contents/docs/a b.md"),
        Some("/contents/docs/a%20b.md".into())
    );
    assert_eq!(
        relative_path("compare/main...fork:topic"),
        Some("/compare/main...fork:topic".into())
    );
}

#[test]
fn every_refused_path_form_is_refused() {
    for path in [
        "/",
        "/pulls",
        "https://api.github.com/repos/o/r",
        "http:pulls",
        "//evil.example/x",
        "pulls//1",
        "..",
        "pulls/../../orgs",
        "pulls/./1",
        "pulls/%2e%2e/x",
        "pulls/%2E./x",
        "pulls/.%2e",
        "pulls/%252e%252e/x",
        "contents%2fsecret",
        "contents%2Fsecret",
        "contents%5csecret",
        "contents\\secret",
        "pulls?per_page=1",
        "pulls#x",
        "pulls/\n1",
    ] {
        assert_eq!(relative_path(path), None, "{path:?} must be refused");
    }
}

#[test]
fn accept_allows_only_the_four_media_types_and_defaults_to_json() {
    assert_eq!(
        accepted_media_type(None),
        Some("application/vnd.github+json")
    );
    for media_type in ACCEPTED_MEDIA_TYPES {
        assert_eq!(
            accepted_media_type(Some(&json!(media_type))),
            Some(*media_type)
        );
    }
    for refused in [
        json!("application/json"),
        json!("application/vnd.github.v3.raw"),
        json!("application/vnd.github+json; charset=utf-8"),
        json!("*/*"),
        json!(1),
    ] {
        assert_eq!(accepted_media_type(Some(&refused)), None, "{refused}");
    }
    assert!(media_type_is_json("application/vnd.github+json"));
    assert!(!media_type_is_json("application/vnd.github.raw+json"));
    assert!(!media_type_is_json("application/vnd.github.diff"));
}

#[test]
fn search_refuses_scope_qualifiers_and_fences_to_the_bound_repository() {
    let args = |q: &str| json!({"q": q});
    let built = vendor_args(
        "github.search.code",
        "acme",
        "widgets",
        &args("parse_config"),
    )
    .unwrap();
    assert_eq!(built["q"], "parse_config repo:acme/widgets");
    assert!(!built.contains_key("page"));
    for q in [
        "x repo:acme/other",
        "x REPO:acme/other",
        "org:acme x",
        "x Org:acme",
        "user:someone x",
        "x\tuser:someone",
        "a repo:b",
    ] {
        assert_eq!(
            vendor_args("github.search.issues", "acme", "widgets", &args(q)),
            Err(BotReadError::EndpointNotAllowed { field: "q".into() }),
            "{q:?}"
        );
    }
    assert_eq!(
        vendor_args(
            "github.search.code",
            "acme",
            "widgets",
            &json!({"q": "x", "per_page": 101})
        ),
        Err(BotReadError::EndpointNotAllowed {
            field: "per_page".into()
        })
    );
    assert!(vendor_args(
        "github.search.code",
        "acme",
        "widgets",
        &json!({"q": "x", "per_page": 100, "page": 3})
    )
    .is_ok());
}

#[test]
fn repo_get_refuses_non_string_query_values_and_unknown_arguments() {
    assert_eq!(
        vendor_args(
            "github.repo.get",
            "acme",
            "widgets",
            &json!({"path": "", "query": {"page": 2}})
        ),
        Err(BotReadError::EndpointNotAllowed {
            field: "query".into()
        })
    );
    assert_eq!(
        vendor_args(
            "github.repo.get",
            "acme",
            "widgets",
            &json!({"path": "", "method": "POST"})
        ),
        Err(BotReadError::EndpointNotAllowed {
            field: "method".into()
        })
    );
    let built = vendor_args(
        "github.repo.get",
        "acme",
        "widgets",
        &json!({"path": "pulls", "query": {"state": "open"}}),
    )
    .unwrap();
    assert_eq!(built["accept"], "application/vnd.github+json");
    assert_eq!(built["query"], json!({"state": "open"}));
}

#[test]
fn next_page_reads_only_the_rel_next_target() {
    let link = r#"<https://api.github.com/repositories/1/pulls?state=open&page=3>; rel="next", <https://api.github.com/repositories/1/pulls?state=open&page=9>; rel="last""#;
    assert_eq!(next_page(Some(link)), Some(3));
    let last_page = r#"<https://api.github.com/repositories/1/pulls?page=1>; rel="prev", <https://api.github.com/repositories/1/pulls?page=1>; rel="first""#;
    assert_eq!(next_page(Some(last_page)), None);
    assert_eq!(next_page(None), None);
}
