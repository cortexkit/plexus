use plexus_core::github::resolver::{
    filter_search_results, mapped_args, path_args, resolve, search_query, Binding, RequestKind,
    ResolvedRepositories,
};
use plexus_core::governance::ResolverDenial;
use serde_json::{json, Value};
use std::cell::Cell;

fn bound(args: Value) -> Result<ResolvedRepositories, ResolverDenial> {
    resolve(&args, "handle-x", |repo| {
        Ok(match repo {
            "org/x" => Some(Binding {
                app_handle_id: "github_app:x".into(),
                connection_id: "handle-x".into(),
            }),
            "org/y" => Some(Binding {
                app_handle_id: "github_app:y".into(),
                connection_id: "handle-y".into(),
            }),
            _ => None,
        })
    })
}

#[test]
fn unbound_repository_is_refused() {
    assert_eq!(
        bound(json!({"repository":"org/missing"})).unwrap_err(),
        ResolverDenial::RepositoryUnbound
    );
}

#[test]
fn second_repository_field_is_refused_before_lookup() {
    let lookups = Cell::new(0);
    let refusal = resolve(
        &json!({"repository":"org/x","target_repository":"org/y"}),
        "handle-x",
        |_| {
            lookups.set(lookups.get() + 1);
            Ok(None)
        },
    )
    .unwrap_err();
    assert_eq!(
        refusal,
        ResolverDenial::RequestFieldForbidden {
            field: "target_repository".into()
        }
    );
    assert_eq!(lookups.get(), 0);
}

#[test]
fn mismatched_path_and_installed_other_repository_are_refused() {
    assert_eq!(
        bound(json!({"repository":"org/x","owner":"org","repo":"y"})).unwrap_err(),
        ResolverDenial::RepositoryUnbound
    );
    let resolved = bound(json!({"repository":"org/x"})).unwrap();
    assert_eq!(
        path_args(&resolved, "org/y").unwrap_err(),
        ResolverDenial::RepositoryUnbound
    );
    assert_eq!(
        path_args(&resolved, "org/x").unwrap(),
        json!({"owner":"org","repo":"x"})
            .as_object()
            .unwrap()
            .clone()
    );
}

#[test]
fn search_rejects_multiple_handles_and_qualifiers_and_filters_hits() {
    assert_eq!(
        bound(json!({"repositories":["org/x","org/y"],"terms":"bug"})).unwrap_err(),
        ResolverDenial::RequestFieldForbidden {
            field: "repositories".into()
        }
    );
    assert_eq!(
        bound(json!({"repositories":["org/x"],"terms":"bug repo:org/y"})).unwrap_err(),
        ResolverDenial::RequestFieldForbidden {
            field: "query_qualifier".into()
        }
    );
    let resolved = bound(json!({"repositories":["org/x"],"terms":"bug"})).unwrap();
    assert_eq!(search_query(&resolved, "bug").unwrap(), "bug repo:org/x");
    let mut hits = vec![
        json!({"repository":{"full_name":"org/x"}}),
        json!({"repository":{"full_name":"org/y"}}),
        json!({}),
    ];
    filter_search_results(&resolved, &mut hits);
    assert_eq!(hits, vec![json!({"repository":{"full_name":"org/x"}})]);
}

/// GitHub names compare without regard to case: an owner or repo argument in
/// another case still names the bound repository, and a search hit GitHub
/// reports in its owner's chosen case is still one of the requested ones.
#[test]
fn repository_names_match_in_any_case() {
    let resolved = bound(json!({"repository":"org/x","owner":"ORG","repo":"X"})).unwrap();
    assert_eq!(resolved.repositories, ["org/x"]);
    let search = bound(json!({"repositories":["org/x"],"terms":"bug"})).unwrap();
    let mut hits = vec![
        json!({"repository":{"full_name":"Org/X"}}),
        json!({"repository":{"full_name":"Org/Y"}}),
    ];
    filter_search_results(&search, &mut hits);
    assert_eq!(hits, vec![json!({"repository":{"full_name":"Org/X"}})]);
}

#[test]
fn mapped_args_allowlist_drops_extra_fields_on_each_kind() {
    let resolved = bound(json!({"repository":"org/x"})).unwrap();
    for (kind, name) in [
        (RequestKind::Close, "close"),
        (RequestKind::Reopen, "reopen"),
        (RequestKind::Comment, "comment"),
        (RequestKind::Reaction, "reaction"),
        (RequestKind::IssueCreate, "issue_create"),
        (RequestKind::IssueEdit, "issue_edit"),
        (RequestKind::CommentEdit, "comment_edit"),
        (RequestKind::PrReview, "pr_review"),
        (RequestKind::PrCreate, "pr_create"),
    ] {
        let request = json!({"repository":"org/x","unexpected":"leak","title":"wrong title","state":"closed","body":"words"});
        let args = mapped_args(&resolved, "org/x", &request, kind).unwrap();
        assert_eq!(args["owner"], "org", "{name}");
        assert_eq!(args["repo"], "x", "{name}");
        assert!(args.get("unexpected").is_none(), "{name}");
        if matches!(kind, RequestKind::Close | RequestKind::Reopen) {
            assert!(args.get("title").is_none(), "{name}");
        }
    }
}
