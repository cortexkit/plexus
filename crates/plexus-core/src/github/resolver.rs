//! Repository-bound routing before a handle connection or credential is loaded.

use crate::governance::{AuthorizationRequest, ResolverDenial};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub app_handle_id: String,
    pub connection_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRepositories {
    pub repositories: Vec<String>,
    pub binding: Binding,
}

/// Check the entire repository selection before a connection lookup or vault read.
/// The lookup must consult the binding table, not the installation's inventory.
pub fn resolve<F>(
    args: &Value,
    connection_id: &str,
    mut binding_for: F,
) -> Result<ResolvedRepositories, ResolverDenial>
where
    F: FnMut(&str) -> Result<Option<Binding>, ResolverDenial>,
{
    let fields = args.as_object().ok_or(ResolverDenial::RepositoryUnbound)?;
    let search = fields.contains_key("repositories");
    if search && fields.contains_key("repository") {
        return Err(forbidden("repository"));
    }
    if !search && fields.contains_key("repositories") {
        return Err(forbidden("repositories"));
    }
    let repositories: Vec<String> = if search {
        let items = fields["repositories"]
            .as_array()
            .filter(|items| !items.is_empty())
            .ok_or(ResolverDenial::RepositoryUnbound)?;
        items
            .iter()
            .map(|item| {
                let name = item.as_str().ok_or(ResolverDenial::RepositoryUnbound)?;
                split_repository(name)?;
                Ok(name.to_owned())
            })
            .collect::<Result<_, _>>()?
    } else {
        let name = fields
            .get("repository")
            .and_then(Value::as_str)
            .ok_or(ResolverDenial::RepositoryUnbound)?;
        split_repository(name)?;
        vec![name.to_owned()]
    };

    // These names must never be interpreted as an independent path selector.
    for field in ["target_repository", "path_repository", "full_name"] {
        if fields.contains_key(field) {
            return Err(forbidden(field));
        }
    }
    if search {
        for field in ["repo", "owner", "org", "user", "visibility"] {
            if fields.contains_key(field) {
                return Err(forbidden(field));
            }
        }
        let terms = fields.get("terms").and_then(Value::as_str).unwrap_or("");
        if terms.split_whitespace().any(|word| {
            ["repo:", "org:", "user:", "visibility:"]
                .iter()
                .any(|prefix| word.to_ascii_lowercase().starts_with(prefix))
        }) {
            return Err(forbidden("query_qualifier"));
        }
    } else {
        let (owner, repo) = split_repository(&repositories[0])?;
        // GitHub names compare without regard to case, so owner and repo
        // naming the bound repository in another case still name it.
        let mismatched = |field: &str, expected: &str| {
            fields.get(field).is_some_and(|value| {
                !value
                    .as_str()
                    .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
            })
        };
        if mismatched("owner", owner) || mismatched("repo", repo) {
            return Err(ResolverDenial::RepositoryUnbound);
        }
    }

    let mut selected: Option<Binding> = None;
    for repository in &repositories {
        let binding = binding_for(repository)?.ok_or(ResolverDenial::RepositoryUnbound)?;
        if selected
            .as_ref()
            .is_some_and(|first| first.app_handle_id != binding.app_handle_id)
        {
            return Err(forbidden("repositories"));
        }
        if binding.connection_id != connection_id {
            return Err(ResolverDenial::RepositoryUnbound);
        }
        selected = Some(binding);
    }
    Ok(ResolvedRepositories {
        repositories,
        binding: selected.expect("nonempty repository selection"),
    })
}

pub fn resolve_invoke<F>(
    request: &AuthorizationRequest,
    binding_for: F,
) -> Result<(), ResolverDenial>
where
    F: FnMut(&str) -> Result<Option<Binding>, ResolverDenial>,
{
    resolve(&request.args, &request.connection_id, binding_for).map(|_| ())
}

/// Construct REST path arguments from the already resolved binding. Never copy
/// arbitrary request fields into transport args: REST sends all non-path args as JSON.
pub fn path_args(
    resolved: &ResolvedRepositories,
    repository: &str,
) -> Result<Map<String, Value>, ResolverDenial> {
    if !resolved.repositories.iter().any(|name| name == repository) {
        return Err(ResolverDenial::RepositoryUnbound);
    }
    let (owner, repo) = split_repository(repository)?;
    Ok(Map::from_iter([
        ("owner".into(), Value::String(owner.into())),
        ("repo".into(), Value::String(repo.into())),
    ]))
}

/// The closed field inventory for mapped GitHub operations. The caller does
/// not get to provide a list of permissible JSON-body fields.
#[derive(Debug, Clone, Copy)]
pub enum RequestKind {
    Close,
    Reopen,
    Comment,
    Reaction,
    IssueCreate,
    IssueEdit,
    CommentEdit,
    PrReview,
    PrCreate,
    PrReady,
}

impl RequestKind {
    fn body_fields(self) -> &'static [&'static str] {
        match self {
            Self::Close => &["issue_number", "state", "state_reason", "comment"],
            Self::Reopen => &["issue_number", "state", "comment"],
            Self::Comment => &["issue_number", "body"],
            Self::CommentEdit => &["issue_number", "comment_id", "body"],
            Self::Reaction => &["issue_number", "content"],
            // A review lives on the pull request's own path, which names it
            // pull_number, and without an event GitHub leaves it PENDING.
            Self::PrReview => &["pull_number", "body", "event"],
            Self::PrReady => &["pull_number"],
            Self::IssueCreate => &["title", "body", "labels"],
            // Owner and repo come from the repository the bot is bound to (see
            // path_args), never from caller fields. GitHub's head_repo, maintainer_can_modify and issue are left out
            // on purpose; see create_pull_request in catalog/github_rest.jsonc.
            Self::PrCreate => &["title", "body", "base", "head", "draft"],
            Self::IssueEdit => &[
                "issue_number",
                "title",
                "body",
                "labels",
                "assignees",
                "add_labels",
                "remove_labels",
                "add_assignees",
                "remove_assignees",
            ],
        }
    }
}

/// Copy only this operation's declared fields into its transport body.
pub fn mapped_args(
    resolved: &ResolvedRepositories,
    repository: &str,
    request: &Value,
    kind: RequestKind,
) -> Result<Value, ResolverDenial> {
    let mut args = path_args(resolved, repository)?;
    let fields = request
        .as_object()
        .ok_or(ResolverDenial::RepositoryUnbound)?;
    for &field in kind.body_fields() {
        if let Some(value) = fields.get(field) {
            args.insert(field.into(), value.clone());
        }
    }
    Ok(Value::Object(args))
}

/// Why [`declared_args`] could not narrow a governed call's arguments to the
/// ones its action's reviewed manifest declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclaredArgsError {
    /// The store could not be read; nothing was decided.
    Store,
    /// The reviewed manifest does not declare this action's argument schema,
    /// so there is no reviewed list of what it may be sent.
    NotDeclared,
}

/// Keep only the arguments `action` declares in its reviewed manifest's
/// `http.args_schema`, dropping every other key.
///
/// One bot request fans out into several governed calls (ownership reads,
/// the write itself, extra legs), and they are all built from one set of
/// request arguments. Each call must carry only what its own action declares:
/// the REST transport puts every non-path argument into the query string or
/// JSON body, and governance refuses any top-level argument the pinned schema
/// does not declare.
pub fn declared_args(
    store: &crate::storage::PlexusStore,
    connection_principal: &str,
    connection_id: &str,
    action: &str,
    args: &Value,
) -> Result<Value, DeclaredArgsError> {
    let declared = store
        .reviewed_arg_names(connection_principal, connection_id, action)
        .map_err(|_| DeclaredArgsError::Store)?
        .ok_or(DeclaredArgsError::NotDeclared)?;
    let fields = args.as_object().ok_or(DeclaredArgsError::NotDeclared)?;
    Ok(Value::Object(
        fields
            .iter()
            .filter(|(key, _)| declared.contains(key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    ))
}

/// Search takes terms, not a caller-built GitHub query. Filter returned hits
/// against the exact requested set even when an installation sees more repos.
pub fn search_query(
    resolved: &ResolvedRepositories,
    terms: &str,
) -> Result<String, ResolverDenial> {
    if terms.split_whitespace().any(|word| {
        ["repo:", "org:", "user:", "visibility:"]
            .iter()
            .any(|prefix| word.to_ascii_lowercase().starts_with(prefix))
    }) {
        return Err(forbidden("query_qualifier"));
    }
    Ok(format!(
        "{} {}",
        terms,
        resolved
            .repositories
            .iter()
            .map(|repo| format!("repo:{repo}"))
            .collect::<Vec<_>>()
            .join(" ")
    )
    .trim()
    .to_owned())
}

pub fn filter_search_results(resolved: &ResolvedRepositories, items: &mut Vec<Value>) {
    // GitHub reports a repository's name in the case its owner chose, which
    // need not be the canonical lowercase form the selection is held in.
    let allowed: BTreeSet<String> = resolved
        .repositories
        .iter()
        .map(|name| crate::github::canonical_repository(name))
        .collect();
    items.retain(|item| {
        item.pointer("/repository/full_name")
            .and_then(Value::as_str)
            .is_some_and(|name| allowed.contains(&crate::github::canonical_repository(name)))
    });
}

pub(crate) fn split_repository(name: &str) -> Result<(&str, &str), ResolverDenial> {
    let (owner, repo) = name
        .split_once('/')
        .ok_or(ResolverDenial::RepositoryUnbound)?;
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return Err(ResolverDenial::RepositoryUnbound);
    }
    Ok((owner, repo))
}

fn forbidden(field: &str) -> ResolverDenial {
    ResolverDenial::RequestFieldForbidden {
        field: field.into(),
    }
}
