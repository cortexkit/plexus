//! Bounded, read-only GitHub list walks shared by facade reads and the handle probe.
//!
//! The caller supplies a read-only page dispatcher (for example, a governed
//! `github.issue_comments.list` invoke). A completed walk is the only evidence
//! that an absent bot comment means not found.

use serde_json::Value;

pub const PER_PAGE: usize = 100;
pub const MAX_PAGES: usize = 100;

/// Reads may finish after the deadline, but must not extend the claim's budget.
pub(crate) fn check_lease(expires_at_ms: i64, now_ms: i64) -> Result<(), WalkError> {
    if now_ms >= expires_at_ms {
        Err(WalkError::LeaseExpired)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListRead {
    IssueComments,
    InstallationRepositories,
}

impl ListRead {
    #[cfg(any(test, feature = "test-support"))]
    pub fn action(self) -> &'static str {
        match self {
            Self::IssueComments => "github.issue_comments.list",
            Self::InstallationRepositories => "GET /installation/repositories",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRequest {
    pub read: ListRead,
    pub page: usize,
    pub per_page: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkError {
    Incomplete,
    InvalidResponse,
    ReadFailed,
    LeaseExpired,
}

#[derive(Debug, Clone)]
pub struct CompletedWalk {
    read: ListRead,
    items: Vec<Value>,
}

impl CompletedWalk {
    pub fn items(&self) -> &[Value] {
        &self.items
    }

    /// Issue comments arrive oldest first. Only a complete walk can identify
    /// the newest comment owned by the App, including one on the last page.
    pub fn newest_bot_comment(&self, slug: &str) -> Option<&Value> {
        if self.read != ListRead::IssueComments {
            return None;
        }
        let login = crate::github::credential::bot_login(&format!(
            "{}{slug}",
            crate::github::credential::APP_PREFIX
        ))?;
        self.items.iter().rev().find(|item| {
            item.pointer("/user/login")
                .and_then(Value::as_str)
                .is_some_and(|actual| actual.eq_ignore_ascii_case(&login))
                && item.pointer("/user/type").and_then(Value::as_str) == Some("Bot")
        })
    }
}

/// A list-dependent request must not dispatch without proof of its completed
/// pre-dispatch read. An incomplete or failed walk cannot yield this proof.
#[cfg(any(test, feature = "test-support"))]
pub fn may_dispatch(read_table: &[ListRead], completed: &[CompletedWalk]) -> bool {
    read_table
        .iter()
        .all(|read| completed.iter().any(|walk| walk.read == *read))
}

/// Walk until the vendor returns a short page. A full last page requires one
/// more empty page; hitting the bound never means "not found". The clock is
/// checked both before and after dispatch, including the final page.
pub fn walk<F, C>(
    read: ListRead,
    started_at_ms: i64,
    now_ms: C,
    fetch: F,
) -> Result<CompletedWalk, WalkError>
where
    F: FnMut(PageRequest) -> Result<Value, WalkError>,
    C: FnMut() -> i64,
{
    walk_selected(read, started_at_ms, now_ms, fetch, None)
}

/// Complete the walk while retaining only the newest matching bot comment.
/// The full thread is not needed for an edit-last ownership check.
pub fn walk_newest_bot_comment<F, C>(
    slug: &str,
    started_at_ms: i64,
    now_ms: C,
    fetch: F,
) -> Result<CompletedWalk, WalkError>
where
    F: FnMut(PageRequest) -> Result<Value, WalkError>,
    C: FnMut() -> i64,
{
    let login = crate::github::credential::bot_login(&format!(
        "{}{slug}",
        crate::github::credential::APP_PREFIX
    ))
    .ok_or(WalkError::InvalidResponse)?;
    walk_selected(
        ListRead::IssueComments,
        started_at_ms,
        now_ms,
        fetch,
        Some(&login),
    )
}

fn walk_selected<F, C>(
    read: ListRead,
    started_at_ms: i64,
    mut now_ms: C,
    mut fetch: F,
    newest_login: Option<&str>,
) -> Result<CompletedWalk, WalkError>
where
    F: FnMut(PageRequest) -> Result<Value, WalkError>,
    C: FnMut() -> i64,
{
    let mut items = Vec::new();
    let expires_at_ms =
        started_at_ms.saturating_add(crate::github::receipt::DEFAULT_CLAIM_LEASE_SECONDS * 1000);
    for page in 1..=MAX_PAGES {
        check_lease(expires_at_ms, now_ms())?;
        let response = fetch(PageRequest {
            read,
            page,
            per_page: PER_PAGE,
        })?;
        check_lease(expires_at_ms, now_ms())?;
        let page_items = match read {
            ListRead::IssueComments => response.as_array(),
            ListRead::InstallationRepositories => {
                response.get("repositories").and_then(Value::as_array)
            }
        }
        .ok_or(WalkError::InvalidResponse)?;
        if page_items.len() > PER_PAGE {
            return Err(WalkError::InvalidResponse);
        }
        let done = page_items.len() < PER_PAGE;
        if let Some(login) = newest_login {
            if let Some(newest) = page_items.iter().rev().find(|item| {
                item.pointer("/user/login")
                    .and_then(Value::as_str)
                    .is_some_and(|actual| actual.eq_ignore_ascii_case(login))
                    && item.pointer("/user/type").and_then(Value::as_str) == Some("Bot")
            }) {
                items.clear();
                items.push(newest.clone());
            }
        } else {
            items.extend(page_items.iter().cloned());
        }
        if done {
            return Ok(CompletedWalk { read, items });
        }
    }
    Err(WalkError::Incomplete)
}
