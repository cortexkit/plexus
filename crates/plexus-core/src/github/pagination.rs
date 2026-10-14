//! Bounded, read-only GitHub list walks shared by facade reads and the handle probe.
//!
//! The caller supplies a read-only page dispatcher (for example, a governed
//! `github.issue_comments.list` invoke). A completed walk is the only evidence
//! that an absent bot comment means not found.

use serde_json::Value;

pub const PER_PAGE: usize = 100;
pub const MAX_PAGES: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListRead {
    IssueComments,
    InstallationRepositories,
}

impl ListRead {
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
        let login = format!("{slug}[bot]");
        self.items.iter().rev().find(|item| {
            item.pointer("/user/login").and_then(Value::as_str) == Some(login.as_str())
                && item.pointer("/user/type").and_then(Value::as_str) == Some("Bot")
        })
    }
}

/// A list-dependent request must not dispatch without proof of its completed
/// pre-dispatch read. An incomplete or failed walk cannot yield this proof.
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
    mut now_ms: C,
    mut fetch: F,
) -> Result<CompletedWalk, WalkError>
where
    F: FnMut(PageRequest) -> Result<Value, WalkError>,
    C: FnMut() -> i64,
{
    let mut items = Vec::new();
    for page in 1..=MAX_PAGES {
        if now_ms().saturating_sub(started_at_ms)
            >= crate::github::config::claim_lease_seconds(None) * 1000
        {
            return Err(WalkError::LeaseExpired);
        }
        let response = fetch(PageRequest {
            read,
            page,
            per_page: PER_PAGE,
        })?;
        if now_ms().saturating_sub(started_at_ms)
            >= crate::github::config::claim_lease_seconds(None) * 1000
        {
            return Err(WalkError::LeaseExpired);
        }
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
        items.extend(page_items.iter().cloned());
        if done {
            return Ok(CompletedWalk { read, items });
        }
    }
    Err(WalkError::Incomplete)
}
