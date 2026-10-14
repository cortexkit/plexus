//! Keep source lookups off the paid web-search backend without blocking prose searches.

use super::WebSearchQuery;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum CodeLookup {
    GithubRepository,
    RawGithub,
    GistGithub,
    DocsRs,
    CratesIo,
    LibRs,
    PkgGoDev,
    NpmPackage,
    PypiProject,
    HexToken,
}

pub(super) fn classify(query: &WebSearchQuery) -> Option<CodeLookup> {
    query
        .include_domains
        .iter()
        .find_map(|domain| code_target(domain))
        .or_else(|| query.query.split(query_separator).find_map(query_target))
        .or_else(|| hex_token(&query.query).then_some(CodeLookup::HexToken))
}

fn query_separator(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            '\'' | '"' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ',' | ';'
        )
}

fn query_target(value: &str) -> Option<CodeLookup> {
    let explicit_target = value
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("site:"))
        || value
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        || value
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"));
    // A bare host in prose is not a URL target; a scheme-less URL must name a path.
    if !explicit_target
        && !value
            .split_once('/')
            .is_some_and(|(_, path)| !path.is_empty())
    {
        return None;
    }
    code_target(value)
}

fn code_target(value: &str) -> Option<CodeLookup> {
    let value = if value
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("site:"))
    {
        &value[5..]
    } else {
        value
    };
    let value = if value
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
    {
        &value[8..]
    } else if value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
    {
        &value[7..]
    } else {
        value
    };
    let (host, suffix) = value.split_once('/').unwrap_or((value, ""));
    let host = host.split(['?', '#']).next().unwrap_or_default();
    let host = host.rsplit('@').next().unwrap_or_default();
    let host = host.split(':').next().unwrap_or_default();
    let host = host.to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    let path = suffix.split(['?', '#']).next().unwrap_or_default();
    match host {
        "github.com" => {
            let mut segments = path.trim_end_matches('/').split('/');
            let owner = segments.next().unwrap_or_default();
            let repo = segments.next().unwrap_or_default();
            if owner.is_empty() || repo.is_empty() {
                return None;
            }
            match segments.next() {
                None | Some("blob" | "tree" | "raw" | "commit" | "commits" | "compare") => {
                    Some(CodeLookup::GithubRepository)
                }
                // Discussions and release notes remain web-search material, not source lookups.
                Some(_) => None,
            }
        }
        "raw.githubusercontent.com" => Some(CodeLookup::RawGithub),
        "gist.githubusercontent.com" => Some(CodeLookup::GistGithub),
        "docs.rs" => Some(CodeLookup::DocsRs),
        "crates.io" => Some(CodeLookup::CratesIo),
        "lib.rs" => Some(CodeLookup::LibRs),
        "pkg.go.dev" => Some(CodeLookup::PkgGoDev),
        "npmjs.com" if path.starts_with("package/") => Some(CodeLookup::NpmPackage),
        "pypi.org" if path.starts_with("project/") => Some(CodeLookup::PypiProject),
        _ => None,
    }
}

fn hex_token(query: &str) -> bool {
    // Split on non-hex characters, so a 40-character substring of a longer hash cannot match.
    query
        .split(|character: char| !character.is_ascii_hexdigit())
        .any(|token| matches!(token.len(), 40 | 64))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[test]
fn url_authorities_cannot_bypass_code_lookup() {
    for target in [
        "https://github.com:443/owner/repo",
        "user@github.com/owner/repo",
        "https://user:pass@github.com:443/owner/repo",
    ] {
        assert_eq!(
            code_target(target),
            Some(CodeLookup::GithubRepository),
            "URL authority must resolve the code host"
        );
    }
    assert_eq!(
        code_target("https://github.com@evil.example/owner/repo"),
        None
    );
}
