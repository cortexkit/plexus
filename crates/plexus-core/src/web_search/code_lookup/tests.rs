use std::collections::BTreeMap;

use serde_json::json;

use super::{classify, CodeLookup};
use crate::web_search::WebSearchQuery;

fn lookup(query: &str, domains: &[&str]) -> Option<CodeLookup> {
    let arguments = json!({"query": query, "include_domains": domains});
    classify(&WebSearchQuery::parse(arguments.as_object().unwrap()).unwrap())
}

#[test]
fn code_hosts_and_repository_paths_are_refused() {
    for (target, expected) in [
        ("github.com/owner/repo", CodeLookup::GithubRepository),
        (
            "raw.githubusercontent.com/owner/repo/main/file",
            CodeLookup::RawGithub,
        ),
        (
            "gist.githubusercontent.com/owner/id/raw/file",
            CodeLookup::GistGithub,
        ),
        ("docs.rs/tokio/latest/tokio/", CodeLookup::DocsRs),
        ("crates.io/crates/tokio", CodeLookup::CratesIo),
        ("lib.rs/crates/tokio", CodeLookup::LibRs),
        ("pkg.go.dev/net/http", CodeLookup::PkgGoDev),
        ("npmjs.com/package/typescript", CodeLookup::NpmPackage),
        ("pypi.org/project/requests/", CodeLookup::PypiProject),
    ] {
        let (host, path) = target.split_once('/').unwrap_or((target, ""));
        for query in [
            format!("site:{target} source"),
            format!("source https://{target}"),
            format!("source http://www.{target}"),
            format!("\"HTTPS://WWW.{}/{path}\"", host.to_ascii_uppercase()),
            format!("source {target}"),
        ] {
            assert_eq!(lookup(&query, &[]), Some(expected), "{query}");
        }
    }
    for host in [
        "raw.githubusercontent.com",
        "gist.githubusercontent.com",
        "docs.rs",
        "crates.io",
        "lib.rs",
        "pkg.go.dev",
    ] {
        assert!(lookup(&format!("site:{host} API"), &[]).is_some());
        assert!(lookup(&format!("https://{host}"), &[]).is_some());
        assert_eq!(lookup(&format!("{host} API"), &[]), None);
    }
    for path in ["blob", "tree", "raw", "commit", "commits", "compare"] {
        for suffix in ["", "/main/src/lib.rs"] {
            let query = format!("site:github.com/owner/repo/{path}{suffix}");
            assert_eq!(
                lookup(&query, &[]),
                Some(CodeLookup::GithubRepository),
                "{query}"
            );
        }
    }
    for query in [
        "SITE:HTTPS://WWW.GitHub.COM/owner/repo/",
        "(https://github.com/owner/repo?tab=readme#readme)",
        "https://github.com/owner/repo/blob/main/lib.rs?plain=1",
    ] {
        assert_eq!(
            lookup(query, &[]),
            Some(CodeLookup::GithubRepository),
            "{query}"
        );
    }
}

#[test]
fn github_discussions_and_release_notes_are_allowed() {
    for path in ["issues", "pull", "pulls", "discussions", "releases", "wiki"] {
        for suffix in ["", "/123"] {
            for prefix in ["site:", "https://", "http://www."] {
                let query = format!("{prefix}github.com/owner/repo/{path}{suffix} discussion");
                assert_eq!(
                    lookup(&query, &[]),
                    None,
                    "GitHub discussions must stay allowed: {query}"
                );
            }
        }
    }
    for target in [
        "github.com",
        "github.com/",
        "github.com/owner",
        "github.com/owner/",
        "github.com/owner/repo/actions",
        "npmjs.com",
        "npmjs.com/",
        "npmjs.com/about",
        "pypi.org",
        "pypi.org/help",
        "notgithub.com/owner/repo",
        "github.com.evil/owner/repo",
        "docs.rs.example.org/tokio",
        "mydocs.rs",
        "gitlab.com/owner/repo",
    ] {
        assert_eq!(
            lookup(&format!("site:{target} discussion"), &[]),
            None,
            "{target}"
        );
    }
}

#[test]
fn include_domains_code_hosts_are_refused() {
    for (host, expected) in [
        ("raw.githubusercontent.com", CodeLookup::RawGithub),
        ("gist.githubusercontent.com", CodeLookup::GistGithub),
        ("docs.rs", CodeLookup::DocsRs),
        ("crates.io", CodeLookup::CratesIo),
        ("lib.rs", CodeLookup::LibRs),
        ("pkg.go.dev", CodeLookup::PkgGoDev),
    ] {
        assert_eq!(
            lookup("API documentation", &["example.org", host]),
            Some(expected),
            "include_domains must refuse code host {host}"
        );
        assert_eq!(
            lookup(
                "API documentation",
                &[&format!("WWW.{}", host.to_ascii_uppercase())]
            ),
            Some(expected),
            "{host}"
        );
    }
    // The existing argument schema only accepts bare hostnames in include_domains.
    for host in ["github.com", "npmjs.com", "pypi.org", "docs.python.org"] {
        assert_eq!(lookup("API documentation", &[host]), None, "{host}");
    }
}

#[test]
fn exact_hex_lengths_and_non_hex_boundaries_are_required() {
    for length in [40, 64] {
        let hex = "aB09".repeat(length / 4);
        for query in [
            hex.clone(),
            format!("\"{hex}\""),
            format!("g{hex}z"),
            format!("é{hex}🙂"),
        ] {
            assert_eq!(
                lookup(&query, &[]),
                Some(CodeLookup::HexToken),
                "exact {length}-hex token must refuse: {query}"
            );
        }
    }
    for length in [39, 41, 63, 65, 80, 128] {
        let hex = "a".repeat(length);
        assert_eq!(lookup(&hex, &[]), None, "length {length}");
        assert_eq!(lookup(&format!("({hex})"), &[]), None, "length {length}");
    }
    assert_eq!(lookup(&format!("{}f", "a".repeat(40)), &[]), None);
    assert_eq!(lookup(&format!("0{}", "a".repeat(64)), &[]), None);
}

/// A hex literal written with `0x` (an Ethereum address, say) is not a
/// commit SHA: git never writes one that way. Bare 40- and 64-hex tokens stay
/// refused, since on real traffic they are commit and dependency-checksum
/// lookups.
#[test]
fn hex_literals_after_0x_are_not_source_lookups() {
    for query in [
        "contract 0xdAC17F958D2ee523a2206206994597C13D831ec7 audit".to_string(),
        format!("storage slot 0X{}", "ab".repeat(32)),
    ] {
        assert_eq!(
            lookup(&query, &[]),
            None,
            "a 0x literal must be served: {query}"
        );
    }
    for query in [
        "dAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
        format!("sha256 {} malware", "c6".repeat(32)),
        format!("x{}", "ab".repeat(20)),
    ] {
        assert_eq!(
            lookup(&query, &[]),
            Some(CodeLookup::HexToken),
            "a bare hex token must still refuse: {query}"
        );
    }
}

#[test]
fn gist_pages_are_source_lookups() {
    assert_eq!(
        lookup("https://gist.github.com/someone/0123abcd", &[]),
        Some(CodeLookup::GistGithub),
        "a gist.github.com page must refuse"
    );
    assert_eq!(
        lookup("API documentation", &["gist.github.com"]),
        Some(CodeLookup::GistGithub),
        "gist.github.com in include_domains must refuse"
    );
}

#[test]
fn prose_and_explicit_documentation_examples_are_allowed() {
    for query in [
        "site:github.com/owner/repo/issues async cancellation discussion",
        "rust async book",
        "site:docs.python.org asyncio",
        "npm package publish provenance documentation",
        "tokio Rust source code examples",
    ] {
        assert_eq!(lookup(query, &[]), None, "{query}");
    }
    assert_eq!(lookup(&"a".repeat(39), &[]), None);
    assert_eq!(lookup(&"a".repeat(41), &[]), None);
}

#[test]
fn synthetic_corpus_classification_matches_explicit_decisions() {
    let rows: Vec<serde_json::Value> =
        include_str!("../../../tests/fixtures/web_search_corpus/synthetic.jsonl")
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
    let reviews: Vec<serde_json::Value> =
        include_str!("../../../tests/fixtures/web_search_corpus/refusal_review.jsonl")
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
    let documentation_reviews: Vec<serde_json::Value> =
        include_str!("../../../tests/fixtures/web_search_corpus/documentation_review.jsonl")
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
    assert!((150..=300).contains(&rows.len()));
    assert_eq!(
        documentation_reviews,
        reviews
            .iter()
            .filter(|row| row["documentation_or_discussion_candidate"] == true)
            .cloned()
            .collect::<Vec<_>>()
    );
    let mut inventory: BTreeMap<usize, &serde_json::Value> = reviews
        .iter()
        .map(|row| (row["corpus_line"].as_u64().unwrap() as usize, row))
        .collect();
    assert_eq!(
        inventory.len(),
        reviews.len(),
        "inventory cannot repeat corpus lines"
    );
    let mut cases = std::collections::BTreeSet::new();
    let mut edges = std::collections::BTreeSet::new();
    let mut counts = BTreeMap::new();
    let mut expected_counts = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        let case = row["case"].as_str().unwrap();
        assert!(cases.insert(case), "duplicate case: {case}");
        edges.insert(row["edge"].as_str().unwrap());
        let domains: Vec<&str> = row["include_domains"]
            .as_array()
            .unwrap()
            .iter()
            .map(|domain| domain.as_str().unwrap())
            .collect();
        let decision = lookup(row["query"].as_str().unwrap(), &domains);
        let label = decision.map(|decision| match decision {
            CodeLookup::GithubRepository => "GithubRepository",
            CodeLookup::RawGithub => "raw.githubusercontent.com",
            CodeLookup::GistGithub => "gist.githubusercontent.com",
            CodeLookup::DocsRs => "docs.rs",
            CodeLookup::CratesIo => "crates.io",
            CodeLookup::LibRs => "lib.rs",
            CodeLookup::PkgGoDev => "pkg.go.dev",
            CodeLookup::NpmPackage => "NpmPackage",
            CodeLookup::PypiProject => "PypiProject",
            CodeLookup::HexToken => "HexToken",
        });
        // Expected decisions are authored in the synthetic fixture, not inferred by the guard.
        let expected = if row["expected_rule"].is_null() {
            None
        } else {
            Some(row["expected_rule"].as_str().unwrap())
        };
        assert_eq!(label, expected, "{case}: {}", row["query"]);
        let review = inventory.remove(&(index + 1));
        assert_eq!(
            review.is_some(),
            expected.is_some(),
            "{case}: refusal inventory"
        );
        if let Some(review) = review {
            assert_eq!(review["query"], row["query"], "{case}");
            assert_eq!(review["rule"], row["expected_rule"], "{case}");
            assert_eq!(
                review["documentation_or_discussion_candidate"],
                row["documentation_or_discussion_candidate"],
                "{case}"
            );
        }
        *counts.entry(label).or_insert(0_usize) += 1;
        *expected_counts.entry(expected).or_insert(0_usize) += 1;
    }
    assert!(inventory.is_empty(), "inventory cannot invent corpus lines");
    assert_eq!(counts, expected_counts);
    assert_eq!(
        counts.keys().copied().collect::<Vec<_>>(),
        vec![
            None,
            Some("GithubRepository"),
            Some("HexToken"),
            Some("NpmPackage"),
            Some("PypiProject"),
            Some("crates.io"),
            Some("docs.rs"),
            Some("gist.githubusercontent.com"),
            Some("lib.rs"),
            Some("pkg.go.dev"),
            Some("raw.githubusercontent.com")
        ]
    );
    assert_eq!(
        edges,
        std::collections::BTreeSet::from([
            "authority",
            "discussion-target",
            "documentation",
            "hex-boundary",
            "host-mention",
            "include-domain",
            "precedence",
            "registry-target",
            "source-target",
        ])
    );
    println!("synthetic corpus: {} rows; {counts:?}", rows.len());
}
