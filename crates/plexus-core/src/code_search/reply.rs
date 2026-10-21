//! Parse grep.app MCP text blocks: repository, path and numbered snippet headers.
//! The captured server replies contain text, not structured matches.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_MATCHES: usize = 20;
pub const MAX_LINES_PER_MATCH: usize = 100;
pub const MAX_TEXT_BYTES: usize = 32 * 1024;
const PARSED_TEXT_BUDGET: usize = 24 * 1024;
/// Longest code line returned, in bytes. grep.app often matches minified
/// bundles whose single line would otherwise fill the whole text budget.
const MAX_LINE_BYTES: usize = 500;
/// Appended to a line cut at [`MAX_LINE_BYTES`].
const LINE_CUT_MARKER: &str = "…";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeLine {
    pub number: u64,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeMatch {
    pub repo: String,
    pub path: String,
    pub lines: Vec<CodeLine>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CodeSearchResponse {
    pub matches: Vec<CodeMatch>,
    pub truncated: bool,
}

pub fn parse_reply(body: &Value) -> Result<CodeSearchResponse, &'static str> {
    if body.get("isError").and_then(Value::as_bool) == Some(true) {
        return Err("vendor refused");
    }
    let content = body
        .get("content")
        .and_then(Value::as_array)
        .ok_or("missing content")?;
    let mut response = CodeSearchResponse {
        matches: Vec::new(),
        truncated: false,
    };
    let mut budget = PARSED_TEXT_BUDGET;
    for block in content {
        let text = block
            .get("text")
            .and_then(Value::as_str)
            .filter(|_| block["type"] == "text")
            .ok_or("non-text content")?;
        if text == "No results found for your query." {
            continue;
        }
        if response.matches.len() == MAX_MATCHES {
            response.truncated = true;
            break;
        }
        let mut lines = text.lines();
        let repo = lines
            .next()
            .and_then(|v| v.strip_prefix("Repository: "))
            .filter(|v| !v.is_empty())
            .ok_or("missing repository")?;
        let path = lines
            .next()
            .and_then(|v| v.strip_prefix("Path: "))
            .filter(|v| !v.is_empty())
            .ok_or("missing path")?;
        if repo.len() > 512 || path.len() > 2048 {
            return Err("oversized header");
        }
        if repo.len() + path.len() > budget {
            response.truncated = true;
            break;
        }
        budget -= repo.len() + path.len();
        let mut hit = CodeMatch {
            repo: repo.to_string(),
            path: path.to_string(),
            lines: Vec::new(),
        };
        let mut number: Option<u64> = None;
        let mut budget_spent = false;
        // Blank lines seen since the last code line, with the number each
        // would carry. grep.app separates snippets with blank lines and ends a
        // block with one, so blanks are kept only once more code follows them.
        let mut pending: Vec<(u64, &str)> = Vec::new();
        'lines: for line in lines {
            // The format carries snippet headers in-band with public file
            // content, so a header counts only where grep.app puts one: before
            // the first snippet, or right after a blank separator line.
            // Anything else, malformed or not, is a line of code.
            if number.is_none() || !pending.is_empty() {
                if let Some(first) = snippet_header(line) {
                    pending.clear();
                    number = Some(first);
                    continue;
                }
            }
            let Some(n) = number else {
                continue;
            };
            number = Some(n.checked_add(1).ok_or("line number overflow")?);
            pending.push((n, line));
            if line.trim().is_empty() {
                continue;
            }
            for (n, line) in pending.drain(..) {
                if hit.lines.len() == MAX_LINES_PER_MATCH {
                    response.truncated = true;
                    break 'lines;
                }
                let (text, cut) = cap_line(line);
                if text.len() > budget {
                    budget_spent = true;
                    break 'lines;
                }
                budget -= text.len();
                response.truncated |= cut;
                hit.lines.push(CodeLine { number: n, text });
            }
        }
        // The text budget ran out inside this match: keep what it has (a match
        // with no lines carries no code, so it is dropped), mark the reply
        // truncated and stop. The truncation flag never excuses a block that
        // has no snippet at all; that is a malformed reply.
        if budget_spent {
            response.truncated = true;
            if !hit.lines.is_empty() {
                response.matches.push(hit);
            }
            break;
        }
        if hit.lines.is_empty() {
            return Err("missing snippet");
        }
        response.matches.push(hit);
    }
    Ok(response)
}

/// The first line number a well-formed `--- Snippet N (Line M) ---` header
/// names, or `None` for any other line.
fn snippet_header(line: &str) -> Option<u64> {
    let (index, first) = line
        .strip_prefix("--- Snippet ")?
        .strip_suffix(") ---")?
        .split_once(" (Line ")?;
    let is_number = |value: &str| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
    if !is_number(index) || !is_number(first) {
        return None;
    }
    first.parse::<u64>().ok().filter(|n| *n > 0)
}

/// The line as returned, cut at [`MAX_LINE_BYTES`] on a character boundary
/// with a marker appended, and whether it was cut.
fn cap_line(line: &str) -> (String, bool) {
    if line.len() <= MAX_LINE_BYTES {
        return (line.to_string(), false);
    }
    let mut end = MAX_LINE_BYTES - LINE_CUT_MARKER.len();
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    (format!("{}{LINE_CUT_MARKER}", &line[..end]), true)
}

/// The text and structured paths share the parsed matches; vendor prose is never forwarded.
pub fn render(response: &CodeSearchResponse) -> String {
    render_with_repo_filter(response, None)
}

/// Render matches and explain possible repository-filter misses on empty replies.
pub fn render_with_repo_filter(response: &CodeSearchResponse, repo_filter: Option<&str>) -> String {
    let mut text = format!("{} code matches. Caps: {MAX_MATCHES} matches, {MAX_LINES_PER_MATCH} lines per match, {MAX_TEXT_BYTES} text bytes.\n", response.matches.len());
    if response.matches.is_empty() && repo_filter.is_some() {
        text.push_str("A repository filter may match no indexed repository. Check the owner/name or retry without the filter. Zero matches do not prove the code does not exist.\n");
    }
    for hit in &response.matches {
        text.push_str(&format!("\n{} {}\n", hit.repo, hit.path));
        for line in &hit.lines {
            text.push_str(&format!("{}: {}\n", line.number, line.text));
        }
    }
    if response.truncated {
        text.push_str("\nResults truncated. Narrow query, repo or path.\n");
    }
    if text.len() > MAX_TEXT_BYTES {
        let suffix = "\nText truncated. Narrow query, repo or path.\n";
        let mut end = MAX_TEXT_BYTES - suffix.len();
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str(suffix);
    }
    text
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    #[ignore = "performance measurement"]
    fn measure_bounded_rendering() {
        let response = parse_reply(&captured_reply()).unwrap();
        let started = std::time::Instant::now();
        for _ in 0..10_000 {
            std::hint::black_box(render(&response));
        }
        println!("10,000 bounded code replies: {:?}", started.elapsed());
    }

    pub fn captured_reply() -> Value {
        fixture_reply(include_str!("../../tests/fixtures/grep_app/search.sse"))
    }

    pub fn captured_empty_reply() -> Value {
        fixture_reply(include_str!("../../tests/fixtures/grep_app/empty.sse"))
    }

    fn fixture_reply(sse: &str) -> Value {
        let data = sse.lines().find_map(|s| s.strip_prefix("data: ")).unwrap();
        serde_json::from_str::<Value>(data).unwrap()["result"].clone()
    }

    #[test]
    fn live_reply_parses_and_renders_numbered_code() {
        let response = parse_reply(&captured_reply()).unwrap();
        assert_eq!(response.matches.len(), 10);
        assert!(!response.truncated);
        let first = &response.matches[0];
        assert_eq!(first.repo, "rust-lang/rust");
        assert_eq!(first.path, "library/std/src/collections/hash/set.rs");
        assert_eq!(first.lines[0].number, 164);
        assert_eq!(
            first.lines[5],
            CodeLine {
                number: 169,
                text: "    pub fn with_capacity(capacity: usize) -> HashSet<T, RandomState> {"
                    .into()
            }
        );
        assert!(first
            .lines
            .iter()
            .any(|l| l.number == 213 && l.text.contains("pub fn with_capacity_in")));
        let text = render(&response);
        assert!(text.contains("rust-lang/rust library/std/src/collections/hash/set.rs\n164:"));
        assert!(text.contains("169:     pub fn with_capacity"));
        assert!(text.len() <= MAX_TEXT_BYTES);
        assert!(parse_reply(&fixture_reply(include_str!(
            "../../tests/fixtures/grep_app/empty.sse"
        )))
        .unwrap()
        .matches
        .is_empty());
    }

    #[test]
    fn zero_match_repo_filter_explains_no_results() {
        let response = CodeSearchResponse {
            matches: Vec::new(),
            truncated: false,
        };
        let filtered = render_with_repo_filter(&response, Some("golang/go"));
        for sentence in [
            "A repository filter may match no indexed repository.",
            "Check the owner/name or retry without the filter.",
            "Zero matches do not prove the code does not exist.",
        ] {
            assert!(
                filtered.contains(sentence),
                "repo-filtered zero matches must explain possible index mismatch: missing {sentence:?}"
            );
        }
        assert!(
            !render(&response).contains("A repository filter may match no indexed repository."),
            "unfiltered zero-match results should not imply a repository filter was used"
        );
    }

    #[test]
    fn reply_caps_and_malformed_vendor_data_are_defended() {
        let first = captured_reply()["content"][0].clone();
        let response = parse_reply(&json!({"content":vec![first; 30]})).unwrap();
        assert!(response.truncated);
        assert!(response.matches.len() <= MAX_MATCHES);
        assert!(render(&response).len() <= MAX_TEXT_BYTES);
        let body = json!({"content":[{"type":"text","text":format!("Repository: o/r\nPath: a.rs\n--- Snippet 1 (Line 1) ---\n{}", "é".repeat(40_000))}]});
        assert!(parse_reply(&body).unwrap().truncated);
        for body in [
            json!({"isError":true,"content":[]}),
            json!({"content":[{"type":"text","text":"unexpected vendor diagnostics"}]}),
            json!({}),
        ] {
            assert!(parse_reply(&body).is_err());
        }
    }

    /// A match with no code lines is never returned, and a truncation earlier
    /// in the reply must not excuse a later block that has no snippet: that
    /// block is malformed whatever came before it.
    #[test]
    fn truncation_never_admits_an_empty_match() {
        let long_match = format!(
            "Repository: o/r\nPath: long.rs\n--- Snippet 1 (Line 1) ---\n{}",
            "x\n".repeat(MAX_LINES_PER_MATCH + 5)
        );
        let no_snippet = "Repository: o/r\nPath: header-only.rs";
        let body = json!({"content":[
            {"type":"text","text":long_match},
            {"type":"text","text":no_snippet},
        ]});
        assert_eq!(
            parse_reply(&body).err(),
            Some("missing snippet"),
            "a header-only block after a truncated match is malformed"
        );

        // A later match's first line overruns what the first match left of
        // the text budget: the reply is truncated and carries no line-less
        // match.
        let filler = format!(
            "Repository: o/r\nPath: a.rs\n--- Snippet 1 (Line 1) ---\n{}",
            format!("{}\n", "y".repeat(244)).repeat(MAX_LINES_PER_MATCH)
        );
        let overrun = format!(
            "Repository: o/r\nPath: b.rs\n--- Snippet 1 (Line 1) ---\n{}",
            "z".repeat(MAX_LINE_BYTES)
        );
        let body = json!({"content":[
            {"type":"text","text":filler},
            {"type":"text","text":overrun},
        ]});
        let response = parse_reply(&body).unwrap();
        assert!(response.truncated);
        assert_eq!(response.matches.len(), 1, "the overrun match is dropped");
        assert!(
            response.matches.iter().all(|hit| !hit.lines.is_empty()),
            "no returned match may be empty"
        );
    }

    /// grep.app separates snippets with blank lines and ends each block with
    /// one. Those lines are not part of the file, so they are never returned
    /// as numbered lines; a blank line between code lines still is.
    #[test]
    fn blank_separator_lines_are_not_numbered() {
        let response = parse_reply(&captured_reply()).unwrap();
        for hit in &response.matches {
            assert!(
                !hit.lines.last().unwrap().text.trim().is_empty(),
                "a match must not end in a separator line: {}",
                hit.path
            );
        }
        let numbers = response.matches[0]
            .lines
            .iter()
            .map(|line| line.number)
            .collect::<Vec<_>>();
        assert_eq!(
            numbers.iter().filter(|n| (164..208).contains(*n)).max(),
            Some(&174),
            "the separator after line 174 must not be numbered 175 and 176"
        );
        let inner = json!({"content":[{"type":"text","text":
            "Repository: o/r\nPath: a.rs\n--- Snippet 1 (Line 10) ---\nfn a() {}\n\nfn b() {}\n\n"}]});
        let lines = &parse_reply(&inner).unwrap().matches[0].lines;
        assert_eq!(
            lines
                .iter()
                .map(|line| (line.number, line.text.as_str()))
                .collect::<Vec<_>>(),
            [(10, "fn a() {}"), (11, ""), (12, "fn b() {}")],
            "a blank line between code lines is part of the file"
        );
    }

    /// Snippet headers share the text with public file content, so a line
    /// that looks like one counts as a header only where grep.app puts one.
    /// Elsewhere, and whenever it is malformed, it is a line of code.
    #[test]
    fn header_shaped_code_lines_stay_code() {
        let text = "Repository: o/r\nPath: notes.md\n--- Snippet 1 (Line 1) ---\nintro\n--- Snippet 1 (Line 900) ---\n--- Snippet notes\nbody\n\n\n--- Snippet 2 (Line 50) ---\nlater";
        let response =
            parse_reply(&json!({"content":[{"type":"text","text":text}]})).expect(
                "a header-shaped line in a public file must not fail the whole reply",
            );
        assert_eq!(
            response.matches[0]
                .lines
                .iter()
                .map(|line| (line.number, line.text.as_str()))
                .collect::<Vec<_>>(),
            [
                (1, "intro"),
                (2, "--- Snippet 1 (Line 900) ---"),
                (3, "--- Snippet notes"),
                (4, "body"),
                (50, "later"),
            ],
            "only the header after the blank separator renumbers lines"
        );
    }

    /// One very long line (a minified bundle) is cut on a character boundary
    /// and marked, so it cannot use up the text budget for every other match.
    #[test]
    fn long_lines_are_cut_and_marked() {
        let long = "é".repeat(20_000);
        let body = json!({"content":[
            {"type":"text","text":format!("Repository: o/r\nPath: bundle.min.js\n--- Snippet 1 (Line 1) ---\n{long}")},
            {"type":"text","text":"Repository: o/r\nPath: b.rs\n--- Snippet 1 (Line 7) ---\nfn b() {}"},
        ]});
        let response = parse_reply(&body).unwrap();
        let cut = &response.matches[0].lines[0].text;
        assert!(
            cut.len() <= MAX_LINE_BYTES && cut.ends_with(LINE_CUT_MARKER),
            "a long line must be cut to {MAX_LINE_BYTES} bytes and marked: {} bytes",
            cut.len()
        );
        assert!(response.truncated, "a cut line marks the reply truncated");
        assert_eq!(
            response.matches.len(),
            2,
            "the matches after a long line are still returned"
        );
    }
}
