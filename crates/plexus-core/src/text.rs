//! Cutting text to a size limit without splitting a UTF-8 character.
//!
//! Callers keep their own limits and markers: a log line, an agent-visible
//! preview and an operator diagnostic each say differently that text was cut.
//! What they share is finding the cut point, which lives here once.

/// The longest prefix of `text` that is at most `max_bytes` bytes and ends on
/// a character boundary.
pub fn prefix_within_bytes(text: &str, max_bytes: usize) -> &str {
    let mut end = max_bytes.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Maximum UTF-8 bytes in one caller-supplied refusal echo, including its marker.
/// Keeping each echo small leaves room for context and JSON escaping within a
/// provider's 64 KiB model-visible result limit.
pub const REFUSAL_ECHO_BYTES: usize = 256;

/// Preserve ordinary argument names verbatim, but visibly shorten large echoes.
pub fn refusal_echo(text: &str) -> std::borrow::Cow<'_, str> {
    const MARKER: &str = "[shortened]";
    if text.len() <= REFUSAL_ECHO_BYTES {
        return std::borrow::Cow::Borrowed(text);
    }
    std::borrow::Cow::Owned(format!(
        "{}{MARKER}",
        prefix_within_bytes(text, REFUSAL_ECHO_BYTES - MARKER.len())
    ))
}

/// The first `max_chars` characters of `text`, and whether any were left out.
pub fn prefix_within_chars(text: &str, max_chars: usize) -> (&str, bool) {
    match text.char_indices().nth(max_chars) {
        Some((cut, _)) => (&text[..cut], true),
        None => (text, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_prefix_never_splits_a_character() {
        // "é" is two bytes and "😀" four, so most limits land inside one.
        let text = "aé😀b";
        let expected = [
            "", "a", "a", "aé", "aé", "aé", "aé", "aé😀", "aé😀b", "aé😀b",
        ];
        for (limit, want) in expected.iter().enumerate() {
            assert_eq!(
                prefix_within_bytes(text, limit),
                *want,
                "limit {limit}: cut on a character boundary"
            );
        }
        assert_eq!(prefix_within_bytes("", 3), "");
    }

    #[test]
    fn char_prefix_counts_characters_and_reports_a_cut() {
        let text = "aé😀b";
        let counted = "cut after a character count";
        assert_eq!(prefix_within_chars(text, 0), ("", true), "{counted}");
        assert_eq!(prefix_within_chars(text, 2), ("aé", true), "{counted}");
        assert_eq!(prefix_within_chars(text, 3), ("aé😀", true), "{counted}");
        assert_eq!(prefix_within_chars(text, 4), ("aé😀b", false), "{counted}");
        assert_eq!(prefix_within_chars(text, 9), ("aé😀b", false), "{counted}");
        assert_eq!(prefix_within_chars("", 0), ("", false), "{counted}");
    }
}

#[cfg(test)]
mod refusal_echo_tests {
    use super::refusal_echo;

    #[test]
    fn ordinary_echoes_are_identical_and_large_echoes_keep_utf8_and_a_marker() {
        for text in ["", "typo", &"x".repeat(256), &"🦀".repeat(64)] {
            assert_eq!(refusal_echo(text), text);
        }
        for text in ["x".repeat(70_000), "🦀".repeat(17_500), "\0".repeat(70_000)] {
            let echo = refusal_echo(&text);
            assert!(echo.len() <= 256);
            let prefix = echo.strip_suffix("[shortened]").unwrap();
            assert!(text.starts_with(prefix));
            assert!(prefix.len() >= 241);
        }
    }
}
