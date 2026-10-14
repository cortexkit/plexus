//! Closed model arguments and their grep.app spelling.

use serde_json::{json, Map, Value};

use super::CodeSearchRefusal;
const MAX_FILTER_CHARS: usize = 500;

pub struct CodeSearchQuery {
    pub query: String,
    regex: bool,
    match_case: bool,
    whole_words: bool,
    repo: Option<String>,
    path: Option<String>,
    language: Option<Vec<String>>,
}

impl CodeSearchQuery {
    pub fn parse(args: &Map<String, Value>) -> Result<Self, CodeSearchRefusal> {
        let invalid = |field: &str| CodeSearchRefusal::invalid(field);
        for field in args.keys() {
            if !matches!(
                field.as_str(),
                "query" | "regex" | "match_case" | "whole_words" | "repo" | "path" | "language"
            ) {
                return Err(invalid(field));
            }
        }
        let query = args
            .get("query")
            .and_then(Value::as_str)
            .map(str::trim)
            .ok_or_else(|| invalid("query"))?;
        if query.trim().is_empty() || query.chars().count() > 500 {
            return Err(invalid("query"));
        }
        let boolean = |field: &str| match args.get(field) {
            None | Some(Value::Null) => Ok(false),
            Some(value) => value.as_bool().ok_or_else(|| invalid(field)),
        };
        let string = |field: &str| match args.get(field) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => value
                .as_str()
                .filter(|s| s.chars().count() <= MAX_FILTER_CHARS)
                .map(|s| Some(s.to_string()))
                .ok_or_else(|| invalid(field)),
        };
        let language = match args.get("language") {
            None | Some(Value::Null) => None,
            Some(value) => {
                let values = value
                    .as_array()
                    .filter(|v| v.len() <= 10)
                    .ok_or_else(|| invalid("language"))?;
                Some(
                    values
                        .iter()
                        .map(|v| {
                            v.as_str()
                                .filter(|s| s.chars().count() <= MAX_FILTER_CHARS)
                                .map(str::to_string)
                                .ok_or_else(|| invalid("language"))
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                )
            }
        };
        Ok(Self {
            query: query.to_string(),
            regex: boolean("regex")?,
            match_case: boolean("match_case")?,
            whole_words: boolean("whole_words")?,
            repo: string("repo")?,
            path: string("path")?,
            language,
        })
    }

    pub fn vendor_args(&self) -> Value {
        let mut args = json!({
            "query": self.query,
            "useRegexp": self.regex,
            "matchCase": self.match_case,
            "matchWholeWords": self.whole_words,
        });
        if let Some(repo) = &self.repo {
            args["repo"] = json!(repo);
        }
        if let Some(path) = &self.path {
            args["path"] = json!(path);
        }
        if let Some(language) = &self.language {
            args["language"] = json!(language);
        }
        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_filters_are_bounded_and_null_is_absent() {
        let args = json!({"query":format!(" {} ", "x".repeat(500)), "repo":null, "path":null, "language":null, "regex":null});
        let query = CodeSearchQuery::parse(args.as_object().unwrap())
            .expect("trimmed query and absent null filters are valid");
        assert_eq!(query.vendor_args()["query"], "x".repeat(500));
        for args in [
            json!({"query":"x", "repo":"x".repeat(501)}),
            json!({"query":"x", "path":"x".repeat(501)}),
            json!({"query":"x", "language":["x".repeat(501)]}),
        ] {
            assert!(
                CodeSearchQuery::parse(args.as_object().unwrap()).is_err(),
                "filters must have a length cap"
            );
        }
    }

    #[test]
    fn argument_mapping_is_exact_and_closed() {
        let args = json!({"query":"foo.*bar", "regex":true, "match_case":true, "whole_words":true,
            "repo":"owner/repo", "path":"src/", "language":["Rust", "Go"]});
        let parsed = CodeSearchQuery::parse(args.as_object().unwrap()).unwrap();
        assert_eq!(
            parsed.vendor_args(),
            json!({"query":"foo.*bar", "useRegexp":true,
            "matchCase":true, "matchWholeWords":true, "repo":"owner/repo", "path":"src/", "language":["Rust", "Go"]})
        );
        assert_eq!(
            CodeSearchQuery::parse(json!({"query":"foo"}).as_object().unwrap())
                .unwrap()
                .vendor_args(),
            json!({"query":"foo", "useRegexp":false, "matchCase":false, "matchWholeWords":false})
        );
    }

    #[test]
    fn invalid_arguments_are_refused() {
        for (args, field) in [
            (json!({"query":"foo", "useRegexp":true}), "useRegexp"),
            (
                json!({"query":"foo", "agent_assertion":{}}),
                "agent_assertion",
            ),
            (json!({"query":" "}), "query"),
            (json!({"query":"x".repeat(501)}), "query"),
            (json!({"query":1}), "query"),
            (json!({}), "query"),
            (json!({"query":"x", "regex":"true"}), "regex"),
            (json!({"query":"x", "language":[1]}), "language"),
            (json!({"query":"x", "language":vec!["Rust";11]}), "language"),
        ] {
            let error = CodeSearchQuery::parse(args.as_object().unwrap())
                .err()
                .unwrap()
                .to_wire();
            assert_eq!(error["error"]["code"], "invalid_query");
            assert_eq!(error["error"]["field"], field);
        }
        assert!(
            CodeSearchQuery::parse(json!({"query":"é".repeat(500)}).as_object().unwrap()).is_ok()
        );
    }
}
