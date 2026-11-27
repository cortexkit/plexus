use super::model::{lower_hex, AgentPolicy, Class, Constraints, Request, RestRequest, MAX_INTEGER};
use crate::github::reads::bot::relative_path;
use crate::manifest::ActionBaseline;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

const REPO_PREFIX: &str = "/repos/{owner}/{repo}/";

#[derive(Debug, PartialEq, Eq)]
pub enum SuffixMatch<'a> {
    None,
    Unique(&'a str),
    Ambiguous,
}

impl AgentPolicy {
    /// Selects by the concrete bot read only; the caller must still check that
    /// the kind is served and the matching policy has been applied to the agent.
    pub fn match_repo_get_suffix(&self, repository: &str, args: &Value) -> SuffixMatch<'_> {
        let Some(rules) = self.rule_sets.github.as_ref() else {
            return SuffixMatch::None;
        };
        let Some(path) = suffix_segments(repository, args) else {
            return SuffixMatch::None;
        };
        let query = match args.get("query") {
            None => None,
            Some(Value::Object(query)) if query.values().all(Value::is_string) => Some(query),
            Some(_) => return SuffixMatch::None,
        };
        let mut matches = rules.kinds.iter().filter(|kind| {
            kind.requests.iter().any(|request| {
                suffix_get(request).is_some_and(|(rest, template)| {
                    rest.body.is_none()
                        && template_matches(template, &path)
                        && rest.query.as_ref().map_or_else(
                            || kind.class == Class::Read || query.is_none_or(Map::is_empty),
                            |constraints| query_matches(constraints, query),
                        )
                })
            })
        });
        match (matches.next(), matches.next()) {
            (Some(_), Some(_)) => SuffixMatch::Ambiguous,
            (Some(kind), None) => SuffixMatch::Unique(&kind.kind),
            (None, _) => SuffixMatch::None,
        }
    }
}

fn suffix_get(request: &Request) -> Option<(&RestRequest, &str)> {
    let Request::Rest(rest) = request else {
        return None;
    };
    if rest.method != "GET" || rest.host != "api.github.com" {
        return None;
    }
    let template = rest.path.strip_prefix(REPO_PREFIX)?;
    (!template.is_empty()).then_some((rest, template))
}

pub(super) fn is_suffix_get(request: &Request) -> bool {
    suffix_get(request).is_some_and(|(rest, template)| {
        let segments = template.split('/');
        let last = segments.clone().count() - 1;
        rest.body.is_none()
            && segments.enumerate().all(|(index, segment)| {
                matches!(segment, "{number}" | "{id}" | "{sha}" | "{name}")
                    || (tail(segment) && index == last)
                    || (plain(segment) && !segment.contains(['{', '}']))
            })
    })
}

fn query_matches(constraints: &Constraints<String>, query: Option<&Map<String, Value>>) -> bool {
    let fields = query.into_iter().flatten();
    fields.clone().all(|(name, _)| {
        !constraints.forbidden.contains(name)
            && (constraints.required.contains(name)
                || constraints.optional.contains(name)
                || constraints.fixed.contains_key(name))
    }) && constraints
        .required
        .iter()
        .all(|name| query.is_some_and(|fields| fields.contains_key(name)))
        && constraints.fixed.iter().all(|(name, value)| {
            query
                .and_then(|fields| fields.get(name))
                .and_then(Value::as_str)
                == Some(value)
        })
}

// See aft-extractor-github-rest-graphql-v1.md in shared-bot-permissions
// (SHA-256 be5018badae92b4d39a91da029b4d0be27c1b4428298f025239117768cd1258e)
// for normalization and the closed list of path parameter types.
fn suffix_segments(repository: &str, args: &Value) -> Option<Vec<String>> {
    let (bound_owner, bound_repo) = repository.split_once('/')?;
    let owner = args.get("owner")?.as_str()?;
    let repo = args.get("repo")?.as_str()?;
    if !owner.eq_ignore_ascii_case(bound_owner)
        || !repo.eq_ignore_ascii_case(bound_repo)
        || !valid_owner(owner)
        || !valid_repo(repo)
    {
        return None;
    }
    // Match the same encoded suffix the REST transport appends after the
    // verified owner/repo; decode each wire segment exactly once.
    let path = relative_path(args.get("path")?.as_str()?)?;
    path.strip_prefix('/')?
        .split('/')
        .map(decode_segment)
        .collect()
}

fn decode_segment(segment: &str) -> Option<String> {
    let mut bytes = segment.bytes();
    let mut decoded = Vec::with_capacity(segment.len());
    while let Some(byte) = bytes.next() {
        let byte = if byte == b'%' {
            let high = char::from(bytes.next()?).to_digit(16)?;
            let low = char::from(bytes.next()?).to_digit(16)?;
            (high * 16 + low) as u8
        } else {
            byte
        };
        decoded.push(byte);
    }
    let decoded = String::from_utf8(decoded).ok()?;
    plain(&decoded).then_some(decoded)
}

fn plain(segment: &str) -> bool {
    !matches!(segment, "" | "." | "..")
        && !segment.contains(['/', '\\'])
        && !segment.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_owner(owner: &str) -> bool {
    let (login, enterprise) = owner
        .split_once('_')
        .map_or((owner, None), |(login, tag)| (login, Some(tag)));
    login.len() <= 39
        && login
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && login
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && login
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && enterprise.is_none_or(|tag| {
            (1..=16).contains(&tag.len()) && tag.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

fn valid_repo(repo: &str) -> bool {
    (1..=100).contains(&repo.len())
        && !matches!(repo, "." | "..")
        && repo
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn positive_decimal(segment: &str, max: i64) -> bool {
    matches!(segment.as_bytes().first(), Some(b'1'..=b'9'))
        && segment.bytes().all(|byte| byte.is_ascii_digit())
        && segment.parse::<i64>().is_ok_and(|value| value <= max)
}

fn tail(segment: &str) -> bool {
    segment
        .strip_prefix('{')
        .and_then(|name| name.strip_suffix("*}"))
        .is_some_and(|name| plain(name) && !name.contains(['{', '}', '*']))
}

fn template_matches(template: &str, path: &[String]) -> bool {
    let mut template = template.split('/').peekable();
    let mut path = path.iter();
    while let Some(segment) = template.next() {
        if tail(segment) {
            let remaining = path.as_slice();
            return template.peek().is_none()
                && !remaining.is_empty()
                && remaining.iter().all(|part| part.len() <= 255)
                && remaining.iter().map(|part| part.len() + 1).sum::<usize>() - 1 <= 1024;
        }
        let Some(part) = path.next() else {
            return false;
        };
        if !segment_matches(segment, part) {
            return false;
        }
    }
    path.next().is_none()
}

fn segment_matches(template: &str, part: &str) -> bool {
    match template {
        "{number}" => positive_decimal(part, i64::from(i32::MAX)),
        "{id}" => positive_decimal(part, MAX_INTEGER),
        "{sha}" => lower_hex(part, 40) || lower_hex(part, 64),
        "{name}" => part.len() <= 255,
        literal => !literal.contains(['{', '}']) && literal == part,
    }
}

/// Build a health label using only literal route words from the loaded catalog
/// and active policy. Never include repository coordinates or query data.
pub fn repo_get_suffix_template(
    catalog: &[ActionBaseline],
    policy: Option<&AgentPolicy>,
    args: &Value,
) -> String {
    let catalog_paths = catalog
        .iter()
        .filter_map(|action| Some(action.http.as_ref()?.path.as_str()));
    let policy_paths = policy
        .and_then(|policy| policy.rule_sets.github.as_ref())
        .into_iter()
        .flat_map(|rules| &rules.kinds)
        .flat_map(|kind| &kind.requests)
        .filter_map(|request| match request {
            Request::Rest(rest) => Some(rest.path.as_str()),
            Request::Graphql(_) => None,
        });
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .split(['?', '#'])
        .next()
        .unwrap_or("");
    let parts: Vec<_> = path.split('/').collect();
    let decoded: Vec<_> = parts.iter().map(|part| decode_segment(part)).collect();
    let mut dynamic = vec![false; parts.len()];
    let mut literals = BTreeSet::new();
    for path in catalog_paths.chain(policy_paths) {
        literals.extend(path.split('/').filter(|word| {
            !word.is_empty()
                && word
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'-' || b == b'_')
        }));
        let Some(suffix) = path.strip_prefix(REPO_PREFIX) else {
            continue;
        };
        for (index, (segment, part)) in suffix.split('/').zip(&decoded).enumerate() {
            if tail(segment) {
                dynamic[index..].fill(true);
                break;
            }
            if segment.starts_with('{') && segment.ends_with('}') {
                dynamic[index] = true;
            }
            let segment = match segment {
                "{issue_number}" | "{pull_number}" | "{stack_number}" => "{number}",
                "{comment_id}" | "{job_id}" => "{id}",
                "{label}" => "{name}",
                segment => segment,
            };
            // Only a matching prefix can identify later parameter positions.
            if !part
                .as_deref()
                .is_some_and(|part| segment_matches(segment, part))
            {
                break;
            }
        }
    }
    parts
        .into_iter()
        .zip(dynamic)
        .map(|(part, dynamic)| {
            if !dynamic && literals.contains(part) {
                part
            } else {
                "{}"
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}
