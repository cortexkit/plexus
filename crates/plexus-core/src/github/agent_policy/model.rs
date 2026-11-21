use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const MAX_POLICY_BYTES: usize = 1024 * 1024;
pub(super) const MAX_INTEGER: i64 = (1 << 53) - 1;

#[derive(Debug, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct AgentPolicy {
    pub schema: Schema,
    pub version: i64,
    pub issued_at_unix_secs: i64,
    pub root_key_id: String,
    pub rule_sets: RuleSets,
    pub bindings: Vec<Binding>,
}

impl AgentPolicy {
    pub fn parse(text: &str) -> Result<Self, serde_json::Error> {
        let policy: Self = parse_exact(text)?;
        if policy.version <= 0 || !lower_hex(&policy.root_key_id, 16) {
            return Err(de::Error::custom("invalid policy version or root key id"));
        }
        if let Some(rule_set) = &policy.rule_sets.github {
            if rule_set.source.is_none() {
                return Err(de::Error::missing_field("source"));
            }
            rule_set.validate_names()?;
        }
        Ok(policy)
    }
}

pub(crate) fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Deserialize)]
pub enum Schema {
    #[serde(rename = "ck-agent-policy/v1")]
    V1,
}

#[derive(Debug, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct RuleSets {
    #[serde(default, deserialize_with = "object_if_present")]
    pub github: Option<RuleSet>,
}

#[derive(Debug, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct Binding {
    pub service: Service,
    pub agent: String,
    pub identity: String,
    pub resources: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    Github,
}

#[derive(Debug, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct RuleSet {
    pub rule_set: Service,
    pub revision: i64,
    // The vault's published GitHub default omits `source`; signed policies must
    // name the release and digest of the default they narrow.
    pub source: Option<Source>,
    pub extractor: Extractor,
    pub hosts: Vec<String>,
    pub redirect_hosts: Vec<String>,
    pub kinds: Vec<Kind>,
    pub actions: Vec<Action>,
}

impl RuleSet {
    fn validate_names(&self) -> Result<(), serde_json::Error> {
        for names in [
            self.kinds
                .iter()
                .map(|k| k.kind.as_str())
                .collect::<Vec<_>>(),
            self.actions.iter().map(|a| a.action.as_str()).collect(),
        ] {
            let mut unique = BTreeSet::new();
            if let Some(invalid) = names
                .into_iter()
                .find(|name| name.is_empty() || !unique.insert(*name))
            {
                return Err(de::Error::custom(format_args!(
                    "empty or duplicate policy name: {invalid:?}"
                )));
            }
        }
        Ok(())
    }
}

fn object_if_present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<RuleSet>, D::Error> {
    RuleSet::deserialize(d).map(Some)
}

#[derive(Debug, Deserialize)]
pub enum Extractor {
    #[serde(rename = "github-rest-graphql/v1")]
    GitHubV1,
}

#[derive(Debug, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct Source {
    pub release: String,
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct Kind {
    pub kind: String,
    pub class: Class,
    pub approval: Approval,
    pub identity: Identity,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub credential: Option<Credential>,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub ownership: Option<Ownership>,
    pub requests: Vec<Request>,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub consent: Option<Consent>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Read,
    Speech,
    Operator,
    Denied,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    None,
    Once,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Identity {
    Agent,
    Anonymous,
}

#[derive(Debug, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct Credential {
    pub github_permissions: BTreeMap<String, Permission>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Read,
    Write,
    Admin,
}

#[derive(Debug, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct Ownership {
    pub check: OwnershipCheck,
    pub reads: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipCheck {
    OwnComment,
    OwnLastComment,
    OwnIssue,
    OwnPullRequest,
    OwnPullRequests,
    OwnStackPullRequests,
    OwnThreadPullRequest,
    ThreadInRepository,
}

#[derive(Debug, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct Consent {
    pub fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    Rest(Box<RestRequest>),
    Graphql(GraphqlRequest),
}

#[derive(Debug, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct RestRequest {
    pub method: String,
    pub host: String,
    pub path: String,
    pub body: Option<Constraints<Scalar>>,
    pub query: Option<Constraints<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(
    remote = "Self",
    deny_unknown_fields,
    bound(deserialize = "T: Deserialize<'de>")
)]
pub struct Constraints<T> {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub optional: Vec<String>,
    #[serde(default)]
    pub fixed: BTreeMap<String, T>,
    #[serde(default)]
    pub forbidden: Vec<String>,
    #[serde(default)]
    pub additional: Additional,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Scalar {
    String(String),
    Integer(i64),
    Boolean(bool),
    Null,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Additional {
    #[default]
    Deny,
    Allow,
}

#[derive(Debug, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct GraphqlRequest {
    pub operation: Operation,
    pub fields: Vec<String>,
    #[serde(default)]
    pub arguments: BTreeMap<String, Predicate>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Query,
    Mutation,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    RepositoryInScope,
    NodeInScope,
}

#[derive(Debug, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct Action {
    pub action: String,
    pub legs: Vec<Leg>,
}

#[derive(Debug, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct Leg {
    pub kind: String,
    #[serde(default)]
    pub optional: bool,
}

// Serde normally accepts both named objects and positional arrays for structs.
// Pass only a map to the derived field decoder; the policy uses named objects.
macro_rules! object_only {
    ($($model:ty),+ $(,)?) => {$ (
        impl<'de> Deserialize<'de> for $model {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct Object;

                impl<'de> Visitor<'de> for Object {
                    type Value = $model;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("a policy object with named fields")
                    }

                    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                        <$model>::deserialize(de::value::MapAccessDeserializer::new(map))
                    }
                }

                d.deserialize_map(Object)
            }
        }
    )+};
}

object_only!(
    AgentPolicy,
    RuleSets,
    Binding,
    RuleSet,
    Source,
    Kind,
    Credential,
    Ownership,
    Consent,
    RestRequest,
    Constraints<Scalar>,
    Constraints<String>,
    GraphqlRequest,
    Action,
    Leg,
);

pub(super) fn parse_exact<T: DeserializeOwned>(text: &str) -> Result<T, serde_json::Error> {
    if text.len() > MAX_POLICY_BYTES {
        return Err(de::Error::custom("policy exceeds 1 MiB"));
    }
    let ExactJson(value) = serde_json::from_str(text)?;
    serde_json::from_value(value)
}

// A regular JSON Value would discard duplicate keys before typed deserialization.
// Check the numeric spelling and object keys while the decoder still sees them.
struct ExactJson(Value);

impl<'de> Deserialize<'de> for ExactJson {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(ExactJsonVisitor).map(Self)
    }
}

struct ExactJsonVisitor;

impl<'de> Visitor<'de> for ExactJsonVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON with exact integers and unique object keys")
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        if (-MAX_INTEGER..=MAX_INTEGER).contains(&value) {
            Ok(value.into())
        } else {
            Err(E::custom("integer outside the signed policy range"))
        }
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        self.visit_i64(i64::try_from(value).map_err(E::custom)?)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(ExactJson(value)) = seq.next_element()? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some((name, ExactJson(value))) = map.next_entry::<String, _>()? {
            if values.insert(name.clone(), value).is_some() {
                return Err(de::Error::custom(format_args!("duplicate member {name:?}")));
            }
        }
        Ok(Value::Object(values))
    }
}
