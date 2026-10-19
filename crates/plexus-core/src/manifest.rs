//! The reviewed, static vendor-manifest model.
//!
//! JSONC normalization belongs to the wire crate because this core crate must
//! remain independent of the subc daemon. The module passes the normalized JSON
//! value here; deserialization is closed so a catalog file cannot smuggle in
//! transport or credential settings that the schema does not define.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

// `PartialEq` only: `actions_baseline[].http.args_schema` is a JSON Schema held
// as `serde_json::Value`, which does not implement `Eq`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AppManifest {
    pub schema_version: u32,
    pub key: String,
    pub name: String,
    pub description: String,
    pub reuse_path: ReusePath,
    pub reuse_rationale: String,
    pub tier: Tier,
    pub transport: Transport,
    pub auth: Auth,
    pub credential_bindings: Vec<CredentialBinding>,
    pub resource_filters: ResourceFilters,
    pub actions_baseline: Vec<ActionBaseline>,
    pub defaults: ManifestDefaults,
    pub availability: Availability,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReusePath {
    McpDirect,
    OpenapiShim,
    DeepWrapper,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    #[serde(rename = "S1")]
    S1,
    #[serde(rename = "S2")]
    S2,
    #[serde(rename = "S3")]
    S3,
    #[serde(rename = "S4")]
    S4,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Transport {
    pub kind: TransportKind,
    pub url: String,
}

/// The manifest spelling of a transport kind, for refusal messages.
///
/// Matches the `snake_case` serde rename so the error names the value the
/// reviewer actually typed rather than its Rust identifier.
pub(crate) fn transport_kind_label(kind: TransportKind) -> &'static str {
    match kind {
        TransportKind::McpRemote => "mcp_remote",
        TransportKind::McpStdio => "mcp_stdio",
        TransportKind::RestApi => "rest_api",
        TransportKind::LocalScript => "local_script",
        TransportKind::LocalHelper => "local_helper",
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    McpRemote,
    McpStdio,
    RestApi,
    LocalScript,
    LocalHelper,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    pub mode: AuthMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<OauthProfile>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    Oauth,
    ApiKey,
    AppInstall,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OauthProfile {
    pub profile_id: String,
    /// Deprecated metadata, ignored. OAuth authority comes from the registered profile.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub profile_digest: String,
    /// Deprecated metadata, ignored; this does not request or restrict scopes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialBinding {
    pub ref_role: String,
    pub placement: String,
    pub key: String,
    pub prefix: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceFilters {
    pub required: Vec<String>,
    pub optional: Vec<String>,
    pub write_enabling: Vec<String>,
}

// `PartialEq` only, like `AppManifest`: the optional `http.args_schema` is a
// `serde_json::Value`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ActionBaseline {
    pub name: String,
    pub risk: Risk,
    #[serde(default)]
    pub ask_first: bool,
    #[serde(default)]
    pub facade_only: bool,
    /// JSON pointers naming every recipient argument. Declaring recipients
    /// enables the per-connection, per-agent allowlist gate before dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipients: Option<Vec<String>>,
    /// Reviewed input schema for non-REST actions. REST
    /// actions use http.args_schema instead, so there is one authoritative schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    #[serde(default)]
    pub reconciliation: Option<Reconciliation>,
    #[serde(default)]
    /// Deprecated metadata, ignored. It never authorizes automatic write retries.
    pub idempotency: Option<Idempotency>,
    /// The optional polling shape for this action. A missing shape means the
    /// action cannot be configured as a trigger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll: Option<PollShape>,
    /// The HTTP shape of this action. Required on every action when
    /// `transport.kind` is `rest_api` and forbidden otherwise (see `validate`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpOperation>,
}

/// One HTTP operation a REST action maps onto: a method, a path template whose
/// `{placeholders}` are filled from invocation args, and the JSON Schema those
/// args are validated against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpOperation {
    pub method: HttpMethod,
    pub path: String,
    pub args_schema: Value,
    /// Where non-path arguments travel. Omission preserves method defaults:
    /// GET and DELETE use the query; POST, PUT and PATCH use a JSON body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<RestParameterLocation>,
    /// Reviewed arguments supplied by the transport on every request. Callers
    /// and cursors cannot supply these keys, even with the same value: changing
    /// a page size would invalidate a poller's coverage and request budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_constants: Option<std::collections::BTreeMap<String, Value>>,
    /// Download a bounded text tail through one HTTPS redirect, without carrying
    /// any headers from the credentialed API request to the storage service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentialless_tail: Option<CredentiallessTail>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RestParameterLocation {
    Body,
    Query,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CredentiallessTail {
    #[serde(default)]
    pub kind: CredentiallessTailKind,
    /// Exact hosts or a single-label wildcard such as *.blob.core.windows.net.
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentiallessTailKind {
    #[default]
    JobLog,
    ArtifactFile,
}

/// The cursor shapes a polling action may expose.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CursorKind {
    SyncToken,
    OrderedTimestamp,
    SnapshotDiff,
    /// Read the newest page a vendor will sort, and emit what is newer than the
    /// last item seen.
    ///
    /// For endpoints that can ORDER but cannot be given a bound. Measured:
    /// `list_pull_requests` accepts sort and direction but no timestamp filter,
    /// so an ordered-timestamp cursor — whose method is to send a resume point —
    /// cannot express it at all.
    ///
    /// Weaker than a windowed cursor by construction: a page can overflow if
    /// more items change between polls than fit on it. The strategy detects that
    /// and records a coverage gap rather than reporting false completeness.
    SortedHead,
    /// One value compared against the last one seen. Not a cursor: it requests
    /// no window, receives no list, and stores the observed value ITSELF rather
    /// than a pointer into a stream.
    ///
    /// Exists because some vendor surfaces are not streams at all.
    /// `get_latest_release` accepts only owner and repo -- no bound, no
    /// pagination, no ordering -- because it returns ONE thing, so there is
    /// nothing to page through and nothing to deduplicate.
    ScalarDiff,
    /// Discover workflow runs, then read each open run attempt and all its jobs.
    /// This multi-action cycle uses event-key dedup, not a time watermark.
    CiRuns,
}

impl CursorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SyncToken => "sync_token",
            Self::OrderedTimestamp => "ordered_timestamp",
            Self::SnapshotDiff => "snapshot_diff",
            Self::ScalarDiff => "scalar_diff",
            Self::SortedHead => "sorted_head",
            Self::CiRuns => "ci_runs",
        }
    }
}

/// Vendor fields used to resume polling. They remain optional in the wire model
/// because each cursor kind requires different fields: ordered-timestamp cursors
/// require a timestamp and tie-breaker field, while snapshot-diff cursors require
/// an item-count ceiling; validation enforces these requirements.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PollShape {
    pub cursor_kind: CursorKind,
    /// RESPONSE field carrying the opaque token that resumes the next poll.
    ///
    /// A sync-token vendor names three things and agrees with no other vendor
    /// about any of them, so all three are declared here rather than assumed by
    /// the poller. Google Calendar returns its cursor as `nextSyncToken` and
    /// takes it back as the request parameter `syncToken` — DIFFERENT NAMES for
    /// the same value, which is why one field cannot serve both directions.
    ///
    /// Getting any of them wrong fails silently rather than loudly: an
    /// unrecognised cursor field leaves the watermark unmoved, so every poll
    /// re-reads the same window forever, and an unrecognised items field yields
    /// zero events, which is indistinguishable from a quiet period.
    ///
    /// Each defaults to the reference envelope
    /// `{"items": [...], "next_cursor": "<opaque>"}` with request parameter
    /// `sync_token`, so a manifest that declares none keeps working.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "sync_token_field"
    )]
    pub token_field: Option<String>,
    /// REQUEST parameter carrying the stored token back to the vendor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_token_field: Option<String>,
    /// RESPONSE field carrying the array of records a poll returns. Google
    /// Calendar uses `items`, Stripe uses `data`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items_field: Option<String>,
    /// Vendor field used for the ordered high-water mark.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_field: Option<String>,
    /// Stable secondary ordering field for equal timestamps.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "tiebreaker_field",
        alias = "id_field"
    )]
    pub tiebreaker_id_field: Option<String>,
    /// REQUEST parameter carrying the ordered-timestamp resume point — a flat
    /// ISO 8601 timestamp — back to the vendor. GitHub issues and notifications
    /// use `since`, PostHog events use `after`; the default is `since`.
    ///
    /// The limit, stated rather than papered over: this is a FLAT parameter
    /// holding a single timestamp, which is exactly what GitHub and PostHog
    /// accept. It does NOT cover Linear (a nested GraphQL
    /// `filter: { updatedAt: { gte } }`) or Notion (a `last_edited_time` filter
    /// object). Those need a richer request shape, and that shape should be
    /// designed once each tool's real `inputSchema` has been read from a live
    /// connection — not guessed at now. A flat name that honestly covers two
    /// vendors is better than a general mechanism built against documentation we
    /// have not verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_since_field: Option<String>,
    /// Request arguments that are reviewed as part of this action's poll shape
    /// and sent on every poll. `None` means the reviewer has not answered the
    /// ordering question for an ordered-timestamp cursor; `Some({})` explicitly
    /// records that the vendor's default ordering is sound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_constants: Option<std::collections::BTreeMap<String, Value>>,
    /// RESPONSE field carrying the single value a scalar-diff watch compares.
    ///
    /// Required for `scalar_diff` and meaningless for the cursor kinds, which
    /// read a list. There is no default: a wrong name here yields no value,
    /// which would read as "unchanged" forever -- the same silent failure as an
    /// unrecognised items field, so the manifest must name it explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scalar_field: Option<String>,
    /// Required for snapshot diff so a subscription cannot become a local
    /// unbounded mirror of a vendor collection.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "max_item_count"
    )]
    pub item_count_ceiling: Option<u64>,
    /// What KIND of item this action yields: `issue`, `pull_request`, `release`.
    ///
    /// Declared in the reviewed manifest rather than inferred from the action
    /// name, for the same reason every other vendor fact is: `list_issues`
    /// yielding issues is vendor knowledge, and a poller that guessed it would be
    /// classifying on a naming convention no vendor promised to keep.
    ///
    /// It rides on every event so a consumer can route without joining back to
    /// the subscription and without parsing display prose. Measured need: a
    /// consumer could not tell an issue from a pull request, because the only
    /// thing distinguishing them was the action name one join away.
    ///
    /// REQUIRED for every poll shape, not optional. A consumer that must handle
    /// an absent kind is back to guessing, which is the problem this solves.
    pub item_kind: String,
    /// Which `request_constants` key carries the vendor's PAGE SIZE, for cursor
    /// kinds that read a bounded page rather than a bounded window.
    ///
    /// Names the key rather than repeating the number, so the value the vendor is
    /// actually sent and the value the strategy reasons about cannot drift apart.
    /// GitHub declares `perPage`; another vendor may call it `limit`.
    ///
    /// WHAT IT IS FOR, and it is a correctness requirement rather than a nicety:
    /// the sorted-head strategy detects a possibly-truncated page by asking
    /// whether every item it received was newer than the watermark. That test is
    /// only evidence of truncation IF THE PAGE WAS FULL. Without the cap, a
    /// vendor returning three items -- its entire collection -- reports a
    /// coverage gap whenever all three changed since the last poll, which is
    /// ordinary behaviour for a small repository and not a gap at all.
    ///
    /// Without this field, a repository with fewer pull requests than one page
    /// can report coverage gaps over windows containing no actual changes, or
    /// only one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_page_size_field: Option<String>,
    /// Intra-poll pagination for ordered timestamps. Omitted by older catalogs,
    /// which retain single-page behavior until their poll shape is upgraded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pagination: Option<PollPagination>,
}

/// Vendor cursor wiring, separate from the durable timestamp watermark.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PollPagination {
    pub request_cursor_field: String,
    /// JSON pointer to the opaque cursor in the response (for example
    /// `/pageInfo/endCursor`). It is used only after a full page.
    pub response_cursor_pointer: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

/// Action risk. The variant order is the authority order (`Read` is the
/// weakest), so derived comparison is exactly the ceiling comparison: a risk is
/// permitted when it sorts no higher than the ceiling.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Read,
    Write,
    Destructive,
}

impl Risk {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "destructive" => Some(Self::Destructive),
            _ => None,
        }
    }

    pub fn within(self, ceiling: Self) -> bool {
        self <= ceiling
    }
}

impl std::fmt::Display for Risk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Destructive => "destructive",
        };
        f.write_str(text)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Reconciliation {
    pub correlation_fields: Vec<String>,
    pub read_back_action: String,
    pub timeout_s: u64,
}

/// Reconciliation arguments are retained for at most one day.
pub(crate) const MAX_RECONCILIATION_TIMEOUT_S: u64 = 86_400;

impl Reconciliation {
    pub(crate) fn valid(&self) -> bool {
        !self.read_back_action.trim().is_empty()
            && (1..=MAX_RECONCILIATION_TIMEOUT_S).contains(&self.timeout_s)
            && !self.correlation_fields.is_empty()
            && self
                .correlation_fields
                .iter()
                .all(|field| !field.trim().is_empty())
    }
}

/// Resolve a dot-delimited object-property path in a reviewed input schema.
/// Arrays and dynamic additional-properties maps are not resource identities.
pub(crate) fn schema_filter_path<'a>(schema: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = schema;
    for component in path.split('.') {
        if component.is_empty() {
            return None;
        }
        current = current.get("properties")?.get(component)?;
    }
    Some(current)
}

pub(crate) fn action_asks_first(
    risk: Risk,
    declared: &[Risk],
    explicit: bool,
    recipients: bool,
) -> bool {
    explicit || recipients || asks_first(risk, declared)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Idempotency {
    None,
    Natural,
    Keyed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestDefaults {
    pub ask_first_risk: Vec<Risk>,
    /// Accepted and ignored. Plexus enforces no per-connection call budget:
    /// vendor 429 replies and their Retry-After are what pace calls, and the
    /// search facades have their own limiters. The field stays declared,
    /// optional, so the shipped catalogs that still carry it parse under
    /// `deny_unknown_fields`, and a manifest without it parses too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
    /// Maximum age of an observed MCP catalog before periodic refresh.
    #[serde(default = "default_catalog_ttl_s")]
    pub catalog_ttl_s: u64,
}

/// The ask-first floor that holds regardless of what a manifest declares:
/// writes and destructive actions always ask first on the default (no-policy)
/// branch. A manifest may WIDEN this set through `defaults.ask_first_risk`
/// (for example, adding `read`) but can never NARROW it — declaring `[]` does
/// not stop a write from asking. This is the same contract as
/// `reversibility_class` with the external decision plane: manifest data is
/// untrusted advisory input, plexus re-derives, and the stricter of the two
/// wins.
pub const ASK_FIRST_FLOOR: &[Risk] = &[Risk::Write, Risk::Destructive];

/// Whether an action of `risk` must ask first on the default branch, given a
/// manifest's declared `defaults.ask_first_risk`. The effective set is the
/// union of [`ASK_FIRST_FLOOR`] and the declared risks, so a manifest can widen
/// the set but never narrow it.
pub fn asks_first(risk: Risk, declared: &[Risk]) -> bool {
    ASK_FIRST_FLOOR.contains(&risk) || declared.contains(&risk)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    pub calls_per_min: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Ga,
    Gated,
    NeedsRegistration,
}

fn default_catalog_ttl_s() -> u64 {
    24 * 60 * 60
}

/// A manifest together with the normalized JSON and its ingest hash.
#[derive(Debug, Clone, PartialEq)]
pub struct IngestedManifest {
    pub manifest: AppManifest,
    pub json: Value,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    InvalidJson(String),
    InvalidField(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(message) => {
                write!(f, "manifest JSON does not match schema: {message}")
            }
            Self::InvalidField(message) => write!(f, "invalid manifest field: {message}"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// Deserialize and validate one normalized manifest value.
///
/// The hash is over serde's deterministic JSON serialization of the parsed
/// value, rather than the JSONC source bytes, so comments and whitespace do not
/// create a false catalog change.
pub(crate) fn validated_manifest(value: &Value) -> Result<AppManifest, ManifestError> {
    // Deserialized through a path-tracking wrapper so the error names WHICH
    // field was wrong. serde's own message reports the bad value and the
    // expected type but never the location, so a one-field typo in a reviewed
    // manifest produced "invalid type: string, expected u32" -- a message that
    // fits every numeric field in the schema and points at none of them.
    //
    // This is the failing path an operator actually triages: the success path
    // here is thoroughly evidenced while the refusal was the least informative
    // output in the crate. Naming the field costs one dependency whose own two
    // dependencies were already in the graph.
    let manifest = serde_path_to_error::deserialize::<_, AppManifest>(value).map_err(|error| {
        let path = error.path().to_string();
        // A root-level failure -- the whole document being a string rather
        // than an object, say -- has no field to name, and the library
        // renders that path as "." rather than as an empty string. Checking
        // for empty would be dead code: `Path::to_string` never returns one,
        // so every root error would be reported as "at '.'", which is a
        // location that identifies nothing.
        if path == "." {
            ManifestError::InvalidJson(error.into_inner().to_string())
        } else {
            ManifestError::InvalidJson(format!("at '{path}': {}", error.into_inner()))
        }
    })?;
    validate(&manifest)?;
    Ok(manifest)
}

pub fn ingest_value(value: Value) -> Result<IngestedManifest, ManifestError> {
    let manifest = validated_manifest(&value)?;
    let normalized = serde_json::to_value(&manifest)
        .map_err(|error| ManifestError::InvalidJson(error.to_string()))?;
    let bytes = crate::jcs::canonicalize_exact_integers(&normalized)
        .map_err(|error| ManifestError::InvalidJson(error.to_string()))?;
    let digest = Sha256::digest(bytes);
    let content_hash = format!("sha256:{digest:x}");
    Ok(IngestedManifest {
        manifest,
        json: value,
        content_hash,
    })
}

fn validate(manifest: &AppManifest) -> Result<(), ManifestError> {
    if manifest.schema_version != 1 {
        return Err(ManifestError::InvalidField(format!(
            "schema_version must be 1, got {}",
            manifest.schema_version
        )));
    }
    if manifest.key.is_empty()
        || !manifest.key.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
    {
        return Err(ManifestError::InvalidField(
            "key must be a non-empty lowercase vendor key".to_string(),
        ));
    }
    // The base URL carries the connection's credential on every request, so a
    // plaintext scheme would put a bearer token on the wire in clear. Checking
    // only for emptiness accepted `http://`, and worse accepted anything at all
    // — the action-path guard below refuses a path that redirects to another
    // host, which is pointless if the base itself may name one freely.
    if !transport_url_is_acceptable(&manifest.transport.url) {
        return Err(ManifestError::InvalidField(format!(
            "transport.url must be an https:// endpoint (http:// is permitted only for loopback), got '{}'",
            manifest.transport.url
        )));
    }
    if (manifest.auth.mode == AuthMode::None) != manifest.credential_bindings.is_empty() {
        return Err(ManifestError::InvalidField(
            "credential_bindings must match auth.mode (none requires no bindings)".into(),
        ));
    }
    let mut headers = std::collections::BTreeSet::new();
    for binding in &manifest.credential_bindings {
        let primary_role = binding.ref_role == "primary"
            || match manifest.auth.mode {
                AuthMode::ApiKey => binding.ref_role == "api_key",
                AuthMode::Oauth => matches!(
                    binding.ref_role.as_str(),
                    "oauth" | "oauth_token" | "access_token"
                ),
                AuthMode::AppInstall => {
                    matches!(binding.ref_role.as_str(), "app_install" | "access_token")
                }
                AuthMode::None => false,
            };
        if !binding.required || !primary_role {
            return Err(ManifestError::InvalidField("credential_bindings supports only required primary credentials (including auth-matching legacy role aliases)".into()));
        }
        if reqwest::header::HeaderName::from_bytes(binding.key.as_bytes()).is_err()
            || !headers.insert(binding.key.to_ascii_lowercase())
        {
            return Err(ManifestError::InvalidField(
                "credential_bindings requires valid, unique header names".into(),
            ));
        }
        // Only header placement is implemented. A manifest naming any other
        // placement previously loaded clean and was then SKIPPED at dispatch,
        // so the request went to the vendor with no credential at all: a
        // constraint that reads as configuration but silently disables the
        // thing it configures.
        if !binding.placement.eq_ignore_ascii_case("header") {
            return Err(ManifestError::InvalidField(format!(
                "credential_bindings placement '{}' is not supported; only 'header' is implemented",
                binding.placement
            )));
        }
        if binding.key.is_empty() {
            return Err(ManifestError::InvalidField(
                "credential_bindings key must not be empty".to_string(),
            ));
        }
        // A header name or prefix containing CR/LF splits the header block and
        // lets a manifest inject headers the reviewer never sees.
        if has_header_control_bytes(&binding.key) || has_header_control_bytes(&binding.prefix) {
            return Err(ManifestError::InvalidField(
                "credential_bindings key and prefix must not contain control characters"
                    .to_string(),
            ));
        }
    }
    match (manifest.auth.mode, manifest.auth.oauth.as_ref()) {
        (AuthMode::Oauth, None) => {
            return Err(ManifestError::InvalidField(
                "auth.oauth is required when auth.mode is oauth".to_string(),
            ));
        }
        (AuthMode::Oauth, Some(profile)) if profile.profile_id.is_empty() => {
            return Err(ManifestError::InvalidField(
                "auth.oauth.profile_id must not be empty".to_string(),
            ));
        }
        (AuthMode::Oauth, Some(_)) => {}
        (_, Some(_)) => {
            return Err(ManifestError::InvalidField(
                "auth.oauth is only valid when auth.mode is oauth".to_string(),
            ));
        }
        (_, None) => {}
    }
    // Only MCP remote and REST have both discovery and dispatch paths. Stdio
    // adapters lack catalog freshness support, so accepting their manifests
    // would advertise actions that governed writes cannot execute.
    if !matches!(
        manifest.transport.kind,
        TransportKind::McpRemote | TransportKind::RestApi
    ) {
        return Err(ManifestError::InvalidField(format!(
            "transport.kind '{}' has no dispatch route: only mcp_remote and rest_api can be served",
            transport_kind_label(manifest.transport.kind)
        )));
    }
    let is_rest = matches!(manifest.transport.kind, TransportKind::RestApi);
    for path in manifest
        .resource_filters
        .required
        .iter()
        .chain(&manifest.resource_filters.optional)
        .chain(&manifest.resource_filters.write_enabling)
    {
        if !manifest.actions_baseline.iter().any(|action| {
            action
                .http
                .as_ref()
                .map(|http| &http.args_schema)
                .or(action.input_schema.as_ref())
                .is_some_and(|schema| schema_filter_path(schema, path).is_some())
        }) {
            return Err(ManifestError::InvalidField(format!(
                "resource filter '{path}' is not a path in a reviewed input schema"
            )));
        }
    }
    let mut action_names = std::collections::BTreeSet::new();
    for action in &manifest.actions_baseline {
        if action.name.is_empty()
            || !action
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
            || !action_names.insert(&action.name)
        {
            return Err(ManifestError::InvalidField(
                "actions_baseline names must be non-empty and unique".to_string(),
            ));
        }
        // This reviewed denylist catches known credential-returning tools, not
        // arbitrary vendor output. New actions still require a human secret review.
        if matches!(action.name.as_str(), "get_connection_string") {
            return Err(ManifestError::InvalidField(format!(
                "action '{}' returns credential material and cannot be declared",
                action.name
            )));
        }
        if action.facade_only && (action.risk == Risk::Read || !is_rest) {
            return Err(ManifestError::InvalidField(format!(
                "facade_only requires a REST write action: '{}'",
                action.name
            )));
        }
        if action.input_schema.is_some() && is_rest {
            return Err(ManifestError::InvalidField(format!(
                "action '{}' input_schema is only for non-REST declarations",
                action.name
            )));
        }
        if let Some(pointers) = &action.recipients {
            let schema = action
                .http
                .as_ref()
                .map(|http| &http.args_schema)
                .or(action.input_schema.as_ref());
            if pointers.is_empty() {
                return Err(ManifestError::InvalidField(format!(
                    "action '{}' recipients must not be empty",
                    action.name
                )));
            }
            for pointer in pointers {
                if !schema.is_some_and(|schema| {
                    crate::recipients::recipient_pointer_valid(schema, pointer)
                }) {
                    return Err(ManifestError::InvalidField(format!(
                        "action '{}' recipients pointer '{}' cannot resolve to a string or string array in the reviewed input schema", action.name, pointer
                    )));
                }
            }
        }
        if let Some(reconciliation) = &action.reconciliation {
            if !reconciliation.valid() {
                return Err(ManifestError::InvalidField(
                    "reconciliation requires nonempty correlation_fields, a read_back_action and timeout_s in 1..=86400".to_string(),
                ));
            }
        }
        if let Some(reconciliation) = &action.reconciliation {
            let target = &reconciliation.read_back_action;
            if target == &action.name {
                return Err(ManifestError::InvalidField(format!(
                    "reconciliation_self_target: action '{}' read-back target '{}' must not be itself",
                    action.name, target
                )));
            }
            let read_back = manifest.actions_baseline.iter().find(|candidate| &candidate.name == target)
                .ok_or_else(|| ManifestError::InvalidField(format!(
                    "reconciliation_target_missing: action '{}' read-back target '{}' is not declared",
                    action.name, target
                )))?;
            if read_back.risk != Risk::Read {
                return Err(ManifestError::InvalidField(format!(
                    "reconciliation_target_not_read: action '{}' read-back target '{}' must have risk read",
                    action.name, target
                )));
            }
            if let Some(schema) = action
                .http
                .as_ref()
                .map(|http| &http.args_schema)
                .or(action.input_schema.as_ref())
            {
                if reconciliation.correlation_fields.iter().any(|field| {
                    schema
                        .get("properties")
                        .and_then(|p| p.get(field))
                        .is_none()
                }) {
                    return Err(ManifestError::InvalidField(format!(
                        "action '{}' reconciliation field is absent from the reviewed write schema",
                        action.name
                    )));
                }
            }
        }
        if let Some(poll) = &action.poll {
            if action.risk != Risk::Read
                || poll.item_kind.trim().is_empty()
                || poll.cursor_kind == CursorKind::SnapshotDiff
            {
                return Err(ManifestError::InvalidField(format!("action '{}' poll requires read risk, nonempty item_kind and an implemented cursor kind", action.name)));
            }
            // A blank constant key dispatches an argument no vendor can match,
            // so it must be rejected before it can become a silent no-op.
            if poll
                .request_constants
                .as_ref()
                .is_some_and(|constants| constants.keys().any(|key| key.trim().is_empty()))
            {
                return Err(ManifestError::InvalidField(format!(
                    "action '{}' poll request_constants keys must not be empty",
                    action.name
                )));
            }
            if let CursorKind::ScalarDiff = poll.cursor_kind {
                // No default is possible. A wrong or absent scalar field yields
                // no value on every poll, which a change test reads as
                // "unchanged" -- so the watch would report healthy silence
                // forever while observing nothing. Refused at ingest for the
                // same reason the ordered-timestamp fields are.
                if poll
                    .scalar_field
                    .as_deref()
                    .map(str::trim)
                    .is_none_or(str::is_empty)
                {
                    return Err(ManifestError::InvalidField(format!(
                        "action '{}' poll.scalar_diff requires scalar_field",
                        action.name
                    )));
                }
                // The cursor fields describe a stream this shape does not read.
                // Declaring one means the reviewer believed they were writing a
                // different kind of shape, and silently ignoring it would leave
                // that misunderstanding in the catalog.
                if poll.items_field.is_some()
                    || poll.timestamp_field.is_some()
                    || poll.token_field.is_some()
                    || poll.request_since_field.is_some()
                    || poll.request_token_field.is_some()
                {
                    return Err(ManifestError::InvalidField(format!(
                        "action '{}' poll.scalar_diff reads one value, so it must not declare \
                         stream fields (items_field, timestamp_field, token_field, \
                         request_since_field, request_token_field)",
                        action.name
                    )));
                }
            }
            if let Some(pagination) = &poll.pagination {
                let page_size = poll
                    .request_page_size_field
                    .as_deref()
                    .and_then(|key| poll.request_constants.as_ref()?.get(key))
                    .and_then(Value::as_u64);
                let cursor_key = pagination.request_cursor_field.as_str();
                if poll.cursor_kind != CursorKind::OrderedTimestamp
                    || cursor_key.trim().is_empty()
                    || !pagination.response_cursor_pointer.starts_with('/')
                    || page_size.is_none_or(|size| size == 0)
                    || cursor_key == poll.request_since_field.as_deref().unwrap_or("since")
                    || poll
                        .request_constants
                        .as_ref()
                        .is_some_and(|constants| constants.contains_key(cursor_key))
                {
                    return Err(ManifestError::InvalidField(format!(
                        "action '{}' poll.pagination requires ordered_timestamp, a distinct cursor request key, a response JSON pointer, and a positive declared page size",
                        action.name
                    )));
                }
            }
            if let CursorKind::SortedHead = poll.cursor_kind {
                // Same fields the ordered-timestamp shape needs, for the same
                // reason: a wrong or absent name reads zero events from a
                // healthy vendor, and there is no honest default for either.
                let named = |field: Option<&str>| {
                    field.map(str::trim).is_some_and(|value| !value.is_empty())
                };
                if !named(poll.timestamp_field.as_deref())
                    || !named(poll.tiebreaker_id_field.as_deref())
                {
                    return Err(ManifestError::InvalidField(format!(
                        "action '{}' poll.sorted_head requires timestamp_field and \
                         tiebreaker_id_field",
                        action.name
                    )));
                }
                // THE ORDERING IS THE WHOLE METHOD. This shape does not filter;
                // it trusts the vendor to sort and reads the head. An
                // unspecified order makes the first page an arbitrary subset
                // that still advances the watermark, which loses events
                // silently. `Some({})` is not accepted here, unlike
                // ordered-timestamp, because there the default ordering only
                // affects efficiency while here it decides correctness.
                let declared_ordering = poll.request_constants.as_ref().is_some_and(|constants| {
                    constants
                        .keys()
                        .any(|key| Some(key.as_str()) != poll.request_page_size_field.as_deref())
                });
                if !declared_ordering {
                    return Err(ManifestError::InvalidField(format!(
                        "action '{}' poll.sorted_head requires request_constants declaring the \
                         vendor's sort order: it reads the head of a sorted page rather than a \
                         filtered window, so an unordered page loses events",
                        action.name
                    )));
                }
                // THE PAGE CAP IS REQUIRED, because the saturation check is
                // meaningless without it. That check asks whether every item on
                // the page was newer than the watermark, which is evidence of
                // truncation only if the page was FULL -- otherwise a vendor
                // returning its entire small collection reports a coverage gap
                // every time all of it changed, a false gap that recurs daily on
                // a repository with fewer pull requests than one page.
                //
                // The named key must actually be present in request_constants
                // and hold a positive integer, so a manifest cannot name a
                // constant it never sends.
                let page_size = poll
                    .request_page_size_field
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                let Some(page_size_key) = page_size else {
                    return Err(ManifestError::InvalidField(format!(
                        "action '{}' poll.sorted_head requires request_page_size_field naming the \
                         request_constants key that carries the vendor's page size: the \
                         truncation check cannot tell a full page from a short one without it",
                        action.name
                    )));
                };
                let declared_cap = poll
                    .request_constants
                    .as_ref()
                    .and_then(|constants| constants.get(page_size_key))
                    .and_then(Value::as_u64);
                if declared_cap.is_none_or(|cap| cap == 0) {
                    return Err(ManifestError::InvalidField(format!(
                        "action '{}' poll.sorted_head names request_page_size_field '{page_size_key}' \
                         but request_constants does not carry it as a positive integer",
                        action.name
                    )));
                }
                // It sends no bound, so declaring one means the reviewer
                // believed they were writing a windowed shape.
                if poll.request_since_field.is_some() || poll.request_token_field.is_some() {
                    return Err(ManifestError::InvalidField(format!(
                        "action '{}' poll.sorted_head sends no bound, so it must not declare \
                         request_since_field or request_token_field",
                        action.name
                    )));
                }
            }
            if let CursorKind::OrderedTimestamp = poll.cursor_kind {
                let timestamp_field = poll
                    .timestamp_field
                    .as_deref()
                    .filter(|field| !field.is_empty());
                let tiebreaker_field = poll
                    .tiebreaker_id_field
                    .as_deref()
                    .filter(|field| !field.is_empty());
                if timestamp_field.is_none() || tiebreaker_field.is_none() {
                    return Err(ManifestError::InvalidField(format!(
                        "action '{}' poll.ordered_timestamp requires timestamp_field and tiebreaker_id_field",
                        action.name
                    )));
                }
                if timestamp_field == tiebreaker_field {
                    return Err(ManifestError::InvalidField(format!(
                        "action '{}' poll timestamp_field and tiebreaker_id_field must differ",
                        action.name
                    )));
                }
                // An ordered-timestamp shape without this declaration leaves the
                // vendor's default ordering unreviewed. `Some({})` is deliberate:
                // it records that the default is sound, while absence refuses the
                // shape rather than silently risking missed events.
                let Some(request_constants) = poll.request_constants.as_ref() else {
                    return Err(ManifestError::InvalidField(format!(
                        "action '{}' poll.ordered_timestamp requires request_constants",
                        action.name
                    )));
                };
                // An empty request parameter name would dispatch an argument the
                // vendor cannot match, producing an unfiltered first page every
                // cycle that dedupe silently discards — the same silent failure
                // the field exists to avoid.
                if let Some(request_since_field) = poll.request_since_field.as_deref() {
                    if request_since_field.trim().is_empty() {
                        return Err(ManifestError::InvalidField(format!(
                            "action '{}' poll request_since_field must not be empty",
                            action.name
                        )));
                    }
                }
                let request_since_field = poll.request_since_field.as_deref().unwrap_or("since");
                if request_constants.contains_key(request_since_field) {
                    return Err(ManifestError::InvalidField(format!(
                        "action '{}' poll request_constants must not contain request_since_field '{}'",
                        action.name, request_since_field
                    )));
                }
            }
        }
        match (&action.http, is_rest) {
            // A REST action with no HTTP shape is unroutable. Rejecting it at
            // ingest prevents the "declared but unreachable" failure: the
            // action would otherwise appear in the catalog as invocable even
            // though dispatch has no HTTP operation to execute, and the gap
            // would surface only at invoke time.
            (None, true) => {
                return Err(ManifestError::InvalidField(format!(
                    "action '{}' must declare http when transport.kind is rest_api",
                    action.name
                )));
            }
            // On any other transport the http field would be silently ignored,
            // which is its own trap: a reviewer would believe they declared a
            // routing that the transport never reads.
            (Some(_), false) => {
                return Err(ManifestError::InvalidField(format!(
                    "action '{}' declares http but transport.kind is not rest_api",
                    action.name
                )));
            }
            (Some(http), true) => {
                validate_http_operation(&action.name, http)?;
                if let (Some(constants), Some(poll)) = (&http.request_constants, &action.poll) {
                    let since_key = poll
                        .request_since_field
                        .as_deref()
                        .or((poll.cursor_kind == CursorKind::OrderedTimestamp).then_some("since"));
                    let token_key = poll
                        .request_token_field
                        .as_deref()
                        .or((poll.cursor_kind == CursorKind::SyncToken).then_some("sync_token"));
                    for key in constants.keys() {
                        if poll
                            .request_constants
                            .as_ref()
                            .is_some_and(|values| values.contains_key(key))
                            || since_key == Some(key.as_str())
                            || token_key == Some(key.as_str())
                            || poll
                                .pagination
                                .as_ref()
                                .is_some_and(|pagination| pagination.request_cursor_field == *key)
                        {
                            return Err(ManifestError::InvalidField(format!(
                                "action '{}' poll supplies HTTP request constant '{}'",
                                action.name, key
                            )));
                        }
                    }
                }
            }
            (None, false) => {}
        }
    }
    Ok(())
}

/// Validate one action's HTTP operation: the path must stay inside the base
/// URL's origin (an SSRF guard — the base URL comes from `transport.url` and an
/// action path must not route the credentialed request elsewhere), and every path placeholder
/// must be fillable from the action's argument schema.
fn validate_http_operation(action_name: &str, http: &HttpOperation) -> Result<(), ManifestError> {
    if let Some(tail) = &http.credentialless_tail {
        if http.method != HttpMethod::Get
            || tail.allowed_hosts.is_empty()
            || tail.allowed_hosts.iter().any(|host| {
                let host = host.strip_prefix("*.").unwrap_or(host);
                host.split('.').count() < 2
                    || host.parse::<std::net::IpAddr>().is_ok()
                    || host.split('.').any(|label| {
                        label.is_empty()
                            || label.starts_with('-')
                            || label.ends_with('-')
                            || !label
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    })
            })
        {
            return Err(ManifestError::InvalidField(format!(
                "action '{action_name}' credentialless_tail requires GET and a nonempty hostname allowlist"
            )));
        }
    }
    if http
        .request_constants
        .as_ref()
        .is_some_and(|constants| constants.keys().any(|key| key.trim().is_empty()))
    {
        return Err(ManifestError::InvalidField(format!(
            "action '{}' http.request_constants keys must not be empty",
            action_name
        )));
    }
    let path = &http.path;
    if !path.starts_with('/') {
        return Err(ManifestError::InvalidField(format!(
            "action '{}' http.path must be absolute (start with '/')",
            action_name
        )));
    }
    // A leading '//' is a network-path reference: joined onto a base URL it
    // replaces the authority and sends the call to another host entirely.
    if path.starts_with("//") {
        return Err(ManifestError::InvalidField(format!(
            "action '{}' http.path must not contain an authority (//host)",
            action_name
        )));
    }
    if path.contains("..") {
        return Err(ManifestError::InvalidField(format!(
            "action '{}' http.path must not contain '..'",
            action_name
        )));
    }
    if path.contains("://") {
        return Err(ManifestError::InvalidField(format!(
            "action '{}' http.path must not contain a scheme (://)",
            action_name
        )));
    }
    let properties = http.args_schema.get("properties");
    for placeholder in path_placeholders(path)? {
        let declared = properties
            .and_then(|properties| properties.get(&placeholder))
            .is_some();
        if !declared {
            return Err(ManifestError::InvalidField(format!(
                "action '{}' http.path placeholder '{placeholder}' is not a property in args_schema",
                action_name
            )));
        }
    }
    Ok(())
}

/// Whether a transport base URL may carry this connection's credential.
///
/// `https` always; `http` only to loopback. The exception is not a convenience:
/// plaintext to a vendor puts a bearer token on the wire in clear, whereas
/// plaintext to loopback never leaves the machine and is how conformance
/// fixtures reach an in-process stub. Any other host over `http` is refused.
///
/// The host is taken from a real URL parse, the same parser the HTTP client
/// uses to decide where to connect. Splitting the authority by hand gets
/// userinfo wrong: in `http://localhost:80@evil.com/` everything before the
/// `@` is a username and password, so the request goes to `evil.com` while a
/// split on `:` reads the host as `localhost`. Comparing the parsed host is the
/// only way the check and the connection agree on which machine is meant.
fn transport_url_is_acceptable(url: &str) -> bool {
    // The parser forgives surrounding whitespace; a reviewed manifest should
    // not need forgiving, and this keeps the accepted set no wider than the
    // literal-prefix check it replaces.
    if url.trim() != url {
        return false;
    }
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    // `host_str` is already normalised by the parser: a domain is lowercased,
    // an IPv4 address is in dotted form, and an IPv6 address keeps brackets.
    let Some(host) = parsed.host_str() else {
        return false;
    };
    match parsed.scheme() {
        "https" => true,
        "http" => {
            let bare = host
                .strip_prefix('[')
                .and_then(|inner| inner.strip_suffix(']'))
                .unwrap_or(host);
            host == "localhost"
                || bare
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        }
        _ => false,
    }
}

/// True when a header name or value fragment carries bytes that would break out
/// of the header it belongs to.
fn has_header_control_bytes(value: &str) -> bool {
    value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
}

/// The `{placeholder}` names in a path template, in order of first appearance.
/// An unterminated placeholder makes the template malformed.
pub(crate) fn path_placeholders(path: &str) -> Result<Vec<String>, ManifestError> {
    let mut names = Vec::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let close = after.find('}').ok_or_else(|| {
            ManifestError::InvalidField(format!(
                "http.path '{path}' has an unterminated '{{' placeholder"
            ))
        })?;
        let name = after[..close].to_string();
        if !names.contains(&name) {
            names.push(name);
        }
        rest = &after[close + 1..];
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    #[test]
    fn rollout_mutation_controls_exist_in_the_catalogue() {
        let controls = include_str!("../../../mutations.toml");
        let ids: std::collections::BTreeSet<_> = controls
            .lines()
            .filter_map(|line| {
                line.strip_prefix("id = \"")
                    .and_then(|line| line.strip_suffix('"'))
            })
            .collect();
        let document = include_str!("../../../docs/rollout/github-events-poll-mode.md");
        let mut checked = 0;
        for line in document.lines().filter(|line| line.starts_with("| ")) {
            for id in line
                .split('`')
                .skip(1)
                .step_by(2)
                .filter(|id| id.contains('-') && !id.contains(' ') && !id.contains('<'))
            {
                assert!(
                    ids.contains(id),
                    "documented mutation control does not exist: {id}"
                );
                checked += 1;
            }
        }
        assert!(checked >= 40, "mutation table must actually be checked");
    }

    #[test]
    fn shipped_credential_and_risk_boundaries_are_reviewed() {
        for (app, name, risk) in [
            ("neon", "complete_database_migration", Risk::Destructive),
            ("resend", "remove-contact", Risk::Destructive),
            ("resend", "remove-broadcast", Risk::Destructive),
            ("browserbase", "navigate", Risk::Write),
        ] {
            let manifest = ingest_value(load_catalog(&format!("{app}.jsonc")))
                .unwrap()
                .manifest;
            assert_eq!(
                manifest
                    .actions_baseline
                    .iter()
                    .find(|a| a.name == name)
                    .unwrap()
                    .risk,
                risk
            );
        }
        assert!(ingest_value(load_catalog("neon.jsonc"))
            .unwrap()
            .manifest
            .actions_baseline
            .iter()
            .all(|a| a.name != "get_connection_string"));
    }
    #[test]
    fn live_connected_catalog_schema_hashes_remain_unchanged() {
        // Captured from the catalog before metadata cleanup. These hashes pin
        // rollback-safe schemas, independently of the current manifest parser.
        let expected: std::collections::BTreeMap<
            String,
            std::collections::BTreeMap<String, String>,
        > = serde_json::from_str(include_str!(
            "../tests/fixtures/live-catalog-schema-hashes.json"
        ))
        .unwrap();
        assert_eq!(expected.len(), 7);
        for (app, actions) in expected {
            let value = load_catalog(&format!("{app}.jsonc"));
            let declared = value["actions_baseline"].as_array().unwrap();
            assert_eq!(actions.len(), declared.len(), "{app} action inventory");
            for action in declared {
                let name = action["name"].as_str().unwrap();
                let placeholder = serde_json::json!({"type":"object","additionalProperties":true});
                let schema = action
                    .pointer("/http/args_schema")
                    .or_else(|| action.get("input_schema"))
                    .unwrap_or(&placeholder);
                assert_eq!(
                    crate::jcs::jcs_sha256(schema).unwrap(),
                    actions[name],
                    "{app}/{name}"
                );
            }
        }
    }
    #[test]
    fn manifest_hash_normalizes_aliases_and_defaults_without_rounding_integers() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "cursor_kind":"ordered_timestamp", "item_kind":"issue", "timestamp_field":"updated_at",
            "id_field":"id", "request_constants":{}
        });
        let alias = ingest_value(value.clone()).unwrap();
        assert_eq!(
            alias.content_hash,
            ingest_value(serde_json::to_value(&alias.manifest).unwrap())
                .unwrap()
                .content_hash
        );
        value["actions_baseline"][0]["http"]["args_schema"]["maximum"] =
            serde_json::json!(9007199254740992_u64);
        let first = ingest_value(value.clone()).unwrap();
        value["actions_baseline"][0]["http"]["args_schema"]["maximum"] =
            serde_json::json!(9007199254740993_u64);
        assert_ne!(
            first.content_hash,
            ingest_value(value).unwrap().content_hash
        );
    }
    #[test]
    fn reviewed_catalog_rejects_credential_returning_actions() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["name"] = serde_json::json!("get_connection_string");
        assert!(ingest_value(value)
            .unwrap_err()
            .to_string()
            .contains("credential"));
    }

    #[test]
    fn resource_filter_paths_must_resolve_in_a_reviewed_schema() {
        let mut value = rest_manifest_value();
        value["resource_filters"]["optional"] = serde_json::json!(["scope.repo"]);
        assert!(ingest_value(value.clone()).is_err());
        value["actions_baseline"][0]["http"]["args_schema"]["properties"]["scope"] =
            serde_json::json!({"type":"object","properties":{"repo":{"type":"string"}}});
        ingest_value(value.clone()).expect("nested reviewed property");
        value["resource_filters"]["optional"] = serde_json::json!(["scope..repo"]);
        assert!(ingest_value(value).is_err());
    }

    #[test]
    fn sorted_head_page_size_alone_is_not_reviewed_ordering() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "cursor_kind":"sorted_head", "item_kind":"issue", "timestamp_field":"updated_at",
            "tiebreaker_id_field":"id", "request_constants":{"perPage":100},
            "request_page_size_field":"perPage"
        });
        assert!(ingest_value(value.clone()).is_err());
        value["actions_baseline"][0]["poll"]["request_constants"]["sort"] =
            serde_json::json!("updated");
        ingest_value(value).expect("ordering separate from page size");
    }

    #[test]
    fn reconciliation_requires_nonempty_fields_and_bounded_timeout() {
        let mut value = rest_manifest_value();
        value["actions_baseline"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        let mut write = value["actions_baseline"][0].clone();
        write["name"] = serde_json::json!("update_issue");
        write["risk"] = serde_json::json!("write");
        write["reconciliation"] = serde_json::json!({
            "read_back_action":"get_issue", "correlation_fields":[], "timeout_s":60
        });
        value["actions_baseline"]
            .as_array_mut()
            .unwrap()
            .push(write);
        assert!(ingest_value(value.clone()).is_err());
        value["actions_baseline"][1]["reconciliation"]["correlation_fields"] =
            serde_json::json!(["issue_id"]);
        value["actions_baseline"][1]["reconciliation"]["timeout_s"] = serde_json::json!(u64::MAX);
        assert!(ingest_value(value.clone()).is_err());
        value["actions_baseline"][1]["reconciliation"]["timeout_s"] = serde_json::json!(60);
        ingest_value(value).expect("bounded correlatable declaration");
    }

    #[test]
    fn poll_shapes_must_be_readable_implemented_and_named() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "cursor_kind":"scalar_diff", "item_kind":"issue", "scalar_field":"id"
        });
        ingest_value(value.clone()).expect("read poll");
        value["actions_baseline"][0]["risk"] = serde_json::json!("write");
        assert!(ingest_value(value.clone()).is_err());
        value["actions_baseline"][0]["risk"] = serde_json::json!("read");
        value["actions_baseline"][0]["poll"]["item_kind"] = serde_json::json!(" ");
        assert!(ingest_value(value.clone()).is_err());
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "cursor_kind":"snapshot_diff", "item_kind":"issue", "item_count_ceiling":100
        });
        assert!(ingest_value(value).is_err());
    }

    #[test]
    fn credentials_require_valid_unique_headers_and_primary_roles() {
        let value = rest_manifest_value();
        for patch in [
            serde_json::json!({"key":"X Key:"}),
            serde_json::json!({"required":false}),
            serde_json::json!({"ref_role":"secondary"}),
        ] {
            let mut invalid = value.clone();
            for (key, field) in patch.as_object().unwrap() {
                invalid["credential_bindings"][0][key] = field.clone();
            }
            assert!(ingest_value(invalid).is_err(), "{patch}");
        }
        let mut invalid = value.clone();
        invalid["credential_bindings"] = serde_json::json!([]);
        assert!(ingest_value(invalid).is_err());
        let mut invalid = value;
        let binding = invalid["credential_bindings"][0].clone();
        invalid["credential_bindings"]
            .as_array_mut()
            .unwrap()
            .push(binding);
        assert!(ingest_value(invalid).is_err());
    }

    #[test]
    fn wildcard_and_ambiguous_action_names_are_refused() {
        for name in ["*", " padded", "line\nbreak", ""] {
            let mut value = rest_manifest_value();
            value["actions_baseline"][0]["name"] = serde_json::json!(name);
            assert!(ingest_value(value).is_err(), "{name:?}");
        }
    }

    #[test]
    fn credentialless_tail_refuses_ip_and_single_label_hosts() {
        for host in ["*.com", "com", "127.0.0.1", "::1"] {
            let mut value = rest_manifest_value();
            value["actions_baseline"][0]["http"]["credentialless_tail"] =
                serde_json::json!({"allowed_hosts":[host]});
            assert!(ingest_value(value).is_err(), "{host}");
        }
    }

    #[test]
    fn every_shipped_manifest_is_valid() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
        let mut count = 0;
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "jsonc") {
                let name = path.file_name().unwrap().to_str().unwrap();
                ingest_value(load_catalog(name)).unwrap_or_else(|error| panic!("{name}: {error}"));
                count += 1;
            }
        }
        assert_eq!(count, 20);
    }

    /// Each of these pins a rule the dispatch path DEPENDS on but cannot
    /// enforce for itself. A manifest is externally-authored configuration
    /// that decides what a connector may reach, so a rule stated in a comment
    /// or implied by the code that consumes it — rather than checked at ingest
    /// — is documentation, and a manifest violating it loads clean and fails
    /// later, quietly, at the vendor.
    #[test]
    fn plaintext_transport_to_a_non_loopback_host_is_rejected() {
        // The base URL carries the credential on every request, so http:// to a
        // vendor puts a bearer token on the wire in clear. Emptiness was the
        // only previous check.
        let mut document = rest_manifest_value();
        document["transport"]["url"] = serde_json::json!("http://api.example.com");
        let error = ingest_value(document).expect_err("plaintext vendor URL must be refused");
        assert!(matches!(error, ManifestError::InvalidField(_)), "{error:?}");
    }

    #[test]
    fn plaintext_transport_to_loopback_is_permitted() {
        // Loopback never leaves the machine and is how fixtures reach an
        // in-process stub, so the exception is deliberate rather than lax.
        let mut document = rest_manifest_value();
        document["transport"]["url"] = serde_json::json!("http://127.0.0.1:8080");
        ingest_value(document).expect("loopback stub endpoints stay usable");
    }

    /// The loopback exception is decided on the host the HTTP client will
    /// actually connect to, not on a substring of the URL.
    ///
    /// Each refused case names a URL whose text contains a loopback name while
    /// the connection goes elsewhere: userinfo before an `@` is a username and
    /// password, and a dotted domain that starts with `127.0.0.1` is an ordinary
    /// public name. Each accepted case is a genuine loopback spelling that a
    /// hand-written authority split refused or mis-read, including bracketed
    /// IPv6 with no port.
    #[test]
    fn plaintext_loopback_is_decided_on_the_parsed_host() {
        for url in [
            "http://localhost:80@evil.com/",
            "http://localhost@evil.com/",
            "http://127.0.0.1:8080@evil.com/mcp",
            "http://[::1]@evil.com/",
            "http://127.0.0.1.evil.com/",
            "http://localhost.evil.com/",
            "http://evil.com/?next=http://localhost/",
            "http://evil.com#@localhost",
            " http://127.0.0.1/",
        ] {
            assert!(
                !transport_url_is_acceptable(url),
                "{url} sends the credential in clear to a non-loopback host"
            );
        }
        for url in [
            "http://localhost/",
            "http://LOCALHOST:8080/mcp",
            "http://127.0.0.1/",
            "http://127.0.0.1:8080",
            "http://[::1]/",
            "http://[::1]:8080/mcp",
            "https://api.example.com/v1",
        ] {
            assert!(
                transport_url_is_acceptable(url),
                "{url} names loopback or uses TLS and must be accepted"
            );
        }
    }

    #[test]
    fn an_unimplemented_credential_placement_is_rejected() {
        // Only header placement is implemented. A manifest naming another
        // placement previously loaded clean and was then SKIPPED at dispatch,
        // so the request reached the vendor with no credential at all — a
        // declaration that reads as configuration while silently disabling the
        // thing it configures.
        let mut document = rest_manifest_value();
        document["credential_bindings"][0]["placement"] = serde_json::json!("query");
        let error = ingest_value(document).expect_err("unimplemented placement must be refused");
        assert!(matches!(error, ManifestError::InvalidField(_)), "{error:?}");
    }

    #[test]
    fn a_credential_binding_cannot_inject_headers() {
        // CR/LF in a header name or prefix splits the header block, letting a
        // manifest add headers no reviewer saw.
        for field in ["key", "prefix"] {
            let mut document = rest_manifest_value();
            document["credential_bindings"][0][field] =
                serde_json::json!("X-Evil\r\nX-Injected: 1");
            let error = ingest_value(document)
                .expect_err("control characters in a credential binding must be refused");
            assert!(
                matches!(error, ManifestError::InvalidField(_)),
                "{field}: {error:?}"
            );
        }
    }

    use super::*;
    use std::fs;
    use std::path::Path;

    fn load_catalog(name: &str) -> Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../catalog")
            .join(name);
        let source = fs::read_to_string(path).expect("catalog fixture must exist");
        let normalized = strip_jsonc_for_test(&source);
        serde_json::from_str(&normalized).expect("catalog fixture must be valid JSONC")
    }

    fn strip_jsonc_for_test(source: &str) -> String {
        // The core tests deliberately use only the two catalog documents after
        // their comments are removed. The module owns the production JSONC
        // parser; this helper keeps the pure-core tests independent of subc.
        let mut output = String::with_capacity(source.len());
        let mut in_string = false;
        let mut escaped = false;
        let mut chars = source.chars().peekable();
        while let Some(character) = chars.next() {
            if in_string {
                output.push(character);
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    in_string = false;
                }
                continue;
            }
            if character == '"' {
                in_string = true;
                output.push(character);
            } else if character == '/' && chars.peek() == Some(&'/') {
                let _ = chars.next();
                for next in chars.by_ref() {
                    if next == '\n' {
                        output.push(next);
                        break;
                    }
                }
            } else {
                output.push(character);
            }
        }
        output.replace(",\n  }", "\n  }").replace(",\n}", "\n}")
    }

    #[test]
    fn exa_manifest_parses() {
        let parsed = ingest_value(load_catalog("exa.jsonc")).expect("exa manifest parses");
        assert_eq!(parsed.manifest.key, "exa");
        assert_eq!(parsed.manifest.tier, Tier::S1);
        assert!(parsed.content_hash.starts_with("sha256:"));
        let round_trip =
            ingest_value(serde_json::to_value(&parsed.manifest).expect("serialize exa"))
                .expect("round-trip exa manifest");
        assert_eq!(round_trip.manifest, parsed.manifest);
    }

    #[test]
    fn reconciliation_write_target_is_refused_at_ingest() {
        let mut document = load_catalog("linear.jsonc");
        document["actions_baseline"] = serde_json::json!([
            {"name": "create", "risk": "write", "reconciliation": {
                "correlation_fields": ["title"], "read_back_action": "lookup", "timeout_s": 120
            }},
            {"name": "lookup", "risk": "write"}
        ]);
        let error = ingest_value(document).expect_err("write read-back must be refused");
        assert!(
            error.to_string().contains("reconciliation_target_not_read"),
            "{error}"
        );
        assert!(error.to_string().contains("'create'"), "{error}");
        assert!(error.to_string().contains("'lookup'"), "{error}");
    }

    #[test]
    fn reconciliation_missing_target_is_refused_at_ingest() {
        let mut document = load_catalog("linear.jsonc");
        document["actions_baseline"] = serde_json::json!([
            {"name": "create", "risk": "write", "reconciliation": {
                "correlation_fields": ["title"], "read_back_action": "missing", "timeout_s": 120
            }}
        ]);
        let error = ingest_value(document).expect_err("missing read-back must be refused");
        assert!(
            error.to_string().contains("reconciliation_target_missing"),
            "{error}"
        );
        assert!(error.to_string().contains("'create'"), "{error}");
        assert!(error.to_string().contains("'missing'"), "{error}");
    }

    #[test]
    fn reconciliation_self_target_is_refused_at_ingest() {
        let mut document = load_catalog("linear.jsonc");
        document["actions_baseline"] = serde_json::json!([
            {"name": "lookup", "risk": "read", "reconciliation": {
                "correlation_fields": ["title"], "read_back_action": "lookup", "timeout_s": 120
            }}
        ]);
        let error =
            ingest_value(document).expect_err("self read-back must be refused even for reads");
        assert!(
            error.to_string().contains("reconciliation_self_target"),
            "{error}"
        );
    }

    #[test]
    fn linear_manifest_omits_unimplemented_reconciliation() {
        let parsed = ingest_value(load_catalog("linear.jsonc")).expect("linear manifest parses");
        assert_eq!(parsed.manifest.key, "linear");
        assert_eq!(parsed.manifest.auth.mode, AuthMode::Oauth);
        assert!(parsed
            .manifest
            .actions_baseline
            .iter()
            .all(|action| action.reconciliation.is_none()));
        let round_trip =
            ingest_value(serde_json::to_value(&parsed.manifest).expect("serialize linear"))
                .expect("round-trip linear manifest");
        assert_eq!(round_trip.manifest, parsed.manifest);
    }

    #[test]
    fn sentry_manifest_omits_unreviewed_filters_and_reconciliation() {
        let parsed = ingest_value(load_catalog("sentry.jsonc")).expect("sentry manifest parses");
        assert_eq!(parsed.manifest.key, "sentry");
        assert_eq!(parsed.manifest.tier, Tier::S2);
        assert_eq!(parsed.manifest.auth.mode, AuthMode::ApiKey);
        assert_eq!(parsed.manifest.transport.url, "https://mcp.sentry.dev/mcp");
        assert!(parsed.manifest.resource_filters.required.is_empty());
        assert!(parsed.manifest.resource_filters.write_enabling.is_empty());
        let comment = parsed
            .manifest
            .actions_baseline
            .iter()
            .find(|action| action.name == "comment_issue")
            .expect("comment_issue baseline");
        assert_eq!(comment.risk, Risk::Write);
        assert!(comment.reconciliation.is_none());
        assert_eq!(comment.idempotency, None);
        let assign = parsed
            .manifest
            .actions_baseline
            .iter()
            .find(|action| action.name == "assign_issue")
            .expect("assign_issue baseline");
        assert_eq!(assign.idempotency, None);
        let round_trip =
            ingest_value(serde_json::to_value(&parsed.manifest).expect("serialize sentry"))
                .expect("round-trip sentry manifest");
        assert_eq!(round_trip.manifest, parsed.manifest);
    }

    #[test]
    fn notion_manifest_parses_as_s3_floor_oauth() {
        let parsed = ingest_value(load_catalog("notion.jsonc")).expect("notion manifest parses");
        assert_eq!(parsed.manifest.key, "notion");
        assert_eq!(parsed.manifest.tier, Tier::S3);
        assert_eq!(parsed.manifest.auth.mode, AuthMode::Oauth);
        assert_eq!(parsed.manifest.transport.url, "https://mcp.notion.com/mcp");
        assert!(parsed.manifest.resource_filters.required.is_empty());
        assert!(parsed.manifest.resource_filters.optional.is_empty());
        assert!(parsed.manifest.resource_filters.write_enabling.is_empty());
        let create = parsed
            .manifest
            .actions_baseline
            .iter()
            .find(|action| action.name == "create_page")
            .expect("create_page baseline");
        assert_eq!(create.risk, Risk::Write);
        assert!(create.reconciliation.is_none());
        assert_eq!(create.idempotency, None);
        let oauth = parsed.manifest.auth.oauth.as_ref().expect("oauth profile");
        assert_eq!(oauth.profile_id, "notion");
        let round_trip =
            ingest_value(serde_json::to_value(&parsed.manifest).expect("serialize notion"))
                .expect("round-trip notion manifest");
        assert_eq!(round_trip.manifest, parsed.manifest);
    }

    #[test]
    fn gcal_manifest_parses_as_read_only_s2_oauth() {
        let parsed = ingest_value(load_catalog("gcal.jsonc")).expect("gcal manifest parses");
        assert_eq!(parsed.manifest.key, "gcal");
        assert_eq!(parsed.manifest.tier, Tier::S2);
        assert_eq!(parsed.manifest.auth.mode, AuthMode::Oauth);
        assert!(parsed.manifest.resource_filters.required.is_empty());
        assert!(parsed.manifest.resource_filters.optional.is_empty());
        assert!(parsed.manifest.resource_filters.write_enabling.is_empty());
        assert_eq!(parsed.manifest.actions_baseline.len(), 3);
        assert!(parsed
            .manifest
            .actions_baseline
            .iter()
            .all(|action| action.risk == Risk::Read));
        let oauth = parsed.manifest.auth.oauth.as_ref().expect("oauth profile");
        assert_eq!(oauth.profile_id, "google-calendar");
        let round_trip =
            ingest_value(serde_json::to_value(&parsed.manifest).expect("serialize gcal"))
                .expect("round-trip gcal manifest");
        assert_eq!(round_trip.manifest, parsed.manifest);
    }

    #[test]
    fn inline_oauth_endpoint_is_rejected() {
        let mut value = load_catalog("linear.jsonc");
        value["auth"]["oauth"]["token_url"] = Value::String("https://example.invalid/token".into());
        let error = ingest_value(value).expect_err("inline OAuth endpoint must be rejected");
        assert!(error.to_string().contains("token_url"));
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let mut value = load_catalog("exa.jsonc");
        value["unexpected"] = Value::Bool(true);
        assert!(matches!(
            ingest_value(value),
            Err(ManifestError::InvalidJson(_))
        ));
    }

    /// A minimal valid rest_api manifest used by the HTTP-shape validation
    /// tests; each test mutates one field and expects rejection.
    #[test]
    #[ignore = "manual read-only manifest validation measurement"]
    fn measure_manifest_validation() {
        let value = rest_manifest_value();
        let start = std::time::Instant::now();
        for _ in 0..2_000 {
            std::hint::black_box(ingest_value(value.clone()).unwrap());
        }
        println!("2000 full ingests: {:?}", start.elapsed());
        let start = std::time::Instant::now();
        for _ in 0..2_000 {
            let manifest = serde_path_to_error::deserialize::<_, AppManifest>(&value).unwrap();
            validate(&manifest).unwrap();
            std::hint::black_box(manifest);
        }
        println!(
            "2000 borrowed validated deserializations: {:?}",
            start.elapsed()
        );
    }

    fn rest_manifest_value() -> Value {
        serde_json::json!({
            "schema_version": 1,
            "key": "restdemo",
            "name": "REST Demo",
            "description": "test rest manifest",
            "reuse_path": "openapi_shim",
            "reuse_rationale": "test",
            "tier": "S2",
            "transport": {"kind": "rest_api", "url": "http://127.0.0.1:0"},
            "auth": {"mode": "api_key"},
            "credential_bindings": [{
                "ref_role": "api_key", "placement": "header", "key": "Authorization",
                "prefix": "Bearer ", "required": true
            }],
            "resource_filters": {"required": [], "optional": [], "write_enabling": []},
            "actions_baseline": [
                {
                    "name": "get_issue",
                    "risk": "read",
                    "http": {
                        "method": "GET",
                        "path": "/v1/issues/{issue_id}",
                        "args_schema": {
                            "type": "object",
                            "properties": {"issue_id": {"type": "string"}},
                            "required": ["issue_id"]
                        }
                    }
                },
                {
                    "name": "create_issue",
                    "risk": "write",
                    "http": {
                        "method": "POST",
                        "path": "/v1/issues",
                        "args_schema": {
                            "type": "object",
                            "properties": {"title": {"type": "string"}}
                        }
                    }
                }
            ],
            "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 60}},
            "availability": "ga"
        })
    }

    /// `defaults.rate_limit` is optional and ignored: plexus enforces no
    /// per-connection call budget. A manifest without it parses, so a later
    /// catalog can drop it; one that still carries it parses unchanged and
    /// keeps it in the normalized form its content hash is computed from, so
    /// the shipped catalogs keep their hashes across this change.
    #[test]
    fn defaults_rate_limit_is_optional_and_ignored() {
        let carried = ingest_value(rest_manifest_value())
            .expect("a catalog that still carries defaults.rate_limit must parse");
        assert_eq!(
            serde_json::to_value(&carried.manifest).unwrap()["defaults"]["rate_limit"],
            serde_json::json!({"calls_per_min": 60}),
            "a carried rate_limit must stay in the hashed form"
        );
        let mut omitted = rest_manifest_value();
        omitted["defaults"]
            .as_object_mut()
            .unwrap()
            .remove("rate_limit");
        let omitted =
            ingest_value(omitted).expect("a manifest without defaults.rate_limit must parse");
        assert!(serde_json::to_value(&omitted.manifest).unwrap()["defaults"]
            .get("rate_limit")
            .is_none());
        let mut zero = rest_manifest_value();
        zero["defaults"]["rate_limit"] = serde_json::json!({"calls_per_min": 0});
        ingest_value(zero).expect("an ignored field carries no validation");
    }

    #[test]
    fn legacy_rest_manifest_without_request_constants_still_ingests() {
        let ingested = ingest_value(rest_manifest_value()).expect("legacy REST manifest");
        let operation = ingested.manifest.actions_baseline[0].http.as_ref().unwrap();
        assert!(operation.request_constants.is_none());
        assert!(serde_json::to_value(operation)
            .unwrap()
            .get("request_constants")
            .is_none());
    }

    #[test]
    fn ci_runs_and_http_request_constants_ingest_and_round_trip() {
        let mut document = rest_manifest_value();
        document["actions_baseline"][0]["poll"] = serde_json::json!({
            "cursor_kind": "ci_runs", "item_kind": "ci_run", "items_field": "workflow_runs"
        });
        document["actions_baseline"][0]["http"]["request_constants"] =
            serde_json::json!({"per_page": 100});
        let ingested = ingest_value(document).expect("CI discovery manifest");
        let action = &ingested.manifest.actions_baseline[0];
        assert_eq!(
            action.poll.as_ref().unwrap().cursor_kind,
            CursorKind::CiRuns
        );
        assert_eq!(CursorKind::CiRuns.as_str(), "ci_runs");
        let serialized = serde_json::to_value(&ingested.manifest).unwrap();
        assert_eq!(
            serialized["actions_baseline"][0]["http"]["request_constants"]["per_page"],
            100
        );
        assert_eq!(
            ingest_value(serialized).unwrap().manifest,
            ingested.manifest
        );
    }

    #[test]
    fn new_manifest_fields_do_not_accept_unknown_http_or_poll_fields() {
        for section in ["http", "poll"] {
            let mut document = rest_manifest_value();
            document["actions_baseline"][0]["http"]["request_constants"] =
                serde_json::json!({"per_page": 100});
            document["actions_baseline"][0]["poll"] = serde_json::json!({
                "cursor_kind": "ci_runs", "item_kind": "ci_run"
            });
            document["actions_baseline"][0][section]["unexpected"] = serde_json::json!(true);
            let error = ingest_value(document).expect_err("unknown field must be refused");
            assert!(error.to_string().contains("unexpected"), "{error}");
        }
    }

    #[test]
    fn http_request_constants_reject_blank_keys() {
        let mut document = rest_manifest_value();
        document["actions_baseline"][0]["http"]["request_constants"] =
            serde_json::json!({" ": 100});
        let error = ingest_value(document).expect_err("blank constant key");
        assert!(
            error.to_string().contains("http.request_constants keys"),
            "{error}"
        );
    }

    #[test]
    fn poll_cannot_supply_http_request_constant_keys() {
        for (key, poll) in [
            (
                "per_page",
                serde_json::json!({"cursor_kind": "ci_runs", "item_kind": "ci_run", "request_constants": {"per_page": 100}}),
            ),
            (
                "since",
                serde_json::json!({"cursor_kind": "ordered_timestamp", "item_kind": "issue", "timestamp_field": "updated_at", "tiebreaker_id_field": "id", "request_constants": {}}),
            ),
            (
                "sync_token",
                serde_json::json!({"cursor_kind": "sync_token", "item_kind": "event"}),
            ),
            (
                "after",
                serde_json::json!({"cursor_kind": "ordered_timestamp", "item_kind": "issue", "timestamp_field": "updated_at", "tiebreaker_id_field": "id", "request_constants": {"per_page": 100}, "request_page_size_field": "per_page", "pagination": {"request_cursor_field": "after", "response_cursor_pointer": "/next"}}),
            ),
        ] {
            let mut document = rest_manifest_value();
            document["actions_baseline"][0]["poll"] = poll;
            document["actions_baseline"][0]["http"]["request_constants"] =
                serde_json::json!({key: 100});
            let error =
                ingest_value(document).expect_err("poll cannot supply a transport constant");
            assert!(
                error
                    .to_string()
                    .contains(&format!("poll supplies HTTP request constant '{key}'")),
                "{error}"
            );
        }
    }

    #[test]
    fn rest_manifest_with_http_operations_parses() {
        let parsed = ingest_value(rest_manifest_value()).expect("rest manifest parses");
        assert_eq!(parsed.manifest.key, "restdemo");
        assert_eq!(parsed.manifest.transport.kind, TransportKind::RestApi);
        let get_issue = &parsed.manifest.actions_baseline[0];
        let http = get_issue.http.as_ref().expect("http operation");
        assert_eq!(http.method, HttpMethod::Get);
        assert_eq!(http.path, "/v1/issues/{issue_id}");
        let round_trip =
            ingest_value(serde_json::to_value(&parsed.manifest).expect("serialize restdemo"))
                .expect("round-trip rest manifest");
        assert_eq!(round_trip.manifest, parsed.manifest);
    }

    // Pins: a rest_api vendor whose action has no HTTP shape is unroutable, so
    // ingest must refuse it rather than letting the action sit in the catalog
    // declared but unreachable.
    #[test]
    fn rest_action_without_http_is_rejected() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][1]["http"] = Value::Null;
        let error = ingest_value(value).expect_err("rest action without http must be rejected");
        assert!(
            error.to_string().contains("must declare http"),
            "unexpected error: {error}"
        );
    }

    // Pins: on a non-rest transport the http field would be silently ignored,
    // so ingest must refuse it rather than let a reviewer believe they declared
    // a routing the transport never reads.
    #[test]
    fn http_on_non_rest_transport_is_rejected() {
        let mut value = rest_manifest_value();
        value["transport"]["kind"] = Value::String("mcp_remote".to_string());
        let error = ingest_value(value).expect_err("http on mcp_remote must be rejected");
        assert!(
            error.to_string().contains("transport.kind is not rest_api"),
            "unexpected error: {error}"
        );
    }

    // Pins: a path parameter with no args_schema property can never be filled
    // from invocation args, so the template is refused at ingest.
    #[test]
    fn path_placeholder_missing_from_args_schema_is_rejected() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["http"]["path"] =
            Value::String("/v1/issues/{issue_id}/comments/{comment_id}".to_string());
        let error =
            ingest_value(value).expect_err("placeholder missing from schema must be rejected");
        assert!(
            error.to_string().contains("comment_id"),
            "unexpected error: {error}"
        );
    }

    // Pins: the path must be absolute; a relative path would be joined onto the
    // base URL ambiguously (resolving against its last segment instead of its
    // origin).
    #[test]
    fn relative_path_is_rejected() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["http"]["path"] = Value::String("v1/issues".to_string());
        let error = ingest_value(value).expect_err("relative path must be rejected");
        assert!(
            error.to_string().contains("must be absolute"),
            "unexpected error: {error}"
        );
    }

    // Pins: '..' segments could climb out of the base URL's path prefix.
    #[test]
    fn path_traversal_is_rejected() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["http"]["path"] =
            Value::String("/v1/../admin/{issue_id}".to_string());
        let error = ingest_value(value).expect_err("path traversal must be rejected");
        assert!(
            error.to_string().contains("'..'"),
            "unexpected error: {error}"
        );
    }

    // Pins: an embedded scheme could turn the joined URL into a redirect to an
    // attacker-chosen origin (SSRF guard).
    #[test]
    fn path_with_scheme_is_rejected() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["http"]["path"] =
            Value::String("/v1/redirect/http://evil.example/{issue_id}".to_string());
        let error = ingest_value(value).expect_err("path with scheme must be rejected");
        assert!(
            error.to_string().contains("scheme"),
            "unexpected error: {error}"
        );
    }

    // Pins: a leading '//' is a network-path reference; joined onto the base
    // URL it replaces the authority and sends the call to another host.
    #[test]
    fn authority_path_is_rejected() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["http"]["path"] =
            Value::String("//evil.example/x".to_string());
        let error = ingest_value(value).expect_err("authority path must be rejected");
        assert!(
            error.to_string().contains("authority"),
            "unexpected error: {error}"
        );
    }

    // Pins: an unterminated placeholder makes the template unrenderable.
    #[test]
    fn unterminated_placeholder_is_rejected() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["http"]["path"] =
            Value::String("/v1/issues/{issue_id".to_string());
        let error = ingest_value(value).expect_err("unterminated placeholder must be rejected");
        assert!(
            error.to_string().contains("unterminated"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn ordered_timestamp_poll_requires_a_stable_tiebreaker() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "item_kind": "issue",
            "cursor_kind": "ordered_timestamp",
            "timestamp_field": "updated_at"
        });
        let error = ingest_value(value).expect_err("bare timestamp cursor must be rejected");
        assert!(
            error.to_string().contains("tiebreaker_id_field"),
            "unexpected error: {error}"
        );
    }

    /// Mutation proved: accepting an absent declaration makes the `expect_err`
    /// assertion fail, so this is not a test that merely exercises rejection.
    #[test]
    fn ordered_timestamp_poll_requires_request_constants() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "item_kind": "issue",
            "cursor_kind": "ordered_timestamp",
            "timestamp_field": "updated_at",
            "tiebreaker_id_field": "id"
        });
        let error = ingest_value(value).expect_err("unreviewed ordering must be rejected");
        assert!(
            error
                .to_string()
                .contains("action 'get_issue' poll.ordered_timestamp requires request_constants"),
            "unexpected error: {error}"
        );
    }

    /// A schema error names the field it came from.
    ///
    /// serde_json's own error reports the bad value and the expected type but
    /// never the path, so a one-field typo in a reviewed vendor manifest
    /// produced "invalid type: string, expected u32" -- a message that fits
    /// every numeric field in the schema and identifies none of them. Manifest
    /// review is the one place a human reads these errors, and the refusal was
    /// the least informative output in the crate while the success path was
    /// thoroughly evidenced.
    ///
    /// Two shapes are covered because they fail through different serde paths:
    /// an unknown enum variant and a wrong scalar type. The root-level case is
    /// asserted separately: an error with no path must NOT be dressed with a
    /// location, since naming a field there would be a fabrication.
    #[test]
    fn a_schema_error_names_the_field_it_came_from() {
        let mut value = rest_manifest_value();
        value["availability"] = serde_json::json!({"nested": "object"});
        let error = ingest_value(value).expect_err("a bad enum value must be refused");
        assert!(
            error.to_string().contains("at 'availability'"),
            "the error must name the offending field: {error}"
        );

        let mut value = rest_manifest_value();
        value["schema_version"] = serde_json::json!("not_a_number");
        let error = ingest_value(value).expect_err("a wrong scalar type must be refused");
        assert!(
            error.to_string().contains("at 'schema_version'"),
            "a type error must name its field, not just the expected type: {error}"
        );

        // A failure at the document ROOT has no field to name and must not
        // acquire a meaningless one. Asserted against "at '.'" specifically,
        // because that is what the library actually produces for a root path --
        // an earlier version of this test checked for "at ''" and passed with
        // the guard disabled, since that string never occurs either way.
        let error = ingest_value(serde_json::json!("not an object"))
            .expect_err("a non-object manifest must be refused");
        assert!(
            !error.to_string().contains("at '.'"),
            "a root-level error must not be dressed with a location naming nothing: {error}"
        );
        assert!(
            error.to_string().contains("expected struct AppManifest"),
            "the root error must still carry serde's own explanation: {error}"
        );
    }

    /// A transport kind the runtime cannot route is refused at ingest.
    ///
    /// `local_script` and `local_helper` have no dispatch paths. Without this
    /// check, they would be silently treated as MCP servers and fail only after
    /// review at dispatch time.
    #[test]
    fn a_transport_kind_with_no_dispatch_route_is_refused() {
        for kind in ["local_script", "local_helper"] {
            let mut value = rest_manifest_value();
            value["transport"]["kind"] = serde_json::json!(kind);
            let error =
                ingest_value(value).expect_err("a kind with no dispatch route must be refused");
            assert!(
                error.to_string().contains("has no dispatch route")
                    && error.to_string().contains(kind),
                "the refusal must name the kind the reviewer typed: {error}"
            );
        }

        // The routable REST kind still ingests, so the refusal narrows rather
        // than closing the catalog.
        ingest_value(rest_manifest_value()).expect("rest_api must remain ingestable");
        // The mcp_remote leg drops the `http` block from EVERY action, because
        // that declaration is REST-only: leaving one would fail for an unrelated
        // reason and the leg would prove nothing about the transport check.
        // Written per-action rather than for the first, since the fixture
        // carries several and only the first was obvious.
        let mut mcp = rest_manifest_value();
        mcp["transport"]["kind"] = serde_json::json!("mcp_remote");
        mcp["transport"]["url"] = serde_json::json!("https://example.invalid/mcp");
        for action in mcp["actions_baseline"]
            .as_array_mut()
            .expect("actions are an array")
        {
            action
                .as_object_mut()
                .expect("action is an object")
                .remove("http");
        }
        ingest_value(mcp).expect("mcp_remote must remain ingestable");
    }

    /// Stdio adapter dispatch does not have catalog discovery/freshness support,
    /// so reviewing a manifest must refuse that transport until both exist.
    #[test]
    fn mcp_stdio_requires_a_catalog_dispatch_route() {
        let value = serde_json::json!({
            "schema_version": 1,
            "key": "stdio_demo",
            "name": "stdio demo",
            "description": "minimal route-plane MCP manifest",
            "reuse_path": "mcp_direct",
            "reuse_rationale": "adapter-owned child process",
            "tier": "S2",
            "transport": {"kind": "mcp_stdio", "url": "https://example.invalid/mcp"},
            "auth": {"mode": "api_key"},
            "credential_bindings": [{
                "ref_role": "api_key", "placement": "header", "key": "Authorization",
                "prefix": "Bearer ", "required": true
            }],
            "resource_filters": {"required": [], "optional": [], "write_enabling": []},
            "actions_baseline": [{"name": "read_status", "risk": "read"}],
            "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 60}},
            "availability": "ga"
        });

        let error =
            ingest_value(value.clone()).expect_err("mcp_stdio must refuse without catalog support");
        assert!(
            error.to_string().contains("mcp_stdio"),
            "refusal must name mcp_stdio"
        );

        let mut unroutable_twin = value;
        unroutable_twin["transport"]["kind"] = serde_json::json!("local_script");
        let error = ingest_value(unroutable_twin)
            .expect_err("the same manifest must refuse an unroutable kind");
        assert!(
            error.to_string().contains("local_script")
                && error.to_string().contains("no dispatch route"),
            "the refusal must name the unroutable transport kind: {error}"
        );
    }

    /// A scalar-diff shape must name its field, and must not name stream
    /// fields.
    ///
    /// The field has no honest default: a wrong or absent name yields no value
    /// on every poll, which a change test reads as "unchanged", so the watch
    /// would report healthy silence forever while observing nothing. Refused at
    /// ingest for the same reason ordered-timestamp refuses an undeclared
    /// ordering.
    ///
    /// Stream fields are refused rather than ignored because declaring one means
    /// the reviewer believed they were writing a different kind of shape.
    /// Silently accepting it would leave that misunderstanding in the catalog,
    /// where the next reader inherits it as though it were reviewed.
    ///
    /// The accept leg is asserted too: without it, refusing every scalar-diff
    /// shape would pass both refusal assertions.
    ///
    /// Mutation proved: dropping the scalar_field check accepts the first case;
    /// dropping the stream-field check accepts the second.
    #[test]
    fn scalar_diff_poll_requires_its_field_and_refuses_stream_fields() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "item_kind": "issue",
            "cursor_kind": "scalar_diff"
        });
        let error = ingest_value(value).expect_err("a scalar shape without its field must refuse");
        assert!(
            error
                .to_string()
                .contains("action 'get_issue' poll.scalar_diff requires scalar_field"),
            "unexpected error: {error}"
        );

        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "item_kind": "issue",
            "cursor_kind": "scalar_diff",
            "scalar_field": "tag_name",
            "items_field": "releases"
        });
        let error =
            ingest_value(value).expect_err("a scalar shape naming a stream field must refuse");
        assert!(
            error.to_string().contains("must not declare stream fields"),
            "unexpected error: {error}"
        );

        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "item_kind": "issue",
            "cursor_kind": "scalar_diff",
            "scalar_field": "tag_name"
        });
        ingest_value(value).expect("a well-formed scalar shape must be accepted");
    }

    /// This test ensures that an explicit empty `request_constants` map is
    /// accepted; validation must not reject every ordered-timestamp shape.
    #[test]
    fn ordered_timestamp_poll_accepts_explicit_empty_request_constants() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "item_kind": "issue",
            "cursor_kind": "ordered_timestamp",
            "timestamp_field": "updated_at",
            "tiebreaker_id_field": "id",
            "request_constants": {}
        });
        assert!(
            value["actions_baseline"][0]["poll"]
                .get("request_constants")
                .and_then(Value::as_object)
                .is_some_and(|constants| constants.is_empty()),
            "fixture must contain an explicit empty request_constants map"
        );
        let parsed = ingest_value(value).expect("reviewed default ordering must be accepted");
        assert_eq!(
            parsed.manifest.actions_baseline[0]
                .poll
                .as_ref()
                .expect("poll shape")
                .request_constants,
            Some(std::collections::BTreeMap::new())
        );
    }

    /// Mutation proved: comparing against the hardcoded `since` name accepts
    /// this `after` collision and fails the refusal assertion.
    #[test]
    fn ordered_timestamp_request_constants_cannot_use_declared_since_field() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "item_kind": "issue",
            "cursor_kind": "ordered_timestamp",
            "timestamp_field": "updated_at",
            "tiebreaker_id_field": "id",
            "request_since_field": "after",
            "request_constants": {"after": "pinned"}
        });
        let error = ingest_value(value).expect_err("cursor request key collision must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("get_issue"),
            "error must name the action: {message}"
        );
        assert!(
            message.contains("after"),
            "error must name the colliding key: {message}"
        );
    }

    /// Mutation proved: replacing the derived default with an unrelated name
    /// makes this omitted-field `since` collision pass ingest.
    #[test]
    fn ordered_timestamp_request_constants_cannot_use_default_since_field() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "item_kind": "issue",
            "cursor_kind": "ordered_timestamp",
            "timestamp_field": "updated_at",
            "tiebreaker_id_field": "id",
            "request_constants": {"since": "pinned"}
        });
        let error = ingest_value(value).expect_err("default cursor key collision must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("get_issue"),
            "error must name the action: {message}"
        );
        assert!(
            message.contains("since"),
            "error must name the default key: {message}"
        );
    }

    /// Mutation proved: allowing a blank key makes the `expect_err` assertion
    /// fail before dispatch can be reached.
    #[test]
    fn request_constants_reject_an_empty_key() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "item_kind": "issue",
            "cursor_kind": "ordered_timestamp",
            "timestamp_field": "updated_at",
            "tiebreaker_id_field": "id",
            "request_constants": {"": true}
        });
        let error = ingest_value(value).expect_err("empty request constant key must be rejected");
        assert!(
            error
                .to_string()
                .contains("request_constants keys must not be empty"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn poll_cursor_shapes_round_trip_with_aliases() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "item_kind": "issue",
            "cursor_kind": "ordered_timestamp",
            "timestamp_field": "updated_at",
            "tiebreaker_field": "id",
            "request_constants": {}
        });
        let parsed = ingest_value(value).expect("ordered cursor parses");
        let poll = parsed.manifest.actions_baseline[0]
            .poll
            .as_ref()
            .expect("poll shape");
        assert_eq!(poll.cursor_kind, CursorKind::OrderedTimestamp);
        assert_eq!(poll.tiebreaker_id_field.as_deref(), Some("id"));
    }

    #[test]
    fn ordered_timestamp_request_since_field_must_not_be_empty() {
        // An empty request parameter name would dispatch an argument the vendor
        // cannot match, yielding an unfiltered first page every cycle that
        // dedupe silently discards — so ingest refuses it.
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "item_kind": "issue",
            "cursor_kind": "ordered_timestamp",
            "timestamp_field": "updated_at",
            "tiebreaker_id_field": "id",
            "request_since_field": "   ",
            "request_constants": {}
        });
        let error = ingest_value(value).expect_err("empty request_since_field must be rejected");
        assert!(
            error.to_string().contains("request_since_field"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn github_list_issues_declares_a_usable_ordered_poll_shape() {
        let parsed = ingest_value(load_catalog("github.jsonc")).expect("github manifest parses");
        let poll = parsed
            .manifest
            .actions_baseline
            .iter()
            .find(|action| action.name == "list_issues")
            .and_then(|action| action.poll.as_ref())
            .expect("list_issues poll shape");
        assert_eq!(poll.cursor_kind, CursorKind::OrderedTimestamp);
        assert_eq!(poll.timestamp_field.as_deref(), Some("updated_at"));
        assert_eq!(poll.tiebreaker_id_field.as_deref(), Some("number"));
        assert_eq!(poll.items_field.as_deref(), Some("issues"));
        assert_eq!(poll.request_since_field.as_deref(), Some("since"));
        let constants = poll
            .request_constants
            .as_ref()
            .expect("reviewed GitHub ordering constants");
        assert_eq!(
            constants.get("orderBy"),
            Some(&serde_json::json!("UPDATED_AT"))
        );
        assert_eq!(constants.get("direction"), Some(&serde_json::json!("ASC")));
    }

    #[test]
    fn ordered_timestamp_request_since_field_round_trips() {
        let mut value = rest_manifest_value();
        value["actions_baseline"][0]["poll"] = serde_json::json!({
            "item_kind": "issue",
            "cursor_kind": "ordered_timestamp",
            "timestamp_field": "updated_at",
            "tiebreaker_id_field": "id",
            "request_since_field": "after",
            "request_constants": {}
        });
        let parsed = ingest_value(value).expect("ordered cursor with request_since_field parses");
        let poll = parsed.manifest.actions_baseline[0]
            .poll
            .as_ref()
            .expect("poll shape");
        assert_eq!(poll.request_since_field.as_deref(), Some("after"));
    }
}
