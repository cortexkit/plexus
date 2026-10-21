//! The poll executor: performs exactly one poll cycle for one subscription.
//!
//! Timers, due-selection, backoff and circuit breakers belong to the scheduler.
//! This executor bounds page drains and actor retries and prevents overlapping
//! probe calls. This module is the part where correctness
//! is subtle — the distinction between a vendor failure and an authorization
//! denial, atomic cursor advancement, and visible coverage gaps — and it must be
//! provable on its own before anything drives it automatically. Nothing in this
//! module runs on a clock; a caller invokes [`Poller::poll_once`] once.

mod accounting;
mod budget;
mod ci_runs;
pub(crate) use accounting::forget_subscription;
pub use accounting::{poll_accounting_metrics, DropReason};
use budget::expired as pass_budget_expired;

use std::cell::Cell;
use std::collections::BTreeSet;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use crate::actor_attribution::{ActorAttribution, ActorUnknownCode};
use crate::credentials::CredentialSource;
use crate::governance::{
    AuthorizationRequest, CredentialDenial, Denial, GovernanceEngine, PollAuthorizationRefusal,
    TransportOutcome,
};
use crate::manifest::PollShape;
use crate::storage::{
    event_outbox::{
        RepoIdUpdate, RepoResolutionAdmission, RETENTION_MAX_WINDOW_MS as MAX_WINDOW_MS,
        SORTED_HEAD_REPLAY_WINDOW_MS,
    },
    now_ms, ActorSource, EventHeaders, KeyedEventIdentity, KeyedPollEventInput, PollEventInput,
    PollGapInput, TriggerEventInsertOutcome, TriggerSubscription,
};
use crate::transport::Transport;
use plexus_probe::{ActionInvoker, ProbeError, ProbeSandbox, ProbeValue, ReturnSchema};

/// Stored-cursor and request-argument field used by the sync-token strategy.
const CURSOR_TOKEN_KEY: &str = "sync_token";
pub(crate) const GITHUB_ACTIONS_CONNECTION: &str = "conn-github-actions";
/// Response field holding the records a sync-token poll returns.
const RESPONSE_ITEMS_KEY: &str = "items";
/// Response field holding the opaque token that resumes the next poll.
const RESPONSE_NEXT_CURSOR_KEY: &str = "next_cursor";
/// Per-record field used as the stable, dedupe-safe vendor event id.
const ITEM_ID_KEY: &str = "id";

/// Stored-cursor field holding the settled high-water mark (epoch milliseconds)
/// for the ordered-timestamp strategy.
const WATERMARK_MS_KEY: &str = "watermark_ms";
/// Stored-cursor field holding the stable id of the row that set the watermark
/// as the composite watermark's tiebreaker. It orders equal-timestamp rows;
/// the request filter itself uses the timestamp and overlap window.
const WATERMARK_ID_KEY: &str = "watermark_id";
/// Stored-cursor field holding the adaptive overlap window (milliseconds).
const WINDOW_MS_KEY: &str = "window_ms";
/// Stored-cursor field holding when the overlap window last widened or
/// narrowed (epoch milliseconds, host clock). The window narrows again only
/// after [`WINDOW_DECAY_QUIET_MS`] have passed since then with no late row, so
/// this is the start of the current quiet period. Absent means the quiet period
/// starts at the next poll.
const WINDOW_CHANGED_MS_KEY: &str = "window_changed_ms";
const PAGE_RESUME_KEY: &str = "page_resume";
const RESPONSE_SHAPE_INVALID: &str = "response_shape_invalid";
const SUBSCRIPTION_NOT_ACTIVE: &str = "subscription_not_active";
/// Default REQUEST parameter for the ordered-timestamp resume point. GitHub
/// issues and notifications use `since`; a manifest may declare another name
/// (PostHog uses `after`) through `PollShape::request_since_field`.
const REQUEST_SINCE_KEY: &str = "since";

/// Initial overlap window for the ordered-timestamp strategy: 60 seconds.
///
/// A vendor writing a row's timestamp and making that row visible are not
/// atomic, so the resume point is pulled back by this window and the re-fetched
/// boundary rows are discarded by dedupe. The window is sized by the cost of
/// DUPLICATES — cheap and bounded, because dedupe absorbs them — rather than by
/// optimism about lag, where a miss is silent and permanent. Sixty seconds
/// covers ordinary write/visibility skew with a wide margin while keeping the
/// duplicate re-fetch small relative to a typical page; the adaptive widening in
/// [`OrderedTimestampStrategy::derive`] grows it whenever real evidence shows it
/// was too small. It narrows again only after a quiet day (see
/// [`WINDOW_DECAY_QUIET_MS`]), and never below this value.
const INITIAL_WINDOW_MS: i64 = 60_000;
/// Bound sequential work to five list pages per ordered-timestamp poll.
const ORDERED_TIMESTAMP_MAX_PAGES_PER_POLL: usize = 5;
/// How long a widened overlap window must go without a late row before it is
/// halved back toward [`INITIAL_WINDOW_MS`]: one day.
///
/// One late row is evidence about the vendor at that moment, not a permanent
/// property of the watch. Webhooks deliver most changes before a poll would, so
/// a window left wide forever only buys duplicate refetches. A day is long
/// enough that a vendor whose lag recurs daily keeps its wider window, and
/// short enough that a one-off spike is undone within days.
const WINDOW_DECAY_QUIET_MS: i64 = 24 * 60 * 60 * 1000;
/// Earliest and latest epoch milliseconds a stored ordered-timestamp watermark
/// may hold: the range [`iso8601::parse_to_millis`] can produce, which is
/// years 0000 through 9999 plus a day either side for a zone offset. A seeded
/// value outside it could not have come from a vendor timestamp, and near the
/// ends of `i64` the resume arithmetic would overflow.
const MIN_WATERMARK_MS: i64 = -62_167_219_200_000 - 86_400_000;
const MAX_WATERMARK_MS: i64 = 253_402_300_799_999 + 86_400_000;

/// How long an unacked event is kept before pruning. Acked events are already
/// reduced to metadata (their payload is cleared at ack), so this bound only
/// governs events nobody has collected yet — the question it answers is "how
/// long do we hold an event the agent has not pulled". 30 days is generous for
/// a personal fleet where an agent may be offline for a stretch and still
/// expects to find what it missed when it returns; beyond that the event is a
/// coverage hole, which `prune` records as a gap marker rather than dropping
/// silently.
pub(crate) const UNACKED_MAX_AGE_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Maximum number of unacked events retained per subscription. A bursty feed
/// that the agent never collects would otherwise grow without limit; 1000 is
/// well above any realistic backlog a working agent accumulates between polls
/// while keeping the table bounded. Pruned rows leave a gap marker, so the
/// ceiling trades space for a visible coverage hole rather than a silent one.
pub(crate) const UNACKED_MAX_ROWS: usize = 1000;

/// Maximum governed actor-enrichment reads in one poll cycle.
///
/// Thirty-two sequential calls are enough to enrich an ordinary repository burst
/// without letting a 500-item backfill turn into 500 issue reads or 1000 pull-
/// request reads inside one scheduler pass. The existing `schedulerPassMaxMs`
/// gauge makes the chosen bound observable in production; until that evidence
/// justifies widening it, failure toward unknown actors is safer than an
/// unbounded blocking section.
pub const ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE: usize = 32;
/// Ask GitHub for its largest supported comment page while retaining one call per
/// method. A saturated bare-list response cannot prove completeness and is read
/// as unknown below.
const ACTOR_COMMENT_PAGE_SIZE: usize = 100;
/// The reviewed REST read that lists an issue's or pull request's timeline.
/// Enrichment falls back to it when the comment window is empty, because label,
/// title, state, assignee, merge, review and push activity leave no comment.
pub const ACTOR_TIMELINE_ACTION: &str = "github.issue_timeline.list";
/// GitHub's largest timeline page. A page shorter than this is the last one.
const ACTOR_TIMELINE_PAGE_SIZE: usize = 100;
/// Timeline pages one event may read. GitHub orders the timeline oldest first,
/// so the newest activity is on the LAST page and the walk must reach it; an
/// item with more than this many pages of history is reported as
/// `timeline_page_saturation` rather than guessed from its older entries.
const ACTOR_TIMELINE_MAX_PAGES: usize = 10;

/// Why a cursor could not be turned into request arguments, or a response could
/// not be turned into a cursor advance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CursorError {
    /// The stored cursor state is not a shape this strategy can use.
    InvalidState(String),
    /// The vendor response does not carry what this strategy needs to advance.
    InvalidResponse(String),
}

/// One record extracted from a vendor response, ready to commit to the log.
#[derive(Debug, Clone, PartialEq)]
pub struct DerivedEvent {
    pub vendor_event_id: String,
    pub payload: Value,
    /// Whether this item sits on an ambiguous sorted-head watermark boundary.
    ///
    /// A boundary item is not yet an established event: storage compares its
    /// content with the prior delivery before actor enrichment can spend another
    /// governed vendor read. Other strategies always set this to `false`.
    pub replay_candidate: bool,
    /// When the vendor last touched this item, as the strategy already parsed it.
    ///
    /// Surfaced so a consumer asking "has anything happened since I saw this?"
    /// compares a number instead of re-parsing a vendor-specific date field out
    /// of the payload -- the same field name the strategy was configured with,
    /// rediscovered by every reader.
    ///
    /// `None` for strategies with no per-item time: a sync-token vendor returns
    /// opaque ordering and a scalar watch has no item at all, and inventing a
    /// timestamp for those would be a claim the vendor never made.
    pub activity_at_ms: Option<i64>,
}

/// The result of a successful cursor derivation: the watermark to store and the
/// events to commit atomically with it.
#[derive(Debug, Clone, PartialEq)]
pub struct CursorAdvance {
    pub cursor_state: Value,
    pub events: Vec<DerivedEvent>,
    /// Input cardinality, measured before filtering, never inferred from outputs.
    /// Scalar and probe watches count one observation, not underlying vendor rows.
    pub items_examined: usize,
    /// In-memory accounting only; no per-drop rows are persisted.
    pub dropped: Vec<(String, DropReason)>,
    /// An interval this poll could NOT establish coverage for.
    ///
    /// A strategy that reads a bounded page rather than a bounded window can
    /// find that every item it received is newer than the last one it saw. That
    /// is not success: it means the page was full of new items, so there may be
    /// more beyond its edge that this poll never observed and the next one never
    /// will, because the watermark is about to advance past them.
    ///
    /// Recorded as a gap rather than swallowed, because the alternative is a
    /// feed that looks healthy while silently missing events -- the exact
    /// failure the gap kind exists to make visible. Written in the SAME
    /// transaction as the cursor advance, so a crash cannot keep the advance and
    /// lose the warning about what it skipped.
    pub coverage_gap: Option<CoverageGap>,
}

/// An interval a poll could not establish coverage for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageGap {
    pub from_ms: i64,
    pub to_ms: i64,
    pub reason: &'static str,
}

/// Cursor behaviour, scoped narrowly on purpose. A strategy knows two things:
/// how to build the vendor request arguments from the stored cursor state, and
/// how to derive the next cursor state plus the observed events from a vendor
/// response. The executor selects the strategy declared by the poll shape;
/// CI attempt polling uses its own bounded multi-action executor.
pub trait CursorStrategy {
    fn build_args(&self, cursor_state: &Value) -> Result<Value, CursorError>;
    fn derive(&self, cursor_state: &Value, response: &Value) -> Result<CursorAdvance, CursorError>;
    /// Request keys controlled by the cursor and therefore unsafe to fix per subscription.
    fn owned_keys(&self) -> Vec<String>;
    /// Keys this strategy READS out of a stored cursor state.
    ///
    /// Used to refuse a seeded subscription whose starting state this strategy
    /// would silently ignore. Seeding is how a threshold watch is expressed --
    /// a scalar-diff subscription seeded with a value the subscriber has already
    /// seen reports on its first poll -- and every strategy reads its state by
    /// key, so a seed under the WRONG key resolves to "no previous value" and
    /// the watch baselines silently. That is indistinguishable from an unseeded
    /// watch, and it fails in the direction that loses the event the subscriber
    /// asked for.
    ///
    /// An empty state is always valid: it means "start from nothing", which is
    /// the ordinary case.
    fn state_keys(&self) -> Vec<String>;
}

/// True cursor / sync token: the vendor returns an opaque token that resumes
/// exactly. The stored cursor state is `{"sync_token": "<opaque>"}`, or `{}`
/// before the first successful poll (a full sync). Each item's `id` is the
/// stable dedupe key and the whole item is the event payload.
///
/// The response field names come from the manifest. This strategy expects a
/// complete change batch, not a vendor's intermediate page: a sync token alone
/// is not sufficient to drain paginated full-sync APIs. Both defaults match
/// the reference envelope
/// `{"items": [...], "next_cursor": "<opaque>"}`.
pub struct SyncTokenStrategy {
    items_field: String,
    next_cursor_field: String,
    request_token_field: String,
}

/// Commit a bounded drain's continuation in the same transaction as its events.
struct DrainedStrategy<'a> {
    inner: &'a dyn CursorStrategy,
    resume: Option<Value>,
}

impl CursorStrategy for DrainedStrategy<'_> {
    fn build_args(&self, state: &Value) -> Result<Value, CursorError> {
        self.inner.build_args(state)
    }

    fn derive(&self, state: &Value, response: &Value) -> Result<CursorAdvance, CursorError> {
        let mut advance = self.inner.derive(state, response)?;
        let next = advance
            .cursor_state
            .as_object_mut()
            .ok_or_else(|| CursorError::InvalidState("ordered cursor must be an object".into()))?;
        next.remove(PAGE_RESUME_KEY);
        if let Some(resume) = &self.resume {
            next.insert(PAGE_RESUME_KEY.into(), resume.clone());
        }
        Ok(advance)
    }

    fn owned_keys(&self) -> Vec<String> {
        self.inner.owned_keys()
    }
    fn state_keys(&self) -> Vec<String> {
        self.inner.state_keys()
    }
}

impl SyncTokenStrategy {
    fn new(poll: Option<&PollShape>) -> Self {
        Self {
            items_field: poll
                .and_then(|poll| poll.items_field.clone())
                .unwrap_or_else(|| RESPONSE_ITEMS_KEY.to_string()),
            next_cursor_field: poll
                .and_then(|poll| poll.token_field.clone())
                .unwrap_or_else(|| RESPONSE_NEXT_CURSOR_KEY.to_string()),
            request_token_field: poll
                .and_then(|poll| poll.request_token_field.clone())
                .unwrap_or_else(|| CURSOR_TOKEN_KEY.to_string()),
        }
    }
}

impl CursorStrategy for SyncTokenStrategy {
    fn build_args(&self, cursor_state: &Value) -> Result<Value, CursorError> {
        match cursor_state.get(CURSOR_TOKEN_KEY) {
            // No token yet (first poll) or an explicitly empty one: ask for a
            // full sync by sending no cursor argument at all.
            None | Some(Value::Null) => Ok(json!({})),
            Some(Value::String(token)) if token.is_empty() => Ok(json!({})),
            Some(Value::String(token)) => Ok(json!({ self.request_token_field.clone(): token })),
            Some(other) => Err(CursorError::InvalidState(format!(
                "{CURSOR_TOKEN_KEY} must be a string, got {other}"
            ))),
        }
    }

    fn owned_keys(&self) -> Vec<String> {
        vec![self.request_token_field.clone()]
    }

    fn state_keys(&self) -> Vec<String> {
        vec![CURSOR_TOKEN_KEY.to_string()]
    }

    fn derive(&self, cursor_state: &Value, response: &Value) -> Result<CursorAdvance, CursorError> {
        let object = response
            .as_object()
            .ok_or_else(|| CursorError::InvalidResponse("response is not an object".to_string()))?;
        let items = match object.get(&self.items_field) {
            None | Some(Value::Null) => &Value::Null,
            Some(items) => items,
        };
        let items = match items {
            Value::Null => &[],
            Value::Array(items) => items.as_slice(),
            other => {
                return Err(CursorError::InvalidResponse(format!(
                    "{} must be an array, got {other}",
                    self.items_field
                )))
            }
        };
        let mut events = Vec::with_capacity(items.len());
        for item in items {
            // A record without a stable id cannot be deduped safely, so a
            // response that carries one is refused whole rather than partially
            // committed: guessing an id would reopen the suppression hole the
            // scoped, hash-checked dedupe exists to close.
            let vendor_event_id = item
                .get(ITEM_ID_KEY)
                .and_then(Value::as_str)
                .filter(|id| !id.trim().is_empty())
                .ok_or_else(|| {
                    CursorError::InvalidResponse(format!(
                        "every item must carry a non-empty string {ITEM_ID_KEY}"
                    ))
                })?;
            events.push(DerivedEvent {
                vendor_event_id: vendor_event_id.to_string(),
                // A sync-token vendor promises opaque ordering and no
                // per-item time, so there is nothing honest to put here.
                activity_at_ms: None,
                payload: item.clone(),
                replay_candidate: false,
            });
        }
        // Advance to the vendor's next token when it gives one; otherwise keep
        // the current watermark. A response with no new token means "nothing
        // further", so the resume point is unchanged.
        let cursor_state = match object.get(&self.next_cursor_field) {
            Some(Value::String(next)) if !next.is_empty() => json!({ CURSOR_TOKEN_KEY: next }),
            _ => cursor_state.clone(),
        };
        Ok(CursorAdvance {
            cursor_state,
            events,
            items_examined: items.len(),
            dropped: Vec::new(),
            // A bounded-window strategy asks the vendor for everything since a
            // point, so a full page is not evidence of anything missed.
            coverage_gap: None,
        })
    }
}

/// Ordered timestamp: poll a collection ordered by a vendor timestamp and keep a
/// SETTLED high-water mark. The stored cursor state is
/// `{"watermark_ms": <i64>, "watermark_id": "<stable id>", "window_ms": <i64>,
/// "window_changed_ms": <i64>}`, or `{}` before the first successful poll (a full
/// fetch). `watermark_id` records
/// which row supplied the timestamp for diagnostics; resume uses time and window.
///
/// The arithmetic is the whole difficulty, and none of it is optional:
///
/// - The resume point is `watermark_ms - window_ms`, NOT the bare maximum. A
///   vendor writing a row's timestamp and making that row visible are not
///   atomic, so resuming from the exact maximum silently drops anything
///   committed during the poll; the window absorbs that skew.
/// - The comparison is `>=` on time. Timestamps collide at whatever precision
///   the vendor truncates to, so rows at exactly the boundary are re-fetched and
///   discarded by the existing dedupe (keyed on `vendor_event_id`). A duplicate
///   is cheap and bounded; a miss is silent and permanent.
/// - The window is adaptive. Evidence that it was too small doubles it (with a
///   ceiling): a row returned below the current resume point (a vendor that
///   does not filter), or a never-stored row well below the previous watermark
///   (a vendor that filters on the server, where the first kind cannot occur).
///   After a day with no such evidence it is halved back toward the initial
///   window; see [`settle_ordered_window`].
/// - The watermark never moves backwards.
///
/// The timestamp and tiebreaker field names come from the manifest because
/// vendors disagree about them (GitHub `updated_at`, PostHog `timestamp`); there
/// is no default for those two, so a shape lacking them yields no strategy and
/// the caller suspends rather than guesses.
pub struct OrderedTimestampStrategy {
    items_field: String,
    timestamp_field: String,
    tiebreaker_id_field: String,
    request_since_field: String,
    request_page_cursor_field: Option<String>,
}

impl OrderedTimestampStrategy {
    /// Build a strategy from the manifest's declared poll shape. Returns `None`
    /// when the shape is absent or lacks the vendor-specific timestamp or
    /// tiebreaker fields: those have no honest default, so the caller refuses
    /// the cursor kind rather than polling against guessed field names.
    fn new(poll: Option<&PollShape>) -> Option<Self> {
        let poll = poll?;
        let timestamp_field = non_empty_trimmed(poll.timestamp_field.as_deref())?;
        let tiebreaker_id_field = non_empty_trimmed(poll.tiebreaker_id_field.as_deref())?;
        Some(Self {
            items_field: poll
                .items_field
                .clone()
                .unwrap_or_else(|| RESPONSE_ITEMS_KEY.to_string()),
            request_page_cursor_field: poll
                .pagination
                .as_ref()
                .map(|pagination| pagination.request_cursor_field.clone()),
            timestamp_field: timestamp_field.to_string(),
            tiebreaker_id_field: tiebreaker_id_field.to_string(),
            request_since_field: poll
                .request_since_field
                .clone()
                .unwrap_or_else(|| REQUEST_SINCE_KEY.to_string()),
        })
    }
}

/// Sorted head: read the newest page a vendor will sort, and emit what is newer
/// than the last thing seen.
///
/// Exists because some vendor list endpoints cannot be asked for a WINDOW.
/// Measured: `list_pull_requests` on the GitHub MCP surface accepts `sort` and
/// `direction` but no timestamp bound of any kind -- no `since`, no `updated:>`
/// -- so the ordered-timestamp cursor, whose whole method is to send a resume
/// point, cannot express it. Issues have `since`; pull requests do not. That
/// single vendor difference is why pull requests were unwatchable.
///
/// The method inverts: instead of asking the vendor to filter, ask it to ORDER,
/// take the first page, and filter locally against the stored watermark. The
/// manifest must declare the ordering as `request_constants` (same rule as
/// ordered-timestamp), because an unordered first page would be an arbitrary
/// subset that still advanced the watermark.
///
/// THE COST, AND THE GUARD THAT MAKES IT HONEST. A bounded page can overflow: if
/// more items change between two polls than fit on one page, the surplus falls
/// off the bottom before it is ever seen, and the advancing watermark guarantees
/// no later poll asks for it. That is silent event loss, and it is invisible
/// from the outside -- the feed keeps delivering, just not everything.
///
/// It is detectable, and this is the load-bearing part: if the OLDEST item on
/// a full page is at or newer than the watermark, unseen changes may remain
/// beyond its edge, including edits within the watermark's timestamp instant.
/// The strategy reports that interval as a coverage gap rather than pretending
/// to completeness it cannot claim. A caller
/// seeing repeated `sorted_head_page_saturated` gaps should raise `perPage` or
/// shorten the cadence.
///
/// Not applied on the first poll: with no prior watermark there is no coverage
/// claim to violate, and every item is new by definition.
pub struct SortedHeadStrategy {
    items_field: Option<String>,
    timestamp_field: String,
    tiebreaker_id_field: String,
    /// The vendor's page cap, resolved from the manifest at construction.
    ///
    /// Load-bearing for the truncation check and nothing else: a page shorter
    /// than this is the vendor's complete answer, so nothing can lie beyond its
    /// edge no matter how new every item is.
    page_size: usize,
}

/// Reason recorded when a full page does not reach strictly before the watermark.
const SATURATED_REASON: &str = "sorted_head_page_saturated";

impl SortedHeadStrategy {
    /// Build from the manifest's declared shape. Returns `None` without the
    /// vendor-specific timestamp and tiebreaker field names: those have no
    /// honest default, and guessing them would read zero events from a healthy
    /// vendor.
    ///
    /// `items_field` is OPTIONAL here, unlike the other list strategies, because
    /// a vendor may return a bare array with no envelope at all -- `list_issues`
    /// answers `{issues, totalCount, pageInfo}` while `list_pull_requests`
    /// answers a bare `[...]`, measured on the same server. Absent means "the
    /// response IS the array".
    fn new(poll: Option<&PollShape>) -> Option<Self> {
        let poll = poll?;
        let timestamp_field = non_empty_trimmed(poll.timestamp_field.as_deref())?;
        let tiebreaker_id_field = non_empty_trimmed(poll.tiebreaker_id_field.as_deref())?;
        // Resolved through the NAMED key so the cap the strategy reasons about is
        // literally the value sent to the vendor. Manifest validation requires
        // both the name and a positive integer behind it, so a shape reaching
        // here without one is refused rather than silently defaulted -- a default
        // would restore exactly the false-gap behaviour this field exists to end.
        let page_size = declared_page_size(poll)? as usize;
        Some(Self {
            items_field: non_empty_trimmed(poll.items_field.as_deref()).map(str::to_string),
            timestamp_field: timestamp_field.to_string(),
            tiebreaker_id_field: tiebreaker_id_field.to_string(),
            page_size,
        })
    }

    /// The item array, from either envelope shape.
    fn items<'a>(&self, response: &'a Value) -> Result<&'a [Value], CursorError> {
        match (&self.items_field, response) {
            // Declared field: the vendor wraps its items, and a response that is
            // not an object cannot carry that field.
            (Some(field), Value::Object(object)) => match object.get(field) {
                None | Some(Value::Null) => Ok(&[]),
                Some(Value::Array(items)) => Ok(items.as_slice()),
                Some(other) => Err(CursorError::InvalidResponse(format!(
                    "{field} must be an array, got {other}"
                ))),
            },
            (Some(field), _) => Err(CursorError::InvalidResponse(format!(
                "response must be an object carrying {field}"
            ))),
            // No declared field: the response itself must be the array.
            (None, Value::Array(items)) => Ok(items.as_slice()),
            (None, other) => Err(CursorError::InvalidResponse(format!(
                "response must be an array when no items_field is declared, got {other}"
            ))),
        }
    }
}

impl CursorStrategy for SortedHeadStrategy {
    /// No arguments. The ordering comes from the manifest's `request_constants`
    /// and the container from the subscription's `fixed_args`; this strategy has
    /// no bound to send, which is the entire reason it exists.
    fn build_args(&self, _cursor_state: &Value) -> Result<Value, CursorError> {
        Ok(json!({}))
    }

    fn derive(&self, cursor_state: &Value, response: &Value) -> Result<CursorAdvance, CursorError> {
        let items = self.items(response)?;
        let prior_ms = read_i64(cursor_state, WATERMARK_MS_KEY)?;
        let prior_id = cursor_state
            .get(WATERMARK_ID_KEY)
            .and_then(Value::as_str)
            .map(str::to_string);

        let mut events = Vec::new();
        let mut dropped = Vec::new();
        let mut max_ms: Option<i64> = None;
        let mut max_id: Option<String> = None;
        let mut oldest_ms: Option<i64> = None;

        for item in items {
            // Refused whole rather than skipped, matching every other list
            // strategy here: a silently skipped item is a lost event.
            let timestamp_raw = item
                .get(&self.timestamp_field)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CursorError::InvalidResponse(format!(
                        "every item must carry a string {}",
                        self.timestamp_field
                    ))
                })?;
            let timestamp_ms = iso8601::parse_to_millis(timestamp_raw).ok_or_else(|| {
                CursorError::InvalidResponse(format!(
                    "{} is not a parseable ISO 8601 timestamp: {timestamp_raw}",
                    self.timestamp_field
                ))
            })?;
            let tiebreaker_id = item
                .get(&self.tiebreaker_id_field)
                .and_then(stable_id_string)
                .ok_or_else(|| {
                    CursorError::InvalidResponse(format!(
                        "every item must carry a non-empty string or integer {}",
                        self.tiebreaker_id_field
                    ))
                })?;

            if oldest_ms.is_none_or(|current| timestamp_ms < current) {
                oldest_ms = Some(timestamp_ms);
            }
            let is_new_max = match max_ms {
                None => true,
                Some(current) => {
                    timestamp_ms > current
                        || (timestamp_ms == current
                            && tiebreaker_id_is_greater(&tiebreaker_id, max_id.as_deref()))
                }
            };
            if is_new_max {
                max_ms = Some(timestamp_ms);
                max_id = Some(tiebreaker_id.clone());
            }

            // Items strictly past the watermark are established events. Items
            // exactly on it are ambiguous because some vendors expose timestamps
            // only to the second: the same item may have changed without moving
            // its timestamp. Mark the boundary for a storage-owned content
            // comparison. The overlap also admits rows that became visible late.
            let (is_new, replay_candidate) = match prior_ms {
                None => (true, false),
                Some(watermark_ms) if timestamp_ms > watermark_ms => (true, false),
                Some(watermark_ms) if timestamp_ms == watermark_ms => {
                    let is_new = tiebreaker_id_is_greater(
                        &tiebreaker_id,
                        Some(watermark_id_or(prior_id.as_deref())),
                    );
                    (is_new, !is_new)
                }
                Some(watermark_ms)
                    if timestamp_ms
                        >= watermark_ms.saturating_sub(SORTED_HEAD_REPLAY_WINDOW_MS) =>
                {
                    (false, true)
                }
                Some(_) => (false, false),
            };
            if is_new || replay_candidate {
                events.push(DerivedEvent {
                    vendor_event_id: tiebreaker_id,
                    activity_at_ms: Some(timestamp_ms),
                    payload: item.clone(),
                    replay_candidate,
                });
            } else {
                dropped.push((tiebreaker_id, DropReason::OlderThanWatermark));
            }
        }

        // Saturation: a full page ending at or after the watermark may hide
        // unseen changes, including edits tied at the boundary instant. Only
        // meaningful once a watermark exists -- on a first poll there is nothing to have
        // missed. An empty page cannot saturate.
        //
        // THE PAGE MUST BE FULL. Every item being at or newer than the watermark is
        // evidence of truncation only when the vendor had no room to send more;
        // a short page IS the complete answer, so nothing can lie beyond its
        // edge. Without this term a repository with fewer items than one page
        // reports a gap every time all of its items changed, which is ordinary
        // for a small collection, so false gaps appear over windows containing
        // no real changes, or only one.
        let page_full = items.len() >= self.page_size;
        let coverage_gap = match (prior_ms, oldest_ms) {
            (Some(watermark_ms), Some(oldest)) if page_full && oldest >= watermark_ms => {
                Some(CoverageGap {
                    from_ms: watermark_ms,
                    to_ms: oldest,
                    reason: SATURATED_REASON,
                })
            }
            _ => None,
        };

        let cursor_state = match (max_ms, max_id) {
            // A seeded cursor, or a head whose newest item disappeared, may be
            // newer than every row on this page. Keep its timestamp/id pair:
            // rewinding makes previously dropped history a boundary replay.
            (Some(page_ms), Some(ref page_id))
                if prior_ms.is_some_and(|prior| {
                    prior > page_ms
                        || (prior == page_ms
                            && !tiebreaker_id_is_greater(page_id, prior_id.as_deref()))
                }) =>
            {
                cursor_state.clone()
            }
            (Some(watermark_ms), Some(watermark_id)) => json!({
                WATERMARK_MS_KEY: watermark_ms,
                WATERMARK_ID_KEY: watermark_id,
            }),
            // An empty page advances nothing: keep the current state so the next
            // poll compares against the same point.
            _ => cursor_state.clone(),
        };

        Ok(CursorAdvance {
            cursor_state,
            events,
            items_examined: items.len(),
            dropped,
            coverage_gap,
        })
    }

    fn owned_keys(&self) -> Vec<String> {
        Vec::new()
    }

    fn state_keys(&self) -> Vec<String> {
        vec![WATERMARK_MS_KEY.to_string(), WATERMARK_ID_KEY.to_string()]
    }
}

/// The stored watermark id, or an empty string when absent.
///
/// A missing id must not make the tie comparison silently favour one side: an
/// empty string is less than every real id, so a same-millisecond item is
/// emitted rather than dropped. Erring toward a duplicate is correct here
/// because dedupe catches it, while erring toward omission loses the event.
fn watermark_id_or(stored: Option<&str>) -> &str {
    stored.unwrap_or("")
}

/// Scalar diff: read ONE value and compare it against the last one seen.
///
/// Not a cursor, and deliberately not built as one. A cursor requests a window,
/// receives many items, deduplicates them by vendor id, and stores a pointer
/// INTO a stream. This requests nothing beyond the subscription's fixed
/// arguments, receives a single value, and stores that value plus a transition
/// ordinal. There is no window to widen or list to walk: the ordinal distinguishes
/// repeated changes to the same value, because this is not a stream of vendor ids.
///
/// Measured motivation: `get_latest_release` accepts exactly owner and repo --
/// no bound, no pagination, no ordering -- because it returns one release.
/// Bending the ordered-timestamp cursor around that would mean paging a
/// collection with no order, and the demand corpus wants no enumeration at all:
/// every release condition is "latest tag is above vX".
///
/// THE FIRST OBSERVATION IS A BASELINE, NOT AN EVENT, unless the subscription
/// seeded a value. A watch with no stored predecessor has, strictly, changed --
/// but emitting there would announce a release that may be weeks old as though
/// it had just happened. A subscriber wanting "tell me when it goes past X" says
/// so by seeding the scalar at subscribe time, which the store already supports;
/// one that says only "tell me when this changes" gets silence until it does.
///
/// That distinction is why the reference implementation this shape was measured
/// against DOES fire on first evaluation: every predicate there carries its own
/// threshold, so the question is "is this true yet?" and the answer can honestly
/// already be yes. A bare vendor scalar carries no threshold, so the same
/// behaviour would be a false alarm rather than a true one.
pub struct ScalarDiffStrategy {
    scalar_field: String,
}

impl ScalarDiffStrategy {
    /// Build from the manifest's declared shape. Returns `None` without a
    /// non-empty `scalar_field`: there is no honest default, and a wrong field
    /// name reads as "unchanged" forever rather than failing, so the caller
    /// suspends instead of watching nothing.
    fn new(poll: Option<&PollShape>) -> Option<Self> {
        let scalar_field = non_empty_trimmed(poll?.scalar_field.as_deref())?;
        Some(Self {
            scalar_field: scalar_field.to_string(),
        })
    }
}

/// The stored scalar, under a key deliberately not named `cursor`.
///
/// Calling it a cursor would invite the next implementer to add a window to it,
/// and the absence of that machinery is the definition of this shape.
const SCALAR_KEY: &str = "scalar";
const SCALAR_ORDINAL_KEY: &str = "scalar_ordinal";

impl CursorStrategy for ScalarDiffStrategy {
    /// No arguments. The vendor call carries only the subscription's fixed
    /// arguments, because this shape has no window to request -- which is also
    /// why it owns no request keys a subscription could be refused for setting.
    fn build_args(&self, _cursor_state: &Value) -> Result<Value, CursorError> {
        Ok(json!({}))
    }

    fn derive(&self, cursor_state: &Value, response: &Value) -> Result<CursorAdvance, CursorError> {
        let object = response.as_object().ok_or_else(|| {
            CursorError::InvalidResponse("vendor response must be a JSON object".to_string())
        })?;
        // An absent field is a REFUSAL, never "unchanged". Downstream the two are
        // indistinguishable -- both leave the log quiet -- and treating a missing
        // field as no-change is exactly how a watch reports healthy silence while
        // observing nothing at all.
        let observed = object.get(&self.scalar_field).ok_or_else(|| {
            CursorError::InvalidResponse(format!(
                "vendor response carries no '{}' field to compare",
                self.scalar_field
            ))
        })?;
        if observed.is_null() {
            return Err(CursorError::InvalidResponse(format!(
                "vendor response field '{}' is null, which cannot be compared",
                self.scalar_field
            )));
        }

        let previous = cursor_state.get(SCALAR_KEY);
        // Existing subscriptions predate the ordinal; their next change starts at one.
        let ordinal = read_i64(cursor_state, SCALAR_ORDINAL_KEY)?.unwrap_or(0);
        let changed = previous.is_some_and(|stored| stored != observed);
        let next_ordinal = ordinal.checked_add(i64::from(changed)).ok_or_else(|| {
            CursorError::InvalidState("scalar transition ordinal exhausted".to_string())
        })?;
        let events = if changed {
            // The same value and payload can recur after an intervening change.
            // An ordinal prevents storage from deduping that new transition against
            // an older event. The event and ordinal commit atomically with the scalar.
            vec![DerivedEvent {
                vendor_event_id: format!("{next_ordinal}:{}", scalar_identity(observed)),
                // A scalar watch observes a VALUE, not an item with a
                // modification time; the change instant is the poll itself,
                // which the row already records as observed_at_ms.
                activity_at_ms: None,
                payload: response.clone(),
                replay_candidate: false,
            }]
        } else {
            Vec::new()
        };
        Ok(CursorAdvance {
            cursor_state: json!({
                SCALAR_KEY: observed.clone(),
                SCALAR_ORDINAL_KEY: next_ordinal,
            }),
            dropped: observation_drops(previous, changed, scalar_identity(observed)),
            items_examined: 1,
            events,
            // One value in, one value compared: there is no page to overflow.
            coverage_gap: None,
        })
    }

    fn owned_keys(&self) -> Vec<String> {
        Vec::new()
    }

    fn state_keys(&self) -> Vec<String> {
        vec![SCALAR_KEY.to_string(), SCALAR_ORDINAL_KEY.to_string()]
    }
}

/// Stored probe baseline. Named to match scalar_diff's "the value itself",
/// not a pointer into a stream.
const PROBE_BASELINE_KEY: &str = "baseline";
/// Monotonic per-subscription counter included in event identity so a value
/// that recurs (A, then B, then A again) is a new observation, not a duplicate.
const PROBE_ORDINAL_KEY: &str = "observation_ordinal";

/// Probe cursor: run a script, compare the validated return against the last
/// observed value, and emit on change.
///
/// Follows [`ScalarDiffStrategy`]'s shape. The first observation is a baseline
/// unless the subscription seeded one; an unchanged value does not deliver;
/// a change delivers exactly once. Event identity includes the observation
/// ordinal so a probe alternating A, B, A reports both transitions -- value-only
/// identity would be swallowed by the shipped uniqueness constraint.
pub struct ProbeStrategy;

impl CursorStrategy for ProbeStrategy {
    fn build_args(&self, _cursor_state: &Value) -> Result<Value, CursorError> {
        Ok(json!({}))
    }

    fn derive(&self, cursor_state: &Value, response: &Value) -> Result<CursorAdvance, CursorError> {
        let previous = cursor_state.get(PROBE_BASELINE_KEY);
        let ordinal = probe_ordinal(cursor_state)?;
        let changed = previous.is_some_and(|stored| stored != response);
        let (events, next_ordinal) = if changed {
            let next_ordinal = ordinal.checked_add(1).ok_or_else(|| {
                CursorError::InvalidState("probe observation ordinal exhausted".to_string())
            })?;
            let identity = probe_event_identity(next_ordinal, response);
            (
                vec![DerivedEvent {
                    vendor_event_id: identity,
                    activity_at_ms: None,
                    payload: response.clone(),
                    replay_candidate: false,
                }],
                next_ordinal,
            )
        } else {
            (Vec::new(), ordinal)
        };
        Ok(CursorAdvance {
            cursor_state: json!({
                PROBE_BASELINE_KEY: response,
                PROBE_ORDINAL_KEY: next_ordinal,
            }),
            dropped: observation_drops(previous, changed, canonical_probe_value(response)),
            items_examined: 1,
            events,
            coverage_gap: None,
        })
    }

    fn owned_keys(&self) -> Vec<String> {
        Vec::new()
    }

    fn state_keys(&self) -> Vec<String> {
        vec![
            PROBE_BASELINE_KEY.to_string(),
            PROBE_ORDINAL_KEY.to_string(),
        ]
    }
}

/// The stored probe observation ordinal, absent meaning none yet.
///
/// Read on its own so the poller can refuse a corrupt cursor BEFORE running the
/// script: a probe whose state can never be advanced would otherwise spend its
/// vendor reads every cycle and then throw the observation away.
fn probe_ordinal(cursor_state: &Value) -> Result<i64, CursorError> {
    Ok(read_i64(cursor_state, PROBE_ORDINAL_KEY)?.unwrap_or(0))
}

// Scalar/probe accounting treats one validated observation as one item. The
// identity is trivial for their one-or-zero event branches; it earns its keep
// on list strategies and when downstream filtering or dedupe loses an entry.
fn observation_drops(
    previous: Option<&Value>,
    changed: bool,
    identity: String,
) -> Vec<(String, DropReason)> {
    if changed {
        Vec::new()
    } else {
        vec![(
            identity,
            if previous.is_none() {
                DropReason::InitialBaseline
            } else {
                DropReason::UnchangedObservation
            },
        )]
    }
}

/// Event identity is `(subscription_id, observation_ordinal, canonical_value)`.
/// The subscription is already in the uniqueness key; this is the other two.
///
/// The ordinal is first so removing it is a visible change to the stored id,
/// which is what the A, B, A mutation test relies on: without it the second A
/// collides with the first and is dropped as a duplicate.
fn probe_event_identity(ordinal: i64, observed: &Value) -> String {
    format!("{ordinal}:{}", canonical_probe_value(observed))
}

fn canonical_probe_value(observed: &Value) -> String {
    match observed {
        Value::String(value) => value.clone(),
        other => crate::jcs::canonicalize(other)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_else(|| other.to_string()),
    }
}

fn probe_value_json(value: &ProbeValue) -> Value {
    match value {
        ProbeValue::Bool(value) => json!(value),
        ProbeValue::Number(number) => Value::Number(number.clone()),
        ProbeValue::String(value) => json!(value),
        ProbeValue::Struct(fields) => {
            let mut object = serde_json::Map::new();
            for (key, field) in fields {
                object.insert(
                    key.clone(),
                    match field {
                        plexus_probe::ScalarValue::Bool(value) => json!(value),
                        plexus_probe::ScalarValue::Number(number) => Value::Number(number.clone()),
                        plexus_probe::ScalarValue::String(value) => json!(value),
                    },
                );
            }
            Value::Object(object)
        }
    }
}

/// Render the value portion of a scalar transition identity.
///
/// Strings (usually release tags) stay readable; other values use JSON. The
/// transition ordinal, not this value alone, distinguishes repeated observations.
fn scalar_identity(observed: &Value) -> String {
    match observed {
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

/// A manifest field value that must be present and non-empty, trimmed.
fn declared_page_size(poll: &PollShape) -> Option<u64> {
    let key = non_empty_trimmed(poll.request_page_size_field.as_deref())?;
    poll.request_constants
        .as_ref()?
        .get(key)?
        .as_u64()
        .filter(|size| *size > 0)
}

fn non_empty_trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|field| !field.is_empty())
}

/// Convert the stable item identifier into the string storage uses for event
/// identity. GitHub's issue number is an integer; other vendors commonly return
/// a string, and both are valid stable identifiers.
fn stable_id_string(value: &Value) -> Option<String> {
    match value {
        Value::String(id) if !id.trim().is_empty() => Some(id.clone()),
        Value::Number(number) if number.is_i64() || number.is_u64() => Some(number.to_string()),
        _ => None,
    }
}

/// Compare equal-timestamp tiebreakers without ordering numeric-looking
/// identifiers as text (`10` must sort after `2`). Numeric ids sort before
/// non-numeric ids so mixed formats still have a transitive order.
fn tiebreaker_id_is_greater(candidate: &str, current: Option<&str>) -> bool {
    let Some(current) = current else {
        return true;
    };
    match (candidate.parse::<i128>(), current.parse::<i128>()) {
        (Ok(candidate_number), Ok(current_number)) => {
            (candidate_number, candidate) > (current_number, current)
        }
        (Ok(_), Err(_)) => false,
        (Err(_), Ok(_)) => true,
        (Err(_), Err(_)) => candidate > current,
    }
}

/// Read an integer cursor-state field. Absent or null means "not set"; anything
/// present but not an integer is a corrupt cursor the strategy refuses.
fn read_i64(state: &Value, key: &str) -> Result<Option<i64>, CursorError> {
    match state.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number.as_i64().map(Some).ok_or_else(|| {
            CursorError::InvalidState(format!("{key} must be an integer, got {number}"))
        }),
        Some(other) => Err(CursorError::InvalidState(format!(
            "{key} must be an integer, got {other}"
        ))),
    }
}

/// [`read_i64`], also refusing a value outside `range`. A stored cursor can be
/// seeded at subscribe time, so its numbers are input like any other.
fn read_i64_in(
    state: &Value,
    key: &str,
    range: std::ops::RangeInclusive<i64>,
) -> Result<Option<i64>, CursorError> {
    match read_i64(state, key)? {
        Some(value) if !range.contains(&value) => Err(CursorError::InvalidState(format!(
            "{key} must be within {}..={}, got {value}",
            range.start(),
            range.end()
        ))),
        value => Ok(value),
    }
}

/// The stored ordered-timestamp watermark, if any. Range-checked so the resume
/// point `watermark - window` can neither overflow nor name an impossible time.
fn ordered_watermark(state: &Value) -> Result<Option<i64>, CursorError> {
    read_i64_in(state, WATERMARK_MS_KEY, MIN_WATERMARK_MS..=MAX_WATERMARK_MS)
}

/// The stored overlap window, or the initial one. A negative window would move
/// the resume point PAST the watermark and skip rows permanently, and one above
/// the ceiling is a value the strategy itself never writes.
fn ordered_window(state: &Value) -> Result<i64, CursorError> {
    Ok(read_i64_in(state, WINDOW_MS_KEY, 0..=MAX_WINDOW_MS)?.unwrap_or(INITIAL_WINDOW_MS))
}

/// The numeric fields of an ordered-timestamp cursor, validated together.
struct OrderedCursorNumbers {
    watermark_ms: Option<i64>,
    window_ms: i64,
}

/// Read and range-check every number an ordered-timestamp cursor stores.
///
/// `build_args` and `derive` both read the cursor through this one function, so
/// they refuse exactly the same states. When only `derive` refused a value, a
/// corrupt cursor still got its governed vendor read (quota, audit row, rate
/// budget) and was refused afterwards under a response-shape reason that blamed
/// the vendor. Refusing in `build_args` suspends it before any vendor contact.
fn ordered_cursor_numbers(state: &Value) -> Result<OrderedCursorNumbers, CursorError> {
    let window_ms = ordered_window(state)?;
    let watermark_ms = ordered_watermark(state)?;
    // Read only to refuse a corrupt value; the change stamp itself is carried
    // forward and interpreted by `settle_ordered_window`.
    read_i64(state, WINDOW_CHANGED_MS_KEY)?;
    Ok(OrderedCursorNumbers {
        watermark_ms,
        window_ms,
    })
}

/// Double the overlap window after evidence it was too small, never past the
/// ceiling and never below the initial window (a seeded window can be smaller).
fn widened_window(window_ms: i64) -> i64 {
    window_ms
        .saturating_mul(2)
        .clamp(INITIAL_WINDOW_MS, MAX_WINDOW_MS)
}

/// Fold the evidence gathered outside [`OrderedTimestampStrategy::derive`]
/// into the cursor that poll is about to commit, and let a quiet window decay.
///
/// `late_row` means storage confirmed a row this poll returned was never seen
/// before even though its timestamp lies well below the previous watermark: it
/// became visible late. GitHub and PostHog filter by the resume point on the
/// server, so such a row is the only lateness evidence those vendors ever give;
/// a row below the resume point itself never comes back. Evidence doubles the
/// window (once per poll) and restarts the quiet period.
///
/// Without evidence, a window above [`INITIAL_WINDOW_MS`] is halved once
/// [`WINDOW_DECAY_QUIET_MS`] has passed since it last changed, so one late row
/// does not leave a watch refetching an hour of overlap forever. A cursor with
/// no watermark yet has no window to adjust.
fn settle_ordered_window(prior_state: &Value, next_state: &mut Value, late_row: bool, now_ms: i64) {
    let Some(next) = next_state.as_object_mut() else {
        return;
    };
    if !next.contains_key(WATERMARK_MS_KEY) {
        return;
    }
    // Both states were validated by derive; a corrupt value here falls back to
    // the defaults rather than failing a poll that has already succeeded.
    let prior_window = ordered_window(prior_state).unwrap_or(INITIAL_WINDOW_MS);
    let mut window = ordered_window(&Value::Object(next.clone())).unwrap_or(prior_window);
    let mut changed_at = next.get(WINDOW_CHANGED_MS_KEY).and_then(Value::as_i64);
    if late_row {
        // `derive` may already have widened the overlap window after finding
        // late rows on this page. Widen only once for the same poll's evidence.
        window = window.max(widened_window(prior_window));
        changed_at = Some(now_ms);
    } else if window > INITIAL_WINDOW_MS {
        match changed_at {
            None => changed_at = Some(now_ms),
            Some(at) if now_ms.saturating_sub(at) >= WINDOW_DECAY_QUIET_MS => {
                window = (window / 2).max(INITIAL_WINDOW_MS);
                changed_at = Some(now_ms);
            }
            Some(_) => {}
        }
    }
    next.insert(WINDOW_MS_KEY.to_string(), json!(window));
    if let Some(at) = changed_at {
        next.insert(WINDOW_CHANGED_MS_KEY.to_string(), json!(at));
    }
}

impl CursorStrategy for OrderedTimestampStrategy {
    fn build_args(&self, cursor_state: &Value) -> Result<Value, CursorError> {
        // Validated before the page-resume branch: a continuation page is still
        // a vendor read, and `derive` refuses these values on every page.
        let numbers = ordered_cursor_numbers(cursor_state)?;
        if let Some(resume) = cursor_state.get(PAGE_RESUME_KEY) {
            let valid = resume.as_object().is_some_and(|args| {
                self.request_page_cursor_field
                    .as_ref()
                    .is_some_and(|field| {
                        args.get(field)
                            .and_then(Value::as_str)
                            .is_some_and(|s| !s.is_empty())
                            && args
                                .keys()
                                .all(|key| key == field || key == &self.request_since_field)
                    })
            });
            if !valid {
                return Err(CursorError::InvalidState(
                    "page_resume must contain a vendor cursor and its original filter".into(),
                ));
            }
            return Ok(resume.clone());
        }
        // No watermark yet (first poll): request everything the vendor will give
        // by sending no filter argument, and derive the first watermark from
        // what comes back.
        let Some(watermark_ms) = numbers.watermark_ms else {
            return Ok(json!({}));
        };
        let window_ms = numbers.window_ms;
        // Resume from the watermark minus the overlap window so late rows can
        // still arrive. Deduplication discards boundary rows already stored.
        // Range checks on both operands prevent subtraction overflow.
        let resume_ms = watermark_ms - window_ms;
        Ok(json!({ self.request_since_field.clone(): iso8601::format_millis(resume_ms) }))
    }

    fn owned_keys(&self) -> Vec<String> {
        let mut keys = vec![self.request_since_field.clone()];
        keys.extend(self.request_page_cursor_field.clone());
        keys
    }

    fn state_keys(&self) -> Vec<String> {
        vec![
            WATERMARK_MS_KEY.to_string(),
            WATERMARK_ID_KEY.to_string(),
            WINDOW_MS_KEY.to_string(),
            WINDOW_CHANGED_MS_KEY.to_string(),
            PAGE_RESUME_KEY.to_string(),
        ]
    }

    fn derive(&self, cursor_state: &Value, response: &Value) -> Result<CursorAdvance, CursorError> {
        let object = response
            .as_object()
            .ok_or_else(|| CursorError::InvalidResponse("response is not an object".to_string()))?;
        let items = match object.get(&self.items_field) {
            None | Some(Value::Null) => &[],
            Some(Value::Array(items)) => items.as_slice(),
            Some(other) => {
                return Err(CursorError::InvalidResponse(format!(
                    "{} must be an array, got {other}",
                    self.items_field
                )))
            }
        };

        // The adaptive window carries forward; it grows on evidence and decays
        // only through `settle_ordered_window`.
        let OrderedCursorNumbers {
            watermark_ms: prior_watermark_ms,
            window_ms: prior_window_ms,
        } = ordered_cursor_numbers(cursor_state)?;
        // The resume point this poll used: watermark - window. A row below it is
        // direct evidence the window was too small. With no watermark (first
        // poll) there is no resume point and therefore no evidence to gather.
        let prior_resume_ms = prior_watermark_ms.map(|watermark_ms| watermark_ms - prior_window_ms);

        let mut events = Vec::with_capacity(items.len());
        let mut max_ms: Option<i64> = None;
        let mut max_id: Option<String> = None;
        let mut window_too_small = false;

        for item in items {
            // A record that does not match the declared shape — a missing or
            // non-string timestamp, an unparseable timestamp, or a missing
            // tiebreaker id — is refused whole rather than skipped: a silently
            // skipped item is a lost event, so the caller suspends instead.
            let timestamp_raw = item
                .get(&self.timestamp_field)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CursorError::InvalidResponse(format!(
                        "every item must carry a string {}",
                        self.timestamp_field
                    ))
                })?;
            let timestamp_ms = iso8601::parse_to_millis(timestamp_raw).ok_or_else(|| {
                CursorError::InvalidResponse(format!(
                    "{} is not a parseable ISO 8601 timestamp: {timestamp_raw}",
                    self.timestamp_field
                ))
            })?;
            let tiebreaker_id = item
                .get(&self.tiebreaker_id_field)
                .and_then(stable_id_string)
                .ok_or_else(|| {
                    CursorError::InvalidResponse(format!(
                        "every item must carry a non-empty string or integer {}",
                        self.tiebreaker_id_field
                    ))
                })?;

            if let Some(resume_ms) = prior_resume_ms {
                if timestamp_ms < resume_ms {
                    window_too_small = true;
                }
            }
            // Composite maximum: greatest timestamp, ties broken on the stable
            // id, so the stored watermark is a deterministic (timestamp, id).
            let is_new_max = match max_ms {
                None => true,
                Some(current) => {
                    timestamp_ms > current
                        || (timestamp_ms == current
                            && tiebreaker_id_is_greater(&tiebreaker_id, max_id.as_deref()))
                }
            };
            if is_new_max {
                max_ms = Some(timestamp_ms);
                max_id = Some(tiebreaker_id.clone());
            }

            events.push(DerivedEvent {
                vendor_event_id: tiebreaker_id,
                activity_at_ms: Some(timestamp_ms),
                payload: item.clone(),
                replay_candidate: false,
            });
        }

        let cursor_state = match (max_ms, max_id) {
            // Rows arrived: advance the watermark. Widen the window once when
            // evidence showed it was too small; otherwise carry it forward.
            (Some(page_ms), Some(page_id)) => {
                let mut next = cursor_state.as_object().cloned().unwrap_or_default();
                if window_too_small {
                    next.insert(
                        WINDOW_MS_KEY.to_string(),
                        json!(widened_window(prior_window_ms)),
                    );
                    // Clear the old change timestamp so `settle_ordered_window`
                    // records a new one and restarts the quiet period before
                    // the overlap window can shrink.
                    next.remove(WINDOW_CHANGED_MS_KEY);
                } else {
                    next.insert(WINDOW_MS_KEY.to_string(), json!(prior_window_ms));
                }
                // The watermark never moves backwards. A page whose newest row
                // is older than the stored one (the watermark row was deleted
                // or left the filter) would otherwise pull the resume point
                // back and widen every later request for nothing.
                let behind = prior_watermark_ms.is_some_and(|prior| {
                    prior > page_ms
                        || (prior == page_ms
                            && !tiebreaker_id_is_greater(
                                &page_id,
                                cursor_state.get(WATERMARK_ID_KEY).and_then(Value::as_str),
                            ))
                });
                if !behind {
                    next.insert(WATERMARK_MS_KEY.to_string(), json!(page_ms));
                    next.insert(WATERMARK_ID_KEY.to_string(), json!(page_id));
                }
                Value::Object(next)
            }
            // An empty page advances nothing and widens nothing: keep the
            // current state so the next poll resumes from the same point.
            _ => cursor_state.clone(),
        };

        Ok(CursorAdvance {
            cursor_state,
            events,
            items_examined: items.len(),
            dropped: Vec::new(),
            // The executor drains full pages and records incomplete pagination
            // separately; derivation alone cannot establish completeness.
            coverage_gap: None,
        })
    }
}

/// Resolve the strategy for a stored cursor kind, configured from the manifest's
/// declared poll shape. Returns `None` for kinds this slice does not implement,
/// or for a kind whose required manifest fields are missing; the caller suspends
/// rather than guesses, because a wrong watermark silently skips records.
pub(crate) fn strategy_for(
    cursor_kind: &str,
    poll: Option<&PollShape>,
) -> Option<Box<dyn CursorStrategy>> {
    match cursor_kind {
        "sync_token" => Some(Box::new(SyncTokenStrategy::new(poll))),
        // Ordered timestamp needs the manifest's declared timestamp and
        // tiebreaker fields; without a usable poll shape there is nothing honest
        // to resume from, so it resolves to None and the caller suspends.
        "ordered_timestamp" => OrderedTimestampStrategy::new(poll)
            .map(|strategy| Box::new(strategy) as Box<dyn CursorStrategy>),
        "scalar_diff" => ScalarDiffStrategy::new(poll)
            .map(|strategy| Box::new(strategy) as Box<dyn CursorStrategy>),
        "sorted_head" => SortedHeadStrategy::new(poll)
            .map(|strategy| Box::new(strategy) as Box<dyn CursorStrategy>),
        // A probe is not configured from a vendor poll shape. The script, the
        // action set, and the return schema live on the companion row; this
        // arm exists so a stored `probe` kind actually dispatches.
        "probe" => Some(Box::new(ProbeStrategy)),
        // CI uses a dedicated multi-action executor. Other unimplemented
        // kinds are refused rather than approximated.
        _ => None,
    }
}

/// The terminal state of one poll cycle. Callers (and tests) assert on this and
/// on the stored subscription state; the two together prove each guard.
#[derive(Debug, Clone, PartialEq)]
pub enum PollCycle {
    /// The vendor read completed and its events were committed atomically with
    /// the cursor advance.
    Completed { inserted: usize, duplicates: usize },
    /// Quota admission refused before any dispatch or attempt stamp. The watch
    /// remains due, with its cursor and vendor-failure streak untouched.
    Deferred { reason: String },
    /// The vendor returned a definitive failure (5xx, timeout, throttle). The
    /// vendor-failure streak was incremented; the cursor is untouched.
    VendorFailed { code: String },
    /// The dispatch was neither a definitive success nor a definitive vendor
    /// failure — the outcome was unknown, or the request was not sent locally.
    /// A read in this state is benign to repeat and catastrophic to skip, so the
    /// cursor and the streak are both left untouched.
    Inconclusive { code: String },
    /// An authorization denial or pre-gate refusal. The subscription was
    /// suspended with a machine-readable reason and a coverage gap recorded.
    /// This is deliberately NOT counted as a vendor failure: backing off a
    /// revoked subscription would leave it claiming coverage it no longer has.
    Suspended { reason: String },
    /// The subscription is not pollable as given: it does not exist for this
    /// principal, or it is not active. No state was changed.
    NotEligible { reason: String },
    /// A store operation failed. No durable state change was made by this cycle.
    StoreFailed { reason: String },
}

/// Performs one poll cycle for one subscription against the governance engine.
pub struct Poller<C, T>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    engine: GovernanceEngine<C, T>,
    ci_quota_waits: Mutex<std::collections::BTreeMap<String, i64>>,
    #[cfg(test)]
    repo_identity_counts: RepoIdentityCounters,
}

const REPO_IDENTITY_COUNTER_NAMES: [&str; 6] = [
    "repo_id_unresolved",
    "repo_id_grant_missing",
    "repo_id_deferred",
    "repo_id_refresh_failed",
    "repo_id_refresh_deferred",
    "repository_identity_changed",
];

#[derive(Clone, Copy)]
#[repr(usize)]
enum RepoIdentityCounter {
    Unresolved,
    GrantMissing,
    Deferred,
    RefreshFailed,
    RefreshDeferred,
    IdentityChanged,
}

struct RepoIdentityCounters([std::sync::atomic::AtomicU64; 6]);

impl RepoIdentityCounters {
    const fn new() -> Self {
        Self([const { std::sync::atomic::AtomicU64::new(0) }; 6])
    }

    fn record(&self, counter: RepoIdentityCounter, count: u64) {
        self.0[counter as usize].fetch_add(count, std::sync::atomic::Ordering::Relaxed);
    }

    fn snapshot(&self) -> Value {
        Value::Object(
            REPO_IDENTITY_COUNTER_NAMES
                .iter()
                .zip(&self.0)
                .map(|(name, value)| {
                    (
                        (*name).to_string(),
                        json!(value.load(std::sync::atomic::Ordering::Relaxed)),
                    )
                })
                .collect(),
        )
    }
}

static REPO_IDENTITY_COUNTERS: RepoIdentityCounters = RepoIdentityCounters::new();

/// Process-lifetime identity counters, including polls invoked outside the scheduler.
pub fn repo_identity_metrics() -> Value {
    REPO_IDENTITY_COUNTERS.snapshot()
}

struct PollRepository {
    name: String,
    event_name: &'static str,
    repo_id: Option<i64>,
}

struct PollEventIdentity {
    key: String,
    change: Option<&'static str>,
    headers: EventHeaders,
}

/// Remaining governed-call capacity for one poll cycle.
///
/// Work is authorised only by [`CallBudget::try_take`]. There is no remaining-count
/// getter, so a caller cannot compute leftover capacity and decide for itself.
/// `try_take` returns [`Option`] rather than a named `Result`: the budget knows
/// only whether the tokens exist, not whether the caller is starting an event
/// (`call_cap_exhausted`) or retrying (`retry_call_cap_exhausted`).
struct CallBudget {
    remaining: Cell<usize>,
}

/// Tokens taken from a [`CallBudget`] and not yet converted into [`CallSlot`]s.
///
/// Dropping a permit returns unused tokens so an event that fails before
/// dispatching every reserved first attempt does not starve later events.
struct CallPermit<'a> {
    budget: &'a CallBudget,
    remaining: usize,
}

// Proof that one governed call has been taken from a CallPermit.
// Neither Copy nor Clone: a slot cannot be spent twice. Over-draw of a spent
// slot is a compile-time error (`use of moved value`), not a runtime check:
//   let slot = permit.take_one().unwrap();
//   dispatch(slot);
//   dispatch(slot); // error: use of moved value: `slot`
#[must_use]
struct CallSlot(());

impl CallBudget {
    fn new(capacity: usize) -> Self {
        Self {
            remaining: Cell::new(capacity),
        }
    }

    /// Consume `n` calls, or return `None` without changing the budget.
    fn try_take(&self, n: usize) -> Option<CallPermit<'_>> {
        if pass_budget_expired() {
            return None;
        }
        let remaining = self.remaining.get();
        let next = remaining.checked_sub(n)?;
        self.remaining.set(next);
        Some(CallPermit {
            budget: self,
            remaining: n,
        })
    }
}

impl CallPermit<'_> {
    /// Authorise one governed call from this permit.
    fn take_one(&mut self) -> Option<CallSlot> {
        self.remaining = self.remaining.checked_sub(1)?;
        Some(CallSlot(()))
    }
}

impl Drop for CallPermit<'_> {
    fn drop(&mut self) {
        self.budget
            .remaining
            .set(self.budget.remaining.get() + self.remaining);
    }
}

/// First-attempt slot plus the cycle budget a retry would draw from.
struct ActorRetryAttempt<'a> {
    first: CallSlot,
    budget: &'a CallBudget,
}

/// Remove sorted-head boundary replays whose content matches a stored payload.
///
/// The lookup is skipped entirely when the strategy produced no candidates, and
/// it runs before actor enrichment so an idle boundary does not consume governed
/// vendor calls.
fn retain_changed_replay_candidates<E>(
    events: &mut Vec<DerivedEvent>,
    dropped: &mut Vec<(String, DropReason)>,
    lookup: impl FnOnce(&[(&str, &Value)]) -> Result<Vec<bool>, E>,
) {
    retain_unstored_payloads(
        events,
        dropped,
        |event| event.replay_candidate,
        DropReason::UnchangedBoundaryReplay,
        lookup,
    );
}

/// Remove established events whose exact payload this subscription already
/// stored, before actor enrichment runs on them.
///
/// Storage would drop such an event at insert as a duplicate, so enriching it
/// only spends governed vendor reads (comments, timeline) on an attribution
/// that is thrown away. The ordered-timestamp overlap window re-reads the item
/// at its watermark on every pass, which made this the steady-state cost of an
/// idle issue watch. The drop is recorded as `AlreadyDelivered`, the reason
/// insert-time dedupe gives the same event, so the ledger reads the same as if
/// the event had reached storage. Returns how many events were removed.
///
/// Boundary replays are left to [`retain_changed_replay_candidates`], which
/// has already asked about them under their own reason.
fn retain_unstored_established_events<E>(
    events: &mut Vec<DerivedEvent>,
    dropped: &mut Vec<(String, DropReason)>,
    lookup: impl FnOnce(&[(&str, &Value)]) -> Result<Vec<bool>, E>,
) -> usize {
    retain_unstored_payloads(
        events,
        dropped,
        |event| !event.replay_candidate,
        DropReason::AlreadyDelivered,
        lookup,
    )
}

#[cfg(test)]
thread_local! {
    /// Makes the pre-enrichment stored-payload lookup in `Poller::complete`
    /// fail, so a unit test can drive the keep-on-failure rule through the real
    /// poll path. Thread-local because a poll runs on its caller's thread and
    /// tests run in parallel; it does not exist outside test builds.
    static FAIL_STORED_PAYLOAD_LOOKUP: Cell<bool> = const { Cell::new(false) };
    static PREVIOUS_OBSERVATION_READS: Cell<usize> = const { Cell::new(0) };
}

/// Drop the `selected` events whose (vendor id, payload) storage reports as
/// already stored, recording each under `reason`. Returns the number dropped.
///
/// The lookup is skipped entirely when nothing is selected.
fn retain_unstored_payloads<E>(
    events: &mut Vec<DerivedEvent>,
    dropped: &mut Vec<(String, DropReason)>,
    selected: impl Fn(&DerivedEvent) -> bool,
    reason: DropReason,
    lookup: impl FnOnce(&[(&str, &Value)]) -> Result<Vec<bool>, E>,
) -> usize {
    let unchanged = {
        let candidates = events
            .iter()
            .filter(|event| selected(event))
            .map(|event| (event.vendor_event_id.as_str(), &event.payload))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return 0;
        }
        match lookup(&candidates) {
            Ok(unchanged) => unchanged,
            // An unreadable history cannot establish that an item is
            // unchanged. Keep it so insert-time dedupe may spend some work, but
            // a real same-timestamp edit is never discarded permanently.
            Err(_) => {
                eprintln!(warn poller: "stored payload lookup failed; retaining candidates for insert-time deduplication");
                return 0;
            }
        }
    };

    let mut candidate_index = 0usize;
    let before = events.len();
    events.retain(|event| {
        if !selected(event) {
            return true;
        }
        // A missing result is not evidence that content is unchanged, so an
        // unexpectedly short store answer follows the same keep-on-uncertainty rule.
        let is_unchanged = unchanged.get(candidate_index).copied().unwrap_or(false);
        candidate_index += 1;
        if is_unchanged {
            dropped.push((event.vendor_event_id.clone(), reason));
        }
        !is_unchanged
    });
    before - events.len()
}

impl<C, T> Poller<C, T>
where
    C: CredentialSource + ?Sized + 'static,
    T: Transport + ?Sized + 'static,
{
    pub fn new(engine: GovernanceEngine<C, T>) -> Self {
        Self {
            engine,
            ci_quota_waits: Mutex::new(std::collections::BTreeMap::new()),
            #[cfg(test)]
            repo_identity_counts: RepoIdentityCounters::new(),
        }
    }

    /// Run exactly one poll cycle for `subscription_id` under `principal`.
    ///
    /// The flow is: load the subscription, resolve a cursor strategy, build the
    /// request arguments, claim a poll authorization through the only route to
    /// poll authority, dispatch, and interpret the outcome. A vendor failure
    /// increments the failure streak; any authorization-side refusal suspends
    /// the subscription instead and never touches that streak.
    pub fn poll_once(&self, principal: &str, subscription_id: &str) -> PollCycle {
        let store = self.engine.store();
        let subscription = match store.subscription(principal, subscription_id) {
            Ok(Some(subscription)) => subscription,
            Ok(None) => {
                return PollCycle::NotEligible {
                    reason: "subscription_not_found".to_string(),
                }
            }
            Err(error) => {
                return PollCycle::StoreFailed {
                    reason: error.to_string(),
                }
            }
        };
        self.poll_loaded(principal, &subscription, None)
    }

    pub(crate) fn poll_loaded(
        &self,
        principal: &str,
        subscription: &TriggerSubscription,
        deadline: Option<std::time::Instant>,
    ) -> PollCycle {
        let cycle = budget::with_deadline(deadline, || {
            if pass_budget_expired() {
                return PollCycle::Deferred {
                    reason: "poll_pass_budget".into(),
                };
            }
            self.poll_subscription(principal, subscription)
        });
        track_credential_repair(principal, &subscription.connection_id, &cycle);
        cycle
    }

    /// [`Self::poll_once`] for a subscription already loaded.
    fn poll_subscription(&self, principal: &str, subscription: &TriggerSubscription) -> PollCycle {
        let store = self.engine.store();
        let subscription_id = subscription.subscription_id.as_str();
        // Only an active subscription is pollable. A suspended one already
        // recorded its coverage gap; polling it again would double-count it.
        if subscription.status != "active" {
            return PollCycle::NotEligible {
                reason: format!("subscription_{}", subscription.status),
            };
        }
        if subscription.cursor_kind == "probe" {
            return self.poll_probe(principal, subscription);
        }
        if subscription.cursor_kind == "ci_runs" {
            return self.poll_ci_runs(principal, subscription);
        }
        // The manifest declares the vendor's real response field names; a store
        // failure here would otherwise silently fall back to the reference
        // envelope and read zero events from a healthy vendor.
        let poll_shape =
            match store.poll_shape(principal, &subscription.connection_id, &subscription.action) {
                Ok(shape) => shape,
                Err(error) => {
                    return PollCycle::StoreFailed {
                        reason: error.to_string(),
                    }
                }
            };
        let Some(strategy) = strategy_for(&subscription.cursor_kind, poll_shape.as_ref()) else {
            return self.suspend(principal, subscription_id, "cursor_kind_unsupported");
        };
        let cursor_args = match strategy.build_args(&subscription.cursor_state) {
            Ok(args) => args,
            Err(_) => return self.suspend(principal, subscription_id, "cursor_state_unusable"),
        };
        let mut args = match subscription.fixed_args.as_object() {
            Some(fixed_args) => fixed_args.clone(),
            None => return self.suspend(principal, subscription_id, "fixed_args_unusable"),
        };
        // Manifest request constants are part of the action definition, so they
        // override per-subscription fixed arguments for the same key. This also
        // makes malformed legacy rows deterministic; new subscriptions refuse
        // the collision.
        if let Some(request_constants) = poll_shape
            .as_ref()
            .and_then(|poll| poll.request_constants.as_ref())
        {
            args.extend(request_constants.clone());
        }
        let Some(cursor_args) = cursor_args.as_object() else {
            return self.suspend(principal, subscription_id, "cursor_args_unusable");
        };
        // Cursor arguments are extended last so a malformed legacy row cannot
        // pin the watermark even if it bypassed subscribe-time validation.
        args.extend(cursor_args.clone());
        // Only the cursor state may supply a continuation, never fixed legacy args.
        let pagination = poll_shape
            .as_ref()
            .filter(|_| subscription.cursor_kind == "ordered_timestamp")
            .and_then(|shape| shape.pagination.as_ref());
        if let Some(pagination) = pagination {
            if !cursor_args.contains_key(&pagination.request_cursor_field) {
                args.remove(&pagination.request_cursor_field);
            }
        }
        let page_size = if pagination.is_some() {
            match poll_shape.as_ref().and_then(declared_page_size) {
                Some(size) => size,
                None => {
                    return self.suspend(
                        principal,
                        subscription_id,
                        "response_shape_invalid: positive request page size required",
                    )
                }
            }
        } else {
            0
        };
        let mut args = Value::Object(args);
        // Identity resolution precedes the watched vendor read. A changed name
        // suspends all its watches atomically, so this cycle must stop here.
        let repository = match self.resolve_poll_repository(principal, subscription) {
            Ok(repository) => repository,
            Err(cycle) => return cycle,
        };
        // Stamp the attempt. An inactive subscription stops here before any
        // authorization work is done on its behalf.
        let observed_at_ms = now_ms();
        match store.record_poll_attempt(principal, subscription_id, observed_at_ms) {
            Ok(true) => {}
            Ok(false) => {
                return PollCycle::NotEligible {
                    reason: SUBSCRIPTION_NOT_ACTIVE.to_string(),
                }
            }
            Err(error) => {
                return PollCycle::StoreFailed {
                    reason: error.to_string(),
                }
            }
        }
        let mut combined_response: Option<Value> = None;
        let mut pages = 0;
        let mut seen_cursors = std::collections::BTreeSet::new();
        if let Some(cursor) = pagination
            .and_then(|p| args.get(&p.request_cursor_field))
            .and_then(Value::as_str)
        {
            seen_cursors.insert(cursor.to_owned());
        }
        loop {
            // The only route to poll authority. It reads the catalog before any gate
            // runs and refuses to even build a request for an action that is no
            // longer an active read; authorization then denies a revoked or
            // expired grant, a quarantined catalog, a drifted schema or a policy
            // block. `read_failure_cycle` decides what each failure means; a
            // denial suspends and is never counted as a vendor failure.
            let mut response = match governed_read(
                &self.engine,
                principal,
                &subscription.connection_id,
                &subscription.action,
                args.clone(),
                subscription_id,
                &subscription.schema_hash,
            ) {
                Ok(response) => response,
                Err(failure) => {
                    return self.read_failure_cycle(principal, subscription_id, failure)
                }
            };
            let mut coverage_gap = None;
            let mut resume = None;
            if let (Some(pagination), Some(shape)) = (pagination, poll_shape.as_ref()) {
                pages += 1;
                let items_field = shape.items_field.as_deref().unwrap_or(RESPONSE_ITEMS_KEY);
                let body = response.as_ref();
                let items = body
                    .and_then(|body| body.get(items_field))
                    .and_then(Value::as_array);
                // A malformed page is not an empty successful answer.
                let (Some(body), Some(items)) = (body, items) else {
                    return self.suspend(
                        principal,
                        subscription_id,
                        &format!("{RESPONSE_SHAPE_INVALID}: {items_field} must be an array"),
                    );
                };
                let full = items.len() as u64 >= page_size;
                let next_cursor = body
                    .pointer(&pagination.response_cursor_pointer)
                    .and_then(Value::as_str)
                    .filter(|cursor| !cursor.is_empty())
                    .map(str::to_owned);
                let mut body = response.take().expect("validated body");
                let Value::Array(page_items) = body[items_field].take() else {
                    unreachable!("validated items")
                };
                if let Some(combined) = combined_response.as_mut() {
                    combined[items_field]
                        .as_array_mut()
                        .expect("validated items")
                        .extend(page_items);
                } else {
                    body[items_field] = Value::Array(page_items);
                    combined_response = Some(body);
                }
                if full {
                    let reason = if next_cursor
                        .as_ref()
                        .is_none_or(|cursor| !seen_cursors.insert(cursor.clone()))
                    {
                        Some("ordered_timestamp_cursor_unusable")
                    } else {
                        None
                    };
                    if let Some(reason) = reason {
                        coverage_gap = Some(reason);
                    } else {
                        // Keep the original filter and ordering: a cursor must
                        // traverse the same result set, not a newly widened one.
                        args[&pagination.request_cursor_field] = json!(next_cursor);
                        if pages >= ORDERED_TIMESTAMP_MAX_PAGES_PER_POLL || pass_budget_expired() {
                            let mut saved = serde_json::Map::new();
                            saved.insert(
                                pagination.request_cursor_field.clone(),
                                args[&pagination.request_cursor_field].clone(),
                            );
                            if let Some(field) = shape.request_since_field.as_deref() {
                                if let Some(value) = args.get(field) {
                                    saved.insert(field.into(), value.clone());
                                }
                            } else if let Some(value) = args.get(REQUEST_SINCE_KEY) {
                                saved.insert(REQUEST_SINCE_KEY.into(), value.clone());
                            }
                            resume = Some(Value::Object(saved));
                        } else {
                            continue;
                        }
                    }
                }
                response = combined_response.take();
            }
            let drained = DrainedStrategy {
                inner: strategy.as_ref(),
                resume,
            };
            return self.complete(
                principal,
                subscription,
                if pagination.is_some() {
                    &drained
                } else {
                    strategy.as_ref()
                },
                response.as_ref(),
                observed_at_ms,
                poll_shape.as_ref().map(|shape| shape.item_kind.as_str()),
                coverage_gap,
                repository.as_ref(),
            );
        }
    }

    fn count_repo_identity(&self, counter: RepoIdentityCounter, count: u64) {
        #[cfg(test)]
        self.repo_identity_counts.record(counter, count);
        REPO_IDENTITY_COUNTERS.record(counter, count);
    }

    /// Rows this ordered-timestamp poll returned that storage has never seen at
    /// their own timestamp, although that timestamp lies more than half the
    /// overlap window below the previous watermark: they were not visible when
    /// the previous poll read that span. Half the window is the margin because
    /// a row that late was within a factor of two of falling below the resume
    /// point and being lost without trace.
    ///
    /// A subscription that has never completed a poll has stored nothing to
    /// compare against (a seeded watermark would make every row look late), and
    /// an unreadable history is not evidence, so both count zero.
    fn count_late_rows(
        &self,
        principal: &str,
        subscription: &TriggerSubscription,
        events: &[DerivedEvent],
    ) -> usize {
        if subscription.last_success_at_ms.is_none() {
            return 0;
        }
        let (Ok(Some(watermark_ms)), Ok(window_ms)) = (
            ordered_watermark(&subscription.cursor_state),
            ordered_window(&subscription.cursor_state),
        ) else {
            return 0;
        };
        let threshold_ms = watermark_ms - window_ms / 2;
        let candidates: Vec<(&str, i64)> = events
            .iter()
            .filter_map(|event| {
                let at = event.activity_at_ms?;
                (at < threshold_ms).then_some((event.vendor_event_id.as_str(), at))
            })
            .collect();
        if candidates.is_empty() {
            return 0;
        }
        match self.engine.store().stored_event_activities(
            principal,
            &subscription.subscription_id,
            &candidates,
        ) {
            Ok(stored) => stored.iter().filter(|stored| !**stored).count(),
            Err(error) => {
                eprintln!(warn poller: "late row lookup failed subscription={:?}: {error}", subscription.subscription_id);
                0
            }
        }
    }

    /// Failure to learn an id is degraded publication, not failure of the
    /// watched list read. The committed name claim also throttles absent
    /// connections and denied grants across all watches sharing that name.
    fn resolve_poll_repository(
        &self,
        principal: &str,
        subscription: &TriggerSubscription,
    ) -> Result<Option<PollRepository>, PollCycle> {
        let event_name = match subscription.action.as_str() {
            "list_issues" => crate::event_key::GITHUB_ISSUE_CHANGED,
            "list_pull_requests" => crate::event_key::GITHUB_PR_CHANGED,
            "get_latest_release" => crate::event_key::GITHUB_RELEASE_PUBLISHED,
            _ => return Ok(None),
        };
        let store = self.engine.store();
        let store_failure = |error: cortexkit_store::StoreError| PollCycle::StoreFailed {
            reason: error.to_string(),
        };
        if !store
            .connection(principal, &subscription.connection_id)
            .map_err(store_failure)?
            .is_some_and(|connection| connection.app_key == "github")
        {
            return Ok(None);
        }
        let owner = subscription
            .fixed_args
            .get("owner")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let repo = subscription
            .fixed_args
            .get("repo")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let (Some(owner), Some(repo)) = (owner, repo) else {
            return Ok(None);
        };
        let name = format!("{owner}/{repo}").to_lowercase();
        let at_ms = now_ms();
        let cache_entry = store.repo_id_cache(&name).map_err(store_failure)?;
        let cached = cache_entry.as_ref().and_then(|entry| entry.repo_id);
        // Claim read authority for the `get_repository` call BEFORE the shared
        // owner/name claim below (`reserve_repo_id_resolution`), and only when
        // the cached id is due for a refresh. That claim records this attempt
        // and blocks every watch on the same repository from retrying for an
        // hour, so a store failure found after it would hold back the id for an
        // hour over a fault that may clear on the next tick. The id cache is
        // shared between watches rather than tied to this subscription, so the
        // read is authorized against the catalog's current schema hash for
        // `get_repository`, under this subscription's poll authority.
        //
        // A store failure here is neither a failed resolution nor a failure of
        // the watched read: this cycle publishes with what the cache already
        // holds, nothing is stamped or counted, and the next poll asks again.
        let unclaimed = |error: &dyn std::fmt::Display| {
            eprintln!(warn poller: "repository identity skipped for {name}: store failure: {error}");
        };
        let resolution_due = cache_entry
            .as_ref()
            .is_none_or(|entry| entry.resolution_due(at_ms));
        let request = if resolution_due {
            match store.catalog_action(principal, GITHUB_ACTIONS_CONNECTION, "get_repository") {
                Err(error) => {
                    unclaimed(&error);
                    return Ok(Some(PollRepository {
                        name,
                        event_name,
                        repo_id: cached,
                    }));
                }
                Ok(None) => None,
                Ok(Some(action)) => match poll_read_request(
                    &self.engine,
                    principal,
                    GITHUB_ACTIONS_CONNECTION,
                    "get_repository",
                    json!({"owner": owner, "repo": repo}),
                    &subscription.subscription_id,
                    &action.schema_hash,
                ) {
                    Ok(request) => Some(request),
                    Err(GovernedReadFailure::StoreFailed { reason }) => {
                        unclaimed(&reason);
                        return Ok(Some(PollRepository {
                            name,
                            event_name,
                            repo_id: cached,
                        }));
                    }
                    // An action that is not an active read cannot resolve the
                    // name; that is a failed resolution like any other.
                    Err(_) => None,
                },
            }
        } else {
            None
        };
        if request.is_none() || pass_budget_expired() {
            if resolution_due && request.is_none() {
                store
                    .record_repo_id_resolution(&name, None, at_ms)
                    .map_err(store_failure)?;
            }
            return Ok(Some(PollRepository {
                name,
                event_name,
                repo_id: cached,
            }));
        }
        let admission = store
            .reserve_repo_id_resolution(principal, &subscription.subscription_id, &name, at_ms)
            .map_err(store_failure)?;
        let cached = match admission {
            RepoResolutionAdmission::NotDue => {
                // Re-read after the atomic claim: another watch may have resolved
                // the shared name between our initial lookup and admission.
                let repo_id = store
                    .repo_id_cache(&name)
                    .map_err(store_failure)?
                    .and_then(|entry| entry.repo_id);
                return Ok(Some(PollRepository {
                    name,
                    event_name,
                    repo_id,
                }));
            }
            RepoResolutionAdmission::Deferred => {
                self.count_repo_identity(
                    if cached.is_some() {
                        RepoIdentityCounter::RefreshDeferred
                    } else {
                        RepoIdentityCounter::Deferred
                    },
                    1,
                );
                return Ok(Some(PollRepository {
                    name,
                    event_name,
                    repo_id: cached,
                }));
            }
            RepoResolutionAdmission::Reserved { cached_repo_id, .. } => cached_repo_id,
            // The watch went inactive after this cycle began. That is the same
            // outcome as the attempt stamp finding it inactive, not a store or
            // vendor failure.
            RepoResolutionAdmission::Inactive => {
                return Err(PollCycle::NotEligible {
                    reason: SUBSCRIPTION_NOT_ACTIVE.to_string(),
                })
            }
        };
        let mut grant_missing = false;
        let resolved = match request
            .map(|request| authorize_and_dispatch_read(&self.engine, request))
        {
            Some(Ok(Some(response))) => response
                .get("id")
                .and_then(Value::as_i64)
                .filter(|id| *id > 0),
            // A store failure is not a failed resolution: recording one would
            // count a fault against the name as though GitHub had refused it.
            // The claim above already stamped this attempt, so the name waits
            // out its retry interval; until then the cached id is used.
            Some(Err(GovernedReadFailure::StoreFailed { reason })) => {
                unclaimed(&reason);
                return Ok(Some(PollRepository {
                    name,
                    event_name,
                    repo_id: cached,
                }));
            }
            Some(Err(GovernedReadFailure::Denied(Denial::Grant(_) | Denial::GrantRefusal(_)))) => {
                grant_missing = true;
                None
            }
            _ => None,
        };
        if resolved.is_none() {
            if cached.is_some() {
                self.count_repo_identity(RepoIdentityCounter::RefreshFailed, 1);
            } else if grant_missing {
                self.count_repo_identity(RepoIdentityCounter::GrantMissing, 1);
            }
        }
        let update = store
            .record_repo_id_resolution(&name, resolved, at_ms)
            .map_err(store_failure)?;
        if matches!(update, RepoIdUpdate::IdentityChanged { .. }) {
            self.count_repo_identity(RepoIdentityCounter::IdentityChanged, 1);
            return Err(PollCycle::Suspended {
                reason: "repository_identity_changed".to_string(),
            });
        }
        Ok(Some(PollRepository {
            name,
            event_name,
            repo_id: resolved.or(cached),
        }))
    }

    /// Run one probe: execute the script, compare against the stored baseline,
    /// and commit any change. Validation failures and budget kills are
    /// non-completing -- they do not retire a `once` probe, because a malformed
    /// return must not silently kill the watch it was meant to serve.
    fn poll_probe(&self, principal: &str, subscription: &TriggerSubscription) -> PollCycle {
        let store = self.engine.store();
        let Some(probe) = (match store.probe_subscription(&subscription.subscription_id) {
            Ok(probe) => probe,
            Err(error) => {
                return PollCycle::StoreFailed {
                    reason: error.to_string(),
                }
            }
        }) else {
            return self.suspend(
                principal,
                &subscription.subscription_id,
                "probe_spec_missing",
            );
        };
        // A stored return schema that does not parse can never validate a run,
        // and neither can a cursor whose ordinal is unreadable. Both are standing
        // defects of the registered probe, not a passing condition, so they
        // suspend with a visible reason. An inconclusive answer would leave the
        // probe due, and because these checks run before the attempt is
        // recorded, the scheduler would re-run it on every tick, forever.
        let schema: ReturnSchema = match serde_json::from_value(probe.return_schema.clone()) {
            Ok(schema) => schema,
            Err(_) => {
                return self.suspend(
                    principal,
                    &subscription.subscription_id,
                    "probe_return_schema_invalid",
                )
            }
        };
        if probe_ordinal(&subscription.cursor_state).is_err() {
            return self.suspend(
                principal,
                &subscription.subscription_id,
                "cursor_state_unusable",
            );
        }
        let observed_at_ms = now_ms();
        match store.record_poll_attempt(principal, &subscription.subscription_id, observed_at_ms) {
            Ok(true) => {}
            Ok(false) => {
                return PollCycle::NotEligible {
                    reason: SUBSCRIPTION_NOT_ACTIVE.to_string(),
                }
            }
            Err(error) => {
                return PollCycle::StoreFailed {
                    reason: error.to_string(),
                }
            }
        }
        // An earlier poll's action call may still run after its deadline.
        // Skip the script rather than start a second call to the same vendor.
        // `record_poll_attempt` has already stored this attempt's timestamp,
        // so the probe next becomes due at its normal cadence.
        if ProbeCallInFlight::held(&subscription.subscription_id) {
            return PollCycle::Inconclusive {
                code: PROBE_ACTION_IN_FLIGHT.to_string(),
            };
        }
        let sandbox = match ProbeSandbox::new(probe.actions.iter().cloned()) {
            Ok(sandbox) => sandbox,
            Err(error) => {
                return self.probe_failure_cycle(principal, &subscription.subscription_id, &error)
            }
        };
        // `plexus-probe` deliberately exposes only string failures to guest code.
        // Keep the governance classification beside the host invoker so the poller
        // can apply ordinary poll semantics after the sandbox reports ActionFailed.
        let action_failure = Arc::new(Mutex::new(None));
        let invoker = ProbeActionDispatch {
            engine: self.engine.clone(),
            principal: principal.to_string(),
            connection_id: subscription.connection_id.clone(),
            subscription_id: subscription.subscription_id.clone(),
            fixed_args: subscription.fixed_args.clone(),
            action_failure: Arc::clone(&action_failure),
            deadline: budget::deadline(),
        };
        let observed = match sandbox.run(&probe.script_source, json!({}), &schema, invoker) {
            Ok(value) => probe_value_json(&value),
            Err(error) => {
                let failure = action_failure
                    .lock()
                    .expect("probe action failure lock")
                    .take();
                return match failure {
                    Some(failure) => self.probe_action_failure_outcome(
                        principal,
                        &subscription.subscription_id,
                        failure,
                    ),
                    None => {
                        self.probe_failure_cycle(principal, &subscription.subscription_id, &error)
                    }
                };
            }
        };
        let mut advance = match ProbeStrategy.derive(&subscription.cursor_state, &observed) {
            Ok(advance) => advance,
            // The return value already passed the schema, so the only way to
            // get here is a cursor that cannot advance (an exhausted ordinal).
            Err(_) => {
                return self.suspend(
                    principal,
                    &subscription.subscription_id,
                    "cursor_state_unusable",
                )
            }
        };
        let inputs: Vec<PollEventInput<'_>> = advance
            .events
            .iter()
            .map(|event| PollEventInput {
                vendor_event_id: event.vendor_event_id.as_str(),
                payload: &event.payload,
                observed_at_ms,
                item_kind: Some("probe"),
                activity_at_ms: event.activity_at_ms,
                actor: &crate::actor_attribution::ActorAttribution::NotEnriched,
            })
            .collect();
        let retire = probe.rearm == "once" && !inputs.is_empty();
        match store.commit_probe_success(
            principal,
            &subscription.connection_id,
            &subscription.subscription_id,
            &advance.cursor_state,
            &inputs,
            observed_at_ms,
            retire,
        ) {
            Ok(outcomes) => {
                accounting::record_completion(
                    &subscription.subscription_id,
                    &mut advance,
                    &outcomes,
                );
                if let Err(error) = store.prune(
                    principal,
                    &subscription.subscription_id,
                    UNACKED_MAX_AGE_MS,
                    UNACKED_MAX_ROWS,
                ) {
                    // Same as the vendor path: a successful observation stays
                    // successful if the later trim fails. Retention retries.
                    eprintln!(warn poller: "subscription retention failed: {error}");
                }
                PollCycle::Completed {
                    inserted: outcomes
                        .iter()
                        .filter(|outcome| {
                            matches!(outcome, TriggerEventInsertOutcome::Inserted { .. })
                        })
                        .count(),
                    duplicates: outcomes
                        .iter()
                        .filter(|outcome| {
                            matches!(outcome, TriggerEventInsertOutcome::Duplicate { .. })
                        })
                        .count(),
                }
            }
            Err(crate::storage::PollCommitError::Inactive) => PollCycle::NotEligible {
                reason: SUBSCRIPTION_NOT_ACTIVE.into(),
            },
            Err(error) => PollCycle::StoreFailed {
                reason: error.to_string(),
            },
        }
    }

    fn probe_failure_cycle(
        &self,
        principal: &str,
        subscription_id: &str,
        error: &ProbeError,
    ) -> PollCycle {
        match probe_run_outcome(error) {
            PollCycle::VendorFailed { code } => {
                self.vendor_failure_cycle(principal, subscription_id, code)
            }
            PollCycle::Suspended { reason } => self.suspend(principal, subscription_id, &reason),
            cycle => cycle,
        }
    }

    fn probe_action_failure_outcome(
        &self,
        principal: &str,
        subscription_id: &str,
        failure: ProbeActionFailure,
    ) -> PollCycle {
        match failure {
            ProbeActionFailure::Read(failure) => {
                self.read_failure_cycle(principal, subscription_id, failure)
            }
            ProbeActionFailure::Inconclusive { code, .. } => PollCycle::Inconclusive { code },
        }
    }

    /// Classify a failed authorized read for the subscription that requested it.
    ///
    /// - Report a store failure without changing subscription state.
    /// - Suspend polling for an authorization refusal or denial that retrying
    ///   alone cannot fix, and retain its reason.
    /// - Count a definitive vendor failure toward consecutive failures. Enough
    ///   failures stop polling until an operator intervenes.
    /// - Treat a request never sent or with an unknown outcome as inconclusive.
    ///   Repeating a read is safe. Local rate limits and unreachable adapters
    ///   must not count as vendor failures and stop polling permanently.
    /// - Treat transient credential errors, such as a locked vault or failed
    ///   token refresh, as inconclusive so polling can resume after recovery
    ///   without an operator reactivating the subscription.
    /// - Also treat credentials that need a person to sign in again or replace
    ///   them as inconclusive. Dispatch reports these requests as not sent.
    ///   One credential can serve many subscriptions; suspending each would
    ///   require manually reactivating all of them after repairing it.
    ///   [`Poller::poll_once`] reports a metric per affected connection and logs
    ///   an error when the connection enters this state or its code changes.
    ///   The scheduler retries these subscriptions at most hourly until success.
    fn read_failure_cycle(
        &self,
        principal: &str,
        subscription_id: &str,
        failure: GovernedReadFailure,
    ) -> PollCycle {
        match failure {
            GovernedReadFailure::StoreFailed { reason } => PollCycle::StoreFailed { reason },
            GovernedReadFailure::Refused(_) => {
                self.suspend(principal, subscription_id, &failure.code())
            }
            GovernedReadFailure::VendorFailed { .. } => {
                self.vendor_failure_cycle(principal, subscription_id, failure.code())
            }
            GovernedReadFailure::Denied(Denial::Credential(CredentialDenial::Transient(_))) => {
                PollCycle::Inconclusive {
                    code: failure.code(),
                }
            }
            GovernedReadFailure::Denied(ref denial) => {
                self.suspend(principal, subscription_id, denial.reason_code())
            }
            GovernedReadFailure::NotSent { ref code, .. } if code == "poll_pass_budget" => {
                PollCycle::Deferred {
                    reason: code.clone(),
                }
            }
            GovernedReadFailure::OutcomeUnknown | GovernedReadFailure::NotSent { .. } => {
                PollCycle::Inconclusive {
                    code: failure.code(),
                }
            }
        }
    }

    /// Count one vendor failure toward the subscription's streak.
    fn vendor_failure_cycle(
        &self,
        principal: &str,
        subscription_id: &str,
        code: String,
    ) -> PollCycle {
        match self
            .engine
            .store()
            .record_vendor_failure(principal, subscription_id)
        {
            Ok(true) => PollCycle::VendorFailed { code },
            Ok(false) => PollCycle::NotEligible {
                reason: SUBSCRIPTION_NOT_ACTIVE.into(),
            },
            Err(error) => PollCycle::StoreFailed {
                reason: error.to_string(),
            },
        }
    }

    /// Commit a definitive success: derive the next cursor and events from the
    /// response and write both atomically. A response that cannot be parsed is
    /// not a success to advance past — it suspends the subscription so the gap
    /// is visible rather than silently skipped.
    #[allow(clippy::too_many_arguments)]
    fn complete(
        &self,
        principal: &str,
        subscription: &TriggerSubscription,
        strategy: &dyn CursorStrategy,
        response: Option<&Value>,
        observed_at_ms: i64,
        // What the reviewed manifest says this action yields. Threaded from the
        // caller rather than re-read here, so the kind stamped on an event comes
        // from the SAME shape that chose the strategy which produced it.
        item_kind: Option<&str>,
        coverage_gap: Option<&'static str>,
        repository: Option<&PollRepository>,
    ) -> PollCycle {
        let store = self.engine.store();
        let mut advance = match response {
            Some(response) => match strategy.derive(&subscription.cursor_state, response) {
                Ok(advance) => advance,
                Err(error) => {
                    return self.suspend(
                        principal,
                        &subscription.subscription_id,
                        &format!("{RESPONSE_SHAPE_INVALID}: {error:?}"),
                    )
                }
            },
            // A completed read with no body records nothing but still clears the
            // failure streak and stamps the success, keeping the current cursor.
            None => CursorAdvance {
                cursor_state: subscription.cursor_state.clone(),
                events: Vec::new(),
                items_examined: 0,
                dropped: Vec::new(),
                coverage_gap: None,
            },
        };
        if let Some(reason) = coverage_gap {
            // An ascending drain leaves its unobserved tail at or after the
            // last observed timestamp, including ties at that boundary.
            let watermark = read_i64(&advance.cursor_state, WATERMARK_MS_KEY)
                .ok()
                .flatten()
                .unwrap_or(observed_at_ms);
            advance.coverage_gap = Some(CoverageGap {
                from_ms: watermark,
                to_ms: watermark.max(observed_at_ms),
                reason,
            });
        }
        if subscription.cursor_kind == "ordered_timestamp" {
            let late_rows = self.count_late_rows(principal, subscription, &advance.events);
            if late_rows > 0 {
                accounting::record_late_rows(&subscription.subscription_id, late_rows);
                eprintln!(info poller: "ordered_timestamp_late_rows subscription_id={:?} count={late_rows}", subscription.subscription_id);
            }
            settle_ordered_window(
                &subscription.cursor_state,
                &mut advance.cursor_state,
                late_rows > 0,
                observed_at_ms,
            );
        }
        retain_changed_replay_candidates(&mut advance.events, &mut advance.dropped, |candidates| {
            store.unchanged_event_payloads(principal, &subscription.subscription_id, candidates).inspect_err(|error| {
                eprintln!(warn poller: "stored payload lookup failed subscription={:?}: {error}", subscription.subscription_id);
            })
        });
        // Only a watch with an actor source spends vendor reads on enrichment,
        // so only it pays for the extra per-item lookup. Without one, an
        // already-stored item costs nothing extra and insert-time dedupe drops
        // it under the same reason.
        let skipped_duplicates = if subscription.actor_source.is_some() {
            retain_unstored_established_events(
                &mut advance.events,
                &mut advance.dropped,
                |candidates| {
                    #[cfg(test)]
                    if FAIL_STORED_PAYLOAD_LOOKUP.with(Cell::get) {
                        return Err(cortexkit_store::StoreError::Backend(
                            "stored payload lookup failure injected by a test".to_string(),
                        ));
                    }
                    store.unchanged_event_payloads(
                        principal,
                        &subscription.subscription_id,
                        candidates,
                    ).inspect_err(|error| {
                        eprintln!(warn poller: "stored payload lookup failed subscription={:?}: {error}", subscription.subscription_id);
                    })
                },
            )
        } else {
            0
        };
        // The reviewed manifest is the only authority on what this action yields,
        // and it is already in scope here as the shape that chose the strategy.
        // Reading it from the same place the strategy came from means the kind
        // recorded on an event and the strategy that produced it can never
        // disagree about which action they describe.
        // Keep vendor bodies byte-identical. In particular, `change` belongs to
        // the marker only, so legacy payload-hash dedup still sees the same item.
        let identities = poll_event_identities(subscription, &advance.events, repository);
        let identities = match identities {
            Ok(identities) => identities,
            Err(_) => {
                return self.suspend(
                    principal,
                    &subscription.subscription_id,
                    "event_identity_invalid",
                )
            }
        };
        let (actor_logins, envelope_contexts) =
            self.enrich_actor_logins(principal, subscription, &advance.events, item_kind);
        let inputs: Vec<KeyedPollEventInput<'_>> = advance
            .events
            .iter()
            .zip(actor_logins.iter())
            .zip(identities.iter())
            .zip(envelope_contexts)
            .map(
                |(((event, actor), identity), envelope_context)| KeyedPollEventInput {
                    event: PollEventInput {
                        vendor_event_id: event.vendor_event_id.as_str(),
                        payload: &event.payload,
                        observed_at_ms,
                        item_kind,
                        activity_at_ms: event.activity_at_ms,
                        actor,
                    },
                    identity: identity.as_ref().map(|identity| KeyedEventIdentity {
                        event_key: &identity.key,
                        event_name: repository.expect("keyed repository").event_name,
                        repo_id: repository
                            .and_then(|repo| repo.repo_id)
                            .expect("resolved repository"),
                        change: identity.change,
                        headers: &identity.headers,
                    }),
                    delivery_id: None,
                    envelope_context,
                },
            )
            .collect();
        let gaps: Vec<_> = advance
            .coverage_gap
            .as_ref()
            .map(|gap| PollGapInput {
                from_ms: gap.from_ms,
                to_ms: gap.to_ms,
                reason: gap.reason,
            })
            .into_iter()
            .collect();
        match store.commit_keyed_poll_success(
            principal,
            &subscription.connection_id,
            &subscription.subscription_id,
            &advance.cursor_state,
            &inputs,
            observed_at_ms,
            &gaps,
        ) {
            Ok(outcomes) => {
                if repository.is_some_and(|repo| repo.repo_id.is_none()) {
                    self.count_repo_identity(
                        RepoIdentityCounter::Unresolved,
                        outcomes
                            .iter()
                            .filter(|outcome| {
                                matches!(outcome, TriggerEventInsertOutcome::Inserted { .. })
                            })
                            .count() as u64,
                    );
                }
                accounting::record_completion(
                    &subscription.subscription_id,
                    &mut advance,
                    &outcomes,
                );
                // Enforce the retention bound from the poll path, now that this
                // subscription has just grown its event set. `prune` records a
                // gap marker for any unacked events it removes, so the coverage
                // hole is visible rather than silent.
                //
                // A prune failure does not turn a successful poll into a failed
                // one. At this point `commit_poll_success` has already
                // succeeded: the events are durable, the cursor advanced, the
                // vendor read genuinely completed. `PollCycle::Completed` is
                // the truthful description of what happened. Retention is
                // idempotent and the next cycle prunes again, so a transient
                // store problem costs one skipped trim rather than a
                // misreported cycle — which matters because the scheduler slice
                // consumes these outcomes to decide backoff and suspension, and
                // a working subscription that looks store-failing would be
                // investigated as a vendor problem.
                if let Err(error) = store.prune(
                    principal,
                    &subscription.subscription_id,
                    UNACKED_MAX_AGE_MS,
                    UNACKED_MAX_ROWS,
                ) {
                    eprintln!(warn poller: "subscription retention failed: {error}");
                }
                PollCycle::Completed {
                    inserted: outcomes
                        .iter()
                        .filter(|outcome| {
                            matches!(outcome, TriggerEventInsertOutcome::Inserted { .. })
                        })
                        .count(),
                    // Events skipped before enrichment are exactly the ones
                    // insert-time dedupe would have reported, so they count here
                    // as they did when they still reached storage.
                    duplicates: skipped_duplicates
                        + outcomes
                            .iter()
                            .filter(|outcome| {
                                matches!(outcome, TriggerEventInsertOutcome::Duplicate { .. })
                            })
                            .count(),
                }
            }
            Err(crate::storage::PollCommitError::Inactive) => PollCycle::NotEligible {
                reason: SUBSCRIPTION_NOT_ACTIVE.into(),
            },
            Err(error) => PollCycle::StoreFailed {
                reason: error.to_string(),
            },
        }
    }

    /// Attribute only this cycle's events. Failures remain unknown and cannot
    /// suspend the watch, abort cursor advancement, or fail the watched read.
    fn enrich_actor_logins(
        &self,
        principal: &str,
        subscription: &TriggerSubscription,
        events: &[DerivedEvent],
        item_kind: Option<&str>,
    ) -> (
        Vec<ActorAttribution>,
        Vec<crate::event_envelope::EnvelopeContext>,
    ) {
        let unknown = |failure: EnrichmentFailure| {
            if let Some(event) = events.first() {
                log_actor_unknown(
                    subscription,
                    event,
                    &format!("{} count={}", failure.detail, events.len()),
                );
            }
            events
                .iter()
                .map(|_event| (failure.clone().into_attribution(), Default::default()))
                .unzip()
        };
        let Some(source) = subscription.actor_source.as_ref() else {
            // An unbound watch has no enrichment to fail and needs no warning.
            return (
                vec![ActorAttribution::NotEnriched; events.len()],
                vec![Default::default(); events.len()],
            );
        };
        let Some(item_kind) = item_kind else {
            return unknown(EnrichmentFailure::bare(ActorUnknownCode::ItemKindUnknown));
        };
        if !actor_methods_cover_item(item_kind, &source.methods) {
            return unknown(EnrichmentFailure::bare(
                ActorUnknownCode::ActorMethodsIncomplete,
            ));
        }
        let schema_hash = match self.engine.store().catalog_action(
            principal,
            &source.connection_id,
            &source.action,
        ) {
            Ok(Some(action)) => action.schema_hash,
            Ok(None) => {
                return unknown(EnrichmentFailure::bare(
                    ActorUnknownCode::CatalogActionMissing,
                ))
            }
            Err(error) => {
                return unknown(EnrichmentFailure::new(
                    ActorUnknownCode::CatalogLookupFailed,
                    format!("catalog_lookup_failed: {error}"),
                ))
            }
        };
        let budget = CallBudget::new(ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE);
        let mut diagnostics = std::collections::BTreeMap::new();
        let result = events
            .iter()
            .map(|event| {
                let mut envelope_context = crate::event_envelope::EnvelopeContext::default();
                let result = (|| -> Result<Vec<String>, EnrichmentFailure> {
                    let first_methods = budget.try_take(source.methods.len()).ok_or_else(|| {
                        EnrichmentFailure::bare(ActorUnknownCode::CallCapExhausted)
                    })?;
                    #[cfg(test)]
                    PREVIOUS_OBSERVATION_READS.with(|reads| reads.set(reads.get() + 1));
                    let previous_observed_at_ms = self
                        .engine
                        .store()
                        .previous_event_observed_at(
                            principal,
                            &subscription.connection_id,
                            &subscription.subscription_id,
                            &event.vendor_event_id,
                        )
                        .map_err(|error| {
                            EnrichmentFailure::new(
                                ActorUnknownCode::PreviousObservationLookupFailed,
                                format!("previous_observation_lookup_failed: {error}"),
                            )
                        })?;
                    // Reserve one first attempt per method before dispatching any of them.
                    // Holding the permit keeps those tokens out of the leftover pool, so a
                    // retry cannot spend capacity that later methods on this event still need.
                    // Tokens not converted into slots return to the budget when the permit
                    // drops, so a mid-event failure does not charge for calls that never ran.
                    // A nonempty previous_event_observed_at result means this item
                    // was delivered before. If comments added after that delivery name
                    // no actor, enrichment also reads the first timeline page to find
                    // who changed the item. Reserve that possible read before any
                    // comment dispatch. The methods-only permit prevented a useless
                    // store lookup when no comment calls fit; return it now and take
                    // one complete permit for comments plus the possible timeline.
                    drop(first_methods);
                    let timeline_reserve = usize::from(previous_observed_at_ms.is_some());
                    let mut event_permit = budget
                        .try_take(source.methods.len() + timeline_reserve)
                        .ok_or_else(|| {
                            EnrichmentFailure::bare(ActorUnknownCode::CallCapExhausted)
                        })?;
                    let mut actors = BTreeSet::new();
                    for method in source.methods.iter() {
                        let args = actor_read_args(subscription, event, item_kind, method)
                            .ok_or_else(|| {
                                EnrichmentFailure::bare(ActorUnknownCode::ActorReadArgsUnbuildable)
                            })?;
                        let slot = event_permit.take_one().ok_or_else(|| {
                            EnrichmentFailure::bare(ActorUnknownCode::CallCapExhausted)
                        })?;
                        let response = self.dispatch_actor_read_with_retry(
                            principal,
                            subscription,
                            source,
                            &schema_hash,
                            args,
                            ActorRetryAttempt {
                                first: slot,
                                budget: &budget,
                            },
                        )?;
                        let method_actors = match method.as_str() {
                            "get_comments" => {
                                envelope_context.comment =
                                    newest_window_comment(&response, previous_observed_at_ms);
                                comment_actor_logins(&response, previous_observed_at_ms)
                            }
                            "get_review_comments" => {
                                review_comment_actor_logins(&response, previous_observed_at_ms)
                            }
                            _ => {
                                return Err(EnrichmentFailure::new(
                                    ActorUnknownCode::ActorMethodUnrecognized,
                                    format!("actor_method_unrecognized: {method}"),
                                ))
                            }
                        }
                        .map_err(|miss| match miss {
                            ExtractionMiss::SameSecond => EnrichmentFailure::new(
                                ActorUnknownCode::SameSecondAmbiguity,
                                format!("same_second_ambiguity method={method}"),
                            ),
                            ExtractionMiss::Unrecognized => {
                                actor_response_failure(method, &response)
                            }
                        })?;
                        actors.extend(method_actors);
                    }
                    // An empty later comment window cannot identify a state,
                    // title, label, merge or review actor, so ask the timeline.
                    // Only the first observation can prove an empty history.
                    match previous_observed_at_ms {
                        Some(previous) if actors.is_empty() => {
                            let first_page = event_permit.take_one().ok_or_else(|| {
                                EnrichmentFailure::bare(ActorUnknownCode::CallCapExhausted)
                            })?;
                            self.timeline_actor_logins(
                                principal,
                                subscription,
                                event,
                                previous,
                                ActorRetryAttempt {
                                    first: first_page,
                                    budget: &budget,
                                },
                            )
                        }
                        _ => Ok(actors.into_iter().collect()),
                    }
                })();
                let attribution = match result {
                    Ok(actors) => ActorAttribution::Known(actors),
                    Err(failure) => {
                        let entry = diagnostics.entry(failure.code.as_str()).or_insert((
                            0usize,
                            event,
                            failure.detail.clone(),
                        ));
                        entry.0 += 1;
                        failure.into_attribution()
                    }
                };
                (attribution, envelope_context)
            })
            .unzip();
        for (_, (count, event, detail)) in diagnostics {
            log_actor_unknown(subscription, event, &format!("{detail} count={count}"));
        }
        result
    }

    fn dispatch_actor_read(
        &self,
        principal: &str,
        subscription: &TriggerSubscription,
        source: &ActorSource,
        schema_hash: &str,
        args: Value,
        _authorized: CallSlot,
    ) -> Result<Value, EnrichmentFailure> {
        // If looking up an event's actor fails, leave the actor unknown rather
        // than suspend or fail the subscription. Preserve reason codes for
        // catalog refusals, store failures, and authorization denials.
        let failure = match governed_read(
            &self.engine,
            principal,
            &source.connection_id,
            &source.action,
            args,
            &subscription.subscription_id,
            schema_hash,
        ) {
            Ok(Some(response)) => return Ok(response),
            Ok(None) => {
                return Err(EnrichmentFailure::new(
                    ActorUnknownCode::TransportFailure,
                    "transport_failure: response_missing".to_string(),
                ))
            }
            Err(failure) => failure,
        };
        let retryable = failure.actor_retryable();
        let mut failure = match failure {
            GovernedReadFailure::Refused(refusal) => actor_governed_refusal(match &refusal {
                PollAuthorizationRefusal::ActionNotFound => "catalog_action_not_found",
                PollAuthorizationRefusal::ActionQuarantined => "catalog_action_quarantined",
                PollAuthorizationRefusal::ActionDisabled => "catalog_action_disabled",
                _ => refusal_reason(&refusal),
            }),
            GovernedReadFailure::StoreFailed { .. } => actor_governed_refusal("store_failure"),
            GovernedReadFailure::Denied(denial) => actor_governed_refusal(denial.reason_code()),
            GovernedReadFailure::VendorFailed { code, message } => EnrichmentFailure::new(
                ActorUnknownCode::TransportFailure,
                format!("transport_failure: {code}: {message}"),
            ),
            GovernedReadFailure::OutcomeUnknown => EnrichmentFailure::new(
                ActorUnknownCode::TransportFailure,
                "transport_failure: outcome_unknown".to_string(),
            ),
            GovernedReadFailure::NotSent { code, message } => {
                if matches!(
                    code.as_str(),
                    "aborted_stale_authorization" | "reservation_expired" | "grant_hash_mismatch"
                ) || code.starts_with("credential_")
                {
                    actor_governed_refusal(&code)
                } else {
                    EnrichmentFailure::new(
                        ActorUnknownCode::TransportFailure,
                        format!("transport_failure: not_sent: {code}: {message}"),
                    )
                }
            }
        };
        failure.retryable = retryable;
        Err(failure)
    }

    /// Retain the existing single retry without spending the capacity reserved
    /// for undispatched methods of the same event. Only the final unknown result
    /// is logged by the event owner, not each failed attempt.
    fn dispatch_actor_read_with_retry(
        &self,
        principal: &str,
        subscription: &TriggerSubscription,
        source: &ActorSource,
        schema_hash: &str,
        args: Value,
        attempt: ActorRetryAttempt<'_>,
    ) -> Result<Value, EnrichmentFailure> {
        let first = self.dispatch_actor_read(
            principal,
            subscription,
            source,
            schema_hash,
            args.clone(),
            attempt.first,
        );
        if first
            .as_ref()
            .err()
            .is_none_or(|failure| !failure.retryable)
        {
            return first;
        }
        // A retry is one extra call. Remaining first attempts are still held by
        // the event permit, so this take succeeds only when leftover capacity
        // covers the retry without stealing them.
        let Some(retry) = attempt
            .budget
            .try_take(1)
            .and_then(|mut permit| permit.take_one())
        else {
            // The retry note joins the logged detail only; the stored code
            // stays the first attempt's.
            return first.map_err(|mut failure| {
                failure.detail.push_str("; retry_call_cap_exhausted");
                failure
            });
        };
        self.dispatch_actor_read(principal, subscription, source, schema_hash, args, retry)
    }

    /// Name who acted on an item whose later comment window is empty, from its
    /// timeline. The read goes through the handle connection the repository is
    /// bound to, under the same governed poll path, retry, and call budget as
    /// the comment reads. `first_page` is the slot the event reserved; each
    /// further page draws one call from the cycle's leftover budget.
    fn timeline_actor_logins(
        &self,
        principal: &str,
        subscription: &TriggerSubscription,
        event: &DerivedEvent,
        previous_observed_at_ms: i64,
        first_page: ActorRetryAttempt<'_>,
    ) -> Result<Vec<String>, EnrichmentFailure> {
        let (owner, repo, number) = actor_item_coordinates(subscription, event)
            .ok_or_else(|| EnrichmentFailure::bare(ActorUnknownCode::ActorReadArgsUnbuildable))?;
        let store = self.engine.store();
        let (connection_principal, connection_id) =
            match store.github_handle_connection_for_repo(&format!("{owner}/{repo}")) {
                Ok(Some(binding)) => binding,
                Ok(None) => return Err(actor_governed_refusal("timeline_repository_unbound")),
                Err(_) => return Err(actor_governed_refusal("timeline_binding_lookup_failed")),
            };
        // A poll reads only connections owned by its own principal; a handle
        // owned by someone else cannot carry this subscription's authority.
        if connection_principal != principal {
            return Err(actor_governed_refusal("timeline_handle_principal_mismatch"));
        }
        let schema_hash =
            match store.catalog_action(principal, &connection_id, ACTOR_TIMELINE_ACTION) {
                Ok(Some(action)) => action.schema_hash,
                Ok(None) => return Err(actor_governed_refusal("catalog_action_not_found")),
                Err(error) => {
                    return Err(EnrichmentFailure::new(
                        ActorUnknownCode::CatalogLookupFailed,
                        format!("catalog_lookup_failed: {error}"),
                    ))
                }
            };
        let timeline = ActorSource {
            connection_id,
            action: ACTOR_TIMELINE_ACTION.to_string(),
            methods: Vec::new(),
        };
        let unrecognized = || {
            EnrichmentFailure::new(
                ActorUnknownCode::UnrecognizedResponseShape,
                "unrecognized_response_shape method=timeline".to_string(),
            )
        };
        let budget = first_page.budget;
        let mut reserved = Some(first_page.first);
        let mut entries = Vec::new();
        for page in 1..=ACTOR_TIMELINE_MAX_PAGES {
            let slot = match reserved.take() {
                Some(slot) => slot,
                None => budget
                    .try_take(1)
                    .and_then(|mut permit| permit.take_one())
                    .ok_or_else(|| {
                        EnrichmentFailure::new(
                            ActorUnknownCode::CallCapExhausted,
                            format!("call_cap_exhausted method=timeline page={page}"),
                        )
                    })?,
            };
            let args = json!({
                "owner": owner,
                "repo": repo,
                "issue_number": number,
                "per_page": ACTOR_TIMELINE_PAGE_SIZE,
                "page": page,
            });
            let response = self.dispatch_actor_read_with_retry(
                principal,
                subscription,
                &timeline,
                &schema_hash,
                args,
                ActorRetryAttempt {
                    first: slot,
                    budget,
                },
            )?;
            let Value::Array(page_entries) = response else {
                return Err(unrecognized());
            };
            let page_len = page_entries.len();
            if page_len > ACTOR_TIMELINE_PAGE_SIZE {
                return Err(unrecognized());
            }
            entries.extend(page_entries);
            if page_len < ACTOR_TIMELINE_PAGE_SIZE {
                return timeline_window_actors(&entries, previous_observed_at_ms);
            }
        }
        Err(EnrichmentFailure::new(
            ActorUnknownCode::TimelinePageSaturation,
            format!(
                "timeline_page_saturation pages={ACTOR_TIMELINE_MAX_PAGES} per_page={ACTOR_TIMELINE_PAGE_SIZE}"
            ),
        ))
    }

    /// Suspend a subscription and report it. `PlexusStore::suspend` records the
    /// coverage gap the suspension creates, so the operator sees the interval
    /// the poller stopped covering.
    fn suspend(&self, principal: &str, subscription_id: &str, reason: &str) -> PollCycle {
        match self
            .engine
            .store()
            .suspend(principal, subscription_id, reason)
        {
            Ok(_) => {
                accounting::forget_subscription(subscription_id);
                PollCycle::Suspended {
                    reason: reason.to_string(),
                }
            }
            Err(error) => PollCycle::StoreFailed {
                reason: error.to_string(),
            },
        }
    }
}

fn poll_event_identities(
    subscription: &TriggerSubscription,
    events: &[DerivedEvent],
    repository: Option<&PollRepository>,
) -> Result<Vec<Option<PollEventIdentity>>, crate::event_key::EventKeyError> {
    events.iter().map(|event| {
            let Some(repository) = repository.filter(|repo| repo.repo_id.is_some()) else {
                return Ok(None);
            };
            let repo_id = repository.repo_id.expect("resolved repository");
            let fields = json!({"repo_id": repo_id, "number": event.payload.get("number"),
                "updated_at": event.payload.get("updated_at"), "release_id": event.payload.get("id")});
            let key = crate::event_key::derive_event_key(repository.event_name, &fields)?;
            let change = if repository.event_name == crate::event_key::GITHUB_ISSUE_CHANGED {
                event.payload.get("created_at").and_then(Value::as_str).zip(
                    event.payload.get("updated_at").and_then(Value::as_str))
                    .map(|(created, updated)| if created == updated { "opened" } else { "updated" })
            } else { None };
            Ok(Some(PollEventIdentity { key, change, headers: EventHeaders {
                repo: repository.name.clone(), project: subscription.project_id.clone(),
                pr: (repository.event_name == crate::event_key::GITHUB_PR_CHANGED).then(|| event.payload["number"].to_string()),
                branch: None, conclusion: None,
            } }))
        }).collect::<Result<Vec<_>, crate::event_key::EventKeyError>>()
}

fn log_actor_unknown(subscription: &TriggerSubscription, event: &DerivedEvent, reason: &str) {
    eprintln!(warn poller:
        "actor_enrichment_unknown subscription={:?} item={:?} actor_source={:?} reason={reason}",
        subscription.subscription_id, event.vendor_event_id, subscription.actor_source
    );
}

/// Why enrichment could not attribute one event: the code that is stored and
/// served, plus the full diagnostic that is only logged.
#[derive(Debug, Clone)]
struct EnrichmentFailure {
    code: ActorUnknownCode,
    detail: String,
    retryable: bool,
}

impl EnrichmentFailure {
    fn new(code: ActorUnknownCode, detail: String) -> Self {
        EnrichmentFailure {
            code,
            detail,
            retryable: false,
        }
    }

    /// A failure whose diagnostic is just its code.
    fn bare(code: ActorUnknownCode) -> Self {
        EnrichmentFailure::new(code, code.as_str().to_string())
    }

    fn into_attribution(self) -> ActorAttribution {
        ActorAttribution::Unknown { code: self.code }
    }
}

/// Why a comment extractor could not return an actor set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtractionMiss {
    /// A comment's creation or edit shares the previous observation's
    /// vendor-reported second, so it cannot be placed inside or outside the
    /// window. The response itself was well formed.
    SameSecond,
    /// The response is not a shape the extractor accepts, or it is a page that
    /// cannot prove completeness. [`actor_response_failure`] tells those apart.
    Unrecognized,
}

fn actor_governed_refusal(code: &str) -> EnrichmentFailure {
    EnrichmentFailure::new(
        ActorUnknownCode::GovernedReadRefusal,
        format!("governed_read_refusal code={code}; operator action required: enrichment was not allowed to read; check authority/connection; for catalog quarantine use review-action then repin-action after review"),
    )
}

/// Diagnose an extractor's unknown result without changing which shapes or
/// windows it accepts. Pagination evidence distinguishes incomplete history
/// from a malformed response; neither is an authoritative actor set.
fn actor_response_failure(method: &str, response: &Value) -> EnrichmentFailure {
    let saturated = match method {
        "get_comments" => response
            .as_array()
            .is_some_and(|comments| comments.len() >= ACTOR_COMMENT_PAGE_SIZE),
        "get_review_comments" => {
            response
                .pointer("/pageInfo/hasNextPage")
                .and_then(Value::as_bool)
                == Some(true)
                || response
                    .get("review_threads")
                    .and_then(Value::as_array)
                    .is_some_and(|threads| {
                        response
                            .get("totalCount")
                            .and_then(Value::as_u64)
                            .is_some_and(|total| total != threads.len() as u64)
                            || threads.iter().any(|thread| {
                                thread
                                    .get("comments")
                                    .and_then(Value::as_array)
                                    .is_some_and(|comments| {
                                        thread
                                            .get("total_count")
                                            .and_then(Value::as_u64)
                                            .is_some_and(|total| total != comments.len() as u64)
                                    })
                            })
                    })
        }
        _ => false,
    };
    let code = if saturated {
        ActorUnknownCode::CommentPageSaturation
    } else {
        ActorUnknownCode::UnrecognizedResponseShape
    };
    EnrichmentFailure::new(code, format!("{} method={method}", code.as_str()))
}

fn actor_methods_cover_item(item_kind: &str, methods: &[String]) -> bool {
    match item_kind {
        "issue" => methods == ["get_comments"],
        "pull_request" => {
            methods.len() == 2
                && methods.iter().any(|method| method == "get_comments")
                && methods.iter().any(|method| method == "get_review_comments")
        }
        _ => false,
    }
}

fn actor_read_args(
    subscription: &TriggerSubscription,
    event: &DerivedEvent,
    item_kind: &str,
    method: &str,
) -> Option<Value> {
    let (owner, repo, number) = actor_item_coordinates(subscription, event)?;
    let item_number_key = match item_kind {
        "issue" => "issue_number",
        "pull_request" => "pullNumber",
        _ => return None,
    };
    let mut args = serde_json::Map::new();
    args.insert("method".to_string(), Value::String(method.to_string()));
    args.insert("owner".to_string(), Value::String(owner.to_string()));
    args.insert("repo".to_string(), Value::String(repo.to_string()));
    args.insert(item_number_key.to_string(), Value::from(number));
    args.insert("perPage".to_string(), Value::from(ACTOR_COMMENT_PAGE_SIZE));
    Some(Value::Object(args))
}

/// The watched repository's owner and name, and the event item's number.
fn actor_item_coordinates<'a>(
    subscription: &'a TriggerSubscription,
    event: &DerivedEvent,
) -> Option<(&'a str, &'a str, u64)> {
    let owner = subscription
        .fixed_args
        .get("owner")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let repo = subscription
        .fixed_args
        .get("repo")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let number = event.payload.get("number")?.as_u64()?;
    Some((owner, repo, number))
}

/// Reuse the already-read conversation comments, without another vendor call.
/// Same-second ambiguity cannot identify a comment in the observation window.
fn newest_window_comment(response: &Value, previous: Option<i64>) -> Option<Value> {
    response
        .as_array()?
        .iter()
        .filter_map(|comment| {
            let created = comment
                .get("created_at")
                .or_else(|| comment.get("createdAt"))?
                .as_str()
                .and_then(iso8601::parse_to_millis)?;
            let updated = comment
                .get("updated_at")
                .or_else(|| comment.get("updatedAt"))
                .and_then(Value::as_str)
                .and_then(iso8601::parse_to_millis)
                .unwrap_or(created);
            (in_actor_window(created, updated, previous).ok()?
                && recognizable_comment_login(comment).is_some())
            .then_some((updated.max(created), comment))
        })
        .max_by_key(|(activity, _)| *activity)
        .map(|(_, comment)| comment.clone())
}

fn comment_actor_logins(
    response: &Value,
    previous_observed_at_ms: Option<i64>,
) -> Result<BTreeSet<String>, ExtractionMiss> {
    let comments = response.as_array().ok_or(ExtractionMiss::Unrecognized)?;
    // A full bare page carries no `hasNextPage` bit, so it cannot prove this is
    // the complete actor set. Treat saturation as unknown rather than storing a
    // partial set that looks authoritative.
    if comments.len() >= ACTOR_COMMENT_PAGE_SIZE {
        return Err(ExtractionMiss::Unrecognized);
    }
    actor_logins_from_comments(comments, previous_observed_at_ms)
}

fn review_comment_actor_logins(
    response: &Value,
    previous_observed_at_ms: Option<i64>,
) -> Result<BTreeSet<String>, ExtractionMiss> {
    // Shape and completeness checks. Every miss here is `Unrecognized`;
    // `actor_response_failure` later separates an incomplete page from a
    // malformed one by looking at the same response.
    let shape = || -> Option<(&Vec<Value>, bool)> {
        let response = response.as_object()?;
        let threads = response.get("review_threads")?.as_array()?;
        let total_count = usize::try_from(response.get("totalCount")?.as_u64()?).ok()?;
        let page_info = response.get("pageInfo")?.as_object()?;
        let has_next_page = page_info.get("hasNextPage")?.as_bool()?;
        Some((threads, total_count == threads.len() && !has_next_page))
    };
    let (threads, complete) = shape().ok_or(ExtractionMiss::Unrecognized)?;
    if !complete {
        return Err(ExtractionMiss::Unrecognized);
    }

    let mut actors = BTreeSet::new();
    for thread in threads {
        let thread_comments = || -> Option<(&Vec<Value>, usize)> {
            let thread = thread.as_object()?;
            let comments = thread.get("comments")?.as_array()?;
            let thread_total = usize::try_from(thread.get("total_count")?.as_u64()?).ok()?;
            Some((comments, thread_total))
        };
        let (comments, thread_total) = thread_comments().ok_or(ExtractionMiss::Unrecognized)?;
        if thread_total != comments.len() {
            return Err(ExtractionMiss::Unrecognized);
        }
        actors.extend(actor_logins_from_comments(
            comments,
            previous_observed_at_ms,
        )?);
    }
    Ok(actors)
}

fn actor_logins_from_comments(
    comments: &[Value],
    previous_observed_at_ms: Option<i64>,
) -> Result<BTreeSet<String>, ExtractionMiss> {
    let mut actors = BTreeSet::new();
    for comment in comments {
        let created_at = comment
            .get("created_at")
            .or_else(|| comment.get("createdAt"))
            .and_then(Value::as_str)
            .and_then(iso8601::parse_to_millis)
            .ok_or(ExtractionMiss::Unrecognized)?;
        let updated_at = match comment
            .get("updated_at")
            .or_else(|| comment.get("updatedAt"))
        {
            Some(value) => value
                .as_str()
                .and_then(iso8601::parse_to_millis)
                .ok_or(ExtractionMiss::Unrecognized)?,
            None => created_at,
        };
        if !in_actor_window(created_at, updated_at, previous_observed_at_ms)? {
            continue;
        }
        let login = recognizable_comment_login(comment).ok_or(ExtractionMiss::Unrecognized)?;
        actors.insert(login.to_string());
    }
    Ok(actors)
}

/// Whether activity created at `created_at` and last updated at `updated_at`
/// (epoch milliseconds) falls after the previous observation. Every activity
/// is inside the window on a first observation.
fn in_actor_window(
    created_at: i64,
    updated_at: i64,
    previous_observed_at_ms: Option<i64>,
) -> Result<bool, ExtractionMiss> {
    let Some(previous) = previous_observed_at_ms else {
        return Ok(true);
    };
    let created_second = created_at.div_euclid(1_000);
    let updated_second = updated_at.div_euclid(1_000);
    let previous_second = previous.div_euclid(1_000);
    // Activity in a later second than the observation is inside the window no
    // matter what else is ambiguous: a comment created in the observation's own
    // second but edited in a later one was acted on after the observation by
    // its author, so that author belongs in the set. Deciding this first keeps
    // a definite answer from being reported as an ambiguous one.
    if created_second > previous_second || updated_second > previous_second {
        return Ok(true);
    }
    // GitHub reports activity only to the second, while the previous
    // observation uses our host's millisecond clock. Even if those clocks
    // agree, activity in the same reported second can be on either side of the
    // observation. Return unknown rather than an invented actor set that could
    // suppress a wake. Clock skew can extend the uncertainty, but widening into
    // earlier seconds would reintroduce historical actors; resolving that
    // requires persisted activity identities or a vendor-relative watermark.
    if created_second == previous_second || updated_second == previous_second {
        return Err(ExtractionMiss::SameSecond);
    }
    Ok(false)
}

/// Who one timeline entry says acted.
enum TimelineActor<'a> {
    /// A GitHub login the vendor attributes the entry to.
    Login(&'a str),
    /// A commit whose git author has no GitHub login we can trust.
    UnresolvedCommit,
}

/// Turn the timeline window after `previous_observed_at_ms` into the event's
/// actor set.
///
/// The result is all-or-nothing: if any in-window entry cannot be attributed
/// (a commit whose author is a bare git identity), the whole event is
/// `unresolved_commit_author`. Returning the logins that could be read would
/// be a partial set, and a partial set holding only bot logins would suppress
/// a wake that a human caused.
fn timeline_window_actors(
    entries: &[Value],
    previous_observed_at_ms: i64,
) -> Result<Vec<String>, EnrichmentFailure> {
    let mut logins = BTreeSet::new();
    let mut unresolved = false;
    for entry in entries {
        // Parsing an entry never compares it with the window, so its only
        // failure is an unrecognized shape.
        let activities = timeline_entry_activities(entry).map_err(|_| {
            EnrichmentFailure::new(
                ActorUnknownCode::UnrecognizedResponseShape,
                "unrecognized_response_shape method=timeline".to_string(),
            )
        })?;
        for (created_at, updated_at, actor) in activities {
            let inside = in_actor_window(created_at, updated_at, Some(previous_observed_at_ms))
                .map_err(|_| {
                    EnrichmentFailure::new(
                        ActorUnknownCode::SameSecondAmbiguity,
                        "same_second_ambiguity method=timeline".to_string(),
                    )
                })?;
            if !inside {
                continue;
            }
            match actor {
                TimelineActor::Login(login) => {
                    logins.insert(login.to_string());
                }
                TimelineActor::UnresolvedCommit => unresolved = true,
            }
        }
    }
    if unresolved {
        return Err(EnrichmentFailure::bare(
            ActorUnknownCode::UnresolvedCommitAuthor,
        ));
    }
    if logins.is_empty() {
        return Err(EnrichmentFailure::bare(ActorUnknownCode::EmptyActorWindow));
    }
    Ok(logins.into_iter().collect())
}

/// The timestamped activities one timeline entry records, each as
/// `(created_at_ms, updated_at_ms, actor)`.
///
/// Which field names the actor depends on the entry type:
/// - `reviewed` and `commented` name the author in `user` (a body-only PR
///   review appears in no comment list, so this is the only place it shows);
/// - `line-commented` and `commit-commented` carry their comments in a nested
///   `comments` list, each with its own `user` and timestamps;
/// - `committed` carries only a git author (`name`, `email`, `date`) and no
///   GitHub account. A git name is free text anyone can set, so it is never
///   taken as a login: only a GitHub noreply email that encodes the login is
///   trusted, and anything else is an unresolved commit;
/// - every other event (labeled, renamed, closed, merged, assigned,
///   review_requested, head_ref_force_pushed, ...) names `actor`.
///
/// An entry with no actor field at all names nobody and records nothing. An
/// actor field that is present but unreadable, or a timestamp that is missing
/// or malformed, is `Unrecognized`: dropping it could leave a partial set.
fn timeline_entry_activities(
    entry: &Value,
) -> Result<Vec<(i64, i64, TimelineActor<'_>)>, ExtractionMiss> {
    let timestamp = |value: Option<&Value>| -> Result<i64, ExtractionMiss> {
        value
            .and_then(Value::as_str)
            .and_then(iso8601::parse_to_millis)
            .ok_or(ExtractionMiss::Unrecognized)
    };
    fn account_login(account: &Value) -> Result<&str, ExtractionMiss> {
        account
            .get("login")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|login| !login.is_empty())
            .ok_or(ExtractionMiss::Unrecognized)
    }
    let entry_object = entry.as_object().ok_or(ExtractionMiss::Unrecognized)?;
    let event = entry_object
        .get("event")
        .and_then(Value::as_str)
        .ok_or(ExtractionMiss::Unrecognized)?;
    match event {
        "committed" => {
            let date = timestamp(
                entry
                    .pointer("/committer/date")
                    .or_else(|| entry.pointer("/author/date")),
            )?;
            let actor = entry
                .pointer("/author/email")
                .and_then(Value::as_str)
                .and_then(noreply_login)
                .map_or(TimelineActor::UnresolvedCommit, TimelineActor::Login);
            Ok(vec![(date, date, actor)])
        }
        "line-commented" | "commit-commented" => {
            let Some(comments) = entry_object.get("comments") else {
                return Ok(Vec::new());
            };
            comments
                .as_array()
                .ok_or(ExtractionMiss::Unrecognized)?
                .iter()
                .map(|comment| {
                    let created_at = timestamp(comment.get("created_at"))?;
                    let updated_at = match comment.get("updated_at") {
                        Some(value) => timestamp(Some(value))?,
                        None => created_at,
                    };
                    let user = comment.get("user").ok_or(ExtractionMiss::Unrecognized)?;
                    Ok((
                        created_at,
                        updated_at,
                        TimelineActor::Login(account_login(user)?),
                    ))
                })
                .collect()
        }
        _ => {
            let account = match event {
                "reviewed" | "commented" => entry_object
                    .get("user")
                    .or_else(|| entry_object.get("actor")),
                _ => entry_object.get("actor"),
            };
            let Some(account) = account else {
                return Ok(Vec::new());
            };
            let login = account_login(account)?;
            let created_at = timestamp(
                entry_object
                    .get("submitted_at")
                    .filter(|_| event == "reviewed")
                    .or_else(|| entry_object.get("created_at")),
            )?;
            let updated_at = match entry_object.get("updated_at") {
                Some(value) => timestamp(Some(value))?,
                None => created_at,
            };
            Ok(vec![(created_at, updated_at, TimelineActor::Login(login))])
        }
    }
}

/// The GitHub login a commit author's email encodes, when it is a GitHub
/// noreply address: `<id>+<login>@users.noreply.github.com` or the older
/// `<login>@users.noreply.github.com`. GitHub assigns these addresses per
/// account, so the login in one is the account's own. Any other email is not
/// evidence of an account.
fn noreply_login(email: &str) -> Option<&str> {
    let (local, domain) = email.trim().rsplit_once('@')?;
    if !domain.eq_ignore_ascii_case("users.noreply.github.com") {
        return None;
    }
    let login = match local.split_once('+') {
        Some((id, login)) => {
            if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            login
        }
        None => local,
    };
    // Accept ASCII letters, digits and hyphens, but no leading hyphen;
    // an App's bot account may add a `[bot]` suffix.
    let name = login.strip_suffix("[bot]").unwrap_or(login);
    let valid = !name.is_empty()
        && name.len() <= 39
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    valid.then_some(login)
}

fn recognizable_comment_login(comment: &Value) -> Option<&str> {
    comment
        .pointer("/user/login")
        .and_then(Value::as_str)
        .or_else(|| comment.pointer("/author/login").and_then(Value::as_str))
        // GitHub's current trimmed review-thread leaf uses `author` as the
        // login string, while issue-style comments use `user.login`.
        .or_else(|| comment.get("author").and_then(Value::as_str))
        .map(str::trim)
        .filter(|login| !login.is_empty())
}

/// Map a pre-gate refusal to the machine-readable suspension reason an operator
/// sees. These are authorization-side states, never vendor failures.
fn refusal_reason(refusal: &PollAuthorizationRefusal) -> &'static str {
    match refusal {
        PollAuthorizationRefusal::ActionNotFound => "action_not_found",
        PollAuthorizationRefusal::ActionRiskNotRead => "action_risk_not_read",
        PollAuthorizationRefusal::ActionQuarantined => "action_quarantined",
        PollAuthorizationRefusal::ActionDisabled => "action_disabled",
        PollAuthorizationRefusal::ActionUnavailable(_) => "action_unavailable",
        // Handled by the caller as StoreFailed, never as a suspension.
        PollAuthorizationRefusal::StoreFailure => "store_failure",
    }
}

fn probe_reason_code(error: &ProbeError) -> &'static str {
    match error {
        ProbeError::Timeout { .. } => "probe_timeout",
        ProbeError::MemoryLimit { .. } => "probe_memory",
        ProbeError::ReturnValidation(_) | ProbeError::InvalidSchema(_) => "probe_return_invalid",
        ProbeError::ActionRefused { .. } => "probe_action_refused",
        ProbeError::ActionFailed { .. } => "probe_action_failed",
        ProbeError::Execution { .. } => "probe_execution",
        ProbeError::HostConfiguration { .. } | ProbeError::Sandbox { .. } => "probe_sandbox",
    }
}

fn probe_run_outcome(error: &ProbeError) -> PollCycle {
    let code = probe_reason_code(error).to_string();
    match error {
        ProbeError::Timeout { .. } | ProbeError::MemoryLimit { .. } => {
            PollCycle::VendorFailed { code }
        }
        _ => PollCycle::Suspended {
            reason: format!(
                "{code}: {}",
                error.to_string().chars().take(512).collect::<String>()
            ),
        },
    }
}

/// Codes with which dispatch reports a credential only a person can repair,
/// as `CredentialDenial::reason_code` names them: the vault wants the user to
/// authenticate again, the credential is permanently unusable, or the
/// connection has none. A locked vault or a failed refresh is not here; those
/// clear by themselves.
const CREDENTIAL_REPAIR_CODES: [&str; 3] = [
    "credential_auth_required",
    "credential_permanent",
    "credential_missing",
];

/// Whether `cycle` is an inconclusive poll caused by a credential only a person
/// can repair. The scheduler polls such a watch at most hourly until a poll
/// succeeds again.
pub(crate) fn needs_credential_repair(cycle: &PollCycle) -> bool {
    matches!(cycle, PollCycle::Inconclusive { code } if CREDENTIAL_REPAIR_CODES.contains(&code.as_str()))
}

/// Make a credential that needs repair loud without suspending anything.
///
/// The connection gets an entry in `credentialNeedsRepairByConnection` and one
/// error line when it enters that state or its code changes; the first
/// successful poll on the connection removes the entry and logs the recovery
/// once. Logging on state changes only keeps a credential shared by many
/// watches from writing a line per watch per poll.
fn track_credential_repair(principal: &str, connection_id: &str, cycle: &PollCycle) {
    let connection = format!("{principal}/{connection_id}");
    match cycle {
        PollCycle::Inconclusive { code } if needs_credential_repair(cycle) => {
            if accounting::mark_credential_repair(&connection, code) {
                eprintln!(error poller: "credential_needs_repair connection={connection:?} code={code}: watches on this connection are retried at most hourly until the credential is repaired");
            }
        }
        PollCycle::Completed { .. } => {
            if let Some(code) = accounting::clear_credential_repair(&connection) {
                eprintln!(info poller: "credential_repaired connection={connection:?} previous_code={code}");
            }
        }
        _ => {}
    }
}

/// Why a governed poll-path read produced no response to act on.
///
/// Every read the poller makes — the watched list, a probe's `invoke`, a CI
/// page, a repository identity read and an actor-enrichment read — claims poll
/// authority, authorizes and dispatches through [`governed_read`], so those
/// steps and the outcomes they can end in are written once. Separate copies of
/// that sequence drifted before: one counted a request that was never sent as a
/// vendor failure. What a failure MEANS for a subscription is then decided in
/// one place too, [`Poller::read_failure_cycle`], except for the two reads that
/// must never fail or suspend the watch (identity and actor enrichment), which
/// map it to their own degraded results.
#[derive(Clone, Debug, PartialEq, Eq)]
enum GovernedReadFailure {
    /// The store could not answer while claiming authority or authorizing.
    StoreFailed { reason: String },
    /// The catalog says this is not an active read action.
    Refused(PollAuthorizationRefusal),
    /// Authorization denied the read. A store failure during authorization is
    /// reported as `StoreFailed` instead, never as a denial.
    Denied(Denial),
    /// The vendor answered with a definitive failure.
    VendorFailed { code: String, message: String },
    /// The request may or may not have reached the vendor.
    OutcomeUnknown,
    /// The request was refused locally and never reached the vendor.
    NotSent { code: String, message: String },
}

impl GovernedReadFailure {
    fn actor_retryable(&self) -> bool {
        match self {
            Self::OutcomeUnknown => true,
            Self::VendorFailed { code, .. } => {
                code == "timeout"
                    || code
                        .strip_prefix("http_")
                        .and_then(|status| status.parse::<u16>().ok())
                        .is_some_and(|status| (500..600).contains(&status))
            }
            _ => false,
        }
    }

    /// The machine-readable code that names this failure.
    fn code(&self) -> String {
        match self {
            Self::StoreFailed { reason } => reason.clone(),
            Self::Refused(refusal) => refusal_reason(refusal).to_string(),
            Self::Denied(Denial::Credential(CredentialDenial::Transient(_))) => {
                "credential_transient".into()
            }
            Self::Denied(denial) => denial.reason_code().to_string(),
            Self::VendorFailed { code, .. } | Self::NotSent { code, .. } => code.clone(),
            Self::OutcomeUnknown => "outcome_unknown".to_string(),
        }
    }
}

/// Claim poll authority for one read: the catalog must still list `action` as
/// an active read whose schema matches `schema_hash`.
fn poll_read_request<C, T>(
    engine: &GovernanceEngine<C, T>,
    principal: &str,
    connection_id: &str,
    action: &str,
    args: Value,
    subscription_id: &str,
    schema_hash: &str,
) -> Result<AuthorizationRequest, GovernedReadFailure>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    engine
        .poll_authorization_request(
            principal,
            connection_id,
            action,
            args,
            subscription_id,
            schema_hash,
        )
        .map_err(|refusal| match refusal {
            PollAuthorizationRefusal::StoreFailure => GovernedReadFailure::StoreFailed {
                reason: "store_failure".to_string(),
            },
            refusal => GovernedReadFailure::Refused(refusal),
        })
}

/// Authorize a claimed read and dispatch it. `Ok(None)` is a success that
/// carried no body; each caller decides whether that is acceptable.
fn authorize_and_dispatch_read<C, T>(
    engine: &GovernanceEngine<C, T>,
    request: AuthorizationRequest,
) -> Result<Option<Value>, GovernedReadFailure>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    if pass_budget_expired() {
        return Err(GovernedReadFailure::NotSent {
            code: "poll_pass_budget".into(),
            message: "poll pass deadline reached".into(),
        });
    }
    let reservation = engine.authorize(request).map_err(|denial| match denial {
        Denial::StoreFailure => GovernedReadFailure::StoreFailed {
            reason: "store_failure".to_string(),
        },
        denial => GovernedReadFailure::Denied(denial),
    })?;
    match engine.revalidate_and_dispatch(&reservation).outcome {
        TransportOutcome::Completed { response } => Ok(response),
        TransportOutcome::VendorFailed { code, message } => {
            Err(GovernedReadFailure::VendorFailed { code, message })
        }
        TransportOutcome::OutcomeUnknown => Err(GovernedReadFailure::OutcomeUnknown),
        TransportOutcome::NotSent { code, message } => {
            Err(GovernedReadFailure::NotSent { code, message })
        }
    }
}

/// The one governed read sequence: claim poll authority, authorize, dispatch.
fn governed_read<C, T>(
    engine: &GovernanceEngine<C, T>,
    principal: &str,
    connection_id: &str,
    action: &str,
    args: Value,
    subscription_id: &str,
    schema_hash: &str,
) -> Result<Option<Value>, GovernedReadFailure>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    let request = poll_read_request(
        engine,
        principal,
        connection_id,
        action,
        args,
        subscription_id,
        schema_hash,
    )?;
    authorize_and_dispatch_read(engine, request)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProbeActionFailure {
    /// The governed read itself failed; classified like any other poll read.
    Read(GovernedReadFailure),
    /// The host refused or abandoned the call, or the vendor's success carried
    /// nothing to hand the script.
    Inconclusive { code: String, message: String },
}

impl ProbeActionFailure {
    fn message(&self) -> String {
        match self {
            Self::Read(failure) => failure.code(),
            Self::Inconclusive { message, .. } => message.clone(),
        }
    }
}

/// Dispatch one probe `invoke` through the existing poll authorization path.
///
/// THE SANDBOX TIMEOUT DOES NOT BOUND THIS CALL. Epoch interruption preempts
/// guest execution only; while the vendor request runs, nothing in the sandbox
/// fires. Each callback therefore carries its own deadline so one hanging
/// vendor request cannot stall the whole poll pass while the 5s budget reports
/// nothing wrong.
struct ProbeActionDispatch<C, T>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    engine: GovernanceEngine<C, T>,
    principal: String,
    connection_id: String,
    subscription_id: String,
    fixed_args: Value,
    action_failure: Arc<Mutex<Option<ProbeActionFailure>>>,
    deadline: Option<std::time::Instant>,
}

impl<C, T> ActionInvoker for ProbeActionDispatch<C, T>
where
    C: CredentialSource + ?Sized + 'static,
    T: Transport + ?Sized + 'static,
{
    fn invoke(&self, action: &str, argument: Value) -> Result<Value, String> {
        let mut args = match argument {
            Value::Object(map) => map,
            _ => {
                let failure = ProbeActionFailure::Inconclusive {
                    code: "probe_action_failed".to_string(),
                    message: "probe action argument must be an object".to_string(),
                };
                self.action_failure
                    .lock()
                    .expect("probe action failure lock")
                    .get_or_insert_with(|| failure.clone());
                return Err(failure.message());
            }
        };
        // Registered fixed arguments win on collision. The script may not
        // override a value the operator pinned at registration -- otherwise
        // registration-time schema validation is theatre.
        if let Some(Value::Object(fixed)) = self.fixed_args.get(action) {
            for (key, value) in fixed {
                args.insert(key.clone(), value.clone());
            }
        }
        let args = Value::Object(args);
        // A call still running after an earlier deadline would overlap this one
        // against the same vendor and quota; it is refused until that call ends.
        let Some(in_flight) = ProbeCallInFlight::claim(&self.subscription_id) else {
            let failure = ProbeActionFailure::Inconclusive {
                code: PROBE_ACTION_IN_FLIGHT.to_string(),
                message: "an earlier action call of this probe is still running".to_string(),
            };
            let message = failure.message();
            self.action_failure
                .lock()
                .expect("probe action failure lock")
                .get_or_insert(failure);
            return Err(message);
        };
        let engine = self.engine.clone();
        let principal = self.principal.clone();
        let connection_id = self.connection_id.clone();
        let subscription_id = self.subscription_id.clone();
        let action = action.to_string();
        let deadline = self.deadline;
        let abandoned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_abandoned = Arc::clone(&abandoned);
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let result = budget::with_deadline(deadline, || {
                dispatch_probe_action(
                    &engine,
                    &principal,
                    &connection_id,
                    &subscription_id,
                    &action,
                    args,
                    &worker_abandoned,
                )
            });
            // Release the claim before replying, so a caller that waited sees
            // the subscription free as soon as it has the answer.
            drop(in_flight);
            let _ = sender.send(result);
        });
        let result = match receiver.recv_timeout(ACTION_CALLBACK_DEADLINE) {
            Ok(result) => result,
            Err(_) => {
                // The worker cannot be interrupted once the vendor request is
                // on the wire. If it has not authorized yet it stops before
                // spending anything; otherwise it runs out its transport
                // timeout while the claim keeps the next poll from overlapping.
                abandoned.store(true, std::sync::atomic::Ordering::SeqCst);
                Err(ProbeActionFailure::Inconclusive {
                    code: "probe_action_failed".to_string(),
                    message: "action callback exceeded its deadline".to_string(),
                })
            }
        };
        result.map_err(|failure| {
            let message = failure.message();
            self.action_failure
                .lock()
                .expect("probe action failure lock")
                .get_or_insert(failure);
            message
        })
    }
}

/// Bounds a vendor callback independently of the sandbox's guest execution
/// budget: synchronous vendor I/O cannot be interrupted by the sandbox clock.
/// Tests use a short deadline to exercise abandoned-call recovery.
const ACTION_CALLBACK_DEADLINE: Duration = if cfg!(test) {
    Duration::from_millis(300)
} else {
    Duration::from_secs(5)
};

/// Inconclusive code for a probe whose earlier action call is still running.
const PROBE_ACTION_IN_FLIGHT: &str = "probe_action_in_flight";

/// Subscriptions with a probe action call still running on a worker thread.
static PROBE_CALLS_IN_FLIGHT: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// Proof that this subscription's probe has no other action call running.
///
/// A call that outlives its deadline keeps running detached, because a vendor
/// request already on the wire cannot be recalled. Holding this claim for the
/// worker's whole life keeps the next poll of the same probe from starting a
/// second call that would overlap it and spend quota twice. Dropping it, on
/// every path including a panic, frees the subscription.
struct ProbeCallInFlight(String);

impl ProbeCallInFlight {
    fn claim(subscription_id: &str) -> Option<Self> {
        let mut in_flight = PROBE_CALLS_IN_FLIGHT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        in_flight
            .insert(subscription_id.to_string())
            .then(|| Self(subscription_id.to_string()))
    }

    fn held(subscription_id: &str) -> bool {
        PROBE_CALLS_IN_FLIGHT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(subscription_id)
    }
}

impl Drop for ProbeCallInFlight {
    fn drop(&mut self) {
        PROBE_CALLS_IN_FLIGHT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.0);
    }
}

fn dispatch_probe_action<C, T>(
    engine: &GovernanceEngine<C, T>,
    principal: &str,
    connection_id: &str,
    subscription_id: &str,
    action: &str,
    args: Value,
    abandoned: &std::sync::atomic::AtomicBool,
) -> Result<Value, ProbeActionFailure>
where
    C: CredentialSource + ?Sized,
    T: Transport + ?Sized,
{
    let abandoned_failure = || ProbeActionFailure::Inconclusive {
        code: "probe_action_failed".to_string(),
        message: "action callback abandoned before dispatch".to_string(),
    };
    let catalog = engine
        .store()
        .catalog_action(principal, connection_id, action)
        .map_err(|error| {
            ProbeActionFailure::Read(GovernedReadFailure::StoreFailed {
                reason: error.to_string(),
            })
        })?
        .ok_or(ProbeActionFailure::Read(GovernedReadFailure::Refused(
            PollAuthorizationRefusal::ActionNotFound,
        )))?;
    let request = poll_read_request(
        engine,
        principal,
        connection_id,
        action,
        args,
        subscription_id,
        &catalog.schema_hash,
    )
    .map_err(ProbeActionFailure::Read)?;
    // The caller stopped waiting while authority was being claimed: nothing
    // has been reserved or sent yet, so stop here rather than spend a vendor
    // read whose answer nobody will read.
    if abandoned.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(abandoned_failure());
    }
    match authorize_and_dispatch_read(engine, request) {
        Ok(Some(response)) => Ok(response),
        Ok(None) => Err(ProbeActionFailure::Inconclusive {
            code: "probe_action_failed".to_string(),
            message: "vendor completed with no body".to_string(),
        }),
        Err(failure) => Err(ProbeActionFailure::Read(failure)),
    }
}

/// Minimal RFC 3339 / ISO 8601 timestamp conversion for the ordered-timestamp
/// cursor. The poller needs exactly two directions — parse a vendor timestamp
/// to epoch milliseconds, and format a resume point back to a string the vendor
/// accepts — so this is a focused parser rather than a datetime-library
/// dependency in a crate that deliberately stays minimal. It handles the forms
/// our catalog vendors emit: `YYYY-MM-DDTHH:MM:SS` with an optional fractional
/// part and a `Z` or `±HH:MM` / `±HHMM` / `±HH` offset (a space is accepted in
/// place of the `T` separator).
///
/// Also used by the web_search result mapping, which normalizes vendor
/// publication dates and stamps receipt times in the same RFC 3339 form.
pub(crate) mod iso8601 {
    const MILLIS_PER_DAY: i64 = 86_400_000;

    /// Parse a timestamp into milliseconds since the Unix epoch in UTC. Returns
    /// `None` for any malformed input rather than panicking; the caller treats
    /// that as a response that does not match its declared shape.
    pub fn parse_to_millis(input: &str) -> Option<i64> {
        let bytes = input.as_bytes();
        // Date: YYYY-MM-DD.
        let year = read_digits(bytes, 0, 4)? as i64;
        if bytes.get(4) != Some(&b'-') {
            return None;
        }
        let month = read_digits(bytes, 5, 2)?;
        if bytes.get(7) != Some(&b'-') {
            return None;
        }
        let day = read_digits(bytes, 8, 2)?;
        let days_in_month = match month {
            2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            _ => return None,
        };
        if !(1..=days_in_month).contains(&day) {
            return None;
        }
        // Separator between date and time.
        match bytes.get(10) {
            Some(b'T') | Some(b't') | Some(b' ') => {}
            _ => return None,
        }
        // Time: HH:MM:SS.
        let hour = read_digits(bytes, 11, 2)? as i64;
        if bytes.get(13) != Some(&b':') {
            return None;
        }
        let minute = read_digits(bytes, 14, 2)? as i64;
        if bytes.get(16) != Some(&b':') {
            return None;
        }
        let second = read_digits(bytes, 17, 2)? as i64;
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }

        let mut index = 19;
        // Optional fractional seconds, truncated to milliseconds.
        let mut fraction_ms: i64 = 0;
        if bytes.get(index) == Some(&b'.') {
            index += 1;
            let start = index;
            while bytes.get(index).is_some_and(|byte| byte.is_ascii_digit()) {
                index += 1;
            }
            let digits = input.get(start..index)?;
            if digits.is_empty() {
                return None;
            }
            fraction_ms = fraction_to_millis(digits);
        }

        // Zone: required, and it must consume the entire remaining tail so
        // trailing garbage is rejected.
        let offset_seconds = parse_zone(input.get(index..)?)?;

        let days = days_from_civil(year, month, day);
        let local_ms = days * MILLIS_PER_DAY
            + hour * 3_600_000
            + minute * 60_000
            + second * 1000
            + fraction_ms;
        // The offset is what local time is AHEAD of UTC, so subtract it.
        Some(local_ms - offset_seconds * 1000)
    }

    /// Format epoch milliseconds as an RFC 3339 UTC timestamp with millisecond
    /// precision (`YYYY-MM-DDTHH:MM:SS.mmmZ`). Milliseconds are preserved so a
    /// resume point computed as `watermark - window` does not lose sub-second
    /// precision on its way back to the vendor.
    pub fn format_millis(millis: i64) -> String {
        // RFC 3339 can only express years 0000 to 9999. A valid watermark near
        // the start of year 0000 can still fall below that range once a
        // positive zone offset is applied while parsing it, or once the
        // overlap window is subtracted to get the resume point. Clamp only
        // the text formatted here, which is what goes to the vendor as a
        // filter argument; the caller's value, such as the stored watermark,
        // is not changed.
        let millis = millis.clamp(-62_167_219_200_000, 253_402_300_799_999);
        let days = millis.div_euclid(MILLIS_PER_DAY);
        let rem = millis.rem_euclid(MILLIS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        let hour = rem / 3_600_000;
        let minute = (rem % 3_600_000) / 60_000;
        let second = (rem % 60_000) / 1000;
        let fraction = rem % 1000;
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{fraction:03}Z")
    }

    /// Read exactly `len` ASCII digits starting at `start` as a number.
    fn read_digits(bytes: &[u8], start: usize, len: usize) -> Option<u32> {
        let mut value: u32 = 0;
        for offset in 0..len {
            let byte = *bytes.get(start + offset)?;
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value * 10 + u32::from(byte - b'0');
        }
        Some(value)
    }

    /// The first three fractional digits as milliseconds (`.5` -> 500,
    /// `.12` -> 120, `.1234` -> 123).
    fn fraction_to_millis(digits: &str) -> i64 {
        let mut millis: i64 = 0;
        let mut place: i64 = 100;
        for byte in digits.bytes().take(3) {
            millis += i64::from(byte - b'0') * place;
            place /= 10;
        }
        millis
    }

    /// Parse a whole zone string (`Z`, `z`, `±HH:MM`, `±HHMM`, or `±HH`) into
    /// the offset in seconds local time is ahead of UTC. Validating the entire
    /// tail (not a prefix) is what rejects trailing garbage.
    fn parse_zone(zone: &str) -> Option<i64> {
        let bytes = zone.as_bytes();
        match bytes {
            [b'Z'] | [b'z'] => Some(0),
            [sign, rest @ ..] if *sign == b'+' || *sign == b'-' => {
                let sign: i64 = if *sign == b'+' { 1 } else { -1 };
                let offset = match rest {
                    [h1, h2, b':', m1, m2] => hours_minutes(*h1, *h2, *m1, *m2)?,
                    [h1, h2, m1, m2] => hours_minutes(*h1, *h2, *m1, *m2)?,
                    [h1, h2] => {
                        let hh = two_digits(*h1, *h2)?;
                        if hh > 23 {
                            return None;
                        }
                        hh * 3600
                    }
                    _ => return None,
                };
                Some(sign * offset)
            }
            _ => None,
        }
    }

    /// An `HH:MM` or `HHMM` pair as a total number of seconds.
    fn hours_minutes(h1: u8, h2: u8, m1: u8, m2: u8) -> Option<i64> {
        let hh = two_digits(h1, h2)?;
        let mm = two_digits(m1, m2)?;
        if hh > 23 || mm > 59 {
            return None;
        }
        Some(hh * 3600 + mm * 60)
    }

    /// Two ASCII digits as a number, without any range check.
    fn two_digits(tens: u8, ones: u8) -> Option<i64> {
        if !tens.is_ascii_digit() || !ones.is_ascii_digit() {
            return None;
        }
        Some(i64::from(tens - b'0') * 10 + i64::from(ones - b'0'))
    }

    /// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
    /// `days_from_civil`).
    fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
        let year = if month <= 2 { year - 1 } else { year };
        let era = if year >= 0 { year } else { year - 399 } / 400;
        let yoe = year - era * 400;
        let month_index = (if month > 2 { month - 3 } else { month + 9 }) as i64;
        let doy = (153 * month_index + 2) / 5 + i64::from(day) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    /// The inverse of [`days_from_civil`]: a (year, month, day) for a day count.
    fn civil_from_days(z: i64) -> (i64, u32, u32) {
        let z = z + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let year = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        (
            if month <= 2 { year + 1 } else { year },
            month as u32,
            day as u32,
        )
    }
}

#[cfg(test)]
mod tests {
    mod liveness_tests;
    use super::*;

    #[test]
    fn outbound_year_zero_overlap_is_clamped_without_changing_cursor() {
        let strategy = ordered_strategy();
        let state = json!({"watermark_ms": -62_167_219_200_000_i64, "window_ms":60_000});
        let args = strategy.build_args(&state).unwrap();
        assert_eq!(
            args["since"], "0000-01-01T00:00:00.000Z",
            "outbound overlap must remain RFC3339"
        );
        assert_eq!(state["watermark_ms"], -62_167_219_200_000_i64);
    }

    #[test]
    fn transient_credential_code_never_contains_error_details() {
        use crate::credentials::TransientCredentialError;
        let failure = GovernedReadFailure::Denied(Denial::Credential(CredentialDenial::Transient(
            TransientCredentialError::VaultLocked,
        )));
        assert_eq!(
            failure.code(),
            "credential_transient",
            "credential code must be stable and detail-free"
        );
    }

    #[test]
    fn newest_conversation_comment_uses_existing_actor_window_only() {
        let response = json!([
            {"created_at":"2026-10-10T00:00:00Z","updated_at":"2026-10-10T00:00:00Z","html_url":"old","user":{"login":"old"}},
            {"created_at":"2026-10-10T00:00:02Z","updated_at":"2026-10-10T00:00:04Z","html_url":"newest","user":{"login":"new"}},
            {"created_at":"2026-10-10T00:00:03Z","updated_at":"2026-10-10T00:00:03Z","html_url":"second","user":{"login":"second"}}
        ]);
        let previous = iso8601::parse_to_millis("2026-10-10T00:00:01Z");
        assert_eq!(
            newest_window_comment(&response, previous).unwrap()["html_url"],
            "newest"
        );
        assert!(
            newest_window_comment(&response, iso8601::parse_to_millis("2026-10-10T00:00:04Z"))
                .is_none()
        );
        assert!(newest_window_comment(&json!({"unexpected":[]}), previous).is_none());
    }

    #[test]
    fn only_a_github_noreply_email_names_a_commit_login() {
        assert_eq!(
            noreply_login("1234+octocat@users.noreply.github.com"),
            Some("octocat")
        );
        assert_eq!(
            noreply_login("octocat@Users.NoReply.GitHub.com"),
            Some("octocat")
        );
        assert_eq!(
            noreply_login("42716385+octo-release[bot]@users.noreply.github.com"),
            Some("octo-release[bot]")
        );
        for email in [
            "octocat@example.com",
            "octocat@users.noreply.github.com.evil.example",
            "abc+octocat@users.noreply.github.com",
            "+octocat@users.noreply.github.com",
            "1234+@users.noreply.github.com",
            "1234+octo cat@users.noreply.github.com",
            "1234+-octocat@users.noreply.github.com",
            "no-at-sign",
        ] {
            assert_eq!(noreply_login(email), None, "{email}");
        }
    }

    #[test]
    fn two_method_event_at_the_cap_boundary_refuses_the_33rd_call() {
        let budget = CallBudget::new(ACTOR_ENRICHMENT_MAX_CALLS_PER_CYCLE);
        for _ in 0..15 {
            let mut permit = budget.try_take(2).expect("complete two-method event fits");
            assert!(permit.take_one().is_some());
            assert!(permit.take_one().is_some());
        }
        let mut event = budget.try_take(2).expect("two first attempts still fit");
        assert!(event.take_one().is_some());
        assert!(
            budget.try_take(1).is_none(),
            "retry would be the 33rd call while the second method is still reserved"
        );
        assert!(event.take_one().is_some());
        assert!(budget.try_take(1).is_none());
    }

    #[test]
    fn call_permit_cannot_issue_more_slots_than_taken() {
        let budget = CallBudget::new(2);
        let mut permit = budget.try_take(2).expect("2 fit");
        assert!(permit.take_one().is_some());
        assert!(permit.take_one().is_some());
        assert!(
            permit.take_one().is_none(),
            "a permit cannot spend more than it took"
        );
        assert!(
            budget.try_take(1).is_none(),
            "exhausted tokens stay exhausted"
        );
    }

    #[test]
    fn unused_permit_tokens_return_when_the_permit_drops() {
        let budget = CallBudget::new(2);
        {
            let mut permit = budget.try_take(2).expect("2 fit");
            assert!(permit.take_one().is_some());
        }
        let _returned = budget.try_take(1).expect("unused token returned on drop");
        assert!(budget.try_take(1).is_none());
    }

    #[test]
    fn sync_token_builds_no_argument_before_the_first_poll() {
        let strategy = SyncTokenStrategy::new(None);
        assert_eq!(
            strategy.build_args(&json!({})).expect("empty state"),
            json!({})
        );
        assert_eq!(
            strategy
                .build_args(&json!({ "sync_token": null }))
                .expect("null token"),
            json!({})
        );
    }

    #[test]
    fn sync_token_resumes_from_a_stored_token() {
        let strategy = SyncTokenStrategy::new(None);
        assert_eq!(
            strategy
                .build_args(&json!({ "sync_token": "tok-1" }))
                .expect("stored token"),
            json!({ "sync_token": "tok-1" })
        );
    }

    #[test]
    fn sync_token_rejects_a_non_string_cursor() {
        let strategy = SyncTokenStrategy::new(None);
        // Mutation proved: replacing the InvalidState arm with a fallback to
        // {} would let a corrupt cursor poll silently from the beginning; this
        // assertion fails the moment that guard is removed.
        assert!(matches!(
            strategy.build_args(&json!({ "sync_token": 42 })),
            Err(CursorError::InvalidState(_))
        ));
    }

    #[test]
    fn sync_token_derives_events_and_advances_to_the_next_cursor() {
        let strategy = SyncTokenStrategy::new(None);
        let response = json!({
            "items": [
                { "id": "e1", "title": "first" },
                { "id": "e2", "title": "second" }
            ],
            "next_cursor": "tok-2"
        });
        let advance = strategy.derive(&json!({}), &response).expect("derive");
        assert_eq!(advance.cursor_state, json!({ "sync_token": "tok-2" }));
        assert_eq!(advance.events.len(), 2);
        assert_eq!(advance.events[0].vendor_event_id, "e1");
        assert_eq!(
            advance.events[0].payload,
            json!({ "id": "e1", "title": "first" })
        );
    }

    #[test]
    fn sync_token_keeps_the_watermark_when_the_response_has_no_next_cursor() {
        let strategy = SyncTokenStrategy::new(None);
        let advance = strategy
            .derive(&json!({ "sync_token": "tok-1" }), &json!({ "items": [] }))
            .expect("derive");
        assert_eq!(advance.cursor_state, json!({ "sync_token": "tok-1" }));
        assert!(advance.events.is_empty());
    }

    #[test]
    fn sync_token_refuses_an_item_without_a_stable_id() {
        let strategy = SyncTokenStrategy::new(None);
        // Mutation proved: synthesizing an id for an id-less item (instead of
        // refusing) would let two different id-less records collide on the same
        // dedupe key and suppress one another; this fails if that guard goes.
        let response = json!({ "items": [{ "title": "no id here" }], "next_cursor": "tok-2" });
        assert!(matches!(
            strategy.derive(&json!({}), &response),
            Err(CursorError::InvalidResponse(_))
        ));
    }

    #[test]
    fn strategy_resolution_by_cursor_kind() {
        // sync_token has a reference-envelope default for every field, so it
        // resolves even with no manifest poll shape.
        assert!(strategy_for("sync_token", None).is_some());
        // ordered_timestamp has NO honest default for its timestamp/tiebreaker
        // fields, so without a usable poll shape it is refused, not guessed.
        assert!(strategy_for("ordered_timestamp", None).is_none());
        assert!(strategy_for("ordered_timestamp", Some(&ordered_shape())).is_some());
        // A shape missing its required fields resolves to nothing either.
        let bare = PollShape {
            cursor_kind: crate::manifest::CursorKind::OrderedTimestamp,
            token_field: None,
            request_token_field: None,
            items_field: None,
            timestamp_field: None,
            tiebreaker_id_field: None,
            item_count_ceiling: None,
            item_kind: "issue".to_string(),
            pagination: None,
            request_page_size_field: None,
            request_since_field: None,
            request_constants: Some(Default::default()),
            scalar_field: None,
        };
        assert!(strategy_for("ordered_timestamp", Some(&bare)).is_none());
        // snapshot_diff and unknown kinds are not implemented in this slice.
        assert!(strategy_for("snapshot_diff", None).is_none());
        assert!(strategy_for("probe", None).is_some());
        assert!(strategy_for("ci_runs", None).is_none());
        assert!(strategy_for("anything_else", None).is_none());
    }

    // --- Ordered-timestamp cursor strategy -----------------------------------
    //
    // Each test states the mutation it proves. The arithmetic under test is the
    // whole difficulty of this cursor kind: a settled watermark that resumes
    // from `watermark - window`, an adaptive window that only grows, and a
    // response that is refused whole when it does not match its declared shape.

    /// A manifest poll shape for an ordered-timestamp action using the field
    /// names the strategy must honour: `updated_at` for the timestamp and `id`
    /// for the tiebreaker, with the reference `items` envelope and the default
    /// `since` request parameter.
    fn ordered_shape() -> PollShape {
        PollShape {
            cursor_kind: crate::manifest::CursorKind::OrderedTimestamp,
            token_field: None,
            request_token_field: None,
            items_field: None,
            timestamp_field: Some("updated_at".to_string()),
            tiebreaker_id_field: Some("id".to_string()),
            item_count_ceiling: None,
            item_kind: "issue".to_string(),
            pagination: None,
            request_page_size_field: None,
            request_since_field: None,
            request_constants: Some(Default::default()),
            scalar_field: None,
        }
    }

    fn ordered_strategy() -> OrderedTimestampStrategy {
        OrderedTimestampStrategy::new(Some(&ordered_shape())).expect("ordered strategy")
    }

    #[test]
    fn ordered_timestamp_requests_everything_before_the_first_poll() {
        let strategy = ordered_strategy();
        assert_eq!(
            strategy.build_args(&json!({})).expect("empty state"),
            json!({})
        );
        assert_eq!(
            strategy
                .build_args(&json!({ "watermark_ms": null }))
                .expect("null watermark"),
            json!({})
        );
    }

    /// The settled watermark subtracts the window: a resumed poll requests from
    /// `watermark - window`, not from the bare maximum.
    ///
    /// Mutation proved: resuming from the bare maximum makes the request
    /// timestamp equal `watermark_ms`, so the equality with `watermark - window`
    /// fails the moment that subtraction is removed.
    #[test]
    fn ordered_timestamp_resumes_from_watermark_minus_window() {
        let strategy = ordered_strategy();
        let watermark_ms = 1_700_000_000_000_i64;
        let window_ms = 60_000_i64;
        let args = strategy
            .build_args(&json!({ "watermark_ms": watermark_ms, "window_ms": window_ms }))
            .expect("resume args");
        let since = args.get("since").and_then(Value::as_str).expect("since");
        assert_eq!(
            super::iso8601::parse_to_millis(since),
            Some(watermark_ms - window_ms),
            "the request must resume from watermark - window, not the bare maximum"
        );
    }

    /// Boundary rows are re-fetched, not skipped: after a watermark is derived
    /// from rows whose newest is at time T, the next request resumes strictly
    /// BEFORE T, so a row at exactly the watermark satisfies the inclusive
    /// (`>=`) filter and comes back to be discarded by dedupe rather than being
    /// dropped.
    ///
    /// Mutation proved: resuming from the bare maximum makes the request
    /// timestamp equal T, so the strict `resume < T` assertion fails.
    #[test]
    fn ordered_timestamp_refetches_rows_at_the_boundary() {
        let strategy = ordered_strategy();
        let response = json!({
            "items": [
                { "id": "a", "updated_at": "2024-01-15T10:00:00Z" },
                { "id": "b", "updated_at": "2024-01-15T10:00:05Z" }
            ]
        });
        let advance = strategy.derive(&json!({}), &response).expect("derive");
        let watermark_ms = advance
            .cursor_state
            .get("watermark_ms")
            .and_then(Value::as_i64)
            .expect("watermark");
        assert_eq!(
            watermark_ms,
            super::iso8601::parse_to_millis("2024-01-15T10:00:05Z").unwrap(),
            "the watermark is the newest row"
        );
        // The next request resumes from watermark - window, strictly before the
        // watermark, so the row at the watermark is inside the `>=` range.
        let args = strategy
            .build_args(&advance.cursor_state)
            .expect("resume args");
        let resume_ms = super::iso8601::parse_to_millis(
            args.get("since").and_then(Value::as_str).expect("since"),
        )
        .expect("parseable since");
        assert!(
            resume_ms < watermark_ms,
            "resume {resume_ms} must be strictly before the watermark {watermark_ms} so the boundary row is re-fetched"
        );
    }

    /// The window widens on evidence: a row below the current resume point
    /// leaves a LARGER `window_ms` in the stored cursor state.
    ///
    /// Mutation proved: not widening on evidence leaves `window_ms` unchanged,
    /// so the assertion on the doubled stored value fails.
    #[test]
    fn ordered_timestamp_widens_the_window_on_evidence() {
        let strategy = ordered_strategy();
        let window_ms = 60_000_i64;
        let watermark_ms = 1_700_000_000_000_i64;
        let resume_ms = watermark_ms - window_ms;
        // A row 30s below the resume point: had it arrived one poll later it
        // would have been missed, so the window must grow.
        let late = super::iso8601::format_millis(resume_ms - 30_000);
        let newest = super::iso8601::format_millis(watermark_ms + 5_000);
        let response = json!({
            "items": [
                { "id": "late", "updated_at": late },
                { "id": "new", "updated_at": newest }
            ]
        });
        let advance = strategy
            .derive(
                &json!({ "watermark_ms": watermark_ms, "window_ms": window_ms }),
                &response,
            )
            .expect("derive");
        assert_eq!(
            advance
                .cursor_state
                .get("window_ms")
                .and_then(Value::as_i64),
            Some(window_ms * 2),
            "evidence below the resume point must double the stored window"
        );
    }

    /// The window never shrinks on an ordinary poll: when no row falls below the
    /// resume point, the stored `window_ms` is carried forward unchanged even
    /// though the rows cluster tightly around the watermark.
    ///
    /// Mutation proved: recomputing the window from the observed spread (or
    /// resetting it toward the initial value) changes the stored value, so the
    /// equality with the prior window fails.
    #[test]
    fn ordered_timestamp_never_shrinks_the_window() {
        let strategy = ordered_strategy();
        let window_ms = 240_000_i64; // already widened well past the initial value
        let watermark_ms = 1_700_000_000_000_i64;
        // Every row is at or above the resume point: an ordinary, quiet poll.
        let at = super::iso8601::format_millis(watermark_ms + 1_000);
        let response = json!({
            "items": [{ "id": "x", "updated_at": at }]
        });
        let advance = strategy
            .derive(
                &json!({ "watermark_ms": watermark_ms, "window_ms": window_ms }),
                &response,
            )
            .expect("derive");
        assert_eq!(
            advance
                .cursor_state
                .get("window_ms")
                .and_then(Value::as_i64),
            Some(window_ms),
            "an ordinary poll must leave the window unchanged"
        );
    }

    /// The window doubles only up to its ceiling.
    ///
    /// Mutation proved: dropping the `.min(MAX_WINDOW_MS)` ceiling lets the
    /// stored window exceed the cap, so this assertion fails.
    #[test]
    fn ordered_timestamp_window_is_capped() {
        let strategy = ordered_strategy();
        let window_ms = super::MAX_WINDOW_MS; // already at the ceiling
        let watermark_ms = 1_700_000_000_000_i64;
        let resume_ms = watermark_ms - window_ms;
        let late = super::iso8601::format_millis(resume_ms - 1_000);
        let response = json!({
            "items": [{ "id": "late", "updated_at": late }]
        });
        let advance = strategy
            .derive(
                &json!({ "watermark_ms": watermark_ms, "window_ms": window_ms }),
                &response,
            )
            .expect("derive");
        assert_eq!(
            advance
                .cursor_state
                .get("window_ms")
                .and_then(Value::as_i64),
            Some(super::MAX_WINDOW_MS),
            "the window must not grow past its ceiling"
        );
    }

    /// A healthy poll advances the watermark and derives its events (the
    /// survival direction: a suite that only expects errors cannot tell a real
    /// parser from one that rejects everything).
    #[test]
    fn ordered_timestamp_derives_events_and_advances_the_watermark() {
        let strategy = ordered_strategy();
        let response = json!({
            "items": [
                { "id": "a", "updated_at": "2024-01-15T10:00:00Z", "title": "first" },
                { "id": "b", "updated_at": "2024-01-15T10:00:05Z", "title": "second" }
            ]
        });
        let advance = strategy.derive(&json!({}), &response).expect("derive");
        assert_eq!(advance.events.len(), 2);
        assert_eq!(advance.events[0].vendor_event_id, "a");
        assert_eq!(advance.events[1].vendor_event_id, "b");
        assert_eq!(
            advance.events[0].payload,
            json!({ "id": "a", "updated_at": "2024-01-15T10:00:00Z", "title": "first" })
        );
        assert_eq!(
            advance
                .cursor_state
                .get("watermark_ms")
                .and_then(Value::as_i64),
            super::iso8601::parse_to_millis("2024-01-15T10:00:05Z"),
            "the watermark is the newest timestamp"
        );
        assert_eq!(
            advance
                .cursor_state
                .get("watermark_id")
                .and_then(Value::as_str),
            Some("b"),
            "the watermark id is the row that set it"
        );
        assert_eq!(
            advance
                .cursor_state
                .get("window_ms")
                .and_then(Value::as_i64),
            Some(super::INITIAL_WINDOW_MS),
            "the first poll seeds the initial window"
        );
    }

    /// A malformed item fails the whole poll rather than being skipped: a
    /// missing timestamp, an unparseable timestamp, or a missing tiebreaker id
    /// each yield `InvalidResponse`, so the caller suspends instead of silently
    /// losing the event.
    ///
    /// Mutation proved: skipping a bad item (instead of erroring) returns `Ok`
    /// with the remaining events, so every `Err` assertion here fails.
    #[test]
    fn ordered_timestamp_refuses_a_malformed_item() {
        let strategy = ordered_strategy();
        let missing_timestamp = json!({ "items": [{ "id": "a" }] });
        assert!(matches!(
            strategy.derive(&json!({}), &missing_timestamp),
            Err(CursorError::InvalidResponse(_))
        ));
        let unparseable_timestamp = json!({ "items": [{ "id": "a", "updated_at": "yesterday" }] });
        assert!(matches!(
            strategy.derive(&json!({}), &unparseable_timestamp),
            Err(CursorError::InvalidResponse(_))
        ));
        let missing_tiebreaker = json!({ "items": [{ "updated_at": "2024-01-15T10:00:00Z" }] });
        assert!(matches!(
            strategy.derive(&json!({}), &missing_tiebreaker),
            Err(CursorError::InvalidResponse(_))
        ));
        // One good row alongside one bad row is still refused whole: a partial
        // commit would advance the watermark past the skipped row.
        let mixed = json!({ "items": [
            { "id": "good", "updated_at": "2024-01-15T10:00:00Z" },
            { "id": "bad", "updated_at": "not-a-date" }
        ] });
        assert!(matches!(
            strategy.derive(&json!({}), &mixed),
            Err(CursorError::InvalidResponse(_))
        ));
    }

    /// An integer tiebreaker is accepted and canonicalized to a string.
    ///
    /// Vendors do not agree on the type of a stable row id: GitHub's `number`
    /// is an integer, while the event log stores vendor ids as strings.
    /// Requiring a JSON string would refuse every item from such a vendor on
    /// the first poll — the strategy refuses a malformed item whole rather
    /// than skipping it, so one integer id would fail the entire cycle.
    ///
    /// The ids here are 2 and 10 at the SAME timestamp, deliberately: that is
    /// the pair where numeric and lexical ordering disagree, so the assertion
    /// also fences the comparison that picks which id is stored.
    ///
    /// Mutation proved: comparing tiebreakers lexically stores 2 instead
    /// of 10.
    #[test]
    fn ordered_timestamp_accepts_an_integer_tiebreaker() {
        let mut shape = ordered_shape();
        shape.tiebreaker_id_field = Some("number".to_string());
        let strategy = OrderedTimestampStrategy::new(Some(&shape)).expect("strategy");
        let advance = strategy
            .derive(
                &json!({}),
                &json!({
                    "items": [
                        {
                            "number": 2,
                            "updated_at": "2024-01-15T10:00:00Z"
                        },
                        {
                            "number": 10,
                            "updated_at": "2024-01-15T10:00:00Z"
                        }
                    ]
                }),
            )
            .expect("integer tiebreaker is a valid stable id");
        assert_eq!(advance.events.len(), 2);
        assert_eq!(advance.cursor_state["watermark_id"], "10");
    }

    /// Field names come from the manifest, not hardcoded: a poll shape declaring
    /// unusual names is honoured in BOTH the request argument and the response
    /// parsing.
    ///
    /// Mutation proved: hardcoding any of `since`, `items`, `updated_at`, or
    /// `id` makes the corresponding assertion fail — the request key would be
    /// wrong, or the response would yield zero events or a missing timestamp.
    #[test]
    fn ordered_timestamp_honours_manifest_field_names() {
        let shape = PollShape {
            cursor_kind: crate::manifest::CursorKind::OrderedTimestamp,
            token_field: None,
            request_token_field: None,
            items_field: Some("records".to_string()),
            timestamp_field: Some("modified_at".to_string()),
            tiebreaker_id_field: Some("uid".to_string()),
            item_count_ceiling: None,
            item_kind: "issue".to_string(),
            pagination: None,
            request_page_size_field: None,
            request_since_field: Some("after".to_string()),
            request_constants: Some(Default::default()),
            scalar_field: None,
        };
        let strategy = OrderedTimestampStrategy::new(Some(&shape)).expect("strategy");
        // The request argument uses the declared request parameter name.
        let args = strategy
            .build_args(&json!({ "watermark_ms": 1_700_000_000_000_i64, "window_ms": 60_000_i64 }))
            .expect("args");
        assert!(args.get("after").is_some(), "request must use 'after'");
        assert!(
            args.get("since").is_none(),
            "request must not use the default 'since'"
        );
        // The response is read from the declared items/timestamp/tiebreaker fields.
        let response = json!({
            "records": [{ "uid": "r1", "modified_at": "2024-01-15T10:00:00Z" }]
        });
        let advance = strategy.derive(&json!({}), &response).expect("derive");
        assert_eq!(advance.events.len(), 1);
        assert_eq!(advance.events[0].vendor_event_id, "r1");
        assert_eq!(
            advance
                .cursor_state
                .get("watermark_ms")
                .and_then(Value::as_i64),
            super::iso8601::parse_to_millis("2024-01-15T10:00:00Z")
        );
    }

    // --- ISO 8601 conversion -------------------------------------------------

    fn chrono_rfc3339_millis(input: &str) -> Option<i64> {
        chrono::DateTime::parse_from_rfc3339(input)
            .ok()
            .map(|timestamp| timestamp.timestamp_millis())
    }

    fn assert_iso8601_matches_chrono(input: &str, chrono_input: &str) {
        let ours = iso8601::parse_to_millis(input);
        let oracle = chrono_rfc3339_millis(chrono_input);
        assert_eq!(
            ours, oracle,
            "ISO-8601 oracle disagreement for {input:?} (chrono input {chrono_input:?}): ours={ours:?}, chrono={oracle:?}"
        );
    }

    #[test]
    fn iso8601_exhaustively_matches_chrono_for_calendar_dates() {
        let mut case_count = 0;
        for year in 1970..=2100 {
            for month in 0..=13 {
                for day in 0..=32 {
                    let input = format!("{year:04}-{month:02}-{day:02}T00:00:00Z");
                    assert_iso8601_matches_chrono(&input, &input);
                    case_count += 1;
                }
            }
        }
        assert_eq!(case_count, 60_522);
    }

    #[test]
    fn iso8601_matches_chrono_at_gregorian_century_boundaries() {
        for input in [
            "1900-02-29T00:00:00Z",
            "1900-03-01T00:00:00Z",
            "2000-02-29T00:00:00Z",
            "2000-03-01T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2100-03-01T00:00:00Z",
        ] {
            assert_iso8601_matches_chrono(input, input);
        }
    }

    #[test]
    fn iso8601_exhaustively_matches_chrono_for_times_and_offset_spellings() {
        let offset_spellings = [
            ("Z", "Z"),
            ("z", "Z"),
            ("+05:30", "+05:30"),
            ("-05:30", "-05:30"),
            ("+0530", "+05:30"),
            ("-0530", "-05:30"),
            ("+05", "+05:00"),
            ("-05", "-05:00"),
        ];
        let mut case_count = 0;
        let mut chrono_only_leap_seconds = 0;

        for hour in 0..=24 {
            for minute in 0..=60 {
                for second in 0..=61 {
                    for (suffix, chrono_suffix) in offset_spellings {
                        let local = format!("2000-01-01T{hour:02}:{minute:02}:{second:02}");
                        let input = format!("{local}{suffix}");
                        let chrono_input = format!("{local}{chrono_suffix}");
                        let ours = iso8601::parse_to_millis(&input);
                        let oracle = chrono_rfc3339_millis(&chrono_input);
                        case_count += 1;

                        // Chrono represents an RFC 3339 `:60` as a leap second. This
                        // parser's malformed-input contract deliberately rejects seconds
                        // outside 00..=59, so preserve and name that divergence.
                        if second == 60 && ours.is_none() && oracle.is_some() {
                            chrono_only_leap_seconds += 1;
                            continue;
                        }

                        assert_eq!(
                            ours, oracle,
                            "ISO-8601 oracle disagreement for {input:?} (chrono input {chrono_input:?}): ours={ours:?}, chrono={oracle:?}"
                        );
                    }
                }
            }
        }

        assert_eq!(case_count, 756_400);
        assert_eq!(
            chrono_only_leap_seconds, 11_520,
            "chrono must accept every valid local time's leap-second spelling while our parser rejects it"
        );
    }

    #[test]
    fn iso8601_fractional_seconds_match_chrono_truncation() {
        for (fraction, expected_millis) in [
            ("1", 100),
            ("123", 123),
            ("123999", 123),
            ("123999999", 123),
        ] {
            let input = format!("2020-01-01T00:00:00.{fraction}Z");
            let oracle = chrono_rfc3339_millis(&input);
            assert_eq!(
                oracle,
                Some(1_577_836_800_000 + expected_millis),
                "chrono oracle did not truncate {fraction:?} to milliseconds"
            );
            assert_iso8601_matches_chrono(&input, &input);
        }
    }

    #[test]
    fn iso8601_parses_utc_and_offsets_to_epoch_millis() {
        use super::iso8601;
        assert_eq!(iso8601::parse_to_millis("1970-01-01T00:00:00Z"), Some(0));
        // A well-known anchor: 2020-01-01T00:00:00Z == 1577836800 s.
        assert_eq!(
            iso8601::parse_to_millis("2020-01-01T00:00:00Z"),
            Some(1_577_836_800_000)
        );
        // A +02:00 offset is two hours ahead of UTC, so it maps back to midnight.
        assert_eq!(
            iso8601::parse_to_millis("2020-01-01T02:00:00+02:00"),
            Some(1_577_836_800_000)
        );
        // A negative offset puts local time behind UTC.
        assert_eq!(
            iso8601::parse_to_millis("2019-12-31T19:00:00-05:00"),
            Some(1_577_836_800_000)
        );
        // Compact and hour-only offsets are accepted too.
        assert_eq!(
            iso8601::parse_to_millis("2020-01-01T02:00:00+0200"),
            Some(1_577_836_800_000)
        );
        assert_eq!(
            iso8601::parse_to_millis("2020-01-01T02:00:00+02"),
            Some(1_577_836_800_000)
        );
        // Fractional seconds truncate to milliseconds.
        assert_eq!(
            iso8601::parse_to_millis("1970-01-01T00:00:00.5Z"),
            Some(500)
        );
        assert_eq!(
            iso8601::parse_to_millis("1970-01-01T00:00:00.123Z"),
            Some(123)
        );
        assert_eq!(
            iso8601::parse_to_millis("1970-01-01T00:00:00.123456Z"),
            Some(123)
        );
        // A space separator is accepted in place of 'T'.
        assert_eq!(
            iso8601::parse_to_millis("2020-01-01 00:00:00Z"),
            Some(1_577_836_800_000)
        );
    }

    #[test]
    fn iso8601_calendar_boundaries() {
        for (input, expected) in [
            ("2026-02-31T00:00:00Z", None),
            ("2026-02-29T00:00:00Z", None),
            ("2026-04-31T00:00:00Z", None),
            ("2026-06-31T00:00:00Z", None),
            ("2026-09-31T00:00:00Z", None),
            ("2026-11-31T00:00:00Z", None),
            ("2026-13-01T00:00:00Z", None),
            ("2026-00-01T00:00:00Z", None),
            ("2026-01-00T00:00:00Z", None),
            ("2024-02-30T00:00:00Z", None),
            ("1900-02-29T00:00:00Z", None),
            ("2026-03-03T00:00:00Z", Some(1_772_496_000_000)),
            ("2024-02-29T00:00:00Z", Some(1_709_164_800_000)),
            ("2000-02-29T00:00:00Z", Some(951_782_400_000)),
            ("1900-02-28T00:00:00Z", Some(-2_203_977_600_000)),
            ("2026-04-30T00:00:00Z", Some(1_777_507_200_000)),
            ("2026-01-31T00:00:00Z", Some(1_769_817_600_000)),
        ] {
            assert_eq!(super::iso8601::parse_to_millis(input), expected, "{input}");
        }
    }

    #[test]
    fn iso8601_rejects_malformed_input() {
        use super::iso8601;
        for bad in [
            "",
            "not-a-date",
            "2020-01-01",                // date only
            "2020-01-01T00:00:00",       // missing zone
            "2020-01-01T00:00:00Zextra", // trailing garbage
            "2020-13-01T00:00:00Z",      // month out of range
            "2020-01-32T00:00:00Z",      // day out of range
            "2020-01-01T24:00:00Z",      // hour out of range
            "2020-01-01T00:60:00Z",      // minute out of range
            "2020-01-01T00:00:60Z",      // second out of range
            "2020-01-01T00:00:00.Z",     // empty fraction
            "2020-01-01T00:00:00+25:00", // offset hour out of range
            "2020-01-01T00:00:00+02:60", // offset minute out of range
        ] {
            assert_eq!(iso8601::parse_to_millis(bad), None, "should reject {bad:?}");
        }
    }

    #[test]
    fn iso8601_round_trips_millisecond_precision() {
        use super::iso8601;
        assert_eq!(iso8601::format_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            iso8601::format_millis(1_577_836_800_000),
            "2020-01-01T00:00:00.000Z"
        );
        for millis in [
            0_i64,
            1,
            999,
            1_577_836_800_123,
            1_700_000_000_000,
            86_399_999,
        ] {
            assert_eq!(
                iso8601::parse_to_millis(&iso8601::format_millis(millis)),
                Some(millis),
                "round trip {millis}"
            );
        }
    }

    mod drop_ledger_tests;

    // --- Poll-path retention tests -------------------------------------------
    //
    // These tests drive `Poller::poll_once` through the full governance chain
    // to prove the retention bound is enforced from the poll path, not merely
    // implemented in `prune`. They need a `sync_token` cursor strategy, which
    // is the only kind `strategy_for` supports in this slice.

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use crate::credentials::StubCredentialSource;
    use crate::governance::GovernanceEngine;
    use crate::storage::{now_ms, CatalogActionInput, Ceiling, GrantInput, PlexusStore};
    use crate::transport::{MockResponse, MockTransport};
    use cortexkit_store::StorageDescriptor;
    use cortexkit_store_types::{Isolation, StorageBackend};

    static POLL_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Build a store whose manifest declares a `sync_token` read action, with a
    /// poll grant and an active credentialed connection, plus a governance
    /// engine over it with a mock transport programmed to return `response`.
    /// The connection is enrolled through the same binding-ticket ceremony the
    /// real facade uses, so `revalidate_and_dispatch` can resolve a credential
    /// and reach the transport.
    fn poll_engine(
        response: Value,
    ) -> (
        Arc<PlexusStore>,
        GovernanceEngine<StubCredentialSource, MockTransport>,
        MockTransport,
    ) {
        poll_engine_with_shape(
            response,
            json!({
                "item_kind": "issue",
                "cursor_kind": "sync_token",
                "request_token_field": "cursor",
                "request_constants": {
                    "cursor": "manifest",
                    "scope": "manifest",
                    "constant_only": "constant"
                }
            }),
        )
    }

    fn poll_engine_with_shape(
        response: Value,
        poll_shape: Value,
    ) -> (
        Arc<PlexusStore>,
        GovernanceEngine<StubCredentialSource, MockTransport>,
        MockTransport,
    ) {
        let (store, credentials) = poll_store_with_shape(poll_shape);
        let transport = MockTransport::default();
        transport.set_response(MockResponse::Success(response));
        let engine = GovernanceEngine::new(
            store.clone(),
            Arc::new(credentials),
            Arc::new(transport.clone()),
        );
        (store, engine, transport)
    }

    /// The store and credentials behind [`poll_engine_with_shape`], for a test
    /// that needs its own transport.
    fn poll_store_with_shape(poll_shape: Value) -> (Arc<PlexusStore>, StubCredentialSource) {
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!(
                "poll-test-{}-{}",
                now_ms(),
                POLL_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
            ),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("open poll store"));
        store
            .insert_connection(
                "direct",
                "connection",
                "poll_fixture",
                "pending",
                &serde_json::json!({}),
            )
            .expect("insert connection");
        let manifest = serde_json::json!({
            "schema_version": 1,
            "key": "poll_fixture",
            "name": "Poll fixture",
            "description": "manifest used by poll-path retention tests",
            "reuse_path": "deep_wrapper",
            "reuse_rationale": "test",
            "tier": "S2",
            "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
            "auth": {"mode": "api_key"},
            "credential_bindings": [{
                "ref_role": "api_key",
                "placement": "header",
                "key": "Authorization",
                "prefix": "Bearer ",
                "required": true
            }],
            "resource_filters": {"required": [], "optional": [], "write_enabling": []},
            "actions_baseline": [{
                "name": "read_action",
                "risk": "read",
                "poll": poll_shape
            }],
            "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 60}},
            "availability": "ga"
        });
        let manifest = crate::manifest::ingest_value(manifest).expect("manifest");
        store
            .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &manifest)
            .expect("store manifest");
        store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: "connection".to_string(),
                principal: "direct".to_string(),
                name: "read_action".to_string(),
                title: Some("read_action".to_string()),
                schema: serde_json::json!({"type": "object"}),
                schema_hash: "hash-read".to_string(),
                risk: "read".to_string(),
                severity: "S2".to_string(),
                ask_first: false,
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .expect("catalog action");
        // Enroll the connection through the binding-ticket ceremony so the
        // dispatch path can resolve a credential. The handle is a test canary
        // the stub credential source is programmed to return.
        let handle = b"test:test-handle";
        let ticket = store
            .create_binding_ticket_bounded(
                "direct",
                "connection",
                "credential_reference",
                handle,
                &Ceiling::unrestricted_for_tests(),
            )
            .expect("binding ticket");
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .expect("connect")
            .expect("connection activated");
        store
            .insert_grant(&GrantInput {
                grant_id: "grant-poll".to_string(),
                principal: "direct".to_string(),
                connection_id: "connection".to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "write".to_string(),
                action_selectors: vec!["*".to_string()],
                authority_kind: crate::governance::AUTHORITY_POLL.to_string(),
                expires_at: Some(now_ms() + 60_000),
            })
            .expect("poll grant");
        let credentials = StubCredentialSource::default();
        credentials.set_success(handle, b"vendor-token".to_vec(), None, 1);
        (store, credentials)
    }

    /// When the stored-payload lookup fails, an item already stored is kept
    /// and enriched, so an unreadable history can cost a comment read but
    /// never lose an edit. Storage then drops it as a duplicate, and the
    /// test-build ledger assertion in `record_completion` checks the balance.
    ///
    /// The same second pass without the injected failure makes no comment read,
    /// which shows the item is one the skip would otherwise remove.
    ///
    /// MUTATION: skipping the item on a lookup error drops the comment read on
    /// the failing pass and fails the dispatch assertion.
    #[test]
    fn a_failing_stored_payload_lookup_keeps_and_enriches_the_item() {
        let item = json!({
            "id": "issue-17",
            "number": 17,
            "updated_at": "2026-08-20T12:00:00Z",
            "title": "unchanged"
        });
        let (store, engine, transport) = poll_engine_with_shape(
            json!({"items": [item]}),
            json!({
                "item_kind": "issue",
                "cursor_kind": "ordered_timestamp",
                "timestamp_field": "updated_at",
                "tiebreaker_id_field": "id",
                "request_constants": {}
            }),
        );
        store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: "connection".to_string(),
                principal: "direct".to_string(),
                name: "issue_read".to_string(),
                title: Some("issue_read".to_string()),
                schema: json!({"type": "object"}),
                schema_hash: "hash-issue-read".to_string(),
                risk: "read".to_string(),
                severity: "S2".to_string(),
                ask_first: false,
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .expect("actor catalog action");
        // The watched read must declare the repository arguments the
        // subscription fixes, which the actor read reuses, and the `since`
        // resume point its ordered-timestamp poll sends.
        store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: "connection".to_string(),
                principal: "direct".to_string(),
                name: "read_action".to_string(),
                title: Some("read_action".to_string()),
                schema: json!({
                    "type": "object",
                    "properties": {
                        "owner": {"type": "string"},
                        "repo": {"type": "string"},
                        "since": {"type": "string"}
                    }
                }),
                schema_hash: "hash-read-repository".to_string(),
                risk: "read".to_string(),
                severity: "S2".to_string(),
                ask_first: false,
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .expect("watched catalog action");
        let id = store
            .subscribe_with_cursor_state(
                "direct",
                "connection",
                "read_action",
                30,
                &json!({}),
                &json!({"owner": "cortexkit", "repo": "plexus"}),
            )
            .expect("subscribe")
            .expect("subscription")
            .subscription_id;
        store
            .set_subscription_actor_source(
                "direct",
                &id,
                Some(&ActorSource {
                    connection_id: "connection".to_string(),
                    action: "issue_read".to_string(),
                    methods: vec!["get_comments".to_string()],
                }),
            )
            .expect("actor source");
        transport.set_response_for_method(
            "issue_read",
            "get_comments",
            MockResponse::Success(json!([])),
        );
        let comment_reads = || {
            transport
                .requests()
                .iter()
                .filter(|request| request.action == "issue_read")
                .count()
        };
        let poller = Poller::new(engine);
        assert_eq!(
            poller.poll_once("direct", &id),
            PollCycle::Completed {
                inserted: 1,
                duplicates: 0
            }
        );
        assert_eq!(comment_reads(), 1, "a new item is enriched");

        assert_eq!(
            poller.poll_once("direct", &id),
            PollCycle::Completed {
                inserted: 0,
                duplicates: 1
            }
        );
        assert_eq!(comment_reads(), 1, "a stored item is skipped");

        FAIL_STORED_PAYLOAD_LOOKUP.with(|fail| fail.set(true));
        let cycle = poller.poll_once("direct", &id);
        FAIL_STORED_PAYLOAD_LOOKUP.with(|fail| fail.set(false));
        assert_eq!(
            cycle,
            PollCycle::Completed {
                inserted: 0,
                duplicates: 1
            }
        );
        assert_eq!(
            comment_reads(),
            2,
            "an item whose stored state is unknown is enriched"
        );
        assert_eq!(
            store.list_events("direct", None, Some(&id)).unwrap().len(),
            1
        );
    }

    #[test]
    fn scalar_transition_repeats_are_distinct_stored_events() {
        let a = json!({"tag_name": "v1", "id": 1});
        let b = json!({"tag_name": "v2", "id": 2});
        let (store, engine, transport) = poll_engine_with_shape(
            a.clone(),
            json!({
                "item_kind": "release",
                "cursor_kind": "scalar_diff",
                "scalar_field": "tag_name"
            }),
        );
        let subscription = store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("subscribe")
            .expect("subscription");
        let id = &subscription.subscription_id;
        let poller = Poller::new(engine);
        let mut cycles = Vec::new();
        for response in [a.clone(), b.clone(), a.clone(), b.clone()] {
            transport.set_response(MockResponse::Success(response));
            cycles.push(poller.poll_once("direct", id));
        }
        let events = store
            .list_events("direct", None, Some(id))
            .expect("stored events");
        assert_eq!(
            events.len(),
            3,
            "four observations must persist three transitions"
        );
        assert!(events.iter().all(|event| event.kind == "event"));
        assert_eq!(events.iter().filter(|event| event.payload == b).count(), 2);
        assert_eq!(events.iter().filter(|event| event.payload == a).count(), 1);
        assert!(matches!(
            cycles[0],
            PollCycle::Completed {
                inserted: 0,
                duplicates: 0
            }
        ));
        for cycle in &cycles[1..] {
            assert!(
                matches!(
                    cycle,
                    PollCycle::Completed {
                        inserted: 1,
                        duplicates: 0
                    }
                ),
                "every transition, including the fourth observation, must insert: {cycle:?}"
            );
        }
        assert_eq!(
            store
                .subscription("direct", id)
                .unwrap()
                .unwrap()
                .cursor_state,
            json!({"scalar": "v2", "scalar_ordinal": 3})
        );
    }

    #[test]
    fn scalar_transition_ordinal_does_not_grow_on_unchanged_polls() {
        let (store, engine, transport) = poll_engine_with_shape(
            json!({"tag_name": "v2"}),
            json!({
                "item_kind": "release",
                "cursor_kind": "scalar_diff",
                "scalar_field": "tag_name"
            }),
        );
        let subscription = store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("subscribe")
            .expect("subscription");
        let id = &subscription.subscription_id;
        // Simulate a successful poll persisted by a version without ordinal support.
        assert!(store
            .record_poll_success("direct", id, &json!({"scalar": "v1"}), now_ms())
            .unwrap());
        let poller = Poller::new(engine);
        assert!(matches!(
            poller.poll_once("direct", id),
            PollCycle::Completed {
                inserted: 1,
                duplicates: 0
            }
        ));
        let changed_state = store
            .subscription("direct", id)
            .unwrap()
            .unwrap()
            .cursor_state;
        assert_eq!(changed_state, json!({"scalar": "v2", "scalar_ordinal": 1}));
        transport.set_response(MockResponse::Success(json!({"tag_name": "v2"})));
        for _ in 0..3 {
            assert!(matches!(
                poller.poll_once("direct", id),
                PollCycle::Completed {
                    inserted: 0,
                    duplicates: 0
                }
            ));
            assert_eq!(
                store
                    .subscription("direct", id)
                    .unwrap()
                    .unwrap()
                    .cursor_state,
                changed_state,
                "unchanged polls must not grow the transition ordinal"
            );
        }
        assert_eq!(
            store.list_events("direct", None, Some(id)).unwrap().len(),
            1
        );
    }

    /// A TRANSIENT credential failure is counted, not suspended.
    ///
    /// Reference credentials resolve at dispatch, so a locked vault produces an
    /// inconclusive, unsent poll rather than an authorization suspension or a
    /// vendor failure. The subscription remains active for the next tick.
    #[test]
    fn a_transient_reference_failure_is_inconclusive_without_suspension() {
        let (store, engine, _transport) = poll_engine(json!({"items": []}));
        let subscription = store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("subscribe")
            .expect("subscription");

        // The vault is momentarily unavailable. Authority is untouched.
        engine.credential_source().set_error(
            b"test:test-handle",
            crate::credentials::CredentialError::Transient(
                crate::credentials::TransientCredentialError::VaultLocked,
            ),
        );

        let poller = Poller::new(engine);
        let cycle = poller.poll_once("direct", &subscription.subscription_id);
        assert!(
            matches!(cycle, PollCycle::Inconclusive { .. }),
            "a transient credential error must not be a suspension: {cycle:?}"
        );

        let stored = store
            .subscription("direct", &subscription.subscription_id)
            .expect("read subscription")
            .expect("subscription exists");
        assert_eq!(
            stored.status, "active",
            "a momentary vault failure suspended the subscription, which never auto-resumes"
        );
        assert_eq!(
            stored.consecutive_vendor_failures, 0,
            "an unsent vault failure is not a vendor failure"
        );
        assert!(
            store
                .list_events("direct", None, Some(&subscription.subscription_id))
                .expect("list events")
                .is_empty(),
            "a transient failure wrote a coverage gap marker for a subscription that is still active"
        );
    }

    /// Poll-path pruning keeps young bodies even beyond the ceiling, but trims
    /// older rows once the seven-day floor no longer protects them.
    #[test]
    fn poll_path_enforces_the_retention_ceiling() {
        for aged in [false, true] {
            let (store, engine, _transport) = poll_engine(json!({"items": []}));
            let subscription = store
                .subscribe("direct", "connection", "read_action", 30)
                .expect("subscribe")
                .expect("subscription");
            for i in 0..(super::UNACKED_MAX_ROWS + 1) {
                store
                    .insert_event(
                        "direct",
                        "connection",
                        &subscription.subscription_id,
                        &format!("vendor-{i}"),
                        &json!({"id": format!("vendor-{i}")}),
                        now_ms(),
                    )
                    .expect("pre-load event");
            }
            if aged {
                store
                    .age_subscription_events_for_test(
                        &subscription.subscription_id,
                        now_ms() - 8 * crate::storage::AUDIT_MILLIS_PER_DAY,
                    )
                    .expect("age beyond body floor");
            }
            let poller = Poller::new(engine);
            let cycle = poller.poll_once("direct", &subscription.subscription_id);
            assert!(
                matches!(cycle, PollCycle::Completed { .. }),
                "poll should complete, got {cycle:?}"
            );
            let events = store
                .list_events("direct", None, Some(&subscription.subscription_id))
                .expect("events after poll");
            let ordinary = events.iter().filter(|event| event.kind == "event").count();
            if aged {
                assert_eq!(
                    ordinary,
                    super::UNACKED_MAX_ROWS,
                    "older rows are trimmed to the ceiling by the real poll path"
                );
                assert_eq!(events.iter().filter(|event| event.kind == "gap").count(), 1);
            } else {
                assert_eq!(
                    ordinary,
                    super::UNACKED_MAX_ROWS + 1,
                    "seven-day body floor overrides the ceiling for young rows"
                );
                assert_eq!(events.iter().filter(|event| event.kind == "gap").count(), 0);
            }
        }
    }

    /// A recent unacked event survives the poll-path prune and is still
    /// delivered by `list`. This is the survival direction: a suite where every
    /// vector expects removal cannot distinguish a real implementation from one
    /// that deletes everything.
    #[test]
    fn poll_path_keeps_a_recent_unacked_event() {
        let (store, engine, _transport) = poll_engine(json!({"items": []}));
        let subscription = store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("subscribe")
            .expect("subscription");
        // One fresh event well within both the age and row bounds.
        let payload = serde_json::json!({"id": "fresh", "value": 42});
        store
            .insert_event(
                "direct",
                "connection",
                &subscription.subscription_id,
                "fresh",
                &payload,
                now_ms(),
            )
            .expect("fresh event");
        let poller = Poller::new(engine);
        let cycle = poller.poll_once("direct", &subscription.subscription_id);
        assert!(
            matches!(cycle, PollCycle::Completed { .. }),
            "poll should complete, got {cycle:?}"
        );
        let events = store
            .list_events("direct", None, Some(&subscription.subscription_id))
            .expect("events after poll");
        let fresh = events
            .iter()
            .find(|event| event.vendor_event_id.as_deref() == Some("fresh"))
            .expect("the fresh unacked event survived the poll-path prune");
        assert_eq!(
            fresh.payload, payload,
            "the payload is intact and delivered by list"
        );
    }

    // --- Ordered-timestamp poll-path tests -----------------------------------
    //
    // These drive `Poller::poll_once` through the full governance chain with an
    // `ordered_timestamp` manifest, proving the cursor arithmetic holds end to
    // end: what the resumed request actually asks for, and that a malformed
    // response suspends without committing anything.

    /// Build a store whose manifest declares an `ordered_timestamp` read action
    /// (timestamp field `updated_at`, tiebreaker `id`), with a poll grant and an
    /// active credentialed connection, plus a governance engine over it with a
    /// mock transport programmed to return `response`. The transport handle is
    /// returned (it shares state with the engine's copy) so a test can inspect
    /// the request arguments actually dispatched.
    fn ordered_poll_engine(
        response: Value,
    ) -> (
        Arc<PlexusStore>,
        GovernanceEngine<StubCredentialSource, MockTransport>,
        MockTransport,
    ) {
        let descriptor = StorageDescriptor {
            module_id: "plexus".to_string(),
            storage_namespace: format!(
                "ordered-poll-test-{}-{}",
                now_ms(),
                POLL_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
            ),
            isolation: Isolation::Module,
            backend: StorageBackend::Sqlite {
                path: ":memory:".to_string(),
            },
        };
        let store = Arc::new(PlexusStore::open(&descriptor).expect("open ordered poll store"));
        store
            .insert_connection(
                "direct",
                "connection",
                "ordered_fixture",
                "pending",
                &serde_json::json!({}),
            )
            .expect("insert connection");
        let manifest = serde_json::json!({
            "schema_version": 1,
            "key": "ordered_fixture",
            "name": "Ordered fixture",
            "description": "manifest used by ordered-timestamp poll-path tests",
            "reuse_path": "deep_wrapper",
            "reuse_rationale": "test",
            "tier": "S2",
            "transport": {"kind": "mcp_remote", "url": "https://example.invalid/mcp"},
            "auth": {"mode": "api_key"},
            "credential_bindings": [{
                "ref_role": "api_key",
                "placement": "header",
                "key": "Authorization",
                "prefix": "Bearer ",
                "required": true
            }],
            "resource_filters": {"required": [], "optional": [], "write_enabling": []},
            "actions_baseline": [{
                "name": "read_action",
                "risk": "read",
                "poll": {
                    "item_kind": "issue",
                    "cursor_kind": "ordered_timestamp",
                    "timestamp_field": "updated_at",
                    "tiebreaker_id_field": "id",
                    "request_constants": {
                        "scope": "manifest",
                        "constant_only": "constant"
                    }
                }
            }],
            "defaults": {"ask_first_risk": ["write"], "rate_limit": {"calls_per_min": 60}},
            "availability": "ga"
        });
        let manifest = crate::manifest::ingest_value(manifest).expect("manifest");
        store
            .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &manifest)
            .expect("store manifest");
        store
            .upsert_catalog_action(&CatalogActionInput {
                connection_id: "connection".to_string(),
                principal: "direct".to_string(),
                name: "read_action".to_string(),
                title: Some("read_action".to_string()),
                // Declares every argument the poll shape above sends (its
                // request constants and the `since` resume point), because
                // governance refuses an argument the schema does not declare.
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "scope": {"type": "string"},
                        "fixed_only": {"type": "string"},
                        "constant_only": {"type": "string"},
                        "since": {"type": "string"}
                    }
                }),
                schema_hash: "hash-read".to_string(),
                risk: "read".to_string(),
                severity: "S2".to_string(),
                ask_first: false,
                status: "active".to_string(),
                quarantine_reason: None,
                reconciliation: None,
            })
            .expect("catalog action");
        let handle = b"test:test-handle";
        let ticket = store
            .create_binding_ticket_bounded(
                "direct",
                "connection",
                "credential_reference",
                handle,
                &Ceiling::unrestricted_for_tests(),
            )
            .expect("binding ticket");
        store
            .connect_with_ticket("direct", &ticket.ticket_id)
            .expect("connect")
            .expect("connection activated");
        store
            .insert_grant(&GrantInput {
                grant_id: "grant-poll".to_string(),
                principal: "direct".to_string(),
                connection_id: "connection".to_string(),
                grantee_principal: "direct".to_string(),
                risk_ceiling: "write".to_string(),
                action_selectors: vec!["*".to_string()],
                authority_kind: crate::governance::AUTHORITY_POLL.to_string(),
                expires_at: Some(now_ms() + 60_000),
            })
            .expect("poll grant");
        let credentials = StubCredentialSource::default();
        credentials.set_success(handle, b"vendor-token".to_vec(), None, 1);
        let transport = MockTransport::default();
        transport.set_response(MockResponse::Success(response));
        let engine = GovernanceEngine::new(
            store.clone(),
            Arc::new(credentials),
            Arc::new(transport.clone()),
        );
        (store, engine, transport)
    }

    /// The request layers are ordered fixed_args < request_constants < cursor.
    /// This uses a legacy-row mutation to exercise all three values on the same
    /// request key; current subscriptions refuse that fixed/cursor collision.
    ///
    /// Mutation proved: swapping either merge extension changes the received
    /// `cursor` or `scope` assertion, so the test observes the transport's
    /// request rather than trusting a local intermediate value.
    #[test]
    fn poll_path_merges_fixed_args_constants_and_cursor_in_reviewed_order() {
        let (store, engine, transport) = poll_engine(json!({
            "items": [{"id": "first"}],
            "next_cursor": "tok-1"
        }));
        let subscription = store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("subscribe")
            .expect("subscription");
        let before = store
            .subscription("direct", &subscription.subscription_id)
            .expect("read subscription")
            .expect("subscription exists");
        assert_eq!(
            before.fixed_args,
            json!({}),
            "legacy-row mutation starts empty"
        );

        let poller = Poller::new(engine);
        assert!(matches!(
            poller.poll_once("direct", &subscription.subscription_id),
            PollCycle::Completed { .. }
        ));
        store
            .replace_fixed_args_for_test(
                "direct",
                &subscription.subscription_id,
                &json!({
                    "cursor": "fixed",
                    "scope": "fixed",
                    "fixed_only": "fixed"
                }),
            )
            .expect("mutate legacy fixed args");
        let mutated = store
            .subscription("direct", &subscription.subscription_id)
            .expect("read mutated subscription")
            .expect("subscription exists after mutation");
        assert_eq!(
            mutated.fixed_args,
            json!({
                "cursor": "fixed",
                "scope": "fixed",
                "fixed_only": "fixed"
            }),
            "precondition: the legacy row must carry all fixed-layer values"
        );

        transport.set_response(MockResponse::Success(json!({"items": []})));
        assert!(matches!(
            poller.poll_once("direct", &subscription.subscription_id),
            PollCycle::Completed { .. }
        ));
        let request = transport
            .requests()
            .last()
            .cloned()
            .expect("second poll request received by transport");
        assert_eq!(request.args["cursor"], json!("tok-1"));
        assert_eq!(request.args["scope"], json!("manifest"));
        assert_eq!(request.args["fixed_only"], json!("fixed"));
        assert_eq!(request.args["constant_only"], json!("constant"));
    }

    /// A healthy ordered-timestamp poll advances the stored watermark and
    /// commits its events (the survival direction at the poll-path level).
    #[test]
    fn ordered_poll_path_advances_the_watermark_and_commits_events() {
        let response = json!({
            "items": [
                { "id": "a", "updated_at": "2024-01-15T10:00:00Z" },
                { "id": "b", "updated_at": "2024-01-15T10:00:05Z" }
            ]
        });
        let (store, engine, _transport) = ordered_poll_engine(response);
        let subscription = store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("subscribe")
            .expect("subscription");
        let poller = Poller::new(engine);
        let cycle = poller.poll_once("direct", &subscription.subscription_id);
        assert!(
            matches!(cycle, PollCycle::Completed { inserted: 2, .. }),
            "expected two inserted events, got {cycle:?}"
        );
        let stored = store
            .subscription("direct", &subscription.subscription_id)
            .expect("read subscription")
            .expect("subscription exists");
        assert_eq!(
            stored
                .cursor_state
                .get("watermark_ms")
                .and_then(Value::as_i64),
            super::iso8601::parse_to_millis("2024-01-15T10:00:05Z"),
            "the stored watermark is the newest timestamp"
        );
        assert_eq!(
            stored
                .cursor_state
                .get("watermark_id")
                .and_then(Value::as_str),
            Some("b")
        );
        let events = store
            .list_events("direct", None, Some(&subscription.subscription_id))
            .expect("list events");
        let ids: Vec<String> = events
            .iter()
            .filter_map(|event| event.vendor_event_id.clone())
            .collect();
        assert!(
            ids.contains(&"a".to_string()) && ids.contains(&"b".to_string()),
            "{ids:?}"
        );
    }

    /// The settled watermark subtracts the window at the poll path: after a
    /// successful poll establishes a watermark, the NEXT dispatched request
    /// carries `since = watermark - window`, not the bare watermark.
    ///
    /// Mutation proved: resuming from the bare maximum makes the recorded
    /// request timestamp equal the watermark, so the equality with
    /// `watermark - window` fails.
    #[test]
    fn ordered_poll_path_requests_from_watermark_minus_window() {
        let response = json!({
            "items": [
                { "id": "a", "updated_at": "2024-01-15T10:00:00Z" },
                { "id": "b", "updated_at": "2024-01-15T10:00:05Z" }
            ]
        });
        let (store, engine, transport) = ordered_poll_engine(response);
        let subscription = store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("subscribe")
            .expect("subscription");
        let poller = Poller::new(engine);
        // First poll: empty cursor, so the request carries no `since` and the
        // watermark is established from the response.
        assert!(matches!(
            poller.poll_once("direct", &subscription.subscription_id),
            PollCycle::Completed { .. }
        ));
        let stored = store
            .subscription("direct", &subscription.subscription_id)
            .expect("read subscription")
            .expect("subscription exists");
        let watermark_ms = stored
            .cursor_state
            .get("watermark_ms")
            .and_then(Value::as_i64)
            .expect("watermark");
        let window_ms = stored
            .cursor_state
            .get("window_ms")
            .and_then(Value::as_i64)
            .expect("window");
        // Quiet second page: the watermark does not move, so the resume point is
        // observable on the next dispatched request.
        transport.set_response(MockResponse::Success(json!({ "items": [] })));
        assert!(matches!(
            poller.poll_once("direct", &subscription.subscription_id),
            PollCycle::Completed { .. }
        ));
        let requests = transport.requests();
        let last = requests.last().expect("a second request was dispatched");
        let since = last
            .args
            .get("since")
            .and_then(Value::as_str)
            .expect("since argument");
        assert_eq!(
            super::iso8601::parse_to_millis(since),
            Some(watermark_ms - window_ms),
            "the resumed request must start at watermark - window"
        );
        assert_ne!(
            super::iso8601::parse_to_millis(since),
            Some(watermark_ms),
            "the resumed request must not start at the bare watermark"
        );
    }

    #[test]
    fn ordered_poll_path_impossible_date_preserves_watermark() {
        let (store, engine, transport) = ordered_poll_engine(json!({
            "items": [{ "id": "baseline", "updated_at": "2026-02-28T00:00:00Z" }]
        }));
        let subscription = store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("subscribe")
            .expect("subscription");
        let poller = Poller::new(engine);
        assert!(matches!(
            poller.poll_once("direct", &subscription.subscription_id),
            PollCycle::Completed { inserted: 1, .. }
        ));
        let baseline = store
            .subscription("direct", &subscription.subscription_id)
            .expect("read baseline")
            .expect("subscription exists");
        assert_eq!(
            baseline.cursor_state["watermark_ms"],
            json!(1_772_236_800_000_i64)
        );
        transport.set_response(MockResponse::Success(json!({
            "items": [
                { "id": "good", "updated_at": "2026-03-01T00:00:00Z" },
                { "id": "bad", "updated_at": "2026-02-31T00:00:00Z" }
            ]
        })));
        let cycle = poller.poll_once("direct", &subscription.subscription_id);
        let stored = store
            .subscription("direct", &subscription.subscription_id)
            .expect("read subscription")
            .expect("subscription exists");
        assert_eq!(
            stored.cursor_state, baseline.cursor_state,
            "an impossible date must not advance the watermark"
        );
        assert!(
            matches!(
                cycle,
                PollCycle::Suspended { ref reason } if reason.starts_with("response_shape_invalid:")
            ),
            "expected response_shape_invalid suspension, got {cycle:?}"
        );
        assert_eq!(stored.status, "suspended");
        let events = store
            .list_events("direct", None, Some(&subscription.subscription_id))
            .expect("list events");
        let ordinary: Vec<_> = events
            .iter()
            .filter(|event| event.kind == "event")
            .collect();
        assert_eq!(ordinary.len(), 1, "the refused page must commit no events");
        assert_eq!(ordinary[0].vendor_event_id.as_deref(), Some("baseline"));
        assert!(events.iter().any(|event| event.kind == "gap"));
    }

    /// A malformed item fails the poll rather than being skipped: the
    /// subscription is suspended and NO events are committed.
    ///
    /// Mutation proved: skipping the bad item (instead of refusing the response)
    /// commits the good row and completes the poll, so both the suspension and
    /// the empty-event assertions fail.
    #[test]
    fn ordered_poll_path_refuses_a_malformed_item_without_committing() {
        let response = json!({
            "items": [
                { "id": "good", "updated_at": "2024-01-15T10:00:00Z" },
                { "id": "bad", "updated_at": "not-a-timestamp" }
            ]
        });
        let (store, engine, _transport) = ordered_poll_engine(response);
        let subscription = store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("subscribe")
            .expect("subscription");
        let poller = Poller::new(engine);
        let cycle = poller.poll_once("direct", &subscription.subscription_id);
        assert!(
            matches!(cycle, PollCycle::Suspended { ref reason } if reason.starts_with("response_shape_invalid:")),
            "a malformed item must suspend the poll, got {cycle:?}"
        );
        let events = store
            .list_events("direct", None, Some(&subscription.subscription_id))
            .expect("list events");
        let ordinary: Vec<_> = events
            .iter()
            .filter(|event| event.kind == "event")
            .collect();
        assert!(
            ordinary.is_empty(),
            "no ordinary events may be committed when the response does not match its declared shape: {ordinary:?}"
        );
        // The suspension itself records a coverage gap marker. That is correct
        // and expected — it is the visible hole the suspension creates, not a
        // committed vendor event.
        assert!(
            events.iter().any(|event| event.kind == "gap"),
            "the suspension must record its coverage gap"
        );
    }

    /// A validation failure must not retire a `once` probe. A malformed return
    /// is not a successful fire, and treating it as one silently kills the
    /// watch it was meant to serve.
    ///
    /// Mutation-proved: retiring on any non-success completion, or retiring
    /// before checking the outcome, leaves this row `retired`.
    #[test]
    fn a_validation_failure_does_not_retire_a_once_probe() {
        let (store, engine, _transport) = poll_engine(json!({}));
        let subscription = store
            .register_probe(
                "direct",
                "connection",
                crate::storage::ProbeRegistration {
                    name: "once-watch",
                    actions: &["read_action".to_string()],
                    script_source: "() => 1",
                    return_schema: &json!({"kind": "bool"}),
                    rearm: "once",
                    cadence_s: 30,
                    fixed_args: &json!({}),
                    cursor_state: &json!({}),
                },
            )
            .expect("store")
            .expect("accepted");
        let cycle = Poller::new(engine).poll_once("direct", &subscription.subscription_id);
        assert!(
            matches!(&cycle, PollCycle::Suspended { reason } if reason.starts_with("probe_return_invalid:")),
            "a type-mismatched return must pause visibly: {cycle:?}"
        );
        let stored = store
            .subscription("direct", &subscription.subscription_id)
            .expect("read")
            .expect("present");
        assert_eq!(
            stored.status, "suspended",
            "a validation failure must suspend, not retire a once probe"
        );
    }

    /// A failed replay lookup keeps the candidate in the batch that reaches the
    /// real event commit, preferring insert-time dedupe over permanent loss.
    ///
    /// Mutation-proved: changing the lookup-error branch to clear candidates
    /// makes the committed outcome count zero instead of one.
    #[test]
    fn store_read_failure_keeps_replay_candidate_for_commit() {
        let (store, _engine, _transport) = poll_engine(json!({}));
        let subscription = store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("subscribe")
            .expect("subscription accepted");
        let mut events = vec![DerivedEvent {
            vendor_event_id: "boundary-1".to_string(),
            payload: json!({"id": "boundary-1", "title": "possibly changed"}),
            replay_candidate: true,
            activity_at_ms: Some(1_000),
        }];

        retain_changed_replay_candidates(&mut events, &mut Vec::new(), |_candidates| {
            Err::<Vec<bool>, _>("injected store read failure")
        });
        let inputs = events
            .iter()
            .map(|event| PollEventInput {
                vendor_event_id: &event.vendor_event_id,
                payload: &event.payload,
                observed_at_ms: 2_000,
                item_kind: Some("issue"),
                activity_at_ms: event.activity_at_ms,
                actor: &crate::actor_attribution::ActorAttribution::NotEnriched,
            })
            .collect::<Vec<_>>();
        let outcomes = store
            .commit_poll_success(
                "direct",
                "connection",
                &subscription.subscription_id,
                &json!({}),
                &inputs,
                2_000,
                None,
            )
            .expect("candidate reaches insert after lookup failure");
        assert_eq!(
            outcomes.len(),
            1,
            "lookup failure must keep the candidate for insert-time dedupe"
        );
        assert!(matches!(
            outcomes[0],
            TriggerEventInsertOutcome::Inserted { .. }
        ));
    }

    /// Ordered-timestamp events are established window results, so they never
    /// invoke the sorted-head replay lookup.
    ///
    /// Mutation-proved: setting `replay_candidate` to true in the ordered strategy
    /// increments the lookup count and fails this test.
    #[test]
    fn ordered_timestamp_issues_no_replay_candidate_lookup() {
        let mut advance = ordered_strategy()
            .derive(
                &json!({}),
                &json!({
                    "items": [{
                        "id": "ordered-1",
                        "updated_at": "2026-09-06T12:00:00Z"
                    }]
                }),
            )
            .expect("derive ordered event");
        let lookup_calls = std::cell::Cell::new(0usize);
        retain_changed_replay_candidates(
            &mut advance.events,
            &mut advance.dropped,
            |_candidates| {
                lookup_calls.set(lookup_calls.get() + 1);
                Ok::<Vec<bool>, ()>(Vec::new())
            },
        );
        assert_eq!(
            lookup_calls.get(),
            0,
            "ordered-timestamp must not issue a replay-candidate lookup"
        );
        assert_eq!(advance.events.len(), 1, "the ordered event remains intact");
    }

    /// A successful `once` fire retires in the same commit as the event.
    #[test]
    fn a_successful_once_fire_retires_the_probe() {
        let (store, engine, _transport) = poll_engine(json!({}));
        let subscription = store
            .register_probe(
                "direct",
                "connection",
                crate::storage::ProbeRegistration {
                    name: "once-watch",
                    actions: &["read_action".to_string()],
                    script_source: "() => 'fired'",
                    return_schema: &json!({"kind": "string", "max_len": 16}),
                    rearm: "once",
                    cadence_s: 30,
                    fixed_args: &json!({}),
                    cursor_state: &json!({"baseline": "seed", "observation_ordinal": 0}),
                },
            )
            .expect("store")
            .expect("accepted");
        let cycle = Poller::new(engine).poll_once("direct", &subscription.subscription_id);
        match cycle {
            PollCycle::Completed { inserted, .. } => {
                assert_eq!(inserted, 1, "the seeded change must deliver");
            }
            other => panic!("expected a completed fire, got {other:?}"),
        }
        let stored = store
            .subscription("direct", &subscription.subscription_id)
            .expect("read")
            .expect("present");
        assert_eq!(
            stored.status, "retired",
            "a successful once fire must retire"
        );
    }

    /// Wait up to ten seconds for `condition` to become true, allowing another
    /// thread to change the state it checks.
    fn wait_until(what: &str, condition: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !condition() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting: {what}"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// A comment created in the previous observation's own second but edited in
    /// a later one was acted on after that observation, so its author is inside
    /// the window. Only activity confined to that second, or to it and earlier
    /// seconds, is ambiguous.
    #[test]
    fn an_edit_after_a_same_second_creation_is_inside_the_actor_window() {
        let previous = 1_787_227_200_500;
        let same_second = 1_787_227_200_000;
        let later = 1_787_227_205_000;
        let earlier = 1_787_227_190_000;
        assert_eq!(
            in_actor_window(same_second, later, Some(previous)),
            Ok(true)
        );
        assert_eq!(in_actor_window(later, later, Some(previous)), Ok(true));
        assert_eq!(in_actor_window(earlier, later, Some(previous)), Ok(true));
        assert_eq!(
            in_actor_window(same_second, same_second, Some(previous)),
            Err(ExtractionMiss::SameSecond)
        );
        assert_eq!(
            in_actor_window(earlier, same_second, Some(previous)),
            Err(ExtractionMiss::SameSecond)
        );
        assert_eq!(in_actor_window(earlier, earlier, Some(previous)), Ok(false));
    }

    /// A seeded cursor is input: values the strategy could never have written
    /// are refused instead of overflowing the resume arithmetic or, for a
    /// negative window, moving the resume point past the watermark and
    /// skipping rows for good.
    #[test]
    fn ordered_timestamp_refuses_cursor_values_it_could_not_have_written() {
        let strategy = ordered_strategy();
        // A paginated strategy accepts a stored page continuation, which takes
        // a separate early-return branch in `build_args`.
        let paginated = OrderedTimestampStrategy::new(Some(&PollShape {
            pagination: Some(crate::manifest::PollPagination {
                request_cursor_field: "after".to_string(),
                response_cursor_pointer: "/next".to_string(),
            }),
            ..ordered_shape()
        }))
        .expect("paginated ordered strategy");
        let page = json!({"items": [{"id": "1", "updated_at": "2024-01-01T00:00:00Z"}]});
        let resume = json!({"after": "vendor-cursor-2"});
        assert!(
            paginated
                .build_args(&json!({"watermark_ms": 1_700_000_000_000_i64, "page_resume": resume}))
                .is_ok(),
            "a sound cursor with a page continuation must stay usable"
        );
        for state in [
            json!({"watermark_ms": i64::MIN}),
            json!({"watermark_ms": i64::MAX}),
            json!({"watermark_ms": MIN_WATERMARK_MS - 1}),
            json!({"watermark_ms": MAX_WATERMARK_MS + 1}),
            json!({"watermark_ms": 1_700_000_000_000_i64, "window_ms": -1}),
            json!({"watermark_ms": 1_700_000_000_000_i64, "window_ms": i64::MIN}),
            json!({"watermark_ms": 1_700_000_000_000_i64, "window_ms": MAX_WINDOW_MS + 1}),
            json!({"watermark_ms": 1_700_000_000_000_i64, "window_changed_ms": "soon"}),
        ] {
            // Refusing before the vendor read matters: a value only `derive`
            // refuses has already spent a governed call by then.
            assert!(
                matches!(
                    strategy.build_args(&state),
                    Err(CursorError::InvalidState(_))
                ),
                "build_args accepted {state}"
            );
            let mut resuming = state.clone();
            resuming["page_resume"] = resume.clone();
            assert!(
                matches!(
                    paginated.build_args(&resuming),
                    Err(CursorError::InvalidState(_))
                ),
                "build_args accepted {resuming} through its page continuation"
            );
            assert!(
                matches!(
                    strategy.derive(&state, &page),
                    Err(CursorError::InvalidState(_))
                ),
                "derive accepted {state}"
            );
        }
        // The accepted range is exactly what a vendor timestamp can parse to.
        for (input, bound) in [
            ("0000-01-01T00:00:00+23:59", MIN_WATERMARK_MS),
            ("9999-12-31T23:59:59.999-23:59", MAX_WATERMARK_MS),
        ] {
            let parsed = iso8601::parse_to_millis(input).expect("parses");
            let state = json!({"watermark_ms": parsed, "window_ms": MAX_WINDOW_MS});
            assert!(strategy.build_args(&state).is_ok(), "{input}");
            assert!((parsed - bound).abs() < 86_400_000, "{input}");
        }
    }

    /// A probe whose observation ordinal is at its limit refuses to advance
    /// rather than overflowing.
    #[test]
    fn probe_ordinal_exhaustion_is_refused() {
        let state = json!({"baseline": false, "observation_ordinal": i64::MAX});
        assert!(matches!(
            ProbeStrategy.derive(&state, &json!(true)),
            Err(CursorError::InvalidState(_))
        ));
        // An unchanged value does not advance the ordinal, so it still derives.
        assert!(ProbeStrategy.derive(&state, &json!(false)).is_ok());
    }

    /// A page whose newest row is older than the stored watermark (the row that
    /// set it was deleted, or no longer matches the filter) leaves the
    /// watermark where it was; moving it back would widen every later request.
    #[test]
    fn ordered_timestamp_watermark_never_moves_backwards() {
        let strategy = ordered_strategy();
        let watermark_ms = iso8601::parse_to_millis("2024-01-15T10:00:50Z").unwrap();
        let prior = json!({"watermark_ms": watermark_ms, "watermark_id": "b", "window_ms": 60_000});
        let older = json!({"items": [{"id": "a", "updated_at": "2024-01-15T10:00:20Z"}]});
        let advance = strategy.derive(&prior, &older).expect("derive");
        assert_eq!(advance.cursor_state, prior);
        assert_eq!(advance.events.len(), 1, "the row itself is still delivered");
        // Same timestamp, smaller id: the pair does not move back either.
        let tie = json!({"items": [{"id": "a", "updated_at": "2024-01-15T10:00:50Z"}]});
        assert_eq!(
            strategy.derive(&prior, &tie).expect("derive").cursor_state,
            prior
        );
        // A newer row still advances it.
        let newer = json!({"items": [{"id": "c", "updated_at": "2024-01-15T10:01:00Z"}]});
        assert_eq!(
            strategy
                .derive(&prior, &newer)
                .expect("derive")
                .cursor_state["watermark_id"],
            "c"
        );
    }

    /// The overlap window doubles on a confirmed late row, then after a full
    /// quiet day halves back toward the initial window, one step per day.
    #[test]
    fn the_overlap_window_widens_on_a_late_row_and_decays_after_a_quiet_day() {
        let watermark = json!({"watermark_ms": 1_700_000_000_000_i64, "watermark_id": "1"});
        let with = |window: i64, changed: Option<i64>| {
            let mut state = watermark.clone();
            state["window_ms"] = json!(window);
            if let Some(changed) = changed {
                state["window_changed_ms"] = json!(changed);
            }
            state
        };
        let settle = |prior: &Value, late: bool, now: i64| {
            let mut next = prior.clone();
            settle_ordered_window(prior, &mut next, late, now);
            next
        };
        let t0 = 1_800_000_000_000_i64;
        // A confirmed late row doubles the window and starts the quiet period.
        let widened = settle(&with(INITIAL_WINDOW_MS, None), true, t0);
        assert_eq!(widened, with(2 * INITIAL_WINDOW_MS, Some(t0)));
        // Further late rows keep doubling it, up to the ceiling.
        assert_eq!(
            settle(&with(MAX_WINDOW_MS, Some(t0)), true, t0 + 5),
            with(MAX_WINDOW_MS, Some(t0 + 5))
        );
        // Short of a quiet day nothing changes.
        let quiet = with(4 * INITIAL_WINDOW_MS, Some(t0));
        assert_eq!(settle(&quiet, false, t0 + WINDOW_DECAY_QUIET_MS - 1), quiet);
        // A quiet day halves it once and restarts the clock.
        let halved = settle(&quiet, false, t0 + WINDOW_DECAY_QUIET_MS);
        assert_eq!(
            halved,
            with(2 * INITIAL_WINDOW_MS, Some(t0 + WINDOW_DECAY_QUIET_MS))
        );
        // It never decays below the initial window.
        let floor = settle(
            &with(INITIAL_WINDOW_MS + 1, Some(t0)),
            false,
            t0 + WINDOW_DECAY_QUIET_MS,
        );
        assert_eq!(floor["window_ms"], json!(INITIAL_WINDOW_MS));
        // A wide window with no stamp (seeded, or widened before stamps were
        // kept) starts its quiet period now instead of halving at once.
        assert_eq!(
            settle(&with(MAX_WINDOW_MS, None), false, t0),
            with(MAX_WINDOW_MS, Some(t0))
        );
        // The initial window needs no stamp at all.
        assert_eq!(
            settle(&with(INITIAL_WINDOW_MS, None), false, t0),
            with(INITIAL_WINDOW_MS, None)
        );
    }

    /// Through the real poll path: a never-stored row well below the previous
    /// watermark (late visibility under a server-side `since` filter) widens
    /// the window and is counted for the watch, while a change to a stored
    /// row's content that leaves its timestamp alone, such as a reaction
    /// count, does not.
    #[test]
    fn ordered_poll_path_widens_only_on_a_row_that_arrived_late() {
        let b = json!({ "id": "b", "updated_at": "2024-01-15T10:00:50Z" });
        let (store, engine, transport) = ordered_poll_engine(json!({
            "items": [{ "id": "a", "updated_at": "2024-01-15T10:00:00Z", "reactions": 0 }, b]
        }));
        let subscription = store
            .subscribe("direct", "connection", "read_action", 30)
            .expect("subscribe")
            .expect("subscription");
        let id = subscription.subscription_id;
        let poller = Poller::new(engine);
        let stored = |store: &PlexusStore| {
            store
                .subscription("direct", &id)
                .expect("read")
                .expect("exists")
                .cursor_state
        };
        let late_rows = || poll_accounting_metrics()["lateRowsBySubscription"][&id].clone();
        assert!(matches!(
            poller.poll_once("direct", &id),
            PollCycle::Completed { inserted: 2, .. }
        ));
        assert_eq!(stored(&store)["window_ms"], json!(INITIAL_WINDOW_MS));

        // Row `a` sits 50 s below the watermark with new content but its own
        // stored timestamp: not late.
        transport.set_response(MockResponse::Success(json!({
            "items": [{ "id": "a", "updated_at": "2024-01-15T10:00:00Z", "reactions": 1 }, b]
        })));
        assert!(matches!(
            poller.poll_once("direct", &id),
            PollCycle::Completed { inserted: 1, .. }
        ));
        assert_eq!(stored(&store)["window_ms"], json!(INITIAL_WINDOW_MS));
        assert_eq!(late_rows(), Value::Null);

        // Row `c` was never seen and sits 40 s below the watermark: it became
        // visible after the previous poll had read past its timestamp.
        transport.set_response(MockResponse::Success(json!({
            "items": [{ "id": "c", "updated_at": "2024-01-15T10:00:10Z" }, b]
        })));
        assert!(matches!(
            poller.poll_once("direct", &id),
            PollCycle::Completed { inserted: 1, .. }
        ));
        let cursor = stored(&store);
        assert_eq!(cursor["window_ms"], json!(2 * INITIAL_WINDOW_MS));
        assert!(cursor["window_changed_ms"].is_i64(), "{cursor}");
        assert_eq!(late_rows(), json!(1));
    }

    /// A transport whose calls block until the test opens the gate, so a probe
    /// action call outlives its callback deadline.
    struct GatedTransport {
        open: std::sync::Mutex<bool>,
        opened: std::sync::Condvar,
        calls: AtomicU64,
    }

    impl crate::transport::Transport for GatedTransport {
        fn dispatch(
            &self,
            _request: crate::transport::TransportRequest,
            _credential: &crate::credentials::ResolvedCredential,
        ) -> crate::transport::TransportResponse {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut open = self.open.lock().unwrap();
            while !*open {
                open = self.opened.wait(open).unwrap();
            }
            crate::transport::TransportResponse::success(json!(true))
        }
    }

    /// A probe action call abandoned at its deadline keeps running, because a
    /// request on the wire cannot be recalled. Until it ends, the next poll of
    /// that probe must not start a second call against the same vendor; once
    /// it ends, polling resumes normally.
    #[test]
    fn an_abandoned_probe_call_blocks_the_next_poll_until_it_ends() {
        let (store, credentials) = poll_store_with_shape(json!({
            "item_kind": "issue",
            "cursor_kind": "sync_token"
        }));
        let transport = Arc::new(GatedTransport {
            open: std::sync::Mutex::new(false),
            opened: std::sync::Condvar::new(),
            calls: AtomicU64::new(0),
        });
        let engine = GovernanceEngine::new(store.clone(), Arc::new(credentials), transport.clone());
        let id = store
            .register_probe(
                "direct",
                "connection",
                crate::storage::ProbeRegistration {
                    name: "slow-vendor",
                    actions: &["read_action".to_string()],
                    script_source: "() => invoke('read_action', {})",
                    return_schema: &json!({"kind": "bool"}),
                    rearm: "always",
                    cadence_s: 30,
                    fixed_args: &json!({}),
                    cursor_state: &json!({}),
                },
            )
            .expect("store")
            .expect("accepted")
            .subscription_id;
        let poller = Poller::new(engine);
        let calls = || transport.calls.load(Ordering::SeqCst);

        assert_eq!(
            poller.poll_once("direct", &id),
            PollCycle::Inconclusive {
                code: "probe_action_failed".to_string()
            }
        );
        wait_until("the abandoned call reaches the vendor", || calls() == 1);
        assert_eq!(
            poller.poll_once("direct", &id),
            PollCycle::Inconclusive {
                code: PROBE_ACTION_IN_FLIGHT.to_string()
            }
        );
        assert_eq!(calls(), 1, "a second call overlapped the abandoned one");

        *transport.open.lock().unwrap() = true;
        transport.opened.notify_all();
        wait_until("the abandoned call ends", || !ProbeCallInFlight::held(&id));
        assert!(matches!(
            poller.poll_once("direct", &id),
            PollCycle::Completed { .. }
        ));
        assert_eq!(calls(), 2);
    }
}

#[cfg(test)]
mod repository_identity_tests {
    use super::*;
    use crate::credentials::{ResolvedCredential, StubCredentialSource};
    use crate::storage::{CatalogActionInput, Ceiling, GrantInput, PlexusStore};
    use crate::test_scratch::Scratch;
    use crate::transport::{MockResponse, MockTransport, TransportRequest, TransportResponse};
    use cortexkit_store_types::{Isolation, StorageBackend, StorageDescriptor};

    const PRINCIPAL: &str = "watch-owner";
    const GITHUB: &str = "conn-github";
    const ACTIONS: &str = "conn-github-actions";

    // Inspect the database through a separate reader while dispatch is running:
    // an in-memory promise or a reservation committed after HTTP cannot pass.
    struct CheckedTransport {
        mock: MockTransport,
        path: std::path::PathBuf,
    }
    impl Transport for CheckedTransport {
        fn dispatch(
            &self,
            request: TransportRequest,
            credential: &ResolvedCredential,
        ) -> TransportResponse {
            if request.connection_id == ACTIONS {
                let conn = rusqlite::Connection::open(&self.path).unwrap();
                let units: i64 = conn.query_row("SELECT COALESCE(SUM(requests),0) FROM github_actions_quota WHERE reserved_at_ms >= ?1", [now_ms() - 3_600_000], |row| row.get(0)).unwrap();
                assert!(
                    units > 0 && units <= 600,
                    "identity HTTP must have a committed quota reservation"
                );
                let claimed: i64 = conn.query_row("SELECT COUNT(*) FROM github_repo_id_cache WHERE repo = lower(?1) AND last_attempt_at_ms > 0", [format!("{}/{}", request.args["owner"].as_str().unwrap(), request.args["repo"].as_str().unwrap())], |row| row.get(0)).unwrap();
                assert_eq!(claimed, 1, "the shared name claim must commit before HTTP");
            }
            self.mock.dispatch(request, credential)
        }
    }

    type Engine = GovernanceEngine<StubCredentialSource, CheckedTransport>;
    struct Fixture {
        store: Arc<PlexusStore>,
        credentials: Arc<StubCredentialSource>,
        engine: Engine,
        poller: Poller<StubCredentialSource, CheckedTransport>,
        mock: MockTransport,
        path: Scratch,
    }
    impl Fixture {
        fn new(actions: bool) -> Self {
            let path = Scratch::database("poll-repository-identity");
            let store = Arc::new(
                PlexusStore::open(&StorageDescriptor {
                    module_id: "plexus".into(),
                    storage_namespace: path.to_string_lossy().into_owned(),
                    isolation: Isolation::Module,
                    backend: StorageBackend::Sqlite {
                        path: path.to_string_lossy().into_owned(),
                    },
                })
                .unwrap(),
            );
            for source in [
                include_str!("../../../catalog/github.jsonc"),
                include_str!("../../../catalog/github_actions.jsonc"),
            ] {
                let source =
                    subc_jsonc::jsonc_to_json(source).expect("shipped catalog is valid JSONC");
                let manifest =
                    crate::manifest::ingest_value(serde_json::from_str(&source).unwrap()).unwrap();
                store
                    .upsert_manifest(crate::storage::CATALOG_PRINCIPAL, &manifest)
                    .unwrap();
            }
            let credentials = Arc::new(StubCredentialSource::default());
            let mock = MockTransport::default();
            let engine = GovernanceEngine::new(
                store.clone(),
                credentials.clone(),
                Arc::new(CheckedTransport {
                    mock: mock.clone(),
                    path: path.to_path_buf(),
                }),
            );
            let fixture = Self {
                store,
                credentials,
                poller: Poller::new(engine.clone()),
                engine,
                mock,
                path,
            };
            fixture.connect(
                GITHUB,
                "github",
                &["list_issues", "list_pull_requests", "get_latest_release"],
            );
            if actions {
                fixture.connect_actions();
            }
            fixture.mock.set_response_for_method(
                "get_repository",
                "",
                MockResponse::Success(json!({"id":101})),
            );
            fixture.mock.set_response_for_method(
                "list_issues",
                "",
                MockResponse::Success(json!({"issues":[issue(7, "2026-10-07T00:00:00Z")]})),
            );
            fixture.mock.set_response_for_method("list_pull_requests", "", MockResponse::Success(json!([{"number":8, "updated_at":"2026-10-07T00:00:00Z", "created_at":"2026-10-07T00:00:00Z", "head":{"ref":"must-not-be-a-header"}}])));
            fixture.mock.set_response_for_method("get_latest_release", "", MockResponse::Success(json!({"id":9,"tag_name":"v1","created_at":"2026-10-07T00:00:00Z","updated_at":"2026-10-07T00:00:00Z"})));
            fixture
        }
        fn connect_actions(&self) {
            self.connect(
                ACTIONS,
                "github_actions",
                &["get_repository", "list_workflow_runs"],
            );
        }
        fn connect(&self, connection: &str, app: &str, actions: &[&str]) {
            self.store
                .insert_connection(PRINCIPAL, connection, app, "pending", &json!({}))
                .unwrap();
            for action in actions {
                self.store.upsert_catalog_action(&CatalogActionInput {
                    connection_id: connection.into(), principal: PRINCIPAL.into(), name: (*action).into(), title: None,
                    schema: json!({"type":"object","properties":{
                        "owner":{"type":"string"},"repo":{"type":"string"},"since":{"type":"string"},
                        "orderBy":{"type":"string"},"direction":{"type":"string"},"perPage":{"type":"integer"},
                        "after":{"type":"string"},"sort":{"type":"string"},"state":{"type":"string"}},"required":["owner","repo"]}),
                    schema_hash: format!("current-{action}"), risk: "read".into(), severity: "S2".into(), ask_first: false,
                    status: "active".into(), quarantine_reason: None, reconciliation: None,
                }).unwrap();
            }
            let handle = format!("test:{connection}").into_bytes();
            let ticket = self
                .store
                .create_binding_ticket_bounded(
                    PRINCIPAL,
                    connection,
                    "credential_reference",
                    &handle,
                    &Ceiling::unrestricted_for_tests(),
                )
                .unwrap();
            self.store
                .connect_with_ticket(PRINCIPAL, &ticket.ticket_id)
                .unwrap()
                .unwrap();
            self.credentials
                .set_success(&handle, b"vendor-token".to_vec(), None, 1);
            self.grant(connection, actions);
        }
        fn grant(&self, connection: &str, actions: &[&str]) {
            self.store
                .insert_grant(&GrantInput {
                    grant_id: format!("poll-{connection}"),
                    principal: PRINCIPAL.into(),
                    connection_id: connection.into(),
                    grantee_principal: PRINCIPAL.into(),
                    risk_ceiling: "read".into(),
                    action_selectors: actions.iter().map(|s| (*s).into()).collect(),
                    authority_kind: crate::governance::AUTHORITY_POLL.into(),
                    expires_at: Some(now_ms() + 3_600_000),
                })
                .unwrap();
        }
        fn watch(&self, action: &str) -> TriggerSubscription {
            self.watch_repo(action, "OWNER", "Repo")
        }
        fn watch_repo(&self, action: &str, owner: &str, repo: &str) -> TriggerSubscription {
            let cursor = if action == "get_latest_release" {
                json!({"scalar":"v0"})
            } else {
                json!({})
            };
            self.store
                .subscribe_with_cursor_state(
                    PRINCIPAL,
                    if action == "list_workflow_runs" {
                        ACTIONS
                    } else {
                        GITHUB
                    },
                    action,
                    300,
                    &cursor,
                    &json!({"owner":owner,"repo":repo}),
                )
                .unwrap()
                .unwrap()
        }
        fn sql(&self, sql: &str) {
            let conn = rusqlite::Connection::open(&*self.path).unwrap();
            conn.execute_batch(sql).unwrap();
        }
        fn count(&self, table: &str) -> i64 {
            rusqlite::Connection::open(&*self.path)
                .unwrap()
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap()
        }
        fn refresh_due(&self) {
            self.sql(&format!(
                "UPDATE github_repo_id_cache SET resolved_at_ms = {}, last_attempt_at_ms = {}",
                now_ms() - 86_400_001,
                now_ms() - 3_600_001
            ));
        }
        fn poll(&self, watch: &TriggerSubscription) -> PollCycle {
            self.poller.poll_once(PRINCIPAL, &watch.subscription_id)
        }
        fn counter(&self, name: &str) -> u64 {
            self.poller.repo_identity_counts.snapshot()[name]
                .as_u64()
                .unwrap()
        }
    }
    fn issue(number: i64, updated: &str) -> Value {
        json!({"number":number,"title":"vendor body","created_at":"2026-10-07T00:00:00Z","updated_at":updated})
    }

    #[test]
    fn identity_read_is_shared_authorized_audited_and_reserved_before_the_vendor_read() {
        let f = Fixture::new(true);
        for action in ["list_issues", "list_pull_requests", "get_latest_release"] {
            let watch = f.watch(action);
            assert_eq!(
                f.poll(&watch),
                PollCycle::Completed {
                    inserted: 1,
                    duplicates: 0
                }
            );
        }
        let requests = f.mock.requests();
        assert_eq!(
            requests
                .iter()
                .map(|r| r.action.as_str())
                .collect::<Vec<_>>(),
            vec![
                "get_repository",
                "list_issues",
                "list_pull_requests",
                "get_latest_release"
            ]
        );
        assert_eq!(requests[0].connection_id, ACTIONS);
        assert_eq!(f.count("github_actions_quota"), 1);
        let audit = f.store.list_audit(PRINCIPAL).unwrap();
        let identity_dispatch = audit
            .iter()
            .find(|row| row.action.as_deref() == Some("get_repository") && row.outcome.is_some())
            .expect("own dispatch audit for repository read");
        assert_eq!(identity_dispatch.principal, PRINCIPAL);
        assert!(identity_dispatch.actor.starts_with("trigger:"));
        let list_dispatch = audit
            .iter()
            .find(|row| row.action.as_deref() == Some("list_issues") && row.outcome.is_some())
            .unwrap();
        assert!(identity_dispatch.journal_id < list_dispatch.journal_id);
        assert_eq!(
            f.store
                .repo_id_cache("owner/repo")
                .unwrap()
                .unwrap()
                .repo_id,
            Some(101)
        );
        assert_eq!(
            f.count("event_outbox"),
            3,
            "current identity schema hash must authorize, not the issue watch's pin"
        );
    }

    #[test]
    fn keyed_poll_markers_keep_change_out_of_bodies_and_pr_branch_out_of_headers() {
        let f = Fixture::new(true);
        let watch = f.watch("list_issues");
        f.sql("UPDATE trigger_subscriptions SET project_id = 'project-p', project_source = 'entorhinal'");
        f.mock.set_response_for_method(
            "list_issues",
            "",
            MockResponse::Success(json!({"issues":[
                issue(7,"2026-10-07T00:00:00Z"), issue(8,"2026-10-07T00:00:01Z"),
                {"number":9,"updated_at":"2026-10-07T00:00:02Z"}
            ]})),
        );
        assert_eq!(
            f.poll(&watch),
            PollCycle::Completed {
                inserted: 3,
                duplicates: 0
            }
        );
        for (number, updated, change) in [
            (7, "2026-10-07T00:00:00Z", Some("opened")),
            (8, "2026-10-07T00:00:01Z", Some("updated")),
            (9, "2026-10-07T00:00:02Z", None),
        ] {
            let key = crate::event_key::derive_event_key(
                "github_issue_changed",
                &json!({"repo_id":101,"number":number,"updated_at":updated}),
            )
            .unwrap();
            let marker = f.store.canonical_event_by_key(&key).unwrap().unwrap();
            assert_eq!(marker.change.as_deref(), change);
            assert_eq!(marker.headers.repo, "owner/repo");
            assert_eq!(marker.event_name, "github_issue_changed");
            assert_eq!(marker.headers.project.as_deref(), Some("project-p"));
            assert!(serde_json::from_str::<Value>(&marker.body)
                .unwrap()
                .get("change")
                .is_none());
        }
        let before = f.count("event_outbox");
        assert!(matches!(
            f.poll(&watch),
            PollCycle::Completed { inserted: 0, .. }
        ));
        assert_eq!(f.count("event_outbox"), before);
        for action in ["list_pull_requests", "get_latest_release"] {
            assert_eq!(
                f.poll(&f.watch(action)),
                PollCycle::Completed {
                    inserted: 1,
                    duplicates: 0
                }
            );
        }
        let markers = f.store.drain_event_outbox(10).unwrap();
        let pr = markers
            .iter()
            .find(|m| m.event_name == "github_pr_changed")
            .unwrap();
        assert_eq!(pr.headers.pr.as_deref(), Some("8"));
        assert_eq!(pr.headers.branch, None);
        assert_eq!(pr.change, None);
        let release = markers
            .iter()
            .find(|m| m.event_name == "github_release_published")
            .unwrap();
        assert_eq!(release.change, None);
        assert_eq!(release.headers.pr, None);
    }

    #[test]
    fn unchanged_legacy_issue_is_duplicate_on_real_poll_with_no_marker() {
        let f = Fixture::new(true);
        let watch = f.watch("list_issues");
        let payload = issue(7, "2026-10-07T00:00:00Z");
        let outcomes = f
            .store
            .commit_poll_success(
                PRINCIPAL,
                GITHUB,
                &watch.subscription_id,
                &json!({}),
                &[PollEventInput {
                    vendor_event_id: "7",
                    payload: &payload,
                    observed_at_ms: now_ms(),
                    item_kind: Some("issue"),
                    activity_at_ms: Some(now_ms()),
                    actor: &ActorAttribution::NotEnriched,
                }],
                now_ms(),
                None,
            )
            .unwrap();
        assert!(matches!(
            outcomes[0],
            TriggerEventInsertOutcome::Inserted { .. }
        ));
        assert_eq!(
            f.poll(&watch),
            PollCycle::Completed {
                inserted: 0,
                duplicates: 1
            }
        );
        assert_eq!(f.count("trigger_events"), 1);
        assert_eq!(f.count("event_outbox"), 0);
        assert!(f.store.list_events(PRINCIPAL, None, None).unwrap()[0]
            .payload
            .get("change")
            .is_none());
        assert_eq!(
            f.poll(&watch),
            PollCycle::Completed {
                inserted: 0,
                duplicates: 1
            }
        );
        assert_eq!(f.count("event_outbox"), 0);
    }

    #[test]
    fn absent_actions_connection_survives_twenty_ticks_and_recovery_does_not_publish_old_state() {
        let f = Fixture::new(false);
        let watch = f.watch("list_issues");
        for second in 0..20 {
            f.mock.set_response_for_method(
                "list_issues",
                "",
                MockResponse::Success(
                    json!({"issues":[issue(7,&format!("2026-10-07T00:00:{second:02}Z"))]}),
                ),
            );
            assert_eq!(
                f.poll(&watch),
                PollCycle::Completed {
                    inserted: 1,
                    duplicates: 0
                }
            );
            let stored = f
                .store
                .subscription(PRINCIPAL, &watch.subscription_id)
                .unwrap()
                .unwrap();
            assert_eq!(stored.status, "active");
            assert_eq!(stored.consecutive_vendor_failures, 0);
        }
        assert_eq!(f.counter("repo_id_unresolved"), 20);
        assert_eq!(f.count("trigger_events"), 20);
        assert_eq!(f.count("event_outbox"), 0);
        assert_eq!(f.mock.requests().len(), 20);
        assert_eq!(
            f.count("github_actions_quota"),
            0,
            "absent connection must not consume a vendor quota reservation"
        );
        let scheduler = crate::scheduler::Scheduler::new(f.engine.clone(), 604_800_000);
        let pass = scheduler.run_pass(&[PRINCIPAL.to_string()], now_ms() + 300_001);
        assert_eq!(pass.len(), 1);
        assert_eq!(
            pass[0].cycle,
            PollCycle::Completed {
                inserted: 0,
                duplicates: 1
            },
            "the scheduler must not trip its breaker after degraded identity ticks"
        );
        f.connect_actions();
        f.sql("UPDATE github_repo_id_cache SET last_attempt_at_ms = 0");
        assert_eq!(
            f.poll(&watch),
            PollCycle::Completed {
                inserted: 0,
                duplicates: 1
            }
        );
        assert_eq!(
            f.count("event_outbox"),
            0,
            "unchanged unkeyed state stays unpublished"
        );
        f.mock.set_response_for_method(
            "list_issues",
            "",
            MockResponse::Success(json!({"issues":[issue(7,"2026-10-07T00:00:20Z")]})),
        );
        assert_eq!(
            f.poll(&watch),
            PollCycle::Completed {
                inserted: 1,
                duplicates: 0
            }
        );
        assert_eq!(f.count("event_outbox"), 1);
    }

    /// A store failure while preparing the `get_repository` read, before the
    /// shared owner/name claim is taken, is neither a failed resolution nor a
    /// failure of the watched read. The cycle publishes without the repository
    /// id but records and counts nothing: the repository name is not blocked
    /// for an hour, no quota is reserved, and the next poll resolves the id and
    /// keys its events.
    #[test]
    fn a_store_failure_claiming_identity_is_not_a_failed_resolution() {
        let f = Fixture::new(true);
        let watch = f.watch("list_issues");
        f.sql(
            "UPDATE catalog_actions SET schema_json = 'unreadable' WHERE name = 'get_repository'",
        );
        assert_eq!(
            f.poll(&watch),
            PollCycle::Completed {
                inserted: 1,
                duplicates: 0
            }
        );
        assert!(
            f.store.repo_id_cache("owner/repo").unwrap().is_none(),
            "a store failure throttled the name as a failed resolution"
        );
        assert_eq!(f.count("github_actions_quota"), 0);
        assert_eq!(f.counter("repo_id_refresh_failed"), 0);
        assert!(f
            .mock
            .requests()
            .iter()
            .all(|r| r.action != "get_repository"));

        f.sql(&format!(
            "UPDATE catalog_actions SET schema_json = '{}' WHERE name = 'get_repository'",
            json!({"type": "object"})
        ));
        f.poll(&watch);
        assert_eq!(
            f.store
                .repo_id_cache("owner/repo")
                .unwrap()
                .and_then(|entry| entry.repo_id),
            Some(101),
            "the next poll must resolve the name"
        );
    }

    #[test]
    fn missing_identity_grant_is_not_a_vendor_failure_or_a_watch_suspension() {
        let f = Fixture::new(true);
        f.sql("DELETE FROM grants WHERE connection_id = 'conn-github-actions'");
        let watch = f.watch("list_issues");
        assert_eq!(
            f.poll(&watch),
            PollCycle::Completed {
                inserted: 1,
                duplicates: 0
            }
        );
        assert_eq!(f.counter("repo_id_grant_missing"), 1);
        assert_eq!(f.counter("repo_id_unresolved"), 1);
        assert_eq!(
            f.mock
                .requests()
                .iter()
                .filter(|r| r.action == "get_repository")
                .count(),
            0
        );
        assert_eq!(
            f.store
                .subscription(PRINCIPAL, &watch.subscription_id)
                .unwrap()
                .unwrap()
                .consecutive_vendor_failures,
            0
        );
        assert_eq!(f.count("event_outbox"), 0);
    }

    #[test]
    fn failed_resolution_is_shared_for_an_hour_and_failed_refresh_keeps_cached_id() {
        let f = Fixture::new(true);
        f.mock.set_response_for_method(
            "get_repository",
            "",
            MockResponse::VendorError {
                code: "http_404".into(),
                message: "missing".into(),
            },
        );
        for action in ["list_issues", "list_pull_requests", "get_latest_release"] {
            assert_eq!(
                f.poll(&f.watch(action)),
                PollCycle::Completed {
                    inserted: 1,
                    duplicates: 0
                }
            );
        }
        assert_eq!(
            f.mock
                .requests()
                .iter()
                .filter(|r| r.action == "get_repository")
                .count(),
            1
        );
        assert_eq!(f.count("event_outbox"), 0);
        f.sql("UPDATE github_repo_id_cache SET last_attempt_at_ms = 0");
        let watch = f
            .store
            .list_subscriptions(PRINCIPAL, None, None)
            .unwrap()
            .into_iter()
            .find(|s| s.action == "list_issues")
            .unwrap();
        f.mock.set_response_for_method(
            "get_repository",
            "",
            MockResponse::Success(json!({"id":101})),
        );
        assert!(matches!(f.poll(&watch), PollCycle::Completed { .. }));
        assert_eq!(
            f.mock
                .requests()
                .iter()
                .filter(|r| r.action == "get_repository")
                .count(),
            2
        );
        f.refresh_due();
        f.mock.set_response_for_method(
            "get_repository",
            "",
            MockResponse::VendorError {
                code: "http_503".into(),
                message: "retry later".into(),
            },
        );
        f.mock.set_response_for_method(
            "list_issues",
            "",
            MockResponse::Success(json!({"issues":[issue(7,"2026-10-07T00:00:01Z")]})),
        );
        assert_eq!(
            f.poll(&watch),
            PollCycle::Completed {
                inserted: 1,
                duplicates: 0
            }
        );
        assert_eq!(f.counter("repo_id_refresh_failed"), 1);
        assert_eq!(
            f.store
                .repo_id_cache("owner/repo")
                .unwrap()
                .unwrap()
                .repo_id,
            Some(101)
        );
        assert_eq!(f.store.drain_event_outbox(10).unwrap()[0].repo_id, 101);
    }

    #[test]
    fn identity_quota_deferral_polls_unkeyed_or_keeps_cached_id_and_retries_next_cycle() {
        for cached in [false, true] {
            let f = Fixture::new(true);
            let watch = f.watch("list_issues");
            if cached {
                f.store
                    .record_repo_id_resolution("owner/repo", Some(101), now_ms() - 86_400_001)
                    .unwrap();
            }
            f.sql(&format!(
                "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<300)
                INSERT INTO github_actions_quota SELECT 'full-' || i, {}, 8 FROM n",
                now_ms()
            ));
            assert_eq!(
                f.poll(&watch),
                PollCycle::Completed {
                    inserted: 1,
                    duplicates: 0
                }
            );
            assert_eq!(
                f.counter(if cached {
                    "repo_id_refresh_deferred"
                } else {
                    "repo_id_deferred"
                }),
                1
            );
            assert_eq!(f.counter("repo_id_unresolved"), u64::from(!cached));
            assert_eq!(
                f.mock
                    .requests()
                    .iter()
                    .filter(|r| r.action == "get_repository")
                    .count(),
                0
            );
            assert_eq!(f.count("event_outbox"), i64::from(cached));
            f.sql("DELETE FROM github_actions_quota");
            assert_eq!(
                f.poll(&watch),
                PollCycle::Completed {
                    inserted: 0,
                    duplicates: 1
                }
            );
            assert_eq!(
                f.mock
                    .requests()
                    .iter()
                    .filter(|r| r.action == "get_repository")
                    .count(),
                1,
                "deferred resolution retries next cycle, not an hour later"
            );
        }
    }

    #[test]
    fn changed_repository_identity_suspends_all_four_watches_before_listing_or_inserting() {
        let f = Fixture::new(true);
        let watches = [
            "list_issues",
            "list_pull_requests",
            "get_latest_release",
            "list_workflow_runs",
        ]
        .map(|action| f.watch(action));
        let unrelated = f.watch_repo("list_issues", "other", "repo");
        assert_eq!(
            f.poll(&watches[0]),
            PollCycle::Completed {
                inserted: 1,
                duplicates: 0
            }
        );
        let old_marker = f.store.drain_event_outbox(10).unwrap()[0].clone();
        let generations: Vec<_> = watches
            .iter()
            .map(|s| {
                f.store
                    .subscription(PRINCIPAL, &s.subscription_id)
                    .unwrap()
                    .unwrap()
                    .generation
            })
            .collect();
        f.refresh_due();
        f.mock.set_response_for_method(
            "get_repository",
            "",
            MockResponse::Success(json!({"id":202})),
        );
        let requests_before = f.mock.requests().len();
        assert_eq!(
            f.poll(&watches[0]),
            PollCycle::Suspended {
                reason: "repository_identity_changed".into()
            }
        );
        let requests = f.mock.requests();
        assert_eq!(requests.len(), requests_before + 1);
        assert_eq!(
            requests.last().unwrap().action,
            "get_repository",
            "identity change must not dispatch a list read"
        );
        assert_eq!(f.count("trigger_events"), 1);
        assert_eq!(f.count("event_outbox"), 1);
        assert_eq!(f.counter("repository_identity_changed"), 1);
        assert_eq!(
            f.store
                .repo_id_cache("owner/repo")
                .unwrap()
                .unwrap()
                .repo_id,
            Some(202)
        );
        for (watch, generation) in watches.iter().zip(generations) {
            let stored = f
                .store
                .subscription(PRINCIPAL, &watch.subscription_id)
                .unwrap()
                .unwrap();
            assert_eq!(stored.status, "suspended");
            assert_eq!(
                stored.suspended_reason.as_deref(),
                Some("repository_identity_changed")
            );
            assert_eq!(stored.generation, generation + 1);
        }
        assert_eq!(
            f.store
                .subscription(PRINCIPAL, &unrelated.subscription_id)
                .unwrap()
                .unwrap()
                .status,
            "active"
        );
        assert_eq!(
            f.store
                .canonical_event_by_key(&old_marker.event_key)
                .unwrap()
                .unwrap(),
            old_marker
        );
    }
}

#[cfg(test)]
mod sorted_head_saturation_tests {
    use super::*;

    fn shape(page_size: u64) -> PollShape {
        let mut constants = std::collections::BTreeMap::new();
        constants.insert("perPage".to_string(), json!(page_size));
        constants.insert("direction".to_string(), json!("desc"));
        PollShape {
            cursor_kind: crate::manifest::CursorKind::SortedHead,
            token_field: None,
            request_token_field: None,
            items_field: None,
            timestamp_field: Some("updated_at".to_string()),
            tiebreaker_id_field: Some("number".to_string()),
            request_since_field: None,
            request_constants: Some(constants),
            scalar_field: None,
            item_count_ceiling: None,
            item_kind: "issue".to_string(),
            pagination: None,
            request_page_size_field: Some("perPage".to_string()),
        }
    }

    fn page(count: usize, start_day: u32) -> Value {
        Value::Array(
            (0..count)
                .map(|index| {
                    json!({
                        "updated_at": format!(
                            "2026-08-{:02}T{:02}:{:02}:00Z",
                            start_day,
                            index / 60,
                            index % 60
                        ),
                        "number": 100 + index as i64
                    })
                })
                .collect(),
        )
    }

    /// A SHORT page never reports truncation, however new its items are.
    ///
    /// This is the production defect: the check asks whether every item beat the
    /// watermark, which is evidence of a cut-short page only when the vendor had
    /// no room to send more. A repository with fewer pull requests than one page
    /// reported two coverage gaps in a day over windows containing zero and one
    /// real changes -- a feed telling its consumer it had holes that did not
    /// exist.
    ///
    /// Both arms, because a fix that simply stopped reporting gaps would pass the
    /// first assertion alone and destroy the guard.
    #[test]
    fn only_a_full_page_can_report_truncation() {
        let strategy = SortedHeadStrategy::new(Some(&shape(100))).expect("strategy");
        let watermark = json!({
            WATERMARK_MS_KEY: iso8601::parse_to_millis("2026-08-01T00:00:00Z").expect("parse"),
            WATERMARK_ID_KEY: "1"
        });

        // SHORT page, every item newer than the watermark: the vendor sent its
        // whole collection, so nothing can lie beyond the edge.
        let short = strategy
            .derive(&watermark, &page(3, 10))
            .expect("derive short page");
        assert_eq!(
            short.coverage_gap, None,
            "a page shorter than the cap is the complete answer and must not report a gap"
        );
        assert_eq!(short.events.len(), 3, "the items are still delivered");

        // FULL page, same condition: now truncation is genuinely possible.
        let full = strategy
            .derive(&watermark, &page(100, 10))
            .expect("derive full page");
        assert!(
            full.coverage_gap.is_some(),
            "a full page whose oldest item beats the watermark must still report truncation"
        );
    }

    /// A shape with no declared page cap is REFUSED rather than defaulted.
    ///
    /// A default would restore the false-gap behaviour: any guess about the cap
    /// is wrong for some vendor, and guessing high makes every page look short
    /// (never reporting real truncation) while guessing low makes every page look
    /// full (reporting it constantly).
    #[test]
    fn a_shape_without_a_page_cap_is_refused() {
        let mut without = shape(100);
        without.request_page_size_field = None;
        assert!(
            SortedHeadStrategy::new(Some(&without)).is_none(),
            "no declared cap must refuse the strategy rather than default one"
        );

        let mut zero = shape(0);
        assert!(
            SortedHeadStrategy::new(Some(&zero)).is_none(),
            "a zero cap must be refused: every page would look full"
        );
        zero.request_page_size_field = Some("absent".to_string());
        assert!(
            SortedHeadStrategy::new(Some(&zero)).is_none(),
            "naming a key that request_constants does not carry must be refused"
        );
    }
}

#[cfg(test)]
mod scalar_diff_tests {
    use super::*;

    fn scalar_shape() -> PollShape {
        PollShape {
            cursor_kind: crate::manifest::CursorKind::ScalarDiff,
            token_field: None,
            request_token_field: None,
            items_field: None,
            timestamp_field: None,
            tiebreaker_id_field: None,
            item_count_ceiling: None,
            item_kind: "issue".to_string(),
            pagination: None,
            request_page_size_field: None,
            request_since_field: None,
            request_constants: None,
            scalar_field: Some("tag_name".to_string()),
        }
    }

    fn scalar_strategy() -> ScalarDiffStrategy {
        ScalarDiffStrategy::new(Some(&scalar_shape())).expect("scalar strategy")
    }

    /// The whole shape in one vector: baseline on first sight, silence while
    /// unchanged, one event on change.
    ///
    /// All three legs matter and they fail in opposite directions. Emitting on
    /// the first observation would announce a release that may be weeks old as
    /// news. Emitting while unchanged would fire on every tick forever, since
    /// the value is re-read each cycle rather than being consumed. Emitting
    /// nothing on change is the watch silently not working -- the failure this
    /// whole design exists to prevent, and the one that reads as a quiet period.
    ///
    /// Mutation-proved: treating an absent predecessor as a change fails the
    /// baseline leg; comparing with `!=` inverted fails the unchanged leg;
    /// returning no events unconditionally fails the change leg.
    #[test]
    fn a_scalar_baselines_then_emits_only_on_change() {
        let strategy = scalar_strategy();

        // Leg 1: no stored predecessor. The value is recorded, nothing is
        // emitted -- the subscriber asked to hear about CHANGES and nothing has
        // changed yet.
        let advance = strategy
            .derive(&json!({}), &json!({"tag_name": "v1.0.0", "id": 1}))
            .expect("first observation derives");
        assert!(
            advance.events.is_empty(),
            "a first observation with no threshold must baseline rather than emit: {:?}",
            advance.events
        );
        assert_eq!(
            advance.cursor_state,
            json!({"scalar": "v1.0.0", "scalar_ordinal": 0}),
            "the observed value must be stored so the next poll can compare"
        );

        // Leg 2: same value again. A cursor would advance; this must not speak.
        let advance = strategy
            .derive(
                &advance.cursor_state,
                &json!({"tag_name": "v1.0.0", "id": 1}),
            )
            .expect("unchanged observation derives");
        assert!(
            advance.events.is_empty(),
            "an unchanged scalar must emit nothing, or the watch fires every tick"
        );

        // Leg 3: the value moves. One event, carrying the whole response so a
        // consumer can render it without a second call.
        let advance = strategy
            .derive(
                &advance.cursor_state,
                &json!({"tag_name": "v1.1.0", "id": 2}),
            )
            .expect("changed observation derives");
        assert_eq!(advance.events.len(), 1, "a changed scalar must emit once");
        assert_eq!(
            advance.events[0].vendor_event_id, "1:v1.1.0",
            "the event identity must distinguish the transition as well as its value"
        );
        assert_eq!(
            advance.events[0].payload,
            json!({"tag_name": "v1.1.0", "id": 2}),
            "the payload must carry the whole vendor response"
        );
        assert_eq!(
            advance.cursor_state,
            json!({"scalar": "v1.1.0", "scalar_ordinal": 1})
        );
    }

    /// A seeded scalar is the threshold, and it makes the first observation
    /// meaningful rather than silent.
    ///
    /// This is how "tell me when it goes past X" is expressed without a new
    /// field: `subscribe` already accepts a starting cursor state, so seeding
    /// the scalar states the value the subscriber has already seen. Without this
    /// leg, baseline-on-first would be indistinguishable from ignoring the seed.
    #[test]
    fn a_seeded_scalar_emits_on_the_first_poll_when_it_has_already_moved() {
        let strategy = scalar_strategy();
        let advance = strategy
            .derive(&json!({"scalar": "v1.0.0"}), &json!({"tag_name": "v2.0.0"}))
            .expect("seeded observation derives");
        assert_eq!(
            advance.events.len(),
            1,
            "a seeded watch whose value already moved must report on its first poll"
        );
        assert_eq!(advance.events[0].vendor_event_id, "1:v2.0.0");
    }

    /// A missing or null scalar field is refused, never read as "unchanged".
    ///
    /// The two are indistinguishable downstream -- both leave the log quiet --
    /// so a misdeclared field name would make the watch report healthy silence
    /// forever while observing nothing. Refusing turns a silent misconfiguration
    /// into a vendor failure the scheduler backs off and reports.
    ///
    /// Mutation-proved: returning the stored state unchanged instead of an error
    /// fails both legs.
    #[test]
    fn an_absent_or_null_scalar_is_refused_rather_than_read_as_unchanged() {
        let strategy = scalar_strategy();
        let error = strategy
            .derive(&json!({}), &json!({"name": "v1.0.0"}))
            .expect_err("a response without the declared field must refuse");
        assert!(
            matches!(error, CursorError::InvalidResponse(ref message) if message.contains("tag_name")),
            "the refusal must name the field the manifest declared: {error:?}"
        );

        let error = strategy
            .derive(&json!({}), &json!({"tag_name": null}))
            .expect_err("a null value must refuse");
        assert!(
            matches!(error, CursorError::InvalidResponse(ref message) if message.contains("null")),
            "a null scalar must be refused as uncomparable: {error:?}"
        );
    }

    /// The strategy requires its declared field and owns no request keys.
    ///
    /// No default is possible for the field: a wrong name reads as unchanged
    /// forever. And owning no keys is what makes this shape different from a
    /// cursor -- there is no window argument a subscription could collide with,
    /// so `fixed_args` may carry anything the vendor's schema accepts.
    #[test]
    fn the_strategy_needs_its_field_and_reserves_no_request_keys() {
        assert!(
            ScalarDiffStrategy::new(None).is_none(),
            "no poll shape means no strategy"
        );
        let mut bare = scalar_shape();
        bare.scalar_field = None;
        assert!(
            ScalarDiffStrategy::new(Some(&bare)).is_none(),
            "a shape without scalar_field must not resolve to a guessing strategy"
        );
        bare.scalar_field = Some("   ".to_string());
        assert!(
            ScalarDiffStrategy::new(Some(&bare)).is_none(),
            "a blank field name must not resolve either"
        );

        assert!(
            strategy_for("scalar_diff", Some(&scalar_shape())).is_some(),
            "the kind must be reachable through the resolver the poller uses"
        );
        assert!(
            strategy_for("scalar_diff", None).is_none(),
            "the resolver must refuse the kind without a declared shape"
        );
        assert_eq!(
            scalar_strategy().state_keys(),
            vec!["scalar", "scalar_ordinal"]
        );
        assert!(
            scalar_strategy().owned_keys().is_empty(),
            "a shape with no window owns no request keys"
        );
        assert_eq!(
            scalar_strategy()
                .build_args(&json!({"scalar": "v1.0.0"}))
                .expect("build args"),
            json!({}),
            "the request must carry no cursor arguments at all"
        );
    }
}

#[cfg(test)]
mod sorted_head_tests {
    use super::*;

    /// The shape a manifest must declare for this kind, matching what
    /// `list_pull_requests` actually needs.
    fn head_shape(items_field: Option<&str>) -> PollShape {
        PollShape {
            cursor_kind: crate::manifest::CursorKind::SortedHead,
            token_field: None,
            request_token_field: None,
            items_field: items_field.map(str::to_string),
            timestamp_field: Some("updated_at".to_string()),
            tiebreaker_id_field: Some("number".to_string()),
            item_count_ceiling: None,
            item_kind: "issue".to_string(),
            pagination: None,
            request_page_size_field: Some("perPage".to_string()),
            request_since_field: None,
            request_constants: Some(std::collections::BTreeMap::from([(
                "perPage".to_string(),
                json!(2),
            )])),
            scalar_field: None,
        }
    }

    fn strategy(items_field: Option<&str>) -> SortedHeadStrategy {
        SortedHeadStrategy::new(Some(&head_shape(items_field))).expect("sorted head strategy")
    }

    fn item(number: i64, updated: &str) -> Value {
        json!({"number": number, "updated_at": updated, "title": format!("pr {number}")})
    }

    /// A BARE ARRAY response is read, and so is an enveloped one.
    ///
    /// Measured on the live GitHub MCP server: `list_pull_requests` answers a
    /// bare `[...]` while `list_issues` answers `{issues, totalCount, pageInfo}`
    /// — the same server, the same session. Every other list strategy here calls
    /// `as_object()` first and would suspend a pull-request watch on shape
    /// before any cursor logic ran, which is why `items_field` is optional for
    /// this kind alone.
    ///
    /// Mutation-proved: requiring an object fails the bare-array leg; ignoring a
    /// declared items_field and always treating the response as the array fails
    /// the enveloped leg.
    #[test]
    fn both_response_envelopes_are_read() {
        let bare = json!([item(1, "2026-08-13T10:00:00Z")]);
        let advance = strategy(None)
            .derive(&json!({}), &bare)
            .expect("a bare array must be readable");
        assert_eq!(advance.events.len(), 1, "the bare array item must be seen");

        let wrapped = json!({"items": [item(1, "2026-08-13T10:00:00Z")], "totalCount": 1});
        let advance = strategy(Some("items"))
            .derive(&json!({}), &wrapped)
            .expect("an enveloped array must be readable");
        assert_eq!(advance.events.len(), 1, "the enveloped item must be seen");

        // The declaration is not advisory: a strategy told to expect an envelope
        // must refuse a bare array rather than silently read it, or a manifest
        // typo would look like a working watch.
        assert!(
            strategy(Some("items")).derive(&json!({}), &bare).is_err(),
            "a declared items_field must not silently accept a bare array"
        );
    }

    /// Strictly newer items remain established events, while equality at the
    /// watermark is now a replay candidate resolved by stored content.
    ///
    /// The old contract excluded equality outright. That is unsafe for vendors
    /// whose update timestamp has only second resolution: content can change while
    /// the timestamp remains fixed. Unchanged boundary content is still removed so
    /// an idle head does not look active or consume enrichment work.
    ///
    /// Mutation-proved: restoring the strict-greater-only filter loses id `2` from
    /// the changed-boundary leg; ignoring the content result leaves id `2` in the
    /// unchanged-boundary leg.
    #[test]
    fn strictly_past_items_and_changed_boundary_items_are_emitted() {
        let page = json!([
            item(3, "2026-08-13T12:00:00Z"),
            item(2, "2026-08-13T11:00:00Z"),
            item(1, "2026-08-13T10:00:00Z"),
        ]);
        let state = json!({
            "watermark_ms": iso8601::parse_to_millis("2026-08-13T11:00:00Z").unwrap(),
            "watermark_id": "2"
        });
        let mut unchanged = strategy(None).derive(&state, &page).expect("derive");
        assert_eq!(
            unchanged
                .events
                .iter()
                .map(|event| (event.vendor_event_id.as_str(), event.replay_candidate))
                .collect::<Vec<_>>(),
            vec![("3", false), ("2", true)],
            "newer items are established and the boundary is explicitly marked"
        );
        retain_changed_replay_candidates(
            &mut unchanged.events,
            &mut unchanged.dropped,
            |_candidates| Ok::<Vec<bool>, ()>(vec![true]),
        );
        assert_eq!(
            unchanged
                .events
                .iter()
                .map(|event| event.vendor_event_id.as_str())
                .collect::<Vec<_>>(),
            vec!["3"],
            "unchanged boundary content must be filtered"
        );

        let mut edited_page = page;
        edited_page[1]["title"] = json!("edited within the same second");
        let mut changed = strategy(None)
            .derive(&state, &edited_page)
            .expect("derive edited boundary");
        retain_changed_replay_candidates(
            &mut changed.events,
            &mut changed.dropped,
            |_candidates| Ok::<Vec<bool>, ()>(vec![false]),
        );
        assert_eq!(
            changed
                .events
                .iter()
                .map(|event| event.vendor_event_id.as_str())
                .collect::<Vec<_>>(),
            vec!["3", "2"],
            "changed boundary content must survive alongside strictly newer items"
        );
        assert_eq!(
            changed.cursor_state["watermark_id"], "3",
            "the watermark must advance to the newest item on the page"
        );
    }

    #[test]
    fn disappeared_newest_item_keeps_watermark_pair_and_excludes_older_head() {
        let strategy = strategy(None);
        let prior = json!({"watermark_ms": iso8601::parse_to_millis("2026-08-13T10:00:00Z").unwrap(), "watermark_id":"9"});
        let page = json!([item(2, "2026-08-12T10:00:00Z")]);
        let first = strategy.derive(&prior, &page).unwrap();
        assert_eq!(first.cursor_state, prior);
        assert!(first.events.is_empty());
        let second = strategy.derive(&first.cursor_state, &page).unwrap();
        assert!(second.events.is_empty());
        // A lower id at the same instant must not replace the paired id either.
        let tied = strategy
            .derive(&prior, &json!([item(2, "2026-08-13T10:00:00Z")]))
            .unwrap();
        assert_eq!(tied.cursor_state, prior);
    }

    /// Items outside the replay window remain excluded from historical rescans.
    #[test]
    fn items_older_than_the_watermark_remain_excluded() {
        let state = json!({
            "watermark_ms": iso8601::parse_to_millis("2026-08-13T11:00:00Z").unwrap(),
            "watermark_id": "2"
        });
        let advance = strategy(None)
            .derive(
                &state,
                &json!([
                    item(2, "2026-08-13T11:00:00Z"),
                    item(1, "2026-08-13T10:58:59Z")
                ]),
            )
            .expect("derive boundary and older item");
        assert_eq!(advance.events.len(), 1, "only the boundary is reconsidered");
        assert_eq!(advance.events[0].vendor_event_id, "2");
        assert!(advance.events[0].replay_candidate);
    }

    /// A page whose OLDEST item is still newer than the watermark records a
    /// coverage gap.
    ///
    /// This is the honest cost of reading a sorted head instead of a filtered
    /// window. If more items change between two polls than fit on one page, the
    /// surplus falls off the bottom, and because the watermark advances to the
    /// newest item no later poll will ever ask for it again. That is silent
    /// event loss and it is invisible from outside: the feed keeps delivering,
    /// just not everything.
    ///
    /// It is detectable exactly when the whole page is new, which is what this
    /// asserts. The gap does not stop the poll — the items that DID arrive are
    /// real and must be delivered — it records what could not be established.
    ///
    /// Mutation-proved: returning `None` unconditionally fails the saturated
    /// leg; dropping the `oldest > watermark` condition reports a gap on the
    /// partial page and fails the second leg.
    #[test]
    fn a_saturated_page_records_a_coverage_gap() {
        let watermark_ms = iso8601::parse_to_millis("2026-08-13T09:00:00Z").unwrap();
        let state = json!({"watermark_ms": watermark_ms, "watermark_id": "1"});

        // Every item newer than the watermark: the page may have been cut short.
        let full = json!([
            item(9, "2026-08-13T12:00:00Z"),
            item(8, "2026-08-13T11:00:00Z"),
        ]);
        let advance = strategy(None).derive(&state, &full).expect("derive");
        let gap = advance
            .coverage_gap
            .expect("a fully-new page must report a coverage gap");
        assert_eq!(gap.reason, "sorted_head_page_saturated");
        assert_eq!(gap.from_ms, watermark_ms, "the gap starts at the watermark");
        assert_eq!(
            gap.to_ms,
            iso8601::parse_to_millis("2026-08-13T11:00:00Z").unwrap(),
            "the gap ends at the oldest item actually seen"
        );
        assert_eq!(
            advance.events.len(),
            2,
            "a gap must not suppress the events that did arrive"
        );

        // A page reaching back past the watermark proves nothing was missed.
        let partial = json!([
            item(9, "2026-08-13T12:00:00Z"),
            item(1, "2026-08-13T08:00:00Z"),
        ]);
        assert!(
            strategy(None)
                .derive(&state, &partial)
                .expect("derive")
                .coverage_gap
                .is_none(),
            "a page reaching past the watermark establishes coverage"
        );
    }

    #[test]
    fn a_full_page_ending_at_the_watermark_records_a_gap() {
        let watermark_ms = iso8601::parse_to_millis("2026-08-13T09:00:00Z").unwrap();
        let state = json!({"watermark_ms": watermark_ms, "watermark_id": "1"});
        // Another edited item at 09:00 may be beyond this two-item page.
        let page = json!([
            item(9, "2026-08-13T12:00:00Z"),
            item(1, "2026-08-13T09:00:00Z"),
        ]);
        let advance = strategy(None).derive(&state, &page).expect("derive");
        let gap = advance
            .coverage_gap
            .expect("a full boundary page cannot prove coverage");
        assert_eq!(gap.reason, "sorted_head_page_saturated");
        assert_eq!(gap.from_ms, watermark_ms);
        assert_eq!(gap.to_ms, watermark_ms);
        assert_eq!(advance.events.len(), 2);
    }

    #[test]
    fn a_full_page_reaching_before_the_watermark_records_no_gap() {
        let watermark_ms = iso8601::parse_to_millis("2026-08-13T09:00:00Z").unwrap();
        let state = json!({"watermark_ms": watermark_ms, "watermark_id": "1"});
        let page = json!([
            item(9, "2026-08-13T12:00:00Z"),
            item(1, "2026-08-13T08:00:00Z"),
        ]);
        assert!(strategy(None)
            .derive(&state, &page)
            .expect("derive")
            .coverage_gap
            .is_none());
    }

    #[test]
    fn a_short_page_records_no_gap_at_any_boundary_position() {
        let watermark_ms = iso8601::parse_to_millis("2026-08-13T09:00:00Z").unwrap();
        let state = json!({"watermark_ms": watermark_ms, "watermark_id": "1"});
        for timestamp in [
            "2026-08-13T08:00:00Z",
            "2026-08-13T09:00:00Z",
            "2026-08-13T10:00:00Z",
        ] {
            let page = json!([item(9, timestamp)]);
            assert!(
                strategy(None)
                    .derive(&state, &page)
                    .expect("derive")
                    .coverage_gap
                    .is_none(),
                "a short page is complete even when its oldest timestamp is {timestamp}"
            );
        }
    }

    /// The FIRST poll never reports a gap, and an empty page advances nothing.
    ///
    /// With no prior watermark every item is new by definition, so the
    /// saturation test would fire on every first poll and cry wolf on a watch
    /// that is working correctly. An empty page has no maximum to advance to,
    /// so the state must survive unchanged or the next poll would compare
    /// against nothing and re-emit the whole page.
    ///
    /// Mutation-proved: dropping the prior-watermark condition fails the first
    /// leg; returning a fresh state on an empty page fails the second.
    #[test]
    fn a_first_poll_and_an_empty_page_report_no_gap() {
        let advance = strategy(None)
            .derive(&json!({}), &json!([item(1, "2026-08-13T10:00:00Z")]))
            .expect("derive");
        assert!(
            advance.coverage_gap.is_none(),
            "a first poll has no coverage claim to violate"
        );
        assert_eq!(advance.events.len(), 1, "a first poll backfills its page");

        let state = json!({"watermark_ms": 1_700_000_000_000i64, "watermark_id": "7"});
        let advance = strategy(None).derive(&state, &json!([])).expect("derive");
        assert!(advance.events.is_empty(), "an empty page emits nothing");
        assert!(
            advance.coverage_gap.is_none(),
            "an empty page cannot be saturated"
        );
        assert_eq!(
            advance.cursor_state, state,
            "an empty page must not move the watermark"
        );
    }

    /// An item missing its declared timestamp or tiebreaker fails the whole
    /// derive rather than being skipped.
    ///
    /// Same discipline as every other list strategy here: a silently skipped
    /// item is a lost event, and the caller suspends so the gap is visible.
    ///
    /// Mutation-proved: skipping malformed items instead of failing turns both
    /// legs green.
    #[test]
    fn a_malformed_item_refuses_the_whole_page() {
        let missing_ts = json!([json!({"number": 1})]);
        assert!(
            strategy(None).derive(&json!({}), &missing_ts).is_err(),
            "an item with no timestamp must refuse the page"
        );
        let missing_id = json!([json!({"updated_at": "2026-08-13T10:00:00Z"})]);
        assert!(
            strategy(None).derive(&json!({}), &missing_id).is_err(),
            "an item with no tiebreaker must refuse the page"
        );
    }
}
