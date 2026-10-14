//! Test access to example relayed tool calls (test vectors) copied from the
//! Prefrontal repository into `tests/fixtures/fetch-plan-v1/` (the README
//! there records the source commit and checksums).
//!
//! Prefrontal core relays tool calls onward to Plexus, and each relayed call
//! may state an `origin`: the module that carried the original call and that
//! call's own key. These vectors let Plexus's tests check that it accepts and
//! records exactly what Prefrontal sends. The `origin` of every vector passes
//! Plexus's checks as written. The vectors in [`RELAYED`] name tools Plexus
//! does not serve, so [`relayed_as`] keeps such a vector's `call_key` and
//! `origin` and swaps only the tool; [`WEB_SEARCH_FROM_OPENCODE_PLUGIN`]
//! names Plexus's own `web_search` and is sent unchanged.

use serde_json::{json, Value};

/// A `browser_use` call that Prefrontal core relayed on behalf of a call Broca
/// carried. Its `origin` names the carrier `reserved:broca` and Broca's own
/// key for that call, `lin_7f3a9c2e:42`.
pub(crate) const FROM_BROCA: &str =
    include_str!("../tests/fixtures/fetch-plan-v1/relayed-from-broca.json");
/// A `computer_use` call that Prefrontal core relayed on behalf of a call the
/// Claude Code bridge carried. Its `origin` names the carrier
/// `reserved:subc-mcp` and the bridge's key for that call, a `cc:toolu_...`
/// tool-use id.
pub(crate) const FROM_CLAUDE_CODE_BRIDGE: &str =
    include_str!("../tests/fixtures/fetch-plan-v1/relayed-from-claude-code-bridge.json");
/// A `browser_use` call that Prefrontal core relayed on behalf of an OpenCode
/// plugin call. The plugin gives its calls no key, so this call has no
/// `origin` at all, only the relay's own top-level `call_key`.
pub(crate) const FROM_OPENCODE_PLUGIN: &str =
    include_str!("../tests/fixtures/fetch-plan-v1/relayed-from-opencode-plugin.json");
/// A web-search call relayed by Prefrontal for an OpenCode session. Search
/// arguments are forwarded unchanged, with a relay-generated `pf:` call key
/// and no origin. The retired identity token is omitted; tests deliver the
/// agent's session stamp separately from the JSON payload.
pub(crate) const WEB_SEARCH_FROM_OPENCODE_PLUGIN: &str =
    include_str!("../tests/fixtures/fetch-plan-v1/relayed-web-search-from-opencode-plugin.json");
/// `pf:` call keys, the form Prefrontal core puts on the calls it relays,
/// split into `valid` and `invalid` lists; each invalid key names the rule
/// that refuses it. Tests send them as `origin.call_key` to check that
/// Plexus's key validation accepts and refuses the same keys the protocol's
/// `validate_call_key` does.
pub(crate) const PF_CALL_KEYS: &str =
    include_str!("../tests/fixtures/fetch-plan-v1/pf-call-keys.json");

/// Every relayed-call vector that names a tool Plexus does not serve
/// (`browser_use`, `computer_use`), labelled.
pub(crate) const RELAYED: [(&str, &str); 3] = [
    ("broca", FROM_BROCA),
    ("claude-code-bridge", FROM_CLAUDE_CODE_BRIDGE),
    ("opencode-plugin", FROM_OPENCODE_PLUGIN),
];

pub(crate) fn parse(vector: &str) -> Value {
    serde_json::from_str(vector).expect("pinned vector is JSON")
}

/// The vector's `origin` as Plexus records it, `(carrier, call_key)`.
///
/// The vector writes the carrier as a principal object; Plexus stores it in
/// the principal's text form, `reserved:<module_id>`. That form is spelled
/// out here rather than computed by Plexus's own conversion, so a fault in
/// that conversion cannot also produce the expected value. Only reserved
/// carriers occur in the vectors.
pub(crate) fn recorded_origin(vector: &Value) -> Option<(String, String)> {
    vector.get("origin").map(|origin| {
        let carrier = &origin["carrier"];
        assert_eq!(carrier["kind"], "reserved", "vector carrier {carrier}");
        let module_id = carrier["module_id"].as_str().expect("module_id");
        (
            format!("reserved:{module_id}"),
            origin["call_key"].as_str().expect("call_key").to_string(),
        )
    })
}

/// The vector's envelope, its top-level `call_key` and `origin` exactly as
/// written, on a call to the Plexus tool `name` with `arguments`.
pub(crate) fn relayed_as(vector: &Value, name: &str, arguments: Value) -> Value {
    let mut call = vector.clone();
    call["name"] = json!(name);
    call["arguments"] = arguments;
    call
}
