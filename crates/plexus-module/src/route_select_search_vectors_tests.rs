//! Routing's recorded `route.select` search pairs, replayed through the
//! request builder and reply reader plexus searches with. The pairs are
//! vendored byte for byte in `tests/fixtures/route-select-search-v1/`.

use plexus_core::web_search::routing::{self, RouteRef, RoutingCallError, SelectOutcome};
use serde_json::Value;

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/route-select-search-v1"
);
const PAIRS: [&str; 4] = [
    "01-allowance-wins.json",
    "02-paid-clears-level.json",
    "03-empty-subset.json",
    "04-refused-requirement.json",
];

fn read(name: &str) -> Vec<u8> {
    std::fs::read(format!("{DIR}/{name}")).unwrap()
}

/// The exact request and reply bytes a pair encloses, cut from the file
/// without reserializing either.
fn raw_pair(name: &str) -> (String, String) {
    let text = String::from_utf8(read(name)).unwrap();
    let text = text.trim_end();
    let body = text
        .strip_prefix("{\"request\":")
        .and_then(|rest| rest.strip_suffix('}'))
        .unwrap_or_else(|| panic!("{name} is not a request/reply pair"));
    let (request, reply) = body
        .split_once(",\"reply\":")
        .unwrap_or_else(|| panic!("{name} has no reply"));
    (request.to_owned(), reply.to_owned())
}

/// The routes a recorded request offers, in the order it lists them.
fn routes(request: &Value, member: &str) -> Vec<RouteRef> {
    request["params"][member]
        .as_array()
        .unwrap()
        .iter()
        .map(|route| {
            RouteRef::new(
                route["provider"].as_str().unwrap(),
                route["model"].as_str().unwrap(),
            )
        })
        .collect()
}

/// A recorded reply as the routing peer hands it to plexus: a result body,
/// or a refusal's code, message and detail.
fn as_peer_reply(reply: &str) -> Result<Value, RoutingCallError> {
    let body: Value = serde_json::from_str(reply).unwrap();
    match body.get("code").and_then(Value::as_str) {
        Some(code) => Err(RoutingCallError::Refused {
            code: code.to_owned(),
            message: body["message"].as_str().unwrap().to_owned(),
            detail: body["detail"].clone(),
        }),
        None => Ok(body),
    }
}

#[test]
fn vendored_pairs_match_their_checksums() {
    let sums = read("SHA256SUMS");
    assert_eq!(
        plexus_core::jcs::sha256_hex(&sums),
        "94fedafb7e06c54e9a2a174c2312180af9cc421b36dd194d9870281a9b293745",
        "SHA256SUMS is the file published with tag route-select-search-v1"
    );
    let sums = String::from_utf8(sums).unwrap();
    let listed = sums
        .lines()
        .map(|line| {
            let (digest, name) = line.split_once("  ").unwrap();
            (name.to_owned(), digest.to_owned())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        listed.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(),
        PAIRS
    );
    for (name, digest) in listed {
        assert_eq!(plexus_core::jcs::sha256_hex(&read(&name)), digest, "{name}");
    }
}

#[test]
fn plexus_builds_each_recorded_select_byte_for_byte() {
    for name in &PAIRS[..3] {
        let (request, _) = raw_pair(name);
        let recorded: Value = serde_json::from_str(&request).unwrap();
        let built = routing::select_request(
            &routes(&recorded, "eligible_routes"),
            &routes(&recorded, "allowance_left"),
        );
        assert_eq!(
            String::from_utf8(serde_json::to_vec(&built).unwrap()).unwrap(),
            request,
            "{name}"
        );
    }
}

#[test]
fn plexus_never_sends_the_refused_requirement() {
    // The fourth pair shows routing refusing a `format` requirement by name.
    // Plexus's select carries only the demand level, so for the same routes
    // its request is the recorded one without `format`.
    let (request, reply) = raw_pair(PAIRS[3]);
    let mut recorded: Value = serde_json::from_str(&request).unwrap();
    let built = routing::select_request(
        &routes(&recorded, "eligible_routes"),
        &routes(&recorded, "allowance_left"),
    );
    recorded["params"]["requirements"]
        .as_object_mut()
        .unwrap()
        .remove("format")
        .unwrap();
    assert_eq!(built, recorded);
    // Were routing to refuse a select this way, it is not "no provider can
    // serve": plexus refuses the search as routing being unavailable.
    assert!(matches!(
        routing::read_select_reply(as_peer_reply(&reply)),
        SelectOutcome::Unavailable(_)
    ));
}

#[test]
fn plexus_reads_each_recorded_answer() {
    let outcome = |name| routing::read_select_reply(as_peer_reply(&raw_pair(name).1));
    assert_eq!(
        outcome(PAIRS[0]),
        SelectOutcome::Selected(routing::Selection {
            decision_id: "dec_000000000000".into(),
            route: RouteRef::new("search-fixture", "allowance"),
        })
    );
    assert_eq!(
        outcome(PAIRS[1]),
        SelectOutcome::Selected(routing::Selection {
            decision_id: "dec_000000000001".into(),
            route: RouteRef::new("search-fixture", "paid"),
        })
    );
    assert_eq!(
        outcome(PAIRS[2]),
        SelectOutcome::NoRoute {
            reason: Some("no_available_model".into())
        }
    );
}
