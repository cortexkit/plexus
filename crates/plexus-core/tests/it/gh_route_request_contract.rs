//! Proves the `gh.route` request contract vectors in
//! `tests/fixtures/gh_shim_wire/requests-contract/` against the real
//! `request_map::map`, the step of the bot-request facade that decides whether
//! a request's shape is accepted. AFT, the repository whose `gh` shim sends
//! these requests, pins its shim tests to these files, so a vector whose
//! expectation disagrees with plexus must fail here.
use plexus_core::github::facade::{effects, request_map};
use plexus_core::github::resolver::{Binding, ResolvedRepositories};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

/// The fields the gh shim stamps on every request. Each vector carries all
/// of them, so a refused vector differs from an accepted one only in the field
/// its name describes, and an accepted vector is what the shim really sends.
const SHIM_ENVELOPE: [&str; 5] = [
    "operation",
    "gh_route_schema",
    "manifest_version",
    "rung_as_of_unix_secs",
    "metadata",
];

/// Repository selectors `map` refuses on every request kind. A vector for
/// each must exist, so the gh shim's tests in AFT see each one refused by its
/// exact code.
const UNIVERSALLY_FORBIDDEN: [&str; 6] = [
    "owner",
    "repo",
    "full_name",
    "repositories",
    "target_repository",
    "path_repository",
];

#[test]
fn gh_route_request_contract_vectors_match_request_map() {
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gh_shim_wire/requests-contract");
    let mut entries: Vec<_> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    assert!(
        !entries.is_empty(),
        "{} holds no vectors",
        directory.display()
    );

    let mut accepted_kinds = BTreeSet::new();
    let mut refusal_codes = BTreeSet::new();
    for path in &entries {
        let file = path.display();
        assert_eq!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("json"),
            "{file}: every file in the directory is a vector"
        );
        let vector: Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap_or_else(|error| {
                panic!("{file}: {error}");
            });
        let keys: BTreeSet<&str> = vector
            .as_object()
            .unwrap_or_else(|| panic!("{file}: a vector is an object"))
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            BTreeSet::from(["name", "request", "expect"]),
            "{file}"
        );
        assert_eq!(
            vector["name"].as_str(),
            path.file_stem().and_then(|stem| stem.to_str()),
            "{file}: name must equal the file name"
        );
        let request = &vector["request"];
        for field in SHIM_ENVELOPE {
            assert!(
                request.get(field).is_some(),
                "{file}: request lacks the shim envelope field {field}"
            );
        }
        // The facade takes the repository from the request and builds the
        // resolved selection from its binding before calling map; this is
        // the same call with that binding present.
        let repository = request["repository"]
            .as_str()
            .unwrap_or_else(|| panic!("{file}: request names no repository"));
        let resolved = ResolvedRepositories {
            repositories: vec![repository.into()],
            binding: Binding {
                app_handle_id: "app-fixture".into(),
                connection_id: "conn-fixture".into(),
            },
        };
        let outcome = request_map::map(request, &resolved, repository);
        let expect = &vector["expect"];
        let expect_keys: Vec<&String> = expect.as_object().unwrap().keys().collect();
        assert_eq!(expect_keys.len(), 1, "{file}: expect names one outcome");
        if let Some(code) = expect.get("refused") {
            let code = code
                .as_str()
                .unwrap_or_else(|| panic!("{file}: refused is a code"));
            assert_eq!(
                outcome.as_ref().map(|mapped| &mapped.request_kind),
                Err(&code.to_owned()),
                "{file}"
            );
            refusal_codes.insert(code.to_owned());
        } else {
            assert_eq!(
                expect["accepted"], true,
                "{file}: expect is accepted or refused"
            );
            let mapped = outcome.unwrap_or_else(|code| panic!("{file}: refused {code}"));
            assert!(
                effects::REQUEST_KINDS.contains(&mapped.request_kind.as_str()),
                "{file}: {} is not a routed kind",
                mapped.request_kind
            );
            accepted_kinds.insert(mapped.request_kind);
        }
    }

    let missing: Vec<_> = effects::REQUEST_KINDS
        .iter()
        .filter(|kind| !accepted_kinds.contains(**kind))
        .collect();
    assert!(
        missing.is_empty(),
        "request kinds with no accepted vector: {missing:?}"
    );
    for field in UNIVERSALLY_FORBIDDEN {
        let code = format!("request_field_forbidden{{field: {field}}}");
        assert!(refusal_codes.contains(&code), "no vector refuses {field}");
    }
    assert!(
        refusal_codes.contains("request_kind_unmapped"),
        "no vector for an unmapped kind"
    );
}
