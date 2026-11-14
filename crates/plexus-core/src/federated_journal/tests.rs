use super::*;
use crate::test_scratch::Scratch;

fn record(id: &str) -> String {
    format!(r#"{{"row_id":"{id}","card_refs":["el_mint"],"deleted_at_ms":1}}"#)
}

fn read(path: &Path) -> Vec<Deletion> {
    let mut entries = Vec::new();
    scan(path, |entry| {
        entries.push(entry);
        Ok(())
    })
    .unwrap();
    entries
}

#[test]
fn malformed_complete_records_are_never_skipped() {
    for line in [
        "not json".to_string(),
        String::new(),
        r#"{"row_id":"plxf_a","card_refs":[],"deleted_at_ms":1,"unknown":true}"#.into(),
        r#"{"row_id":"","card_refs":[],"deleted_at_ms":1}"#.into(),
        r#"{"row_id":null,"card_refs":[],"deleted_at_ms":1}"#.into(),
        r#"{"row_id":null,"card_refs":[""],"deleted_at_ms":1}"#.into(),
    ] {
        for contents in [
            format!("{line}\n"),
            format!("{}\n{line}\n{}", record("plxf_a"), record("plxf_b")),
        ] {
            let scratch = Scratch::file("federated-malformed", NAME);
            std::fs::write(scratch.path(), contents).unwrap();
            assert!(scan(scratch.path(), |_| Ok(())).is_err());
        }
    }
}

#[test]
fn append_recovers_torn_tails_and_preserves_parseable_tails() {
    for prefix in [String::new(), format!("{}\n", record("plxf_a"))] {
        for tail in [
            "{\"row_id\":\"plxf_torn".into(),
            record("plxf_tail"),
            "x".repeat(9000),
        ] {
            let scratch = Scratch::file("federated-append-tail", NAME);
            std::fs::write(scratch.path(), format!("{prefix}{tail}")).unwrap();
            let before = read(scratch.path());
            append(
                scratch.path(),
                &Deletion {
                    row_id: Some("plxf_next".into()),
                    card_refs: vec!["el_next".into()],
                    deleted_at_ms: 2,
                },
            )
            .unwrap();
            let after = read(scratch.path());
            let mut expected: Vec<_> = before.iter().map(|entry| entry.row_id.as_deref()).collect();
            expected.push(Some("plxf_next"));
            assert_eq!(
                after
                    .iter()
                    .map(|entry| entry.row_id.as_deref())
                    .collect::<Vec<_>>(),
                expected
            );
            let bytes = std::fs::read(scratch.path()).unwrap();
            assert_eq!(bytes.last(), Some(&b'\n'));
            assert_eq!(
                bytes.iter().filter(|byte| **byte == b'\n').count(),
                after.len()
            );
        }
    }
}

#[test]
fn scan_handles_missing_empty_and_rowless_journals() {
    let scratch = Scratch::file("federated-rowless", NAME);
    assert_eq!(scan(scratch.path(), |_| Ok(())).unwrap(), 0);
    crate::grant_journal::ensure(scratch.path()).unwrap();
    assert_eq!(scan(scratch.path(), |_| Ok(())).unwrap(), 0);
    append(
        scratch.path(),
        &Deletion {
            row_id: None,
            card_refs: vec!["el_orphan".into()],
            deleted_at_ms: 9,
        },
    )
    .unwrap();
    let bytes = std::fs::read_to_string(scratch.path()).unwrap();
    assert_eq!(
        bytes,
        "{\"row_id\":null,\"card_refs\":[\"el_orphan\"],\"deleted_at_ms\":9}\n"
    );
    assert_eq!(read(scratch.path()).len(), 1);
}

#[test]
fn visitor_errors_stop_replay() {
    let scratch = Scratch::file("federated-visitor-error", NAME);
    std::fs::write(
        scratch.path(),
        format!("{}\n{}\n", record("plxf_a"), record("plxf_b")),
    )
    .unwrap();
    let mut visits = 0;
    assert_eq!(
        scan(scratch.path(), |_| {
            visits += 1;
            Err("stop".into())
        }),
        Err("stop".into())
    );
    assert_eq!(visits, 1);
}
