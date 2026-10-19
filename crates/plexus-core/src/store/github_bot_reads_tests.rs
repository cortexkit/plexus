use super::*;

/// A fresh in-memory store. Each test names its own namespace: tests run in
/// parallel, and the store's lease is per namespace.
fn store(namespace: &str) -> PlexusStore {
    PlexusStore::open(&cortexkit_store_types::StorageDescriptor {
        module_id: "plexus".into(),
        storage_namespace: namespace.into(),
        isolation: cortexkit_store_types::Isolation::Module,
        backend: cortexkit_store_types::StorageBackend::Sqlite {
            path: ":memory:".into(),
        },
    })
    .unwrap()
}

#[test]
fn reads_past_the_hourly_cap_are_refused_until_the_oldest_ages_out() {
    let store = store("bot-read-cap");
    let start = 1_000_000;
    // 3,499 single reads, then one two-request read that takes the hour to
    // exactly 3,501 would not fit; the cap admits exactly 3,500.
    for offset in 0..3_499 {
        assert_eq!(
            store
                .reserve_github_bot_read("bot", 1, start + offset)
                .unwrap(),
            BotReadAdmission::Reserved
        );
    }
    assert_eq!(
        store
            .reserve_github_bot_read("bot", 2, start + 5_000)
            .unwrap(),
        BotReadAdmission::Exhausted {
            // The first read leaves the window an hour after it was sent.
            retry_after_ms: start + BOT_READ_WINDOW_MS - (start + 5_000),
        }
    );
    assert_eq!(
        store
            .reserve_github_bot_read("bot", 1, start + 5_000)
            .unwrap(),
        BotReadAdmission::Reserved
    );
    assert_eq!(
        store
            .reserve_github_bot_read("bot", 1, start + 5_001)
            .unwrap(),
        BotReadAdmission::Exhausted {
            retry_after_ms: start + BOT_READ_WINDOW_MS - (start + 5_001),
        }
    );
    // Another installation's handle has its own budget.
    assert_eq!(
        store
            .reserve_github_bot_read("other", 1, start + 5_001)
            .unwrap(),
        BotReadAdmission::Reserved
    );
    assert_eq!(
        store
            .github_bot_reads_in_window("bot", start + 5_001)
            .unwrap(),
        BOT_READ_HOURLY_CAP
    );
}

#[test]
fn ledger_entries_age_out_after_an_hour() {
    let store = store("bot-read-age-out");
    let start = 50_000_000;
    for offset in 0..BOT_READ_HOURLY_CAP {
        store
            .reserve_github_bot_read("bot", 1, start + offset)
            .unwrap();
    }
    let later = start + BOT_READ_WINDOW_MS + BOT_READ_HOURLY_CAP;
    assert_eq!(store.github_bot_reads_in_window("bot", later).unwrap(), 0);
    assert_eq!(
        store.reserve_github_bot_read("bot", 1, later).unwrap(),
        BotReadAdmission::Reserved
    );
    // Reserving deletes the aged-out rows rather than keeping them forever.
    assert_eq!(store.github_bot_read_ledger_rows().unwrap(), 1);
}

#[test]
fn reads_stop_while_github_reports_under_a_thousand_remaining() {
    let store = store("bot-read-remaining");
    let now = 10_000;
    store
        .record_github_bot_rate_limit(
            "bot",
            BotRateLimit {
                remaining: 999,
                reset_at_ms: now + 30_000,
            },
            now,
        )
        .unwrap();
    assert_eq!(
        store.reserve_github_bot_read("bot", 1, now + 1).unwrap(),
        BotReadAdmission::Exhausted {
            retry_after_ms: 29_999
        }
    );
    assert_eq!(
        store.reserve_github_bot_read("other", 1, now + 1).unwrap(),
        BotReadAdmission::Reserved,
        "another installation is unaffected"
    );
    // At GitHub's reset the old report no longer holds reads back.
    assert_eq!(
        store
            .reserve_github_bot_read("bot", 1, now + 30_000)
            .unwrap(),
        BotReadAdmission::Reserved
    );
    store
        .record_github_bot_rate_limit(
            "bot",
            BotRateLimit {
                remaining: 1_000,
                reset_at_ms: now + 90_000,
            },
            now + 30_001,
        )
        .unwrap();
    assert_eq!(
        store
            .reserve_github_bot_read("bot", 1, now + 30_002)
            .unwrap(),
        BotReadAdmission::Reserved,
        "exactly 1,000 remaining is not under the floor"
    );
}
