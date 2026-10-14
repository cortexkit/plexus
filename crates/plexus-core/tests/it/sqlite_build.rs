#[test]
fn bundled_sqlite_disables_global_memory_statistics_by_default() {
    let connection = rusqlite::Connection::open_in_memory().expect("open SQLite memory connection");
    let disabled: i64 = connection
        .query_row(
            "SELECT sqlite_compileoption_used('DEFAULT_MEMSTATUS=0')",
            [],
            |row| row.get(0),
        )
        .expect("read SQLite compile option");
    assert_eq!(
        disabled, 1,
        "bundled SQLite must disable global memory statistics: keep the .cargo/config.toml \
         LIBSQLITE3_FLAGS = \"-DSQLITE_DEFAULT_MEMSTATUS=0\" line"
    );
}
