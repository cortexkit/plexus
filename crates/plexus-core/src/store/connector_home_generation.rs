use super::*;

const ROLE: &str = "connector_home";

fn highest(conn: &rusqlite::Connection) -> rusqlite::Result<Option<u64>> {
    conn.query_row(
        "SELECT highest_gen FROM connector_home_generation WHERE role = ?1",
        [ROLE],
        |row| {
            row.get::<_, String>(0)?.parse().map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        },
    )
    .optional()
}

impl PlexusStore {
    /// Compare and advance the connector-home fence without losing a wire u64
    /// to SQLite's signed integer range. A failed fence never grants admission.
    pub fn observe_connector_home_generation(&self, generation: u64) -> Result<bool, StoreError> {
        let accepted = self.inner.with_conn_fenced(|conn| {
            if let Some(previous) = highest(conn)? {
                if generation <= previous {
                    return Ok(generation == previous);
                }
            }
            conn.execute(
                "INSERT INTO connector_home_generation(role, highest_gen) VALUES (?1, ?2)
                 ON CONFLICT(role) DO UPDATE SET highest_gen = excluded.highest_gen",
                rusqlite::params![ROLE, generation.to_string()],
            )?;
            Ok(true)
        })?;
        Ok(accepted)
    }
}
