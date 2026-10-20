//! Additive fingerprint storage migrations, committed before a writer starts.

use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    tls::boring::core::sha::sha256,
};
use tokio_postgres::Client;

use super::postgres::bound_transaction;

const MIGRATION_LOCK: i64 = 0x7261_6d61_6670_7632;
const MIGRATIONS: &[&str] = &[
    include_str!("migrations/0001.sql"),
    include_str!("migrations/0002.sql"),
    include_str!("migrations/0003.sql"),
    include_str!("migrations/0004.sql"),
    include_str!("migrations/0005.sql"),
    include_str!("migrations/0006.sql"),
    include_str!("migrations/0007.sql"),
];

pub(super) async fn apply(client: &mut Client) -> Result<(), BoxError> {
    apply_scripts(client, MIGRATIONS).await
}

async fn apply_scripts(client: &mut Client, scripts: &[&str]) -> Result<(), BoxError> {
    let transaction = client.transaction().await.context("begin fp migration")?;
    bound_transaction(&transaction).await?;
    transaction
        .execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK])
        .await
        .context("lock fp migrations")?;
    transaction
        .batch_execute(
            "CREATE SCHEMA IF NOT EXISTS fp_v2;
             CREATE TABLE IF NOT EXISTS fp_v2.migrations (
                 version INTEGER PRIMARY KEY CHECK (version > 0),
                 checksum BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
             );",
        )
        .await
        .context("initialize fp migration ledger")?;
    let read_limit = i64::try_from(scripts.len())
        .context("fp migration count overflow")?
        .checked_add(1)
        .ok_or_else(|| BoxError::from_static_str("fp migration count overflow"))?;
    let applied = transaction
        .query(
            "SELECT version, checksum FROM fp_v2.migrations ORDER BY version LIMIT $1",
            &[&read_limit],
        )
        .await
        .context("read fp migrations")?;
    if applied.len() > scripts.len() {
        return Err(BoxError::from_static_str(
            "unsupported fp migration version",
        ));
    }
    for (index, row) in applied.iter().enumerate() {
        let version: i32 = row.try_get(0).context("decode fp migration version")?;
        let checksum: &[u8] = row.try_get(1).context("decode fp migration checksum")?;
        if usize::try_from(version).ok() != Some(index + 1)
            || checksum != sha256(scripts[index].as_bytes())
        {
            return Err(BoxError::from_static_str(
                "fp migration checksum or sequence mismatch",
            ));
        }
    }
    for (index, script) in scripts.iter().enumerate().skip(applied.len()) {
        let version = i32::try_from(index + 1).context("fp migration version overflow")?;
        transaction
            .batch_execute(script)
            .await
            .context("apply fp migration")?;
        let checksum = sha256(script.as_bytes());
        transaction
            .execute(
                "INSERT INTO fp_v2.migrations (version, checksum) VALUES ($1, $2)",
                &[&version, &&checksum[..]],
            )
            .await
            .context("record fp migration")?;
    }
    transaction.commit().await.context("commit fp migrations")
}

#[cfg(test)]
mod checksums {
    use super::*;

    #[test]
    fn schema_checksums_are_pinned() {
        let expected = [
            [
                87, 89, 109, 251, 246, 65, 255, 41, 232, 236, 6, 123, 111, 42, 225, 70, 120, 128,
                10, 89, 229, 116, 140, 122, 186, 49, 178, 31, 99, 171, 104, 104,
            ],
            [
                119, 20, 64, 71, 69, 68, 252, 207, 120, 82, 66, 176, 150, 145, 132, 154, 140, 197,
                65, 189, 20, 86, 42, 195, 62, 121, 206, 190, 247, 191, 118, 9,
            ],
            [
                183, 64, 249, 226, 219, 89, 61, 56, 249, 54, 16, 83, 54, 197, 79, 181, 24, 124, 32,
                210, 79, 7, 5, 22, 73, 90, 104, 95, 100, 116, 36, 233,
            ],
            [
                163, 92, 62, 116, 110, 231, 233, 178, 67, 184, 16, 188, 152, 178, 98, 237, 20, 44,
                203, 31, 53, 219, 11, 2, 253, 159, 176, 65, 42, 181, 98, 90,
            ],
            [
                202, 230, 16, 49, 70, 96, 32, 173, 248, 120, 27, 15, 167, 58, 160, 167, 253, 35,
                102, 118, 69, 214, 49, 242, 234, 229, 59, 3, 102, 81, 209, 35,
            ],
            [
                143, 69, 211, 44, 167, 204, 61, 101, 165, 208, 189, 164, 205, 44, 223, 28, 199, 74,
                237, 56, 244, 8, 101, 8, 119, 67, 2, 55, 176, 4, 160, 177,
            ],
            [
                60, 74, 11, 213, 17, 221, 133, 154, 5, 86, 210, 175, 108, 242, 240, 210, 28, 29,
                86, 180, 155, 161, 29, 247, 94, 49, 162, 200, 73, 200, 98, 200,
            ],
        ];
        assert_eq!(MIGRATIONS.len(), expected.len());
        for (script, expected) in MIGRATIONS.iter().zip(expected) {
            assert_eq!(sha256(script.as_bytes()), expected);
        }
    }
}
