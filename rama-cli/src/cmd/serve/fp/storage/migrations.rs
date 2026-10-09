//! Additive fingerprint storage migrations, committed before a writer starts.

use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    tls::boring::core::sha::sha256,
};
use tokio_postgres::Client;

const MIGRATION_LOCK: i64 = 0x7261_6d61_6670_7632;
const MIGRATIONS: &[&str] = &[include_str!("migrations/0001.sql")];

pub(super) async fn apply(client: &mut Client) -> Result<(), BoxError> {
    apply_scripts(client, MIGRATIONS).await
}

async fn apply_scripts(client: &mut Client, scripts: &[&str]) -> Result<(), BoxError> {
    let transaction = client.transaction().await.context("begin fp migration")?;
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

#[cfg(all(test, unix))]
mod tests {
    use std::{env, time::Duration};

    use tokio::{task::JoinSet, time::timeout};
    use tokio_postgres::{Config, NoTls, config::Host, error::SqlState};

    use super::*;

    async fn connect(config: &Config) -> Result<Client, BoxError> {
        let (client, connection) = config.connect(NoTls).await?;
        tokio::spawn(connection);
        Ok(client)
    }

    /// The harness starts a private Unix-socket-only PostgreSQL cluster with this marker.
    /// No test accepts a network host or a database with an ordinary production name.
    async fn isolated_database() -> Result<(Config, Client), BoxError> {
        let config: Config = env::var("RAMA_FP_TEST_PG")
            .context("isolated PostgreSQL harness must supply RAMA_FP_TEST_PG")?
            .parse()?;
        assert_eq!(config.get_dbname(), Some("rama_fp_m3_test"));
        assert_eq!(config.get_hosts().len(), 1);
        assert!(
            matches!(&config.get_hosts()[0], Host::Unix(path) if path.to_string_lossy().starts_with("/tmp/rama-fp-m3-pg-"))
        );
        let client = connect(&config).await?;
        let marker: String = client
            .query_one("SELECT current_setting('rama.fp_test')", &[])
            .await?
            .try_get(0)?;
        assert_eq!(marker, "isolated");
        Ok((config, client))
    }

    #[tokio::test]
    #[ignore = "requires the private PostgreSQL integration harness"]
    async fn fp_migrations_are_atomic_checked_and_concurrent() {
        let (config, mut client) = isolated_database().await.unwrap();
        client
            .batch_execute("DROP SCHEMA IF EXISTS fp_v2 CASCADE")
            .await
            .unwrap();
        // A failure rolls back the schema, ledger and all earlier pending migrations.
        apply_scripts(
            &mut client,
            &[
                MIGRATIONS[0],
                "CREATE TABLE fp_v2.rollback_probe (n BIGINT); SELECT 1 / 0;",
            ],
        )
        .await
        .unwrap_err();
        let absent: bool = client
            .query_one("SELECT to_regnamespace('fp_v2') IS NULL", &[])
            .await
            .unwrap()
            .get(0);
        assert!(absent);
        apply(&mut client).await.unwrap();
        apply(&mut client).await.unwrap();
        let mut blocker = connect(&config).await.unwrap();
        let held = blocker.transaction().await.unwrap();
        held.execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK])
            .await
            .unwrap();
        let mut contender = connect(&config).await.unwrap();
        contender
            .batch_execute("SET lock_timeout = '100ms'")
            .await
            .unwrap();
        apply(&mut contender).await.unwrap_err();
        held.rollback().await.unwrap();
        apply(&mut contender).await.unwrap();
        let count: i64 = client
            .query_one("SELECT count(*) FROM fp_v2.migrations", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1);
        client
            .batch_execute("DROP SCHEMA fp_v2 CASCADE")
            .await
            .unwrap();
        client
            .batch_execute(include_str!(
                "migrations/20250915152637_create_ua_profiles.sql"
            ))
            .await
            .unwrap();
        client.execute("INSERT INTO \"ua-profiles\" (uastr, h1_settings) VALUES ('migration-canary', '{\"opaque\":42}') ON CONFLICT (uastr) DO NOTHING", &[]).await.unwrap();
        let legacy_before: String = client.query_one("SELECT row_to_json(p)::text FROM \"ua-profiles\" p WHERE uastr = 'migration-canary'", &[]).await.unwrap().get(0);
        let mut jobs = JoinSet::new();
        for _ in 0..8 {
            let config = config.clone();
            jobs.spawn(async move {
                let mut client = connect(&config).await.unwrap();
                apply(&mut client).await.unwrap();
            });
        }
        timeout(Duration::from_secs(30), async {
            while let Some(result) = jobs.join_next().await {
                result.unwrap();
            }
        })
        .await
        .unwrap();
        let legacy_after: String = client.query_one("SELECT row_to_json(p)::text FROM \"ua-profiles\" p WHERE uastr = 'migration-canary'", &[]).await.unwrap().get(0);
        assert_eq!(legacy_before, legacy_after);
        let count: i64 = client
            .query_one("SELECT count(*) FROM fp_v2.migrations", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1);
        // Altered owned SQL cannot silently reuse an applied version.
        apply_scripts(&mut client, &["SELECT 1"]).await.unwrap_err();
        apply_scripts(&mut client, &[]).await.unwrap_err();
        client
            .execute(
                "UPDATE fp_v2.migrations SET version = 2 WHERE version = 1",
                &[],
            )
            .await
            .unwrap();
        apply(&mut client).await.unwrap_err();
        apply_scripts(&mut client, &[MIGRATIONS[0], "SELECT 1"])
            .await
            .unwrap_err();
        client
            .execute(
                "UPDATE fp_v2.migrations SET version = 1 WHERE version = 2",
                &[],
            )
            .await
            .unwrap();
        // An incremental failure leaves the previous committed schema and checksum intact.
        apply_scripts(
            &mut client,
            &[
                MIGRATIONS[0],
                "CREATE TABLE fp_v2.rollback_probe (n BIGINT); SELECT 1 / 0;",
            ],
        )
        .await
        .unwrap_err();
        let absent: bool = client
            .query_one("SELECT to_regclass('fp_v2.rollback_probe') IS NULL", &[])
            .await
            .unwrap()
            .get(0);
        assert!(absent);
        let mut restarted = connect(&config).await.unwrap();
        apply(&mut restarted).await.unwrap();
        let checksum: Vec<u8> = restarted
            .query_one(
                "SELECT checksum FROM fp_v2.migrations WHERE version = 1",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(checksum, sha256(MIGRATIONS[0].as_bytes()));
        let count: i64 = restarted
            .query_one("SELECT count(*) FROM fp_v2.quotas", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 2);

        // The database itself rejects cross-authorization references.
        restarted.batch_execute("INSERT INTO fp_v2.profiles VALUES (TRUE, decode(repeat('01', 32), 'hex'), 'profile');").await.unwrap();
        let error = restarted.execute("INSERT INTO fp_v2.flows VALUES (FALSE, decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 'flow')", &[]).await.unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::FOREIGN_KEY_VIOLATION));
        restarted.batch_execute("INSERT INTO fp_v2.profiles VALUES (FALSE, decode(repeat('01', 32), 'hex'), 'profile');
            INSERT INTO fp_v2.structures VALUES (FALSE, decode(repeat('03', 32), 'hex'), 1, 0, 'structure');
            INSERT INTO fp_v2.values VALUES (TRUE, decode(repeat('04', 32), 'hex'), 1, 'value');
            INSERT INTO fp_v2.buckets VALUES (FALSE, decode(repeat('05', 32), 'hex'), 100, decode(repeat('01', 32), 'hex'), NULL, decode(repeat('03', 32), 'hex'), 'scope', 1, 1, 1, 0, 5);").await.unwrap();
        let error = restarted.execute("INSERT INTO fp_v2.literal_counts VALUES (FALSE, decode(repeat('05', 32), 'hex'), 100, decode(repeat('04', 32), 'hex'), 1)", &[]).await.unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::FOREIGN_KEY_VIOLATION));
        let error = restarted.execute("INSERT INTO fp_v2.samples VALUES (FALSE, decode(repeat('05', 32), 'hex'), 100, decode(repeat('06', 16), 'hex'), 1, decode(repeat('07', 32), 'hex'), decode(repeat('04', 32), 'hex'))", &[]).await.unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::FOREIGN_KEY_VIOLATION));
        let error = restarted
            .execute(
                "UPDATE fp_v2.quotas SET canonical_bytes = -1 WHERE authorized = FALSE",
                &[],
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
    }
}
