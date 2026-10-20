use std::{str::FromStr as _, time::Duration};

use bb8_postgres::PostgresConnectionManager;
use tokio_postgres::{NoTls, Transaction};

use rama::error::{BoxError, ErrorContext};

pub(super) type Pool = bb8::Pool<PostgresConnectionManager<NoTls>>;

pub(super) async fn try_new_pool(url: String) -> Result<Pool, BoxError> {
    let config =
        tokio_postgres::config::Config::from_str(&url).context("create PG config from url")?;
    let pg_mgr = PostgresConnectionManager::new(config, tokio_postgres::NoTls);
    Pool::builder()
        .connection_timeout(Duration::from_secs(5))
        .build(pg_mgr)
        .await
        .context("build PSQL pool")
}

/// Server bounds remain active when the client future is cancelled. Production
/// collection attempts have a five-second client budget.
pub(super) async fn bound_transaction(transaction: &Transaction<'_>) -> Result<(), BoxError> {
    transaction
        .batch_execute(
            "SET LOCAL statement_timeout = '4s';
         SET LOCAL lock_timeout = '1s';
         SET LOCAL idle_in_transaction_session_timeout = '4s'",
        )
        .await?;
    Ok(())
}
