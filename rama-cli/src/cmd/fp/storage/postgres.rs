use std::{str::FromStr as _, time::Duration};

use bb8_postgres::PostgresConnectionManager;
use tokio_postgres::NoTls;

use rama::error::{ErrorContext, OpaqueError};

pub(super) type Pool = bb8::Pool<PostgresConnectionManager<NoTls>>;

pub(super) async fn new_pool(url: String) -> Result<Pool, OpaqueError> {
    let config = tokio_postgres::config::Config::from_str(&url).unwrap();
    let pg_mgr = PostgresConnectionManager::new(config, tokio_postgres::NoTls);
    Pool::builder()
        .connection_timeout(Duration::from_secs(5))
        .build(pg_mgr)
        .await
        .context("build PSQL pool")
}
