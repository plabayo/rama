use std::{str::FromStr as _, time::Duration};

use bb8_postgres::PostgresConnectionManager;
use tokio_postgres::NoTls;

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
