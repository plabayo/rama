use std::{fmt, sync::Arc};

use rama::error::{BoxError, ErrorContext};
use rama::net::address::ip::geo::IpGeoDb;

use super::{data::DataSource, redacted_storage_auth, storage::Storage};

#[derive(Clone)]
#[non_exhaustive]
pub(super) struct State {
    pub(super) data_source: DataSource,
    pub(super) storage: Option<Storage>,
    pub(super) storage_auth: Option<String>,
    /// Optional IP geolocation database, configured via `RAMA_IP_GEO_DB`.
    pub(super) geo_db: Option<Arc<IpGeoDb>>,
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("State")
            .field("data_source", &self.data_source)
            .field("storage", &self.storage)
            .field(
                "storage_auth",
                &redacted_storage_auth(self.storage_auth.as_deref()),
            )
            .field("geo_db", &self.geo_db)
            .finish()
    }
}

impl State {
    /// Create a new instance of [`State`].
    pub(super) async fn new(
        pg_url: Option<String>,
        storage_auth: Option<&str>,
    ) -> Result<Self, BoxError> {
        let storage = match pg_url {
            Some(pg_url) => Some(Storage::try_new(pg_url).await.context("create storage")?),
            None => None,
        };

        let geo_db = crate::utils::geo::load_geo_db_from_env();

        Ok(Self {
            data_source: DataSource::default(),
            storage,
            storage_auth: storage_auth.map(|s| s.to_owned()),
            geo_db,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_debug_redacts_storage_auth() {
        let state = State {
            data_source: DataSource::default(),
            storage: None,
            storage_auth: Some("super-secret-cookie".to_owned()),
            geo_db: None,
        };

        let formatted = format!("{state:?}");

        assert!(
            !formatted.contains("super-secret-cookie"),
            "debug leaked storage auth: {formatted}"
        );
        assert!(
            formatted.contains("<redacted>"),
            "debug missing storage auth redaction marker: {formatted}"
        );
    }
}
