use std::sync::Arc;

use rama::error::{BoxError, ErrorContext};
use rama::net::address::ip::geo::IpGeoDb;

use super::{data::DataSource, storage::Storage};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub(super) struct State {
    pub(super) data_source: DataSource,
    pub(super) storage: Option<Storage>,
    pub(super) storage_auth: Option<String>,
    /// Optional IP geolocation database, configured via `RAMA_IP_GEO_DB`.
    pub(super) geo_db: Option<Arc<IpGeoDb>>,
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
