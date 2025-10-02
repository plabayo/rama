use rama::error::{ErrorContext, OpaqueError};

use super::{data::DataSource, storage::Storage};

#[derive(Debug)]
#[non_exhaustive]
pub(super) struct State {
    pub(super) data_source: DataSource,
    pub(super) storage: Option<Storage>,
    pub(super) storage_auth: Option<String>,
}

impl State {
    /// Create a new instance of [`State`].
    pub(super) async fn new(
        pg_url: Option<String>,
        storage_auth: Option<&str>,
    ) -> Result<Self, OpaqueError> {
        let storage = match pg_url {
            Some(pg_url) => Some(Storage::new(pg_url).await.context("create storage")?),
            None => None,
        };

        Ok(Self {
            data_source: DataSource::default(),
            storage,
            storage_auth: storage_auth.map(|s| s.to_owned()),
        })
    }
}
