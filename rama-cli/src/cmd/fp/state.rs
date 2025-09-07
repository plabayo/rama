use std::collections::HashMap;

use rama::error::{ErrorContext, OpaqueError};

use super::{data::DataSource, storage::Storage};

#[derive(Debug)]
#[non_exhaustive]
pub(super) struct State {
    pub(super) data_source: DataSource,
    pub(super) acme: ACMEData,
    pub(super) storage: Option<Storage>,
    pub(super) storage_auth: Option<String>,
}

impl State {
    /// Create a new instance of [`State`].
    pub(super) async fn new(
        acme: ACMEData,
        pg_url: Option<String>,
        storage_auth: Option<&str>,
    ) -> Result<Self, OpaqueError> {
        let storage = match pg_url {
            Some(pg_url) => Some(Storage::new(pg_url).await.context("create storage")?),
            None => None,
        };

        Ok(Self {
            data_source: DataSource::default(),
            acme,
            storage,
            storage_auth: storage_auth.map(|s| s.to_owned()),
        })
    }
}

#[derive(Debug, Clone)]
pub(super) struct ACMEData {
    challenges: HashMap<String, String>,
}

impl ACMEData {
    pub(super) fn new() -> Self {
        Self {
            challenges: HashMap::new(),
        }
    }

    pub(super) fn with_challenges(challenges: Vec<(impl Into<String>, impl Into<String>)>) -> Self {
        Self {
            challenges: challenges
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    pub(super) fn get_challenge(&self, key: impl AsRef<str>) -> Option<&str> {
        self.challenges.get(key.as_ref()).map(|v| v.as_str())
    }
}

impl Default for ACMEData {
    fn default() -> Self {
        Self::new()
    }
}
