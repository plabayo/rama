use std::{collections::HashMap, sync::atomic::AtomicUsize};

use rama::service::context::AsRef;

use super::data::DataSource;

#[derive(Debug, AsRef)]
#[non_exhaustive]
pub struct State {
    pub data_source: DataSource,
    pub counter: AtomicUsize,
    pub acme: ACMEData,
}

impl State {
    /// Create a new instance of [`State`].
    pub fn new(acme: ACMEData) -> Self {
        State {
            data_source: DataSource::default(),
            counter: AtomicUsize::new(0),
            acme,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ACMEData {
    challenges: HashMap<String, String>,
}

impl ACMEData {
    pub fn new() -> Self {
        Self {
            challenges: HashMap::new(),
        }
    }

    pub fn with_challenges(challenges: Vec<(impl Into<String>, impl Into<String>)>) -> Self {
        Self {
            challenges: challenges
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    pub fn get_challenge(&self, key: impl AsRef<str>) -> Option<&str> {
        self.challenges.get(key.as_ref()).map(|v| v.as_str())
    }
}

impl Default for ACMEData {
    fn default() -> Self {
        Self::new()
    }
}
