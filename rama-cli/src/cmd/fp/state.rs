use std::{collections::HashMap, sync::atomic::AtomicUsize};

use super::data::DataSource;

#[derive(Debug)]
#[non_exhaustive]
pub(super) struct State {
    pub(super) data_source: DataSource,
    pub(super) counter: AtomicUsize,
    pub(super) acme: ACMEData,
}

impl State {
    /// Create a new instance of [`State`].
    pub(super) fn new(acme: ACMEData) -> Self {
        State {
            data_source: DataSource::default(),
            counter: AtomicUsize::new(0),
            acme,
        }
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
