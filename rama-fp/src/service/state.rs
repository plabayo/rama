use std::sync::atomic::AtomicUsize;

use rama::service::context::AsRef;

use super::data::DataSource;

#[derive(Debug, AsRef)]
#[non_exhaustive]
pub struct State {
    pub data_source: DataSource,
    pub counter: AtomicUsize,
}

impl State {
    /// Create a new instance of [`State`].
    pub fn new() -> Self {
        State {
            data_source: DataSource::default(),
            counter: AtomicUsize::new(0),
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
