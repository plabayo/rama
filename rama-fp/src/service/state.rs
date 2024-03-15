use rama::service::context::AsRef;

#[derive(Debug, Clone, AsRef)]
#[non_exhaustive]
pub struct State;

impl State {
    /// Create a new instance of [`State`].
    pub fn new() -> Self {
        Self
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
