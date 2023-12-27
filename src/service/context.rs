//! Context passed to and between services as input.

/// Context passed to and between services as input.
#[derive(Debug)]
pub struct Context<S> {
    state: S,
}

impl<S> Context<S> {
    /// Create a new [`Context`] with the given state.
    pub fn new(state: S) -> Self {
        Self { state }
    }

    /// Get a reference to the state.
    pub fn state(&self) -> &S {
        &self.state
    }

    /// Get a mutable reference to the state.
    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }
}
