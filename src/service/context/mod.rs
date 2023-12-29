//! Context passed to and between services as input.

mod extensions;
pub use extensions::Extensions;

/// Context passed to and between services as input.
#[derive(Debug, Clone)]
pub struct Context<S> {
    state: S,
    extensions: Extensions,
}

impl Default for Context<()> {
    fn default() -> Self {
        Self::new(())
    }
}

impl<S> Context<S> {
    /// Create a new [`Context`] with the given state.
    pub fn new(state: S) -> Self {
        Self {
            state,
            extensions: Extensions::new(),
        }
    }

    /// Get a reference to the state.
    pub fn state(&self) -> &S {
        &self.state
    }

    /// Get a mutable reference to the state.
    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }

    /// Get a reference to the extensions.
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Get a mutable reference to the extensions.
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}
