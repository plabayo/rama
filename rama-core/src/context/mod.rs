//! Context passed to and between services as input.

#[non_exhaustive]
#[derive(Debug, Default, Clone)]
/// Context passed to and between services as input.
///
/// See [`crate::context`] for more information.
pub struct Context;

impl Context {
    #[must_use]
    /// Create a new [`Context`] with the given state.
    pub fn new() -> Self {
        Self {}
    }
}
