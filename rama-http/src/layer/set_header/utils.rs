use std::fmt;

/// Wrapper used internally as part of making typed headers
/// encode header values on the spot, when needed.
pub struct TypedHeaderAsMaker<H>(pub(super) H);

impl<H: fmt::Debug> fmt::Debug for TypedHeaderAsMaker<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TypedHeaderAsMaker").field(&self.0).finish()
    }
}

impl<H: Clone> Clone for TypedHeaderAsMaker<H> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
