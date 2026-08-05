/// Create an independent logical child of a value.
///
/// `Fork` is similar to [`Clone`], but allows a type to isolate mutable or
/// append-only state that must not be shared between independent attempts.
/// Implementations should preserve the observable input while ensuring that
/// changes made to the fork do not leak back into the original value.
pub trait Fork: Sized {
    /// Create an independent logical child of this value.
    #[must_use]
    fn fork(&self) -> Self;
}

impl Fork for crate::extensions::Extensions {
    fn fork(&self) -> Self {
        Self::fork(self)
    }
}

#[cfg(test)]
mod tests {
    use crate::extensions::{Extension, Extensions};

    use super::*;

    #[derive(Debug, Extension)]
    struct Parent;

    #[derive(Debug, Extension)]
    struct Child;

    #[test]
    fn extensions_fork_preserves_parent_without_leaking_child() {
        let parent = Extensions::new();
        parent.insert(Parent);

        let child = Fork::fork(&parent);
        assert!(child.contains::<Parent>());

        child.insert(Child);
        assert!(!parent.contains::<Child>());
    }
}
