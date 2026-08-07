/// Create a structurally isolated logical child of a value.
///
/// `Fork` is similar to [`Clone`], but allows a type to isolate structural or
/// append-only state that must not be shared between independent attempts.
/// Implementations should preserve the observable input and document which
/// mutations are isolated. Values intentionally shared through handles such as
/// [`Arc`](crate::std::sync::Arc) may still expose shared interior mutability.
pub trait Fork: Sized {
    /// Create a structurally isolated logical child of this value.
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
