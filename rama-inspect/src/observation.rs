//! Shared, typed observations attached to a captured connection or operation.
use rama_core::extensions::{Extension, Extensions};
use std::{ops::Deref, sync::Arc};

/// An append-only observation scope. Clones share observations; independent
/// scopes keep connection, exchange and upstream data separate.
#[derive(Debug, Clone, Default)]
pub struct Observations(Arc<Inner>);
#[derive(Debug, Default)]
struct Inner {
    values: Extensions,
    insertion: parking_lot::Mutex<()>,
}
impl Observations {
    /// Initialize an observation once, including when concurrent streams first
    /// encounter the same connection. The initializer must not insert recursively.
    pub fn get_or_insert<T: Extension>(&self, create: impl FnOnce() -> T) -> &T {
        if let Some(value) = self.0.values.get_ref() {
            return value;
        }
        let _insertion = self.0.insertion.lock();
        self.0.values.get_ref_or_insert(create)
    }
}
impl Deref for Observations {
    type Target = Extensions;
    fn deref(&self) -> &Self::Target {
        &self.0.values
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, Extension)]
    struct Count;
    #[test]
    fn concurrent_initialization_runs_once() {
        let observations = Observations::default();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..16 {
                scope.spawn(|| {
                    observations.get_or_insert(|| {
                        calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Count
                    });
                });
            }
        });
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        let cloned = observations.clone();
        #[derive(Debug, Extension)]
        struct Later;
        observations.insert(Later);
        assert!(cloned.contains::<Count>() && cloned.contains::<Later>());
        assert!(!Observations::default().contains::<Count>());
    }
}
