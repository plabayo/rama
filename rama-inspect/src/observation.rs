//! Shared, typed observations attached to a captured connection or operation.

use std::{fmt, sync::Arc};

use rama_core::extensions::{Extension, Extensions};

/// An append-only observation scope. Clones share observations; independent
/// scopes keep connection, exchange and upstream data separate.
///
/// Store values, not live handles: an observation must not change after it was recorded.
#[derive(Debug, Clone, Default)]
pub struct Observations(Arc<Inner>);

#[derive(Debug, Default)]
struct Inner {
    values: Extensions,
    insertion: parking_lot::Mutex<()>,
}

/// Keeps observed values apart from extensions of the same type.
#[derive(Debug)]
struct Observation<T>(T);

impl<T: fmt::Debug + Send + Sync + 'static> Extension for Observation<T> {}

impl Observations {
    /// The newest value of this type.
    pub fn get_ref<T: fmt::Debug + Send + Sync + 'static>(&self) -> Option<&T> {
        self.0
            .values
            .self_get_ref::<Observation<T>>()
            .map(|value| &value.0)
    }

    /// The oldest value of this type.
    pub fn get_first<T: fmt::Debug + Send + Sync + 'static>(&self) -> Option<&T> {
        self.0
            .values
            .self_first_ref::<Observation<T>>()
            .map(|value| &value.0)
    }

    /// Every value of this type, newest first.
    pub fn iter<T: fmt::Debug + Send + Sync + 'static>(&self) -> impl Iterator<Item = &T> {
        self.0
            .values
            .self_iter_ref::<Observation<T>>()
            .map(|value| &value.0)
    }

    pub fn contains<T: fmt::Debug + Send + Sync + 'static>(&self) -> bool {
        self.0.values.self_contains::<Observation<T>>()
    }

    /// Append a value, after any earlier ones of this type.
    pub fn insert<T: fmt::Debug + Send + Sync + 'static>(&self, value: T) -> &T {
        &self.0.values.insert(Observation(value)).0
    }

    /// Initialize an observation once, including when concurrent streams first
    /// encounter the same connection. The initializer must not insert recursively.
    pub fn get_or_insert<T: fmt::Debug + Send + Sync + 'static>(
        &self,
        create: impl FnOnce() -> T,
    ) -> &T {
        if let Some(value) = self.get_ref() {
            return value;
        }
        let _insertion = self.0.insertion.lock();
        &self
            .0
            .values
            .self_get_ref_or_insert(|| Observation(create()))
            .0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
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
        #[derive(Debug)]
        struct Later;
        observations.insert(Later);
        assert!(cloned.contains::<Count>() && cloned.contains::<Later>());
        assert!(!Observations::default().contains::<Count>());
    }

    #[test]
    fn inserts_append_and_reads_see_newest_first() {
        let observations = Observations::default();
        observations.insert(1u32);
        observations.insert(2u32);
        observations.insert(3u32);
        assert_eq!(observations.get_ref::<u32>(), Some(&3));
        assert_eq!(observations.get_first::<u32>(), Some(&1));
        assert_eq!(
            observations.iter::<u32>().copied().collect::<Vec<_>>(),
            [3, 2, 1]
        );
        assert_eq!(observations.get_or_insert(|| 4u32), &3);
    }

    #[test]
    fn observations_are_apart_from_extensions_of_the_same_type() {
        #[derive(Debug, Extension)]
        struct Live;
        let observations = Observations::default();
        observations.0.values.insert(Live);
        assert!(!observations.contains::<Live>());
    }
}
