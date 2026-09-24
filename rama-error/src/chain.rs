use core::error::Error;

const DEFAULT_MAX_DEPTH: usize = 64;

/// Iterate over an error and its sources, visiting at most 64 errors.
///
/// The supplied error is the first item and counts toward the limit. The limit
/// bounds cyclic as well as unusually long source chains; repeated errors are
/// not deduplicated. This iterator does not allocate.
///
/// Sources are requested only when advancing past the current error, so an early
/// match does not inspect that error's source. Only [`Error::source`] is followed;
/// use [`error_chain_with`] for errors that expose causes through another API,
/// or [`error_chain_with_limit`] to choose another traversal bound.
pub fn error_chain<'a>(
    error: &'a (dyn Error + 'static),
) -> impl Iterator<Item = &'a (dyn Error + 'static)> {
    error_chain_with_limit(error, DEFAULT_MAX_DEPTH)
}

/// Iterate over an error and its sources, visiting at most `max_depth` errors.
///
/// The supplied error counts toward the limit. A zero limit yields no items.
/// Otherwise this behaves like [`error_chain`], with an explicit traversal bound.
pub fn error_chain_with_limit<'a>(
    error: &'a (dyn Error + 'static),
    max_depth: usize,
) -> impl Iterator<Item = &'a (dyn Error + 'static)> {
    error_chain_with_limit_and(error, max_depth, |error| error.source())
}

/// Iterate over an error and custom successors, visiting at most 64 errors.
///
/// The `next_source` callback selects one successor per error, replacing
/// [`Error::source`] traversal. Return `None` to end the chain, or explicitly call
/// [`Error::source`] in the callback when it should provide the fallback successor.
///
/// The callback runs only when another item is requested within the limit and
/// stops once the chain ends. The iterator does not allocate or deduplicate
/// errors. Use [`error_chain_with_limit_and`] to choose another traversal bound.
pub fn error_chain_with<'a, F>(
    error: &'a (dyn Error + 'static),
    next_source: F,
) -> impl Iterator<Item = &'a (dyn Error + 'static)>
where
    F: FnMut(&'a (dyn Error + 'static)) -> Option<&'a (dyn Error + 'static)>,
{
    error_chain_with_limit_and(error, DEFAULT_MAX_DEPTH, next_source)
}

/// Iterate over an error and custom successors, visiting at most `max_depth` errors.
///
/// The supplied error counts toward the limit. The callback is never called for
/// a zero or one-item limit. Otherwise this behaves like [`error_chain_with`],
/// with an explicit traversal bound that also limits cycles from the callback.
pub fn error_chain_with_limit_and<'a, F>(
    error: &'a (dyn Error + 'static),
    max_depth: usize,
    mut next_source: F,
) -> impl Iterator<Item = &'a (dyn Error + 'static)>
where
    F: FnMut(&'a (dyn Error + 'static)) -> Option<&'a (dyn Error + 'static)>,
{
    let mut current = Some(error);
    core::iter::once(error)
        .chain(core::iter::from_fn(move || {
            current = next_source(current?);
            current
        }))
        .take(max_depth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::std::{Box, Vec};
    use core::fmt;

    #[derive(Debug)]
    struct Node {
        value: usize,
        source: Option<Box<Self>>,
    }

    impl fmt::Display for Node {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "node {}", self.value)
        }
    }

    impl Error for Node {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.source.as_deref().map(|source| source as _)
        }
    }

    #[test]
    fn includes_root_and_preserves_order_within_limit() {
        let error = Node {
            value: 1,
            source: Some(Box::new(Node {
                value: 2,
                source: Some(Box::new(Node {
                    value: 3,
                    source: None,
                })),
            })),
        };

        for limit in 0..=4 {
            let values: Vec<_> = error_chain_with_limit(&error, limit)
                .map(|error| error.downcast_ref::<Node>().unwrap().value)
                .collect();
            assert_eq!(values, &[1, 2, 3][..limit.min(3)], "limit {limit}");
        }
    }

    #[test]
    fn cyclic_sources_are_bounded() {
        #[derive(Debug)]
        struct Cycle;

        impl fmt::Display for Cycle {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("cycle")
            }
        }

        impl Error for Cycle {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                Some(self)
            }
        }

        assert_eq!(error_chain(&Cycle).count(), 64);
        assert_eq!(error_chain_with_limit(&Cycle, 5).count(), 5);
        assert_eq!(error_chain_with_limit(&Cycle, 100).count(), 100);
    }

    #[test]
    fn custom_successor_reaches_an_error_hidden_from_source() {
        let root = Node {
            value: 1,
            source: None,
        };
        let hidden = Node {
            value: 2,
            source: None,
        };
        assert_eq!(error_chain(&root).count(), 1);

        let values: Vec<_> = error_chain_with(&root, |error| {
            if error.downcast_ref::<Node>().unwrap().value == 1 {
                Some(&hidden)
            } else {
                None
            }
        })
        .map(|error| error.downcast_ref::<Node>().unwrap().value)
        .collect();
        assert_eq!(values, [1, 2]);
    }

    #[test]
    fn custom_successor_cycles_are_bounded() {
        let error = Node {
            value: 1,
            source: None,
        };
        assert_eq!(error_chain_with(&error, |_| Some(&error)).count(), 64);
        assert_eq!(
            error_chain_with_limit_and(&error, 5, |_| Some(&error)).count(),
            5
        );
        assert_eq!(
            error_chain_with_limit_and(&error, 100, |_| Some(&error)).count(),
            100
        );
    }

    #[test]
    fn does_not_request_successors_beyond_limit_or_after_an_early_match() {
        let error = Node {
            value: 1,
            source: None,
        };
        for limit in [0, 1] {
            assert_eq!(
                error_chain_with_limit_and(&error, limit, |_| panic!("unexpected successor"))
                    .count(),
                limit,
            );
        }
        assert!(
            error_chain_with_limit_and(&error, 5, |_| panic!("unexpected successor"))
                .any(|error| error.is::<Node>())
        );
    }
}
