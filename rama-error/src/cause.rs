use core::error::Error;

use crate::{ErrorList, chain::DEFAULT_MAX_DEPTH, error_chain, error_source};

/// Look up causes of an error by type.
///
/// The lookup walks the same chain as [`error_chain`](crate::error_chain), so it
/// also finds an error that a `std::io::Error` wraps, and it enters every
/// failure of an [`ErrorList`], not only the primary one. At most 64 errors are
/// visited in total.
///
/// Implemented for every concrete error type and for `dyn Error` trait objects,
/// which includes [`BoxError`](crate::BoxError) through auto-deref.
///
/// ```
/// # #[cfg(feature = "std")] {
/// use rama_error::{BoxError, CauseExt, ErrorExt};
///
/// #[derive(Debug)]
/// struct Timeout;
///
/// impl std::fmt::Display for Timeout {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         f.write_str("timeout")
///     }
/// }
///
/// impl std::error::Error for Timeout {}
///
/// let error: BoxError = std::io::Error::other(Timeout).context("connect");
/// assert!(error.has_cause::<Timeout>());
/// assert!(error.find_cause::<std::io::Error>().is_some());
/// assert!(!error.has_cause::<std::fmt::Error>());
/// # }
/// ```
pub trait CauseExt: private::Sealed {
    /// Whether this error or one of its causes is a `T`.
    fn has_cause<T: Error + 'static>(&self) -> bool;

    /// The first error of type `T`, starting with this error itself.
    fn find_cause<T: Error + 'static>(&self) -> Option<&T>;

    /// The last error in the chain: this error when it has no cause. Through an
    /// [`ErrorList`] the chain follows its primary failure.
    ///
    /// The walk visits at most 64 errors, as [`error_chain`](crate::error_chain)
    /// does; for a longer or cyclic chain this is the last error visited.
    fn root_cause(&self) -> &(dyn Error + 'static);
}

#[inline]
fn find_cause<'a, T: Error + 'static>(error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    let mut budget = DEFAULT_MAX_DEPTH;
    find_in_tree(error, &mut budget)
}

/// Depth-first over the chain, entering every failure of an [`ErrorList`]
/// instead of only its primary one. `budget` bounds the errors visited in total.
fn find_in_tree<'a, T: Error + 'static>(
    error: &'a (dyn Error + 'static),
    budget: &mut usize,
) -> Option<&'a T> {
    let mut current = Some(error);
    while let Some(error) = current {
        *budget = budget.checked_sub(1)?;
        if let Some(found) = error.downcast_ref::<T>() {
            return Some(found);
        }
        if let Some(list) = error.downcast_ref::<ErrorList>() {
            for failure in list.iter() {
                if *budget == 0 {
                    return None;
                }
                if let Some(found) = find_in_tree(failure as &(dyn Error + 'static), budget) {
                    return Some(found);
                }
            }
            return None;
        }
        current = error_source(error);
    }
    None
}

#[inline]
fn root_cause<'a>(error: &'a (dyn Error + 'static)) -> &'a (dyn Error + 'static) {
    error_chain(error).last().unwrap_or(error)
}

macro_rules! impl_cause_ext {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl CauseExt for $ty {
                #[inline]
                fn has_cause<T: Error + 'static>(&self) -> bool {
                    find_cause::<T>(self).is_some()
                }

                #[inline]
                fn find_cause<T: Error + 'static>(&self) -> Option<&T> {
                    find_cause(self)
                }

                #[inline]
                fn root_cause(&self) -> &(dyn Error + 'static) {
                    root_cause(self)
                }
            }

            impl private::Sealed for $ty {}
        )+
    };
}

impl_cause_ext!(
    dyn Error + 'static,
    dyn Error + Send + 'static,
    dyn Error + Send + Sync + 'static,
);

impl<E: Error + 'static> CauseExt for E {
    #[inline]
    fn has_cause<T: Error + 'static>(&self) -> bool {
        find_cause::<T>(self).is_some()
    }

    #[inline]
    fn find_cause<T: Error + 'static>(&self) -> Option<&T> {
        find_cause(self)
    }

    #[inline]
    fn root_cause(&self) -> &(dyn Error + 'static) {
        root_cause(self)
    }
}

impl<E: Error + 'static> private::Sealed for E {}

mod private {
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    use core::{
        fmt,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::{BoxError, BoxErrorExt as _, ErrorExt as _, std::Box};

    #[derive(Debug)]
    struct Leaf;

    impl fmt::Display for Leaf {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("leaf")
        }
    }

    impl Error for Leaf {}

    #[derive(Debug)]
    struct Wrap(Box<dyn Error + Send + Sync>);

    impl fmt::Display for Wrap {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("wrap")
        }
    }

    impl Error for Wrap {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    #[test]
    fn finds_itself_and_nested_causes() {
        let error = Wrap(Box::new(Leaf));
        assert!(error.has_cause::<Wrap>());
        assert!(error.has_cause::<Leaf>());
        assert!(!error.has_cause::<fmt::Error>());
        assert!(error.root_cause().is::<Leaf>());
        assert!(Leaf.root_cause().is::<Leaf>());
    }

    #[test]
    fn works_on_box_error_through_context() {
        let error: BoxError = Wrap(Box::new(Leaf)).context_field("k", "v");
        assert!(error.has_cause::<Leaf>());
        assert!(error.find_cause::<Wrap>().is_some());
        assert!(error.root_cause().is::<Leaf>());

        let plain = BoxError::from_static_str("plain");
        assert!(core::ptr::addr_eq(plain.root_cause(), plain.as_ref()));
    }

    #[test]
    fn a_cyclic_chain_ends() {
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

        assert!(!Cycle.has_cause::<Leaf>());
        assert!(Cycle.root_cause().is::<Cycle>());
    }

    #[derive(Debug)]
    struct Depth(usize, Option<Box<Self>>);

    impl fmt::Display for Depth {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "depth {}", self.0)
        }
    }

    impl Error for Depth {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.1.as_deref().map(|source| source as _)
        }
    }

    fn depth_chain(len: usize) -> Depth {
        let mut error = Depth(len - 1, None);
        for depth in (0..len - 1).rev() {
            error = Depth(depth, Some(Box::new(error)));
        }
        error
    }

    #[test]
    fn root_cause_is_the_last_error_within_the_bound() {
        for (len, root) in [(1, 0), (64, 63), (65, 63), (100, 63)] {
            let error = depth_chain(len);
            let found = error.root_cause().downcast_ref::<Depth>().unwrap().0;
            assert_eq!(found, root, "chain of {len}");
        }
        assert!(depth_chain(64).find_cause::<Depth>().is_some());
    }

    #[test]
    fn lookup_stops_visiting_once_the_budget_is_spent() {
        static SOURCES: AtomicUsize = AtomicUsize::new(0);

        #[derive(Debug)]
        struct Counted;

        impl fmt::Display for Counted {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("counted")
            }
        }

        impl Error for Counted {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                SOURCES.fetch_add(1, Ordering::Relaxed);
                None
            }
        }

        let inner: ErrorList = (0..10_000).map(|_| Counted).collect();
        let outer: ErrorList = [inner]
            .into_iter()
            .chain((0..10_000).map(|_| ErrorList::new()))
            .collect();
        assert!(!outer.has_cause::<Leaf>());
        // The outer and inner list take two of the 64 visits.
        assert_eq!(SOURCES.load(Ordering::Relaxed), DEFAULT_MAX_DEPTH - 2);
    }

    #[cfg(feature = "std")]
    #[test]
    fn finds_the_error_an_io_error_wraps() {
        let io = std::io::Error::other(Wrap(Box::new(Leaf)));
        assert!(
            io.source().is_some_and(|source| source.is::<Leaf>()),
            "std skips the wrapped error itself"
        );
        assert!(io.has_cause::<Wrap>());
        assert!(io.has_cause::<Leaf>());

        let nested = std::io::Error::other(std::io::Error::other(Leaf));
        let chain: crate::std::Vec<_> = error_chain(&nested).collect();
        assert_eq!(chain.len(), 3, "each error once: {chain:?}");
        assert!(chain[2].is::<Leaf>());

        let os = std::io::Error::from(std::io::ErrorKind::TimedOut);
        assert_eq!(error_chain(&os).count(), 1);
    }
}
