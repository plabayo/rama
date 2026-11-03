use core::{any::Any, error::Error};

use crate::{
    ContextField, ErrorList, chain::DEFAULT_MAX_DEPTH, error_chain, error_source,
    ext::ErrorWithContext,
};

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
/// assert!(error.any_cause(|cause| cause
///     .downcast_ref::<std::io::Error>()
///     .is_some_and(|io| io.kind() == std::io::ErrorKind::Other)));
/// # }
/// ```
pub trait CauseExt: private::Sealed {
    /// Whether this error or one of its causes is a `T`.
    fn has_cause<T: Error + 'static>(&self) -> bool;

    /// The first error of type `T`, starting with this error itself.
    fn find_cause<T: Error + 'static>(&self) -> Option<&T>;

    /// Whether `predicate` holds for this error or one of its causes, visited
    /// in the same order and within the same bound as [`Self::find_cause`].
    fn any_cause(&self, predicate: impl FnMut(&(dyn Error + 'static)) -> bool) -> bool;

    /// The last error in the chain: this error when it has no cause. Through an
    /// [`ErrorList`] the chain follows its primary failure.
    ///
    /// The walk visits at most 64 errors, as [`error_chain`](crate::error_chain)
    /// does; for a longer or cyclic chain this is the last error visited.
    fn root_cause(&self) -> &(dyn Error + 'static);

    /// Every context field on the chain, outermost error first and in the order
    /// each error received them. Follows the same chain as
    /// [`error_chain`](crate::error_chain): through an [`ErrorList`] only its
    /// primary failure.
    fn context_fields(&self) -> impl Iterator<Item = &ContextField>;

    /// The first context value with this key that was added as a `T`
    /// (see [`ContextField::downcast_ref`]), searched as [`Self::context_fields`].
    fn context_value<T: Any>(&self, key: &str) -> Option<&T>;
}

#[inline]
fn find_cause<'a, T: Error + 'static>(error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    let mut budget = DEFAULT_MAX_DEPTH;
    find_in_tree(error, &mut budget, &mut |error| error.downcast_ref::<T>())
}

#[inline]
fn any_cause(
    error: &(dyn Error + 'static),
    mut predicate: impl FnMut(&(dyn Error + 'static)) -> bool,
) -> bool {
    let mut budget = DEFAULT_MAX_DEPTH;
    find_in_tree(error, &mut budget, &mut |error| {
        predicate(error).then_some(())
    })
    .is_some()
}

/// Depth-first over the chain, entering every failure of an [`ErrorList`]
/// instead of only its primary one. `budget` bounds the errors visited in total.
fn find_in_tree<'a, R>(
    error: &'a (dyn Error + 'static),
    budget: &mut usize,
    found: &mut impl FnMut(&'a (dyn Error + 'static)) -> Option<R>,
) -> Option<R> {
    let mut current = Some(error);
    while let Some(error) = current {
        *budget = budget.checked_sub(1)?;
        if let Some(result) = found(error) {
            return Some(result);
        }
        if let Some(list) = error.downcast_ref::<ErrorList>() {
            for failure in list.iter() {
                if *budget == 0 {
                    return None;
                }
                if let Some(result) = find_in_tree(failure as &(dyn Error + 'static), budget, found)
                {
                    return Some(result);
                }
            }
            return None;
        }
        current = error_source(error);
    }
    None
}

fn context_fields<'a>(error: &'a (dyn Error + 'static)) -> impl Iterator<Item = &'a ContextField> {
    error_chain(error)
        .filter_map(|error| error.downcast_ref::<ErrorWithContext>())
        .flat_map(ErrorWithContext::fields)
}

fn context_value<'a, T: Any>(error: &'a (dyn Error + 'static), key: &str) -> Option<&'a T> {
    context_fields(error)
        .filter(|field| field.key() == Some(key))
        .find_map(ContextField::downcast_ref)
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
                fn any_cause(
                    &self,
                    predicate: impl FnMut(&(dyn Error + 'static)) -> bool,
                ) -> bool {
                    any_cause(self, predicate)
                }

                #[inline]
                fn root_cause(&self) -> &(dyn Error + 'static) {
                    root_cause(self)
                }

                #[inline]
                fn context_fields(&self) -> impl Iterator<Item = &ContextField> {
                    context_fields(self)
                }

                #[inline]
                fn context_value<T: Any>(&self, key: &str) -> Option<&T> {
                    context_value(self, key)
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
    fn any_cause(&self, predicate: impl FnMut(&(dyn Error + 'static)) -> bool) -> bool {
        any_cause(self, predicate)
    }

    #[inline]
    fn root_cause(&self) -> &(dyn Error + 'static) {
        root_cause(self)
    }

    #[inline]
    fn context_fields(&self) -> impl Iterator<Item = &ContextField> {
        context_fields(self)
    }

    #[inline]
    fn context_value<T: Any>(&self, key: &str) -> Option<&T> {
        context_value(self, key)
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
    use crate::{ArcError, BoxError, BoxErrorExt as _, ErrorExt as _, std::Box};

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

    #[test]
    fn context_fields_are_listed_outermost_first_and_in_order() {
        let inner: BoxError = Wrap(Leaf.context_field("depth", 2u8))
            .context_field("depth", 1u8)
            .context("note");
        let fields: crate::std::Vec<_> = inner
            .context_fields()
            .map(|field| (field.key(), field.value().to_string()))
            .collect();
        assert_eq!(
            fields,
            [
                (Some("depth"), "1".into()),
                (None, "note".into()),
                (Some("depth"), "2".into()),
            ]
        );
        assert_eq!(inner.context_value::<u8>("depth"), Some(&1));
        assert_eq!(inner.context_value::<u16>("depth"), None, "typed lookup");
        assert_eq!(inner.context_value::<u8>("missing"), None);
        assert_eq!(Leaf.context_fields().count(), 0);
        assert_eq!(
            BoxError::from_static_str("bare").context_fields().count(),
            0
        );
    }

    #[test]
    fn context_values_downcast_to_the_type_they_were_added_as() {
        #[derive(Debug, PartialEq)]
        struct Port(u16);

        let error = BoxError::from_static_str("x")
            .context_field("str", "literal")
            .context_debug_field("debug", Port(80))
            .context_hex_field("hex", 0xffu8)
            .context_str_field("owned", "copied")
            .context_field("spilled", "after two inline fields");
        assert_eq!(error.context_value::<&str>("str"), Some(&"literal"));
        assert_eq!(error.context_value::<Port>("debug"), Some(&Port(80)));
        assert_eq!(error.context_value::<u8>("hex"), Some(&0xff));
        assert_eq!(
            error
                .context_value::<crate::std::String>("owned")
                .map(|s| s.as_str()),
            Some("copied")
        );
        assert_eq!(
            error.context_value::<&str>("spilled"),
            Some(&"after two inline fields")
        );
        assert_eq!(
            error.to_string(),
            r#"x | str="literal" debug="Port(80)" hex="ff" owned="copied" spilled="after two inline fields""#
        );
    }

    #[test]
    fn any_cause_tests_every_failure_within_one_budget() {
        let shared = ArcError::new(Depth(7, None));
        let elsewhere = ArcError::new(Depth(8, None));
        let mut inner: ErrorList = (0..2).map(|_| BoxError::from_static_str("x")).collect();
        inner.push(shared.clone());
        let mut list: ErrorList = (0..3).map(|_| BoxError::from_static_str("x")).collect();
        list.push(Box::new(inner) as BoxError);
        list.push(Wrap(Box::new(Leaf)));
        assert!(list.any_cause(|error| error.is::<Leaf>()));
        assert!(list.any_cause(|error| core::ptr::addr_eq(error, shared.as_error())));
        assert!(!list.any_cause(|error| core::ptr::addr_eq(error, elsewhere.as_error())));

        let mut visited = 0;
        let wide: ErrorList = (0..1_000).map(|_| BoxError::from_static_str("x")).collect();
        assert!(!wide.any_cause(|_| {
            visited += 1;
            false
        }));
        assert_eq!(visited, DEFAULT_MAX_DEPTH);
    }

    #[test]
    fn a_static_message_takes_context_in_place() {
        let error = BoxError::from_static_str("x")
            .context("y")
            .context_field("k", 1u8);
        assert_eq!(error_chain(error.as_ref()).count(), 1, "{error:?}");
        assert_eq!(error.to_string(), r#"x | "y" k="1""#);

        let typed: BoxError = Leaf.context("y");
        assert_eq!(
            error_chain(typed.as_ref()).count(),
            2,
            "a typed error stays its own link"
        );
        assert!(typed.has_cause::<Leaf>());
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
