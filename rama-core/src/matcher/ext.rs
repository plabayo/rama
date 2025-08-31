use crate::{
    Context,
    matcher::{Extensions, Matcher},
};

use std::marker::PhantomData;
/// A matcher which allows you to match based on an extension,
/// either by comparing with an extension ([`ExtensionMatcher::with_const`]),
/// or using a custom predicate ([`ExtensionMatcher::with_fn`]).
pub struct ExtensionMatcher<P, T> {
    predicate: P,
    _marker: PhantomData<fn() -> T>,
}

impl<F, T> ExtensionMatcher<private::PredicateFn<F, T>, T>
where
    F: Fn(&T) -> bool + Send + Sync + 'static,
    T: Clone + Eq + Send + Sync + 'static,
{
    /// Create a new [`ExtensionMatcher`] with a predicate `F`,
    /// that will be called using the found `T` (if one is present),
    /// to let it decide whether or not the extension value is a match or not.
    pub fn with_fn(predicate: F) -> Self {
        Self {
            predicate: private::PredicateFn(predicate, PhantomData),
            _marker: PhantomData,
        }
    }
}

impl<T> ExtensionMatcher<private::PredicateConst<T>, T>
where
    T: Clone + Eq + Send + Sync + 'static,
{
    /// Create a new [`ExtensionMatcher`] with a const value `T`,
    /// that will be [`Eq`]-checked to find a match.
    pub fn with_const(value: T) -> Self {
        Self {
            predicate: private::PredicateConst(value),
            _marker: PhantomData,
        }
    }
}

impl<Request, P, T> Matcher<Request> for ExtensionMatcher<P, T>
where
    Request: Send + 'static,
    T: Clone + Send + Sync + 'static,
    P: private::ExtensionPredicate<T>,
{
    fn matches(&self, _ext: Option<&mut Extensions>, ctx: &Context, _req: &Request) -> bool {
        ctx.get::<T>()
            .map(|v| self.predicate.call(v))
            .unwrap_or_default()
    }
}

mod private {
    use std::marker::PhantomData;

    pub(super) trait ExtensionPredicate<T>: Send + Sync + 'static {
        fn call(&self, value: &T) -> bool;
    }

    pub(super) struct PredicateConst<T>(pub(super) T);

    impl<T> ExtensionPredicate<T> for PredicateConst<T>
    where
        T: Clone + Eq + Send + Sync + 'static,
    {
        #[inline]
        fn call(&self, value: &T) -> bool {
            self.0.eq(value)
        }
    }

    pub(super) struct PredicateFn<F, T>(pub(super) F, pub(super) PhantomData<fn() -> T>);

    impl<F, T> ExtensionPredicate<T> for PredicateFn<F, T>
    where
        F: Fn(&T) -> bool + Send + Sync + 'static,
        T: Clone + Eq + Send + Sync + 'static,
    {
        #[inline]
        fn call(&self, value: &T) -> bool {
            self.0(value)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MyMarker(i32);

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MyOtherMarker(i32);

    #[test]
    fn test_extension_matcher() {
        let matcher = ExtensionMatcher::with_const(MyMarker(10));
        let mut ctx = Context::default();

        assert!(!matcher.matches(None, &ctx, &()));

        ctx.insert(MyMarker(20));
        assert!(!matcher.matches(None, &ctx, &()));

        ctx.insert(MyOtherMarker(10));
        assert!(!matcher.matches(None, &ctx, &()));

        ctx.insert(MyMarker(10));
        assert!(matcher.matches(None, &ctx, &()));
    }

    #[test]
    fn test_fn_extension_matcher() {
        let matcher = ExtensionMatcher::with_fn(|v: &MyMarker| v.0 % 2 == 0);
        let mut ctx = Context::default();

        assert!(!matcher.matches(None, &ctx, &()));

        ctx.insert(MyMarker(4));
        assert!(matcher.matches(None, &ctx, &()));

        ctx.insert(MyMarker(5));
        assert!(!matcher.matches(None, &ctx, &()));

        ctx.insert(MyOtherMarker(4));
        assert!(!matcher.matches(None, &ctx, &()));
    }
}
