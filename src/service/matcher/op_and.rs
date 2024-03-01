use super::Matcher;
use crate::service::{context::Extensions, Context};
use std::hash::Hash;

/// A matcher that matches if all of the inner matchers match.
pub struct And<T>(T);

impl<T: Hash> Hash for And<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for And<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("And").field(&self.0).finish()
    }
}

impl<T: Clone> Clone for And<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> And<T> {
    /// Create a new `And` matcher.
    pub fn new(inner: T) -> Self {
        Self(inner)
    }
}

macro_rules! impl_and {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<State, Request, $($ty),+> Matcher<State, Request> for And<($($ty),+,)>
            where $($ty: Matcher<State, Request>),+
        {
            fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, req: &Request) -> bool {
                let ($($ty),+,) = &self.0;
                match ext {
                    Some(ext) => {
                        $(
                            let mut inner_ext = Extensions::new();
                            if !$ty.matches(Some(&mut inner_ext), ctx, req) {
                                return false;
                            }
                        )+
                        ext.extend(inner_ext);
                        true
                    }
                    None => {
                        $(
                            if !$ty.matches(None, ctx, req) {
                                return false;
                            }
                        )+
                        true
                    }
                }
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_and);

#[doc(hidden)]
#[macro_export]
macro_rules! __and {
    ($($ty:expr),+ $(,)?) => {
        $crate::service::matcher::And::new(($($ty),+,))
    };
}

/// Create a new `And` matcher.
#[doc(inline)]
pub use __and as and;
