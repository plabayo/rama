use super::Matcher;
use crate::service::{context::Extensions, Context};
use std::hash::Hash;

/// A matcher that matches if any of the inner matchers match.
pub struct Or<T>(T);

impl<T: Hash> Hash for Or<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(b"or");
        self.0.hash(state);
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Or<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Or").field(&self.0).finish()
    }
}

impl<T: Clone> Clone for Or<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Or<T> {
    /// Create a new `Or` matcher.
    pub fn new(inner: T) -> Self {
        Self(inner)
    }
}

macro_rules! impl_or {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<State, Request, $($ty),+> Matcher<State, Request> for Or<($($ty),+,)>
            where $($ty: Matcher<State, Request>),+
        {
            fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, req: &Request) -> bool {
                let ($($ty),+,) = &self.0;
                match ext {
                    Some(ext) => {
                        let mut inner_ext = Extensions::new();
                        $(
                            if $ty.matches(Some(&mut inner_ext), ctx, req) {
                                ext.extend(inner_ext);
                                return true;
                            }
                            inner_ext.clear();
                        )+
                        false
                    }
                    None => {
                        $(
                            if $ty.matches(None, ctx, req) {
                                return true;
                            }
                        )+
                        false
                    }
                }
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_or);

#[doc(hidden)]
#[macro_export]
/// Create a new [`Or`] matcher.
macro_rules! __op_or {
    ($($ty:expr),+ $(,)?) => {
        $crate::service::matcher::Or::new(($($ty),+,))
    };
}

#[doc(inline)]
pub use __op_or as or;
