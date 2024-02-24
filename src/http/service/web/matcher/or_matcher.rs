use super::Matcher;
use crate::{
    http::Request,
    service::{context::Extensions, Context},
};

/// A matcher that matches if any of the inner matchers match.
pub struct Or<T>(T);

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
        impl<State, Body, $($ty),+> Matcher<State, Body> for Or<($($ty),+,)>
            where $($ty: Matcher<State, Body>),+
        {
            fn matches(&self, ext: &mut Extensions, ctx: &Context<State>, req: &Request<Body>) -> bool {
                let ($($ty),+,) = &self.0;
                let mut inner_ext = Extensions::new();
                $(
                    if $ty.matches(&mut inner_ext, ctx, req) {
                        ext.extend(inner_ext);
                        return true;
                    }
                    inner_ext.clear();
                )+
                false
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_or);

#[doc(hidden)]
#[macro_export]
macro_rules! __or {
    ($($ty:expr),+ $(,)?) => {
        $crate::http::service::web::matcher::Or::new(($($ty),+,))
    };
}

#[doc(inline)]
pub use __or as or;
