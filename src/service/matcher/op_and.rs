use super::Matcher;
use crate::service::{context::Extensions, Context};

/// A matcher that matches if all of the inner matchers match.
pub struct And<T>(T);

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

macro_rules! impl_and_matches {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, req: &Request) -> bool {
            let ($($ty),+,) = &self.0;
            match ext {
                Some(ext) => {
                    let mut inner_ext = Extensions::new();
                    $(
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
    };
}

macro_rules! impl_and {
    ($T1:ident,$T2:ident,$T3:ident,$T4:ident,$T5:ident,$T6:ident,$T7:ident,$T8:ident,$T9:ident,$T10:ident,$T11:ident,$T12:ident $(,)?) => {
        #[allow(non_snake_case)]
        impl<State, Request, $T1, $T2, $T3, $T4, $T5, $T6, $T7, $T8, $T9, $T10, $T11, $T12> Matcher<State, Request> for And<($T1, $T2, $T3, $T4, $T5, $T6, $T7, $T8, $T9, $T10, $T11, $T12)>
            where $T1: Matcher<State, Request>,
                  $T2: Matcher<State, Request>,
                  $T3: Matcher<State, Request>,
                  $T4: Matcher<State, Request>,
                  $T5: Matcher<State, Request>,
                  $T6: Matcher<State, Request>,
                  $T7: Matcher<State, Request>,
                  $T8: Matcher<State, Request>,
                  $T9: Matcher<State, Request>,
                  $T10: Matcher<State, Request>,
                  $T11: Matcher<State, Request>,
                  $T12: Matcher<State, Request>
        {
            impl_and_matches!( $T1, $T2, $T3, $T4, $T5, $T6, $T7, $T8, $T9, $T10, $T11, $T12 );
        }
    };

    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<State, Request, $($ty),+> Matcher<State, Request> for And<($($ty),+,)>
            where $($ty: Matcher<State, Request>),+
        {
            impl_and_matches!($($ty),+);

            fn and<M>(self, matcher: M) -> impl Matcher<State, Request>
            where
                Self: Sized,
                M: Matcher<State, Request>,
            {
                let ($($ty),+,) = self.0;
                let inner = ($($ty,)+ matcher);
                And::new(inner)
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_and);

#[doc(hidden)]
#[macro_export]
/// Create a new [`And`] matcher.
macro_rules! __op_and {
    ($($ty:expr),+ $(,)?) => {
        $crate::service::matcher::And::new(($($ty),+,))
    };
}

#[doc(inline)]
pub use __op_and as and;
