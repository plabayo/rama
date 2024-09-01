use super::Matcher;
use crate::utils::macros::all_the_tuples_no_last_special_case;
use crate::{context::Extensions, Context};

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
    pub const fn new(inner: T) -> Self {
        Self(inner)
    }
}

macro_rules! impl_or_matches {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
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
    };
}

macro_rules! impl_or {
    ($T1:ident,$T2:ident,$T3:ident,$T4:ident,$T5:ident,$T6:ident,$T7:ident,$T8:ident,$T9:ident,$T10:ident,$T11:ident,$T12:ident $(,)?) => {
        #[allow(non_snake_case)]
        impl<State, Request, $T1, $T2, $T3, $T4, $T5, $T6, $T7, $T8, $T9, $T10, $T11, $T12> Matcher<State, Request> for Or<($T1, $T2, $T3, $T4, $T5, $T6, $T7, $T8, $T9, $T10, $T11, $T12)>
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
                  $T12: Matcher<State, Request>,
        {
            impl_or_matches!( $T1, $T2, $T3, $T4, $T5, $T6, $T7, $T8, $T9, $T10, $T11, $T12 );
        }
    };

    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<State, Request, $($ty),+> Matcher<State, Request> for Or<($($ty),+,)>
            where $($ty: Matcher<State, Request>),+
        {
            impl_or_matches!( $($ty),+ );

            fn or<M>(self, matcher: M) -> impl Matcher<State, Request>
            where
                Self: Sized,
                M: Matcher<State, Request>,
            {
                let ($($ty),+,) = self.0;
                let inner = ($($ty,)+ matcher);
                Or::new(inner)
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_or);
