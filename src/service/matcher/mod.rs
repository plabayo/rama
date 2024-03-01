//! matcher utilities for any middleware where need to match
//! on incoming requests within a given [`Context`]
//!
//! [`Context`]: crate::service::Context

use std::hash::Hash;

use super::{context::Extensions, Context};

mod any;
#[doc(inline)]
pub use any::Any;

mod op_or;
#[doc(inline)]
pub use op_or::{or, Or};

mod op_and;
#[doc(inline)]
pub use op_and::{and, And};

/// condition to decide whether [`Request`] within the given [`Context`] matches to a defined (web) [`Service`]
///
/// [`Service`]: crate::service::Service
pub trait Matcher<State, Request>: Hash + Send + Sync + 'static {
    /// returns true on a match, false otherwise
    ///
    /// `ext` is None in case the callee is not interested in collecting potential
    /// match metadata gathered during the matching process. An example of this
    /// path parameters for an http Uri matcher.
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, req: &Request) -> bool;
}

macro_rules! impl_matcher_tuple {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<State, Request, $($ty),+> Matcher<State, Request> for ($($ty),+,)
            where $($ty: Matcher<State, Request>),+
        {
            fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, req: &Request) -> bool {
                match ext {
                    Some(ext) => {
                        let ($($ty),+,) = self;
                        $(
                            $ty.matches(Some(ext), ctx, req)
                        ) &&+
                    }
                    None => {
                        let ($($ty),+,) = self;
                        $($ty.matches(None, ctx, req)) &&+
                    }
                }
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_matcher_tuple);
