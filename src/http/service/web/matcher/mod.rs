//! matchers to match a request to a web service

mod method;
pub use method::MethodFilter;

mod domain;
pub use domain::DomainFilter;

mod path;
pub use path::{PathFilter, UriParams};

use crate::{http::Request, service::Context};

/// condition to decide whether [`Request`] within the given [`Context`] matches to a defined (web) [`Service`]
///
/// [`Service`]: crate::service::Service
pub trait Matcher<State>: Send + Sync + 'static {
    /// returns true on a match, false otherwise
    fn matches(&self, ctx: &mut Context<State>, req: &Request) -> bool;
}

macro_rules! impl_matcher_tuple {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<State,$($ty),+> Matcher<State> for ($($ty),+,)
            where $($ty: Matcher<State>),+
        {
            fn matches(&self, ctx: &mut Context<State>, req: &Request) -> bool {
                let ($($ty),+,) = self;
                $($ty.matches(ctx, req))&&+
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_matcher_tuple);
