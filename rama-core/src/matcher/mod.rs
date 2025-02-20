//! matcher utilities for any middleware where need to match
//! on incoming requests within a given [`Context`]
//!
//! This module provides the [`Matcher`] trait and convenience utilities around it.
//!
//! - Examples of this are iterator "reducers" as made available via [`IteratorMatcherExt`],
//!   as well as optional [`Matcher::or`] and [`Matcher::and`] trait methods.
//! - These all serve as building blocks together with [`And`], [`Or`], [`Not`] and a bool
//!   to combine and transform any kind of [`Matcher`].
//! - And finally there is [`MatchFn`], easily created using [`match_fn`] to create a [`Matcher`]
//!   from any compatible [`Fn`].
//!
//! [`Context`]: crate::Context

use std::sync::Arc;

use super::{Context, context::Extensions};
use crate::Service;
use paste::paste;
use rama_utils::macros::all_the_tuples_no_last_special_case;

mod op_or;
#[doc(inline)]
pub use op_or::Or;

mod op_and;
#[doc(inline)]
pub use op_and::And;

mod op_not;
#[doc(inline)]
pub use op_not::Not;

mod mfn;
#[doc(inline)]
pub use mfn::{MatchFn, match_fn};

mod iter;
#[doc(inline)]
pub use iter::IteratorMatcherExt;

mod ext;
#[doc(inline)]
pub use ext::ExtensionMatcher;

/// A condition to decide whether `Request` within the given [`Context`] matches for
/// router or other middleware purposes.
pub trait Matcher<State, Request>: Send + Sync + 'static {
    /// returns true on a match, false otherwise
    ///
    /// `ext` is None in case the callee is not interested in collecting potential
    /// match metadata gathered during the matching process. An example of this
    /// path parameters for an http Uri matcher.
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, req: &Request) -> bool;

    /// Provide an alternative matcher to match if the current one does not match.
    fn or<M>(self, other: M) -> impl Matcher<State, Request>
    where
        Self: Sized,
        M: Matcher<State, Request>,
    {
        Or::new((self, other))
    }

    /// Add another condition to match on top of the current one.
    fn and<M>(self, other: M) -> impl Matcher<State, Request>
    where
        Self: Sized,
        M: Matcher<State, Request>,
    {
        And::new((self, other))
    }

    /// Negate the current condition.
    fn not(self) -> impl Matcher<State, Request>
    where
        Self: Sized,
    {
        Not::new(self)
    }
}

impl<State, Request, T> Matcher<State, Request> for Arc<T>
where
    T: Matcher<State, Request>,
{
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, req: &Request) -> bool {
        (**self).matches(ext, ctx, req)
    }
}

impl<State, Request, T> Matcher<State, Request> for &'static T
where
    T: Matcher<State, Request>,
{
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, req: &Request) -> bool {
        (**self).matches(ext, ctx, req)
    }
}

impl<State, Request, T> Matcher<State, Request> for Option<T>
where
    T: Matcher<State, Request>,
{
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, req: &Request) -> bool {
        match self {
            Some(inner) => inner.matches(ext, ctx, req),
            None => false,
        }
    }
}

impl<State, Request, T> Matcher<State, Request> for Box<T>
where
    T: Matcher<State, Request>,
{
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, req: &Request) -> bool {
        (**self).matches(ext, ctx, req)
    }
}

impl<State, Request> Matcher<State, Request> for Box<(dyn Matcher<State, Request> + 'static)>
where
    State: Clone + Send + Sync + 'static,
    Request: Send + 'static,
{
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, req: &Request) -> bool {
        (**self).matches(ext, ctx, req)
    }
}

impl<State, Request> Matcher<State, Request> for bool {
    fn matches(&self, _: Option<&mut Extensions>, _: &Context<State>, _: &Request) -> bool {
        *self
    }
}

macro_rules! impl_matcher_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+, State, Request> Matcher<State, Request> for crate::combinators::$id<$($param),+>
        where
            $($param: Matcher<State, Request>),+,
            Request: Send + 'static,
            State: Clone + Send + Sync + 'static,
        {
            fn matches(
                &self,
                ext: Option<&mut Extensions>,
                ctx: &Context<State>,
                req: &Request
            ) -> bool{
                match self {
                    $(
                        crate::combinators::$id::$param(layer) => layer.matches(ext, ctx, req),
                    )+
                }
            }
        }
    };
}

crate::combinators::impl_either!(impl_matcher_either);

macro_rules! impl_matcher_service_tuple {
    ($($T:ident),+ $(,)?) => {
        paste!{
            #[allow(non_camel_case_types)]
            #[allow(non_snake_case)]
            impl<State, $([<M_ $T>], $T),+, S, Request, Response, Error> Service<State, Request> for ($(([<M_ $T>], $T)),+, S)
            where
                State: Clone + Send + Sync + 'static,
                Request: Send + 'static,
                Response: Send + 'static,
                $(
                    [<M_ $T>]: Matcher<State, Request>,
                    $T: Service<State, Request, Response = Response, Error = Error>,
                )+
                S: Service<State, Request, Response = Response, Error = Error>,
                Error: Send + Sync + 'static,
            {
                type Response = Response;
                type Error = Error;

                async fn serve(
                    &self,
                    mut ctx: Context<State>,
                    req: Request,
                ) -> Result<Self::Response, Self::Error> {
                    let ($(([<M_ $T>], $T)),+, S) = self;
                    let mut ext = Extensions::new();
                    $(
                        if [<M_ $T>].matches(Some(&mut ext), &ctx, &req) {
                            ctx.extend(ext);
                            return $T.serve(ctx, req).await;
                        }
                        ext.clear();
                    )+
                    S.serve(ctx, req).await
                }
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_matcher_service_tuple);

#[cfg(test)]
mod test;
