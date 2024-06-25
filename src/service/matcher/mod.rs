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
//! Implementation Examples:
//!
//! - [`http::matcher`]: [`Matcher`] implementations for [`http::Request`]s.
//! - [`net::stream::matcher`]: [`Matcher`] implementations for [`Socket`]s (e.g. [`TcpStream`]).
//!
//! [`Context`]: crate::service::Context
//! [`http::matcher`]: crate::http::matcher
//! [`http::Request`]: crate::http::Request
//! [`net::stream::matcher`]: crate::net::stream::matcher
//! [`Socket`]: crate::net::stream::Socket
//! [`TcpStream`]: tokio::net::TcpStream

use super::{context::Extensions, Context};

mod op_or;
#[doc(inline)]
pub use op_or::{or, Or};

mod op_and;
#[doc(inline)]
pub use op_and::{and, And};

mod op_not;
#[doc(inline)]
pub use op_not::Not;

mod mfn;
#[doc(inline)]
pub use mfn::{match_fn, MatchFn};

mod iter;
#[doc(inline)]
pub use iter::IteratorMatcherExt;

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
        or!(self, other)
    }

    /// Add another condition to match on top of the current one.
    fn and<M>(self, other: M) -> impl Matcher<State, Request>
    where
        Self: Sized,
        M: Matcher<State, Request>,
    {
        and!(self, other)
    }

    /// Negate the current condition.
    fn not(self) -> impl Matcher<State, Request>
    where
        Self: Sized,
    {
        Not::new(self)
    }
}

impl<State, Request, T> Matcher<State, Request> for Option<T>
where
    T: Matcher<State, Request>,
{
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, req: &Request) -> bool {
        match self {
            Some(inner) => inner.matches(ext, ctx, req),
            None => true,
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
    State: Send + Sync + 'static,
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
        impl<$($param),+, State, Request> Matcher<State, Request> for crate::utils::combinators::$id<$($param),+>
        where
            $($param: Matcher<State, Request>),+,
            Request: Send + 'static,
            State: Send + Sync + 'static,
        {
            fn matches(
                &self,
                ext: Option<&mut Extensions>,
                ctx: &Context<State>,
                req: &Request
            ) -> bool{
                match self {
                    $(
                        crate::utils::combinators::$id::$param(layer) => layer.matches(ext, ctx, req),
                    )+
                }
            }
        }
    };
}

crate::utils::combinators::impl_either!(impl_matcher_either);

#[cfg(test)]
mod test;
