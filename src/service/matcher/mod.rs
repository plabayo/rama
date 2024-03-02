//! matcher utilities for any middleware where need to match
//! on incoming requests within a given [`Context`]
//!
//! [`Context`]: crate::service::Context

use super::{context::Extensions, Context};

mod always;
#[doc(inline)]
pub use always::Always;

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

#[cfg(test)]
mod test;