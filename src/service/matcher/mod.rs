//! matcher utilities for any middleware where need to match
//! on incoming requests within a given [`Context`]
//!
//! [`Context`]: crate::service::Context

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

mod op_not;
#[doc(inline)]
pub use op_not::Not;

/// A condition to decide whether `Request` within the given [`Context`] matches for
/// router or other middleware purposes.
pub trait Matcher<State, Request>: Send + Sync + 'static {
    /// returns true on a match, false otherwise
    ///
    /// `ext` is None in case the callee is not interested in collecting potential
    /// match metadata gathered during the matching process. An example of this
    /// path parameters for an http Uri matcher.
    fn matches(&self, ext: Option<&mut Extensions>, ctx: &Context<State>, req: &Request) -> bool;
}

mod mfn;
#[doc(inline)]
pub use mfn::{match_fn, MatchFn};
