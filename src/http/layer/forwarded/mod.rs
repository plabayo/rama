//! Middleware to support the reading and writing of Forwarded headers.
//!
//! See the [`GetForwardedHeadersLayer`] and [`SetForwardedHeadersLayer`] documentation for more details.

mod get_forwarded;
#[doc(inline)]
pub use get_forwarded::{GetForwardedHeadersLayer, GetForwardedHeadersService};

mod set_forwarded;
#[doc(inline)]
pub use set_forwarded::{SetForwardedHeadersLayer, SetForwardedHeadersService};
