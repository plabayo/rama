//! Middleware to support the reading and writing of Forwarded headers.

mod get_forwarded;
#[doc(inline)]
pub use get_forwarded::{GetForwardedLayer, GetForwardedService};

mod set_forwarded;
#[doc(inline)]
pub use set_forwarded::{SetForwardedLayer, SetForwardedService};
