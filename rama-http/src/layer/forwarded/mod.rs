//! Middleware to support the reading and writing of Forwarded headers.

mod get_forwarded;
#[doc(inline)]
pub use get_forwarded::{GetForwardedHeaderLayer, GetForwardedHeaderService};

mod get_forwarded_multi;
#[doc(inline)]
pub use get_forwarded_multi::{GetForwardedHeadersLayer, GetForwardedHeadersService};

mod set_forwarded;
#[doc(inline)]
pub use set_forwarded::{SetForwardedHeaderLayer, SetForwardedHeaderService};

mod set_forwarded_multi;
#[doc(inline)]
pub use set_forwarded_multi::{SetForwardedHeadersLayer, SetForwardedHeadersService};
