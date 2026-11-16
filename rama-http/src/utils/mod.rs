//! Utilities for HTTP.

mod upgrade;
pub(crate) use upgrade::is_plain_connect;
#[doc(inline)]
pub use upgrade::request_connect_protocol;

mod body_error;
pub(crate) use body_error::body_error_status;

mod header_value;
#[doc(inline)]
pub use header_value::{HeaderValueErr, HeaderValueGetter};

#[doc(hidden)]
#[macro_use]
pub(crate) mod macros;
