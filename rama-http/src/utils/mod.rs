//! Utilities for HTTP.

mod upgrade;
#[doc(inline)]
pub use upgrade::request_connect_protocol;

mod header_value;
#[doc(inline)]
pub use header_value::{HeaderValueErr, HeaderValueGetter};

#[doc(hidden)]
#[macro_use]
pub(crate) mod macros;
