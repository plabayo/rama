//! Utilities for HTTP.

mod header_value;
#[doc(inline)]
pub use header_value::{HeaderValueErr, HeaderValueGetter};

#[doc(hidden)]
#[macro_use]
pub(crate) mod macros;

mod request;
pub use request::request_uri;
