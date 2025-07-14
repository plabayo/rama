//! Utilities for HTTP.

mod header_value;
#[doc(inline)]
pub use header_value::{HeaderValueErr, HeaderValueGetter};

#[doc(hidden)]
#[macro_use]
pub(crate) mod macros;

mod req_switch_version_ext;
pub use req_switch_version_ext::RequestSwitchVersionExt;
