//! Utilities for HTTP.

#[doc(inline)]
pub use ::rama_http_types::utils::{http_date, structured_fields};

mod upgrade;
pub(crate) use upgrade::{is_adaptable_upgrade, is_plain_connect, is_websocket_protocol};
#[doc(inline)]
pub use upgrade::{request_adaptable_upgrade, request_connect_protocol, request_signals_upgrade};

mod body_error;
pub(crate) use body_error::body_error_status;

mod header_value;
#[doc(inline)]
pub use header_value::{HeaderValueErr, HeaderValueGetter};

#[doc(hidden)]
#[macro_use]
pub(crate) mod macros;
