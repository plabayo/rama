//! Middleware that fills in headers a request or response is expected to carry.
//!
//! - [`AddRequiredRequestHeaders`]: `Host` and `User-Agent` on the outgoing request,
//!   typically used by http clients.
//! - [`AddRequiredResponseHeaders`]: `Server` and `Date` on the outgoing response,
//!   typically used by http servers.
//!
//! By default only missing headers are added; existing ones are left untouched
//! unless overwriting is enabled.

pub mod request;
pub mod response;

#[doc(inline)]
pub use self::{
    request::{AddRequiredRequestHeaders, AddRequiredRequestHeadersLayer},
    response::{AddRequiredResponseHeaders, AddRequiredResponseHeadersLayer},
};
