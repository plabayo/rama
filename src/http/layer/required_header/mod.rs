//! Middleware for setting required headers on requests and responses, if they are missing.
//!
//! See [request] and [response] for more details.

pub mod request;
pub mod response;

#[doc(inline)]
pub use self::{
    request::{AddRequiredRequestHeaders, AddRequiredRequestHeadersLayer},
    response::{AddRequiredResponseHeaders, AddRequiredResponseHeadersLayer},
};
