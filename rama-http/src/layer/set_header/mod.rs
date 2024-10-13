//! Middleware for setting headers on requests and responses.
//!
//! See [request] and [response] for more details.

pub mod request;
pub mod response;

#[doc(inline)]
pub use self::{
    request::{SetRequestHeader, SetRequestHeaderLayer},
    response::{SetResponseHeader, SetResponseHeaderLayer},
};
