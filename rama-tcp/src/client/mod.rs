//! Rama TCP Client module.

#[cfg(feature = "http")]
pub mod service;

mod connect;
#[doc(inline)]
pub use connect::tcp_connect;

#[cfg(feature = "http")]
mod request;
#[cfg(feature = "http")]
#[doc(inline)]
pub use request::{Parts, Request};
