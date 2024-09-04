//! Rama TCP Client module.

pub mod service;

mod connect;
#[doc(inline)]
pub use connect::{connect, connect_trusted};

#[cfg(feature = "http")]
mod request;
#[cfg(feature = "http")]
#[doc(inline)]
pub use request::{Parts, Request};
