//! Rama TCP Client module.

pub mod service;

mod connect;
#[doc(inline)]
pub use connect::{connect, connect_trusted};

mod request;
#[doc(inline)]
pub use request::{Parts, Request};
