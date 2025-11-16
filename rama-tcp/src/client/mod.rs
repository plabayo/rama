//! Rama TCP Client module.

#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub mod service;

mod connect;
#[doc(inline)]
pub use connect::{TcpStreamConnector, default_tcp_connect, tcp_connect};

#[cfg(feature = "http")]
mod request;
#[cfg(feature = "http")]
#[doc(inline)]
pub use request::Request;
