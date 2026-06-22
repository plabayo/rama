//! Rama TCP Client module.

pub mod service;

mod connect;
#[doc(inline)]
pub use connect::{
    DenyTcpStreamConnector, TcpConnectDeniedError, TcpStreamConnector, default_tcp_connect,
    tcp_connect,
};
