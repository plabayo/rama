//! Rama TCP Client module.

#[cfg(feature = "http")]
pub mod service;

mod connect;
#[doc(inline)]
pub use connect::{TcpStreamConnector, default_tcp_connect, tcp_connect};

mod pool;
#[doc(inline)]
pub use pool::{
    PoolMode, TcpStreamConnectorPool,
    ipcidr_connector::IpCidrConnector,
    utils::{
        IpCidrConExt, IpCidrConExtUsernameLabelParser, ipv4_from_extension, ipv4_with_range,
        ipv6_from_extension, ipv6_with_range, rand_ipv4, rand_ipv6,
    },
};

#[cfg(feature = "http")]
mod request;
#[cfg(feature = "http")]
#[doc(inline)]
pub use request::{Parts, Request};
