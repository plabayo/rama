//! Implementation of the SOCKS5 Protocol [RFC 1928]
//!
//! [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928

pub mod client;
pub mod server;

mod enums;
pub use enums::{
    AddressType, Command, ProtocolVersion, ReplyKind, SocksMethod,
    UsernamePasswordSubnegotiationVersion,
};
