//! Client implementation of the SOCKS5 Protocol [RFC 1928]
//!
//! [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928

use super::version::{ProtocolVersion, SocksMethod};
use smallvec::SmallVec;

#[derive(Debug, Clone)]
/// The client connects to the server, and sends a header which
/// contains the protocol version desired and SOCKS methods supported by the client.
pub struct Header {
    pub version: ProtocolVersion,
    pub number_methods: u8,
    pub methods: SmallVec<[SocksMethod; 2]>,
}
