//! Server implementation of the SOCKS5 Protocol [RFC 1928]
//!
//! [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928

use super::version::{ProtocolVersion, SocksMethod};

#[derive(Debug, Clone)]
/// The server selects from one of the methods given in METHODS, and
/// sends a header back containing the selected METHOD and same Protocol vesion.
///
/// ```plain
/// +-----+--------+
/// | VER | METHOD |
/// +-----+--------+
/// |  1  |   1    |
/// +-----+--------+
/// ```
pub struct Header {
    pub version: ProtocolVersion,
    pub method: SocksMethod,
}
