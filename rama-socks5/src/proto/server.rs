//! Server implementation of the SOCKS5 Protocol [RFC 1928]
//!
//! [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928

use rama_net::address::Authority;

use super::{ProtocolVersion, ReplyKind, SocksMethod, UsernamePasswordSubnegotiationVersion};

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

#[derive(Debug, Clone)]
/// Sent by the server as a reply on an earlier client request.
///
/// The SOCKS request information is sent by the client as soon as it has
/// established a connection to the SOCKS server, and completed the
/// authentication negotiations.  The server evaluates the request, and
/// returns a reply formed as follows:
///
/// ```plain
/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
///
/// If the chosen method includes encapsulation for purposes of
/// authentication, integrity and/or confidentiality, the replies are
/// encapsulated in the method-dependent encapsulation.
pub struct Reply {
    pub version: ProtocolVersion,
    pub reply: ReplyKind,
    pub bind_address: Authority,
}

#[derive(Debug, Clone)]
/// Response to the username-password request sent by the client.
///
/// he server verifies the supplied UNAME and PASSWD, and sends the
/// following response:
///
/// ```plain
/// +----+--------+
/// |VER | STATUS |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
/// ```
///
/// A STATUS field of X'00' indicates success. If the server returns a
/// `failure' (STATUS value other than X'00') status, it MUST close the
/// connection.
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc1929#section-2>
pub struct UsernamePasswordResponse {
    pub version: UsernamePasswordSubnegotiationVersion,
    pub status: u8,
}

impl UsernamePasswordResponse {
    /// Indicates if the (auth) response from the server indicates success.
    pub fn success(&self) -> bool {
        self.status == 0
    }
}
