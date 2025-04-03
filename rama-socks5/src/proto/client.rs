//! Client implementation of the SOCKS5 Protocol [RFC 1928]
//!
//! [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928

use super::{Command, ProtocolVersion, SocksMethod, UsernamePasswordSubnegotiationVersion};
use rama_net::address::Authority;
use smallvec::SmallVec;

#[derive(Debug, Clone)]
/// The client connects to the server, and sends a header which
/// contains the protocol version desired and SOCKS methods supported by the client.
///
/// ```plain
/// +-----+----------+----------+
/// | VER | NMETHODS | METHODS  |
/// +-----+----------+----------+
/// |  1  |    1     | 1 to 255 |
/// +-----+----------+----------|
/// ```
pub struct Header {
    pub version: ProtocolVersion,
    pub number_methods: u8,
    pub methods: SmallVec<[SocksMethod; 2]>,
}

#[derive(Debug, Clone)]
/// The SOCKS request sent by the client.
///
/// Once the method-dependent subnegotiation has completed, the client
/// sends the request details. If the negotiated method includes
/// encapsulation for purposes of integrity checking and/or
/// confidentiality, these requests MUST be encapsulated in the method-
/// dependent encapsulation.
///
/// The SOCKS request is formed as follows:
///
/// ```plain
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
///
/// The SOCKS server will typically evaluate the request based on source
/// and destination addresses, and return one or more reply messages, as
/// appropriate for the request type.
pub struct Request {
    pub version: ProtocolVersion,
    pub command: Command,
    pub destination: Authority,
}

#[derive(Debug, Clone)]
/// Initial username-password negotiation starts with the client sending this request.
///
/// Once the SOCKS V5 server has started, and the client has selected the
/// Username/Password Authentication protocol, the Username/Password
/// subnegotiation begins.  This begins with the client producing a
/// Username/Password request:
///
/// ```plain
/// +----+------+----------+------+----------+
/// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
/// +----+------+----------+------+----------+
/// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
/// +----+------+----------+------+----------+
/// ```
///
/// The VER field contains the current version of the subnegotiation,
/// which is X'01'. The ULEN field contains the length of the UNAME field
/// that follows. The UNAME field contains the username as known to the
/// source operating system. The PLEN field contains the length of the
/// PASSWD field that follows. The PASSWD field contains the password
/// association with the given UNAME.
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc1929#section-2>
///
/// ## Security Considerations
///
/// Since the request carries the
/// password in cleartext, this subnegotiation is not recommended for
/// environments where "sniffing" is possible and practical.
pub struct UsernamePasswordRequest {
    pub version: UsernamePasswordSubnegotiationVersion,
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

#[derive(Debug, Clone)]
/// Header for each datagram sent by a UDP Client.
///
/// A UDP-based client MUST send its datagrams to the UDP relay server at
/// the UDP port indicated by BND.PORT in the reply to the UDP ASSOCIATE
/// request.  If the selected authentication method provides
/// encapsulation for the purposes of authenticity, integrity, and/or
/// confidentiality, the datagram MUST be encapsulated using the
/// appropriate encapsulation.  Each UDP datagram carries a UDP request
/// header with it:
///
/// ```plain
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
/// ```
///
/// When a UDP relay server decides to relay a UDP datagram, it does so
/// silently, without any notification to the requesting client.
/// Similarly, it will drop datagrams it cannot or will not relay.  When
/// a UDP relay server receives a reply datagram from a remote host, it
/// MUST encapsulate that datagram using the above UDP request header,
/// and any authentication-method-dependent encapsulation.
///
/// The UDP relay server MUST acquire from the SOCKS server the expected
/// IP address of the client that will send datagrams to the BND.PORT
/// given in the reply to UDP ASSOCIATE.  It MUST drop any datagrams
/// arriving from any source IP address other than the one recorded for
/// the particular association.
///
/// The FRAG field indicates whether or not this datagram is one of a
/// number of fragments.  If implemented, the high-order bit indicates
/// end-of-fragment sequence, while a value of X'00' indicates that this
/// datagram is standalone.  Values between 1 and 127 indicate the
/// fragment position within a fragment sequence.  Each receiver will
/// have a REASSEMBLY QUEUE and a REASSEMBLY TIMER associated with these
/// fragments.  The reassembly queue must be reinitialized and the
/// associated fragments abandoned whenever the REASSEMBLY TIMER expires,
/// or a new datagram arrives carrying a FRAG field whose value is less
/// than the highest FRAG value processed for this fragment sequence.
/// The reassembly timer MUST be no less than 5 seconds.  It is
/// recommended that fragmentation be avoided by applications wherever
/// possible.
///
/// Implementation of fragmentation is optional; an implementation that
/// does not support fragmentation MUST drop any datagram whose FRAG
/// field is other than X'00'.
///
/// The programming interface for a SOCKS-aware UDP MUST report an
/// available buffer space for UDP datagrams that is smaller than the
/// actual space provided by the operating system:
///
/// - if ATYP is X'01': 10+method_dependent octets smaller
/// - if ATYP is X'03': 262+method_dependent octets smaller
/// - if ATYP is X'04': 20+method_dependent octets smaller
pub struct UdpRequestHeader {
    pub fragment_number: u8,
    pub destination: Authority,
    pub data: Vec<u8>,
}
